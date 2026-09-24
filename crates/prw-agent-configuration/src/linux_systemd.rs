//! Linux-only managed user-systemd configuration writer selected by C03e-TV.
//!
//! This module owns only the two PRW-managed non-secret drop-ins. It never reloads or starts a
//! service, changes enablement/linger state, or mutates the vendor unit or identity drop-in.

use std::{
    fmt,
    fs::{self, File, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::{
    fs::{AtFlags, FlockOperation, Mode, OFlags, flock, mkdirat, open, openat, renameat, unlinkat},
    io::Errno,
    process::{geteuid, getuid},
};

use crate::{
    AgentExecutionMode, ConfiguredRemoteBundle, PRW_AGENT_EXECUTION_MODE,
    PRW_REMOTE_APPLICATION_LEASE_SECONDS, PRW_REMOTE_BIND_ADDR,
    PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS, PRW_REMOTE_MAX_ACTIVE_WORKERS,
    PRW_REMOTE_PEER_DEVICE_ID, PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
    SystemdSerializationError, recognize_configured_remote_drop_in,
    recognize_execution_mode_drop_in, render_configured_remote_drop_in,
    render_execution_mode_drop_in,
};

/// Exact managed mode drop-in filename.
pub const EXECUTION_MODE_DROPIN_NAME: &str = "30-agent-execution-mode.conf";
/// Exact managed configured-remote bundle drop-in filename.
pub const CONFIGURED_REMOTE_INPUTS_DROPIN_NAME: &str = "40-configured-remote-inputs.conf";
/// Separate identity-custody drop-in filename, never owned by this writer.
pub const DEVICE_IDENTITY_DROPIN_NAME: &str = "20-device-identity-credential.conf";

const MANAGED_DIRECTORY_NAME: &str = "prw-agent.service.d";
const USER_UNIT_DIRECTORY_RELATIVE: &str = "systemd/user";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MANAGED_LEAF_MODE: u32 = 0o600;
const SYSTEMD_ANALYZE_PATH: &str = "/usr/bin/systemd-analyze";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Explicit intended-user filesystem context supplied by a separately gated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntendedUserSystemdContext {
    uid: u32,
    home_dir: PathBuf,
    xdg_config_root: PathBuf,
}

/// Intended-user context is not absolute/testable as required by C03e-TV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntendedUserSystemdContextError;

impl fmt::Display for IntendedUserSystemdContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("intended-user systemd context invalid")
    }
}

impl std::error::Error for IntendedUserSystemdContextError {}

impl IntendedUserSystemdContext {
    /// Constructs one explicit intended-user context without consulting ambient HOME/XDG values.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute HOME or XDG configuration roots.
    pub fn new(
        uid: u32,
        home_dir: PathBuf,
        xdg_config_root: PathBuf,
    ) -> Result<Self, IntendedUserSystemdContextError> {
        if !home_dir.is_absolute() || !xdg_config_root.is_absolute() {
            return Err(IntendedUserSystemdContextError);
        }
        Ok(Self {
            uid,
            home_dir,
            xdg_config_root,
        })
    }

    /// Returns the intended numeric user ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the explicit intended-user HOME path.
    #[must_use]
    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }

    /// Returns the explicit effective XDG configuration root.
    #[must_use]
    pub fn xdg_config_root(&self) -> &Path {
        &self.xdg_config_root
    }

    fn user_unit_directory(&self) -> PathBuf {
        self.xdg_config_root.join(USER_UNIT_DIRECTORY_RELATIVE)
    }

    fn managed_directory(&self) -> PathBuf {
        self.user_unit_directory().join(MANAGED_DIRECTORY_NAME)
    }
}

/// Fully validated desired PRW-managed file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedAgentConfiguration {
    /// Canonical local-only mode with no managed remote-input bundle.
    LocalOnly,
    /// Canonical configured-remote mode with one complete six-value bundle.
    ConfiguredRemote(Box<ConfiguredRemoteBundle>),
}

impl ManagedAgentConfiguration {
    const fn mode(&self) -> AgentExecutionMode {
        match self {
            Self::LocalOnly => AgentExecutionMode::LocalOnly,
            Self::ConfiguredRemote(_) => AgentExecutionMode::ConfiguredRemote,
        }
    }
}

/// Successful verified managed-file transaction result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSystemdWriteResult {
    mode: AgentExecutionMode,
}

impl ManagedSystemdWriteResult {
    /// Returns the exact verified desired execution mode.
    #[must_use]
    pub const fn mode(self) -> AgentExecutionMode {
        self.mode
    }
}

/// Opaque one-use recovery authority for one verified managed-file transaction.
///
/// The token deliberately exposes neither raw snapshot bytes nor arbitrary filesystem paths.
/// Dropping it performs no rollback; callers that need post-write activation recovery must consume
/// it through [`restore_recoverable_managed_systemd_configuration`].
pub struct RecoverableManagedSystemdTransaction {
    before_mode: LeafSnapshot,
    before_remote: LeafSnapshot,
    committed_mode: LeafSnapshot,
    committed_remote: LeafSnapshot,
    committed_execution_mode: AgentExecutionMode,
}

impl fmt::Debug for RecoverableManagedSystemdTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableManagedSystemdTransaction")
            .field("committed_execution_mode", &self.committed_execution_mode)
            .finish_non_exhaustive()
    }
}

impl RecoverableManagedSystemdTransaction {
    /// Returns the execution mode whose exact managed state was committed.
    #[must_use]
    pub const fn committed_execution_mode(&self) -> AgentExecutionMode {
        self.committed_execution_mode
    }
}

/// Successful managed-file commit plus opaque one-use post-write recovery authority.
pub struct RecoverableManagedSystemdWrite {
    result: ManagedSystemdWriteResult,
    recovery: RecoverableManagedSystemdTransaction,
}

impl fmt::Debug for RecoverableManagedSystemdWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableManagedSystemdWrite")
            .field("result", &self.result)
            .field("recovery", &self.recovery)
            .finish()
    }
}

impl RecoverableManagedSystemdWrite {
    /// Returns the verified managed-file result without exposing recovery internals.
    #[must_use]
    pub const fn result(&self) -> ManagedSystemdWriteResult {
        self.result
    }

    /// Splits the verified result from its one-use recovery authority.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ManagedSystemdWriteResult,
        RecoverableManagedSystemdTransaction,
    ) {
        (self.result, self.recovery)
    }
}

/// Bounded failure for the TV-selected managed-file transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedSystemdConfigurationError {
    /// Current real/effective user is not the explicitly intended user.
    IntendedUserMismatch,
    /// Required XDG/systemd parent directory custody is unsafe or unavailable.
    ParentDirectoryCustody,
    /// Managed drop-in directory could not be safely created/opened/validated.
    ManagedDirectoryCustody,
    /// Advisory writer lock could not be acquired.
    WriterLock,
    /// Existing managed leaf metadata is unsafe.
    ManagedLeafCustody,
    /// Existing managed leaf content is not recognized canonical PRW content.
    ForeignManagedLeaf,
    /// Installed systemd tooling could not provide trustworthy user-unit search paths.
    UnitSearchPathDiscovery,
    /// External effective service custody can affect one of the seven selected variables.
    ExternalConfigurationConflict,
    /// Canonical desired-state serialization rejected semantic text.
    Serialization(SystemdSerializationError),
    /// Same-directory temp staging or durability validation failed.
    Staging,
    /// One selected namespace commit/removal failed.
    Commit,
    /// Final reopened desired-state verification failed.
    PostCommitVerification,
    /// Exact in-process managed-file rollback failed.
    Rollback,
}

impl fmt::Display for ManagedSystemdConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IntendedUserMismatch => "managed systemd intended-user mismatch",
            Self::ParentDirectoryCustody => "managed systemd parent-directory custody failed",
            Self::ManagedDirectoryCustody => "managed systemd directory custody failed",
            Self::WriterLock => "managed systemd writer lock failed",
            Self::ManagedLeafCustody => "managed systemd leaf custody failed",
            Self::ForeignManagedLeaf => "managed systemd leaf content unrecognized",
            Self::UnitSearchPathDiscovery => "systemd user-unit search-path discovery failed",
            Self::ExternalConfigurationConflict => "competing systemd environment custody detected",
            Self::Serialization(_) => "managed systemd serialization failed",
            Self::Staging => "managed systemd staging failed",
            Self::Commit => "managed systemd commit failed",
            Self::PostCommitVerification => "managed systemd post-commit verification failed",
            Self::Rollback => "managed systemd rollback failed",
        })
    }
}

impl std::error::Error for ManagedSystemdConfigurationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SystemdSerializationError> for ManagedSystemdConfigurationError {
    fn from(error: SystemdSerializationError) -> Self {
        Self::Serialization(error)
    }
}

/// Commits and verifies only the TV-selected managed `30-`/`40-` file desired state.
///
/// This function performs a read-only `systemd-analyze --user unit-paths` query for effective
/// custody preflight. It never invokes daemon reload, start/restart/stop, enablement or linger APIs.
///
/// # Errors
///
/// Fails closed on intended-user mismatch, unsafe filesystem custody, external competing
/// configuration, serialization/staging/commit/verification failure, or rollback failure.
pub fn apply_managed_systemd_configuration(
    context: &IntendedUserSystemdContext,
    desired: &ManagedAgentConfiguration,
) -> Result<ManagedSystemdWriteResult, ManagedSystemdConfigurationError> {
    apply_managed_systemd_configuration_recoverable(context, desired).map(|write| write.result())
}

/// Commits and verifies desired managed-file state while retaining opaque exact rollback authority.
///
/// The returned recovery token is created only after exact post-commit reopen verification and a
/// second secure snapshot of the committed state. No service-manager operation is performed.
///
/// # Errors
///
/// Has the same fail-closed filesystem, custody and serialization behavior as
/// [`apply_managed_systemd_configuration`]. Any failure before token return rolls managed files back
/// through the existing in-process writer rollback path.
pub fn apply_managed_systemd_configuration_recoverable(
    context: &IntendedUserSystemdContext,
    desired: &ManagedAgentConfiguration,
) -> Result<RecoverableManagedSystemdWrite, ManagedSystemdConfigurationError> {
    validate_current_user(context)?;
    let unit_paths = discover_user_unit_search_paths(context)?;
    let mut event_sink = |_| {};
    apply_recoverable_with_unit_paths(
        context,
        desired,
        &unit_paths,
        &mut event_sink,
        FaultInjection::None,
    )
}

fn validate_current_user(
    context: &IntendedUserSystemdContext,
) -> Result<(), ManagedSystemdConfigurationError> {
    if getuid().as_raw() != context.uid || geteuid().as_raw() != context.uid {
        return Err(ManagedSystemdConfigurationError::IntendedUserMismatch);
    }
    Ok(())
}

fn configure_unit_path_discovery_environment(
    command: &mut Command,
    context: &IntendedUserSystemdContext,
) {
    command
        .env_clear()
        .env("HOME", &context.home_dir)
        .env("XDG_CONFIG_HOME", &context.xdg_config_root)
        .env("LC_ALL", "C")
        .env("LANG", "C");
}

fn discover_user_unit_search_paths(
    context: &IntendedUserSystemdContext,
) -> Result<Vec<PathBuf>, ManagedSystemdConfigurationError> {
    let mut command = Command::new(SYSTEMD_ANALYZE_PATH);
    configure_unit_path_discovery_environment(&mut command, context);
    let output = command
        .arg("--user")
        .arg("unit-paths")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ManagedSystemdConfigurationError::UnitSearchPathDiscovery)?;
    if !output.status.success() {
        return Err(ManagedSystemdConfigurationError::UnitSearchPathDiscovery);
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| ManagedSystemdConfigurationError::UnitSearchPathDiscovery)?;
    let mut paths = Vec::new();
    for line in text.lines() {
        let path = PathBuf::from(line);
        if line.is_empty() || !path.is_absolute() {
            return Err(ManagedSystemdConfigurationError::UnitSearchPathDiscovery);
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(ManagedSystemdConfigurationError::UnitSearchPathDiscovery);
    }
    Ok(paths)
}

struct ManagedDirectory {
    file: File,
    path: PathBuf,
}

fn validate_owned_directory(path: &Path, uid: u32, exact_mode: Option<u32>) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    !metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == uid
        && exact_mode.is_none_or(|mode| metadata.mode() & 0o777 == mode)
}

fn open_managed_directory(
    context: &IntendedUserSystemdContext,
) -> Result<ManagedDirectory, ManagedSystemdConfigurationError> {
    let config_root = context.xdg_config_root();
    let systemd_dir = config_root.join("systemd");
    let user_dir = context.user_unit_directory();
    if !validate_owned_directory(config_root, context.uid, None)
        || !validate_owned_directory(&systemd_dir, context.uid, None)
        || !validate_owned_directory(&user_dir, context.uid, None)
    {
        return Err(ManagedSystemdConfigurationError::ParentDirectoryCustody);
    }

    let user_dir_fd = open(
        &user_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedSystemdConfigurationError::ParentDirectoryCustody)?;

    let managed_path = context.managed_directory();
    let created = match fs::symlink_metadata(&managed_path) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match mkdirat(
                &user_dir_fd,
                MANAGED_DIRECTORY_NAME,
                Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE),
            ) {
                Ok(()) => true,
                Err(Errno::EXIST) => false,
                Err(_) => return Err(ManagedSystemdConfigurationError::ManagedDirectoryCustody),
            }
        }
        Err(_) => return Err(ManagedSystemdConfigurationError::ManagedDirectoryCustody),
    };

    let managed_fd = openat(
        &user_dir_fd,
        MANAGED_DIRECTORY_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedSystemdConfigurationError::ManagedDirectoryCustody)?;
    let file = File::from(managed_fd);
    if created {
        file.set_permissions(Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .map_err(|_| ManagedSystemdConfigurationError::ManagedDirectoryCustody)?;
    }
    let metadata = file
        .metadata()
        .map_err(|_| ManagedSystemdConfigurationError::ManagedDirectoryCustody)?;
    if !metadata.is_dir()
        || metadata.uid() != context.uid
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(ManagedSystemdConfigurationError::ManagedDirectoryCustody);
    }
    flock(&file, FlockOperation::LockExclusive)
        .map_err(|_| ManagedSystemdConfigurationError::WriterLock)?;
    Ok(ManagedDirectory {
        file,
        path: managed_path,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafSnapshot {
    bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
enum LeafKind {
    ExecutionMode,
    ConfiguredRemote,
}

const fn validate_leaf_metadata_values(
    is_file: bool,
    uid: u32,
    expected_uid: u32,
    mode: u32,
) -> bool {
    is_file && uid == expected_uid && mode & 0o777 == MANAGED_LEAF_MODE
}

fn snapshot_leaf(
    directory: &ManagedDirectory,
    name: &str,
    kind: LeafKind,
    uid: u32,
) -> Result<LeafSnapshot, ManagedSystemdConfigurationError> {
    let fd = match openat(
        &directory.file,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(LeafSnapshot { bytes: None }),
        Err(_) => return Err(ManagedSystemdConfigurationError::ManagedLeafCustody),
    };
    let mut file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| ManagedSystemdConfigurationError::ManagedLeafCustody)?;
    if !validate_leaf_metadata_values(metadata.is_file(), metadata.uid(), uid, metadata.mode()) {
        return Err(ManagedSystemdConfigurationError::ManagedLeafCustody);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| ManagedSystemdConfigurationError::ManagedLeafCustody)?;
    let recognized = match kind {
        LeafKind::ExecutionMode => recognize_execution_mode_drop_in(&bytes).map(|_| ()),
        LeafKind::ConfiguredRemote => recognize_configured_remote_drop_in(&bytes).map(|_| ()),
    };
    if recognized.is_err() {
        return Err(ManagedSystemdConfigurationError::ForeignManagedLeaf);
    }
    Ok(LeafSnapshot { bytes: Some(bytes) })
}

fn preflight_external_configuration(
    directory: &ManagedDirectory,
    unit_paths: &[PathBuf],
) -> Result<(), ManagedSystemdConfigurationError> {
    for unit_path in unit_paths {
        let unit = unit_path.join("prw-agent.service");
        match fs::symlink_metadata(&unit) {
            Ok(_) => {
                if external_fragment_conflicts(&unit)? {
                    return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
        }

        let dropin_dir = unit_path.join(MANAGED_DIRECTORY_NAME);
        match fs::symlink_metadata(&dropin_dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
            Ok(_) => {}
        }
        let entries = fs::read_dir(&dropin_dir)
            .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
        for entry in entries {
            let entry = entry
                .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if dropin_dir == directory.path
                && matches!(
                    name.as_ref(),
                    EXECUTION_MODE_DROPIN_NAME | CONFIGURED_REMOTE_INPUTS_DROPIN_NAME
                )
            {
                continue;
            }
            if external_fragment_conflicts(&path)? {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
        }
    }
    Ok(())
}

fn external_fragment_conflicts(path: &Path) -> Result<bool, ManagedSystemdConfigurationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(true);
    }
    let text = fs::read_to_string(path)
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    Ok(fragment_text_conflicts(&text))
}

fn fragment_text_conflicts(text: &str) -> bool {
    const SELECTED: [&str; 7] = [
        PRW_AGENT_EXECUTION_MODE,
        PRW_REMOTE_BIND_ADDR,
        PRW_REMOTE_PEER_DEVICE_ID,
        PRW_REMOTE_MAX_ACTIVE_WORKERS,
        PRW_REMOTE_APPLICATION_LEASE_SECONDS,
        PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
        PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
    ];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.ends_with('\\') {
            return true;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key == "EnvironmentFile" {
            return true;
        }
        if matches!(key, "Environment" | "UnsetEnvironment" | "PassEnvironment")
            && SELECTED.iter().any(|name| value.contains(name))
        {
            return true;
        }
    }
    false
}

struct StagedFile {
    name: String,
}

fn next_temp_name(label: &str) -> String {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        ".prw-agent-configuration.{label}.{}.{}.tmp",
        std::process::id(),
        sequence
    )
}

fn stage_bytes(
    directory: &ManagedDirectory,
    label: &str,
    bytes: &[u8],
    uid: u32,
) -> Result<StagedFile, ManagedSystemdConfigurationError> {
    let name = next_temp_name(label);
    let fd = openat(
        &directory.file,
        name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(MANAGED_LEAF_MODE),
    )
    .map_err(|_| ManagedSystemdConfigurationError::Staging)?;
    let mut file = File::from(fd);
    let stage_result = (|| {
        file.set_permissions(Permissions::from_mode(MANAGED_LEAF_MODE))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !validate_leaf_metadata_values(metadata.is_file(), metadata.uid(), uid, metadata.mode())
        {
            return Err(std::io::Error::other("staged metadata invalid"));
        }
        Ok::<(), std::io::Error>(())
    })();
    drop(file);
    if stage_result.is_err() {
        let _ = unlinkat(&directory.file, name.as_str(), AtFlags::empty());
        return Err(ManagedSystemdConfigurationError::Staging);
    }
    let reopened = openat(
        &directory.file,
        name.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedSystemdConfigurationError::Staging)?;
    let mut reopened = File::from(reopened);
    let mut readback = Vec::new();
    reopened
        .read_to_end(&mut readback)
        .map_err(|_| ManagedSystemdConfigurationError::Staging)?;
    if readback != bytes {
        let _ = unlinkat(&directory.file, name.as_str(), AtFlags::empty());
        return Err(ManagedSystemdConfigurationError::Staging);
    }
    Ok(StagedFile { name })
}

fn cleanup_stage(directory: &ManagedDirectory, staged: Option<&StagedFile>) {
    if let Some(staged) = staged {
        let _ = unlinkat(&directory.file, staged.name.as_str(), AtFlags::empty());
    }
}

fn commit_stage(
    directory: &ManagedDirectory,
    staged: &StagedFile,
    destination: &str,
) -> Result<(), ManagedSystemdConfigurationError> {
    renameat(
        &directory.file,
        staged.name.as_str(),
        &directory.file,
        destination,
    )
    .map_err(|_| ManagedSystemdConfigurationError::Commit)?;
    directory
        .file
        .sync_all()
        .map_err(|_| ManagedSystemdConfigurationError::Commit)
}

fn remove_leaf(
    directory: &ManagedDirectory,
    name: &str,
) -> Result<(), ManagedSystemdConfigurationError> {
    unlinkat(&directory.file, name, AtFlags::empty())
        .map_err(|_| ManagedSystemdConfigurationError::Commit)?;
    directory
        .file
        .sync_all()
        .map_err(|_| ManagedSystemdConfigurationError::Commit)
}

fn verify_desired_state(
    directory: &ManagedDirectory,
    desired: &ManagedAgentConfiguration,
    uid: u32,
) -> Result<(), ManagedSystemdConfigurationError> {
    let mode = snapshot_leaf(
        directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::PostCommitVerification)?;
    let expected_mode = render_execution_mode_drop_in(desired.mode()).as_bytes();
    if mode.bytes.as_deref() != Some(expected_mode) {
        return Err(ManagedSystemdConfigurationError::PostCommitVerification);
    }
    let remote = snapshot_leaf(
        directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::PostCommitVerification)?;
    match desired {
        ManagedAgentConfiguration::LocalOnly => {
            if remote.bytes.is_some() {
                return Err(ManagedSystemdConfigurationError::PostCommitVerification);
            }
        }
        ManagedAgentConfiguration::ConfiguredRemote(bundle) => {
            let expected = render_configured_remote_drop_in(bundle)
                .map_err(ManagedSystemdConfigurationError::Serialization)?;
            if remote.bytes.as_deref() != Some(expected.as_bytes()) {
                return Err(ManagedSystemdConfigurationError::PostCommitVerification);
            }
        }
    }
    Ok(())
}

fn restore_leaf(
    directory: &ManagedDirectory,
    name: &str,
    kind: LeafKind,
    snapshot: &LeafSnapshot,
    uid: u32,
) -> Result<(), ManagedSystemdConfigurationError> {
    let current = snapshot_leaf(directory, name, kind, uid);
    match (&snapshot.bytes, current) {
        (None, Ok(LeafSnapshot { bytes: None })) => Ok(()),
        (None, Ok(_)) => {
            unlinkat(&directory.file, name, AtFlags::empty())
                .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
            directory
                .file
                .sync_all()
                .map_err(|_| ManagedSystemdConfigurationError::Rollback)
        }
        (Some(bytes), Ok(_)) => {
            let staged = stage_bytes(directory, "rollback", bytes, uid)
                .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
            renameat(&directory.file, staged.name.as_str(), &directory.file, name)
                .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
            directory
                .file
                .sync_all()
                .map_err(|_| ManagedSystemdConfigurationError::Rollback)
        }
        (_, Err(_)) => Err(ManagedSystemdConfigurationError::Rollback),
    }
}

fn rollback(
    directory: &ManagedDirectory,
    desired: &ManagedAgentConfiguration,
    before_mode: &LeafSnapshot,
    before_remote: &LeafSnapshot,
    uid: u32,
    fault: FaultInjection,
) -> Result<(), ManagedSystemdConfigurationError> {
    if matches!(fault, FaultInjection::RollbackFailure) {
        return Err(ManagedSystemdConfigurationError::Rollback);
    }
    match desired {
        ManagedAgentConfiguration::ConfiguredRemote(_) => {
            restore_leaf(
                directory,
                EXECUTION_MODE_DROPIN_NAME,
                LeafKind::ExecutionMode,
                before_mode,
                uid,
            )?;
            restore_leaf(
                directory,
                CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
                LeafKind::ConfiguredRemote,
                before_remote,
                uid,
            )?;
        }
        ManagedAgentConfiguration::LocalOnly => {
            restore_leaf(
                directory,
                CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
                LeafKind::ConfiguredRemote,
                before_remote,
                uid,
            )?;
            restore_leaf(
                directory,
                EXECUTION_MODE_DROPIN_NAME,
                LeafKind::ExecutionMode,
                before_mode,
                uid,
            )?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterEvent {
    CommitRemoteInputs,
    CommitExecutionMode,
    RemoveRemoteInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "C03e-TW deterministic fault injection is exercised only by unit tests"
    )
)]
enum FaultInjection {
    None,
    AfterFirstCommit,
    PostCommitVerification,
    RollbackFailure,
}

fn fail_with_rollback(
    directory: &ManagedDirectory,
    desired: &ManagedAgentConfiguration,
    before_mode: &LeafSnapshot,
    before_remote: &LeafSnapshot,
    uid: u32,
    cause: ManagedSystemdConfigurationError,
    fault: FaultInjection,
) -> ManagedSystemdConfigurationError {
    match rollback(directory, desired, before_mode, before_remote, uid, fault) {
        Ok(()) => cause,
        Err(_) => ManagedSystemdConfigurationError::Rollback,
    }
}

fn commit_desired_state(
    directory: &ManagedDirectory,
    desired: &ManagedAgentConfiguration,
    before_remote: &LeafSnapshot,
    mode_stage: &mut Option<StagedFile>,
    remote_stage: &mut Option<StagedFile>,
    event_sink: &mut impl FnMut(WriterEvent),
    fault: FaultInjection,
) -> Result<(), ManagedSystemdConfigurationError> {
    match desired {
        ManagedAgentConfiguration::ConfiguredRemote(_) => {
            let remote = remote_stage.take().expect("configured remote stage exists");
            commit_stage(directory, &remote, CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)?;
            event_sink(WriterEvent::CommitRemoteInputs);
            if matches!(
                fault,
                FaultInjection::AfterFirstCommit | FaultInjection::RollbackFailure
            ) {
                return Err(ManagedSystemdConfigurationError::Commit);
            }
            let mode = mode_stage.take().expect("mode stage exists");
            commit_stage(directory, &mode, EXECUTION_MODE_DROPIN_NAME)?;
            event_sink(WriterEvent::CommitExecutionMode);
        }
        ManagedAgentConfiguration::LocalOnly => {
            let mode = mode_stage.take().expect("mode stage exists");
            commit_stage(directory, &mode, EXECUTION_MODE_DROPIN_NAME)?;
            event_sink(WriterEvent::CommitExecutionMode);
            if matches!(
                fault,
                FaultInjection::AfterFirstCommit | FaultInjection::RollbackFailure
            ) {
                return Err(ManagedSystemdConfigurationError::Commit);
            }
            if before_remote.bytes.is_some() {
                remove_leaf(directory, CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)?;
                event_sink(WriterEvent::RemoveRemoteInputs);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn apply_with_unit_paths(
    context: &IntendedUserSystemdContext,
    desired: &ManagedAgentConfiguration,
    unit_paths: &[PathBuf],
    event_sink: &mut impl FnMut(WriterEvent),
    fault: FaultInjection,
) -> Result<ManagedSystemdWriteResult, ManagedSystemdConfigurationError> {
    apply_recoverable_with_unit_paths(context, desired, unit_paths, event_sink, fault)
        .map(|write| write.result())
}

fn stage_desired_state(
    directory: &ManagedDirectory,
    desired: &ManagedAgentConfiguration,
    uid: u32,
) -> Result<(Option<StagedFile>, Option<StagedFile>), ManagedSystemdConfigurationError> {
    let mode_bytes = render_execution_mode_drop_in(desired.mode()).as_bytes();
    let remote_rendered = match desired {
        ManagedAgentConfiguration::LocalOnly => None,
        ManagedAgentConfiguration::ConfiguredRemote(bundle) => {
            Some(render_configured_remote_drop_in(bundle)?)
        }
    };
    let mode_stage = Some(stage_bytes(directory, "mode", mode_bytes, uid)?);
    let remote_stage = match remote_rendered.as_deref() {
        Some(bytes) => match stage_bytes(directory, "remote", bytes.as_bytes(), uid) {
            Ok(staged) => Some(staged),
            Err(error) => {
                cleanup_stage(directory, mode_stage.as_ref());
                return Err(error);
            }
        },
        None => None,
    };
    Ok((mode_stage, remote_stage))
}

fn snapshot_committed_state_or_rollback(
    directory: &ManagedDirectory,
    context: &IntendedUserSystemdContext,
    desired: &ManagedAgentConfiguration,
    before_mode: &LeafSnapshot,
    before_remote: &LeafSnapshot,
    fault: FaultInjection,
) -> Result<(LeafSnapshot, LeafSnapshot), ManagedSystemdConfigurationError> {
    let Ok(committed_mode) = snapshot_leaf(
        directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        context.uid,
    ) else {
        return Err(fail_with_rollback(
            directory,
            desired,
            before_mode,
            before_remote,
            context.uid,
            ManagedSystemdConfigurationError::PostCommitVerification,
            fault,
        ));
    };
    let Ok(committed_remote) = snapshot_leaf(
        directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        context.uid,
    ) else {
        return Err(fail_with_rollback(
            directory,
            desired,
            before_mode,
            before_remote,
            context.uid,
            ManagedSystemdConfigurationError::PostCommitVerification,
            fault,
        ));
    };
    Ok((committed_mode, committed_remote))
}

fn apply_recoverable_with_unit_paths(
    context: &IntendedUserSystemdContext,
    desired: &ManagedAgentConfiguration,
    unit_paths: &[PathBuf],
    event_sink: &mut impl FnMut(WriterEvent),
    fault: FaultInjection,
) -> Result<RecoverableManagedSystemdWrite, ManagedSystemdConfigurationError> {
    validate_current_user(context)?;
    let directory = open_managed_directory(context)?;
    let before_mode = snapshot_leaf(
        &directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        context.uid,
    )?;
    let before_remote = snapshot_leaf(
        &directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        context.uid,
    )?;
    preflight_external_configuration(&directory, unit_paths)?;

    let (mut mode_stage, mut remote_stage) = stage_desired_state(&directory, desired, context.uid)?;

    let current_mode = snapshot_leaf(
        &directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        context.uid,
    );
    let current_remote = snapshot_leaf(
        &directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        context.uid,
    );
    if current_mode.as_ref().ok() != Some(&before_mode)
        || current_remote.as_ref().ok() != Some(&before_remote)
    {
        cleanup_stage(&directory, mode_stage.as_ref());
        cleanup_stage(&directory, remote_stage.as_ref());
        return Err(ManagedSystemdConfigurationError::ManagedLeafCustody);
    }

    let commit_result = commit_desired_state(
        &directory,
        desired,
        &before_remote,
        &mut mode_stage,
        &mut remote_stage,
        event_sink,
        fault,
    );
    cleanup_stage(&directory, mode_stage.as_ref());
    cleanup_stage(&directory, remote_stage.as_ref());
    if let Err(error) = commit_result {
        return Err(fail_with_rollback(
            &directory,
            desired,
            &before_mode,
            &before_remote,
            context.uid,
            error,
            fault,
        ));
    }

    if matches!(fault, FaultInjection::PostCommitVerification) {
        return Err(fail_with_rollback(
            &directory,
            desired,
            &before_mode,
            &before_remote,
            context.uid,
            ManagedSystemdConfigurationError::PostCommitVerification,
            fault,
        ));
    }
    if let Err(error) = verify_desired_state(&directory, desired, context.uid) {
        return Err(fail_with_rollback(
            &directory,
            desired,
            &before_mode,
            &before_remote,
            context.uid,
            error,
            fault,
        ));
    }

    let (committed_mode, committed_remote) = snapshot_committed_state_or_rollback(
        &directory,
        context,
        desired,
        &before_mode,
        &before_remote,
        fault,
    )?;
    let result = ManagedSystemdWriteResult {
        mode: desired.mode(),
    };
    Ok(RecoverableManagedSystemdWrite {
        result,
        recovery: RecoverableManagedSystemdTransaction {
            before_mode,
            before_remote,
            committed_mode,
            committed_remote,
            committed_execution_mode: desired.mode(),
        },
    })
}

/// Restores the exact pretransaction managed-file state from one opaque recovery token.
///
/// The token is consumed by value. Restore first reopens both managed leaves through the same
/// directory-FD/NOFOLLOW custody and refuses to proceed unless their exact state still equals the
/// token's verified committed state. No service-manager operation is performed.
///
/// # Errors
///
/// Fails closed on user/custody mismatch, post-write drift, unsafe metadata, foreign content or any
/// staging/durability/restore failure.
pub fn restore_recoverable_managed_systemd_configuration(
    context: &IntendedUserSystemdContext,
    recovery: RecoverableManagedSystemdTransaction,
) -> Result<(), ManagedSystemdConfigurationError> {
    let RecoverableManagedSystemdTransaction {
        before_mode,
        before_remote,
        committed_mode,
        committed_remote,
        committed_execution_mode,
    } = recovery;
    validate_current_user(context)?;
    let directory = open_managed_directory(context)?;
    let current_mode = snapshot_leaf(
        &directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        context.uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
    let current_remote = snapshot_leaf(
        &directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        context.uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
    if current_mode != committed_mode || current_remote != committed_remote {
        return Err(ManagedSystemdConfigurationError::Rollback);
    }

    match committed_execution_mode {
        AgentExecutionMode::ConfiguredRemote => {
            restore_leaf(
                &directory,
                EXECUTION_MODE_DROPIN_NAME,
                LeafKind::ExecutionMode,
                &before_mode,
                context.uid,
            )?;
            restore_leaf(
                &directory,
                CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
                LeafKind::ConfiguredRemote,
                &before_remote,
                context.uid,
            )?;
        }
        AgentExecutionMode::LocalOnly => {
            restore_leaf(
                &directory,
                CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
                LeafKind::ConfiguredRemote,
                &before_remote,
                context.uid,
            )?;
            restore_leaf(
                &directory,
                EXECUTION_MODE_DROPIN_NAME,
                LeafKind::ExecutionMode,
                &before_mode,
                context.uid,
            )?;
        }
    }
    let restored_mode = snapshot_leaf(
        &directory,
        EXECUTION_MODE_DROPIN_NAME,
        LeafKind::ExecutionMode,
        context.uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
    let restored_remote = snapshot_leaf(
        &directory,
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME,
        LeafKind::ConfiguredRemote,
        context.uid,
    )
    .map_err(|_| ManagedSystemdConfigurationError::Rollback)?;
    if restored_mode != before_mode || restored_remote != before_remote {
        return Err(ManagedSystemdConfigurationError::Rollback);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        rc::Rc,
    };

    use rustix::process::getuid;

    use super::*;

    struct Sandbox {
        root: PathBuf,
        context: IntendedUserSystemdContext,
        user_unit: PathBuf,
        managed: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "prw-agent-configuration-test-{}-{sequence}",
                std::process::id()
            ));
            let config = root.join("config");
            let user_unit = config.join("systemd/user");
            fs::create_dir_all(&user_unit).expect("test user unit directory");
            for path in [&root, &config, &config.join("systemd"), &user_unit] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("test directory mode");
            }
            let uid = getuid().as_raw();
            let context = IntendedUserSystemdContext::new(uid, root.clone(), config)
                .expect("absolute intended-user context");
            let managed = user_unit.join(MANAGED_DIRECTORY_NAME);
            Self {
                root,
                context,
                user_unit,
                managed,
            }
        }

        fn unit_paths(&self) -> Vec<PathBuf> {
            vec![self.user_unit.clone()]
        }

        fn ensure_managed(&self) {
            fs::create_dir_all(&self.managed).expect("managed test directory");
            fs::set_permissions(&self.managed, fs::Permissions::from_mode(0o700))
                .expect("managed directory mode");
        }

        fn write_managed(&self, name: &str, bytes: &[u8]) {
            self.ensure_managed();
            let path = self.managed.join(name);
            fs::write(&path, bytes).expect("managed test file");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("managed leaf mode");
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn bundle(peer: &str) -> ConfiguredRemoteBundle {
        ConfiguredRemoteBundle::try_new("127.0.0.1:0", peer, "0002", "003600", "0007", "0009")
            .expect("valid test bundle")
    }

    fn apply_test(
        sandbox: &Sandbox,
        desired: &ManagedAgentConfiguration,
        fault: FaultInjection,
    ) -> (
        Result<ManagedSystemdWriteResult, ManagedSystemdConfigurationError>,
        Vec<WriterEvent>,
    ) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let sink_events = Rc::clone(&events);
        let mut sink = move |event| sink_events.borrow_mut().push(event);
        let result = apply_with_unit_paths(
            &sandbox.context,
            desired,
            &sandbox.unit_paths(),
            &mut sink,
            fault,
        );
        let captured = events.borrow().clone();
        (result, captured)
    }

    #[test]
    fn configured_remote_commits_complete_40_before_configured_30() {
        let sandbox = Sandbox::new();
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-1")));
        let (result, events) = apply_test(&sandbox, &desired, FaultInjection::None);
        assert_eq!(
            result.expect("configured transaction").mode(),
            AgentExecutionMode::ConfiguredRemote
        );
        assert_eq!(
            events,
            [
                WriterEvent::CommitRemoteInputs,
                WriterEvent::CommitExecutionMode
            ]
        );
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("mode bytes"),
            render_execution_mode_drop_in(AgentExecutionMode::ConfiguredRemote).as_bytes()
        );
        let expected_remote = render_configured_remote_drop_in(&bundle("peer-1")).expect("render");
        assert_eq!(
            fs::read(sandbox.managed.join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME))
                .expect("remote bytes"),
            expected_remote.as_bytes()
        );
    }

    #[test]
    fn local_only_commits_30_before_recognized_40_removal() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::ConfiguredRemote).as_bytes(),
        );
        let remote = render_configured_remote_drop_in(&bundle("peer-2")).expect("render");
        sandbox.write_managed(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME, remote.as_bytes());
        let (result, events) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::LocalOnly,
            FaultInjection::None,
        );
        assert_eq!(
            result.expect("local transaction").mode(),
            AgentExecutionMode::LocalOnly
        );
        assert_eq!(
            events,
            [
                WriterEvent::CommitExecutionMode,
                WriterEvent::RemoveRemoteInputs
            ]
        );
        assert!(
            !sandbox
                .managed
                .join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                .exists()
        );
    }

    #[test]
    fn external_conflict_fails_before_managed_leaf_mutation() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        fs::write(
            sandbox.managed.join("50-external.conf"),
            "[Service]\nEnvironment=PRW_REMOTE_BIND_ADDR=127.0.0.1:9\n",
        )
        .expect("external conflict");
        let before = fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("before");
        let (result, events) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-3"))),
            FaultInjection::None,
        );
        assert_eq!(
            result,
            Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict)
        );
        assert!(events.is_empty());
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("after"),
            before
        );
        assert!(
            !sandbox
                .managed
                .join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                .exists()
        );
    }

    #[test]
    fn foreign_symlink_nonregular_and_wrong_mode_managed_leaves_fail_closed() {
        let sandbox = Sandbox::new();
        sandbox.ensure_managed();
        let target = sandbox.root.join("outside");
        fs::write(&target, "outside").expect("outside file");
        symlink(&target, sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("symlink");
        let (symlink_result, _) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::LocalOnly,
            FaultInjection::None,
        );
        assert_eq!(
            symlink_result,
            Err(ManagedSystemdConfigurationError::ManagedLeafCustody)
        );
        fs::remove_file(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("remove symlink");
        fs::create_dir(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("directory leaf");
        let (directory_result, _) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::LocalOnly,
            FaultInjection::None,
        );
        assert_eq!(
            directory_result,
            Err(ManagedSystemdConfigurationError::ManagedLeafCustody)
        );
        fs::remove_dir(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("remove directory");
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        fs::set_permissions(
            sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .expect("wrong mode");
        let (mode_result, _) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::LocalOnly,
            FaultInjection::None,
        );
        assert_eq!(
            mode_result,
            Err(ManagedSystemdConfigurationError::ManagedLeafCustody)
        );
        assert!(!validate_leaf_metadata_values(
            true,
            sandbox.context.uid + 1,
            sandbox.context.uid,
            0o600
        ));
    }

    #[test]
    fn foreign_canonical_shape_mismatch_is_not_taken_over() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            b"[Service]\nEnvironment=PRW_AGENT_EXECUTION_MODE=LOCAL_ONLY\n",
        );
        let (result, _) = apply_test(
            &sandbox,
            &ManagedAgentConfiguration::LocalOnly,
            FaultInjection::None,
        );
        assert_eq!(
            result,
            Err(ManagedSystemdConfigurationError::ForeignManagedLeaf)
        );
    }

    #[test]
    fn injected_second_step_failure_restores_exact_prestate() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let before_mode =
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("before");
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-4")));
        let (result, events) = apply_test(&sandbox, &desired, FaultInjection::AfterFirstCommit);
        assert_eq!(result, Err(ManagedSystemdConfigurationError::Commit));
        assert_eq!(events, [WriterEvent::CommitRemoteInputs]);
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("mode restored"),
            before_mode
        );
        assert!(
            !sandbox
                .managed
                .join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                .exists()
        );
    }

    #[test]
    fn postcommit_verification_failure_rolls_back_both_managed_leaves() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let before = fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("before");
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-5")));
        let (result, _) = apply_test(&sandbox, &desired, FaultInjection::PostCommitVerification);
        assert_eq!(
            result,
            Err(ManagedSystemdConfigurationError::PostCommitVerification)
        );
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("restored mode"),
            before
        );
        assert!(
            !sandbox
                .managed
                .join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                .exists()
        );
    }

    #[test]
    fn rollback_failure_has_distinct_bounded_classification() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-6")));
        let (result, events) = apply_test(&sandbox, &desired, FaultInjection::RollbackFailure);
        assert_eq!(result, Err(ManagedSystemdConfigurationError::Rollback));
        assert_eq!(events, [WriterEvent::CommitRemoteInputs]);
    }

    #[test]
    fn serialization_failure_occurs_before_any_temp_or_managed_leaf_stage() {
        let sandbox = Sandbox::new();
        let desired =
            ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer\ncontrol")));
        let (result, events) = apply_test(&sandbox, &desired, FaultInjection::None);
        assert_eq!(
            result,
            Err(ManagedSystemdConfigurationError::Serialization(
                SystemdSerializationError::NonPrintableValue
            ))
        );
        assert!(events.is_empty());
        let entries = fs::read_dir(&sandbox.managed)
            .expect("managed directory exists after custody validation")
            .collect::<Result<Vec<_>, _>>()
            .expect("managed directory readable");
        assert!(entries.is_empty());
    }

    #[test]
    fn non_directory_external_unit_path_fails_closed() {
        let sandbox = Sandbox::new();
        let invalid_unit_path = sandbox.root.join("not-a-directory");
        fs::write(&invalid_unit_path, "not a unit search directory").expect("test file");
        let mut events = Vec::new();
        let result = apply_with_unit_paths(
            &sandbox.context,
            &ManagedAgentConfiguration::LocalOnly,
            &[invalid_unit_path],
            &mut |event| events.push(event),
            FaultInjection::None,
        );
        assert_eq!(
            result,
            Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict)
        );
        assert!(events.is_empty());
    }

    #[test]
    fn fragment_preflight_rejects_selected_custody_and_ambiguous_environment_file() {
        assert!(fragment_text_conflicts(
            "[Service]\nEnvironment=PRW_AGENT_EXECUTION_MODE=local_only\n"
        ));
        assert!(fragment_text_conflicts(
            "[Service]\nUnsetEnvironment=PRW_REMOTE_BIND_ADDR\n"
        ));
        assert!(fragment_text_conflicts(
            "[Service]\nPassEnvironment=PRW_REMOTE_PEER_DEVICE_ID\n"
        ));
        assert!(fragment_text_conflicts(
            "[Service]\nEnvironmentFile=-/etc/prw/environment\n"
        ));
        assert!(fragment_text_conflicts(
            "[Service]\nEnvironmentFile = -/etc/prw/environment\n"
        ));
        assert!(fragment_text_conflicts(
            "[Service]\nEnvironment=UNRELATED=value \\\n PRW_AGENT_EXECUTION_MODE=configured_remote\n"
        ));
        assert!(!fragment_text_conflicts(
            "[Service]\nEnvironment=UNRELATED=value\nLoadCredentialEncrypted=identity:/path\n"
        ));
    }

    #[test]
    fn unit_path_discovery_child_environment_is_explicit_and_cleared() {
        let sandbox = Sandbox::new();
        let mut command = Command::new("/usr/bin/env");
        command.env("SYSTEMD_UNIT_PATH", "/tmp/prw-ty-poison").env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/tmp/prw-ty-poison-bus",
        );
        configure_unit_path_discovery_environment(&mut command, &sandbox.context);
        let output = command.output().expect("sanitized env child runs");
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).expect("env output utf8");
        let mut lines = text.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        let mut expected = vec![
            format!("HOME={}", sandbox.context.home_dir().display()),
            format!(
                "XDG_CONFIG_HOME={}",
                sandbox.context.xdg_config_root().display()
            ),
            "LANG=C".to_owned(),
            "LC_ALL=C".to_owned(),
        ];
        expected.sort_unstable();
        assert_eq!(lines, expected);
        assert!(!text.contains("SYSTEMD_UNIT_PATH="));
        assert!(!text.contains("DBUS_SESSION_BUS_ADDRESS="));
    }

    #[test]
    fn recoverable_token_restores_exact_prior_managed_state() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let before_mode =
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("before mode");
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-token")));
        let mut events = Vec::new();
        let write = apply_recoverable_with_unit_paths(
            &sandbox.context,
            &desired,
            &sandbox.unit_paths(),
            &mut |event| events.push(event),
            FaultInjection::None,
        )
        .expect("recoverable write");
        assert_eq!(write.result().mode(), AgentExecutionMode::ConfiguredRemote);
        assert_eq!(
            events,
            [
                WriterEvent::CommitRemoteInputs,
                WriterEvent::CommitExecutionMode
            ]
        );
        let (_, recovery) = write.into_parts();
        restore_recoverable_managed_systemd_configuration(&sandbox.context, recovery)
            .expect("exact restore");
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("restored mode"),
            before_mode
        );
        assert!(
            !sandbox
                .managed
                .join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                .exists()
        );
    }

    #[test]
    fn recoverable_restore_refuses_postcommit_drift_without_takeover() {
        let sandbox = Sandbox::new();
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let desired = ManagedAgentConfiguration::ConfiguredRemote(Box::new(bundle("peer-drift")));
        let write = apply_recoverable_with_unit_paths(
            &sandbox.context,
            &desired,
            &sandbox.unit_paths(),
            &mut |_| {},
            FaultInjection::None,
        )
        .expect("recoverable write");
        sandbox.write_managed(
            EXECUTION_MODE_DROPIN_NAME,
            render_execution_mode_drop_in(AgentExecutionMode::LocalOnly).as_bytes(),
        );
        let drifted =
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("drifted mode");
        let (_, recovery) = write.into_parts();
        assert_eq!(
            restore_recoverable_managed_systemd_configuration(&sandbox.context, recovery),
            Err(ManagedSystemdConfigurationError::Rollback)
        );
        assert_eq!(
            fs::read(sandbox.managed.join(EXECUTION_MODE_DROPIN_NAME)).expect("still drifted"),
            drifted
        );
    }

    #[test]
    fn context_rejects_relative_roots() {
        assert_eq!(
            IntendedUserSystemdContext::new(1, PathBuf::from("relative"), PathBuf::from("/abs")),
            Err(IntendedUserSystemdContextError)
        );
    }

    #[test]
    fn systemd_recognition_error_remains_separate_from_writer_error_surface() {
        let error = recognize_execution_mode_drop_in(b"not-canonical").expect_err("not canonical");
        assert_eq!(error, crate::SystemdRecognitionError::NonCanonical);
    }
}

const EXTERNAL_FRAGMENT_MAX_FILES: usize = 128;
const EXTERNAL_FRAGMENT_MAX_FILE_BYTES: u64 = 1_048_576;
const EXTERNAL_FRAGMENT_MAX_TOTAL_BYTES: u64 = 8_388_608;
const EXTERNAL_AGENT_UNIT_NAME: &str = "prw-agent.service";

/// Opaque in-process snapshot of external systemd fragment identity and exact bytes.
///
/// The token intentionally exposes no paths, metadata fingerprints, or bytes through `Debug` or
/// serialization. It is valid only for one administrative transaction and is never persisted.
#[derive(PartialEq, Eq)]
pub struct ExternalSystemdFragmentCustody {
    unit_paths: Vec<PathBuf>,
    fragments: Vec<ExternalFragmentSnapshot>,
}

impl fmt::Debug for ExternalSystemdFragmentCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalSystemdFragmentCustody")
            .field("fragment_count", &self.fragments.len())
            .finish_non_exhaustive()
    }
}

#[derive(PartialEq, Eq)]
struct ExternalFragmentSnapshot {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
    bytes: Vec<u8>,
}

/// Captures exact read-only custody of all external fragments that can affect `prw-agent.service`.
///
/// The ordered sanitized user-unit search path is part of the token. Main unit candidates and every
/// direct non-managed target drop-in are captured with final-component `O_NOFOLLOW`, regular-file
/// proof, exact selected metadata identity, and exact bytes. Only the exact managed 30/40 leaves in
/// the intended managed directory are excluded.
///
/// # Errors
///
/// Fails closed on intended-user mismatch, unit-path discovery failure, unsafe fragment shape,
/// external selected-variable conflict, unstable capture, or the selected file/byte ceilings.
pub fn capture_external_systemd_fragment_custody(
    context: &IntendedUserSystemdContext,
) -> Result<ExternalSystemdFragmentCustody, ManagedSystemdConfigurationError> {
    validate_current_user(context)?;
    let unit_paths = discover_user_unit_search_paths(context)?;
    capture_external_systemd_fragment_custody_with_unit_paths(context, &unit_paths)
}

/// Re-proves one original external-fragment custody token without refreshing its baseline.
///
/// # Errors
///
/// Returns a bounded custody error when the ordered search paths, candidate inventory, file shape,
/// selected metadata identity, or exact bytes differ from the original snapshot.
pub fn reprove_external_systemd_fragment_custody(
    context: &IntendedUserSystemdContext,
    custody: &ExternalSystemdFragmentCustody,
) -> Result<(), ManagedSystemdConfigurationError> {
    validate_current_user(context)?;
    let unit_paths = discover_user_unit_search_paths(context)?;
    reprove_external_systemd_fragment_custody_with_unit_paths(context, custody, &unit_paths)
}

fn reprove_external_systemd_fragment_custody_with_unit_paths(
    context: &IntendedUserSystemdContext,
    custody: &ExternalSystemdFragmentCustody,
    unit_paths: &[PathBuf],
) -> Result<(), ManagedSystemdConfigurationError> {
    let current = capture_external_systemd_fragment_custody_with_unit_paths(context, unit_paths)?;
    if current == *custody {
        Ok(())
    } else {
        Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict)
    }
}

fn capture_external_systemd_fragment_custody_with_unit_paths(
    context: &IntendedUserSystemdContext,
    unit_paths: &[PathBuf],
) -> Result<ExternalSystemdFragmentCustody, ManagedSystemdConfigurationError> {
    if unit_paths.is_empty() {
        return Err(ManagedSystemdConfigurationError::UnitSearchPathDiscovery);
    }
    let mut seen_unit_paths = std::collections::BTreeSet::new();
    for path in unit_paths {
        if !path.is_absolute() || !seen_unit_paths.insert(path.clone()) {
            return Err(ManagedSystemdConfigurationError::UnitSearchPathDiscovery);
        }
    }

    let managed_directory = context.managed_directory();
    let mut candidates = Vec::new();
    for unit_path in unit_paths {
        let main_unit = unit_path.join(EXTERNAL_AGENT_UNIT_NAME);
        match fs::symlink_metadata(&main_unit) {
            Ok(_) => candidates.push(main_unit),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
        }

        let drop_in_directory = unit_path.join(MANAGED_DIRECTORY_NAME);
        match fs::symlink_metadata(&drop_in_directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
            }
            Ok(_) => {}
        }
        let entries = fs::read_dir(&drop_in_directory)
            .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
        let mut entry_paths = entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)
            })
            .collect::<Result<Vec<_>, _>>()?;
        entry_paths.sort();
        for path in entry_paths {
            let excluded_managed_leaf = drop_in_directory == managed_directory
                && matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some(EXECUTION_MODE_DROPIN_NAME | CONFIGURED_REMOTE_INPUTS_DROPIN_NAME)
                );
            if !excluded_managed_leaf {
                candidates.push(path);
            }
        }
    }

    if candidates.len() > EXTERNAL_FRAGMENT_MAX_FILES {
        return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
    }
    let mut total_bytes = 0_u64;
    let mut fragments = Vec::with_capacity(candidates.len());
    for path in candidates {
        let snapshot = capture_external_fragment(&path)?;
        total_bytes = total_bytes
            .checked_add(snapshot.length)
            .ok_or(ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
        if total_bytes > EXTERNAL_FRAGMENT_MAX_TOTAL_BYTES {
            return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
        }
        fragments.push(snapshot);
    }
    Ok(ExternalSystemdFragmentCustody {
        unit_paths: unit_paths.to_vec(),
        fragments,
    })
}

fn external_metadata_identity_matches(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn capture_external_fragment(
    path: &Path,
) -> Result<ExternalFragmentSnapshot, ManagedSystemdConfigurationError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    let mut file = File::from(fd);
    let before = file
        .metadata()
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    if !before.is_file() || before.len() > EXTERNAL_FRAGMENT_MAX_FILE_BYTES {
        return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
    }

    let capacity = usize::try_from(before.len())
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(EXTERNAL_FRAGMENT_MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    if bytes.len() as u64 > EXTERNAL_FRAGMENT_MAX_FILE_BYTES {
        return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
    }
    let after = file
        .metadata()
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    if path_after.file_type().is_symlink()
        || !external_metadata_identity_matches(&before, &after)
        || !external_metadata_identity_matches(&after, &path_after)
        || bytes.len() as u64 != after.len()
    {
        return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ManagedSystemdConfigurationError::ExternalConfigurationConflict)?;
    if fragment_text_conflicts(text) {
        return Err(ManagedSystemdConfigurationError::ExternalConfigurationConflict);
    }
    Ok(ExternalFragmentSnapshot {
        path: path.to_path_buf(),
        device: after.dev(),
        inode: after.ino(),
        mode: after.mode(),
        uid: after.uid(),
        gid: after.gid(),
        length: after.len(),
        mtime_seconds: after.mtime(),
        mtime_nanoseconds: after.mtime_nsec(),
        ctime_seconds: after.ctime(),
        ctime_nanoseconds: after.ctime_nsec(),
        bytes,
    })
}

#[cfg(test)]
mod external_custody_tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

    use rustix::process::getuid;

    use super::*;

    struct CustodySandbox {
        root: PathBuf,
        context: IntendedUserSystemdContext,
        user_unit: PathBuf,
        drop_ins: PathBuf,
    }

    impl CustodySandbox {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "prw-agent-external-custody-test-{}-{sequence}",
                std::process::id()
            ));
            let config = root.join("config");
            let user_unit = config.join("systemd/user");
            let drop_ins = user_unit.join(MANAGED_DIRECTORY_NAME);
            fs::create_dir_all(&drop_ins).expect("external custody test directories");
            for path in [
                &root,
                &config,
                &config.join("systemd"),
                &user_unit,
                &drop_ins,
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("external custody test directory mode");
            }
            let context = IntendedUserSystemdContext::new(getuid().as_raw(), root.clone(), config)
                .expect("absolute context");
            Self {
                root,
                context,
                user_unit,
                drop_ins,
            }
        }

        fn unit_paths(&self) -> Vec<PathBuf> {
            vec![self.user_unit.clone()]
        }

        fn write_file(path: &Path, bytes: &[u8], mode: u32) {
            fs::write(path, bytes).expect("write external fragment");
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .expect("external fragment mode");
        }
    }

    impl Drop for CustodySandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn harmless_fragment(label: &str) -> String {
        format!("[Unit]\nDescription={label}\n")
    }

    #[test]
    fn custody_inventory_includes_main_and_nonmanaged_dropins_only() {
        let sandbox = CustodySandbox::new();
        let main = sandbox.user_unit.join(EXTERNAL_AGENT_UNIT_NAME);
        let identity = sandbox.drop_ins.join(DEVICE_IDENTITY_DROPIN_NAME);
        let external = sandbox.drop_ins.join("50-external.conf");
        let managed_mode = sandbox.drop_ins.join(EXECUTION_MODE_DROPIN_NAME);
        let managed_remote = sandbox.drop_ins.join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME);
        CustodySandbox::write_file(&main, harmless_fragment("main").as_bytes(), 0o644);
        CustodySandbox::write_file(&identity, harmless_fragment("identity").as_bytes(), 0o600);
        CustodySandbox::write_file(&external, harmless_fragment("external").as_bytes(), 0o600);
        CustodySandbox::write_file(&managed_mode, b"excluded mode", 0o600);
        CustodySandbox::write_file(&managed_remote, b"excluded remote", 0o600);
        let before_identity = fs::read(&identity).expect("identity bytes before capture");

        let custody = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("capture external custody");
        let paths = custody
            .fragments
            .iter()
            .map(|fragment| fragment.path.as_path())
            .collect::<Vec<_>>();
        assert!(paths.contains(&main.as_path()));
        assert!(paths.contains(&identity.as_path()));
        assert!(paths.contains(&external.as_path()));
        assert!(!paths.contains(&managed_mode.as_path()));
        assert!(!paths.contains(&managed_remote.as_path()));
        reprove_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &custody,
            &sandbox.unit_paths(),
        )
        .expect("unchanged custody reproves");
        assert_eq!(
            fs::read(&identity).expect("identity bytes after reproof"),
            before_identity
        );
        let debug = format!("{custody:?}");
        assert!(!debug.contains("identity"));
        assert!(!debug.contains("50-external"));
        assert!(!debug.contains("Description="));
    }

    #[test]
    fn reproof_detects_same_path_bytes_inode_and_metadata_drift() {
        let sandbox = CustodySandbox::new();
        let path = sandbox.drop_ins.join("50-external.conf");
        let original = harmless_fragment("original");
        CustodySandbox::write_file(&path, original.as_bytes(), 0o600);

        let bytes_baseline = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("bytes baseline");
        CustodySandbox::write_file(&path, harmless_fragment("changed").as_bytes(), 0o600);
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &bytes_baseline,
                &sandbox.unit_paths(),
            )
            .is_err()
        );

        CustodySandbox::write_file(&path, original.as_bytes(), 0o600);
        let inode_baseline = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("inode baseline");
        let replacement = sandbox.drop_ins.join("replacement.tmp");
        CustodySandbox::write_file(&replacement, original.as_bytes(), 0o600);
        fs::rename(&replacement, &path).expect("replace same-path inode");
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &inode_baseline,
                &sandbox.unit_paths(),
            )
            .is_err()
        );

        let metadata_baseline = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("metadata baseline");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode drift");
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &metadata_baseline,
                &sandbox.unit_paths(),
            )
            .is_err()
        );
    }

    #[test]
    fn reproof_detects_inventory_and_search_path_sequence_drift() {
        let sandbox = CustodySandbox::new();
        let first = sandbox.drop_ins.join("50-first.conf");
        CustodySandbox::write_file(&first, harmless_fragment("first").as_bytes(), 0o600);
        let baseline = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("inventory baseline");
        let added = sandbox.drop_ins.join("60-added.conf");
        CustodySandbox::write_file(&added, harmless_fragment("added").as_bytes(), 0o600);
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &baseline,
                &sandbox.unit_paths(),
            )
            .is_err()
        );

        let added_baseline = capture_external_systemd_fragment_custody_with_unit_paths(
            &sandbox.context,
            &sandbox.unit_paths(),
        )
        .expect("added baseline");
        fs::remove_file(&added).expect("remove external candidate");
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &added_baseline,
                &sandbox.unit_paths(),
            )
            .is_err()
        );

        let second_unit_path = sandbox.root.join("second-unit-path");
        fs::create_dir_all(&second_unit_path).expect("second unit path");
        let ordered = vec![sandbox.user_unit.clone(), second_unit_path.clone()];
        let order_baseline =
            capture_external_systemd_fragment_custody_with_unit_paths(&sandbox.context, &ordered)
                .expect("ordered search path baseline");
        assert!(
            reprove_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &order_baseline,
                &[second_unit_path, sandbox.user_unit.clone()],
            )
            .is_err()
        );
    }

    #[test]
    fn symlink_and_nonregular_external_candidates_fail_closed() {
        let sandbox = CustodySandbox::new();
        let target = sandbox.root.join("outside.conf");
        CustodySandbox::write_file(&target, harmless_fragment("outside").as_bytes(), 0o600);
        let symlink_path = sandbox.drop_ins.join("50-link.conf");
        symlink(&target, &symlink_path).expect("external symlink");
        assert!(
            capture_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &sandbox.unit_paths(),
            )
            .is_err()
        );
        fs::remove_file(&symlink_path).expect("remove symlink");
        fs::create_dir(sandbox.drop_ins.join("50-directory.conf")).expect("nonregular candidate");
        assert!(
            capture_external_systemd_fragment_custody_with_unit_paths(
                &sandbox.context,
                &sandbox.unit_paths(),
            )
            .is_err()
        );
    }

    #[test]
    fn configured_external_custody_bounds_fail_closed() {
        let per_file = CustodySandbox::new();
        let large = per_file.drop_ins.join("50-large.conf");
        let per_file_limit = usize::try_from(EXTERNAL_FRAGMENT_MAX_FILE_BYTES)
            .expect("external fragment per-file limit fits usize");
        let oversized = vec![b'x'; per_file_limit + 1];
        CustodySandbox::write_file(&large, &oversized, 0o600);
        assert!(
            capture_external_systemd_fragment_custody_with_unit_paths(
                &per_file.context,
                &per_file.unit_paths(),
            )
            .is_err()
        );

        let count = CustodySandbox::new();
        for index in 0..=EXTERNAL_FRAGMENT_MAX_FILES {
            let path = count.drop_ins.join(format!("{index:03}-count.conf"));
            CustodySandbox::write_file(&path, harmless_fragment("count").as_bytes(), 0o600);
        }
        assert!(
            capture_external_systemd_fragment_custody_with_unit_paths(
                &count.context,
                &count.unit_paths(),
            )
            .is_err()
        );

        let total = CustodySandbox::new();
        let one_megabyte = vec![b'x'; per_file_limit];
        for index in 0..9 {
            let path = total.drop_ins.join(format!("{index:02}-total.conf"));
            CustodySandbox::write_file(&path, &one_megabyte, 0o600);
        }
        assert!(
            capture_external_systemd_fragment_custody_with_unit_paths(
                &total.context,
                &total.unit_paths(),
            )
            .is_err()
        );
    }
}
