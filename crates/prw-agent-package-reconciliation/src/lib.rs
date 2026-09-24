//! Fixed-purpose Linux package reconciliation for the PRW Agent executable.
//!
//! This crate owns exactly one privileged package-file operation; C03e-WD retargets its fixed production identities:
//! replacing the known prior PRW Agent executable with the exact current candidate while the
//! vendor unit is verification-only. It deliberately exposes no arbitrary destination, shell,
//! service-manager, identity, managed-drop-in, enablement, or linger authority.

#![cfg(target_os = "linux")]

use std::{
    env,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

#[cfg(test)]
use std::io::Write;

use aws_lc_rs::digest::{Context, SHA256};
use rustix::{
    fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, open, openat, openat2,
        renameat_with, unlinkat,
    },
    process::{geteuid, getuid},
};

/// The sole semantic operation accepted by the administrative binary.
pub const RECONCILE_CURRENT_AGENT_ACTION: &str = "reconcile-current-agent";
/// Fixed production Agent destination.
pub const AGENT_DESTINATION: &str = "/usr/lib/private-remote-workspace/prw-agent";
/// Fixed production vendor-unit destination. It is verification-only.
pub const VENDOR_UNIT_DESTINATION: &str = "/usr/lib/systemd/user/prw-agent.service";
/// Fixed candidate filename beneath the caller-supplied stage directory.
pub const CANDIDATE_FILE_NAME: &str = "candidate-prw-agent";
/// Fixed manifest filename beneath the caller-supplied stage directory.
pub const MANIFEST_FILE_NAME: &str = "C03E_WD_DEPLOYMENT_MANIFEST";
/// Exact installed prior PRW-managed Agent hash selected by C03e-WD.
pub const OLD_AGENT_SHA256: &str =
    "9db768c1536868662150d9a4de321499fa61813f29fda5bc27cde4a50d61fec7";
/// Exact WA Agent candidate hash selected by C03e-WC and bound by C03e-WD.
pub const NEW_AGENT_SHA256: &str =
    "6a229c76a6b9cc05a413486dfc5e1c2fb920c2890503fe8091bae91a1cd10c44";
/// Exact verify-only vendor-unit hash re-proved for C03e-WD.
pub const VENDOR_UNIT_SHA256: &str =
    "24f646dc96777542904cd824f1678e6c32256b64911d4a031c0315d198c0a909";
/// Exact installed prior Agent length observed and selected by C03e-WD.
pub const OLD_AGENT_BYTES: u64 = 11_068_384;
/// Exact WA candidate length selected by C03e-WC and bound by C03e-WD.
pub const NEW_AGENT_BYTES: u64 = 11_089_904;
/// Exact source head from which the current candidate was built.
pub const CANDIDATE_SOURCE_HEAD: &str = "fe24713c4a72e7e3ad6048f19df5352b8668f552";
/// Exact source tree from which the current candidate was built.
pub const CANDIDATE_SOURCE_TREE: &str = "bcd8ee5d8f1d3e67b68217e77e341c98be5e9e5f";
/// Exact Cargo.lock hash bound by C03e-WC.
pub const CANDIDATE_CARGO_LOCK_SHA256: &str =
    "2258f178ab0076cc2899c50074503f7936491af566aa8ec2d35a2c247f4e5ac7";
/// Canonical absolute Cargo target path required by the WC path-bound provenance law.
pub const CANDIDATE_CANONICAL_TARGET: &str = "/tmp/prw-c03e-wc-canonical-target";

const AGENT_PARENT: &str = "/usr/lib/private-remote-workspace";
const AGENT_FILE: &str = "prw-agent";
const UNIT_PARENT: &str = "/usr/lib/systemd/user";
const UNIT_FILE: &str = "prw-agent.service";
const PACKAGE_DIRECTORY_MODE: u32 = 0o755;
const AGENT_MODE: u32 = 0o755;
const UNIT_MODE: u32 = 0o644;
const STAGE_MODE: u32 = 0o700;
const MANIFEST_MODE: u32 = 0o600;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4096;

/// Bounded, path/content-free terminal classifications for package reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconciliationError {
    /// CLI shape or stage locator is outside the selected invocation surface.
    InvalidInvocation,
    /// The privileged transaction was not entered with the selected root real/effective UID.
    RootRequired,
    /// Authenticated sudo invoking-user identity was absent, malformed, or prohibited.
    InvokingUserIdentityInvalid,
    /// Stage directory custody did not satisfy the selected no-symlink/private-user law.
    StageCustodyInvalid,
    /// Candidate metadata, length, or exact selected hash did not match.
    CandidateInvalid,
    /// Frozen deployment manifest was absent, unsafe, oversized, or not exact.
    ManifestInvalid,
    /// Fixed package parent failed root-owned directory custody.
    PackageParentInvalid,
    /// Fixed installed Agent failed exact prior-PRW identity custody.
    InstalledAgentInvalid,
    /// Verification-only vendor unit failed exact identity custody.
    VendorUnitInvalid,
    /// Root-owned same-filesystem staging failed before exchange.
    RootStagingFailed,
    /// Atomic `RENAME_EXCHANGE` was unavailable or failed.
    ExchangeFailed,
    /// Post-exchange exact new/old/unit verification failed, but exact rollback was proven.
    PostExchangeFailureRolledBack,
    /// Post-exchange state could not be safely rolled back or final rollback state was ambiguous.
    RollbackFailedOrAmbiguous,
    /// Transaction-owned staging cleanup failed before production exchange.
    CleanupFailed,
    /// Required file or directory durability synchronization failed.
    DurabilityFailed,
}

impl fmt::Display for ReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInvocation => "invalid_invocation",
            Self::RootRequired => "root_required",
            Self::InvokingUserIdentityInvalid => "invoking_user_identity_invalid",
            Self::StageCustodyInvalid => "stage_custody_invalid",
            Self::CandidateInvalid => "candidate_invalid",
            Self::ManifestInvalid => "manifest_invalid",
            Self::PackageParentInvalid => "package_parent_invalid",
            Self::InstalledAgentInvalid => "installed_agent_invalid",
            Self::VendorUnitInvalid => "vendor_unit_invalid",
            Self::RootStagingFailed => "root_staging_failed",
            Self::ExchangeFailed => "exchange_failed",
            Self::PostExchangeFailureRolledBack => "post_exchange_failure_rolled_back",
            Self::RollbackFailedOrAmbiguous => "rollback_failed_or_ambiguous",
            Self::CleanupFailed => "cleanup_failed",
            Self::DurabilityFailed => "durability_failed",
        })
    }
}

impl std::error::Error for ReconciliationError {}

/// Returns the exact bounded deployment manifest required beneath a future prepared stage.
#[must_use]
pub fn expected_deployment_manifest() -> String {
    expected_manifest_for(&ProductionPolicy::new())
}

/// Executes the one selected fixed-purpose Agent reconciliation transaction.
///
/// The only caller-controlled locator is `stage_directory`; production destination paths,
/// expected old/new/unit hashes, modes, and lengths are compiled into this crate.
///
/// The caller must independently establish the C03e-WB non-running service preflight before
/// invoking this privileged operation. This function deliberately performs no systemd-manager
/// call and does not claim a race-free binding to that external preflight.
///
/// # Errors
///
/// Returns a bounded [`ReconciliationError`] for any custody, exact-identity, exchange,
/// rollback, cleanup, or durability failure.
pub fn reconcile_current_agent(stage_directory: &Path) -> Result<(), ReconciliationError> {
    let mut policy = ProductionPolicy::new();
    validate_required_process_identity(&policy)?;
    let invoking_user = resolve_invoking_user_identity_from_environment()?;
    policy.stage_owner_uid = invoking_user.uid;
    policy.stage_owner_gid = invoking_user.gid;
    let layout = ProductionLayout::new();
    reconcile_with(&layout, &policy, stage_directory, FaultInjection::None).map(|_| ())
}

/// Parses the fixed CLI surface and returns a process exit code.
///
/// Accepted shape:
/// `prw-agent-package-reconcile reconcile-current-agent <absolute-stage-directory>`.
#[must_use]
pub fn run_cli<I>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let Some(action) = arguments.next() else {
        eprintln!("prw-agent-package-reconcile error=invalid_invocation");
        return ExitCode::from(2);
    };
    let Some(stage) = arguments.next() else {
        eprintln!("prw-agent-package-reconcile error=invalid_invocation");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() || action != OsStr::new(RECONCILE_CURRENT_AGENT_ACTION) {
        eprintln!("prw-agent-package-reconcile error=invalid_invocation");
        return ExitCode::from(2);
    }
    let stage = PathBuf::from(stage);
    if !is_normal_absolute_path(&stage) {
        eprintln!("prw-agent-package-reconcile error=invalid_invocation");
        return ExitCode::from(2);
    }
    match reconcile_current_agent(&stage) {
        Ok(()) => {
            println!("prw-agent-package-reconcile result=current_agent_payload_reconciled");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("prw-agent-package-reconcile error={error}");
            ExitCode::from(1)
        }
    }
}

#[derive(Clone)]
struct ProductionLayout {
    agent_parent: PathBuf,
    unit_parent: PathBuf,
}

impl ProductionLayout {
    fn new() -> Self {
        Self {
            agent_parent: PathBuf::from(AGENT_PARENT),
            unit_parent: PathBuf::from(UNIT_PARENT),
        }
    }
}

#[derive(Clone)]
struct ProductionPolicy {
    required_ruid: u32,
    required_euid: u32,
    package_uid: u32,
    package_gid: u32,
    stage_owner_uid: u32,
    stage_owner_gid: u32,
    old_agent_hash: String,
    new_agent_hash: String,
    unit_hash: String,
    old_agent_bytes: u64,
    new_agent_bytes: u64,
}

impl ProductionPolicy {
    fn new() -> Self {
        Self {
            required_ruid: 0,
            required_euid: 0,
            package_uid: 0,
            package_gid: 0,
            stage_owner_uid: 0,
            stage_owner_gid: 0,
            old_agent_hash: OLD_AGENT_SHA256.to_owned(),
            new_agent_hash: NEW_AGENT_SHA256.to_owned(),
            unit_hash: VENDOR_UNIT_SHA256.to_owned(),
            old_agent_bytes: OLD_AGENT_BYTES,
            new_agent_bytes: NEW_AGENT_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvokingUserIdentity {
    uid: u32,
    gid: u32,
}

fn validate_required_process_identity(
    policy: &ProductionPolicy,
) -> Result<(), ReconciliationError> {
    if getuid().as_raw() != policy.required_ruid || geteuid().as_raw() != policy.required_euid {
        return Err(ReconciliationError::RootRequired);
    }
    Ok(())
}

fn resolve_invoking_user_identity_from_environment()
-> Result<InvokingUserIdentity, ReconciliationError> {
    let uid = env::var_os("SUDO_UID");
    let gid = env::var_os("SUDO_GID");
    let user = env::var_os("SUDO_USER");
    parse_invoking_user_identity(uid.as_deref(), gid.as_deref(), user.as_deref())
}

fn parse_invoking_user_identity(
    uid: Option<&OsStr>,
    gid: Option<&OsStr>,
    user: Option<&OsStr>,
) -> Result<InvokingUserIdentity, ReconciliationError> {
    let uid = uid
        .and_then(parse_nonzero_canonical_decimal_id)
        .ok_or(ReconciliationError::InvokingUserIdentityInvalid)?;
    let gid = gid
        .and_then(parse_nonzero_canonical_decimal_id)
        .ok_or(ReconciliationError::InvokingUserIdentityInvalid)?;
    let user = user.ok_or(ReconciliationError::InvokingUserIdentityInvalid)?;
    if user.is_empty() || user.as_bytes() == b"root" {
        return Err(ReconciliationError::InvokingUserIdentityInvalid);
    }
    Ok(InvokingUserIdentity { uid, gid })
}

fn parse_nonzero_canonical_decimal_id(value: &OsStr) -> Option<u32> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return None;
    }
    let mut parsed = 0_u32;
    for byte in bytes {
        parsed = parsed
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
    }
    (parsed != 0).then_some(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum FaultInjection {
    None,
    BeforeExchange,
    AfterExchange,
    #[cfg(test)]
    CorruptAfterRollback,
}

const fn forces_post_exchange_failure(fault: FaultInjection) -> bool {
    match fault {
        FaultInjection::AfterExchange => true,
        #[cfg(test)]
        FaultInjection::CorruptAfterRollback => true,
        FaultInjection::None | FaultInjection::BeforeExchange => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransactionReport {
    exchanges: u8,
    rolled_back: bool,
}

fn reconcile_with(
    layout: &ProductionLayout,
    policy: &ProductionPolicy,
    stage_directory: &Path,
    fault: FaultInjection,
) -> Result<TransactionReport, ReconciliationError> {
    validate_required_process_identity(policy)?;

    let (stage, stage_uid) = open_validated_stage(stage_directory, policy)?;
    let candidate = open_validated_candidate(&stage, stage_uid, policy)?;
    validate_manifest(&stage, stage_uid, policy)?;

    let agent_parent = open_fixed_package_directory(&layout.agent_parent, policy)?;
    let unit_parent = open_fixed_package_directory(&layout.unit_parent, policy)?;
    validate_agent_at(&agent_parent, policy, false)?;
    validate_unit_at(&unit_parent, policy)?;

    let (temporary_name, temporary) = create_root_sibling(&agent_parent, policy)?;
    if let Err(error) = stage_root_candidate(&candidate, &temporary, policy) {
        return cleanup_before_exchange(&agent_parent, &temporary_name, error);
    }

    if matches!(fault, FaultInjection::BeforeExchange) {
        return cleanup_before_exchange(
            &agent_parent,
            &temporary_name,
            ReconciliationError::RootStagingFailed,
        );
    }

    if validate_agent_at(&agent_parent, policy, false).is_err()
        || validate_root_candidate_file(&temporary, policy).is_err()
        || validate_unit_at(&unit_parent, policy).is_err()
    {
        return cleanup_before_exchange(
            &agent_parent,
            &temporary_name,
            ReconciliationError::RootStagingFailed,
        );
    }

    if renameat_with(
        &agent_parent,
        AGENT_FILE,
        &agent_parent,
        temporary_name.as_str(),
        RenameFlags::EXCHANGE,
    )
    .is_err()
    {
        return cleanup_before_exchange(
            &agent_parent,
            &temporary_name,
            ReconciliationError::ExchangeFailed,
        );
    }

    let mut report = TransactionReport {
        exchanges: 1,
        rolled_back: false,
    };

    let post_exchange_ok = !forces_post_exchange_failure(fault)
        && validate_agent_at(&agent_parent, policy, true).is_ok()
        && validate_rollback_at(&agent_parent, &temporary_name, policy).is_ok()
        && validate_unit_at(&unit_parent, policy).is_ok()
        && sync_directory(&agent_parent).is_ok();

    if !post_exchange_ok {
        return rollback_after_exchange(&agent_parent, &temporary_name, policy, fault, &mut report);
    }

    unlinkat(&agent_parent, temporary_name.as_str(), AtFlags::empty())
        .map_err(|_| ReconciliationError::CleanupFailed)?;
    sync_directory(&agent_parent)?;
    Ok(report)
}

fn rollback_after_exchange(
    agent_parent: &File,
    temporary_name: &str,
    policy: &ProductionPolicy,
    fault: FaultInjection,
    report: &mut TransactionReport,
) -> Result<TransactionReport, ReconciliationError> {
    #[cfg(not(test))]
    let _ = fault;
    if validate_agent_at(agent_parent, policy, true).is_err()
        || validate_rollback_at(agent_parent, temporary_name, policy).is_err()
    {
        return Err(ReconciliationError::RollbackFailedOrAmbiguous);
    }

    renameat_with(
        agent_parent,
        AGENT_FILE,
        agent_parent,
        temporary_name,
        RenameFlags::EXCHANGE,
    )
    .map_err(|_| ReconciliationError::RollbackFailedOrAmbiguous)?;
    report.exchanges = report.exchanges.saturating_add(1);

    #[cfg(test)]
    if matches!(fault, FaultInjection::CorruptAfterRollback) {
        let mut destination = File::from(
            openat(
                agent_parent,
                AGENT_FILE,
                OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| ReconciliationError::RollbackFailedOrAmbiguous)?,
        );
        destination
            .write_all(b"corrupt")
            .map_err(|_| ReconciliationError::RollbackFailedOrAmbiguous)?;
        destination
            .sync_all()
            .map_err(|_| ReconciliationError::RollbackFailedOrAmbiguous)?;
    }

    if validate_agent_at(agent_parent, policy, false).is_err() {
        return Err(ReconciliationError::RollbackFailedOrAmbiguous);
    }
    report.rolled_back = true;
    let _ = cleanup_transaction_sibling(agent_parent, temporary_name);
    let _ = sync_directory(agent_parent);
    Err(ReconciliationError::PostExchangeFailureRolledBack)
}

fn open_validated_stage(
    stage_directory: &Path,
    policy: &ProductionPolicy,
) -> Result<(File, u32), ReconciliationError> {
    if !is_normal_absolute_path(stage_directory) {
        return Err(ReconciliationError::StageCustodyInvalid);
    }
    let stage = open_absolute_directory_no_symlinks(stage_directory)
        .map_err(|()| ReconciliationError::StageCustodyInvalid)?;
    let metadata = stage
        .metadata()
        .map_err(|_| ReconciliationError::StageCustodyInvalid)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != STAGE_MODE
        || policy.stage_owner_uid == 0
        || policy.stage_owner_gid == 0
        || metadata.uid() != policy.stage_owner_uid
        || metadata.gid() != policy.stage_owner_gid
        || metadata.mode() & 0o022 != 0
    {
        return Err(ReconciliationError::StageCustodyInvalid);
    }
    Ok((stage, metadata.uid()))
}

fn open_validated_candidate(
    stage: &File,
    stage_uid: u32,
    policy: &ProductionPolicy,
) -> Result<File, ReconciliationError> {
    let candidate = File::from(
        openat2(
            stage,
            CANDIDATE_FILE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ReconciliationError::CandidateInvalid)?,
    );
    let before = exact_identity(&candidate).map_err(|()| ReconciliationError::CandidateInvalid)?;
    if !candidate
        .metadata()
        .map_err(|_| ReconciliationError::CandidateInvalid)?
        .is_file()
        || before.uid != stage_uid
        || before.mode & 0o022 != 0
        || before.len != policy.new_agent_bytes
        || hash_file(&candidate, before.len).map_err(|()| ReconciliationError::CandidateInvalid)?
            != policy.new_agent_hash
    {
        return Err(ReconciliationError::CandidateInvalid);
    }
    let after = exact_identity(&candidate).map_err(|()| ReconciliationError::CandidateInvalid)?;
    if before != after {
        return Err(ReconciliationError::CandidateInvalid);
    }
    Ok(candidate)
}

fn validate_manifest(
    stage: &File,
    stage_uid: u32,
    policy: &ProductionPolicy,
) -> Result<(), ReconciliationError> {
    let manifest = File::from(
        openat2(
            stage,
            MANIFEST_FILE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ReconciliationError::ManifestInvalid)?,
    );
    let metadata = manifest
        .metadata()
        .map_err(|_| ReconciliationError::ManifestInvalid)?;
    if !metadata.is_file()
        || metadata.uid() != stage_uid
        || metadata.mode() & 0o7777 != MANIFEST_MODE
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(ReconciliationError::ManifestInvalid);
    }
    let bytes = read_exact_file(&manifest, metadata.len())
        .map_err(|()| ReconciliationError::ManifestInvalid)?;
    if bytes != expected_manifest_for(policy).as_bytes() {
        return Err(ReconciliationError::ManifestInvalid);
    }
    Ok(())
}

fn open_fixed_package_directory(
    path: &Path,
    policy: &ProductionPolicy,
) -> Result<File, ReconciliationError> {
    let directory = open_absolute_directory_no_symlinks(path)
        .map_err(|()| ReconciliationError::PackageParentInvalid)?;
    let metadata = directory
        .metadata()
        .map_err(|_| ReconciliationError::PackageParentInvalid)?;
    if !metadata.is_dir()
        || metadata.uid() != policy.package_uid
        || metadata.gid() != policy.package_gid
        || metadata.mode() & 0o7777 != PACKAGE_DIRECTORY_MODE
    {
        return Err(ReconciliationError::PackageParentInvalid);
    }
    Ok(directory)
}

fn validate_agent_at(
    parent: &File,
    policy: &ProductionPolicy,
    expect_new: bool,
) -> Result<(), ReconciliationError> {
    let file = File::from(
        openat2(
            parent,
            AGENT_FILE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ReconciliationError::InstalledAgentInvalid)?,
    );
    let expected_len = if expect_new {
        policy.new_agent_bytes
    } else {
        policy.old_agent_bytes
    };
    let expected_hash = if expect_new {
        policy.new_agent_hash.as_str()
    } else {
        policy.old_agent_hash.as_str()
    };
    validate_exact_package_file(
        &file,
        policy.package_uid,
        policy.package_gid,
        AGENT_MODE,
        expected_len,
        expected_hash,
    )
    .map_err(|()| ReconciliationError::InstalledAgentInvalid)
}

fn validate_unit_at(parent: &File, policy: &ProductionPolicy) -> Result<(), ReconciliationError> {
    let unit = File::from(
        openat2(
            parent,
            UNIT_FILE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ReconciliationError::VendorUnitInvalid)?,
    );
    let metadata = unit
        .metadata()
        .map_err(|_| ReconciliationError::VendorUnitInvalid)?;
    validate_exact_package_file(
        &unit,
        policy.package_uid,
        policy.package_gid,
        UNIT_MODE,
        metadata.len(),
        policy.unit_hash.as_str(),
    )
    .map_err(|()| ReconciliationError::VendorUnitInvalid)
}

fn validate_rollback_at(
    parent: &File,
    temporary_name: &str,
    policy: &ProductionPolicy,
) -> Result<(), ReconciliationError> {
    let rollback = File::from(
        openat2(
            parent,
            temporary_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ReconciliationError::RollbackFailedOrAmbiguous)?,
    );
    validate_exact_package_file(
        &rollback,
        policy.package_uid,
        policy.package_gid,
        AGENT_MODE,
        policy.old_agent_bytes,
        policy.old_agent_hash.as_str(),
    )
    .map_err(|()| ReconciliationError::RollbackFailedOrAmbiguous)
}

fn validate_root_candidate_file(
    file: &File,
    policy: &ProductionPolicy,
) -> Result<(), ReconciliationError> {
    validate_exact_package_file(
        file,
        policy.package_uid,
        policy.package_gid,
        AGENT_MODE,
        policy.new_agent_bytes,
        policy.new_agent_hash.as_str(),
    )
    .map_err(|()| ReconciliationError::RootStagingFailed)
}

fn validate_exact_package_file(
    file: &File,
    uid: u32,
    gid: u32,
    mode: u32,
    expected_len: u64,
    expected_hash: &str,
) -> Result<(), ()> {
    let before = exact_identity(file)?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || before.uid != uid
        || before.gid != gid
        || before.mode & 0o7777 != mode
        || before.len != expected_len
        || hash_file(file, expected_len)? != expected_hash
    {
        return Err(());
    }
    let after = exact_identity(file)?;
    if before != after {
        return Err(());
    }
    Ok(())
}

fn create_root_sibling(
    parent: &File,
    policy: &ProductionPolicy,
) -> Result<(String, File), ReconciliationError> {
    let pid = std::process::id();
    for attempt in 0_u8..32 {
        let name = format!(".prw-agent.c03e-ug.{pid}.{attempt}.candidate");
        if let Ok(fd) = openat(
            parent,
            name.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o700),
        ) {
            let file = File::from(fd);
            let metadata = file
                .metadata()
                .map_err(|_| ReconciliationError::RootStagingFailed)?;
            if !metadata.is_file()
                || metadata.uid() != policy.package_uid
                || metadata.gid() != policy.package_gid
            {
                let _ = unlinkat(parent, name.as_str(), AtFlags::empty());
                return Err(ReconciliationError::RootStagingFailed);
            }
            return Ok((name, file));
        }
    }
    Err(ReconciliationError::RootStagingFailed)
}

fn stage_root_candidate(
    candidate: &File,
    temporary: &File,
    policy: &ProductionPolicy,
) -> Result<(), ReconciliationError> {
    let candidate_before =
        exact_identity(candidate).map_err(|()| ReconciliationError::CandidateInvalid)?;
    copy_exact(candidate, temporary, policy.new_agent_bytes)?;
    temporary
        .sync_all()
        .map_err(|_| ReconciliationError::DurabilityFailed)?;
    fchmod(temporary, Mode::from_raw_mode(AGENT_MODE))
        .map_err(|_| ReconciliationError::RootStagingFailed)?;
    temporary
        .sync_all()
        .map_err(|_| ReconciliationError::DurabilityFailed)?;
    let candidate_after =
        exact_identity(candidate).map_err(|()| ReconciliationError::CandidateInvalid)?;
    if candidate_before != candidate_after
        || hash_file(candidate, policy.new_agent_bytes)
            .map_err(|()| ReconciliationError::CandidateInvalid)?
            != policy.new_agent_hash
        || validate_root_candidate_file(temporary, policy).is_err()
    {
        return Err(ReconciliationError::RootStagingFailed);
    }
    Ok(())
}

fn copy_exact(
    source: &File,
    destination: &File,
    expected_len: u64,
) -> Result<(), ReconciliationError> {
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    while offset < expected_len {
        let remaining = expected_len - offset;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ReconciliationError::RootStagingFailed)?;
        let read = source
            .read_at(&mut buffer[..wanted], offset)
            .map_err(|_| ReconciliationError::RootStagingFailed)?;
        if read == 0 {
            return Err(ReconciliationError::RootStagingFailed);
        }
        let mut written = 0_usize;
        while written < read {
            let count = destination
                .write_at(&buffer[written..read], offset + written as u64)
                .map_err(|_| ReconciliationError::RootStagingFailed)?;
            if count == 0 {
                return Err(ReconciliationError::RootStagingFailed);
            }
            written += count;
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or(ReconciliationError::RootStagingFailed)?;
    }
    let metadata = destination
        .metadata()
        .map_err(|_| ReconciliationError::RootStagingFailed)?;
    if metadata.len() != expected_len {
        return Err(ReconciliationError::RootStagingFailed);
    }
    Ok(())
}

fn hash_file(file: &File, expected_len: u64) -> Result<String, ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.len() != expected_len {
        return Err(());
    }
    let mut context = Context::new(&SHA256);
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    while offset < expected_len {
        let remaining = expected_len - offset;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| ())?;
        let read = file
            .read_at(&mut buffer[..wanted], offset)
            .map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        context.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or(())?;
    }
    let digest = context.finish();
    Ok(hex_lower(digest.as_ref()))
}

fn read_exact_file(file: &File, expected_len: u64) -> Result<Vec<u8>, ()> {
    let len = usize::try_from(expected_len).map_err(|_| ())?;
    let mut output = vec![0_u8; len];
    let mut offset = 0_usize;
    while offset < output.len() {
        let read = file
            .read_at(&mut output[offset..], offset as u64)
            .map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        offset += read;
    }
    Ok(output)
}

fn exact_identity(file: &File) -> Result<ExactIdentity, ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    Ok(ExactIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn open_absolute_directory_no_symlinks(path: &Path) -> Result<File, ()> {
    let relative = absolute_relative(path).ok_or(())?;
    let root = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    let fd = openat2(
        &root,
        relative.as_path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ())?;
    Ok(File::from(fd))
}

fn absolute_relative(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => relative.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}

fn is_normal_absolute_path(path: &Path) -> bool {
    absolute_relative(path).is_some()
}

fn cleanup_before_exchange<T>(
    parent: &File,
    temporary_name: &str,
    original: ReconciliationError,
) -> Result<T, ReconciliationError> {
    cleanup_transaction_sibling(parent, temporary_name)
        .map_err(|()| ReconciliationError::CleanupFailed)?;
    sync_directory(parent)?;
    Err(original)
}

fn cleanup_transaction_sibling(parent: &File, name: &str) -> Result<(), ()> {
    unlinkat(parent, name, AtFlags::empty()).map_err(|_| ())
}

fn sync_directory(directory: &File) -> Result<(), ReconciliationError> {
    directory
        .sync_all()
        .map_err(|_| ReconciliationError::DurabilityFailed)
}

fn expected_manifest_for(policy: &ProductionPolicy) -> String {
    format!(
        concat!(
            "schema=c03e-wd-wa-agent-package-reconciliation-v1\n",
            "source_head={}\n",
            "source_tree={}\n",
            "cargo_lock_sha256={}\n",
            "canonical_target={}\n",
            "candidate_bytes={}\n",
            "candidate_sha256={}\n",
            "old_agent_sha256={}\n",
            "vendor_unit_sha256={}\n",
            "operation={}\n",
        ),
        CANDIDATE_SOURCE_HEAD,
        CANDIDATE_SOURCE_TREE,
        CANDIDATE_CARGO_LOCK_SHA256,
        CANDIDATE_CANONICAL_TARGET,
        policy.new_agent_bytes,
        policy.new_agent_hash,
        policy.old_agent_hash,
        policy.unit_hash,
        RECONCILE_CURRENT_AGENT_ACTION,
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions, Permissions},
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        stage: PathBuf,
        layout: ProductionLayout,
        policy: ProductionPolicy,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
        unit_bytes: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "prw-c03e-ug-test-{}-{sequence}",
                std::process::id()
            ));
            let stage = root.join("stage");
            let agent_parent = root.join("usr/lib/private-remote-workspace");
            let unit_parent = root.join("usr/lib/systemd/user");
            fs::create_dir_all(&stage).expect("stage");
            fs::create_dir_all(&agent_parent).expect("agent parent");
            fs::create_dir_all(&unit_parent).expect("unit parent");
            set_mode(&stage, STAGE_MODE);
            set_mode(&agent_parent, PACKAGE_DIRECTORY_MODE);
            set_mode(&unit_parent, PACKAGE_DIRECTORY_MODE);

            let old_bytes = b"old-prw-agent-fixture".to_vec();
            let new_bytes = b"new-prw-agent-fixture-current".to_vec();
            let unit_bytes = b"[Service]\nExecStart=/fixture/prw-agent\n".to_vec();
            write_file(&agent_parent.join(AGENT_FILE), &old_bytes, AGENT_MODE);
            write_file(&unit_parent.join(UNIT_FILE), &unit_bytes, UNIT_MODE);

            let uid = geteuid().as_raw();
            let ruid = getuid().as_raw();
            let gid = fs::metadata(&agent_parent).expect("metadata").gid();
            let stage_gid = fs::metadata(&stage).expect("stage metadata").gid();
            let policy = ProductionPolicy {
                required_ruid: ruid,
                required_euid: uid,
                package_uid: uid,
                package_gid: gid,
                stage_owner_uid: uid,
                stage_owner_gid: stage_gid,
                old_agent_hash: hash_bytes(&old_bytes),
                new_agent_hash: hash_bytes(&new_bytes),
                unit_hash: hash_bytes(&unit_bytes),
                old_agent_bytes: old_bytes.len() as u64,
                new_agent_bytes: new_bytes.len() as u64,
            };
            write_file(&stage.join(CANDIDATE_FILE_NAME), &new_bytes, 0o755);
            write_file(
                &stage.join(MANIFEST_FILE_NAME),
                expected_manifest_for(&policy).as_bytes(),
                MANIFEST_MODE,
            );

            Self {
                root,
                stage,
                layout: ProductionLayout {
                    agent_parent,
                    unit_parent,
                },
                policy,
                old_bytes,
                new_bytes,
                unit_bytes,
            }
        }

        fn destination(&self) -> PathBuf {
            self.layout.agent_parent.join(AGENT_FILE)
        }

        fn unit(&self) -> PathBuf {
            self.layout.unit_parent.join(UNIT_FILE)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn freezes_fixed_production_authority() {
        assert_eq!(
            AGENT_DESTINATION,
            "/usr/lib/private-remote-workspace/prw-agent"
        );
        assert_eq!(
            VENDOR_UNIT_DESTINATION,
            "/usr/lib/systemd/user/prw-agent.service"
        );
        assert_eq!(OLD_AGENT_SHA256.len(), 64);
        assert_eq!(NEW_AGENT_SHA256.len(), 64);
        assert_eq!(VENDOR_UNIT_SHA256.len(), 64);
        assert_eq!(OLD_AGENT_BYTES, 11_068_384);
        assert_eq!(NEW_AGENT_BYTES, 11_089_904);
        assert_eq!(MANIFEST_FILE_NAME, "C03E_WD_DEPLOYMENT_MANIFEST");
        assert_eq!(RECONCILE_CURRENT_AGENT_ACTION, "reconcile-current-agent");
    }

    #[test]
    fn manifest_binds_exact_wc_candidate_provenance() {
        let manifest = expected_deployment_manifest();
        assert!(manifest.starts_with("schema=c03e-wd-wa-agent-package-reconciliation-v1\n"));
        assert!(manifest.contains(CANDIDATE_SOURCE_HEAD));
        assert!(manifest.contains(CANDIDATE_SOURCE_TREE));
        assert!(manifest.contains(CANDIDATE_CARGO_LOCK_SHA256));
        assert!(manifest.contains(CANDIDATE_CANONICAL_TARGET));
        assert!(manifest.contains(NEW_AGENT_SHA256));
        assert!(manifest.ends_with("operation=reconcile-current-agent\n"));
    }

    #[test]
    fn disposable_same_filesystem_exchange_succeeds() {
        let fixture = Fixture::new();
        let report = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect("reconcile");
        assert_eq!(report.exchanges, 1);
        assert!(!report.rolled_back);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.new_bytes
        );
        assert_eq!(fs::read(fixture.unit()).expect("unit"), fixture.unit_bytes);
        assert_no_transaction_siblings(&fixture.layout.agent_parent);
    }

    #[test]
    fn injected_pre_exchange_failure_preserves_destination() {
        let fixture = Fixture::new();
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::BeforeExchange,
        )
        .expect_err("must fail");
        assert_eq!(error, ReconciliationError::RootStagingFailed);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
        assert_no_transaction_siblings(&fixture.layout.agent_parent);
    }

    #[test]
    fn injected_post_exchange_failure_performs_one_exact_exchange_back() {
        let fixture = Fixture::new();
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::AfterExchange,
        )
        .expect_err("must fail after rollback");
        assert_eq!(error, ReconciliationError::PostExchangeFailureRolledBack);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
        assert_no_transaction_siblings(&fixture.layout.agent_parent);
    }

    #[test]
    fn rollback_success_is_not_claimed_without_old_destination_readback() {
        let fixture = Fixture::new();
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::CorruptAfterRollback,
        )
        .expect_err("rollback readback must fail");
        assert_eq!(error, ReconciliationError::RollbackFailedOrAmbiguous);
    }

    #[test]
    fn rejects_candidate_hash_drift() {
        let fixture = Fixture::new();
        write_file(
            &fixture.stage.join(CANDIDATE_FILE_NAME),
            b"wrong-candidate-of-same-shape",
            0o755,
        );
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("hash drift");
        assert_eq!(error, ReconciliationError::CandidateInvalid);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
    }

    #[test]
    fn rejects_candidate_symlink() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        fs::remove_file(fixture.stage.join(CANDIDATE_FILE_NAME)).expect("remove candidate");
        symlink(
            fixture.destination(),
            fixture.stage.join(CANDIDATE_FILE_NAME),
        )
        .expect("symlink");
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("symlink rejected");
        assert_eq!(error, ReconciliationError::CandidateInvalid);
    }

    #[test]
    fn rejects_candidate_group_write_mode() {
        let fixture = Fixture::new();
        set_mode(&fixture.stage.join(CANDIDATE_FILE_NAME), 0o775);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("mode rejected");
        assert_eq!(error, ReconciliationError::CandidateInvalid);
    }

    #[test]
    fn rejects_nonregular_candidate() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.stage.join(CANDIDATE_FILE_NAME)).expect("remove candidate");
        fs::create_dir(fixture.stage.join(CANDIDATE_FILE_NAME)).expect("directory candidate");
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("nonregular rejected");
        assert_eq!(error, ReconciliationError::CandidateInvalid);
    }

    #[test]
    fn rejects_vendor_unit_drift_before_exchange() {
        let fixture = Fixture::new();
        write_file(&fixture.unit(), b"drifted-unit", UNIT_MODE);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("unit drift");
        assert_eq!(error, ReconciliationError::VendorUnitInvalid);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
    }

    #[test]
    fn rejects_installed_agent_drift_before_exchange() {
        let fixture = Fixture::new();
        write_file(&fixture.destination(), b"foreign-agent", AGENT_MODE);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("old hash drift");
        assert_eq!(error, ReconciliationError::InstalledAgentInvalid);
    }

    #[test]
    fn rejects_package_owner_mismatch_before_exchange() {
        let fixture = Fixture::new();
        let mut policy = fixture.policy.clone();
        policy.package_uid = policy.package_uid.saturating_add(1);
        let error = reconcile_with(
            &fixture.layout,
            &policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("owner mismatch");
        assert_eq!(error, ReconciliationError::PackageParentInvalid);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
    }

    #[test]
    fn rejects_installed_agent_mode_drift_before_exchange() {
        let fixture = Fixture::new();
        set_mode(&fixture.destination(), 0o775);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("mode drift");
        assert_eq!(error, ReconciliationError::InstalledAgentInvalid);
    }

    #[test]
    fn rejects_stage_owner_mismatch() {
        let mut fixture = Fixture::new();
        fixture.policy.stage_owner_uid = fixture.policy.stage_owner_uid.saturating_add(1);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("stage owner mismatch");
        assert_eq!(error, ReconciliationError::StageCustodyInvalid);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
    }

    #[test]
    fn rejects_stage_group_mismatch() {
        let mut fixture = Fixture::new();
        fixture.policy.stage_owner_gid = fixture.policy.stage_owner_gid.saturating_add(1);
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("stage group mismatch");
        assert_eq!(error, ReconciliationError::StageCustodyInvalid);
        assert_eq!(
            fs::read(fixture.destination()).expect("destination"),
            fixture.old_bytes
        );
    }

    #[test]
    fn requires_selected_real_and_effective_process_identity() {
        let fixture = Fixture::new();
        let mut real_mismatch = fixture.policy.clone();
        real_mismatch.required_ruid = u32::from(getuid().as_raw() == 0);
        assert_eq!(
            reconcile_with(
                &fixture.layout,
                &real_mismatch,
                &fixture.stage,
                FaultInjection::None,
            ),
            Err(ReconciliationError::RootRequired)
        );

        let mut effective_mismatch = fixture.policy.clone();
        effective_mismatch.required_euid = u32::from(geteuid().as_raw() == 0);
        assert_eq!(
            reconcile_with(
                &fixture.layout,
                &effective_mismatch,
                &fixture.stage,
                FaultInjection::None,
            ),
            Err(ReconciliationError::RootRequired)
        );
    }

    #[test]
    fn parses_exact_sudo_rs_invoking_user_identity() {
        let identity = parse_invoking_user_identity(
            Some(OsStr::new("1000")),
            Some(OsStr::new("1000")),
            Some(OsStr::new("gersi365")),
        )
        .expect("valid identity");
        assert_eq!(
            identity,
            InvokingUserIdentity {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn rejects_missing_or_prohibited_sudo_identity_fields() {
        for (uid, gid, user) in [
            (None, Some(OsStr::new("1000")), Some(OsStr::new("gersi365"))),
            (Some(OsStr::new("1000")), None, Some(OsStr::new("gersi365"))),
            (Some(OsStr::new("1000")), Some(OsStr::new("1000")), None),
            (
                Some(OsStr::new("1000")),
                Some(OsStr::new("1000")),
                Some(OsStr::new("")),
            ),
            (
                Some(OsStr::new("1000")),
                Some(OsStr::new("1000")),
                Some(OsStr::new("root")),
            ),
        ] {
            assert_eq!(
                parse_invoking_user_identity(uid, gid, user),
                Err(ReconciliationError::InvokingUserIdentityInvalid)
            );
        }
    }

    #[test]
    fn rejects_noncanonical_or_zero_sudo_numeric_identity() {
        for invalid in [
            "",
            "0",
            "00",
            "01000",
            "+1000",
            "-1",
            " 1000",
            "1000 ",
            "1_000",
            "abc",
            "4294967296",
        ] {
            assert_eq!(
                parse_nonzero_canonical_decimal_id(OsStr::new(invalid)),
                None
            );
        }
        assert_eq!(parse_nonzero_canonical_decimal_id(OsStr::new("1")), Some(1));
        assert_eq!(
            parse_nonzero_canonical_decimal_id(OsStr::new("4294967295")),
            Some(u32::MAX)
        );
    }

    #[test]
    fn rejects_symlinked_stage_locator_component() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let link = fixture.root.join("stage-link");
        symlink(&fixture.stage, &link).expect("stage symlink");
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &link,
            FaultInjection::None,
        )
        .expect_err("stage symlink rejected");
        assert_eq!(error, ReconciliationError::StageCustodyInvalid);
    }

    #[test]
    fn rejects_manifest_drift() {
        let fixture = Fixture::new();
        write_file(
            &fixture.stage.join(MANIFEST_FILE_NAME),
            b"schema=foreign\n",
            MANIFEST_MODE,
        );
        let error = reconcile_with(
            &fixture.layout,
            &fixture.policy,
            &fixture.stage,
            FaultInjection::None,
        )
        .expect_err("manifest drift");
        assert_eq!(error, ReconciliationError::ManifestInvalid);
    }

    #[test]
    fn rejects_non_normal_stage_locator() {
        assert!(!is_normal_absolute_path(Path::new("relative/stage")));
        assert!(!is_normal_absolute_path(Path::new("/tmp/../stage")));
        assert!(is_normal_absolute_path(Path::new("/tmp/prw-stage")));
    }

    #[test]
    fn cli_rejects_arbitrary_subcommands_and_extra_arguments() {
        let invalid = run_cli([
            OsString::from("prw-agent-package-reconcile"),
            OsString::from("shell"),
            OsString::from("/tmp/stage"),
        ]);
        assert_eq!(invalid, ExitCode::from(2));
        let extra = run_cli([
            OsString::from("prw-agent-package-reconcile"),
            OsString::from(RECONCILE_CURRENT_AGENT_ACTION),
            OsString::from("/tmp/stage"),
            OsString::from("/usr/other"),
        ]);
        assert_eq!(extra, ExitCode::from(2));
    }

    fn hash_bytes(bytes: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(bytes);
        hex_lower(context.finish().as_ref())
    }

    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .expect("open fixture file");
        file.write_all(bytes).expect("write fixture");
        file.sync_all().expect("sync fixture");
        drop(file);
        set_mode(path, mode);
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("set mode");
    }

    fn assert_no_transaction_siblings(parent: &Path) {
        let names = fs::read_dir(parent)
            .expect("read parent")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![OsString::from(AGENT_FILE)]);
    }
}
