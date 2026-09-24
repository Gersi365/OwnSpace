//! Bound-but-not-listening Linux Agent socket with post-bind validation.
//!
//! Phase 067 creates a filesystem-backed Unix stream socket only after Phase 066
//! path preparation and retains the Phase 065 lifecycle lock by borrow. It does
//! not call `listen`, `accept`, or `connect`.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;

use rustix::fs::{AtFlags, FileType, Mode, Stat, chmodat, statat, unlinkat};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, socket_with};

use super::effective_agent_uid;
use super::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
use super::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::AgentInstanceLock;
use super::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::socket_path::{
    AgentSocketPathPreparationError, AgentSocketPathPreparationOutcome,
    prepare_agent_socket_path_for_bind,
};
use crate::{AGENT_SOCKET_FILENAME, AGENT_SOCKET_MODE};

/// Filesystem identity of the validated bound Agent socket node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSocketFilesystemIdentity {
    device: u128,
    inode: u128,
    uid: u32,
    mode: u32,
}

impl AgentSocketFilesystemIdentity {
    fn from_metadata(metadata: &Stat) -> Self {
        Self {
            device: u128::from(metadata.st_dev),
            inode: u128::from(metadata.st_ino),
            uid: metadata.st_uid,
            mode: Mode::from_raw_mode(metadata.st_mode).bits(),
        }
    }

    fn stable_matches(self, metadata: &Stat) -> bool {
        self.device == u128::from(metadata.st_dev)
            && self.inode == u128::from(metadata.st_ino)
            && self.uid == metadata.st_uid
            && FileType::from_raw_mode(metadata.st_mode).is_socket()
    }

    fn exact_matches(self, metadata: &Stat) -> bool {
        self.stable_matches(metadata) && self.mode == Mode::from_raw_mode(metadata.st_mode).bits()
    }
}

/// Bound, validated Agent socket that has not entered `listen` state.
#[derive(Debug)]
pub struct BoundAgentSocket<'a> {
    socket: OwnedFd,
    runtime_directory: &'a ValidatedPrwRuntimeDirectory,
    _instance_lock: &'a AgentInstanceLock,
    identity: AgentSocketFilesystemIdentity,
    path_preparation: AgentSocketPathPreparationOutcome,
}

impl AsFd for BoundAgentSocket<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl BoundAgentSocket<'_> {
    /// Returns how Phase 066 prepared the fixed pathname before this bind.
    #[must_use]
    pub const fn path_preparation(&self) -> AgentSocketPathPreparationOutcome {
        self.path_preparation
    }

    /// Returns the validated filesystem identity recorded after mode normalization.
    #[must_use]
    pub const fn filesystem_identity(&self) -> AgentSocketFilesystemIdentity {
        self.identity
    }

    /// Closes the bound socket and removes only the unchanged validated pathname.
    ///
    /// # Errors
    ///
    /// Returns a bounded cleanup error if metadata cannot be read, the pathname
    /// has been replaced, unlink fails, or final absence cannot be verified.
    pub fn cleanup(self) -> Result<(), BoundAgentSocketCleanupError> {
        let Self {
            socket,
            runtime_directory,
            identity,
            ..
        } = self;
        drop(socket);
        cleanup_validated_bound_socket_path(runtime_directory, identity)
    }
}

/// Bounded failure while constructing a bound validated Agent socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundAgentSocketError {
    /// Phase 066 could not safely prepare the fixed pathname.
    PathPreparation(AgentSocketPathPreparationError),
    /// Unix stream socket creation failed.
    SocketCreateFailed,
    /// The descriptor-anchored Unix socket address could not be constructed.
    AddressBuildFailed,
    /// Kernel bind failed.
    BindFailed,
    /// Initial no-follow post-bind metadata lookup failed.
    PostBindMetadataReadFailed,
    /// The post-bind filesystem object was not a Unix socket.
    PostBindNotSocket,
    /// The post-bind filesystem object was not owned by the effective Agent UID.
    PostBindWrongOwner {
        /// Effective Agent UID required by the contract.
        expected_uid: u32,
        /// UID reported by descriptor-relative metadata.
        actual_uid: u32,
    },
    /// Descriptor-relative normalization to exact `0600` failed.
    ModeNormalizeFailed,
    /// Metadata lookup after mode normalization failed.
    PostNormalizeMetadataReadFailed,
    /// Device/inode/type/owner identity changed after mode normalization.
    IdentityChangedAfterModeNormalize,
    /// Mode after normalization was not exact `0600`.
    WrongModeAfterNormalization {
        /// Permission and special-mode bits observed after normalization.
        actual_mode: u32,
    },
}

/// Bounded failure while explicitly cleaning up a bound validated socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundAgentSocketCleanupError {
    /// Descriptor-relative metadata lookup failed for a reason other than absence.
    MetadataReadFailed,
    /// The pathname no longer identifies the exact validated bound socket.
    IdentityChanged,
    /// Descriptor-relative unlink failed.
    UnlinkFailed,
    /// Post-unlink metadata lookup failed for a reason other than absence.
    VerificationFailed,
    /// An object remained or reappeared at the pathname after unlink.
    PathStillPresent,
}

/// Creates and validates a bound-but-not-listening filesystem-backed Agent socket.
///
/// # Errors
///
/// Returns [`BoundAgentSocketError`] if Phase 066 preparation, socket/address
/// creation, bind, post-bind identity capture, mode normalization, or final
/// no-follow revalidation fails.
pub fn bind_validated_agent_socket<'a>(
    runtime_directory: &'a ValidatedPrwRuntimeDirectory,
    instance_lock: &'a AgentInstanceLock,
) -> Result<BoundAgentSocket<'a>, BoundAgentSocketError> {
    let path_preparation = prepare_agent_socket_path_for_bind(runtime_directory, instance_lock)
        .map_err(BoundAgentSocketError::PathPreparation)?;

    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| BoundAgentSocketError::SocketCreateFailed)?;

    let bind_path = descriptor_anchored_socket_path(runtime_directory);
    let address =
        SocketAddrUnix::new(&bind_path).map_err(|_| BoundAgentSocketError::AddressBuildFailed)?;
    if bind(&socket, &address).is_err() {
        return Err(BoundAgentSocketError::BindFailed);
    }

    let Ok(initial) = socket_metadata(runtime_directory) else {
        drop(socket);
        return Err(BoundAgentSocketError::PostBindMetadataReadFailed);
    };
    validate_initial_bound_socket_identity(&initial, effective_agent_uid())?;
    let created_identity = AgentSocketFilesystemIdentity::from_metadata(&initial);

    if chmodat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        Mode::RUSR | Mode::WUSR,
        AtFlags::empty(),
    )
    .is_err()
    {
        drop(socket);
        best_effort_remove_created_socket(runtime_directory, created_identity);
        return Err(BoundAgentSocketError::ModeNormalizeFailed);
    }

    let Ok(normalized) = socket_metadata(runtime_directory) else {
        drop(socket);
        best_effort_remove_created_socket(runtime_directory, created_identity);
        return Err(BoundAgentSocketError::PostNormalizeMetadataReadFailed);
    };

    if !created_identity.stable_matches(&normalized) {
        drop(socket);
        best_effort_remove_created_socket(runtime_directory, created_identity);
        return Err(BoundAgentSocketError::IdentityChangedAfterModeNormalize);
    }

    let actual_mode = Mode::from_raw_mode(normalized.st_mode).bits();
    if actual_mode != AGENT_SOCKET_MODE {
        drop(socket);
        best_effort_remove_created_socket(runtime_directory, created_identity);
        return Err(BoundAgentSocketError::WrongModeAfterNormalization { actual_mode });
    }

    let identity = AgentSocketFilesystemIdentity::from_metadata(&normalized);

    Ok(BoundAgentSocket {
        socket,
        runtime_directory,
        _instance_lock: instance_lock,
        identity,
        path_preparation,
    })
}

fn descriptor_anchored_socket_path(runtime_directory: &ValidatedPrwRuntimeDirectory) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        runtime_directory.as_fd().as_raw_fd(),
        AGENT_SOCKET_FILENAME
    ))
}

fn socket_metadata(runtime_directory: &ValidatedPrwRuntimeDirectory) -> Result<Stat, Errno> {
    statat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    )
}

fn validate_initial_bound_socket_identity(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), BoundAgentSocketError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_socket() {
        return Err(BoundAgentSocketError::PostBindNotSocket);
    }

    if metadata.st_uid != expected_uid {
        return Err(BoundAgentSocketError::PostBindWrongOwner {
            expected_uid,
            actual_uid: metadata.st_uid,
        });
    }

    Ok(())
}

fn best_effort_remove_created_socket(
    runtime_directory: &ValidatedPrwRuntimeDirectory,
    identity: AgentSocketFilesystemIdentity,
) {
    let Ok(current) = socket_metadata(runtime_directory) else {
        return;
    };
    if !identity.stable_matches(&current) {
        return;
    }

    let _unlink_result = unlinkat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::empty(),
    );
}

fn cleanup_validated_bound_socket_path(
    runtime_directory: &ValidatedPrwRuntimeDirectory,
    identity: AgentSocketFilesystemIdentity,
) -> Result<(), BoundAgentSocketCleanupError> {
    let current = match socket_metadata(runtime_directory) {
        Ok(metadata) => metadata,
        Err(error) if error == Errno::NOENT => return Ok(()),
        Err(_) => return Err(BoundAgentSocketCleanupError::MetadataReadFailed),
    };

    if !identity.exact_matches(&current) {
        return Err(BoundAgentSocketCleanupError::IdentityChanged);
    }

    unlinkat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::empty(),
    )
    .map_err(|_| BoundAgentSocketCleanupError::UnlinkFailed)?;

    match socket_metadata(runtime_directory) {
        Err(error) if error == Errno::NOENT => Ok(()),
        Ok(_) => Err(BoundAgentSocketCleanupError::PathStillPresent),
        Err(_) => Err(BoundAgentSocketCleanupError::VerificationFailed),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{AtFlags, FileType, Mode, statat};

    use super::{
        BoundAgentSocketCleanupError, BoundAgentSocketError, bind_validated_agent_socket,
    };
    use crate::linux_identity::effective_agent_uid;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::AgentInstanceLock;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::socket_path::{
        AgentSocketPathPreparationError, AgentSocketPathPreparationOutcome,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-067-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 067 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 067 directory mode sets");
    }

    fn create_authorized_runtime(
        label: &str,
    ) -> (PathBuf, ValidatedPrwRuntimeDirectory, AgentInstanceLock) {
        let root_path = unique_temp_path(label);
        create_directory_with_mode(&root_path, 0o700);
        let root = super::super::xdg_runtime_root::validate_xdg_runtime_root_path(&root_path)
            .expect("temporary root satisfies Phase 062 validation");
        let runtime_directory =
            super::super::xdg_runtime_root::prw_runtime_directory::prepare_prw_runtime_directory(
                &root,
            )
            .expect("temporary PRW directory satisfies Phase 063 preparation");
        drop(root);
        let instance_lock = super::super::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::acquire_agent_instance_lock(&runtime_directory)
            .expect("temporary lifecycle authority satisfies Phase 065");
        (root_path, runtime_directory, instance_lock)
    }

    fn agent_socket_path(root_path: &Path) -> PathBuf {
        root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    fn bind_test_socket(path: &Path, mode: u32) -> UnixListener {
        let listener = UnixListener::bind(path).expect("temporary pathname Unix socket binds");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary socket mode sets");
        listener
    }

    #[test]
    fn absent_path_binds_validated_0600_socket_and_cleanup_removes_it() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("bind");
        let socket_path = agent_socket_path(&root_path);

        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("validated socket binds");
        assert_eq!(
            bound.path_preparation(),
            AgentSocketPathPreparationOutcome::AlreadyAbsent
        );
        let metadata = statat(
            runtime_directory.as_fd(),
            AGENT_SOCKET_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("bound socket metadata reads");
        assert!(FileType::from_raw_mode(metadata.st_mode).is_socket());
        assert_eq!(metadata.st_uid, effective_agent_uid());
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o600);

        bound.cleanup().expect("bound socket cleanup succeeds");
        assert!(!socket_path.exists());

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn trusted_stale_socket_is_removed_before_new_bind() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("stale");
        let socket_path = agent_socket_path(&root_path);
        let stale = bind_test_socket(&socket_path, 0o600);
        drop(stale);

        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("stale socket is replaced by validated bind");
        assert_eq!(
            bound.path_preparation(),
            AgentSocketPathPreparationOutcome::StaleSocketRemoved
        );
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("replacement socket exists")
                .file_type()
                .is_socket()
        );

        bound.cleanup().expect("bound socket cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn bind_remains_anchored_to_validated_runtime_directory_descriptor() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("anchor");
        let original_runtime_path = root_path.join(AGENT_RUNTIME_SUBDIRECTORY);
        let renamed_runtime_path = root_path.join("private-remote-workspace-renamed");
        fs::rename(&original_runtime_path, &renamed_runtime_path)
            .expect("validated PRW runtime pathname renames");
        create_directory_with_mode(&original_runtime_path, 0o700);

        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("descriptor-anchored socket binds");

        assert!(
            renamed_runtime_path
                .join(AGENT_SOCKET_FILENAME)
                .symlink_metadata()
                .expect("anchored socket exists in renamed directory")
                .file_type()
                .is_socket()
        );
        assert!(!original_runtime_path.join(AGENT_SOCKET_FILENAME).exists());

        bound.cleanup().expect("anchored socket cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn wrong_mode_stale_socket_blocks_before_bind_and_remains() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("wrong-mode");
        let socket_path = agent_socket_path(&root_path);
        let stale = bind_test_socket(&socket_path, 0o660);
        drop(stale);

        assert_eq!(
            bind_validated_agent_socket(&runtime_directory, &instance_lock).unwrap_err(),
            BoundAgentSocketError::PathPreparation(AgentSocketPathPreparationError::WrongMode {
                actual_mode: 0o660
            })
        );
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("wrong-mode stale socket remains")
                .file_type()
                .is_socket()
        );

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("temporary stale socket removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn cleanup_refuses_to_unlink_replacement_socket_identity() {
        let (root_path, runtime_directory, instance_lock) =
            create_authorized_runtime("cleanup-race");
        let socket_path = agent_socket_path(&root_path);
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("validated socket binds");

        fs::remove_file(&socket_path)
            .expect("original bound pathname unlinks for replacement test");
        let replacement = bind_test_socket(&socket_path, 0o600);

        assert_eq!(
            bound.cleanup().unwrap_err(),
            BoundAgentSocketCleanupError::IdentityChanged
        );
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("replacement remains")
                .file_type()
                .is_socket()
        );

        drop(replacement);
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("replacement socket removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }
}
