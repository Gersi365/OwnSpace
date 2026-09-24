//! Descriptor-anchored single-instance authority for the Linux PRW Agent.
//!
//! Phase 065 owns only the persistent `agent.lock` file and its advisory lock.
//! Phase 066 is nested beneath this authority and handles stale `agent.sock`
//! preparation without binding or listening.

#[allow(
    dead_code,
    reason = "pre-bind Agent socket-path preparation is intentionally crate-internal"
)]
#[path = "linux_agent_socket_path.rs"]
pub mod socket_path;

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, FlockOperation, Mode, OFlags, Stat, fchmod, flock, fstat, openat};
use rustix::io::Errno;

use super::ValidatedPrwRuntimeDirectory;
use crate::linux_identity::effective_agent_uid;

pub(super) const AGENT_INSTANCE_LOCK_FILENAME: &str = "agent.lock";
pub(super) const AGENT_INSTANCE_LOCK_MODE: u32 = 0o600;

/// Owned guard proving this process holds the PRW Agent instance lock.
#[derive(Debug)]
pub struct AgentInstanceLock {
    descriptor: OwnedFd,
}

impl AsFd for AgentInstanceLock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Bounded failure while acquiring the PRW Agent single-instance lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstanceLockError {
    /// `agent.lock` could not be opened/created with the required semantics.
    OpenFailed,
    /// Descriptor metadata could not be read before normalization.
    MetadataReadFailed,
    /// The opened lock object was not a regular file.
    NotRegularFile,
    /// The lock-file owner did not match the effective Agent UID.
    WrongOwner {
        /// Effective Agent UID required by the contract.
        expected_uid: u32,
        /// UID reported by descriptor metadata.
        actual_uid: u32,
    },
    /// Exact `0600` normalization on a verified same-UID lock file failed.
    ModeNormalizeFailed,
    /// Descriptor metadata could not be read after mode normalization.
    RevalidationMetadataReadFailed,
    /// Revalidation observed a mode other than exact `0600`.
    WrongModeAfterNormalization {
        /// Permission and special-mode bits observed after normalization.
        actual_mode: u32,
    },
    /// Another conforming Agent instance already holds the exclusive lock.
    AlreadyRunning,
    /// The kernel rejected the nonblocking exclusive lock for another reason.
    LockFailed,
}

/// Opens/validates `agent.lock` and acquires the nonblocking exclusive instance lock.
///
/// # Errors
///
/// Returns [`AgentInstanceLockError::AlreadyRunning`] when another process holds
/// the lock, or another bounded error when the lock object cannot be safely
/// opened, validated, normalized, or locked.
pub fn acquire_agent_instance_lock(
    runtime_directory: &ValidatedPrwRuntimeDirectory,
) -> Result<AgentInstanceLock, AgentInstanceLockError> {
    let descriptor = openat(
        runtime_directory.as_fd(),
        AGENT_INSTANCE_LOCK_FILENAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| AgentInstanceLockError::OpenFailed)?;

    let metadata = fstat(&descriptor).map_err(|_| AgentInstanceLockError::MetadataReadFailed)?;
    validate_lock_identity(&metadata, effective_agent_uid())?;

    if Mode::from_raw_mode(metadata.st_mode).bits() != AGENT_INSTANCE_LOCK_MODE {
        fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| AgentInstanceLockError::ModeNormalizeFailed)?;
        let revalidated = fstat(&descriptor)
            .map_err(|_| AgentInstanceLockError::RevalidationMetadataReadFailed)?;
        validate_lock_complete(&revalidated, effective_agent_uid())?;
    }

    match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(AgentInstanceLock { descriptor }),
        Err(error) if error == Errno::WOULDBLOCK || error == Errno::AGAIN => {
            Err(AgentInstanceLockError::AlreadyRunning)
        }
        Err(_) => Err(AgentInstanceLockError::LockFailed),
    }
}

fn validate_lock_identity(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), AgentInstanceLockError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Err(AgentInstanceLockError::NotRegularFile);
    }

    if metadata.st_uid != expected_uid {
        return Err(AgentInstanceLockError::WrongOwner {
            expected_uid,
            actual_uid: metadata.st_uid,
        });
    }

    Ok(())
}

fn validate_lock_complete(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), AgentInstanceLockError> {
    validate_lock_identity(metadata, expected_uid)?;

    let actual_mode = Mode::from_raw_mode(metadata.st_mode).bits();
    if actual_mode != AGENT_INSTANCE_LOCK_MODE {
        return Err(AgentInstanceLockError::WrongModeAfterNormalization { actual_mode });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, Permissions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{Mode, OFlags, fstat, open};

    use super::{
        AGENT_INSTANCE_LOCK_FILENAME, AgentInstanceLockError, acquire_agent_instance_lock,
        validate_lock_identity,
    };
    use crate::AGENT_RUNTIME_SUBDIRECTORY;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-065-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 065 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 065 directory mode sets");
    }

    fn create_prepared_runtime_directory(
        label: &str,
    ) -> (PathBuf, super::ValidatedPrwRuntimeDirectory) {
        let root_path = unique_temp_path(label);
        create_directory_with_mode(&root_path, 0o700);
        let root = super::super::super::validate_xdg_runtime_root_path(&root_path)
            .expect("temporary root satisfies Phase 062 validation");
        let runtime_directory = super::super::prepare_prw_runtime_directory(&root)
            .expect("temporary PRW directory satisfies Phase 063 preparation");
        drop(root);
        (root_path, runtime_directory)
    }

    #[test]
    fn absent_lock_file_is_created_locked_and_validated_at_0600() {
        let (root_path, runtime_directory) = create_prepared_runtime_directory("create");

        let guard =
            acquire_agent_instance_lock(&runtime_directory).expect("instance lock acquires");
        let lock_path = root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_INSTANCE_LOCK_FILENAME);
        let metadata = fs::metadata(&lock_path).expect("lock pathname metadata reads");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);

        drop(guard);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn second_conforming_acquisition_reports_already_running() {
        let (root_path, runtime_directory) = create_prepared_runtime_directory("contention");
        let first = acquire_agent_instance_lock(&runtime_directory).expect("first lock acquires");

        assert_eq!(
            acquire_agent_instance_lock(&runtime_directory).unwrap_err(),
            AgentInstanceLockError::AlreadyRunning
        );

        drop(first);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn lock_can_be_reacquired_after_first_guard_is_dropped() {
        let (root_path, runtime_directory) = create_prepared_runtime_directory("reacquire");
        let first = acquire_agent_instance_lock(&runtime_directory).expect("first lock acquires");
        drop(first);

        let second = acquire_agent_instance_lock(&runtime_directory).expect("second lock acquires");

        drop(second);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn same_uid_wrong_mode_lock_file_is_normalized_to_0600() {
        let (root_path, runtime_directory) = create_prepared_runtime_directory("normalize");
        let lock_path = root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_INSTANCE_LOCK_FILENAME);
        File::create(&lock_path).expect("temporary lock file creates");
        fs::set_permissions(&lock_path, Permissions::from_mode(0o644))
            .expect("temporary lock mode sets");

        let guard = acquire_agent_instance_lock(&runtime_directory).expect("lock normalizes");
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("normalized lock metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        drop(guard);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn symlink_lock_path_fails_closed_without_modifying_target() {
        let (root_path, runtime_directory) = create_prepared_runtime_directory("symlink");
        let target_path = unique_temp_path("symlink-target");
        File::create(&target_path).expect("temporary target file creates");
        fs::set_permissions(&target_path, Permissions::from_mode(0o644))
            .expect("temporary target mode sets");
        let lock_path = root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_INSTANCE_LOCK_FILENAME);
        symlink(&target_path, &lock_path).expect("temporary lock symlink creates");

        assert_eq!(
            acquire_agent_instance_lock(&runtime_directory).unwrap_err(),
            AgentInstanceLockError::OpenFailed
        );
        assert_eq!(
            fs::metadata(&target_path)
                .expect("target metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );

        drop(runtime_directory);
        fs::remove_file(&lock_path).expect("temporary lock symlink removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
        fs::remove_file(&target_path).expect("temporary target removes");
    }

    #[test]
    fn wrong_owner_metadata_is_rejected_before_mode_policy() {
        let lock_path = unique_temp_path("wrong-owner-classification");
        File::create(&lock_path).expect("temporary lock file creates");
        fs::set_permissions(&lock_path, Permissions::from_mode(0o644))
            .expect("temporary lock mode sets");
        let descriptor = open(
            &lock_path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("temporary lock file opens");
        let metadata = fstat(&descriptor).expect("temporary lock metadata reads");
        let non_matching_uid = metadata.st_uid.wrapping_add(1);

        assert_eq!(
            validate_lock_identity(&metadata, non_matching_uid),
            Err(AgentInstanceLockError::WrongOwner {
                expected_uid: non_matching_uid,
                actual_uid: metadata.st_uid,
            })
        );
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o644);

        drop(descriptor);
        fs::remove_file(&lock_path).expect("temporary lock file removes");
    }
}
