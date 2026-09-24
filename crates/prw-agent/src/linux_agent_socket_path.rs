//! Locked stale-path preparation for the Linux PRW Agent socket.
//!
//! Phase 066 may remove only an unchanged trusted-shape stale `agent.sock`
//! while a Phase 065 [`AgentInstanceLock`] is held. It never binds or listens.

use std::os::fd::AsFd;

use rustix::fs::{AtFlags, FileType, Mode, Stat, statat, unlinkat};
use rustix::io::Errno;

use super::super::ValidatedPrwRuntimeDirectory;
use super::AgentInstanceLock;
use crate::linux_identity::effective_agent_uid;
use crate::{AGENT_SOCKET_FILENAME, AGENT_SOCKET_MODE};

/// Successful preparation of the fixed `agent.sock` pathname for a later bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSocketPathPreparationOutcome {
    /// No socket pathname existed, so no stale cleanup was required.
    AlreadyAbsent,
    /// A trusted-shape unchanged stale socket node was removed and absence verified.
    StaleSocketRemoved,
}

/// Bounded failure while preparing the fixed Agent socket pathname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSocketPathPreparationError {
    /// Descriptor-relative metadata lookup failed for a reason other than absence.
    MetadataReadFailed,
    /// The existing object was not a Unix socket.
    NotSocket,
    /// The existing socket owner did not match the effective Agent UID.
    WrongOwner {
        /// Effective Agent UID required by the contract.
        expected_uid: u32,
        /// UID reported by descriptor-relative metadata.
        actual_uid: u32,
    },
    /// The existing socket did not already have exact mode `0600`.
    WrongMode {
        /// Permission and special-mode bits reported by metadata.
        actual_mode: u32,
    },
    /// The mandatory metadata recheck failed before unlink.
    RecheckFailed,
    /// The pathname disappeared or changed identity before unlink.
    ChangedBeforeUnlink,
    /// Descriptor-relative unlink of an unchanged trusted-shape socket failed.
    UnlinkFailed,
    /// Post-unlink metadata verification failed for a reason other than absence.
    VerificationFailed,
    /// An object remained or reappeared at the fixed pathname after unlink.
    PathStillPresent,
}

/// Prepares the fixed Agent socket pathname for a future bind.
///
/// The supplied [`AgentInstanceLock`] is a mandatory type-level proof that this
/// process owns the Phase 064 lifecycle authority while classification and any
/// stale unlink occur.
///
/// # Errors
///
/// Returns a bounded [`AgentSocketPathPreparationError`] for untrusted object
/// shape/ownership/mode, metadata errors, identity changes, unlink failure, or
/// failed absence verification.
pub fn prepare_agent_socket_path_for_bind(
    runtime_directory: &ValidatedPrwRuntimeDirectory,
    _instance_lock: &AgentInstanceLock,
) -> Result<AgentSocketPathPreparationOutcome, AgentSocketPathPreparationError> {
    let initial = match statat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => metadata,
        Err(error) if error == Errno::NOENT => {
            return Ok(AgentSocketPathPreparationOutcome::AlreadyAbsent);
        }
        Err(_) => return Err(AgentSocketPathPreparationError::MetadataReadFailed),
    };

    validate_stale_socket_candidate(&initial, effective_agent_uid())?;

    let rechecked = match statat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => metadata,
        Err(error) if error == Errno::NOENT => {
            return Err(AgentSocketPathPreparationError::ChangedBeforeUnlink);
        }
        Err(_) => return Err(AgentSocketPathPreparationError::RecheckFailed),
    };

    if !same_stale_socket_identity(&initial, &rechecked) {
        return Err(AgentSocketPathPreparationError::ChangedBeforeUnlink);
    }

    unlinkat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::empty(),
    )
    .map_err(|_| AgentSocketPathPreparationError::UnlinkFailed)?;

    match statat(
        runtime_directory.as_fd(),
        AGENT_SOCKET_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(error) if error == Errno::NOENT => {
            Ok(AgentSocketPathPreparationOutcome::StaleSocketRemoved)
        }
        Ok(_) => Err(AgentSocketPathPreparationError::PathStillPresent),
        Err(_) => Err(AgentSocketPathPreparationError::VerificationFailed),
    }
}

fn validate_stale_socket_candidate(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), AgentSocketPathPreparationError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_socket() {
        return Err(AgentSocketPathPreparationError::NotSocket);
    }

    if metadata.st_uid != expected_uid {
        return Err(AgentSocketPathPreparationError::WrongOwner {
            expected_uid,
            actual_uid: metadata.st_uid,
        });
    }

    let actual_mode = Mode::from_raw_mode(metadata.st_mode).bits();
    if actual_mode != AGENT_SOCKET_MODE {
        return Err(AgentSocketPathPreparationError::WrongMode { actual_mode });
    }

    Ok(())
}

fn same_stale_socket_identity(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && FileType::from_raw_mode(first.st_mode).is_socket()
        && FileType::from_raw_mode(second.st_mode).is_socket()
        && Mode::from_raw_mode(first.st_mode).bits() == Mode::from_raw_mode(second.st_mode).bits()
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, Permissions};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{AtFlags, statat};

    use super::{
        AgentSocketPathPreparationError, AgentSocketPathPreparationOutcome,
        prepare_agent_socket_path_for_bind, same_stale_socket_identity,
        validate_stale_socket_candidate,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-066-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 066 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 066 directory mode sets");
    }

    fn create_authorized_runtime(
        label: &str,
    ) -> (
        PathBuf,
        super::super::super::ValidatedPrwRuntimeDirectory,
        super::super::AgentInstanceLock,
    ) {
        let root_path = unique_temp_path(label);
        create_directory_with_mode(&root_path, 0o700);
        let root = super::super::super::super::validate_xdg_runtime_root_path(&root_path)
            .expect("temporary root satisfies Phase 062 validation");
        let runtime_directory = super::super::super::prepare_prw_runtime_directory(&root)
            .expect("temporary PRW directory satisfies Phase 063 preparation");
        drop(root);
        let instance_lock = super::super::acquire_agent_instance_lock(&runtime_directory)
            .expect("temporary lifecycle authority satisfies Phase 065");
        (root_path, runtime_directory, instance_lock)
    }

    fn agent_socket_path(root_path: &Path) -> PathBuf {
        root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    fn bind_socket_with_mode(path: &Path, mode: u32) -> UnixListener {
        let listener = UnixListener::bind(path).expect("temporary pathname Unix socket binds");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary socket mode sets");
        listener
    }

    #[test]
    fn missing_socket_path_is_already_absent() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("absent");

        assert_eq!(
            prepare_agent_socket_path_for_bind(&runtime_directory, &instance_lock)
                .expect("missing socket path is ready"),
            AgentSocketPathPreparationOutcome::AlreadyAbsent
        );

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn trusted_shape_stale_socket_is_removed_and_absence_verified() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("stale");
        let socket_path = agent_socket_path(&root_path);
        let listener = bind_socket_with_mode(&socket_path, 0o600);
        drop(listener);

        assert_eq!(
            prepare_agent_socket_path_for_bind(&runtime_directory, &instance_lock)
                .expect("trusted stale socket removes"),
            AgentSocketPathPreparationOutcome::StaleSocketRemoved
        );
        assert!(!socket_path.exists());

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn symlink_socket_path_fails_closed_and_target_is_unchanged() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("symlink");
        let socket_path = agent_socket_path(&root_path);
        let target_path = unique_temp_path("symlink-target");
        File::create(&target_path).expect("temporary target creates");
        fs::set_permissions(&target_path, Permissions::from_mode(0o644))
            .expect("temporary target mode sets");
        symlink(&target_path, &socket_path).expect("temporary agent.sock symlink creates");

        assert_eq!(
            prepare_agent_socket_path_for_bind(&runtime_directory, &instance_lock).unwrap_err(),
            AgentSocketPathPreparationError::NotSocket
        );
        assert_eq!(
            fs::metadata(&target_path)
                .expect("target metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("symlink remains")
                .file_type()
                .is_symlink()
        );

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("temporary symlink removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
        fs::remove_file(&target_path).expect("temporary target removes");
    }

    #[test]
    fn regular_file_socket_path_fails_closed_and_remains() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("file");
        let socket_path = agent_socket_path(&root_path);
        File::create(&socket_path).expect("temporary regular agent.sock creates");

        assert_eq!(
            prepare_agent_socket_path_for_bind(&runtime_directory, &instance_lock).unwrap_err(),
            AgentSocketPathPreparationError::NotSocket
        );
        assert!(socket_path.is_file());

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("temporary file removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn wrong_mode_socket_fails_closed_and_remains() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("mode");
        let socket_path = agent_socket_path(&root_path);
        let listener = bind_socket_with_mode(&socket_path, 0o660);
        drop(listener);

        assert_eq!(
            prepare_agent_socket_path_for_bind(&runtime_directory, &instance_lock).unwrap_err(),
            AgentSocketPathPreparationError::WrongMode { actual_mode: 0o660 }
        );
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("wrong-mode socket remains")
                .file_type()
                .is_socket()
        );

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("temporary socket removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn wrong_owner_metadata_classification_fails_closed() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("owner");
        let socket_path = agent_socket_path(&root_path);
        let listener = bind_socket_with_mode(&socket_path, 0o600);
        let metadata = statat(
            runtime_directory.as_fd(),
            AGENT_SOCKET_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("temporary socket metadata reads");
        let non_matching_uid = metadata.st_uid.wrapping_add(1);

        assert_eq!(
            validate_stale_socket_candidate(&metadata, non_matching_uid),
            Err(AgentSocketPathPreparationError::WrongOwner {
                expected_uid: non_matching_uid,
                actual_uid: metadata.st_uid,
            })
        );

        drop(listener);
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("temporary socket removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn distinct_socket_nodes_do_not_match_stale_identity() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("identity");
        let socket_path = agent_socket_path(&root_path);
        let other_path = root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join("other.sock");
        let first_listener = bind_socket_with_mode(&socket_path, 0o600);
        let second_listener = bind_socket_with_mode(&other_path, 0o600);
        let first = statat(
            runtime_directory.as_fd(),
            AGENT_SOCKET_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("first socket metadata reads");
        let second = statat(
            runtime_directory.as_fd(),
            "other.sock",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("second socket metadata reads");

        assert!(!same_stale_socket_identity(&first, &second));

        drop(first_listener);
        drop(second_listener);
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_file(&socket_path).expect("first temporary socket removes");
        fs::remove_file(&other_path).expect("second temporary socket removes");
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn second_lifecycle_authority_is_rejected_before_socket_path_work() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("authority");

        assert_eq!(
            super::super::acquire_agent_instance_lock(&runtime_directory).unwrap_err(),
            super::super::AgentInstanceLockError::AlreadyRunning
        );

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }
}
