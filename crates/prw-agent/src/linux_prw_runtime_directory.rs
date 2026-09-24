//! Descriptor-anchored preparation of the PRW-owned Linux runtime directory.
//!
//! Phase 063 may create or normalize only the fixed PRW child beneath an
//! already-validated Phase 062 XDG runtime-root descriptor. It never touches
//! the future `agent.sock` pathname.

#[allow(
    dead_code,
    reason = "pre-runtime Agent instance lock is intentionally crate-internal"
)]
#[path = "linux_agent_instance_lock.rs"]
pub mod agent_instance_lock;

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags, Stat, fchmod, fstat, mkdirat, openat};
use rustix::io::Errno;

use super::ValidatedXdgRuntimeRoot;
use crate::linux_identity::effective_agent_uid;
use crate::{AGENT_RUNTIME_DIRECTORY_MODE, AGENT_RUNTIME_SUBDIRECTORY};

/// An opened PRW runtime directory validated relative to its Phase 062 root.
#[derive(Debug)]
pub struct ValidatedPrwRuntimeDirectory {
    descriptor: OwnedFd,
}

impl AsFd for ValidatedPrwRuntimeDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Bounded failure while preparing the PRW-owned runtime directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrwRuntimeDirectoryPreparationError {
    /// The fixed child could not be created and did not already exist.
    CreateFailed,
    /// The fixed child could not be opened as a no-follow directory.
    OpenFailed,
    /// Descriptor metadata could not be queried before normalization.
    MetadataReadFailed,
    /// The opened child descriptor did not identify a directory.
    NotDirectory,
    /// The opened child owner did not match the effective Agent UID.
    WrongOwner {
        /// Effective Agent UID required by the contract.
        expected_uid: u32,
        /// UID reported by descriptor metadata.
        actual_uid: u32,
    },
    /// Exact `0700` normalization on the verified same-UID descriptor failed.
    ModeNormalizeFailed,
    /// Descriptor metadata could not be queried after mode normalization.
    RevalidationMetadataReadFailed,
    /// Revalidation observed a mode other than exact `0700`.
    WrongModeAfterNormalization {
        /// Permission and special-mode bits observed after normalization.
        actual_mode: u32,
    },
}

/// Creates or validates the fixed PRW runtime child beneath a validated XDG root.
///
/// # Errors
///
/// Returns a bounded [`PrwRuntimeDirectoryPreparationError`] if creation, the
/// descriptor-relative no-follow open, ownership validation, mode normalization,
/// or post-normalization revalidation fails.
pub fn prepare_prw_runtime_directory(
    root: &ValidatedXdgRuntimeRoot,
) -> Result<ValidatedPrwRuntimeDirectory, PrwRuntimeDirectoryPreparationError> {
    let creation = mkdirat(root.as_fd(), AGENT_RUNTIME_SUBDIRECTORY, Mode::RWXU);
    if !matches!(creation, Ok(()) | Err(Errno::EXIST)) {
        return Err(PrwRuntimeDirectoryPreparationError::CreateFailed);
    }

    let descriptor = openat(
        root.as_fd(),
        AGENT_RUNTIME_SUBDIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrwRuntimeDirectoryPreparationError::OpenFailed)?;

    let metadata =
        fstat(&descriptor).map_err(|_| PrwRuntimeDirectoryPreparationError::MetadataReadFailed)?;
    validate_child_identity(&metadata, effective_agent_uid())?;

    if Mode::from_raw_mode(metadata.st_mode).bits() != AGENT_RUNTIME_DIRECTORY_MODE {
        fchmod(&descriptor, Mode::RWXU)
            .map_err(|_| PrwRuntimeDirectoryPreparationError::ModeNormalizeFailed)?;

        let revalidated = fstat(&descriptor)
            .map_err(|_| PrwRuntimeDirectoryPreparationError::RevalidationMetadataReadFailed)?;
        validate_child_complete(&revalidated, effective_agent_uid())?;
    }

    Ok(ValidatedPrwRuntimeDirectory { descriptor })
}

fn validate_child_identity(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), PrwRuntimeDirectoryPreparationError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(PrwRuntimeDirectoryPreparationError::NotDirectory);
    }

    if metadata.st_uid != expected_uid {
        return Err(PrwRuntimeDirectoryPreparationError::WrongOwner {
            expected_uid,
            actual_uid: metadata.st_uid,
        });
    }

    Ok(())
}

fn validate_child_complete(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), PrwRuntimeDirectoryPreparationError> {
    validate_child_identity(metadata, expected_uid)?;

    let actual_mode = Mode::from_raw_mode(metadata.st_mode).bits();
    if actual_mode != AGENT_RUNTIME_DIRECTORY_MODE {
        return Err(
            PrwRuntimeDirectoryPreparationError::WrongModeAfterNormalization { actual_mode },
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, Permissions};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{Mode, OFlags, fstat, open};

    use super::{
        PrwRuntimeDirectoryPreparationError, prepare_prw_runtime_directory, validate_child_identity,
    };
    use crate::AGENT_RUNTIME_SUBDIRECTORY;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-063-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 063 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 063 directory mode sets");
    }

    fn create_validated_root(label: &str) -> (PathBuf, super::ValidatedXdgRuntimeRoot) {
        let root_path = unique_temp_path(label);
        create_directory_with_mode(&root_path, 0o700);
        let root = super::super::validate_xdg_runtime_root_path(&root_path)
            .expect("temporary root satisfies Phase 062 validation");
        (root_path, root)
    }

    #[test]
    fn absent_child_is_created_and_validated_at_0700() {
        let (root_path, root) = create_validated_root("create");

        let child = prepare_prw_runtime_directory(&root).expect("PRW child prepares");
        let metadata = fstat(child.as_fd()).expect("prepared child metadata reads");
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o700);
        assert!(root_path.join(AGENT_RUNTIME_SUBDIRECTORY).is_dir());

        drop(child);
        drop(root);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn same_uid_wrong_mode_child_is_normalized_to_exact_0700() {
        let (root_path, root) = create_validated_root("normalize");
        let child_path = root_path.join(AGENT_RUNTIME_SUBDIRECTORY);
        create_directory_with_mode(&child_path, 0o755);

        let child = prepare_prw_runtime_directory(&root).expect("same-UID child normalizes");
        let metadata = fstat(child.as_fd()).expect("normalized child metadata reads");
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o700);
        assert_eq!(
            fs::metadata(&child_path)
                .expect("normalized child pathname metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        drop(child);
        drop(root);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn symlink_child_fails_closed() {
        let (root_path, root) = create_validated_root("symlink");
        let target = unique_temp_path("symlink-target");
        create_directory_with_mode(&target, 0o700);
        let child_path = root_path.join(AGENT_RUNTIME_SUBDIRECTORY);
        symlink(&target, &child_path).expect("temporary child symlink creates");

        assert_eq!(
            prepare_prw_runtime_directory(&root).unwrap_err(),
            PrwRuntimeDirectoryPreparationError::OpenFailed
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("symlink target metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        drop(root);
        fs::remove_file(&child_path).expect("temporary child symlink removes");
        fs::remove_dir(&root_path).expect("temporary root removes");
        fs::remove_dir(&target).expect("temporary target removes");
    }

    #[test]
    fn regular_file_child_fails_closed() {
        let (root_path, root) = create_validated_root("regular-file");
        let child_path = root_path.join(AGENT_RUNTIME_SUBDIRECTORY);
        File::create(&child_path).expect("temporary regular child creates");

        assert_eq!(
            prepare_prw_runtime_directory(&root).unwrap_err(),
            PrwRuntimeDirectoryPreparationError::OpenFailed
        );

        drop(root);
        fs::remove_file(&child_path).expect("temporary regular child removes");
        fs::remove_dir(&root_path).expect("temporary root removes");
    }

    #[test]
    fn wrong_owner_metadata_is_rejected_before_mode_policy() {
        let child_path = unique_temp_path("wrong-owner-classification");
        create_directory_with_mode(&child_path, 0o755);
        let descriptor = open(
            &child_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("temporary child opens");
        let metadata = fstat(&descriptor).expect("temporary child metadata reads");
        let non_matching_uid = metadata.st_uid.wrapping_add(1);

        assert_eq!(
            validate_child_identity(&metadata, non_matching_uid),
            Err(PrwRuntimeDirectoryPreparationError::WrongOwner {
                expected_uid: non_matching_uid,
                actual_uid: metadata.st_uid,
            })
        );
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o755);

        drop(descriptor);
        fs::remove_dir(&child_path).expect("temporary child removes");
    }

    #[test]
    fn child_resolution_remains_anchored_to_validated_root_descriptor() {
        let (root_path, root) = create_validated_root("anchor-original");
        let renamed_root = unique_temp_path("anchor-renamed");
        fs::rename(&root_path, &renamed_root).expect("validated root pathname renames");
        create_directory_with_mode(&root_path, 0o700);

        let child = prepare_prw_runtime_directory(&root).expect("anchored child prepares");

        assert!(renamed_root.join(AGENT_RUNTIME_SUBDIRECTORY).is_dir());
        assert!(!root_path.join(AGENT_RUNTIME_SUBDIRECTORY).exists());

        drop(child);
        drop(root);
        fs::remove_dir(&root_path).expect("replacement root removes");
        fs::remove_dir_all(&renamed_root).expect("renamed validated root removes");
    }
}
