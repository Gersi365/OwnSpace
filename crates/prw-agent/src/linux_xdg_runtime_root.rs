//! Read-only Linux `$XDG_RUNTIME_DIR` root validation.
//!
//! Phase 062 implements only the root-validation portion of the Phase 061
//! security algorithm. Production code performs no filesystem mutation.

#[allow(
    dead_code,
    reason = "pre-runtime PRW runtime-directory preparation is intentionally crate-internal"
)]
#[path = "linux_prw_runtime_directory.rs"]
pub mod prw_runtime_directory;

use std::env;
use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, open};

use crate::AGENT_RUNTIME_DIRECTORY_MODE;
use crate::linux_identity::effective_agent_uid;

/// An opened XDG runtime root proven to satisfy the Phase 061 root baseline.
#[derive(Debug)]
pub struct ValidatedXdgRuntimeRoot {
    descriptor: OwnedFd,
}

impl AsFd for ValidatedXdgRuntimeRoot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Bounded failure while validating the Linux XDG runtime root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdgRuntimeRootValidationError {
    /// `XDG_RUNTIME_DIR` was not present in the process environment.
    MissingEnvironmentValue,
    /// `XDG_RUNTIME_DIR` was present but empty.
    EmptyEnvironmentValue,
    /// `XDG_RUNTIME_DIR` did not contain an absolute path.
    RelativePath,
    /// The root could not be opened with the required descriptor semantics.
    OpenFailed,
    /// Metadata could not be queried from the opened descriptor.
    MetadataReadFailed,
    /// The opened descriptor did not identify a directory.
    NotDirectory,
    /// The descriptor owner did not match the effective Agent UID.
    WrongOwner {
        /// Effective Agent UID required by the contract.
        expected_uid: u32,
        /// UID reported by descriptor metadata.
        actual_uid: u32,
    },
    /// The runtime root did not have exact security mode `0700`.
    WrongMode {
        /// Permission and special-mode bits reported by descriptor metadata.
        actual_mode: u32,
    },
}

/// Reads and validates the process `XDG_RUNTIME_DIR` value.
///
/// # Errors
///
/// Returns a bounded [`XdgRuntimeRootValidationError`] when the value is absent,
/// malformed, cannot be opened safely, or fails descriptor metadata checks.
pub fn validate_xdg_runtime_root_from_env()
-> Result<ValidatedXdgRuntimeRoot, XdgRuntimeRootValidationError> {
    let value = env::var_os("XDG_RUNTIME_DIR");
    validate_xdg_runtime_root_value(value.as_deref())
}

fn validate_xdg_runtime_root_value(
    value: Option<&OsStr>,
) -> Result<ValidatedXdgRuntimeRoot, XdgRuntimeRootValidationError> {
    let value = value.ok_or(XdgRuntimeRootValidationError::MissingEnvironmentValue)?;
    if value.is_empty() {
        return Err(XdgRuntimeRootValidationError::EmptyEnvironmentValue);
    }

    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(XdgRuntimeRootValidationError::RelativePath);
    }

    validate_xdg_runtime_root_path(path)
}

/// Validates one already-resolved absolute runtime-root path within the Linux module.
pub(super) fn validate_xdg_runtime_root_path(
    path: &Path,
) -> Result<ValidatedXdgRuntimeRoot, XdgRuntimeRootValidationError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XdgRuntimeRootValidationError::OpenFailed)?;

    let metadata =
        fstat(&descriptor).map_err(|_| XdgRuntimeRootValidationError::MetadataReadFailed)?;
    validate_descriptor_metadata(&metadata, effective_agent_uid())?;

    Ok(ValidatedXdgRuntimeRoot { descriptor })
}

fn validate_descriptor_metadata(
    metadata: &Stat,
    expected_uid: u32,
) -> Result<(), XdgRuntimeRootValidationError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(XdgRuntimeRootValidationError::NotDirectory);
    }

    if metadata.st_uid != expected_uid {
        return Err(XdgRuntimeRootValidationError::WrongOwner {
            expected_uid,
            actual_uid: metadata.st_uid,
        });
    }

    let actual_mode = Mode::from_raw_mode(metadata.st_mode).bits();
    if actual_mode != AGENT_RUNTIME_DIRECTORY_MODE {
        return Err(XdgRuntimeRootValidationError::WrongMode { actual_mode });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::{self, File, Permissions};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{Mode, OFlags, fstat, open};

    use super::{
        XdgRuntimeRootValidationError, validate_descriptor_metadata,
        validate_xdg_runtime_root_path, validate_xdg_runtime_root_value,
    };
    use crate::linux_identity::effective_agent_uid;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-062-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(label: &str, mode: u32) -> PathBuf {
        let path = unique_temp_path(label);
        fs::create_dir(&path).expect("temporary Phase 062 directory creates");
        fs::set_permissions(&path, Permissions::from_mode(mode))
            .expect("temporary Phase 062 directory mode sets");
        path
    }

    #[test]
    fn valid_absolute_same_uid_0700_directory_is_accepted() {
        let path = create_directory_with_mode("valid", 0o700);

        let validated =
            validate_xdg_runtime_root_path(&path).expect("valid XDG runtime root accepts");
        let metadata = fstat(validated.as_fd()).expect("validated descriptor metadata reads");
        assert_eq!(metadata.st_uid, effective_agent_uid());
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits(), 0o700);

        drop(validated);
        fs::remove_dir(&path).expect("temporary valid root removes");
    }

    #[test]
    fn missing_empty_and_relative_values_fail_before_open() {
        assert_eq!(
            validate_xdg_runtime_root_value(None).unwrap_err(),
            XdgRuntimeRootValidationError::MissingEnvironmentValue
        );
        assert_eq!(
            validate_xdg_runtime_root_value(Some(OsStr::new(""))).unwrap_err(),
            XdgRuntimeRootValidationError::EmptyEnvironmentValue
        );
        assert_eq!(
            validate_xdg_runtime_root_value(Some(OsStr::new("relative/runtime"))).unwrap_err(),
            XdgRuntimeRootValidationError::RelativePath
        );
    }

    #[test]
    fn wrong_root_mode_fails_closed_without_repair() {
        let path = create_directory_with_mode("wrong-mode", 0o755);

        assert_eq!(
            validate_xdg_runtime_root_path(&path).unwrap_err(),
            XdgRuntimeRootValidationError::WrongMode { actual_mode: 0o755 }
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("temporary root metadata reads")
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );

        fs::remove_dir(&path).expect("temporary wrong-mode root removes");
    }

    #[test]
    fn final_component_symlink_is_rejected() {
        let target = create_directory_with_mode("symlink-target", 0o700);
        let link = unique_temp_path("symlink-root");
        symlink(&target, &link).expect("temporary root symlink creates");

        assert_eq!(
            validate_xdg_runtime_root_path(&link).unwrap_err(),
            XdgRuntimeRootValidationError::OpenFailed
        );

        fs::remove_file(&link).expect("temporary symlink removes");
        fs::remove_dir(&target).expect("temporary symlink target removes");
    }

    #[test]
    fn non_directory_is_rejected() {
        let path = unique_temp_path("regular-file");
        File::create(&path).expect("temporary regular file creates");

        assert_eq!(
            validate_xdg_runtime_root_path(&path).unwrap_err(),
            XdgRuntimeRootValidationError::OpenFailed
        );

        fs::remove_file(&path).expect("temporary regular file removes");
    }

    #[test]
    fn descriptor_metadata_wrong_owner_classification_is_fail_closed() {
        let path = create_directory_with_mode("wrong-owner-classification", 0o700);
        let descriptor = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("temporary root opens");
        let metadata = fstat(&descriptor).expect("temporary root metadata reads");
        let non_matching_uid = metadata.st_uid.wrapping_add(1);

        assert_eq!(
            validate_descriptor_metadata(&metadata, non_matching_uid),
            Err(XdgRuntimeRootValidationError::WrongOwner {
                expected_uid: non_matching_uid,
                actual_uid: metadata.st_uid,
            })
        );

        drop(descriptor);
        fs::remove_dir(&path).expect("temporary wrong-owner classification root removes");
    }
}
