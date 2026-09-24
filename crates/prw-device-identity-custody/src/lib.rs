//! Ubuntu systemd service-credential adapter for PRW device identity.
//!
//! This crate owns only the runtime custody-acquisition boundary. It does not
//! provision encrypted credentials, create device keys, modify systemd units,
//! read persistent plaintext key files, or expose generic signing operations.

use std::fmt;

use prw_device_identity_signer::{UbuntuEnrollmentSigner, UbuntuEnrollmentSignerError};

/// Exact Phase 118 systemd service-visible device-identity credential name.
pub const SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME: &str = "prw.device-identity.private-key.v1";

/// Environment variable through which systemd exposes the service credential directory.
pub const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// Failure while acquiring the Ubuntu device-identity signer from systemd custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UbuntuDeviceIdentityCustodyError {
    /// This adapter is available only on Linux hosts.
    UnsupportedPlatform,
    /// systemd did not provide a credential-directory environment value.
    CredentialsDirectoryMissing,
    /// The supplied credential-directory value was not an absolute valid directory boundary.
    CredentialsDirectoryInvalid,
    /// The credential directory failed the locked ownership or permission checks.
    CredentialsDirectoryNotSecure,
    /// The exact locked credential name was absent or could not be opened safely.
    CredentialUnavailable,
    /// The locked credential path did not resolve to one stable regular file.
    CredentialNotRegular,
    /// The credential was not owned by the effective service user.
    CredentialOwnershipMismatch,
    /// The credential permissions violated the locked runtime safety checks.
    CredentialPermissionsInsecure,
    /// The credential could not be read completely through the bounded reader.
    CredentialReadFailed,
    /// The credential was empty or exceeded the signer input bound.
    CredentialSizeOutOfBounds,
    /// The bounded credential reached signer parsing but violated the signer contract.
    Signer(UbuntuEnrollmentSignerError),
}

impl fmt::Display for UbuntuDeviceIdentityCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("unsupported custody platform"),
            Self::CredentialsDirectoryMissing => {
                formatter.write_str("systemd credential directory is unavailable")
            }
            Self::CredentialsDirectoryInvalid => {
                formatter.write_str("systemd credential directory is invalid")
            }
            Self::CredentialsDirectoryNotSecure => {
                formatter.write_str("systemd credential directory is not secure")
            }
            Self::CredentialUnavailable => {
                formatter.write_str("device identity credential is unavailable")
            }
            Self::CredentialNotRegular => {
                formatter.write_str("device identity credential is not a regular file")
            }
            Self::CredentialOwnershipMismatch => {
                formatter.write_str("device identity credential ownership mismatch")
            }
            Self::CredentialPermissionsInsecure => {
                formatter.write_str("device identity credential permissions are insecure")
            }
            Self::CredentialReadFailed => {
                formatter.write_str("device identity credential read failed")
            }
            Self::CredentialSizeOutOfBounds => {
                formatter.write_str("device identity credential size out of bounds")
            }
            Self::Signer(error) => write!(formatter, "device identity signer load failed: {error}"),
        }
    }
}

impl std::error::Error for UbuntuDeviceIdentityCustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signer(error) => Some(error),
            _ => None,
        }
    }
}

/// Loads the Ubuntu enrollment signer from the exact systemd-delivered credential.
///
/// The function reads only the fixed Phase 118 credential name relative to
/// `$CREDENTIALS_DIRECTORY`. The plaintext credential is held in a zeroizing
/// temporary buffer and is dropped immediately after signer construction succeeds
/// or fails. No fallback persistent plaintext path is consulted.
///
/// # Errors
///
/// Returns [`UbuntuDeviceIdentityCustodyError`] when the platform, systemd runtime
/// boundary, file shape, ownership, permissions, bounded read, or signer contract
/// fails validation.
pub fn load_ubuntu_enrollment_signer_from_systemd_credential()
-> Result<UbuntuEnrollmentSigner, UbuntuDeviceIdentityCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(UbuntuDeviceIdentityCustodyError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env,
        ffi::OsString,
        fs::{self, File},
        io::{self, Read},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    use prw_device_identity_signer::{
        MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES, UbuntuEnrollmentSigner,
    };
    use rustix::{
        fs::{Mode, OFlags, open},
        process::geteuid,
    };
    use zeroize::Zeroizing;

    use super::{
        SYSTEMD_CREDENTIALS_DIRECTORY_ENV, SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME,
        UbuntuDeviceIdentityCustodyError,
    };

    const INSECURE_WRITE_BITS: u32 = 0o022;
    const EXECUTE_BITS: u32 = 0o111;
    const OWNER_READ_BIT: u32 = 0o400;
    const OWNER_DIRECTORY_ACCESS_BITS: u32 = 0o500;

    pub fn load_from_environment()
    -> Result<UbuntuEnrollmentSigner, UbuntuDeviceIdentityCustodyError> {
        let directory =
            credentials_directory_from_value(env::var_os(SYSTEMD_CREDENTIALS_DIRECTORY_ENV))?;
        load_from_credentials_directory(&directory)
    }

    fn credentials_directory_from_value(
        value: Option<OsString>,
    ) -> Result<PathBuf, UbuntuDeviceIdentityCustodyError> {
        let value = value.ok_or(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryMissing)?;
        if value.is_empty() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryMissing);
        }

        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid);
        }
        Ok(path)
    }

    fn load_from_credentials_directory(
        directory: &Path,
    ) -> Result<UbuntuEnrollmentSigner, UbuntuDeviceIdentityCustodyError> {
        validate_credentials_directory(directory)?;

        let credential_path = directory.join(SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME);
        let pre_open_metadata = match fs::symlink_metadata(&credential_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UbuntuDeviceIdentityCustodyError::CredentialUnavailable);
            }
            Err(_) => return Err(UbuntuDeviceIdentityCustodyError::CredentialUnavailable),
        };
        if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.file_type().is_file() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&pre_open_metadata)?;
        if pre_open_metadata.len() > MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES as u64 {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialSizeOutOfBounds);
        }

        let owned_fd = open(
            &credential_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| UbuntuDeviceIdentityCustodyError::CredentialUnavailable)?;
        let mut file = File::from(owned_fd);
        let opened_metadata = file
            .metadata()
            .map_err(|_| UbuntuDeviceIdentityCustodyError::CredentialUnavailable)?;
        if !opened_metadata.file_type().is_file() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialNotRegular);
        }
        if pre_open_metadata.dev() != opened_metadata.dev()
            || pre_open_metadata.ino() != opened_metadata.ino()
        {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&opened_metadata)?;

        let credential = read_bounded(&mut file)?;
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(credential.as_ref())
            .map_err(UbuntuDeviceIdentityCustodyError::Signer)
    }

    fn validate_credentials_directory(
        directory: &Path,
    ) -> Result<(), UbuntuDeviceIdentityCustodyError> {
        if !directory.is_absolute() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid);
        }

        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryMissing);
            }
            Err(_) => return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid);
        }

        let current_uid = geteuid().as_raw();
        let mode = metadata.mode();
        if metadata.uid() != current_uid
            || mode & INSECURE_WRITE_BITS != 0
            || mode & OWNER_DIRECTORY_ACCESS_BITS != OWNER_DIRECTORY_ACCESS_BITS
        {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialsDirectoryNotSecure);
        }
        Ok(())
    }

    fn validate_credential_metadata(
        metadata: &fs::Metadata,
    ) -> Result<(), UbuntuDeviceIdentityCustodyError> {
        if metadata.uid() != geteuid().as_raw() {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialOwnershipMismatch);
        }

        let mode = metadata.mode();
        if mode & INSECURE_WRITE_BITS != 0 || mode & EXECUTE_BITS != 0 || mode & OWNER_READ_BIT == 0
        {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialPermissionsInsecure);
        }
        Ok(())
    }

    fn read_bounded<R: Read>(
        reader: &mut R,
    ) -> Result<Zeroizing<Vec<u8>>, UbuntuDeviceIdentityCustodyError> {
        let mut credential = Zeroizing::new(Vec::new());
        let mut limited = reader.take((MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES + 1) as u64);
        limited
            .read_to_end(&mut credential)
            .map_err(|_| UbuntuDeviceIdentityCustodyError::CredentialReadFailed)?;
        if credential.is_empty() || credential.len() > MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES {
            return Err(UbuntuDeviceIdentityCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(credential)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            io::{self, Read},
            os::unix::fs::{PermissionsExt, symlink},
            path::{Path, PathBuf},
            process,
            sync::atomic::{AtomicU64, Ordering},
        };

        use aws_lc_rs::{
            rand::SystemRandom,
            signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
        };
        use prw_device_identity_signer::UbuntuEnrollmentSignerError;

        use super::{
            SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME, UbuntuDeviceIdentityCustodyError,
            credentials_directory_from_value, load_from_credentials_directory, read_bounded,
        };

        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

        struct TestDirectory {
            path: PathBuf,
        }

        impl TestDirectory {
            fn new() -> Self {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("prw-phase122-{}-{id}", process::id()));
                fs::create_dir(&path).expect("create isolated Phase 122 test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure test directory mode");
                Self { path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn credential_path(&self) -> PathBuf {
                self.path.join(SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME)
            }

            fn write_credential(&self, bytes: &[u8]) {
                fs::write(self.credential_path(), bytes).expect("write test credential");
                fs::set_permissions(self.credential_path(), fs::Permissions::from_mode(0o400))
                    .expect("secure test credential mode");
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        fn generate_p256_pkcs8() -> Vec<u8> {
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable P-256 credential")
                .as_ref()
                .to_vec()
        }

        #[test]
        fn environment_value_requires_present_absolute_directory() {
            assert_eq!(
                credentials_directory_from_value(None).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialsDirectoryMissing
            );
            assert_eq!(
                credentials_directory_from_value(Some("relative/path".into())).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid
            );
        }

        #[test]
        fn exact_named_secure_credential_loads_signer() {
            let directory = TestDirectory::new();
            directory.write_credential(&generate_p256_pkcs8());

            let signer = load_from_credentials_directory(directory.path()).expect("load signer");
            assert!(!signer.public_identity().as_bytes().is_empty());
        }

        #[test]
        fn wrong_filename_does_not_fallback() {
            let directory = TestDirectory::new();
            fs::write(directory.path().join("private-key"), generate_p256_pkcs8())
                .expect("write alternate test file");

            assert_eq!(
                load_from_credentials_directory(directory.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialUnavailable
            );
        }

        #[test]
        fn credential_directory_symlink_is_rejected() {
            let real_directory = TestDirectory::new();
            real_directory.write_credential(&generate_p256_pkcs8());
            let link_parent = TestDirectory::new();
            let link = link_parent.path().join("credentials-link");
            symlink(real_directory.path(), &link).expect("create directory symlink");

            assert_eq!(
                load_from_credentials_directory(&link).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialsDirectoryInvalid
            );
        }

        #[test]
        fn credential_symlink_and_non_regular_file_are_rejected() {
            let symlink_directory = TestDirectory::new();
            let target = symlink_directory.path().join("target");
            fs::write(&target, generate_p256_pkcs8()).expect("write symlink target");
            symlink(&target, symlink_directory.credential_path())
                .expect("create credential symlink");
            assert_eq!(
                load_from_credentials_directory(symlink_directory.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialNotRegular
            );

            let directory_credential = TestDirectory::new();
            fs::create_dir(directory_credential.credential_path())
                .expect("create non-regular credential path");
            assert_eq!(
                load_from_credentials_directory(directory_credential.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialNotRegular
            );
        }

        #[test]
        fn insecure_directory_or_credential_modes_are_rejected() {
            let insecure_directory = TestDirectory::new();
            insecure_directory.write_credential(&generate_p256_pkcs8());
            fs::set_permissions(insecure_directory.path(), fs::Permissions::from_mode(0o722))
                .expect("set insecure directory mode");
            assert_eq!(
                load_from_credentials_directory(insecure_directory.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialsDirectoryNotSecure
            );

            let insecure_credential = TestDirectory::new();
            insecure_credential.write_credential(&generate_p256_pkcs8());
            fs::set_permissions(
                insecure_credential.credential_path(),
                fs::Permissions::from_mode(0o600 | 0o020),
            )
            .expect("set insecure credential mode");
            assert_eq!(
                load_from_credentials_directory(insecure_credential.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialPermissionsInsecure
            );
        }

        #[test]
        fn empty_oversized_and_trailing_content_fail_closed() {
            let empty = TestDirectory::new();
            empty.write_credential(&[]);
            assert_eq!(
                load_from_credentials_directory(empty.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialSizeOutOfBounds
            );

            let oversized = TestDirectory::new();
            oversized.write_credential(&vec![0x5a; 4097]);
            assert_eq!(
                load_from_credentials_directory(oversized.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialSizeOutOfBounds
            );

            let trailing = TestDirectory::new();
            let mut payload = generate_p256_pkcs8();
            payload.push(b'\n');
            trailing.write_credential(&payload);
            assert_eq!(
                load_from_credentials_directory(trailing.path()).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::Signer(
                    UbuntuEnrollmentSignerError::InvalidPrivateCredential
                )
            );
        }

        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected read failure"))
            }
        }

        #[test]
        fn bounded_reader_maps_read_failure_without_secret_data() {
            assert_eq!(
                read_bounded(&mut FailingReader).unwrap_err(),
                UbuntuDeviceIdentityCustodyError::CredentialReadFailed
            );
        }
    }
}
