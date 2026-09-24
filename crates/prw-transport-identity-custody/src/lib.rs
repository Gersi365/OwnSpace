//! Ubuntu custody adapter for the dedicated PRW transport identity.
//!
//! This crate reads only the fixed systemd-delivered transport private-key
//! credential, validates canonical P-256 PKCS#8 v1 DER, derives the public SPKI,
//! and returns the opaque PRW `TransportIdentity`. It does not create keys,
//! provision encrypted credentials, issue certificates, modify systemd, or
//! expose private-key bytes to callers.

use std::fmt;

use aws_lc_rs::{
    digest::{SHA256, digest},
    encoding::AsDer,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use prw_connectivity::TransportIdentity;

/// Exact systemd service-visible transport private-key credential name.
pub const SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME: &str =
    "prw.transport-identity.private-key.v1";
/// Environment variable through which systemd exposes service credentials.
pub const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
/// Maximum accepted plaintext transport-identity PKCS#8 credential size.
pub const MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES: usize = 4096;

/// Failure while loading or deriving the local Ubuntu transport identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UbuntuTransportIdentityCustodyError {
    /// This adapter is available only on Linux hosts.
    UnsupportedPlatform,
    /// systemd did not provide a credential-directory environment value.
    CredentialsDirectoryMissing,
    /// The supplied credential-directory value was not an absolute valid directory.
    CredentialsDirectoryInvalid,
    /// The credential directory violated the locked owner/permission boundary.
    CredentialsDirectoryNotSecure,
    /// The exact locked credential was absent or could not be opened safely.
    CredentialUnavailable,
    /// The exact credential path was not one stable regular file.
    CredentialNotRegular,
    /// The credential was not owned by the effective service user.
    CredentialOwnershipMismatch,
    /// Credential permissions violated the locked runtime boundary.
    CredentialPermissionsInsecure,
    /// The bounded credential read failed.
    CredentialReadFailed,
    /// The credential was empty or exceeded the locked size bound.
    CredentialSizeOutOfBounds,
    /// The credential was not canonical P-256 PKCS#8 v1 DER.
    InvalidPrivateCredential,
    /// The provider could not derive canonical public SPKI.
    PublicIdentityDerivationFailed,
    /// The derived SPKI digest did not satisfy the transport-identity contract.
    InvalidTransportIdentity,
}

impl fmt::Display for UbuntuTransportIdentityCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "unsupported transport identity custody platform",
            Self::CredentialsDirectoryMissing => {
                "systemd transport credential directory is unavailable"
            }
            Self::CredentialsDirectoryInvalid => {
                "systemd transport credential directory is invalid"
            }
            Self::CredentialsDirectoryNotSecure => {
                "systemd transport credential directory is not secure"
            }
            Self::CredentialUnavailable => "transport identity credential is unavailable",
            Self::CredentialNotRegular => "transport identity credential is not a regular file",
            Self::CredentialOwnershipMismatch => "transport identity credential ownership mismatch",
            Self::CredentialPermissionsInsecure => {
                "transport identity credential permissions are insecure"
            }
            Self::CredentialReadFailed => "transport identity credential read failed",
            Self::CredentialSizeOutOfBounds => "transport identity credential out of bounds",
            Self::InvalidPrivateCredential => "invalid transport identity private credential",
            Self::PublicIdentityDerivationFailed => "transport public identity derivation failed",
            Self::InvalidTransportIdentity => "derived transport identity is invalid",
        })
    }
}

impl std::error::Error for UbuntuTransportIdentityCustodyError {}

/// Derives PRW `TransportIdentity` from one canonical P-256 PKCS#8 v1 DER credential.
///
/// The credential is borrowed only for validation/derivation. No raw private-key
/// material is retained or returned.
///
/// # Errors
///
/// Rejects empty/oversized input, non-canonical or non-P-256 PKCS#8 material,
/// public-SPKI derivation failure, or an invalid derived transport identity.
pub fn derive_transport_identity_from_pkcs8_v1_der(
    credential: &[u8],
) -> Result<TransportIdentity, UbuntuTransportIdentityCustodyError> {
    if credential.is_empty() || credential.len() > MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES {
        return Err(UbuntuTransportIdentityCustodyError::CredentialSizeOutOfBounds);
    }

    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, credential)
        .map_err(|_| UbuntuTransportIdentityCustodyError::InvalidPrivateCredential)?;
    let canonical_private = key_pair
        .to_pkcs8v1()
        .map_err(|_| UbuntuTransportIdentityCustodyError::InvalidPrivateCredential)?;
    if canonical_private.as_ref() != credential {
        return Err(UbuntuTransportIdentityCustodyError::InvalidPrivateCredential);
    }

    let public_der = key_pair
        .public_key()
        .as_der()
        .map_err(|_| UbuntuTransportIdentityCustodyError::PublicIdentityDerivationFailed)?;
    let value = digest(&SHA256, public_der.as_ref());
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(value.as_ref());
    TransportIdentity::new(fingerprint)
        .map_err(|_| UbuntuTransportIdentityCustodyError::InvalidTransportIdentity)
}

/// Loads the current local Ubuntu transport identity from the fixed systemd credential.
///
/// # Errors
///
/// Fails closed on platform, credential-directory, file-shape, ownership,
/// permission, bounded-read, canonical-key, or identity-derivation failure.
pub fn load_ubuntu_transport_identity_from_systemd_credential()
-> Result<TransportIdentity, UbuntuTransportIdentityCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(UbuntuTransportIdentityCustodyError::UnsupportedPlatform)
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

    use rustix::{
        fs::{Mode, OFlags, open},
        process::geteuid,
    };
    use zeroize::Zeroizing;

    use super::{
        MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES, SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
        SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME, UbuntuTransportIdentityCustodyError,
        derive_transport_identity_from_pkcs8_v1_der,
    };
    use prw_connectivity::TransportIdentity;

    const INSECURE_WRITE_BITS: u32 = 0o022;
    const EXECUTE_BITS: u32 = 0o111;
    const OWNER_READ_BIT: u32 = 0o400;
    const OWNER_DIRECTORY_ACCESS_BITS: u32 = 0o500;

    pub fn load_from_environment() -> Result<TransportIdentity, UbuntuTransportIdentityCustodyError>
    {
        let directory =
            credentials_directory_from_value(env::var_os(SYSTEMD_CREDENTIALS_DIRECTORY_ENV))?;
        load_from_credentials_directory(&directory)
    }

    fn credentials_directory_from_value(
        value: Option<OsString>,
    ) -> Result<PathBuf, UbuntuTransportIdentityCustodyError> {
        let value =
            value.ok_or(UbuntuTransportIdentityCustodyError::CredentialsDirectoryMissing)?;
        if value.is_empty() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryMissing);
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryInvalid);
        }
        Ok(path)
    }

    fn load_from_credentials_directory(
        directory: &Path,
    ) -> Result<TransportIdentity, UbuntuTransportIdentityCustodyError> {
        validate_credentials_directory(directory)?;

        let credential_path = directory.join(SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME);
        let pre_open_metadata = match fs::symlink_metadata(&credential_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UbuntuTransportIdentityCustodyError::CredentialUnavailable);
            }
            Err(_) => return Err(UbuntuTransportIdentityCustodyError::CredentialUnavailable),
        };
        if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.file_type().is_file() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&pre_open_metadata)?;
        if pre_open_metadata.len() > MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES as u64 {
            return Err(UbuntuTransportIdentityCustodyError::CredentialSizeOutOfBounds);
        }

        let owned_fd = open(
            &credential_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| UbuntuTransportIdentityCustodyError::CredentialUnavailable)?;
        let mut file = File::from(owned_fd);
        let opened_metadata = file
            .metadata()
            .map_err(|_| UbuntuTransportIdentityCustodyError::CredentialUnavailable)?;
        if !opened_metadata.file_type().is_file() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialNotRegular);
        }
        if pre_open_metadata.dev() != opened_metadata.dev()
            || pre_open_metadata.ino() != opened_metadata.ino()
        {
            return Err(UbuntuTransportIdentityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&opened_metadata)?;

        let credential = read_bounded(&mut file)?;
        derive_transport_identity_from_pkcs8_v1_der(credential.as_ref())
    }

    fn validate_credentials_directory(
        directory: &Path,
    ) -> Result<(), UbuntuTransportIdentityCustodyError> {
        if !directory.is_absolute() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryInvalid);
        }
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryMissing);
            }
            Err(_) => return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryInvalid),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryInvalid);
        }
        let mode = metadata.mode();
        if metadata.uid() != geteuid().as_raw()
            || mode & INSECURE_WRITE_BITS != 0
            || mode & OWNER_DIRECTORY_ACCESS_BITS != OWNER_DIRECTORY_ACCESS_BITS
        {
            return Err(UbuntuTransportIdentityCustodyError::CredentialsDirectoryNotSecure);
        }
        Ok(())
    }

    fn validate_credential_metadata(
        metadata: &fs::Metadata,
    ) -> Result<(), UbuntuTransportIdentityCustodyError> {
        if metadata.uid() != geteuid().as_raw() {
            return Err(UbuntuTransportIdentityCustodyError::CredentialOwnershipMismatch);
        }
        let mode = metadata.mode();
        if mode & INSECURE_WRITE_BITS != 0 || mode & EXECUTE_BITS != 0 || mode & OWNER_READ_BIT == 0
        {
            return Err(UbuntuTransportIdentityCustodyError::CredentialPermissionsInsecure);
        }
        Ok(())
    }

    fn read_bounded<R: Read>(
        reader: &mut R,
    ) -> Result<Zeroizing<Vec<u8>>, UbuntuTransportIdentityCustodyError> {
        let mut credential = Zeroizing::new(Vec::new());
        let mut limited = reader.take((MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES + 1) as u64);
        limited
            .read_to_end(&mut credential)
            .map_err(|_| UbuntuTransportIdentityCustodyError::CredentialReadFailed)?;
        if credential.is_empty() || credential.len() > MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES {
            return Err(UbuntuTransportIdentityCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(credential)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
            path::{Path, PathBuf},
            process,
            sync::atomic::{AtomicU64, Ordering},
        };

        use aws_lc_rs::{
            rand::SystemRandom,
            signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
        };

        use super::{
            SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME, UbuntuTransportIdentityCustodyError,
            load_from_credentials_directory,
        };

        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

        struct TestDirectory {
            path: PathBuf,
        }

        impl TestDirectory {
            fn new() -> Self {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("prw-c03e-yp-transport-{}-{id}", process::id()));
                fs::create_dir(&path).expect("create isolated transport custody test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure test directory");
                Self { path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn credential_path(&self) -> PathBuf {
                self.path.join(SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME)
            }

            fn write_credential(&self, bytes: &[u8]) {
                fs::write(self.credential_path(), bytes).expect("write disposable credential");
                fs::set_permissions(self.credential_path(), fs::Permissions::from_mode(0o400))
                    .expect("secure disposable credential");
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        fn generate_p256_pkcs8() -> Vec<u8> {
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable transport key")
                .as_ref()
                .to_vec()
        }

        #[test]
        fn exact_secure_transport_credential_derives_stable_nonzero_identity() {
            let directory = TestDirectory::new();
            let credential = generate_p256_pkcs8();
            directory.write_credential(&credential);

            let first =
                load_from_credentials_directory(directory.path()).expect("load transport identity");
            let second = load_from_credentials_directory(directory.path())
                .expect("reload transport identity");
            assert_eq!(first, second);
            assert_ne!(first.as_bytes(), &[0_u8; 32]);
        }

        #[test]
        fn wrong_name_and_symlink_do_not_fallback() {
            let wrong_name = TestDirectory::new();
            fs::write(wrong_name.path().join("private-key"), generate_p256_pkcs8())
                .expect("write alternate file");
            assert_eq!(
                load_from_credentials_directory(wrong_name.path()).unwrap_err(),
                UbuntuTransportIdentityCustodyError::CredentialUnavailable
            );

            let symlink_directory = TestDirectory::new();
            let target = symlink_directory.path().join("target");
            fs::write(&target, generate_p256_pkcs8()).expect("write symlink target");
            symlink(&target, symlink_directory.credential_path())
                .expect("create credential symlink");
            assert_eq!(
                load_from_credentials_directory(symlink_directory.path()).unwrap_err(),
                UbuntuTransportIdentityCustodyError::CredentialNotRegular
            );
        }

        #[test]
        fn insecure_permissions_fail_closed() {
            let directory = TestDirectory::new();
            directory.write_credential(&generate_p256_pkcs8());
            fs::set_permissions(
                directory.credential_path(),
                fs::Permissions::from_mode(0o620),
            )
            .expect("make credential group writable");
            assert_eq!(
                load_from_credentials_directory(directory.path()).unwrap_err(),
                UbuntuTransportIdentityCustodyError::CredentialPermissionsInsecure
            );
        }

        #[test]
        fn malformed_key_material_is_rejected() {
            let directory = TestDirectory::new();
            directory.write_credential(b"not-a-p256-key");
            assert_eq!(
                load_from_credentials_directory(directory.path()).unwrap_err(),
                UbuntuTransportIdentityCustodyError::InvalidPrivateCredential
            );
        }
    }
}
