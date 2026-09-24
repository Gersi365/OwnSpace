//! Linux systemd service-credential custody for production durable-registry etcd bootstrap.
//!
//! C03e-IZ materializes only the C03e-IY-selected fixed credential-acquisition boundary. It reads
//! exactly the six selected durable-registry service credentials, validates their filesystem custody,
//! preserves the private key in zeroizing ownership, and returns only the existing control-plane
//! [`DurableRegistryProductionEtcdBootstrapConfig`].
//!
//! This module performs no provider network I/O, provisions no credential, mutates no systemd unit or
//! provider RBAC, creates no registry record, and activates no Agent/runtime/deployment path.

use std::fmt;

use prw_control_plane::durable_registry_etcd_bootstrap::{
    DurableRegistryEtcdClientIdentityMaterialError, DurableRegistryProductionEtcdBootstrapConfig,
    DurableRegistryProductionEtcdBootstrapConfigError,
};

/// First fixed durable-registry authority endpoint credential name.
pub const REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME: &str =
    "prw.registry.authority-endpoint-1.v1";
/// Second fixed durable-registry authority endpoint credential name.
pub const REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME: &str =
    "prw.registry.authority-endpoint-2.v1";
/// Third fixed durable-registry authority endpoint credential name.
pub const REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME: &str =
    "prw.registry.authority-endpoint-3.v1";
/// Fixed durable-registry private authority CA bundle credential name.
pub const REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME: &str =
    "prw.registry.authority-ca-bundle.v1";
/// Fixed dedicated durable-registry client certificate credential name.
pub const REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME: &str = "prw.registry.client-certificate.v1";
/// Fixed dedicated durable-registry client private-key credential name.
pub const REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME: &str = "prw.registry.client-private-key.v1";
/// Environment variable through which systemd exposes service credentials.
pub const REGISTRY_SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// Failure while acquiring the fixed durable-registry provider bootstrap material from systemd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableRegistryCustodyError {
    /// The fixed systemd custody adapter is available only on Linux hosts.
    UnsupportedPlatform,
    /// systemd did not provide a credential-directory environment value.
    CredentialsDirectoryMissing,
    /// The credential-directory value is not an absolute valid directory boundary.
    CredentialsDirectoryInvalid,
    /// The credential directory failed the locked ownership or permission checks.
    CredentialsDirectoryNotSecure,
    /// One fixed registry credential is absent or cannot be securely opened.
    CredentialUnavailable,
    /// One fixed registry credential is a symlink or is not one stable regular file.
    CredentialNotRegular,
    /// One fixed registry credential is not owned by the effective service user.
    CredentialOwnershipMismatch,
    /// One fixed registry credential violates the locked runtime permission checks.
    CredentialPermissionsInsecure,
    /// One bounded registry credential read failed.
    CredentialReadFailed,
    /// One fixed registry credential is empty or exceeds its selected upper bound.
    CredentialSizeOutOfBounds,
    /// One fixed registry authority endpoint credential is not valid UTF-8.
    EndpointEncodingInvalid,
    /// Dedicated registry mTLS identity material failed bounded control-plane validation.
    IdentityMaterial(DurableRegistryEtcdClientIdentityMaterialError),
    /// The assembled registry provider bootstrap config failed control-plane validation.
    BootstrapConfig(DurableRegistryProductionEtcdBootstrapConfigError),
}

impl fmt::Display for DurableRegistryCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("unsupported durable registry custody platform")
            }
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
                formatter.write_str("durable registry credential is unavailable")
            }
            Self::CredentialNotRegular => {
                formatter.write_str("durable registry credential is not a regular file")
            }
            Self::CredentialOwnershipMismatch => {
                formatter.write_str("durable registry credential ownership mismatch")
            }
            Self::CredentialPermissionsInsecure => {
                formatter.write_str("durable registry credential permissions are insecure")
            }
            Self::CredentialReadFailed => {
                formatter.write_str("durable registry credential read failed")
            }
            Self::CredentialSizeOutOfBounds => {
                formatter.write_str("durable registry credential size out of bounds")
            }
            Self::EndpointEncodingInvalid => {
                formatter.write_str("durable registry endpoint credential encoding is invalid")
            }
            Self::IdentityMaterial(_) => {
                formatter.write_str("durable registry client identity material is invalid")
            }
            Self::BootstrapConfig(_) => {
                formatter.write_str("durable registry bootstrap configuration is invalid")
            }
        }
    }
}

impl std::error::Error for DurableRegistryCustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IdentityMaterial(error) => Some(error),
            Self::BootstrapConfig(error) => Some(error),
            _ => None,
        }
    }
}

/// Loads the fixed production durable-registry etcd bootstrap config from systemd credentials.
///
/// The function reads only the six C03e-IY-selected credential names relative to
/// `$CREDENTIALS_DIRECTORY`. Private-key bytes remain in zeroizing ownership until they are moved
/// directly into the existing control-plane identity carrier. This function performs no provider
/// network I/O.
///
/// # Errors
///
/// Returns [`DurableRegistryCustodyError`] when the platform, systemd directory boundary, file
/// shape, ownership, permissions, bounded read, endpoint encoding, identity material, or bootstrap
/// configuration fails validation.
pub fn load_durable_registry_production_etcd_bootstrap_config_from_systemd_credentials()
-> Result<DurableRegistryProductionEtcdBootstrapConfig, DurableRegistryCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(DurableRegistryCustodyError::UnsupportedPlatform)
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

    use prw_control_plane::durable_registry_etcd_bootstrap::{
        DurableRegistryEtcdClientIdentityMaterial, DurableRegistryProductionEtcdBootstrapConfig,
    };
    use rustix::{
        fs::{Mode, OFlags, open},
        process::geteuid,
    };
    use zeroize::Zeroizing;

    use super::{
        DurableRegistryCustodyError, REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
        REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
        REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME,
        REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME, REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
        REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME, REGISTRY_SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
    };

    const MAX_ENDPOINT_CREDENTIAL_BYTES: usize = 2_048;
    const MAX_AUTHORITY_CA_BUNDLE_BYTES: usize = 262_144;
    const MAX_CLIENT_CERTIFICATE_BYTES: usize = 131_072;
    const MAX_CLIENT_PRIVATE_KEY_BYTES: usize = 32_768;

    const INSECURE_WRITE_BITS: u32 = 0o022;
    const EXECUTE_BITS: u32 = 0o111;
    const OWNER_READ_BIT: u32 = 0o400;
    const OWNER_DIRECTORY_ACCESS_BITS: u32 = 0o500;

    pub fn load_from_environment()
    -> Result<DurableRegistryProductionEtcdBootstrapConfig, DurableRegistryCustodyError> {
        let directory = credentials_directory_from_value(env::var_os(
            REGISTRY_SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
        ))?;
        load_from_credentials_directory(&directory)
    }

    fn credentials_directory_from_value(
        value: Option<OsString>,
    ) -> Result<PathBuf, DurableRegistryCustodyError> {
        let value = value.ok_or(DurableRegistryCustodyError::CredentialsDirectoryMissing)?;
        if value.is_empty() {
            return Err(DurableRegistryCustodyError::CredentialsDirectoryMissing);
        }

        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(DurableRegistryCustodyError::CredentialsDirectoryInvalid);
        }
        Ok(path)
    }

    fn load_from_credentials_directory(
        directory: &Path,
    ) -> Result<DurableRegistryProductionEtcdBootstrapConfig, DurableRegistryCustodyError> {
        validate_credentials_directory(directory)?;

        let endpoint_1 = read_endpoint(directory, REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME)?;
        let endpoint_2 = read_endpoint(directory, REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME)?;
        let endpoint_3 = read_endpoint(directory, REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME)?;
        let trust_bundle_pem = read_non_secret_credential(
            directory,
            REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
            MAX_AUTHORITY_CA_BUNDLE_BYTES,
        )?;
        let certificate_pem = read_non_secret_credential(
            directory,
            REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let private_key_pem =
            read_private_key_credential(directory, REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME)?;

        let registry_identity =
            DurableRegistryEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                certificate_pem,
                private_key_pem,
            )
            .map_err(DurableRegistryCustodyError::IdentityMaterial)?;

        DurableRegistryProductionEtcdBootstrapConfig::new(
            [endpoint_1, endpoint_2, endpoint_3],
            trust_bundle_pem,
            registry_identity,
        )
        .map_err(DurableRegistryCustodyError::BootstrapConfig)
    }

    fn read_endpoint(directory: &Path, name: &str) -> Result<String, DurableRegistryCustodyError> {
        let bytes = read_non_secret_credential(directory, name, MAX_ENDPOINT_CREDENTIAL_BYTES)?;
        String::from_utf8(bytes).map_err(|_| DurableRegistryCustodyError::EndpointEncodingInvalid)
    }

    fn read_non_secret_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, DurableRegistryCustodyError> {
        let mut file = open_validated_credential(directory, name, max_bytes)?;
        read_bounded_vec(&mut file, max_bytes)
    }

    fn read_private_key_credential(
        directory: &Path,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, DurableRegistryCustodyError> {
        let mut file = open_validated_credential(directory, name, MAX_CLIENT_PRIVATE_KEY_BYTES)?;
        read_bounded_zeroizing(&mut file, MAX_CLIENT_PRIVATE_KEY_BYTES)
    }

    fn open_validated_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<File, DurableRegistryCustodyError> {
        let credential_path = directory.join(name);
        let pre_open_metadata = match fs::symlink_metadata(&credential_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(DurableRegistryCustodyError::CredentialUnavailable);
            }
            Err(_) => return Err(DurableRegistryCustodyError::CredentialUnavailable),
        };
        if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.file_type().is_file() {
            return Err(DurableRegistryCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&pre_open_metadata)?;
        if pre_open_metadata.len() > max_bytes as u64 {
            return Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds);
        }

        let owned_fd = open(
            &credential_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| DurableRegistryCustodyError::CredentialUnavailable)?;
        let file = File::from(owned_fd);
        let opened_metadata = file
            .metadata()
            .map_err(|_| DurableRegistryCustodyError::CredentialUnavailable)?;
        if !opened_metadata.file_type().is_file() {
            return Err(DurableRegistryCustodyError::CredentialNotRegular);
        }
        if pre_open_metadata.dev() != opened_metadata.dev()
            || pre_open_metadata.ino() != opened_metadata.ino()
        {
            return Err(DurableRegistryCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&opened_metadata)?;
        if opened_metadata.len() > max_bytes as u64 {
            return Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(file)
    }

    fn validate_credentials_directory(directory: &Path) -> Result<(), DurableRegistryCustodyError> {
        if !directory.is_absolute() {
            return Err(DurableRegistryCustodyError::CredentialsDirectoryInvalid);
        }

        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(DurableRegistryCustodyError::CredentialsDirectoryMissing);
            }
            Err(_) => return Err(DurableRegistryCustodyError::CredentialsDirectoryInvalid),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(DurableRegistryCustodyError::CredentialsDirectoryInvalid);
        }

        let mode = metadata.mode();
        if metadata.uid() != geteuid().as_raw()
            || mode & INSECURE_WRITE_BITS != 0
            || mode & OWNER_DIRECTORY_ACCESS_BITS != OWNER_DIRECTORY_ACCESS_BITS
        {
            return Err(DurableRegistryCustodyError::CredentialsDirectoryNotSecure);
        }
        Ok(())
    }

    fn validate_credential_metadata(
        metadata: &fs::Metadata,
    ) -> Result<(), DurableRegistryCustodyError> {
        if metadata.uid() != geteuid().as_raw() {
            return Err(DurableRegistryCustodyError::CredentialOwnershipMismatch);
        }

        let mode = metadata.mode();
        if mode & INSECURE_WRITE_BITS != 0 || mode & EXECUTE_BITS != 0 || mode & OWNER_READ_BIT == 0
        {
            return Err(DurableRegistryCustodyError::CredentialPermissionsInsecure);
        }
        Ok(())
    }

    fn read_bounded_vec<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Vec<u8>, DurableRegistryCustodyError> {
        let mut bytes = Vec::new();
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| DurableRegistryCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(bytes)
    }

    fn read_bounded_zeroizing<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, DurableRegistryCustodyError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| DurableRegistryCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            ffi::OsString,
            fs,
            os::unix::fs::{PermissionsExt, symlink},
            path::{Path, PathBuf},
            process,
            sync::atomic::{AtomicU64, Ordering},
        };

        use super::*;

        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

        struct TestDirectory {
            path: PathBuf,
        }

        impl TestDirectory {
            fn new() -> Self {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("prw-phase152-c03e-iz-{}-{id}", process::id()));
                fs::create_dir(&path).expect("create isolated C03e-IZ test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure C03e-IZ test directory mode");
                Self { path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn credential_path(&self, name: &str) -> PathBuf {
                self.path.join(name)
            }

            fn write_credential(&self, name: &str, bytes: &[u8]) {
                let path = self.credential_path(name);
                if path.exists() {
                    fs::remove_file(&path).expect("replace C03e-IZ test credential");
                }
                fs::write(&path, bytes).expect("write C03e-IZ test credential");
                fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                    .expect("secure C03e-IZ credential mode");
            }

            fn populate_valid(&self) {
                self.write_credential(
                    REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
                    b"https://registry-etcd-a.authority.example:2379",
                );
                self.write_credential(
                    REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME,
                    b"https://registry-etcd-b.authority.example:2379",
                );
                self.write_credential(
                    REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME,
                    b"https://registry-etcd-c.authority.example:2379",
                );
                self.write_credential(
                    REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
                    b"registry-private-authority-ca",
                );
                self.write_credential(
                    REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                    b"registry-client-certificate",
                );
                self.write_credential(
                    REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                    b"registry-client-private-key",
                );
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        #[test]
        fn selected_registry_credential_names_are_exact_and_distinct() {
            assert_eq!(
                REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
                "prw.registry.authority-endpoint-1.v1"
            );
            assert_eq!(
                REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME,
                "prw.registry.authority-endpoint-2.v1"
            );
            assert_eq!(
                REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME,
                "prw.registry.authority-endpoint-3.v1"
            );
            assert_eq!(
                REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
                "prw.registry.authority-ca-bundle.v1"
            );
            assert_eq!(
                REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                "prw.registry.client-certificate.v1"
            );
            assert_eq!(
                REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                "prw.registry.client-private-key.v1"
            );
            let names = [
                REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
                REGISTRY_AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME,
                REGISTRY_AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME,
                REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
                REGISTRY_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
            ];
            for (index, name) in names.iter().enumerate() {
                assert!(!names[index + 1..].contains(name));
            }
        }

        #[test]
        fn rejects_missing_and_relative_credentials_directory_values() {
            assert_eq!(
                credentials_directory_from_value(None),
                Err(DurableRegistryCustodyError::CredentialsDirectoryMissing)
            );
            assert_eq!(
                credentials_directory_from_value(Some(OsString::from("relative/path"))),
                Err(DurableRegistryCustodyError::CredentialsDirectoryInvalid)
            );
        }

        #[test]
        fn fixed_registry_credential_set_builds_opaque_config_without_network_io() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            assert!(load_from_credentials_directory(directory.path()).is_ok());
        }

        #[test]
        fn private_key_reader_preserves_zeroizing_container_before_identity_handoff() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let key = read_private_key_credential(
                directory.path(),
                REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
            )
            .expect("zeroizing private key");
            assert_eq!(&*key, b"registry-client-private-key");
        }

        #[test]
        fn rejects_invalid_endpoint_encoding_without_normalization() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            directory.write_credential(REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME, &[0xff]);
            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(DurableRegistryCustodyError::EndpointEncodingInvalid)
            ));
        }

        #[test]
        fn rejects_symlink_credential() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let endpoint_path =
                directory.credential_path(REGISTRY_AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME);
            fs::remove_file(&endpoint_path).expect("remove regular registry endpoint credential");
            let target = directory.credential_path("registry-endpoint-target");
            fs::write(&target, b"https://registry-etcd-a.authority.example:2379")
                .expect("write registry symlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o400))
                .expect("secure registry target mode");
            symlink(&target, endpoint_path).expect("create registry endpoint credential symlink");

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(DurableRegistryCustodyError::CredentialNotRegular)
            ));
        }

        #[test]
        fn rejects_insecure_private_key_permissions() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            fs::set_permissions(
                directory.credential_path(REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME),
                fs::Permissions::from_mode(0o420),
            )
            .expect("set intentionally insecure registry key mode");

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(DurableRegistryCustodyError::CredentialPermissionsInsecure)
            ));
        }

        #[test]
        fn rejects_oversized_private_key() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let oversized = vec![b'k'; MAX_CLIENT_PRIVATE_KEY_BYTES + 1];
            directory.write_credential(REGISTRY_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME, &oversized);

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds)
            ));
        }

        #[test]
        fn rejects_empty_fixed_credential() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            directory.write_credential(REGISTRY_AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME, b"");

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(DurableRegistryCustodyError::CredentialSizeOutOfBounds)
            ));
        }
    }
}
