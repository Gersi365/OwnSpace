//! Linux systemd service-credential custody boundary for PRW reachability authority bootstrap.
//!
//! This crate owns only bounded acquisition and validation of the fixed Phase 152 credential set.
//! It does not provision credentials, connect to etcd, activate authority lifecycle operations,
//! modify systemd units, or expose private-key bytes through a public API.

pub mod durable_registry_custody;
pub mod mesh_transport_custody;

use std::fmt;

use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
    ReachabilityEtcdClientIdentityMaterialError, ReachabilityLiveOwnerEtcdBootstrapConfig,
    ReachabilityLiveOwnerEtcdBootstrapConfigError, ReachabilityProductionEtcdBootstrapConfig,
};

/// First fixed reachability authority endpoint credential name.
pub const AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME: &str = "prw.reachability.authority-endpoint-1.v1";
/// Second fixed reachability authority endpoint credential name.
pub const AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME: &str = "prw.reachability.authority-endpoint-2.v1";
/// Third fixed reachability authority endpoint credential name.
pub const AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME: &str = "prw.reachability.authority-endpoint-3.v1";
/// Fixed private authority CA bundle credential name.
pub const AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME: &str = "prw.reachability.authority-ca-bundle.v1";
/// Fixed live-owner client certificate credential name.
pub const LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME: &str =
    "prw.reachability.live-owner.client-certificate.v1";
/// Fixed live-owner client private-key credential name.
pub const LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME: &str =
    "prw.reachability.live-owner.client-private-key.v1";
/// Fixed fence-allocator client certificate credential name.
pub const FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME: &str =
    "prw.reachability.fence-allocator.client-certificate.v1";
/// Fixed fence-allocator client private-key credential name.
pub const FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME: &str =
    "prw.reachability.fence-allocator.client-private-key.v1";
/// Fixed durable-snapshot client certificate credential name.
pub const DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME: &str =
    "prw.reachability.durable-snapshot.client-certificate.v1";
/// Fixed durable-snapshot client private-key credential name.
pub const DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME: &str =
    "prw.reachability.durable-snapshot.client-private-key.v1";
/// Environment variable through which systemd exposes the service credential directory.
pub const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// Failure while acquiring the fixed reachability authority bootstrap material from systemd custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityCustodyError {
    /// This custody adapter is available only on Linux hosts.
    UnsupportedPlatform,
    /// systemd did not provide a credential-directory environment value.
    CredentialsDirectoryMissing,
    /// The supplied credential-directory value was not an absolute valid directory boundary.
    CredentialsDirectoryInvalid,
    /// The credential directory failed the locked ownership or permission checks.
    CredentialsDirectoryNotSecure,
    /// One fixed credential was absent or could not be opened safely.
    CredentialUnavailable,
    /// One fixed credential path did not resolve to one stable regular file.
    CredentialNotRegular,
    /// One fixed credential was not owned by the effective service user.
    CredentialOwnershipMismatch,
    /// One fixed credential violated the locked runtime permission checks.
    CredentialPermissionsInsecure,
    /// One fixed credential could not be read completely through its bounded reader.
    CredentialReadFailed,
    /// One fixed credential was empty or exceeded its type-specific upper bound.
    CredentialSizeOutOfBounds,
    /// One authority endpoint credential was not valid UTF-8.
    EndpointEncodingInvalid,
    /// Role-scoped identity material failed bounded control-plane validation.
    IdentityMaterial(ReachabilityEtcdClientIdentityMaterialError),
    /// The assembled authority bootstrap configuration failed bounded control-plane validation.
    BootstrapConfig(ReachabilityLiveOwnerEtcdBootstrapConfigError),
}

impl fmt::Display for ReachabilityCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("unsupported reachability custody platform")
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
                formatter.write_str("reachability credential is unavailable")
            }
            Self::CredentialNotRegular => {
                formatter.write_str("reachability credential is not a regular file")
            }
            Self::CredentialOwnershipMismatch => {
                formatter.write_str("reachability credential ownership mismatch")
            }
            Self::CredentialPermissionsInsecure => {
                formatter.write_str("reachability credential permissions are insecure")
            }
            Self::CredentialReadFailed => {
                formatter.write_str("reachability credential read failed")
            }
            Self::CredentialSizeOutOfBounds => {
                formatter.write_str("reachability credential size out of bounds")
            }
            Self::EndpointEncodingInvalid => {
                formatter.write_str("reachability endpoint credential encoding is invalid")
            }
            Self::IdentityMaterial(_) => {
                formatter.write_str("reachability client identity material is invalid")
            }
            Self::BootstrapConfig(_) => {
                formatter.write_str("reachability authority bootstrap configuration is invalid")
            }
        }
    }
}

impl std::error::Error for ReachabilityCustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IdentityMaterial(error) => Some(error),
            Self::BootstrapConfig(error) => Some(error),
            _ => None,
        }
    }
}

/// Loads the fixed reachability authority bootstrap configuration from systemd service credentials.
///
/// The function reads only the eight fixed Phase 152 credential names relative to
/// `$CREDENTIALS_DIRECTORY`. Private-key plaintext is retained only in zeroizing owned buffers and
/// moved directly into the control-plane identity boundary. This function performs no provider
/// connection or other network I/O.
///
/// # Errors
///
/// Returns [`ReachabilityCustodyError`] when the platform, systemd runtime boundary, file shape,
/// ownership, permissions, bounded read, endpoint encoding, identity material, or bootstrap
/// configuration fails validation.
pub fn load_reachability_live_owner_etcd_bootstrap_config_from_systemd_credentials()
-> Result<ReachabilityLiveOwnerEtcdBootstrapConfig, ReachabilityCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(ReachabilityCustodyError::UnsupportedPlatform)
    }
}

/// Loads the fixed three-role production reachability bootstrap configuration from systemd
/// service credentials.
///
/// The function reads the existing eight fixed reachability credentials plus the two dedicated
/// durable-snapshot identity credentials relative to `$CREDENTIALS_DIRECTORY`. All private keys
/// remain in zeroizing owned buffers and are moved directly into the control-plane identity
/// boundary. This function performs no provider connection or other network I/O.
///
/// # Errors
///
/// Returns [`ReachabilityCustodyError`] when the platform, systemd runtime boundary, file shape,
/// ownership, permissions, bounded read, endpoint encoding, identity material, or production
/// bootstrap configuration fails validation.
pub fn load_reachability_production_etcd_bootstrap_config_from_systemd_credentials()
-> Result<ReachabilityProductionEtcdBootstrapConfig, ReachabilityCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_production_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(ReachabilityCustodyError::UnsupportedPlatform)
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

    use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
        ReachabilityEtcdClientIdentityMaterial, ReachabilityLiveOwnerEtcdBootstrapConfig,
        ReachabilityProductionEtcdBootstrapConfig,
    };
    use rustix::{
        fs::{Mode, OFlags, open},
        process::geteuid,
    };
    use zeroize::Zeroizing;

    use super::{
        AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME, AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
        AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME, AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME,
        DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
        DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
        FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
        FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
        LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
        LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME, ReachabilityCustodyError,
        SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
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
    -> Result<ReachabilityLiveOwnerEtcdBootstrapConfig, ReachabilityCustodyError> {
        let directory =
            credentials_directory_from_value(env::var_os(SYSTEMD_CREDENTIALS_DIRECTORY_ENV))?;
        load_from_credentials_directory(&directory)
    }

    pub fn load_production_from_environment()
    -> Result<ReachabilityProductionEtcdBootstrapConfig, ReachabilityCustodyError> {
        let directory =
            credentials_directory_from_value(env::var_os(SYSTEMD_CREDENTIALS_DIRECTORY_ENV))?;
        load_production_from_credentials_directory(&directory)
    }

    fn credentials_directory_from_value(
        value: Option<OsString>,
    ) -> Result<PathBuf, ReachabilityCustodyError> {
        let value = value.ok_or(ReachabilityCustodyError::CredentialsDirectoryMissing)?;
        if value.is_empty() {
            return Err(ReachabilityCustodyError::CredentialsDirectoryMissing);
        }

        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(ReachabilityCustodyError::CredentialsDirectoryInvalid);
        }
        Ok(path)
    }

    fn load_from_credentials_directory(
        directory: &Path,
    ) -> Result<ReachabilityLiveOwnerEtcdBootstrapConfig, ReachabilityCustodyError> {
        validate_credentials_directory(directory)?;

        let endpoint_1 = read_endpoint(directory, AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME)?;
        let endpoint_2 = read_endpoint(directory, AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME)?;
        let endpoint_3 = read_endpoint(directory, AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME)?;
        let trust_bundle_pem = read_non_secret_credential(
            directory,
            AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
            MAX_AUTHORITY_CA_BUNDLE_BYTES,
        )?;

        let live_owner_certificate = read_non_secret_credential(
            directory,
            LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let live_owner_private_key =
            read_private_key_credential(directory, LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME)?;
        let live_owner_identity =
            ReachabilityEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                live_owner_certificate,
                live_owner_private_key,
            )
            .map_err(ReachabilityCustodyError::IdentityMaterial)?;

        let fence_allocator_certificate = read_non_secret_credential(
            directory,
            FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let fence_allocator_private_key = read_private_key_credential(
            directory,
            FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
        )?;
        let fence_allocator_identity =
            ReachabilityEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                fence_allocator_certificate,
                fence_allocator_private_key,
            )
            .map_err(ReachabilityCustodyError::IdentityMaterial)?;

        ReachabilityLiveOwnerEtcdBootstrapConfig::new(
            [endpoint_1, endpoint_2, endpoint_3],
            trust_bundle_pem,
            live_owner_identity,
            fence_allocator_identity,
        )
        .map_err(ReachabilityCustodyError::BootstrapConfig)
    }

    fn load_production_from_credentials_directory(
        directory: &Path,
    ) -> Result<ReachabilityProductionEtcdBootstrapConfig, ReachabilityCustodyError> {
        validate_credentials_directory(directory)?;

        let endpoint_1 = read_endpoint(directory, AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME)?;
        let endpoint_2 = read_endpoint(directory, AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME)?;
        let endpoint_3 = read_endpoint(directory, AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME)?;
        let trust_bundle_pem = read_non_secret_credential(
            directory,
            AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME,
            MAX_AUTHORITY_CA_BUNDLE_BYTES,
        )?;

        let live_owner_certificate = read_non_secret_credential(
            directory,
            LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let live_owner_private_key =
            read_private_key_credential(directory, LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME)?;
        let live_owner_identity =
            ReachabilityEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                live_owner_certificate,
                live_owner_private_key,
            )
            .map_err(ReachabilityCustodyError::IdentityMaterial)?;

        let fence_allocator_certificate = read_non_secret_credential(
            directory,
            FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let fence_allocator_private_key = read_private_key_credential(
            directory,
            FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
        )?;
        let fence_allocator_identity =
            ReachabilityEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                fence_allocator_certificate,
                fence_allocator_private_key,
            )
            .map_err(ReachabilityCustodyError::IdentityMaterial)?;

        let durable_snapshot_certificate = read_non_secret_credential(
            directory,
            DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_CLIENT_CERTIFICATE_BYTES,
        )?;
        let durable_snapshot_private_key = read_private_key_credential(
            directory,
            DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
        )?;
        let durable_snapshot_identity =
            ReachabilityEtcdClientIdentityMaterial::new_with_zeroizing_private_key(
                durable_snapshot_certificate,
                durable_snapshot_private_key,
            )
            .map_err(ReachabilityCustodyError::IdentityMaterial)?;

        ReachabilityProductionEtcdBootstrapConfig::new(
            [endpoint_1, endpoint_2, endpoint_3],
            trust_bundle_pem,
            live_owner_identity,
            fence_allocator_identity,
            durable_snapshot_identity,
        )
        .map_err(ReachabilityCustodyError::BootstrapConfig)
    }

    fn read_endpoint(directory: &Path, name: &str) -> Result<String, ReachabilityCustodyError> {
        let bytes = read_non_secret_credential(directory, name, MAX_ENDPOINT_CREDENTIAL_BYTES)?;
        String::from_utf8(bytes).map_err(|_| ReachabilityCustodyError::EndpointEncodingInvalid)
    }

    fn read_non_secret_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ReachabilityCustodyError> {
        let mut file = open_validated_credential(directory, name, max_bytes)?;
        read_bounded_vec(&mut file, max_bytes)
    }

    fn read_private_key_credential(
        directory: &Path,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ReachabilityCustodyError> {
        let mut file = open_validated_credential(directory, name, MAX_CLIENT_PRIVATE_KEY_BYTES)?;
        read_bounded_zeroizing(&mut file, MAX_CLIENT_PRIVATE_KEY_BYTES)
    }

    fn open_validated_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<File, ReachabilityCustodyError> {
        let credential_path = directory.join(name);
        let pre_open_metadata = match fs::symlink_metadata(&credential_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ReachabilityCustodyError::CredentialUnavailable);
            }
            Err(_) => return Err(ReachabilityCustodyError::CredentialUnavailable),
        };
        if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.file_type().is_file() {
            return Err(ReachabilityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&pre_open_metadata)?;
        if pre_open_metadata.len() > max_bytes as u64 {
            return Err(ReachabilityCustodyError::CredentialSizeOutOfBounds);
        }

        let owned_fd = open(
            &credential_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ReachabilityCustodyError::CredentialUnavailable)?;
        let file = File::from(owned_fd);
        let opened_metadata = file
            .metadata()
            .map_err(|_| ReachabilityCustodyError::CredentialUnavailable)?;
        if !opened_metadata.file_type().is_file() {
            return Err(ReachabilityCustodyError::CredentialNotRegular);
        }
        if pre_open_metadata.dev() != opened_metadata.dev()
            || pre_open_metadata.ino() != opened_metadata.ino()
        {
            return Err(ReachabilityCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&opened_metadata)?;
        if opened_metadata.len() > max_bytes as u64 {
            return Err(ReachabilityCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(file)
    }

    fn validate_credentials_directory(directory: &Path) -> Result<(), ReachabilityCustodyError> {
        if !directory.is_absolute() {
            return Err(ReachabilityCustodyError::CredentialsDirectoryInvalid);
        }

        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ReachabilityCustodyError::CredentialsDirectoryMissing);
            }
            Err(_) => return Err(ReachabilityCustodyError::CredentialsDirectoryInvalid),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(ReachabilityCustodyError::CredentialsDirectoryInvalid);
        }

        let current_uid = geteuid().as_raw();
        let mode = metadata.mode();
        if metadata.uid() != current_uid
            || mode & INSECURE_WRITE_BITS != 0
            || mode & OWNER_DIRECTORY_ACCESS_BITS != OWNER_DIRECTORY_ACCESS_BITS
        {
            return Err(ReachabilityCustodyError::CredentialsDirectoryNotSecure);
        }
        Ok(())
    }

    fn validate_credential_metadata(
        metadata: &fs::Metadata,
    ) -> Result<(), ReachabilityCustodyError> {
        if metadata.uid() != geteuid().as_raw() {
            return Err(ReachabilityCustodyError::CredentialOwnershipMismatch);
        }

        let mode = metadata.mode();
        if mode & INSECURE_WRITE_BITS != 0 || mode & EXECUTE_BITS != 0 || mode & OWNER_READ_BIT == 0
        {
            return Err(ReachabilityCustodyError::CredentialPermissionsInsecure);
        }
        Ok(())
    }

    fn read_bounded_vec<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ReachabilityCustodyError> {
        let mut bytes = Vec::new();
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| ReachabilityCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(ReachabilityCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(bytes)
    }

    fn read_bounded_zeroizing<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ReachabilityCustodyError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| ReachabilityCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(ReachabilityCustodyError::CredentialSizeOutOfBounds);
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

        use prw_control_plane::reachability_acquisition_evidence::bootstrap::ReachabilityLiveOwnerEtcdBootstrapConfigError;

        use super::*;

        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

        struct TestDirectory {
            path: PathBuf,
        }

        impl TestDirectory {
            fn new() -> Self {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("prw-phase152-c02f-ce-{}-{id}", process::id()));
                fs::create_dir(&path).expect("create isolated CE test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure CE test directory mode");
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
                    fs::remove_file(&path).expect("replace CE test credential");
                }
                fs::write(&path, bytes).expect("write CE test credential");
                fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                    .expect("secure CE credential mode");
            }

            fn populate_valid(&self) {
                self.write_credential(
                    AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME,
                    b"https://etcd-a.authority.example:2379",
                );
                self.write_credential(
                    AUTHORITY_ENDPOINT_2_CREDENTIAL_NAME,
                    b"https://etcd-b.authority.example:2379",
                );
                self.write_credential(
                    AUTHORITY_ENDPOINT_3_CREDENTIAL_NAME,
                    b"https://etcd-c.authority.example:2379",
                );
                self.write_credential(AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME, b"private-authority-ca");
                self.write_credential(
                    LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                    b"live-owner-certificate",
                );
                self.write_credential(
                    LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                    b"live-owner-private-key",
                );
                self.write_credential(
                    FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                    b"fence-allocator-certificate",
                );
                self.write_credential(
                    FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                    b"fence-allocator-private-key",
                );
            }

            fn populate_valid_production(&self) {
                self.populate_valid();
                self.write_credential(
                    DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                    b"durable-snapshot-certificate",
                );
                self.write_credential(
                    DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                    b"durable-snapshot-private-key",
                );
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        #[test]
        fn rejects_missing_and_relative_credentials_directory_values() {
            assert_eq!(
                credentials_directory_from_value(None),
                Err(ReachabilityCustodyError::CredentialsDirectoryMissing)
            );
            assert_eq!(
                credentials_directory_from_value(Some(OsString::from("relative/path"))),
                Err(ReachabilityCustodyError::CredentialsDirectoryInvalid)
            );
        }

        #[test]
        fn fixed_credential_set_builds_opaque_config_without_network_io() {
            let directory = TestDirectory::new();
            directory.populate_valid();

            assert!(load_from_credentials_directory(directory.path()).is_ok());
        }

        #[test]
        fn production_credential_names_are_fixed_and_role_distinct() {
            assert_eq!(
                DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                "prw.reachability.durable-snapshot.client-certificate.v1"
            );
            assert_eq!(
                DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                "prw.reachability.durable-snapshot.client-private-key.v1"
            );

            let existing_names = [
                LIVE_OWNER_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                FENCE_ALLOCATOR_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
            ];
            assert!(!existing_names.contains(&DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME));
            assert!(!existing_names.contains(&DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME));
            assert_ne!(
                DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME,
                DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME
            );
        }

        #[test]
        fn production_fixed_credential_set_builds_opaque_config_without_network_io() {
            let directory = TestDirectory::new();
            directory.populate_valid_production();

            assert!(load_production_from_credentials_directory(directory.path()).is_ok());
        }

        #[test]
        fn production_loader_rejects_missing_durable_identity_credential() {
            let missing_certificate = TestDirectory::new();
            missing_certificate.populate_valid_production();
            fs::remove_file(
                missing_certificate
                    .credential_path(DURABLE_SNAPSHOT_CLIENT_CERTIFICATE_CREDENTIAL_NAME),
            )
            .expect("remove durable certificate credential");
            assert!(matches!(
                load_production_from_credentials_directory(missing_certificate.path()),
                Err(ReachabilityCustodyError::CredentialUnavailable)
            ));

            let missing_private_key = TestDirectory::new();
            missing_private_key.populate_valid_production();
            fs::remove_file(
                missing_private_key
                    .credential_path(DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME),
            )
            .expect("remove durable private-key credential");
            assert!(matches!(
                load_production_from_credentials_directory(missing_private_key.path()),
                Err(ReachabilityCustodyError::CredentialUnavailable)
            ));
        }

        #[test]
        fn production_loader_rejects_oversized_durable_private_key() {
            let directory = TestDirectory::new();
            directory.populate_valid_production();
            let oversized = vec![b'k'; MAX_CLIENT_PRIVATE_KEY_BYTES + 1];
            directory.write_credential(
                DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                &oversized,
            );

            assert!(matches!(
                load_production_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::CredentialSizeOutOfBounds)
            ));
        }

        #[test]
        fn production_loader_preserves_durable_private_key_reuse_rejection_with_live_owner() {
            let directory = TestDirectory::new();
            directory.populate_valid_production();
            directory.write_credential(
                DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                b"live-owner-private-key",
            );

            assert!(matches!(
                load_production_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::BootstrapConfig(
                    ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey
                ))
            ));
        }

        #[test]
        fn production_loader_preserves_durable_private_key_reuse_rejection_with_fence_allocator() {
            let directory = TestDirectory::new();
            directory.populate_valid_production();
            directory.write_credential(
                DURABLE_SNAPSHOT_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                b"fence-allocator-private-key",
            );

            assert!(matches!(
                load_production_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::BootstrapConfig(
                    ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey
                ))
            ));
        }

        #[test]
        fn rejects_symlink_credential() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let endpoint_path = directory.credential_path(AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME);
            fs::remove_file(&endpoint_path).expect("remove regular endpoint credential");
            let target = directory.credential_path("endpoint-target");
            fs::write(&target, b"https://etcd-a.authority.example:2379")
                .expect("write symlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o400))
                .expect("secure symlink target mode");
            symlink(&target, endpoint_path).expect("create endpoint credential symlink");

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::CredentialNotRegular)
            ));
        }

        #[test]
        fn rejects_insecure_credential_permissions() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            fs::set_permissions(
                directory.credential_path(AUTHORITY_CA_BUNDLE_CREDENTIAL_NAME),
                fs::Permissions::from_mode(0o420),
            )
            .expect("set intentionally insecure CE credential mode");

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::CredentialPermissionsInsecure)
            ));
        }

        #[test]
        fn rejects_oversized_private_key_before_control_plane_construction() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let oversized = vec![b'k'; MAX_CLIENT_PRIVATE_KEY_BYTES + 1];
            directory.write_credential(LIVE_OWNER_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME, &oversized);

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::CredentialSizeOutOfBounds)
            ));
        }

        #[test]
        fn rejects_invalid_endpoint_encoding_without_normalization() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            directory.write_credential(AUTHORITY_ENDPOINT_1_CREDENTIAL_NAME, &[0xff]);

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::EndpointEncodingInvalid)
            ));
        }

        #[test]
        fn preserves_control_plane_cross_role_private_key_reuse_rejection() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            directory.write_credential(
                FENCE_ALLOCATOR_CLIENT_PRIVATE_KEY_CREDENTIAL_NAME,
                b"live-owner-private-key",
            );

            assert!(matches!(
                load_from_credentials_directory(directory.path()),
                Err(ReachabilityCustodyError::BootstrapConfig(
                    ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey
                ))
            ));
        }
    }
}
