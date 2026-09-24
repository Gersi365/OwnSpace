//! Linux systemd service-credential custody for the Ubuntu Agent mesh transport identity.
//!
//! This module owns only bounded acquisition of the fixed C03b credential set. It performs no
//! network I/O, constructs no QUIC endpoint, and does not grant remote readiness or capability.

use std::fmt;

use zeroize::Zeroizing;

/// Fixed private mesh trust-root certificate credential name.
pub const MESH_ROOT_CERTIFICATE_CREDENTIAL_NAME: &str = "prw.mesh.private-root-certificate.v1";
/// Fixed Agent mesh leaf certificate credential name.
pub const MESH_AGENT_CERTIFICATE_CREDENTIAL_NAME: &str = "prw.mesh.agent-certificate.v1";
/// Fixed Agent mesh private-key credential name.
pub const MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME: &str = "prw.mesh.agent-private-key.v1";
/// Environment variable through which systemd exposes service credentials.
pub const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// Bounded fixed mesh transport material acquired from systemd custody.
#[allow(
    clippy::struct_field_names,
    reason = "DER suffixes encode the exact serialized credential formats and are security-significant"
)]
pub struct MeshTransportCredentialMaterial {
    root_certificate_der: Vec<u8>,
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MeshTransportCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshTransportCredentialMaterial")
            .field(
                "root_certificate_der_bytes",
                &self.root_certificate_der.len(),
            )
            .field("certificate_der_bytes", &self.certificate_der.len())
            .field("private_key_pkcs8_der", &"<redacted>")
            .finish()
    }
}

impl MeshTransportCredentialMaterial {
    /// Returns the exact private trust-root certificate DER bytes.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.root_certificate_der
    }

    /// Returns the exact Agent mesh leaf certificate DER bytes.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Returns the bounded private-key length without exposing private-key bytes.
    #[must_use]
    pub fn private_key_len(&self) -> usize {
        self.private_key_pkcs8_der.len()
    }

    /// Consumes this custody object and transfers its exact DER material toward TLS composition.
    ///
    /// The private key remains wrapped in [`Zeroizing`] during the ownership transfer. This is the
    /// only public private-key handoff: no borrowed, mutable, clone, slice, or reusable raw-key
    /// accessor is exposed. The caller is expected to transfer the owned key immediately into the
    /// transport-owned rustls builder.
    #[must_use]
    pub fn into_transport_tls_der(self) -> (Vec<u8>, Vec<u8>, Zeroizing<Vec<u8>>) {
        (
            self.root_certificate_der,
            self.certificate_der,
            self.private_key_pkcs8_der,
        )
    }
}

/// Failure while acquiring fixed mesh transport material from systemd service credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeshTransportCustodyError {
    /// The systemd credential adapter is Linux-only.
    UnsupportedPlatform,
    /// `$CREDENTIALS_DIRECTORY` was absent or empty.
    CredentialsDirectoryMissing,
    /// The credential directory was not an absolute stable directory boundary.
    CredentialsDirectoryInvalid,
    /// The credential directory violated ownership or permission requirements.
    CredentialsDirectoryNotSecure,
    /// A fixed credential was absent or could not be opened safely.
    CredentialUnavailable,
    /// A fixed credential was a symlink or not a stable regular file.
    CredentialNotRegular,
    /// A fixed credential was not owned by the effective service user.
    CredentialOwnershipMismatch,
    /// A fixed credential violated the locked runtime permission checks.
    CredentialPermissionsInsecure,
    /// A bounded read failed.
    CredentialReadFailed,
    /// A fixed credential was empty or exceeded its type-specific bound.
    CredentialSizeOutOfBounds,
}

impl fmt::Display for MeshTransportCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "unsupported mesh transport custody platform",
            Self::CredentialsDirectoryMissing => "systemd credential directory is unavailable",
            Self::CredentialsDirectoryInvalid => "systemd credential directory is invalid",
            Self::CredentialsDirectoryNotSecure => "systemd credential directory is not secure",
            Self::CredentialUnavailable => "mesh transport credential is unavailable",
            Self::CredentialNotRegular => "mesh transport credential is not a regular file",
            Self::CredentialOwnershipMismatch => "mesh transport credential ownership mismatch",
            Self::CredentialPermissionsInsecure => {
                "mesh transport credential permissions are insecure"
            }
            Self::CredentialReadFailed => "mesh transport credential read failed",
            Self::CredentialSizeOutOfBounds => "mesh transport credential size out of bounds",
        })
    }
}

impl std::error::Error for MeshTransportCustodyError {}

/// Loads the fixed Agent mesh transport credentials from systemd service custody.
///
/// The loader reads only three fixed credential names relative to `$CREDENTIALS_DIRECTORY`.
/// Private-key bytes are read directly into a zeroizing buffer and have no reusable borrowed/raw
/// getter. The only public secret transfer consumes the complete custody object and preserves the
/// zeroizing key wrapper for immediate TLS ownership transfer. No certificate parsing, TLS
/// construction, socket I/O, readiness transition, credential provisioning, or systemd mutation
/// occurs here.
///
/// # Errors
///
/// Returns [`MeshTransportCustodyError`] when the platform, credential-directory boundary, file
/// shape, ownership, permissions, or bounded read fails validation.
pub fn load_mesh_transport_credentials_from_systemd()
-> Result<MeshTransportCredentialMaterial, MeshTransportCustodyError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_from_environment()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(MeshTransportCustodyError::UnsupportedPlatform)
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
        MESH_AGENT_CERTIFICATE_CREDENTIAL_NAME, MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME,
        MESH_ROOT_CERTIFICATE_CREDENTIAL_NAME, MeshTransportCredentialMaterial,
        MeshTransportCustodyError, SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
    };

    const MAX_ROOT_CERTIFICATE_DER_BYTES: usize = 65_536;
    const MAX_AGENT_CERTIFICATE_DER_BYTES: usize = 65_536;
    const MAX_AGENT_PRIVATE_KEY_PKCS8_DER_BYTES: usize = 32_768;

    const INSECURE_WRITE_BITS: u32 = 0o022;
    const EXECUTE_BITS: u32 = 0o111;
    const OWNER_READ_BIT: u32 = 0o400;
    const OWNER_DIRECTORY_ACCESS_BITS: u32 = 0o500;

    pub fn load_from_environment()
    -> Result<MeshTransportCredentialMaterial, MeshTransportCustodyError> {
        let directory =
            credentials_directory_from_value(env::var_os(SYSTEMD_CREDENTIALS_DIRECTORY_ENV))?;
        load_from_credentials_directory(&directory)
    }

    fn credentials_directory_from_value(
        value: Option<OsString>,
    ) -> Result<PathBuf, MeshTransportCustodyError> {
        let value = value.ok_or(MeshTransportCustodyError::CredentialsDirectoryMissing)?;
        if value.is_empty() {
            return Err(MeshTransportCustodyError::CredentialsDirectoryMissing);
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(MeshTransportCustodyError::CredentialsDirectoryInvalid);
        }
        Ok(path)
    }

    fn load_from_credentials_directory(
        directory: &Path,
    ) -> Result<MeshTransportCredentialMaterial, MeshTransportCustodyError> {
        validate_credentials_directory(directory)?;
        let root_certificate_der = read_non_secret_credential(
            directory,
            MESH_ROOT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_ROOT_CERTIFICATE_DER_BYTES,
        )?;
        let certificate_der = read_non_secret_credential(
            directory,
            MESH_AGENT_CERTIFICATE_CREDENTIAL_NAME,
            MAX_AGENT_CERTIFICATE_DER_BYTES,
        )?;
        let private_key_pkcs8_der = read_private_key_credential(directory)?;
        Ok(MeshTransportCredentialMaterial {
            root_certificate_der,
            certificate_der,
            private_key_pkcs8_der,
        })
    }

    fn read_non_secret_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, MeshTransportCustodyError> {
        let mut file = open_validated_credential(directory, name, max_bytes)?;
        read_bounded_vec(&mut file, max_bytes)
    }

    fn read_private_key_credential(
        directory: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, MeshTransportCustodyError> {
        let mut file = open_validated_credential(
            directory,
            MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME,
            MAX_AGENT_PRIVATE_KEY_PKCS8_DER_BYTES,
        )?;
        read_bounded_zeroizing(&mut file, MAX_AGENT_PRIVATE_KEY_PKCS8_DER_BYTES)
    }

    fn open_validated_credential(
        directory: &Path,
        name: &str,
        max_bytes: usize,
    ) -> Result<File, MeshTransportCustodyError> {
        let credential_path = directory.join(name);
        let pre_open_metadata = match fs::symlink_metadata(&credential_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(MeshTransportCustodyError::CredentialUnavailable);
            }
            Err(_) => return Err(MeshTransportCustodyError::CredentialUnavailable),
        };
        if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.file_type().is_file() {
            return Err(MeshTransportCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&pre_open_metadata)?;
        if pre_open_metadata.len() > max_bytes as u64 {
            return Err(MeshTransportCustodyError::CredentialSizeOutOfBounds);
        }

        let owned_fd = open(
            &credential_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| MeshTransportCustodyError::CredentialUnavailable)?;
        let file = File::from(owned_fd);
        let opened_metadata = file
            .metadata()
            .map_err(|_| MeshTransportCustodyError::CredentialUnavailable)?;
        if !opened_metadata.file_type().is_file() {
            return Err(MeshTransportCustodyError::CredentialNotRegular);
        }
        if pre_open_metadata.dev() != opened_metadata.dev()
            || pre_open_metadata.ino() != opened_metadata.ino()
        {
            return Err(MeshTransportCustodyError::CredentialNotRegular);
        }
        validate_credential_metadata(&opened_metadata)?;
        if opened_metadata.len() > max_bytes as u64 {
            return Err(MeshTransportCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(file)
    }

    fn validate_credentials_directory(directory: &Path) -> Result<(), MeshTransportCustodyError> {
        if !directory.is_absolute() {
            return Err(MeshTransportCustodyError::CredentialsDirectoryInvalid);
        }
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(MeshTransportCustodyError::CredentialsDirectoryMissing);
            }
            Err(_) => return Err(MeshTransportCustodyError::CredentialsDirectoryInvalid),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(MeshTransportCustodyError::CredentialsDirectoryInvalid);
        }
        let mode = metadata.mode();
        if metadata.uid() != geteuid().as_raw()
            || mode & INSECURE_WRITE_BITS != 0
            || mode & OWNER_DIRECTORY_ACCESS_BITS != OWNER_DIRECTORY_ACCESS_BITS
        {
            return Err(MeshTransportCustodyError::CredentialsDirectoryNotSecure);
        }
        Ok(())
    }

    fn validate_credential_metadata(
        metadata: &fs::Metadata,
    ) -> Result<(), MeshTransportCustodyError> {
        if metadata.uid() != geteuid().as_raw() {
            return Err(MeshTransportCustodyError::CredentialOwnershipMismatch);
        }
        let mode = metadata.mode();
        if mode & INSECURE_WRITE_BITS != 0 || mode & EXECUTE_BITS != 0 || mode & OWNER_READ_BIT == 0
        {
            return Err(MeshTransportCustodyError::CredentialPermissionsInsecure);
        }
        Ok(())
    }

    fn read_bounded_vec<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Vec<u8>, MeshTransportCustodyError> {
        let mut bytes = Vec::new();
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| MeshTransportCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(MeshTransportCustodyError::CredentialSizeOutOfBounds);
        }
        Ok(bytes)
    }

    fn read_bounded_zeroizing<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, MeshTransportCustodyError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut limited = reader.take((max_bytes + 1) as u64);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| MeshTransportCustodyError::CredentialReadFailed)?;
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(MeshTransportCustodyError::CredentialSizeOutOfBounds);
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
                let path =
                    std::env::temp_dir().join(format!("prw-phase152-c03b-{}-{id}", process::id()));
                fs::create_dir(&path).expect("create isolated C03b test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure C03b test directory mode");
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
                    fs::remove_file(&path).expect("replace C03b test credential");
                }
                fs::write(&path, bytes).expect("write C03b test credential");
                fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                    .expect("secure C03b credential mode");
            }

            fn populate_valid(&self) {
                self.write_credential(MESH_ROOT_CERTIFICATE_CREDENTIAL_NAME, b"root-der");
                self.write_credential(MESH_AGENT_CERTIFICATE_CREDENTIAL_NAME, b"agent-cert-der");
                self.write_credential(MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME, b"agent-private-key");
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
                Err(MeshTransportCustodyError::CredentialsDirectoryMissing)
            );
            assert_eq!(
                credentials_directory_from_value(Some(OsString::from("relative/path"))),
                Err(MeshTransportCustodyError::CredentialsDirectoryInvalid)
            );
        }

        #[test]
        fn fixed_credential_set_loads_without_network_io() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let material = load_from_credentials_directory(directory.path()).expect("material");
            assert_eq!(material.root_certificate_der(), b"root-der");
            assert_eq!(material.certificate_der(), b"agent-cert-der");
            assert_eq!(material.private_key_len(), b"agent-private-key".len());
            let debug = format!("{material:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("agent-private-key"));
        }

        #[test]
        fn consuming_tls_handoff_preserves_exact_der_and_zeroizing_key_container() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let material = load_from_credentials_directory(directory.path()).expect("material");
            let (root, certificate, private_key) = material.into_transport_tls_der();
            assert_eq!(root, b"root-der");
            assert_eq!(certificate, b"agent-cert-der");
            assert_eq!(&*private_key, b"agent-private-key");
        }

        #[test]
        fn rejects_symlink_credential() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let credential_path = directory.credential_path(MESH_ROOT_CERTIFICATE_CREDENTIAL_NAME);
            fs::remove_file(&credential_path).expect("remove regular root credential");
            let target = directory.credential_path("root-target");
            fs::write(&target, b"root-der").expect("write symlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o400))
                .expect("secure target mode");
            symlink(&target, credential_path).expect("create credential symlink");
            assert_eq!(
                load_from_credentials_directory(directory.path()).err(),
                Some(MeshTransportCustodyError::CredentialNotRegular)
            );
        }

        #[test]
        fn rejects_insecure_private_key_permissions() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            fs::set_permissions(
                directory.credential_path(MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME),
                fs::Permissions::from_mode(0o420),
            )
            .expect("set intentionally insecure key mode");
            assert_eq!(
                load_from_credentials_directory(directory.path()).err(),
                Some(MeshTransportCustodyError::CredentialPermissionsInsecure)
            );
        }

        #[test]
        fn rejects_oversized_private_key() {
            let directory = TestDirectory::new();
            directory.populate_valid();
            let oversized = vec![b'k'; MAX_AGENT_PRIVATE_KEY_PKCS8_DER_BYTES + 1];
            directory.write_credential(MESH_AGENT_PRIVATE_KEY_CREDENTIAL_NAME, &oversized);
            assert_eq!(
                load_from_credentials_directory(directory.path()).err(),
                Some(MeshTransportCustodyError::CredentialSizeOutOfBounds)
            );
        }
    }
}
