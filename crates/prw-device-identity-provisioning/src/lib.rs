//! Creation-only Ubuntu device-identity provisioning for Ownspace.
//!
//! This crate generates a new P-256 identity locally and persists only a systemd
//! encrypted credential plus its fixed per-user service credential binding. It
//! deliberately exposes no existing-key import/export, no arbitrary credential
//! name/path selection, no enrollment, and no networking.

#![cfg(target_os = "linux")]

use std::{
    env, fmt,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_device_identity_custody::SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME;
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use rustix::{
    fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with},
    process::getuid,
};
use zeroize::{Zeroize, Zeroizing};

/// Relative location of the persistent encrypted device-identity credential.
pub const DEVICE_IDENTITY_CIPHERTEXT_RELATIVE_PATH: &str =
    "private-remote-workspace/credentials/device-identity-private-key-v1.cred";

/// Relative location of the per-user service drop-in bound by Phase 124.
pub const DEVICE_IDENTITY_DROPIN_RELATIVE_PATH: &str =
    "systemd/user/prw-agent.service.d/20-device-identity-credential.conf";

const SYSTEMD_CREDS_PATH: &str = "/usr/bin/systemd-creds";
const MAX_ENCRYPTED_CREDENTIAL_BYTES: u64 = 65_536;
const MAX_DROPIN_BYTES: usize = 4_096;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const CIPHERTEXT_MODE: u32 = 0o600;
const DROPIN_MODE: u32 = 0o600;
const FORBIDDEN_INITIAL_CIPHERTEXT_MODE_BITS: u32 = 0o133;

/// Successful creation-only identity provisioning result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedDeviceIdentity {
    public_spki_sha256: [u8; 32],
    encrypted_credential_path: PathBuf,
}

impl ProvisionedDeviceIdentity {
    /// Returns SHA-256 over canonical public `SubjectPublicKeyInfo` DER.
    #[must_use]
    pub const fn public_spki_sha256(&self) -> [u8; 32] {
        self.public_spki_sha256
    }

    /// Returns the committed encrypted credential path.
    #[must_use]
    pub fn encrypted_credential_path(&self) -> &Path {
        &self.encrypted_credential_path
    }
}

/// Bounded non-secret failure classification for first identity provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIdentityProvisioningError {
    /// XDG state/HOME did not resolve to an absolute usable state root.
    InvalidStateRoot,
    /// XDG config/HOME did not resolve to an absolute usable config root.
    InvalidConfigRoot,
    /// The fixed encrypted-credential path cannot be represented safely in systemd syntax.
    InvalidCredentialBinding,
    /// A required existing directory failed ownership/type/mode validation.
    InsecureDirectory,
    /// A production identity ciphertext or credential drop-in already exists.
    AlreadyProvisioned,
    /// A required private PRW directory could not be created safely.
    DirectoryCreationFailed,
    /// Local P-256 private identity generation failed.
    KeyGenerationFailed,
    /// The generated key failed canonical signer construction.
    GeneratedIdentityInvalid,
    /// The locked systemd credential utility could not be started or failed.
    CredentialEncryptionFailed,
    /// The encrypted credential output was empty or exceeded its bound.
    EncryptedCredentialOutOfBounds,
    /// Temporary ciphertext persistence or validation failed.
    CiphertextWriteFailed,
    /// No-replace atomic ciphertext commit failed.
    CiphertextCommitFailed,
    /// Temporary credential drop-in persistence or validation failed.
    DropinWriteFailed,
    /// No-replace atomic credential drop-in commit failed.
    DropinCommitFailed,
    /// Final parent-directory durability synchronization failed.
    DirectorySyncFailed,
}

impl fmt::Display for DeviceIdentityProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidStateRoot => "invalid device identity state root",
            Self::InvalidConfigRoot => "invalid device identity config root",
            Self::InvalidCredentialBinding => "invalid device identity credential binding",
            Self::InsecureDirectory => "insecure device identity directory",
            Self::AlreadyProvisioned => "device identity is already provisioned",
            Self::DirectoryCreationFailed => "device identity directory creation failed",
            Self::KeyGenerationFailed => "device identity key generation failed",
            Self::GeneratedIdentityInvalid => "generated device identity failed validation",
            Self::CredentialEncryptionFailed => "device identity credential encryption failed",
            Self::EncryptedCredentialOutOfBounds => {
                "encrypted device identity credential out of bounds"
            }
            Self::CiphertextWriteFailed => "encrypted device identity persistence failed",
            Self::CiphertextCommitFailed => "encrypted device identity commit failed",
            Self::DropinWriteFailed => "device identity credential drop-in persistence failed",
            Self::DropinCommitFailed => "device identity credential drop-in commit failed",
            Self::DirectorySyncFailed => "device identity directory sync failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DeviceIdentityProvisioningError {}

/// Formats a public SHA-256 fingerprint as exactly 64 lowercase hexadecimal digits.
#[must_use]
pub fn sha256_hex(fingerprint: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in fingerprint {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Generates and atomically commits the first Ubuntu production device identity.
///
/// The private PKCS#8 value exists only in provider/zeroizing process memory and the
/// stdin pipe to `/usr/bin/systemd-creds`. Only encrypted ciphertext and the fixed
/// non-secret per-user systemd credential binding are persisted.
///
/// # Errors
///
/// Returns [`DeviceIdentityProvisioningError`] for invalid XDG roots, pre-existing
/// identity state, generation/encryption failure, insecure filesystem state, or
/// durability/atomic-commit failure.
pub fn provision_first_ubuntu_device_identity()
-> Result<ProvisionedDeviceIdentity, DeviceIdentityProvisioningError> {
    let uid = getuid().as_raw();
    let state_root = resolve_xdg_root("XDG_STATE_HOME", ".local/state")
        .ok_or(DeviceIdentityProvisioningError::InvalidStateRoot)?;
    let config_root = resolve_xdg_root("XDG_CONFIG_HOME", ".config")
        .ok_or(DeviceIdentityProvisioningError::InvalidConfigRoot)?;

    validate_existing_root(&state_root, uid)?;
    if config_root.exists() {
        validate_existing_root(&config_root, uid)?;
    }

    let final_ciphertext = state_root.join(DEVICE_IDENTITY_CIPHERTEXT_RELATIVE_PATH);
    let dropin = config_root.join(DEVICE_IDENTITY_DROPIN_RELATIVE_PATH);
    let dropin_payload = render_device_identity_dropin(&final_ciphertext)?;
    require_absent(&final_ciphertext)?;
    require_absent(&dropin)?;

    let application_dir = state_root.join("private-remote-workspace");
    ensure_private_directory(&application_dir, uid)?;
    let credential_dir = application_dir.join("credentials");
    ensure_private_directory(&credential_dir, uid)?;
    require_absent(&final_ciphertext)?;

    let generated =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .map_err(|_| DeviceIdentityProvisioningError::KeyGenerationFailed)?;
    let private_pkcs8 = Zeroizing::new(generated.as_ref().to_vec());
    drop(generated);
    let signer = UbuntuEnrollmentSigner::from_pkcs8_v1_der(private_pkcs8.as_slice())
        .map_err(|_| DeviceIdentityProvisioningError::GeneratedIdentityInvalid)?;
    let public_spki_sha256 = signer.public_identity_sha256();

    let temp_ciphertext = credential_dir.join(format!(
        ".device-identity-private-key-v1.cred.phase126.{}.tmp",
        std::process::id()
    ));
    require_absent(&temp_ciphertext)
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;

    if let Err(error) = encrypt_with_systemd_creds(&temp_ciphertext, private_pkcs8) {
        let _ = fs::remove_file(&temp_ciphertext);
        return Err(error);
    }

    let (opened_temp, opened_metadata) =
        match harden_validate_and_sync_ciphertext_temp(&temp_ciphertext, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_ciphertext);
                return Err(error);
            }
        };

    let commit_result = renameat_with(
        CWD,
        &temp_ciphertext,
        CWD,
        &final_ciphertext,
        RenameFlags::NOREPLACE,
    );
    if commit_result.is_err() {
        let _ = fs::remove_file(&temp_ciphertext);
        return Err(DeviceIdentityProvisioningError::CiphertextCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(&final_ciphertext) else {
        let _ = fs::remove_file(&final_ciphertext);
        return Err(DeviceIdentityProvisioningError::CiphertextCommitFailed);
    };
    if validate_ciphertext_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        let _ = fs::remove_file(&final_ciphertext);
        let _ = sync_directory(&credential_dir);
        return Err(DeviceIdentityProvisioningError::CiphertextCommitFailed);
    }
    drop(opened_temp);

    if sync_directory(&credential_dir).is_err() {
        let _ = fs::remove_file(&final_ciphertext);
        let _ = sync_directory(&credential_dir);
        return Err(DeviceIdentityProvisioningError::DirectorySyncFailed);
    }

    commit_device_identity_dropin(&config_root, &dropin, &dropin_payload, uid)?;

    Ok(ProvisionedDeviceIdentity {
        public_spki_sha256,
        encrypted_credential_path: final_ciphertext,
    })
}

fn resolve_xdg_root(variable: &str, home_suffix: &str) -> Option<PathBuf> {
    if let Some(value) = env::var_os(variable) {
        if value.is_empty() {
            return None;
        }
        let path = PathBuf::from(value);
        return path.is_absolute().then_some(path);
    }

    let home = env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(home_suffix))
}

fn validate_existing_root(path: &Path, uid: u32) -> Result<(), DeviceIdentityProvisioningError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DeviceIdentityProvisioningError::InsecureDirectory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(DeviceIdentityProvisioningError::InsecureDirectory);
    }
    Ok(())
}

fn ensure_private_directory(path: &Path, uid: u32) -> Result<(), DeviceIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(DeviceIdentityProvisioningError::InsecureDirectory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| DeviceIdentityProvisioningError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| DeviceIdentityProvisioningError::DirectoryCreationFailed)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| DeviceIdentityProvisioningError::DirectoryCreationFailed)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(DeviceIdentityProvisioningError::InsecureDirectory);
            }
        }
        Err(_) => return Err(DeviceIdentityProvisioningError::InsecureDirectory),
    }
    Ok(())
}

fn ensure_user_directory(path: &Path, uid: u32) -> Result<(), DeviceIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_root(path, uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| DeviceIdentityProvisioningError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| DeviceIdentityProvisioningError::DirectoryCreationFailed)?;
            validate_existing_root(path, uid)
        }
        Err(_) => Err(DeviceIdentityProvisioningError::InsecureDirectory),
    }
}

fn require_absent(path: &Path) -> Result<(), DeviceIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(DeviceIdentityProvisioningError::AlreadyProvisioned),
    }
}

fn render_device_identity_dropin(
    encrypted_credential_path: &Path,
) -> Result<Vec<u8>, DeviceIdentityProvisioningError> {
    if !encrypted_credential_path.is_absolute() {
        return Err(DeviceIdentityProvisioningError::InvalidCredentialBinding);
    }
    let path = encrypted_credential_path
        .to_str()
        .ok_or(DeviceIdentityProvisioningError::InvalidCredentialBinding)?;
    if path.is_empty()
        || path.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'\\' | b'\'' | b'"' | b'%')
        })
    {
        return Err(DeviceIdentityProvisioningError::InvalidCredentialBinding);
    }

    let payload = format!(
        "[Service]\nLoadCredentialEncrypted={SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME}:{path}\n"
    )
    .into_bytes();
    if payload.is_empty() || payload.len() > MAX_DROPIN_BYTES {
        return Err(DeviceIdentityProvisioningError::InvalidCredentialBinding);
    }
    Ok(payload)
}

fn commit_device_identity_dropin(
    config_root: &Path,
    final_dropin: &Path,
    payload: &[u8],
    uid: u32,
) -> Result<(), DeviceIdentityProvisioningError> {
    ensure_user_directory(config_root, uid)?;
    let systemd_dir = config_root.join("systemd");
    ensure_user_directory(&systemd_dir, uid)?;
    let user_dir = systemd_dir.join("user");
    ensure_user_directory(&user_dir, uid)?;
    let dropin_dir = user_dir.join("prw-agent.service.d");
    ensure_user_directory(&dropin_dir, uid)?;
    require_absent(final_dropin)?;

    let temp_dropin = dropin_dir.join(format!(
        ".20-device-identity-credential.conf.{}.tmp",
        std::process::id()
    ));
    require_absent(&temp_dropin).map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;

    let (opened_temp, opened_metadata) =
        match write_validate_and_sync_dropin_temp(&temp_dropin, payload, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_dropin);
                return Err(error);
            }
        };

    let commit_result = renameat_with(CWD, &temp_dropin, CWD, final_dropin, RenameFlags::NOREPLACE);
    if commit_result.is_err() {
        let _ = fs::remove_file(&temp_dropin);
        return Err(DeviceIdentityProvisioningError::DropinCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(final_dropin) else {
        return Err(DeviceIdentityProvisioningError::DropinCommitFailed);
    };
    if validate_dropin_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        let _ = fs::remove_file(final_dropin);
        let _ = sync_directory(&dropin_dir);
        return Err(DeviceIdentityProvisioningError::DropinCommitFailed);
    }
    drop(opened_temp);

    sync_directory(&dropin_dir).map_err(|_| DeviceIdentityProvisioningError::DirectorySyncFailed)
}

fn write_validate_and_sync_dropin_temp(
    path: &Path,
    payload: &[u8],
    uid: u32,
) -> Result<(File, fs::Metadata), DeviceIdentityProvisioningError> {
    if payload.is_empty() || payload.len() > MAX_DROPIN_BYTES {
        return Err(DeviceIdentityProvisioningError::DropinWriteFailed);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DROPIN_MODE)
        .open(path)
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;
    file.set_permissions(Permissions::from_mode(DROPIN_MODE))
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;
    file.write_all(payload)
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;
    file.flush()
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;
    file.sync_all()
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;

    let metadata = file
        .metadata()
        .map_err(|_| DeviceIdentityProvisioningError::DropinWriteFailed)?;
    validate_dropin_metadata(&metadata, uid)?;
    Ok((file, metadata))
}

fn validate_dropin_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), DeviceIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != DROPIN_MODE
        || metadata.len() == 0
        || metadata.len() > MAX_DROPIN_BYTES as u64
    {
        return Err(DeviceIdentityProvisioningError::DropinWriteFailed);
    }
    Ok(())
}

fn encrypt_with_systemd_creds(
    temp_ciphertext: &Path,
    mut private_pkcs8: Zeroizing<Vec<u8>>,
) -> Result<(), DeviceIdentityProvisioningError> {
    let mut child = Command::new(SYSTEMD_CREDS_PATH)
        .arg("--user")
        .arg("encrypt")
        .arg(format!("--name={SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME}"))
        .arg("-")
        .arg(temp_ciphertext)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| DeviceIdentityProvisioningError::CredentialEncryptionFailed)?;

    let write_result = child.stdin.take().map_or_else(
        || Err(io::Error::other("systemd-creds stdin unavailable")),
        |mut stdin| {
            stdin
                .write_all(private_pkcs8.as_slice())
                .and_then(|()| stdin.flush())
        },
    );
    private_pkcs8.zeroize();
    drop(private_pkcs8);

    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(DeviceIdentityProvisioningError::CredentialEncryptionFailed);
    }

    let status = child
        .wait()
        .map_err(|_| DeviceIdentityProvisioningError::CredentialEncryptionFailed)?;
    if !status.success() {
        return Err(DeviceIdentityProvisioningError::CredentialEncryptionFailed);
    }
    Ok(())
}

fn harden_validate_and_sync_ciphertext_temp(
    path: &Path,
    uid: u32,
) -> Result<(File, fs::Metadata), DeviceIdentityProvisioningError> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_initial_ciphertext_metadata(&before, uid)?;

    let owned_fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    let file = File::from(owned_fd);
    let opened = file
        .metadata()
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_initial_ciphertext_metadata(&opened, uid)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(DeviceIdentityProvisioningError::CiphertextWriteFailed);
    }

    file.set_permissions(Permissions::from_mode(CIPHERTEXT_MODE))
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    let hardened = file
        .metadata()
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_ciphertext_metadata(&hardened, uid)?;
    if hardened.dev() != opened.dev() || hardened.ino() != opened.ino() {
        return Err(DeviceIdentityProvisioningError::CiphertextWriteFailed);
    }
    file.sync_all()
        .map_err(|_| DeviceIdentityProvisioningError::CiphertextWriteFailed)?;
    Ok((file, hardened))
}

fn validate_initial_ciphertext_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), DeviceIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & FORBIDDEN_INITIAL_CIPHERTEXT_MODE_BITS != 0
    {
        return Err(DeviceIdentityProvisioningError::CiphertextWriteFailed);
    }
    validate_ciphertext_size(metadata)
}

fn validate_ciphertext_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), DeviceIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != CIPHERTEXT_MODE
    {
        return Err(DeviceIdentityProvisioningError::CiphertextWriteFailed);
    }
    validate_ciphertext_size(metadata)
}

fn validate_ciphertext_size(
    metadata: &fs::Metadata,
) -> Result<(), DeviceIdentityProvisioningError> {
    if metadata.len() == 0 || metadata.len() > MAX_ENCRYPTED_CREDENTIAL_BYTES {
        return Err(DeviceIdentityProvisioningError::EncryptedCredentialOutOfBounds);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        DeviceIdentityProvisioningError, SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME,
        render_device_identity_dropin, sha256_hex,
    };

    #[test]
    fn public_fingerprint_hex_is_fixed_lowercase_width() {
        let mut fingerprint = [0_u8; 32];
        fingerprint[0] = 0xab;
        fingerprint[31] = 0xef;
        let encoded = sha256_hex(fingerprint);
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[..2], "ab");
        assert_eq!(&encoded[62..], "ef");
        assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(encoded, encoded.to_ascii_lowercase());
    }

    #[test]
    fn device_identity_dropin_payload_is_exact() {
        let encrypted_path = Path::new(
            "/home/gersi365/.local/state/private-remote-workspace/credentials/device-identity-private-key-v1.cred",
        );
        let rendered = render_device_identity_dropin(encrypted_path).expect("render fixed binding");
        let expected = format!(
            "[Service]\nLoadCredentialEncrypted={SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME}:{}\n",
            encrypted_path.display()
        );
        assert_eq!(rendered, expected.into_bytes());
    }

    #[test]
    fn device_identity_dropin_rejects_relative_or_unsafe_paths() {
        assert_eq!(
            render_device_identity_dropin(Path::new("relative/device-identity.cred")),
            Err(DeviceIdentityProvisioningError::InvalidCredentialBinding)
        );
        assert_eq!(
            render_device_identity_dropin(Path::new("/home/user with space/device-identity.cred")),
            Err(DeviceIdentityProvisioningError::InvalidCredentialBinding)
        );
        assert_eq!(
            render_device_identity_dropin(Path::new("/home/user/%n/device-identity.cred")),
            Err(DeviceIdentityProvisioningError::InvalidCredentialBinding)
        );
    }
}
