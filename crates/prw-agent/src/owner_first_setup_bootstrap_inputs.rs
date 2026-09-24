//! First-setup bootstrap input sources for the owner PC.
//!
//! This module materializes typed generation, codec, loading, atomic creation and
//! composition for first-time owner bootstrap inputs. Executable startup reaches
//! these sources only through the validated first-run dispatcher path. The creation
//! seam is explicit; validation uses only disposable roots. This module does not
//! generate a production transport key,
//! open `SQLite`, invoke the fresh-owner transaction, or change service/network state.

use std::{
    fmt,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_connectivity::TransportIdentity;
use prw_control_plane::{DeviceIdentityBinding, PublicIdentityMaterial};
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};
use rustix::{
    fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with},
    process::geteuid,
};

/// Fixed non-secret owner logical-identity record location below XDG state.
pub const OWNER_LOGICAL_IDENTITY_RELATIVE_PATH: &str =
    "private-remote-workspace/bootstrap/owner-logical-identity-v1.bin";

const OWNER_LOGICAL_IDENTITY_MAGIC: [u8; 8] = *b"PRWOBI1\0";
const ENTROPY_BYTES: usize = 16;
const ENCODED_IDENTIFIER_BYTES: usize = 34;
const OWNER_LOGICAL_IDENTITY_RECORD_BYTES: usize =
    OWNER_LOGICAL_IDENTITY_MAGIC.len() + (ENCODED_IDENTIFIER_BYTES * 3);
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

/// One versioned, non-secret logical identity tuple for the initial owner PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerLogicalIdentityRecord {
    workspace: WorkspaceId,
    user: UserId,
    device: DeviceId,
}

impl OwnerLogicalIdentityRecord {
    /// Returns the internal workspace identifier.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace
    }

    /// Returns the internal initial-owner principal identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user
    }

    /// Returns the internal logical owner-PC device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device
    }

    /// Encodes the exact bounded v1 record.
    #[must_use]
    pub fn encode(&self) -> [u8; OWNER_LOGICAL_IDENTITY_RECORD_BYTES] {
        let mut output = [0_u8; OWNER_LOGICAL_IDENTITY_RECORD_BYTES];
        output[..OWNER_LOGICAL_IDENTITY_MAGIC.len()].copy_from_slice(&OWNER_LOGICAL_IDENTITY_MAGIC);

        let mut offset = OWNER_LOGICAL_IDENTITY_MAGIC.len();
        for value in [
            self.workspace.as_str(),
            self.user.as_str(),
            self.device.as_str(),
        ] {
            let bytes = value.as_bytes();
            output[offset..offset + ENCODED_IDENTIFIER_BYTES].copy_from_slice(bytes);
            offset += ENCODED_IDENTIFIER_BYTES;
        }
        output
    }
}

/// Result of ensuring the first owner logical-identity record exists exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerLogicalIdentityRecordOutcome {
    /// This call atomically created the first persistent record.
    Created(OwnerLogicalIdentityRecord),
    /// A valid persistent record already existed and was reused exactly.
    Existing(OwnerLogicalIdentityRecord),
}

impl OwnerLogicalIdentityRecordOutcome {
    /// Returns the authoritative logical identity tuple selected by this operation.
    #[must_use]
    pub const fn record(&self) -> &OwnerLogicalIdentityRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }

    /// Reports whether this call created persistent state.
    #[must_use]
    pub const fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Fully composed input required by the fresh-owner `SQLite` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerFirstSetupBootstrapInputs {
    binding: DeviceIdentityBinding,
    transport_identity: TransportIdentity,
}

impl OwnerFirstSetupBootstrapInputs {
    /// Returns the enrolled initial owner-PC device binding.
    #[must_use]
    pub const fn binding(&self) -> &DeviceIdentityBinding {
        &self.binding
    }

    /// Returns the current transport identity derived from the dedicated transport key.
    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.transport_identity
    }

    /// Consumes the carrier into the exact transaction arguments.
    #[must_use]
    pub fn into_parts(self) -> (DeviceIdentityBinding, TransportIdentity) {
        (self.binding, self.transport_identity)
    }
}

/// Fail-closed error for first-setup bootstrap input materialization.
#[derive(Debug)]
pub enum OwnerFirstSetupBootstrapInputError {
    /// OS cryptographic randomness was unavailable.
    RandomUnavailable,
    /// The versioned non-secret logical-identity record was malformed or non-canonical.
    MalformedLogicalIdentityRecord,
    /// XDG or HOME could not resolve to an absolute state root.
    InvalidStateRoot,
    /// State root was missing, symlinked, foreign-owned, or insecure.
    InsecureStateRoot,
    /// PRW application directory was absent or insecure.
    InsecureApplicationDirectory,
    /// Bootstrap directory was absent or insecure.
    InsecureBootstrapDirectory,
    /// The exact owner logical-identity record was absent or unsafe to open.
    LogicalIdentityRecordUnavailable,
    /// The record path was symlinked, non-regular, foreign-owned, or wrong-mode.
    LogicalIdentityRecordInsecure,
    /// The bounded record read failed.
    LogicalIdentityRecordReadFailed,
    /// A required private PRW bootstrap directory could not be created safely.
    DirectoryCreationFailed,
    /// Temporary record creation, write, validation, or durability failed.
    LogicalIdentityRecordWriteFailed,
    /// Atomic no-replace commit or final record verification failed.
    LogicalIdentityRecordCommitFailed,
    /// Final parent-directory durability synchronization failed.
    DirectorySyncFailed,
    /// Existing device-identity custody could not supply the public device identity.
    DeviceIdentityCustody(prw_device_identity_custody::UbuntuDeviceIdentityCustodyError),
    /// Dedicated transport-key custody could not supply the current transport identity.
    TransportIdentityCustody(prw_transport_identity_custody::UbuntuTransportIdentityCustodyError),
}

impl fmt::Display for OwnerFirstSetupBootstrapInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomUnavailable => formatter.write_str("owner identity randomness unavailable"),
            Self::MalformedLogicalIdentityRecord => {
                formatter.write_str("owner logical identity record malformed")
            }
            Self::InvalidStateRoot => formatter.write_str("owner bootstrap state root invalid"),
            Self::InsecureStateRoot => formatter.write_str("owner bootstrap state root insecure"),
            Self::InsecureApplicationDirectory => {
                formatter.write_str("owner bootstrap application directory insecure")
            }
            Self::InsecureBootstrapDirectory => {
                formatter.write_str("owner bootstrap directory insecure")
            }
            Self::LogicalIdentityRecordUnavailable => {
                formatter.write_str("owner logical identity record unavailable")
            }
            Self::LogicalIdentityRecordInsecure => {
                formatter.write_str("owner logical identity record insecure")
            }
            Self::LogicalIdentityRecordReadFailed => {
                formatter.write_str("owner logical identity record read failed")
            }
            Self::DirectoryCreationFailed => {
                formatter.write_str("owner logical identity directory creation failed")
            }
            Self::LogicalIdentityRecordWriteFailed => {
                formatter.write_str("owner logical identity record write failed")
            }
            Self::LogicalIdentityRecordCommitFailed => {
                formatter.write_str("owner logical identity record commit failed")
            }
            Self::DirectorySyncFailed => {
                formatter.write_str("owner logical identity directory sync failed")
            }
            Self::DeviceIdentityCustody(error) => {
                write!(formatter, "device identity custody failed: {error}")
            }
            Self::TransportIdentityCustody(error) => {
                write!(formatter, "transport identity custody failed: {error}")
            }
        }
    }
}

impl std::error::Error for OwnerFirstSetupBootstrapInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceIdentityCustody(error) => Some(error),
            Self::TransportIdentityCustody(error) => Some(error),
            _ => None,
        }
    }
}

/// Generates a fresh opaque logical identity tuple from independent 128-bit values.
///
/// This function only returns the in-memory non-secret record. It does not persist
/// anything; executable startup can reach it only through the bounded first-run ensure path.
///
/// # Errors
///
/// Returns `RandomUnavailable` when the OS cryptographic RNG cannot provide all
/// three independent values.
pub fn generate_owner_logical_identity_record()
-> Result<OwnerLogicalIdentityRecord, OwnerFirstSetupBootstrapInputError> {
    let random = SystemRandom::new();
    let mut workspace = [0_u8; ENTROPY_BYTES];
    let mut user = [0_u8; ENTROPY_BYTES];
    let mut device = [0_u8; ENTROPY_BYTES];
    random
        .fill(&mut workspace)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::RandomUnavailable)?;
    random
        .fill(&mut user)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::RandomUnavailable)?;
    random
        .fill(&mut device)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::RandomUnavailable)?;
    record_from_entropy(workspace, user, device)
}

/// Decodes the exact canonical v1 non-secret owner logical-identity record.
///
/// # Errors
///
/// Rejects wrong size or magic, non-UTF-8, wrong prefixes, non-lowercase-hex
/// identifiers, or identifiers rejected by the existing PRW domain types.
pub fn decode_owner_logical_identity_record(
    input: &[u8],
) -> Result<OwnerLogicalIdentityRecord, OwnerFirstSetupBootstrapInputError> {
    if input.len() != OWNER_LOGICAL_IDENTITY_RECORD_BYTES
        || input[..OWNER_LOGICAL_IDENTITY_MAGIC.len()] != OWNER_LOGICAL_IDENTITY_MAGIC
    {
        return Err(OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord);
    }

    let mut offset = OWNER_LOGICAL_IDENTITY_MAGIC.len();
    let workspace = decode_identifier(&input[offset..offset + ENCODED_IDENTIFIER_BYTES], "w-")?;
    offset += ENCODED_IDENTIFIER_BYTES;
    let user = decode_identifier(&input[offset..offset + ENCODED_IDENTIFIER_BYTES], "u-")?;
    offset += ENCODED_IDENTIFIER_BYTES;
    let device = decode_identifier(&input[offset..offset + ENCODED_IDENTIFIER_BYTES], "d-")?;

    Ok(OwnerLogicalIdentityRecord {
        workspace: WorkspaceId::new(workspace)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
        user: UserId::new(user)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
        device: DeviceId::new(device)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
    })
}

/// Loads the exact owner logical-identity record from current XDG or HOME state.
///
/// This is read-only and creates no directories or files.
///
/// # Errors
///
/// Fails closed for unresolved or insecure custody or malformed record bytes.
pub fn load_owner_logical_identity_record_from_env()
-> Result<OwnerLogicalIdentityRecord, OwnerFirstSetupBootstrapInputError> {
    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstSetupBootstrapInputError::InvalidStateRoot)?;
    load_owner_logical_identity_record_from_state_root(&state_root, geteuid().as_raw())
}

/// Ensures that the first owner logical-identity record exists exactly once.
///
/// This is a creation-only first-time-setup write seam. A valid existing record is
/// replayed exactly; it is never replaced or regenerated. A missing record is
/// generated locally, written to a same-directory temporary file, fsynced, and
/// committed with an atomic no-replace rename.
///
/// This function is reached only through validated first-run startup authority composition.
///
/// # Errors
///
/// Fails closed on invalid/insecure custody, malformed existing state, randomness
/// failure, write/commit failure, or parent-directory durability failure.
pub fn ensure_owner_logical_identity_record_from_env()
-> Result<OwnerLogicalIdentityRecordOutcome, OwnerFirstSetupBootstrapInputError> {
    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstSetupBootstrapInputError::InvalidStateRoot)?;
    ensure_owner_logical_identity_record_at_state_root(&state_root, geteuid().as_raw())
}

/// Purely composes already-authoritative identity parts into the fresh-owner YL transaction input.
#[must_use]
pub fn compose_owner_first_setup_bootstrap_inputs_from_identity_parts(
    workspace_id: &WorkspaceId,
    user_id: &UserId,
    device_id: &DeviceId,
    public_device_identity: &PublicIdentityMaterial,
    transport_identity: TransportIdentity,
) -> OwnerFirstSetupBootstrapInputs {
    OwnerFirstSetupBootstrapInputs {
        binding: DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            public_identity: public_device_identity.clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        },
        transport_identity,
    }
}

/// Purely composes an authoritative owner logical-identity record into the fresh-owner YL input.
#[must_use]
pub fn compose_owner_first_setup_bootstrap_inputs(
    record: &OwnerLogicalIdentityRecord,
    public_device_identity: &PublicIdentityMaterial,
    transport_identity: TransportIdentity,
) -> OwnerFirstSetupBootstrapInputs {
    compose_owner_first_setup_bootstrap_inputs_from_identity_parts(
        record.workspace_id(),
        record.user_id(),
        record.device_id(),
        public_device_identity,
        transport_identity,
    )
}

/// Loads all current authoritative owner bootstrap inputs without mutating authority.
///
/// This function is reached only through validated first-run startup authority composition.
///
/// # Errors
///
/// Propagates fail-closed record, device-identity custody, or transport-identity
/// custody failures. It never substitutes inferred or fallback identity values.
pub fn load_owner_first_setup_bootstrap_inputs_from_current_sources()
-> Result<OwnerFirstSetupBootstrapInputs, OwnerFirstSetupBootstrapInputError> {
    let record = load_owner_logical_identity_record_from_env()?;
    let signer =
        prw_device_identity_custody::load_ubuntu_enrollment_signer_from_systemd_credential()
            .map_err(OwnerFirstSetupBootstrapInputError::DeviceIdentityCustody)?;
    let transport_identity =
        prw_transport_identity_custody::load_ubuntu_transport_identity_from_systemd_credential()
            .map_err(OwnerFirstSetupBootstrapInputError::TransportIdentityCustody)?;

    Ok(compose_owner_first_setup_bootstrap_inputs(
        &record,
        signer.public_identity(),
        transport_identity,
    ))
}

fn record_from_entropy(
    workspace: [u8; ENTROPY_BYTES],
    user: [u8; ENTROPY_BYTES],
    device: [u8; ENTROPY_BYTES],
) -> Result<OwnerLogicalIdentityRecord, OwnerFirstSetupBootstrapInputError> {
    let workspace = encode_identifier("w-", workspace);
    let user = encode_identifier("u-", user);
    let device = encode_identifier("d-", device);
    Ok(OwnerLogicalIdentityRecord {
        workspace: WorkspaceId::new(workspace)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
        user: UserId::new(user)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
        device: DeviceId::new(device)
            .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?,
    })
}

fn encode_identifier(prefix: &str, entropy: [u8; ENTROPY_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(ENCODED_IDENTIFIER_BYTES);
    value.push_str(prefix);
    for byte in entropy {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn decode_identifier(
    bytes: &[u8],
    prefix: &str,
) -> Result<String, OwnerFirstSetupBootstrapInputError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)?;
    if value.len() != ENCODED_IDENTIFIER_BYTES
        || !value.starts_with(prefix)
        || !value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord);
    }
    Ok(value.to_owned())
}

fn ensure_owner_logical_identity_record_at_state_root(
    state_root: &Path,
    uid: u32,
) -> Result<OwnerLogicalIdentityRecordOutcome, OwnerFirstSetupBootstrapInputError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    ensure_private_directory(
        &application_dir,
        uid,
        OwnerFirstSetupBootstrapInputError::InsecureApplicationDirectory,
    )?;
    let bootstrap_dir = application_dir.join("bootstrap");
    ensure_private_directory(
        &bootstrap_dir,
        uid,
        OwnerFirstSetupBootstrapInputError::InsecureBootstrapDirectory,
    )?;

    let final_path = state_root.join(OWNER_LOGICAL_IDENTITY_RELATIVE_PATH);
    match fs::symlink_metadata(&final_path) {
        Ok(_) => {
            let existing = load_owner_logical_identity_record_from_state_root(state_root, uid)?;
            return Ok(OwnerLogicalIdentityRecordOutcome::Existing(existing));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordInsecure);
        }
    }

    let record = generate_owner_logical_identity_record()?;
    let encoded = record.encode();
    let temp_path = bootstrap_dir.join(format!(
        ".owner-logical-identity-v1.bin.c03e-yq.{}.tmp",
        std::process::id()
    ));
    match fs::symlink_metadata(&temp_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => {
            return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed);
        }
    }

    let (temp_file, temp_metadata) =
        match write_validate_and_sync_record_temp(&temp_path, &encoded, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                return Err(error);
            }
        };

    if renameat_with(CWD, &temp_path, CWD, &final_path, RenameFlags::NOREPLACE).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(&final_path) else {
        let _ = fs::remove_file(&final_path);
        return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordCommitFailed);
    };
    if validate_record_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != temp_metadata.dev()
        || final_metadata.ino() != temp_metadata.ino()
    {
        let _ = fs::remove_file(&final_path);
        let _ = sync_directory(&bootstrap_dir);
        return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordCommitFailed);
    }
    drop(temp_file);

    if sync_directory(&bootstrap_dir).is_err() {
        let _ = fs::remove_file(&final_path);
        let _ = sync_directory(&bootstrap_dir);
        return Err(OwnerFirstSetupBootstrapInputError::DirectorySyncFailed);
    }

    Ok(OwnerLogicalIdentityRecordOutcome::Created(record))
}

fn load_owner_logical_identity_record_from_state_root(
    state_root: &Path,
    uid: u32,
) -> Result<OwnerLogicalIdentityRecord, OwnerFirstSetupBootstrapInputError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    if !private_directory_is_secure(&application_dir, uid) {
        return Err(OwnerFirstSetupBootstrapInputError::InsecureApplicationDirectory);
    }
    let bootstrap_dir = application_dir.join("bootstrap");
    if !private_directory_is_secure(&bootstrap_dir, uid) {
        return Err(OwnerFirstSetupBootstrapInputError::InsecureBootstrapDirectory);
    }

    let path = state_root.join(OWNER_LOGICAL_IDENTITY_RELATIVE_PATH);
    let pre_open = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordUnavailable);
        }
        Err(_) => {
            return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordUnavailable);
        }
    };
    validate_record_metadata(&pre_open, uid)?;

    let fd = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordUnavailable)?;
    let file = File::from(fd);
    let opened = file
        .metadata()
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordUnavailable)?;
    if pre_open.dev() != opened.dev() || pre_open.ino() != opened.ino() {
        return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordInsecure);
    }
    validate_record_metadata(&opened, uid)?;

    let mut bytes = Vec::new();
    file.take((OWNER_LOGICAL_IDENTITY_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordReadFailed)?;
    decode_owner_logical_identity_record(&bytes)
}

fn validate_state_root(path: &Path, uid: u32) -> Result<(), OwnerFirstSetupBootstrapInputError> {
    if !path.is_absolute() {
        return Err(OwnerFirstSetupBootstrapInputError::InvalidStateRoot);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::InsecureStateRoot)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(OwnerFirstSetupBootstrapInputError::InsecureStateRoot);
    }
    Ok(())
}

fn ensure_private_directory(
    path: &Path,
    uid: u32,
    insecure: OwnerFirstSetupBootstrapInputError,
) -> Result<(), OwnerFirstSetupBootstrapInputError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| OwnerFirstSetupBootstrapInputError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| OwnerFirstSetupBootstrapInputError::DirectoryCreationFailed)?;
            if private_directory_is_secure(path, uid) {
                Ok(())
            } else {
                Err(insecure)
            }
        }
        Ok(_) if private_directory_is_secure(path, uid) => Ok(()),
        Ok(_) | Err(_) => Err(insecure),
    }
}

fn private_directory_is_secure(path: &Path, uid: u32) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    !metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == uid
        && metadata.mode() & 0o777 == PRIVATE_DIRECTORY_MODE
}

fn validate_record_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), OwnerFirstSetupBootstrapInputError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() != OWNER_LOGICAL_IDENTITY_RECORD_BYTES as u64
    {
        return Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordInsecure);
    }
    Ok(())
}

fn write_validate_and_sync_record_temp(
    path: &Path,
    payload: &[u8; OWNER_LOGICAL_IDENTITY_RECORD_BYTES],
    uid: u32,
) -> Result<(File, fs::Metadata), OwnerFirstSetupBootstrapInputError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed)?;
    file.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed)?;
    file.write_all(payload)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed)?;

    let metadata = file
        .metadata()
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed)?;
    validate_record_metadata(&metadata, uid)
        .map_err(|_| OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordWriteFailed)?;
    Ok((file, metadata))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
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

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };
    use rustix::process::geteuid;

    use super::{
        OWNER_LOGICAL_IDENTITY_MAGIC, OWNER_LOGICAL_IDENTITY_RELATIVE_PATH,
        OwnerFirstSetupBootstrapInputError, OwnerLogicalIdentityRecordOutcome,
        compose_owner_first_setup_bootstrap_inputs, decode_owner_logical_identity_record,
        ensure_owner_logical_identity_record_at_state_root, generate_owner_logical_identity_record,
        load_owner_logical_identity_record_from_state_root, record_from_entropy,
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestStateRoot {
        path: PathBuf,
    }

    impl TestStateRoot {
        fn new_root_only() -> Self {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("prw-c03e-yq-owner-{}-{id}", process::id()));
            fs::create_dir(&path).expect("create test state root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure state root");
            Self { path }
        }

        fn new() -> Self {
            let state = Self::new_root_only();
            let application = state.path.join("private-remote-workspace");
            let bootstrap = application.join("bootstrap");
            fs::create_dir(&application).expect("create application dir");
            fs::create_dir(&bootstrap).expect("create bootstrap dir");
            fs::set_permissions(&application, fs::Permissions::from_mode(0o700))
                .expect("secure application dir");
            fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o700))
                .expect("secure bootstrap dir");
            state
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn record_path(&self) -> PathBuf {
            self.path.join(OWNER_LOGICAL_IDENTITY_RELATIVE_PATH)
        }

        fn write_record(&self, bytes: &[u8]) {
            fs::write(self.record_path(), bytes).expect("write record");
            fs::set_permissions(self.record_path(), fs::Permissions::from_mode(0o600))
                .expect("secure record");
        }
    }

    impl Drop for TestStateRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn generated_record_is_canonical_and_round_trips() {
        let record = generate_owner_logical_identity_record().expect("generate record");
        for (prefix, value) in [
            ("w-", record.workspace_id().as_str()),
            ("u-", record.user_id().as_str()),
            ("d-", record.device_id().as_str()),
        ] {
            assert!(value.starts_with(prefix));
            assert_eq!(value.len(), 34);
            assert!(
                value[2..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
        }

        let encoded = record.encode();
        assert_eq!(
            &encoded[..OWNER_LOGICAL_IDENTITY_MAGIC.len()],
            &OWNER_LOGICAL_IDENTITY_MAGIC
        );
        assert_eq!(
            decode_owner_logical_identity_record(&encoded).expect("decode record"),
            record
        );
    }

    #[test]
    fn deterministic_entropy_produces_exact_stable_ids() {
        let record = record_from_entropy([0x11; 16], [0x22; 16], [0x33; 16])
            .expect("construct deterministic record");
        assert_eq!(
            record.workspace_id().as_str(),
            "w-11111111111111111111111111111111"
        );
        assert_eq!(
            record.user_id().as_str(),
            "u-22222222222222222222222222222222"
        );
        assert_eq!(
            record.device_id().as_str(),
            "d-33333333333333333333333333333333"
        );
    }

    #[test]
    fn malformed_or_extended_record_fails_closed() {
        let record = record_from_entropy([1; 16], [2; 16], [3; 16])
            .expect("construct record")
            .encode();
        let mut wrong_magic = record;
        wrong_magic[0] ^= 0xff;
        assert!(matches!(
            decode_owner_logical_identity_record(&wrong_magic),
            Err(OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)
        ));

        let mut extended = record.to_vec();
        extended.push(0);
        assert!(matches!(
            decode_owner_logical_identity_record(&extended),
            Err(OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)
        ));
    }

    #[test]
    fn secure_state_record_loads_and_symlink_is_rejected() {
        let state = TestStateRoot::new();
        let record = record_from_entropy([4; 16], [5; 16], [6; 16]).expect("construct record");
        state.write_record(&record.encode());

        assert_eq!(
            load_owner_logical_identity_record_from_state_root(state.path(), geteuid().as_raw())
                .expect("load exact record"),
            record
        );

        fs::remove_file(state.record_path()).expect("remove record");
        let external = state.path().join("external-record");
        fs::write(&external, record.encode()).expect("write external record");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600))
            .expect("secure external record");
        symlink(&external, state.record_path()).expect("symlink record");
        assert!(matches!(
            load_owner_logical_identity_record_from_state_root(state.path(), geteuid().as_raw()),
            Err(OwnerFirstSetupBootstrapInputError::LogicalIdentityRecordInsecure)
        ));
    }

    #[test]
    fn ensure_creates_once_and_replays_exact_existing_identity() {
        let state = TestStateRoot::new_root_only();
        let uid = geteuid().as_raw();

        let first = ensure_owner_logical_identity_record_at_state_root(state.path(), uid)
            .expect("create first owner identity record");
        assert!(first.was_created());
        let first_record = first.record().clone();

        let metadata = fs::symlink_metadata(state.record_path()).expect("created record metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let second = ensure_owner_logical_identity_record_at_state_root(state.path(), uid)
            .expect("replay existing owner identity record");
        assert!(!second.was_created());
        assert_eq!(second.record(), &first_record);
        assert!(matches!(
            second,
            OwnerLogicalIdentityRecordOutcome::Existing(_)
        ));
    }

    #[test]
    fn ensure_rejects_malformed_existing_identity_without_replacement() {
        let state = TestStateRoot::new();
        let mut malformed = record_from_entropy([0x41; 16], [0x42; 16], [0x43; 16])
            .expect("construct record")
            .encode();
        malformed[0] ^= 0xff;
        state.write_record(&malformed);

        assert!(matches!(
            ensure_owner_logical_identity_record_at_state_root(state.path(), geteuid().as_raw()),
            Err(OwnerFirstSetupBootstrapInputError::MalformedLogicalIdentityRecord)
        ));
        assert_eq!(
            fs::read(state.record_path()).expect("existing malformed record remains"),
            malformed
        );
    }

    #[test]
    fn composition_preserves_three_identity_roles_without_capability_grant() {
        let record = record_from_entropy([7; 16], [8; 16], [9; 16]).expect("construct record");
        let public_identity = PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![1, 2, 3],
        )
        .expect("public identity");
        let transport_identity = TransportIdentity::new([0x55; 32]).expect("transport identity");

        let inputs = compose_owner_first_setup_bootstrap_inputs(
            &record,
            &public_identity,
            transport_identity,
        );
        assert_eq!(&inputs.binding().workspace_id, record.workspace_id());
        assert_eq!(&inputs.binding().user_id, record.user_id());
        assert_eq!(&inputs.binding().device_id, record.device_id());
        assert_eq!(&inputs.binding().public_identity, &public_identity);
        assert!(inputs.binding().lifecycle.can_participate());
        assert_eq!(inputs.transport_identity(), transport_identity);
    }
}
