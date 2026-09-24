//! XDG-state setup-intent adapter for owner-PC first-run authority.
//!
//! C03e-ZF implements the owner-locked representation, C03e-ZG adds the explicit
//! create-once writer, and C03e-ZK adds post-success retirement for the same fixed
//! versioned record. Startup uses only the fail-closed reader/classifier and retirement path.
//! None of these functions is referenced by Agent startup, ZC, installer,
//! Desktop, systemd, or another production activation call site.

use std::{
    fmt,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use rustix::{
    fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with},
    process::geteuid,
};

use prw_registry::durable_registry_sqlite_store::OwnerPcLocalAuthorityBootstrapOutcome;

use crate::owner_first_setup_custody_policy_orchestration::OwnerFirstSetupTransportCustodySelection;

/// Owner-locked non-secret first-run transport-custody intent record location.
pub const OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH: &str =
    "private-remote-workspace/setup/owner-first-run-transport-custody-intent-v1";

const PREFERRED_DEFAULT_INTENT: &[u8] = b"preferred-default-v1\n";
const EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT: &[u8] = b"explicit-host-key-only-fallback-v1\n";
const MAX_INTENT_RECORD_BYTES: usize = EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT.len();
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Result of ensuring the owner-locked first-run setup-intent record exists once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFirstRunSetupIntentWriteOutcome {
    /// This call atomically created the canonical record.
    Created(OwnerFirstSetupTransportCustodySelection),
    /// The exact requested canonical selection already existed and was reused.
    Existing(OwnerFirstSetupTransportCustodySelection),
}

impl OwnerFirstRunSetupIntentWriteOutcome {
    /// Returns the exact authoritative typed selection represented by the record.
    #[must_use]
    pub const fn selection(self) -> OwnerFirstSetupTransportCustodySelection {
        match self {
            Self::Created(selection) | Self::Existing(selection) => selection,
        }
    }

    /// Reports whether this call created persistent setup-intent state.
    #[must_use]
    pub const fn was_created(self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Result of one post-success setup-intent retirement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFirstRunSetupIntentRetirementOutcome {
    /// The exact validated matching setup-intent record was removed.
    Retired(OwnerFirstSetupTransportCustodySelection),
    /// The fixed record was already absent in the caller's post-success context.
    AlreadyRetired,
}

/// Validated startup-dispatch presence of the fixed first-run setup-intent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFirstRunSetupIntentPresence {
    /// A present record passed the existing exact custody and canonical-token validation.
    Present,
    /// The fixed record is absent beneath an otherwise valid established setup custody path.
    Absent,
}

/// Fail-closed error for the locked XDG-state first-run setup-intent adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFirstRunSetupIntentError {
    /// XDG or HOME could not resolve to an absolute state root.
    InvalidStateRoot,
    /// State root was missing, symlinked, foreign-owned, or group/world writable.
    InsecureStateRoot,
    /// PRW application directory was absent or insecure.
    InsecureApplicationDirectory,
    /// Fixed setup directory was absent or insecure.
    InsecureSetupDirectory,
    /// The exact setup-intent record was absent or could not be opened safely.
    IntentRecordUnavailable,
    /// The record was symlinked, non-regular, foreign-owned, wrong-mode, or wrong-size.
    IntentRecordInsecure,
    /// The bounded record read failed.
    IntentRecordReadFailed,
    /// Record bytes were not one exact canonical owner-locked token.
    MalformedIntentRecord,
    /// A required private PRW setup directory could not be created safely.
    DirectoryCreationFailed,
    /// Temporary canonical record creation, write, validation, or durability failed.
    IntentRecordWriteFailed,
    /// A valid existing record carries the other owner-locked selection.
    ConflictingIntentRecord,
    /// Atomic no-replace publication or final record verification failed.
    IntentRecordCommitFailed,
    /// Exact matching record removal or post-remove verification failed.
    IntentRecordRetirementFailed,
    /// Final setup-directory durability synchronization failed.
    DirectorySyncFailed,
}

impl fmt::Display for OwnerFirstRunSetupIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStateRoot => "owner first-run setup-intent state root invalid",
            Self::InsecureStateRoot => "owner first-run setup-intent state root insecure",
            Self::InsecureApplicationDirectory => {
                "owner first-run setup-intent application directory insecure"
            }
            Self::InsecureSetupDirectory => "owner first-run setup-intent directory insecure",
            Self::IntentRecordUnavailable => "owner first-run setup-intent record unavailable",
            Self::IntentRecordInsecure => "owner first-run setup-intent record insecure",
            Self::IntentRecordReadFailed => "owner first-run setup-intent record read failed",
            Self::MalformedIntentRecord => "owner first-run setup-intent record malformed",
            Self::DirectoryCreationFailed => {
                "owner first-run setup-intent directory creation failed"
            }
            Self::IntentRecordWriteFailed => "owner first-run setup-intent record write failed",
            Self::ConflictingIntentRecord => {
                "owner first-run setup-intent record conflicts with requested selection"
            }
            Self::IntentRecordCommitFailed => "owner first-run setup-intent record commit failed",
            Self::IntentRecordRetirementFailed => {
                "owner first-run setup-intent record retirement failed"
            }
            Self::DirectorySyncFailed => "owner first-run setup-intent directory sync failed",
        })
    }
}

impl std::error::Error for OwnerFirstRunSetupIntentError {}

/// Loads the owner-locked first-run custody selection from current XDG/HOME state.
///
/// This function is read-only. It does not create, repair, replace, retire, or
/// normalize the setup-intent record.
///
/// # Errors
///
/// Fails closed on unresolved/insecure custody, absent state, unsafe metadata,
/// read failure, or bytes other than the two exact canonical owner-locked tokens.
pub fn load_owner_first_run_transport_custody_selection_from_env()
-> Result<OwnerFirstSetupTransportCustodySelection, OwnerFirstRunSetupIntentError> {
    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstRunSetupIntentError::InvalidStateRoot)?;

    load_owner_first_run_transport_custody_selection_from_state_root(
        &state_root,
        geteuid().as_raw(),
    )
}

/// Classifies only validated pending first-run intent versus exact record absence.
///
/// `Present` is returned only after the existing record passes the same fail-closed
/// custody and canonical-token validation as the authoritative reader. `Absent`
/// is returned only when the fixed record is missing beneath an otherwise secure
/// existing PRW/setup directory chain.
///
/// This function never maps malformed, insecure, unreadable, or ambiguous state
/// to `Absent`.
///
/// # Errors
///
/// Fails closed on unresolved/insecure custody or any present record that cannot
/// be validated exactly.
pub fn inspect_owner_first_run_setup_intent_presence_from_env()
-> Result<OwnerFirstRunSetupIntentPresence, OwnerFirstRunSetupIntentError> {
    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstRunSetupIntentError::InvalidStateRoot)?;

    inspect_owner_first_run_setup_intent_presence_at_state_root(&state_root, geteuid().as_raw())
}

/// Ensures that one exact owner-locked first-run setup-intent record exists.
///
/// This is a create-once, exact-replay write seam. A missing record is written
/// atomically from the caller-supplied typed selection. An existing valid record
/// is reused only when it represents that exact same selection. A different
/// valid selection is a conflict and is never overwritten.
///
/// This explicit authoring seam is used by the dedicated `prw-first-run` command.
/// Agent startup only reads/classifies and retires the resulting record; it never
/// authors or silently replaces setup intent. Desktop, installer/package hooks and
/// systemd do not call this writer.
///
/// # Errors
///
/// Fails closed on invalid/insecure custody, malformed or conflicting existing
/// state, unsafe directory creation, write/commit failure, or durability failure.
pub fn ensure_owner_first_run_transport_custody_intent_from_env(
    selection: OwnerFirstSetupTransportCustodySelection,
) -> Result<OwnerFirstRunSetupIntentWriteOutcome, OwnerFirstRunSetupIntentError> {
    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstRunSetupIntentError::InvalidStateRoot)?;

    ensure_owner_first_run_transport_custody_intent_at_state_root(
        &state_root,
        geteuid().as_raw(),
        selection,
    )
}

/// Retires the exact matching first-run setup-intent record after local-authority success.
///
/// The caller supplies the exact typed selection used by the completed first-run
/// attempt plus the successful local-authority bootstrap outcome returned by that
/// same bounded flow. The outcome type has only the `Initialized` and `AlreadyCurrent`
/// success states; this entrypoint never accepts an error result.
///
/// This function does not inspect or mutate `SQLite`, infer setup intent, or call ZC,
/// Agent startup, installer, Desktop, systemd, or services.
///
/// # Errors
///
/// Fails closed on invalid/insecure custody, malformed or mismatched present state,
/// removal failure, or final setup-directory durability failure.
pub fn retire_owner_first_run_transport_custody_intent_after_local_authority_success_from_env(
    selection: OwnerFirstSetupTransportCustodySelection,
    local_authority_outcome: OwnerPcLocalAuthorityBootstrapOutcome,
) -> Result<OwnerFirstRunSetupIntentRetirementOutcome, OwnerFirstRunSetupIntentError> {
    match local_authority_outcome {
        OwnerPcLocalAuthorityBootstrapOutcome::Initialized
        | OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent => {}
    }

    let state_root = prw_registry::durable_registry_sqlite_custody::resolve_owner_pc_state_root(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .ok_or(OwnerFirstRunSetupIntentError::InvalidStateRoot)?;

    retire_owner_first_run_transport_custody_intent_at_state_root(
        &state_root,
        geteuid().as_raw(),
        selection,
    )
}

fn retire_owner_first_run_transport_custody_intent_at_state_root(
    state_root: &Path,
    uid: u32,
    expected_selection: OwnerFirstSetupTransportCustodySelection,
) -> Result<OwnerFirstRunSetupIntentRetirementOutcome, OwnerFirstRunSetupIntentError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    if !private_directory_is_secure(&application_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureApplicationDirectory);
    }

    let setup_dir = application_dir.join("setup");
    if !private_directory_is_secure(&setup_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureSetupDirectory);
    }

    let final_path = state_root.join(OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH);
    let pre_validation = match fs::symlink_metadata(&final_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired);
        }
        Err(_) => return Err(OwnerFirstRunSetupIntentError::IntentRecordUnavailable),
    };
    validate_intent_record_metadata(&pre_validation, uid)?;

    let existing =
        load_owner_first_run_transport_custody_selection_from_state_root(state_root, uid)?;
    if existing != expected_selection {
        return Err(OwnerFirstRunSetupIntentError::ConflictingIntentRecord);
    }

    let pre_remove = fs::symlink_metadata(&final_path)
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordRetirementFailed)?;
    validate_intent_record_metadata(&pre_remove, uid)?;
    if pre_validation.dev() != pre_remove.dev() || pre_validation.ino() != pre_remove.ino() {
        return Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure);
    }

    fs::remove_file(&final_path)
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordRetirementFailed)?;

    match fs::symlink_metadata(&final_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => {
            return Err(OwnerFirstRunSetupIntentError::IntentRecordRetirementFailed);
        }
    }

    if sync_directory(&setup_dir).is_err() {
        return Err(OwnerFirstRunSetupIntentError::DirectorySyncFailed);
    }

    Ok(OwnerFirstRunSetupIntentRetirementOutcome::Retired(existing))
}

fn ensure_owner_first_run_transport_custody_intent_at_state_root(
    state_root: &Path,
    uid: u32,
    selection: OwnerFirstSetupTransportCustodySelection,
) -> Result<OwnerFirstRunSetupIntentWriteOutcome, OwnerFirstRunSetupIntentError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    ensure_private_directory(
        &application_dir,
        uid,
        OwnerFirstRunSetupIntentError::InsecureApplicationDirectory,
    )?;
    let setup_dir = application_dir.join("setup");
    ensure_private_directory(
        &setup_dir,
        uid,
        OwnerFirstRunSetupIntentError::InsecureSetupDirectory,
    )?;

    let final_path = state_root.join(OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH);
    match fs::symlink_metadata(&final_path) {
        Ok(_) => {
            let existing =
                load_owner_first_run_transport_custody_selection_from_state_root(state_root, uid)?;
            if existing != selection {
                return Err(OwnerFirstRunSetupIntentError::ConflictingIntentRecord);
            }
            return Ok(OwnerFirstRunSetupIntentWriteOutcome::Existing(existing));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure),
    }

    let payload = canonical_owner_first_run_transport_custody_intent(selection);
    let temp_path = setup_dir.join(format!(
        ".owner-first-run-transport-custody-intent-v1.c03e-zg.{}.tmp",
        std::process::id()
    ));
    match fs::symlink_metadata(&temp_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(OwnerFirstRunSetupIntentError::IntentRecordWriteFailed),
    }

    let (temp_file, temp_metadata) =
        match write_validate_and_sync_intent_temp(&temp_path, payload, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                return Err(error);
            }
        };

    if renameat_with(CWD, &temp_path, CWD, &final_path, RenameFlags::NOREPLACE).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(OwnerFirstRunSetupIntentError::IntentRecordCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(&final_path) else {
        let _ = fs::remove_file(&final_path);
        return Err(OwnerFirstRunSetupIntentError::IntentRecordCommitFailed);
    };
    if validate_intent_record_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != temp_metadata.dev()
        || final_metadata.ino() != temp_metadata.ino()
    {
        let _ = fs::remove_file(&final_path);
        let _ = sync_directory(&setup_dir);
        return Err(OwnerFirstRunSetupIntentError::IntentRecordCommitFailed);
    }
    drop(temp_file);

    if sync_directory(&setup_dir).is_err() {
        let _ = fs::remove_file(&final_path);
        let _ = sync_directory(&setup_dir);
        return Err(OwnerFirstRunSetupIntentError::DirectorySyncFailed);
    }

    Ok(OwnerFirstRunSetupIntentWriteOutcome::Created(selection))
}

fn inspect_owner_first_run_setup_intent_presence_at_state_root(
    state_root: &Path,
    uid: u32,
) -> Result<OwnerFirstRunSetupIntentPresence, OwnerFirstRunSetupIntentError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    if !private_directory_is_secure(&application_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureApplicationDirectory);
    }

    let setup_dir = application_dir.join("setup");
    if !private_directory_is_secure(&setup_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureSetupDirectory);
    }

    let path = state_root.join(OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(OwnerFirstRunSetupIntentPresence::Absent)
        }
        Err(_) => Err(OwnerFirstRunSetupIntentError::IntentRecordUnavailable),
        Ok(_) => {
            load_owner_first_run_transport_custody_selection_from_state_root(state_root, uid)?;
            Ok(OwnerFirstRunSetupIntentPresence::Present)
        }
    }
}

fn load_owner_first_run_transport_custody_selection_from_state_root(
    state_root: &Path,
    uid: u32,
) -> Result<OwnerFirstSetupTransportCustodySelection, OwnerFirstRunSetupIntentError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    if !private_directory_is_secure(&application_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureApplicationDirectory);
    }

    let setup_dir = application_dir.join("setup");
    if !private_directory_is_secure(&setup_dir, uid) {
        return Err(OwnerFirstRunSetupIntentError::InsecureSetupDirectory);
    }

    let path = state_root.join(OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH);
    let pre_open = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(OwnerFirstRunSetupIntentError::IntentRecordUnavailable);
        }
        Err(_) => return Err(OwnerFirstRunSetupIntentError::IntentRecordUnavailable),
    };
    validate_intent_record_metadata(&pre_open, uid)?;

    let fd = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordUnavailable)?;
    let file = File::from(fd);
    let opened = file
        .metadata()
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordUnavailable)?;
    if pre_open.dev() != opened.dev() || pre_open.ino() != opened.ino() {
        return Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure);
    }
    validate_intent_record_metadata(&opened, uid)?;

    let mut bytes = Vec::new();
    file.take((MAX_INTENT_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordReadFailed)?;

    decode_owner_first_run_transport_custody_intent(&bytes)
}

fn decode_owner_first_run_transport_custody_intent(
    input: &[u8],
) -> Result<OwnerFirstSetupTransportCustodySelection, OwnerFirstRunSetupIntentError> {
    match input {
        PREFERRED_DEFAULT_INTENT => Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault),
        EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT => {
            Ok(OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback)
        }
        _ => Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord),
    }
}

const fn canonical_owner_first_run_transport_custody_intent(
    selection: OwnerFirstSetupTransportCustodySelection,
) -> &'static [u8] {
    match selection {
        OwnerFirstSetupTransportCustodySelection::PreferredDefault => PREFERRED_DEFAULT_INTENT,
        OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback => {
            EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT
        }
    }
}

fn validate_state_root(path: &Path, uid: u32) -> Result<(), OwnerFirstRunSetupIntentError> {
    if !path.is_absolute() {
        return Err(OwnerFirstRunSetupIntentError::InvalidStateRoot);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| OwnerFirstRunSetupIntentError::InsecureStateRoot)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(OwnerFirstRunSetupIntentError::InsecureStateRoot);
    }
    Ok(())
}

fn ensure_private_directory(
    path: &Path,
    uid: u32,
    insecure: OwnerFirstRunSetupIntentError,
) -> Result<(), OwnerFirstRunSetupIntentError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| OwnerFirstRunSetupIntentError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| OwnerFirstRunSetupIntentError::DirectoryCreationFailed)?;
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

fn validate_intent_record_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), OwnerFirstRunSetupIntentError> {
    let valid_size = metadata.len() == PREFERRED_DEFAULT_INTENT.len() as u64
        || metadata.len() == EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT.len() as u64;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        || !valid_size
    {
        return Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure);
    }
    Ok(())
}

fn write_validate_and_sync_intent_temp(
    path: &Path,
    payload: &[u8],
    uid: u32,
) -> Result<(File, fs::Metadata), OwnerFirstRunSetupIntentError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordWriteFailed)?;
    file.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordWriteFailed)?;
    file.write_all(payload)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordWriteFailed)?;

    let metadata = file
        .metadata()
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordWriteFailed)?;
    validate_intent_record_metadata(&metadata, uid)
        .map_err(|_| OwnerFirstRunSetupIntentError::IntentRecordWriteFailed)?;
    Ok((file, metadata))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rustix::process::geteuid;

    use super::{
        EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT,
        OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH, OwnerFirstRunSetupIntentError,
        OwnerFirstRunSetupIntentPresence, OwnerFirstRunSetupIntentRetirementOutcome,
        OwnerFirstRunSetupIntentWriteOutcome, PREFERRED_DEFAULT_INTENT,
        decode_owner_first_run_transport_custody_intent,
        ensure_owner_first_run_transport_custody_intent_at_state_root,
        inspect_owner_first_run_setup_intent_presence_at_state_root,
        load_owner_first_run_transport_custody_selection_from_state_root,
        retire_owner_first_run_transport_custody_intent_at_state_root,
    };
    use crate::owner_first_setup_custody_policy_orchestration::OwnerFirstSetupTransportCustodySelection;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestStateRoot {
        path: PathBuf,
    }

    impl TestStateRoot {
        fn new_root_only() -> Self {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("prw-c03e-zg-setup-intent-{}-{id}", process::id()));
            fs::create_dir(&path).expect("create state root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure state root");
            Self { path }
        }

        fn new() -> Self {
            let state = Self::new_root_only();
            let application = state.path.join("private-remote-workspace");
            let setup = application.join("setup");

            fs::create_dir(&application).expect("create application directory");
            fs::create_dir(&setup).expect("create setup directory");
            for directory in [&application, &setup] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("secure directory");
            }

            state
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn setup_dir(&self) -> PathBuf {
            self.path.join("private-remote-workspace/setup")
        }

        fn intent_path(&self) -> PathBuf {
            self.path
                .join(OWNER_FIRST_RUN_TRANSPORT_CUSTODY_INTENT_RELATIVE_PATH)
        }

        fn write_intent(&self, bytes: &[u8]) {
            fs::write(self.intent_path(), bytes).expect("write setup intent");
            fs::set_permissions(self.intent_path(), fs::Permissions::from_mode(0o600))
                .expect("secure setup intent");
        }
    }

    impl Drop for TestStateRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn canonical_tokens_map_to_exact_typed_selections() {
        assert_eq!(
            decode_owner_first_run_transport_custody_intent(PREFERRED_DEFAULT_INTENT),
            Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault)
        );
        assert_eq!(
            decode_owner_first_run_transport_custody_intent(EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT),
            Ok(OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback)
        );
    }

    #[test]
    fn secure_fixed_record_loads_both_owner_locked_selections() {
        for (bytes, expected) in [
            (
                PREFERRED_DEFAULT_INTENT,
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            (
                EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT,
                OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
            ),
        ] {
            let state = TestStateRoot::new();
            state.write_intent(bytes);

            assert_eq!(
                load_owner_first_run_transport_custody_selection_from_state_root(
                    state.path(),
                    geteuid().as_raw(),
                ),
                Ok(expected)
            );
        }
    }

    #[test]
    fn startup_presence_classifies_only_valid_present_or_exact_absent_state() {
        for bytes in [
            PREFERRED_DEFAULT_INTENT,
            EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT,
        ] {
            let state = TestStateRoot::new();
            state.write_intent(bytes);
            assert_eq!(
                inspect_owner_first_run_setup_intent_presence_at_state_root(
                    state.path(),
                    geteuid().as_raw(),
                ),
                Ok(OwnerFirstRunSetupIntentPresence::Present)
            );
        }

        let absent = TestStateRoot::new();
        assert_eq!(
            inspect_owner_first_run_setup_intent_presence_at_state_root(
                absent.path(),
                geteuid().as_raw(),
            ),
            Ok(OwnerFirstRunSetupIntentPresence::Absent)
        );
    }

    #[test]
    fn startup_presence_never_maps_invalid_present_state_to_absent() {
        let malformed = TestStateRoot::new();
        malformed.write_intent(b"preferred-default-v2\n");
        assert_eq!(
            inspect_owner_first_run_setup_intent_presence_at_state_root(
                malformed.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord)
        );
        assert!(malformed.intent_path().exists());

        let insecure = TestStateRoot::new();
        insecure.write_intent(PREFERRED_DEFAULT_INTENT);
        fs::set_permissions(insecure.intent_path(), fs::Permissions::from_mode(0o644))
            .expect("weaken setup-intent mode");
        assert_eq!(
            inspect_owner_first_run_setup_intent_presence_at_state_root(
                insecure.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure)
        );
        assert!(insecure.intent_path().exists());

        let incomplete_custody = TestStateRoot::new_root_only();
        assert_eq!(
            inspect_owner_first_run_setup_intent_presence_at_state_root(
                incomplete_custody.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::InsecureApplicationDirectory)
        );
    }

    #[test]
    fn writer_creates_private_custody_for_both_owner_locked_selections() {
        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            let state = TestStateRoot::new_root_only();

            assert_eq!(
                ensure_owner_first_run_transport_custody_intent_at_state_root(
                    state.path(),
                    geteuid().as_raw(),
                    selection,
                ),
                Ok(OwnerFirstRunSetupIntentWriteOutcome::Created(selection))
            );
            assert_eq!(
                load_owner_first_run_transport_custody_selection_from_state_root(
                    state.path(),
                    geteuid().as_raw(),
                ),
                Ok(selection)
            );

            for directory in [
                state.path().join("private-remote-workspace"),
                state.setup_dir(),
            ] {
                assert_eq!(
                    fs::symlink_metadata(directory)
                        .expect("created private directory")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
            assert_eq!(
                fs::symlink_metadata(state.intent_path())
                    .expect("created intent record")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn writer_exact_replay_reuses_same_record_object() {
        let state = TestStateRoot::new_root_only();
        let selection = OwnerFirstSetupTransportCustodySelection::PreferredDefault;

        assert_eq!(
            ensure_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                selection,
            ),
            Ok(OwnerFirstRunSetupIntentWriteOutcome::Created(selection))
        );
        let before = fs::symlink_metadata(state.intent_path()).expect("created intent record");

        assert_eq!(
            ensure_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                selection,
            ),
            Ok(OwnerFirstRunSetupIntentWriteOutcome::Existing(selection))
        );
        let after = fs::symlink_metadata(state.intent_path()).expect("replayed intent record");
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    }

    #[test]
    fn writer_rejects_conflicting_valid_selection_without_replacement() {
        let state = TestStateRoot::new_root_only();
        let preferred = OwnerFirstSetupTransportCustodySelection::PreferredDefault;
        let fallback = OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback;

        assert_eq!(
            ensure_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                preferred,
            ),
            Ok(OwnerFirstRunSetupIntentWriteOutcome::Created(preferred))
        );
        let before = fs::read(state.intent_path()).expect("read preferred intent");

        assert_eq!(
            ensure_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                fallback,
            ),
            Err(OwnerFirstRunSetupIntentError::ConflictingIntentRecord)
        );
        assert_eq!(
            fs::read(state.intent_path()).expect("read preserved intent"),
            before
        );
        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Ok(preferred)
        );
    }

    #[test]
    fn writer_never_replaces_malformed_existing_state() {
        let state = TestStateRoot::new();
        let malformed = b"preferred-default-v2\n";
        state.write_intent(malformed);

        assert_eq!(
            ensure_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord)
        );
        assert_eq!(
            fs::read(state.intent_path()).expect("read preserved malformed intent"),
            malformed
        );
    }

    #[test]
    fn retirement_removes_only_exact_matching_intent_and_is_idempotent() {
        for (bytes, selection) in [
            (
                PREFERRED_DEFAULT_INTENT,
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            (
                EXPLICIT_HOST_KEY_ONLY_FALLBACK_INTENT,
                OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
            ),
        ] {
            let state = TestStateRoot::new();
            state.write_intent(bytes);
            let unrelated = state.setup_dir().join("unrelated-state");
            fs::write(&unrelated, b"preserve\n").expect("write unrelated state");
            fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600))
                .expect("secure unrelated state");

            assert_eq!(
                retire_owner_first_run_transport_custody_intent_at_state_root(
                    state.path(),
                    geteuid().as_raw(),
                    selection,
                ),
                Ok(OwnerFirstRunSetupIntentRetirementOutcome::Retired(
                    selection
                ))
            );
            assert!(!state.intent_path().exists());
            assert_eq!(
                fs::read(&unrelated).expect("preserved unrelated state"),
                b"preserve\n"
            );
            assert!(state.setup_dir().is_dir());
            assert!(state.path().join("private-remote-workspace").is_dir());

            assert_eq!(
                retire_owner_first_run_transport_custody_intent_at_state_root(
                    state.path(),
                    geteuid().as_raw(),
                    selection,
                ),
                Ok(OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired)
            );
            assert!(unrelated.exists());
        }
    }

    #[test]
    fn retirement_preserves_mismatched_valid_selection() {
        let state = TestStateRoot::new();
        state.write_intent(PREFERRED_DEFAULT_INTENT);

        assert_eq!(
            retire_owner_first_run_transport_custody_intent_at_state_root(
                state.path(),
                geteuid().as_raw(),
                OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
            ),
            Err(OwnerFirstRunSetupIntentError::ConflictingIntentRecord)
        );
        assert_eq!(
            fs::read(state.intent_path()).expect("preserved source record"),
            PREFERRED_DEFAULT_INTENT
        );
    }

    #[test]
    fn retirement_preserves_malformed_and_insecure_present_state() {
        let malformed = TestStateRoot::new();
        malformed.write_intent(b"preferred-default-v2\n");
        assert_eq!(
            retire_owner_first_run_transport_custody_intent_at_state_root(
                malformed.path(),
                geteuid().as_raw(),
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord)
        );
        assert_eq!(
            fs::read(malformed.intent_path()).expect("preserved malformed state"),
            b"preferred-default-v2\n"
        );

        let insecure = TestStateRoot::new();
        insecure.write_intent(PREFERRED_DEFAULT_INTENT);
        fs::set_permissions(insecure.intent_path(), fs::Permissions::from_mode(0o644))
            .expect("weaken intent mode");
        assert_eq!(
            retire_owner_first_run_transport_custody_intent_at_state_root(
                insecure.path(),
                geteuid().as_raw(),
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure)
        );
        assert!(insecure.intent_path().exists());
    }

    #[test]
    fn malformed_same_size_token_fails_closed() {
        let state = TestStateRoot::new();
        state.write_intent(b"preferred-default-v2\n");

        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord)
        );
    }

    #[test]
    fn missing_record_is_not_treated_as_preferred_or_fallback() {
        let state = TestStateRoot::new();

        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::IntentRecordUnavailable)
        );
    }

    #[test]
    fn insecure_mode_and_symlinked_record_fail_closed() {
        let state = TestStateRoot::new();
        state.write_intent(PREFERRED_DEFAULT_INTENT);
        fs::set_permissions(state.intent_path(), fs::Permissions::from_mode(0o644))
            .expect("weaken setup intent mode");

        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure)
        );

        fs::remove_file(state.intent_path()).expect("remove setup intent");
        let external = state.path().join("external-intent");
        fs::write(&external, PREFERRED_DEFAULT_INTENT).expect("write external intent");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600))
            .expect("secure external intent");
        symlink(&external, state.intent_path()).expect("symlink setup intent");

        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::IntentRecordInsecure)
        );
    }

    #[test]
    fn insecure_setup_directory_fails_before_record_read() {
        let state = TestStateRoot::new();
        state.write_intent(PREFERRED_DEFAULT_INTENT);
        fs::set_permissions(state.setup_dir(), fs::Permissions::from_mode(0o755))
            .expect("weaken setup directory");

        assert_eq!(
            load_owner_first_run_transport_custody_selection_from_state_root(
                state.path(),
                geteuid().as_raw(),
            ),
            Err(OwnerFirstRunSetupIntentError::InsecureSetupDirectory)
        );
    }
}
