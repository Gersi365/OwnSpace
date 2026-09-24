//! Dormant owner-PC local `SQLite` path and filesystem custody.
//!
//! This module selects only the per-user persistent state location for the embedded PRW authority.
//! It does not wire Agent startup, migrate provider data, or remove historical provider source.

use std::{
    env, fmt, fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::process::getuid;

use crate::durable_registry_sqlite_store::DurableRegistrySqliteStore;

/// Stable relative path for the owner-PC embedded authority database.
pub const OWNER_PC_SQLITE_RELATIVE_PATH: &str =
    "private-remote-workspace/database/prw-authority-v1.sqlite3";

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const DATABASE_FILE_MODE: u32 = 0o600;

/// Bounded failure while resolving or preparing local owner-PC `SQLite` custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableRegistrySqliteCustodyError {
    InvalidStateRoot,
    InsecureStateRoot,
    InsecureApplicationDirectory,
    InsecureDatabaseDirectory,
    DirectoryCreationFailed,
    InsecureDatabaseFile,
    AuthorityOpenFailed,
}

impl fmt::Display for DurableRegistrySqliteCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStateRoot => "invalid local authority state root",
            Self::InsecureStateRoot => "insecure local authority state root",
            Self::InsecureApplicationDirectory => "insecure local authority application directory",
            Self::InsecureDatabaseDirectory => "insecure local authority database directory",
            Self::DirectoryCreationFailed => "local authority directory creation failed",
            Self::InsecureDatabaseFile => "insecure local authority database file",
            Self::AuthorityOpenFailed => "local authority database open failed",
        })
    }
}

impl std::error::Error for DurableRegistrySqliteCustodyError {}

/// Resolves the current user's XDG state root without creating or normalizing it.
///
/// `XDG_STATE_HOME` wins when present and must be a non-empty absolute path. Otherwise `HOME` must
/// be a non-empty absolute path and the default .local/state suffix is used.
#[must_use]
pub fn resolve_owner_pc_state_root(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(value) = xdg_state_home {
        if value.is_empty() {
            return None;
        }
        let path = PathBuf::from(value);
        return path.is_absolute().then_some(path);
    }

    let home = home?;
    if home.is_empty() {
        return None;
    }
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(".local/state"))
}

/// Resolves and prepares the current user's private PRW database directory.
///
/// This function does not create or open the `SQLite` database file.
///
/// # Errors
///
/// Fails closed for invalid XDG/HOME roots, insecure ownership/type/mode, symlinked custody
/// directories, or directory creation failure.
pub fn prepare_owner_pc_sqlite_path_from_env() -> Result<PathBuf, DurableRegistrySqliteCustodyError>
{
    let state_root = resolve_owner_pc_state_root(
        env::var_os("XDG_STATE_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    )
    .ok_or(DurableRegistrySqliteCustodyError::InvalidStateRoot)?;
    prepare_owner_pc_sqlite_path(&state_root, getuid().as_raw())
}

/// Opens the dormant owner-PC local authority at the fixed private XDG state path.
///
/// This is intentionally not called by Agent startup in C03e-YK.
///
/// # Errors
///
/// Fails closed on path custody violations, `SQLite` open/schema failure, or inability to harden the
/// resulting main database file to owner-only mode.
pub fn open_owner_pc_sqlite_authority_from_env()
-> Result<DurableRegistrySqliteStore, DurableRegistrySqliteCustodyError> {
    let path = prepare_owner_pc_sqlite_path_from_env()?;
    let store = DurableRegistrySqliteStore::open(&path)
        .map_err(|_| DurableRegistrySqliteCustodyError::AuthorityOpenFailed)?;
    harden_database_file(&path, getuid().as_raw())?;
    Ok(store)
}

/// Opens only an already-existing owner-PC authority through strict read-only custody.
///
/// This post-first-run restart path does not create directories or a database, does not repair file
/// modes, and does not run schema migration. Missing or insecure established custody fails closed.
///
/// # Errors
///
/// Fails closed when XDG/HOME resolution is invalid, any existing custody directory/file violates
/// the locked owner/type/mode boundary, or the existing database cannot be opened read-only.
pub fn open_existing_owner_pc_sqlite_authority_from_env()
-> Result<DurableRegistrySqliteStore, DurableRegistrySqliteCustodyError> {
    let state_root = resolve_owner_pc_state_root(
        env::var_os("XDG_STATE_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    )
    .ok_or(DurableRegistrySqliteCustodyError::InvalidStateRoot)?;
    let path = existing_owner_pc_sqlite_path(&state_root, getuid().as_raw())?;
    DurableRegistrySqliteStore::open_existing_read_only(&path)
        .map_err(|_| DurableRegistrySqliteCustodyError::AuthorityOpenFailed)
}

fn existing_owner_pc_sqlite_path(
    state_root: &Path,
    uid: u32,
) -> Result<PathBuf, DurableRegistrySqliteCustodyError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    validate_existing_private_directory(
        &application_dir,
        uid,
        DurableRegistrySqliteCustodyError::InsecureApplicationDirectory,
    )?;
    let database_dir = application_dir.join("database");
    validate_existing_private_directory(
        &database_dir,
        uid,
        DurableRegistrySqliteCustodyError::InsecureDatabaseDirectory,
    )?;

    let path = database_dir.join("prw-authority-v1.sqlite3");
    validate_database_file(&path, uid)?;
    Ok(path)
}

fn validate_existing_private_directory(
    path: &Path,
    uid: u32,
    insecure: DurableRegistrySqliteCustodyError,
) -> Result<(), DurableRegistrySqliteCustodyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| insecure)?;
    validate_private_directory_metadata(&metadata, uid, insecure)
}

fn prepare_owner_pc_sqlite_path(
    state_root: &Path,
    uid: u32,
) -> Result<PathBuf, DurableRegistrySqliteCustodyError> {
    validate_state_root(state_root, uid)?;

    let application_dir = state_root.join("private-remote-workspace");
    ensure_private_directory(
        &application_dir,
        uid,
        DurableRegistrySqliteCustodyError::InsecureApplicationDirectory,
    )?;
    let database_dir = application_dir.join("database");
    ensure_private_directory(
        &database_dir,
        uid,
        DurableRegistrySqliteCustodyError::InsecureDatabaseDirectory,
    )?;

    let path = database_dir.join("prw-authority-v1.sqlite3");
    match fs::symlink_metadata(&path) {
        Ok(_) => validate_database_file(&path, uid)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(DurableRegistrySqliteCustodyError::InsecureDatabaseFile),
    }
    Ok(path)
}

fn validate_state_root(path: &Path, uid: u32) -> Result<(), DurableRegistrySqliteCustodyError> {
    if !path.is_absolute() {
        return Err(DurableRegistrySqliteCustodyError::InvalidStateRoot);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DurableRegistrySqliteCustodyError::InsecureStateRoot)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(DurableRegistrySqliteCustodyError::InsecureStateRoot);
    }
    Ok(())
}

fn ensure_private_directory(
    path: &Path,
    uid: u32,
    insecure: DurableRegistrySqliteCustodyError,
) -> Result<(), DurableRegistrySqliteCustodyError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory_metadata(&metadata, uid, insecure),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| DurableRegistrySqliteCustodyError::DirectoryCreationFailed)?;
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| DurableRegistrySqliteCustodyError::DirectoryCreationFailed)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| DurableRegistrySqliteCustodyError::DirectoryCreationFailed)?;
            validate_private_directory_metadata(&metadata, uid, insecure)
        }
        Err(_) => Err(insecure),
    }
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
    uid: u32,
    insecure: DurableRegistrySqliteCustodyError,
) -> Result<(), DurableRegistrySqliteCustodyError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(insecure);
    }
    Ok(())
}

fn harden_database_file(path: &Path, uid: u32) -> Result<(), DurableRegistrySqliteCustodyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DurableRegistrySqliteCustodyError::InsecureDatabaseFile)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != uid {
        return Err(DurableRegistrySqliteCustodyError::InsecureDatabaseFile);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(DATABASE_FILE_MODE))
        .map_err(|_| DurableRegistrySqliteCustodyError::InsecureDatabaseFile)?;
    validate_database_file(path, uid)
}

fn validate_database_file(path: &Path, uid: u32) -> Result<(), DurableRegistrySqliteCustodyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DurableRegistrySqliteCustodyError::InsecureDatabaseFile)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != DATABASE_FILE_MODE
    {
        return Err(DurableRegistrySqliteCustodyError::InsecureDatabaseFile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DurableRegistrySqliteCustodyError, OWNER_PC_SQLITE_RELATIVE_PATH,
        existing_owner_pc_sqlite_path, prepare_owner_pc_sqlite_path, resolve_owner_pc_state_root,
    };
    use rustix::process::getuid;
    use std::{
        ffi::OsStr,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "prw-registry-sqlite-custody-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn xdg_state_root_selection_is_absolute_and_deterministic() {
        assert_eq!(
            resolve_owner_pc_state_root(
                Some(OsStr::new("/srv/prw-state")),
                Some(OsStr::new("/home/owner")),
            ),
            Some(PathBuf::from("/srv/prw-state"))
        );
        assert_eq!(
            resolve_owner_pc_state_root(None, Some(OsStr::new("/home/owner"))),
            Some(PathBuf::from("/home/owner/.local/state"))
        );
        assert_eq!(
            resolve_owner_pc_state_root(Some(OsStr::new("relative")), None),
            None
        );
        assert_eq!(
            resolve_owner_pc_state_root(Some(OsStr::new("")), None),
            None
        );
    }

    #[test]
    fn existing_database_path_never_creates_missing_custody() {
        let root = test_root("existing-missing");
        fs::create_dir(&root).expect("create state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("harden state root");

        assert!(matches!(
            existing_owner_pc_sqlite_path(&root, getuid().as_raw()),
            Err(DurableRegistrySqliteCustodyError::InsecureApplicationDirectory)
        ));
        assert!(!root.join("private-remote-workspace").exists());

        fs::remove_dir(&root).expect("remove state root");
    }

    #[test]
    fn private_database_path_is_created_under_existing_secure_state_root() {
        let root = test_root("create");
        fs::create_dir(&root).expect("create state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("harden state root");

        let path = prepare_owner_pc_sqlite_path(&root, getuid().as_raw())
            .expect("prepare local database path");
        assert_eq!(path, root.join(OWNER_PC_SQLITE_RELATIVE_PATH));
        assert_eq!(
            fs::symlink_metadata(root.join("private-remote-workspace"))
                .expect("application dir")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(root.join("private-remote-workspace/database"))
                .expect("database dir")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn insecure_or_symlinked_custody_fails_closed() {
        let root = test_root("insecure");
        fs::create_dir(&root).expect("create state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("set insecure mode");
        assert_eq!(
            prepare_owner_pc_sqlite_path(&root, getuid().as_raw()),
            Err(DurableRegistrySqliteCustodyError::InsecureStateRoot)
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("harden root");

        let external = test_root("external");
        fs::create_dir(&external).expect("create external dir");
        symlink(&external, root.join("private-remote-workspace")).expect("create symlink");
        assert_eq!(
            prepare_owner_pc_sqlite_path(&root, getuid().as_raw()),
            Err(DurableRegistrySqliteCustodyError::InsecureApplicationDirectory)
        );

        fs::remove_file(root.join("private-remote-workspace")).expect("remove symlink");
        fs::remove_dir_all(&external).expect("remove external");

        let path = prepare_owner_pc_sqlite_path(&root, getuid().as_raw())
            .expect("prepare private database directory");
        symlink(root.join("missing-target.sqlite3"), &path)
            .expect("create dangling database symlink");
        assert_eq!(
            prepare_owner_pc_sqlite_path(&root, getuid().as_raw()),
            Err(DurableRegistrySqliteCustodyError::InsecureDatabaseFile)
        );

        fs::remove_file(&path).expect("remove dangling database symlink");
        fs::remove_dir_all(&root).expect("remove test root");
    }
}
