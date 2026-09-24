//! Descriptor-anchored Linux file-management primitives for PRW.
//!
//! Phase 131 intentionally implements only bounded list/stat/read and creation-only
//! file/directory operations. Transfer resume, overwrite/replace, deletion, capability
//! policy, and remote transport integration remain outside this crate.

mod transfer_storage;
pub use transfer_storage::{
    MAX_TRANSFER_CHUNK_BYTES, StagedUploadFile, TransferStorageError, transfer_staging_name,
};

use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use rustix::{
    fs::{AtFlags, Dir, FileType, Mode, OFlags, fchmod, fstat, mkdirat, open, openat, statat},
    io::{Errno, dup},
};

/// Maximum encoded remote path length.
pub const MAX_REMOTE_PATH_BYTES: usize = 4096;
/// Maximum remote path component count.
pub const MAX_REMOTE_PATH_COMPONENTS: usize = 64;
/// Maximum UTF-8 bytes in one remote path component.
pub const MAX_REMOTE_COMPONENT_BYTES: usize = 255;
/// Maximum entries returned by one bounded directory listing.
pub const MAX_DIRECTORY_ENTRIES: usize = 4096;
/// Maximum whole-file Phase 131 read/write payload.
pub const MAX_WHOLE_FILE_BYTES: usize = 1_048_576;

const FILE_MODE: Mode = Mode::from_bits_retain(0o600);
const DIRECTORY_MODE: Mode = Mode::from_bits_retain(0o700);
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_READ_FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_CREATE_FILE: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Validated UTF-8 relative path stored as already-checked components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePath {
    components: Vec<String>,
}

impl RemotePath {
    /// Parses one Phase 131 remote path.
    ///
    /// The empty string is the authorized root directory. Non-empty input is strict
    /// relative `/`-separated UTF-8 and rejects traversal or ambiguous components.
    ///
    /// # Errors
    ///
    /// Returns [`RemotePathError`] when syntax or a locked bound is violated.
    pub fn parse(input: &str) -> Result<Self, RemotePathError> {
        if input.is_empty() {
            return Ok(Self {
                components: Vec::new(),
            });
        }
        if input.len() > MAX_REMOTE_PATH_BYTES {
            return Err(RemotePathError::PathTooLong);
        }
        if input.starts_with('/') {
            return Err(RemotePathError::Absolute);
        }
        if input.ends_with('/') {
            return Err(RemotePathError::EmptyComponent);
        }
        if input.contains('\0') {
            return Err(RemotePathError::Nul);
        }
        if input.contains('\\') {
            return Err(RemotePathError::Backslash);
        }

        let mut components = Vec::new();
        for component in input.split('/') {
            if component.is_empty() {
                return Err(RemotePathError::EmptyComponent);
            }
            if component == "." {
                return Err(RemotePathError::CurrentDirectory);
            }
            if component == ".." {
                return Err(RemotePathError::ParentTraversal);
            }
            if component.len() > MAX_REMOTE_COMPONENT_BYTES {
                return Err(RemotePathError::ComponentTooLong);
            }
            components.push(component.to_owned());
            if components.len() > MAX_REMOTE_PATH_COMPONENTS {
                return Err(RemotePathError::TooManyComponents);
            }
        }
        Ok(Self { components })
    }

    /// Returns whether this path denotes the authorized root.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns validated components.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    fn final_component(&self) -> Result<&str, FileServiceError> {
        self.components
            .last()
            .map(String::as_str)
            .ok_or(FileServiceError::RootNotAllowed)
    }
}

/// Remote-path parsing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemotePathError {
    /// Path is absolute.
    Absolute,
    /// Empty component, repeated separator, or trailing separator.
    EmptyComponent,
    /// Current-directory component is forbidden.
    CurrentDirectory,
    /// Parent traversal is forbidden.
    ParentTraversal,
    /// NUL is forbidden.
    Nul,
    /// Backslash is forbidden by the portable remote syntax.
    Backslash,
    /// Full path exceeds 4096 UTF-8 bytes.
    PathTooLong,
    /// One component exceeds 255 UTF-8 bytes.
    ComponentTooLong,
    /// Path contains more than 64 components.
    TooManyComponents,
}

impl fmt::Display for RemotePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Absolute => "remote path must be relative",
            Self::EmptyComponent => "remote path contains an empty component",
            Self::CurrentDirectory => "remote path current-directory component is forbidden",
            Self::ParentTraversal => "remote path parent traversal is forbidden",
            Self::Nul => "remote path NUL is forbidden",
            Self::Backslash => "remote path backslash is forbidden",
            Self::PathTooLong => "remote path too long",
            Self::ComponentTooLong => "remote path component too long",
            Self::TooManyComponents => "remote path has too many components",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RemotePathError {}

/// File object type exposed by the Phase 131 API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteFileType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link, reported but never followed for authority.
    SymbolicLink,
    /// Other filesystem object.
    Other,
}

/// Bounded metadata snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMetadata {
    file_type: RemoteFileType,
    size: u64,
}

impl RemoteMetadata {
    /// Returns the object type.
    #[must_use]
    pub const fn file_type(&self) -> RemoteFileType {
        self.file_type
    }

    /// Returns the observed object size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// One UTF-8 directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDirectoryEntry {
    name: String,
    file_type: RemoteFileType,
}

impl RemoteDirectoryEntry {
    /// Returns the exact UTF-8 entry name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the entry type reported by the directory stream.
    #[must_use]
    pub const fn file_type(&self) -> RemoteFileType {
        self.file_type
    }
}

/// Stable file-service failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileServiceError {
    /// Root directory could not be securely opened.
    InvalidRoot,
    /// Operation requires a non-root final component.
    RootNotAllowed,
    /// Descendant filesystem resolution or I/O failed.
    Filesystem,
    /// Destination already exists for a creation-only operation.
    AlreadyExists,
    /// Expected regular file was another object type.
    NotRegularFile,
    /// Expected directory was another object type.
    NotDirectory,
    /// Directory contained a non-UTF-8 entry name.
    NonUtf8Entry,
    /// Directory listing exceeded the hard entry bound.
    DirectoryTooLarge,
    /// Read or write payload exceeded the Phase 131 whole-file bound.
    PayloadTooLarge,
    /// Post-create mode/type validation failed.
    PostconditionFailed,
}

impl fmt::Display for FileServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRoot => "invalid file-service root",
            Self::RootNotAllowed => "operation does not allow root path",
            Self::Filesystem => "file-service filesystem operation failed",
            Self::AlreadyExists => "file-service destination already exists",
            Self::NotRegularFile => "file-service object is not a regular file",
            Self::NotDirectory => "file-service object is not a directory",
            Self::NonUtf8Entry => "file-service directory entry is not UTF-8",
            Self::DirectoryTooLarge => "file-service directory listing too large",
            Self::PayloadTooLarge => "file-service payload too large",
            Self::PostconditionFailed => "file-service postcondition failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FileServiceError {}

/// Descriptor-anchored filesystem authority.
#[derive(Debug)]
pub struct AnchoredFileRoot {
    root: OwnedFd,
}

impl AnchoredFileRoot {
    /// Opens one existing root directory without following a final symbolic link.
    ///
    /// # Errors
    ///
    /// Returns [`FileServiceError::InvalidRoot`] if the root cannot be opened as a
    /// directory descriptor under the locked flags.
    pub fn open(path: &Path) -> Result<Self, FileServiceError> {
        let root =
            open(path, OPEN_DIRECTORY, Mode::empty()).map_err(|_| FileServiceError::InvalidRoot)?;
        Ok(Self { root })
    }

    /// Returns bounded metadata without following the final symbolic link.
    ///
    /// # Errors
    ///
    /// Returns a bounded filesystem classification on resolution/stat failure.
    pub fn metadata(&self, path: &RemotePath) -> Result<RemoteMetadata, FileServiceError> {
        let stat = if path.is_root() {
            fstat(&self.root).map_err(|_| FileServiceError::Filesystem)?
        } else {
            let (parent, final_name) = self.open_parent(path)?;
            statat(&parent, final_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| FileServiceError::Filesystem)?
        };
        Ok(RemoteMetadata {
            file_type: classify_mode(stat.st_mode),
            size: stat.st_size.try_into().unwrap_or(u64::MAX),
        })
    }

    /// Lists one directory with a hard entry bound and no lossy filename conversion.
    ///
    /// # Errors
    ///
    /// Rejects non-directories, non-UTF-8 names, and listing overflow.
    pub fn list_directory(
        &self,
        path: &RemotePath,
    ) -> Result<Vec<RemoteDirectoryEntry>, FileServiceError> {
        let fd = self.open_directory(path)?;
        let dir = Dir::read_from(fd).map_err(|_| FileServiceError::Filesystem)?;
        let mut entries = Vec::new();
        for entry in dir {
            let entry = entry.map_err(|_| FileServiceError::Filesystem)?;
            let raw_name = entry.file_name().to_bytes();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            if entries.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(FileServiceError::DirectoryTooLarge);
            }
            if raw_name.len() > MAX_REMOTE_COMPONENT_BYTES {
                return Err(FileServiceError::DirectoryTooLarge);
            }
            let name = std::str::from_utf8(raw_name).map_err(|_| FileServiceError::NonUtf8Entry)?;
            entries.push(RemoteDirectoryEntry {
                name: name.to_owned(),
                file_type: classify_file_type(entry.file_type()),
            });
        }
        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    /// Reads one regular file into memory with a hard whole-file bound.
    ///
    /// # Errors
    ///
    /// Rejects root, symbolic links/other types, filesystem failures, and files that
    /// exceed the bound including files that grow during the read.
    pub fn read_file(&self, path: &RemotePath) -> Result<Vec<u8>, FileServiceError> {
        let (parent, final_name) = self.open_parent(path)?;
        let fd = openat(&parent, final_name, OPEN_READ_FILE, Mode::empty())
            .map_err(|_| FileServiceError::Filesystem)?;
        let stat = fstat(&fd).map_err(|_| FileServiceError::Filesystem)?;
        if classify_mode(stat.st_mode) != RemoteFileType::RegularFile {
            return Err(FileServiceError::NotRegularFile);
        }
        let mut file = File::from(fd);
        let mut payload = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((MAX_WHOLE_FILE_BYTES + 1) as u64)
            .read_to_end(&mut payload)
            .map_err(|_| FileServiceError::Filesystem)?;
        if payload.len() > MAX_WHOLE_FILE_BYTES {
            return Err(FileServiceError::PayloadTooLarge);
        }
        Ok(payload)
    }

    /// Creates one new regular file without overwrite semantics.
    ///
    /// # Errors
    ///
    /// Rejects root, oversized payload, an existing destination, resolution/write
    /// failure, or post-create type/mode mismatch.
    pub fn create_file(&self, path: &RemotePath, payload: &[u8]) -> Result<(), FileServiceError> {
        if payload.len() > MAX_WHOLE_FILE_BYTES {
            return Err(FileServiceError::PayloadTooLarge);
        }
        let (parent, final_name) = self.open_parent(path)?;
        let fd =
            openat(&parent, final_name, OPEN_CREATE_FILE, FILE_MODE).map_err(map_create_error)?;
        fchmod(&fd, FILE_MODE).map_err(|_| FileServiceError::Filesystem)?;
        {
            let mut file = File::from(fd);
            file.write_all(payload)
                .map_err(|_| FileServiceError::Filesystem)?;
            file.sync_all().map_err(|_| FileServiceError::Filesystem)?;
            let stat = file.metadata().map_err(|_| FileServiceError::Filesystem)?;
            if !stat.is_file() || stat.permissions().mode() & 0o777 != 0o600 {
                return Err(FileServiceError::PostconditionFailed);
            }
        }
        Ok(())
    }

    /// Creates one new directory without replacement semantics.
    ///
    /// # Errors
    ///
    /// Rejects root, existing destination, resolution failure, or post-create mismatch.
    pub fn create_directory(&self, path: &RemotePath) -> Result<(), FileServiceError> {
        let (parent, final_name) = self.open_parent(path)?;
        mkdirat(&parent, final_name, DIRECTORY_MODE).map_err(map_create_error)?;
        let fd = openat(&parent, final_name, OPEN_DIRECTORY, Mode::empty())
            .map_err(|_| FileServiceError::PostconditionFailed)?;
        fchmod(&fd, DIRECTORY_MODE).map_err(|_| FileServiceError::Filesystem)?;
        let stat = fstat(&fd).map_err(|_| FileServiceError::Filesystem)?;
        if classify_mode(stat.st_mode) != RemoteFileType::Directory || stat.st_mode & 0o777 != 0o700
        {
            return Err(FileServiceError::PostconditionFailed);
        }
        Ok(())
    }

    fn open_parent<'a>(
        &self,
        path: &'a RemotePath,
    ) -> Result<(OwnedFd, &'a str), FileServiceError> {
        let final_name = path.final_component()?;
        let mut current = dup(&self.root).map_err(|_| FileServiceError::Filesystem)?;
        for component in &path.components[..path.components.len() - 1] {
            current = openat(&current, component.as_str(), OPEN_DIRECTORY, Mode::empty())
                .map_err(|_| FileServiceError::Filesystem)?;
        }
        Ok((current, final_name))
    }

    fn open_directory(&self, path: &RemotePath) -> Result<OwnedFd, FileServiceError> {
        let mut current = dup(&self.root).map_err(|_| FileServiceError::Filesystem)?;
        for component in &path.components {
            current = openat(&current, component.as_str(), OPEN_DIRECTORY, Mode::empty())
                .map_err(|_| FileServiceError::NotDirectory)?;
        }
        Ok(current)
    }
}

fn map_create_error(error: Errno) -> FileServiceError {
    if error == Errno::EXIST {
        FileServiceError::AlreadyExists
    } else {
        FileServiceError::Filesystem
    }
}

const fn classify_mode(mode: rustix::fs::RawMode) -> RemoteFileType {
    classify_file_type(FileType::from_raw_mode(mode))
}

const fn classify_file_type(file_type: FileType) -> RemoteFileType {
    match file_type {
        FileType::RegularFile => RemoteFileType::RegularFile,
        FileType::Directory => RemoteFileType::Directory,
        FileType::Symlink => RemoteFileType::SymbolicLink,
        _ => RemoteFileType::Other,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        AnchoredFileRoot, FileServiceError, MAX_DIRECTORY_ENTRIES, MAX_REMOTE_PATH_COMPONENTS,
        MAX_WHOLE_FILE_BYTES, RemoteFileType, RemotePath, RemotePathError,
    };

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("prw-phase131-{label}-{}-{nonce}", process::id()));
            fs::create_dir(&path).expect("create disposable root");
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn path_parser_rejects_escape_and_ambiguity() {
        assert!(RemotePath::parse("").expect("root").is_root());
        assert_eq!(RemotePath::parse("/etc"), Err(RemotePathError::Absolute));
        assert_eq!(
            RemotePath::parse("a//b"),
            Err(RemotePathError::EmptyComponent)
        );
        assert_eq!(
            RemotePath::parse("a/./b"),
            Err(RemotePathError::CurrentDirectory)
        );
        assert_eq!(
            RemotePath::parse("a/../b"),
            Err(RemotePathError::ParentTraversal)
        );
        assert_eq!(RemotePath::parse("a\\b"), Err(RemotePathError::Backslash));
        let too_many = std::iter::repeat_n("a", MAX_REMOTE_PATH_COMPONENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            RemotePath::parse(&too_many),
            Err(RemotePathError::TooManyComponents)
        );
    }

    #[test]
    fn list_stat_and_read_remain_inside_root() {
        let tree = TempTree::new("basic");
        fs::create_dir(tree.path.join("docs")).expect("create docs");
        fs::write(tree.path.join("docs/readme.txt"), b"hello").expect("write fixture");
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");

        let entries = root
            .list_directory(&RemotePath::parse("docs").expect("path"))
            .expect("list docs");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "readme.txt");
        assert_eq!(entries[0].file_type(), RemoteFileType::RegularFile);

        let metadata = root
            .metadata(&RemotePath::parse("docs/readme.txt").expect("path"))
            .expect("metadata");
        assert_eq!(metadata.file_type(), RemoteFileType::RegularFile);
        assert_eq!(metadata.size(), 5);
        assert_eq!(
            root.read_file(&RemotePath::parse("docs/readme.txt").expect("path"))
                .expect("read fixture"),
            b"hello"
        );
    }

    #[test]
    fn intermediate_and_final_symlinks_fail_closed() {
        let tree = TempTree::new("symlink");
        let outside = TempTree::new("outside");
        fs::write(outside.path.join("secret"), b"outside").expect("outside secret");
        symlink(&outside.path, tree.path.join("escape")).expect("intermediate symlink");
        symlink(outside.path.join("secret"), tree.path.join("final-link")).expect("final symlink");
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");

        assert!(
            root.read_file(&RemotePath::parse("escape/secret").expect("path"))
                .is_err()
        );
        assert!(
            root.read_file(&RemotePath::parse("final-link").expect("path"))
                .is_err()
        );
        assert_eq!(
            root.create_file(
                &RemotePath::parse("final-link").expect("path"),
                b"replacement"
            ),
            Err(FileServiceError::AlreadyExists)
        );
        assert_eq!(
            fs::read(outside.path.join("secret")).expect("outside unchanged"),
            b"outside"
        );
    }

    #[test]
    fn opened_root_descriptor_survives_path_replacement_without_redirect() {
        let tree = TempTree::new("root-anchor");
        fs::write(tree.path.join("original.txt"), b"original").expect("original fixture");
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");
        let moved = tree.path.with_extension("moved");
        fs::rename(&tree.path, &moved).expect("move original root");
        fs::create_dir(&tree.path).expect("create replacement root path");
        fs::write(tree.path.join("original.txt"), b"replacement").expect("replacement fixture");

        let payload = root
            .read_file(&RemotePath::parse("original.txt").expect("path"))
            .expect("read pinned original directory");
        assert_eq!(payload, b"original");

        fs::remove_dir_all(&tree.path).expect("remove replacement root");
        fs::rename(&moved, &tree.path).expect("restore root for cleanup");
    }

    #[test]
    fn creation_only_file_and_directory_enforce_modes_and_non_overwrite() {
        let tree = TempTree::new("create");
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");
        let dir = RemotePath::parse("new-dir").expect("dir path");
        root.create_directory(&dir).expect("create directory");
        assert_eq!(
            fs::metadata(tree.path.join("new-dir"))
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let file = RemotePath::parse("new-dir/file.txt").expect("file path");
        root.create_file(&file, b"first").expect("create file");
        assert_eq!(
            fs::metadata(tree.path.join("new-dir/file.txt"))
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            root.create_file(&file, b"second"),
            Err(FileServiceError::AlreadyExists)
        );
        assert_eq!(
            fs::read(tree.path.join("new-dir/file.txt")).expect("existing content"),
            b"first"
        );
    }

    #[test]
    fn payload_bound_fails_before_create_and_read_is_bounded() {
        let tree = TempTree::new("payload");
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");
        let oversize = vec![7_u8; MAX_WHOLE_FILE_BYTES + 1];
        let target = RemotePath::parse("too-large.bin").expect("path");
        assert_eq!(
            root.create_file(&target, &oversize),
            Err(FileServiceError::PayloadTooLarge)
        );
        assert!(!tree.path.join("too-large.bin").exists());

        fs::write(tree.path.join("existing.bin"), oversize).expect("oversize read fixture");
        assert_eq!(
            root.read_file(&RemotePath::parse("existing.bin").expect("path")),
            Err(FileServiceError::PayloadTooLarge)
        );
    }

    #[test]
    fn directory_listing_bound_fails_closed() {
        let tree = TempTree::new("listing-bound");
        for index in 0..=MAX_DIRECTORY_ENTRIES {
            fs::write(tree.path.join(format!("entry-{index}")), b"").expect("create entry");
        }
        let root = AnchoredFileRoot::open(&tree.path).expect("open anchored root");
        assert_eq!(
            root.list_directory(&RemotePath::parse("").expect("root path")),
            Err(FileServiceError::DirectoryTooLarge)
        );
    }
}
