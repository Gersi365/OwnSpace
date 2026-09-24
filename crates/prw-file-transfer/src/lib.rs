//! Resumable create-only file-transfer transactions for PRW.
//!
//! This crate owns transfer identity, plan validation, sequential upload state, final
//! content-integrity verification, and bounded download-chunk orchestration. Raw
//! filesystem authority remains inside `prw-file-service`.

use std::{collections::HashMap, fmt};

use prw_file_service::{
    AnchoredFileRoot, MAX_TRANSFER_CHUNK_BYTES, RemotePath, StagedUploadFile, TransferStorageError,
    transfer_staging_name,
};

/// Maximum total Phase 132 file size.
pub const MAX_TRANSFER_BYTES: u64 = 1_073_741_824;
/// Maximum simultaneously active in-memory upload transactions.
pub const MAX_ACTIVE_UPLOADS: usize = 128;

/// Exact 128-bit transfer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId([u8; 16]);

impl TransferId {
    /// Creates an identifier from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Encodes exactly 32 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(32);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("write to String");
        }
        output
    }

    /// Parses exactly 32 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`TransferIdError`] for any other representation.
    pub fn from_hex(value: &str) -> Result<Self, TransferIdError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(TransferIdError);
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// Invalid external transfer-id representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferIdError;

impl fmt::Display for TransferIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transfer id must be 32 lowercase hexadecimal characters")
    }
}

impl std::error::Error for TransferIdError {}

/// Immutable upload plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPlan {
    transfer_id: TransferId,
    destination: RemotePath,
    total_bytes: u64,
    sha256: [u8; 32],
}

impl UploadPlan {
    /// Creates a bounded upload plan.
    ///
    /// # Errors
    ///
    /// Rejects total sizes above the Phase 132 bound.
    pub fn new(
        transfer_id: TransferId,
        destination: RemotePath,
        total_bytes: u64,
        sha256: [u8; 32],
    ) -> Result<Self, FileTransferError> {
        if destination.is_root() {
            return Err(FileTransferError::RootDestination);
        }
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(FileTransferError::TransferTooLarge);
        }
        Ok(Self {
            transfer_id,
            destination,
            total_bytes,
            sha256,
        })
    }

    /// Returns the transfer identifier.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Returns the validated final destination.
    #[must_use]
    pub const fn destination(&self) -> &RemotePath {
        &self.destination
    }

    /// Returns exact total bytes expected at commit.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns exact expected SHA-256 digest.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Stable transfer transaction failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileTransferError {
    /// Final destination cannot be the authorized root directory itself.
    RootDestination,
    /// Total planned bytes exceed the global transfer bound.
    TransferTooLarge,
    /// Active transfer capacity reached the hard bound.
    ActiveTransferCapacity,
    /// Transfer identifier is already active.
    TransferAlreadyActive,
    /// Transfer identifier is not active.
    TransferUnknown,
    /// Chunk is empty or above the one-chunk bound.
    InvalidChunkLength,
    /// Supplied offset does not match the exact committed staged offset.
    OffsetMismatch,
    /// Chunk would exceed the exact planned total.
    ExceedsPlannedTotal,
    /// Staged size is not exactly complete.
    Incomplete,
    /// Final SHA-256 did not match the plan.
    DigestMismatch,
    /// Underlying descriptor-anchored storage rejected the operation.
    Storage,
}

impl fmt::Display for FileTransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RootDestination => "transfer destination cannot be root",
            Self::TransferTooLarge => "transfer exceeds total byte bound",
            Self::ActiveTransferCapacity => "active transfer capacity reached",
            Self::TransferAlreadyActive => "transfer is already active",
            Self::TransferUnknown => "transfer is not active",
            Self::InvalidChunkLength => "invalid transfer chunk length",
            Self::OffsetMismatch => "transfer chunk offset mismatch",
            Self::ExceedsPlannedTotal => "transfer chunk exceeds planned total",
            Self::Incomplete => "transfer is incomplete",
            Self::DigestMismatch => "transfer SHA-256 mismatch",
            Self::Storage => "transfer storage rejected operation",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FileTransferError {}

/// Active upload transaction.
#[derive(Debug)]
struct ActiveUpload {
    plan: UploadPlan,
    staged: StagedUploadFile,
}

/// Bounded in-memory upload transaction manager over one descriptor-anchored root.
#[derive(Debug)]
pub struct UploadTransferManager<'a> {
    root: &'a AnchoredFileRoot,
    uploads: HashMap<TransferId, ActiveUpload>,
}

impl<'a> UploadTransferManager<'a> {
    /// Creates an empty manager over one existing filesystem authority.
    #[must_use]
    pub fn new(root: &'a AnchoredFileRoot) -> Self {
        Self {
            root,
            uploads: HashMap::new(),
        }
    }

    /// Begins a fresh creation-only staged upload.
    ///
    /// # Errors
    ///
    /// Rejects duplicate active IDs, capacity overflow, or storage failure.
    pub fn begin(&mut self, plan: UploadPlan) -> Result<u64, FileTransferError> {
        if self.uploads.contains_key(&plan.transfer_id) {
            return Err(FileTransferError::TransferAlreadyActive);
        }
        if self.uploads.len() >= MAX_ACTIVE_UPLOADS {
            return Err(FileTransferError::ActiveTransferCapacity);
        }
        let staging_name = transfer_staging_name(*plan.transfer_id.as_bytes());
        let staged = self
            .root
            .begin_staged_upload(&plan.destination, &staging_name)
            .map_err(map_storage_error)?;
        let offset = staged.len().map_err(map_storage_error)?;
        debug_assert_eq!(offset, 0);
        self.uploads
            .insert(plan.transfer_id, ActiveUpload { plan, staged });
        Ok(offset)
    }

    /// Resumes an exact existing staged upload from its current committed length.
    ///
    /// # Errors
    ///
    /// Rejects duplicate active IDs, capacity overflow, unsafe/missing staging, or a
    /// staged length already above the supplied plan total.
    pub fn resume(&mut self, plan: UploadPlan) -> Result<u64, FileTransferError> {
        if self.uploads.contains_key(&plan.transfer_id) {
            return Err(FileTransferError::TransferAlreadyActive);
        }
        if self.uploads.len() >= MAX_ACTIVE_UPLOADS {
            return Err(FileTransferError::ActiveTransferCapacity);
        }
        let staging_name = transfer_staging_name(*plan.transfer_id.as_bytes());
        let staged = self
            .root
            .resume_staged_upload(&plan.destination, &staging_name)
            .map_err(map_storage_error)?;
        let offset = staged.len().map_err(map_storage_error)?;
        if offset > plan.total_bytes || offset > MAX_TRANSFER_BYTES {
            return Err(FileTransferError::ExceedsPlannedTotal);
        }
        self.uploads
            .insert(plan.transfer_id, ActiveUpload { plan, staged });
        Ok(offset)
    }

    /// Appends and syncs one exact sequential chunk.
    ///
    /// # Errors
    ///
    /// Rejects unknown transfer, invalid length, offset mismatch, planned-total
    /// overflow, or storage failure before acknowledging the new offset.
    pub fn upload_chunk(
        &mut self,
        transfer_id: TransferId,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, FileTransferError> {
        if chunk.is_empty() || chunk.len() > MAX_TRANSFER_CHUNK_BYTES {
            return Err(FileTransferError::InvalidChunkLength);
        }
        let upload = self
            .uploads
            .get_mut(&transfer_id)
            .ok_or(FileTransferError::TransferUnknown)?;
        let current = upload.staged.len().map_err(map_storage_error)?;
        if offset != current {
            return Err(FileTransferError::OffsetMismatch);
        }
        let chunk_len =
            u64::try_from(chunk.len()).map_err(|_| FileTransferError::InvalidChunkLength)?;
        let new_len = current
            .checked_add(chunk_len)
            .ok_or(FileTransferError::ExceedsPlannedTotal)?;
        if new_len > upload.plan.total_bytes || new_len > MAX_TRANSFER_BYTES {
            return Err(FileTransferError::ExceedsPlannedTotal);
        }
        upload
            .staged
            .write_chunk(offset, chunk)
            .map_err(map_storage_error)
    }

    /// Finalizes one complete upload after exact length and SHA-256 verification.
    ///
    /// The final filesystem commit is atomic create-only `NOREPLACE`.
    ///
    /// # Errors
    ///
    /// Rejects unknown/incomplete transfer, digest mismatch, or storage failure.
    pub fn finalize(&mut self, transfer_id: TransferId) -> Result<(), FileTransferError> {
        let upload = self
            .uploads
            .remove(&transfer_id)
            .ok_or(FileTransferError::TransferUnknown)?;
        let current = upload.staged.len().map_err(map_storage_error)?;
        if current != upload.plan.total_bytes {
            self.uploads.insert(transfer_id, upload);
            return Err(FileTransferError::Incomplete);
        }
        let digest = upload.staged.sha256().map_err(map_storage_error)?;
        if &digest != upload.plan.sha256() {
            self.uploads.insert(transfer_id, upload);
            return Err(FileTransferError::DigestMismatch);
        }
        upload.staged.commit_noreplace().map_err(map_storage_error)
    }

    /// Explicitly aborts one active transfer and removes only its staging file.
    ///
    /// # Errors
    ///
    /// Rejects unknown transfers or unsafe/unlink storage failure.
    pub fn abort(&mut self, transfer_id: TransferId) -> Result<(), FileTransferError> {
        let upload = self
            .uploads
            .remove(&transfer_id)
            .ok_or(FileTransferError::TransferUnknown)?;
        upload.staged.abort().map_err(map_storage_error)
    }

    /// Returns current committed offset for one active transfer.
    ///
    /// # Errors
    ///
    /// Rejects unknown transfer or unsafe staged metadata.
    pub fn offset(&self, transfer_id: TransferId) -> Result<u64, FileTransferError> {
        self.uploads
            .get(&transfer_id)
            .ok_or(FileTransferError::TransferUnknown)?
            .staged
            .len()
            .map_err(map_storage_error)
    }

    /// Returns active upload count.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.uploads.len()
    }
}

/// Reads one bounded download chunk through the descriptor-anchored root.
///
/// # Errors
///
/// Returns [`FileTransferError::Storage`] for path/type/read failure or
/// [`FileTransferError::InvalidChunkLength`] for an invalid request length.
pub fn download_chunk(
    root: &AnchoredFileRoot,
    path: &RemotePath,
    offset: u64,
    requested_len: usize,
) -> Result<Vec<u8>, FileTransferError> {
    root.read_download_chunk(path, offset, requested_len)
        .map_err(map_storage_error)
}

const fn map_storage_error(error: TransferStorageError) -> FileTransferError {
    match error {
        TransferStorageError::OffsetMismatch => FileTransferError::OffsetMismatch,
        TransferStorageError::InvalidChunkLength => FileTransferError::InvalidChunkLength,
        _ => FileTransferError::Storage,
    }
}

const fn hex_nibble(value: u8) -> Result<u8, TransferIdError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(TransferIdError),
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

    use aws_lc_rs::digest::{SHA256, digest};
    use prw_file_service::{
        AnchoredFileRoot, MAX_TRANSFER_CHUNK_BYTES, RemotePath, transfer_staging_name,
    };

    use super::{
        FileTransferError, MAX_TRANSFER_BYTES, TransferId, UploadPlan, UploadTransferManager,
        download_chunk,
    };

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("prw-phase132-{label}-{}-{nonce}", process::id()));
            fs::create_dir(&path).expect("create disposable root");
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn id(value: u8) -> TransferId {
        TransferId::new([value; 16])
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        let digest = digest(&SHA256, bytes);
        let mut value = [0_u8; 32];
        value.copy_from_slice(digest.as_ref());
        value
    }

    #[test]
    fn transfer_id_round_trip_is_exact_lowercase_hex() {
        let value = TransferId::new([0xab; 16]);
        let encoded = value.to_hex();
        assert_eq!(encoded, "abababababababababababababababab");
        assert_eq!(TransferId::from_hex(&encoded), Ok(value));
        assert!(TransferId::from_hex("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(TransferId::from_hex("abc").is_err());
    }

    #[test]
    fn plan_and_chunk_bounds_fail_before_storage_mutation() {
        let tree = TempTree::new("bounds");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        assert_eq!(
            UploadPlan::new(
                id(1),
                RemotePath::parse("large.bin").expect("path"),
                MAX_TRANSFER_BYTES + 1,
                [0; 32]
            ),
            Err(FileTransferError::TransferTooLarge)
        );
        let plan = UploadPlan::new(
            id(2),
            RemotePath::parse("bounded.bin").expect("path"),
            1,
            sha(b"x"),
        )
        .expect("plan");
        let mut manager = UploadTransferManager::new(&root);
        manager.begin(plan).expect("begin");
        let oversize = vec![0_u8; MAX_TRANSFER_CHUNK_BYTES + 1];
        assert_eq!(
            manager.upload_chunk(id(2), 0, &oversize),
            Err(FileTransferError::InvalidChunkLength)
        );
        assert_eq!(manager.offset(id(2)).expect("offset"), 0);
    }

    #[test]
    fn sequential_chunks_resume_and_commit_exact_content() {
        let tree = TempTree::new("resume");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        let payload = b"hello resumable world";
        let destination = RemotePath::parse("result.bin").expect("path");
        let plan =
            UploadPlan::new(id(3), destination, payload.len() as u64, sha(payload)).expect("plan");
        {
            let mut manager = UploadTransferManager::new(&root);
            manager.begin(plan.clone()).expect("begin");
            assert_eq!(
                manager
                    .upload_chunk(id(3), 0, &payload[..5])
                    .expect("chunk"),
                5
            );
            assert_eq!(
                manager.upload_chunk(id(3), 0, b"overlap"),
                Err(FileTransferError::OffsetMismatch)
            );
        }
        let mut resumed = UploadTransferManager::new(&root);
        assert_eq!(resumed.resume(plan).expect("resume"), 5);
        resumed
            .upload_chunk(id(3), 5, &payload[5..])
            .expect("remaining chunk");
        resumed.finalize(id(3)).expect("finalize");
        assert_eq!(
            fs::read(tree.path.join("result.bin")).expect("final bytes"),
            payload
        );
        assert_eq!(
            fs::metadata(tree.path.join("result.bin"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn incomplete_and_wrong_digest_never_publish_final_destination() {
        let tree = TempTree::new("integrity");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        let destination = RemotePath::parse("integrity.bin").expect("path");
        let plan = UploadPlan::new(id(4), destination, 4, sha(b"good")).expect("plan");
        let mut manager = UploadTransferManager::new(&root);
        manager.begin(plan).expect("begin");
        manager.upload_chunk(id(4), 0, b"bad").expect("chunk");
        assert_eq!(manager.finalize(id(4)), Err(FileTransferError::Incomplete));
        manager
            .upload_chunk(id(4), 3, b"!")
            .expect("complete wrong bytes");
        assert_eq!(
            manager.finalize(id(4)),
            Err(FileTransferError::DigestMismatch)
        );
        assert!(!tree.path.join("integrity.bin").exists());
        manager.abort(id(4)).expect("abort");
        assert!(
            !tree
                .path
                .join(transfer_staging_name(*id(4).as_bytes()))
                .exists()
        );
    }

    #[test]
    fn preexisting_final_destination_is_never_overwritten() {
        let tree = TempTree::new("noreplace");
        fs::write(tree.path.join("existing.bin"), b"old").expect("existing file");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        let plan = UploadPlan::new(
            id(5),
            RemotePath::parse("existing.bin").expect("path"),
            3,
            sha(b"new"),
        )
        .expect("plan");
        let mut manager = UploadTransferManager::new(&root);
        manager.begin(plan).expect("begin");
        manager.upload_chunk(id(5), 0, b"new").expect("chunk");
        assert_eq!(manager.finalize(id(5)), Err(FileTransferError::Storage));
        assert_eq!(
            fs::read(tree.path.join("existing.bin")).expect("old remains"),
            b"old"
        );
    }

    #[test]
    fn staging_symlink_substitution_fails_closed() {
        let tree = TempTree::new("staging-symlink");
        let outside = TempTree::new("staging-outside");
        fs::write(outside.path.join("victim"), b"safe").expect("victim");
        let staging = transfer_staging_name(*id(6).as_bytes());
        symlink(outside.path.join("victim"), tree.path.join(&staging)).expect("staging symlink");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        let plan = UploadPlan::new(
            id(6),
            RemotePath::parse("final.bin").expect("path"),
            1,
            sha(b"x"),
        )
        .expect("plan");
        let mut manager = UploadTransferManager::new(&root);
        assert_eq!(manager.begin(plan), Err(FileTransferError::Storage));
        assert_eq!(
            fs::read(outside.path.join("victim")).expect("victim unchanged"),
            b"safe"
        );
    }

    #[test]
    fn download_chunks_are_bounded_and_eof_is_empty() {
        let tree = TempTree::new("download");
        fs::write(tree.path.join("file.bin"), b"abcdefghij").expect("fixture");
        let root = AnchoredFileRoot::open(&tree.path).expect("root");
        let path = RemotePath::parse("file.bin").expect("path");
        assert_eq!(download_chunk(&root, &path, 3, 4).expect("slice"), b"defg");
        assert!(download_chunk(&root, &path, 99, 4).expect("eof").is_empty());
        assert_eq!(
            download_chunk(&root, &path, 0, 0),
            Err(FileTransferError::InvalidChunkLength)
        );
    }
}
