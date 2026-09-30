//! Narrow command-3 `AgentStatus` + `DeviceList` + `FileList` + bounded upload runtime adapter.
//!
//! The production slice remains explicitly narrower than the generic typed-management
//! surface. `AgentStatus`, read-only `DeviceList`, and `FileList` preserve bounded behavior. A connection
//! may additionally own at most one fresh create-only upload using `UploadBegin`,
//! `UploadChunk`, `UploadFinalize`, and internal/client-requested `UploadAbort`.
//! `UploadResume`, `DownloadChunk`, file mutation commands outside upload, terminal, and
//! forwarding remain unsupported or denied. Filesystem authority is anchored to the
//! Agent user-service `$HOME`, never to `/` or a request-supplied host path.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::path::PathBuf;

use prw_file_service::FileServiceError;
use prw_file_transfer::{FileTransferError, TransferId, UploadTransferManager};
use prw_policy::{BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, Decision};
use prw_registry::durable_registry_sqlite_custody::open_existing_owner_pc_sqlite_authority_from_env;
use prw_remote_bridge::BridgeCommand;

use super::LocalAgentResponseStatus;
use super::management_authority::LocalManagementFilesystemAuthority;
use super::management_request::{
    LocalManagementAdmissionError, admit_authenticated_linux_management_request,
};
use super::management_response::build_management_provider_response;
use super::management_typed_provider_dispatch::{
    LocalManagementTypedProviderDispatchError, LocalManagementTypedProviderResult,
};
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
use crate::frame_object::LocalIpcFrame;
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

const fn agent_status_file_list_policy() -> BoundedLocalManagementPolicy {
    BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
        agent_status: Decision::Allow,
        private_dns: Decision::Deny,
        terminal_open: Decision::Deny,
        terminal_exec: Decision::Deny,
        files_read: Decision::Allow,
        files_write: Decision::Deny,
        forwarding_create: Decision::Deny,
        device_read: Decision::Allow,
    })
}

const fn agent_status_file_list_upload_policy() -> BoundedLocalManagementPolicy {
    BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
        agent_status: Decision::Allow,
        private_dns: Decision::Deny,
        terminal_open: Decision::Deny,
        terminal_exec: Decision::Deny,
        files_read: Decision::Allow,
        files_write: Decision::Allow,
        forwarding_create: Decision::Deny,
        device_read: Decision::Allow,
    })
}

/// Connection-scoped mutable state for the bounded fresh-upload production slice.
///
/// The runtime borrows one already-opened Agent-selected filesystem authority and owns
/// exactly one transfer manager for the authenticated local connection lifetime. The
/// explicit `active_transfer` field deliberately narrows the generic transfer manager's
/// capacity to at most one upload in this production slice so teardown can deterministically
/// abort the exact retained transaction.
#[derive(Debug)]
pub struct LocalBoundedUploadRuntime<'authority> {
    filesystem: &'authority LocalManagementFilesystemAuthority,
    transfers: UploadTransferManager<'authority>,
    active_transfer: Option<TransferId>,
}

/// Explicit bounded-upload teardown failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBoundedUploadCleanupError {
    /// The active staging transaction could not be explicitly aborted.
    Abort(FileTransferError),
    /// Provider state remained active after deterministic cleanup.
    StateNotDrained,
}

impl<'authority> LocalBoundedUploadRuntime<'authority> {
    /// Creates one inert upload runtime over an already-opened trusted root.
    #[must_use]
    pub(crate) fn new(filesystem: &'authority LocalManagementFilesystemAuthority) -> Self {
        Self {
            filesystem,
            transfers: UploadTransferManager::new(filesystem.root()),
            active_transfer: None,
        }
    }

    /// Returns whether this authenticated connection currently owns an upload transaction.
    #[must_use]
    pub(crate) const fn is_upload_active(&self) -> bool {
        self.active_transfer.is_some()
    }

    fn begin(&mut self, plan: &prw_file_transfer::UploadPlan) -> Result<u64, FileTransferError> {
        if self.active_transfer.is_some() {
            return Err(FileTransferError::TransferAlreadyActive);
        }
        let offset = self.transfers.begin(plan.clone())?;
        self.active_transfer = Some(plan.transfer_id());
        Ok(offset)
    }

    fn upload_chunk(
        &mut self,
        transfer_id: TransferId,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, FileTransferError> {
        self.require_active(transfer_id)?;
        self.transfers.upload_chunk(transfer_id, offset, chunk)
    }

    fn finalize(&mut self, transfer_id: TransferId) -> Result<(), FileTransferError> {
        self.require_active(transfer_id)?;
        self.transfers.finalize(transfer_id)?;
        self.active_transfer = None;
        Ok(())
    }

    fn abort(&mut self, transfer_id: TransferId) -> Result<(), FileTransferError> {
        self.require_active(transfer_id)?;
        self.transfers.abort(transfer_id)?;
        self.active_transfer = None;
        Ok(())
    }

    fn require_active(&self, transfer_id: TransferId) -> Result<(), FileTransferError> {
        if self.active_transfer == Some(transfer_id) {
            Ok(())
        } else {
            Err(FileTransferError::TransferUnknown)
        }
    }

    /// Explicitly drains any active upload before the connection-scoped runtime is dropped.
    ///
    /// This is the fail-closed cleanup path for clean EOF, request-processing failure,
    /// hard request-bound exhaustion, or caller cancellation. It never publishes a final
    /// destination; only the active staging transaction is removed.
    pub(crate) fn finish(mut self) -> Result<(), LocalBoundedUploadCleanupError> {
        if let Some(transfer_id) = self.active_transfer {
            self.transfers
                .abort(transfer_id)
                .map_err(LocalBoundedUploadCleanupError::Abort)?;
            self.active_transfer = None;
        }
        if self.transfers.active_count() == 0 {
            Ok(())
        } else {
            Err(LocalBoundedUploadCleanupError::StateNotDrained)
        }
    }
}

/// Processes one canonical command-3 request through the existing read-only slice.
///
/// This compatibility path owns no mutable transfer state. Canonical admission still
/// binds the request to the authenticated same-UID Linux peer. `DeviceList` reads only the
/// existing owner-PC registry authority, while `FileList` remains descriptor-anchored to
/// `$HOME`. Every other command fails closed.
///
/// # Errors
///
/// Returns only failures from the existing terminal-response frame builder.
pub(super) fn process_authenticated_linux_agent_status_file_list_management<S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    agent_status: LocalAgentStatusSnapshot,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory(
        frame,
        connection,
        agent_status,
        home_filesystem_authority,
    )
}

fn process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory<S, F>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    agent_status: LocalAgentStatusSnapshot,
    open_filesystem: F,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError>
where
    F: FnOnce() -> Result<LocalManagementFilesystemAuthority, FileServiceError>,
{
    let request_id = frame.header().request_id();
    let policy = agent_status_file_list_policy();
    let admission = match admit_authenticated_linux_management_request(frame, connection, &policy) {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_error_status(error), &[]);
        }
    };

    match admission.command() {
        BridgeCommand::AgentStatus => build_management_provider_response(
            request_id,
            Ok(LocalManagementTypedProviderResult::AgentStatus(
                agent_status,
            )),
        ),
        BridgeCommand::DeviceList => {
            let result = open_existing_owner_pc_sqlite_authority_from_env()
                .map_err(|_| LocalManagementTypedProviderDispatchError::RegistryRead)
                .and_then(|registry| {
                    registry
                        .registered_devices()
                        .map(LocalManagementTypedProviderResult::RegisteredDevices)
                        .map_err(|_| LocalManagementTypedProviderDispatchError::RegistryRead)
                });
            build_management_provider_response(request_id, result)
        }
        BridgeCommand::FileList(path) => {
            let Ok(filesystem) = open_filesystem() else {
                return build_terminal_response_frame(
                    request_id,
                    LocalAgentResponseStatus::InternalError,
                    &[],
                );
            };
            let result = filesystem
                .root()
                .list_directory(path)
                .map(LocalManagementTypedProviderResult::DirectoryEntries)
                .map_err(LocalManagementTypedProviderDispatchError::File);
            build_management_provider_response(request_id, result)
        }
        _ => build_terminal_response_frame(
            request_id,
            LocalAgentResponseStatus::UnsupportedCommand,
            &[],
        ),
    }
}

/// Processes one command-3 request through the production bounded-upload extension.
///
/// Only `AgentStatus`, read-only `DeviceList`, `FileList`, fresh upload begin/chunk/finalize,
/// and upload abort
/// are reachable after capability admission. `UploadResume`, `DownloadChunk`, `FileStat`,
/// other file mutation, terminal, and forwarding commands remain closed. Once an upload
/// begins, command-3 requests on that connection are restricted to the matching upload's
/// chunk/finalize/abort operations until it is finalized or aborted.
///
/// # Errors
///
/// Returns only failures from the existing terminal-response frame builder.
pub(super) fn process_authenticated_linux_agent_status_file_list_upload_management<S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    agent_status: LocalAgentStatusSnapshot,
    runtime: &mut LocalBoundedUploadRuntime<'_>,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    let request_id = frame.header().request_id();
    let policy = agent_status_file_list_upload_policy();
    let admission = match admit_authenticated_linux_management_request(frame, connection, &policy) {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_error_status(error), &[]);
        }
    };

    if runtime.is_upload_active()
        && !matches!(
            admission.command(),
            BridgeCommand::UploadChunk { .. }
                | BridgeCommand::UploadFinalize(_)
                | BridgeCommand::UploadAbort(_)
        )
    {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    }

    let result = match admission.command() {
        BridgeCommand::AgentStatus => Ok(LocalManagementTypedProviderResult::AgentStatus(
            agent_status,
        )),
        BridgeCommand::DeviceList => open_existing_owner_pc_sqlite_authority_from_env()
            .map_err(|_| LocalManagementTypedProviderDispatchError::RegistryRead)
            .and_then(|registry| {
                registry
                    .registered_devices()
                    .map(LocalManagementTypedProviderResult::RegisteredDevices)
                    .map_err(|_| LocalManagementTypedProviderDispatchError::RegistryRead)
            }),
        BridgeCommand::FileList(path) => runtime
            .filesystem
            .root()
            .list_directory(path)
            .map(LocalManagementTypedProviderResult::DirectoryEntries)
            .map_err(LocalManagementTypedProviderDispatchError::File),
        BridgeCommand::UploadBegin(plan) => runtime
            .begin(plan)
            .map(LocalManagementTypedProviderResult::Offset)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadChunk {
            transfer_id,
            offset,
            chunk,
        } => runtime
            .upload_chunk(*transfer_id, *offset, chunk)
            .map(LocalManagementTypedProviderResult::Offset)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadFinalize(transfer_id) => runtime
            .finalize(*transfer_id)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadAbort(transfer_id) => runtime
            .abort(*transfer_id)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::FileStat(_)
        | BridgeCommand::FileCreate { .. }
        | BridgeCommand::DirectoryCreate(_)
        | BridgeCommand::UploadResume(_)
        | BridgeCommand::DownloadChunk { .. }
        | BridgeCommand::TerminalOpen { .. }
        | BridgeCommand::TerminalInput { .. }
        | BridgeCommand::TerminalResize { .. }
        | BridgeCommand::TerminalRead { .. }
        | BridgeCommand::TerminalClose(_)
        | BridgeCommand::ForwardOpen { .. }
        | BridgeCommand::ForwardClose(_) => {
            return build_terminal_response_frame(
                request_id,
                LocalAgentResponseStatus::UnsupportedCommand,
                &[],
            );
        }
    };

    build_management_provider_response(request_id, result)
}

pub fn home_filesystem_authority() -> Result<LocalManagementFilesystemAuthority, FileServiceError> {
    open_home_filesystem_authority_from_raw(std::env::var_os("HOME").as_deref())
}

fn open_home_filesystem_authority_from_raw(
    raw: Option<&OsStr>,
) -> Result<LocalManagementFilesystemAuthority, FileServiceError> {
    let raw = raw.ok_or(FileServiceError::InvalidRoot)?;
    if raw.is_empty() {
        return Err(FileServiceError::InvalidRoot);
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(FileServiceError::InvalidRoot);
    }
    LocalManagementFilesystemAuthority::open_trusted_root(&path)
}

const fn admission_error_status(error: LocalManagementAdmissionError) -> LocalAgentResponseStatus {
    match error {
        LocalManagementAdmissionError::Framing(_)
        | LocalManagementAdmissionError::CanonicalCommand(_) => {
            LocalAgentResponseStatus::InvalidRequest
        }
        LocalManagementAdmissionError::CapabilityDenied => LocalAgentResponseStatus::Unauthorized,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aws_lc_rs::digest::{SHA256, digest};
    use prw_file_service::RemotePath;
    use prw_file_transfer::{TransferId, UploadPlan};
    use prw_policy::{Capability, Decision, PolicyEvaluator};
    use prw_remote_bridge::BridgeCommand;

    use super::{
        LocalBoundedUploadRuntime, agent_status_file_list_policy,
        agent_status_file_list_upload_policy, open_home_filesystem_authority_from_raw,
        process_authenticated_linux_agent_status_file_list_management,
        process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory,
        process_authenticated_linux_agent_status_file_list_upload_management,
    };
    use crate::LocalIpcRequestId;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("request id is non-zero")
    }

    fn request(request_id: u64, command: &BridgeCommand) -> crate::frame_object::LocalIpcFrame {
        let bridge = command.encode().expect("command encodes");
        build_local_management_request_frame(id(request_id), &bridge)
            .expect("management frame builds")
    }

    fn test_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "ownspace-file-list-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("test root creates");
        path
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = digest(&SHA256, bytes);
        let mut value = [0_u8; 32];
        value.copy_from_slice(digest.as_ref());
        value
    }

    fn response_offset(frame: &crate::frame_object::LocalIpcFrame) -> u64 {
        let bytes = frame.payload().as_bytes();
        assert_eq!(bytes.get(2), Some(&5));
        u64::from_be_bytes(bytes[3..11].try_into().expect("offset body is exact"))
    }

    #[test]
    fn fixed_policy_allows_agent_status_and_files_read_only() {
        let policy = agent_status_file_list_policy();
        assert_eq!(
            policy.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        assert_eq!(policy.evaluate(Capability::FilesRead), Decision::Allow);
        assert_eq!(policy.evaluate(Capability::DeviceRead), Decision::Allow);
        for capability in [
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesWrite,
            Capability::ForwardingCreate,
            Capability::FilesDelete,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn bounded_upload_policy_adds_only_files_write() {
        let policy = agent_status_file_list_upload_policy();
        for capability in [
            Capability::AgentStatusRead,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::DeviceRead,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Allow);
        }
        for capability in [
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::ForwardingCreate,
            Capability::FilesDelete,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn file_list_home_root_requires_nonempty_absolute_path() {
        assert!(open_home_filesystem_authority_from_raw(None).is_err());
        assert!(open_home_filesystem_authority_from_raw(Some(OsStr::new(""))).is_err());
        assert!(open_home_filesystem_authority_from_raw(Some(OsStr::new("relative"))).is_err());
    }

    #[test]
    fn file_list_request_uses_only_supplied_descriptor_root_and_returns_directory_entries() {
        let root = test_root();
        fs::create_dir(root.join("docs")).expect("directory creates");
        fs::write(root.join("notes.txt"), b"notes").expect("file creates");
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let frame = request(
            902,
            &BridgeCommand::FileList(RemotePath::parse("").expect("root path")),
        );
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

        let response =
            process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory(
                &frame,
                &connection,
                snapshot,
                || open_home_filesystem_authority_from_raw(Some(root.as_os_str())),
            )
            .expect("FileList response builds");
        let terminal =
            validate_terminal_response_frame(&response).expect("terminal response validates");

        assert_eq!(terminal.request_id(), id(902));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        assert_eq!(response.payload().as_bytes().get(2), Some(&2));
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn other_files_read_commands_remain_unsupported_after_capability_admission() {
        for (request_id, command) in [
            (
                903,
                BridgeCommand::FileStat(RemotePath::parse("notes.txt").expect("path")),
            ),
            (
                904,
                BridgeCommand::DownloadChunk {
                    path: RemotePath::parse("notes.txt").expect("path"),
                    offset: 0,
                    requested_len: 1,
                },
            ),
        ] {
            let (server, _client) = UnixStream::pair().expect("local pair creates");
            let connection = AuthenticatedLocalLinuxConnection::try_new(server)
                .expect("same-UID local pair authenticates");
            let frame = request(request_id, &command);
            let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

            let response = process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory(
                &frame,
                &connection,
                snapshot,
                || panic!("unsupported command must not acquire filesystem authority"),
            )
            .expect("unsupported response builds");
            let terminal =
                validate_terminal_response_frame(&response).expect("terminal response validates");
            assert_eq!(
                terminal.status(),
                LocalAgentResponseStatus::UnsupportedCommand
            );
        }
    }

    #[test]
    fn bounded_upload_commits_exact_content_and_drains_runtime() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let payload = b"bounded upload payload";
        let transfer_id = TransferId::new([0x31; 16]);
        let plan = UploadPlan::new(
            transfer_id,
            RemotePath::parse("uploaded.bin").expect("path"),
            payload.len() as u64,
            sha256(payload),
        )
        .expect("plan");

        let begin = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(910, &BridgeCommand::UploadBegin(plan)),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("begin response builds");
        assert_eq!(response_offset(&begin), 0);
        assert!(runtime.is_upload_active());

        let chunk = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                911,
                &BridgeCommand::UploadChunk {
                    transfer_id,
                    offset: 0,
                    chunk: payload.to_vec(),
                },
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("chunk response builds");
        assert_eq!(response_offset(&chunk), payload.len() as u64);

        let finalize = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(912, &BridgeCommand::UploadFinalize(transfer_id)),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("finalize response builds");
        assert_eq!(finalize.payload().as_bytes().get(2), Some(&4));
        assert!(!runtime.is_upload_active());
        runtime.finish().expect("runtime drains after finalize");
        assert_eq!(
            fs::read(root.join("uploaded.bin")).expect("file reads"),
            payload
        );
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn bounded_upload_cleanup_aborts_unfinished_staging_transaction() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let transfer_id = TransferId::new([0x32; 16]);
        let plan = UploadPlan::new(
            transfer_id,
            RemotePath::parse("unfinished.bin").expect("path"),
            4,
            sha256(b"data"),
        )
        .expect("plan");

        let begin = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(913, &BridgeCommand::UploadBegin(plan)),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("begin response builds");
        assert_eq!(response_offset(&begin), 0);
        assert!(runtime.is_upload_active());
        runtime
            .finish()
            .expect("unfinished transfer aborts cleanly");
        assert!(!root.join("unfinished.bin").exists());
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn bounded_upload_command_gate_keeps_adjacent_write_and_download_commands_closed() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let transfer_id = TransferId::new([0x33; 16]);
        let resume_plan = UploadPlan::new(
            transfer_id,
            RemotePath::parse("resume.bin").expect("path"),
            1,
            sha256(b"x"),
        )
        .expect("plan");

        for (request_id, command) in [
            (
                914,
                BridgeCommand::FileCreate {
                    path: RemotePath::parse("create.bin").expect("path"),
                    contents: b"x".to_vec(),
                },
            ),
            (915, BridgeCommand::UploadResume(resume_plan)),
            (
                916,
                BridgeCommand::DownloadChunk {
                    path: RemotePath::parse("missing.bin").expect("path"),
                    offset: 0,
                    requested_len: 1,
                },
            ),
        ] {
            let response = process_authenticated_linux_agent_status_file_list_upload_management(
                &request(request_id, &command),
                &connection,
                snapshot,
                &mut runtime,
            )
            .expect("unsupported response builds");
            let terminal = validate_terminal_response_frame(&response).expect("response validates");
            assert_eq!(
                terminal.status(),
                LocalAgentResponseStatus::UnsupportedCommand
            );
        }

        runtime.finish().expect("runtime remains quiescent");
        assert!(!root.join("create.bin").exists());
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn agent_status_request_returns_correlated_management_success() {
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let bridge = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus command encodes");
        let frame = build_local_management_request_frame(id(901), &bridge)
            .expect("management frame builds");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

        let response = process_authenticated_linux_agent_status_file_list_management(
            &frame,
            &connection,
            snapshot,
        )
        .expect("AgentStatus response builds");
        let terminal =
            validate_terminal_response_frame(&response).expect("terminal response validates");

        assert_eq!(terminal.request_id(), id(901));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        assert_eq!(response.payload().as_bytes().get(2), Some(&1));
    }
}
