//! Narrow production command-3 runtime for local status/files/upload plus one local terminal.
//!
//! The production slice remains explicitly narrower than the generic typed-management
//! surface. `AgentStatus`, read-only `DeviceList`, `FileList`, and `FileStat` preserve bounded
//! behavior. A connection may additionally own at most one fresh create-only upload or one fixed-profile
//! local PTY terminal.
//! Upload and terminal lifecycles are mutually exclusive on one authenticated connection.
//! `UploadResume`, `DownloadChunk`, file mutation commands outside upload, forwarding, and
//! non-POSIX terminal profiles remain unsupported or denied. Filesystem authority is anchored to the
//! Agent user-service `$HOME`, never to `/` or a request-supplied host path.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::path::PathBuf;

use prw_file_service::FileServiceError;
use prw_file_transfer::{FileTransferError, TransferId, UploadTransferManager};
use prw_policy::{BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, Decision};
use prw_registry::durable_registry_sqlite_custody::open_existing_owner_pc_sqlite_authority_from_env;
use prw_remote_bridge::BridgeCommand;
use prw_terminal::{
    LocalTerminalPrincipal, TerminalBroker, TerminalError, TerminalSessionId,
    TerminalSessionPrincipal, TerminalState,
};

use super::LocalAgentResponseStatus;
use super::linux_terminal_backend::LocalPosixPtyTerminalBackend;
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
        terminal_open: Decision::Allow,
        terminal_exec: Decision::Allow,
        files_read: Decision::Allow,
        files_write: Decision::Allow,
        forwarding_create: Decision::Deny,
        device_read: Decision::Allow,
    })
}

/// Connection-scoped mutable state for the bounded production management slice.
///
/// The runtime borrows one already-opened Agent-selected filesystem authority and owns
/// one transfer manager plus one fixed-profile local PTY broker. At most one upload and
/// one terminal identifier can be tracked, and command dispatch prevents those mutable
/// families from being active concurrently on the same authenticated connection.
#[derive(Debug)]
pub struct LocalBoundedUploadRuntime<'authority> {
    filesystem: &'authority LocalManagementFilesystemAuthority,
    transfers: UploadTransferManager<'authority>,
    active_transfer: Option<TransferId>,
    terminal: TerminalBroker<LocalPosixPtyTerminalBackend>,
    active_terminal: Option<TerminalSessionId>,
}

/// Explicit connection-scoped provider teardown failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBoundedUploadCleanupError {
    /// The active staging transaction could not be explicitly aborted.
    Abort(FileTransferError),
    /// The active terminal process group could not be explicitly closed.
    Terminal(TerminalError),
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
            terminal: TerminalBroker::new(LocalPosixPtyTerminalBackend::new()),
            active_terminal: None,
        }
    }

    /// Returns whether this authenticated connection currently owns an upload transaction.
    #[must_use]
    pub(crate) const fn is_upload_active(&self) -> bool {
        self.active_transfer.is_some()
    }

    /// Returns whether this authenticated connection currently owns a terminal session.
    #[must_use]
    pub(crate) const fn is_terminal_active(&self) -> bool {
        self.active_terminal.is_some()
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

    fn terminal_open(
        &mut self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
        profile: prw_terminal::TerminalProfile,
        geometry: prw_terminal::TerminalGeometry,
    ) -> Result<(), LocalManagementTypedProviderDispatchError> {
        if self.active_terminal.is_some() {
            return Err(LocalManagementTypedProviderDispatchError::Terminal(
                TerminalError::SessionCapacity,
            ));
        }
        self.terminal
            .open_session(session_id, principal, profile, geometry)
            .map_err(LocalManagementTypedProviderDispatchError::Terminal)?;
        self.active_terminal = Some(session_id);
        Ok(())
    }

    fn terminal_input(
        &mut self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
        bytes: &[u8],
    ) -> Result<(), LocalManagementTypedProviderDispatchError> {
        self.require_terminal_principal(principal, session_id)?;
        self.terminal
            .write_input(session_id, bytes)
            .map_err(LocalManagementTypedProviderDispatchError::Terminal)
    }

    fn terminal_resize(
        &mut self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
        geometry: prw_terminal::TerminalGeometry,
    ) -> Result<(), LocalManagementTypedProviderDispatchError> {
        self.require_terminal_principal(principal, session_id)?;
        self.terminal
            .resize_session(session_id, geometry)
            .map_err(LocalManagementTypedProviderDispatchError::Terminal)
    }

    fn terminal_read(
        &mut self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, LocalManagementTypedProviderDispatchError> {
        self.require_terminal_principal(principal, session_id)?;
        self.terminal
            .read_output(session_id, maximum_bytes)
            .map_err(LocalManagementTypedProviderDispatchError::Terminal)
    }

    fn terminal_close(
        &mut self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
    ) -> Result<(), LocalManagementTypedProviderDispatchError> {
        self.require_terminal_principal(principal, session_id)?;
        self.terminal
            .close_session(session_id)
            .map_err(LocalManagementTypedProviderDispatchError::Terminal)?;
        self.active_terminal = None;
        Ok(())
    }

    fn require_terminal_principal(
        &self,
        principal: LocalTerminalPrincipal,
        session_id: TerminalSessionId,
    ) -> Result<(), LocalManagementTypedProviderDispatchError> {
        if self.active_terminal != Some(session_id) {
            return Err(LocalManagementTypedProviderDispatchError::Terminal(
                TerminalError::UnknownSession,
            ));
        }
        let expected = TerminalSessionPrincipal::LocalSameUid(principal);
        let existing = self.terminal.session(session_id).ok_or(
            LocalManagementTypedProviderDispatchError::Terminal(TerminalError::UnknownSession),
        )?;
        if existing.principal() == &expected {
            Ok(())
        } else {
            Err(LocalManagementTypedProviderDispatchError::PrincipalMismatch)
        }
    }

    /// Explicitly drains active upload/terminal state before the connection runtime is dropped.
    ///
    /// This is the fail-closed cleanup path for clean EOF, request-processing failure,
    /// hard request-bound exhaustion, or caller cancellation. Upload cleanup never publishes
    /// a final destination. Terminal cleanup explicitly kills/reaps the provider process group.
    pub(crate) fn finish(mut self) -> Result<(), LocalBoundedUploadCleanupError> {
        if let Some(transfer_id) = self.active_transfer {
            self.transfers
                .abort(transfer_id)
                .map_err(LocalBoundedUploadCleanupError::Abort)?;
            self.active_transfer = None;
        }
        if let Some(session_id) = self.active_terminal {
            let state = self
                .terminal
                .session(session_id)
                .map(prw_terminal::TerminalSession::state)
                .ok_or(LocalBoundedUploadCleanupError::StateNotDrained)?;
            match state {
                TerminalState::Open => self
                    .terminal
                    .close_session(session_id)
                    .map_err(LocalBoundedUploadCleanupError::Terminal)?,
                TerminalState::Failed => self
                    .terminal
                    .retry_failed_close(session_id)
                    .map_err(LocalBoundedUploadCleanupError::Terminal)?,
                TerminalState::Opening | TerminalState::Closing | TerminalState::Closed => {
                    return Err(LocalBoundedUploadCleanupError::StateNotDrained);
                }
            };
            self.active_terminal = None;
        }
        if self.transfers.active_count() == 0 && self.terminal.is_empty() {
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

/// Processes one command-3 request through the production upload + local-terminal extension.
///
/// `AgentStatus`, read-only `DeviceList`, `FileList`, `FileStat`, fresh upload
/// begin/chunk/finalize/abort, and fixed-profile local terminal open/input/resize/read/close
/// are reachable after capability
/// admission. `UploadResume`, `DownloadChunk`, other file mutation, and forwarding remain closed.
/// An active upload and active terminal are mutually exclusive on one authenticated connection.
///
/// # Errors
///
/// Returns only failures from the existing terminal-response frame builder.
#[allow(clippy::too_many_lines)]
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

    if runtime.is_terminal_active()
        && !matches!(
            admission.command(),
            BridgeCommand::TerminalInput { .. }
                | BridgeCommand::TerminalResize { .. }
                | BridgeCommand::TerminalRead { .. }
                | BridgeCommand::TerminalClose(_)
        )
    {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    }

    if !runtime.is_terminal_active()
        && matches!(
            admission.command(),
            BridgeCommand::TerminalInput { .. }
                | BridgeCommand::TerminalResize { .. }
                | BridgeCommand::TerminalRead { .. }
                | BridgeCommand::TerminalClose(_)
        )
    {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    }

    let terminal_principal = LocalTerminalPrincipal::new(connection.peer_credentials().uid());

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
        BridgeCommand::FileStat(path) => runtime
            .filesystem
            .root()
            .metadata(path)
            .map(LocalManagementTypedProviderResult::Metadata)
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
        BridgeCommand::TerminalOpen {
            session_id,
            profile,
            geometry,
        } => runtime
            .terminal_open(terminal_principal, *session_id, *profile, *geometry)
            .map(|()| LocalManagementTypedProviderResult::Empty),
        BridgeCommand::TerminalInput { session_id, bytes } => runtime
            .terminal_input(terminal_principal, *session_id, bytes)
            .map(|()| LocalManagementTypedProviderResult::Empty),
        BridgeCommand::TerminalResize {
            session_id,
            geometry,
        } => runtime
            .terminal_resize(terminal_principal, *session_id, *geometry)
            .map(|()| LocalManagementTypedProviderResult::Empty),
        BridgeCommand::TerminalRead {
            session_id,
            maximum_bytes,
        } => runtime
            .terminal_read(terminal_principal, *session_id, *maximum_bytes)
            .map(LocalManagementTypedProviderResult::Bytes),
        BridgeCommand::TerminalClose(session_id) => runtime
            .terminal_close(terminal_principal, *session_id)
            .map(|()| LocalManagementTypedProviderResult::Empty),
        BridgeCommand::FileCreate { .. }
        | BridgeCommand::DirectoryCreate(_)
        | BridgeCommand::UploadResume(_)
        | BridgeCommand::DownloadChunk { .. }
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
    use prw_terminal::{
        LocalTerminalPrincipal, TerminalGeometry, TerminalProfile, TerminalSessionId,
    };

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
    fn production_policy_adds_files_write_and_bounded_terminal_authority() {
        let policy = agent_status_file_list_upload_policy();
        for capability in [
            Capability::AgentStatusRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::DeviceRead,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Allow);
        }
        for capability in [
            Capability::PrivateDnsConfigRead,
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
    fn production_file_stat_reports_correlated_type_and_size_without_following_symlinks() {
        let root = test_root();
        fs::write(root.join("notes.txt"), b"notes").expect("regular test file creates");
        fs::create_dir(root.join("docs")).expect("test directory creates");
        std::os::unix::fs::symlink("notes.txt", root.join("shortcut"))
            .expect("test symlink creates");
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

        for (request_id, path, expected_type, expected_size) in [
            (930, "notes.txt", 1, 5),
            (
                931,
                "docs",
                2,
                fs::symlink_metadata(root.join("docs"))
                    .expect("directory metadata")
                    .len(),
            ),
            (
                932,
                "shortcut",
                3,
                fs::symlink_metadata(root.join("shortcut"))
                    .expect("symlink metadata")
                    .len(),
            ),
        ] {
            let response = process_authenticated_linux_agent_status_file_list_upload_management(
                &request(
                    request_id,
                    &BridgeCommand::FileStat(RemotePath::parse(path).expect("canonical path")),
                ),
                &connection,
                snapshot,
                &mut runtime,
            )
            .expect("FileStat response builds");
            let terminal = validate_terminal_response_frame(&response).expect("response validates");
            assert_eq!(terminal.request_id(), id(request_id));
            assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
            let bytes = response.payload().as_bytes();
            assert_eq!(bytes.len(), 12);
            assert_eq!(bytes[2], 3, "existing metadata result tag");
            assert_eq!(bytes[3], expected_type);
            assert_eq!(
                u64::from_be_bytes(bytes[4..12].try_into().expect("exact size body")),
                expected_size
            );
        }

        let missing = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                933,
                &BridgeCommand::FileStat(RemotePath::parse("missing.txt").expect("path")),
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("missing metadata response builds");
        let terminal = validate_terminal_response_frame(&missing).expect("response validates");
        assert_eq!(terminal.request_id(), id(933));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::InternalError);
        assert_eq!(
            missing.payload().as_bytes().len(),
            2,
            "no forged metadata success"
        );

        runtime.finish().expect("quiescent runtime drains");
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn production_file_stat_rejects_intermediate_symlink_without_escaping_root() {
        let root = test_root();
        let outside = test_root();
        fs::write(outside.join("secret.txt"), b"outside").expect("outside fixture creates");
        std::os::unix::fs::symlink(&outside, root.join("escape"))
            .expect("intermediate symlink creates");
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let escaped = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                936,
                &BridgeCommand::FileStat(
                    RemotePath::parse("escape/secret.txt").expect("canonical relative path"),
                ),
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("intermediate symlink rejection response builds");
        let terminal = validate_terminal_response_frame(&escaped).expect("response validates");
        assert_eq!(terminal.request_id(), id(936));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::InternalError);
        assert_eq!(
            escaped.payload().as_bytes().len(),
            2,
            "no escaped metadata success"
        );
        assert_eq!(
            fs::read(outside.join("secret.txt")).expect("outside fixture remains intact"),
            b"outside"
        );
        runtime.finish().expect("quiescent runtime drains");
        fs::remove_dir_all(root).expect("test root removes");
        fs::remove_dir_all(outside).expect("outside fixture removes");
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

    fn terminal_id(value: u64) -> TerminalSessionId {
        TerminalSessionId::new(value).expect("terminal id is non-zero")
    }

    fn terminal_geometry(columns: u16, rows: u16) -> TerminalGeometry {
        TerminalGeometry::new(columns, rows).expect("terminal geometry is bounded")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn production_terminal_runtime_opens_resizes_reads_and_closes_on_same_principal() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let session_id = terminal_id(0x51);

        let open = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                905,
                &BridgeCommand::TerminalOpen {
                    session_id,
                    profile: TerminalProfile::PosixShell,
                    geometry: terminal_geometry(80, 24),
                },
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("terminal open response builds");
        let terminal = validate_terminal_response_frame(&open).expect("open response validates");
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        assert_eq!(open.payload().as_bytes().get(2), Some(&4));
        assert!(runtime.is_terminal_active());

        let resize = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                906,
                &BridgeCommand::TerminalResize {
                    session_id,
                    geometry: terminal_geometry(100, 35),
                },
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("terminal resize response builds");
        assert_eq!(
            validate_terminal_response_frame(&resize)
                .expect("resize response validates")
                .status(),
            LocalAgentResponseStatus::Ok
        );

        let input = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                907,
                &BridgeCommand::TerminalInput {
                    session_id,
                    bytes: b"printf 'OWNSPACE_RUNTIME_OK\n'\n".to_vec(),
                },
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("terminal input response builds");
        assert_eq!(
            validate_terminal_response_frame(&input)
                .expect("input response validates")
                .status(),
            LocalAgentResponseStatus::Ok
        );

        let read = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                908,
                &BridgeCommand::TerminalRead {
                    session_id,
                    maximum_bytes: 4096,
                },
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("terminal read response builds");
        assert_eq!(
            validate_terminal_response_frame(&read)
                .expect("read response validates")
                .status(),
            LocalAgentResponseStatus::Ok
        );
        assert_eq!(read.payload().as_bytes().get(2), Some(&6));

        let close = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(909, &BridgeCommand::TerminalClose(session_id)),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("terminal close response builds");
        assert_eq!(
            validate_terminal_response_frame(&close)
                .expect("close response validates")
                .status(),
            LocalAgentResponseStatus::Ok
        );
        assert!(!runtime.is_terminal_active());
        runtime.finish().expect("terminal runtime drains");
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn production_terminal_runtime_preserves_principal_and_family_exclusion() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let principal = LocalTerminalPrincipal::new(1000);
        let other_principal = LocalTerminalPrincipal::new(1001);
        let session_id = terminal_id(0x52);
        runtime
            .terminal_open(
                principal,
                session_id,
                TerminalProfile::PosixShell,
                terminal_geometry(80, 24),
            )
            .expect("terminal opens");
        assert_eq!(
            runtime.terminal_input(other_principal, session_id, b"x"),
            Err(super::LocalManagementTypedProviderDispatchError::PrincipalMismatch)
        );

        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let response = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(918, &BridgeCommand::AgentStatus),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("conflict response builds");
        assert_eq!(
            validate_terminal_response_frame(&response)
                .expect("conflict response validates")
                .status(),
            LocalAgentResponseStatus::Conflict
        );
        let file_stat = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                934,
                &BridgeCommand::FileStat(RemotePath::parse("notes.txt").expect("path")),
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("active terminal blocks metadata request");
        let terminal = validate_terminal_response_frame(&file_stat).expect("response validates");
        assert_eq!(terminal.request_id(), id(934));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Conflict);
        runtime.finish().expect("terminal cleanup succeeds");
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn terminal_commands_without_active_terminal_fail_closed_as_conflict() {
        let root = test_root();
        let filesystem = open_home_filesystem_authority_from_raw(Some(root.as_os_str()))
            .expect("test filesystem authority opens");
        let mut runtime = LocalBoundedUploadRuntime::new(&filesystem);
        let (server, _client) = UnixStream::pair().expect("local pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local pair authenticates");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let session_id = terminal_id(0x53);

        for (request_id, command) in [
            (
                919,
                BridgeCommand::TerminalInput {
                    session_id,
                    bytes: b"x".to_vec(),
                },
            ),
            (
                920,
                BridgeCommand::TerminalResize {
                    session_id,
                    geometry: terminal_geometry(80, 24),
                },
            ),
            (
                921,
                BridgeCommand::TerminalRead {
                    session_id,
                    maximum_bytes: 1,
                },
            ),
            (922, BridgeCommand::TerminalClose(session_id)),
        ] {
            let response = process_authenticated_linux_agent_status_file_list_upload_management(
                &request(request_id, &command),
                &connection,
                snapshot,
                &mut runtime,
            )
            .expect("conflict response builds");
            assert_eq!(
                validate_terminal_response_frame(&response)
                    .expect("conflict response validates")
                    .status(),
                LocalAgentResponseStatus::Conflict
            );
        }
        runtime.finish().expect("quiescent runtime drains");
        fs::remove_dir_all(root).expect("test root removes");
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
        let file_stat = process_authenticated_linux_agent_status_file_list_upload_management(
            &request(
                935,
                &BridgeCommand::FileStat(RemotePath::parse("uploaded.bin").expect("path")),
            ),
            &connection,
            snapshot,
            &mut runtime,
        )
        .expect("active upload blocks metadata request");
        let terminal = validate_terminal_response_frame(&file_stat).expect("response validates");
        assert_eq!(terminal.request_id(), id(935));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Conflict);

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
