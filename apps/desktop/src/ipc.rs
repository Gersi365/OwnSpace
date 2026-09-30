use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use prw_agent::frame_object::LocalIpcFrame;
use prw_agent::frame_object::reader::read_frame;
use prw_agent::frame_object::writer::write_frame;
use prw_agent::local_commands::management_request::build_local_management_request_frame;
use prw_agent::local_commands::private_dns_response::decode_success_private_dns_frame;
use prw_agent::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use prw_agent::local_commands::request_frame::stream::write_local_command_request;
use prw_agent::local_commands::status_snapshot::LocalAgentStatusSnapshot;
use prw_agent::local_commands::status_snapshot::response_frame::decode_success_status_frame;
use prw_agent::local_commands::terminal_response::validate_terminal_response_frame;
use prw_agent::local_commands::{LocalAgentCommand, LocalAgentResponseStatus};
use prw_agent::{
    AGENT_RUNTIME_DIRECTORY_MODE, AGENT_SOCKET_MODE, LocalIpcContract, LocalIpcRequestId,
};
use rustix::process::geteuid;

use crate::local_management_ipc::{
    LocalFileListEntry, LocalRegisteredDeviceEntry, build_file_list_management_request,
    build_registered_device_list_management_request, decode_file_list_success_body,
    decode_registered_device_list_success_body,
};
use crate::state::{AgentAvailability, DesktopPresentationState};

const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINAL_OPEN_REQUEST_ID: u64 = 4;
const TERMINAL_INPUT_REQUEST_ID: u64 = 5;
const TERMINAL_CLOSE_REQUEST_ID: u64 = 6;
const UPLOAD_BEGIN_REQUEST_ID: u64 = 7;
const UPLOAD_CHUNK_REQUEST_ID: u64 = 8;
const UPLOAD_FINALIZE_REQUEST_ID: u64 = 9;
const UPLOAD_ABORT_REQUEST_ID: u64 = 10;
const DEVICE_LIST_REQUEST_ID: u64 = 11;
const MANAGEMENT_STATUS_PREFIX_LENGTH: usize = 2;
const MANAGEMENT_EMPTY_RESULT: u8 = 4;
const MANAGEMENT_OFFSET_RESULT: u8 = 5;

#[derive(Debug, Clone)]
pub struct StatusProbe {
    pub(crate) status: Result<LocalAgentStatusSnapshot, DesktopIpcError>,
    pub(crate) private_dns: Result<LocalPrivateDnsSnapshot, DesktopIpcError>,
}

impl StatusProbe {
    pub(crate) fn into_presentation(self) -> DesktopPresentationState {
        let mut state = DesktopPresentationState::connecting();
        let status_succeeded = self.status.is_ok();

        match self.status {
            Ok(snapshot) => {
                state = state.with_status(snapshot);
            }
            Err(error) => {
                state = state.with_error(error.availability(), error.to_string());
            }
        }

        match self.private_dns {
            Ok(snapshot) => {
                state = state.with_private_dns(&snapshot);
            }
            Err(error) if status_succeeded => {
                state.detail = format!("{} Private DNS status unavailable: {error}.", state.detail);
            }
            Err(_) => {}
        }

        state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopIpcError {
    MissingRuntimeDirectory,
    InvalidRuntimeDirectory,
    RuntimeRootUnavailable,
    RuntimeRootUntrusted,
    PrwRuntimeDirectoryUnavailable,
    PrwRuntimeDirectoryUntrusted,
    AgentSocketUnavailable,
    AgentSocketUntrusted,
    ConnectFailed,
    ConfigureFailed,
    RequestIdGenerationFailed,
    RequestWriteFailed,
    ResponseReadFailed,
    ResponseInvalid,
    RequestIdMismatch,
    AgentStatus(LocalAgentResponseStatus),
    ManagementRequestInvalid,
}

impl DesktopIpcError {
    pub(crate) const fn availability(self) -> AgentAvailability {
        match self {
            Self::MissingRuntimeDirectory
            | Self::InvalidRuntimeDirectory
            | Self::RuntimeRootUnavailable
            | Self::PrwRuntimeDirectoryUnavailable
            | Self::AgentSocketUnavailable
            | Self::ConnectFailed => AgentAvailability::Offline,
            Self::RuntimeRootUntrusted
            | Self::PrwRuntimeDirectoryUntrusted
            | Self::AgentSocketUntrusted
            | Self::ConfigureFailed
            | Self::RequestIdGenerationFailed
            | Self::RequestWriteFailed
            | Self::ResponseReadFailed
            | Self::ResponseInvalid
            | Self::RequestIdMismatch
            | Self::AgentStatus(_)
            | Self::ManagementRequestInvalid => AgentAvailability::Error,
        }
    }
}

impl fmt::Display for DesktopIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingRuntimeDirectory => "XDG_RUNTIME_DIR is unavailable",
            Self::InvalidRuntimeDirectory => "XDG_RUNTIME_DIR is not an absolute path",
            Self::RuntimeRootUnavailable => "XDG runtime root is unavailable",
            Self::RuntimeRootUntrusted => "XDG runtime root failed local trust checks",
            Self::PrwRuntimeDirectoryUnavailable => "Ownspace runtime directory is unavailable",
            Self::PrwRuntimeDirectoryUntrusted => {
                "Ownspace runtime directory failed local trust checks"
            }
            Self::AgentSocketUnavailable => "Ownspace Agent socket is unavailable",
            Self::AgentSocketUntrusted => "Ownspace Agent socket failed local trust checks",
            Self::ConnectFailed => "Ownspace Agent connection failed",
            Self::ConfigureFailed => "Ownspace Agent connection timeout configuration failed",
            Self::RequestIdGenerationFailed => "Ownspace request identifier generation failed",
            Self::RequestWriteFailed => "Ownspace Agent request write failed",
            Self::ResponseReadFailed => "Ownspace Agent response read failed",
            Self::ResponseInvalid => "Ownspace Agent response failed protocol validation",
            Self::RequestIdMismatch => "Ownspace Agent response correlation failed",
            Self::AgentStatus(LocalAgentResponseStatus::InvalidRequest) => {
                "Ownspace Agent rejected the request as invalid"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Unauthorized) => {
                "Ownspace Agent rejected the request as unauthorized"
            }
            Self::AgentStatus(LocalAgentResponseStatus::UnsupportedCommand) => {
                "Ownspace Agent does not support the requested command"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Conflict) => {
                "Ownspace Agent reported a state conflict"
            }
            Self::AgentStatus(LocalAgentResponseStatus::InternalError) => {
                "Ownspace Agent reported an internal error"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Ok) => {
                "Ownspace Agent returned an unexpected success-status error"
            }
            Self::AgentStatus(_) => "Ownspace Agent returned an unknown response status",
            Self::ManagementRequestInvalid => "Ownspace management request is invalid",
        };
        formatter.write_str(message)
    }
}

pub fn query_status_probe() -> StatusProbe {
    let endpoint = endpoint_from_environment();
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return StatusProbe {
                status: Err(error),
                private_dns: Err(error),
            };
        }
    };

    let status_id =
        LocalIpcRequestId::new(1).map_err(|_| DesktopIpcError::RequestIdGenerationFailed);
    let dns_id = LocalIpcRequestId::new(2).map_err(|_| DesktopIpcError::RequestIdGenerationFailed);

    let status = status_id.and_then(|request_id| query_status(&endpoint, request_id));
    let private_dns = dns_id.and_then(|request_id| query_private_dns(&endpoint, request_id));

    StatusProbe {
        status,
        private_dns,
    }
}

/// Queries one read-only directory listing through the fixed local command-3 `FileList` slice.
///
/// Paths are canonical relative paths under the Agent-selected owner-home authority. The
/// desktop cannot select a host filesystem root and does not issue `FileStat`, download,
/// mutation, transfer, terminal or forwarding operations here.
pub fn query_file_list(path: &str) -> Result<Vec<LocalFileListEntry>, DesktopIpcError> {
    let endpoint = endpoint_from_environment()?;
    let request_id =
        LocalIpcRequestId::new(3).map_err(|_| DesktopIpcError::RequestIdGenerationFailed)?;
    let request = build_file_list_management_request(request_id, path)
        .map_err(|_| DesktopIpcError::ManagementRequestInvalid)?;
    let frame = query_prebuilt_success_frame(&endpoint, request_id, &request)?;
    decode_file_list_success_body(frame.payload().as_bytes())
        .map_err(|_| DesktopIpcError::ResponseInvalid)
}

/// Queries the owner-PC registered-device projection through the authenticated local Agent.
///
/// The response contains only registry device identity and lifecycle metadata. Reachability is not
/// inferred from endpoints or transport identity by this query.
pub fn query_registered_devices() -> Result<Vec<LocalRegisteredDeviceEntry>, DesktopIpcError> {
    let endpoint = endpoint_from_environment()?;
    let request_id = LocalIpcRequestId::new(DEVICE_LIST_REQUEST_ID)
        .map_err(|_| DesktopIpcError::RequestIdGenerationFailed)?;
    let request = build_registered_device_list_management_request(request_id)
        .map_err(|_| DesktopIpcError::ManagementRequestInvalid)?;
    let frame = query_prebuilt_success_frame(&endpoint, request_id, &request)?;
    decode_registered_device_list_success_body(frame.payload().as_bytes())
        .map_err(|_| DesktopIpcError::ResponseInvalid)
}

/// Executes one already-encoded terminal-open management intent through the trusted local Agent socket.
pub fn query_terminal_open(bridge_payload: &[u8]) -> Result<(), DesktopIpcError> {
    query_empty_management(TERMINAL_OPEN_REQUEST_ID, bridge_payload)
}

/// Executes one already-encoded terminal-input management intent through the trusted local Agent socket.
pub fn query_terminal_input(bridge_payload: &[u8]) -> Result<(), DesktopIpcError> {
    query_empty_management(TERMINAL_INPUT_REQUEST_ID, bridge_payload)
}

/// Executes one already-encoded terminal-close management intent through the trusted local Agent socket.
pub fn query_terminal_close(bridge_payload: &[u8]) -> Result<(), DesktopIpcError> {
    query_empty_management(TERMINAL_CLOSE_REQUEST_ID, bridge_payload)
}

fn query_empty_management(
    request_id_value: u64,
    bridge_payload: &[u8],
) -> Result<(), DesktopIpcError> {
    let endpoint = endpoint_from_environment()?;
    let request_id = LocalIpcRequestId::new(request_id_value)
        .map_err(|_| DesktopIpcError::RequestIdGenerationFailed)?;
    let request = build_local_management_request_frame(request_id, bridge_payload)
        .map_err(|_| DesktopIpcError::ManagementRequestInvalid)?;
    let frame = query_prebuilt_success_frame(&endpoint, request_id, &request)?;
    validate_empty_management_ack(frame.payload().as_bytes())
}

/// One connection-scoped bounded upload session.
///
/// The Agent retains the active upload transaction on the authenticated local connection, so
/// begin/chunk/finalize/abort must use this same Unix stream for the entire transaction. Dropping
/// the stream before finalization lets the Agent's connection teardown abort any active staging.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct BoundedUploadSession {
    stream: UnixStream,
}

impl BoundedUploadSession {
    pub(crate) fn connect() -> Result<Self, DesktopIpcError> {
        let endpoint = endpoint_from_environment()?;
        let stream = connect_configured_stream(&endpoint)?;
        Ok(Self { stream })
    }

    /// Begins one already-encoded bounded upload and returns the Agent-committed offset.
    pub(crate) fn begin(&mut self, bridge_payload: &[u8]) -> Result<u64, DesktopIpcError> {
        self.query_offset_management(UPLOAD_BEGIN_REQUEST_ID, bridge_payload)
    }

    /// Sends one already-encoded bounded upload chunk and returns the Agent-committed offset.
    pub(crate) fn chunk(&mut self, bridge_payload: &[u8]) -> Result<u64, DesktopIpcError> {
        self.query_offset_management(UPLOAD_CHUNK_REQUEST_ID, bridge_payload)
    }

    /// Finalizes one already-encoded bounded upload.
    pub(crate) fn finalize(&mut self, bridge_payload: &[u8]) -> Result<(), DesktopIpcError> {
        self.query_empty_management(UPLOAD_FINALIZE_REQUEST_ID, bridge_payload)
    }

    /// Best-effort cleanup for one already-encoded failed upload.
    pub(crate) fn abort(&mut self, bridge_payload: &[u8]) -> Result<(), DesktopIpcError> {
        self.query_empty_management(UPLOAD_ABORT_REQUEST_ID, bridge_payload)
    }

    fn query_empty_management(
        &mut self,
        request_id_value: u64,
        bridge_payload: &[u8],
    ) -> Result<(), DesktopIpcError> {
        let frame = self.query_management_success_frame(request_id_value, bridge_payload)?;
        validate_empty_management_ack(frame.payload().as_bytes())
    }

    fn query_offset_management(
        &mut self,
        request_id_value: u64,
        bridge_payload: &[u8],
    ) -> Result<u64, DesktopIpcError> {
        let frame = self.query_management_success_frame(request_id_value, bridge_payload)?;
        validate_offset_management_ack(frame.payload().as_bytes())
    }

    fn query_management_success_frame(
        &mut self,
        request_id_value: u64,
        bridge_payload: &[u8],
    ) -> Result<LocalIpcFrame, DesktopIpcError> {
        let request_id = LocalIpcRequestId::new(request_id_value)
            .map_err(|_| DesktopIpcError::RequestIdGenerationFailed)?;
        let request = build_local_management_request_frame(request_id, bridge_payload)
            .map_err(|_| DesktopIpcError::ManagementRequestInvalid)?;
        query_prebuilt_success_frame_on_stream(&mut self.stream, request_id, &request)
    }
}

fn validate_empty_management_ack(payload: &[u8]) -> Result<(), DesktopIpcError> {
    let body = payload
        .get(MANAGEMENT_STATUS_PREFIX_LENGTH..)
        .ok_or(DesktopIpcError::ResponseInvalid)?;
    if body == [MANAGEMENT_EMPTY_RESULT].as_slice() {
        Ok(())
    } else {
        Err(DesktopIpcError::ResponseInvalid)
    }
}

fn validate_offset_management_ack(payload: &[u8]) -> Result<u64, DesktopIpcError> {
    let body = payload
        .get(MANAGEMENT_STATUS_PREFIX_LENGTH..)
        .ok_or(DesktopIpcError::ResponseInvalid)?;
    if body.len() != 9 || body.first().copied() != Some(MANAGEMENT_OFFSET_RESULT) {
        return Err(DesktopIpcError::ResponseInvalid);
    }
    let mut offset = [0_u8; 8];
    offset.copy_from_slice(&body[1..]);
    Ok(u64::from_be_bytes(offset))
}

fn query_prebuilt_success_frame(
    endpoint: &Path,
    request_id: LocalIpcRequestId,
    request: &LocalIpcFrame,
) -> Result<LocalIpcFrame, DesktopIpcError> {
    let mut stream = connect_configured_stream(endpoint)?;
    query_prebuilt_success_frame_on_stream(&mut stream, request_id, request)
}

fn connect_configured_stream(endpoint: &Path) -> Result<UnixStream, DesktopIpcError> {
    let stream = UnixStream::connect(endpoint).map_err(|_| DesktopIpcError::ConnectFailed)?;
    stream
        .set_read_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| DesktopIpcError::ConfigureFailed)?;
    stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| DesktopIpcError::ConfigureFailed)?;
    Ok(stream)
}

fn query_prebuilt_success_frame_on_stream(
    stream: &mut UnixStream,
    request_id: LocalIpcRequestId,
    request: &LocalIpcFrame,
) -> Result<LocalIpcFrame, DesktopIpcError> {
    write_frame(stream, request).map_err(|_| DesktopIpcError::RequestWriteFailed)?;
    stream
        .flush()
        .map_err(|_| DesktopIpcError::RequestWriteFailed)?;

    let frame = read_frame(stream).map_err(|_| DesktopIpcError::ResponseReadFailed)?;
    let terminal =
        validate_terminal_response_frame(&frame).map_err(|_| DesktopIpcError::ResponseInvalid)?;
    ensure_response_id(request_id, terminal.request_id())?;
    if !terminal.status().is_success() {
        return Err(DesktopIpcError::AgentStatus(terminal.status()));
    }
    Ok(frame)
}

fn runtime_root_from_raw(raw: Option<&OsStr>) -> Result<PathBuf, DesktopIpcError> {
    let raw = raw.ok_or(DesktopIpcError::MissingRuntimeDirectory)?;
    if raw.is_empty() {
        return Err(DesktopIpcError::MissingRuntimeDirectory);
    }

    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(DesktopIpcError::InvalidRuntimeDirectory);
    }
    Ok(path)
}

pub fn endpoint_candidate_from_environment() -> Result<PathBuf, DesktopIpcError> {
    let raw = env::var_os("XDG_RUNTIME_DIR");
    endpoint_candidate_from_raw(raw.as_deref())
}

fn endpoint_candidate_from_raw(raw: Option<&OsStr>) -> Result<PathBuf, DesktopIpcError> {
    let root = runtime_root_from_raw(raw)?;
    Ok(LocalIpcContract::socket_path(&root))
}

fn endpoint_from_environment() -> Result<PathBuf, DesktopIpcError> {
    let raw = env::var_os("XDG_RUNTIME_DIR");
    let root = runtime_root_from_raw(raw.as_deref())?;
    validate_endpoint(&root)
}

fn validate_endpoint(runtime_root: &Path) -> Result<PathBuf, DesktopIpcError> {
    let expected_owner = geteuid().as_raw();
    let root_metadata =
        fs::symlink_metadata(runtime_root).map_err(|_| DesktopIpcError::RuntimeRootUnavailable)?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.uid() != expected_owner
        || mode_bits(&root_metadata) != AGENT_RUNTIME_DIRECTORY_MODE
    {
        return Err(DesktopIpcError::RuntimeRootUntrusted);
    }

    let socket_path = LocalIpcContract::socket_path(runtime_root);
    let runtime_directory = socket_path
        .parent()
        .ok_or(DesktopIpcError::PrwRuntimeDirectoryUntrusted)?;
    let runtime_metadata = fs::symlink_metadata(runtime_directory)
        .map_err(|_| DesktopIpcError::PrwRuntimeDirectoryUnavailable)?;
    if !runtime_metadata.file_type().is_dir()
        || runtime_metadata.uid() != expected_owner
        || mode_bits(&runtime_metadata) != AGENT_RUNTIME_DIRECTORY_MODE
    {
        return Err(DesktopIpcError::PrwRuntimeDirectoryUntrusted);
    }

    let socket_metadata =
        fs::symlink_metadata(&socket_path).map_err(|_| DesktopIpcError::AgentSocketUnavailable)?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != expected_owner
        || mode_bits(&socket_metadata) != AGENT_SOCKET_MODE
    {
        return Err(DesktopIpcError::AgentSocketUntrusted);
    }

    Ok(socket_path)
}

fn mode_bits(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

fn query_status(
    endpoint: &Path,
    request_id: LocalIpcRequestId,
) -> Result<LocalAgentStatusSnapshot, DesktopIpcError> {
    let frame = query_success_frame(endpoint, request_id, LocalAgentCommand::GetAgentStatus)?;
    let decoded =
        decode_success_status_frame(&frame).map_err(|_| DesktopIpcError::ResponseInvalid)?;
    ensure_response_id(request_id, decoded.request_id())?;
    Ok(decoded.snapshot())
}

fn query_private_dns(
    endpoint: &Path,
    request_id: LocalIpcRequestId,
) -> Result<LocalPrivateDnsSnapshot, DesktopIpcError> {
    let frame = query_success_frame(endpoint, request_id, LocalAgentCommand::GetPrivateDnsConfig)?;
    let decoded =
        decode_success_private_dns_frame(&frame).map_err(|_| DesktopIpcError::ResponseInvalid)?;
    ensure_response_id(request_id, decoded.request_id())?;
    Ok(decoded.snapshot().clone())
}

fn query_success_frame(
    endpoint: &Path,
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
) -> Result<LocalIpcFrame, DesktopIpcError> {
    let mut stream = UnixStream::connect(endpoint).map_err(|_| DesktopIpcError::ConnectFailed)?;
    stream
        .set_read_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| DesktopIpcError::ConfigureFailed)?;
    stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| DesktopIpcError::ConfigureFailed)?;

    write_local_command_request(&mut stream, request_id, command)
        .map_err(|_| DesktopIpcError::RequestWriteFailed)?;
    stream
        .flush()
        .map_err(|_| DesktopIpcError::RequestWriteFailed)?;

    let frame = read_frame(&mut stream).map_err(|_| DesktopIpcError::ResponseReadFailed)?;
    let terminal =
        validate_terminal_response_frame(&frame).map_err(|_| DesktopIpcError::ResponseInvalid)?;
    ensure_response_id(request_id, terminal.request_id())?;
    if !terminal.status().is_success() {
        return Err(DesktopIpcError::AgentStatus(terminal.status()));
    }

    Ok(frame)
}

fn ensure_response_id(
    expected: LocalIpcRequestId,
    actual: LocalIpcRequestId,
) -> Result<(), DesktopIpcError> {
    if expected == actual {
        Ok(())
    } else {
        Err(DesktopIpcError::RequestIdMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use super::{
        DesktopIpcError, StatusProbe, endpoint_candidate_from_raw, ensure_response_id,
        runtime_root_from_raw, validate_empty_management_ack, validate_offset_management_ack,
    };
    use crate::state::{AgentAvailability, AgentRuntimePresentation};
    use prw_agent::local_commands::{
        LocalAgentResponseStatus,
        status_snapshot::{LocalAgentRuntimeState, LocalAgentStatusSnapshot},
    };
    use prw_agent::{LocalIpcContract, LocalIpcRequestId};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("test IDs are non-zero")
    }

    #[test]
    fn missing_and_empty_runtime_roots_are_rejected() {
        assert_eq!(
            runtime_root_from_raw(None),
            Err(DesktopIpcError::MissingRuntimeDirectory)
        );
        assert_eq!(
            runtime_root_from_raw(Some(OsStr::new(""))),
            Err(DesktopIpcError::MissingRuntimeDirectory)
        );
    }

    #[test]
    fn relative_runtime_root_is_rejected_before_socket_use() {
        assert_eq!(
            runtime_root_from_raw(Some(OsStr::new("run/user/1000"))),
            Err(DesktopIpcError::InvalidRuntimeDirectory)
        );
    }

    #[test]
    fn endpoint_candidate_uses_authoritative_socket_derivation() {
        assert_eq!(
            endpoint_candidate_from_raw(Some(OsStr::new("/run/user/1000"))),
            Ok(Path::new("/run/user/1000/private-remote-workspace/agent.sock").to_path_buf())
        );
        assert_eq!(
            endpoint_candidate_from_raw(Some(OsStr::new("run/user/1000"))),
            Err(DesktopIpcError::InvalidRuntimeDirectory)
        );
    }

    #[test]
    fn absolute_runtime_root_uses_the_authoritative_socket_derivation() {
        let root = runtime_root_from_raw(Some(OsStr::new("/run/user/1000")))
            .expect("absolute root is admitted as a candidate");
        assert_eq!(
            LocalIpcContract::socket_path(&root),
            Path::new("/run/user/1000/private-remote-workspace/agent.sock")
        );
    }

    #[test]
    fn response_request_id_mismatch_fails_closed() {
        assert_eq!(ensure_response_id(id(7), id(7)), Ok(()));
        assert_eq!(
            ensure_response_id(id(7), id(8)),
            Err(DesktopIpcError::RequestIdMismatch)
        );
    }

    #[test]
    fn management_offset_ack_requires_exact_tag_and_width() {
        assert_eq!(
            validate_offset_management_ack(&[0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3]),
            Ok(3)
        );
        for invalid in [
            &[0, 0, 4][..],
            &[0, 0, 5, 0, 0, 0, 0, 0, 0, 0][..],
            &[0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0][..],
            &[0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 3][..],
        ] {
            assert_eq!(
                validate_offset_management_ack(invalid),
                Err(DesktopIpcError::ResponseInvalid)
            );
        }
    }

    #[test]
    fn private_dns_failure_is_visible_without_downgrading_agent_status() {
        let state = StatusProbe {
            status: Ok(LocalAgentStatusSnapshot::current(
                LocalAgentRuntimeState::Ready,
            )),
            private_dns: Err(DesktopIpcError::ResponseInvalid),
        }
        .into_presentation();

        assert_eq!(state.availability, AgentAvailability::Online);
        assert_eq!(state.runtime, Some(AgentRuntimePresentation::Ready));
        assert!(state.private_dns.is_none());
        assert!(state.detail.starts_with("Local IPC protocol "));
        assert!(state.detail.ends_with(
            "Private DNS status unavailable: Ownspace Agent response failed protocol validation."
        ));
    }

    #[test]
    fn shared_endpoint_failure_is_not_duplicated_in_presentation_detail() {
        let state = StatusProbe {
            status: Err(DesktopIpcError::ConnectFailed),
            private_dns: Err(DesktopIpcError::ConnectFailed),
        }
        .into_presentation();

        assert_eq!(state.availability, AgentAvailability::Offline);
        assert_eq!(state.detail, "Ownspace Agent connection failed");
        assert!(state.private_dns.is_none());
    }

    #[test]
    fn secondary_private_dns_failure_does_not_mask_primary_status_failure() {
        let state = StatusProbe {
            status: Err(DesktopIpcError::ConnectFailed),
            private_dns: Err(DesktopIpcError::ResponseInvalid),
        }
        .into_presentation();

        assert_eq!(state.availability, AgentAvailability::Offline);
        assert_eq!(state.detail, "Ownspace Agent connection failed");
        assert!(state.private_dns.is_none());
    }

    fn assert_error_contract(
        error: DesktopIpcError,
        availability: AgentAvailability,
        message: &str,
    ) {
        assert_eq!(error.availability(), availability, "{error:?}");
        assert_eq!(error.to_string(), message, "{error:?}");
    }

    #[test]
    fn offline_ipc_errors_have_stable_presentation_contract() {
        for (error, message) in [
            (
                DesktopIpcError::MissingRuntimeDirectory,
                "XDG_RUNTIME_DIR is unavailable",
            ),
            (
                DesktopIpcError::InvalidRuntimeDirectory,
                "XDG_RUNTIME_DIR is not an absolute path",
            ),
            (
                DesktopIpcError::RuntimeRootUnavailable,
                "XDG runtime root is unavailable",
            ),
            (
                DesktopIpcError::PrwRuntimeDirectoryUnavailable,
                "Ownspace runtime directory is unavailable",
            ),
            (
                DesktopIpcError::AgentSocketUnavailable,
                "Ownspace Agent socket is unavailable",
            ),
            (
                DesktopIpcError::ConnectFailed,
                "Ownspace Agent connection failed",
            ),
        ] {
            assert_error_contract(error, AgentAvailability::Offline, message);
        }
    }

    #[test]
    fn trust_protocol_and_io_errors_have_stable_presentation_contract() {
        for (error, message) in [
            (
                DesktopIpcError::RuntimeRootUntrusted,
                "XDG runtime root failed local trust checks",
            ),
            (
                DesktopIpcError::PrwRuntimeDirectoryUntrusted,
                "Ownspace runtime directory failed local trust checks",
            ),
            (
                DesktopIpcError::AgentSocketUntrusted,
                "Ownspace Agent socket failed local trust checks",
            ),
            (
                DesktopIpcError::ConfigureFailed,
                "Ownspace Agent connection timeout configuration failed",
            ),
            (
                DesktopIpcError::RequestIdGenerationFailed,
                "Ownspace request identifier generation failed",
            ),
            (
                DesktopIpcError::RequestWriteFailed,
                "Ownspace Agent request write failed",
            ),
            (
                DesktopIpcError::ResponseReadFailed,
                "Ownspace Agent response read failed",
            ),
            (
                DesktopIpcError::ResponseInvalid,
                "Ownspace Agent response failed protocol validation",
            ),
            (
                DesktopIpcError::RequestIdMismatch,
                "Ownspace Agent response correlation failed",
            ),
        ] {
            assert_error_contract(error, AgentAvailability::Error, message);
        }
    }

    #[test]
    fn agent_response_status_errors_have_stable_presentation_contract() {
        for (status, message) in [
            (
                LocalAgentResponseStatus::InvalidRequest,
                "Ownspace Agent rejected the request as invalid",
            ),
            (
                LocalAgentResponseStatus::Unauthorized,
                "Ownspace Agent rejected the request as unauthorized",
            ),
            (
                LocalAgentResponseStatus::UnsupportedCommand,
                "Ownspace Agent does not support the requested command",
            ),
            (
                LocalAgentResponseStatus::Conflict,
                "Ownspace Agent reported a state conflict",
            ),
            (
                LocalAgentResponseStatus::InternalError,
                "Ownspace Agent reported an internal error",
            ),
            (
                LocalAgentResponseStatus::Ok,
                "Ownspace Agent returned an unexpected success-status error",
            ),
        ] {
            assert_error_contract(
                DesktopIpcError::AgentStatus(status),
                AgentAvailability::Error,
                message,
            );
        }
    }

    #[test]
    fn invalid_management_request_has_stable_error_contract() {
        assert_error_contract(
            DesktopIpcError::ManagementRequestInvalid,
            AgentAvailability::Error,
            "Ownspace management request is invalid",
        );
    }

    #[test]
    fn terminal_management_ack_accepts_only_exact_empty_result() {
        assert_eq!(validate_empty_management_ack(&[0, 0, 4]), Ok(()));
        assert_eq!(
            validate_empty_management_ack(&[0, 0]),
            Err(DesktopIpcError::ResponseInvalid)
        );
        assert_eq!(
            validate_empty_management_ack(&[0, 0, 6]),
            Err(DesktopIpcError::ResponseInvalid)
        );
        assert_eq!(
            validate_empty_management_ack(&[0, 0, 4, 0]),
            Err(DesktopIpcError::ResponseInvalid)
        );
    }
}
