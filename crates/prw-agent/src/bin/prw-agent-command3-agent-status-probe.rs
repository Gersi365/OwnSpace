//! Bounded one-shot same-UID command-3 `AgentStatus` production probe.
//!
//! This executable is intentionally narrow:
//! - it derives the Agent endpoint only through `LocalIpcContract`;
//! - it validates current-UID ownership and locked runtime/socket modes;
//! - it constructs only `BridgeCommand::AgentStatus`;
//! - it wraps that canonical PRWC payload only through the Agent-owned command-3 builder;
//! - it performs exactly one request/response exchange per process invocation;
//! - it requires exact request-ID correlation, terminal `Ok`, result tag 1, and a
//!   Ready/current-protocol Agent status snapshot.
//!
//! Source materialization and compilation do not execute this probe.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use prw_agent::frame_object::LocalIpcFrame;
use prw_agent::frame_object::reader::read_frame;
use prw_agent::frame_object::writer::write_frame;
use prw_agent::local_commands::LocalAgentResponseStatus;
use prw_agent::local_commands::management_request::build_local_management_request_frame;
use prw_agent::local_commands::response_codec::decode_response_status_prefix;
use prw_agent::local_commands::status_snapshot::codec::decode_status_snapshot;
use prw_agent::local_commands::status_snapshot::{
    LocalAgentRuntimeState, LocalAgentStatusSnapshot,
};
use prw_agent::local_commands::terminal_response::validate_terminal_response_frame;
use prw_agent::{LocalIpcContract, LocalIpcRequestId};
use prw_remote_bridge::BridgeCommand;
use rustix::process::geteuid;

const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const WO_REQUEST_ID_VALUE: u64 = 0x574f_0000_0000_0001;
const MANAGEMENT_AGENT_STATUS_RESULT_TAG: u8 = 1;

fn main() -> ExitCode {
    match run_probe() {
        Ok(snapshot) => {
            let version = snapshot.protocol_version();
            println!(
                "prw-agent-command3-agent-status-probe status=ready request_id={} protocol={}.{}",
                WO_REQUEST_ID_VALUE,
                version.major(),
                version.minor()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("prw-agent-command3-agent-status-probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_probe() -> Result<LocalAgentStatusSnapshot, ProbeError> {
    let endpoint = endpoint_from_environment()?;
    let request_id =
        LocalIpcRequestId::new(WO_REQUEST_ID_VALUE).map_err(|_| ProbeError::RequestId)?;
    let bridge_payload = BridgeCommand::AgentStatus
        .encode()
        .map_err(|_| ProbeError::BridgeEncode)?;
    let request = build_local_management_request_frame(request_id, &bridge_payload)
        .map_err(|_| ProbeError::RequestBuild)?;

    let mut stream = UnixStream::connect(&endpoint).map_err(|_| ProbeError::Connect)?;
    stream
        .set_read_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| ProbeError::Configure)?;
    stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| ProbeError::Configure)?;

    let revalidated = endpoint_from_environment()?;
    if revalidated != endpoint {
        return Err(ProbeError::EndpointChanged);
    }

    write_frame(&mut stream, &request).map_err(|_| ProbeError::RequestWrite)?;
    stream.flush().map_err(|_| ProbeError::RequestFlush)?;

    let response = read_frame(&mut stream).map_err(|_| ProbeError::ResponseRead)?;
    validate_agent_status_response(&response, request_id)
}

fn endpoint_from_environment() -> Result<PathBuf, ProbeError> {
    let raw = env::var_os("XDG_RUNTIME_DIR");
    let root = runtime_root_from_raw(raw.as_deref())?;
    validate_endpoint(&root)
}

fn runtime_root_from_raw(raw: Option<&OsStr>) -> Result<PathBuf, ProbeError> {
    let raw = raw.ok_or(ProbeError::MissingRuntimeDirectory)?;
    if raw.is_empty() {
        return Err(ProbeError::InvalidRuntimeDirectory);
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(ProbeError::InvalidRuntimeDirectory);
    }
    Ok(path)
}

fn validate_endpoint(runtime_root: &Path) -> Result<PathBuf, ProbeError> {
    let expected_owner = geteuid().as_raw();
    let contract = LocalIpcContract::baseline();

    let root_metadata =
        fs::symlink_metadata(runtime_root).map_err(|_| ProbeError::RuntimeRootUnavailable)?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.uid() != expected_owner
        || mode_bits(&root_metadata) != contract.runtime_directory_mode
    {
        return Err(ProbeError::RuntimeRootUntrusted);
    }

    let socket_path = LocalIpcContract::socket_path(runtime_root);
    let runtime_directory = socket_path
        .parent()
        .ok_or(ProbeError::PrwRuntimeDirectoryUntrusted)?;
    let runtime_metadata = fs::symlink_metadata(runtime_directory)
        .map_err(|_| ProbeError::PrwRuntimeDirectoryUnavailable)?;
    if !runtime_metadata.file_type().is_dir()
        || runtime_metadata.uid() != expected_owner
        || mode_bits(&runtime_metadata) != contract.runtime_directory_mode
    {
        return Err(ProbeError::PrwRuntimeDirectoryUntrusted);
    }

    let socket_metadata =
        fs::symlink_metadata(&socket_path).map_err(|_| ProbeError::AgentSocketUnavailable)?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != expected_owner
        || mode_bits(&socket_metadata) != contract.socket_mode
    {
        return Err(ProbeError::AgentSocketUntrusted);
    }

    Ok(socket_path)
}

fn mode_bits(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

fn validate_agent_status_response(
    frame: &LocalIpcFrame,
    expected_request_id: LocalIpcRequestId,
) -> Result<LocalAgentStatusSnapshot, ProbeError> {
    let terminal =
        validate_terminal_response_frame(frame).map_err(|_| ProbeError::ResponseInvalid)?;
    if terminal.request_id() != expected_request_id {
        return Err(ProbeError::RequestIdMismatch);
    }
    if terminal.status() != LocalAgentResponseStatus::Ok {
        return Err(ProbeError::AgentRejected(terminal.status()));
    }

    let (status, body) = decode_response_status_prefix(frame.payload().as_bytes())
        .map_err(|_| ProbeError::ResponseInvalid)?;
    if status != LocalAgentResponseStatus::Ok {
        return Err(ProbeError::ResponseInvalid);
    }

    let Some((&tag, status_body)) = body.split_first() else {
        return Err(ProbeError::ResponseBodyInvalid);
    };
    if tag != MANAGEMENT_AGENT_STATUS_RESULT_TAG {
        return Err(ProbeError::ResponseBodyInvalid);
    }

    let snapshot =
        decode_status_snapshot(status_body).map_err(|_| ProbeError::ResponseBodyInvalid)?;
    if !snapshot.runtime_state().is_ready() {
        return Err(ProbeError::AgentNotReady(snapshot.runtime_state()));
    }

    Ok(snapshot)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeError {
    MissingRuntimeDirectory,
    InvalidRuntimeDirectory,
    RuntimeRootUnavailable,
    RuntimeRootUntrusted,
    PrwRuntimeDirectoryUnavailable,
    PrwRuntimeDirectoryUntrusted,
    AgentSocketUnavailable,
    AgentSocketUntrusted,
    RequestId,
    BridgeEncode,
    RequestBuild,
    Connect,
    Configure,
    EndpointChanged,
    RequestWrite,
    RequestFlush,
    ResponseRead,
    ResponseInvalid,
    RequestIdMismatch,
    AgentRejected(LocalAgentResponseStatus),
    ResponseBodyInvalid,
    AgentNotReady(LocalAgentRuntimeState),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRuntimeDirectory => formatter.write_str("XDG_RUNTIME_DIR is unavailable"),
            Self::InvalidRuntimeDirectory => {
                formatter.write_str("XDG_RUNTIME_DIR is empty or not absolute")
            }
            Self::RuntimeRootUnavailable => formatter.write_str("runtime root is unavailable"),
            Self::RuntimeRootUntrusted => formatter.write_str("runtime root is untrusted"),
            Self::PrwRuntimeDirectoryUnavailable => {
                formatter.write_str("PRW runtime directory is unavailable")
            }
            Self::PrwRuntimeDirectoryUntrusted => {
                formatter.write_str("PRW runtime directory is untrusted")
            }
            Self::AgentSocketUnavailable => formatter.write_str("Agent socket is unavailable"),
            Self::AgentSocketUntrusted => formatter.write_str("Agent socket is untrusted"),
            Self::RequestId => formatter.write_str("fixed request ID is invalid"),
            Self::BridgeEncode => formatter.write_str("canonical AgentStatus encoding failed"),
            Self::RequestBuild => formatter.write_str("Agent command-3 request build failed"),
            Self::Connect => formatter.write_str("Agent socket connection failed"),
            Self::Configure => formatter.write_str("socket timeout configuration failed"),
            Self::EndpointChanged => {
                formatter.write_str("Agent endpoint changed during pre-write validation")
            }
            Self::RequestWrite => formatter.write_str("command-3 request write failed"),
            Self::RequestFlush => formatter.write_str("command-3 request flush failed"),
            Self::ResponseRead => formatter.write_str("command-3 response read failed"),
            Self::ResponseInvalid => formatter.write_str("terminal response validation failed"),
            Self::RequestIdMismatch => formatter.write_str("response request ID mismatch"),
            Self::AgentRejected(status) => {
                write!(
                    formatter,
                    "Agent rejected command-3 request with status {}",
                    status.code()
                )
            }
            Self::ResponseBodyInvalid => {
                formatter.write_str("AgentStatus management response body is invalid")
            }
            Self::AgentNotReady(state) => {
                write!(
                    formatter,
                    "AgentStatus reported non-ready state {}",
                    state.code()
                )
            }
        }
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests {
    use prw_agent::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use prw_agent::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    use super::{
        MANAGEMENT_AGENT_STATUS_RESULT_TAG, ProbeError, WO_REQUEST_ID_VALUE,
        validate_agent_status_response,
    };
    use prw_agent::local_commands::management_request::build_local_management_request_frame;
    use prw_remote_bridge::BridgeCommand;

    fn request_id() -> LocalIpcRequestId {
        LocalIpcRequestId::new(WO_REQUEST_ID_VALUE).expect("WO request ID is non-zero")
    }

    fn response_frame(request_id: LocalIpcRequestId, payload_bytes: &[u8]) -> LocalIpcFrame {
        let payload =
            LocalIpcPayload::new(payload_bytes.to_vec()).expect("bounded response payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Response,
            request_id,
            payload.len(),
        )
        .expect("valid response header");
        LocalIpcFrame::new(header, payload).expect("header and payload agree")
    }

    #[test]
    fn request_is_exact_canonical_agent_status_command3_frame() {
        let bridge_payload = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus canonical encoding");
        assert_eq!(
            bridge_payload,
            hex_literal_agent_status_prwc(),
            "inner PRWC bytes remain exact"
        );

        let request = build_local_management_request_frame(request_id(), &bridge_payload)
            .expect("command-3 request builds");
        assert_eq!(request.header().request_id(), request_id());
        assert_eq!(request.header().kind(), LocalIpcMessageKind::Request);
        assert_eq!(request.header().frame_length(), 42);
        assert_eq!(
            request.payload().as_bytes(),
            &[
                0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x50, 0x52, 0x57, 0x43, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn exact_ok_tag1_ready_response_is_accepted() {
        let frame = response_frame(
            request_id(),
            &[
                0x00,
                0x00,
                MANAGEMENT_AGENT_STATUS_RESULT_TAG,
                0x02,
                0x00,
                0x01,
                0x00,
                0x00,
            ],
        );
        let snapshot =
            validate_agent_status_response(&frame, request_id()).expect("response validates");
        assert!(snapshot.runtime_state().is_ready());
        assert_eq!(
            snapshot.protocol_version(),
            LocalIpcProtocolVersion::current()
        );
    }

    #[test]
    fn wrong_result_tag_fails_closed() {
        let frame = response_frame(
            request_id(),
            &[0x00, 0x00, 0x02, 0x02, 0x00, 0x01, 0x00, 0x00],
        );
        assert_eq!(
            validate_agent_status_response(&frame, request_id()),
            Err(ProbeError::ResponseBodyInvalid)
        );
    }

    #[test]
    fn non_ready_status_fails_closed() {
        let frame = response_frame(
            request_id(),
            &[
                0x00,
                0x00,
                MANAGEMENT_AGENT_STATUS_RESULT_TAG,
                0x03,
                0x00,
                0x01,
                0x00,
                0x00,
            ],
        );
        assert_eq!(
            validate_agent_status_response(&frame, request_id()),
            Err(ProbeError::AgentNotReady(
                prw_agent::local_commands::status_snapshot::LocalAgentRuntimeState::Degraded
            ))
        );
    }

    #[test]
    fn mismatched_request_id_fails_closed() {
        let frame = response_frame(
            LocalIpcRequestId::new(WO_REQUEST_ID_VALUE + 1).expect("different request ID"),
            &[
                0x00,
                0x00,
                MANAGEMENT_AGENT_STATUS_RESULT_TAG,
                0x02,
                0x00,
                0x01,
                0x00,
                0x00,
            ],
        );
        assert_eq!(
            validate_agent_status_response(&frame, request_id()),
            Err(ProbeError::RequestIdMismatch)
        );
    }

    fn hex_literal_agent_status_prwc() -> Vec<u8> {
        vec![
            0x50, 0x52, 0x57, 0x43, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ]
    }
}
