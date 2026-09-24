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

use crate::state::{AgentAvailability, DesktopPresentationState};

const IPC_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct StartupProbe {
    pub(crate) status: Result<LocalAgentStatusSnapshot, DesktopIpcError>,
    pub(crate) private_dns: Result<LocalPrivateDnsSnapshot, DesktopIpcError>,
}

impl StartupProbe {
    pub(crate) fn into_presentation(self) -> DesktopPresentationState {
        let mut state = DesktopPresentationState::connecting();

        match self.status {
            Ok(snapshot) => {
                state = state.with_status(snapshot);
            }
            Err(error) => {
                state = state.with_error(error.availability(), error.to_string());
            }
        }

        if let Ok(snapshot) = self.private_dns {
            state = state.with_private_dns(&snapshot);
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
            | Self::AgentStatus(_) => AgentAvailability::Error,
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
            Self::PrwRuntimeDirectoryUnavailable => "PRW runtime directory is unavailable",
            Self::PrwRuntimeDirectoryUntrusted => "PRW runtime directory failed local trust checks",
            Self::AgentSocketUnavailable => "PRW Agent socket is unavailable",
            Self::AgentSocketUntrusted => "PRW Agent socket failed local trust checks",
            Self::ConnectFailed => "PRW Agent connection failed",
            Self::ConfigureFailed => "PRW Agent connection timeout configuration failed",
            Self::RequestIdGenerationFailed => "PRW request identifier generation failed",
            Self::RequestWriteFailed => "PRW Agent request write failed",
            Self::ResponseReadFailed => "PRW Agent response read failed",
            Self::ResponseInvalid => "PRW Agent response failed protocol validation",
            Self::RequestIdMismatch => "PRW Agent response correlation failed",
            Self::AgentStatus(LocalAgentResponseStatus::InvalidRequest) => {
                "PRW Agent rejected the request as invalid"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Unauthorized) => {
                "PRW Agent rejected the request as unauthorized"
            }
            Self::AgentStatus(LocalAgentResponseStatus::UnsupportedCommand) => {
                "PRW Agent does not support the requested command"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Conflict) => {
                "PRW Agent reported a state conflict"
            }
            Self::AgentStatus(LocalAgentResponseStatus::InternalError) => {
                "PRW Agent reported an internal error"
            }
            Self::AgentStatus(LocalAgentResponseStatus::Ok) => {
                "PRW Agent returned an unexpected success-status error"
            }
            Self::AgentStatus(_) => "PRW Agent returned an unknown response status",
        };
        formatter.write_str(message)
    }
}

pub fn query_startup() -> StartupProbe {
    let endpoint = endpoint_from_environment();
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return StartupProbe {
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

    StartupProbe {
        status,
        private_dns,
    }
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

    use super::{DesktopIpcError, ensure_response_id, runtime_root_from_raw};
    use crate::state::AgentAvailability;
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
    fn bounded_errors_map_to_offline_or_error_presentation() {
        assert_eq!(
            DesktopIpcError::AgentSocketUnavailable.availability(),
            AgentAvailability::Offline
        );
        assert_eq!(
            DesktopIpcError::AgentSocketUntrusted.availability(),
            AgentAvailability::Error
        );
        assert_eq!(
            DesktopIpcError::RequestIdMismatch.to_string(),
            "PRW Agent response correlation failed"
        );
    }
}
