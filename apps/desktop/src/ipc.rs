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

    use super::{DesktopIpcError, StartupProbe, ensure_response_id, runtime_root_from_raw};
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
    fn private_dns_failure_is_visible_without_downgrading_agent_status() {
        let state = StartupProbe {
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
        let state = StartupProbe {
            status: Err(DesktopIpcError::ConnectFailed),
            private_dns: Err(DesktopIpcError::ConnectFailed),
        }
        .into_presentation();

        assert_eq!(state.availability, AgentAvailability::Offline);
        assert_eq!(state.detail, "Ownspace Agent connection failed");
        assert!(state.private_dns.is_none());
    }

    #[test]
    fn ipc_errors_have_stable_availability_and_user_facing_messages() {
        for (error, availability, message) in [
            (
                DesktopIpcError::MissingRuntimeDirectory,
                AgentAvailability::Offline,
                "XDG_RUNTIME_DIR is unavailable",
            ),
            (
                DesktopIpcError::InvalidRuntimeDirectory,
                AgentAvailability::Offline,
                "XDG_RUNTIME_DIR is not an absolute path",
            ),
            (
                DesktopIpcError::RuntimeRootUnavailable,
                AgentAvailability::Offline,
                "XDG runtime root is unavailable",
            ),
            (
                DesktopIpcError::RuntimeRootUntrusted,
                AgentAvailability::Error,
                "XDG runtime root failed local trust checks",
            ),
            (
                DesktopIpcError::PrwRuntimeDirectoryUnavailable,
                AgentAvailability::Offline,
                "Ownspace runtime directory is unavailable",
            ),
            (
                DesktopIpcError::PrwRuntimeDirectoryUntrusted,
                AgentAvailability::Error,
                "Ownspace runtime directory failed local trust checks",
            ),
            (
                DesktopIpcError::AgentSocketUnavailable,
                AgentAvailability::Offline,
                "Ownspace Agent socket is unavailable",
            ),
            (
                DesktopIpcError::AgentSocketUntrusted,
                AgentAvailability::Error,
                "Ownspace Agent socket failed local trust checks",
            ),
            (
                DesktopIpcError::ConnectFailed,
                AgentAvailability::Offline,
                "Ownspace Agent connection failed",
            ),
            (
                DesktopIpcError::ConfigureFailed,
                AgentAvailability::Error,
                "Ownspace Agent connection timeout configuration failed",
            ),
            (
                DesktopIpcError::RequestIdGenerationFailed,
                AgentAvailability::Error,
                "Ownspace request identifier generation failed",
            ),
            (
                DesktopIpcError::RequestWriteFailed,
                AgentAvailability::Error,
                "Ownspace Agent request write failed",
            ),
            (
                DesktopIpcError::ResponseReadFailed,
                AgentAvailability::Error,
                "Ownspace Agent response read failed",
            ),
            (
                DesktopIpcError::ResponseInvalid,
                AgentAvailability::Error,
                "Ownspace Agent response failed protocol validation",
            ),
            (
                DesktopIpcError::RequestIdMismatch,
                AgentAvailability::Error,
                "Ownspace Agent response correlation failed",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::InvalidRequest),
                AgentAvailability::Error,
                "Ownspace Agent rejected the request as invalid",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::Unauthorized),
                AgentAvailability::Error,
                "Ownspace Agent rejected the request as unauthorized",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::UnsupportedCommand),
                AgentAvailability::Error,
                "Ownspace Agent does not support the requested command",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::Conflict),
                AgentAvailability::Error,
                "Ownspace Agent reported a state conflict",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::InternalError),
                AgentAvailability::Error,
                "Ownspace Agent reported an internal error",
            ),
            (
                DesktopIpcError::AgentStatus(LocalAgentResponseStatus::Ok),
                AgentAvailability::Error,
                "Ownspace Agent returned an unexpected success-status error",
            ),
        ] {
            assert_eq!(error.availability(), availability, "{error:?}");
            assert_eq!(error.to_string(), message, "{error:?}");
        }
    }
}
