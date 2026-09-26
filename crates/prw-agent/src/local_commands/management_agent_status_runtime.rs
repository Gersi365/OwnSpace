//! Narrow command-3 `AgentStatus` + read-only `FileList` runtime adapter.
//!
//! This module intentionally omits mutable provider lifecycle and terminal/forwarding
//! backends. The management policy is fixed inside the adapter: `AgentStatusRead` and
//! `FilesRead` are admitted, then an explicit command gate permits only `AgentStatus`
//! and `FileList`. `FileStat` and `DownloadChunk` therefore remain unsupported even
//! though they share `FilesRead`. The `FileList` authority is anchored to the Agent
//! user-service `$HOME`, never to `/` or a request-supplied host path.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::path::PathBuf;

use prw_file_service::FileServiceError;
use prw_policy::{BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, Decision};
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
    })
}

/// Processes one canonical command-3 request through the fixed `AgentStatus` + `FileList` slice.
///
/// The caller supplies no management policy or mutable provider lifecycle. Canonical
/// admission still binds the request to the authenticated same-UID Linux peer.
/// `FileList` is descriptor-anchored to the Agent user-service `$HOME`; the requested
/// path remains a canonical relative `RemotePath`. Every other command fails closed.
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

fn home_filesystem_authority() -> Result<LocalManagementFilesystemAuthority, FileServiceError> {
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

    use prw_file_service::RemotePath;
    use prw_policy::{Capability, Decision, PolicyEvaluator};
    use prw_remote_bridge::BridgeCommand;

    use super::{
        agent_status_file_list_policy, open_home_filesystem_authority_from_raw,
        process_authenticated_linux_agent_status_file_list_management,
        process_authenticated_linux_agent_status_file_list_management_with_filesystem_factory,
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

    #[test]
    fn fixed_policy_allows_agent_status_and_files_read_only() {
        let policy = agent_status_file_list_policy();
        assert_eq!(
            policy.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        assert_eq!(policy.evaluate(Capability::FilesRead), Decision::Allow);
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
