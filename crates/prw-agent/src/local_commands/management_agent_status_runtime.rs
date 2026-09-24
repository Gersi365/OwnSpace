//! Narrow command-3 AgentStatus-only runtime adapter.
//!
//! This module intentionally omits filesystem authority, provider lifecycle and
//! terminal/forwarding backends. The management policy is fixed inside the adapter:
//! `AgentStatusRead` is allowed and every other represented capability is denied.
//! Callers cannot widen that policy through runtime assembly.

#![cfg(target_os = "linux")]

use prw_policy::{BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, Decision};
use prw_remote_bridge::BridgeCommand;

use super::LocalAgentResponseStatus;
use super::management_request::{
    LocalManagementAdmissionError, admit_authenticated_linux_management_request,
};
use super::management_response::build_management_provider_response;
use super::management_typed_provider_dispatch::LocalManagementTypedProviderResult;
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
use crate::frame_object::LocalIpcFrame;
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

const fn agent_status_only_policy() -> BoundedLocalManagementPolicy {
    BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
        agent_status: Decision::Allow,
        private_dns: Decision::Deny,
        terminal_open: Decision::Deny,
        terminal_exec: Decision::Deny,
        files_read: Decision::Deny,
        files_write: Decision::Deny,
        forwarding_create: Decision::Deny,
    })
}

/// Processes one canonical command-3 request through the fixed AgentStatus-only slice.
///
/// The caller supplies no management policy, filesystem authority or provider lifecycle.
/// Canonical admission still binds the request to the authenticated same-UID Linux peer.
/// Any represented command other than `AgentStatus` fails closed before a success response.
///
/// # Errors
///
/// Returns only failures from the existing terminal-response frame builder.
pub(super) fn process_authenticated_linux_agent_status_management<S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    agent_status: LocalAgentStatusSnapshot,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    let request_id = frame.header().request_id();
    let policy = agent_status_only_policy();
    let admission = match admit_authenticated_linux_management_request(frame, connection, &policy) {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_error_status(error), &[]);
        }
    };

    if !matches!(admission.command(), BridgeCommand::AgentStatus) {
        return build_terminal_response_frame(
            request_id,
            LocalAgentResponseStatus::UnsupportedCommand,
            &[],
        );
    }

    build_management_provider_response(
        request_id,
        Ok(LocalManagementTypedProviderResult::AgentStatus(
            agent_status,
        )),
    )
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
    use std::os::unix::net::UnixStream;

    use prw_policy::{Capability, Decision, PolicyEvaluator};
    use prw_remote_bridge::BridgeCommand;

    use super::{agent_status_only_policy, process_authenticated_linux_agent_status_management};
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

    #[test]
    fn fixed_policy_allows_only_agent_status() {
        let policy = agent_status_only_policy();
        assert_eq!(
            policy.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        for capability in [
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
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

        let response =
            process_authenticated_linux_agent_status_management(&frame, &connection, snapshot)
                .expect("AgentStatus response builds");
        let terminal =
            validate_terminal_response_frame(&response).expect("terminal response validates");

        assert_eq!(terminal.request_id(), id(901));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        assert_eq!(response.payload().as_bytes().get(2), Some(&1));
    }
}
