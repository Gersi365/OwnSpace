//! Shared local boundary for legacy commands 1/2 plus fixed command-3 `AgentStatus`.
//!
//! Generic framing is acquired before command classification. Legacy commands retain
//! their existing decoder/policy/responder path. Code 3 is delegated only to the
//! fixed AgentStatus-only runtime adapter, which owns no mutable provider authority.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};

use prw_policy::PolicyEvaluator;

use super::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use super::inbound_state::LocalInboundRequestState;
use super::management_agent_status_runtime::process_authenticated_linux_agent_status_management;
use super::management_request::LOCAL_MANAGEMENT_BRIDGE_COMMAND_CODE;
use super::policy_response::{
    LocalPolicyResponseBuildError, build_policy_gated_read_only_response,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_frame::{LocalAgentRequestFrameDecodeError, decode_local_command_request_frame};
use super::response_writer::{
    LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    write_terminal_response_guarded,
};
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::terminal_response::builder::LocalTerminalResponseBuildError;
use crate::frame_object::LocalIpcFrame;
use crate::frame_object::boundary_reader::{LocalIpcFrameBoundaryRead, read_frame_at_boundary};
use crate::frame_object::reader::LocalIpcFrameReadError;
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

/// One narrow `AgentStatus` management boundary failure after authoritative state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusManagementBoundaryError {
    /// Generic frame acquisition failed and poisoned the inbound direction.
    FrameRead(LocalIpcFrameReadError),
    /// A non-management frame failed the exact legacy decoder and poisoned inbound.
    ReadOnlyDecode(LocalAgentRequestFrameDecodeError),
    /// Legacy policy-response construction failed before response write.
    ReadOnlyResponse(LocalPolicyResponseBuildError),
    /// Fixed `AgentStatus` management response construction failed before response write.
    ManagementResponse(LocalTerminalResponseBuildError),
    /// Guarded response writing failed.
    ResponseWrite(LocalTerminalResponseWriteError),
}

/// Processes one clean-EOF-aware local request with an AgentStatus-only command-3 slice.
///
/// Command 3 receives no caller-supplied management policy or provider context. Commands
/// 1/2 retain the existing read-only evaluator and exact response path.
///
/// # Errors
///
/// Preserves generic frame/read poisoning, legacy decode failures and guarded response
/// write failures. Canonical command-3 admission failures are encoded as correlated
/// terminal responses by the fixed AgentStatus-only runtime adapter.
#[allow(
    clippy::too_many_arguments,
    reason = "authenticated connection, legacy policy and protocol snapshots remain explicit"
)]
pub fn process_one_agent_status_management_at_boundary<R, W, RE, S>(
    reader: &mut R,
    writer: &mut W,
    inbound_state: &mut LocalInboundRequestState,
    response_write_state: &mut LocalTerminalResponseWriteState,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalBoundaryRequestResponseOutcome, LocalAgentStatusManagementBoundaryError>
where
    R: Read,
    W: Write,
    RE: PolicyEvaluator + ?Sized,
{
    if inbound_state.is_read_poisoned() {
        return Err(LocalAgentStatusManagementBoundaryError::FrameRead(
            LocalIpcFrameReadError::HeaderIo,
        ));
    }
    if response_write_state.is_write_poisoned() {
        return Err(LocalAgentStatusManagementBoundaryError::ResponseWrite(
            LocalTerminalResponseWriteError::WritePoisoned,
        ));
    }

    let frame = match read_frame_at_boundary(reader) {
        Ok(LocalIpcFrameBoundaryRead::CleanEof) => {
            return Ok(LocalBoundaryRequestResponseOutcome::CleanEof);
        }
        Ok(LocalIpcFrameBoundaryRead::Frame(frame)) => frame,
        Err(error) => {
            *inbound_state = LocalInboundRequestState::ReadPoisoned;
            return Err(LocalAgentStatusManagementBoundaryError::FrameRead(error));
        }
    };

    let response = if payload_command_code(&frame) == Some(LOCAL_MANAGEMENT_BRIDGE_COMMAND_CODE) {
        process_authenticated_linux_agent_status_management(&frame, connection, status_snapshot)
            .map_err(LocalAgentStatusManagementBoundaryError::ManagementResponse)?
    } else {
        let request = match decode_local_command_request_frame(&frame) {
            Ok(request) => request,
            Err(error) => {
                *inbound_state = LocalInboundRequestState::ReadPoisoned;
                return Err(LocalAgentStatusManagementBoundaryError::ReadOnlyDecode(
                    error,
                ));
            }
        };
        build_policy_gated_read_only_response(
            request,
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
        )
        .map_err(LocalAgentStatusManagementBoundaryError::ReadOnlyResponse)?
    };

    write_terminal_response_guarded(response_write_state, writer, &response)
        .map_err(LocalAgentStatusManagementBoundaryError::ResponseWrite)?;
    Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
}

fn payload_command_code(frame: &LocalIpcFrame) -> Option<u16> {
    let bytes = frame.payload().as_bytes();
    (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
}
