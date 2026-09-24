//! Complete in-memory `GetAgentStatus` response frame composition.

pub mod stream;
pub mod stream_completion;

use super::LocalAgentStatusSnapshot;
use super::codec::{LocalAgentStatusDecodeError, decode_status_snapshot, encode_status_snapshot};
use crate::LocalIpcRequestId;
use crate::frame_object::LocalIpcFrame;
use crate::local_commands::LocalAgentResponseStatus;
use crate::local_commands::response_codec::LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH;
use crate::local_commands::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
use crate::local_commands::terminal_response::{
    LocalTerminalResponseError, validate_terminal_response_frame,
};

/// Typed successful `GetAgentStatus` frame result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAgentStatusFrame {
    request_id: LocalIpcRequestId,
    snapshot: LocalAgentStatusSnapshot,
}

impl LocalAgentStatusFrame {
    /// Returns the correlated request identifier.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the decoded status snapshot.
    #[must_use]
    pub const fn snapshot(self) -> LocalAgentStatusSnapshot {
        self.snapshot
    }
}

/// Builds a complete successful `GetAgentStatus` response frame.
///
/// # Errors
///
/// Preserves any lower-level Phase 022 terminal-frame build failure.
pub fn build_success_status_frame(
    request_id: LocalIpcRequestId,
    snapshot: LocalAgentStatusSnapshot,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    let body = encode_status_snapshot(snapshot);
    build_terminal_response_frame(request_id, LocalAgentResponseStatus::Ok, &body)
}

/// Decodes a complete successful `GetAgentStatus` response frame.
///
/// # Errors
///
/// Returns [`LocalAgentStatusFrameDecodeError::Terminal`] when the Phase 020
/// terminal-frame invariant fails,
/// [`LocalAgentStatusFrameDecodeError::NonSuccessStatus`] for a valid terminal
/// error frame, or [`LocalAgentStatusFrameDecodeError::StatusBody`] when the
/// five-byte Phase 018 status body is invalid.
pub fn decode_success_status_frame(
    frame: &LocalIpcFrame,
) -> Result<LocalAgentStatusFrame, LocalAgentStatusFrameDecodeError> {
    let terminal = validate_terminal_response_frame(frame)
        .map_err(LocalAgentStatusFrameDecodeError::Terminal)?;
    if !terminal.status().is_success() {
        return Err(LocalAgentStatusFrameDecodeError::NonSuccessStatus);
    }

    let body = &frame.payload().as_bytes()[LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH..];
    let snapshot =
        decode_status_snapshot(body).map_err(LocalAgentStatusFrameDecodeError::StatusBody)?;

    Ok(LocalAgentStatusFrame {
        request_id: terminal.request_id(),
        snapshot,
    })
}

/// Fail-closed Phase 023 complete status-frame decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusFrameDecodeError {
    /// Outer terminal response framing/status invariant failed.
    Terminal(LocalTerminalResponseError),
    /// The frame is a valid terminal response but carries a non-success status.
    NonSuccessStatus,
    /// The command-specific five-byte Agent-status body is invalid.
    StatusBody(LocalAgentStatusDecodeError),
}

#[cfg(test)]
mod tests {
    use super::{
        LocalAgentStatusFrameDecodeError, build_success_status_frame, decode_success_status_frame,
    };
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::status_snapshot::response_payload::encode_success_status_response;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::builder::build_terminal_response_frame;
    use crate::{LocalIpcMessageKind, LocalIpcRequestId};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn builder_matches_phase_019_payload_and_response_kind() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let frame = build_success_status_frame(id(70), snapshot).expect("valid status frame");

        assert_eq!(frame.header().kind(), LocalIpcMessageKind::Response);
        assert_eq!(frame.header().request_id(), id(70));
        assert_eq!(frame.header().payload_length(), 7);
        assert_eq!(
            frame.payload().as_bytes(),
            &encode_success_status_response(snapshot)
        );
    }

    #[test]
    fn all_runtime_states_round_trip_through_complete_frame() {
        for state in [
            LocalAgentRuntimeState::Starting,
            LocalAgentRuntimeState::Ready,
            LocalAgentRuntimeState::Degraded,
            LocalAgentRuntimeState::Stopping,
        ] {
            let snapshot = LocalAgentStatusSnapshot::current(state);
            let frame = build_success_status_frame(id(71), snapshot).expect("valid status frame");
            let decoded = decode_success_status_frame(&frame).expect("status frame decodes");

            assert_eq!(decoded.request_id(), id(71));
            assert_eq!(decoded.snapshot(), snapshot);
        }
    }

    #[test]
    fn valid_terminal_error_is_not_a_success_status_frame() {
        let frame = build_terminal_response_frame(id(72), LocalAgentResponseStatus::Conflict, &[])
            .expect("valid terminal error");

        assert_eq!(
            decode_success_status_frame(&frame),
            Err(LocalAgentStatusFrameDecodeError::NonSuccessStatus)
        );
    }

    #[test]
    fn malformed_status_body_is_rejected_after_terminal_validation() {
        let frame = build_terminal_response_frame(id(73), LocalAgentResponseStatus::Ok, &[2])
            .expect("structurally valid terminal response");

        assert_eq!(
            decode_success_status_frame(&frame),
            Err(LocalAgentStatusFrameDecodeError::StatusBody(
                super::LocalAgentStatusDecodeError::InvalidLength
            ))
        );
    }
}
