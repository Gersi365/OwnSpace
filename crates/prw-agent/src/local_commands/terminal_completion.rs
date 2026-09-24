//! Transactional completion of a validated terminal response against the
//! connection-local outstanding-request tracker.
//!
//! Phase 021 remains pure in-memory state composition and performs no socket
//! I/O, timeout handling, or command dispatch.

use crate::frame_object::LocalIpcFrame;

use super::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};
use super::terminal_response::{
    LocalTerminalResponse, LocalTerminalResponseError, validate_terminal_response_frame,
};

/// Validates a terminal response and completes exactly its known request ID.
///
/// # Errors
///
/// Returns [`LocalTerminalCompletionError::InvalidTerminalResponse`] when the
/// Phase 020 terminal-frame invariant fails. Returns
/// [`LocalTerminalCompletionError::RequestTracker`] when the validated frame's
/// request ID is not currently outstanding. Tracker state is mutated only after
/// terminal-frame validation succeeds and only when completion succeeds.
pub fn validate_and_complete_terminal_response(
    frame: &LocalIpcFrame,
    tracker: &mut LocalRequestTracker,
) -> Result<LocalTerminalResponse, LocalTerminalCompletionError> {
    let response = validate_terminal_response_frame(frame)
        .map_err(LocalTerminalCompletionError::InvalidTerminalResponse)?;
    tracker
        .complete(response.request_id())
        .map_err(LocalTerminalCompletionError::RequestTracker)?;
    Ok(response)
}

/// Fail-closed Phase 021 terminal-completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTerminalCompletionError {
    /// The frame is not a valid terminal response under the Phase 020 invariant.
    InvalidTerminalResponse(LocalTerminalResponseError),
    /// The validated response cannot complete the current request-tracker state.
    RequestTracker(LocalRequestTrackerError),
}

#[cfg(test)]
mod tests {
    use super::{LocalTerminalCompletionError, validate_and_complete_terminal_response};
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};
    use crate::local_commands::response_codec::encode_response_status;
    use crate::local_commands::terminal_response::LocalTerminalResponseError;
    use crate::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn frame(
        request_id: LocalIpcRequestId,
        kind: LocalIpcMessageKind,
        status: LocalAgentResponseStatus,
    ) -> LocalIpcFrame {
        let payload = LocalIpcPayload::new(encode_response_status(status).to_vec())
            .expect("bounded test payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            kind,
            request_id,
            payload.len(),
        )
        .expect("valid test header");
        LocalIpcFrame::new(header, payload).expect("matching frame")
    }

    #[test]
    fn valid_success_completes_exactly_one_known_request() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(10)).expect("request 10 registered");
        tracker.register(id(11)).expect("request 11 registered");
        let response_frame = frame(
            id(10),
            LocalIpcMessageKind::Response,
            LocalAgentResponseStatus::Ok,
        );

        let response = validate_and_complete_terminal_response(&response_frame, &mut tracker)
            .expect("known success completes");

        assert_eq!(response.request_id(), id(10));
        assert_eq!(response.status(), LocalAgentResponseStatus::Ok);
        assert!(!tracker.contains(id(10)));
        assert!(tracker.contains(id(11)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn valid_error_completes_known_request() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(12)).expect("request registered");
        let response_frame = frame(
            id(12),
            LocalIpcMessageKind::Error,
            LocalAgentResponseStatus::Conflict,
        );

        let response = validate_and_complete_terminal_response(&response_frame, &mut tracker)
            .expect("known error completes");

        assert_eq!(response.status(), LocalAgentResponseStatus::Conflict);
        assert!(tracker.is_empty());
    }

    #[test]
    fn invalid_terminal_frame_does_not_consume_request_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(20)).expect("request registered");
        let invalid_frame = frame(
            id(20),
            LocalIpcMessageKind::Response,
            LocalAgentResponseStatus::InternalError,
        );

        assert_eq!(
            validate_and_complete_terminal_response(&invalid_frame, &mut tracker),
            Err(LocalTerminalCompletionError::InvalidTerminalResponse(
                LocalTerminalResponseError::KindStatusMismatch
            ))
        );
        assert!(tracker.contains(id(20)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn unknown_request_id_does_not_consume_other_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(30)).expect("request registered");
        let unknown_frame = frame(
            id(31),
            LocalIpcMessageKind::Response,
            LocalAgentResponseStatus::Ok,
        );

        assert_eq!(
            validate_and_complete_terminal_response(&unknown_frame, &mut tracker),
            Err(LocalTerminalCompletionError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.contains(id(30)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn duplicate_terminal_response_is_rejected_after_first_completion() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(40)).expect("request registered");
        let response_frame = frame(
            id(40),
            LocalIpcMessageKind::Response,
            LocalAgentResponseStatus::Ok,
        );

        validate_and_complete_terminal_response(&response_frame, &mut tracker)
            .expect("first terminal response completes");
        assert_eq!(
            validate_and_complete_terminal_response(&response_frame, &mut tracker),
            Err(LocalTerminalCompletionError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.is_empty());
    }
}
