//! Decode-before-complete stream composition for successful `GetAgentStatus`.
//!
//! Phase 025 ensures command-specific decoding succeeds before the connection-
//! local outstanding-request tracker is mutated.

use std::io::Read;

use super::{LocalAgentStatusFrame, stream::LocalAgentStatusStreamReadError};
use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};

/// Reads, fully decodes, and then completes one successful `GetAgentStatus` response.
///
/// # Errors
///
/// Returns [`LocalAgentStatusTrackedReadError::ReadDecode`] when generic frame
/// acquisition or complete command-specific status decoding fails. Tracker state
/// is unchanged in that case. Returns
/// [`LocalAgentStatusTrackedReadError::RequestTracker`] when the fully decoded
/// response names an ID that is not currently outstanding; unrelated tracker
/// state remains unchanged.
pub fn read_decode_and_complete_status_response<R: Read>(
    reader: &mut R,
    tracker: &mut LocalRequestTracker,
) -> Result<LocalAgentStatusFrame, LocalAgentStatusTrackedReadError> {
    let decoded = super::stream::read_success_status_response(reader)
        .map_err(LocalAgentStatusTrackedReadError::ReadDecode)?;
    tracker
        .complete(decoded.request_id())
        .map_err(LocalAgentStatusTrackedReadError::RequestTracker)?;
    Ok(decoded)
}

/// Fail-closed Phase 025 status read/decode/completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusTrackedReadError {
    /// Frame acquisition or complete command-specific decoding failed.
    ReadDecode(LocalAgentStatusStreamReadError),
    /// Fully decoded response could not complete the outstanding-request state.
    RequestTracker(LocalRequestTrackerError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{LocalAgentStatusTrackedReadError, read_decode_and_complete_status_response};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::write_frame;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};
    use crate::local_commands::status_snapshot::response_frame::LocalAgentStatusFrameDecodeError;
    use crate::local_commands::status_snapshot::response_frame::stream::{
        LocalAgentStatusStreamReadError, write_success_status_response,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::builder::build_terminal_response_frame;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn fully_valid_known_status_response_completes_exactly_its_request() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(90)).expect("request 90 registered");
        tracker.register(id(91)).expect("request 91 registered");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(90), snapshot).expect("memory write succeeds");
        let mut cursor = Cursor::new(bytes);

        let decoded = read_decode_and_complete_status_response(&mut cursor, &mut tracker)
            .expect("valid response completes");

        assert_eq!(decoded.request_id(), id(90));
        assert_eq!(decoded.snapshot(), snapshot);
        assert!(!tracker.contains(id(90)));
        assert!(tracker.contains(id(91)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn malformed_command_body_does_not_consume_request_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(92)).expect("request registered");
        let frame = build_terminal_response_frame(id(92), LocalAgentResponseStatus::Ok, &[2])
            .expect("structurally valid terminal frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");
        let mut cursor = Cursor::new(bytes);

        let result = read_decode_and_complete_status_response(&mut cursor, &mut tracker);
        assert!(matches!(
            result,
            Err(LocalAgentStatusTrackedReadError::ReadDecode(
                LocalAgentStatusStreamReadError::Decode(
                    LocalAgentStatusFrameDecodeError::StatusBody(_)
                )
            ))
        ));
        assert!(tracker.contains(id(92)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn truncated_stream_does_not_consume_request_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(93)).expect("request registered");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(93), snapshot).expect("memory write succeeds");
        bytes.pop();
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_decode_and_complete_status_response(&mut cursor, &mut tracker),
            Err(LocalAgentStatusTrackedReadError::ReadDecode(
                LocalAgentStatusStreamReadError::Read(LocalIpcFrameReadError::TruncatedPayload)
            ))
        );
        assert!(tracker.contains(id(93)));
    }

    #[test]
    fn fully_decoded_unknown_id_leaves_other_tracker_state_untouched() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(94)).expect("request registered");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Degraded);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(95), snapshot).expect("memory write succeeds");
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_decode_and_complete_status_response(&mut cursor, &mut tracker),
            Err(LocalAgentStatusTrackedReadError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.contains(id(94)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn replay_after_successful_completion_is_rejected() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(96)).expect("request registered");
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(96), snapshot).expect("memory write succeeds");

        let mut first = Cursor::new(bytes.clone());
        read_decode_and_complete_status_response(&mut first, &mut tracker)
            .expect("first response completes");

        let mut replay = Cursor::new(bytes);
        assert_eq!(
            read_decode_and_complete_status_response(&mut replay, &mut tracker),
            Err(LocalAgentStatusTrackedReadError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.is_empty());
    }
}
