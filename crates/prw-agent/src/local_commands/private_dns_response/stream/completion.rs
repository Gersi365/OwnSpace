//! Decode-before-complete stream composition for `GetPrivateDnsConfig`.
//!
//! Phase 030 ensures bounded private-DNS decoding succeeds before the
//! connection-local outstanding-request tracker is mutated.

use std::io::Read;

use super::{LocalPrivateDnsStreamReadError, read_success_private_dns_response};
use crate::local_commands::private_dns_response::LocalPrivateDnsFrame;
use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};

/// Reads, fully decodes, and then completes one successful private-DNS response.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsTrackedReadError::ReadDecode`] when generic frame
/// acquisition or bounded command-specific decoding fails. Tracker state is
/// unchanged in that case. Returns
/// [`LocalPrivateDnsTrackedReadError::RequestTracker`] when the fully decoded
/// response names an ID that is not currently outstanding.
pub fn read_decode_and_complete_private_dns_response<R: Read>(
    reader: &mut R,
    tracker: &mut LocalRequestTracker,
) -> Result<LocalPrivateDnsFrame, LocalPrivateDnsTrackedReadError> {
    let decoded = read_success_private_dns_response(reader)
        .map_err(LocalPrivateDnsTrackedReadError::ReadDecode)?;
    tracker
        .complete(decoded.request_id())
        .map_err(LocalPrivateDnsTrackedReadError::RequestTracker)?;
    Ok(decoded)
}

/// Fail-closed Phase 030 private-DNS read/decode/completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsTrackedReadError {
    /// Frame acquisition or bounded command-specific decoding failed.
    ReadDecode(LocalPrivateDnsStreamReadError),
    /// Fully decoded response could not complete the outstanding-request state.
    RequestTracker(LocalRequestTrackerError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{LocalPrivateDnsTrackedReadError, read_decode_and_complete_private_dns_response};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::write_frame;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::private_dns_codec::LocalPrivateDnsDecodeError;
    use crate::local_commands::private_dns_response::LocalPrivateDnsFrameDecodeError;
    use crate::local_commands::private_dns_response::stream::{
        LocalPrivateDnsStreamReadError, write_success_private_dns_response,
    };
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};
    use crate::local_commands::terminal_response::builder::build_terminal_response_frame;
    use prw_network::PrivateDnsConfig;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into()],
            split_domains: vec!["corp.example".into()],
        })
        .expect("bounded test config")
    }

    #[test]
    fn fully_valid_known_private_dns_response_completes_only_its_request() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(120)).expect("request 120 registered");
        tracker.register(id(121)).expect("request 121 registered");
        let snapshot = snapshot();
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(120), &snapshot)
            .expect("memory write succeeds");
        let mut cursor = Cursor::new(bytes);

        let decoded = read_decode_and_complete_private_dns_response(&mut cursor, &mut tracker)
            .expect("valid response completes");

        assert_eq!(decoded.request_id(), id(120));
        assert_eq!(decoded.snapshot(), &snapshot);
        assert!(!tracker.contains(id(120)));
        assert!(tracker.contains(id(121)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn malformed_private_dns_body_does_not_consume_request_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(122)).expect("request registered");
        let frame =
            build_terminal_response_frame(id(122), LocalAgentResponseStatus::Ok, &[0b100, 0, 0])
                .expect("structurally valid terminal frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_decode_and_complete_private_dns_response(&mut cursor, &mut tracker),
            Err(LocalPrivateDnsTrackedReadError::ReadDecode(
                LocalPrivateDnsStreamReadError::Decode(LocalPrivateDnsFrameDecodeError::Body(
                    LocalPrivateDnsDecodeError::ReservedFlagsSet
                ))
            ))
        );
        assert!(tracker.contains(id(122)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn truncated_stream_does_not_consume_request_state() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(123)).expect("request registered");
        let snapshot = snapshot();
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(123), &snapshot)
            .expect("memory write succeeds");
        bytes.pop();
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_decode_and_complete_private_dns_response(&mut cursor, &mut tracker),
            Err(LocalPrivateDnsTrackedReadError::ReadDecode(
                LocalPrivateDnsStreamReadError::Read(LocalIpcFrameReadError::TruncatedPayload)
            ))
        );
        assert!(tracker.contains(id(123)));
    }

    #[test]
    fn fully_decoded_unknown_id_leaves_other_tracker_state_untouched() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(124)).expect("request registered");
        let snapshot = snapshot();
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(125), &snapshot)
            .expect("memory write succeeds");
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_decode_and_complete_private_dns_response(&mut cursor, &mut tracker),
            Err(LocalPrivateDnsTrackedReadError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.contains(id(124)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn replay_after_successful_completion_is_rejected() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(126)).expect("request registered");
        let snapshot = snapshot();
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(126), &snapshot)
            .expect("memory write succeeds");

        let mut first = Cursor::new(bytes.clone());
        read_decode_and_complete_private_dns_response(&mut first, &mut tracker)
            .expect("first response completes");

        let mut replay = Cursor::new(bytes);
        assert_eq!(
            read_decode_and_complete_private_dns_response(&mut replay, &mut tracker),
            Err(LocalPrivateDnsTrackedReadError::RequestTracker(
                LocalRequestTrackerError::UnknownRequestId
            ))
        );
        assert!(tracker.is_empty());
    }
}
