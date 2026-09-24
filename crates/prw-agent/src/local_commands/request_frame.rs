//! Complete in-memory local read-only command Request frame composition.
//!
//! Phase 031 reuses the Phase 015 two-byte command codec and the existing
//! validated frame constructors. It performs no stream or socket I/O.

#[allow(
    dead_code,
    reason = "pre-runtime Request boundary stream is intentionally crate-internal"
)]
pub(crate) mod boundary_stream;
pub mod discard;
pub mod send_state;
pub mod stream;
pub mod transaction;

use crate::frame_object::{
    LocalIpcFrame, LocalIpcFrameError, LocalIpcPayload, LocalIpcPayloadError,
};
use crate::{
    LocalIpcFrameHeader, LocalIpcFrameHeaderError, LocalIpcMessageKind, LocalIpcProtocolVersion,
    LocalIpcRequestId,
};

use super::codec::{LocalAgentRequestDecodeError, decode_request_command, encode_request_command};
use super::{LocalAgentCommand, LocalAgentRequestEnvelope};

/// Exact command-specific payload length of every current local Request frame.
pub const LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH: usize = 2;
/// Exact wire length for the current read-only request frame: 24-byte header + 2-byte payload.
pub const LOCAL_AGENT_REQUEST_WIRE_LENGTH: usize = 26;

/// Builds one complete local read-only command Request frame.
///
/// # Errors
///
/// Preserves failures from the validated payload, header, and frame
/// constructors. With the current typed inputs and fixed two-byte payload these
/// are defensive failures rather than caller-controlled alternate wire forms.
pub fn build_local_command_request_frame(
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
) -> Result<LocalIpcFrame, LocalAgentRequestFrameBuildError> {
    let payload = LocalIpcPayload::new(encode_request_command(command).to_vec())
        .map_err(LocalAgentRequestFrameBuildError::Payload)?;
    let header = LocalIpcFrameHeader::new(
        LocalIpcProtocolVersion::current(),
        LocalIpcMessageKind::Request,
        request_id,
        payload.len(),
    )
    .map_err(LocalAgentRequestFrameBuildError::Header)?;

    LocalIpcFrame::new(header, payload).map_err(LocalAgentRequestFrameBuildError::Frame)
}

/// Decodes one complete local read-only command Request frame.
///
/// # Errors
///
/// Returns [`LocalAgentRequestFrameDecodeError::NonRequestKind`] unless the
/// outer frame kind is `Request`. The payload is then delegated to the Phase
/// 015 command decoder, which requires exactly two bytes and a known command
/// identifier.
pub fn decode_local_command_request_frame(
    frame: &LocalIpcFrame,
) -> Result<LocalAgentRequestEnvelope, LocalAgentRequestFrameDecodeError> {
    if frame.header().kind() != LocalIpcMessageKind::Request {
        return Err(LocalAgentRequestFrameDecodeError::NonRequestKind);
    }

    let command = decode_request_command(frame.payload().as_bytes())
        .map_err(LocalAgentRequestFrameDecodeError::Command)?;
    Ok(LocalAgentRequestEnvelope::new(
        frame.header().request_id(),
        command,
    ))
}

/// Defensive Phase 031 Request frame construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentRequestFrameBuildError {
    /// Validated payload construction failed.
    Payload(LocalIpcPayloadError),
    /// Validated frame-header construction failed.
    Header(LocalIpcFrameHeaderError),
    /// Header/payload coupling failed.
    Frame(LocalIpcFrameError),
}

/// Fail-closed Phase 031 Request frame decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentRequestFrameDecodeError {
    /// Only outer `Request` frames are admitted to this command decoder.
    NonRequestKind,
    /// The Phase 015 two-byte command payload is invalid.
    Command(LocalAgentRequestDecodeError),
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH, LOCAL_AGENT_REQUEST_WIRE_LENGTH,
        LocalAgentRequestFrameDecodeError, build_local_command_request_frame,
        decode_local_command_request_frame,
    };
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentCommand;
    use crate::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn fixed_request_lengths_are_locked() {
        assert_eq!(LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH, 2);
        assert_eq!(LOCAL_AGENT_REQUEST_WIRE_LENGTH, 26);
    }

    #[test]
    fn both_read_only_commands_build_with_stable_payload_bytes() {
        for (command, expected) in [
            (LocalAgentCommand::GetAgentStatus, [0, 1]),
            (LocalAgentCommand::GetPrivateDnsConfig, [0, 2]),
        ] {
            let frame = build_local_command_request_frame(id(130), command)
                .expect("typed command request builds");

            assert_eq!(frame.header().kind(), LocalIpcMessageKind::Request);
            assert_eq!(frame.header().request_id(), id(130));
            assert_eq!(frame.header().payload_length(), 2);
            assert_eq!(frame.payload().as_bytes(), &expected);

            let decoded = decode_local_command_request_frame(&frame).expect("request decodes");
            assert_eq!(decoded.request_id(), id(130));
            assert_eq!(decoded.command(), command);
        }
    }

    #[test]
    fn response_and_error_frames_are_rejected_before_command_decode() {
        for kind in [LocalIpcMessageKind::Response, LocalIpcMessageKind::Error] {
            let payload = LocalIpcPayload::new(vec![0, 1]).expect("bounded payload");
            let header = LocalIpcFrameHeader::new(
                LocalIpcProtocolVersion::current(),
                kind,
                id(131),
                payload.len(),
            )
            .expect("valid header");
            let frame = LocalIpcFrame::new(header, payload).expect("matching frame");

            assert_eq!(
                decode_local_command_request_frame(&frame),
                Err(LocalAgentRequestFrameDecodeError::NonRequestKind)
            );
        }
    }

    #[test]
    fn malformed_command_payload_is_delegated_to_phase_015_decoder() {
        let payload = LocalIpcPayload::new(vec![0]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(132),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");

        assert!(matches!(
            decode_local_command_request_frame(&frame),
            Err(LocalAgentRequestFrameDecodeError::Command(_))
        ));
    }
}
