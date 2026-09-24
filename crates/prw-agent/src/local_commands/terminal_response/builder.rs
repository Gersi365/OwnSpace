//! Encode-side builder for kind/status-consistent terminal response frames.

use crate::frame_object::{
    LocalIpcFrame, LocalIpcFrameError, LocalIpcPayload, LocalIpcPayloadError,
};
use crate::{
    LocalIpcFrameHeader, LocalIpcFrameHeaderError, LocalIpcProtocolVersion, LocalIpcRequestId,
};

use super::expected_terminal_kind;
use crate::local_commands::LocalAgentResponseStatus;
use crate::local_commands::response_codec::encode_response_status;

/// Maximum command-specific body length after reserving the two-byte status prefix.
pub const LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH: usize = 1_048_574;

/// Builds one complete kind/status-consistent terminal response frame.
///
/// # Errors
///
/// Returns [`LocalTerminalResponseBuildError::BodyTooLarge`] when `body`
/// exceeds the Phase 022 command-specific body bound. Lower-level validated
/// payload, header, and frame-construction failures are preserved as typed
/// variants.
pub fn build_terminal_response_frame(
    request_id: LocalIpcRequestId,
    status: LocalAgentResponseStatus,
    body: &[u8],
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    if body.len() > LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH {
        return Err(LocalTerminalResponseBuildError::BodyTooLarge);
    }

    let prefix = encode_response_status(status);
    let mut bytes = Vec::with_capacity(prefix.len() + body.len());
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(body);

    let payload = LocalIpcPayload::new(bytes).map_err(LocalTerminalResponseBuildError::Payload)?;
    let header = LocalIpcFrameHeader::new(
        LocalIpcProtocolVersion::current(),
        expected_terminal_kind(status),
        request_id,
        payload.len(),
    )
    .map_err(LocalTerminalResponseBuildError::Header)?;

    LocalIpcFrame::new(header, payload).map_err(LocalTerminalResponseBuildError::Frame)
}

/// Fail-closed Phase 022 terminal-response frame construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTerminalResponseBuildError {
    /// Command-specific body leaves insufficient room for the status prefix.
    BodyTooLarge,
    /// Validated payload construction failed.
    Payload(LocalIpcPayloadError),
    /// Validated header construction failed.
    Header(LocalIpcFrameHeaderError),
    /// Header/payload coupling failed.
    Frame(LocalIpcFrameError),
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH, LocalTerminalResponseBuildError,
        build_terminal_response_frame,
    };
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::{LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcMessageKind, LocalIpcRequestId};

    fn id() -> LocalIpcRequestId {
        LocalIpcRequestId::new(55).expect("non-zero request id")
    }

    #[test]
    fn terminal_body_bound_reserves_exact_status_prefix_space() {
        assert_eq!(LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH, 1_048_574);
        assert_eq!(
            LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH + 2,
            usize::try_from(LOCAL_IPC_MAX_PAYLOAD_LENGTH).expect("u32 fits usize")
        );
    }

    #[test]
    fn success_builder_uses_response_kind_and_prepends_ok_status() {
        let frame = build_terminal_response_frame(id(), LocalAgentResponseStatus::Ok, &[9, 8])
            .expect("bounded success frame");

        assert_eq!(frame.header().kind(), LocalIpcMessageKind::Response);
        assert_eq!(frame.header().request_id(), id());
        assert_eq!(frame.header().payload_length(), 4);
        assert_eq!(frame.payload().as_bytes(), &[0, 0, 9, 8]);
        assert_eq!(
            validate_terminal_response_frame(&frame)
                .expect("builder output validates")
                .status(),
            LocalAgentResponseStatus::Ok
        );
    }

    #[test]
    fn non_success_builder_uses_error_kind() {
        for status in [
            LocalAgentResponseStatus::InvalidRequest,
            LocalAgentResponseStatus::Unauthorized,
            LocalAgentResponseStatus::UnsupportedCommand,
            LocalAgentResponseStatus::Conflict,
            LocalAgentResponseStatus::InternalError,
        ] {
            let frame =
                build_terminal_response_frame(id(), status, &[]).expect("bounded error frame");
            assert_eq!(frame.header().kind(), LocalIpcMessageKind::Error);
            assert_eq!(frame.payload().as_bytes(), &status.code().to_be_bytes());
            assert_eq!(
                validate_terminal_response_frame(&frame)
                    .expect("builder output validates")
                    .status(),
                status
            );
        }
    }

    #[test]
    fn maximum_command_body_produces_maximum_valid_payload() {
        let body = vec![7; LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH];
        let frame = build_terminal_response_frame(id(), LocalAgentResponseStatus::Ok, &body)
            .expect("maximum terminal body is valid");

        assert_eq!(
            frame.header().payload_length(),
            LOCAL_IPC_MAX_PAYLOAD_LENGTH
        );
        assert_eq!(frame.payload().as_bytes()[..2], [0, 0]);
        assert_eq!(frame.payload().as_bytes().len(), 1_048_576);
    }

    #[test]
    fn above_maximum_command_body_is_rejected_before_frame_construction() {
        let body = vec![0; LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH + 1];
        assert_eq!(
            build_terminal_response_frame(id(), LocalAgentResponseStatus::Ok, &body),
            Err(LocalTerminalResponseBuildError::BodyTooLarge)
        );
    }
}
