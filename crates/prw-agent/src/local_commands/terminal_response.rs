//! Terminal-response frame invariant validation.
//!
//! Phase 020 couples an already validated in-memory frame with the common
//! response-status prefix. Phase 022 adds an encode-side builder that can only
//! construct kind/status-consistent terminal frames. No socket I/O occurs.

pub mod builder;

use crate::frame_object::LocalIpcFrame;
use crate::{LocalIpcMessageKind, LocalIpcRequestId};

use super::LocalAgentResponseStatus;
use super::response_codec::{LocalAgentResponseDecodeError, decode_response_status_prefix};

/// Validated terminal-response metadata derived from an existing frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTerminalResponse {
    request_id: LocalIpcRequestId,
    status: LocalAgentResponseStatus,
}

impl LocalTerminalResponse {
    /// Returns the correlated non-zero request identifier from the frame header.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the validated terminal response status from the payload prefix.
    #[must_use]
    pub const fn status(self) -> LocalAgentResponseStatus {
        self.status
    }
}

/// Returns the only outer message kind valid for a terminal response status.
#[must_use]
pub const fn expected_terminal_kind(status: LocalAgentResponseStatus) -> LocalIpcMessageKind {
    if status.is_success() {
        LocalIpcMessageKind::Response
    } else {
        LocalIpcMessageKind::Error
    }
}

/// Validates the Phase 020 outer terminal-response frame invariant.
///
/// # Errors
///
/// Returns [`LocalTerminalResponseError::RequestKind`] when the frame is a
/// request, [`LocalTerminalResponseError::MissingStatus`] or
/// [`LocalTerminalResponseError::UnknownStatus`] when the common response
/// prefix is invalid, or [`LocalTerminalResponseError::KindStatusMismatch`]
/// when `Response` does not carry `Ok` or `Error` carries `Ok`.
pub fn validate_terminal_response_frame(
    frame: &LocalIpcFrame,
) -> Result<LocalTerminalResponse, LocalTerminalResponseError> {
    let kind = frame.header().kind();
    if kind == LocalIpcMessageKind::Request {
        return Err(LocalTerminalResponseError::RequestKind);
    }

    let (status, _) =
        decode_response_status_prefix(frame.payload().as_bytes()).map_err(map_status_error)?;
    if kind != expected_terminal_kind(status) {
        return Err(LocalTerminalResponseError::KindStatusMismatch);
    }

    Ok(LocalTerminalResponse {
        request_id: frame.header().request_id(),
        status,
    })
}

const fn map_status_error(error: LocalAgentResponseDecodeError) -> LocalTerminalResponseError {
    match error {
        LocalAgentResponseDecodeError::MissingStatus => LocalTerminalResponseError::MissingStatus,
        LocalAgentResponseDecodeError::UnknownStatus => LocalTerminalResponseError::UnknownStatus,
    }
}

/// Fail-closed Phase 020 terminal-response validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTerminalResponseError {
    /// A request frame cannot be interpreted as a terminal response.
    RequestKind,
    /// Fewer than two payload bytes are available for the mandatory status.
    MissingStatus,
    /// The payload begins with an undefined response-status identifier.
    UnknownStatus,
    /// Outer message kind and decoded terminal status disagree.
    KindStatusMismatch,
}

#[cfg(test)]
mod tests {
    use super::{
        LocalTerminalResponseError, expected_terminal_kind, validate_terminal_response_frame,
    };
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::response_codec::encode_response_status;
    use crate::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn frame(kind: LocalIpcMessageKind, payload: Vec<u8>) -> LocalIpcFrame {
        let payload = LocalIpcPayload::new(payload).expect("bounded test payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            kind,
            LocalIpcRequestId::new(41).expect("non-zero request id"),
            payload.len(),
        )
        .expect("valid test header");
        LocalIpcFrame::new(header, payload).expect("matching frame")
    }

    fn status_payload(status: LocalAgentResponseStatus) -> Vec<u8> {
        encode_response_status(status).to_vec()
    }

    #[test]
    fn expected_kind_mapping_is_stable() {
        assert_eq!(
            expected_terminal_kind(LocalAgentResponseStatus::Ok),
            LocalIpcMessageKind::Response
        );
        for status in [
            LocalAgentResponseStatus::InvalidRequest,
            LocalAgentResponseStatus::Unauthorized,
            LocalAgentResponseStatus::UnsupportedCommand,
            LocalAgentResponseStatus::Conflict,
            LocalAgentResponseStatus::InternalError,
        ] {
            assert_eq!(expected_terminal_kind(status), LocalIpcMessageKind::Error);
        }
    }

    #[test]
    fn response_with_ok_is_valid_and_preserves_request_id() {
        let frame = frame(
            LocalIpcMessageKind::Response,
            status_payload(LocalAgentResponseStatus::Ok),
        );
        let validated = validate_terminal_response_frame(&frame).expect("valid success response");

        assert_eq!(validated.status(), LocalAgentResponseStatus::Ok);
        assert_eq!(validated.request_id(), frame.header().request_id());
    }

    #[test]
    fn error_with_each_non_success_status_is_valid() {
        for status in [
            LocalAgentResponseStatus::InvalidRequest,
            LocalAgentResponseStatus::Unauthorized,
            LocalAgentResponseStatus::UnsupportedCommand,
            LocalAgentResponseStatus::Conflict,
            LocalAgentResponseStatus::InternalError,
        ] {
            let frame = frame(LocalIpcMessageKind::Error, status_payload(status));
            assert_eq!(
                validate_terminal_response_frame(&frame)
                    .expect("valid error response")
                    .status(),
                status
            );
        }
    }

    #[test]
    fn response_with_non_success_status_is_rejected() {
        let frame = frame(
            LocalIpcMessageKind::Response,
            status_payload(LocalAgentResponseStatus::InvalidRequest),
        );
        assert_eq!(
            validate_terminal_response_frame(&frame),
            Err(LocalTerminalResponseError::KindStatusMismatch)
        );
    }

    #[test]
    fn error_with_ok_is_rejected() {
        let frame = frame(
            LocalIpcMessageKind::Error,
            status_payload(LocalAgentResponseStatus::Ok),
        );
        assert_eq!(
            validate_terminal_response_frame(&frame),
            Err(LocalTerminalResponseError::KindStatusMismatch)
        );
    }

    #[test]
    fn request_kind_is_rejected_before_payload_interpretation() {
        let frame = frame(
            LocalIpcMessageKind::Request,
            status_payload(LocalAgentResponseStatus::Ok),
        );
        assert_eq!(
            validate_terminal_response_frame(&frame),
            Err(LocalTerminalResponseError::RequestKind)
        );
    }

    #[test]
    fn missing_and_unknown_status_prefixes_are_rejected() {
        let missing = frame(LocalIpcMessageKind::Response, vec![0]);
        assert_eq!(
            validate_terminal_response_frame(&missing),
            Err(LocalTerminalResponseError::MissingStatus)
        );

        let unknown = frame(LocalIpcMessageKind::Error, vec![0, 6]);
        assert_eq!(
            validate_terminal_response_frame(&unknown),
            Err(LocalTerminalResponseError::UnknownStatus)
        );
    }
}
