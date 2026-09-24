//! Composition codec for a successful `GetAgentStatus` response payload.

use super::LocalAgentStatusSnapshot;
use super::codec::{
    LOCAL_AGENT_STATUS_BODY_LENGTH, LocalAgentStatusDecodeError, decode_status_snapshot,
    encode_status_snapshot,
};
use crate::local_commands::LocalAgentResponseStatus;
use crate::local_commands::response_codec::{
    LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH, LocalAgentResponseDecodeError,
    decode_response_status_prefix, encode_response_status,
};

/// Exact byte length of a successful Phase 019 `GetAgentStatus` payload.
pub const LOCAL_AGENT_STATUS_SUCCESS_PAYLOAD_LENGTH: usize =
    LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH + LOCAL_AGENT_STATUS_BODY_LENGTH;

/// Encodes a successful `GetAgentStatus` payload.
#[must_use]
pub const fn encode_success_status_response(
    snapshot: LocalAgentStatusSnapshot,
) -> [u8; LOCAL_AGENT_STATUS_SUCCESS_PAYLOAD_LENGTH] {
    let prefix = encode_response_status(LocalAgentResponseStatus::Ok);
    let body = encode_status_snapshot(snapshot);

    [
        prefix[0], prefix[1], body[0], body[1], body[2], body[3], body[4],
    ]
}

/// Decodes a successful `GetAgentStatus` payload.
///
/// # Errors
///
/// Returns a [`LocalAgentStatusResponseDecodeError`] when the common response
/// prefix is missing or unknown, when the response status is not `Ok`, or when
/// the Phase 018 status body fails its exact length/state/version validation.
pub fn decode_success_status_response(
    payload: &[u8],
) -> Result<LocalAgentStatusSnapshot, LocalAgentStatusResponseDecodeError> {
    let (status, body) = decode_response_status_prefix(payload).map_err(map_status_error)?;
    if status != LocalAgentResponseStatus::Ok {
        return Err(LocalAgentStatusResponseDecodeError::NonSuccessStatus);
    }

    decode_status_snapshot(body).map_err(map_body_error)
}

const fn map_status_error(
    error: LocalAgentResponseDecodeError,
) -> LocalAgentStatusResponseDecodeError {
    match error {
        LocalAgentResponseDecodeError::MissingStatus => {
            LocalAgentStatusResponseDecodeError::MissingStatus
        }
        LocalAgentResponseDecodeError::UnknownStatus => {
            LocalAgentStatusResponseDecodeError::UnknownStatus
        }
    }
}

const fn map_body_error(error: LocalAgentStatusDecodeError) -> LocalAgentStatusResponseDecodeError {
    match error {
        LocalAgentStatusDecodeError::InvalidLength => {
            LocalAgentStatusResponseDecodeError::InvalidBodyLength
        }
        LocalAgentStatusDecodeError::UnknownRuntimeState => {
            LocalAgentStatusResponseDecodeError::UnknownRuntimeState
        }
        LocalAgentStatusDecodeError::UnsupportedProtocolVersion => {
            LocalAgentStatusResponseDecodeError::UnsupportedProtocolVersion
        }
    }
}

/// Fail-closed Phase 019 successful-status response decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusResponseDecodeError {
    /// Fewer than two bytes are available for the common response-status prefix.
    MissingStatus,
    /// Common response-status identifier is unknown.
    UnknownStatus,
    /// A known response status other than `Ok` was supplied.
    NonSuccessStatus,
    /// Status body is not exactly five bytes.
    InvalidBodyLength,
    /// Status body contains an unknown runtime-state identifier.
    UnknownRuntimeState,
    /// Status body names an unsupported local IPC protocol version.
    UnsupportedProtocolVersion,
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_AGENT_STATUS_SUCCESS_PAYLOAD_LENGTH, LocalAgentStatusResponseDecodeError,
        decode_success_status_response, encode_success_status_response,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    #[test]
    fn successful_status_payload_length_is_locked_to_seven_bytes() {
        assert_eq!(LOCAL_AGENT_STATUS_SUCCESS_PAYLOAD_LENGTH, 7);
    }

    #[test]
    fn ready_status_has_stable_current_success_bytes() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        assert_eq!(
            encode_success_status_response(snapshot),
            [0, 0, 2, 0, 1, 0, 0]
        );
    }

    #[test]
    fn all_runtime_states_round_trip_through_success_payload() {
        for state in [
            LocalAgentRuntimeState::Starting,
            LocalAgentRuntimeState::Ready,
            LocalAgentRuntimeState::Degraded,
            LocalAgentRuntimeState::Stopping,
        ] {
            let snapshot = LocalAgentStatusSnapshot::current(state);
            let payload = encode_success_status_response(snapshot);
            assert_eq!(decode_success_status_response(&payload), Ok(snapshot));
        }
    }

    #[test]
    fn missing_and_unknown_status_prefixes_are_rejected() {
        assert_eq!(
            decode_success_status_response(&[0]),
            Err(LocalAgentStatusResponseDecodeError::MissingStatus)
        );
        assert_eq!(
            decode_success_status_response(&[0, 6, 2, 0, 1, 0, 0]),
            Err(LocalAgentStatusResponseDecodeError::UnknownStatus)
        );
    }

    #[test]
    fn known_non_success_status_is_rejected() {
        assert_eq!(
            decode_success_status_response(&[0, 1, 2, 0, 1, 0, 0]),
            Err(LocalAgentStatusResponseDecodeError::NonSuccessStatus)
        );
    }

    #[test]
    fn status_body_failures_remain_fail_closed() {
        assert_eq!(
            decode_success_status_response(&[0, 0, 2, 0, 1, 0]),
            Err(LocalAgentStatusResponseDecodeError::InvalidBodyLength)
        );
        assert_eq!(
            decode_success_status_response(&[0, 0, 0, 0, 1, 0, 0]),
            Err(LocalAgentStatusResponseDecodeError::UnknownRuntimeState)
        );
        assert_eq!(
            decode_success_status_response(&[0, 0, 2, 0, 2, 0, 0]),
            Err(LocalAgentStatusResponseDecodeError::UnsupportedProtocolVersion)
        );
    }
}
