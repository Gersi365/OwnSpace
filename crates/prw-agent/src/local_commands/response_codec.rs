//! Pure Phase 016 response-status prefix codec.
//!
//! Every future local Agent terminal response payload begins with one unsigned
//! 16-bit Phase 008 response-status identifier in big-endian order. Any bytes
//! after the prefix remain command-specific body bytes.

use std::fmt;

use super::LocalAgentResponseStatus;

/// Exact byte length of the Phase 016 local response-status prefix.
pub const LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH: usize = 2;

/// Encodes one typed response status into its exact two-byte prefix.
#[must_use]
pub const fn encode_response_status(
    status: LocalAgentResponseStatus,
) -> [u8; LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH] {
    status.code().to_be_bytes()
}

/// Decodes the response-status prefix and returns the untouched body bytes.
///
/// # Errors
///
/// Returns [`LocalAgentResponseDecodeError::MissingStatus`] when fewer than two
/// bytes are supplied, or [`LocalAgentResponseDecodeError::UnknownStatus`] when
/// the encoded status identifier is not part of the active response taxonomy.
pub fn decode_response_status_prefix(
    payload: &[u8],
) -> Result<(LocalAgentResponseStatus, &[u8]), LocalAgentResponseDecodeError> {
    let prefix = payload
        .get(..LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH)
        .ok_or(LocalAgentResponseDecodeError::MissingStatus)?;
    let code = u16::from_be_bytes([prefix[0], prefix[1]]);
    let status = LocalAgentResponseStatus::from_code(code)
        .ok_or(LocalAgentResponseDecodeError::UnknownStatus)?;
    Ok((
        status,
        &payload[LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH..],
    ))
}

/// Fail-closed response status prefix decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentResponseDecodeError {
    /// Fewer than two bytes are available for the mandatory status prefix.
    MissingStatus,
    /// Status identifier is not defined by the active response taxonomy.
    UnknownStatus,
}

impl fmt::Display for LocalAgentResponseDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStatus => formatter.write_str("local Agent response status is missing"),
            Self::UnknownStatus => formatter.write_str("unknown local Agent response status"),
        }
    }
}

impl std::error::Error for LocalAgentResponseDecodeError {}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH, LocalAgentResponseDecodeError,
        decode_response_status_prefix, encode_response_status,
    };
    use crate::local_commands::LocalAgentResponseStatus;

    #[test]
    fn response_status_prefix_length_is_locked() {
        assert_eq!(LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH, 2);
    }

    #[test]
    fn response_status_codes_encode_big_endian() {
        assert_eq!(encode_response_status(LocalAgentResponseStatus::Ok), [0, 0]);
        assert_eq!(
            encode_response_status(LocalAgentResponseStatus::InternalError),
            [0, 5]
        );
    }

    #[test]
    fn all_current_statuses_round_trip() {
        for status in [
            LocalAgentResponseStatus::Ok,
            LocalAgentResponseStatus::InvalidRequest,
            LocalAgentResponseStatus::Unauthorized,
            LocalAgentResponseStatus::UnsupportedCommand,
            LocalAgentResponseStatus::Conflict,
            LocalAgentResponseStatus::InternalError,
        ] {
            let encoded = encode_response_status(status);
            assert_eq!(
                decode_response_status_prefix(&encoded),
                Ok((status, &[][..]))
            );
        }
    }

    #[test]
    fn decoder_preserves_body_bytes_unchanged() {
        let mut payload = encode_response_status(LocalAgentResponseStatus::Ok).to_vec();
        payload.extend_from_slice(&[9, 8, 7]);

        assert_eq!(
            decode_response_status_prefix(&payload),
            Ok((LocalAgentResponseStatus::Ok, &[9, 8, 7][..]))
        );
    }

    #[test]
    fn missing_status_prefix_is_rejected() {
        assert_eq!(
            decode_response_status_prefix(&[]),
            Err(LocalAgentResponseDecodeError::MissingStatus)
        );
        assert_eq!(
            decode_response_status_prefix(&[0]),
            Err(LocalAgentResponseDecodeError::MissingStatus)
        );
    }

    #[test]
    fn unknown_status_code_is_rejected() {
        assert_eq!(
            decode_response_status_prefix(&[0, 6]),
            Err(LocalAgentResponseDecodeError::UnknownStatus)
        );
    }
}
