//! Pure Phase 015 command-request payload codec.
//!
//! The two current read-only local commands have no request arguments. Their
//! opaque Phase 007 payload is therefore exactly one unsigned 16-bit command
//! identifier in big-endian order.

use std::fmt;

use super::LocalAgentCommand;

/// Exact byte length of a Phase 015 local command request payload.
pub const LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH: usize = 2;

/// Encodes one read-only local Agent command into its exact request payload.
#[must_use]
pub const fn encode_request_command(
    command: LocalAgentCommand,
) -> [u8; LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH] {
    command.code().to_be_bytes()
}

/// Decodes one exact Phase 015 local command request payload.
///
/// # Errors
///
/// Returns [`LocalAgentRequestDecodeError::InvalidLength`] unless `payload`
/// contains exactly two bytes, or [`LocalAgentRequestDecodeError::UnknownCommand`]
/// when the encoded command identifier is not part of the active read-only
/// command namespace.
pub fn decode_request_command(
    payload: &[u8],
) -> Result<LocalAgentCommand, LocalAgentRequestDecodeError> {
    let bytes: [u8; LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH] = payload
        .try_into()
        .map_err(|_| LocalAgentRequestDecodeError::InvalidLength)?;
    let code = u16::from_be_bytes(bytes);
    LocalAgentCommand::from_code(code).ok_or(LocalAgentRequestDecodeError::UnknownCommand)
}

/// Fail-closed command request payload decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentRequestDecodeError {
    /// Request payload is not exactly two bytes.
    InvalidLength,
    /// Command identifier is not defined by the active local command namespace.
    UnknownCommand,
}

impl fmt::Display for LocalAgentRequestDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => {
                formatter.write_str("local Agent command payload must be exactly two bytes")
            }
            Self::UnknownCommand => formatter.write_str("unknown local Agent command identifier"),
        }
    }
}

impl std::error::Error for LocalAgentRequestDecodeError {}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH, LocalAgentRequestDecodeError, decode_request_command,
        encode_request_command,
    };
    use crate::local_commands::LocalAgentCommand;

    #[test]
    fn command_payload_length_is_locked() {
        assert_eq!(LOCAL_AGENT_REQUEST_PAYLOAD_LENGTH, 2);
    }

    #[test]
    fn commands_encode_as_big_endian_u16_codes() {
        assert_eq!(
            encode_request_command(LocalAgentCommand::GetAgentStatus),
            [0, 1]
        );
        assert_eq!(
            encode_request_command(LocalAgentCommand::GetPrivateDnsConfig),
            [0, 2]
        );
    }

    #[test]
    fn current_commands_round_trip() {
        for command in [
            LocalAgentCommand::GetAgentStatus,
            LocalAgentCommand::GetPrivateDnsConfig,
        ] {
            let encoded = encode_request_command(command);
            assert_eq!(decode_request_command(&encoded), Ok(command));
        }
    }

    #[test]
    fn wrong_payload_length_is_rejected() {
        assert_eq!(
            decode_request_command(&[]),
            Err(LocalAgentRequestDecodeError::InvalidLength)
        );
        assert_eq!(
            decode_request_command(&[0, 1, 0]),
            Err(LocalAgentRequestDecodeError::InvalidLength)
        );
    }

    #[test]
    fn unknown_command_code_is_rejected() {
        assert_eq!(
            decode_request_command(&[0, 3]),
            Err(LocalAgentRequestDecodeError::UnknownCommand)
        );
    }
}
