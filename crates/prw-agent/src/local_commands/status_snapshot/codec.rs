//! Fixed-width byte codec for the minimal local Agent status snapshot.

use super::{LocalAgentRuntimeState, LocalAgentStatusSnapshot};
use crate::LocalIpcProtocolVersion;

/// Exact Phase 018 status-body length in bytes.
pub const LOCAL_AGENT_STATUS_BODY_LENGTH: usize = 5;

/// Encodes one minimal Agent status snapshot into the locked Phase 018 body.
#[must_use]
pub const fn encode_status_snapshot(
    snapshot: LocalAgentStatusSnapshot,
) -> [u8; LOCAL_AGENT_STATUS_BODY_LENGTH] {
    let major = snapshot.protocol_version().major().to_be_bytes();
    let minor = snapshot.protocol_version().minor().to_be_bytes();

    [
        snapshot.runtime_state().code(),
        major[0],
        major[1],
        minor[0],
        minor[1],
    ]
}

/// Decodes one exact Phase 018 status body.
///
/// # Errors
///
/// Returns [`LocalAgentStatusDecodeError::InvalidLength`] unless `payload` is
/// exactly five bytes, [`LocalAgentStatusDecodeError::UnknownRuntimeState`]
/// for an unrecognized runtime-state identifier, or
/// [`LocalAgentStatusDecodeError::UnsupportedProtocolVersion`] when the body
/// does not name the exact local IPC version supported by this build.
pub const fn decode_status_snapshot(
    payload: &[u8],
) -> Result<LocalAgentStatusSnapshot, LocalAgentStatusDecodeError> {
    if payload.len() != LOCAL_AGENT_STATUS_BODY_LENGTH {
        return Err(LocalAgentStatusDecodeError::InvalidLength);
    }

    let Some(runtime_state) = LocalAgentRuntimeState::from_code(payload[0]) else {
        return Err(LocalAgentStatusDecodeError::UnknownRuntimeState);
    };
    let version = LocalIpcProtocolVersion::from_parts(
        u16::from_be_bytes([payload[1], payload[2]]),
        u16::from_be_bytes([payload[3], payload[4]]),
    );
    if !version.is_supported() {
        return Err(LocalAgentStatusDecodeError::UnsupportedProtocolVersion);
    }

    Ok(LocalAgentStatusSnapshot::current(runtime_state))
}

/// Fail-closed Phase 018 Agent-status decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusDecodeError {
    /// Body length is not exactly five bytes.
    InvalidLength,
    /// Runtime-state identifier is not part of the locked Phase 017 mapping.
    UnknownRuntimeState,
    /// Protocol version differs from the exact local IPC version supported here.
    UnsupportedProtocolVersion,
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_AGENT_STATUS_BODY_LENGTH, LocalAgentStatusDecodeError, decode_status_snapshot,
        encode_status_snapshot,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    #[test]
    fn body_length_is_locked_to_five_bytes() {
        assert_eq!(LOCAL_AGENT_STATUS_BODY_LENGTH, 5);
    }

    #[test]
    fn ready_status_has_stable_current_wire_bytes() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        assert_eq!(encode_status_snapshot(snapshot), [2, 0, 1, 0, 0]);
    }

    #[test]
    fn all_runtime_states_round_trip() {
        for state in [
            LocalAgentRuntimeState::Starting,
            LocalAgentRuntimeState::Ready,
            LocalAgentRuntimeState::Degraded,
            LocalAgentRuntimeState::Stopping,
        ] {
            let snapshot = LocalAgentStatusSnapshot::current(state);
            let encoded = encode_status_snapshot(snapshot);
            assert_eq!(decode_status_snapshot(&encoded), Ok(snapshot));
        }
    }

    #[test]
    fn non_exact_lengths_are_rejected() {
        assert_eq!(
            decode_status_snapshot(&[2, 0, 1, 0]),
            Err(LocalAgentStatusDecodeError::InvalidLength)
        );
        assert_eq!(
            decode_status_snapshot(&[2, 0, 1, 0, 0, 0]),
            Err(LocalAgentStatusDecodeError::InvalidLength)
        );
    }

    #[test]
    fn unknown_runtime_state_is_rejected() {
        assert_eq!(
            decode_status_snapshot(&[0, 0, 1, 0, 0]),
            Err(LocalAgentStatusDecodeError::UnknownRuntimeState)
        );
    }

    #[test]
    fn unsupported_protocol_versions_are_rejected() {
        assert_eq!(
            decode_status_snapshot(&[2, 0, 2, 0, 0]),
            Err(LocalAgentStatusDecodeError::UnsupportedProtocolVersion)
        );
        assert_eq!(
            decode_status_snapshot(&[2, 0, 1, 0, 1]),
            Err(LocalAgentStatusDecodeError::UnsupportedProtocolVersion)
        );
    }
}
