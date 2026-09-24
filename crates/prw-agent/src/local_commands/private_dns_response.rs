//! Complete in-memory successful `GetPrivateDnsConfig` response frame.

pub mod stream;

use crate::LocalIpcRequestId;
use crate::frame_object::LocalIpcFrame;

use super::LocalAgentResponseStatus;
use super::private_dns_codec::{
    LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH, LocalPrivateDnsDecodeError, LocalPrivateDnsEncodeError,
    decode_private_dns_snapshot, encode_private_dns_snapshot,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::response_codec::LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH;
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
use super::terminal_response::{LocalTerminalResponseError, validate_terminal_response_frame};

/// Maximum successful `GetPrivateDnsConfig` payload length, including `Ok` prefix.
pub const LOCAL_PRIVATE_DNS_MAX_SUCCESS_PAYLOAD_LENGTH: usize =
    LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH + LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH;
/// Maximum complete wire length with the 24-byte local IPC frame header.
pub const LOCAL_PRIVATE_DNS_MAX_SUCCESS_WIRE_LENGTH: usize =
    24 + LOCAL_PRIVATE_DNS_MAX_SUCCESS_PAYLOAD_LENGTH;

/// Typed successful `GetPrivateDnsConfig` response-frame result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrivateDnsFrame {
    request_id: LocalIpcRequestId,
    snapshot: LocalPrivateDnsSnapshot,
}

impl LocalPrivateDnsFrame {
    /// Returns the correlated non-zero request identifier.
    #[must_use]
    pub const fn request_id(&self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the decoded bounded private-DNS snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &LocalPrivateDnsSnapshot {
        &self.snapshot
    }
}

/// Builds one complete successful `GetPrivateDnsConfig` response frame.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsFrameBuildError::Encode`] if defensive Phase 027
/// snapshot encoding fails or [`LocalPrivateDnsFrameBuildError::Frame`] if the
/// generic Phase 022 terminal-response builder rejects the encoded body.
pub fn build_success_private_dns_frame(
    request_id: LocalIpcRequestId,
    snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalIpcFrame, LocalPrivateDnsFrameBuildError> {
    let body =
        encode_private_dns_snapshot(snapshot).map_err(LocalPrivateDnsFrameBuildError::Encode)?;
    build_terminal_response_frame(request_id, LocalAgentResponseStatus::Ok, &body)
        .map_err(LocalPrivateDnsFrameBuildError::Frame)
}

/// Decodes one complete successful `GetPrivateDnsConfig` response frame.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsFrameDecodeError::Terminal`] when the Phase 020
/// terminal-frame invariant fails,
/// [`LocalPrivateDnsFrameDecodeError::NonSuccessStatus`] for a valid terminal
/// error frame, or [`LocalPrivateDnsFrameDecodeError::Body`] when the Phase 027
/// private-DNS body fails bounded decoding.
pub fn decode_success_private_dns_frame(
    frame: &LocalIpcFrame,
) -> Result<LocalPrivateDnsFrame, LocalPrivateDnsFrameDecodeError> {
    let terminal = validate_terminal_response_frame(frame)
        .map_err(LocalPrivateDnsFrameDecodeError::Terminal)?;
    if !terminal.status().is_success() {
        return Err(LocalPrivateDnsFrameDecodeError::NonSuccessStatus);
    }

    let body = &frame.payload().as_bytes()[LOCAL_AGENT_RESPONSE_STATUS_PREFIX_LENGTH..];
    let snapshot =
        decode_private_dns_snapshot(body).map_err(LocalPrivateDnsFrameDecodeError::Body)?;

    Ok(LocalPrivateDnsFrame {
        request_id: terminal.request_id(),
        snapshot,
    })
}

/// Phase 028 complete private-DNS frame construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsFrameBuildError {
    /// Phase 027 bounded snapshot encoding failed defensively.
    Encode(LocalPrivateDnsEncodeError),
    /// Phase 022 terminal frame construction failed.
    Frame(LocalTerminalResponseBuildError),
}

/// Phase 028 complete private-DNS frame decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsFrameDecodeError {
    /// Outer terminal response framing/status invariant failed.
    Terminal(LocalTerminalResponseError),
    /// Frame is a valid terminal response but carries a non-success status.
    NonSuccessStatus,
    /// Command-specific bounded private-DNS body failed Phase 027 decoding.
    Body(LocalPrivateDnsDecodeError),
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_PRIVATE_DNS_MAX_SUCCESS_PAYLOAD_LENGTH, LOCAL_PRIVATE_DNS_MAX_SUCCESS_WIRE_LENGTH,
        LocalPrivateDnsFrameDecodeError, build_success_private_dns_frame,
        decode_success_private_dns_frame,
    };
    use crate::LocalIpcMessageKind;
    use crate::LocalIpcRequestId;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::private_dns_codec::{
        LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH, LocalPrivateDnsDecodeError,
        encode_private_dns_snapshot,
    };
    use crate::local_commands::private_dns_snapshot::{
        LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES, LOCAL_PRIVATE_DNS_MAX_RESOLVERS,
        LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES, LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS,
        LocalPrivateDnsSnapshot,
    };
    use crate::local_commands::terminal_response::builder::build_terminal_response_frame;
    use prw_network::PrivateDnsConfig;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn snapshot(config: &PrivateDnsConfig) -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(config).expect("bounded test config")
    }

    #[test]
    fn locked_maximum_lengths_are_consistent() {
        assert_eq!(LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH, 18_403);
        assert_eq!(LOCAL_PRIVATE_DNS_MAX_SUCCESS_PAYLOAD_LENGTH, 18_405);
        assert_eq!(LOCAL_PRIVATE_DNS_MAX_SUCCESS_WIRE_LENGTH, 18_429);
    }

    #[test]
    fn default_snapshot_builds_stable_success_payload() {
        let snapshot = snapshot(&PrivateDnsConfig::default());
        let frame = build_success_private_dns_frame(id(100), &snapshot).expect("valid DNS frame");

        assert_eq!(frame.header().kind(), LocalIpcMessageKind::Response);
        assert_eq!(frame.header().request_id(), id(100));
        assert_eq!(frame.header().payload_length(), 5);
        assert_eq!(frame.payload().as_bytes(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn bounded_utf8_snapshot_round_trips_through_complete_frame() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into(), "fd00::53".into()],
            split_domains: vec!["corp.example".into(), "láb.example".into()],
        };
        let snapshot = snapshot(&config);
        let frame = build_success_private_dns_frame(id(101), &snapshot).expect("valid DNS frame");
        let decoded = decode_success_private_dns_frame(&frame).expect("DNS frame decodes");

        assert_eq!(decoded.request_id(), id(101));
        assert_eq!(decoded.snapshot(), &snapshot);
    }

    #[test]
    fn maximum_snapshot_fits_locked_success_payload() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec![
                "r".repeat(LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES);
                LOCAL_PRIVATE_DNS_MAX_RESOLVERS
            ],
            split_domains: vec![
                "d".repeat(LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES);
                LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS
            ],
        };
        let snapshot = snapshot(&config);
        let encoded = encode_private_dns_snapshot(&snapshot).expect("maximum snapshot encodes");
        let frame =
            build_success_private_dns_frame(id(102), &snapshot).expect("maximum frame fits");

        assert_eq!(encoded.len(), LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH);
        assert_eq!(
            usize::try_from(frame.header().payload_length()).expect("u32 fits usize"),
            LOCAL_PRIVATE_DNS_MAX_SUCCESS_PAYLOAD_LENGTH
        );
        assert_eq!(
            decode_success_private_dns_frame(&frame)
                .expect("decodes")
                .snapshot(),
            &snapshot
        );
    }

    #[test]
    fn valid_terminal_error_is_not_a_success_private_dns_frame() {
        let frame = build_terminal_response_frame(id(103), LocalAgentResponseStatus::Conflict, &[])
            .expect("valid terminal error");

        assert_eq!(
            decode_success_private_dns_frame(&frame),
            Err(LocalPrivateDnsFrameDecodeError::NonSuccessStatus)
        );
    }

    #[test]
    fn malformed_private_dns_body_is_rejected_after_terminal_validation() {
        let frame =
            build_terminal_response_frame(id(104), LocalAgentResponseStatus::Ok, &[0b100, 0, 0])
                .expect("structurally valid response");

        assert_eq!(
            decode_success_private_dns_frame(&frame),
            Err(LocalPrivateDnsFrameDecodeError::Body(
                LocalPrivateDnsDecodeError::ReservedFlagsSet
            ))
        );
    }
}
