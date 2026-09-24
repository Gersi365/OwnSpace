//! Pure in-memory PRWA v1.0 logical-session authentication codec over Phase 129 PRWC frames.
//!
//! This module maps bounded typed authentication values to and from the C03e-CA-selected
//! `ControlMessageKind::{Authentication, Response, Error}` envelopes. It performs no socket I/O,
//! request-id allocation, challenge generation, proof verification, registry access, session
//! binding, requester routing, candidate publication, or runtime activation.

use std::fmt;

use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentitySignature, DeviceIdentitySignatureEncoding,
    session_auth::{
        MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS, MAX_SESSION_AUTH_IDENTIFIER_BYTES,
        SESSION_AUTH_NONCE_LEN, SessionAuthNonce,
    },
};
use prw_control_transport::{
    ControlFrame, ControlFrameError, ControlMessageKind, MAX_CONTROL_PAYLOAD_BYTES,
};
use prw_core::{DeviceId, SessionId};

/// C03e-CA PRWC-specific pre-mesh authentication payload magic.
pub const CONTROL_SESSION_AUTH_MAGIC: [u8; 4] = *b"PRWA";
/// Initial PRWA protocol major version.
pub const CONTROL_SESSION_AUTH_MAJOR: u16 = 1;
/// Initial PRWA protocol minor version.
pub const CONTROL_SESSION_AUTH_MINOR: u16 = 0;
/// Fixed PRWA header length.
pub const CONTROL_SESSION_AUTH_HEADER_BYTES: usize = 12;
/// Maximum locked-profile DER signature bytes carried by PRWA v1.0.
pub const MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES: usize = 256;

/// Exact maximum PRWA Begin payload bytes.
pub const MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES: usize =
    CONTROL_SESSION_AUTH_HEADER_BYTES + 2 + MAX_SESSION_AUTH_IDENTIFIER_BYTES;
/// Exact maximum PRWA Challenge payload bytes.
pub const MAX_CONTROL_SESSION_AUTH_CHALLENGE_BYTES: usize = CONTROL_SESSION_AUTH_HEADER_BYTES
    + 2
    + MAX_SESSION_AUTH_IDENTIFIER_BYTES
    + SESSION_AUTH_NONCE_LEN
    + 8
    + 8;
/// Exact maximum PRWA Proof payload bytes.
pub const MAX_CONTROL_SESSION_AUTH_PROOF_BYTES: usize = CONTROL_SESSION_AUTH_HEADER_BYTES
    + 2
    + MAX_SESSION_AUTH_IDENTIFIER_BYTES
    + SESSION_AUTH_NONCE_LEN
    + 2
    + 2
    + 2
    + MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES;
/// Exact maximum PRWA Authenticated payload bytes.
pub const MAX_CONTROL_SESSION_AUTH_AUTHENTICATED_BYTES: usize =
    CONTROL_SESSION_AUTH_HEADER_BYTES + 2 + MAX_SESSION_AUTH_IDENTIFIER_BYTES;
/// Exact PRWA Rejected payload bytes.
pub const CONTROL_SESSION_AUTH_REJECTED_BYTES: usize = CONTROL_SESSION_AUTH_HEADER_BYTES;

const BEGIN_OPERATION: u16 = 1;
const CHALLENGE_OPERATION: u16 = 2;
const PROOF_OPERATION: u16 = 3;
const AUTHENTICATED_OPERATION: u16 = 4;
const REJECTED_OPERATION: u16 = 5;
const ECDSA_P256_SHA256_CODE: u16 = 1;
const ECDSA_SIG_VALUE_DER_CODE: u16 = 1;

/// One structurally valid PRWA v1.0 authentication message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSessionAuthenticationMessage {
    /// Client-originated untrusted logical-device selector.
    Begin { device_id: DeviceId },
    /// Server/verifier-issued typed challenge fields.
    Challenge {
        session_id: SessionId,
        nonce: SessionAuthNonce,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    },
    /// Client-originated proof fields for the locked initial device-signature profile.
    Proof {
        session_id: SessionId,
        nonce: SessionAuthNonce,
        signature: DeviceIdentitySignature,
    },
    /// Terminal successful authentication correlation carrying only the completed session ID.
    Authenticated { session_id: SessionId },
    /// Terminal generic authentication rejection with no detailed external reason.
    Rejected,
}

impl ControlSessionAuthenticationMessage {
    const fn operation(&self) -> u16 {
        match self {
            Self::Begin { .. } => BEGIN_OPERATION,
            Self::Challenge { .. } => CHALLENGE_OPERATION,
            Self::Proof { .. } => PROOF_OPERATION,
            Self::Authenticated { .. } => AUTHENTICATED_OPERATION,
            Self::Rejected => REJECTED_OPERATION,
        }
    }

    const fn outer_kind(&self) -> ControlMessageKind {
        match self {
            Self::Begin { .. } | Self::Challenge { .. } | Self::Proof { .. } => {
                ControlMessageKind::Authentication
            }
            Self::Authenticated { .. } => ControlMessageKind::Response,
            Self::Rejected => ControlMessageKind::Error,
        }
    }
}

/// Stable failure classification at the pure PRWA codec boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlSessionAuthenticationWireError {
    /// Outer Phase 129 message kind did not match the decoded PRWA operation.
    InvalidOuterKind,
    /// PRWA structure, bounds, UTF-8, typed identifier, lifetime, or trailing data were invalid.
    InvalidPayload,
    /// A Proof used a device-signature profile other than the locked PRWA v1.0 profile.
    UnsupportedSignatureProfile,
    /// Existing Phase 129 frame construction rejected the request ID or payload.
    Frame(ControlFrameError),
}

impl fmt::Display for ControlSessionAuthenticationWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOuterKind => "invalid outer PRWC kind for PRWA authentication message",
            Self::InvalidPayload => "invalid PRWA authentication payload",
            Self::UnsupportedSignatureProfile => {
                "unsupported PRWA authentication signature profile"
            }
            Self::Frame(_) => "failed to construct PRWA control frame",
        })
    }
}

impl std::error::Error for ControlSessionAuthenticationWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            _ => None,
        }
    }
}

/// Encodes one complete PRWA message into an existing bounded Phase 129 control frame.
///
/// The supplied request ID is preserved exactly. Allocation/custody remains outside this codec.
///
/// # Errors
///
/// Rejects invalid typed-field bounds, challenge lifetime, unsupported signature profile, or an
/// outer frame rejected by existing Phase 129 validation.
pub fn encode_control_session_authentication_frame(
    request_id: u64,
    message: &ControlSessionAuthenticationMessage,
) -> Result<ControlFrame, ControlSessionAuthenticationWireError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&CONTROL_SESSION_AUTH_MAGIC);
    payload.extend_from_slice(&CONTROL_SESSION_AUTH_MAJOR.to_be_bytes());
    payload.extend_from_slice(&CONTROL_SESSION_AUTH_MINOR.to_be_bytes());
    payload.extend_from_slice(&message.operation().to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    match message {
        ControlSessionAuthenticationMessage::Begin { device_id } => {
            push_identifier(&mut payload, device_id.as_str())?;
        }
        ControlSessionAuthenticationMessage::Challenge {
            session_id,
            nonce,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        } => {
            validate_challenge_lifetime(*issued_at_unix_seconds, *expires_at_unix_seconds)?;
            push_identifier(&mut payload, session_id.as_str())?;
            payload.extend_from_slice(nonce.as_bytes());
            payload.extend_from_slice(&issued_at_unix_seconds.to_be_bytes());
            payload.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
        }
        ControlSessionAuthenticationMessage::Proof {
            session_id,
            nonce,
            signature,
        } => {
            validate_signature_profile(signature)?;
            push_identifier(&mut payload, session_id.as_str())?;
            payload.extend_from_slice(nonce.as_bytes());
            payload.extend_from_slice(&ECDSA_P256_SHA256_CODE.to_be_bytes());
            payload.extend_from_slice(&ECDSA_SIG_VALUE_DER_CODE.to_be_bytes());
            push_signature(&mut payload, signature.as_bytes())?;
        }
        ControlSessionAuthenticationMessage::Authenticated { session_id } => {
            push_identifier(&mut payload, session_id.as_str())?;
        }
        ControlSessionAuthenticationMessage::Rejected => {}
    }

    ControlFrame::new(message.outer_kind(), request_id, payload)
        .map_err(ControlSessionAuthenticationWireError::Frame)
}

/// Decodes one complete PRWA v1.0 message from an already-decoded Phase 129 control frame.
///
/// Successful decode proves only bounded structural and typed-value validity. It does not prove
/// enrollment, current registry state, signature validity, logical authentication, authorization,
/// or requester/rendezvous authority.
///
/// # Errors
///
/// Rejects malformed metadata, unsupported versions/operations, wrong outer-kind pairing,
/// invalid bounds or typed values, unsupported signature tags, truncation, or trailing bytes.
pub fn decode_control_session_authentication_frame(
    frame: &ControlFrame,
) -> Result<ControlSessionAuthenticationMessage, ControlSessionAuthenticationWireError> {
    let mut decoder = Decoder::new(frame.payload());
    if decoder.take(4)? != CONTROL_SESSION_AUTH_MAGIC.as_slice()
        || decoder.u16()? != CONTROL_SESSION_AUTH_MAJOR
        || decoder.u16()? != CONTROL_SESSION_AUTH_MINOR
    {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }
    let operation = decoder.u16()?;
    if decoder.u16()? != 0 {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }

    let (expected_outer_kind, message) = match operation {
        BEGIN_OPERATION => {
            let device_id = DeviceId::new(decoder.identifier()?)
                .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
            (
                ControlMessageKind::Authentication,
                ControlSessionAuthenticationMessage::Begin { device_id },
            )
        }
        CHALLENGE_OPERATION => {
            let session_id = SessionId::new(decoder.identifier()?)
                .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
            let nonce = decode_nonce(&mut decoder)?;
            let issued_at_unix_seconds = decoder.u64()?;
            let expires_at_unix_seconds = decoder.u64()?;
            validate_challenge_lifetime(issued_at_unix_seconds, expires_at_unix_seconds)?;
            (
                ControlMessageKind::Authentication,
                ControlSessionAuthenticationMessage::Challenge {
                    session_id,
                    nonce,
                    issued_at_unix_seconds,
                    expires_at_unix_seconds,
                },
            )
        }
        PROOF_OPERATION => {
            let session_id = SessionId::new(decoder.identifier()?)
                .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
            let nonce = decode_nonce(&mut decoder)?;
            if decoder.u16()? != ECDSA_P256_SHA256_CODE
                || decoder.u16()? != ECDSA_SIG_VALUE_DER_CODE
            {
                return Err(ControlSessionAuthenticationWireError::UnsupportedSignatureProfile);
            }
            let signature_len = usize::from(decoder.u16()?);
            if signature_len == 0 || signature_len > MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES {
                return Err(ControlSessionAuthenticationWireError::InvalidPayload);
            }
            let signature = DeviceIdentitySignature::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
                decoder.take(signature_len)?.to_vec(),
            )
            .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
            (
                ControlMessageKind::Authentication,
                ControlSessionAuthenticationMessage::Proof {
                    session_id,
                    nonce,
                    signature,
                },
            )
        }
        AUTHENTICATED_OPERATION => {
            let session_id = SessionId::new(decoder.identifier()?)
                .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
            (
                ControlMessageKind::Response,
                ControlSessionAuthenticationMessage::Authenticated { session_id },
            )
        }
        REJECTED_OPERATION => (
            ControlMessageKind::Error,
            ControlSessionAuthenticationMessage::Rejected,
        ),
        _ => return Err(ControlSessionAuthenticationWireError::InvalidPayload),
    };

    decoder.finish()?;
    if frame.kind() != expected_outer_kind {
        return Err(ControlSessionAuthenticationWireError::InvalidOuterKind);
    }
    Ok(message)
}

fn validate_signature_profile(
    signature: &DeviceIdentitySignature,
) -> Result<(), ControlSessionAuthenticationWireError> {
    if signature.algorithm() != DeviceIdentityAlgorithm::EcdsaP256Sha256
        || signature.encoding() != DeviceIdentitySignatureEncoding::EcdsaSigValueDer
    {
        return Err(ControlSessionAuthenticationWireError::UnsupportedSignatureProfile);
    }
    let len = signature.as_bytes().len();
    if len == 0 || len > MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }
    Ok(())
}

fn validate_challenge_lifetime(
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<(), ControlSessionAuthenticationWireError> {
    let lifetime = expires_at_unix_seconds
        .checked_sub(issued_at_unix_seconds)
        .ok_or(ControlSessionAuthenticationWireError::InvalidPayload)?;
    if lifetime == 0 || lifetime > MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }
    Ok(())
}

fn push_identifier(
    output: &mut Vec<u8>,
    value: &str,
) -> Result<(), ControlSessionAuthenticationWireError> {
    let len = value.len();
    if len == 0 || len > MAX_SESSION_AUTH_IDENTIFIER_BYTES || value.trim().is_empty() {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }
    let len =
        u16::try_from(len).map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_signature(
    output: &mut Vec<u8>,
    signature: &[u8],
) -> Result<(), ControlSessionAuthenticationWireError> {
    if signature.is_empty() || signature.len() > MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES {
        return Err(ControlSessionAuthenticationWireError::InvalidPayload);
    }
    let len = u16::try_from(signature.len())
        .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(signature);
    Ok(())
}

fn decode_nonce(
    decoder: &mut Decoder<'_>,
) -> Result<SessionAuthNonce, ControlSessionAuthenticationWireError> {
    SessionAuthNonce::try_from_slice(decoder.take(SESSION_AUTH_NONCE_LEN)?)
        .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ControlSessionAuthenticationWireError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(ControlSessionAuthenticationWireError::InvalidPayload)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(ControlSessionAuthenticationWireError::InvalidPayload)?;
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, ControlSessionAuthenticationWireError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, ControlSessionAuthenticationWireError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn identifier(&mut self) -> Result<String, ControlSessionAuthenticationWireError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_SESSION_AUTH_IDENTIFIER_BYTES {
            return Err(ControlSessionAuthenticationWireError::InvalidPayload);
        }
        let value = std::str::from_utf8(self.take(len)?)
            .map_err(|_| ControlSessionAuthenticationWireError::InvalidPayload)?;
        if value.trim().is_empty() {
            return Err(ControlSessionAuthenticationWireError::InvalidPayload);
        }
        Ok(value.to_owned())
    }

    const fn finish(self) -> Result<(), ControlSessionAuthenticationWireError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(ControlSessionAuthenticationWireError::InvalidPayload)
        }
    }
}

const _: () = {
    assert!(MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES <= MAX_CONTROL_PAYLOAD_BYTES);
    assert!(MAX_CONTROL_SESSION_AUTH_CHALLENGE_BYTES <= MAX_CONTROL_PAYLOAD_BYTES);
    assert!(MAX_CONTROL_SESSION_AUTH_PROOF_BYTES <= MAX_CONTROL_PAYLOAD_BYTES);
    assert!(MAX_CONTROL_SESSION_AUTH_AUTHENTICATED_BYTES <= MAX_CONTROL_PAYLOAD_BYTES);
    assert!(CONTROL_SESSION_AUTH_REJECTED_BYTES <= MAX_CONTROL_PAYLOAD_BYTES);
};

#[cfg(test)]
mod tests {
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentitySignature, DeviceIdentitySignatureEncoding,
        session_auth::{MAX_SESSION_AUTH_IDENTIFIER_BYTES, SessionAuthNonce},
    };
    use prw_control_transport::{ControlFrame, ControlMessageKind, MAX_CONTROL_PAYLOAD_BYTES};
    use prw_core::{DeviceId, SessionId};

    use super::{
        CONTROL_SESSION_AUTH_HEADER_BYTES, CONTROL_SESSION_AUTH_MAGIC,
        CONTROL_SESSION_AUTH_REJECTED_BYTES, ControlSessionAuthenticationMessage,
        ControlSessionAuthenticationWireError, MAX_CONTROL_SESSION_AUTH_AUTHENTICATED_BYTES,
        MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES, MAX_CONTROL_SESSION_AUTH_CHALLENGE_BYTES,
        MAX_CONTROL_SESSION_AUTH_PROOF_BYTES, MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES,
        decode_control_session_authentication_frame, encode_control_session_authentication_frame,
    };

    fn nonce(byte: u8) -> SessionAuthNonce {
        SessionAuthNonce::new([byte; 32])
    }

    fn signature(bytes: Vec<u8>) -> DeviceIdentitySignature {
        DeviceIdentitySignature::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
            bytes,
        )
        .expect("non-empty signature")
    }

    #[test]
    fn begin_has_exact_selected_golden_layout_and_preserves_request_id() {
        let message = ControlSessionAuthenticationMessage::Begin {
            device_id: DeviceId::new("device-1").expect("device id"),
        };
        let frame = encode_control_session_authentication_frame(41, &message).expect("encode");

        let mut expected = Vec::new();
        expected.extend_from_slice(&CONTROL_SESSION_AUTH_MAGIC);
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&8_u16.to_be_bytes());
        expected.extend_from_slice(b"device-1");

        assert_eq!(frame.kind(), ControlMessageKind::Authentication);
        assert_eq!(frame.request_id(), 41);
        assert_eq!(frame.payload(), expected);
        assert_eq!(
            decode_control_session_authentication_frame(&frame).expect("decode"),
            message
        );
    }

    #[test]
    fn every_selected_operation_round_trips_with_exact_outer_kind() {
        let messages = [
            (
                ControlSessionAuthenticationMessage::Challenge {
                    session_id: SessionId::new("session-1").expect("session id"),
                    nonce: nonce(7),
                    issued_at_unix_seconds: 1_000,
                    expires_at_unix_seconds: 1_300,
                },
                ControlMessageKind::Authentication,
            ),
            (
                ControlSessionAuthenticationMessage::Proof {
                    session_id: SessionId::new("session-1").expect("session id"),
                    nonce: nonce(7),
                    signature: signature(vec![0x30, 0x01, 0x01]),
                },
                ControlMessageKind::Authentication,
            ),
            (
                ControlSessionAuthenticationMessage::Authenticated {
                    session_id: SessionId::new("session-1").expect("session id"),
                },
                ControlMessageKind::Response,
            ),
            (
                ControlSessionAuthenticationMessage::Rejected,
                ControlMessageKind::Error,
            ),
        ];

        for (message, expected_kind) in messages {
            let frame = encode_control_session_authentication_frame(99, &message).expect("encode");
            assert_eq!(frame.kind(), expected_kind);
            assert_eq!(frame.request_id(), 99);
            assert_eq!(
                decode_control_session_authentication_frame(&frame).expect("decode"),
                message
            );
        }
    }

    #[test]
    fn wrong_outer_kind_fails_closed() {
        let valid = encode_control_session_authentication_frame(
            7,
            &ControlSessionAuthenticationMessage::Begin {
                device_id: DeviceId::new("device-1").expect("device id"),
            },
        )
        .expect("encode");
        let wrong = ControlFrame::new(ControlMessageKind::Command, 7, valid.payload().to_vec())
            .expect("frame");

        assert_eq!(
            decode_control_session_authentication_frame(&wrong),
            Err(ControlSessionAuthenticationWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn challenge_accepts_exact_300_second_edge_and_rejects_longer_lifetime() {
        let exact = ControlSessionAuthenticationMessage::Challenge {
            session_id: SessionId::new("session-edge").expect("session id"),
            nonce: nonce(1),
            issued_at_unix_seconds: 5_000,
            expires_at_unix_seconds: 5_300,
        };
        encode_control_session_authentication_frame(1, &exact).expect("300 seconds accepted");

        let too_long = ControlSessionAuthenticationMessage::Challenge {
            session_id: SessionId::new("session-edge").expect("session id"),
            nonce: nonce(1),
            issued_at_unix_seconds: 5_000,
            expires_at_unix_seconds: 5_301,
        };
        assert_eq!(
            encode_control_session_authentication_frame(1, &too_long),
            Err(ControlSessionAuthenticationWireError::InvalidPayload)
        );
    }

    #[test]
    fn maximum_identifier_and_signature_bounds_round_trip() {
        let device = "d".repeat(MAX_SESSION_AUTH_IDENTIFIER_BYTES);
        let begin = ControlSessionAuthenticationMessage::Begin {
            device_id: DeviceId::new(device).expect("max device id"),
        };
        let begin_frame = encode_control_session_authentication_frame(2, &begin).expect("begin");
        assert_eq!(
            begin_frame.payload().len(),
            MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES
        );
        assert_eq!(
            decode_control_session_authentication_frame(&begin_frame).expect("begin decode"),
            begin
        );

        let session = "s".repeat(MAX_SESSION_AUTH_IDENTIFIER_BYTES);
        let proof = ControlSessionAuthenticationMessage::Proof {
            session_id: SessionId::new(session).expect("max session id"),
            nonce: nonce(3),
            signature: signature(vec![0x30; MAX_CONTROL_SESSION_AUTH_SIGNATURE_BYTES]),
        };
        let proof_frame = encode_control_session_authentication_frame(3, &proof).expect("proof");
        assert_eq!(
            proof_frame.payload().len(),
            MAX_CONTROL_SESSION_AUTH_PROOF_BYTES
        );
        assert_eq!(
            decode_control_session_authentication_frame(&proof_frame).expect("proof decode"),
            proof
        );
    }

    #[test]
    fn malformed_truncated_trailing_and_unsupported_profile_payloads_fail_closed() {
        let begin = encode_control_session_authentication_frame(
            4,
            &ControlSessionAuthenticationMessage::Begin {
                device_id: DeviceId::new("device-1").expect("device id"),
            },
        )
        .expect("begin");

        let truncated = ControlFrame::new(
            ControlMessageKind::Authentication,
            4,
            begin.payload()[..CONTROL_SESSION_AUTH_HEADER_BYTES - 1].to_vec(),
        )
        .expect("frame");
        assert_eq!(
            decode_control_session_authentication_frame(&truncated),
            Err(ControlSessionAuthenticationWireError::InvalidPayload)
        );

        let mut trailing_payload = begin.payload().to_vec();
        trailing_payload.push(0);
        let trailing = ControlFrame::new(ControlMessageKind::Authentication, 4, trailing_payload)
            .expect("frame");
        assert_eq!(
            decode_control_session_authentication_frame(&trailing),
            Err(ControlSessionAuthenticationWireError::InvalidPayload)
        );

        let proof = encode_control_session_authentication_frame(
            5,
            &ControlSessionAuthenticationMessage::Proof {
                session_id: SessionId::new("s").expect("session id"),
                nonce: nonce(8),
                signature: signature(vec![0x30, 1]),
            },
        )
        .expect("proof");
        let mut unsupported_payload = proof.payload().to_vec();
        let algorithm_offset = CONTROL_SESSION_AUTH_HEADER_BYTES + 2 + 1 + 32;
        unsupported_payload[algorithm_offset..algorithm_offset + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        let unsupported =
            ControlFrame::new(ControlMessageKind::Authentication, 5, unsupported_payload)
                .expect("frame");
        assert_eq!(
            decode_control_session_authentication_frame(&unsupported),
            Err(ControlSessionAuthenticationWireError::UnsupportedSignatureProfile)
        );
    }

    #[test]
    fn selected_maximum_payloads_fit_phase_129_ceiling() {
        assert_eq!(MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES, 1_038);
        assert_eq!(MAX_CONTROL_SESSION_AUTH_CHALLENGE_BYTES, 1_086);
        assert_eq!(MAX_CONTROL_SESSION_AUTH_PROOF_BYTES, 1_332);
        assert_eq!(MAX_CONTROL_SESSION_AUTH_AUTHENTICATED_BYTES, 1_038);
        assert_eq!(CONTROL_SESSION_AUTH_REJECTED_BYTES, 12);
        for size in [
            MAX_CONTROL_SESSION_AUTH_BEGIN_BYTES,
            MAX_CONTROL_SESSION_AUTH_CHALLENGE_BYTES,
            MAX_CONTROL_SESSION_AUTH_PROOF_BYTES,
            MAX_CONTROL_SESSION_AUTH_AUTHENTICATED_BYTES,
            CONTROL_SESSION_AUTH_REJECTED_BYTES,
        ] {
            assert!(size <= MAX_CONTROL_PAYLOAD_BYTES);
        }
    }
}
