//! Pure bounded requester/rendezvous target-request wire codec over PRWM.
//!
//! C03e-EM materializes only the C03e-EK-selected `PRWZ` v1.0 target nomination request at the
//! C03e-EL-corrected bridge crate boundary. The codec preserves one outer request correlation value
//! and one typed logical target `DeviceId`. It performs no requester authentication, registry or
//! policy evaluation, provider mutation, stream I/O, response construction, networking activation,
//! or deployment.

use std::fmt;

use prw_core::DeviceId;
use prw_remote_transport::{ControlFrame, ControlMessageKind, RemoteTransportError};

/// Exact inner payload magic for one requester/rendezvous target request.
pub const REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC: [u8; 4] = *b"PRWZ";
/// Initial requester/rendezvous target-request wire major version.
pub const REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR: u16 = 1;
/// Initial requester/rendezvous target-request wire minor version.
pub const REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR: u16 = 0;
/// Fixed PRWZ header bytes before the target body.
pub const REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_HEADER_BYTES: usize = 12;
/// Maximum UTF-8 bytes accepted for one logical target `DeviceId` at this wire boundary.
pub const MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES: usize = 1024;

const REQUESTER_RENDEZVOUS_START_TARGET_OPERATION: u16 = 1;

/// One structurally valid PRWZ target nomination plus its outer PRWM correlation value.
///
/// The target is caller-nominated intent only. This value contains no requester identity and grants
/// no registry, policy, provider, reachability, or current-session authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterRendezvousTargetWireRequest {
    request_id: u64,
    target_device_id: DeviceId,
}

impl RequesterRendezvousTargetWireRequest {
    /// Returns the exact non-zero outer PRWM request correlation value.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the exact caller-nominated logical target decoded from PRWZ.
    #[must_use]
    pub const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }

    /// Transfers ownership of the exact decoded logical target without reinterpretation.
    #[must_use]
    pub fn into_target_device_id(self) -> DeviceId {
        self.target_device_id
    }
}

/// Failure at the pure PRWZ requester/rendezvous target-request wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousTargetWireError {
    /// The outer PRWM frame was not the selected `Request` kind.
    InvalidOuterKind,
    /// PRWZ structure, version, operation, flags, target bounds, UTF-8, type, or trailing data failed.
    InvalidPayload,
    /// Existing PRWM frame construction rejected the supplied correlation or bounded payload.
    Frame(RemoteTransportError),
}

impl fmt::Display for RequesterRendezvousTargetWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOuterKind => {
                "invalid outer PRWM kind for requester rendezvous target request"
            }
            Self::InvalidPayload => "invalid requester rendezvous PRWZ target-request payload",
            Self::Frame(_) => "failed to construct requester rendezvous PRWM target request",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RequesterRendezvousTargetWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RemoteTransportError> for RequesterRendezvousTargetWireError {
    fn from(error: RemoteTransportError) -> Self {
        Self::Frame(error)
    }
}

/// Encodes one typed logical target inside the C03e-EK-selected PRWM `Request` envelope.
///
/// The supplied request ID remains correlation only. The target remains nomination only; this
/// function performs no requester authentication or authorization.
///
/// # Errors
///
/// Rejects a target outside the fixed `1..=1024` UTF-8-byte wire bound or a request identifier
/// rejected by the existing PRWM frame constructor.
pub fn encode_requester_rendezvous_target_request_frame(
    request_id: u64,
    target_device_id: &DeviceId,
) -> Result<ControlFrame, RequesterRendezvousTargetWireError> {
    let target = target_device_id.as_str().as_bytes();
    validate_target_bytes(target)?;
    let target_len = u16::try_from(target.len())
        .map_err(|_| RequesterRendezvousTargetWireError::InvalidPayload)?;

    let mut payload = Vec::with_capacity(
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_HEADER_BYTES + 2 + target.len(),
    );
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC);
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR.to_be_bytes());
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR.to_be_bytes());
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_START_TARGET_OPERATION.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&target_len.to_be_bytes());
    payload.extend_from_slice(target);

    ControlFrame::new(ControlMessageKind::Request, request_id, payload)
        .map_err(RequesterRendezvousTargetWireError::Frame)
}

/// Decodes one complete C03e-EK-selected PRWZ target request from an existing PRWM frame.
///
/// Successful return proves only bounded wire structure plus typed target construction. The outer
/// request ID is preserved unchanged as correlation and never interpreted as identity.
///
/// # Errors
///
/// Rejects a non-`Request` outer kind, malformed or unsupported PRWZ metadata, non-zero flags,
/// invalid target bounds/UTF-8/domain value, truncation, or trailing bytes.
pub fn decode_requester_rendezvous_target_request_frame(
    frame: &ControlFrame,
) -> Result<RequesterRendezvousTargetWireRequest, RequesterRendezvousTargetWireError> {
    if frame.kind() != ControlMessageKind::Request {
        return Err(RequesterRendezvousTargetWireError::InvalidOuterKind);
    }

    let mut decoder = Decoder::new(frame.payload());
    if decoder.take(4)? != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC.as_slice()
        || decoder.u16()? != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR
        || decoder.u16()? != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR
        || decoder.u16()? != REQUESTER_RENDEZVOUS_START_TARGET_OPERATION
        || decoder.u16()? != 0
    {
        return Err(RequesterRendezvousTargetWireError::InvalidPayload);
    }

    let target_len = usize::from(decoder.u16()?);
    if target_len == 0 || target_len > MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES {
        return Err(RequesterRendezvousTargetWireError::InvalidPayload);
    }
    let target = std::str::from_utf8(decoder.take(target_len)?)
        .map_err(|_| RequesterRendezvousTargetWireError::InvalidPayload)?;
    let target_device_id = DeviceId::new(target.to_owned())
        .map_err(|_| RequesterRendezvousTargetWireError::InvalidPayload)?;
    decoder.finish()?;

    Ok(RequesterRendezvousTargetWireRequest {
        request_id: frame.request_id(),
        target_device_id,
    })
}

const fn validate_target_bytes(target: &[u8]) -> Result<(), RequesterRendezvousTargetWireError> {
    if target.is_empty() || target.len() > MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES {
        return Err(RequesterRendezvousTargetWireError::InvalidPayload);
    }
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RequesterRendezvousTargetWireError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(RequesterRendezvousTargetWireError::InvalidPayload)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(RequesterRendezvousTargetWireError::InvalidPayload)?;
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, RequesterRendezvousTargetWireError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| RequesterRendezvousTargetWireError::InvalidPayload)?;
        Ok(u16::from_be_bytes(bytes))
    }

    const fn finish(self) -> Result<(), RequesterRendezvousTargetWireError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        }
    }
}

#[cfg(test)]
mod tests {
    use prw_core::DeviceId;
    use prw_remote_transport::{ControlFrame, ControlMessageKind, RemoteTransportError};

    use super::{
        MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES,
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC, RequesterRendezvousTargetWireError,
        decode_requester_rendezvous_target_request_frame,
        encode_requester_rendezvous_target_request_frame,
    };

    fn target(value: &str) -> DeviceId {
        DeviceId::new(value).expect("test target must be a valid DeviceId")
    }

    fn valid_payload(target: &[u8]) -> Vec<u8> {
        let target_len = u16::try_from(target.len()).expect("test target length fits u16");
        let mut payload = Vec::new();
        payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC);
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&target_len.to_be_bytes());
        payload.extend_from_slice(target);
        payload
    }

    fn request_frame(payload: Vec<u8>) -> ControlFrame {
        ControlFrame::new(ControlMessageKind::Request, 17, payload)
            .expect("bounded test request frame must be valid")
    }

    #[test]
    fn round_trip_preserves_exact_request_id_and_target() {
        let expected_target = target("device-target-17");
        let frame = encode_requester_rendezvous_target_request_frame(91, &expected_target)
            .expect("bounded typed target must encode");

        assert_eq!(frame.kind(), ControlMessageKind::Request);
        assert_eq!(frame.request_id(), 91);
        let decoded = decode_requester_rendezvous_target_request_frame(&frame)
            .expect("encoded frame must decode");
        assert_eq!(decoded.request_id(), 91);
        assert_eq!(decoded.target_device_id(), &expected_target);
        assert_eq!(decoded.into_target_device_id(), expected_target);
    }

    #[test]
    fn decode_rejects_wrong_outer_kind() {
        let frame = ControlFrame::new(
            ControlMessageKind::Event,
            17,
            valid_payload(b"device-target"),
        )
        .expect("generic bounded event frame must be valid");

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&frame),
            Err(RequesterRendezvousTargetWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut payload = valid_payload(b"device-target");
        payload[0] = b'X';

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut payload = valid_payload(b"device-target");
        payload[5] = 2;

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_unknown_operation() {
        let mut payload = valid_payload(b"device-target");
        payload[9] = 2;

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_non_zero_flags() {
        let mut payload = valid_payload(b"device-target");
        payload[11] = 1;

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_zero_target_length() {
        let payload = valid_payload(b"");

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_target_above_wire_bound() {
        let oversized = vec![b'x'; MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES + 1];
        let payload = valid_payload(&oversized);

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_invalid_utf8_target() {
        let payload = valid_payload(&[0xff]);

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_whitespace_only_target() {
        let payload = valid_payload(b"   ");

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut payload = valid_payload(b"device-target");
        payload.push(0);

        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&request_frame(payload)),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn encode_rejects_target_above_wire_bound() {
        let oversized_target =
            target(&"x".repeat(MAX_REQUESTER_RENDEZVOUS_TARGET_DEVICE_ID_BYTES + 1));

        assert_eq!(
            encode_requester_rendezvous_target_request_frame(17, &oversized_target),
            Err(RequesterRendezvousTargetWireError::InvalidPayload)
        );
    }

    #[test]
    fn encode_preserves_existing_zero_request_id_rejection() {
        let result = encode_requester_rendezvous_target_request_frame(0, &target("device-target"));

        assert_eq!(
            result,
            Err(RequesterRendezvousTargetWireError::Frame(
                RemoteTransportError::InvalidControlFrame
            ))
        );
    }
}
