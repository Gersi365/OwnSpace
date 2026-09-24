//! Pure frame-header codec for the Phase 007 local IPC wire layout.
//!
//! The codec operates on exactly one fixed 24-byte header. It performs no
//! socket I/O and does not inspect or allocate the opaque payload.

use std::fmt;

use crate::{
    LOCAL_IPC_FRAME_HEADER_LENGTH, LOCAL_IPC_FRAME_MAGIC, LocalIpcFrameHeader,
    LocalIpcFrameHeaderError, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    LocalIpcRequestIdError,
};

/// Fixed byte length of an encoded local IPC frame header.
pub const ENCODED_LOCAL_IPC_HEADER_LENGTH: usize = LOCAL_IPC_FRAME_HEADER_LENGTH as usize;

/// Encodes validated local IPC frame metadata into the fixed Phase 007 header.
#[must_use]
pub fn encode_frame_header(header: LocalIpcFrameHeader) -> [u8; ENCODED_LOCAL_IPC_HEADER_LENGTH] {
    let mut bytes = [0_u8; ENCODED_LOCAL_IPC_HEADER_LENGTH];

    bytes[0..4].copy_from_slice(&LOCAL_IPC_FRAME_MAGIC);
    bytes[4..6].copy_from_slice(&header.version().major().to_be_bytes());
    bytes[6..8].copy_from_slice(&header.version().minor().to_be_bytes());
    bytes[8] = message_kind_code(header.kind());
    bytes[9] = 0;
    bytes[10..12].copy_from_slice(&0_u16.to_be_bytes());
    bytes[12..20].copy_from_slice(&header.request_id().get().to_be_bytes());
    bytes[20..24].copy_from_slice(&header.payload_length().to_be_bytes());

    bytes
}

/// Decodes and validates exactly one fixed Phase 007 local IPC frame header.
///
/// # Errors
///
/// Returns [`LocalIpcFrameDecodeError`] when the magic, version, message kind,
/// reserved fields, request identifier, or payload bound violates the locked
/// protocol contract.
pub fn decode_frame_header(
    bytes: &[u8; ENCODED_LOCAL_IPC_HEADER_LENGTH],
) -> Result<LocalIpcFrameHeader, LocalIpcFrameDecodeError> {
    if bytes[0..4] != LOCAL_IPC_FRAME_MAGIC {
        return Err(LocalIpcFrameDecodeError::InvalidMagic);
    }
    if bytes[9] != 0 {
        return Err(LocalIpcFrameDecodeError::NonZeroFlags);
    }
    if bytes[10] != 0 || bytes[11] != 0 {
        return Err(LocalIpcFrameDecodeError::NonZeroReserved);
    }

    let version = LocalIpcProtocolVersion::from_parts(
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
    );
    let kind = decode_message_kind(bytes[8])?;
    let request_id = LocalIpcRequestId::new(u64::from_be_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .map_err(map_request_id_error)?;
    let payload_length = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

    LocalIpcFrameHeader::new(version, kind, request_id, payload_length).map_err(map_header_error)
}

const fn message_kind_code(kind: LocalIpcMessageKind) -> u8 {
    match kind {
        LocalIpcMessageKind::Request => 1,
        LocalIpcMessageKind::Response => 2,
        LocalIpcMessageKind::Error => 3,
    }
}

const fn decode_message_kind(code: u8) -> Result<LocalIpcMessageKind, LocalIpcFrameDecodeError> {
    match code {
        1 => Ok(LocalIpcMessageKind::Request),
        2 => Ok(LocalIpcMessageKind::Response),
        3 => Ok(LocalIpcMessageKind::Error),
        _ => Err(LocalIpcFrameDecodeError::UnknownMessageKind),
    }
}

const fn map_request_id_error(error: LocalIpcRequestIdError) -> LocalIpcFrameDecodeError {
    match error {
        LocalIpcRequestIdError::Zero => LocalIpcFrameDecodeError::ZeroRequestId,
    }
}

const fn map_header_error(error: LocalIpcFrameHeaderError) -> LocalIpcFrameDecodeError {
    match error {
        LocalIpcFrameHeaderError::UnsupportedVersion => {
            LocalIpcFrameDecodeError::UnsupportedVersion
        }
        LocalIpcFrameHeaderError::PayloadTooLarge => LocalIpcFrameDecodeError::PayloadTooLarge,
    }
}

/// Fail-closed reason for rejecting a fixed local IPC frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcFrameDecodeError {
    /// The four magic bytes are not `PRW\0`.
    InvalidMagic,
    /// The message-kind code is not defined by local IPC version 1.0.
    UnknownMessageKind,
    /// Version-1.0 flags byte is non-zero.
    NonZeroFlags,
    /// Version-1.0 reserved bytes are non-zero.
    NonZeroReserved,
    /// Request identifier zero is reserved and invalid.
    ZeroRequestId,
    /// The protocol version is not exactly the supported version.
    UnsupportedVersion,
    /// The declared payload length exceeds the global control-channel bound.
    PayloadTooLarge,
}

impl fmt::Display for LocalIpcFrameDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidMagic => "invalid local IPC frame magic",
            Self::UnknownMessageKind => "unknown local IPC message kind",
            Self::NonZeroFlags => "unsupported non-zero local IPC flags",
            Self::NonZeroReserved => "unsupported non-zero local IPC reserved field",
            Self::ZeroRequestId => "local IPC request id must be non-zero",
            Self::UnsupportedVersion => "unsupported local IPC protocol version",
            Self::PayloadTooLarge => "local IPC payload exceeds maximum length",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LocalIpcFrameDecodeError {}

#[cfg(test)]
mod tests {
    use super::{LocalIpcFrameDecodeError, decode_frame_header, encode_frame_header};
    use crate::{
        LOCAL_IPC_FRAME_MAGIC, LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcFrameHeader,
        LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn request_header(payload_length: u32) -> LocalIpcFrameHeader {
        LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            LocalIpcRequestId::new(0x0102_0304_0506_0708).expect("non-zero request id"),
            payload_length,
        )
        .expect("valid request header")
    }

    #[test]
    fn header_round_trip_preserves_validated_metadata() {
        let header = request_header(17);
        let encoded = encode_frame_header(header);
        let decoded = decode_frame_header(&encoded).expect("encoded header is valid");

        assert_eq!(decoded, header);
    }

    #[test]
    fn encoding_matches_locked_big_endian_layout() {
        let encoded = encode_frame_header(request_header(0x0001_0203));

        assert_eq!(&encoded[0..4], &LOCAL_IPC_FRAME_MAGIC);
        assert_eq!(&encoded[4..6], &[0, 1]);
        assert_eq!(&encoded[6..8], &[0, 0]);
        assert_eq!(encoded[8], 1);
        assert_eq!(encoded[9], 0);
        assert_eq!(&encoded[10..12], &[0, 0]);
        assert_eq!(&encoded[12..20], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&encoded[20..24], &[0, 1, 2, 3]);
    }

    #[test]
    fn decoder_rejects_invalid_magic() {
        let mut encoded = encode_frame_header(request_header(0));
        encoded[0] = b'X';

        assert_eq!(
            decode_frame_header(&encoded),
            Err(LocalIpcFrameDecodeError::InvalidMagic)
        );
    }

    #[test]
    fn decoder_rejects_unknown_kind_flags_and_reserved_bytes() {
        let mut unknown_kind = encode_frame_header(request_header(0));
        unknown_kind[8] = 255;
        assert_eq!(
            decode_frame_header(&unknown_kind),
            Err(LocalIpcFrameDecodeError::UnknownMessageKind)
        );

        let mut flags = encode_frame_header(request_header(0));
        flags[9] = 1;
        assert_eq!(
            decode_frame_header(&flags),
            Err(LocalIpcFrameDecodeError::NonZeroFlags)
        );

        let mut reserved = encode_frame_header(request_header(0));
        reserved[11] = 1;
        assert_eq!(
            decode_frame_header(&reserved),
            Err(LocalIpcFrameDecodeError::NonZeroReserved)
        );
    }

    #[test]
    fn decoder_rejects_zero_request_id() {
        let mut encoded = encode_frame_header(request_header(0));
        encoded[12..20].fill(0);

        assert_eq!(
            decode_frame_header(&encoded),
            Err(LocalIpcFrameDecodeError::ZeroRequestId)
        );
    }

    #[test]
    fn decoder_rejects_unsupported_version() {
        let mut encoded = encode_frame_header(request_header(0));
        encoded[4..6].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            decode_frame_header(&encoded),
            Err(LocalIpcFrameDecodeError::UnsupportedVersion)
        );
    }

    #[test]
    fn decoder_rejects_payload_above_global_bound() {
        let mut encoded = encode_frame_header(request_header(0));
        encoded[20..24].copy_from_slice(&(LOCAL_IPC_MAX_PAYLOAD_LENGTH + 1).to_be_bytes());

        assert_eq!(
            decode_frame_header(&encoded),
            Err(LocalIpcFrameDecodeError::PayloadTooLarge)
        );
    }
}
