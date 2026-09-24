//! Bounded generic reader for one complete local IPC frame.
//!
//! The reader works over `std::io::Read`. Phase 011 tests it with in-memory
//! cursors only; it does not bind, connect to, or configure a Unix socket.

use std::fmt;
use std::io::{ErrorKind, Read};

use crate::frame_codec::{
    ENCODED_LOCAL_IPC_HEADER_LENGTH, LocalIpcFrameDecodeError, decode_frame_header,
};

use super::{LocalIpcFrame, LocalIpcPayload};

/// Reads exactly one validated local IPC frame from a byte stream.
///
/// Header bytes are acquired first and decoded before payload storage is
/// allocated. The decoded Phase 007 payload bound therefore gates the receive
/// allocation.
///
/// # Errors
///
/// Returns [`LocalIpcFrameReadError`] for truncated I/O, other I/O failure,
/// invalid header metadata, platform length incompatibility, or an unexpected
/// internal frame invariant failure.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<LocalIpcFrame, LocalIpcFrameReadError> {
    let mut header_bytes = [0_u8; ENCODED_LOCAL_IPC_HEADER_LENGTH];
    reader
        .read_exact(&mut header_bytes)
        .map_err(|error| classify_header_io_error(&error))?;

    let header =
        decode_frame_header(&header_bytes).map_err(LocalIpcFrameReadError::InvalidHeader)?;
    let payload_length = usize::try_from(header.payload_length())
        .map_err(|_| LocalIpcFrameReadError::PayloadLengthUnsupported)?;

    let mut payload_bytes = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload_bytes)
        .map_err(|error| classify_payload_io_error(&error))?;

    let payload = LocalIpcPayload::new(payload_bytes)
        .map_err(|_| LocalIpcFrameReadError::PayloadInvariant)?;
    LocalIpcFrame::new(header, payload).map_err(|_| LocalIpcFrameReadError::FrameInvariant)
}

fn classify_header_io_error(error: &std::io::Error) -> LocalIpcFrameReadError {
    if error.kind() == ErrorKind::UnexpectedEof {
        LocalIpcFrameReadError::TruncatedHeader
    } else {
        LocalIpcFrameReadError::HeaderIo
    }
}

fn classify_payload_io_error(error: &std::io::Error) -> LocalIpcFrameReadError {
    if error.kind() == ErrorKind::UnexpectedEof {
        LocalIpcFrameReadError::TruncatedPayload
    } else {
        LocalIpcFrameReadError::PayloadIo
    }
}

/// Bounded failure classes for acquiring one local IPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcFrameReadError {
    /// EOF occurred before all 24 header bytes were acquired.
    TruncatedHeader,
    /// A non-EOF I/O failure occurred while acquiring the header.
    HeaderIo,
    /// The complete 24-byte header violates the Phase 007/009 contract.
    InvalidHeader(LocalIpcFrameDecodeError),
    /// The validated wire payload length cannot be represented by this target's `usize`.
    PayloadLengthUnsupported,
    /// EOF occurred before the full validated payload length was acquired.
    TruncatedPayload,
    /// A non-EOF I/O failure occurred while acquiring payload bytes.
    PayloadIo,
    /// An internal bounded-payload invariant unexpectedly failed after header validation.
    PayloadInvariant,
    /// Header/payload coupling unexpectedly failed after exact payload acquisition.
    FrameInvariant,
}

impl fmt::Display for LocalIpcFrameReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TruncatedHeader => "truncated local IPC frame header",
            Self::HeaderIo => "local IPC header read failed",
            Self::InvalidHeader(_) => "invalid local IPC frame header",
            Self::PayloadLengthUnsupported => "local IPC payload length unsupported on this target",
            Self::TruncatedPayload => "truncated local IPC frame payload",
            Self::PayloadIo => "local IPC payload read failed",
            Self::PayloadInvariant => "local IPC payload invariant failed",
            Self::FrameInvariant => "local IPC frame invariant failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LocalIpcFrameReadError {}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{LocalIpcFrameReadError, read_frame};
    use crate::frame_codec::{LocalIpcFrameDecodeError, encode_frame_header};
    use crate::{
        LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcFrameHeader, LocalIpcMessageKind,
        LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn header(payload_length: u32) -> LocalIpcFrameHeader {
        LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            LocalIpcRequestId::new(23).expect("non-zero request id"),
            payload_length,
        )
        .expect("valid header")
    }

    #[test]
    fn reads_one_frame_and_leaves_following_bytes() {
        let mut bytes = encode_frame_header(header(3)).to_vec();
        bytes.extend_from_slice(&[1, 2, 3, 9, 8]);
        let mut cursor = Cursor::new(bytes);

        let frame = read_frame(&mut cursor).expect("valid frame");
        let mut trailing = Vec::new();
        cursor
            .read_to_end(&mut trailing)
            .expect("read trailing bytes");

        assert_eq!(frame.payload().as_bytes(), &[1, 2, 3]);
        assert_eq!(trailing, vec![9, 8]);
    }

    #[test]
    fn rejects_truncated_header() {
        let mut cursor = Cursor::new(vec![0_u8; 10]);

        assert_eq!(
            read_frame(&mut cursor),
            Err(LocalIpcFrameReadError::TruncatedHeader)
        );
    }

    #[test]
    fn validates_header_before_payload_allocation_or_read() {
        let mut encoded = encode_frame_header(header(0));
        encoded[20..24].copy_from_slice(&(LOCAL_IPC_MAX_PAYLOAD_LENGTH + 1).to_be_bytes());
        let mut cursor = Cursor::new(encoded);

        assert_eq!(
            read_frame(&mut cursor),
            Err(LocalIpcFrameReadError::InvalidHeader(
                LocalIpcFrameDecodeError::PayloadTooLarge
            ))
        );
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut bytes = encode_frame_header(header(3)).to_vec();
        bytes.extend_from_slice(&[1, 2]);
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_frame(&mut cursor),
            Err(LocalIpcFrameReadError::TruncatedPayload)
        );
    }

    #[test]
    fn accepts_zero_length_payload_without_consuming_next_frame_data() {
        let mut bytes = encode_frame_header(header(0)).to_vec();
        bytes.extend_from_slice(&[7, 6]);
        let mut cursor = Cursor::new(bytes);

        let frame = read_frame(&mut cursor).expect("zero-length frame");
        let mut trailing = Vec::new();
        cursor
            .read_to_end(&mut trailing)
            .expect("read trailing bytes");

        assert!(frame.payload().is_empty());
        assert_eq!(trailing, vec![7, 6]);
    }
}
