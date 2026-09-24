//! Frame-boundary-aware generic reader for future connection-loop semantics.
//!
//! Phase 046 distinguishes clean EOF before a new frame begins from truncation
//! after at least one frame byte has been acquired. It owns no transport.

use std::io::{ErrorKind, Read};

use super::LocalIpcFrame;
use super::reader::{LocalIpcFrameReadError, read_frame};

/// Result of attempting to acquire one frame at a connection frame boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalIpcFrameBoundaryRead {
    /// The peer reached EOF before any byte of a new frame was acquired.
    CleanEof,
    /// One complete validated frame was acquired.
    Frame(LocalIpcFrame),
}

/// Reads one frame when positioned at a frame boundary, preserving clean EOF.
///
/// The first byte is probed separately. EOF before that byte is returned as
/// [`LocalIpcFrameBoundaryRead::CleanEof`]. Once one byte has been acquired, it
/// is prefixed back into a temporary chained reader and the existing Phase 011
/// [`read_frame`] implementation remains authoritative for the complete frame.
///
/// Interrupted first-byte reads are retried. A different I/O failure before the
/// first byte is classified as [`LocalIpcFrameReadError::HeaderIo`].
///
/// # Errors
///
/// Returns the existing bounded [`LocalIpcFrameReadError`] taxonomy after a
/// frame begins, or `HeaderIo` for a non-interrupted first-byte I/O failure.
pub fn read_frame_at_boundary<R: Read>(
    reader: &mut R,
) -> Result<LocalIpcFrameBoundaryRead, LocalIpcFrameReadError> {
    let mut first_byte = [0_u8; 1];

    loop {
        match reader.read(&mut first_byte) {
            Ok(0) => return Ok(LocalIpcFrameBoundaryRead::CleanEof),
            Ok(_) => {
                let mut prefixed = first_byte.as_slice().chain(reader);
                return read_frame(&mut prefixed).map(LocalIpcFrameBoundaryRead::Frame);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(LocalIpcFrameReadError::HeaderIo),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, ErrorKind, Read, Result as IoResult};

    use super::{LocalIpcFrameBoundaryRead, read_frame_at_boundary};
    use crate::frame_codec::encode_frame_header;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::write_frame;
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn frame(value: u64, payload: &[u8]) -> LocalIpcFrame {
        let payload = LocalIpcPayload::new(payload.to_vec()).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(value),
            payload.len(),
        )
        .expect("valid header");
        LocalIpcFrame::new(header, payload).expect("matching frame")
    }

    #[test]
    fn empty_stream_is_clean_eof_without_frame_error() {
        let mut input = Cursor::new(Vec::<u8>::new());

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Ok(LocalIpcFrameBoundaryRead::CleanEof)
        );
    }

    #[test]
    fn complete_frame_is_delegated_and_returned() {
        let expected = frame(260, &[1, 2, 3]);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &expected).expect("memory frame write succeeds");

        assert_eq!(
            read_frame_at_boundary(&mut Cursor::new(bytes)),
            Ok(LocalIpcFrameBoundaryRead::Frame(expected))
        );
    }

    #[test]
    fn eof_after_first_header_byte_is_truncated_header() {
        let encoded = encode_frame_header(frame(261, &[]).header()).to_vec();
        let mut input = Cursor::new(encoded[..1].to_vec());

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Err(LocalIpcFrameReadError::TruncatedHeader)
        );
    }

    #[test]
    fn eof_after_partial_header_is_truncated_header() {
        let encoded = encode_frame_header(frame(262, &[]).header()).to_vec();
        let mut input = Cursor::new(encoded[..23].to_vec());

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Err(LocalIpcFrameReadError::TruncatedHeader)
        );
    }

    #[test]
    fn successful_read_leaves_following_frame_unconsumed() {
        let first = frame(263, &[4]);
        let second = frame(264, &[5, 6]);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &first).expect("first frame writes");
        write_frame(&mut bytes, &second).expect("second frame writes");
        let mut input = Cursor::new(bytes);

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Ok(LocalIpcFrameBoundaryRead::Frame(first))
        );
        assert_eq!(
            read_frame_at_boundary(&mut input),
            Ok(LocalIpcFrameBoundaryRead::Frame(second))
        );
        assert_eq!(
            read_frame_at_boundary(&mut input),
            Ok(LocalIpcFrameBoundaryRead::CleanEof)
        );
    }

    #[test]
    fn first_byte_non_eof_io_failure_is_bounded_header_io() {
        let mut input = FailImmediately;

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Err(LocalIpcFrameReadError::HeaderIo)
        );
    }

    #[test]
    fn interrupted_first_byte_read_is_retried() {
        let expected = frame(265, &[]);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &expected).expect("memory frame write succeeds");
        let mut input = InterruptOnce::new(bytes);

        assert_eq!(
            read_frame_at_boundary(&mut input),
            Ok(LocalIpcFrameBoundaryRead::Frame(expected))
        );
    }

    struct FailImmediately;

    impl Read for FailImmediately {
        fn read(&mut self, _buffer: &mut [u8]) -> IoResult<usize> {
            Err(Error::other("planned read failure"))
        }
    }

    struct InterruptOnce {
        inner: Cursor<Vec<u8>>,
        calls: usize,
    }

    impl InterruptOnce {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                calls: 0,
            }
        }
    }

    impl Read for InterruptOnce {
        fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(Error::new(ErrorKind::Interrupted, "planned interruption"));
            }
            self.inner.read(buffer)
        }
    }
}
