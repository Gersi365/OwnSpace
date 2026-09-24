//! Generic writer for one complete validated local IPC frame.
//!
//! The writer targets `std::io::Write`. Phase 012 tests memory buffers and
//! deterministic synthetic failures only; it performs no Unix socket setup.

use std::fmt;
use std::io::Write;

use crate::frame_codec::encode_frame_header;

use super::LocalIpcFrame;

/// Writes exactly one validated local IPC frame to a byte stream.
///
/// The fixed header is written first, followed by exactly the bounded payload
/// bytes. The function deliberately does not flush the writer; buffering and
/// flush policy belong to the future connection/runtime layer.
///
/// # Errors
///
/// Returns [`LocalIpcFrameWriteError::HeaderIo`] if the fixed header cannot be
/// fully written, or [`LocalIpcFrameWriteError::PayloadIo`] if payload writing
/// fails after the header has been completed.
pub fn write_frame<W: Write>(
    writer: &mut W,
    frame: &LocalIpcFrame,
) -> Result<(), LocalIpcFrameWriteError> {
    let header = encode_frame_header(frame.header());
    writer
        .write_all(&header)
        .map_err(|_| LocalIpcFrameWriteError::HeaderIo)?;
    writer
        .write_all(frame.payload().as_bytes())
        .map_err(|_| LocalIpcFrameWriteError::PayloadIo)?;
    Ok(())
}

/// Bounded failure classes for writing one local IPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcFrameWriteError {
    /// The fixed 24-byte frame header could not be fully written.
    HeaderIo,
    /// The bounded payload could not be fully written after the header.
    PayloadIo,
}

impl fmt::Display for LocalIpcFrameWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderIo => formatter.write_str("local IPC frame header write failed"),
            Self::PayloadIo => formatter.write_str("local IPC frame payload write failed"),
        }
    }
}

impl std::error::Error for LocalIpcFrameWriteError {}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, Result as IoResult, Write};

    use super::{LocalIpcFrameWriteError, write_frame};
    use crate::frame_codec::encode_frame_header;
    use crate::frame_object::reader::read_frame;
    use crate::{
        LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    use super::super::{LocalIpcFrame, LocalIpcPayload};

    fn frame(payload_bytes: Vec<u8>) -> LocalIpcFrame {
        let payload = LocalIpcPayload::new(payload_bytes).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Response,
            LocalIpcRequestId::new(31).expect("non-zero request id"),
            payload.len(),
        )
        .expect("valid header");
        LocalIpcFrame::new(header, payload).expect("matching frame")
    }

    #[test]
    fn writer_emits_exact_header_then_payload() {
        let frame = frame(vec![1, 2, 3]);
        let mut written = Vec::new();

        write_frame(&mut written, &frame).expect("frame write succeeds");

        let mut expected = encode_frame_header(frame.header()).to_vec();
        expected.extend_from_slice(&[1, 2, 3]);
        assert_eq!(written, expected);
    }

    #[test]
    fn written_frame_round_trips_through_generic_reader() {
        let frame = frame(vec![4, 5, 6, 7]);
        let mut written = Vec::new();
        write_frame(&mut written, &frame).expect("frame write succeeds");

        let decoded = read_frame(&mut Cursor::new(written)).expect("written frame reads back");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn zero_payload_writes_header_only() {
        let frame = frame(Vec::new());
        let mut written = Vec::new();

        write_frame(&mut written, &frame).expect("empty frame write succeeds");

        assert_eq!(written, encode_frame_header(frame.header()));
    }

    #[test]
    fn classifies_header_write_failure() {
        let frame = frame(vec![1]);
        let mut writer = FailAfter::new(0);

        assert_eq!(
            write_frame(&mut writer, &frame),
            Err(LocalIpcFrameWriteError::HeaderIo)
        );
    }

    #[test]
    fn classifies_payload_write_failure_after_complete_header() {
        let frame = frame(vec![1, 2, 3]);
        let mut writer = FailAfter::new(24);

        assert_eq!(
            write_frame(&mut writer, &frame),
            Err(LocalIpcFrameWriteError::PayloadIo)
        );
        assert_eq!(writer.written, 24);
    }

    struct FailAfter {
        limit: usize,
        written: usize,
    }

    impl FailAfter {
        const fn new(limit: usize) -> Self {
            Self { limit, written: 0 }
        }
    }

    impl Write for FailAfter {
        fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
            if self.written >= self.limit {
                return Err(Error::other("planned write failure"));
            }

            let remaining = self.limit - self.written;
            let count = remaining.min(buffer.len());
            self.written += count;
            Ok(count)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }
}
