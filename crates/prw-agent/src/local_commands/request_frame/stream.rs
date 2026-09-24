//! Generic stream composition for complete local read-only Request frames.
//!
//! Phase 032 composes the Phase 031 Request frame builder/decoder with the
//! Phase 011/012 generic frame reader/writer. Tests use memory streams only.

use std::io::{Read, Write};

use crate::LocalIpcRequestId;
use crate::frame_object::reader::{LocalIpcFrameReadError, read_frame};
use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};

use super::{
    LocalAgentRequestFrameBuildError, LocalAgentRequestFrameDecodeError,
    build_local_command_request_frame, decode_local_command_request_frame,
};
use crate::local_commands::{LocalAgentCommand, LocalAgentRequestEnvelope};

/// Builds and writes one complete local read-only command Request frame.
///
/// This function deliberately does not flush the writer.
///
/// # Errors
///
/// Returns [`LocalAgentRequestStreamWriteError::Build`] when the typed Request
/// frame cannot be constructed, or [`LocalAgentRequestStreamWriteError::Write`]
/// when the generic frame writer cannot emit the complete frame.
pub fn write_local_command_request<W: Write>(
    writer: &mut W,
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
) -> Result<(), LocalAgentRequestStreamWriteError> {
    let frame = build_local_command_request_frame(request_id, command)
        .map_err(LocalAgentRequestStreamWriteError::Build)?;
    write_frame(writer, &frame).map_err(LocalAgentRequestStreamWriteError::Write)
}

/// Reads and fully decodes one complete local read-only command Request frame.
///
/// Exactly one generic frame is consumed. Bytes belonging to a following frame
/// remain unread in the supplied stream.
///
/// # Errors
///
/// Returns [`LocalAgentRequestStreamReadError::Read`] when generic frame
/// acquisition fails, or [`LocalAgentRequestStreamReadError::Decode`] when the
/// acquired frame is not a valid Phase 031 Request frame.
pub fn read_local_command_request<R: Read>(
    reader: &mut R,
) -> Result<LocalAgentRequestEnvelope, LocalAgentRequestStreamReadError> {
    let frame = read_frame(reader).map_err(LocalAgentRequestStreamReadError::Read)?;
    decode_local_command_request_frame(&frame).map_err(LocalAgentRequestStreamReadError::Decode)
}

/// Phase 032 Request stream write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentRequestStreamWriteError {
    /// The complete typed Request frame could not be built.
    Build(LocalAgentRequestFrameBuildError),
    /// The generic frame writer could not emit the complete frame.
    Write(LocalIpcFrameWriteError),
}

/// Phase 032 Request stream read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentRequestStreamReadError {
    /// Generic frame acquisition failed.
    Read(LocalIpcFrameReadError),
    /// The acquired frame failed Request-specific decoding.
    Decode(LocalAgentRequestFrameDecodeError),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, Result as IoResult, Write};

    use super::{
        LocalAgentRequestStreamReadError, LocalAgentRequestStreamWriteError,
        read_local_command_request, write_local_command_request,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::request_frame::{
        LOCAL_AGENT_REQUEST_WIRE_LENGTH, LocalAgentRequestFrameDecodeError,
    };
    use crate::{LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn both_read_only_commands_round_trip_through_memory_stream() {
        for command in [
            LocalAgentCommand::GetAgentStatus,
            LocalAgentCommand::GetPrivateDnsConfig,
        ] {
            let mut bytes = Vec::new();
            write_local_command_request(&mut bytes, id(140), command)
                .expect("memory request write succeeds");

            assert_eq!(bytes.len(), LOCAL_AGENT_REQUEST_WIRE_LENGTH);

            let decoded = read_local_command_request(&mut Cursor::new(bytes))
                .expect("memory request read succeeds");
            assert_eq!(decoded.request_id(), id(140));
            assert_eq!(decoded.command(), command);
        }
    }

    #[test]
    fn one_read_consumes_exactly_one_request_frame() {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(141), LocalAgentCommand::GetAgentStatus)
            .expect("first request write succeeds");
        write_local_command_request(&mut bytes, id(142), LocalAgentCommand::GetPrivateDnsConfig)
            .expect("second request write succeeds");
        let mut cursor = Cursor::new(bytes);

        let first = read_local_command_request(&mut cursor).expect("first request reads");
        let second = read_local_command_request(&mut cursor).expect("second request reads");

        assert_eq!(first.request_id(), id(141));
        assert_eq!(first.command(), LocalAgentCommand::GetAgentStatus);
        assert_eq!(second.request_id(), id(142));
        assert_eq!(second.command(), LocalAgentCommand::GetPrivateDnsConfig);
    }

    #[test]
    fn truncated_request_preserves_generic_read_error() {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(143), LocalAgentCommand::GetAgentStatus)
            .expect("memory request write succeeds");
        bytes.pop();

        assert_eq!(
            read_local_command_request(&mut Cursor::new(bytes)),
            Err(LocalAgentRequestStreamReadError::Read(
                LocalIpcFrameReadError::TruncatedPayload
            ))
        );
    }

    #[test]
    fn non_request_frame_preserves_request_decode_error() {
        let payload = LocalIpcPayload::new(vec![0, 1]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Response,
            id(144),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");

        assert_eq!(
            read_local_command_request(&mut Cursor::new(bytes)),
            Err(LocalAgentRequestStreamReadError::Decode(
                LocalAgentRequestFrameDecodeError::NonRequestKind
            ))
        );
    }

    #[test]
    fn payload_write_failure_is_preserved() {
        let mut writer = FailAfter::new(24);

        assert_eq!(
            write_local_command_request(
                &mut writer,
                id(145),
                LocalAgentCommand::GetPrivateDnsConfig,
            ),
            Err(LocalAgentRequestStreamWriteError::Write(
                LocalIpcFrameWriteError::PayloadIo
            ))
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
