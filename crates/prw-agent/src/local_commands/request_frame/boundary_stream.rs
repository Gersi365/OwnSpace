//! Boundary-aware generic Request reader for future connection-loop semantics.
//!
//! Phase 047 composes the Phase 046 frame-boundary reader with the existing
//! Request-frame decoder. It owns no transport, policy, or response writing.

use std::io::Read;

use crate::frame_object::boundary_reader::{LocalIpcFrameBoundaryRead, read_frame_at_boundary};
use crate::local_commands::LocalAgentRequestEnvelope;

use super::decode_local_command_request_frame;
use super::stream::LocalAgentRequestStreamReadError;

/// Successful boundary-aware outcome for one local command Request attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAgentRequestBoundaryRead {
    /// The peer reached EOF before any byte of a new frame was acquired.
    CleanEof,
    /// One complete valid current local command Request was decoded.
    Request(LocalAgentRequestEnvelope),
}

/// Reads and decodes one local command Request at a frame boundary.
///
/// Clean EOF from Phase 046 remains a successful lifecycle outcome. A complete
/// frame is delegated to the existing Phase 031 Request decoder. No policy
/// evaluation or response construction occurs here.
///
/// # Errors
///
/// Preserves frame-acquisition failures as
/// [`LocalAgentRequestStreamReadError::Read`] and Request-specific decode
/// failures as [`LocalAgentRequestStreamReadError::Decode`].
pub fn read_local_command_request_at_boundary<R: Read>(
    reader: &mut R,
) -> Result<LocalAgentRequestBoundaryRead, LocalAgentRequestStreamReadError> {
    match read_frame_at_boundary(reader).map_err(LocalAgentRequestStreamReadError::Read)? {
        LocalIpcFrameBoundaryRead::CleanEof => Ok(LocalAgentRequestBoundaryRead::CleanEof),
        LocalIpcFrameBoundaryRead::Frame(frame) => decode_local_command_request_frame(&frame)
            .map(LocalAgentRequestBoundaryRead::Request)
            .map_err(LocalAgentRequestStreamReadError::Decode),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{LocalAgentRequestBoundaryRead, read_local_command_request_at_boundary};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::write_frame;
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::codec::LocalAgentRequestDecodeError;
    use crate::local_commands::request_frame::LocalAgentRequestFrameDecodeError;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::{LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn empty_stream_is_clean_eof() {
        let mut input = Cursor::new(Vec::<u8>::new());

        assert_eq!(
            read_local_command_request_at_boundary(&mut input),
            Ok(LocalAgentRequestBoundaryRead::CleanEof)
        );
    }

    #[test]
    fn valid_request_preserves_id_and_command() {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(270), LocalAgentCommand::GetPrivateDnsConfig)
            .expect("memory Request write succeeds");

        let outcome = read_local_command_request_at_boundary(&mut Cursor::new(bytes))
            .expect("valid Request reads");
        let LocalAgentRequestBoundaryRead::Request(request) = outcome else {
            panic!("expected Request outcome");
        };

        assert_eq!(request.request_id(), id(270));
        assert_eq!(request.command(), LocalAgentCommand::GetPrivateDnsConfig);
    }

    #[test]
    fn repeated_reads_preserve_frame_boundaries_then_report_clean_eof() {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(271), LocalAgentCommand::GetAgentStatus)
            .expect("first Request writes");
        write_local_command_request(&mut bytes, id(272), LocalAgentCommand::GetPrivateDnsConfig)
            .expect("second Request writes");
        let mut input = Cursor::new(bytes);

        let first = read_local_command_request_at_boundary(&mut input).expect("first reads");
        let second = read_local_command_request_at_boundary(&mut input).expect("second reads");
        let eof = read_local_command_request_at_boundary(&mut input).expect("EOF classifies");

        assert!(matches!(first, LocalAgentRequestBoundaryRead::Request(_)));
        assert!(matches!(second, LocalAgentRequestBoundaryRead::Request(_)));
        assert_eq!(eof, LocalAgentRequestBoundaryRead::CleanEof);
    }

    #[test]
    fn partial_header_is_not_clean_eof() {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(273), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");
        bytes.truncate(7);

        assert_eq!(
            read_local_command_request_at_boundary(&mut Cursor::new(bytes)),
            Err(LocalAgentRequestStreamReadError::Read(
                LocalIpcFrameReadError::TruncatedHeader
            ))
        );
    }

    #[test]
    fn complete_non_request_frame_preserves_decode_error() {
        let payload = LocalIpcPayload::new(vec![0, 1]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Response,
            id(274),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");

        assert_eq!(
            read_local_command_request_at_boundary(&mut Cursor::new(bytes)),
            Err(LocalAgentRequestStreamReadError::Decode(
                LocalAgentRequestFrameDecodeError::NonRequestKind
            ))
        );
    }

    #[test]
    fn unknown_command_is_not_clean_eof() {
        let payload = LocalIpcPayload::new(vec![0, 3]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(275),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");

        assert_eq!(
            read_local_command_request_at_boundary(&mut Cursor::new(bytes)),
            Err(LocalAgentRequestStreamReadError::Decode(
                LocalAgentRequestFrameDecodeError::Command(
                    LocalAgentRequestDecodeError::UnknownCommand
                )
            ))
        );
    }
}
