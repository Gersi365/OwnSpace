//! Generic stream composition for successful `GetAgentStatus` response frames.
//!
//! Phase 024 uses only `std::io::Read` and `std::io::Write`. It does not create
//! or configure a socket.

use std::io::{Read, Write};

use super::{
    LocalAgentStatusFrame, LocalAgentStatusFrameDecodeError, build_success_status_frame,
    decode_success_status_frame,
};
use crate::LocalIpcRequestId;
use crate::frame_object::reader::{LocalIpcFrameReadError, read_frame};
use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;
use crate::local_commands::terminal_response::builder::LocalTerminalResponseBuildError;

/// Builds and writes one successful `GetAgentStatus` frame to a generic stream.
///
/// The function deliberately does not flush the writer.
///
/// # Errors
///
/// Returns [`LocalAgentStatusStreamWriteError::Build`] when complete status
/// frame construction fails, or [`LocalAgentStatusStreamWriteError::Write`]
/// when the validated frame cannot be fully written.
pub fn write_success_status_response<W: Write>(
    writer: &mut W,
    request_id: LocalIpcRequestId,
    snapshot: LocalAgentStatusSnapshot,
) -> Result<(), LocalAgentStatusStreamWriteError> {
    let frame = build_success_status_frame(request_id, snapshot)
        .map_err(LocalAgentStatusStreamWriteError::Build)?;
    write_frame(writer, &frame).map_err(LocalAgentStatusStreamWriteError::Write)
}

/// Reads and decodes one successful `GetAgentStatus` frame from a generic stream.
///
/// # Errors
///
/// Returns [`LocalAgentStatusStreamReadError::Read`] when one complete validated
/// frame cannot be acquired, or [`LocalAgentStatusStreamReadError::Decode`]
/// when that frame is not a valid successful `GetAgentStatus` response.
pub fn read_success_status_response<R: Read>(
    reader: &mut R,
) -> Result<LocalAgentStatusFrame, LocalAgentStatusStreamReadError> {
    let frame = read_frame(reader).map_err(LocalAgentStatusStreamReadError::Read)?;
    decode_success_status_frame(&frame).map_err(LocalAgentStatusStreamReadError::Decode)
}

/// Phase 024 write-side composition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusStreamWriteError {
    /// Complete status-frame construction failed.
    Build(LocalTerminalResponseBuildError),
    /// Generic frame writing failed.
    Write(LocalIpcFrameWriteError),
}

/// Phase 024 read-side composition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentStatusStreamReadError {
    /// Generic frame acquisition failed.
    Read(LocalIpcFrameReadError),
    /// Acquired frame failed successful status-frame decoding.
    Decode(LocalAgentStatusFrameDecodeError),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{
        LocalAgentStatusStreamReadError, read_success_status_response,
        write_success_status_response,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    fn id() -> LocalIpcRequestId {
        LocalIpcRequestId::new(80).expect("non-zero request id")
    }

    #[test]
    fn status_response_wire_length_is_exactly_thirty_one_bytes() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();

        write_success_status_response(&mut bytes, id(), snapshot).expect("memory write succeeds");

        assert_eq!(bytes.len(), 31);
    }

    #[test]
    fn every_runtime_state_round_trips_through_generic_stream_io() {
        for state in [
            LocalAgentRuntimeState::Starting,
            LocalAgentRuntimeState::Ready,
            LocalAgentRuntimeState::Degraded,
            LocalAgentRuntimeState::Stopping,
        ] {
            let snapshot = LocalAgentStatusSnapshot::current(state);
            let mut bytes = Vec::new();
            write_success_status_response(&mut bytes, id(), snapshot)
                .expect("memory write succeeds");
            let mut cursor = Cursor::new(bytes);
            let decoded =
                read_success_status_response(&mut cursor).expect("memory read/decode succeeds");

            assert_eq!(decoded.request_id(), id());
            assert_eq!(decoded.snapshot(), snapshot);
        }
    }

    #[test]
    fn reader_consumes_exactly_one_frame_and_leaves_trailing_bytes() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(), snapshot).expect("memory write succeeds");
        bytes.extend_from_slice(&[9, 8, 7]);
        let mut cursor = Cursor::new(bytes);

        read_success_status_response(&mut cursor).expect("first frame succeeds");
        assert_eq!(cursor.position(), 31);

        let mut trailing = Vec::new();
        cursor.read_to_end(&mut trailing).expect("trailing read");
        assert_eq!(trailing, [9, 8, 7]);
    }

    #[test]
    fn truncated_header_and_payload_preserve_generic_read_errors() {
        let mut short_header = Cursor::new(vec![0_u8; 10]);
        assert_eq!(
            read_success_status_response(&mut short_header),
            Err(LocalAgentStatusStreamReadError::Read(
                LocalIpcFrameReadError::TruncatedHeader
            ))
        );

        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let mut bytes = Vec::new();
        write_success_status_response(&mut bytes, id(), snapshot).expect("memory write succeeds");
        bytes.pop();
        let mut short_payload = Cursor::new(bytes);
        assert_eq!(
            read_success_status_response(&mut short_payload),
            Err(LocalAgentStatusStreamReadError::Read(
                LocalIpcFrameReadError::TruncatedPayload
            ))
        );
    }
}
