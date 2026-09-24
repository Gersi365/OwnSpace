//! Outstanding-request registration and write transaction semantics.
//!
//! Phase 033 remains generic over `std::io::Write`; it does not create or own a
//! live connection. Registration happens before the first byte is written.

use std::io::Write;

use crate::LocalIpcRequestId;
use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};

use super::{LocalAgentRequestFrameBuildError, build_local_command_request_frame};
use crate::local_commands::LocalAgentCommand;
use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};

/// Builds, registers, and writes one tracked local read-only Request.
///
/// Ordering is strictly:
///
/// 1. build the complete validated Request frame;
/// 2. register the request ID as outstanding;
/// 3. write the complete frame through the generic writer.
///
/// A registration failure performs no write. A write failure intentionally does
/// not roll back the registration because the byte stream may already contain a
/// prefix of the frame and therefore must not silently continue with request-ID
/// reuse.
///
/// # Errors
///
/// Returns [`LocalAgentTrackedRequestWriteError::Build`] before tracker mutation
/// if frame construction fails, [`LocalAgentTrackedRequestWriteError::Register`]
/// before I/O if tracker registration fails, or
/// [`LocalAgentTrackedRequestWriteError::Write`] after registration if the
/// generic frame write fails. On `Write`, the request ID remains outstanding.
pub fn register_and_write_local_command_request<W: Write>(
    writer: &mut W,
    tracker: &mut LocalRequestTracker,
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
) -> Result<(), LocalAgentTrackedRequestWriteError> {
    let frame = build_local_command_request_frame(request_id, command)
        .map_err(LocalAgentTrackedRequestWriteError::Build)?;
    tracker
        .register(request_id)
        .map_err(LocalAgentTrackedRequestWriteError::Register)?;
    write_frame(writer, &frame).map_err(LocalAgentTrackedRequestWriteError::Write)
}

/// Phase 033 tracked Request write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAgentTrackedRequestWriteError {
    /// Request frame construction failed before tracker mutation or I/O.
    Build(LocalAgentRequestFrameBuildError),
    /// Outstanding-request registration failed before any byte was written.
    Register(LocalRequestTrackerError),
    /// Frame writing failed after the request ID became outstanding.
    Write(LocalIpcFrameWriteError),
}

#[cfg(test)]
mod tests {
    use std::io::{Error, Result as IoResult, Write};

    use super::{LocalAgentTrackedRequestWriteError, register_and_write_local_command_request};
    use crate::LocalIpcRequestId;
    use crate::frame_object::writer::LocalIpcFrameWriteError;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::request_frame::LOCAL_AGENT_REQUEST_WIRE_LENGTH;
    use crate::local_commands::request_tracker::{
        LOCAL_IPC_MAX_OUTSTANDING_REQUESTS, LocalRequestTracker, LocalRequestTrackerError,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn successful_write_leaves_request_outstanding() {
        let mut tracker = LocalRequestTracker::new();
        let mut bytes = Vec::new();

        register_and_write_local_command_request(
            &mut bytes,
            &mut tracker,
            id(150),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("tracked request write succeeds");

        assert_eq!(bytes.len(), LOCAL_AGENT_REQUEST_WIRE_LENGTH);
        assert!(tracker.contains(id(150)));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn duplicate_registration_prevents_all_io() {
        let mut tracker = LocalRequestTracker::new();
        tracker
            .register(id(151))
            .expect("initial request registered");
        let mut writer = CountingWriter::default();

        assert_eq!(
            register_and_write_local_command_request(
                &mut writer,
                &mut tracker,
                id(151),
                LocalAgentCommand::GetAgentStatus,
            ),
            Err(LocalAgentTrackedRequestWriteError::Register(
                LocalRequestTrackerError::DuplicateRequestId
            ))
        );
        assert_eq!(writer.written, 0);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn capacity_failure_prevents_all_io() {
        let mut tracker = LocalRequestTracker::new();
        for value in 1_u64..=64 {
            tracker.register(id(value)).expect("within tracker bound");
        }
        assert_eq!(tracker.len(), LOCAL_IPC_MAX_OUTSTANDING_REQUESTS);
        let mut writer = CountingWriter::default();

        assert_eq!(
            register_and_write_local_command_request(
                &mut writer,
                &mut tracker,
                id(152),
                LocalAgentCommand::GetPrivateDnsConfig,
            ),
            Err(LocalAgentTrackedRequestWriteError::Register(
                LocalRequestTrackerError::TooManyOutstandingRequests
            ))
        );
        assert_eq!(writer.written, 0);
        assert_eq!(tracker.len(), LOCAL_IPC_MAX_OUTSTANDING_REQUESTS);
    }

    #[test]
    fn header_write_failure_retains_registration() {
        let mut tracker = LocalRequestTracker::new();
        let mut writer = FailAfter::new(0);

        assert_eq!(
            register_and_write_local_command_request(
                &mut writer,
                &mut tracker,
                id(153),
                LocalAgentCommand::GetAgentStatus,
            ),
            Err(LocalAgentTrackedRequestWriteError::Write(
                LocalIpcFrameWriteError::HeaderIo
            ))
        );
        assert!(tracker.contains(id(153)));
    }

    #[test]
    fn payload_write_failure_retains_registration() {
        let mut tracker = LocalRequestTracker::new();
        let mut writer = FailAfter::new(24);

        assert_eq!(
            register_and_write_local_command_request(
                &mut writer,
                &mut tracker,
                id(154),
                LocalAgentCommand::GetPrivateDnsConfig,
            ),
            Err(LocalAgentTrackedRequestWriteError::Write(
                LocalIpcFrameWriteError::PayloadIo
            ))
        );
        assert_eq!(writer.written, 24);
        assert!(tracker.contains(id(154)));
        assert_eq!(tracker.len(), 1);
    }

    #[derive(Default)]
    struct CountingWriter {
        written: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
            self.written += buffer.len();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
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
