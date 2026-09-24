//! Guarded generic writer for validated terminal response frames.
//!
//! Phase 041 owns only an in-memory response-write safety state and delegates
//! bytes to the existing generic frame writer. It owns no socket or transport.

use std::io::Write;

use crate::frame_object::LocalIpcFrame;
use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};

use super::terminal_response::{LocalTerminalResponseError, validate_terminal_response_frame};

/// Response-side write safety state for one future connection instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalTerminalResponseWriteState {
    /// No ambiguous terminal-response write failure has occurred.
    #[default]
    Healthy,
    /// A terminal-response write failed and the stream may be desynchronized.
    WritePoisoned,
}

impl LocalTerminalResponseWriteState {
    /// Creates a healthy response-write state.
    #[must_use]
    pub const fn new() -> Self {
        Self::Healthy
    }

    /// Returns whether a terminal response may still be written.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns whether this response-write state is poisoned.
    #[must_use]
    pub const fn is_write_poisoned(self) -> bool {
        matches!(self, Self::WritePoisoned)
    }

    const fn poison(&mut self) {
        *self = Self::WritePoisoned;
    }
}

/// Validates and writes one terminal response only while the write state is healthy.
///
/// Ordering is strictly:
///
/// 1. reject an already-poisoned state before validation or I/O;
/// 2. validate the terminal Response/Error invariant;
/// 3. write the complete frame through the existing generic frame writer;
/// 4. on any generic write failure, transition to `WritePoisoned` before return.
///
/// Invalid in-memory terminal frames do not poison because no writer I/O occurs.
/// This function deliberately does not flush the writer.
///
/// # Errors
///
/// Returns [`LocalTerminalResponseWriteError::WritePoisoned`] when the state was
/// already poisoned, [`LocalTerminalResponseWriteError::InvalidFrame`] before
/// I/O when the frame is not a valid terminal response, or
/// [`LocalTerminalResponseWriteError::Write`] after poisoning the state when
/// generic frame writing fails.
pub fn write_terminal_response_guarded<W: Write>(
    state: &mut LocalTerminalResponseWriteState,
    writer: &mut W,
    frame: &LocalIpcFrame,
) -> Result<(), LocalTerminalResponseWriteError> {
    if state.is_write_poisoned() {
        return Err(LocalTerminalResponseWriteError::WritePoisoned);
    }

    validate_terminal_response_frame(frame)
        .map_err(LocalTerminalResponseWriteError::InvalidFrame)?;

    match write_frame(writer, frame) {
        Ok(()) => Ok(()),
        Err(error) => {
            state.poison();
            Err(LocalTerminalResponseWriteError::Write(error))
        }
    }
}

/// Phase 041 guarded terminal-response write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTerminalResponseWriteError {
    /// This response-write state was already poisoned.
    WritePoisoned,
    /// The supplied in-memory frame is not a valid terminal response.
    InvalidFrame(LocalTerminalResponseError),
    /// Generic frame writing failed and poisoned the response-write state.
    Write(LocalIpcFrameWriteError),
}

#[cfg(test)]
mod tests {
    use std::io::{Error, Result as IoResult, Write};

    use super::{
        LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
        write_terminal_response_guarded,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::writer::LocalIpcFrameWriteError;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::request_frame::build_local_command_request_frame;
    use crate::local_commands::terminal_response::LocalTerminalResponseError;
    use crate::local_commands::terminal_response::builder::build_terminal_response_frame;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn success_frame(value: u64) -> crate::frame_object::LocalIpcFrame {
        build_terminal_response_frame(id(value), LocalAgentResponseStatus::Ok, &[])
            .expect("valid terminal response frame")
    }

    #[test]
    fn valid_response_write_succeeds_and_state_remains_healthy() {
        let mut state = LocalTerminalResponseWriteState::new();
        let mut bytes = Vec::new();
        let frame = success_frame(220);

        write_terminal_response_guarded(&mut state, &mut bytes, &frame)
            .expect("memory response write succeeds");

        assert!(state.can_write());
        assert!(!state.is_write_poisoned());
        assert_eq!(bytes.len(), 26);
    }

    #[test]
    fn invalid_terminal_frame_is_rejected_before_io_without_poisoning() {
        let mut state = LocalTerminalResponseWriteState::new();
        let mut writer = CountingWriter::default();
        let request = build_local_command_request_frame(id(221), LocalAgentCommand::GetAgentStatus)
            .expect("valid Request frame");

        assert_eq!(
            write_terminal_response_guarded(&mut state, &mut writer, &request),
            Err(LocalTerminalResponseWriteError::InvalidFrame(
                LocalTerminalResponseError::RequestKind
            ))
        );
        assert_eq!(writer.written, 0);
        assert!(state.can_write());
    }

    #[test]
    fn header_write_failure_poisons_response_state() {
        let mut state = LocalTerminalResponseWriteState::new();
        let mut writer = FailAfter::new(0);
        let frame = success_frame(222);

        assert_eq!(
            write_terminal_response_guarded(&mut state, &mut writer, &frame),
            Err(LocalTerminalResponseWriteError::Write(
                LocalIpcFrameWriteError::HeaderIo
            ))
        );
        assert!(state.is_write_poisoned());
    }

    #[test]
    fn payload_write_failure_poisons_response_state() {
        let mut state = LocalTerminalResponseWriteState::new();
        let mut writer = FailAfter::new(24);
        let frame = success_frame(223);

        assert_eq!(
            write_terminal_response_guarded(&mut state, &mut writer, &frame),
            Err(LocalTerminalResponseWriteError::Write(
                LocalIpcFrameWriteError::PayloadIo
            ))
        );
        assert_eq!(writer.written, 24);
        assert!(state.is_write_poisoned());
    }

    #[test]
    fn poisoned_state_rejects_later_write_before_io() {
        let mut state = LocalTerminalResponseWriteState::new();
        let mut failing_writer = FailAfter::new(0);
        let first = success_frame(224);
        assert!(write_terminal_response_guarded(&mut state, &mut failing_writer, &first).is_err());
        assert!(state.is_write_poisoned());

        let mut later_writer = CountingWriter::default();
        let later = success_frame(225);
        assert_eq!(
            write_terminal_response_guarded(&mut state, &mut later_writer, &later),
            Err(LocalTerminalResponseWriteError::WritePoisoned)
        );
        assert_eq!(later_writer.written, 0);
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
