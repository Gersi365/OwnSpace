//! Pure in-memory connection send-state and write-poisoning semantics.
//!
//! Phase 034 models whether one future connection instance remains safe for
//! additional Request writes. It owns no socket or operating-system resource.

use std::io::Write;

use crate::LocalIpcRequestId;

use super::transaction::{
    LocalAgentTrackedRequestWriteError, register_and_write_local_command_request,
};
use crate::local_commands::LocalAgentCommand;
use crate::local_commands::request_tracker::LocalRequestTracker;

/// Provider-neutral send state for one future local IPC connection instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalConnectionSendState {
    /// No ambiguous write failure has occurred on this connection instance.
    #[default]
    Healthy,
    /// A Request write failed after registration and the stream may be desynchronized.
    WritePoisoned,
}

impl LocalConnectionSendState {
    /// Creates a healthy connection send-state.
    #[must_use]
    pub const fn new() -> Self {
        Self::Healthy
    }

    /// Returns whether new Request sends are still permitted.
    #[must_use]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns whether this connection instance has been write-poisoned.
    #[must_use]
    pub const fn is_write_poisoned(self) -> bool {
        matches!(self, Self::WritePoisoned)
    }

    const fn poison_after_write_failure(&mut self) {
        *self = Self::WritePoisoned;
    }
}

/// Sends one tracked Request only while the connection send-state is healthy.
///
/// A pre-existing `WritePoisoned` state rejects the attempt before frame build,
/// tracker registration, or writer I/O. A build or registration error leaves a
/// healthy state healthy. Any generic frame-write error permanently transitions
/// this state object to `WritePoisoned` before the error is returned.
///
/// # Errors
///
/// Returns [`LocalConnectionRequestSendError::WritePoisoned`] when the supplied
/// connection state was already poisoned. Returns
/// [`LocalConnectionRequestSendError::Request`] for the Phase 033 build,
/// registration, or write failure; a nested `Write` failure also poisons the
/// connection state.
pub fn send_tracked_local_command_request<W: Write>(
    state: &mut LocalConnectionSendState,
    writer: &mut W,
    tracker: &mut LocalRequestTracker,
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
) -> Result<(), LocalConnectionRequestSendError> {
    if state.is_write_poisoned() {
        return Err(LocalConnectionRequestSendError::WritePoisoned);
    }

    match register_and_write_local_command_request(writer, tracker, request_id, command) {
        Ok(()) => Ok(()),
        Err(error @ LocalAgentTrackedRequestWriteError::Write(_)) => {
            state.poison_after_write_failure();
            Err(LocalConnectionRequestSendError::Request(error))
        }
        Err(error) => Err(LocalConnectionRequestSendError::Request(error)),
    }
}

/// Phase 034 connection-aware Request send failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalConnectionRequestSendError {
    /// This connection instance was already write-poisoned before the send attempt.
    WritePoisoned,
    /// The underlying Phase 033 tracked Request transaction failed.
    Request(LocalAgentTrackedRequestWriteError),
}

#[cfg(test)]
mod tests {
    use std::io::{Error, Result as IoResult, Write};

    use super::{
        LocalConnectionRequestSendError, LocalConnectionSendState,
        send_tracked_local_command_request,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::writer::LocalIpcFrameWriteError;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::request_frame::transaction::LocalAgentTrackedRequestWriteError;
    use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn new_state_is_healthy_and_successful_send_keeps_it_healthy() {
        let mut state = LocalConnectionSendState::new();
        let mut tracker = LocalRequestTracker::new();
        let mut bytes = Vec::new();

        send_tracked_local_command_request(
            &mut state,
            &mut bytes,
            &mut tracker,
            id(160),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("healthy send succeeds");

        assert!(state.can_send());
        assert!(!state.is_write_poisoned());
        assert!(tracker.contains(id(160)));
    }

    #[test]
    fn registration_failure_does_not_poison_or_write() {
        let mut state = LocalConnectionSendState::new();
        let mut tracker = LocalRequestTracker::new();
        tracker
            .register(id(161))
            .expect("initial request registered");
        let mut writer = CountingWriter::default();

        assert_eq!(
            send_tracked_local_command_request(
                &mut state,
                &mut writer,
                &mut tracker,
                id(161),
                LocalAgentCommand::GetAgentStatus,
            ),
            Err(LocalConnectionRequestSendError::Request(
                LocalAgentTrackedRequestWriteError::Register(
                    LocalRequestTrackerError::DuplicateRequestId
                )
            ))
        );
        assert!(state.can_send());
        assert_eq!(writer.written, 0);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn write_failure_poisons_and_retains_outstanding_request() {
        let mut state = LocalConnectionSendState::new();
        let mut tracker = LocalRequestTracker::new();
        let mut writer = FailAfter::new(24);

        assert_eq!(
            send_tracked_local_command_request(
                &mut state,
                &mut writer,
                &mut tracker,
                id(162),
                LocalAgentCommand::GetPrivateDnsConfig,
            ),
            Err(LocalConnectionRequestSendError::Request(
                LocalAgentTrackedRequestWriteError::Write(LocalIpcFrameWriteError::PayloadIo)
            ))
        );
        assert!(state.is_write_poisoned());
        assert!(tracker.contains(id(162)));
        assert_eq!(writer.written, 24);
    }

    #[test]
    fn poisoned_state_rejects_later_send_before_tracker_or_io() {
        let mut state = LocalConnectionSendState::new();
        let mut tracker = LocalRequestTracker::new();
        let mut failing_writer = FailAfter::new(0);

        assert!(
            send_tracked_local_command_request(
                &mut state,
                &mut failing_writer,
                &mut tracker,
                id(163),
                LocalAgentCommand::GetAgentStatus,
            )
            .is_err()
        );
        assert!(state.is_write_poisoned());
        assert!(tracker.contains(id(163)));

        let tracker_len_before = tracker.len();
        let mut later_writer = CountingWriter::default();
        assert_eq!(
            send_tracked_local_command_request(
                &mut state,
                &mut later_writer,
                &mut tracker,
                id(164),
                LocalAgentCommand::GetPrivateDnsConfig,
            ),
            Err(LocalConnectionRequestSendError::WritePoisoned)
        );
        assert_eq!(later_writer.written, 0);
        assert_eq!(tracker.len(), tracker_len_before);
        assert!(!tracker.contains(id(164)));
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
