//! Boundary-aware inbound Request safety state composition.
//!
//! Phase 050 composes the Phase 043 inbound state with the Phase 049
//! clean-EOF-aware request/response transaction. It owns no transport.

use std::io::{Read, Write};

use prw_policy::PolicyEvaluator;

use super::boundary_request_response_transaction::{
    LocalBoundaryRequestResponseError, LocalBoundaryRequestResponseOutcome,
    process_and_write_one_read_only_request_at_boundary,
};
use super::inbound_state::LocalInboundRequestState;
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_processor::LocalRequestProcessorError;
use super::response_writer::LocalTerminalResponseWriteState;
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Processes one boundary-aware Request attempt only while inbound state is healthy.
///
/// Clean EOF is a normal outcome and does not poison inbound state. Only a
/// delegated Request acquisition/decoding failure transitions inbound state to
/// `ReadPoisoned`. Response construction/write failures preserve inbound state.
///
/// # Errors
///
/// Returns [`LocalBoundaryInboundError::ReadPoisoned`] when inbound state was
/// already poisoned, or [`LocalBoundaryInboundError::Transaction`] for the
/// delegated Phase 049 failure after any applicable state transition.
pub fn process_one_with_boundary_inbound_guard<R: Read, W: Write, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    inbound_state: &mut LocalInboundRequestState,
    response_write_state: &mut LocalTerminalResponseWriteState,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalBoundaryRequestResponseOutcome, LocalBoundaryInboundError> {
    if inbound_state.is_read_poisoned() {
        return Err(LocalBoundaryInboundError::ReadPoisoned);
    }

    match process_and_write_one_read_only_request_at_boundary(
        reader,
        writer,
        response_write_state,
        evaluator,
        status_snapshot,
        private_dns_snapshot,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(
            error @ LocalBoundaryRequestResponseError::Processing(
                LocalRequestProcessorError::Request(_),
            ),
        ) => {
            *inbound_state = LocalInboundRequestState::ReadPoisoned;
            Err(LocalBoundaryInboundError::Transaction(error))
        }
        Err(error) => Err(LocalBoundaryInboundError::Transaction(error)),
    }
}

/// Phase 050 boundary-aware inbound-guard failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBoundaryInboundError {
    /// This inbound connection state was already poisoned before the attempt.
    ReadPoisoned,
    /// The delegated Phase 049 transaction failed.
    Transaction(LocalBoundaryRequestResponseError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Error, Read, Result as IoResult, Write};

    use super::{LocalBoundaryInboundError, process_one_with_boundary_inbound_guard};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::LocalIpcFrameWriteError;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::boundary_request_response_transaction::{
        LocalBoundaryRequestResponseError, LocalBoundaryRequestResponseOutcome,
    };
    use crate::local_commands::inbound_state::LocalInboundRequestState;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::local_commands::request_processor::LocalRequestProcessorError;
    use crate::local_commands::response_writer::{
        LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn request_bytes(request_id: LocalIpcRequestId, command: LocalAgentCommand) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, request_id, command)
            .expect("memory Request write succeeds");
        bytes
    }

    struct CountingPolicy {
        calls: Cell<usize>,
    }

    impl CountingPolicy {
        const fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl PolicyEvaluator for CountingPolicy {
        fn evaluate(&self, _capability: Capability) -> Decision {
            self.calls.set(self.calls.get() + 1);
            Decision::Allow
        }
    }

    #[test]
    fn clean_eof_is_normal_and_leaves_both_states_healthy() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut writer = CountingWriter::default();

        assert_eq!(
            process_one_with_boundary_inbound_guard(
                &mut Cursor::new(Vec::<u8>::new()),
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof)
        );
        assert!(inbound.can_read());
        assert!(response.can_write());
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn successful_request_leaves_both_states_healthy() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut output = Vec::new();

        assert_eq!(
            process_one_with_boundary_inbound_guard(
                &mut Cursor::new(request_bytes(id(300), LocalAgentCommand::GetAgentStatus)),
                &mut output,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );
        assert!(inbound.can_read());
        assert!(response.can_write());
        assert_eq!(policy.calls(), 1);
        assert!(!output.is_empty());
    }

    #[test]
    fn truncated_request_poisons_only_inbound_state() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut input = request_bytes(id(301), LocalAgentCommand::GetAgentStatus);
        input.truncate(5);
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut writer = CountingWriter::default();

        assert_eq!(
            process_one_with_boundary_inbound_guard(
                &mut Cursor::new(input),
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryInboundError::Transaction(
                LocalBoundaryRequestResponseError::Processing(LocalRequestProcessorError::Request(
                    LocalAgentRequestStreamReadError::Read(LocalIpcFrameReadError::TruncatedHeader)
                ))
            ))
        );
        assert!(inbound.is_read_poisoned());
        assert!(response.can_write());
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn preexisting_inbound_poison_rejects_before_any_io() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut inbound = LocalInboundRequestState::ReadPoisoned;
        let mut response = LocalTerminalResponseWriteState::new();
        let mut reader =
            CountingReader::new(request_bytes(id(302), LocalAgentCommand::GetAgentStatus));
        let mut writer = CountingWriter::default();

        assert_eq!(
            process_one_with_boundary_inbound_guard(
                &mut reader,
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryInboundError::ReadPoisoned)
        );
        assert_eq!(reader.read_calls, 0);
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn response_write_failure_poisons_only_response_state() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut writer = FailAfter::new(24);

        assert_eq!(
            process_one_with_boundary_inbound_guard(
                &mut Cursor::new(request_bytes(id(303), LocalAgentCommand::GetAgentStatus)),
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryInboundError::Transaction(
                LocalBoundaryRequestResponseError::ResponseWrite(
                    LocalTerminalResponseWriteError::Write(LocalIpcFrameWriteError::PayloadIo)
                )
            ))
        );
        assert!(inbound.can_read());
        assert!(response.is_write_poisoned());
        assert_eq!(policy.calls(), 1);
        assert_eq!(writer.written, 24);
    }

    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        read_calls: usize,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                read_calls: 0,
            }
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
            self.read_calls += 1;
            self.inner.read(buffer)
        }
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
