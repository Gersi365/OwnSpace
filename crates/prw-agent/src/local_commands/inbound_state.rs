//! Pure in-memory inbound Request processing state.
//!
//! Phase 043 prevents a future connection instance from continuing to consume
//! Requests after a Request read/decode failure. It owns no transport.

use std::io::{Read, Write};

use prw_policy::PolicyEvaluator;

use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_processor::LocalRequestProcessorError;
use super::request_response_transaction::{
    LocalRequestResponseTransactionError, process_and_write_one_read_only_request,
};
use super::response_writer::LocalTerminalResponseWriteState;
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Inbound Request-processing safety state for one future connection instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalInboundRequestState {
    /// No Request read/decode failure has occurred.
    #[default]
    Healthy,
    /// A Request read/decode failure occurred and the input stream must not continue.
    ReadPoisoned,
}

impl LocalInboundRequestState {
    /// Creates a healthy inbound-processing state.
    #[must_use]
    pub const fn new() -> Self {
        Self::Healthy
    }

    /// Returns whether another Request may be consumed.
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns whether the inbound state is poisoned.
    #[must_use]
    pub const fn is_read_poisoned(self) -> bool {
        matches!(self, Self::ReadPoisoned)
    }

    const fn poison(&mut self) {
        *self = Self::ReadPoisoned;
    }
}

/// Processes one Request only while the inbound state is healthy.
///
/// An already-poisoned inbound state rejects before any input read, policy
/// evaluation, or response write. If Phase 042 returns a Request read/decode
/// failure, this state transitions to `ReadPoisoned` before the error returns.
/// Response construction/write failures do not by themselves poison inbound
/// framing state; response write ambiguity remains owned by Phase 041.
///
/// # Errors
///
/// Returns [`LocalInboundTransactionError::ReadPoisoned`] when the inbound state
/// was already poisoned, or [`LocalInboundTransactionError::Transaction`] for
/// the delegated Phase 042 failure. Request read/decode failures inside the
/// latter also poison the inbound state.
pub fn process_one_with_inbound_guard<R: Read, W: Write, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    inbound_state: &mut LocalInboundRequestState,
    response_write_state: &mut LocalTerminalResponseWriteState,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<(), LocalInboundTransactionError> {
    if inbound_state.is_read_poisoned() {
        return Err(LocalInboundTransactionError::ReadPoisoned);
    }

    match process_and_write_one_read_only_request(
        reader,
        writer,
        response_write_state,
        evaluator,
        status_snapshot,
        private_dns_snapshot,
    ) {
        Ok(()) => Ok(()),
        Err(
            error @ LocalRequestResponseTransactionError::RequestProcessing(
                LocalRequestProcessorError::Request(_),
            ),
        ) => {
            inbound_state.poison();
            Err(LocalInboundTransactionError::Transaction(error))
        }
        Err(error) => Err(LocalInboundTransactionError::Transaction(error)),
    }
}

/// Phase 043 inbound-guarded transaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalInboundTransactionError {
    /// This inbound connection state was already poisoned before the attempt.
    ReadPoisoned,
    /// The delegated Phase 042 transaction failed.
    Transaction(LocalRequestResponseTransactionError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Error, Read, Result as IoResult, Write};

    use super::{
        LocalInboundRequestState, LocalInboundTransactionError, process_one_with_inbound_guard,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::codec::LocalAgentRequestDecodeError;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::LocalAgentRequestFrameDecodeError;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::local_commands::request_processor::LocalRequestProcessorError;
    use crate::local_commands::request_response_transaction::LocalRequestResponseTransactionError;
    use crate::local_commands::response_writer::{
        LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::{LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion};
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
        allowed: Option<Capability>,
        calls: Cell<usize>,
    }

    impl CountingPolicy {
        const fn allow(capability: Capability) -> Self {
            Self {
                allowed: Some(capability),
                calls: Cell::new(0),
            }
        }

        const fn deny_all() -> Self {
            Self {
                allowed: None,
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl PolicyEvaluator for CountingPolicy {
        fn evaluate(&self, capability: Capability) -> Decision {
            self.calls.set(self.calls.get() + 1);
            if self.allowed == Some(capability) {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    #[test]
    fn successful_transaction_leaves_inbound_state_healthy() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader = Cursor::new(request_bytes(id(240), LocalAgentCommand::GetAgentStatus));
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();

        process_one_with_inbound_guard(
            &mut reader,
            &mut output,
            &mut inbound,
            &mut response,
            &policy,
            status,
            &dns,
        )
        .expect("healthy transaction succeeds");

        assert!(inbound.can_read());
        assert!(response.can_write());
        assert_eq!(policy.calls(), 1);
        assert!(!output.is_empty());
    }

    #[test]
    fn unknown_command_poisons_inbound_before_return() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let payload = LocalIpcPayload::new(vec![0, 3]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(241),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut input = Vec::new();
        write_frame(&mut input, &frame).expect("memory frame write succeeds");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_one_with_inbound_guard(
                &mut Cursor::new(input),
                &mut output,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalInboundTransactionError::Transaction(
                LocalRequestResponseTransactionError::RequestProcessing(
                    LocalRequestProcessorError::Request(LocalAgentRequestStreamReadError::Decode(
                        LocalAgentRequestFrameDecodeError::Command(
                            LocalAgentRequestDecodeError::UnknownCommand
                        )
                    ))
                )
            ))
        );
        assert!(inbound.is_read_poisoned());
        assert!(response.can_write());
        assert_eq!(policy.calls(), 0);
        assert!(output.is_empty());
    }

    #[test]
    fn poisoned_inbound_rejects_later_attempt_before_read_policy_or_write() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut inbound = LocalInboundRequestState::ReadPoisoned;
        let mut response = LocalTerminalResponseWriteState::new();
        let mut reader =
            CountingReader::new(request_bytes(id(242), LocalAgentCommand::GetAgentStatus));
        let mut writer = CountingWriter::default();

        assert_eq!(
            process_one_with_inbound_guard(
                &mut reader,
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalInboundTransactionError::ReadPoisoned)
        );
        assert_eq!(reader.read_calls, 0);
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn response_write_failure_does_not_misclassify_inbound_state() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader = Cursor::new(request_bytes(id(243), LocalAgentCommand::GetAgentStatus));
        let mut writer = FailAfter::new(24);
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_one_with_inbound_guard(
                &mut reader,
                &mut writer,
                &mut inbound,
                &mut response,
                &policy,
                status,
                &dns,
            ),
            Err(LocalInboundTransactionError::Transaction(
                LocalRequestResponseTransactionError::ResponseWrite(
                    LocalTerminalResponseWriteError::Write(LocalIpcFrameWriteError::PayloadIo)
                )
            ))
        );
        assert!(inbound.can_read());
        assert!(response.is_write_poisoned());
        assert_eq!(policy.calls(), 1);
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
