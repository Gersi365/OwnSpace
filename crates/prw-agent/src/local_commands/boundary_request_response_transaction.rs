//! Boundary-aware one-request policy processing and guarded response write.
//!
//! Phase 049 composes the Phase 048 boundary-aware policy processor with the
//! existing Phase 041 guarded terminal-response writer. It owns no transport.

use std::io::{Read, Write};

use prw_policy::PolicyEvaluator;

use super::boundary_policy_processor::{
    LocalBoundaryPolicyResponse, read_and_build_policy_response_at_boundary,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_processor::LocalRequestProcessorError;
use super::response_writer::{
    LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    write_terminal_response_guarded,
};
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Successful Phase 049 boundary-aware transaction outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBoundaryRequestResponseOutcome {
    /// The peer reached EOF before any byte of a new frame was acquired.
    CleanEof,
    /// One policy-gated terminal response was written successfully.
    ResponseWritten,
}

/// Processes one boundary-aware Request attempt and writes its terminal response.
///
/// An already-poisoned response-write state rejects before input consumption.
/// Clean EOF returns without output. A valid Request is processed by Phase 048
/// and its terminal frame is emitted through the Phase 041 guarded writer.
///
/// # Errors
///
/// Returns [`LocalBoundaryRequestResponseError::ResponseWrite`] immediately for
/// an already-poisoned response state or after a guarded response-write failure.
/// Returns [`LocalBoundaryRequestResponseError::Processing`] for boundary,
/// Request-decoding, or policy-response construction failures.
pub fn process_and_write_one_read_only_request_at_boundary<
    R: Read,
    W: Write,
    E: PolicyEvaluator + ?Sized,
>(
    reader: &mut R,
    writer: &mut W,
    response_write_state: &mut LocalTerminalResponseWriteState,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalBoundaryRequestResponseOutcome, LocalBoundaryRequestResponseError> {
    if response_write_state.is_write_poisoned() {
        return Err(LocalBoundaryRequestResponseError::ResponseWrite(
            LocalTerminalResponseWriteError::WritePoisoned,
        ));
    }

    match read_and_build_policy_response_at_boundary(
        reader,
        evaluator,
        status_snapshot,
        private_dns_snapshot,
    )
    .map_err(LocalBoundaryRequestResponseError::Processing)?
    {
        LocalBoundaryPolicyResponse::CleanEof => Ok(LocalBoundaryRequestResponseOutcome::CleanEof),
        LocalBoundaryPolicyResponse::Response(response) => {
            write_terminal_response_guarded(response_write_state, writer, &response)
                .map_err(LocalBoundaryRequestResponseError::ResponseWrite)?;
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        }
    }
}

/// Phase 049 boundary-aware transaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBoundaryRequestResponseError {
    /// Boundary/Request acquisition, decoding, or policy-response construction failed.
    Processing(LocalRequestProcessorError),
    /// Guarded terminal-response validation/writing failed.
    ResponseWrite(LocalTerminalResponseWriteError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Error, Read, Result as IoResult, Write};

    use super::{
        LocalBoundaryRequestResponseError, LocalBoundaryRequestResponseOutcome,
        process_and_write_one_read_only_request_at_boundary,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::{LocalIpcFrameReadError, read_frame};
    use crate::frame_object::writer::LocalIpcFrameWriteError;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::local_commands::request_processor::LocalRequestProcessorError;
    use crate::local_commands::response_writer::{
        LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    };
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
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
    fn already_poisoned_response_state_rejects_before_read_policy_or_write() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader =
            CountingReader::new(request_bytes(id(290), LocalAgentCommand::GetAgentStatus));
        let mut writer = CountingWriter::default();
        let mut state = LocalTerminalResponseWriteState::WritePoisoned;

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut reader,
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryRequestResponseError::ResponseWrite(
                LocalTerminalResponseWriteError::WritePoisoned
            ))
        );
        assert_eq!(reader.read_calls, 0);
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn clean_eof_returns_without_policy_or_write_and_keeps_state_healthy() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let mut writer = CountingWriter::default();
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut Cursor::new(Vec::<u8>::new()),
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof)
        );
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
        assert!(state.can_write());
    }

    #[test]
    fn allowed_request_writes_correlated_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut input = Cursor::new(request_bytes(id(291), LocalAgentCommand::GetAgentStatus));
        let mut output = Vec::new();
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );

        let frame = read_frame(&mut Cursor::new(output)).expect("response frame reads");
        let decoded = decode_success_status_frame(&frame).expect("status response decodes");
        assert_eq!(decoded.request_id(), id(291));
        assert_eq!(decoded.snapshot(), status);
        assert_eq!(policy.calls(), 1);
        assert!(state.can_write());
    }

    #[test]
    fn denied_request_writes_correlated_unauthorized_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let mut input = Cursor::new(request_bytes(
            id(292),
            LocalAgentCommand::GetPrivateDnsConfig,
        ));
        let mut output = Vec::new();
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );

        let frame = read_frame(&mut Cursor::new(output)).expect("response frame reads");
        let terminal =
            validate_terminal_response_frame(&frame).expect("terminal response validates");
        assert_eq!(terminal.request_id(), id(292));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
        assert_eq!(policy.calls(), 1);
        assert!(state.can_write());
    }

    #[test]
    fn truncated_request_stops_before_policy_and_response_write() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut input = request_bytes(id(293), LocalAgentCommand::GetAgentStatus);
        input.truncate(7);
        let mut writer = CountingWriter::default();
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut Cursor::new(input),
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryRequestResponseError::Processing(
                LocalRequestProcessorError::Request(LocalAgentRequestStreamReadError::Read(
                    LocalIpcFrameReadError::TruncatedHeader
                ))
            ))
        );
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
        assert!(state.can_write());
    }

    #[test]
    fn response_write_failure_poisons_state_after_policy_processing() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut input = Cursor::new(request_bytes(id(294), LocalAgentCommand::GetAgentStatus));
        let mut writer = FailAfter::new(24);
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request_at_boundary(
                &mut input,
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalBoundaryRequestResponseError::ResponseWrite(
                LocalTerminalResponseWriteError::Write(LocalIpcFrameWriteError::PayloadIo)
            ))
        );
        assert_eq!(policy.calls(), 1);
        assert_eq!(writer.written, 24);
        assert!(state.is_write_poisoned());
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
