//! One-request read, policy evaluation, and guarded terminal-response write.
//!
//! Phase 042 composes the Phase 040 request processor with the Phase 041
//! response writer over caller-supplied generic `Read`/`Write` objects. It owns
//! no socket and performs no peer authentication.

use std::io::{Read, Write};

use prw_policy::PolicyEvaluator;

use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_processor::{LocalRequestProcessorError, read_and_build_policy_response};
use super::response_writer::{
    LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    write_terminal_response_guarded,
};
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Processes and writes exactly one valid current local read-only Request.
///
/// Ordering is strictly:
///
/// 1. reject an already-poisoned response-write state before consuming input;
/// 2. read and fully decode one Request;
/// 3. evaluate policy and build the correlated terminal response in memory;
/// 4. validate/write that response through the guarded response writer.
///
/// Invalid/truncated Request input returns before response writing. A terminal
/// response write failure poisons the response-write state through Phase 041.
///
/// # Errors
///
/// Returns [`LocalRequestResponseTransactionError::ResponseWrite`] immediately
/// when the response-write state is already poisoned. Returns
/// [`LocalRequestResponseTransactionError::RequestProcessing`] for Request read,
/// decode, policy-response construction failures, or
/// [`LocalRequestResponseTransactionError::ResponseWrite`] for guarded response
/// validation/write failures.
pub fn process_and_write_one_read_only_request<R: Read, W: Write, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    response_write_state: &mut LocalTerminalResponseWriteState,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<(), LocalRequestResponseTransactionError> {
    if response_write_state.is_write_poisoned() {
        return Err(LocalRequestResponseTransactionError::ResponseWrite(
            LocalTerminalResponseWriteError::WritePoisoned,
        ));
    }

    let response =
        read_and_build_policy_response(reader, evaluator, status_snapshot, private_dns_snapshot)
            .map_err(LocalRequestResponseTransactionError::RequestProcessing)?;

    write_terminal_response_guarded(response_write_state, writer, &response)
        .map_err(LocalRequestResponseTransactionError::ResponseWrite)
}

/// Phase 042 one-request read/policy/write transaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRequestResponseTransactionError {
    /// Request acquisition/decoding or policy-response construction failed.
    RequestProcessing(LocalRequestProcessorError),
    /// Guarded terminal-response validation/writing failed.
    ResponseWrite(LocalTerminalResponseWriteError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Error, Read, Result as IoResult, Write};

    use super::{LocalRequestResponseTransactionError, process_and_write_one_read_only_request};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::codec::LocalAgentRequestDecodeError;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::LocalAgentRequestFrameDecodeError;
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
    fn already_poisoned_response_state_rejects_before_read_policy_or_write() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader =
            CountingReader::new(request_bytes(id(230), LocalAgentCommand::GetAgentStatus));
        let mut writer = CountingWriter::default();
        let mut state = LocalTerminalResponseWriteState::WritePoisoned;

        assert_eq!(
            process_and_write_one_read_only_request(
                &mut reader,
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalRequestResponseTransactionError::ResponseWrite(
                LocalTerminalResponseWriteError::WritePoisoned
            ))
        );
        assert_eq!(reader.read_calls, 0);
        assert_eq!(writer.written, 0);
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn allowed_request_writes_correlated_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader = Cursor::new(request_bytes(id(231), LocalAgentCommand::GetAgentStatus));
        let mut output = Vec::new();
        let mut state = LocalTerminalResponseWriteState::new();

        process_and_write_one_read_only_request(
            &mut reader,
            &mut output,
            &mut state,
            &policy,
            status,
            &dns,
        )
        .expect("allowed transaction succeeds");

        let frame = read_frame(&mut Cursor::new(output)).expect("response frame reads");
        let decoded = decode_success_status_frame(&frame).expect("status response decodes");
        assert_eq!(decoded.request_id(), id(231));
        assert_eq!(decoded.snapshot(), status);
        assert_eq!(policy.calls(), 1);
        assert!(state.can_write());
    }

    #[test]
    fn denied_request_writes_correlated_unauthorized_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let mut reader = Cursor::new(request_bytes(
            id(232),
            LocalAgentCommand::GetPrivateDnsConfig,
        ));
        let mut output = Vec::new();
        let mut state = LocalTerminalResponseWriteState::new();

        process_and_write_one_read_only_request(
            &mut reader,
            &mut output,
            &mut state,
            &policy,
            status,
            &dns,
        )
        .expect("denied transaction writes Unauthorized");

        let frame = read_frame(&mut Cursor::new(output)).expect("response frame reads");
        let terminal =
            validate_terminal_response_frame(&frame).expect("terminal response validates");
        assert_eq!(terminal.request_id(), id(232));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
        assert_eq!(policy.calls(), 1);
        assert!(state.can_write());
    }

    #[test]
    fn invalid_command_stops_before_policy_and_response_write() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let payload = LocalIpcPayload::new(vec![0, 3]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(233),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut input = Vec::new();
        write_frame(&mut input, &frame).expect("memory frame write succeeds");
        let mut output = Vec::new();
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request(
                &mut Cursor::new(input),
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalRequestResponseTransactionError::RequestProcessing(
                LocalRequestProcessorError::Request(LocalAgentRequestStreamReadError::Decode(
                    LocalAgentRequestFrameDecodeError::Command(
                        LocalAgentRequestDecodeError::UnknownCommand
                    )
                ))
            ))
        );
        assert_eq!(policy.calls(), 0);
        assert!(output.is_empty());
        assert!(state.can_write());
    }

    #[test]
    fn response_write_failure_poisons_state_after_valid_policy_processing() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut reader = Cursor::new(request_bytes(id(234), LocalAgentCommand::GetAgentStatus));
        let mut writer = FailAfter::new(24);
        let mut state = LocalTerminalResponseWriteState::new();

        assert_eq!(
            process_and_write_one_read_only_request(
                &mut reader,
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
            ),
            Err(LocalRequestResponseTransactionError::ResponseWrite(
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
