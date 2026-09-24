//! Bounded provider-neutral server connection processing loop.
//!
//! Phase 052 repeatedly invokes the Phase 051 boundary-aware aggregate entry
//! point for a caller-supplied non-zero work budget. It owns no transport.

use std::io::{Read, Write};
use std::num::NonZeroUsize;

use prw_policy::PolicyEvaluator;

use super::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::server_connection_state::{
    LocalBoundaryServerConnectionProcessError, LocalServerConnectionState,
    process_one_at_boundary_on_server_connection,
};
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Successful stop reason for one bounded connection-loop invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalServerConnectionLoopStop {
    /// Orderly EOF was reached before another frame began.
    CleanEof {
        /// Number of terminal responses written during this invocation.
        responses_written: usize,
    },
    /// The caller-supplied work budget was consumed exactly.
    BudgetExhausted {
        /// Number of terminal responses written during this invocation.
        responses_written: usize,
    },
}

/// Processes Requests until clean EOF, an error, or the caller-supplied budget.
///
/// Budget exhaustion returns immediately after the final permitted response and
/// does not probe the reader for another frame. A caller may invoke this function
/// again with the same stream and aggregate state to resume processing.
///
/// # Errors
///
/// Returns the existing Phase 051 aggregate processing error immediately. Any
/// component-state transition performed by lower layers remains authoritative.
pub fn process_server_connection_with_budget<R: Read, W: Write, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    state: &mut LocalServerConnectionState,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    request_budget: NonZeroUsize,
) -> Result<LocalServerConnectionLoopStop, LocalBoundaryServerConnectionProcessError> {
    for responses_written in 0..request_budget.get() {
        match process_one_at_boundary_on_server_connection(
            reader,
            writer,
            state,
            evaluator,
            status_snapshot,
            private_dns_snapshot,
        )? {
            LocalBoundaryRequestResponseOutcome::CleanEof => {
                return Ok(LocalServerConnectionLoopStop::CleanEof { responses_written });
            }
            LocalBoundaryRequestResponseOutcome::ResponseWritten => {}
        }
    }

    Ok(LocalServerConnectionLoopStop::BudgetExhausted {
        responses_written: request_budget.get(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Error, Result as IoResult, Write};
    use std::num::NonZeroUsize;

    use super::{LocalServerConnectionLoopStop, process_server_connection_with_budget};
    use crate::LocalIpcRequestId;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::{
        LOCAL_AGENT_REQUEST_WIRE_LENGTH, stream::write_local_command_request,
    };
    use crate::local_commands::server_connection_state::{
        LocalServerConnectionState, LocalServerConnectionUnusableReason,
    };
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn budget(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test budget is non-zero")
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
    fn empty_stream_stops_cleanly_without_policy_or_output() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut state = LocalServerConnectionState::new();
        let mut output = Vec::new();

        assert_eq!(
            process_server_connection_with_budget(
                &mut Cursor::new(Vec::<u8>::new()),
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(4),
            ),
            Ok(LocalServerConnectionLoopStop::CleanEof {
                responses_written: 0
            })
        );
        assert!(state.is_usable());
        assert!(output.is_empty());
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn loop_processes_multiple_requests_then_clean_eof() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut state = LocalServerConnectionState::new();
        let mut bytes = request_bytes(id(320), LocalAgentCommand::GetAgentStatus);
        bytes.extend(request_bytes(
            id(321),
            LocalAgentCommand::GetPrivateDnsConfig,
        ));
        let mut input = Cursor::new(bytes);
        let mut output = Vec::new();

        assert_eq!(
            process_server_connection_with_budget(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(3),
            ),
            Ok(LocalServerConnectionLoopStop::CleanEof {
                responses_written: 2
            })
        );
        assert!(state.is_usable());
        assert_eq!(policy.calls(), 2);
        assert!(!output.is_empty());
    }

    #[test]
    fn budget_exhaustion_does_not_probe_following_frame_and_can_resume() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut state = LocalServerConnectionState::new();
        let mut bytes = request_bytes(id(322), LocalAgentCommand::GetAgentStatus);
        bytes.extend(request_bytes(id(323), LocalAgentCommand::GetAgentStatus));
        let mut input = Cursor::new(bytes);
        let mut output = Vec::new();

        assert_eq!(
            process_server_connection_with_budget(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(1),
            ),
            Ok(LocalServerConnectionLoopStop::BudgetExhausted {
                responses_written: 1
            })
        );
        assert_eq!(input.position(), LOCAL_AGENT_REQUEST_WIRE_LENGTH as u64);

        assert_eq!(
            process_server_connection_with_budget(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(1),
            ),
            Ok(LocalServerConnectionLoopStop::BudgetExhausted {
                responses_written: 1
            })
        );
        assert_eq!(
            input.position(),
            (LOCAL_AGENT_REQUEST_WIRE_LENGTH * 2) as u64
        );

        assert_eq!(
            process_server_connection_with_budget(
                &mut input,
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(1),
            ),
            Ok(LocalServerConnectionLoopStop::CleanEof {
                responses_written: 0
            })
        );
        assert!(state.is_usable());
        assert_eq!(policy.calls(), 2);
    }

    #[test]
    fn truncation_after_one_success_stops_with_inbound_unusable_state() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut state = LocalServerConnectionState::new();
        let mut bytes = request_bytes(id(324), LocalAgentCommand::GetAgentStatus);
        let mut second = request_bytes(id(325), LocalAgentCommand::GetAgentStatus);
        second.truncate(5);
        bytes.extend(second);
        let mut output = Vec::new();

        assert!(
            process_server_connection_with_budget(
                &mut Cursor::new(bytes),
                &mut output,
                &mut state,
                &policy,
                status,
                &dns,
                budget(3),
            )
            .is_err()
        );
        assert_eq!(
            state.unusable_reason(),
            Some(LocalServerConnectionUnusableReason::InboundRead)
        );
        assert_eq!(policy.calls(), 1);
        assert!(!output.is_empty());
    }

    #[test]
    fn write_failure_stops_with_response_unusable_state() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut state = LocalServerConnectionState::new();
        let mut writer = FailAfter::new(24);

        assert!(
            process_server_connection_with_budget(
                &mut Cursor::new(request_bytes(id(326), LocalAgentCommand::GetAgentStatus)),
                &mut writer,
                &mut state,
                &policy,
                status,
                &dns,
                budget(2),
            )
            .is_err()
        );
        assert_eq!(
            state.unusable_reason(),
            Some(LocalServerConnectionUnusableReason::ResponseWrite)
        );
        assert_eq!(policy.calls(), 1);
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
