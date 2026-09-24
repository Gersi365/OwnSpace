//! Finite authenticated Linux session worker body.
//!
//! Phase 076 consumes one authenticated session and one Phase 075 capacity
//! permit, applies Phase 074 deadlines to each Request, and never returns the
//! connection for reuse. It does not spawn a thread or accept a connection.

use std::num::NonZeroUsize;
use std::os::unix::net::UnixStream;

use prw_policy::PolicyEvaluator;

use super::authenticated_session::{
    AuthenticatedLocalLinuxSession, LocalLinuxDeadlineSessionProcessError,
};
use super::deadline_io::LocalLinuxIoBudget;
use super::worker_capacity::LocalLinuxWorkerPermit;
use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

#[path = "linux_session_worker/management_agent_status.rs"]
mod management_agent_status;

/// Immutable finite-worker processing bounds supplied by the future runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLinuxSessionWorkerConfig {
    requests: NonZeroUsize,
    read_io: LocalLinuxIoBudget,
    write_io: LocalLinuxIoBudget,
}

impl LocalLinuxSessionWorkerConfig {
    /// Creates one finite-worker configuration from already-validated bounds.
    #[must_use]
    pub const fn new(
        request_budget: NonZeroUsize,
        read_budget: LocalLinuxIoBudget,
        write_budget: LocalLinuxIoBudget,
    ) -> Self {
        Self {
            requests: request_budget,
            read_io: read_budget,
            write_io: write_budget,
        }
    }

    /// Returns the maximum Request count for this worker invocation.
    #[must_use]
    pub const fn request_budget(self) -> NonZeroUsize {
        self.requests
    }

    /// Returns the per-Request absolute read budget.
    #[must_use]
    pub const fn read_budget(self) -> LocalLinuxIoBudget {
        self.read_io
    }

    /// Returns the per-Request absolute response-write budget.
    #[must_use]
    pub const fn write_budget(self) -> LocalLinuxIoBudget {
        self.write_io
    }
}

/// Successful terminal reason for one finite authenticated-session worker body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxSessionWorkerStop {
    /// The peer reached clean EOF before another Request began.
    CleanEof {
        /// Number of terminal responses written before EOF.
        responses_written: usize,
    },
    /// The caller-supplied maximum Request count was consumed exactly.
    RequestBudgetExhausted {
        /// Number of terminal responses written; equal to the configured budget.
        responses_written: usize,
    },
}

/// Failure while running one finite authenticated-session worker body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxSessionWorkerError {
    /// One Request transaction failed after the stated number of prior responses.
    Processing {
        /// Number of terminal responses completed before the failing Request.
        responses_written: usize,
        /// Existing Phase 074 deadline-aware processing failure.
        error: LocalLinuxDeadlineSessionProcessError,
    },
    /// One fixed AgentStatus-management request failed after prior responses completed.
    AgentStatusManagementProcessing {
        /// Number of terminal responses completed before the failing request.
        responses_written: usize,
    },
}

/// Runs one authenticated session to a finite terminal condition.
///
/// The session and worker permit are consumed. The connection is never returned
/// for reuse: on clean EOF, processing failure, or Request-budget exhaustion the
/// function returns and drops the session stream. The permit remains live for
/// the entire function scope and is released by RAII on return/unwind.
///
/// Each Request receives a fresh Phase 074 absolute read deadline and an
/// independent deferred response-write deadline from `config`.
///
/// # Errors
///
/// Returns [`LocalLinuxSessionWorkerError::Processing`] on the first Phase 074
/// Request-processing failure, including the count of previously completed
/// responses.
pub fn run_authenticated_session_worker<E: PolicyEvaluator + ?Sized>(
    mut session: AuthenticatedLocalLinuxSession<UnixStream>,
    _permit: LocalLinuxWorkerPermit,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxSessionWorkerError> {
    for responses_written in 0..config.request_budget().get() {
        match session.process_one_with_deadlines(
            evaluator,
            status_snapshot,
            private_dns_snapshot,
            config.read_budget(),
            config.write_budget(),
        ) {
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten) => {}
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof) => {
                return Ok(LocalLinuxSessionWorkerStop::CleanEof { responses_written });
            }
            Err(error) => {
                return Err(LocalLinuxSessionWorkerError::Processing {
                    responses_written,
                    error,
                });
            }
        }
    }

    Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
        responses_written: config.request_budget().get(),
    })
}

/// Runs one authenticated session through the fixed AgentStatus-management worker.
///
/// This crate-internal adapter preserves the shared worker result envelope used by
/// scoped spawning, registry ownership, completion classification and runtime teardown.
/// The underlying VU child worker remains private and owns the fixed management policy.
///
/// # Errors
///
/// Converts the narrow worker's coarse processing failure into the shared bounded
/// `LocalLinuxSessionWorkerError` envelope without exposing provider authority.
pub(super) fn run_authenticated_session_worker_with_agent_status_management<
    RE: PolicyEvaluator + ?Sized,
>(
    session: AuthenticatedLocalLinuxSession<UnixStream>,
    permit: LocalLinuxWorkerPermit,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxSessionWorkerError> {
    management_agent_status::run_authenticated_session_worker_with_agent_status_management(
        session,
        permit,
        read_evaluator,
        status_snapshot,
        private_dns_snapshot,
        config,
    )
    .map_err(|error| {
        match error {
            management_agent_status::LocalLinuxAgentStatusManagementSessionWorkerError::Processing {
                responses_written,
            } => LocalLinuxSessionWorkerError::AgentStatusManagementProcessing {
                responses_written,
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Read;
    use std::net::Shutdown;
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    use super::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerError, LocalLinuxSessionWorkerStop,
        run_authenticated_session_worker,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn worker_capacity(value: usize) -> LocalLinuxWorkerCapacity {
        LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(value).expect("test worker capacity is non-zero"),
        )
    }

    fn worker_config(
        requests: usize,
        read_ms: u64,
        write_ms: u64,
    ) -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(requests).expect("test Request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(read_ms))
                .expect("test read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(write_ms))
                .expect("test write budget is non-zero"),
        )
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn session(stream: UnixStream) -> AuthenticatedLocalLinuxSession<UnixStream> {
        let connection = AuthenticatedLocalLinuxConnection::try_new(stream)
            .expect("same-UID test stream authenticates");
        AuthenticatedLocalLinuxSession::new(connection)
    }

    struct CapacityObservingPolicy<'a> {
        capacity: &'a LocalLinuxWorkerCapacity,
        calls: Cell<usize>,
    }

    impl PolicyEvaluator for CapacityObservingPolicy<'_> {
        fn evaluate(&self, _capability: Capability) -> Decision {
            assert_eq!(self.capacity.active_workers(), 1);
            self.calls.set(self.calls.get() + 1);
            Decision::Allow
        }
    }

    #[test]
    fn request_budget_exhaustion_closes_session_and_releases_permit() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = worker_capacity(1);
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let policy = CapacityObservingPolicy {
            capacity: &capacity,
            calls: Cell::new(0),
        };
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();

        write_local_command_request(&mut client, id(400), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        assert_eq!(
            run_authenticated_session_worker(
                session(server),
                permit,
                &policy,
                status,
                &dns,
                worker_config(1, 500, 500),
            ),
            Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                responses_written: 1
            })
        );
        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(policy.calls.get(), 1);

        let response = read_frame(&mut client).expect("terminal response remains readable");
        let response = decode_success_status_frame(&response).expect("status response decodes");
        assert_eq!(response.request_id(), id(400));

        let mut trailing = [0_u8; 1];
        assert_eq!(
            client
                .read(&mut trailing)
                .expect("worker stream reached EOF"),
            0
        );
    }

    #[test]
    fn clean_eof_releases_permit_without_policy_call() {
        let (server, client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = worker_capacity(1);
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let policy = CapacityObservingPolicy {
            capacity: &capacity,
            calls: Cell::new(0),
        };
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        client
            .shutdown(Shutdown::Write)
            .expect("peer write side closes cleanly");

        assert_eq!(
            run_authenticated_session_worker(
                session(server),
                permit,
                &policy,
                status,
                &dns,
                worker_config(2, 500, 500),
            ),
            Ok(LocalLinuxSessionWorkerStop::CleanEof {
                responses_written: 0
            })
        );
        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(policy.calls.get(), 0);
    }

    #[test]
    fn read_deadline_failure_releases_permit_and_reports_prior_response_count() {
        let (server, _client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = worker_capacity(1);
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let policy = CapacityObservingPolicy {
            capacity: &capacity,
            calls: Cell::new(0),
        };
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();

        let error = run_authenticated_session_worker(
            session(server),
            permit,
            &policy,
            status,
            &dns,
            worker_config(2, 25, 500),
        )
        .expect_err("idle peer reaches Request read deadline");

        assert!(matches!(
            error,
            LocalLinuxSessionWorkerError::Processing {
                responses_written: 0,
                ..
            }
        ));
        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(policy.calls.get(), 0);
    }
}
