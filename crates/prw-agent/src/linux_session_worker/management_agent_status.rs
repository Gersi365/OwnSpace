//! Finite worker for legacy commands plus fixed command-3 `AgentStatus`.
//!
//! The existing public legacy worker is unchanged. This child function consumes the same
//! permit, request budget and per-request I/O budgets while delegating to the narrow
//! AgentStatus-only authenticated-session method.

use std::os::unix::net::UnixStream;

use prw_policy::PolicyEvaluator;

use super::{LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop};
use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
use crate::linux_identity::worker_capacity::LocalLinuxWorkerPermit;
use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

/// Coarse crate-internal failure for one AgentStatus-management finite worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalLinuxAgentStatusManagementSessionWorkerError {
    /// One request failed after the stated number of prior responses.
    Processing {
        /// Number of terminal responses completed before the failing request.
        responses_written: usize,
    },
}

/// Runs one authenticated local session through the fixed `AgentStatus` command-3 slice.
///
/// Permit RAII, request-budget exhaustion, fresh read deadlines and deferred write deadlines
/// are identical to the existing finite worker. No caller can supply management policy,
/// filesystem authority or mutable provider lifecycle to this function.
///
/// # Errors
///
/// Returns on the first narrow request-processing failure and preserves the number of prior
/// completed terminal responses.
pub(super) fn run_authenticated_session_worker_with_agent_status_management<
    RE: PolicyEvaluator + ?Sized,
>(
    mut session: AuthenticatedLocalLinuxSession<UnixStream>,
    _permit: LocalLinuxWorkerPermit,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxAgentStatusManagementSessionWorkerError> {
    for responses_written in 0..config.request_budget().get() {
        match session.process_one_agent_status_management_with_deadlines(
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
            config.read_budget(),
            config.write_budget(),
        ) {
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten) => {}
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof) => {
                return Ok(LocalLinuxSessionWorkerStop::CleanEof { responses_written });
            }
            Err(_) => {
                return Err(
                    LocalLinuxAgentStatusManagementSessionWorkerError::Processing {
                        responses_written,
                    },
                );
            }
        }
    }

    Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
        responses_written: config.request_budget().get(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::BoundedLocalReadPolicy;
    use prw_remote_bridge::BridgeCommand;

    use super::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop,
        run_authenticated_session_worker_with_agent_status_management,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::write_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::build_local_command_request_frame;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("request id is non-zero")
    }

    fn session(stream: UnixStream) -> AuthenticatedLocalLinuxSession<UnixStream> {
        let connection = AuthenticatedLocalLinuxConnection::try_new(stream)
            .expect("same-UID test stream authenticates");
        AuthenticatedLocalLinuxSession::new(connection)
    }

    fn status() -> LocalAgentStatusSnapshot {
        LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready)
    }

    fn dns() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn config() -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("write budget is non-zero"),
        )
    }

    #[test]
    fn command_three_agent_status_runs_through_narrow_worker() {
        let (server, mut client) = UnixStream::pair().expect("local pair creates");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity is non-zero"));
        let permit = capacity.try_acquire().expect("worker permit acquires");
        let bridge = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus command encodes");
        let frame = build_local_management_request_frame(id(951), &bridge)
            .expect("management frame builds");
        write_frame(&mut client, &frame).expect("management request writes");

        let stop = run_authenticated_session_worker_with_agent_status_management(
            session(server),
            permit,
            &BoundedLocalReadPolicy::deny_all(),
            status(),
            &dns(),
            config(),
        )
        .expect("narrow management worker succeeds");

        assert_eq!(
            stop,
            LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                responses_written: 1
            }
        );
        assert_eq!(capacity.active_workers(), 0);

        let response = read_frame(&mut client).expect("management response reads");
        let terminal =
            validate_terminal_response_frame(&response).expect("management response validates");
        assert_eq!(terminal.request_id(), id(951));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
    }

    #[test]
    fn legacy_command_one_keeps_existing_response_path() {
        let (server, mut client) = UnixStream::pair().expect("local pair creates");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity is non-zero"));
        let permit = capacity.try_acquire().expect("worker permit acquires");
        let frame = build_local_command_request_frame(id(952), LocalAgentCommand::GetAgentStatus)
            .expect("legacy frame builds");
        write_frame(&mut client, &frame).expect("legacy request writes");

        run_authenticated_session_worker_with_agent_status_management(
            session(server),
            permit,
            &BoundedLocalReadPolicy::allow_local_reads(),
            status(),
            &dns(),
            config(),
        )
        .expect("legacy request succeeds");

        assert_eq!(capacity.active_workers(), 0);
        let response = read_frame(&mut client).expect("legacy response reads");
        let decoded =
            decode_success_status_frame(&response).expect("legacy status response decodes");
        assert_eq!(decoded.request_id(), id(952));

        let mut trailing = [0_u8; 1];
        assert_eq!(
            client
                .read(&mut trailing)
                .expect("worker stream reaches EOF"),
            0
        );
    }
}
