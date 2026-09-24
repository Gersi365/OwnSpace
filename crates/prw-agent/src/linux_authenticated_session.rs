//! Authenticated Linux application-session composition.
//!
//! Phase 060 binds one Phase 059 authenticated connection to the Phase 052
//! bounded application loop and one aggregate connection state. Phase 074 adds
//! a one-Request path with independent absolute read and deferred write deadlines.

use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::net::UnixStream;

use prw_policy::PolicyEvaluator;

use crate::linux_identity::LocalLinuxPeerCredentials;
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
use crate::linux_identity::deadline_io::{
    LocalLinuxDeadlineReader, LocalLinuxDeadlineStartError, LocalLinuxDeferredDeadlineWriter,
    LocalLinuxIoBudget,
};
use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::server_connection_loop::{
    LocalServerConnectionLoopStop, process_server_connection_with_budget,
};
use crate::local_commands::server_connection_state::{
    LocalBoundaryServerConnectionProcessError, LocalServerConnectionState,
    process_one_at_boundary_on_server_connection,
};
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

#[path = "linux_authenticated_session/management_agent_status.rs"]
mod management_agent_status;

/// One already-authenticated Linux connection with its application protocol state.
#[derive(Debug)]
pub struct AuthenticatedLocalLinuxSession<S> {
    connection: AuthenticatedLocalLinuxConnection<S>,
    state: LocalServerConnectionState,
}

impl<S> AuthenticatedLocalLinuxSession<S> {
    /// Creates a fresh application session from an already-authenticated connection.
    #[must_use]
    pub const fn new(connection: AuthenticatedLocalLinuxConnection<S>) -> Self {
        Self {
            connection,
            state: LocalServerConnectionState::new(),
        }
    }

    /// Returns the authenticated kernel peer credentials associated with this session.
    #[must_use]
    pub const fn peer_credentials(&self) -> LocalLinuxPeerCredentials {
        self.connection.peer_credentials()
    }

    /// Returns the current aggregate application-protocol connection state.
    #[must_use]
    pub const fn state(&self) -> LocalServerConnectionState {
        self.state
    }

    /// Returns ownership of the authenticated connection.
    #[must_use]
    pub fn into_connection(self) -> AuthenticatedLocalLinuxConnection<S> {
        self.connection
    }

    /// Processes a caller-bounded quantum of application Requests on the authenticated stream.
    ///
    /// The caller supplies policy and snapshot context. Same-UID transport
    /// authentication does not manufacture or bind the policy evaluator.
    ///
    /// # Errors
    ///
    /// Returns the existing Phase 051 aggregate processing failure. Any inbound
    /// or response-write poisoning performed by lower layers remains stored in
    /// this session's owned [`LocalServerConnectionState`].
    pub fn process_with_budget<E: PolicyEvaluator + ?Sized>(
        &mut self,
        evaluator: &E,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &LocalPrivateDnsSnapshot,
        request_budget: NonZeroUsize,
    ) -> Result<LocalServerConnectionLoopStop, LocalBoundaryServerConnectionProcessError>
    where
        for<'a> &'a S: Read + Write,
    {
        let Self { connection, state } = self;
        let stream = connection.stream();
        let mut reader = stream;
        let mut writer = stream;

        process_server_connection_with_budget(
            &mut reader,
            &mut writer,
            state,
            evaluator,
            status_snapshot,
            private_dns_snapshot,
            request_budget,
        )
    }
}

impl AuthenticatedLocalLinuxSession<UnixStream> {
    /// Processes exactly one boundary-aware Request with independent absolute I/O budgets.
    ///
    /// The read deadline starts immediately before frame acquisition. The write
    /// deadline is deferred until the first non-empty terminal-response write,
    /// so Request-read time never consumes response-write budget.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxDeadlineSessionProcessError::ReadDeadlineStart`] when
    /// the absolute read deadline cannot be represented, or
    /// [`LocalLinuxDeadlineSessionProcessError::Processing`] for the existing
    /// aggregate Request-processing failure after any authoritative poisoning
    /// transition has occurred.
    pub fn process_one_with_deadlines<E: PolicyEvaluator + ?Sized>(
        &mut self,
        evaluator: &E,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &LocalPrivateDnsSnapshot,
        read_budget: LocalLinuxIoBudget,
        write_budget: LocalLinuxIoBudget,
    ) -> Result<LocalBoundaryRequestResponseOutcome, LocalLinuxDeadlineSessionProcessError> {
        let Self { connection, state } = self;
        let stream = connection.stream();
        let mut reader = LocalLinuxDeadlineReader::start(stream, read_budget)
            .map_err(LocalLinuxDeadlineSessionProcessError::ReadDeadlineStart)?;
        let mut writer = LocalLinuxDeferredDeadlineWriter::new(stream, write_budget);

        process_one_at_boundary_on_server_connection(
            &mut reader,
            &mut writer,
            state,
            evaluator,
            status_snapshot,
            private_dns_snapshot,
        )
        .map_err(LocalLinuxDeadlineSessionProcessError::Processing)
    }
}

/// Phase 074 deadline-aware authenticated-session processing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxDeadlineSessionProcessError {
    /// The absolute Request-read deadline could not be constructed.
    ReadDeadlineStart(LocalLinuxDeadlineStartError),
    /// The existing aggregate Request-processing pipeline failed.
    Processing(LocalBoundaryServerConnectionProcessError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Write;
    use std::net::Shutdown;
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    use super::AuthenticatedLocalLinuxSession;
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::effective_agent_uid;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::server_connection_loop::LocalServerConnectionLoopStop;
    use crate::local_commands::server_connection_state::LocalServerConnectionUnusableReason;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn budget(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test budget is non-zero")
    }

    fn io_budget(milliseconds: u64) -> LocalLinuxIoBudget {
        LocalLinuxIoBudget::try_new(Duration::from_millis(milliseconds))
            .expect("test I/O budget is non-zero")
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
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
    fn authenticated_session_processes_bounded_requests_and_emits_responses() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();

        write_local_command_request(&mut client, id(330), LocalAgentCommand::GetAgentStatus)
            .expect("first Request writes");
        write_local_command_request(&mut client, id(331), LocalAgentCommand::GetAgentStatus)
            .expect("second Request writes");

        assert_eq!(
            session.process_with_budget(&policy, status, &dns, budget(2)),
            Ok(LocalServerConnectionLoopStop::BudgetExhausted {
                responses_written: 2
            })
        );

        let first = read_frame(&mut client).expect("first response reads");
        let second = read_frame(&mut client).expect("second response reads");
        let first = decode_success_status_frame(&first).expect("first status response decodes");
        let second = decode_success_status_frame(&second).expect("second status response decodes");

        assert_eq!(first.request_id(), id(330));
        assert_eq!(second.request_id(), id(331));
        assert_eq!(first.snapshot(), status);
        assert_eq!(second.snapshot(), status);
        assert_eq!(policy.calls(), 2);
        assert!(session.state().is_usable());
        assert_eq!(session.peer_credentials().uid(), effective_agent_uid());
    }

    #[test]
    fn authenticated_session_preserves_clean_eof_as_normal_stop() {
        let (server, client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        client
            .shutdown(Shutdown::Write)
            .expect("peer write side shuts down cleanly");

        assert_eq!(
            session.process_with_budget(&policy, status, &dns, budget(1)),
            Ok(LocalServerConnectionLoopStop::CleanEof {
                responses_written: 0
            })
        );
        assert!(session.state().is_usable());
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn malformed_authenticated_input_updates_owned_aggregate_state() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let mut request = Vec::new();
        write_local_command_request(&mut request, id(332), LocalAgentCommand::GetAgentStatus)
            .expect("Request encodes");
        client
            .write_all(&request[..5])
            .expect("partial Request bytes write");
        client
            .shutdown(Shutdown::Write)
            .expect("peer write side closes after truncation");

        assert!(
            session
                .process_with_budget(&policy, status, &dns, budget(1))
                .is_err()
        );
        assert_eq!(
            session.state().unusable_reason(),
            Some(LocalServerConnectionUnusableReason::InboundRead)
        );
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn deadline_transaction_processes_one_request_and_response() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();

        write_local_command_request(&mut client, id(333), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        assert_eq!(
            session.process_one_with_deadlines(
                &policy,
                status,
                &dns,
                io_budget(500),
                io_budget(500),
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );

        let response = read_frame(&mut client).expect("response reads");
        let decoded = decode_success_status_frame(&response).expect("status response decodes");
        assert_eq!(decoded.request_id(), id(333));
        assert_eq!(decoded.snapshot(), status);
        assert_eq!(policy.calls(), 1);
        assert!(session.state().is_usable());
    }

    #[test]
    fn idle_peer_read_deadline_poisons_inbound_state() {
        let (server, _client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();

        assert!(
            session
                .process_one_with_deadlines(&policy, status, &dns, io_budget(25), io_budget(500),)
                .is_err()
        );
        assert_eq!(
            session.state().unusable_reason(),
            Some(LocalServerConnectionUnusableReason::InboundRead)
        );
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn clean_eof_never_starts_deferred_write_deadline() {
        let (server, client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID server endpoint authenticates");
        let mut session = AuthenticatedLocalLinuxSession::new(connection);
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::new();
        let unrepresentable_write_budget =
            LocalLinuxIoBudget::try_new(Duration::MAX).expect("huge budget is non-zero");
        client
            .shutdown(Shutdown::Write)
            .expect("peer write side shuts down cleanly");

        assert_eq!(
            session.process_one_with_deadlines(
                &policy,
                status,
                &dns,
                io_budget(500),
                unrepresentable_write_budget,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof)
        );
        assert!(session.state().is_usable());
        assert_eq!(policy.calls(), 0);
    }
}
