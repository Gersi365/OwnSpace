//! Deadline composition for the fixed command-3 AgentStatus-only local slice.
//!
//! This child module keeps the existing public legacy deadline path unchanged.
//! It adds only a crate-private sibling method that reuses the same read and deferred
//! write deadline primitives while delegating to the narrow aggregate server-state path.

use std::os::unix::net::UnixStream;

use prw_policy::PolicyEvaluator;

use super::AuthenticatedLocalLinuxSession;
use crate::linux_identity::deadline_io::{
    LocalLinuxDeadlineReader, LocalLinuxDeadlineStartError, LocalLinuxDeferredDeadlineWriter,
    LocalLinuxIoBudget,
};
use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::server_connection_state::LocalAgentStatusManagementServerConnectionError;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

impl AuthenticatedLocalLinuxSession<UnixStream> {
    /// Processes exactly one legacy-or-AgentStatus request with independent I/O budgets.
    ///
    /// The read deadline starts immediately before generic frame acquisition. The response
    /// write deadline remains deferred until the first non-empty write. No filesystem,
    /// provider lifecycle, terminal backend or forwarding backend is acquired.
    ///
    /// # Errors
    ///
    /// Returns a read-deadline construction error before I/O or the narrow aggregate
    /// server-state failure after authoritative state transitions.
    pub(crate) fn process_one_agent_status_management_with_deadlines<
        RE: PolicyEvaluator + ?Sized,
    >(
        &mut self,
        read_evaluator: &RE,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &LocalPrivateDnsSnapshot,
        read_budget: LocalLinuxIoBudget,
        write_budget: LocalLinuxIoBudget,
    ) -> Result<
        LocalBoundaryRequestResponseOutcome,
        LocalLinuxAgentStatusManagementDeadlineSessionProcessError,
    > {
        let Self { connection, state } = self;
        let stream = connection.stream();
        let mut reader = LocalLinuxDeadlineReader::start(stream, read_budget).map_err(
            LocalLinuxAgentStatusManagementDeadlineSessionProcessError::ReadDeadlineStart,
        )?;
        let mut writer = LocalLinuxDeferredDeadlineWriter::new(stream, write_budget);

        state
            .process_one_agent_status_management_at_boundary(
                &mut reader,
                &mut writer,
                connection,
                read_evaluator,
                status_snapshot,
                private_dns_snapshot,
            )
            .map_err(LocalLinuxAgentStatusManagementDeadlineSessionProcessError::Processing)
    }
}

/// Crate-internal failure for the narrow `AgentStatus` management deadline path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxAgentStatusManagementDeadlineSessionProcessError {
    /// The absolute request-read deadline could not be constructed.
    ReadDeadlineStart(LocalLinuxDeadlineStartError),
    /// The narrow aggregate request pipeline failed.
    Processing(LocalAgentStatusManagementServerConnectionError),
}
