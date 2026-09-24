//! Production-local Linux runtime configuration and bounded evidence types.
//!
//! Phase 095 defines only immutable validated configuration, saturating process-
//! lifetime counters, terminal evidence, and the initial runtime error-disposition
//! classifier locked by Phase 094-A01. It starts no listener, performs no signal
//! handling, and contains no outer runtime loop.

use std::num::{NonZeroU16, NonZeroUsize};

use super::accept_ready::AuthenticatedAgentAcceptError;
use super::bound_socket::BoundAgentSocketCleanupError;
use super::deadline_io::LocalLinuxIoBudget;
use super::one_shot_scheduler::LocalLinuxOneShotScheduleError;
use super::runtime_orchestration::{
    LocalLinuxRuntimeOrchestrationError, LocalLinuxRuntimeOrchestrationReport,
    LocalLinuxRuntimeOrchestrationStop, LocalLinuxRuntimeSchedulingCycleError,
    LocalLinuxRuntimeSchedulingCycleReport,
};
use super::runtime_readiness::LocalLinuxRuntimeReadinessError;
use super::session_worker::LocalLinuxSessionWorkerConfig;
use super::signal_aware_readiness::{
    LocalLinuxSignalAwareReadinessOutcome, LocalLinuxSignalAwareReadinessReport,
};
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::LocalLinuxRegisteredWorkerCancellation;

/// Immutable validated bounds consumed by the future production-local runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLinuxProductionRuntimeConfig {
    worker_capacity: NonZeroUsize,
    listener_backlog: NonZeroU16,
    scheduling_attempt_budget: NonZeroUsize,
    worker_config: LocalLinuxSessionWorkerConfig,
}

impl LocalLinuxProductionRuntimeConfig {
    /// Creates a production-runtime configuration from already-validated bounds.
    #[must_use]
    pub const fn new(
        worker_capacity: NonZeroUsize,
        listener_backlog: NonZeroU16,
        scheduling_attempt_budget: NonZeroUsize,
        worker_request_budget: NonZeroUsize,
        worker_read_io_budget: LocalLinuxIoBudget,
        worker_write_io_budget: LocalLinuxIoBudget,
    ) -> Self {
        Self {
            worker_capacity,
            listener_backlog,
            scheduling_attempt_budget,
            worker_config: LocalLinuxSessionWorkerConfig::new(
                worker_request_budget,
                worker_read_io_budget,
                worker_write_io_budget,
            ),
        }
    }

    /// Returns the maximum number of concurrently retained session workers.
    #[must_use]
    pub const fn worker_capacity(self) -> NonZeroUsize {
        self.worker_capacity
    }

    /// Returns the explicit Unix-listener backlog.
    #[must_use]
    pub const fn listener_backlog(self) -> NonZeroU16 {
        self.listener_backlog
    }

    /// Returns the maximum scheduling attempts after one listener-ready event.
    #[must_use]
    pub const fn scheduling_attempt_budget(self) -> NonZeroUsize {
        self.scheduling_attempt_budget
    }

    /// Returns the finite per-session worker processing configuration.
    #[must_use]
    pub const fn worker_config(self) -> LocalLinuxSessionWorkerConfig {
        self.worker_config
    }
}

/// Saturating process-lifetime evidence counter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalLinuxRuntimeCounter(u64);

impl LocalLinuxRuntimeCounter {
    /// Returns the current counter value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Saturating-increments this counter by one.
    pub const fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    /// Saturating-adds one bounded `usize` observation.
    pub fn add_usize(&mut self, value: usize) {
        let value = u64::try_from(value).unwrap_or(u64::MAX);
        self.0 = self.0.saturating_add(value);
    }
}

/// Memory-bounded aggregate evidence for one production-local runtime lifetime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalLinuxProductionRuntimeCounters {
    readiness_steps: LocalLinuxRuntimeCounter,
    listener_armed_steps: LocalLinuxRuntimeCounter,
    runtime_wakes: LocalLinuxRuntimeCounter,
    wait_interruptions: LocalLinuxRuntimeCounter,
    scheduling_attempts: LocalLinuxRuntimeCounter,
    workers_registered: LocalLinuxRuntimeCounter,
    worker_completions: LocalLinuxRuntimeCounter,
    peer_rejections: LocalLinuxRuntimeCounter,
}

impl LocalLinuxProductionRuntimeCounters {
    /// Records one successful finite Phase 092 orchestration report.
    pub fn record_orchestration(&mut self, report: &LocalLinuxRuntimeOrchestrationReport) {
        self.readiness_steps.increment();
        if report.listener_armed() {
            self.listener_armed_steps.increment();
        }

        match report.stop() {
            LocalLinuxRuntimeOrchestrationStop::RuntimeWake => self.runtime_wakes.increment(),
            LocalLinuxRuntimeOrchestrationStop::WaitInterrupted => {
                self.wait_interruptions.increment();
            }
            LocalLinuxRuntimeOrchestrationStop::ShutdownObserved
            | LocalLinuxRuntimeOrchestrationStop::Scheduling(_) => {}
        }

        self.scheduling_attempts
            .add_usize(report.scheduling_attempts());
        self.workers_registered
            .add_usize(report.workers_registered());
        self.worker_completions
            .add_usize(report.readiness_completions().len());
        self.worker_completions
            .add_usize(report.scheduling_completions().len());
    }

    /// Records one successful signal-aware readiness step.
    pub fn record_signal_aware_readiness(&mut self, report: &LocalLinuxSignalAwareReadinessReport) {
        self.readiness_steps.increment();
        if report.listener_armed() {
            self.listener_armed_steps.increment();
        }
        match report.outcome() {
            LocalLinuxSignalAwareReadinessOutcome::RuntimeWake => self.runtime_wakes.increment(),
            LocalLinuxSignalAwareReadinessOutcome::WaitInterrupted => {
                self.wait_interruptions.increment();
            }
            LocalLinuxSignalAwareReadinessOutcome::ShutdownObserved
            | LocalLinuxSignalAwareReadinessOutcome::TerminationSignal(_)
            | LocalLinuxSignalAwareReadinessOutcome::ListenerReady => {}
        }
        self.worker_completions
            .add_usize(report.completions().len());
    }

    /// Records one successful runtime-specific scheduling cycle after readiness.
    pub fn record_runtime_scheduling_report(
        &mut self,
        report: &LocalLinuxRuntimeSchedulingCycleReport,
    ) {
        self.scheduling_attempts
            .add_usize(report.scheduling_attempts());
        self.workers_registered
            .add_usize(report.workers_registered());
        self.worker_completions
            .add_usize(report.completions().len());
    }

    /// Records scheduling evidence after readiness was already counted separately.
    pub fn record_runtime_scheduling_error(
        &mut self,
        error: &LocalLinuxRuntimeSchedulingCycleError,
    ) {
        self.scheduling_attempts
            .add_usize(error.scheduling_attempts());
        self.workers_registered
            .add_usize(error.workers_registered());
        self.worker_completions.add_usize(error.completions().len());
    }

    /// Records evidence accumulated before one scheduling failure.
    pub fn record_scheduling_error(&mut self, error: &LocalLinuxRuntimeSchedulingCycleError) {
        self.readiness_steps.increment();
        self.listener_armed_steps.increment();
        self.scheduling_attempts
            .add_usize(error.scheduling_attempts());
        self.workers_registered
            .add_usize(error.workers_registered());
        self.worker_completions.add_usize(error.completions().len());
    }

    /// Records worker completions joined during the final shutdown transaction.
    pub fn record_final_completions(&mut self, count: usize) {
        self.worker_completions.add_usize(count);
    }

    /// Records one connection-local peer-authorization rejection.
    pub const fn record_peer_rejection(&mut self) {
        self.peer_rejections.increment();
    }

    /// Returns the total number of successful readiness/orchestration steps.
    #[must_use]
    pub const fn readiness_steps(self) -> u64 {
        self.readiness_steps.value()
    }

    /// Returns how many readiness steps armed listener interest.
    #[must_use]
    pub const fn listener_armed_steps(self) -> u64 {
        self.listener_armed_steps.value()
    }

    /// Returns how many successful steps ended after runtime-wake processing.
    #[must_use]
    pub const fn runtime_wakes(self) -> u64 {
        self.runtime_wakes.value()
    }

    /// Returns how many successful steps surfaced `poll` interruption.
    #[must_use]
    pub const fn wait_interruptions(self) -> u64 {
        self.wait_interruptions.value()
    }

    /// Returns total scheduling attempts accumulated with saturation.
    #[must_use]
    pub const fn scheduling_attempts(self) -> u64 {
        self.scheduling_attempts.value()
    }

    /// Returns total successfully registered workers accumulated with saturation.
    #[must_use]
    pub const fn workers_registered(self) -> u64 {
        self.workers_registered.value()
    }

    /// Returns total reaped worker completions accumulated with saturation.
    #[must_use]
    pub const fn worker_completions(self) -> u64 {
        self.worker_completions.value()
    }

    /// Returns total connection-local peer rejections accumulated with saturation.
    #[must_use]
    pub const fn peer_rejections(self) -> u64 {
        self.peer_rejections.value()
    }
}

/// Locked initial disposition for one Phase 092 orchestration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeErrorDisposition {
    /// Same-UID peer authorization rejected one accepted connection; continue.
    ContinueAfterPeerRejection,
    /// The failure is daemon-fatal in the initial production-local baseline.
    FailStop,
}

const fn classify_schedule_error(
    error: LocalLinuxOneShotScheduleError,
) -> LocalLinuxRuntimeErrorDisposition {
    match error {
        LocalLinuxOneShotScheduleError::Accept(
            AuthenticatedAgentAcceptError::PeerAuthorization(_),
        ) => LocalLinuxRuntimeErrorDisposition::ContinueAfterPeerRejection,
        LocalLinuxOneShotScheduleError::Accept(AuthenticatedAgentAcceptError::AcceptFailed)
        | LocalLinuxOneShotScheduleError::CancellationClone(_)
        | LocalLinuxOneShotScheduleError::Spawn(_) => LocalLinuxRuntimeErrorDisposition::FailStop,
    }
}

/// Returns the Phase 094-A01 initial production disposition for one runtime error.
#[must_use]
pub const fn classify_production_runtime_error(
    error: &LocalLinuxRuntimeOrchestrationError,
) -> LocalLinuxRuntimeErrorDisposition {
    match error {
        LocalLinuxRuntimeOrchestrationError::Readiness(_) => {
            LocalLinuxRuntimeErrorDisposition::FailStop
        }
        LocalLinuxRuntimeOrchestrationError::Scheduling(scheduling) => {
            classify_schedule_error(scheduling.error())
        }
    }
}

/// Exact fatal runtime error retained when the initial baseline enters fail-stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxProductionRuntimeFatalError {
    /// Phase 091 readiness failed closed.
    Readiness(LocalLinuxRuntimeReadinessError),
    /// Phase 092 scheduling failed for a non-peer-rejection reason.
    Scheduling(LocalLinuxOneShotScheduleError),
}

impl LocalLinuxProductionRuntimeFatalError {
    /// Extracts the exact fatal classification from an orchestration error.
    ///
    /// Returns `None` only for the explicitly non-terminal peer-rejection case.
    #[must_use]
    pub const fn from_orchestration_error(
        error: &LocalLinuxRuntimeOrchestrationError,
    ) -> Option<Self> {
        match error {
            LocalLinuxRuntimeOrchestrationError::Readiness(error) => Some(Self::Readiness(*error)),
            LocalLinuxRuntimeOrchestrationError::Scheduling(scheduling) => {
                let error = scheduling.error();
                match classify_schedule_error(error) {
                    LocalLinuxRuntimeErrorDisposition::ContinueAfterPeerRejection => None,
                    LocalLinuxRuntimeErrorDisposition::FailStop => Some(Self::Scheduling(error)),
                }
            }
        }
    }
}

/// Terminal reason returned by a future callable production-local runtime owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxProductionRuntimeTerminalReason {
    /// Terminal shutdown was requested/observed through the runtime control path.
    ShutdownRequested,
    /// A daemon-fatal readiness or scheduling failure initiated teardown.
    Fatal(LocalLinuxProductionRuntimeFatalError),
}

/// Listener cleanup classification preserved alongside the original terminal reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxProductionRuntimeCleanup {
    /// The validated listener/socket pathname cleanup completed successfully.
    Clean,
    /// Cleanup failed after the terminal reason had already been established.
    Failed(BoundAgentSocketCleanupError),
}

/// Bounded final evidence returned by a future production-local runtime owner.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxProductionRuntimeTerminalReport {
    reason: LocalLinuxProductionRuntimeTerminalReason,
    counters: LocalLinuxProductionRuntimeCounters,
    cancellations: Vec<LocalLinuxRegisteredWorkerCancellation>,
    final_completions: Vec<LocalLinuxScopedWorkerCompletion>,
    cleanup: LocalLinuxProductionRuntimeCleanup,
}

impl LocalLinuxProductionRuntimeTerminalReport {
    /// Creates terminal evidence after cancellation/join/listener cleanup completes.
    #[must_use]
    pub const fn new(
        reason: LocalLinuxProductionRuntimeTerminalReason,
        counters: LocalLinuxProductionRuntimeCounters,
        cancellations: Vec<LocalLinuxRegisteredWorkerCancellation>,
        final_completions: Vec<LocalLinuxScopedWorkerCompletion>,
        cleanup: LocalLinuxProductionRuntimeCleanup,
    ) -> Self {
        Self {
            reason,
            counters,
            cancellations,
            final_completions,
            cleanup,
        }
    }

    /// Returns the original terminal runtime reason.
    #[must_use]
    pub const fn reason(&self) -> LocalLinuxProductionRuntimeTerminalReason {
        self.reason
    }

    /// Returns the memory-bounded process-lifetime aggregate counters.
    #[must_use]
    pub const fn counters(&self) -> LocalLinuxProductionRuntimeCounters {
        self.counters
    }

    /// Returns final cancellation outcomes, bounded by configured worker capacity.
    #[must_use]
    pub fn cancellations(&self) -> &[LocalLinuxRegisteredWorkerCancellation] {
        &self.cancellations
    }

    /// Returns final joined completions, bounded by configured worker capacity.
    #[must_use]
    pub fn final_completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.final_completions
    }

    /// Returns listener/socket cleanup evidence without replacing the terminal reason.
    #[must_use]
    pub const fn cleanup(&self) -> LocalLinuxProductionRuntimeCleanup {
        self.cleanup
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::time::Duration;

    use super::{
        LocalLinuxProductionRuntimeConfig, LocalLinuxProductionRuntimeCounters,
        LocalLinuxProductionRuntimeFatalError, LocalLinuxRuntimeCounter,
        LocalLinuxRuntimeErrorDisposition, classify_production_runtime_error,
        classify_schedule_error,
    };
    use crate::linux_identity::accept_ready::AuthenticatedAgentAcceptError;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::one_shot_scheduler::LocalLinuxOneShotScheduleError;
    use crate::linux_identity::peer_auth::LocalLinuxPeerAuthorizationError;
    use crate::linux_identity::runtime_orchestration::LocalLinuxRuntimeOrchestrationError;
    use crate::linux_identity::runtime_readiness::LocalLinuxRuntimeReadinessError;

    fn nonzero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test value is nonzero")
    }

    fn io_budget(milliseconds: u64) -> LocalLinuxIoBudget {
        LocalLinuxIoBudget::try_new(Duration::from_millis(milliseconds))
            .expect("test I/O budget is nonzero")
    }

    #[test]
    fn production_config_preserves_every_validated_bound() {
        let config = LocalLinuxProductionRuntimeConfig::new(
            nonzero(8),
            NonZeroU16::new(32).expect("test backlog is nonzero"),
            nonzero(4),
            nonzero(16),
            io_budget(250),
            io_budget(500),
        );

        assert_eq!(config.worker_capacity().get(), 8);
        assert_eq!(config.listener_backlog().get(), 32);
        assert_eq!(config.scheduling_attempt_budget().get(), 4);
        assert_eq!(config.worker_config().request_budget().get(), 16);
        assert_eq!(
            config.worker_config().read_budget().duration(),
            Duration::from_millis(250)
        );
        assert_eq!(
            config.worker_config().write_budget().duration(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn counter_saturates_instead_of_wrapping() {
        let mut counter = LocalLinuxRuntimeCounter(u64::MAX - 1);
        counter.increment();
        counter.increment();
        counter.add_usize(usize::MAX);
        assert_eq!(counter.value(), u64::MAX);
    }

    #[test]
    fn peer_rejection_counter_is_memory_bounded() {
        let mut counters = LocalLinuxProductionRuntimeCounters::default();
        counters.record_peer_rejection();
        counters.record_peer_rejection();
        assert_eq!(counters.peer_rejections(), 2);
        assert_eq!(
            std::mem::size_of_val(&counters),
            8 * std::mem::size_of::<u64>()
        );
    }

    #[test]
    fn readiness_failure_is_fail_stop_and_preserves_exact_classification() {
        let error = LocalLinuxRuntimeOrchestrationError::Readiness(
            LocalLinuxRuntimeReadinessError::WakeDescriptorFailed,
        );
        assert_eq!(
            classify_production_runtime_error(&error),
            LocalLinuxRuntimeErrorDisposition::FailStop
        );
        assert_eq!(
            LocalLinuxProductionRuntimeFatalError::from_orchestration_error(&error),
            Some(LocalLinuxProductionRuntimeFatalError::Readiness(
                LocalLinuxRuntimeReadinessError::WakeDescriptorFailed
            ))
        );
    }

    #[test]
    fn peer_authorization_rejection_is_the_only_nonterminal_schedule_class() {
        let error = LocalLinuxOneShotScheduleError::Accept(
            AuthenticatedAgentAcceptError::PeerAuthorization(
                LocalLinuxPeerAuthorizationError::UserIdMismatch,
            ),
        );
        assert_eq!(
            classify_schedule_error(error),
            LocalLinuxRuntimeErrorDisposition::ContinueAfterPeerRejection
        );
    }

    #[test]
    fn ordinary_accept_failure_is_fail_stop() {
        let error =
            LocalLinuxOneShotScheduleError::Accept(AuthenticatedAgentAcceptError::AcceptFailed);
        assert_eq!(
            classify_schedule_error(error),
            LocalLinuxRuntimeErrorDisposition::FailStop
        );
    }
}
