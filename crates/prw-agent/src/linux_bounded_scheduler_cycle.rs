//! Finite scheduler-cycle composition for the Linux Agent local runtime.
//!
//! Phase 086 composes nonblocking finished-worker reaping, a monotonic shutdown
//! gate, and Phase 084 one-shot scheduling under a caller-supplied attempt budget.
//! It contains no outer wait loop, sleep, poll, or Agent bootstrap activation.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::Scope;

use super::accept_ready::AcceptReadyAgentSocket;
use super::one_shot_scheduler::{
    LocalLinuxOneShotScheduleError, LocalLinuxOneShotScheduleOutcome,
    LocalLinuxOneShotSchedulerContext, schedule_one_authenticated_worker,
};
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::LocalLinuxScopedWorkerRegistry;

/// Shared monotonic scheduler stop control for one runtime instance.
#[derive(Debug, Clone)]
pub struct LocalLinuxSchedulerControl {
    shutdown_requested: Arc<AtomicBool>,
}

impl LocalLinuxSchedulerControl {
    /// Creates one running scheduler control.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Requests terminal scheduler shutdown for this runtime instance.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }

    /// Returns whether terminal scheduler shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }
}

impl Default for LocalLinuxSchedulerControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Terminal reason for one successful bounded scheduling-cycle invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxSchedulingCycleStop {
    /// The exact caller-supplied Phase 084 attempt budget was consumed.
    AttemptBudgetExhausted,
    /// Worker capacity was full when the next one-shot scheduling attempt ran.
    AtCapacity,
    /// No connection was queued when the next one-shot scheduling attempt ran.
    NoConnectionReady,
    /// Shutdown was observed after reaping and before the next accept attempt.
    ShutdownRequested,
}

/// Evidence returned from one successful bounded scheduling cycle.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxSchedulingCycleReport {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    workers_registered: usize,
    scheduling_attempts: usize,
    stop: LocalLinuxSchedulingCycleStop,
}

impl LocalLinuxSchedulingCycleReport {
    /// Returns worker completions reaped during this cycle in observation order.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns how many workers were successfully registered during this cycle.
    #[must_use]
    pub const fn workers_registered(&self) -> usize {
        self.workers_registered
    }

    /// Returns how many Phase 084 scheduling attempts were actually performed.
    #[must_use]
    pub const fn scheduling_attempts(&self) -> usize {
        self.scheduling_attempts
    }

    /// Returns the terminal stop reason for this cycle.
    #[must_use]
    pub const fn stop(&self) -> LocalLinuxSchedulingCycleStop {
        self.stop
    }
}

/// Evidence returned when one Phase 084 scheduling attempt fails.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxSchedulingCycleError {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    workers_registered: usize,
    scheduling_attempts: usize,
    error: LocalLinuxOneShotScheduleError,
}

impl LocalLinuxSchedulingCycleError {
    /// Returns worker completions reaped before the scheduling failure.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns how many workers were registered earlier in this cycle.
    #[must_use]
    pub const fn workers_registered(&self) -> usize {
        self.workers_registered
    }

    /// Returns the number of Phase 084 attempts including the failed attempt.
    #[must_use]
    pub const fn scheduling_attempts(&self) -> usize {
        self.scheduling_attempts
    }

    /// Returns the bounded Phase 084 scheduling failure.
    #[must_use]
    pub const fn error(&self) -> LocalLinuxOneShotScheduleError {
        self.error
    }
}

/// Runs one finite scheduling cycle under an explicit attempt budget.
///
/// Before every possible Phase 084 attempt, finished workers are reaped and the
/// monotonic shutdown flag is checked. `AtCapacity` and `NoConnectionReady` stop
/// the cycle immediately rather than being retried internally.
///
/// # Errors
///
/// Returns [`LocalLinuxSchedulingCycleError`] on the first Phase 084 scheduling
/// failure, preserving completions and registration/attempt counts accumulated
/// earlier in the same cycle.
pub fn run_bounded_scheduling_cycle<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &AcceptReadyAgentSocket<'_>,
    registry: &mut LocalLinuxScopedWorkerRegistry<'scope>,
    control: &LocalLinuxSchedulerControl,
    context: LocalLinuxOneShotSchedulerContext<'scope>,
    attempt_budget: NonZeroUsize,
) -> Result<LocalLinuxSchedulingCycleReport, LocalLinuxSchedulingCycleError> {
    let mut completions = Vec::new();
    let mut workers_registered = 0;
    let mut scheduling_attempts = 0;

    for _ in 0..attempt_budget.get() {
        completions.extend(registry.reap_finished());

        if control.is_shutdown_requested() {
            return Ok(LocalLinuxSchedulingCycleReport {
                completions,
                workers_registered,
                scheduling_attempts,
                stop: LocalLinuxSchedulingCycleStop::ShutdownRequested,
            });
        }

        scheduling_attempts += 1;
        let outcome = schedule_one_authenticated_worker(scope, listener, registry, context)
            .map_err(|error| LocalLinuxSchedulingCycleError {
                completions: std::mem::take(&mut completions),
                workers_registered,
                scheduling_attempts,
                error,
            })?;

        match outcome {
            LocalLinuxOneShotScheduleOutcome::WorkerRegistered => workers_registered += 1,
            LocalLinuxOneShotScheduleOutcome::AtCapacity => {
                return Ok(LocalLinuxSchedulingCycleReport {
                    completions,
                    workers_registered,
                    scheduling_attempts,
                    stop: LocalLinuxSchedulingCycleStop::AtCapacity,
                });
            }
            LocalLinuxOneShotScheduleOutcome::NoConnectionReady => {
                return Ok(LocalLinuxSchedulingCycleReport {
                    completions,
                    workers_registered,
                    scheduling_attempts,
                    stop: LocalLinuxSchedulingCycleStop::NoConnectionReady,
                });
            }
        }
    }

    Ok(LocalLinuxSchedulingCycleReport {
        completions,
        workers_registered,
        scheduling_attempts,
        stop: LocalLinuxSchedulingCycleStop::AttemptBudgetExhausted,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::BoundedLocalReadPolicy;

    use super::{
        LocalLinuxSchedulerControl, LocalLinuxSchedulingCycleStop, run_bounded_scheduling_cycle,
    };
    use crate::LocalIpcRequestId;
    use crate::linux_identity::accept_ready::{
        AcceptReadyAgentSocket, prepare_accept_ready_agent_socket,
    };
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::listening_socket::listen_bound_agent_socket;
    use crate::linux_identity::one_shot_scheduler::{
        LocalLinuxOneShotScheduleOutcome, LocalLinuxOneShotSchedulerContext,
        schedule_one_authenticated_worker,
    };
    use crate::linux_identity::session_worker::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop,
    };
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::linux_identity::worker_completion::LocalLinuxScopedWorkerCompletion;
    use crate::linux_identity::worker_registry::LocalLinuxScopedWorkerRegistry;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLock, acquire_agent_instance_lock,
    };
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn attempts(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test scheduling attempt budget is non-zero")
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-086-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 086 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 086 directory mode sets");
    }

    fn runtime_owners(label: &str) -> (PathBuf, ValidatedPrwRuntimeDirectory, AgentInstanceLock) {
        let root_path = unique_temp_path(label);
        create_directory_with_mode(&root_path, 0o700);
        let root =
            crate::linux_identity::xdg_runtime_root::validate_xdg_runtime_root_path(&root_path)
                .expect("temporary root satisfies Phase 062 validation");
        let runtime_directory = crate::linux_identity::xdg_runtime_root::prw_runtime_directory::prepare_prw_runtime_directory(&root)
            .expect("temporary PRW directory satisfies Phase 063 preparation");
        drop(root);
        let instance_lock = acquire_agent_instance_lock(&runtime_directory)
            .expect("temporary lifecycle authority satisfies Phase 065");
        (root_path, runtime_directory, instance_lock)
    }

    fn accept_ready<'a>(
        runtime_directory: &'a ValidatedPrwRuntimeDirectory,
        instance_lock: &'a AgentInstanceLock,
    ) -> AcceptReadyAgentSocket<'a> {
        let bound = bind_validated_agent_socket(runtime_directory, instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(8).expect("backlog non-zero"))
                .expect("Phase 068 listener creates");
        prepare_accept_ready_agent_socket(listening).expect("Phase 070 readiness creates")
    }

    fn socket_path(root: &Path) -> PathBuf {
        root.join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    fn worker_config() -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("Request budget non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500)).expect("read budget non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500)).expect("write budget non-zero"),
        )
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config bounded")
    }

    #[test]
    fn shutdown_before_cycle_performs_zero_accept_attempts_and_leaves_client_queued() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("shutdown");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let mut client = UnixStream::connect(&socket_path).expect("client queues");
        write_local_command_request(&mut client, id(700), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let control = LocalLinuxSchedulerControl::new();
        control.request_shutdown();

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                worker_config(),
            );
            let report = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                context,
                attempts(3),
            )
            .expect("shutdown-gated cycle succeeds");

            assert_eq!(
                report.stop(),
                LocalLinuxSchedulingCycleStop::ShutdownRequested
            );
            assert_eq!(report.scheduling_attempts(), 0);
            assert_eq!(report.workers_registered(), 0);
            assert!(registry.is_empty());

            let fresh_control = LocalLinuxSchedulerControl::new();
            let follow_up = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &fresh_control,
                context,
                attempts(1),
            )
            .expect("fresh runtime control can schedule queued test client");
            assert_eq!(follow_up.workers_registered(), 1);
            assert_eq!(registry.join_all().len(), 1);
        });

        assert_eq!(capacity.active_workers(), 0);
        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn no_ready_stops_after_exactly_one_attempt_even_with_larger_budget() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("no-ready");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(2).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::deny_all();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                worker_config(),
            );
            let report = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                context,
                attempts(5),
            )
            .expect("empty-queue cycle succeeds");

            assert_eq!(
                report.stop(),
                LocalLinuxSchedulingCycleStop::NoConnectionReady
            );
            assert_eq!(report.scheduling_attempts(), 1);
            assert_eq!(report.workers_registered(), 0);
            assert!(registry.is_empty());
        });

        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn at_capacity_stops_after_one_attempt_without_consuming_queued_client() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("at-capacity");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let mut client = UnixStream::connect(&socket_path).expect("client queues");
        write_local_command_request(&mut client, id(701), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let held = capacity.try_acquire().expect("capacity held");
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                worker_config(),
            );
            let report = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                context,
                attempts(4),
            )
            .expect("capacity cycle succeeds");

            assert_eq!(report.stop(), LocalLinuxSchedulingCycleStop::AtCapacity);
            assert_eq!(report.scheduling_attempts(), 1);
            assert!(registry.is_empty());

            drop(held);
            assert_eq!(
                schedule_one_authenticated_worker(scope, &listener, &mut registry, context),
                Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
            );
            assert_eq!(registry.join_all().len(), 1);
        });

        assert_eq!(capacity.active_workers(), 0);
        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn exact_attempt_budget_limits_multiple_queued_registrations() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("attempt-budget");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let _first = UnixStream::connect(&socket_path).expect("first idle client queues");
        let _second = UnixStream::connect(&socket_path).expect("second idle client queues");
        let _third = UnixStream::connect(&socket_path).expect("third idle client queues");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(3).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let control = LocalLinuxSchedulerControl::new();
        let long_worker_config = LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("Request budget non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(5)).expect("read budget non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500)).expect("write budget non-zero"),
        );

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                long_worker_config,
            );
            let report = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                context,
                attempts(2),
            )
            .expect("bounded scheduling cycle succeeds");

            assert_eq!(
                report.stop(),
                LocalLinuxSchedulingCycleStop::AttemptBudgetExhausted
            );
            assert_eq!(report.scheduling_attempts(), 2);
            assert_eq!(report.workers_registered(), 2);
            assert_eq!(registry.len(), 2);
            assert_eq!(capacity.active_workers(), 2);

            assert_eq!(registry.cancel_all().len(), 2);
            assert_eq!(registry.join_all().len(), 2);
        });

        assert_eq!(capacity.active_workers(), 0);
        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn reaps_finished_worker_before_next_schedule_attempt() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("reap-first");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let mut first_client = UnixStream::connect(&socket_path).expect("first client queues");
        write_local_command_request(
            &mut first_client,
            id(702),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("first Request writes");
        let mut second_client = UnixStream::connect(&socket_path).expect("second client queues");
        write_local_command_request(
            &mut second_client,
            id(703),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("second Request writes");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                worker_config(),
            );

            assert_eq!(
                schedule_one_authenticated_worker(scope, &listener, &mut registry, context),
                Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
            );

            while !registry.has_finished_worker_for_test() {
                thread::yield_now();
            }
            assert_eq!(capacity.active_workers(), 0);
            assert_eq!(registry.len(), 1);

            let report = run_bounded_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                context,
                attempts(1),
            )
            .expect("reap-first cycle succeeds");

            assert_eq!(report.completions().len(), 1);
            assert!(matches!(
                report.completions()[0],
                LocalLinuxScopedWorkerCompletion::Stopped(
                    LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                        responses_written: 1
                    }
                )
            ));
            assert_eq!(report.workers_registered(), 1);
            assert_eq!(registry.len(), 1);
            assert_eq!(registry.join_all().len(), 1);
        });

        assert_eq!(capacity.active_workers(), 0);
        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }
}
