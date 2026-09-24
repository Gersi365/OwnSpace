//! Finite Linux runtime readiness + scheduling orchestration proof.
//!
//! Phase 092 composes one Phase 091 readiness wait with a runtime-specific,
//! caller-bounded scheduling cycle whose workers always use the Phase 090
//! completion-wake spawn path. It deliberately preserves Phase 084/086 APIs and
//! contains no production outer loop or Agent bootstrap activation.

use std::num::NonZeroUsize;
use std::thread::Scope;

use prw_policy::BoundedLocalReadPolicy;

use super::accept_ready::{AcceptReadyAgentSocket, AuthenticatedAgentAcceptOutcome};
use super::authenticated_session_bridge::{
    AuthenticatedAgentSessionOutcome, compose_authenticated_session,
};
use super::bounded_scheduler_cycle::{LocalLinuxSchedulerControl, LocalLinuxSchedulingCycleStop};
use super::one_shot_scheduler::{LocalLinuxOneShotScheduleError, LocalLinuxOneShotScheduleOutcome};
use super::runtime_readiness::{
    LocalLinuxRuntimeReadinessError, LocalLinuxRuntimeReadinessOutcome,
    wait_once_for_linux_runtime_readiness,
};
use super::runtime_wake::{
    LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeNotifier, LocalLinuxRuntimeWakeNotify,
    LocalLinuxRuntimeWakeNotifyError,
};
use super::session_worker::LocalLinuxSessionWorkerConfig;
use super::session_worker_thread::{
    LocalLinuxCompletionWakeWorkerConfig,
    spawn_authenticated_session_worker_with_agent_status_management_and_completion_wake,
    spawn_authenticated_session_worker_with_completion_wake,
};
use super::worker_cancellation::LocalLinuxWorkerCancellation;
use super::worker_capacity::{LocalLinuxWorkerCapacity, LocalLinuxWorkerCapacityError};
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::LocalLinuxScopedWorkerRegistry;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxRuntimeWorkerSelection {
    LegacyReadOnly,
    AgentStatusOnlyManagement,
}

/// Runtime-specific scheduling context whose workers emit completion wake.
#[derive(Debug, Clone)]
pub struct LocalLinuxRuntimeSchedulerContext<'a> {
    capacity: &'a LocalLinuxWorkerCapacity,
    policy: &'a BoundedLocalReadPolicy,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
    worker_config: LocalLinuxSessionWorkerConfig,
    completion_wake: LocalLinuxRuntimeWakeNotifier,
    worker_selection: LocalLinuxRuntimeWorkerSelection,
}

impl<'a> LocalLinuxRuntimeSchedulerContext<'a> {
    /// Creates a finite runtime scheduling context from validated components.
    #[must_use]
    pub const fn new(
        capacity: &'a LocalLinuxWorkerCapacity,
        policy: &'a BoundedLocalReadPolicy,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
        worker_config: LocalLinuxSessionWorkerConfig,
        completion_wake: LocalLinuxRuntimeWakeNotifier,
    ) -> Self {
        Self {
            capacity,
            policy,
            status_snapshot,
            private_dns_snapshot,
            worker_config,
            completion_wake,
            worker_selection: LocalLinuxRuntimeWorkerSelection::LegacyReadOnly,
        }
    }

    /// Creates a scheduler context that selects the fixed AgentStatus-management worker.
    ///
    /// This constructor carries no management policy or provider authority. Commands 1/2
    /// continue to use the existing bounded read policy stored in the context.
    #[must_use]
    pub(super) const fn new_with_agent_status_management(
        capacity: &'a LocalLinuxWorkerCapacity,
        policy: &'a BoundedLocalReadPolicy,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
        worker_config: LocalLinuxSessionWorkerConfig,
        completion_wake: LocalLinuxRuntimeWakeNotifier,
    ) -> Self {
        Self {
            capacity,
            policy,
            status_snapshot,
            private_dns_snapshot,
            worker_config,
            completion_wake,
            worker_selection: LocalLinuxRuntimeWorkerSelection::AgentStatusOnlyManagement,
        }
    }

    /// Returns the shared Phase 075 worker capacity used by readiness/scheduling.
    #[must_use]
    pub const fn capacity(&self) -> &LocalLinuxWorkerCapacity {
        self.capacity
    }
}

/// Evidence from one runtime-specific bounded scheduling cycle.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxRuntimeSchedulingCycleReport {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    workers_registered: usize,
    scheduling_attempts: usize,
    stop: LocalLinuxSchedulingCycleStop,
}

impl LocalLinuxRuntimeSchedulingCycleReport {
    /// Returns completions reaped before runtime scheduling attempts.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns how many completion-wake workers were registered.
    #[must_use]
    pub const fn workers_registered(&self) -> usize {
        self.workers_registered
    }

    /// Returns the exact number of runtime scheduling attempts performed.
    #[must_use]
    pub const fn scheduling_attempts(&self) -> usize {
        self.scheduling_attempts
    }

    /// Returns the Phase 085-compatible stop reason.
    #[must_use]
    pub const fn stop(&self) -> LocalLinuxSchedulingCycleStop {
        self.stop
    }
}

/// Evidence returned when runtime-specific scheduling fails.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxRuntimeSchedulingCycleError {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    workers_registered: usize,
    scheduling_attempts: usize,
    error: LocalLinuxOneShotScheduleError,
}

impl LocalLinuxRuntimeSchedulingCycleError {
    /// Returns completions reaped before the scheduling failure.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns workers registered earlier in the same finite cycle.
    #[must_use]
    pub const fn workers_registered(&self) -> usize {
        self.workers_registered
    }

    /// Returns attempts including the failed attempt.
    #[must_use]
    pub const fn scheduling_attempts(&self) -> usize {
        self.scheduling_attempts
    }

    /// Returns the existing bounded Phase 084 error taxonomy.
    #[must_use]
    pub const fn error(&self) -> LocalLinuxOneShotScheduleError {
        self.error
    }
}

/// Terminal outcome of one finite readiness + scheduling orchestration step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeOrchestrationStop {
    /// Terminal shutdown was observed before listener dispatch.
    ShutdownObserved,
    /// A runtime wake was handled without an eligible listener dispatch.
    RuntimeWake,
    /// The single blocking poll was interrupted and not retried internally.
    WaitInterrupted,
    /// Listener readiness was dispatched to one caller-bounded scheduling cycle.
    Scheduling(LocalLinuxSchedulingCycleStop),
}

/// Evidence from exactly one finite Phase 092 orchestration invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxRuntimeOrchestrationReport {
    readiness_completions: Vec<LocalLinuxScopedWorkerCompletion>,
    scheduling_completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    workers_registered: usize,
    scheduling_attempts: usize,
    stop: LocalLinuxRuntimeOrchestrationStop,
}

impl LocalLinuxRuntimeOrchestrationReport {
    /// Returns completions observed during wake-first Phase 091 processing.
    #[must_use]
    pub fn readiness_completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.readiness_completions
    }

    /// Returns completions reaped inside the runtime scheduling cycle.
    #[must_use]
    pub fn scheduling_completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.scheduling_completions
    }

    /// Returns whether listener interest was armed by Phase 091.
    #[must_use]
    pub const fn listener_armed(&self) -> bool {
        self.listener_armed
    }

    /// Returns how many completion-wake workers were registered.
    #[must_use]
    pub const fn workers_registered(&self) -> usize {
        self.workers_registered
    }

    /// Returns how many runtime-specific scheduling attempts were performed.
    #[must_use]
    pub const fn scheduling_attempts(&self) -> usize {
        self.scheduling_attempts
    }

    /// Returns the finite terminal orchestration reason.
    #[must_use]
    pub const fn stop(&self) -> LocalLinuxRuntimeOrchestrationStop {
        self.stop
    }
}

/// Bounded failure from one Phase 092 orchestration invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalLinuxRuntimeOrchestrationError {
    /// The one-step Phase 091 readiness primitive failed closed.
    Readiness(LocalLinuxRuntimeReadinessError),
    /// Runtime-specific scheduling failed after listener readiness.
    Scheduling(LocalLinuxRuntimeSchedulingCycleError),
}

/// Cloneable shutdown producer preserving state-before-wake ordering.
#[derive(Debug, Clone)]
pub struct LocalLinuxRuntimeShutdownHandle {
    control: LocalLinuxSchedulerControl,
    wake: LocalLinuxRuntimeWakeNotifier,
}

impl LocalLinuxRuntimeShutdownHandle {
    /// Couples monotonic scheduler control with one Phase 089 wake notifier.
    #[must_use]
    pub const fn new(
        control: LocalLinuxSchedulerControl,
        wake: LocalLinuxRuntimeWakeNotifier,
    ) -> Self {
        Self { control, wake }
    }

    /// Requests terminal shutdown before posting runtime wake.
    ///
    /// The shutdown bit remains terminally set even if notification fails.
    ///
    /// # Errors
    ///
    /// Returns the bounded Phase 089 notifier error after the shutdown state has
    /// already been committed.
    pub fn request_shutdown_and_wake(
        &self,
    ) -> Result<LocalLinuxRuntimeWakeNotify, LocalLinuxRuntimeWakeNotifyError> {
        self.control.request_shutdown();
        self.wake.notify()
    }
}

/// Performs at most one capacity-gated authenticated scheduling transaction,
/// using the Phase 090 completion-wake worker spawn path.
///
/// # Errors
///
/// Returns the existing bounded Phase 084 error taxonomy for accept,
/// cancellation-clone, or scoped-spawn failure.
pub fn schedule_one_authenticated_runtime_worker<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &AcceptReadyAgentSocket<'_>,
    registry: &mut LocalLinuxScopedWorkerRegistry<'scope>,
    context: &LocalLinuxRuntimeSchedulerContext<'scope>,
) -> Result<LocalLinuxOneShotScheduleOutcome, LocalLinuxOneShotScheduleError> {
    let permit = match context.capacity.try_acquire() {
        Ok(permit) => permit,
        Err(LocalLinuxWorkerCapacityError::AtCapacity) => {
            return Ok(LocalLinuxOneShotScheduleOutcome::AtCapacity);
        }
    };

    let accept_outcome = listener
        .try_accept_authenticated()
        .map_err(LocalLinuxOneShotScheduleError::Accept)?;

    let cancellation = match &accept_outcome {
        AuthenticatedAgentAcceptOutcome::NoConnectionReady => {
            drop(permit);
            return Ok(LocalLinuxOneShotScheduleOutcome::NoConnectionReady);
        }
        AuthenticatedAgentAcceptOutcome::Authenticated(connection) => {
            LocalLinuxWorkerCancellation::try_from_authenticated_connection(connection)
                .map_err(LocalLinuxOneShotScheduleError::CancellationClone)?
        }
    };

    let AuthenticatedAgentSessionOutcome::AuthenticatedSession(session) =
        compose_authenticated_session(accept_outcome)
    else {
        unreachable!("authenticated accept outcome was checked before session composition");
    };

    let config = LocalLinuxCompletionWakeWorkerConfig::new(
        context.worker_config,
        context.completion_wake.clone(),
    );
    let handle = match context.worker_selection {
        LocalLinuxRuntimeWorkerSelection::LegacyReadOnly => {
            spawn_authenticated_session_worker_with_completion_wake(
                scope,
                session,
                permit,
                context.policy,
                context.status_snapshot,
                context.private_dns_snapshot,
                config,
            )
        }
        LocalLinuxRuntimeWorkerSelection::AgentStatusOnlyManagement => {
            spawn_authenticated_session_worker_with_agent_status_management_and_completion_wake(
                scope,
                session,
                permit,
                context.policy,
                context.status_snapshot,
                context.private_dns_snapshot,
                config,
            )
        }
    }
    .map_err(LocalLinuxOneShotScheduleError::Spawn)?;

    registry.register(handle, cancellation);
    Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
}

/// Runs one caller-bounded runtime-specific scheduling cycle.
///
/// The semantics mirror the Phase 085/086 finite cycle, but every registered
/// worker is spawned through the Phase 090 completion-wake path. Before every
/// possible accept, finished workers are reaped and shutdown is re-observed.
/// `AtCapacity`, `NoConnectionReady`, and the first error terminate the cycle.
///
/// # Errors
///
/// Returns the first bounded scheduling failure with accumulated evidence.
pub fn run_bounded_runtime_scheduling_cycle<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &AcceptReadyAgentSocket<'_>,
    registry: &mut LocalLinuxScopedWorkerRegistry<'scope>,
    control: &LocalLinuxSchedulerControl,
    context: &LocalLinuxRuntimeSchedulerContext<'scope>,
    attempt_budget: NonZeroUsize,
) -> Result<LocalLinuxRuntimeSchedulingCycleReport, LocalLinuxRuntimeSchedulingCycleError> {
    let mut completions = Vec::new();
    let mut workers_registered = 0_usize;
    let mut scheduling_attempts = 0_usize;

    for _ in 0..attempt_budget.get() {
        completions.extend(registry.reap_finished());

        if control.is_shutdown_requested() {
            return Ok(LocalLinuxRuntimeSchedulingCycleReport {
                completions,
                workers_registered,
                scheduling_attempts,
                stop: LocalLinuxSchedulingCycleStop::ShutdownRequested,
            });
        }

        scheduling_attempts += 1;
        let outcome = schedule_one_authenticated_runtime_worker(scope, listener, registry, context)
            .map_err(|error| LocalLinuxRuntimeSchedulingCycleError {
                completions: std::mem::take(&mut completions),
                workers_registered,
                scheduling_attempts,
                error,
            })?;

        match outcome {
            LocalLinuxOneShotScheduleOutcome::WorkerRegistered => workers_registered += 1,
            LocalLinuxOneShotScheduleOutcome::AtCapacity => {
                return Ok(LocalLinuxRuntimeSchedulingCycleReport {
                    completions,
                    workers_registered,
                    scheduling_attempts,
                    stop: LocalLinuxSchedulingCycleStop::AtCapacity,
                });
            }
            LocalLinuxOneShotScheduleOutcome::NoConnectionReady => {
                return Ok(LocalLinuxRuntimeSchedulingCycleReport {
                    completions,
                    workers_registered,
                    scheduling_attempts,
                    stop: LocalLinuxSchedulingCycleStop::NoConnectionReady,
                });
            }
        }
    }

    Ok(LocalLinuxRuntimeSchedulingCycleReport {
        completions,
        workers_registered,
        scheduling_attempts,
        stop: LocalLinuxSchedulingCycleStop::AttemptBudgetExhausted,
    })
}

/// Performs one finite readiness wait and, only for listener readiness, one
/// caller-bounded runtime scheduling cycle.
///
/// There is no internal outer loop. `RuntimeWake`, `ShutdownObserved`, and
/// `WaitInterrupted` return immediately with zero scheduling attempts. Listener
/// readiness is the only Phase 091 outcome that may enter scheduling, and the
/// scheduling layer rechecks shutdown before every possible accept.
///
/// # Errors
///
/// Returns the bounded Phase 091 readiness failure or the first runtime-specific
/// scheduling failure.
pub fn run_finite_linux_runtime_orchestration<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &AcceptReadyAgentSocket<'_>,
    wake: &LocalLinuxRuntimeWake,
    registry: &mut LocalLinuxScopedWorkerRegistry<'scope>,
    control: &LocalLinuxSchedulerControl,
    context: &LocalLinuxRuntimeSchedulerContext<'scope>,
    attempt_budget: NonZeroUsize,
) -> Result<LocalLinuxRuntimeOrchestrationReport, LocalLinuxRuntimeOrchestrationError> {
    let readiness =
        wait_once_for_linux_runtime_readiness(listener, wake, context.capacity, registry, control)
            .map_err(LocalLinuxRuntimeOrchestrationError::Readiness)?;

    let listener_armed = readiness.listener_armed();
    let readiness_completions = readiness.completions().to_vec();

    match readiness.outcome() {
        LocalLinuxRuntimeReadinessOutcome::ShutdownObserved => Ok(orchestration_report(
            readiness_completions,
            Vec::new(),
            listener_armed,
            0,
            0,
            LocalLinuxRuntimeOrchestrationStop::ShutdownObserved,
        )),
        LocalLinuxRuntimeReadinessOutcome::RuntimeWake => Ok(orchestration_report(
            readiness_completions,
            Vec::new(),
            listener_armed,
            0,
            0,
            LocalLinuxRuntimeOrchestrationStop::RuntimeWake,
        )),
        LocalLinuxRuntimeReadinessOutcome::WaitInterrupted => Ok(orchestration_report(
            readiness_completions,
            Vec::new(),
            listener_armed,
            0,
            0,
            LocalLinuxRuntimeOrchestrationStop::WaitInterrupted,
        )),
        LocalLinuxRuntimeReadinessOutcome::ListenerReady => {
            let scheduling = run_bounded_runtime_scheduling_cycle(
                scope,
                listener,
                registry,
                control,
                context,
                attempt_budget,
            )
            .map_err(LocalLinuxRuntimeOrchestrationError::Scheduling)?;

            Ok(orchestration_report(
                readiness_completions,
                scheduling.completions,
                listener_armed,
                scheduling.workers_registered,
                scheduling.scheduling_attempts,
                LocalLinuxRuntimeOrchestrationStop::Scheduling(scheduling.stop),
            ))
        }
    }
}

const fn orchestration_report(
    readiness_completions: Vec<LocalLinuxScopedWorkerCompletion>,
    scheduling_completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    workers_registered: usize,
    scheduling_attempts: usize,
    stop: LocalLinuxRuntimeOrchestrationStop,
) -> LocalLinuxRuntimeOrchestrationReport {
    LocalLinuxRuntimeOrchestrationReport {
        readiness_completions,
        scheduling_completions,
        listener_armed,
        workers_registered,
        scheduling_attempts,
        stop,
    }
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
    use prw_remote_bridge::BridgeCommand;

    use super::{
        LocalLinuxRuntimeOrchestrationStop, LocalLinuxRuntimeSchedulerContext,
        LocalLinuxRuntimeShutdownHandle, LocalLinuxRuntimeWorkerSelection,
        run_finite_linux_runtime_orchestration, wait_once_for_linux_runtime_readiness,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::write_frame;
    use crate::linux_identity::accept_ready::{
        AcceptReadyAgentSocket, AuthenticatedAgentAcceptOutcome, prepare_accept_ready_agent_socket,
    };
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::bounded_scheduler_cycle::{
        LocalLinuxSchedulerControl, LocalLinuxSchedulingCycleStop,
    };
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::listening_socket::listen_bound_agent_socket;
    use crate::linux_identity::runtime_wake::{
        LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeDrainError,
    };
    use crate::linux_identity::session_worker::LocalLinuxSessionWorkerConfig;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::linux_identity::worker_registry::LocalLinuxScopedWorkerRegistry;
    use crate::linux_identity::xdg_runtime_root;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLock, acquire_agent_instance_lock,
    };
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::local_commands::{LocalAgentCommand, LocalAgentResponseStatus};
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct RuntimeFixture {
        root_path: PathBuf,
        runtime_directory: ValidatedPrwRuntimeDirectory,
        instance_lock: AgentInstanceLock,
    }

    impl RuntimeFixture {
        fn new(label: &str) -> Self {
            let root_path = unique_temp_path(label);
            create_directory_with_mode(&root_path, 0o700);
            let root = xdg_runtime_root::validate_xdg_runtime_root_path(&root_path)
                .expect("temporary root satisfies Phase 062 validation");
            let runtime_directory =
                xdg_runtime_root::prw_runtime_directory::prepare_prw_runtime_directory(&root)
                    .expect("temporary PRW directory satisfies Phase 063 preparation");
            drop(root);
            let instance_lock = acquire_agent_instance_lock(&runtime_directory)
                .expect("temporary lifecycle authority satisfies Phase 065");
            Self {
                root_path,
                runtime_directory,
                instance_lock,
            }
        }

        fn listener(&self) -> AcceptReadyAgentSocket<'_> {
            let bound = bind_validated_agent_socket(&self.runtime_directory, &self.instance_lock)
                .expect("Phase 067 bound socket creates");
            let listening = listen_bound_agent_socket(
                bound,
                NonZeroU16::new(8).expect("test backlog is nonzero"),
            )
            .expect("Phase 068 listener creates");
            prepare_accept_ready_agent_socket(listening)
                .expect("Phase 070 listener becomes accept-ready")
        }

        fn socket_path(&self) -> PathBuf {
            self.root_path
                .join(AGENT_RUNTIME_SUBDIRECTORY)
                .join(AGENT_SOCKET_FILENAME)
        }

        fn cleanup(&self, listener: AcceptReadyAgentSocket<'_>) {
            listener.cleanup().expect("listener cleanup succeeds");
            fs::remove_dir_all(&self.root_path).expect("temporary Phase 092 root removes");
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-092-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 092 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 092 directory mode sets");
    }

    fn worker_capacity(value: usize) -> LocalLinuxWorkerCapacity {
        LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(value).expect("test worker capacity is non-zero"),
        )
    }

    fn worker_config(request_budget: usize) -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(request_budget).expect("test request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2))
                .expect("test read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2))
                .expect("test write budget is non-zero"),
        )
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn context<'a>(
        capacity: &'a LocalLinuxWorkerCapacity,
        policy: &'a BoundedLocalReadPolicy,
        dns: &'a LocalPrivateDnsSnapshot,
        wake: &LocalLinuxRuntimeWake,
        request_budget: usize,
    ) -> LocalLinuxRuntimeSchedulerContext<'a> {
        LocalLinuxRuntimeSchedulerContext::new(
            capacity,
            policy,
            LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready),
            dns,
            worker_config(request_budget),
            wake.notifier(),
        )
    }

    fn agent_status_context<'a>(
        capacity: &'a LocalLinuxWorkerCapacity,
        policy: &'a BoundedLocalReadPolicy,
        dns: &'a LocalPrivateDnsSnapshot,
        wake: &LocalLinuxRuntimeWake,
        request_budget: usize,
    ) -> LocalLinuxRuntimeSchedulerContext<'a> {
        LocalLinuxRuntimeSchedulerContext::new_with_agent_status_management(
            capacity,
            policy,
            LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready),
            dns,
            worker_config(request_budget),
            wake.notifier(),
        )
    }

    fn canonical_file_list_payload(path: &str) -> Vec<u8> {
        let path = path.as_bytes();
        let path_len = u16::try_from(path.len()).expect("test path length fits u16");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"PRWC");
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&2_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path);
        payload
    }

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn runtime_context_constructors_select_legacy_and_agent_status_workers_explicitly() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();

        let legacy = context(&capacity, &policy, &dns, &wake, 1);
        let agent_status = agent_status_context(&capacity, &policy, &dns, &wake, 1);

        assert_eq!(
            legacy.worker_selection,
            LocalLinuxRuntimeWorkerSelection::LegacyReadOnly
        );
        assert_eq!(
            agent_status.worker_selection,
            LocalLinuxRuntimeWorkerSelection::AgentStatusOnlyManagement
        );
    }

    #[test]
    fn agent_status_worker_selection_routes_management_and_preserves_legacy_command_one() {
        let fixture = RuntimeFixture::new("agent-status-selection");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let context = agent_status_context(&capacity, &policy, &dns, &wake, 2);
        let mut client = UnixStream::connect(socket_path).expect("test client connects");

        let bridge = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus command encodes");
        let management = build_local_management_request_frame(id(710), &bridge)
            .expect("management frame builds");
        write_frame(&mut client, &management).expect("management request writes");
        write_local_command_request(&mut client, id(711), LocalAgentCommand::GetAgentStatus)
            .expect("legacy request writes");

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("AgentStatus-selected orchestration succeeds");

            assert_eq!(report.workers_registered(), 1);

            let management_response = read_frame(&mut client).expect("management response reads");
            let management_terminal = validate_terminal_response_frame(&management_response)
                .expect("management response validates");
            assert_eq!(management_terminal.request_id(), id(710));
            assert_eq!(management_terminal.status(), LocalAgentResponseStatus::Ok);

            let legacy_response = read_frame(&mut client).expect("legacy response reads");
            let legacy_status = decode_success_status_frame(&legacy_response)
                .expect("legacy status response decodes");
            assert_eq!(legacy_status.request_id(), id(711));

            let completion = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &capacity,
                &mut registry,
                &control,
            )
            .expect("narrow worker completion wake is observed");
            assert_eq!(capacity.active_workers(), 0);
            let reaped = completion.completions().len();
            let remaining = registry.join_all();
            assert_eq!(reaped + remaining.len(), 1);
        });

        fixture.cleanup(listener);
    }

    #[test]
    fn agent_status_worker_selection_denies_non_agent_status_management_command() {
        let fixture = RuntimeFixture::new("agent-status-deny");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let context = agent_status_context(&capacity, &policy, &dns, &wake, 1);
        let mut client = UnixStream::connect(socket_path).expect("test client connects");
        let file_list = canonical_file_list_payload("documents");
        let request = build_local_management_request_frame(id(712), &file_list)
            .expect("file-list management frame builds");
        write_frame(&mut client, &request).expect("file-list management request writes");

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("denied management command still receives terminal response");

            assert_eq!(report.workers_registered(), 1);

            let response = read_frame(&mut client).expect("denial response reads");
            let terminal =
                validate_terminal_response_frame(&response).expect("denial response validates");
            assert_eq!(terminal.request_id(), id(712));
            assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);

            let completion = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &capacity,
                &mut registry,
                &control,
            )
            .expect("denied worker completion wake is observed");
            assert_eq!(capacity.active_workers(), 0);
            let reaped = completion.completions().len();
            let remaining = registry.join_all();
            assert_eq!(reaped + remaining.len(), 1);
        });

        fixture.cleanup(listener);
    }

    #[test]
    fn listener_ready_orchestration_registers_only_completion_wake_worker() {
        let fixture = RuntimeFixture::new("register");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let context = context(&capacity, &policy, &dns, &wake, 1);
        let mut client = UnixStream::connect(socket_path).expect("test client connects");
        write_local_command_request(&mut client, id(700), LocalAgentCommand::GetAgentStatus)
            .expect("test request writes");

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("finite orchestration succeeds");

            assert_eq!(
                report.stop(),
                LocalLinuxRuntimeOrchestrationStop::Scheduling(
                    LocalLinuxSchedulingCycleStop::AttemptBudgetExhausted
                )
            );
            assert_eq!(report.workers_registered(), 1);
            assert_eq!(report.scheduling_attempts(), 1);
            assert!(report.listener_armed());

            let response = read_frame(&mut client).expect("worker response reads");
            let response = decode_success_status_frame(&response).expect("status response decodes");
            assert_eq!(response.request_id(), id(700));

            let completion = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &capacity,
                &mut registry,
                &control,
            )
            .expect("completion wake is observed");
            assert!(matches!(
                completion.outcome(),
                crate::linux_identity::runtime_readiness::LocalLinuxRuntimeReadinessOutcome::RuntimeWake
                    | crate::linux_identity::runtime_readiness::LocalLinuxRuntimeReadinessOutcome::ListenerReady
            ));
            assert_eq!(capacity.active_workers(), 0);

            let _ = registry.cancel_all();
            let _ = registry.join_all();
        });

        fixture.cleanup(listener);
    }

    #[test]
    fn worker_completion_wake_restores_capacity_for_next_client() {
        let fixture = RuntimeFixture::new("completion-restores-capacity");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let context = context(&capacity, &policy, &dns, &wake, 1);
        let first_client = UnixStream::connect(&socket_path).expect("first client connects");

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let first = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("first client schedules");
            assert_eq!(first.workers_registered(), 1);
            assert_eq!(capacity.active_workers(), 1);
            assert_eq!(
                wake.drain(),
                Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
            );

            drop(first_client);

            let completion = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &capacity,
                &mut registry,
                &control,
            )
            .expect("first completion wake is observed");
            assert_eq!(
                completion.outcome(),
                crate::linux_identity::runtime_readiness::LocalLinuxRuntimeReadinessOutcome::RuntimeWake
            );
            assert_eq!(capacity.active_workers(), 0);

            let mut second_client =
                UnixStream::connect(&socket_path).expect("second client connects after wake");
            write_local_command_request(
                &mut second_client,
                id(701),
                LocalAgentCommand::GetAgentStatus,
            )
            .expect("second request writes");

            let second = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("released capacity permits next scheduling step");

            assert_eq!(second.workers_registered(), 1);
            assert_eq!(second.scheduling_attempts(), 1);
            assert_eq!(
                second.stop(),
                LocalLinuxRuntimeOrchestrationStop::Scheduling(
                    LocalLinuxSchedulingCycleStop::AttemptBudgetExhausted
                )
            );

            let response = read_frame(&mut second_client).expect("second response reads");
            let response =
                decode_success_status_frame(&response).expect("second status response decodes");
            assert_eq!(response.request_id(), id(701));

            let _ = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &capacity,
                &mut registry,
                &control,
            )
            .expect("second completion wake is observed");
            assert_eq!(capacity.active_workers(), 0);

            let _ = registry.cancel_all();
            let _ = registry.join_all();
        });

        fixture.cleanup(listener);
    }

    #[test]
    fn shutdown_state_is_committed_before_wake_and_prevents_queued_accept() {
        let fixture = RuntimeFixture::new("shutdown");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let shutdown = LocalLinuxRuntimeShutdownHandle::new(control.clone(), wake.notifier());
        let context = context(&capacity, &policy, &dns, &wake, 1);
        let client =
            UnixStream::connect(socket_path).expect("queued shutdown-test client connects");

        assert!(shutdown.request_shutdown_and_wake().is_ok());
        assert!(control.is_shutdown_requested());

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = run_finite_linux_runtime_orchestration(
                scope,
                &listener,
                &wake,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(1).expect("attempt budget is nonzero"),
            )
            .expect("shutdown is a normal finite outcome");

            assert_eq!(
                report.stop(),
                LocalLinuxRuntimeOrchestrationStop::ShutdownObserved
            );
            assert_eq!(report.workers_registered(), 0);
            assert_eq!(report.scheduling_attempts(), 0);
            assert_eq!(capacity.active_workers(), 0);
            assert!(registry.is_empty());
        });

        match listener
            .try_accept_authenticated()
            .expect("queued client remains acceptable after proof")
        {
            AuthenticatedAgentAcceptOutcome::Authenticated(connection) => drop(connection),
            AuthenticatedAgentAcceptOutcome::NoConnectionReady => {
                panic!("shutdown orchestration unexpectedly consumed queued client")
            }
        }
        drop(client);
        fixture.cleanup(listener);
    }

    #[test]
    fn runtime_cycle_stops_at_capacity_without_accepting_queued_client() {
        let fixture = RuntimeFixture::new("cycle-capacity");
        let socket_path = fixture.socket_path();
        let listener = fixture.listener();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let capacity = worker_capacity(1);
        let permit = capacity.try_acquire().expect("sole worker permit acquires");
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let control = LocalLinuxSchedulerControl::new();
        let context = context(&capacity, &policy, &dns, &wake, 1);
        let client =
            UnixStream::connect(socket_path).expect("queued capacity-test client connects");

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = super::run_bounded_runtime_scheduling_cycle(
                scope,
                &listener,
                &mut registry,
                &control,
                &context,
                NonZeroUsize::new(3).expect("attempt budget is nonzero"),
            )
            .expect("capacity is a normal stop");

            assert_eq!(report.stop(), LocalLinuxSchedulingCycleStop::AtCapacity);
            assert_eq!(report.scheduling_attempts(), 1);
            assert_eq!(report.workers_registered(), 0);
            assert!(registry.is_empty());
        });

        drop(permit);
        match listener
            .try_accept_authenticated()
            .expect("queued client remains after at-capacity stop")
        {
            AuthenticatedAgentAcceptOutcome::Authenticated(connection) => drop(connection),
            AuthenticatedAgentAcceptOutcome::NoConnectionReady => {
                panic!("at-capacity runtime cycle unexpectedly consumed queued client")
            }
        }
        drop(client);
        fixture.cleanup(listener);
    }

    #[test]
    fn completion_wake_does_not_encode_worker_result_count() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let notifier = wake.notifier();
        notifier.notify().expect("first wake posts");
        notifier.notify().expect("second wake posts");
        assert_eq!(wake.drain(), Ok(()));
        assert_eq!(
            wake.drain(),
            Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
        );
    }
}
