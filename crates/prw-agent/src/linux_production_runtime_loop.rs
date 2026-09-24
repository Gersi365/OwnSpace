//! Callable long-running production-local Linux runtime loop.
//!
//! Phase 097 repeatedly invokes the finite Phase 092 orchestration primitive
//! under the Phase 094-A01 success/error disposition policy. The loop is usable
//! only from an already-prepared Phase 096 lifecycle boundary and can be stopped
//! through the existing programmatic shutdown handle. It does not process OS
//! signals, wire `main.rs`, or activate systemd.

use std::thread;

use prw_policy::BoundedLocalReadPolicy;

use super::accept_ready::AcceptReadyAgentSocket;
use super::bounded_scheduler_cycle::LocalLinuxSchedulerControl;
use super::production_lifecycle::{
    LocalLinuxProductionLifecycleAssemblyError, with_local_linux_production_lifecycle_from_env,
};
use super::production_runtime_types::{
    LocalLinuxProductionRuntimeCleanup, LocalLinuxProductionRuntimeConfig,
    LocalLinuxProductionRuntimeCounters, LocalLinuxProductionRuntimeFatalError,
    LocalLinuxProductionRuntimeTerminalReason, LocalLinuxProductionRuntimeTerminalReport,
    LocalLinuxRuntimeErrorDisposition, classify_production_runtime_error,
};
use super::runtime_orchestration::{
    LocalLinuxRuntimeOrchestrationError, LocalLinuxRuntimeOrchestrationStop,
    LocalLinuxRuntimeSchedulerContext, LocalLinuxRuntimeShutdownHandle,
    run_finite_linux_runtime_orchestration,
};
use super::runtime_wake::LocalLinuxRuntimeWake;
use super::worker_capacity::LocalLinuxWorkerCapacity;
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::{
    LocalLinuxRegisteredWorkerCancellation, LocalLinuxScopedWorkerRegistry,
};
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

/// Immutable operational inputs for one production-local runtime invocation.
#[derive(Debug, Clone, Copy)]
pub struct LocalLinuxProductionRuntimeInputs<'a> {
    config: LocalLinuxProductionRuntimeConfig,
    policy: BoundedLocalReadPolicy,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
}

impl<'a> LocalLinuxProductionRuntimeInputs<'a> {
    /// Creates one immutable runtime-input bundle from already-validated values.
    #[must_use]
    pub const fn new(
        config: LocalLinuxProductionRuntimeConfig,
        policy: BoundedLocalReadPolicy,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
    ) -> Self {
        Self {
            config,
            policy,
            status_snapshot,
            private_dns_snapshot,
        }
    }

    /// Returns the validated production runtime configuration.
    #[must_use]
    pub const fn config(self) -> LocalLinuxProductionRuntimeConfig {
        self.config
    }

    /// Returns the bounded local authorization policy by shared reference.
    #[must_use]
    pub const fn policy(&self) -> &BoundedLocalReadPolicy {
        &self.policy
    }

    /// Returns the immutable local Agent status snapshot.
    #[must_use]
    pub const fn status_snapshot(self) -> LocalAgentStatusSnapshot {
        self.status_snapshot
    }

    /// Returns the immutable bounded private-DNS snapshot reference.
    #[must_use]
    pub const fn private_dns_snapshot(self) -> &'a LocalPrivateDnsSnapshot {
        self.private_dns_snapshot
    }
}

/// Terminal evidence produced inside the worker scope, before listener cleanup.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxProductionRuntimeLoopExit {
    reason: LocalLinuxProductionRuntimeTerminalReason,
    counters: LocalLinuxProductionRuntimeCounters,
    cancellations: Vec<LocalLinuxRegisteredWorkerCancellation>,
    final_completions: Vec<LocalLinuxScopedWorkerCompletion>,
}

impl LocalLinuxProductionRuntimeLoopExit {
    /// Returns the original terminal loop reason.
    #[must_use]
    pub const fn reason(&self) -> LocalLinuxProductionRuntimeTerminalReason {
        self.reason
    }

    /// Returns memory-bounded process-lifetime counters.
    #[must_use]
    pub const fn counters(&self) -> LocalLinuxProductionRuntimeCounters {
        self.counters
    }

    /// Returns final cancellation outcomes, bounded by configured capacity.
    #[must_use]
    pub fn cancellations(&self) -> &[LocalLinuxRegisteredWorkerCancellation] {
        &self.cancellations
    }

    /// Returns final joined completions, bounded by configured capacity.
    #[must_use]
    pub fn final_completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.final_completions
    }

    /// Combines scope-terminal evidence with later listener/socket cleanup evidence.
    #[must_use]
    pub fn into_terminal_report(
        self,
        cleanup: LocalLinuxProductionRuntimeCleanup,
    ) -> LocalLinuxProductionRuntimeTerminalReport {
        LocalLinuxProductionRuntimeTerminalReport::new(
            self.reason,
            self.counters,
            self.cancellations,
            self.final_completions,
            cleanup,
        )
    }
}

/// Runs the production-local readiness/scheduling loop until shutdown or fail-stop.
///
/// Every iteration calls exactly one finite Phase 092 orchestration invocation.
/// Successful nonterminal outcomes return to capacity-aware blocking readiness.
/// Same-UID peer authorization rejection is the only initial connection-local
/// error that continues. Every other Phase 091/092 error establishes a fatal
/// terminal reason and begins bounded worker cancellation/join teardown.
#[must_use]
pub fn run_local_linux_production_runtime_loop(
    listener: &AcceptReadyAgentSocket<'_>,
    wake: &LocalLinuxRuntimeWake,
    capacity: &LocalLinuxWorkerCapacity,
    control: &LocalLinuxSchedulerControl,
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
) -> LocalLinuxProductionRuntimeLoopExit {
    let context = LocalLinuxRuntimeSchedulerContext::new(
        capacity,
        &inputs.policy,
        inputs.status_snapshot,
        inputs.private_dns_snapshot,
        inputs.config.worker_config(),
        wake.notifier(),
    );

    thread::scope(|scope| {
        let mut registry = LocalLinuxScopedWorkerRegistry::new();
        let mut counters = LocalLinuxProductionRuntimeCounters::default();

        let reason = loop {
            let iteration = run_finite_linux_runtime_orchestration(
                scope,
                listener,
                wake,
                &mut registry,
                control,
                &context,
                inputs.config.scheduling_attempt_budget(),
            );

            match iteration {
                Ok(report) => {
                    counters.record_orchestration(&report);
                    match report.stop() {
                        LocalLinuxRuntimeOrchestrationStop::ShutdownObserved => {
                            break LocalLinuxProductionRuntimeTerminalReason::ShutdownRequested;
                        }
                        LocalLinuxRuntimeOrchestrationStop::RuntimeWake
                        | LocalLinuxRuntimeOrchestrationStop::WaitInterrupted
                        | LocalLinuxRuntimeOrchestrationStop::Scheduling(_) => {}
                    }
                }
                Err(error) => {
                    record_error_evidence(&mut counters, &error);
                    match classify_production_runtime_error(&error) {
                        LocalLinuxRuntimeErrorDisposition::ContinueAfterPeerRejection => {
                            counters.record_peer_rejection();
                        }
                        LocalLinuxRuntimeErrorDisposition::FailStop => {
                            let fatal = LocalLinuxProductionRuntimeFatalError::from_orchestration_error(
                                &error,
                            )
                            .expect("Phase 097 fail-stop classification always preserves fatal cause");
                            break LocalLinuxProductionRuntimeTerminalReason::Fatal(fatal);
                        }
                    }
                }
            }
        };

        let cancellations = registry.cancel_all();
        let final_completions = registry.join_all();
        counters.record_final_completions(final_completions.len());

        LocalLinuxProductionRuntimeLoopExit {
            reason,
            counters,
            cancellations,
            final_completions,
        }
    })
}

fn record_error_evidence(
    counters: &mut LocalLinuxProductionRuntimeCounters,
    error: &LocalLinuxRuntimeOrchestrationError,
) {
    if let LocalLinuxRuntimeOrchestrationError::Scheduling(scheduling) = error {
        counters.record_scheduling_error(scheduling);
    }
}

/// Runs the programmatic-shutdown production-local runtime from process environment.
///
/// `on_started` receives one cloneable Phase 092 shutdown handle after lifecycle
/// resources are assembled and before the blocking loop begins. This is the
/// Phase 097 control seam for tests and pre-signal integration; OS signals remain
/// deferred to Phase 098.
///
/// # Errors
///
/// Returns only Phase 096 lifecycle assembly failures. Runtime readiness and
/// scheduling failures are represented as bounded terminal report reasons.
pub fn run_local_linux_production_runtime_from_env<F>(
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
    on_started: F,
) -> Result<LocalLinuxProductionRuntimeTerminalReport, LocalLinuxProductionLifecycleAssemblyError>
where
    F: FnOnce(LocalLinuxRuntimeShutdownHandle),
{
    let execution = with_local_linux_production_lifecycle_from_env(
        inputs.config(),
        |listener, wake, capacity, control| {
            on_started(LocalLinuxRuntimeShutdownHandle::new(
                control.clone(),
                wake.notifier(),
            ));
            run_local_linux_production_runtime_loop(listener, wake, capacity, control, inputs)
        },
    )?;

    let cleanup = execution.cleanup();
    Ok(execution.into_value().into_terminal_report(cleanup))
}

#[cfg(test)]
fn run_local_linux_production_runtime_in_root_path<F>(
    root_path: &std::path::Path,
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
    on_started: F,
) -> Result<LocalLinuxProductionRuntimeTerminalReport, LocalLinuxProductionLifecycleAssemblyError>
where
    F: FnOnce(LocalLinuxRuntimeShutdownHandle),
{
    let execution =
        super::production_lifecycle::with_local_linux_production_lifecycle_in_root_path(
            root_path,
            inputs.config(),
            |listener, wake, capacity, control| {
                on_started(LocalLinuxRuntimeShutdownHandle::new(
                    control.clone(),
                    wake.notifier(),
                ));
                run_local_linux_production_runtime_loop(listener, wake, capacity, control, inputs)
            },
        )?;

    let cleanup = execution.cleanup();
    Ok(execution.into_value().into_terminal_report(cleanup))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::BoundedLocalReadPolicy;

    use super::{
        LocalLinuxProductionRuntimeInputs, run_local_linux_production_runtime_in_root_path,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::production_runtime_types::{
        LocalLinuxProductionRuntimeCleanup, LocalLinuxProductionRuntimeConfig,
        LocalLinuxProductionRuntimeTerminalReason,
    };
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn create_root(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "prw-phase-097-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("temporary Phase 097 root creates");
        fs::set_permissions(&root, Permissions::from_mode(0o700))
            .expect("temporary Phase 097 root mode sets");
        root
    }

    fn config() -> LocalLinuxProductionRuntimeConfig {
        LocalLinuxProductionRuntimeConfig::new(
            NonZeroUsize::new(2).expect("capacity nonzero"),
            NonZeroU16::new(8).expect("backlog nonzero"),
            NonZeroUsize::new(2).expect("attempt budget nonzero"),
            NonZeroUsize::new(1).expect("request budget nonzero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("read budget nonzero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("write budget nonzero"),
        )
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn inputs(dns: &LocalPrivateDnsSnapshot) -> LocalLinuxProductionRuntimeInputs<'_> {
        LocalLinuxProductionRuntimeInputs::new(
            config(),
            BoundedLocalReadPolicy::allow_local_reads(),
            LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready),
            dns,
        )
    }

    fn socket_path(root: &Path) -> PathBuf {
        root.join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("request id is nonzero")
    }

    #[test]
    fn programmatic_shutdown_before_first_wait_returns_clean_terminal_report() {
        let root = create_root("shutdown-first");
        let dns = dns_snapshot();

        let report =
            run_local_linux_production_runtime_in_root_path(&root, inputs(&dns), |shutdown| {
                shutdown
                    .request_shutdown_and_wake()
                    .expect("programmatic shutdown wake posts");
            })
            .expect("Phase 097 runtime assembles");

        assert_eq!(
            report.reason(),
            LocalLinuxProductionRuntimeTerminalReason::ShutdownRequested
        );
        assert_eq!(report.cleanup(), LocalLinuxProductionRuntimeCleanup::Clean);
        assert_eq!(report.counters().readiness_steps(), 1);
        assert_eq!(report.counters().workers_registered(), 0);
        assert!(report.cancellations().is_empty());
        assert!(report.final_completions().is_empty());
        assert!(!socket_path(&root).exists());

        fs::remove_dir_all(root).expect("temporary shutdown-first root removes");
    }

    #[test]
    fn one_client_round_trip_then_programmatic_shutdown_exits_and_cleans() {
        let root = create_root("client-shutdown");
        let path = socket_path(&root);
        let dns = dns_snapshot();
        let client_thread = Arc::new(Mutex::new(None));
        let client_thread_slot = Arc::clone(&client_thread);

        let report =
            run_local_linux_production_runtime_in_root_path(&root, inputs(&dns), move |shutdown| {
                let path = path.clone();
                let handle = thread::spawn(move || {
                    let mut client = UnixStream::connect(path).expect("client connects");
                    write_local_command_request(
                        &mut client,
                        id(970),
                        LocalAgentCommand::GetAgentStatus,
                    )
                    .expect("client request writes");
                    let frame = read_frame(&mut client).expect("client response frame reads");
                    let response = decode_success_status_frame(&frame)
                        .expect("client status response decodes");
                    assert_eq!(response.request_id(), id(970));
                    shutdown
                        .request_shutdown_and_wake()
                        .expect("shutdown after response posts");
                });
                *client_thread_slot.lock().expect("client thread slot locks") = Some(handle);
            })
            .expect("Phase 097 runtime assembles");

        client_thread
            .lock()
            .expect("client thread slot locks after runtime")
            .take()
            .expect("client thread was registered")
            .join()
            .expect("client thread exits cleanly");

        assert_eq!(
            report.reason(),
            LocalLinuxProductionRuntimeTerminalReason::ShutdownRequested
        );
        assert_eq!(report.cleanup(), LocalLinuxProductionRuntimeCleanup::Clean);
        assert!(report.counters().readiness_steps() >= 2);
        assert!(report.counters().scheduling_attempts() >= 1);
        assert_eq!(report.counters().workers_registered(), 1);
        assert_eq!(report.counters().worker_completions(), 1);
        assert_eq!(report.counters().peer_rejections(), 0);
        assert!(!socket_path(&root).exists());

        fs::remove_dir_all(root).expect("temporary client-shutdown root removes");
    }
}
