//! Single scoped OS-thread spawn adapter for one finite authenticated session worker.
//!
//! Phase 078 creates exactly one scoped native worker from already-authenticated
//! session state and an already-acquired Phase 075 permit. Phase 090 adds an
//! optional runtime-specific spawn path whose wrapper emits a non-panicking
//! Phase 089 completion wake after worker-owned state has returned or unwound.
//! Neither path accepts connections, schedules multiple workers, or activates
//! the Agent bootstrap.

use std::os::unix::net::UnixStream;
use std::thread::{Builder, Scope, ScopedJoinHandle};

use prw_policy::PolicyEvaluator;

use super::authenticated_session::AuthenticatedLocalLinuxSession;
use super::runtime_wake::LocalLinuxRuntimeWakeNotifier;
use super::session_worker::{
    LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerError, LocalLinuxSessionWorkerStop,
    run_authenticated_session_worker,
    run_authenticated_session_worker_with_agent_status_management,
};
use super::worker_capacity::LocalLinuxWorkerPermit;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

/// Result returned by one scoped finite session worker.
pub type LocalLinuxScopedWorkerResult =
    Result<LocalLinuxSessionWorkerStop, LocalLinuxSessionWorkerError>;

/// Bounded failure while creating one scoped session-worker OS thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxScopedWorkerSpawnError {
    /// The operating system rejected the scoped thread-creation request.
    SpawnFailed,
}

/// Runtime-specific Phase 090 worker configuration with completion wake authority.
#[derive(Debug, Clone)]
pub struct LocalLinuxCompletionWakeWorkerConfig {
    worker_config: LocalLinuxSessionWorkerConfig,
    completion_wake: LocalLinuxRuntimeWakeNotifier,
}

impl LocalLinuxCompletionWakeWorkerConfig {
    /// Couples one existing finite worker configuration to one Phase 089 notifier.
    #[must_use]
    pub const fn new(
        worker_config: LocalLinuxSessionWorkerConfig,
        completion_wake: LocalLinuxRuntimeWakeNotifier,
    ) -> Self {
        Self {
            worker_config,
            completion_wake,
        }
    }
}

#[derive(Debug)]
struct LocalLinuxWorkerCompletionWakeGuard {
    notifier: LocalLinuxRuntimeWakeNotifier,
}

impl Drop for LocalLinuxWorkerCompletionWakeGuard {
    fn drop(&mut self) {
        let _ = self.notifier.notify();
    }
}

/// Spawns exactly one scoped OS thread for an already-accounted authenticated session.
///
/// The authenticated session and worker permit move into the spawned closure.
/// On a successful spawn, the returned scoped join handle remains the caller's
/// explicit authority to observe the worker result. The enclosing Rust thread
/// scope provides the structural no-detach lifetime boundary from Phase 077.
///
/// If OS thread creation fails, the moved closure inputs are dropped by the
/// failed spawn operation: the authenticated stream closes and the Phase 075
/// permit releases its slot rather than leaving a half-registered worker.
///
/// # Errors
///
/// Returns [`LocalLinuxScopedWorkerSpawnError::SpawnFailed`] when
/// [`Builder::spawn_scoped`] cannot create the native thread.
pub fn spawn_authenticated_session_worker<'scope, E>(
    scope: &'scope Scope<'scope, '_>,
    session: AuthenticatedLocalLinuxSession<UnixStream>,
    permit: LocalLinuxWorkerPermit,
    evaluator: &'scope E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'scope LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<ScopedJoinHandle<'scope, LocalLinuxScopedWorkerResult>, LocalLinuxScopedWorkerSpawnError>
where
    E: PolicyEvaluator + Sync + ?Sized,
{
    Builder::new()
        .spawn_scoped(scope, move || {
            run_authenticated_session_worker(
                session,
                permit,
                evaluator,
                status_snapshot,
                private_dns_snapshot,
                config,
            )
        })
        .map_err(|_| LocalLinuxScopedWorkerSpawnError::SpawnFailed)
}

/// Spawns one scoped worker whose wrapper emits a Phase 089 completion wake.
///
/// The completion guard lives in the wrapper frame outside
/// [`run_authenticated_session_worker`]. On normal return, worker-owned state,
/// including the Phase 075 permit, has already been released before the guard
/// posts the wake. During panic unwinding, callee-owned state unwinds before the
/// wrapper guard is dropped, preserving the same release-before-wake ordering.
///
/// Wake notification failure is deliberately non-panicking during wrapper drop.
/// Worker result/panic classification remains owned by the existing Phase 079
/// join boundary rather than being encoded in the wake counter.
///
/// # Errors
///
/// Returns [`LocalLinuxScopedWorkerSpawnError::SpawnFailed`] when
/// [`Builder::spawn_scoped`] cannot create the native thread. A failed spawn does
/// not emit a completion wake because no worker began execution.
pub fn spawn_authenticated_session_worker_with_completion_wake<'scope, E>(
    scope: &'scope Scope<'scope, '_>,
    session: AuthenticatedLocalLinuxSession<UnixStream>,
    permit: LocalLinuxWorkerPermit,
    evaluator: &'scope E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'scope LocalPrivateDnsSnapshot,
    config: LocalLinuxCompletionWakeWorkerConfig,
) -> Result<ScopedJoinHandle<'scope, LocalLinuxScopedWorkerResult>, LocalLinuxScopedWorkerSpawnError>
where
    E: PolicyEvaluator + Sync + ?Sized,
{
    Builder::new()
        .spawn_scoped(scope, move || {
            let _completion_wake_guard = LocalLinuxWorkerCompletionWakeGuard {
                notifier: config.completion_wake,
            };

            run_authenticated_session_worker(
                session,
                permit,
                evaluator,
                status_snapshot,
                private_dns_snapshot,
                config.worker_config,
            )
        })
        .map_err(|_| LocalLinuxScopedWorkerSpawnError::SpawnFailed)
}

/// Spawns one fixed AgentStatus-management worker with the existing completion wake.
///
/// This sibling adapter preserves the Phase 090 wrapper ordering and shared scoped
/// result type while selecting only the VU AgentStatus-management worker body.
/// No management policy or provider authority is accepted by this function.
///
/// # Errors
///
/// Returns `LocalLinuxScopedWorkerSpawnError::SpawnFailed` when the operating system
/// rejects native scoped-thread creation. Failed spawn does not emit a completion wake.
pub(super) fn spawn_authenticated_session_worker_with_agent_status_management_and_completion_wake<
    'scope,
    E,
>(
    scope: &'scope Scope<'scope, '_>,
    session: AuthenticatedLocalLinuxSession<UnixStream>,
    permit: LocalLinuxWorkerPermit,
    evaluator: &'scope E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'scope LocalPrivateDnsSnapshot,
    config: LocalLinuxCompletionWakeWorkerConfig,
) -> Result<ScopedJoinHandle<'scope, LocalLinuxScopedWorkerResult>, LocalLinuxScopedWorkerSpawnError>
where
    E: PolicyEvaluator + Sync + ?Sized,
{
    Builder::new()
        .spawn_scoped(scope, move || {
            let _completion_wake_guard = LocalLinuxWorkerCompletionWakeGuard {
                notifier: config.completion_wake,
            };

            run_authenticated_session_worker_with_agent_status_management(
                session,
                permit,
                evaluator,
                status_snapshot,
                private_dns_snapshot,
                config.worker_config,
            )
        })
        .map_err(|_| LocalLinuxScopedWorkerSpawnError::SpawnFailed)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use prw_network::PrivateDnsConfig;
    use prw_policy::{BoundedLocalReadPolicy, Capability, Decision, PolicyEvaluator};
    use prw_remote_bridge::BridgeCommand;

    use super::{
        LocalLinuxCompletionWakeWorkerConfig, spawn_authenticated_session_worker,
        spawn_authenticated_session_worker_with_agent_status_management_and_completion_wake,
        spawn_authenticated_session_worker_with_completion_wake,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::write_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::runtime_wake::LocalLinuxRuntimeWake;
    use crate::linux_identity::session_worker::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop,
    };
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::stream::write_local_command_request;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::local_commands::{LocalAgentCommand, LocalAgentResponseStatus};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn worker_config() -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("test Request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500))
                .expect("test read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500))
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

    struct BlockingPolicy {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        calls: AtomicUsize,
    }

    impl PolicyEvaluator for BlockingPolicy {
        fn evaluate(&self, _capability: Capability) -> Decision {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.wait();
            self.release.wait();
            Decision::Allow
        }
    }

    #[test]
    fn scoped_worker_holds_permit_until_worker_body_finishes_and_returns_result() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let policy = BlockingPolicy {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            calls: AtomicUsize::new(0),
        };
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();

        write_local_command_request(&mut client, id(500), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes before worker starts");

        thread::scope(|scope| {
            let handle = spawn_authenticated_session_worker(
                scope,
                session(server),
                permit,
                &policy,
                status,
                &dns,
                worker_config(),
            )
            .expect("scoped worker spawns");

            entered.wait();
            assert_eq!(capacity.active_workers(), 1);
            release.wait();

            assert_eq!(
                handle.join().expect("scoped worker does not panic"),
                Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                    responses_written: 1
                })
            );
        });

        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(policy.calls.load(Ordering::Acquire), 1);

        let response = read_frame(&mut client).expect("worker response reads");
        let response = decode_success_status_frame(&response).expect("status response decodes");
        assert_eq!(response.request_id(), id(500));

        let mut trailing = [0_u8; 1];
        assert_eq!(client.read(&mut trailing).expect("worker stream closes"), 0);
    }

    #[test]
    fn scoped_worker_can_borrow_policy_and_snapshot_from_scope_environment() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let policy = AlwaysAllow;
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        write_local_command_request(&mut client, id(501), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        thread::scope(|scope| {
            let permit = capacity.try_acquire().expect("worker slot acquires");
            let handle = spawn_authenticated_session_worker(
                scope,
                session(server),
                permit,
                &policy,
                status,
                &dns,
                worker_config(),
            )
            .expect("scoped worker spawns");

            assert!(matches!(
                handle.join().expect("worker does not panic"),
                Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted { .. })
            ));
        });

        assert_eq!(capacity.active_workers(), 0);
        let response = read_frame(&mut client).expect("response reads");
        assert_eq!(response.header().request_id(), id(501));
    }

    #[test]
    fn completion_wake_is_observable_after_normal_worker_releases_capacity() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let policy = AlwaysAllow;
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");

        write_local_command_request(&mut client, id(502), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        thread::scope(|scope| {
            let permit = capacity.try_acquire().expect("worker slot acquires");
            let config =
                LocalLinuxCompletionWakeWorkerConfig::new(worker_config(), wake.notifier());
            let handle = spawn_authenticated_session_worker_with_completion_wake(
                scope,
                session(server),
                permit,
                &policy,
                status,
                &dns,
                config,
            )
            .expect("completion-wake worker spawns");

            assert!(matches!(
                handle.join().expect("worker does not panic"),
                Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted { .. })
            ));
        });

        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(wake.drain(), Ok(()));

        let response = read_frame(&mut client).expect("response reads");
        assert_eq!(response.header().request_id(), id(502));
    }

    #[test]
    fn agent_status_management_completion_wake_releases_capacity_and_preserves_shared_result() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let policy = BoundedLocalReadPolicy::deny_all();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let bridge = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus command encodes");
        let frame = build_local_management_request_frame(id(504), &bridge)
            .expect("management frame builds");
        write_frame(&mut client, &frame).expect("management request writes");

        thread::scope(|scope| {
            let config =
                LocalLinuxCompletionWakeWorkerConfig::new(worker_config(), wake.notifier());
            let handle =
                spawn_authenticated_session_worker_with_agent_status_management_and_completion_wake(
                    scope,
                    session(server),
                    permit,
                    &policy,
                    status,
                    &dns,
                    config,
                )
                .expect("AgentStatus completion-wake worker spawns");

            assert_eq!(
                handle.join().expect("worker does not panic"),
                Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                    responses_written: 1
                })
            );
        });

        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(wake.drain(), Ok(()));

        let response = read_frame(&mut client).expect("management response reads");
        let terminal =
            validate_terminal_response_frame(&response).expect("management response validates");
        assert_eq!(terminal.request_id(), id(504));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
    }

    #[test]
    fn completion_wake_survives_policy_panic_after_permit_unwinds() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let policy = PanicPolicy;
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");

        write_local_command_request(&mut client, id(503), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        thread::scope(|scope| {
            let permit = capacity.try_acquire().expect("worker slot acquires");
            let config =
                LocalLinuxCompletionWakeWorkerConfig::new(worker_config(), wake.notifier());
            let handle = spawn_authenticated_session_worker_with_completion_wake(
                scope,
                session(server),
                permit,
                &policy,
                status,
                &dns,
                config,
            )
            .expect("completion-wake worker spawns");

            assert!(handle.join().is_err());
        });

        assert_eq!(capacity.active_workers(), 0);
        assert_eq!(wake.drain(), Ok(()));
    }

    struct AlwaysAllow;

    impl PolicyEvaluator for AlwaysAllow {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Allow
        }
    }

    struct PanicPolicy;

    impl PolicyEvaluator for PanicPolicy {
        fn evaluate(&self, _capability: Capability) -> Decision {
            panic!("planned Phase 090 policy panic")
        }
    }
}
