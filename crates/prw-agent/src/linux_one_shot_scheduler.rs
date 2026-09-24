//! One-shot capacity-gated authenticated session scheduling transaction.
//!
//! Phase 084 performs at most one accept attempt and can spawn at most one
//! worker. It is not an accept loop and is not wired into the Agent bootstrap.

use std::thread::Scope;

use prw_policy::BoundedLocalReadPolicy;

use super::accept_ready::{
    AcceptReadyAgentSocket, AuthenticatedAgentAcceptError, AuthenticatedAgentAcceptOutcome,
};
use super::authenticated_session_bridge::{
    AuthenticatedAgentSessionOutcome, compose_authenticated_session,
};
use super::session_worker::LocalLinuxSessionWorkerConfig;
use super::session_worker_thread::{
    LocalLinuxScopedWorkerSpawnError, spawn_authenticated_session_worker,
};
use super::worker_cancellation::{
    LocalLinuxWorkerCancellation, LocalLinuxWorkerCancellationCreateError,
};
use super::worker_capacity::{LocalLinuxWorkerCapacity, LocalLinuxWorkerCapacityError};
use super::worker_registry::LocalLinuxScopedWorkerRegistry;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

/// Borrowed bounded context for one Phase 084 scheduling attempt.
#[derive(Debug, Clone, Copy)]
pub struct LocalLinuxOneShotSchedulerContext<'a> {
    capacity: &'a LocalLinuxWorkerCapacity,
    policy: &'a BoundedLocalReadPolicy,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
    worker_config: LocalLinuxSessionWorkerConfig,
}

impl<'a> LocalLinuxOneShotSchedulerContext<'a> {
    /// Creates one scheduler context from already-validated bounded components.
    #[must_use]
    pub const fn new(
        capacity: &'a LocalLinuxWorkerCapacity,
        policy: &'a BoundedLocalReadPolicy,
        status_snapshot: LocalAgentStatusSnapshot,
        private_dns_snapshot: &'a LocalPrivateDnsSnapshot,
        worker_config: LocalLinuxSessionWorkerConfig,
    ) -> Self {
        Self {
            capacity,
            policy,
            status_snapshot,
            private_dns_snapshot,
            worker_config,
        }
    }
}

/// Successful result of one capacity-gated scheduling attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxOneShotScheduleOutcome {
    /// No worker slot was available; no accept operation was attempted.
    AtCapacity,
    /// A worker slot was acquired but no connection was queued; the slot was released.
    NoConnectionReady,
    /// One authenticated connection was cancellation-registered and spawned.
    WorkerRegistered,
}

/// Bounded failure from one Phase 084 scheduling transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxOneShotScheduleError {
    /// The one-shot authenticated accept failed.
    Accept(AuthenticatedAgentAcceptError),
    /// The authenticated stream could not be cloned for shutdown authority.
    CancellationClone(LocalLinuxWorkerCancellationCreateError),
    /// The scoped OS worker could not be created.
    Spawn(LocalLinuxScopedWorkerSpawnError),
}

/// Performs at most one capacity-gated accept/authenticate/spawn/register transaction.
///
/// Ordering is fail-closed:
///
/// 1. acquire one Phase 075 worker permit;
/// 2. if at capacity, return without touching the listener;
/// 3. perform exactly one Phase 070 authenticated accept attempt;
/// 4. on no-ready, release the permit and return;
/// 5. clone Phase 082 cancellation authority from the authenticated connection;
/// 6. consume the Phase 070 outcome through the Phase 071 session bridge;
/// 7. spawn exactly one Phase 078 scoped worker using only the Phase 083 bounded
///    in-memory local read policy;
/// 8. register the handle together with its matching cancellation authority.
///
/// # Errors
///
/// Returns a bounded error for accept, cancellation-clone, or scoped-spawn
/// failure. Every pre-registration failure drops/releases owned connection and
/// capacity state rather than leaving a half-registered worker.
pub fn schedule_one_authenticated_worker<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &AcceptReadyAgentSocket<'_>,
    registry: &mut LocalLinuxScopedWorkerRegistry<'scope>,
    context: LocalLinuxOneShotSchedulerContext<'scope>,
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

    let handle = spawn_authenticated_session_worker(
        scope,
        session,
        permit,
        context.policy,
        context.status_snapshot,
        context.private_dns_snapshot,
        context.worker_config,
    )
    .map_err(LocalLinuxOneShotScheduleError::Spawn)?;

    registry.register(handle, cancellation);
    Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
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
        LocalLinuxOneShotScheduleOutcome, LocalLinuxOneShotSchedulerContext,
        schedule_one_authenticated_worker,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::linux_identity::accept_ready::{
        AcceptReadyAgentSocket, prepare_accept_ready_agent_socket,
    };
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::listening_socket::listen_bound_agent_socket;
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
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-084-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 084 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 084 directory mode sets");
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
    fn at_capacity_does_not_consume_queued_connection() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("capacity");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let mut client = UnixStream::connect(&socket_path).expect("client queues");
        write_local_command_request(&mut client, id(600), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let held = capacity.try_acquire().expect("capacity held");
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

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
                Ok(LocalLinuxOneShotScheduleOutcome::AtCapacity)
            );
            assert!(registry.is_empty());

            drop(held);
            assert_eq!(
                schedule_one_authenticated_worker(scope, &listener, &mut registry, context),
                Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
            );
            assert_eq!(registry.len(), 1);

            let completions = registry.join_all();
            assert_eq!(
                completions,
                vec![LocalLinuxScopedWorkerCompletion::Stopped(
                    LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                        responses_written: 1
                    }
                )]
            );
        });

        let response = read_frame(&mut client).expect("queued Request response reads");
        let response = decode_success_status_frame(&response).expect("status response decodes");
        assert_eq!(response.request_id(), id(600));
        assert_eq!(capacity.active_workers(), 0);

        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn no_ready_releases_capacity_without_registry_entry() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("no-ready");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::deny_all();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

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
                Ok(LocalLinuxOneShotScheduleOutcome::NoConnectionReady)
            );
            assert!(registry.is_empty());
            assert_eq!(capacity.active_workers(), 0);
        });

        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }

    #[test]
    fn successful_schedule_registers_cancellable_scoped_worker() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("success");
        let listener = accept_ready(&runtime_directory, &instance_lock);
        let socket_path = socket_path(&root_path);
        let _client = UnixStream::connect(&socket_path).expect("idle client queues");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity non-zero"));
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let dns = dns_snapshot();
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

        thread::scope(|scope| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let context = LocalLinuxOneShotSchedulerContext::new(
                &capacity,
                &policy,
                status,
                &dns,
                LocalLinuxSessionWorkerConfig::new(
                    NonZeroUsize::new(1).expect("Request budget non-zero"),
                    LocalLinuxIoBudget::try_new(Duration::from_secs(5))
                        .expect("read budget non-zero"),
                    LocalLinuxIoBudget::try_new(Duration::from_millis(500))
                        .expect("write budget non-zero"),
                ),
            );

            assert_eq!(
                schedule_one_authenticated_worker(scope, &listener, &mut registry, context),
                Ok(LocalLinuxOneShotScheduleOutcome::WorkerRegistered)
            );
            assert_eq!(registry.len(), 1);
            assert_eq!(capacity.active_workers(), 1);

            assert_eq!(registry.cancel_all().len(), 1);
            assert_eq!(registry.join_all().len(), 1);
        });

        assert_eq!(capacity.active_workers(), 0);
        listener.cleanup().expect("listener cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(root_path).expect("temporary root removes");
    }
}
