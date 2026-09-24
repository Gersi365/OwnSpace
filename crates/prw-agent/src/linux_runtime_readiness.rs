//! One-step capacity-aware Linux runtime readiness wait.
//!
//! Phase 091 performs at most one blocking `poll` call. The Phase 089 runtime
//! wake is always armed; the Phase 070 accept-ready listener is armed only while
//! Phase 075 worker capacity is available. Runtime wake is processed before any
//! simultaneous listener readiness. This module contains no outer readiness loop
//! and does not activate the Agent bootstrap.

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;

use super::accept_ready::AcceptReadyAgentSocket;
use super::bounded_scheduler_cycle::LocalLinuxSchedulerControl;
use super::runtime_wake::{LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeDrainError};
use super::worker_capacity::LocalLinuxWorkerCapacity;
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::LocalLinuxScopedWorkerRegistry;

/// Successful terminal outcome of one Phase 091 wait invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeReadinessOutcome {
    /// Shutdown was observed before blocking or after wake processing.
    ShutdownObserved,
    /// Runtime wake was drained and no listener dispatch is currently eligible.
    RuntimeWake,
    /// Listener readiness may be dispatched to the finite scheduling layer.
    ListenerReady,
    /// `poll` was interrupted; the caller must re-observe runtime state.
    WaitInterrupted,
}

/// Evidence returned from one successful Phase 091 invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxRuntimeReadinessReport {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    outcome: LocalLinuxRuntimeReadinessOutcome,
}

impl LocalLinuxRuntimeReadinessReport {
    /// Returns worker completions reaped while processing runtime wake.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns whether listener readiness was included in this wait set.
    #[must_use]
    pub const fn listener_armed(&self) -> bool {
        self.listener_armed
    }

    /// Returns the terminal outcome of this finite wait invocation.
    #[must_use]
    pub const fn outcome(&self) -> LocalLinuxRuntimeReadinessOutcome {
        self.outcome
    }
}

/// Bounded Phase 091 readiness failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeReadinessError {
    /// `poll` failed for an errno other than `EINTR`.
    WaitFailed,
    /// Blocking `poll` returned an impossible/contradictory ready-count state.
    InvalidWaitReturn,
    /// Runtime-wake descriptor reported an error condition.
    WakeDescriptorFailed,
    /// Listener descriptor reported an error condition.
    ListenerDescriptorFailed,
    /// Runtime-wake descriptor returned unsupported readiness flags.
    InvalidWakeReadiness,
    /// Listener descriptor returned unsupported readiness flags.
    InvalidListenerReadiness,
    /// Runtime wake was reported readable but could not be drained validly.
    WakeDrain(LocalLinuxRuntimeWakeDrainError),
    /// Listener readiness became ineligible before dispatch without wake handling.
    ListenerCapacityInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxPollCall {
    Ready(usize),
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxPollDescriptor {
    Wake,
    Listener,
}

/// Performs exactly one capacity-aware blocking readiness wait.
///
/// Ordering is fail-closed:
///
/// 1. observe terminal shutdown before blocking;
/// 2. always arm runtime wake;
/// 3. arm listener only when `active_workers() < max_workers()`;
/// 4. perform at most one blocking `poll(..., None)` call;
/// 5. validate every returned descriptor readiness state;
/// 6. if wake is readable, drain it before any listener dispatch, reap finished
///    registered workers, then re-observe shutdown and capacity;
/// 7. dispatch listener readiness only while shutdown is false and capacity is
///    still available.
///
/// `poll` `EINTR` is returned as [`LocalLinuxRuntimeReadinessOutcome::WaitInterrupted`]
/// rather than retried internally.
///
/// # Errors
///
/// Returns a bounded error for poll failure, contradictory ready counts,
/// descriptor error/unsupported readiness, invalid wake drain, or a capacity
/// invariant violation.
pub fn wait_once_for_linux_runtime_readiness(
    listener: &AcceptReadyAgentSocket<'_>,
    wake: &LocalLinuxRuntimeWake,
    capacity: &LocalLinuxWorkerCapacity,
    registry: &mut LocalLinuxScopedWorkerRegistry<'_>,
    control: &LocalLinuxSchedulerControl,
) -> Result<LocalLinuxRuntimeReadinessReport, LocalLinuxRuntimeReadinessError> {
    if control.is_shutdown_requested() {
        return Ok(report(
            Vec::new(),
            false,
            LocalLinuxRuntimeReadinessOutcome::ShutdownObserved,
        ));
    }

    let listener_armed = capacity.active_workers() < capacity.max_workers();
    let mut descriptors = vec![PollFd::new(wake, PollFlags::IN)];
    if listener_armed {
        descriptors.push(PollFd::new(listener, PollFlags::IN));
    }

    let poll_call = classify_poll_call(poll(&mut descriptors, None), descriptors.len())?;
    if poll_call == LocalLinuxPollCall::Interrupted {
        return Ok(report(
            Vec::new(),
            listener_armed,
            LocalLinuxRuntimeReadinessOutcome::WaitInterrupted,
        ));
    }

    let LocalLinuxPollCall::Ready(ready_count) = poll_call else {
        unreachable!("interrupted poll returned above");
    };

    let wake_revents = descriptors[0].revents();
    let listener_revents = if listener_armed {
        descriptors[1].revents()
    } else {
        PollFlags::empty()
    };

    validate_ready_count(ready_count, wake_revents, listener_revents, listener_armed)?;
    let wake_ready = classify_descriptor_revents(wake_revents, LocalLinuxPollDescriptor::Wake)?;
    let listener_ready = if listener_armed {
        classify_descriptor_revents(listener_revents, LocalLinuxPollDescriptor::Listener)?
    } else {
        false
    };

    if wake_ready {
        wake.drain()
            .map_err(LocalLinuxRuntimeReadinessError::WakeDrain)?;
        let completions = registry.reap_finished();

        if control.is_shutdown_requested() {
            return Ok(report(
                completions,
                listener_armed,
                LocalLinuxRuntimeReadinessOutcome::ShutdownObserved,
            ));
        }

        if listener_ready && capacity.active_workers() < capacity.max_workers() {
            return Ok(report(
                completions,
                listener_armed,
                LocalLinuxRuntimeReadinessOutcome::ListenerReady,
            ));
        }

        return Ok(report(
            completions,
            listener_armed,
            LocalLinuxRuntimeReadinessOutcome::RuntimeWake,
        ));
    }

    if listener_ready {
        if control.is_shutdown_requested() {
            return Ok(report(
                Vec::new(),
                listener_armed,
                LocalLinuxRuntimeReadinessOutcome::ShutdownObserved,
            ));
        }
        if capacity.active_workers() >= capacity.max_workers() {
            return Err(LocalLinuxRuntimeReadinessError::ListenerCapacityInvariant);
        }
        return Ok(report(
            Vec::new(),
            listener_armed,
            LocalLinuxRuntimeReadinessOutcome::ListenerReady,
        ));
    }

    Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn)
}

const fn report(
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    outcome: LocalLinuxRuntimeReadinessOutcome,
) -> LocalLinuxRuntimeReadinessReport {
    LocalLinuxRuntimeReadinessReport {
        completions,
        listener_armed,
        outcome,
    }
}

fn classify_poll_call(
    result: Result<usize, Errno>,
    descriptor_count: usize,
) -> Result<LocalLinuxPollCall, LocalLinuxRuntimeReadinessError> {
    match result {
        Ok(0) => Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn),
        Ok(count) if count > descriptor_count => {
            Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn)
        }
        Ok(count) => Ok(LocalLinuxPollCall::Ready(count)),
        Err(error) if error == Errno::INTR => Ok(LocalLinuxPollCall::Interrupted),
        Err(_) => Err(LocalLinuxRuntimeReadinessError::WaitFailed),
    }
}

fn validate_ready_count(
    ready_count: usize,
    wake_revents: PollFlags,
    listener_revents: PollFlags,
    listener_armed: bool,
) -> Result<(), LocalLinuxRuntimeReadinessError> {
    let observed = usize::from(!wake_revents.is_empty())
        + usize::from(listener_armed && !listener_revents.is_empty());
    if observed != ready_count {
        return Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn);
    }
    Ok(())
}

fn classify_descriptor_revents(
    revents: PollFlags,
    descriptor: LocalLinuxPollDescriptor,
) -> Result<bool, LocalLinuxRuntimeReadinessError> {
    let errors = PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL;
    if revents.intersects(errors) {
        return Err(match descriptor {
            LocalLinuxPollDescriptor::Wake => LocalLinuxRuntimeReadinessError::WakeDescriptorFailed,
            LocalLinuxPollDescriptor::Listener => {
                LocalLinuxRuntimeReadinessError::ListenerDescriptorFailed
            }
        });
    }

    if !revents.difference(PollFlags::IN).is_empty() {
        return Err(match descriptor {
            LocalLinuxPollDescriptor::Wake => LocalLinuxRuntimeReadinessError::InvalidWakeReadiness,
            LocalLinuxPollDescriptor::Listener => {
                LocalLinuxRuntimeReadinessError::InvalidListenerReadiness
            }
        });
    }

    Ok(revents.contains(PollFlags::IN))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread::{self, Builder};

    use rustix::event::PollFlags;
    use rustix::io::Errno;

    use super::{
        LocalLinuxPollCall, LocalLinuxPollDescriptor, LocalLinuxRuntimeReadinessError,
        LocalLinuxRuntimeReadinessOutcome, classify_descriptor_revents, classify_poll_call,
        wait_once_for_linux_runtime_readiness,
    };
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::bounded_scheduler_cycle::LocalLinuxSchedulerControl;
    use crate::linux_identity::listening_socket::listen_bound_agent_socket;
    use crate::linux_identity::runtime_wake::{
        LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeDrainError,
    };
    use crate::linux_identity::session_worker::LocalLinuxSessionWorkerStop;
    use crate::linux_identity::session_worker_thread::LocalLinuxScopedWorkerResult;
    use crate::linux_identity::worker_cancellation::LocalLinuxWorkerCancellation;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::linux_identity::worker_completion::LocalLinuxScopedWorkerCompletion;
    use crate::linux_identity::worker_registry::LocalLinuxScopedWorkerRegistry;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLock, acquire_agent_instance_lock,
    };
    use crate::linux_identity::{
        accept_ready::prepare_accept_ready_agent_socket, xdg_runtime_root,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-091-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 091 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 091 directory mode sets");
    }

    fn runtime_owners(label: &str) -> (PathBuf, ValidatedPrwRuntimeDirectory, AgentInstanceLock) {
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
        (root_path, runtime_directory, instance_lock)
    }

    fn agent_socket_path(root_path: &Path) -> PathBuf {
        root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    fn capacity(value: usize) -> LocalLinuxWorkerCapacity {
        LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(value).expect("test worker capacity is non-zero"),
        )
    }

    fn cleanup_runtime(
        listener: crate::linux_identity::accept_ready::AcceptReadyAgentSocket<'_>,
        root_path: &Path,
    ) {
        listener.cleanup().expect("listener cleanup succeeds");
        fs::remove_dir_all(root_path).expect("temporary Phase 091 root removes");
    }

    #[test]
    fn shutdown_before_wait_returns_without_blocking_or_arming_listener() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("shutdown");
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(4).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        let listener = prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 listener becomes accept-ready");
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let workers = capacity(1);
        let control = LocalLinuxSchedulerControl::new();
        control.request_shutdown();

        thread::scope(|_| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("shutdown is a normal finite outcome");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::ShutdownObserved
            );
            assert!(!report.listener_armed());
            assert!(report.completions().is_empty());
        });

        cleanup_runtime(listener, &root_path);
    }

    #[test]
    fn queued_client_is_listener_ready_when_capacity_is_available() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("listener-ready");
        let socket_path = agent_socket_path(&root_path);
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(4).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        let listener = prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 listener becomes accept-ready");
        let client = UnixStream::connect(&socket_path).expect("test client queues");
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let workers = capacity(1);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|_| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("listener readiness is observed");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::ListenerReady
            );
            assert!(report.listener_armed());
            assert!(report.completions().is_empty());
        });

        drop(client);
        cleanup_runtime(listener, &root_path);
    }

    #[test]
    fn full_capacity_omits_queued_listener_until_runtime_wake_and_release() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("at-capacity");
        let socket_path = agent_socket_path(&root_path);
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(4).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        let listener = prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 listener becomes accept-ready");
        let client = UnixStream::connect(&socket_path).expect("queued test client connects");
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let workers = capacity(1);
        let permit = workers
            .try_acquire()
            .expect("sole capacity permit acquires");
        let control = LocalLinuxSchedulerControl::new();
        wake.notifier()
            .notify()
            .expect("controlled runtime wake posts");

        thread::scope(|_| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("wake-only wait succeeds while capacity is full");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::RuntimeWake
            );
            assert!(!report.listener_armed());
        });

        drop(permit);

        thread::scope(|_| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("listener becomes eligible after capacity release");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::ListenerReady
            );
            assert!(report.listener_armed());
        });

        drop(client);
        cleanup_runtime(listener, &root_path);
    }

    #[test]
    fn simultaneous_wake_and_listener_readiness_drains_wake_before_listener_outcome() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("both-ready");
        let socket_path = agent_socket_path(&root_path);
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(4).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        let listener = prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 listener becomes accept-ready");
        let client = UnixStream::connect(&socket_path).expect("queued test client connects");
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        wake.notifier()
            .notify()
            .expect("controlled runtime wake posts");
        let workers = capacity(1);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|_| {
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("simultaneous readiness is valid");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::ListenerReady
            );
            assert_eq!(
                wake.drain(),
                Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
            );
        });

        drop(client);
        cleanup_runtime(listener, &root_path);
    }

    #[test]
    fn runtime_wake_reaps_already_finished_registered_worker() {
        let (root_path, runtime_directory, instance_lock) = runtime_owners("reap");
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(4).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        let listener = prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 listener becomes accept-ready");
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 wake creates");
        let workers = capacity(1);
        let control = LocalLinuxSchedulerControl::new();

        thread::scope(|scope| {
            let handle = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    Ok(LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 9,
                    })
                })
                .expect("finished worker spawns");
            while !handle.is_finished() {
                thread::yield_now();
            }

            let (server, _peer) = UnixStream::pair().expect("cancellation socket pair creates");
            let connection = AuthenticatedLocalLinuxConnection::try_new(server)
                .expect("same-UID cancellation stream authenticates");
            let cancellation =
                LocalLinuxWorkerCancellation::try_from_authenticated_connection(&connection)
                    .expect("cancellation clone creates");
            drop(connection);

            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            registry.register(handle, cancellation);
            wake.notifier()
                .notify()
                .expect("controlled completion-style wake posts");

            let report = wait_once_for_linux_runtime_readiness(
                &listener,
                &wake,
                &workers,
                &mut registry,
                &control,
            )
            .expect("runtime wake reaps finished handle");

            assert_eq!(
                report.outcome(),
                LocalLinuxRuntimeReadinessOutcome::RuntimeWake
            );
            assert_eq!(
                report.completions(),
                &[LocalLinuxScopedWorkerCompletion::Stopped(
                    LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 9,
                    }
                )]
            );
            assert!(registry.is_empty());
        });

        cleanup_runtime(listener, &root_path);
    }

    #[test]
    fn poll_result_classifier_surfaces_interrupt_without_retry() {
        assert_eq!(
            classify_poll_call(Err(Errno::INTR), 2),
            Ok(LocalLinuxPollCall::Interrupted)
        );
        assert_eq!(
            classify_poll_call(Err(Errno::IO), 2),
            Err(LocalLinuxRuntimeReadinessError::WaitFailed)
        );
        assert_eq!(
            classify_poll_call(Ok(0), 2),
            Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn)
        );
        assert_eq!(
            classify_poll_call(Ok(3), 2),
            Err(LocalLinuxRuntimeReadinessError::InvalidWaitReturn)
        );
    }

    #[test]
    fn descriptor_classifier_fails_closed_on_error_and_unexpected_flags() {
        assert_eq!(
            classify_descriptor_revents(PollFlags::ERR, LocalLinuxPollDescriptor::Wake),
            Err(LocalLinuxRuntimeReadinessError::WakeDescriptorFailed)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::HUP, LocalLinuxPollDescriptor::Listener),
            Err(LocalLinuxRuntimeReadinessError::ListenerDescriptorFailed)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::OUT, LocalLinuxPollDescriptor::Wake),
            Err(LocalLinuxRuntimeReadinessError::InvalidWakeReadiness)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::IN, LocalLinuxPollDescriptor::Listener),
            Ok(true)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::empty(), LocalLinuxPollDescriptor::Wake),
            Ok(false)
        );
    }
}
