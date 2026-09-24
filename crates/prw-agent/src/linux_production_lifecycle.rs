//! Production-local Linux lifecycle resource assembly and rollback boundary.
//!
//! Phase 096 composes the already-validated XDG root, PRW runtime directory,
//! single-instance lock, Unix listener, accept-ready transition, runtime wake,
//! worker capacity, and scheduler control beneath one callable boundary. It does
//! not run a readiness loop, process OS signals, wire `main.rs`, or activate a
//! service manager.

use super::accept_ready::{
    AcceptReadyAgentSocket, AcceptReadyAgentSocketError, prepare_accept_ready_agent_socket,
};
use super::bound_socket::{
    BoundAgentSocketCleanupError, BoundAgentSocketError, bind_validated_agent_socket,
};
use super::bounded_scheduler_cycle::LocalLinuxSchedulerControl;
use super::listening_socket::{ListeningAgentSocketError, listen_bound_agent_socket};
use super::production_runtime_types::{
    LocalLinuxProductionRuntimeCleanup, LocalLinuxProductionRuntimeConfig,
};
use super::runtime_wake::{LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeCreateError};
use super::worker_capacity::LocalLinuxWorkerCapacity;
use super::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
    AgentInstanceLockError, acquire_agent_instance_lock,
};
use super::xdg_runtime_root::prw_runtime_directory::{
    PrwRuntimeDirectoryPreparationError, prepare_prw_runtime_directory,
};
use super::xdg_runtime_root::{
    ValidatedXdgRuntimeRoot, XdgRuntimeRootValidationError, validate_xdg_runtime_root_from_env,
};

/// Failure while assembling the production-local lifecycle boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxProductionLifecycleAssemblyError {
    /// `$XDG_RUNTIME_DIR` failed the existing descriptor-anchored validation.
    RuntimeRoot(XdgRuntimeRootValidationError),
    /// The fixed PRW runtime child could not be safely prepared.
    RuntimeDirectory(PrwRuntimeDirectoryPreparationError),
    /// The exclusive same-user Agent instance lock could not be acquired.
    InstanceLock(AgentInstanceLockError),
    /// The validated filesystem-backed Agent socket could not be bound.
    Bind(BoundAgentSocketError),
    /// The bound socket could not enter listening state; rollback evidence is preserved.
    Listen {
        /// Existing Phase 068 transition failure.
        error: ListeningAgentSocketError,
        /// Explicit rollback result for the already-bound socket path.
        cleanup: LocalLinuxProductionRuntimeCleanup,
    },
    /// The listener could not enter verified nonblocking accept-ready state.
    AcceptReady {
        /// Existing Phase 070 transition failure.
        error: AcceptReadyAgentSocketError,
        /// Explicit listener/socket rollback result.
        cleanup: LocalLinuxProductionRuntimeCleanup,
    },
    /// The shared runtime wake descriptor could not be created after listener setup.
    RuntimeWake {
        /// Existing Phase 089 eventfd creation failure.
        error: LocalLinuxRuntimeWakeCreateError,
        /// Explicit listener/socket rollback result.
        cleanup: LocalLinuxProductionRuntimeCleanup,
    },
}

/// Successful callback result plus explicit listener/socket cleanup evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxProductionLifecycleExecution<R> {
    value: R,
    cleanup: LocalLinuxProductionRuntimeCleanup,
}

impl<R> LocalLinuxProductionLifecycleExecution<R> {
    /// Returns the callback result produced while all lifecycle resources were live.
    #[must_use]
    pub fn into_value(self) -> R {
        self.value
    }

    /// Returns the explicit listener/socket cleanup result.
    #[must_use]
    pub const fn cleanup(&self) -> LocalLinuxProductionRuntimeCleanup {
        self.cleanup
    }
}

struct LocalLinuxListenerCleanupGuard<'owners> {
    listener: Option<AcceptReadyAgentSocket<'owners>>,
}

impl<'owners> LocalLinuxListenerCleanupGuard<'owners> {
    const fn new(listener: AcceptReadyAgentSocket<'owners>) -> Self {
        Self {
            listener: Some(listener),
        }
    }

    const fn listener(&self) -> &AcceptReadyAgentSocket<'owners> {
        self.listener
            .as_ref()
            .expect("Phase 096 listener guard remains armed during callback")
    }

    fn finish(mut self) -> LocalLinuxProductionRuntimeCleanup {
        let listener = self
            .listener
            .take()
            .expect("Phase 096 listener guard finishes exactly once");
        cleanup_result(listener.cleanup())
    }
}

impl Drop for LocalLinuxListenerCleanupGuard<'_> {
    fn drop(&mut self) {
        if let Some(listener) = self.listener.take() {
            let _ = listener.cleanup();
        }
    }
}

const fn cleanup_result(
    result: Result<(), BoundAgentSocketCleanupError>,
) -> LocalLinuxProductionRuntimeCleanup {
    match result {
        Ok(()) => LocalLinuxProductionRuntimeCleanup::Clean,
        Err(error) => LocalLinuxProductionRuntimeCleanup::Failed(error),
    }
}

/// Assembles the callable production-local lifecycle from process environment.
///
/// The callback executes while the instance lock, listener, runtime wake,
/// capacity accounting, and scheduler control are all live. On normal return,
/// listener/socket cleanup is explicit and reported. On panic unwind, a private
/// guard performs best-effort listener/socket cleanup before ownership unwinds.
///
/// # Errors
///
/// Returns a typed assembly failure for the first failed lifecycle stage. When a
/// failure occurs after bind, explicit listener/socket rollback evidence is
/// retained alongside the original stage error.
pub fn with_local_linux_production_lifecycle_from_env<R, F>(
    config: LocalLinuxProductionRuntimeConfig,
    operation: F,
) -> Result<LocalLinuxProductionLifecycleExecution<R>, LocalLinuxProductionLifecycleAssemblyError>
where
    F: FnOnce(
        &AcceptReadyAgentSocket<'_>,
        &LocalLinuxRuntimeWake,
        &LocalLinuxWorkerCapacity,
        &LocalLinuxSchedulerControl,
    ) -> R,
{
    let root = validate_xdg_runtime_root_from_env()
        .map_err(LocalLinuxProductionLifecycleAssemblyError::RuntimeRoot)?;
    with_validated_root(&root, config, operation)
}

fn with_validated_root<R, F>(
    root: &ValidatedXdgRuntimeRoot,
    config: LocalLinuxProductionRuntimeConfig,
    operation: F,
) -> Result<LocalLinuxProductionLifecycleExecution<R>, LocalLinuxProductionLifecycleAssemblyError>
where
    F: FnOnce(
        &AcceptReadyAgentSocket<'_>,
        &LocalLinuxRuntimeWake,
        &LocalLinuxWorkerCapacity,
        &LocalLinuxSchedulerControl,
    ) -> R,
{
    let runtime_directory = prepare_prw_runtime_directory(root)
        .map_err(LocalLinuxProductionLifecycleAssemblyError::RuntimeDirectory)?;
    let instance_lock = acquire_agent_instance_lock(&runtime_directory)
        .map_err(LocalLinuxProductionLifecycleAssemblyError::InstanceLock)?;
    let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
        .map_err(LocalLinuxProductionLifecycleAssemblyError::Bind)?;

    let listening = match listen_bound_agent_socket(bound, config.listener_backlog()) {
        Ok(listening) => listening,
        Err(failure) => {
            let (bound, error) = failure.into_parts();
            return Err(LocalLinuxProductionLifecycleAssemblyError::Listen {
                error,
                cleanup: cleanup_result(bound.cleanup()),
            });
        }
    };

    let listener = match prepare_accept_ready_agent_socket(listening) {
        Ok(listener) => listener,
        Err(failure) => {
            let (listening, error) = failure.into_parts();
            return Err(LocalLinuxProductionLifecycleAssemblyError::AcceptReady {
                error,
                cleanup: cleanup_result(listening.cleanup()),
            });
        }
    };

    let listener = LocalLinuxListenerCleanupGuard::new(listener);
    let wake = match LocalLinuxRuntimeWake::create() {
        Ok(wake) => wake,
        Err(error) => {
            return Err(LocalLinuxProductionLifecycleAssemblyError::RuntimeWake {
                error,
                cleanup: listener.finish(),
            });
        }
    };
    let capacity = LocalLinuxWorkerCapacity::new(config.worker_capacity());
    let control = LocalLinuxSchedulerControl::new();

    let value = operation(listener.listener(), &wake, &capacity, &control);
    let cleanup = listener.finish();

    Ok(LocalLinuxProductionLifecycleExecution { value, cleanup })
}

#[cfg(test)]
pub(super) fn with_local_linux_production_lifecycle_in_root_path<R, F>(
    root_path: &std::path::Path,
    config: LocalLinuxProductionRuntimeConfig,
    operation: F,
) -> Result<LocalLinuxProductionLifecycleExecution<R>, LocalLinuxProductionLifecycleAssemblyError>
where
    F: FnOnce(
        &AcceptReadyAgentSocket<'_>,
        &LocalLinuxRuntimeWake,
        &LocalLinuxWorkerCapacity,
        &LocalLinuxSchedulerControl,
    ) -> R,
{
    let root = super::xdg_runtime_root::validate_xdg_runtime_root_path(root_path)
        .map_err(LocalLinuxProductionLifecycleAssemblyError::RuntimeRoot)?;
    with_validated_root(&root, config, operation)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::{
        LocalLinuxProductionLifecycleAssemblyError,
        with_local_linux_production_lifecycle_in_root_path,
    };
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::production_runtime_types::{
        LocalLinuxProductionRuntimeCleanup, LocalLinuxProductionRuntimeConfig,
    };
    use crate::linux_identity::runtime_wake::LocalLinuxRuntimeWakeDrainError;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLockError, acquire_agent_instance_lock,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_root(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-096-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_root(label: &str) -> PathBuf {
        let root = unique_root(label);
        fs::create_dir(&root).expect("temporary Phase 096 root creates");
        fs::set_permissions(&root, Permissions::from_mode(0o700))
            .expect("temporary Phase 096 root mode sets");
        root
    }

    fn config() -> LocalLinuxProductionRuntimeConfig {
        LocalLinuxProductionRuntimeConfig::new(
            NonZeroUsize::new(2).expect("capacity nonzero"),
            NonZeroU16::new(8).expect("backlog nonzero"),
            NonZeroUsize::new(2).expect("attempt budget nonzero"),
            NonZeroUsize::new(4).expect("request budget nonzero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(250)).expect("read budget nonzero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(250)).expect("write budget nonzero"),
        )
    }

    fn socket_path(root: &Path) -> PathBuf {
        root.join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    #[test]
    fn successful_assembly_exposes_live_resources_then_removes_socket() {
        let root = create_root("success");
        let path = socket_path(&root);

        let execution = with_local_linux_production_lifecycle_in_root_path(
            &root,
            config(),
            |listener, wake, capacity, control| {
                assert_eq!(capacity.max_workers(), 2);
                assert_eq!(capacity.active_workers(), 0);
                assert!(!control.is_shutdown_requested());
                assert_eq!(
                    wake.drain(),
                    Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
                );
                let client = UnixStream::connect(&path).expect("prepared listener accepts connect");
                drop(client);
                std::os::fd::AsFd::as_fd(listener);
                41_u8
            },
        )
        .expect("Phase 096 lifecycle assembles");

        assert_eq!(
            execution.cleanup(),
            LocalLinuxProductionRuntimeCleanup::Clean
        );
        assert_eq!(execution.into_value(), 41);
        assert!(!path.exists());

        fs::remove_dir_all(root).expect("temporary Phase 096 root removes");
    }

    #[test]
    fn lifecycle_can_be_reassembled_after_clean_return() {
        let root = create_root("repeat");
        let path = socket_path(&root);

        for expected in [1_u8, 2_u8] {
            let execution = with_local_linux_production_lifecycle_in_root_path(
                &root,
                config(),
                |_listener, _wake, _capacity, _control| {
                    assert!(path.exists());
                    expected
                },
            )
            .expect("lifecycle reassembles after prior cleanup");
            assert_eq!(execution.into_value(), expected);
            assert!(!path.exists());
        }

        fs::remove_dir_all(root).expect("temporary repeated root removes");
    }

    #[test]
    fn callback_unwind_best_effort_cleans_listener_and_releases_lock() {
        let root = create_root("unwind");
        let path = socket_path(&root);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = with_local_linux_production_lifecycle_in_root_path(
                &root,
                config(),
                |_listener, _wake, _capacity, _control| -> () {
                    assert!(path.exists());
                    panic!("intentional Phase 096 callback unwind");
                },
            );
        }));
        assert!(panic.is_err());
        assert!(!path.exists());

        let second = with_local_linux_production_lifecycle_in_root_path(
            &root,
            config(),
            |_listener, _wake, _capacity, _control| (),
        )
        .expect("instance lock and socket path are reusable after unwind");
        assert_eq!(second.cleanup(), LocalLinuxProductionRuntimeCleanup::Clean);

        fs::remove_dir_all(root).expect("temporary unwind root removes");
    }

    #[test]
    fn preexisting_instance_lock_fails_before_socket_bind() {
        let root_path = create_root("already-running");
        let root =
            crate::linux_identity::xdg_runtime_root::validate_xdg_runtime_root_path(&root_path)
                .expect("temporary root validates");
        let runtime_directory = crate::linux_identity::xdg_runtime_root::prw_runtime_directory::prepare_prw_runtime_directory(&root)
            .expect("runtime directory prepares");
        let lock =
            acquire_agent_instance_lock(&runtime_directory).expect("first instance lock holds");

        let result = with_local_linux_production_lifecycle_in_root_path(
            &root_path,
            config(),
            |_listener, _wake, _capacity, _control| (),
        );
        assert_eq!(
            result,
            Err(LocalLinuxProductionLifecycleAssemblyError::InstanceLock(
                AgentInstanceLockError::AlreadyRunning
            ))
        );
        assert!(!socket_path(&root_path).exists());

        drop(lock);
        drop(runtime_directory);
        drop(root);
        fs::remove_dir_all(root_path).expect("temporary already-running root removes");
    }
}
