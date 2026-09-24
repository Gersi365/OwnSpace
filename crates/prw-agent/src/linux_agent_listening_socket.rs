//! One-way transition from a validated bound Agent socket to listening state.
//!
//! Phase 068 calls `listen` exactly once and deliberately implements no accept
//! operation or application-protocol processing.

use std::num::NonZeroU16;
use std::os::fd::{AsFd, BorrowedFd};

use rustix::net::listen;

use super::bound_socket::{
    AgentSocketFilesystemIdentity, BoundAgentSocket, BoundAgentSocketCleanupError,
};

/// Validated Agent socket after the kernel `listen` transition.
#[derive(Debug)]
pub struct ListeningAgentSocket<'a> {
    bound_socket: BoundAgentSocket<'a>,
    backlog: NonZeroU16,
}

impl AsFd for ListeningAgentSocket<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.bound_socket.as_fd()
    }
}

impl ListeningAgentSocket<'_> {
    /// Returns the explicit caller-supplied backlog used for the transition.
    #[must_use]
    pub const fn backlog(&self) -> NonZeroU16 {
        self.backlog
    }

    /// Returns the Phase 067 filesystem identity retained across `listen`.
    #[must_use]
    pub const fn filesystem_identity(&self) -> AgentSocketFilesystemIdentity {
        self.bound_socket.filesystem_identity()
    }

    /// Closes the listening descriptor and delegates exact-path cleanup to Phase 067.
    ///
    /// # Errors
    ///
    /// Returns the bounded Phase 067 cleanup error when the validated pathname
    /// cannot be safely removed or verified absent.
    pub fn cleanup(self) -> Result<(), BoundAgentSocketCleanupError> {
        self.bound_socket.cleanup()
    }
}

/// Bounded failure while entering listening state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListeningAgentSocketError {
    /// The kernel rejected `listen` on the validated bound socket.
    ListenFailed,
}

/// Failed `bound -> listening` transition retaining the original bound object.
#[derive(Debug)]
pub struct ListeningAgentSocketTransitionFailure<'a> {
    bound_socket: BoundAgentSocket<'a>,
    error: ListeningAgentSocketError,
}

impl ListeningAgentSocketTransitionFailure<'_> {
    /// Returns the bounded transition error without consuming the failure.
    #[must_use]
    pub const fn error(&self) -> ListeningAgentSocketError {
        self.error
    }
}

impl<'a> ListeningAgentSocketTransitionFailure<'a> {
    /// Returns the still-bound socket and transition error for caller-directed cleanup.
    #[must_use]
    pub fn into_parts(self) -> (BoundAgentSocket<'a>, ListeningAgentSocketError) {
        (self.bound_socket, self.error)
    }
}

/// Consumes a validated bound socket and transitions it to listening state.
///
/// # Errors
///
/// Returns [`ListeningAgentSocketTransitionFailure`] with the original bound
/// socket when the kernel rejects `listen`.
pub fn listen_bound_agent_socket(
    bound_socket: BoundAgentSocket<'_>,
    backlog: NonZeroU16,
) -> Result<ListeningAgentSocket<'_>, ListeningAgentSocketTransitionFailure<'_>> {
    if listen(&bound_socket, i32::from(backlog.get())).is_err() {
        return Err(ListeningAgentSocketTransitionFailure {
            bound_socket,
            error: ListeningAgentSocketError::ListenFailed,
        });
    }

    Ok(ListeningAgentSocket {
        bound_socket,
        backlog,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::listen_bound_agent_socket;
    use crate::AGENT_RUNTIME_SUBDIRECTORY;
    use crate::AGENT_SOCKET_FILENAME;
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLock, AgentInstanceLockError, acquire_agent_instance_lock,
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-068-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 068 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 068 directory mode sets");
    }

    fn create_authorized_runtime(
        label: &str,
    ) -> (PathBuf, ValidatedPrwRuntimeDirectory, AgentInstanceLock) {
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

    fn agent_socket_path(root_path: &Path) -> PathBuf {
        root_path
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }

    #[test]
    fn bound_socket_transitions_to_listening_with_explicit_backlog() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("listen");
        let socket_path = agent_socket_path(&root_path);
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let identity = bound.filesystem_identity();
        let backlog = NonZeroU16::new(8).expect("test backlog is nonzero");

        let listening =
            listen_bound_agent_socket(bound, backlog).expect("bound socket enters listen state");

        assert_eq!(listening.backlog(), backlog);
        assert_eq!(listening.filesystem_identity(), identity);

        let client = UnixStream::connect(&socket_path)
            .expect("local test client connects after listen transition");
        drop(client);

        listening
            .cleanup()
            .expect("listening socket cleanup succeeds");
        assert!(!socket_path.exists());

        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn listening_state_retains_instance_lock_authority() {
        let (root_path, runtime_directory, instance_lock) = create_authorized_runtime("authority");
        let bound = bind_validated_agent_socket(&runtime_directory, &instance_lock)
            .expect("Phase 067 bound socket creates");
        let backlog = NonZeroU16::new(4).expect("test backlog is nonzero");
        let listening =
            listen_bound_agent_socket(bound, backlog).expect("bound socket enters listen state");

        assert_eq!(
            acquire_agent_instance_lock(&runtime_directory).unwrap_err(),
            AgentInstanceLockError::AlreadyRunning
        );

        listening
            .cleanup()
            .expect("listening socket cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }
}
