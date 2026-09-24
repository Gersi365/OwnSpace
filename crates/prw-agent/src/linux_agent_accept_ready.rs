//! Nonblocking accept-ready type state and one-shot authenticated Linux accept.
//!
//! Phase 070 transitions a Phase 068 listening socket to verified `O_NONBLOCK`
//! status before exposing one kernel accept attempt. Accepted streams are
//! immediately passed through Phase 059 same-UID authentication before return.

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::net::{SocketFlags, accept_with};

use super::authenticated_connection::AuthenticatedLocalLinuxConnection;
use super::bound_socket::BoundAgentSocketCleanupError;
use super::listening_socket::ListeningAgentSocket;
use super::peer_auth::LocalLinuxPeerAuthorizationError;

/// Listening Agent socket proven nonblocking before any accept operation.
#[derive(Debug)]
pub struct AcceptReadyAgentSocket<'a> {
    listening_socket: ListeningAgentSocket<'a>,
}

impl AsFd for AcceptReadyAgentSocket<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.listening_socket.as_fd()
    }
}

impl AcceptReadyAgentSocket<'_> {
    /// Performs at most one nonblocking accept attempt and authenticates any peer.
    ///
    /// A readiness miss is returned as
    /// [`AuthenticatedAgentAcceptOutcome::NoConnectionReady`] rather than an
    /// error. A successfully accepted raw stream is never returned before the
    /// Phase 059 same-effective-UID authorization succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedAgentAcceptError::AcceptFailed`] for kernel accept
    /// errors other than a readiness miss, or
    /// [`AuthenticatedAgentAcceptError::PeerAuthorization`] when `SO_PEERCRED`
    /// same-UID authorization rejects the accepted stream.
    pub fn try_accept_authenticated(
        &self,
    ) -> Result<AuthenticatedAgentAcceptOutcome, AuthenticatedAgentAcceptError> {
        let accepted = match accept_with(&self.listening_socket, SocketFlags::CLOEXEC) {
            Ok(descriptor) => descriptor,
            Err(error) if error == Errno::WOULDBLOCK || error == Errno::AGAIN => {
                return Ok(AuthenticatedAgentAcceptOutcome::NoConnectionReady);
            }
            Err(_) => return Err(AuthenticatedAgentAcceptError::AcceptFailed),
        };

        let stream = UnixStream::from(accepted);
        match AuthenticatedLocalLinuxConnection::try_new(stream) {
            Ok(connection) => Ok(AuthenticatedAgentAcceptOutcome::Authenticated(connection)),
            Err(failure) => {
                let (stream, error) = failure.into_parts();
                drop(stream);
                Err(AuthenticatedAgentAcceptError::PeerAuthorization(error))
            }
        }
    }

    /// Closes the listener and delegates exact-identity pathname cleanup to Phase 068/067.
    ///
    /// # Errors
    ///
    /// Returns the existing bounded Phase 067 cleanup error when the validated
    /// socket pathname cannot be safely removed or verified absent.
    pub fn cleanup(self) -> Result<(), BoundAgentSocketCleanupError> {
        self.listening_socket.cleanup()
    }
}

/// Successful outcome of one nonblocking authenticated accept attempt.
#[derive(Debug)]
pub enum AuthenticatedAgentAcceptOutcome {
    /// No connection was queued when the one-shot nonblocking accept ran.
    NoConnectionReady,
    /// One accepted stream passed kernel `SO_PEERCRED` same-UID authorization.
    Authenticated(AuthenticatedLocalLinuxConnection<UnixStream>),
}

/// Bounded failure from one authenticated accept attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedAgentAcceptError {
    /// Kernel accept failed for a reason other than a readiness miss.
    AcceptFailed,
    /// The accepted connected stream failed Phase 058/059 peer authorization.
    PeerAuthorization(LocalLinuxPeerAuthorizationError),
}

/// Bounded failure while preparing a listener for nonblocking accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptReadyAgentSocketError {
    /// Current listener status flags could not be read.
    StatusReadFailed,
    /// `O_NONBLOCK` could not be set while preserving current status flags.
    StatusWriteFailed,
    /// Listener status flags could not be read after the update.
    StatusRevalidationFailed,
    /// Revalidation did not observe `O_NONBLOCK`.
    NonblockingNotSet,
}

/// Failed readiness transition retaining the original Phase 068 listening object.
#[derive(Debug)]
pub struct AcceptReadyAgentSocketTransitionFailure<'a> {
    listening_socket: ListeningAgentSocket<'a>,
    error: AcceptReadyAgentSocketError,
}

impl AcceptReadyAgentSocketTransitionFailure<'_> {
    /// Returns the bounded readiness-transition error without consuming the failure.
    #[must_use]
    pub const fn error(&self) -> AcceptReadyAgentSocketError {
        self.error
    }
}

impl<'a> AcceptReadyAgentSocketTransitionFailure<'a> {
    /// Returns the original listener and error for caller-directed cleanup.
    #[must_use]
    pub fn into_parts(self) -> (ListeningAgentSocket<'a>, AcceptReadyAgentSocketError) {
        (self.listening_socket, self.error)
    }
}

/// Consumes a Phase 068 listener and returns it only after `O_NONBLOCK` is verified.
///
/// # Errors
///
/// Returns [`AcceptReadyAgentSocketTransitionFailure`] containing the original
/// listening object when status inspection, update, or revalidation fails.
pub fn prepare_accept_ready_agent_socket(
    listening_socket: ListeningAgentSocket<'_>,
) -> Result<AcceptReadyAgentSocket<'_>, AcceptReadyAgentSocketTransitionFailure<'_>> {
    let Ok(current_flags) = fcntl_getfl(&listening_socket) else {
        return Err(AcceptReadyAgentSocketTransitionFailure {
            listening_socket,
            error: AcceptReadyAgentSocketError::StatusReadFailed,
        });
    };

    if !current_flags.contains(OFlags::NONBLOCK)
        && fcntl_setfl(&listening_socket, current_flags | OFlags::NONBLOCK).is_err()
    {
        return Err(AcceptReadyAgentSocketTransitionFailure {
            listening_socket,
            error: AcceptReadyAgentSocketError::StatusWriteFailed,
        });
    }

    let Ok(revalidated_flags) = fcntl_getfl(&listening_socket) else {
        return Err(AcceptReadyAgentSocketTransitionFailure {
            listening_socket,
            error: AcceptReadyAgentSocketError::StatusRevalidationFailed,
        });
    };

    if !revalidated_flags.contains(OFlags::NONBLOCK) {
        return Err(AcceptReadyAgentSocketTransitionFailure {
            listening_socket,
            error: AcceptReadyAgentSocketError::NonblockingNotSet,
        });
    }

    Ok(AcceptReadyAgentSocket { listening_socket })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::io::{Read, Write};
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{OFlags, fcntl_getfl};
    use rustix::io::{FdFlags, fcntl_getfd};

    use super::{
        AcceptReadyAgentSocket, AuthenticatedAgentAcceptOutcome, prepare_accept_ready_agent_socket,
    };
    use crate::linux_identity::bound_socket::bind_validated_agent_socket;
    use crate::linux_identity::effective_agent_uid;
    use crate::linux_identity::listening_socket::listen_bound_agent_socket;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::ValidatedPrwRuntimeDirectory;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::{
        AgentInstanceLock, AgentInstanceLockError, acquire_agent_instance_lock,
    };
    use crate::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-phase-070-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn create_directory_with_mode(path: &Path, mode: u32) {
        fs::create_dir(path).expect("temporary Phase 070 directory creates");
        fs::set_permissions(path, Permissions::from_mode(mode))
            .expect("temporary Phase 070 directory mode sets");
    }

    fn create_runtime_owners(
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

    fn make_accept_ready<'a>(
        runtime_directory: &'a ValidatedPrwRuntimeDirectory,
        instance_lock: &'a AgentInstanceLock,
    ) -> AcceptReadyAgentSocket<'a> {
        let bound = bind_validated_agent_socket(runtime_directory, instance_lock)
            .expect("Phase 067 bound socket creates");
        let listening =
            listen_bound_agent_socket(bound, NonZeroU16::new(8).expect("test backlog is nonzero"))
                .expect("Phase 068 listener creates");
        prepare_accept_ready_agent_socket(listening)
            .expect("Phase 070 readiness transition succeeds")
    }

    #[test]
    fn readiness_transition_sets_nonblocking_and_empty_queue_returns_no_ready() {
        let (root_path, runtime_directory, instance_lock) = create_runtime_owners("no-ready");
        let ready = make_accept_ready(&runtime_directory, &instance_lock);

        let status = fcntl_getfl(&ready).expect("accept-ready status flags read");
        assert!(status.contains(OFlags::NONBLOCK));
        assert!(matches!(
            ready
                .try_accept_authenticated()
                .expect("empty nonblocking accept is a normal outcome"),
            AuthenticatedAgentAcceptOutcome::NoConnectionReady
        ));

        ready.cleanup().expect("accept-ready cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn accepted_stream_is_cloexec_blocking_authenticated_and_bytes_remain_unread() {
        let (root_path, runtime_directory, instance_lock) = create_runtime_owners("accepted");
        let socket_path = agent_socket_path(&root_path);
        let ready = make_accept_ready(&runtime_directory, &instance_lock);
        let mut client = UnixStream::connect(&socket_path).expect("test client connects");
        let sentinel = *b"PRW-phase-070-auth-order";
        client
            .write_all(&sentinel)
            .expect("sentinel writes before accept/authentication");

        let outcome = ready
            .try_accept_authenticated()
            .expect("same-UID client accept/auth succeeds");
        let AuthenticatedAgentAcceptOutcome::Authenticated(mut connection) = outcome else {
            panic!("queued client must produce an authenticated connection");
        };

        assert_eq!(connection.peer_credentials().uid(), effective_agent_uid());
        let descriptor_flags =
            fcntl_getfd(connection.stream()).expect("accepted descriptor flags read");
        assert!(descriptor_flags.contains(FdFlags::CLOEXEC));
        let status_flags =
            fcntl_getfl(connection.stream()).expect("accepted stream status flags read");
        assert!(!status_flags.contains(OFlags::NONBLOCK));

        let mut received = [0_u8; 24];
        connection
            .stream_mut()
            .read_exact(&mut received)
            .expect("sentinel remains unread until authenticated access");
        assert_eq!(received, sentinel);

        drop(connection);
        drop(client);
        ready.cleanup().expect("accept-ready cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }

    #[test]
    fn one_accept_does_not_consume_listener_lifecycle_or_later_client() {
        let (root_path, runtime_directory, instance_lock) = create_runtime_owners("reusable");
        let socket_path = agent_socket_path(&root_path);
        let ready = make_accept_ready(&runtime_directory, &instance_lock);

        let first_client = UnixStream::connect(&socket_path).expect("first client connects");
        let first = ready
            .try_accept_authenticated()
            .expect("first accept succeeds");
        assert!(matches!(
            &first,
            AuthenticatedAgentAcceptOutcome::Authenticated(_)
        ));
        drop(first);
        drop(first_client);

        let second_client = UnixStream::connect(&socket_path).expect("second client connects");
        let second = ready
            .try_accept_authenticated()
            .expect("second accept succeeds");
        assert!(matches!(
            &second,
            AuthenticatedAgentAcceptOutcome::Authenticated(_)
        ));
        drop(second);
        drop(second_client);

        assert!(matches!(
            ready
                .try_accept_authenticated()
                .expect("empty queue after two accepts is normal"),
            AuthenticatedAgentAcceptOutcome::NoConnectionReady
        ));
        assert_eq!(
            acquire_agent_instance_lock(&runtime_directory).unwrap_err(),
            AgentInstanceLockError::AlreadyRunning
        );

        ready.cleanup().expect("accept-ready cleanup succeeds");
        drop(instance_lock);
        drop(runtime_directory);
        fs::remove_dir_all(&root_path).expect("temporary root removes");
    }
}
