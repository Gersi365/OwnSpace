//! Authenticated-session worker cancellation authority.
//!
//! Phase 082 creates an independently owned `UnixStream` clone only from an
//! already-authenticated Phase 059 connection. The clone is reserved for
//! terminal `shutdown(Both)` and is never exposed as an application I/O stream.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use super::authenticated_connection::AuthenticatedLocalLinuxConnection;

/// Independently owned terminal shutdown authority for one authenticated stream.
#[derive(Debug)]
pub struct LocalLinuxWorkerCancellation {
    stream: UnixStream,
}

impl LocalLinuxWorkerCancellation {
    /// Clones one already-authenticated connected stream for cancellation only.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxWorkerCancellationCreateError::CloneFailed`] when the
    /// operating system cannot duplicate the connected stream handle.
    pub fn try_from_authenticated_connection(
        connection: &AuthenticatedLocalLinuxConnection<UnixStream>,
    ) -> Result<Self, LocalLinuxWorkerCancellationCreateError> {
        connection
            .stream()
            .try_clone()
            .map(|stream| Self { stream })
            .map_err(|_| LocalLinuxWorkerCancellationCreateError::CloneFailed)
    }

    /// Terminally shuts down both halves of the underlying authenticated stream.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxWorkerCancellationError::ShutdownFailed`] when the
    /// operating system rejects the shutdown request.
    pub fn cancel(&self) -> Result<(), LocalLinuxWorkerCancellationError> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|_| LocalLinuxWorkerCancellationError::ShutdownFailed)
    }
}

/// Failure to create one worker cancellation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxWorkerCancellationCreateError {
    /// Duplicating the already-authenticated stream handle failed.
    CloneFailed,
}

/// Failure while issuing terminal worker-stream cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxWorkerCancellationError {
    /// `shutdown(Both)` failed for the retained cancellation handle.
    ShutdownFailed,
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::LocalLinuxWorkerCancellation;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

    #[test]
    fn cancellation_clone_is_created_only_after_authenticated_wrapper_exists() {
        let (server, _client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID test stream authenticates");

        let cancellation =
            LocalLinuxWorkerCancellation::try_from_authenticated_connection(&connection)
                .expect("authenticated stream cancellation clone creates");

        drop(cancellation);
        assert!(connection.stream().peer_addr().is_ok());
    }

    #[test]
    fn cancellation_shutdown_wakes_blocked_peer_side_io_and_is_terminal() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID test stream authenticates");
        let cancellation =
            LocalLinuxWorkerCancellation::try_from_authenticated_connection(&connection)
                .expect("authenticated stream cancellation clone creates");

        cancellation.cancel().expect("terminal shutdown succeeds");

        let mut byte = [0_u8; 1];
        assert_eq!(
            connection
                .stream()
                .read(&mut byte)
                .expect("shutdown read returns promptly"),
            0
        );
        assert!(client.write_all(&[1]).is_err());
    }
}
