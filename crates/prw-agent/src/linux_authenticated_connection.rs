//! Typed ownership of an already-connected, same-UID-authorized Linux stream.
//!
//! Phase 059 associates one owned stream with the Phase 058 authorization token
//! before exposing stream access inside the crate. It owns no listener.

use rustix::fd::AsFd;

use crate::linux_identity::LocalLinuxPeerCredentials;
use crate::linux_identity::peer_auth::{
    AuthorizedLocalLinuxPeer, LocalLinuxPeerAuthorizationError, authorize_same_effective_uid,
};

/// An already-connected Linux stream whose kernel peer UID matched the Agent effective UID.
#[derive(Debug)]
pub struct AuthenticatedLocalLinuxConnection<S> {
    stream: S,
    peer: AuthorizedLocalLinuxPeer,
}

impl<S: AsFd> AuthenticatedLocalLinuxConnection<S> {
    /// Authorizes and wraps ownership of one already-connected Linux stream.
    ///
    /// Construction performs no application-protocol read or write. On failure,
    /// ownership of the original stream is returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxConnectionAuthorizationFailure`] containing the
    /// original stream and bounded Phase 058 authorization error when same-UID
    /// authorization cannot be established.
    pub fn try_new(stream: S) -> Result<Self, LocalLinuxConnectionAuthorizationFailure<S>> {
        match authorize_same_effective_uid(&stream) {
            Ok(peer) => Ok(Self { stream, peer }),
            Err(error) => Err(LocalLinuxConnectionAuthorizationFailure { stream, error }),
        }
    }
}

impl<S> AuthenticatedLocalLinuxConnection<S> {
    /// Returns immutable kernel credentials associated with this authorized stream.
    #[must_use]
    pub const fn peer_credentials(&self) -> LocalLinuxPeerCredentials {
        self.peer.credentials()
    }

    /// Returns shared access to the stream only after successful authorization.
    #[must_use]
    pub const fn stream(&self) -> &S {
        &self.stream
    }

    /// Returns mutable access to the stream only after successful authorization.
    pub const fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Returns ownership of the already-authorized stream.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }
}

/// Failed attempt to turn an owned connected stream into an authenticated wrapper.
#[derive(Debug)]
pub struct LocalLinuxConnectionAuthorizationFailure<S> {
    stream: S,
    error: LocalLinuxPeerAuthorizationError,
}

impl<S> LocalLinuxConnectionAuthorizationFailure<S> {
    /// Returns the bounded authorization failure without consuming the result.
    #[must_use]
    pub const fn error(&self) -> LocalLinuxPeerAuthorizationError {
        self.error
    }

    /// Returns both the original stream and bounded authorization failure.
    #[must_use]
    pub fn into_parts(self) -> (S, LocalLinuxPeerAuthorizationError) {
        (self.stream, self.error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::LocalLinuxIdentityError;
    use crate::linux_identity::effective_agent_uid;
    use crate::linux_identity::peer_auth::LocalLinuxPeerAuthorizationError;

    #[test]
    fn successful_wrapper_preserves_kernel_authorization_metadata() {
        let (server, _client) = UnixStream::pair().expect("anonymous Unix pair creates");

        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID peer wraps successfully");

        assert_eq!(connection.peer_credentials().uid(), effective_agent_uid());
    }

    #[test]
    fn authorization_occurs_without_consuming_application_bytes() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let sentinel = *b"PRW-auth-order";
        client
            .write_all(&sentinel)
            .expect("sentinel writes before authorization");

        let mut connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID peer wraps successfully");
        let mut received = [0_u8; 14];
        connection
            .stream_mut()
            .read_exact(&mut received)
            .expect("sentinel remains unread until post-authorization access");

        assert_eq!(received, sentinel);
    }

    #[test]
    fn failed_authorization_returns_original_stream_ownership() {
        let file = File::open("/dev/null").expect("read-only /dev/null opens");

        let failure = AuthenticatedLocalLinuxConnection::try_new(file)
            .expect_err("non-socket descriptor must fail closed");
        assert_eq!(
            failure.error(),
            LocalLinuxPeerAuthorizationError::Identity(
                LocalLinuxIdentityError::PeerCredentialLookup
            )
        );

        let (returned_file, error) = failure.into_parts();
        assert!(returned_file.metadata().is_ok());
        assert_eq!(
            error,
            LocalLinuxPeerAuthorizationError::Identity(
                LocalLinuxIdentityError::PeerCredentialLookup
            )
        );
    }
}
