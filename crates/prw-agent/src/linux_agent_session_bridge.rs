//! Pure composition from a Phase 070 authenticated accept outcome into Phase 060 session state.
//!
//! Phase 071 performs no accept, credential lookup, application I/O, policy
//! evaluation, or Request processing.

use std::os::unix::net::UnixStream;

use super::accept_ready::AuthenticatedAgentAcceptOutcome;
use super::authenticated_session::AuthenticatedLocalLinuxSession;

/// Phase 071 composition result preserving the Phase 070 no-ready outcome.
#[derive(Debug)]
pub enum AuthenticatedAgentSessionOutcome {
    /// Phase 070 observed no queued connection; no session was constructed.
    NoConnectionReady,
    /// One already-authenticated accepted connection was wrapped in fresh Phase 060 session state.
    AuthenticatedSession(AuthenticatedLocalLinuxSession<UnixStream>),
}

/// Consumes one successful Phase 070 accept outcome and composes Phase 060 session state.
///
/// This function is infallible because it performs only ownership/state
/// composition. It does not accept a connection, retrieve credentials, read or
/// write application bytes, select policy, or process Requests.
#[must_use]
pub fn compose_authenticated_session(
    outcome: AuthenticatedAgentAcceptOutcome,
) -> AuthenticatedAgentSessionOutcome {
    match outcome {
        AuthenticatedAgentAcceptOutcome::NoConnectionReady => {
            AuthenticatedAgentSessionOutcome::NoConnectionReady
        }
        AuthenticatedAgentAcceptOutcome::Authenticated(connection) => {
            AuthenticatedAgentSessionOutcome::AuthenticatedSession(
                AuthenticatedLocalLinuxSession::new(connection),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::{AuthenticatedAgentSessionOutcome, compose_authenticated_session};
    use crate::linux_identity::accept_ready::AuthenticatedAgentAcceptOutcome;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::effective_agent_uid;

    #[test]
    fn no_connection_ready_maps_without_constructing_a_session() {
        assert!(matches!(
            compose_authenticated_session(AuthenticatedAgentAcceptOutcome::NoConnectionReady),
            AuthenticatedAgentSessionOutcome::NoConnectionReady
        ));
    }

    #[test]
    fn authenticated_connection_maps_to_fresh_session_without_consuming_bytes() {
        let (server, mut client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let sentinel = *b"PRW-phase-071-session";
        client
            .write_all(&sentinel)
            .expect("sentinel writes before authentication and session composition");

        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID endpoint authenticates");
        let outcome = AuthenticatedAgentAcceptOutcome::Authenticated(connection);

        let AuthenticatedAgentSessionOutcome::AuthenticatedSession(session) =
            compose_authenticated_session(outcome)
        else {
            panic!("authenticated outcome must construct a Phase 060 session");
        };

        assert_eq!(session.peer_credentials().uid(), effective_agent_uid());
        assert!(session.state().is_usable());

        let mut connection = session.into_connection();
        let mut received = [0_u8; 21];
        connection
            .stream_mut()
            .read_exact(&mut received)
            .expect("sentinel remains unread until explicit post-bridge access");
        assert_eq!(received, sentinel);
    }
}
