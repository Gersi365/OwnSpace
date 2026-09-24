//! Agent-owned execution of one prepared logical-session challenge/proof transaction.
//!
//! C03e-H materializes only the C03e-G-selected transaction seam. The caller must supply the same
//! authority-gated Agent runtime, accepted lower-transport-authenticated peer, Phase 128 session
//! service, and C03e-E prepared challenge. This module does not create a remote-session lease,
//! bind capabilities, spawn tasks, retry authentication, or publish remote readiness.

use std::fmt;

use prw_control_plane::session_auth::{SessionAuthChallenge, SessionAuthProof};
use prw_core::SessionId;
use prw_remote_bridge::{
    remote_server_transport_runtime::{
        AuthenticatedRemotePeerConnection, RemoteServerTransportRuntimeError,
    },
    session_auth_wire::{
        SessionAuthenticationWireChallenge, SessionAuthenticationWireError,
        SessionAuthenticationWireMessage, receive_session_authentication_message,
        send_session_authentication_message,
    },
};
use prw_session::{
    AuthenticatedDeviceSession, SessionAuthenticationService, SessionServiceError,
    prwa_verifier_source::PrwaVerifierSourceError,
};

use crate::remote_transport_runtime::AgentRemoteTransportRuntime;

const SESSION_AUTHENTICATION_FAILURE_CLOSE_CODE: u32 = 1;
const SESSION_AUTHENTICATION_FAILURE_CLOSE_REASON: &[u8] =
    b"session authentication transaction failed";

/// Primary failure class for one prepared logical-session challenge/proof transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentRemoteSessionAuthenticationPrimaryError {
    /// Accepting the peer-initiated control stream failed.
    Transport(RemoteServerTransportRuntimeError),
    /// C03d PRWS frame construction, I/O, or decoding failed.
    Wire(SessionAuthenticationWireError),
    /// The proof frame used a different PRWM correlation request identifier.
    RequestIdMismatch,
    /// The peer returned a logical-session message other than `Proof`.
    UnexpectedMessage,
    /// The wire proof referenced a different logical session identifier.
    SessionIdMismatch,
    /// Fresh server-owned verifier time could not be observed for proof verification.
    VerifierTime(PrwaVerifierSourceError),
    /// Existing Phase 128 proof verification or authenticated-session commit failed.
    Session(SessionServiceError),
}

impl fmt::Display for AgentRemoteSessionAuthenticationPrimaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => {
                formatter.write_str("remote session control-stream accept failed")
            }
            Self::Wire(_) => formatter.write_str("remote session authentication wire failed"),
            Self::RequestIdMismatch => {
                formatter.write_str("remote session authentication request id mismatch")
            }
            Self::UnexpectedMessage => {
                formatter.write_str("remote session authentication expected proof message")
            }
            Self::SessionIdMismatch => {
                formatter.write_str("remote session authentication session id mismatch")
            }
            Self::VerifierTime(_) => {
                formatter.write_str("remote session authentication verifier time failed")
            }
            Self::Session(_) => formatter.write_str("remote session authentication proof failed"),
        }
    }
}

impl std::error::Error for AgentRemoteSessionAuthenticationPrimaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::VerifierTime(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::RequestIdMismatch | Self::UnexpectedMessage | Self::SessionIdMismatch => None,
        }
    }
}

impl From<RemoteServerTransportRuntimeError> for AgentRemoteSessionAuthenticationPrimaryError {
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Transport(error)
    }
}

impl From<SessionAuthenticationWireError> for AgentRemoteSessionAuthenticationPrimaryError {
    fn from(error: SessionAuthenticationWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<SessionServiceError> for AgentRemoteSessionAuthenticationPrimaryError {
    fn from(error: SessionServiceError) -> Self {
        Self::Session(error)
    }
}

/// Terminal transaction failure with explicit pending-session cleanup evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRemoteSessionAuthenticationFailure {
    primary: AgentRemoteSessionAuthenticationPrimaryError,
    cleanup_error: Option<SessionServiceError>,
}

impl AgentRemoteSessionAuthenticationFailure {
    const fn new(
        primary: AgentRemoteSessionAuthenticationPrimaryError,
        cleanup_error: Option<SessionServiceError>,
    ) -> Self {
        Self {
            primary,
            cleanup_error,
        }
    }

    /// Returns the primary transaction failure.
    #[must_use]
    pub const fn primary(&self) -> AgentRemoteSessionAuthenticationPrimaryError {
        self.primary
    }

    /// Returns the explicit C03e-F abort failure when cleanup did not succeed.
    #[must_use]
    pub const fn cleanup_error(&self) -> Option<SessionServiceError> {
        self.cleanup_error
    }
}

impl fmt::Display for AgentRemoteSessionAuthenticationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.cleanup_error.is_some() {
            formatter.write_str("remote session authentication and pending-session cleanup failed")
        } else {
            self.primary.fmt(formatter)
        }
    }
}

impl std::error::Error for AgentRemoteSessionAuthenticationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

/// Completes one C03e-E prepared logical-session challenge over one C03d control stream.
///
/// `challenge` must be the challenge just prepared by the same `session_authentication` service for
/// this peer transaction. The supplied Agent runtime borrow keeps the authority-gated endpoint owner
/// alive for the transaction; no new endpoint or peer is created here.
///
/// The function accepts exactly one peer-initiated control stream, sends exactly one challenge,
/// receives exactly one proof candidate, enforces exact PRWM request-id and logical-session-id
/// correlation, then delegates nonce/replay/time/signature verification to the existing Phase 128
/// service exactly once.
///
/// On every terminal failure after the prepared pending challenge exists, this function calls
/// C03e-F `abort_pending_session` exactly once and then explicitly closes the entire authenticated
/// peer. Any abort failure is retained alongside the primary failure. Successful proof verification
/// performs no abort and leaves the peer open for separately gated post-authentication work.
///
/// # Errors
///
/// Returns [`AgentRemoteSessionAuthenticationFailure`] for stream acceptance, C03d wire,
/// correlation, expected-message, session-id, or Phase 128 proof failures. The returned value also
/// exposes any explicit pending-session cleanup failure.
pub async fn complete_registry_bound_session_authentication(
    runtime: &AgentRemoteTransportRuntime,
    peer: &AuthenticatedRemotePeerConnection,
    session_authentication: &mut SessionAuthenticationService,
    challenge: &SessionAuthChallenge,
    request_id: u64,
    now_unix_seconds: u64,
) -> Result<AuthenticatedDeviceSession, AgentRemoteSessionAuthenticationFailure> {
    let mut verifier_time_unix_seconds = || Ok(now_unix_seconds);
    complete_registry_bound_session_authentication_with_time_source(
        runtime,
        peer,
        session_authentication,
        challenge,
        request_id,
        &mut verifier_time_unix_seconds,
    )
    .await
}

pub(crate) async fn complete_registry_bound_session_authentication_with_fresh_verifier_time<T>(
    runtime: &AgentRemoteTransportRuntime,
    peer: &AuthenticatedRemotePeerConnection,
    session_authentication: &mut SessionAuthenticationService,
    challenge: &SessionAuthChallenge,
    request_id: u64,
    verifier_time_unix_seconds: &mut T,
) -> Result<AuthenticatedDeviceSession, AgentRemoteSessionAuthenticationFailure>
where
    T: FnMut() -> Result<u64, PrwaVerifierSourceError>,
{
    complete_registry_bound_session_authentication_with_time_source(
        runtime,
        peer,
        session_authentication,
        challenge,
        request_id,
        verifier_time_unix_seconds,
    )
    .await
}

async fn complete_registry_bound_session_authentication_with_time_source<T>(
    runtime: &AgentRemoteTransportRuntime,
    peer: &AuthenticatedRemotePeerConnection,
    session_authentication: &mut SessionAuthenticationService,
    challenge: &SessionAuthChallenge,
    request_id: u64,
    verifier_time_unix_seconds: &mut T,
) -> Result<AuthenticatedDeviceSession, AgentRemoteSessionAuthenticationFailure>
where
    T: FnMut() -> Result<u64, PrwaVerifierSourceError>,
{
    let _authority_owner_guard = runtime.authority_owner();
    let session_id = challenge.session_id();

    let mut stream = match peer.accept_control_stream().await {
        Ok(stream) => stream,
        Err(error) => {
            return Err(fail_transaction(
                peer,
                session_authentication,
                session_id,
                error.into(),
            ));
        }
    };

    let challenge_message = SessionAuthenticationWireMessage::Challenge(
        SessionAuthenticationWireChallenge::from_typed(challenge),
    );
    if let Err(error) =
        send_session_authentication_message(&mut stream, request_id, &challenge_message).await
    {
        return Err(fail_transaction(
            peer,
            session_authentication,
            session_id,
            error.into(),
        ));
    }

    let (proof_request_id, proof_message) =
        match receive_session_authentication_message(&mut stream).await {
            Ok(message) => message,
            Err(error) => {
                return Err(fail_transaction(
                    peer,
                    session_authentication,
                    session_id,
                    error.into(),
                ));
            }
        };
    if proof_request_id != request_id {
        return Err(fail_transaction(
            peer,
            session_authentication,
            session_id,
            AgentRemoteSessionAuthenticationPrimaryError::RequestIdMismatch,
        ));
    }

    let SessionAuthenticationWireMessage::Proof(wire_proof) = proof_message else {
        return Err(fail_transaction(
            peer,
            session_authentication,
            session_id,
            AgentRemoteSessionAuthenticationPrimaryError::UnexpectedMessage,
        ));
    };
    if wire_proof.session_id() != session_id.as_str() {
        return Err(fail_transaction(
            peer,
            session_authentication,
            session_id,
            AgentRemoteSessionAuthenticationPrimaryError::SessionIdMismatch,
        ));
    }

    let proof = SessionAuthProof::new(
        session_id.clone(),
        wire_proof.nonce(),
        wire_proof.signature().clone(),
    );
    let now_unix_seconds = match observe_fresh_proof_verifier_time(verifier_time_unix_seconds) {
        Ok(now_unix_seconds) => now_unix_seconds,
        Err(error) => {
            return Err(fail_transaction(
                peer,
                session_authentication,
                session_id,
                error,
            ));
        }
    };
    session_authentication
        .submit_proof(session_id, &proof, now_unix_seconds)
        .map_err(|error| {
            fail_transaction(
                peer,
                session_authentication,
                session_id,
                AgentRemoteSessionAuthenticationPrimaryError::Session(error),
            )
        })
}

fn observe_fresh_proof_verifier_time<T>(
    verifier_time_unix_seconds: &mut T,
) -> Result<u64, AgentRemoteSessionAuthenticationPrimaryError>
where
    T: FnMut() -> Result<u64, PrwaVerifierSourceError>,
{
    verifier_time_unix_seconds().map_err(AgentRemoteSessionAuthenticationPrimaryError::VerifierTime)
}

fn fail_transaction(
    peer: &AuthenticatedRemotePeerConnection,
    session_authentication: &mut SessionAuthenticationService,
    session_id: &SessionId,
    primary: AgentRemoteSessionAuthenticationPrimaryError,
) -> AgentRemoteSessionAuthenticationFailure {
    let cleanup_error = session_authentication
        .abort_pending_session(session_id)
        .err();
    peer.close(
        SESSION_AUTHENTICATION_FAILURE_CLOSE_CODE,
        SESSION_AUTHENTICATION_FAILURE_CLOSE_REASON,
    );
    AgentRemoteSessionAuthenticationFailure::new(primary, cleanup_error)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use prw_session::{SessionServiceError, prwa_verifier_source::PrwaVerifierSourceError};

    use super::{
        AgentRemoteSessionAuthenticationFailure, AgentRemoteSessionAuthenticationPrimaryError,
        SESSION_AUTHENTICATION_FAILURE_CLOSE_CODE, SESSION_AUTHENTICATION_FAILURE_CLOSE_REASON,
        complete_registry_bound_session_authentication,
        complete_registry_bound_session_authentication_with_fresh_verifier_time,
        observe_fresh_proof_verifier_time,
    };

    #[test]
    fn transaction_surface_requires_runtime_peer_service_challenge_correlation_and_time() {
        let _ = complete_registry_bound_session_authentication;
    }

    #[test]
    fn fresh_transaction_surface_accepts_request_owned_fallible_verifier_time() {
        let _ = complete_registry_bound_session_authentication_with_fresh_verifier_time::<
            fn() -> Result<u64, PrwaVerifierSourceError>,
        >;
    }

    #[test]
    fn fresh_verifier_time_is_observed_once_and_preserves_value() {
        let mut calls = 0_u8;
        let mut source = || {
            calls += 1;
            Ok(47_u64)
        };

        let observed = observe_fresh_proof_verifier_time(&mut source);

        assert_eq!(observed, Ok(47));
        assert_eq!(calls, 1);
    }

    #[test]
    fn fresh_verifier_time_failure_preserves_typed_source() {
        let mut source = || Err(PrwaVerifierSourceError::VerifierTime);
        let error = observe_fresh_proof_verifier_time(&mut source)
            .expect_err("fresh verifier-time failure must remain typed");

        assert_eq!(
            error,
            AgentRemoteSessionAuthenticationPrimaryError::VerifierTime(
                PrwaVerifierSourceError::VerifierTime
            )
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn failure_surface_preserves_primary_and_cleanup_errors_separately() {
        let failure = AgentRemoteSessionAuthenticationFailure::new(
            AgentRemoteSessionAuthenticationPrimaryError::RequestIdMismatch,
            Some(SessionServiceError::UnknownSession),
        );

        assert_eq!(
            failure.primary(),
            AgentRemoteSessionAuthenticationPrimaryError::RequestIdMismatch
        );
        assert_eq!(
            failure.cleanup_error(),
            Some(SessionServiceError::UnknownSession)
        );
    }

    #[test]
    fn peer_close_diagnostic_is_fixed_nonzero_and_nonempty() {
        assert_ne!(SESSION_AUTHENTICATION_FAILURE_CLOSE_CODE, 0);
        assert!(!SESSION_AUTHENTICATION_FAILURE_CLOSE_REASON.is_empty());
    }
}
