//! Bounded enrolled-device session authentication orchestration for PRW.
//!
//! This crate creates fresh server challenges and composes the locked typed signer/
//! verifier boundaries into one authenticated session identity. It deliberately does
//! not select a network transport, persist registry state, authenticate accounts, or
//! grant file, terminal, forwarding, networking, DNS, or administrative capabilities.

pub mod prwa_verifier_source;

use std::{collections::HashMap, fmt};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_control_plane::{
    DeviceIdentityBinding, PublicIdentityMaterial,
    session_auth::{
        SESSION_AUTH_NONCE_LEN, SessionAuthChallenge, SessionAuthChallengeError,
        SessionAuthChallengeState, SessionAuthNonce, SessionAuthProof,
    },
};
use prw_core::{DeviceId, SessionId, UserId, WorkspaceId};
use prw_device_identity::{SessionAuthVerificationError, verify_session_auth_proof};

/// Immutable identity established by one successful device session proof.
///
/// This type intentionally carries no capability set. Authorization remains a
/// separate policy decision after authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDeviceSession {
    session_id: SessionId,
    workspace_id: WorkspaceId,
    user_id: UserId,
    device_id: DeviceId,
    public_identity: PublicIdentityMaterial,
}

impl AuthenticatedDeviceSession {
    /// Returns the authenticated session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the workspace bound by the enrolled device identity.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    /// Returns the logical user bound by the enrolled device identity.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the authenticated device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the authenticated canonical public identity.
    #[must_use]
    pub const fn public_identity(&self) -> &PublicIdentityMaterial {
        &self.public_identity
    }
}

/// Bounded session-authentication orchestration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionServiceError {
    /// Cryptographic provider could not generate a challenge nonce.
    ChallengeRandomness,
    /// Device binding was not enrolled.
    BindingNotEnrolled,
    /// Challenge lifetime violated the locked bounds.
    InvalidChallengeLifetime,
    /// Session identifier is already pending or authenticated.
    SessionAlreadyExists,
    /// No pending session exists for the supplied identifier.
    UnknownSession,
    /// Session already authenticated successfully.
    SessionAlreadyAuthenticated,
    /// Typed proof failed replay, message, public-key, or signature verification.
    ProofRejected,
}

impl fmt::Display for SessionServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ChallengeRandomness => "session challenge randomness failed",
            Self::BindingNotEnrolled => "session binding is not enrolled",
            Self::InvalidChallengeLifetime => "invalid session challenge lifetime",
            Self::SessionAlreadyExists => "session already exists",
            Self::UnknownSession => "unknown session",
            Self::SessionAlreadyAuthenticated => "session already authenticated",
            Self::ProofRejected => "session authentication proof rejected",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionServiceError {}

/// In-memory single-use device-session authentication authority.
#[derive(Debug, Default)]
pub struct SessionAuthenticationService {
    pending: HashMap<SessionId, SessionAuthChallengeState>,
    authenticated: HashMap<SessionId, AuthenticatedDeviceSession>,
}

impl SessionAuthenticationService {
    /// Creates an empty fail-closed session service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Begins authentication for one enrolled device and fresh session identifier.
    ///
    /// # Errors
    ///
    /// Rejects duplicate session identifiers, non-enrolled bindings, invalid challenge
    /// lifetimes, and provider randomness failures.
    pub fn begin_session(
        &mut self,
        binding: DeviceIdentityBinding,
        session_id: SessionId,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<SessionAuthChallenge, SessionServiceError> {
        if self.pending.contains_key(&session_id) || self.authenticated.contains_key(&session_id) {
            return Err(SessionServiceError::SessionAlreadyExists);
        }

        let mut nonce_bytes = [0_u8; SESSION_AUTH_NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| SessionServiceError::ChallengeRandomness)?;
        let nonce = SessionAuthNonce::new(nonce_bytes);
        let state = SessionAuthChallengeState::new(
            binding,
            session_id.clone(),
            nonce,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        )
        .map_err(map_challenge_error)?;
        let challenge = state.challenge().clone();
        self.pending.insert(session_id, state);
        Ok(challenge)
    }

    /// Verifies one typed proof and commits one authenticated session identity.
    ///
    /// # Errors
    ///
    /// Rejects unknown/completed sessions and any invalid typed proof.
    pub fn submit_proof(
        &mut self,
        session_id: &SessionId,
        proof: &SessionAuthProof,
        now_unix_seconds: u64,
    ) -> Result<AuthenticatedDeviceSession, SessionServiceError> {
        if self.authenticated.contains_key(session_id) {
            return Err(SessionServiceError::SessionAlreadyAuthenticated);
        }

        let state = self
            .pending
            .get_mut(session_id)
            .ok_or(SessionServiceError::UnknownSession)?;
        verify_session_auth_proof(state, proof, now_unix_seconds)
            .map_err(map_verification_error)?;

        let binding = state.bound_identity();
        let authenticated = AuthenticatedDeviceSession {
            session_id: session_id.clone(),
            workspace_id: binding.workspace_id.clone(),
            user_id: binding.user_id.clone(),
            device_id: binding.device_id.clone(),
            public_identity: binding.public_identity.clone(),
        };
        self.authenticated
            .insert(session_id.clone(), authenticated.clone());
        self.pending.remove(session_id);
        Ok(authenticated)
    }

    /// Explicitly aborts one still-pending session-authentication transaction.
    ///
    /// This removes only the private pending challenge state. It does not return challenge or
    /// identity material, remove an authenticated session, retry authentication, close a transport,
    /// or grant any capability. Cleanup is explicit rather than delegated to `Drop`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionServiceError::SessionAlreadyAuthenticated`] if the identifier has already
    /// authenticated, or [`SessionServiceError::UnknownSession`] if no pending transaction exists.
    pub fn abort_pending_session(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), SessionServiceError> {
        if self.authenticated.contains_key(session_id) {
            return Err(SessionServiceError::SessionAlreadyAuthenticated);
        }
        if self.pending.remove(session_id).is_none() {
            return Err(SessionServiceError::UnknownSession);
        }
        Ok(())
    }

    /// Returns a completed authenticated session by identifier.
    #[must_use]
    pub fn authenticated_session(
        &self,
        session_id: &SessionId,
    ) -> Option<&AuthenticatedDeviceSession> {
        self.authenticated.get(session_id)
    }

    /// Returns the number of pending challenge transactions.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of authenticated sessions held by this authority.
    #[must_use]
    pub fn authenticated_count(&self) -> usize {
        self.authenticated.len()
    }
}

const fn map_challenge_error(error: SessionAuthChallengeError) -> SessionServiceError {
    match error {
        SessionAuthChallengeError::BindingNotEnrolled => SessionServiceError::BindingNotEnrolled,
        SessionAuthChallengeError::InvalidLifetime => SessionServiceError::InvalidChallengeLifetime,
    }
}

const fn map_verification_error(_error: SessionAuthVerificationError) -> SessionServiceError {
    SessionServiceError::ProofRejected
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_control_plane::{
        DeviceIdentityBinding, DeviceIdentitySignature,
        session_auth::{SessionAuthNonce, SessionAuthProof},
    };
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;

    use super::{SessionAuthenticationService, SessionServiceError};

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable session test key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("load disposable signer")
    }

    fn binding(
        signer: &UbuntuEnrollmentSigner,
        lifecycle: DeviceLifecycle,
    ) -> DeviceIdentityBinding {
        DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-1").expect("workspace id"),
            user_id: UserId::new("user-1").expect("user id"),
            device_id: DeviceId::new("device-1").expect("device id"),
            public_identity: signer.public_identity().clone(),
            lifecycle,
        }
    }

    #[test]
    fn valid_typed_proof_authenticates_exact_bound_identity_once() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-1").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 1_000, 1_300)
            .expect("begin session");
        let proof = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("sign session proof");

        let authenticated = service
            .submit_proof(&session_id, &proof, 1_001)
            .expect("authenticate session");

        assert_eq!(authenticated.session_id(), &session_id);
        assert_eq!(authenticated.workspace_id(), &bound.workspace_id);
        assert_eq!(authenticated.user_id(), &bound.user_id);
        assert_eq!(authenticated.device_id(), &bound.device_id);
        assert_eq!(authenticated.public_identity(), &bound.public_identity);
        assert_eq!(service.pending_count(), 0);
        assert_eq!(service.authenticated_count(), 1);
        assert_eq!(
            service.authenticated_session(&session_id),
            Some(&authenticated)
        );
        assert_eq!(
            service.submit_proof(&session_id, &proof, 1_002),
            Err(SessionServiceError::SessionAlreadyAuthenticated)
        );
    }

    #[test]
    fn pending_and_revoked_bindings_fail_before_pending_state() {
        let signer = signer();
        let mut service = SessionAuthenticationService::new();
        assert_eq!(
            service.begin_session(
                binding(&signer, DeviceLifecycle::PendingEnrollment),
                SessionId::new("pending-session").expect("session id"),
                10,
                20,
            ),
            Err(SessionServiceError::BindingNotEnrolled)
        );
        assert_eq!(
            service.begin_session(
                binding(&signer, DeviceLifecycle::Revoked),
                SessionId::new("revoked-session").expect("session id"),
                10,
                20,
            ),
            Err(SessionServiceError::BindingNotEnrolled)
        );
        assert_eq!(service.pending_count(), 0);
    }

    #[test]
    fn explicit_abort_removes_only_pending_state() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-abort").expect("session id");
        let mut service = SessionAuthenticationService::new();
        service
            .begin_session(bound.clone(), session_id.clone(), 10, 100)
            .expect("begin pending session");

        assert_eq!(service.pending_count(), 1);
        assert_eq!(service.authenticated_count(), 0);
        assert_eq!(service.abort_pending_session(&session_id), Ok(()));
        assert_eq!(service.pending_count(), 0);
        assert_eq!(service.authenticated_count(), 0);
        assert_eq!(
            service.abort_pending_session(&session_id),
            Err(SessionServiceError::UnknownSession)
        );
        assert!(service.begin_session(bound, session_id, 101, 200).is_ok());
    }

    #[test]
    fn authenticated_session_cannot_be_aborted() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-authenticated-abort").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 10, 100)
            .expect("begin session");
        let proof = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("proof");
        let authenticated = service
            .submit_proof(&session_id, &proof, 11)
            .expect("authenticate session");

        assert_eq!(
            service.abort_pending_session(&session_id),
            Err(SessionServiceError::SessionAlreadyAuthenticated)
        );
        assert_eq!(service.pending_count(), 0);
        assert_eq!(service.authenticated_count(), 1);
        assert_eq!(
            service.authenticated_session(&session_id),
            Some(&authenticated)
        );
    }

    #[test]
    fn proof_for_other_session_is_rejected_without_consuming_correct_challenge() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_a = SessionId::new("session-a").expect("session id");
        let session_b = SessionId::new("session-b").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge_a = service
            .begin_session(bound.clone(), session_a.clone(), 10, 100)
            .expect("session a");
        let challenge_b = service
            .begin_session(bound.clone(), session_b, 10, 100)
            .expect("session b");
        let proof_b = signer
            .sign_session_auth_proof(&bound, &challenge_b)
            .expect("proof b");

        assert_eq!(
            service.submit_proof(&session_a, &proof_b, 11),
            Err(SessionServiceError::ProofRejected)
        );

        let proof_a = signer
            .sign_session_auth_proof(&bound, &challenge_a)
            .expect("proof a");
        assert!(service.submit_proof(&session_a, &proof_a, 11).is_ok());
    }

    #[test]
    fn changed_bound_identity_signature_is_rejected_without_consumption() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-binding").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 10, 100)
            .expect("begin session");

        let mut changed = bound.clone();
        changed.user_id = UserId::new("user-2").expect("user id");
        let wrong_proof = signer
            .sign_session_auth_proof(&changed, &challenge)
            .expect("sign changed binding proof");
        assert_eq!(
            service.submit_proof(&session_id, &wrong_proof, 11),
            Err(SessionServiceError::ProofRejected)
        );

        let correct_proof = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("correct proof");
        assert!(
            service
                .submit_proof(&session_id, &correct_proof, 11)
                .is_ok()
        );
    }

    #[test]
    fn wrong_nonce_is_rejected_before_correct_proof_can_complete() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-nonce").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 100, 200)
            .expect("begin session");
        let correct = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("correct proof");
        let wrong = SessionAuthProof::new(
            session_id.clone(),
            SessionAuthNonce::new([0xA5; 32]),
            DeviceIdentitySignature::new(
                correct.signature().algorithm(),
                correct.signature().encoding(),
                correct.signature().as_bytes().to_vec(),
            )
            .expect("copy typed signature"),
        );

        assert_eq!(
            service.submit_proof(&session_id, &wrong, 101),
            Err(SessionServiceError::ProofRejected)
        );
        assert!(service.submit_proof(&session_id, &correct, 101).is_ok());
    }

    #[test]
    fn rejected_proof_remains_pending_until_explicit_abort() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-rejected-abort").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 100, 200)
            .expect("begin session");
        let correct = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("correct proof");
        let wrong = SessionAuthProof::new(
            session_id.clone(),
            SessionAuthNonce::new([0x5A; 32]),
            DeviceIdentitySignature::new(
                correct.signature().algorithm(),
                correct.signature().encoding(),
                correct.signature().as_bytes().to_vec(),
            )
            .expect("copy typed signature"),
        );

        assert_eq!(
            service.submit_proof(&session_id, &wrong, 101),
            Err(SessionServiceError::ProofRejected)
        );
        assert_eq!(service.pending_count(), 1);
        assert_eq!(service.abort_pending_session(&session_id), Ok(()));
        assert_eq!(service.pending_count(), 0);
        assert_eq!(service.authenticated_count(), 0);
    }

    #[test]
    fn challenge_time_window_fails_closed() {
        let signer = signer();
        let bound = binding(&signer, DeviceLifecycle::Enrolled);
        let session_id = SessionId::new("session-time").expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(bound.clone(), session_id.clone(), 100, 200)
            .expect("begin session");
        let proof = signer
            .sign_session_auth_proof(&bound, &challenge)
            .expect("proof");

        assert_eq!(
            service.submit_proof(&session_id, &proof, 99),
            Err(SessionServiceError::ProofRejected)
        );
        assert_eq!(
            service.submit_proof(&session_id, &proof, 200),
            Err(SessionServiceError::ProofRejected)
        );
        assert_eq!(service.authenticated_count(), 0);
    }
}
