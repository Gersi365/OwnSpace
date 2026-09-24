//! Provider-neutral enrolled-device session authentication domain.
//!
//! This module defines challenge, proof, replay-state, and canonical-message
//! semantics only. It does not generate random challenges, sign messages, verify
//! cryptographic signatures, persist registry state, select a transport, or grant
//! capabilities.

use std::fmt;

use prw_core::SessionId;

use crate::{
    DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
    DeviceIdentitySignature,
};

/// Exact Phase 128 session-authentication domain separator.
pub const SESSION_AUTH_DOMAIN_SEPARATOR: &[u8; 32] = b"PRW\0DeviceSessionAuthentication\0";
/// Initial canonical session-authentication message version.
pub const SESSION_AUTH_MESSAGE_VERSION: u16 = 1;
/// Exact challenge nonce length in bytes.
pub const SESSION_AUTH_NONCE_LEN: usize = 32;
/// Maximum UTF-8 byte length for each identifier in a session-authentication message.
pub const MAX_SESSION_AUTH_IDENTIFIER_BYTES: usize = 1024;
/// Maximum public-identity byte length for the locked initial P-256 SPKI profile.
pub const MAX_SESSION_AUTH_PUBLIC_IDENTITY_BYTES: usize = 256;
/// Maximum canonical Phase 128 session-authentication message length in bytes.
pub const MAX_SESSION_AUTH_MESSAGE_BYTES: usize = 4442;
/// Maximum server challenge lifetime in seconds.
pub const MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS: u64 = 300;

const ECDSA_P256_SHA256_CODE: u16 = 1;
const SUBJECT_PUBLIC_KEY_INFO_DER_CODE: u16 = 1;

/// Exact 256-bit server challenge nonce for one device session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionAuthNonce([u8; SESSION_AUTH_NONCE_LEN]);

impl SessionAuthNonce {
    /// Creates a nonce from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; SESSION_AUTH_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_AUTH_NONCE_LEN] {
        &self.0
    }

    /// Copies an exact-length byte slice into a nonce.
    ///
    /// # Errors
    ///
    /// Returns [`SessionAuthNonceError::InvalidLength`] when the slice is not
    /// exactly 32 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SessionAuthNonceError> {
        let bytes: [u8; SESSION_AUTH_NONCE_LEN] = bytes
            .try_into()
            .map_err(|_| SessionAuthNonceError::InvalidLength)?;
        Ok(Self(bytes))
    }
}

/// Invalid session-authentication nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthNonceError {
    /// The nonce was not exactly 32 bytes.
    InvalidLength,
}

impl fmt::Display for SessionAuthNonceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("session auth nonce must be 32 bytes"),
        }
    }
}

impl std::error::Error for SessionAuthNonceError {}

/// Server-issued challenge for one strongly typed session identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthChallenge {
    session_id: SessionId,
    nonce: SessionAuthNonce,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl SessionAuthChallenge {
    /// Returns the session identifier bound to this challenge.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the exact server challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> SessionAuthNonce {
        self.nonce
    }

    /// Returns the verifier-owned issue timestamp.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the verifier-owned expiry timestamp.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns whether the challenge is expired at the supplied verifier time.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }

    /// Returns whether the supplied verifier time precedes challenge issuance.
    #[must_use]
    pub const fn is_not_yet_valid_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds < self.issued_at_unix_seconds
    }
}

/// Device session-authentication proof submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthProof {
    session_id: SessionId,
    nonce: SessionAuthNonce,
    signature: DeviceIdentitySignature,
}

impl SessionAuthProof {
    /// Creates a proof value from its session identifier, nonce, and device signature.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        nonce: SessionAuthNonce,
        signature: DeviceIdentitySignature,
    ) -> Self {
        Self {
            session_id,
            nonce,
            signature,
        }
    }

    /// Returns the session identifier supplied by the device.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the submitted challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> SessionAuthNonce {
        self.nonce
    }

    /// Returns the submitted device-identity signature.
    #[must_use]
    pub const fn signature(&self) -> &DeviceIdentitySignature {
        &self.signature
    }
}

/// Server-side single-use challenge state bound to one immutable enrolled identity snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthChallengeState {
    bound_identity: DeviceIdentityBinding,
    challenge: SessionAuthChallenge,
    consumed: bool,
}

impl SessionAuthChallengeState {
    /// Creates challenge state for one immutable enrolled identity snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SessionAuthChallengeError::BindingNotEnrolled`] unless the bound
    /// lifecycle is exactly enrolled, or [`SessionAuthChallengeError::InvalidLifetime`]
    /// when challenge lifetime is zero, reversed, or above 300 seconds.
    pub fn new(
        bound_identity: DeviceIdentityBinding,
        session_id: SessionId,
        nonce: SessionAuthNonce,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, SessionAuthChallengeError> {
        if !bound_identity.lifecycle.can_participate() {
            return Err(SessionAuthChallengeError::BindingNotEnrolled);
        }
        validate_challenge_lifetime(issued_at_unix_seconds, expires_at_unix_seconds)?;
        Ok(Self {
            bound_identity,
            challenge: SessionAuthChallenge {
                session_id,
                nonce,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            },
            consumed: false,
        })
    }

    /// Returns the immutable enrolled identity snapshot bound to this state.
    #[must_use]
    pub const fn bound_identity(&self) -> &DeviceIdentityBinding {
        &self.bound_identity
    }

    /// Returns the current server challenge.
    #[must_use]
    pub const fn challenge(&self) -> &SessionAuthChallenge {
        &self.challenge
    }

    /// Returns whether successful verification has consumed this challenge.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Validates replay, session, nonce, and verifier-time context before crypto.
    ///
    /// # Errors
    ///
    /// Returns [`SessionAuthSubmissionError`] when the challenge cannot accept the proof.
    pub fn validate_submission(
        &self,
        proof: &SessionAuthProof,
        now_unix_seconds: u64,
    ) -> Result<(), SessionAuthSubmissionError> {
        if self.consumed {
            return Err(SessionAuthSubmissionError::Consumed);
        }
        if self.challenge.is_not_yet_valid_at(now_unix_seconds) {
            return Err(SessionAuthSubmissionError::NotYetValid);
        }
        if self.challenge.is_expired_at(now_unix_seconds) {
            return Err(SessionAuthSubmissionError::Expired);
        }
        if proof.session_id() != self.challenge.session_id() {
            return Err(SessionAuthSubmissionError::SessionMismatch);
        }
        if proof.nonce() != self.challenge.nonce() {
            return Err(SessionAuthSubmissionError::NonceMismatch);
        }
        Ok(())
    }

    /// Marks the challenge consumed after successful signature verification.
    ///
    /// # Errors
    ///
    /// Revalidates the proof context and returns [`SessionAuthSubmissionError`]
    /// if the challenge can no longer accept the proof.
    pub fn consume_verified(
        &mut self,
        proof: &SessionAuthProof,
        now_unix_seconds: u64,
    ) -> Result<(), SessionAuthSubmissionError> {
        self.validate_submission(proof, now_unix_seconds)?;
        self.consumed = true;
        Ok(())
    }
}

/// Invalid server challenge construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthChallengeError {
    /// Bound device lifecycle was not enrolled.
    BindingNotEnrolled,
    /// Lifetime was zero, reversed, or exceeded 300 seconds.
    InvalidLifetime,
}

impl fmt::Display for SessionAuthChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindingNotEnrolled => formatter.write_str("session auth binding is not enrolled"),
            Self::InvalidLifetime => formatter.write_str("invalid session auth challenge lifetime"),
        }
    }
}

impl std::error::Error for SessionAuthChallengeError {}

/// Rejected proof-submission context before or after signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthSubmissionError {
    /// The challenge was already successfully consumed.
    Consumed,
    /// Verifier time precedes the server-recorded issue time.
    NotYetValid,
    /// Challenge reached or passed server-recorded expiry.
    Expired,
    /// Proof references a different session identifier.
    SessionMismatch,
    /// Proof nonce does not match the active challenge.
    NonceMismatch,
}

impl fmt::Display for SessionAuthSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed => formatter.write_str("session auth challenge already consumed"),
            Self::NotYetValid => formatter.write_str("session auth challenge not yet valid"),
            Self::Expired => formatter.write_str("session auth challenge expired"),
            Self::SessionMismatch => formatter.write_str("session auth session mismatch"),
            Self::NonceMismatch => formatter.write_str("session auth nonce mismatch"),
        }
    }
}

impl std::error::Error for SessionAuthSubmissionError {}

/// Canonical session-authentication message construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthMessageError {
    /// One of the bound identifiers is empty or exceeds the session-specific byte bound.
    IdentifierOutOfBounds,
    /// Public identity bytes are empty or exceed the initial P-256 SPKI byte bound.
    PublicIdentityOutOfBounds,
    /// Device lifecycle is not enrolled.
    BindingNotEnrolled,
    /// Declared device-identity algorithm is not the locked initial profile.
    UnsupportedAlgorithm,
    /// Declared public-key encoding is not the locked initial profile.
    UnsupportedPublicKeyEncoding,
    /// Checked message-length computation failed or exceeded the locked maximum.
    MessageTooLarge,
}

impl fmt::Display for SessionAuthMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentifierOutOfBounds => {
                formatter.write_str("session auth identifier out of bounds")
            }
            Self::PublicIdentityOutOfBounds => {
                formatter.write_str("session auth public identity out of bounds")
            }
            Self::BindingNotEnrolled => formatter.write_str("session auth binding is not enrolled"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("unsupported session auth identity algorithm")
            }
            Self::UnsupportedPublicKeyEncoding => {
                formatter.write_str("unsupported session auth public-key encoding")
            }
            Self::MessageTooLarge => formatter.write_str("session auth message too large"),
        }
    }
}

impl std::error::Error for SessionAuthMessageError {}

/// Constructs the exact Phase 128 canonical session-authentication message.
///
/// # Errors
///
/// Returns [`SessionAuthMessageError`] when the binding is not enrolled, identifiers
/// or public identity exceed locked bounds, the identity profile is unsupported, or
/// checked message-size computation fails.
pub fn encode_session_auth_message(
    binding: &DeviceIdentityBinding,
    session_id: &SessionId,
    nonce: SessionAuthNonce,
) -> Result<Vec<u8>, SessionAuthMessageError> {
    if !binding.lifecycle.can_participate() {
        return Err(SessionAuthMessageError::BindingNotEnrolled);
    }

    let session_id = bounded_identifier(session_id.as_str().as_bytes())?;
    let workspace_id = bounded_identifier(binding.workspace_id.as_str().as_bytes())?;
    let user_id = bounded_identifier(binding.user_id.as_str().as_bytes())?;
    let device_id = bounded_identifier(binding.device_id.as_str().as_bytes())?;
    let public_identity = binding.public_identity.as_bytes();
    if public_identity.is_empty() || public_identity.len() > MAX_SESSION_AUTH_PUBLIC_IDENTITY_BYTES
    {
        return Err(SessionAuthMessageError::PublicIdentityOutOfBounds);
    }

    let algorithm_code = match binding.public_identity.algorithm() {
        DeviceIdentityAlgorithm::EcdsaP256Sha256 => ECDSA_P256_SHA256_CODE,
    };
    let encoding_code = match binding.public_identity.encoding() {
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer => {
            SUBJECT_PUBLIC_KEY_INFO_DER_CODE
        }
    };

    let message_len = SESSION_AUTH_DOMAIN_SEPARATOR
        .len()
        .checked_add(size_of::<u16>())
        .and_then(|len| len.checked_add(length_prefixed_size(session_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(workspace_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(user_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(device_id)))
        .and_then(|len| len.checked_add(size_of::<u16>()))
        .and_then(|len| len.checked_add(size_of::<u16>()))
        .and_then(|len| len.checked_add(length_prefixed_size(public_identity)))
        .and_then(|len| len.checked_add(SESSION_AUTH_NONCE_LEN))
        .ok_or(SessionAuthMessageError::MessageTooLarge)?;
    if message_len > MAX_SESSION_AUTH_MESSAGE_BYTES {
        return Err(SessionAuthMessageError::MessageTooLarge);
    }

    let mut message = Vec::with_capacity(message_len);
    message.extend_from_slice(SESSION_AUTH_DOMAIN_SEPARATOR);
    message.extend_from_slice(&SESSION_AUTH_MESSAGE_VERSION.to_be_bytes());
    push_length_prefixed(&mut message, session_id)?;
    push_length_prefixed(&mut message, workspace_id)?;
    push_length_prefixed(&mut message, user_id)?;
    push_length_prefixed(&mut message, device_id)?;
    message.extend_from_slice(&algorithm_code.to_be_bytes());
    message.extend_from_slice(&encoding_code.to_be_bytes());
    push_length_prefixed(&mut message, public_identity)?;
    message.extend_from_slice(nonce.as_bytes());
    debug_assert_eq!(message.len(), message_len);
    Ok(message)
}

fn validate_challenge_lifetime(
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<(), SessionAuthChallengeError> {
    let lifetime = expires_at_unix_seconds
        .checked_sub(issued_at_unix_seconds)
        .ok_or(SessionAuthChallengeError::InvalidLifetime)?;
    if lifetime == 0 || lifetime > MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS {
        return Err(SessionAuthChallengeError::InvalidLifetime);
    }
    Ok(())
}

const fn bounded_identifier(bytes: &[u8]) -> Result<&[u8], SessionAuthMessageError> {
    if bytes.is_empty() || bytes.len() > MAX_SESSION_AUTH_IDENTIFIER_BYTES {
        return Err(SessionAuthMessageError::IdentifierOutOfBounds);
    }
    Ok(bytes)
}

const fn length_prefixed_size(bytes: &[u8]) -> usize {
    size_of::<u32>() + bytes.len()
}

fn push_length_prefixed(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SessionAuthMessageError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| SessionAuthMessageError::MessageTooLarge)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};

    use crate::{DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial};

    use super::{
        MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS, MAX_SESSION_AUTH_MESSAGE_BYTES,
        SESSION_AUTH_DOMAIN_SEPARATOR, SESSION_AUTH_NONCE_LEN, SessionAuthChallengeError,
        SessionAuthChallengeState, SessionAuthMessageError, SessionAuthNonce,
        encode_session_auth_message,
    };

    fn binding(lifecycle: DeviceLifecycle) -> crate::DeviceIdentityBinding {
        crate::DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-1").expect("workspace id"),
            user_id: UserId::new("user-1").expect("user id"),
            device_id: DeviceId::new("device-1").expect("device id"),
            public_identity: PublicIdentityMaterial::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
                vec![0x30, 0x01, 0x00],
            )
            .expect("public identity"),
            lifecycle,
        }
    }

    #[test]
    fn domain_separator_and_nonce_length_are_locked() {
        assert_eq!(SESSION_AUTH_DOMAIN_SEPARATOR.len(), 32);
        assert_eq!(SESSION_AUTH_NONCE_LEN, 32);
        assert_eq!(
            SESSION_AUTH_DOMAIN_SEPARATOR,
            b"PRW\0DeviceSessionAuthentication\0"
        );
    }

    #[test]
    fn only_enrolled_binding_can_create_challenge_state() {
        let nonce = SessionAuthNonce::new([7; SESSION_AUTH_NONCE_LEN]);
        let session = SessionId::new("session-1").expect("session id");
        assert!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::Enrolled),
                session.clone(),
                nonce,
                10,
                20
            )
            .is_ok()
        );
        assert_eq!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::PendingEnrollment),
                session.clone(),
                nonce,
                10,
                20
            ),
            Err(SessionAuthChallengeError::BindingNotEnrolled)
        );
        assert_eq!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::Revoked),
                session,
                nonce,
                10,
                20
            ),
            Err(SessionAuthChallengeError::BindingNotEnrolled)
        );
    }

    #[test]
    fn challenge_lifetime_accepts_one_through_300_seconds_only() {
        let nonce = SessionAuthNonce::new([1; SESSION_AUTH_NONCE_LEN]);
        let session = SessionId::new("session-1").expect("session id");
        assert!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::Enrolled),
                session.clone(),
                nonce,
                100,
                101
            )
            .is_ok()
        );
        assert!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::Enrolled),
                session.clone(),
                nonce,
                100,
                100 + MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS
            )
            .is_ok()
        );
        assert_eq!(
            SessionAuthChallengeState::new(
                binding(DeviceLifecycle::Enrolled),
                session,
                nonce,
                100,
                401
            ),
            Err(SessionAuthChallengeError::InvalidLifetime)
        );
    }

    #[test]
    fn canonical_message_changes_with_every_bound_identifier() {
        let nonce = SessionAuthNonce::new([9; SESSION_AUTH_NONCE_LEN]);
        let base = binding(DeviceLifecycle::Enrolled);
        let session = SessionId::new("session-a").expect("session id");
        let base_message = encode_session_auth_message(&base, &session, nonce).expect("message");

        let changed_session = encode_session_auth_message(
            &base,
            &SessionId::new("session-b").expect("session id"),
            nonce,
        )
        .expect("message");
        assert_ne!(base_message, changed_session);

        let mut changed = base.clone();
        changed.workspace_id = WorkspaceId::new("workspace-2").expect("workspace id");
        assert_ne!(
            base_message,
            encode_session_auth_message(&changed, &session, nonce).expect("message")
        );
        changed = base.clone();
        changed.user_id = UserId::new("user-2").expect("user id");
        assert_ne!(
            base_message,
            encode_session_auth_message(&changed, &session, nonce).expect("message")
        );
        changed = base;
        changed.device_id = DeviceId::new("device-2").expect("device id");
        assert_ne!(
            base_message,
            encode_session_auth_message(&changed, &session, nonce).expect("message")
        );
    }

    #[test]
    fn non_enrolled_binding_cannot_encode_message() {
        let nonce = SessionAuthNonce::new([3; SESSION_AUTH_NONCE_LEN]);
        let session = SessionId::new("session-1").expect("session id");
        assert_eq!(
            encode_session_auth_message(&binding(DeviceLifecycle::Revoked), &session, nonce),
            Err(SessionAuthMessageError::BindingNotEnrolled)
        );
    }

    #[test]
    fn derived_maximum_message_bound_matches_locked_constant() {
        let derived = SESSION_AUTH_DOMAIN_SEPARATOR.len()
            + size_of::<u16>()
            + 4 * (size_of::<u32>() + super::MAX_SESSION_AUTH_IDENTIFIER_BYTES)
            + size_of::<u16>()
            + size_of::<u16>()
            + size_of::<u32>()
            + super::MAX_SESSION_AUTH_PUBLIC_IDENTITY_BYTES
            + SESSION_AUTH_NONCE_LEN;
        assert_eq!(derived, MAX_SESSION_AUTH_MESSAGE_BYTES);
        assert_eq!(derived, 4442);
    }
}
