//! Provider-neutral enrollment proof-of-possession domain and canonical message encoding.
//!
//! This module defines challenge, proof, replay-state, and byte-encoding semantics only.
//! It does not generate random challenges, sign messages, verify cryptographic signatures,
//! persist state, authenticate an approving actor, or expose a network protocol.

use std::fmt;

use prw_core::EnrollmentId;

use crate::{
    DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, DeviceIdentitySignature,
    EnrollmentRequest,
};

/// Exact Phase 114 proof-of-possession domain separator.
pub const ENROLLMENT_PROOF_DOMAIN_SEPARATOR: &[u8; 32] = b"PRW\0EnrollmentProofOfPossession\0";
/// Initial canonical proof-message version.
pub const ENROLLMENT_PROOF_MESSAGE_VERSION: u16 = 1;
/// Exact challenge nonce length in bytes.
pub const ENROLLMENT_PROOF_NONCE_LEN: usize = 32;
/// Maximum UTF-8 byte length for each identifier in a proof message.
pub const MAX_ENROLLMENT_PROOF_IDENTIFIER_BYTES: usize = 1024;
/// Maximum public-identity byte length for the locked initial P-256 SPKI profile.
pub const MAX_ENROLLMENT_PROOF_PUBLIC_IDENTITY_BYTES: usize = 256;
/// Maximum canonical Phase 114 proof-message length in bytes.
pub const MAX_ENROLLMENT_PROOF_MESSAGE_BYTES: usize = 4442;
/// Maximum server challenge lifetime in seconds.
pub const MAX_ENROLLMENT_PROOF_CHALLENGE_LIFETIME_SECONDS: u64 = 300;

const ECDSA_P256_SHA256_CODE: u16 = 1;
const SUBJECT_PUBLIC_KEY_INFO_DER_CODE: u16 = 1;

/// Exact 256-bit server challenge nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnrollmentProofNonce([u8; ENROLLMENT_PROOF_NONCE_LEN]);

impl EnrollmentProofNonce {
    /// Creates a nonce from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; ENROLLMENT_PROOF_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENROLLMENT_PROOF_NONCE_LEN] {
        &self.0
    }

    /// Copies an exact-length byte slice into a nonce.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentProofNonceError::InvalidLength`] when the slice is not
    /// exactly 32 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, EnrollmentProofNonceError> {
        let bytes: [u8; ENROLLMENT_PROOF_NONCE_LEN] = bytes
            .try_into()
            .map_err(|_| EnrollmentProofNonceError::InvalidLength)?;
        Ok(Self(bytes))
    }
}

/// Invalid proof nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentProofNonceError {
    /// The nonce was not exactly 32 bytes.
    InvalidLength,
}

impl fmt::Display for EnrollmentProofNonceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("enrollment proof nonce must be 32 bytes"),
        }
    }
}

impl std::error::Error for EnrollmentProofNonceError {}

/// Server-issued enrollment proof challenge visible to the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProofChallenge {
    enrollment_id: EnrollmentId,
    nonce: EnrollmentProofNonce,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl EnrollmentProofChallenge {
    /// Returns the enrollment request identifier bound to this challenge.
    #[must_use]
    pub const fn enrollment_id(&self) -> &EnrollmentId {
        &self.enrollment_id
    }

    /// Returns the exact server challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> EnrollmentProofNonce {
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

/// Device proof submission. Security-critical binding fields are reconstructed by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProofOfPossession {
    enrollment_id: EnrollmentId,
    nonce: EnrollmentProofNonce,
    signature: DeviceIdentitySignature,
}

impl EnrollmentProofOfPossession {
    /// Creates a proof value from its enrollment identifier, nonce, and device signature.
    #[must_use]
    pub const fn new(
        enrollment_id: EnrollmentId,
        nonce: EnrollmentProofNonce,
        signature: DeviceIdentitySignature,
    ) -> Self {
        Self {
            enrollment_id,
            nonce,
            signature,
        }
    }

    /// Returns the enrollment identifier supplied by the device.
    #[must_use]
    pub const fn enrollment_id(&self) -> &EnrollmentId {
        &self.enrollment_id
    }

    /// Returns the submitted challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> EnrollmentProofNonce {
        self.nonce
    }

    /// Returns the submitted device-identity signature.
    #[must_use]
    pub const fn signature(&self) -> &DeviceIdentitySignature {
        &self.signature
    }
}

/// Server-side single-active-challenge state bound to one immutable enrollment snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProofChallengeState {
    bound_request: EnrollmentRequest,
    challenge: EnrollmentProofChallenge,
    consumed: bool,
}

impl EnrollmentProofChallengeState {
    /// Creates server challenge state for an immutable enrollment request snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentProofChallengeError::InvalidLifetime`] when the challenge
    /// lifetime is zero, reversed, or exceeds 300 seconds.
    pub fn new(
        bound_request: EnrollmentRequest,
        nonce: EnrollmentProofNonce,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, EnrollmentProofChallengeError> {
        validate_challenge_lifetime(issued_at_unix_seconds, expires_at_unix_seconds)?;
        let enrollment_id = bound_request.enrollment_id.clone();
        Ok(Self {
            bound_request,
            challenge: EnrollmentProofChallenge {
                enrollment_id,
                nonce,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            },
            consumed: false,
        })
    }

    /// Returns the immutable enrollment request snapshot bound to this state.
    #[must_use]
    pub const fn bound_request(&self) -> &EnrollmentRequest {
        &self.bound_request
    }

    /// Returns the current challenge exposed to the device.
    #[must_use]
    pub const fn challenge(&self) -> &EnrollmentProofChallenge {
        &self.challenge
    }

    /// Returns whether successful verification has consumed this challenge.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Replaces the active challenge for the same immutable enrollment snapshot.
    ///
    /// Replacing a challenge invalidates the old nonce and clears consumed state.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentProofChallengeError::InvalidLifetime`] when the replacement
    /// lifetime is invalid.
    pub fn replace_challenge(
        &mut self,
        nonce: EnrollmentProofNonce,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<(), EnrollmentProofChallengeError> {
        validate_challenge_lifetime(issued_at_unix_seconds, expires_at_unix_seconds)?;
        self.challenge = EnrollmentProofChallenge {
            enrollment_id: self.bound_request.enrollment_id.clone(),
            nonce,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        };
        self.consumed = false;
        Ok(())
    }

    /// Validates replay, enrollment, nonce, and verifier-time context before crypto verification.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentProofSubmissionError`] when the challenge is consumed,
    /// not yet valid, expired, or does not match the submitted proof context.
    pub fn validate_submission(
        &self,
        proof: &EnrollmentProofOfPossession,
        now_unix_seconds: u64,
    ) -> Result<(), EnrollmentProofSubmissionError> {
        if self.consumed {
            return Err(EnrollmentProofSubmissionError::Consumed);
        }
        if self.challenge.is_not_yet_valid_at(now_unix_seconds) {
            return Err(EnrollmentProofSubmissionError::NotYetValid);
        }
        if self.challenge.is_expired_at(now_unix_seconds) {
            return Err(EnrollmentProofSubmissionError::Expired);
        }
        if proof.enrollment_id() != &self.bound_request.enrollment_id {
            return Err(EnrollmentProofSubmissionError::EnrollmentMismatch);
        }
        if proof.nonce() != self.challenge.nonce() {
            return Err(EnrollmentProofSubmissionError::NonceMismatch);
        }
        Ok(())
    }

    /// Atomically marks the current in-memory challenge consumed after successful verification.
    ///
    /// This method revalidates the proof context before changing state. A future persistent
    /// control plane must preserve equivalent compare-and-consume semantics transactionally.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentProofSubmissionError`] when the current challenge can no longer
    /// accept the supplied proof.
    pub fn consume_verified(
        &mut self,
        proof: &EnrollmentProofOfPossession,
        now_unix_seconds: u64,
    ) -> Result<(), EnrollmentProofSubmissionError> {
        self.validate_submission(proof, now_unix_seconds)?;
        self.consumed = true;
        Ok(())
    }
}

/// Invalid server challenge lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentProofChallengeError {
    /// Lifetime is zero, reversed, or exceeds the maximum 300-second window.
    InvalidLifetime,
}

impl fmt::Display for EnrollmentProofChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLifetime => {
                formatter.write_str("invalid enrollment proof challenge lifetime")
            }
        }
    }
}

impl std::error::Error for EnrollmentProofChallengeError {}

/// Rejected proof-submission context before or after signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentProofSubmissionError {
    /// The challenge has already been successfully consumed.
    Consumed,
    /// The verifier time precedes the server-recorded issue time.
    NotYetValid,
    /// The challenge has reached or passed its server-recorded expiry time.
    Expired,
    /// The proof references a different enrollment request.
    EnrollmentMismatch,
    /// The proof nonce does not match the current active challenge.
    NonceMismatch,
}

impl fmt::Display for EnrollmentProofSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed => formatter.write_str("enrollment proof challenge already consumed"),
            Self::NotYetValid => formatter.write_str("enrollment proof challenge not yet valid"),
            Self::Expired => formatter.write_str("enrollment proof challenge expired"),
            Self::EnrollmentMismatch => formatter.write_str("enrollment proof enrollment mismatch"),
            Self::NonceMismatch => formatter.write_str("enrollment proof nonce mismatch"),
        }
    }
}

impl std::error::Error for EnrollmentProofSubmissionError {}

/// Proof-message construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentProofMessageError {
    /// One of the bound identifiers is empty or exceeds the PoP-specific byte bound.
    IdentifierOutOfBounds,
    /// Public identity bytes are empty or exceed the initial P-256 SPKI byte bound.
    PublicIdentityOutOfBounds,
    /// The declared device-identity algorithm is not the locked initial profile.
    UnsupportedAlgorithm,
    /// The declared public-key encoding is not the locked initial profile.
    UnsupportedPublicKeyEncoding,
    /// Checked message-length computation failed or exceeded the locked maximum.
    MessageTooLarge,
}

impl fmt::Display for EnrollmentProofMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentifierOutOfBounds => {
                formatter.write_str("enrollment proof identifier out of bounds")
            }
            Self::PublicIdentityOutOfBounds => {
                formatter.write_str("enrollment proof public identity out of bounds")
            }
            Self::UnsupportedAlgorithm => {
                formatter.write_str("unsupported enrollment proof identity algorithm")
            }
            Self::UnsupportedPublicKeyEncoding => {
                formatter.write_str("unsupported enrollment proof public-key encoding")
            }
            Self::MessageTooLarge => formatter.write_str("enrollment proof message too large"),
        }
    }
}

impl std::error::Error for EnrollmentProofMessageError {}

/// Constructs the exact Phase 114 canonical enrollment proof message.
///
/// The caller supplies only the immutable server-side enrollment snapshot and the
/// exact server challenge nonce. Challenge timestamps are deliberately not encoded.
///
/// # Errors
///
/// Returns [`EnrollmentProofMessageError`] when identifiers/public identity bytes
/// exceed their proof-specific bounds, the identity profile is unsupported, or
/// checked message-size computation fails.
pub fn encode_enrollment_proof_message(
    request: &EnrollmentRequest,
    nonce: EnrollmentProofNonce,
) -> Result<Vec<u8>, EnrollmentProofMessageError> {
    let enrollment_id = bounded_identifier(request.enrollment_id.as_str().as_bytes())?;
    let workspace_id = bounded_identifier(request.workspace_id.as_str().as_bytes())?;
    let user_id = bounded_identifier(request.user_id.as_str().as_bytes())?;
    let device_id = bounded_identifier(request.device_id.as_str().as_bytes())?;
    let public_identity = request.public_identity.as_bytes();
    if public_identity.is_empty()
        || public_identity.len() > MAX_ENROLLMENT_PROOF_PUBLIC_IDENTITY_BYTES
    {
        return Err(EnrollmentProofMessageError::PublicIdentityOutOfBounds);
    }

    let algorithm_code = match request.public_identity.algorithm() {
        DeviceIdentityAlgorithm::EcdsaP256Sha256 => ECDSA_P256_SHA256_CODE,
    };
    let encoding_code = match request.public_identity.encoding() {
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer => {
            SUBJECT_PUBLIC_KEY_INFO_DER_CODE
        }
    };

    let message_len = ENROLLMENT_PROOF_DOMAIN_SEPARATOR
        .len()
        .checked_add(size_of::<u16>())
        .and_then(|len| len.checked_add(length_prefixed_size(enrollment_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(workspace_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(user_id)))
        .and_then(|len| len.checked_add(length_prefixed_size(device_id)))
        .and_then(|len| len.checked_add(size_of::<u16>() * 2))
        .and_then(|len| len.checked_add(length_prefixed_size(public_identity)))
        .and_then(|len| len.checked_add(ENROLLMENT_PROOF_NONCE_LEN))
        .ok_or(EnrollmentProofMessageError::MessageTooLarge)?;

    if message_len > MAX_ENROLLMENT_PROOF_MESSAGE_BYTES {
        return Err(EnrollmentProofMessageError::MessageTooLarge);
    }

    let mut message = Vec::with_capacity(message_len);
    message.extend_from_slice(ENROLLMENT_PROOF_DOMAIN_SEPARATOR);
    message.extend_from_slice(&ENROLLMENT_PROOF_MESSAGE_VERSION.to_be_bytes());
    push_length_prefixed(&mut message, enrollment_id)?;
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
) -> Result<(), EnrollmentProofChallengeError> {
    let lifetime = expires_at_unix_seconds
        .checked_sub(issued_at_unix_seconds)
        .filter(|lifetime| {
            *lifetime > 0 && *lifetime <= MAX_ENROLLMENT_PROOF_CHALLENGE_LIFETIME_SECONDS
        })
        .ok_or(EnrollmentProofChallengeError::InvalidLifetime)?;
    debug_assert!(lifetime <= MAX_ENROLLMENT_PROOF_CHALLENGE_LIFETIME_SECONDS);
    Ok(())
}

const fn bounded_identifier(bytes: &[u8]) -> Result<&[u8], EnrollmentProofMessageError> {
    if bytes.is_empty() || bytes.len() > MAX_ENROLLMENT_PROOF_IDENTIFIER_BYTES {
        return Err(EnrollmentProofMessageError::IdentifierOutOfBounds);
    }
    Ok(bytes)
}

const fn length_prefixed_size(bytes: &[u8]) -> usize {
    size_of::<u32>() + bytes.len()
}

fn push_length_prefixed(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), EnrollmentProofMessageError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| EnrollmentProofMessageError::MessageTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use prw_core::{DeviceId, EnrollmentId, UserId, WorkspaceId};

    use super::{
        ENROLLMENT_PROOF_DOMAIN_SEPARATOR, ENROLLMENT_PROOF_MESSAGE_VERSION,
        EnrollmentProofChallengeError, EnrollmentProofChallengeState, EnrollmentProofMessageError,
        EnrollmentProofNonce, EnrollmentProofNonceError, EnrollmentProofOfPossession,
        EnrollmentProofSubmissionError, MAX_ENROLLMENT_PROOF_CHALLENGE_LIFETIME_SECONDS,
        MAX_ENROLLMENT_PROOF_IDENTIFIER_BYTES, MAX_ENROLLMENT_PROOF_MESSAGE_BYTES,
        MAX_ENROLLMENT_PROOF_PUBLIC_IDENTITY_BYTES, encode_enrollment_proof_message,
    };
    use crate::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, DeviceIdentitySignature,
        DeviceIdentitySignatureEncoding, EnrollmentRequest, PublicIdentityMaterial,
    };

    fn request_with(
        enrollment_id: &str,
        workspace_id: &str,
        user_id: &str,
        device_id: &str,
        public_identity: Vec<u8>,
    ) -> EnrollmentRequest {
        EnrollmentRequest {
            enrollment_id: EnrollmentId::new(enrollment_id).expect("valid enrollment id"),
            workspace_id: WorkspaceId::new(workspace_id).expect("valid workspace id"),
            user_id: UserId::new(user_id).expect("valid user id"),
            device_id: DeviceId::new(device_id).expect("valid device id"),
            public_identity: PublicIdentityMaterial::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
                public_identity,
            )
            .expect("non-empty identity"),
        }
    }

    fn request() -> EnrollmentRequest {
        request_with("e", "w", "u", "d", vec![1, 2, 3])
    }

    fn signature() -> DeviceIdentitySignature {
        DeviceIdentitySignature::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
            vec![0x30, 0x01, 0x00],
        )
        .expect("non-empty signature")
    }

    #[test]
    fn domain_separator_and_version_are_locked() {
        assert_eq!(ENROLLMENT_PROOF_DOMAIN_SEPARATOR.len(), 32);
        assert_eq!(ENROLLMENT_PROOF_MESSAGE_VERSION, 1);
    }

    #[test]
    fn nonce_requires_exactly_32_bytes() {
        assert_eq!(
            EnrollmentProofNonce::try_from_slice(&[0_u8; 31]),
            Err(EnrollmentProofNonceError::InvalidLength)
        );
        assert_eq!(
            EnrollmentProofNonce::try_from_slice(&[0_u8; 33]),
            Err(EnrollmentProofNonceError::InvalidLength)
        );
        assert_eq!(
            EnrollmentProofNonce::try_from_slice(&[7_u8; 32]),
            Ok(EnrollmentProofNonce::new([7_u8; 32]))
        );
    }

    #[test]
    fn canonical_message_has_exact_locked_bytes() {
        let nonce = EnrollmentProofNonce::new([0xaa; 32]);
        let actual =
            encode_enrollment_proof_message(&request(), nonce).expect("encode proof message");
        let expected: Vec<u8> = vec![
            0x50, 0x52, 0x57, 0x00, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74,
            0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4f, 0x66, 0x50, 0x6f, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x65, 0x00, 0x00, 0x00,
            0x01, 0x77, 0x00, 0x00, 0x00, 0x01, 0x75, 0x00, 0x00, 0x00, 0x01, 0x64, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn every_bound_field_changes_the_message() {
        let nonce = EnrollmentProofNonce::new([1_u8; 32]);
        let baseline = encode_enrollment_proof_message(&request(), nonce).expect("baseline");
        let variants = [
            request_with("e2", "w", "u", "d", vec![1, 2, 3]),
            request_with("e", "w2", "u", "d", vec![1, 2, 3]),
            request_with("e", "w", "u2", "d", vec![1, 2, 3]),
            request_with("e", "w", "u", "d2", vec![1, 2, 3]),
            request_with("e", "w", "u", "d", vec![1, 2, 4]),
        ];
        for variant in variants {
            assert_ne!(
                encode_enrollment_proof_message(&variant, nonce).expect("variant"),
                baseline
            );
        }
        assert_ne!(
            encode_enrollment_proof_message(&request(), EnrollmentProofNonce::new([2_u8; 32]))
                .expect("nonce variant"),
            baseline
        );
    }

    #[test]
    fn maximum_locked_message_size_is_exactly_4442_bytes() {
        let id = "x".repeat(MAX_ENROLLMENT_PROOF_IDENTIFIER_BYTES);
        let request = request_with(
            &id,
            &id,
            &id,
            &id,
            vec![0x55; MAX_ENROLLMENT_PROOF_PUBLIC_IDENTITY_BYTES],
        );
        let message =
            encode_enrollment_proof_message(&request, EnrollmentProofNonce::new([3_u8; 32]))
                .expect("maximum bounded message");
        assert_eq!(message.len(), MAX_ENROLLMENT_PROOF_MESSAGE_BYTES);
        assert_eq!(message.len(), 4442);
    }

    #[test]
    fn identifier_and_public_identity_bounds_fail_closed() {
        let overlong_id = "x".repeat(MAX_ENROLLMENT_PROOF_IDENTIFIER_BYTES + 1);
        let request = request_with(&overlong_id, "w", "u", "d", vec![1]);
        assert_eq!(
            encode_enrollment_proof_message(&request, EnrollmentProofNonce::new([4_u8; 32])),
            Err(EnrollmentProofMessageError::IdentifierOutOfBounds)
        );

        let request = request_with(
            "e",
            "w",
            "u",
            "d",
            vec![1; MAX_ENROLLMENT_PROOF_PUBLIC_IDENTITY_BYTES + 1],
        );
        assert_eq!(
            encode_enrollment_proof_message(&request, EnrollmentProofNonce::new([4_u8; 32])),
            Err(EnrollmentProofMessageError::PublicIdentityOutOfBounds)
        );
    }

    #[test]
    fn challenge_lifetime_accepts_one_through_300_seconds_only() {
        let request = request();
        let nonce = EnrollmentProofNonce::new([5_u8; 32]);
        assert!(EnrollmentProofChallengeState::new(request.clone(), nonce, 100, 101).is_ok());
        assert!(
            EnrollmentProofChallengeState::new(
                request.clone(),
                nonce,
                100,
                100 + MAX_ENROLLMENT_PROOF_CHALLENGE_LIFETIME_SECONDS,
            )
            .is_ok()
        );
        assert_eq!(
            EnrollmentProofChallengeState::new(request.clone(), nonce, 100, 100),
            Err(EnrollmentProofChallengeError::InvalidLifetime)
        );
        assert_eq!(
            EnrollmentProofChallengeState::new(request.clone(), nonce, 100, 99),
            Err(EnrollmentProofChallengeError::InvalidLifetime)
        );
        assert_eq!(
            EnrollmentProofChallengeState::new(request, nonce, 100, 401),
            Err(EnrollmentProofChallengeError::InvalidLifetime)
        );
    }

    #[test]
    fn server_time_enforces_not_yet_valid_and_expiry_boundaries() {
        let state = EnrollmentProofChallengeState::new(
            request(),
            EnrollmentProofNonce::new([6_u8; 32]),
            100,
            200,
        )
        .expect("valid challenge");
        let proof = EnrollmentProofOfPossession::new(
            state.bound_request().enrollment_id.clone(),
            state.challenge().nonce(),
            signature(),
        );
        assert_eq!(
            state.validate_submission(&proof, 99),
            Err(EnrollmentProofSubmissionError::NotYetValid)
        );
        assert_eq!(state.validate_submission(&proof, 100), Ok(()));
        assert_eq!(state.validate_submission(&proof, 199), Ok(()));
        assert_eq!(
            state.validate_submission(&proof, 200),
            Err(EnrollmentProofSubmissionError::Expired)
        );
    }

    #[test]
    fn successful_consume_is_single_use() {
        let mut state = EnrollmentProofChallengeState::new(
            request(),
            EnrollmentProofNonce::new([7_u8; 32]),
            100,
            200,
        )
        .expect("valid challenge");
        let proof = EnrollmentProofOfPossession::new(
            state.bound_request().enrollment_id.clone(),
            state.challenge().nonce(),
            signature(),
        );
        state.consume_verified(&proof, 150).expect("consume once");
        assert!(state.is_consumed());
        assert_eq!(
            state.consume_verified(&proof, 150),
            Err(EnrollmentProofSubmissionError::Consumed)
        );
    }

    #[test]
    fn mismatched_enrollment_and_nonce_are_rejected() {
        let state = EnrollmentProofChallengeState::new(
            request(),
            EnrollmentProofNonce::new([8_u8; 32]),
            100,
            200,
        )
        .expect("valid challenge");
        let wrong_enrollment = EnrollmentProofOfPossession::new(
            EnrollmentId::new("other").expect("valid id"),
            state.challenge().nonce(),
            signature(),
        );
        assert_eq!(
            state.validate_submission(&wrong_enrollment, 150),
            Err(EnrollmentProofSubmissionError::EnrollmentMismatch)
        );
        let wrong_nonce = EnrollmentProofOfPossession::new(
            state.bound_request().enrollment_id.clone(),
            EnrollmentProofNonce::new([9_u8; 32]),
            signature(),
        );
        assert_eq!(
            state.validate_submission(&wrong_nonce, 150),
            Err(EnrollmentProofSubmissionError::NonceMismatch)
        );
    }

    #[test]
    fn replacement_challenge_supersedes_old_nonce_and_clears_consumed_state() {
        let mut state = EnrollmentProofChallengeState::new(
            request(),
            EnrollmentProofNonce::new([10_u8; 32]),
            100,
            200,
        )
        .expect("valid challenge");
        let old_proof = EnrollmentProofOfPossession::new(
            state.bound_request().enrollment_id.clone(),
            state.challenge().nonce(),
            signature(),
        );
        state
            .consume_verified(&old_proof, 150)
            .expect("consume old");
        state
            .replace_challenge(EnrollmentProofNonce::new([11_u8; 32]), 201, 301)
            .expect("replace challenge");
        assert!(!state.is_consumed());
        assert_eq!(
            state.validate_submission(&old_proof, 250),
            Err(EnrollmentProofSubmissionError::NonceMismatch)
        );
    }
}
