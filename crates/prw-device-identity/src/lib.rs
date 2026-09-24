//! Production device-identity public signature verification for Ownspace.
//!
//! This crate owns the provider-specific verification boundary for the locked PRW
//! device-identity profile. It deliberately exposes no private-key generation,
//! private-key import/export, signing, persistence, or transport-cryptography API.

use std::fmt;

use aws_lc_rs::{
    encoding::{AsDer, PublicKeyX509Der},
    signature::{ECDSA_P256_SHA256_ASN1, ParsedPublicKey},
};
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, DeviceIdentitySignature,
    DeviceIdentitySignatureEncoding, PublicIdentityMaterial,
    enrollment_pop::{
        EnrollmentProofChallengeState, EnrollmentProofMessageError, EnrollmentProofOfPossession,
        EnrollmentProofSubmissionError, encode_enrollment_proof_message,
    },
    session_auth::{
        SessionAuthChallengeState, SessionAuthMessageError, SessionAuthProof,
        SessionAuthSubmissionError, encode_session_auth_message,
    },
};

/// Failure while verifying the locked PRW device-identity profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIdentityVerificationError {
    /// The declared algorithm or encoding does not match the locked PRW profile.
    UnsupportedProfile,
    /// Public-key bytes are malformed or incompatible with the locked P-256 profile.
    InvalidPublicKey,
    /// The key is valid but is not the exact canonical DER SPKI representation.
    NonCanonicalPublicKeyEncoding,
    /// Signature verification failed or the signature encoding is malformed.
    InvalidSignature,
}

impl fmt::Display for DeviceIdentityVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile => formatter.write_str("unsupported device identity profile"),
            Self::InvalidPublicKey => formatter.write_str("invalid device identity public key"),
            Self::NonCanonicalPublicKeyEncoding => {
                formatter.write_str("device identity public key is not canonical DER SPKI")
            }
            Self::InvalidSignature => formatter.write_str("invalid device identity signature"),
        }
    }
}

impl std::error::Error for DeviceIdentityVerificationError {}

/// Failure while validating and cryptographically verifying an enrollment proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnrollmentProofVerificationError {
    /// Server-side challenge/replay context rejected the proof submission.
    Submission(EnrollmentProofSubmissionError),
    /// The bound enrollment snapshot could not be encoded under the locked message contract.
    Message(EnrollmentProofMessageError),
    /// Device-identity public-key or signature verification failed.
    DeviceIdentity(DeviceIdentityVerificationError),
}

impl fmt::Display for EnrollmentProofVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submission(error) => {
                write!(formatter, "enrollment proof submission rejected: {error}")
            }
            Self::Message(error) => write!(formatter, "enrollment proof message rejected: {error}"),
            Self::DeviceIdentity(error) => {
                write!(
                    formatter,
                    "enrollment proof device identity rejected: {error}"
                )
            }
        }
    }
}

impl std::error::Error for EnrollmentProofVerificationError {}

/// Failure while validating and cryptographically verifying a device session proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionAuthVerificationError {
    /// Server-side challenge/replay context rejected the proof submission.
    Submission(SessionAuthSubmissionError),
    /// The bound enrolled identity could not be encoded under the locked message contract.
    Message(SessionAuthMessageError),
    /// Device-identity public-key or signature verification failed.
    DeviceIdentity(DeviceIdentityVerificationError),
}

impl fmt::Display for SessionAuthVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submission(error) => {
                write!(
                    formatter,
                    "session authentication submission rejected: {error}"
                )
            }
            Self::Message(error) => {
                write!(
                    formatter,
                    "session authentication message rejected: {error}"
                )
            }
            Self::DeviceIdentity(error) => {
                write!(
                    formatter,
                    "session authentication device identity rejected: {error}"
                )
            }
        }
    }
}

impl std::error::Error for SessionAuthVerificationError {}

/// Verifies a signature under the locked PRW device-identity profile.
///
/// The accepted profile is exactly:
///
/// - ECDSA over NIST P-256 with SHA-256;
/// - DER X.509 `SubjectPublicKeyInfo` public keys;
/// - DER RFC 3279 `ECDSA-Sig-Value` signatures.
///
/// Provider input flexibility is intentionally narrower at the PRW boundary. The
/// parsed key is re-serialized as canonical X.509 DER and must match the supplied
/// bytes exactly before the signature is verified. This rejects alternate public-key
/// encodings such as raw SEC1 points even if the provider can parse them.
///
/// # Errors
///
/// Returns [`DeviceIdentityVerificationError`] when the declared profile is not the
/// locked profile, when the public key is invalid or non-canonical, or when signature
/// verification fails.
pub fn verify_device_identity_signature(
    public_identity: &PublicIdentityMaterial,
    message: &[u8],
    signature: &DeviceIdentitySignature,
) -> Result<(), DeviceIdentityVerificationError> {
    if public_identity.algorithm() != DeviceIdentityAlgorithm::EcdsaP256Sha256
        || public_identity.encoding() != DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer
        || signature.algorithm() != DeviceIdentityAlgorithm::EcdsaP256Sha256
        || signature.encoding() != DeviceIdentitySignatureEncoding::EcdsaSigValueDer
    {
        return Err(DeviceIdentityVerificationError::UnsupportedProfile);
    }

    let parsed = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_identity.as_bytes())
        .map_err(|_| DeviceIdentityVerificationError::InvalidPublicKey)?;
    let canonical: PublicKeyX509Der<'static> = parsed
        .as_der()
        .map_err(|_| DeviceIdentityVerificationError::InvalidPublicKey)?;

    if canonical.as_ref() != public_identity.as_bytes() {
        return Err(DeviceIdentityVerificationError::NonCanonicalPublicKeyEncoding);
    }

    parsed
        .verify_sig(message, signature.as_bytes())
        .map_err(|_| DeviceIdentityVerificationError::InvalidSignature)
}

/// Verifies one enrollment proof against the immutable server-side challenge state.
///
/// Verification order is fail-closed: challenge/replay context, canonical message
/// construction, device-identity signature verification, then single-use consumption.
/// Invalid signatures do not consume the challenge. Successful verification consumes
/// the current in-memory challenge before this function returns.
///
/// This function does not approve enrollment, authenticate an account, persist state,
/// or generate/sign with a private key.
///
/// # Errors
///
/// Returns [`EnrollmentProofVerificationError`] when challenge/replay checks fail,
/// canonical message construction fails, or device-identity verification fails.
pub fn verify_enrollment_proof(
    state: &mut EnrollmentProofChallengeState,
    proof: &EnrollmentProofOfPossession,
    now_unix_seconds: u64,
) -> Result<(), EnrollmentProofVerificationError> {
    state
        .validate_submission(proof, now_unix_seconds)
        .map_err(EnrollmentProofVerificationError::Submission)?;

    let message = encode_enrollment_proof_message(state.bound_request(), state.challenge().nonce())
        .map_err(EnrollmentProofVerificationError::Message)?;

    verify_device_identity_signature(
        &state.bound_request().public_identity,
        &message,
        proof.signature(),
    )
    .map_err(EnrollmentProofVerificationError::DeviceIdentity)?;

    state
        .consume_verified(proof, now_unix_seconds)
        .map_err(EnrollmentProofVerificationError::Submission)
}

/// Verifies one enrolled-device session proof against immutable server challenge state.
///
/// Verification order is fail-closed: challenge/replay context, canonical message
/// construction, device-identity signature verification, then single-use consumption.
/// Invalid signatures do not consume the challenge. Successful verification consumes
/// the current in-memory challenge before this function returns.
///
/// This function authenticates possession of the bound enrolled device identity only.
/// It does not grant capabilities, persist a session, select a transport, or perform
/// account authentication.
///
/// # Errors
///
/// Returns [`SessionAuthVerificationError`] when challenge/replay checks fail,
/// canonical message construction fails, or device-identity verification fails.
pub fn verify_session_auth_proof(
    state: &mut SessionAuthChallengeState,
    proof: &SessionAuthProof,
    now_unix_seconds: u64,
) -> Result<(), SessionAuthVerificationError> {
    state
        .validate_submission(proof, now_unix_seconds)
        .map_err(SessionAuthVerificationError::Submission)?;

    let message = encode_session_auth_message(
        state.bound_identity(),
        state.challenge().session_id(),
        state.challenge().nonce(),
    )
    .map_err(SessionAuthVerificationError::Message)?;

    verify_device_identity_signature(
        &state.bound_identity().public_identity,
        &message,
        proof.signature(),
    )
    .map_err(SessionAuthVerificationError::DeviceIdentity)?;

    state
        .consume_verified(proof, now_unix_seconds)
        .map_err(SessionAuthVerificationError::Submission)
}
