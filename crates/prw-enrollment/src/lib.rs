//! Bounded production enrollment transaction orchestration for Ownspace.
//!
//! This crate composes the locked enrollment proof-of-possession verifier with
//! server-generated challenges and explicit single-use enrollment state. It does
//! not select a network transport, account-authentication mechanism, durable
//! registry, or remote approval UI.

use std::{collections::HashMap, fmt};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_control_plane::{
    DeviceIdentityBinding, EnrollmentRequest,
    enrollment_pop::{
        ENROLLMENT_PROOF_NONCE_LEN, EnrollmentProofChallenge, EnrollmentProofChallengeError,
        EnrollmentProofChallengeState, EnrollmentProofNonce, EnrollmentProofOfPossession,
    },
};
use prw_core::{DeviceId, DeviceLifecycle, EnrollmentId};
use prw_device_identity::{EnrollmentProofVerificationError, verify_enrollment_proof};

/// Enrollment-service failure with bounded, non-secret classifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnrollmentServiceError {
    /// The cryptographic provider could not generate a challenge nonce.
    ChallengeRandomness,
    /// The requested challenge lifetime violated the locked `PoP` bounds.
    InvalidChallengeLifetime,
    /// The enrollment identifier is already pending or completed.
    EnrollmentAlreadyExists,
    /// The device identifier is already enrolled.
    DeviceAlreadyEnrolled,
    /// No pending enrollment exists for the supplied identifier.
    UnknownEnrollment,
    /// The enrollment has already completed successfully.
    EnrollmentAlreadyCompleted,
    /// The proof failed bounded replay, message, public-key, or signature verification.
    ProofRejected,
}

impl fmt::Display for EnrollmentServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ChallengeRandomness => "enrollment challenge randomness failed",
            Self::InvalidChallengeLifetime => "invalid enrollment challenge lifetime",
            Self::EnrollmentAlreadyExists => "enrollment already exists",
            Self::DeviceAlreadyEnrolled => "device already enrolled",
            Self::UnknownEnrollment => "unknown enrollment",
            Self::EnrollmentAlreadyCompleted => "enrollment already completed",
            Self::ProofRejected => "enrollment proof rejected",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EnrollmentServiceError {}

/// In-memory transaction authority for one bounded enrollment service instance.
///
/// Durable workspace/device registry persistence is intentionally deferred to the
/// registry phase. Successful entries remain in-memory for the lifetime of this
/// value so replay and duplicate-device attempts fail closed.
#[derive(Debug, Default)]
pub struct EnrollmentService {
    pending: HashMap<EnrollmentId, EnrollmentProofChallengeState>,
    completed: HashMap<EnrollmentId, DeviceIdentityBinding>,
    enrolled_devices: HashMap<DeviceId, EnrollmentId>,
}

impl EnrollmentService {
    /// Creates an empty fail-closed enrollment service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts one enrollment by generating a fresh 256-bit server challenge.
    ///
    /// # Errors
    ///
    /// Rejects duplicate enrollment identifiers, already-enrolled devices,
    /// invalid challenge lifetimes, and provider randomness failures.
    pub fn begin_enrollment(
        &mut self,
        request: EnrollmentRequest,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<EnrollmentProofChallenge, EnrollmentServiceError> {
        if self.pending.contains_key(&request.enrollment_id)
            || self.completed.contains_key(&request.enrollment_id)
        {
            return Err(EnrollmentServiceError::EnrollmentAlreadyExists);
        }
        if self.enrolled_devices.contains_key(&request.device_id) {
            return Err(EnrollmentServiceError::DeviceAlreadyEnrolled);
        }

        let mut nonce_bytes = [0_u8; ENROLLMENT_PROOF_NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| EnrollmentServiceError::ChallengeRandomness)?;
        let nonce = EnrollmentProofNonce::new(nonce_bytes);
        let state = EnrollmentProofChallengeState::new(
            request,
            nonce,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        )
        .map_err(map_challenge_error)?;
        let challenge = state.challenge().clone();
        let enrollment_id = challenge.enrollment_id().clone();
        self.pending.insert(enrollment_id, state);
        Ok(challenge)
    }

    /// Verifies and completes exactly one pending enrollment.
    ///
    /// Successful verification consumes the challenge before the resulting
    /// enrolled binding is committed to this service's in-memory authority.
    ///
    /// # Errors
    ///
    /// Rejects unknown/completed enrollment identifiers and any invalid proof.
    pub fn submit_proof(
        &mut self,
        enrollment_id: &EnrollmentId,
        proof: &EnrollmentProofOfPossession,
        now_unix_seconds: u64,
    ) -> Result<DeviceIdentityBinding, EnrollmentServiceError> {
        if self.completed.contains_key(enrollment_id) {
            return Err(EnrollmentServiceError::EnrollmentAlreadyCompleted);
        }

        let state = self
            .pending
            .get_mut(enrollment_id)
            .ok_or(EnrollmentServiceError::UnknownEnrollment)?;
        verify_enrollment_proof(state, proof, now_unix_seconds).map_err(map_verification_error)?;

        let request = state.bound_request().clone();
        if self.enrolled_devices.contains_key(&request.device_id) {
            return Err(EnrollmentServiceError::DeviceAlreadyEnrolled);
        }

        let binding = DeviceIdentityBinding {
            workspace_id: request.workspace_id,
            user_id: request.user_id,
            device_id: request.device_id.clone(),
            public_identity: request.public_identity,
            lifecycle: DeviceLifecycle::Enrolled,
        };

        self.enrolled_devices
            .insert(request.device_id, enrollment_id.clone());
        self.completed
            .insert(enrollment_id.clone(), binding.clone());
        self.pending.remove(enrollment_id);
        Ok(binding)
    }

    /// Returns a completed binding by enrollment identifier.
    #[must_use]
    pub fn completed_binding(
        &self,
        enrollment_id: &EnrollmentId,
    ) -> Option<&DeviceIdentityBinding> {
        self.completed.get(enrollment_id)
    }

    /// Returns whether a device identifier is already enrolled in this authority.
    #[must_use]
    pub fn is_device_enrolled(&self, device_id: &DeviceId) -> bool {
        self.enrolled_devices.contains_key(device_id)
    }

    /// Returns the number of currently pending enrollment transactions.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of completed enrollment transactions.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}

const fn map_challenge_error(_error: EnrollmentProofChallengeError) -> EnrollmentServiceError {
    EnrollmentServiceError::InvalidChallengeLifetime
}

const fn map_verification_error(
    _error: EnrollmentProofVerificationError,
) -> EnrollmentServiceError {
    EnrollmentServiceError::ProofRejected
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_control_plane::EnrollmentRequest;
    use prw_core::{DeviceId, DeviceLifecycle, EnrollmentId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;

    use super::{EnrollmentService, EnrollmentServiceError};

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable test key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable test signer")
    }

    fn request(
        signer: &UbuntuEnrollmentSigner,
        enrollment: &str,
        device: &str,
    ) -> EnrollmentRequest {
        EnrollmentRequest {
            enrollment_id: EnrollmentId::new(enrollment).expect("valid enrollment id"),
            workspace_id: WorkspaceId::new("workspace-1").expect("valid workspace id"),
            user_id: UserId::new("user-1").expect("valid user id"),
            device_id: DeviceId::new(device).expect("valid device id"),
            public_identity: signer.public_identity().clone(),
        }
    }

    #[test]
    fn valid_proof_enrolls_exact_bound_device_once() {
        let signer = signer();
        let request = request(&signer, "enrollment-1", "device-1");
        let enrollment_id = request.enrollment_id.clone();
        let device_id = request.device_id.clone();
        let mut service = EnrollmentService::new();
        let challenge = service
            .begin_enrollment(request.clone(), 1_000, 1_300)
            .expect("start enrollment");
        let proof = signer
            .sign_enrollment_proof(&request, &challenge)
            .expect("sign typed enrollment proof");

        let binding = service
            .submit_proof(&enrollment_id, &proof, 1_001)
            .expect("verify enrollment proof");

        assert_eq!(binding.workspace_id, request.workspace_id);
        assert_eq!(binding.user_id, request.user_id);
        assert_eq!(binding.device_id, device_id);
        assert_eq!(binding.public_identity, request.public_identity);
        assert_eq!(binding.lifecycle, DeviceLifecycle::Enrolled);
        assert!(service.is_device_enrolled(&binding.device_id));
        assert_eq!(service.pending_count(), 0);
        assert_eq!(service.completed_count(), 1);
        assert_eq!(service.completed_binding(&enrollment_id), Some(&binding));
        assert_eq!(
            service.submit_proof(&enrollment_id, &proof, 1_002),
            Err(EnrollmentServiceError::EnrollmentAlreadyCompleted)
        );
    }

    #[test]
    fn duplicate_enrollment_identifier_fails_closed() {
        let signer = signer();
        let request = request(&signer, "enrollment-duplicate", "device-a");
        let mut service = EnrollmentService::new();
        service
            .begin_enrollment(request.clone(), 10, 20)
            .expect("first enrollment");

        assert_eq!(
            service.begin_enrollment(request, 10, 20),
            Err(EnrollmentServiceError::EnrollmentAlreadyExists)
        );
    }

    #[test]
    fn invalid_lifetime_creates_no_pending_state() {
        let signer = signer();
        let request = request(&signer, "enrollment-lifetime", "device-lifetime");
        let mut service = EnrollmentService::new();

        assert_eq!(
            service.begin_enrollment(request, 100, 100),
            Err(EnrollmentServiceError::InvalidChallengeLifetime)
        );
        assert_eq!(service.pending_count(), 0);
    }

    #[test]
    fn proof_for_other_enrollment_is_rejected_without_completion() {
        let signer = signer();
        let request_a = request(&signer, "enrollment-a", "device-a");
        let request_b = request(&signer, "enrollment-b", "device-b");
        let enrollment_a = request_a.enrollment_id.clone();
        let mut service = EnrollmentService::new();
        let challenge_a = service
            .begin_enrollment(request_a.clone(), 50, 100)
            .expect("start enrollment a");
        let challenge_b = service
            .begin_enrollment(request_b.clone(), 50, 100)
            .expect("start enrollment b");
        let proof_b = signer
            .sign_enrollment_proof(&request_b, &challenge_b)
            .expect("sign proof b");

        assert_eq!(
            service.submit_proof(&enrollment_a, &proof_b, 51),
            Err(EnrollmentServiceError::ProofRejected)
        );
        assert_eq!(service.completed_count(), 0);
        assert_eq!(service.pending_count(), 2);

        let proof_a = signer
            .sign_enrollment_proof(&request_a, &challenge_a)
            .expect("sign proof a");
        assert!(service.submit_proof(&enrollment_a, &proof_a, 51).is_ok());
    }

    #[test]
    fn already_enrolled_device_cannot_begin_second_enrollment() {
        let signer = signer();
        let first = request(&signer, "enrollment-first", "device-stable");
        let first_id = first.enrollment_id.clone();
        let mut service = EnrollmentService::new();
        let challenge = service
            .begin_enrollment(first.clone(), 1, 100)
            .expect("start first enrollment");
        let proof = signer
            .sign_enrollment_proof(&first, &challenge)
            .expect("sign first proof");
        service
            .submit_proof(&first_id, &proof, 2)
            .expect("complete first enrollment");

        let second = request(&signer, "enrollment-second", "device-stable");
        assert_eq!(
            service.begin_enrollment(second, 3, 100),
            Err(EnrollmentServiceError::DeviceAlreadyEnrolled)
        );
    }
}
