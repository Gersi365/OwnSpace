use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, DeviceIdentitySignature,
    DeviceIdentitySignatureEncoding, EnrollmentRequest, PublicIdentityMaterial,
    enrollment_pop::{
        EnrollmentProofChallengeState, EnrollmentProofNonce, EnrollmentProofOfPossession,
        EnrollmentProofSubmissionError, encode_enrollment_proof_message,
    },
};
use prw_core::{DeviceId, EnrollmentId, UserId, WorkspaceId};
use prw_device_identity::{
    DeviceIdentityVerificationError, EnrollmentProofVerificationError, verify_enrollment_proof,
};

fn key_and_request(user_id: &str) -> (EcdsaKeyPair, EnrollmentRequest) {
    let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
        .expect("generate disposable enrollment test key");
    let public_der = key_pair
        .public_key()
        .as_der()
        .expect("serialize test key as SPKI DER");
    let request = EnrollmentRequest {
        enrollment_id: EnrollmentId::new("enrollment-115").expect("valid enrollment id"),
        workspace_id: WorkspaceId::new("workspace-115").expect("valid workspace id"),
        user_id: UserId::new(user_id).expect("valid user id"),
        device_id: DeviceId::new("device-115").expect("valid device id"),
        public_identity: PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            public_der.as_ref().to_vec(),
        )
        .expect("non-empty public identity"),
    };
    (key_pair, request)
}

fn state_for(request: EnrollmentRequest, nonce_byte: u8) -> EnrollmentProofChallengeState {
    EnrollmentProofChallengeState::new(
        request,
        EnrollmentProofNonce::new([nonce_byte; 32]),
        1_000,
        1_300,
    )
    .expect("valid challenge state")
}

fn sign_message(key_pair: &EcdsaKeyPair, message: &[u8]) -> DeviceIdentitySignature {
    let signature = key_pair
        .sign(&SystemRandom::new(), message)
        .expect("sign enrollment proof message");
    DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        signature.as_ref().to_vec(),
    )
    .expect("non-empty signature")
}

fn valid_proof(
    key_pair: &EcdsaKeyPair,
    state: &EnrollmentProofChallengeState,
) -> EnrollmentProofOfPossession {
    let message = encode_enrollment_proof_message(state.bound_request(), state.challenge().nonce())
        .expect("encode enrollment proof message");
    EnrollmentProofOfPossession::new(
        state.bound_request().enrollment_id.clone(),
        state.challenge().nonce(),
        sign_message(key_pair, &message),
    )
}

#[test]
fn valid_proof_consumes_challenge_exactly_once() {
    let (key_pair, request) = key_and_request("user-115");
    let mut state = state_for(request, 1);
    let proof = valid_proof(&key_pair, &state);

    assert_eq!(verify_enrollment_proof(&mut state, &proof, 1_100), Ok(()));
    assert!(state.is_consumed());
    assert_eq!(
        verify_enrollment_proof(&mut state, &proof, 1_100),
        Err(EnrollmentProofVerificationError::Submission(
            EnrollmentProofSubmissionError::Consumed
        ))
    );
}

#[test]
fn invalid_signature_does_not_consume_challenge() {
    let (key_pair, request) = key_and_request("user-115");
    let mut state = state_for(request, 2);
    let valid = valid_proof(&key_pair, &state);
    let mut bytes = valid.signature().as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let invalid_signature = DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        bytes,
    )
    .expect("non-empty signature");
    let proof = EnrollmentProofOfPossession::new(
        valid.enrollment_id().clone(),
        valid.nonce(),
        invalid_signature,
    );

    assert_eq!(
        verify_enrollment_proof(&mut state, &proof, 1_100),
        Err(EnrollmentProofVerificationError::DeviceIdentity(
            DeviceIdentityVerificationError::InvalidSignature
        ))
    );
    assert!(!state.is_consumed());

    let retry = valid_proof(&key_pair, &state);
    assert_eq!(verify_enrollment_proof(&mut state, &retry, 1_100), Ok(()));
}

#[test]
fn wrong_nonce_is_rejected_before_crypto_and_does_not_consume() {
    let (key_pair, request) = key_and_request("user-115");
    let mut state = state_for(request, 3);
    let valid = valid_proof(&key_pair, &state);
    let wrong_nonce = EnrollmentProofOfPossession::new(
        valid.enrollment_id().clone(),
        EnrollmentProofNonce::new([4_u8; 32]),
        valid.signature().clone(),
    );

    assert_eq!(
        verify_enrollment_proof(&mut state, &wrong_nonce, 1_100),
        Err(EnrollmentProofVerificationError::Submission(
            EnrollmentProofSubmissionError::NonceMismatch
        ))
    );
    assert!(!state.is_consumed());
}

#[test]
fn expired_challenge_is_rejected_without_consumption() {
    let (key_pair, request) = key_and_request("user-115");
    let mut state = state_for(request, 5);
    let proof = valid_proof(&key_pair, &state);

    assert_eq!(
        verify_enrollment_proof(&mut state, &proof, 1_300),
        Err(EnrollmentProofVerificationError::Submission(
            EnrollmentProofSubmissionError::Expired
        ))
    );
    assert!(!state.is_consumed());
}

#[test]
fn signature_for_changed_snapshot_fails_against_bound_snapshot() {
    let (key_pair, request) = key_and_request("user-original");
    let mut state = state_for(request.clone(), 6);

    let mut changed_request = request;
    changed_request.user_id = UserId::new("user-changed").expect("valid changed user id");
    let changed_message =
        encode_enrollment_proof_message(&changed_request, state.challenge().nonce())
            .expect("encode changed snapshot message");
    let proof = EnrollmentProofOfPossession::new(
        state.bound_request().enrollment_id.clone(),
        state.challenge().nonce(),
        sign_message(&key_pair, &changed_message),
    );

    assert_eq!(
        verify_enrollment_proof(&mut state, &proof, 1_100),
        Err(EnrollmentProofVerificationError::DeviceIdentity(
            DeviceIdentityVerificationError::InvalidSignature
        ))
    );
    assert!(!state.is_consumed());
}

#[test]
fn replacement_challenge_invalidates_old_proof() {
    let (key_pair, request) = key_and_request("user-115");
    let mut state = state_for(request, 7);
    let old_proof = valid_proof(&key_pair, &state);

    state
        .replace_challenge(EnrollmentProofNonce::new([8_u8; 32]), 1_301, 1_601)
        .expect("replace challenge");

    assert_eq!(
        verify_enrollment_proof(&mut state, &old_proof, 1_400),
        Err(EnrollmentProofVerificationError::Submission(
            EnrollmentProofSubmissionError::NonceMismatch
        ))
    );
    assert!(!state.is_consumed());
}
