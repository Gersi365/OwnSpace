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
        encode_enrollment_proof_message,
    },
};
use prw_core::{DeviceId, EnrollmentId, UserId, WorkspaceId};
use prw_device_identity::{
    DeviceIdentityVerificationError, EnrollmentProofVerificationError,
    verify_device_identity_signature, verify_enrollment_proof,
};

fn generate_disposable_key() -> (Vec<u8>, EcdsaKeyPair, PublicIdentityMaterial) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate disposable P-256 PKCS#8");
    let pkcs8_bytes = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_bytes)
        .expect("reload disposable P-256 PKCS#8");
    let public_der = key_pair
        .public_key()
        .as_der()
        .expect("serialize canonical X.509 SPKI");
    let public_identity = PublicIdentityMaterial::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
        public_der.as_ref().to_vec(),
    )
    .expect("construct public identity");

    (pkcs8_bytes, key_pair, public_identity)
}

fn sign_message(key_pair: &EcdsaKeyPair, message: &[u8]) -> DeviceIdentitySignature {
    let rng = SystemRandom::new();
    let signature = key_pair
        .sign(&rng, message)
        .expect("sign disposable test message");
    DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        signature.as_ref().to_vec(),
    )
    .expect("construct typed DER ECDSA signature")
}

fn enrollment_request(public_identity: PublicIdentityMaterial) -> EnrollmentRequest {
    EnrollmentRequest {
        enrollment_id: EnrollmentId::new("phase119-enrollment").expect("valid enrollment id"),
        workspace_id: WorkspaceId::new("phase119-workspace").expect("valid workspace id"),
        user_id: UserId::new("phase119-user").expect("valid user id"),
        device_id: DeviceId::new("phase119-device").expect("valid device id"),
        public_identity,
    }
}

#[test]
fn pkcs8_v1_round_trip_preserves_canonical_public_identity() {
    let (generated_pkcs8, reloaded, public_identity) = generate_disposable_key();

    assert!(!generated_pkcs8.is_empty());
    assert_eq!(generated_pkcs8[0], 0x30, "PKCS#8 must be DER SEQUENCE");

    let reserialized = reloaded.to_pkcs8v1().expect("re-serialize PKCS#8 v1");
    let reloaded_again =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, reserialized.as_ref())
            .expect("reload re-serialized PKCS#8 v1");
    let public_again = reloaded_again
        .public_key()
        .as_der()
        .expect("serialize reloaded X.509 SPKI");

    assert_eq!(public_again.as_ref(), public_identity.as_bytes());
}

#[test]
fn asn1_der_signature_verifies_through_production_verifier() {
    let (_, key_pair, public_identity) = generate_disposable_key();
    let message = b"PRW Phase 119 disposable signer compatibility message";
    let signature = sign_message(&key_pair, message);

    assert_eq!(signature.as_bytes().first(), Some(&0x30));
    verify_device_identity_signature(&public_identity, message, &signature)
        .expect("production verifier accepts AWS-LC ASN.1 DER signature");
}

#[test]
fn full_enrollment_pop_from_reloaded_pkcs8_verifies_and_consumes_once() {
    let (_, key_pair, public_identity) = generate_disposable_key();
    let request = enrollment_request(public_identity);
    let nonce = EnrollmentProofNonce::new([0x42; 32]);
    let message = encode_enrollment_proof_message(&request, nonce)
        .expect("encode canonical enrollment PoP message");
    let signature = sign_message(&key_pair, &message);
    let proof = EnrollmentProofOfPossession::new(request.enrollment_id.clone(), nonce, signature);
    let mut state = EnrollmentProofChallengeState::new(request, nonce, 1_000, 1_200)
        .expect("valid server challenge state");

    verify_enrollment_proof(&mut state, &proof, 1_001).expect("valid disposable enrollment proof");
    assert!(state.is_consumed());

    assert!(matches!(
        verify_enrollment_proof(&mut state, &proof, 1_002),
        Err(EnrollmentProofVerificationError::Submission(_))
    ));
}

#[test]
fn signature_from_different_private_key_is_rejected_without_consuming_challenge() {
    let (_, _, public_identity) = generate_disposable_key();
    let (_, wrong_key, _) = generate_disposable_key();
    let request = enrollment_request(public_identity);
    let nonce = EnrollmentProofNonce::new([0x43; 32]);
    let message = encode_enrollment_proof_message(&request, nonce)
        .expect("encode canonical enrollment PoP message");
    let signature = sign_message(&wrong_key, &message);
    let proof = EnrollmentProofOfPossession::new(request.enrollment_id.clone(), nonce, signature);
    let mut state = EnrollmentProofChallengeState::new(request, nonce, 2_000, 2_200)
        .expect("valid server challenge state");

    assert!(matches!(
        verify_enrollment_proof(&mut state, &proof, 2_001),
        Err(EnrollmentProofVerificationError::DeviceIdentity(
            DeviceIdentityVerificationError::InvalidSignature
        ))
    ));
    assert!(!state.is_consumed());
}

#[test]
fn signature_over_mutated_canonical_message_is_rejected_without_consuming_challenge() {
    let (_, key_pair, public_identity) = generate_disposable_key();
    let request = enrollment_request(public_identity);
    let nonce = EnrollmentProofNonce::new([0x44; 32]);
    let mut wrong_message = encode_enrollment_proof_message(&request, nonce)
        .expect("encode canonical enrollment PoP message");
    let last = wrong_message
        .last_mut()
        .expect("canonical enrollment PoP message is non-empty");
    *last ^= 0x01;
    let signature = sign_message(&key_pair, &wrong_message);
    let proof = EnrollmentProofOfPossession::new(request.enrollment_id.clone(), nonce, signature);
    let mut state = EnrollmentProofChallengeState::new(request, nonce, 3_000, 3_200)
        .expect("valid server challenge state");

    assert!(matches!(
        verify_enrollment_proof(&mut state, &proof, 3_001),
        Err(EnrollmentProofVerificationError::DeviceIdentity(
            DeviceIdentityVerificationError::InvalidSignature
        ))
    ));
    assert!(!state.is_consumed());
}

#[test]
fn truncated_pkcs8_is_rejected() {
    let (mut pkcs8, _, _) = generate_disposable_key();
    pkcs8.pop().expect("generated PKCS#8 is non-empty");

    assert!(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).is_err());
}
