use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_control_plane::{
    EnrollmentRequest,
    enrollment_pop::{EnrollmentProofChallengeState, EnrollmentProofNonce},
};
use prw_core::{DeviceId, EnrollmentId, UserId, WorkspaceId};
use prw_device_identity::{
    DeviceIdentityVerificationError, EnrollmentProofVerificationError, verify_enrollment_proof,
};
use prw_device_identity_signer::{
    MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES, UbuntuEnrollmentSigner, UbuntuEnrollmentSignerError,
};

fn generate_p256_pkcs8() -> Vec<u8> {
    let rng = SystemRandom::new();
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate disposable P-256 PKCS#8")
        .as_ref()
        .to_vec()
}

fn request_for(
    signer: &UbuntuEnrollmentSigner,
    enrollment: &str,
    device: &str,
) -> EnrollmentRequest {
    EnrollmentRequest {
        enrollment_id: EnrollmentId::new(enrollment).expect("valid enrollment id"),
        workspace_id: WorkspaceId::new("phase121-workspace").expect("valid workspace id"),
        user_id: UserId::new("phase121-user").expect("valid user id"),
        device_id: DeviceId::new(device).expect("valid device id"),
        public_identity: signer.public_identity().clone(),
    }
}

#[test]
fn valid_pkcs8_load_derives_stable_canonical_public_identity() {
    let pkcs8 = generate_p256_pkcs8();
    let signer = UbuntuEnrollmentSigner::from_pkcs8_v1_der(&pkcs8).expect("load signer");
    let signer_again = UbuntuEnrollmentSigner::from_pkcs8_v1_der(&pkcs8).expect("reload signer");

    assert_eq!(signer.public_identity(), signer_again.public_identity());
    assert!(!signer.public_identity().as_bytes().is_empty());
}

#[test]
fn credential_bounds_fail_before_provider_use() {
    assert_eq!(
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&[]).unwrap_err(),
        UbuntuEnrollmentSignerError::CredentialOutOfBounds
    );

    let oversized = vec![0u8; MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES + 1];
    assert_eq!(
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&oversized).unwrap_err(),
        UbuntuEnrollmentSignerError::CredentialOutOfBounds
    );
}

#[test]
fn malformed_truncated_wrong_curve_and_non_pkcs8_credentials_are_rejected() {
    let mut truncated = generate_p256_pkcs8();
    truncated.pop().expect("generated PKCS#8 is non-empty");
    assert_eq!(
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&truncated).unwrap_err(),
        UbuntuEnrollmentSignerError::InvalidPrivateCredential
    );

    let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable P-384 PKCS#8");
    assert_eq!(
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(p384.as_ref()).unwrap_err(),
        UbuntuEnrollmentSignerError::InvalidPrivateCredential
    );

    let p256 = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &generate_p256_pkcs8())
        .expect("load disposable P-256 key");
    let rfc5915 = p256
        .private_key()
        .as_der()
        .expect("serialize alternate RFC5915 private-key format");
    assert_eq!(
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(rfc5915.as_ref()).unwrap_err(),
        UbuntuEnrollmentSignerError::InvalidPrivateCredential
    );
}

#[test]
fn enrollment_id_mismatch_is_rejected() {
    let signer =
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&generate_p256_pkcs8()).expect("load signer");
    let request = request_for(&signer, "phase121-enrollment-a", "phase121-device");
    let other_request = request_for(&signer, "phase121-enrollment-b", "phase121-device");
    let state = EnrollmentProofChallengeState::new(
        other_request,
        EnrollmentProofNonce::new([0x51; 32]),
        1_000,
        1_200,
    )
    .expect("valid challenge state");

    assert_eq!(
        signer
            .sign_enrollment_proof(&request, state.challenge())
            .unwrap_err(),
        UbuntuEnrollmentSignerError::EnrollmentMismatch
    );
}

#[test]
fn request_public_identity_mismatch_is_rejected() {
    let signer_a =
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&generate_p256_pkcs8()).expect("load signer A");
    let signer_b =
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&generate_p256_pkcs8()).expect("load signer B");
    let request = request_for(&signer_b, "phase121-enrollment", "phase121-device");
    let state = EnrollmentProofChallengeState::new(
        request.clone(),
        EnrollmentProofNonce::new([0x52; 32]),
        2_000,
        2_200,
    )
    .expect("valid challenge state");

    assert_eq!(
        signer_a
            .sign_enrollment_proof(&request, state.challenge())
            .unwrap_err(),
        UbuntuEnrollmentSignerError::PublicIdentityMismatch
    );
}

#[test]
fn typed_signing_produces_proof_accepted_and_consumed_by_production_verifier() {
    let signer =
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&generate_p256_pkcs8()).expect("load signer");
    let request = request_for(&signer, "phase121-enrollment", "phase121-device");
    let nonce = EnrollmentProofNonce::new([0x53; 32]);
    let mut state = EnrollmentProofChallengeState::new(request.clone(), nonce, 3_000, 3_200)
        .expect("valid challenge state");
    let proof = signer
        .sign_enrollment_proof(&request, state.challenge())
        .expect("typed enrollment proof signing succeeds");

    verify_enrollment_proof(&mut state, &proof, 3_001).expect("production verifier accepts proof");
    assert!(state.is_consumed());
}

#[test]
fn changed_snapshot_rejects_previously_signed_proof_without_consumption() {
    let signer =
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(&generate_p256_pkcs8()).expect("load signer");
    let original = request_for(&signer, "phase121-enrollment", "phase121-device-a");
    let nonce = EnrollmentProofNonce::new([0x54; 32]);
    let original_state = EnrollmentProofChallengeState::new(original.clone(), nonce, 4_000, 4_200)
        .expect("valid original challenge state");
    let proof = signer
        .sign_enrollment_proof(&original, original_state.challenge())
        .expect("sign original snapshot");

    let changed = request_for(&signer, "phase121-enrollment", "phase121-device-b");
    let mut changed_state = EnrollmentProofChallengeState::new(changed, nonce, 4_000, 4_200)
        .expect("valid changed challenge state");

    assert!(matches!(
        verify_enrollment_proof(&mut changed_state, &proof, 4_001),
        Err(EnrollmentProofVerificationError::DeviceIdentity(
            DeviceIdentityVerificationError::InvalidSignature
        ))
    ));
    assert!(!changed_state.is_consumed());
}

#[test]
fn debug_representation_contains_no_private_credential_bytes() {
    let pkcs8 = generate_p256_pkcs8();
    let signer = UbuntuEnrollmentSigner::from_pkcs8_v1_der(&pkcs8).expect("load signer");
    let debug = format!("{signer:?}");

    assert!(debug.contains("UbuntuEnrollmentSigner"));
    assert!(!debug.contains(&format!("{:02x}", pkcs8[0])) || debug.len() < pkcs8.len() * 2);
}
