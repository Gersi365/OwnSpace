use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_control_plane::{
    DeviceIdentityBinding,
    session_auth::{SessionAuthChallengeState, SessionAuthProof},
};
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_remote_bridge::session_auth_wire::{
    SESSION_AUTH_WIRE_MAGIC, SessionAuthenticationWireChallenge, SessionAuthenticationWireError,
    SessionAuthenticationWireMessage, SessionAuthenticationWireProof,
    decode_session_authentication_frame, encode_session_authentication_frame,
};
use prw_remote_transport::{ControlFrame, ControlMessageKind};
use prw_session::SessionAuthenticationService;

fn device_signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable device key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("load device signer")
}

fn device_binding(signer: &UbuntuEnrollmentSigner) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        workspace_id: WorkspaceId::new("workspace-c03d").expect("workspace id"),
        user_id: UserId::new("user-c03d").expect("user id"),
        device_id: DeviceId::new("device-c03d").expect("device id"),
        public_identity: signer.public_identity().clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    }
}

#[test]
fn logical_session_challenge_and_proof_round_trip_into_existing_authentication_service() {
    let signer = device_signer();
    let binding = device_binding(&signer);
    let session_id = SessionId::new("session-c03d").expect("session id");
    let mut service = SessionAuthenticationService::new();
    let challenge = service
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_200)
        .expect("begin typed session authentication");

    let challenge_frame = encode_session_authentication_frame(
        91,
        &SessionAuthenticationWireMessage::Challenge(
            SessionAuthenticationWireChallenge::from_typed(&challenge),
        ),
    )
    .expect("encode challenge frame");
    assert_eq!(
        challenge_frame.kind(),
        ControlMessageKind::SessionAuthentication
    );
    assert_eq!(challenge_frame.request_id(), 91);

    let decoded_challenge = match decode_session_authentication_frame(&challenge_frame)
        .expect("decode challenge frame")
    {
        SessionAuthenticationWireMessage::Challenge(wire) => wire,
        SessionAuthenticationWireMessage::Proof(_) => panic!("expected challenge"),
    };
    let decoded_challenge_state = SessionAuthChallengeState::new(
        binding.clone(),
        SessionId::new(decoded_challenge.session_id()).expect("decoded session id"),
        decoded_challenge.nonce(),
        decoded_challenge.issued_at_unix_seconds(),
        decoded_challenge.expires_at_unix_seconds(),
    )
    .expect("rehydrate typed challenge through existing domain constructor");
    let typed_challenge = decoded_challenge_state.challenge().clone();
    assert_eq!(typed_challenge, challenge);

    let proof = signer
        .sign_session_auth_proof(&binding, &typed_challenge)
        .expect("sign existing Phase 128 proof");
    let proof_frame = encode_session_authentication_frame(
        challenge_frame.request_id(),
        &SessionAuthenticationWireMessage::Proof(SessionAuthenticationWireProof::from_typed(
            &proof,
        )),
    )
    .expect("encode proof frame");
    assert_eq!(
        proof_frame.kind(),
        ControlMessageKind::SessionAuthentication
    );
    assert_eq!(proof_frame.request_id(), challenge_frame.request_id());

    let decoded_wire_proof =
        match decode_session_authentication_frame(&proof_frame).expect("decode proof frame") {
            SessionAuthenticationWireMessage::Proof(proof) => proof,
            SessionAuthenticationWireMessage::Challenge(_) => panic!("expected proof"),
        };
    let decoded_proof = SessionAuthProof::new(
        SessionId::new(decoded_wire_proof.session_id()).expect("decoded proof session id"),
        decoded_wire_proof.nonce(),
        decoded_wire_proof.signature().clone(),
    );
    let authenticated = service
        .submit_proof(&session_id, &decoded_proof, 1_001)
        .expect("existing session service authenticates decoded proof");
    assert_eq!(authenticated.session_id(), &session_id);
    assert_eq!(authenticated.workspace_id(), &binding.workspace_id);
    assert_eq!(authenticated.user_id(), &binding.user_id);
    assert_eq!(authenticated.device_id(), &binding.device_id);
}

#[test]
fn session_wire_fails_closed_on_wrong_outer_kind_and_malformed_header() {
    let wrong_outer = ControlFrame::new(ControlMessageKind::Request, 7, Vec::new())
        .expect("bounded wrong outer frame");
    assert_eq!(
        decode_session_authentication_frame(&wrong_outer),
        Err(SessionAuthenticationWireError::InvalidOuterKind)
    );

    let mut malformed = Vec::new();
    malformed.extend_from_slice(&SESSION_AUTH_WIRE_MAGIC);
    malformed.extend_from_slice(&1_u16.to_be_bytes());
    malformed.extend_from_slice(&0_u16.to_be_bytes());
    malformed.extend_from_slice(&1_u16.to_be_bytes());
    malformed.extend_from_slice(&1_u16.to_be_bytes());
    let frame = ControlFrame::new(ControlMessageKind::SessionAuthentication, 8, malformed)
        .expect("bounded malformed session frame");
    assert_eq!(
        decode_session_authentication_frame(&frame),
        Err(SessionAuthenticationWireError::InvalidPayload)
    );
}
