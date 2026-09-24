//! Phase 152 C02e source-level semantic-adapter staging.
//!
//! The candidate semantic adapter intentionally remains absent from the production
//! `prw-remote-bridge` module graph. This integration-test path inclusion gives the
//! closed build gate a future compile/test surface without exporting a wire or runtime API.

#[path = "../src/candidate_reachability.rs"]
mod candidate_reachability;

use std::net::{IpAddr, Ipv4Addr};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use candidate_reachability::{
    CandidateReachabilityError, publish_current_candidates, refresh_from_authenticated_publication,
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_registry::{RegistryError, WorkspaceDeviceRegistry, WorkspaceRole};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable semantic-adapter key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable semantic-adapter signer")
}

fn binding(
    signer: &UbuntuEnrollmentSigner,
    workspace_id: WorkspaceId,
    user_id: UserId,
    device_id: &str,
) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        workspace_id,
        user_id,
        device_id: DeviceId::new(device_id).expect("device id"),
        public_identity: signer.public_identity().clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    }
}

fn session(
    signer: &UbuntuEnrollmentSigner,
    binding: &DeviceIdentityBinding,
    session_id: &str,
) -> AuthenticatedDeviceSession {
    let mut service = SessionAuthenticationService::new();
    let session_id = SessionId::new(session_id).expect("session id");
    let challenge = service
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
        .expect("begin disposable session");
    let proof = signer
        .sign_session_auth_proof(binding, &challenge)
        .expect("sign disposable proof");
    service
        .submit_proof(&session_id, &proof, 1_001)
        .expect("authenticate disposable session")
}

fn transport(seed: u8) -> TransportIdentity {
    TransportIdentity::new([seed; 32]).expect("transport identity")
}

fn candidate(id: u64, kind: ConnectivityPathKind, port: u16) -> ConnectivityCandidate {
    ConnectivityCandidate::new(
        CandidateId::new(id).expect("candidate id"),
        kind,
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .expect("candidate endpoint"),
    )
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    target_device_id: DeviceId,
    requester_session: AuthenticatedDeviceSession,
    target_session: AuthenticatedDeviceSession,
    target_transport: TransportIdentity,
    plan: PeerConnectivityPlan,
}

fn fixture() -> Fixture {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace_id = WorkspaceId::new("workspace-semantic-adapter").expect("workspace id");
    let requester_user = UserId::new("requester-semantic-adapter").expect("user id");
    let target_user = UserId::new("target-semantic-adapter").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        requester_user.clone(),
        "requester-semantic-adapter",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        target_user.clone(),
        "target-semantic-adapter",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester_session = session(
        &requester_signer,
        &requester_binding,
        "session-requester-semantic-adapter",
    );
    let target_session = session(
        &target_signer,
        &target_binding,
        "session-target-semantic-adapter",
    );
    let target_transport = transport(2);

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace_id.clone(), requester_user, WorkspaceRole::Member)
        .expect("requester membership");
    registry
        .add_membership(workspace_id, target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .register_device(requester_binding)
        .expect("requester device");
    registry
        .register_device(target_binding)
        .expect("target device");
    registry
        .bind_transport_identity(&target_device_id, target_transport)
        .expect("target transport identity");

    let plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device_id.clone(), target_transport),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("initial target plan");

    Fixture {
        registry,
        target_device_id,
        requester_session,
        target_session,
        target_transport,
        plan,
    }
}

#[test]
fn semantic_adapter_derives_publisher_identity_and_refreshes_exact_target_only() {
    let mut fixture = fixture();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("current target publication");

    assert_eq!(publication.peer(), fixture.plan.peer());
    assert_eq!(publication.publisher_session(), &fixture.target_session);
    assert_eq!(publication.candidates().len(), 1);

    refresh_from_authenticated_publication(
        &fixture.registry,
        &fixture.requester_session,
        &publication,
        &mut fixture.plan,
    )
    .expect("same-workspace exact-target refresh");
    assert_eq!(fixture.plan.candidate_count(), 1);
}

#[test]
fn semantic_adapter_rejects_stale_target_transport_before_plan_mutation() {
    let mut fixture = fixture();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("current target publication");
    let before = fixture.plan.clone();

    fixture
        .registry
        .rotate_transport_identity(
            &fixture.target_device_id,
            fixture.target_transport,
            transport(3),
        )
        .expect("rotate target transport identity");

    assert_eq!(
        refresh_from_authenticated_publication(
            &fixture.registry,
            &fixture.requester_session,
            &publication,
            &mut fixture.plan,
        ),
        Err(CandidateReachabilityError::Registry(
            RegistryError::TransportIdentityMismatch
        ))
    );
    assert_eq!(fixture.plan, before);
}

#[test]
fn semantic_adapter_rejects_candidate_id_rebinding_transactionally() {
    let mut fixture = fixture();
    let before = fixture.plan.clone();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 9001)],
    )
    .expect("syntactically valid publication before target-plan correlation");

    assert_eq!(
        refresh_from_authenticated_publication(
            &fixture.registry,
            &fixture.requester_session,
            &publication,
            &mut fixture.plan,
        ),
        Err(CandidateReachabilityError::Connectivity(
            ConnectivityError::CandidateIdRebound
        ))
    );
    assert_eq!(fixture.plan, before);
}
