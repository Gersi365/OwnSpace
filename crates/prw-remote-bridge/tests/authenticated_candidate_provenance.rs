//! Phase 152 C02e source-level authenticated candidate provenance tests.
//!
//! This file stages only a typed, in-memory provenance boundary. It performs no socket,
//! control-transport, ICE/STUN/TURN, DNS, filesystem, process, PTY, runtime, deployment,
//! or service-manager operation and does not define a production wire format.

use std::net::{IpAddr, Ipv4Addr};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, ReachabilityObservation,
    SelectedConnectivityPath, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_registry::{RegistryError, WorkspaceDeviceRegistry, WorkspaceRole};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateProvenanceError {
    Registry(RegistryError),
    WorkspaceMismatch,
    PublicationTargetMismatch,
    Connectivity(ConnectivityError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedCandidatePublication {
    publisher_session: AuthenticatedDeviceSession,
    peer: PeerConnectivityIdentity,
    candidates: Vec<ConnectivityCandidate>,
}

fn publish_current_candidates(
    registry: &WorkspaceDeviceRegistry,
    publisher_session: &AuthenticatedDeviceSession,
    presented_transport_identity: TransportIdentity,
    candidates: Vec<ConnectivityCandidate>,
) -> Result<AuthenticatedCandidatePublication, CandidateProvenanceError> {
    let publisher = registry
        .validate_authenticated_session(publisher_session)
        .map_err(CandidateProvenanceError::Registry)?;
    registry
        .validate_transport_identity(publisher.device_id(), presented_transport_identity)
        .map_err(CandidateProvenanceError::Registry)?;

    let peer =
        PeerConnectivityIdentity::new(publisher.device_id().clone(), presented_transport_identity);
    PeerConnectivityPlan::new(peer.clone(), candidates.clone())
        .map_err(CandidateProvenanceError::Connectivity)?;

    Ok(AuthenticatedCandidatePublication {
        publisher_session: publisher_session.clone(),
        peer,
        candidates,
    })
}

fn refresh_from_authenticated_publication(
    registry: &WorkspaceDeviceRegistry,
    requester_session: &AuthenticatedDeviceSession,
    publication: &AuthenticatedCandidatePublication,
    plan: &mut PeerConnectivityPlan,
) -> Result<(), CandidateProvenanceError> {
    let requester = registry
        .validate_authenticated_session(requester_session)
        .map_err(CandidateProvenanceError::Registry)?;
    let publisher = registry
        .validate_authenticated_session(&publication.publisher_session)
        .map_err(CandidateProvenanceError::Registry)?;

    if requester.workspace_id() != publisher.workspace_id() {
        return Err(CandidateProvenanceError::WorkspaceMismatch);
    }
    if publisher.device_id() != publication.peer.device_id() || plan.peer() != &publication.peer {
        return Err(CandidateProvenanceError::PublicationTargetMismatch);
    }

    registry
        .validate_transport_identity(
            publication.peer.device_id(),
            publication.peer.transport_identity(),
        )
        .map_err(CandidateProvenanceError::Registry)?;

    plan.refresh_candidates(publication.candidates.clone())
        .map_err(CandidateProvenanceError::Connectivity)
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable C02e provenance key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable C02e provenance signer")
}

fn binding(
    signer: &UbuntuEnrollmentSigner,
    workspace_id: WorkspaceId,
    user_id: UserId,
    device: &str,
) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        workspace_id,
        user_id,
        device_id: DeviceId::new(device).expect("device id"),
        public_identity: signer.public_identity().clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    }
}

fn authenticated_session(
    signer: &UbuntuEnrollmentSigner,
    binding: &DeviceIdentityBinding,
    session: &str,
) -> AuthenticatedDeviceSession {
    let mut service = SessionAuthenticationService::new();
    let session_id = SessionId::new(session).expect("session id");
    let challenge = service
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
        .expect("begin disposable session");
    let proof = signer
        .sign_session_auth_proof(binding, &challenge)
        .expect("sign disposable session proof");
    service
        .submit_proof(&session_id, &proof, 1_001)
        .expect("authenticate disposable session")
}

fn transport(seed: u8) -> TransportIdentity {
    TransportIdentity::new([seed; 32]).expect("non-zero transport identity")
}

fn candidate(value: u64, kind: ConnectivityPathKind, port: u16) -> ConnectivityCandidate {
    ConnectivityCandidate::new(
        CandidateId::new(value).expect("candidate id"),
        kind,
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .expect("explicit endpoint"),
    )
}

struct SameWorkspaceFixture {
    registry: WorkspaceDeviceRegistry,
    workspace_id: WorkspaceId,
    requester_user_id: UserId,
    target_user_id: UserId,
    requester_device_id: DeviceId,
    target_device_id: DeviceId,
    requester_session: AuthenticatedDeviceSession,
    target_session: AuthenticatedDeviceSession,
    requester_transport: TransportIdentity,
    target_transport: TransportIdentity,
    plan: PeerConnectivityPlan,
}

fn same_workspace_fixture() -> SameWorkspaceFixture {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace_id = WorkspaceId::new("workspace-provenance").expect("workspace id");
    let requester_user_id = UserId::new("user-requester-provenance").expect("user id");
    let target_user_id = UserId::new("user-target-provenance").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        requester_user_id.clone(),
        "requester-provenance",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        target_user_id.clone(),
        "target-provenance",
    );
    let requester_device_id = requester_binding.device_id.clone();
    let target_device_id = target_binding.device_id.clone();
    let requester_session = authenticated_session(
        &requester_signer,
        &requester_binding,
        "session-requester-provenance",
    );
    let target_session =
        authenticated_session(&target_signer, &target_binding, "session-target-provenance");
    let requester_transport = transport(1);
    let target_transport = transport(2);

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(
            workspace_id.clone(),
            requester_user_id.clone(),
            WorkspaceRole::Member,
        )
        .expect("requester membership");
    registry
        .add_membership(
            workspace_id.clone(),
            target_user_id.clone(),
            WorkspaceRole::Member,
        )
        .expect("target membership");
    registry
        .register_device(requester_binding)
        .expect("registered requester");
    registry
        .register_device(target_binding)
        .expect("registered target");
    registry
        .bind_transport_identity(&requester_device_id, requester_transport)
        .expect("requester transport identity");
    registry
        .bind_transport_identity(&target_device_id, target_transport)
        .expect("target transport identity");

    let plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device_id.clone(), target_transport),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("target connectivity plan");

    SameWorkspaceFixture {
        registry,
        workspace_id,
        requester_user_id,
        target_user_id,
        requester_device_id,
        target_device_id,
        requester_session,
        target_session,
        requester_transport,
        target_transport,
        plan,
    }
}

#[test]
fn authenticated_target_publication_allows_same_workspace_refresh() {
    let mut fixture = same_workspace_fixture();
    fixture
        .plan
        .set_observation(
            CandidateId::new(1).expect("candidate id"),
            ReachabilityObservation::Reachable,
        )
        .expect("old reachability evidence");
    let expected_identity = fixture.plan.peer().clone();

    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![
            candidate(2, ConnectivityPathKind::InternetDirect, 3002),
            candidate(3, ConnectivityPathKind::Relay, 3003),
        ],
    )
    .expect("authenticated current target publication");

    refresh_from_authenticated_publication(
        &fixture.registry,
        &fixture.requester_session,
        &publication,
        &mut fixture.plan,
    )
    .expect("current same-workspace requester consumes target publication");

    assert_eq!(fixture.plan.peer(), &expected_identity);
    assert_eq!(fixture.plan.candidate_count(), 2);
    assert_eq!(
        fixture.plan.selected_path(),
        SelectedConnectivityPath::Offline
    );
    assert_eq!(
        fixture.plan.set_observation(
            CandidateId::new(1).expect("removed candidate id"),
            ReachabilityObservation::Reachable,
        ),
        Err(ConnectivityError::UnknownCandidate)
    );
}

#[test]
fn authenticated_requester_publication_cannot_be_retargeted_to_peer_plan() {
    let mut fixture = same_workspace_fixture();
    let before = fixture.plan.clone();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.requester_session,
        fixture.requester_transport,
        vec![candidate(4, ConnectivityPathKind::InternetDirect, 4004)],
    )
    .expect("authenticated requester publication");

    assert_eq!(
        refresh_from_authenticated_publication(
            &fixture.registry,
            &fixture.requester_session,
            &publication,
            &mut fixture.plan,
        ),
        Err(CandidateProvenanceError::PublicationTargetMismatch)
    );
    assert_eq!(fixture.plan, before);
}

#[test]
fn target_transport_rotation_rejects_stale_publication_before_mutation() {
    let mut fixture = same_workspace_fixture();
    let before = fixture.plan.clone();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(5, ConnectivityPathKind::InternetDirect, 4005)],
    )
    .expect("authenticated target publication");
    let replacement = transport(3);

    fixture
        .registry
        .rotate_transport_identity(
            &fixture.target_device_id,
            fixture.target_transport,
            replacement,
        )
        .expect("rotate target transport identity");

    assert_eq!(
        refresh_from_authenticated_publication(
            &fixture.registry,
            &fixture.requester_session,
            &publication,
            &mut fixture.plan,
        ),
        Err(CandidateProvenanceError::Registry(
            RegistryError::TransportIdentityMismatch
        ))
    );
    assert_eq!(fixture.plan, before);
}

#[test]
fn target_membership_suspension_rejects_stale_publication_before_mutation() {
    let mut fixture = same_workspace_fixture();
    let before = fixture.plan.clone();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(6, ConnectivityPathKind::Relay, 4006)],
    )
    .expect("authenticated target publication");

    fixture
        .registry
        .suspend_membership(&fixture.workspace_id, &fixture.target_user_id)
        .expect("suspend target publisher membership");

    assert_eq!(
        refresh_from_authenticated_publication(
            &fixture.registry,
            &fixture.requester_session,
            &publication,
            &mut fixture.plan,
        ),
        Err(CandidateProvenanceError::Registry(
            RegistryError::MembershipNotActive
        ))
    );
    assert_eq!(fixture.plan, before);
}

#[test]
fn cross_workspace_requester_cannot_consume_authenticated_target_publication() {
    let target_signer = signer();
    let requester_signer = signer();
    let target_workspace = WorkspaceId::new("workspace-target-publication").expect("workspace id");
    let requester_workspace =
        WorkspaceId::new("workspace-requester-publication").expect("workspace id");
    let target_user = UserId::new("user-target-publication").expect("user id");
    let requester_user = UserId::new("user-requester-publication").expect("user id");
    let target_binding = binding(
        &target_signer,
        target_workspace.clone(),
        target_user.clone(),
        "target-cross-workspace-publication",
    );
    let requester_binding = binding(
        &requester_signer,
        requester_workspace.clone(),
        requester_user.clone(),
        "requester-cross-workspace-publication",
    );
    let target_device = target_binding.device_id.clone();
    let target_session = authenticated_session(
        &target_signer,
        &target_binding,
        "session-target-cross-workspace-publication",
    );
    let requester_session = authenticated_session(
        &requester_signer,
        &requester_binding,
        "session-requester-cross-workspace-publication",
    );
    let target_transport = transport(7);

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(target_workspace, target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .add_membership(requester_workspace, requester_user, WorkspaceRole::Member)
        .expect("requester membership");
    registry
        .register_device(target_binding)
        .expect("registered target");
    registry
        .register_device(requester_binding)
        .expect("registered requester");
    registry
        .bind_transport_identity(&target_device, target_transport)
        .expect("target transport identity");

    let publication = publish_current_candidates(
        &registry,
        &target_session,
        target_transport,
        vec![candidate(8, ConnectivityPathKind::InternetDirect, 4008)],
    )
    .expect("authenticated target publication");
    let mut plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device, target_transport),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("target plan");
    let before = plan.clone();

    assert_eq!(
        refresh_from_authenticated_publication(
            &registry,
            &requester_session,
            &publication,
            &mut plan,
        ),
        Err(CandidateProvenanceError::WorkspaceMismatch)
    );
    assert_eq!(plan, before);
}

#[test]
fn invalid_candidate_set_is_rejected_before_publication_exists() {
    let fixture = same_workspace_fixture();
    let duplicate = vec![
        candidate(9, ConnectivityPathKind::InternetDirect, 4009),
        candidate(9, ConnectivityPathKind::Relay, 4010),
    ];

    assert_eq!(
        publish_current_candidates(
            &fixture.registry,
            &fixture.target_session,
            fixture.target_transport,
            duplicate,
        ),
        Err(CandidateProvenanceError::Connectivity(
            ConnectivityError::DuplicateCandidateId
        ))
    );
}

#[test]
fn fixture_keeps_requester_and_target_identities_distinct() {
    let fixture = same_workspace_fixture();
    assert_ne!(fixture.requester_user_id, fixture.target_user_id);
    assert_ne!(fixture.requester_device_id, fixture.target_device_id);
}
