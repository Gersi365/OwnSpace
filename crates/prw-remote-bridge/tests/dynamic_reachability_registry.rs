//! Phase 152 C02e source-level registry/reachability admission tests.
//!
//! These tests intentionally perform no socket, NAT traversal, relay, DNS, filesystem,
//! process, PTY, runtime, deployment, or service-manager operation. They stage the
//! fail-closed ordering required before transient endpoint refresh may be admitted by a
//! later runtime integration.

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
enum ReachabilityAdmissionError {
    Registry(RegistryError),
    WorkspaceMismatch,
    Connectivity(ConnectivityError),
}

fn refresh_after_current_admission_revalidation(
    registry: &WorkspaceDeviceRegistry,
    requester_session: &AuthenticatedDeviceSession,
    plan: &mut PeerConnectivityPlan,
    candidates: Vec<ConnectivityCandidate>,
) -> Result<(), ReachabilityAdmissionError> {
    let requester = registry
        .validate_authenticated_session(requester_session)
        .map_err(ReachabilityAdmissionError::Registry)?;

    let target =
        registry
            .device(plan.peer().device_id())
            .ok_or(ReachabilityAdmissionError::Registry(
                RegistryError::DeviceUnknown,
            ))?;
    if target.binding().workspace_id != *requester.workspace_id() {
        return Err(ReachabilityAdmissionError::WorkspaceMismatch);
    }

    registry
        .validate_transport_identity(plan.peer().device_id(), plan.peer().transport_identity())
        .map_err(ReachabilityAdmissionError::Registry)?;

    plan.refresh_candidates(candidates)
        .map_err(ReachabilityAdmissionError::Connectivity)
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable C02e key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("load disposable C02e signer")
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
        CandidateId::new(value).expect("non-zero candidate id"),
        kind,
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .expect("valid explicit endpoint"),
    )
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

fn registry_session_and_plan(
    current_transport: TransportIdentity,
) -> (
    WorkspaceDeviceRegistry,
    WorkspaceId,
    UserId,
    DeviceId,
    AuthenticatedDeviceSession,
    PeerConnectivityPlan,
) {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace_id = WorkspaceId::new("workspace-c02e").expect("workspace id");
    let user_id = UserId::new("user-c02e").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        user_id.clone(),
        "requester-c02e",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        user_id.clone(),
        "target-c02e",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester_session =
        authenticated_session(&requester_signer, &requester_binding, "session-c02e");

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Member)
        .expect("active membership");
    registry
        .register_device(requester_binding)
        .expect("registered requester");
    registry
        .register_device(target_binding)
        .expect("registered target");
    registry
        .bind_transport_identity(&target_device_id, current_transport)
        .expect("current target transport identity");

    let identity = PeerConnectivityIdentity::new(target_device_id.clone(), current_transport);
    let plan = PeerConnectivityPlan::new(
        identity,
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("initial connectivity plan");

    (
        registry,
        workspace_id,
        user_id,
        target_device_id,
        requester_session,
        plan,
    )
}

#[test]
fn current_session_workspace_and_target_identity_allow_transient_refresh() {
    let current_transport = transport(1);
    let (registry, _workspace, _user, _target, requester_session, mut plan) =
        registry_session_and_plan(current_transport);
    plan.set_observation(
        CandidateId::new(1).expect("candidate id"),
        ReachabilityObservation::Reachable,
    )
    .expect("old path observation");
    let expected_identity = plan.peer().clone();

    refresh_after_current_admission_revalidation(
        &registry,
        &requester_session,
        &mut plan,
        vec![
            candidate(2, ConnectivityPathKind::InternetDirect, 3002),
            candidate(3, ConnectivityPathKind::Relay, 3003),
        ],
    )
    .expect("current same-workspace admission permits transient endpoint refresh");

    assert_eq!(plan.peer(), &expected_identity);
    assert_eq!(plan.peer().transport_identity(), current_transport);
    assert_eq!(plan.candidate_count(), 2);
    assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);
    assert_eq!(
        plan.set_observation(
            CandidateId::new(1).expect("removed candidate id"),
            ReachabilityObservation::Reachable,
        ),
        Err(ConnectivityError::UnknownCandidate)
    );
}

#[test]
fn transport_rotation_rejects_stale_plan_before_endpoint_mutation() {
    let original_transport = transport(1);
    let replacement_transport = transport(2);
    let (mut registry, _workspace, _user, target_device, requester_session, mut plan) =
        registry_session_and_plan(original_transport);
    plan.set_observation(
        CandidateId::new(1).expect("candidate id"),
        ReachabilityObservation::Reachable,
    )
    .expect("old path observation");
    let before = plan.clone();

    registry
        .rotate_transport_identity(&target_device, original_transport, replacement_transport)
        .expect("registry transport rotation");

    assert_eq!(
        refresh_after_current_admission_revalidation(
            &registry,
            &requester_session,
            &mut plan,
            vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
        ),
        Err(ReachabilityAdmissionError::Registry(
            RegistryError::TransportIdentityMismatch
        ))
    );
    assert_eq!(plan, before);
}

#[test]
fn target_device_revocation_rejects_refresh_before_endpoint_mutation() {
    let current_transport = transport(1);
    let (mut registry, _workspace, _user, target_device, requester_session, mut plan) =
        registry_session_and_plan(current_transport);
    let before = plan.clone();

    registry
        .revoke_device(&target_device)
        .expect("revoke target device");

    assert_eq!(
        refresh_after_current_admission_revalidation(
            &registry,
            &requester_session,
            &mut plan,
            vec![candidate(2, ConnectivityPathKind::Relay, 3002)],
        ),
        Err(ReachabilityAdmissionError::Registry(
            RegistryError::DeviceRevoked
        ))
    );
    assert_eq!(plan, before);
}

#[test]
fn requester_membership_suspension_rejects_refresh_before_endpoint_mutation() {
    let current_transport = transport(1);
    let (mut registry, workspace, user, _target, requester_session, mut plan) =
        registry_session_and_plan(current_transport);
    let before = plan.clone();

    registry
        .suspend_membership(&workspace, &user)
        .expect("suspend requester membership");

    assert_eq!(
        refresh_after_current_admission_revalidation(
            &registry,
            &requester_session,
            &mut plan,
            vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
        ),
        Err(ReachabilityAdmissionError::Registry(
            RegistryError::MembershipNotActive
        ))
    );
    assert_eq!(plan, before);
}

#[test]
fn cross_workspace_target_rejects_refresh_before_endpoint_mutation() {
    let requester_signer = signer();
    let target_signer = signer();
    let requester_workspace = WorkspaceId::new("workspace-requester").expect("workspace id");
    let target_workspace = WorkspaceId::new("workspace-target").expect("workspace id");
    let requester_user = UserId::new("user-requester").expect("user id");
    let target_user = UserId::new("user-target").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        requester_workspace.clone(),
        requester_user.clone(),
        "requester-cross-workspace",
    );
    let target_binding = binding(
        &target_signer,
        target_workspace.clone(),
        target_user.clone(),
        "target-cross-workspace",
    );
    let target_device = target_binding.device_id.clone();
    let requester_session = authenticated_session(
        &requester_signer,
        &requester_binding,
        "session-cross-workspace",
    );
    let current_transport = transport(7);

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(requester_workspace, requester_user, WorkspaceRole::Member)
        .expect("requester membership");
    registry
        .add_membership(target_workspace, target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .register_device(requester_binding)
        .expect("registered requester");
    registry
        .register_device(target_binding)
        .expect("registered target");
    registry
        .bind_transport_identity(&target_device, current_transport)
        .expect("target transport identity");

    let mut plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device, current_transport),
        vec![candidate(1, ConnectivityPathKind::InternetDirect, 2001)],
    )
    .expect("cross-workspace target plan");
    let before = plan.clone();

    assert_eq!(
        refresh_after_current_admission_revalidation(
            &registry,
            &requester_session,
            &mut plan,
            vec![candidate(2, ConnectivityPathKind::Relay, 3002)],
        ),
        Err(ReachabilityAdmissionError::WorkspaceMismatch)
    );
    assert_eq!(plan, before);
}
