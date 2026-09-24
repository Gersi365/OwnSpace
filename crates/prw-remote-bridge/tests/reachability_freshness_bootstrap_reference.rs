//! Phase 152 C02e test-only candidate-freshness bootstrap lifecycle reference.
//!
//! The lifecycle markers and bootstrap values in this file are deliberately local test values.
//! They are not a production counter, nonce, token, timestamp, wire field, persistence schema,
//! restart protocol, or transport-rotation protocol. The purpose is only to prove that a
//! legitimately new peer lifecycle is distinct from an existing lifecycle whose verifier state
//! is unavailable.

#[path = "../src/candidate_reachability.rs"]
mod candidate_reachability;

use std::net::{IpAddr, Ipv4Addr};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use candidate_reachability::{
    AuthenticatedCandidatePublication, CandidateReachabilityError, publish_current_candidates,
    refresh_from_authenticated_publication, validate_authenticated_publication_admission,
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

// Keep the lower authenticated-refresh adapter compile-linked without invoking it here.
// Bootstrap freshness remains an explicit verifier-owned gate in this reference harness.
const _: fn(
    &WorkspaceDeviceRegistry,
    &AuthenticatedDeviceSession,
    &AuthenticatedCandidatePublication,
    &mut PeerConnectivityPlan,
) -> Result<(), CandidateReachabilityError> = refresh_from_authenticated_publication;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestBootstrapState {
    FirstPeerLifecycle,
    ReplacementPeerLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestEstablishedFreshness {
    FirstCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestFreshnessLifecycle {
    NewLifecycleEligible(TestBootstrapState),
    Established(TestEstablishedFreshness),
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapReferenceError {
    Admission(CandidateReachabilityError),
    RecoveryRequired,
    AlreadyEstablished,
    BootstrapMismatch,
}

struct BootstrapFreshnessReference {
    plan: PeerConnectivityPlan,
    lifecycle: TestFreshnessLifecycle,
}

impl BootstrapFreshnessReference {
    const fn new_lifecycle(plan: PeerConnectivityPlan, bootstrap: TestBootstrapState) -> Self {
        Self {
            plan,
            lifecycle: TestFreshnessLifecycle::NewLifecycleEligible(bootstrap),
        }
    }

    const fn recovery_required(plan: PeerConnectivityPlan) -> Self {
        Self {
            plan,
            lifecycle: TestFreshnessLifecycle::RecoveryRequired,
        }
    }

    const fn lifecycle(&self) -> TestFreshnessLifecycle {
        self.lifecycle
    }

    const fn plan(&self) -> &PeerConnectivityPlan {
        &self.plan
    }

    fn commit_first_publication(
        &mut self,
        presented_bootstrap: TestBootstrapState,
        registry: &WorkspaceDeviceRegistry,
        requester_session: &AuthenticatedDeviceSession,
        publication: &AuthenticatedCandidatePublication,
    ) -> Result<TestEstablishedFreshness, BootstrapReferenceError> {
        validate_authenticated_publication_admission(
            registry,
            requester_session,
            publication,
            &self.plan,
        )
        .map_err(BootstrapReferenceError::Admission)?;

        let expected_bootstrap = match self.lifecycle {
            TestFreshnessLifecycle::NewLifecycleEligible(bootstrap) => bootstrap,
            TestFreshnessLifecycle::Established(_) => {
                return Err(BootstrapReferenceError::AlreadyEstablished);
            }
            TestFreshnessLifecycle::RecoveryRequired => {
                return Err(BootstrapReferenceError::RecoveryRequired);
            }
        };
        if expected_bootstrap != presented_bootstrap {
            return Err(BootstrapReferenceError::BootstrapMismatch);
        }

        // Candidate validation is staged against private scratch state. Failure leaves the
        // verifier-owned bootstrap lifecycle unchanged and therefore retryable with a corrected
        // candidate vector under the same authoritative bootstrap state.
        let mut staged_plan = self.plan.clone();
        staged_plan
            .refresh_candidates(publication.candidates().to_vec())
            .map_err(|error| {
                BootstrapReferenceError::Admission(CandidateReachabilityError::Connectivity(error))
            })?;

        let established = TestEstablishedFreshness::FirstCommit;
        self.plan = staged_plan;
        self.lifecycle = TestFreshnessLifecycle::Established(established);
        Ok(established)
    }
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable bootstrap-reference key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable bootstrap-reference signer")
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
        .expect("sign disposable session proof");
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
    requester_session: AuthenticatedDeviceSession,
    target_signer: UbuntuEnrollmentSigner,
    target_binding: DeviceIdentityBinding,
    target_session: AuthenticatedDeviceSession,
    target_transport: TransportIdentity,
    plan: PeerConnectivityPlan,
}

fn fixture() -> Fixture {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace_id = WorkspaceId::new("workspace-bootstrap-reference").expect("workspace id");
    let requester_user = UserId::new("requester-bootstrap-reference").expect("user id");
    let target_user = UserId::new("target-bootstrap-reference").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        requester_user.clone(),
        "requester-bootstrap-reference",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        target_user.clone(),
        "target-bootstrap-reference",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester_session = session(
        &requester_signer,
        &requester_binding,
        "session-requester-bootstrap-reference",
    );
    let target_session = session(
        &target_signer,
        &target_binding,
        "session-target-bootstrap-reference",
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
        .register_device(target_binding.clone())
        .expect("target device");
    registry
        .bind_transport_identity(&target_device_id, target_transport)
        .expect("target transport identity");

    let plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device_id, target_transport),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("initial target plan");

    Fixture {
        registry,
        requester_session,
        target_signer,
        target_binding,
        target_session,
        target_transport,
        plan,
    }
}

#[test]
fn new_lifecycle_first_publication_establishes_freshness_once() {
    let fixture = fixture();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("first candidate publication");
    let mut owner = BootstrapFreshnessReference::new_lifecycle(
        fixture.plan,
        TestBootstrapState::FirstPeerLifecycle,
    );

    assert_eq!(
        owner
            .commit_first_publication(
                TestBootstrapState::FirstPeerLifecycle,
                &fixture.registry,
                &fixture.requester_session,
                &publication,
            )
            .expect("first publication establishes current freshness"),
        TestEstablishedFreshness::FirstCommit
    );
    assert_eq!(
        owner.lifecycle(),
        TestFreshnessLifecycle::Established(TestEstablishedFreshness::FirstCommit)
    );
    assert_eq!(
        owner.commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(BootstrapReferenceError::AlreadyEstablished)
    );
}

#[test]
fn invalid_first_candidate_vector_does_not_consume_bootstrap() {
    let fixture = fixture();
    let rebound = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 9001)],
    )
    .expect("publication vector is internally bounded");
    let corrected = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("corrected publication");
    let mut owner = BootstrapFreshnessReference::new_lifecycle(
        fixture.plan,
        TestBootstrapState::FirstPeerLifecycle,
    );
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &rebound,
        ),
        Err(BootstrapReferenceError::Admission(
            CandidateReachabilityError::Connectivity(ConnectivityError::CandidateIdRebound)
        ))
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(
        owner.lifecycle(),
        TestFreshnessLifecycle::NewLifecycleEligible(TestBootstrapState::FirstPeerLifecycle)
    );

    owner
        .commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &corrected,
        )
        .expect("corrected first publication uses the still-current bootstrap");
}

#[test]
fn missing_state_for_existing_lifecycle_does_not_alias_new_bootstrap() {
    let fixture = fixture();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("candidate publication");
    let mut owner = BootstrapFreshnessReference::recovery_required(fixture.plan);
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(BootstrapReferenceError::RecoveryRequired)
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(owner.lifecycle(), TestFreshnessLifecycle::RecoveryRequired);
}

#[test]
fn same_peer_session_renewal_during_bootstrap_uses_the_existing_bootstrap_state() {
    let fixture = fixture();
    let renewed_target_session = session(
        &fixture.target_signer,
        &fixture.target_binding,
        "session-target-bootstrap-reference-renewed",
    );
    let publication = publish_current_candidates(
        &fixture.registry,
        &renewed_target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("renewed-session candidate publication");
    let mut owner = BootstrapFreshnessReference::new_lifecycle(
        fixture.plan,
        TestBootstrapState::FirstPeerLifecycle,
    );

    owner
        .commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        )
        .expect("session renewal does not require a second bootstrap namespace");
    assert_eq!(
        owner.lifecycle(),
        TestFreshnessLifecycle::Established(TestEstablishedFreshness::FirstCommit)
    );
}

#[test]
fn transport_rotation_creates_a_distinct_replacement_peer_bootstrap_lifecycle() {
    let mut fixture = fixture();
    let replacement_transport = transport(3);
    fixture
        .registry
        .rotate_transport_identity(
            fixture.plan.peer().device_id(),
            fixture.target_transport,
            replacement_transport,
        )
        .expect("rotate target transport identity");

    let replacement_publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        replacement_transport,
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 4001)],
    )
    .expect("replacement peer publication");
    let replacement_plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(
            fixture.plan.peer().device_id().clone(),
            replacement_transport,
        ),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 4001)],
    )
    .expect("replacement peer plan");
    let mut replacement_owner = BootstrapFreshnessReference::new_lifecycle(
        replacement_plan,
        TestBootstrapState::ReplacementPeerLifecycle,
    );

    assert_eq!(
        replacement_owner.commit_first_publication(
            TestBootstrapState::FirstPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &replacement_publication,
        ),
        Err(BootstrapReferenceError::BootstrapMismatch)
    );
    replacement_owner
        .commit_first_publication(
            TestBootstrapState::ReplacementPeerLifecycle,
            &fixture.registry,
            &fixture.requester_session,
            &replacement_publication,
        )
        .expect("replacement peer uses its distinct verifier bootstrap lifecycle");
}
