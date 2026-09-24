//! Phase 152 C02e test-only exclusive-owner reachability composition reference.
//!
//! This file deliberately does not add `prw-nat-traversal` as a dev-dependency while the
//! build/Cargo gate is closed. Instead it composes the actual C02e authenticated candidate
//! semantic adapter and `PeerConnectivityPlan` with an opaque test-only traversal-lifecycle
//! marker. The marker is not a production generation, nonce, counter, wire field, or replay
//! mechanism. It exists only to stage the locked upper-owner lifecycle semantics for later
//! compilation/validation.
//!
//! Candidate-publication freshness remains a mandatory external verifier-owned gate. The
//! zero-sized test admission marker below is not freshness proof; it makes that precondition
//! explicit without selecting a representation.

#[path = "../src/candidate_reachability.rs"]
mod candidate_reachability;

use std::net::{IpAddr, Ipv4Addr};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use candidate_reachability::{
    AuthenticatedCandidatePublication, CandidateReachabilityError, publish_current_candidates,
    refresh_from_authenticated_publication,
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

// This test exercises the authenticated refresh path directly. Keep the publication candidate
// accessor compile-linked as part of the same private semantic adapter without adding runtime work.
const _: fn(&AuthenticatedCandidatePublication) -> &[ConnectivityCandidate] =
    AuthenticatedCandidatePublication::candidates;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TestOnlyFreshnessAdmission;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestTraversalLifecycle {
    BeforeRefresh,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceObservationError {
    StaleTraversal,
    Connectivity(ConnectivityError),
}

struct ReachabilityCompositionReference {
    plan: PeerConnectivityPlan,
    current_traversal: Option<TestTraversalLifecycle>,
}

impl ReachabilityCompositionReference {
    const fn new(plan: PeerConnectivityPlan, traversal: TestTraversalLifecycle) -> Self {
        Self {
            plan,
            current_traversal: Some(traversal),
        }
    }

    const fn plan(&self) -> &PeerConnectivityPlan {
        &self.plan
    }

    const fn current_traversal(&self) -> Option<TestTraversalLifecycle> {
        self.current_traversal
    }

    fn commit_after_external_freshness_admission(
        &mut self,
        _freshness_admission: TestOnlyFreshnessAdmission,
        registry: &WorkspaceDeviceRegistry,
        requester_session: &AuthenticatedDeviceSession,
        publication: &AuthenticatedCandidatePublication,
    ) -> Result<(), CandidateReachabilityError> {
        // The real C02e semantic adapter performs current requester/publisher/workspace/target/
        // transport admission and transactional plan refresh. Exclusive `&mut self` ownership
        // prevents another reference-model operation from observing the successful plan refresh
        // before the following infallible lifecycle invalidation.
        refresh_from_authenticated_publication(
            registry,
            requester_session,
            publication,
            &mut self.plan,
        )?;
        self.current_traversal = None;
        Ok(())
    }

    fn install_replacement(&mut self, traversal: TestTraversalLifecycle) {
        assert!(
            self.current_traversal.is_none(),
            "replacement is installed only after prior traversal invalidation"
        );
        self.current_traversal = Some(traversal);
    }

    fn apply_observation(
        &mut self,
        traversal: TestTraversalLifecycle,
        candidate_id: CandidateId,
        observation: ReachabilityObservation,
    ) -> Result<(), ReferenceObservationError> {
        if self.current_traversal != Some(traversal) {
            return Err(ReferenceObservationError::StaleTraversal);
        }
        self.plan
            .set_observation(candidate_id, observation)
            .map_err(ReferenceObservationError::Connectivity)
    }
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable composition-reference key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable composition-reference signer")
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
    let workspace_id = WorkspaceId::new("workspace-composition-reference").expect("workspace id");
    let requester_user = UserId::new("requester-composition-reference").expect("user id");
    let target_user = UserId::new("target-composition-reference").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        requester_user.clone(),
        "requester-composition-reference",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        target_user.clone(),
        "target-composition-reference",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester_session = session(
        &requester_signer,
        &requester_binding,
        "session-requester-composition-reference",
    );
    let target_session = session(
        &target_signer,
        &target_binding,
        "session-target-composition-reference",
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
fn successful_refresh_invalidates_old_lifecycle_even_for_exact_retained_candidate() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("exact retained-candidate publication");
    let mut owner =
        ReachabilityCompositionReference::new(fixture.plan, TestTraversalLifecycle::BeforeRefresh);

    owner
        .apply_observation(
            TestTraversalLifecycle::BeforeRefresh,
            retained.id(),
            ReachabilityObservation::Reachable,
        )
        .expect("pre-refresh traversal observation applies");
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Candidate(retained)
    );

    owner
        .commit_after_external_freshness_admission(
            TestOnlyFreshnessAdmission,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        )
        .expect("successful full refresh commits");

    assert_eq!(owner.current_traversal(), None);
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Offline
    );
    assert_eq!(
        owner.apply_observation(
            TestTraversalLifecycle::BeforeRefresh,
            retained.id(),
            ReachabilityObservation::Reachable,
        ),
        Err(ReferenceObservationError::StaleTraversal)
    );
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Offline
    );

    owner.install_replacement(TestTraversalLifecycle::Replacement);
    owner
        .apply_observation(
            TestTraversalLifecycle::Replacement,
            retained.id(),
            ReachabilityObservation::Reachable,
        )
        .expect("replacement traversal observation applies");
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Candidate(retained)
    );
}

#[test]
fn rejected_candidate_refresh_preserves_plan_and_current_traversal_lifecycle() {
    let fixture = fixture();
    let initial = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let rebound = candidate(1, ConnectivityPathKind::LocalDirect, 9001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![rebound],
    )
    .expect("publication is internally bounded before target-plan refresh");
    let mut owner =
        ReachabilityCompositionReference::new(fixture.plan, TestTraversalLifecycle::BeforeRefresh);
    owner
        .apply_observation(
            TestTraversalLifecycle::BeforeRefresh,
            initial.id(),
            ReachabilityObservation::Reachable,
        )
        .expect("initial observation applies");
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_after_external_freshness_admission(
            TestOnlyFreshnessAdmission,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(CandidateReachabilityError::Connectivity(
            ConnectivityError::CandidateIdRebound
        ))
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::BeforeRefresh)
    );

    owner
        .apply_observation(
            TestTraversalLifecycle::BeforeRefresh,
            initial.id(),
            ReachabilityObservation::Unreachable,
        )
        .expect("rejected refresh does not invalidate current traversal");
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Offline
    );
}

#[test]
fn stale_transport_admission_failure_preserves_plan_and_traversal() {
    let mut fixture = fixture();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![candidate(2, ConnectivityPathKind::InternetDirect, 3002)],
    )
    .expect("current target publication");
    let mut owner =
        ReachabilityCompositionReference::new(fixture.plan, TestTraversalLifecycle::BeforeRefresh);
    let before = owner.plan().clone();

    fixture
        .registry
        .rotate_transport_identity(
            &fixture.target_device_id,
            fixture.target_transport,
            transport(3),
        )
        .expect("rotate target transport identity");

    assert_eq!(
        owner.commit_after_external_freshness_admission(
            TestOnlyFreshnessAdmission,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(CandidateReachabilityError::Registry(
            RegistryError::TransportIdentityMismatch
        ))
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::BeforeRefresh)
    );
}

#[test]
fn every_successful_full_refresh_invalidates_the_current_replacement_lifecycle() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let first_publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("first publication");
    let mut owner =
        ReachabilityCompositionReference::new(fixture.plan, TestTraversalLifecycle::BeforeRefresh);

    owner
        .commit_after_external_freshness_admission(
            TestOnlyFreshnessAdmission,
            &fixture.registry,
            &fixture.requester_session,
            &first_publication,
        )
        .expect("first refresh");
    owner.install_replacement(TestTraversalLifecycle::Replacement);

    let second = candidate(2, ConnectivityPathKind::InternetDirect, 3002);
    let second_publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained, second],
    )
    .expect("second publication");
    owner
        .commit_after_external_freshness_admission(
            TestOnlyFreshnessAdmission,
            &fixture.registry,
            &fixture.requester_session,
            &second_publication,
        )
        .expect("second refresh");

    assert_eq!(owner.current_traversal(), None);
    assert_eq!(
        owner.apply_observation(
            TestTraversalLifecycle::Replacement,
            retained.id(),
            ReachabilityObservation::Reachable,
        ),
        Err(ReferenceObservationError::StaleTraversal)
    );
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Offline
    );
}
