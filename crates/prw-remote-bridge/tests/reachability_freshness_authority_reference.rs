//! Phase 152 C02e test-only candidate-publication freshness authority reference.
//!
//! This integration-test source proves compare/validate/commit ordering with test-local opaque
//! freshness states. Those states are not a production counter, nonce, timestamp, wire field,
//! persistence format, or restart protocol. The actual C02e candidate semantic adapter and
//! `PeerConnectivityPlan` remain the source authorities for identity admission and candidate
//! refresh semantics.

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
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, ReachabilityObservation,
    SelectedConnectivityPath, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

// This reference harness intentionally performs admission, freshness comparison, staging, and
// commit explicitly. Keep the lower authenticated-refresh adapter compile-linked without
// invoking it here, so the reference does not bypass the freshness boundary it is proving.
const _: fn(
    &WorkspaceDeviceRegistry,
    &AuthenticatedDeviceSession,
    &AuthenticatedCandidatePublication,
    &mut PeerConnectivityPlan,
) -> Result<(), CandidateReachabilityError> = refresh_from_authenticated_publication;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestFreshnessState {
    Initial,
    AfterFirstCommit,
    AfterSecondCommit,
}

impl TestFreshnessState {
    const fn next(self) -> Option<Self> {
        match self {
            Self::Initial => Some(Self::AfterFirstCommit),
            Self::AfterFirstCommit => Some(Self::AfterSecondCommit),
            Self::AfterSecondCommit => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestTraversalLifecycle {
    BeforeRefresh,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshnessReferenceError {
    FreshnessUnavailable,
    StaleExpectedFreshness,
    TestFreshnessExhausted,
    Admission(CandidateReachabilityError),
}

struct FreshnessReachabilityReference {
    plan: PeerConnectivityPlan,
    current_freshness: Option<TestFreshnessState>,
    current_traversal: Option<TestTraversalLifecycle>,
}

impl FreshnessReachabilityReference {
    const fn with_current_freshness(
        plan: PeerConnectivityPlan,
        current_freshness: TestFreshnessState,
        traversal: TestTraversalLifecycle,
    ) -> Self {
        Self {
            plan,
            current_freshness: Some(current_freshness),
            current_traversal: Some(traversal),
        }
    }

    const fn without_current_freshness(
        plan: PeerConnectivityPlan,
        traversal: TestTraversalLifecycle,
    ) -> Self {
        Self {
            plan,
            current_freshness: None,
            current_traversal: Some(traversal),
        }
    }

    const fn plan(&self) -> &PeerConnectivityPlan {
        &self.plan
    }

    const fn current_freshness(&self) -> Option<TestFreshnessState> {
        self.current_freshness
    }

    const fn current_traversal(&self) -> Option<TestTraversalLifecycle> {
        self.current_traversal
    }

    fn install_replacement_traversal(&mut self) {
        assert!(
            self.current_traversal.is_none(),
            "replacement traversal follows a successful refresh invalidation"
        );
        self.current_traversal = Some(TestTraversalLifecycle::Replacement);
    }

    fn commit_publication(
        &mut self,
        expected_freshness: TestFreshnessState,
        registry: &WorkspaceDeviceRegistry,
        requester_session: &AuthenticatedDeviceSession,
        publication: &AuthenticatedCandidatePublication,
    ) -> Result<TestFreshnessState, FreshnessReferenceError> {
        // Preserve the locked C02e ordering: current requester/publisher/workspace/target/transport
        // admission is checked before exposing freshness comparison results to the caller.
        validate_authenticated_publication_admission(
            registry,
            requester_session,
            publication,
            &self.plan,
        )
        .map_err(FreshnessReferenceError::Admission)?;

        let current = self
            .current_freshness
            .ok_or(FreshnessReferenceError::FreshnessUnavailable)?;
        if current != expected_freshness {
            return Err(FreshnessReferenceError::StaleExpectedFreshness);
        }
        let next = current
            .next()
            .ok_or(FreshnessReferenceError::TestFreshnessExhausted)?;

        // Stage candidate-plan validation against a private clone after freshness admission. A
        // rejected vector cannot mutate the authoritative plan or consume freshness.
        let mut staged_plan = self.plan.clone();
        staged_plan
            .refresh_candidates(publication.candidates().to_vec())
            .map_err(|error| {
                FreshnessReferenceError::Admission(CandidateReachabilityError::Connectivity(error))
            })?;

        // No fallible work remains. Exclusive `&mut self` ownership makes these state moves one
        // serialized reference-model commit: refreshed plan, advanced verifier state, and stale
        // previous traversal lifecycle become externally observable together.
        self.plan = staged_plan;
        self.current_freshness = Some(next);
        self.current_traversal = None;
        Ok(next)
    }

    fn apply_observation(
        &mut self,
        traversal: TestTraversalLifecycle,
        candidate_id: CandidateId,
        observation: ReachabilityObservation,
    ) -> Result<(), ConnectivityError> {
        assert_eq!(
            self.current_traversal,
            Some(traversal),
            "test helper applies observations only for the current traversal lifecycle"
        );
        self.plan.set_observation(candidate_id, observation)
    }
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable freshness-reference key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable freshness-reference signer")
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
    requester_session: AuthenticatedDeviceSession,
    second_requester_session: AuthenticatedDeviceSession,
    target_session: AuthenticatedDeviceSession,
    target_signer: UbuntuEnrollmentSigner,
    target_binding: DeviceIdentityBinding,
    target_transport: TransportIdentity,
    plan: PeerConnectivityPlan,
}

fn fixture() -> Fixture {
    let requester_signer = signer();
    let second_requester_signer = signer();
    let target_signer = signer();
    let workspace_id = WorkspaceId::new("workspace-freshness-reference").expect("workspace id");
    let requester_user = UserId::new("requester-freshness-reference").expect("user id");
    let second_requester_user = UserId::new("requester-two-freshness-reference").expect("user id");
    let target_user = UserId::new("target-freshness-reference").expect("user id");
    let requester_binding = binding(
        &requester_signer,
        workspace_id.clone(),
        requester_user.clone(),
        "requester-freshness-reference",
    );
    let second_requester_binding = binding(
        &second_requester_signer,
        workspace_id.clone(),
        second_requester_user.clone(),
        "requester-two-freshness-reference",
    );
    let target_binding = binding(
        &target_signer,
        workspace_id.clone(),
        target_user.clone(),
        "target-freshness-reference",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester_session = session(
        &requester_signer,
        &requester_binding,
        "session-requester-freshness-reference",
    );
    let second_requester_session = session(
        &second_requester_signer,
        &second_requester_binding,
        "session-requester-two-freshness-reference",
    );
    let target_session = session(
        &target_signer,
        &target_binding,
        "session-target-freshness-reference",
    );
    let target_transport = transport(2);

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace_id.clone(), requester_user, WorkspaceRole::Member)
        .expect("requester membership");
    registry
        .add_membership(
            workspace_id.clone(),
            second_requester_user,
            WorkspaceRole::Member,
        )
        .expect("second requester membership");
    registry
        .add_membership(workspace_id, target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .register_device(requester_binding)
        .expect("requester device");
    registry
        .register_device(second_requester_binding)
        .expect("second requester device");
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
        second_requester_session,
        target_session,
        target_signer,
        target_binding,
        target_transport,
        plan,
    }
}

#[test]
fn stale_or_duplicate_expected_freshness_fails_before_authoritative_mutation() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("bounded current publication");
    let mut owner = FreshnessReachabilityReference::with_current_freshness(
        fixture.plan,
        TestFreshnessState::Initial,
        TestTraversalLifecycle::BeforeRefresh,
    );

    assert_eq!(
        owner
            .commit_publication(
                TestFreshnessState::Initial,
                &fixture.registry,
                &fixture.requester_session,
                &publication,
            )
            .expect("first publication commits"),
        TestFreshnessState::AfterFirstCommit
    );
    owner.install_replacement_traversal();
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_publication(
            TestFreshnessState::Initial,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(FreshnessReferenceError::StaleExpectedFreshness)
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(
        owner.current_freshness(),
        Some(TestFreshnessState::AfterFirstCommit)
    );
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::Replacement)
    );
}

#[test]
fn candidate_validation_failure_does_not_consume_current_freshness() {
    let fixture = fixture();
    let rebound = candidate(1, ConnectivityPathKind::LocalDirect, 9001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![rebound],
    )
    .expect("publication is internally valid before target-plan refresh");
    let mut owner = FreshnessReachabilityReference::with_current_freshness(
        fixture.plan,
        TestFreshnessState::Initial,
        TestTraversalLifecycle::BeforeRefresh,
    );
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_publication(
            TestFreshnessState::Initial,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(FreshnessReferenceError::Admission(
            CandidateReachabilityError::Connectivity(ConnectivityError::CandidateIdRebound)
        ))
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(owner.current_freshness(), Some(TestFreshnessState::Initial));
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::BeforeRefresh)
    );
}

#[test]
fn same_peer_session_renewal_continues_the_existing_freshness_lifecycle() {
    let fixture = fixture();
    let current = candidate(2, ConnectivityPathKind::InternetDirect, 3002);
    let first_publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![current],
    )
    .expect("first publication");
    let mut owner = FreshnessReachabilityReference::with_current_freshness(
        fixture.plan,
        TestFreshnessState::Initial,
        TestTraversalLifecycle::BeforeRefresh,
    );

    assert_eq!(
        owner
            .commit_publication(
                TestFreshnessState::Initial,
                &fixture.registry,
                &fixture.requester_session,
                &first_publication,
            )
            .expect("first publication commits"),
        TestFreshnessState::AfterFirstCommit
    );
    owner.install_replacement_traversal();

    let renewed_target_session = session(
        &fixture.target_signer,
        &fixture.target_binding,
        "session-target-freshness-reference-renewed",
    );
    let renewed_publication = publish_current_candidates(
        &fixture.registry,
        &renewed_target_session,
        fixture.target_transport,
        vec![current],
    )
    .expect("renewed-session publication");

    assert_eq!(
        owner
            .commit_publication(
                TestFreshnessState::AfterFirstCommit,
                &fixture.registry,
                &fixture.requester_session,
                &renewed_publication,
            )
            .expect("renewed session continues current peer freshness"),
        TestFreshnessState::AfterSecondCommit
    );
    assert_eq!(
        owner.current_freshness(),
        Some(TestFreshnessState::AfterSecondCommit)
    );
    assert_eq!(owner.current_traversal(), None);
}

#[test]
fn requester_change_does_not_create_an_independent_replay_namespace() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("target publication");
    let mut owner = FreshnessReachabilityReference::with_current_freshness(
        fixture.plan,
        TestFreshnessState::Initial,
        TestTraversalLifecycle::BeforeRefresh,
    );

    owner
        .commit_publication(
            TestFreshnessState::Initial,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        )
        .expect("first requester commits target publication");
    owner.install_replacement_traversal();
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_publication(
            TestFreshnessState::Initial,
            &fixture.registry,
            &fixture.second_requester_session,
            &publication,
        ),
        Err(FreshnessReferenceError::StaleExpectedFreshness)
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(
        owner.current_freshness(),
        Some(TestFreshnessState::AfterFirstCommit)
    );
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::Replacement)
    );
}

#[test]
fn unavailable_verifier_state_fails_closed_without_resetting_to_an_initial_baseline() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("target publication");
    let mut owner = FreshnessReachabilityReference::without_current_freshness(
        fixture.plan,
        TestTraversalLifecycle::BeforeRefresh,
    );
    let before = owner.plan().clone();

    assert_eq!(
        owner.commit_publication(
            TestFreshnessState::Initial,
            &fixture.registry,
            &fixture.requester_session,
            &publication,
        ),
        Err(FreshnessReferenceError::FreshnessUnavailable)
    );
    assert_eq!(owner.plan(), &before);
    assert_eq!(owner.current_freshness(), None);
    assert_eq!(
        owner.current_traversal(),
        Some(TestTraversalLifecycle::BeforeRefresh)
    );
}

#[test]
fn successful_commit_advances_freshness_resets_observation_and_invalidates_traversal_together() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target_session,
        fixture.target_transport,
        vec![retained],
    )
    .expect("target publication");
    let mut owner = FreshnessReachabilityReference::with_current_freshness(
        fixture.plan,
        TestFreshnessState::Initial,
        TestTraversalLifecycle::BeforeRefresh,
    );
    owner
        .apply_observation(
            TestTraversalLifecycle::BeforeRefresh,
            retained.id(),
            ReachabilityObservation::Reachable,
        )
        .expect("pre-refresh observation applies");
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Candidate(retained)
    );

    assert_eq!(
        owner
            .commit_publication(
                TestFreshnessState::Initial,
                &fixture.registry,
                &fixture.requester_session,
                &publication,
            )
            .expect("publication commit"),
        TestFreshnessState::AfterFirstCommit
    );

    assert_eq!(
        owner.current_freshness(),
        Some(TestFreshnessState::AfterFirstCommit)
    );
    assert_eq!(owner.current_traversal(), None);
    assert_eq!(
        owner.plan().selected_path(),
        SelectedConnectivityPath::Offline
    );
}
