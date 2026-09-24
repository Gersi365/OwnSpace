//! Phase 152 C02e Tranche 4 executable production-owner seam checks.
//!
//! These tests exercise authenticated publication admission, durable expected-current CAS,
//! fail-closed recovery, traversal invalidation and durable retirement. They use only in-memory
//! stores and Sans-I/O Phase 141 objects; no socket, async runtime or network adapter is opened.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::{Future, ready},
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan,
    PeerConnectivityPlanDurableState, SelectedConnectivityPath, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_nat_traversal::IceConnectivitySession;
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_remote_bridge::{
    candidate_publication_freshness::{
        CandidatePublicationFreshnessLifecycle, CandidatePublicationFreshnessRecord,
        CandidatePublicationFreshnessToken,
    },
    candidate_reachability::publish_current_candidates,
    reachability_owner::{
        CandidatePublicationFreshnessTokenSource, FreshnessTokenSourceError,
        ProductionReachabilityOwner, ReachabilityDurableSnapshot, ReachabilityDurableStore,
        ReachabilityOwnerError, ReachabilityOwnerMode, ReachabilityPersistenceCommit,
        ReachabilityPersistenceError, ReachabilitySnapshotError, ReachabilityTraversalFactory,
        ReachabilityTraversalFactoryError,
    },
};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

fn resolve_ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

#[derive(Clone)]
struct MemoryStoreHandle {
    current: Rc<RefCell<Option<ReachabilityDurableSnapshot>>>,
    ambiguous_next_commit: Rc<Cell<bool>>,
}

impl MemoryStoreHandle {
    fn replace(&self, snapshot: ReachabilityDurableSnapshot) {
        *self.current.borrow_mut() = Some(snapshot);
    }

    fn snapshot(&self) -> ReachabilityDurableSnapshot {
        self.current
            .borrow()
            .as_ref()
            .expect("seeded durable snapshot")
            .clone()
    }

    fn make_next_commit_ambiguous(&self) {
        self.ambiguous_next_commit.set(true);
    }
}

struct MemoryStore {
    handle: MemoryStoreHandle,
}

impl MemoryStore {
    fn seeded(snapshot: ReachabilityDurableSnapshot) -> (Self, MemoryStoreHandle) {
        let handle = MemoryStoreHandle {
            current: Rc::new(RefCell::new(Some(snapshot))),
            ambiguous_next_commit: Rc::new(Cell::new(false)),
        };
        (
            Self {
                handle: handle.clone(),
            },
            handle,
        )
    }
}

impl ReachabilityDurableStore for MemoryStore {
    fn load_current<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<Option<ReachabilityDurableSnapshot>, ReachabilityPersistenceError>,
    > + Send
    + 'a {
        let result = Ok(self
            .handle
            .current
            .borrow()
            .as_ref()
            .filter(|snapshot| snapshot.plan().peer() == peer)
            .cloned());
        ready(result)
    }

    fn compare_and_commit<'a>(
        &'a mut self,
        expected_current: CandidatePublicationFreshnessToken,
        replacement: &'a ReachabilityDurableSnapshot,
    ) -> impl Future<Output = Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError>>
    + Send
    + 'a {
        let result = if self.handle.ambiguous_next_commit.replace(false) {
            Err(ReachabilityPersistenceError::UnavailableOrAmbiguous)
        } else {
            let current_token = self
                .handle
                .current
                .borrow()
                .as_ref()
                .and_then(|snapshot| snapshot.freshness().lifecycle().current_token());
            if current_token == Some(expected_current) {
                *self.handle.current.borrow_mut() = Some(replacement.clone());
                Ok(ReachabilityPersistenceCommit::Committed)
            } else {
                Ok(ReachabilityPersistenceCommit::StaleExpected)
            }
        };
        ready(result)
    }
}

struct TokenSource {
    tokens: VecDeque<CandidatePublicationFreshnessToken>,
}

impl TokenSource {
    fn new(tokens: impl IntoIterator<Item = CandidatePublicationFreshnessToken>) -> Self {
        Self {
            tokens: tokens.into_iter().collect(),
        }
    }
}

impl CandidatePublicationFreshnessTokenSource for TokenSource {
    fn issue_token(
        &mut self,
    ) -> Result<CandidatePublicationFreshnessToken, FreshnessTokenSourceError> {
        self.tokens
            .pop_front()
            .ok_or(FreshnessTokenSourceError::Unavailable)
    }
}

struct NewTraversalFactory;

impl ReachabilityTraversalFactory for NewTraversalFactory {
    fn build_for_current_plan(
        &mut self,
        plan: &PeerConnectivityPlan,
    ) -> Result<IceConnectivitySession, ReachabilityTraversalFactoryError> {
        assert!(plan.candidate_count() > 0);
        IceConnectivitySession::new()
            .map_err(|_| ReachabilityTraversalFactoryError::UnavailableOrInvalidCoordination)
    }
}

struct FailingTraversalFactory;

impl ReachabilityTraversalFactory for FailingTraversalFactory {
    fn build_for_current_plan(
        &mut self,
        _plan: &PeerConnectivityPlan,
    ) -> Result<IceConnectivitySession, ReachabilityTraversalFactoryError> {
        Err(ReachabilityTraversalFactoryError::UnavailableOrInvalidCoordination)
    }
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    requester: AuthenticatedDeviceSession,
    target: AuthenticatedDeviceSession,
    target_device_id: DeviceId,
    transport: TransportIdentity,
    initial_candidate: ConnectivityCandidate,
    initial_plan: PeerConnectivityPlan,
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("load signer")
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

fn authenticated_session(
    signer: &UbuntuEnrollmentSigner,
    binding: &DeviceIdentityBinding,
    session_id: &str,
) -> AuthenticatedDeviceSession {
    let mut service = SessionAuthenticationService::new();
    let session_id = SessionId::new(session_id).expect("session id");
    let challenge = service
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
        .expect("begin session");
    let proof = signer
        .sign_session_auth_proof(binding, &challenge)
        .expect("sign proof");
    service
        .submit_proof(&session_id, &proof, 1_001)
        .expect("authenticate")
}

fn transport(seed: u8) -> TransportIdentity {
    TransportIdentity::new([seed; 32]).expect("transport")
}

fn freshness(seed: u8) -> CandidatePublicationFreshnessToken {
    CandidatePublicationFreshnessToken::new([seed; 32]).expect("freshness")
}

fn endpoint(port: u16) -> ConnectivityEndpoint {
    ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("endpoint")
}

fn candidate(id: u64, kind: ConnectivityPathKind, port: u16) -> ConnectivityCandidate {
    ConnectivityCandidate::new(
        CandidateId::new(id).expect("candidate id"),
        kind,
        endpoint(port),
    )
}

fn fixture() -> Fixture {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace = WorkspaceId::new("workspace-tranche4-owner").expect("workspace");
    let requester_user = UserId::new("requester-tranche4-owner").expect("requester user");
    let target_user = UserId::new("target-tranche4-owner").expect("target user");
    let requester_binding = binding(
        &requester_signer,
        workspace.clone(),
        requester_user.clone(),
        "requester-tranche4-owner",
    );
    let target_binding = binding(
        &target_signer,
        workspace.clone(),
        target_user.clone(),
        "target-tranche4-owner",
    );
    let requester = authenticated_session(
        &requester_signer,
        &requester_binding,
        "session-requester-tranche4-owner",
    );
    let target = authenticated_session(
        &target_signer,
        &target_binding,
        "session-target-tranche4-owner",
    );
    let target_device_id = target_binding.device_id.clone();
    let transport = transport(21);
    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace.clone(), requester_user, WorkspaceRole::Member)
        .expect("requester membership");
    registry
        .add_membership(workspace, target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .register_device(requester_binding)
        .expect("requester device");
    registry
        .register_device(target_binding)
        .expect("target device");
    registry
        .bind_transport_identity(&target_device_id, transport)
        .expect("transport binding");
    let initial_candidate = candidate(1, ConnectivityPathKind::LocalDirect, 52001);
    let initial_plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device_id.clone(), transport),
        vec![initial_candidate],
    )
    .expect("initial plan");
    Fixture {
        registry,
        requester,
        target,
        target_device_id,
        transport,
        initial_candidate,
        initial_plan,
    }
}

fn owner(
    fixture: &Fixture,
    initial_freshness: CandidatePublicationFreshnessToken,
    replacements: impl IntoIterator<Item = CandidatePublicationFreshnessToken>,
) -> (
    ProductionReachabilityOwner<MemoryStore, TokenSource>,
    MemoryStoreHandle,
) {
    let freshness = CandidatePublicationFreshnessRecord::new_lifecycle_eligible(
        fixture.initial_plan.peer().clone(),
        initial_freshness,
    );
    let snapshot =
        ReachabilityDurableSnapshot::new(fixture.initial_plan.durable_state(), freshness)
            .expect("peer-consistent seed");
    let (store, handle) = MemoryStore::seeded(snapshot);
    let owner = resolve_ready(ProductionReachabilityOwner::recover(
        store,
        TokenSource::new(replacements),
        fixture.initial_plan.peer(),
    ))
    .expect("recover owner");
    (owner, handle)
}

#[test]
fn successful_commit_advances_durable_freshness_and_invalidates_current_traversal() {
    let fixture = fixture();
    let current = freshness(1);
    let replacement = freshness(2);
    let (mut owner, store) = owner(&fixture, current, [replacement]);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");
    assert!(owner.has_current_traversal());

    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![fixture.initial_candidate],
    )
    .expect("authenticated publication");
    let outcome = resolve_ready(owner.commit_candidate_publication(
        &fixture.registry,
        &fixture.requester,
        &publication,
        current,
    ))
    .expect("durable publication commit");

    assert_eq!(outcome.replacement_freshness(), replacement);
    assert!(outcome.invalidated_traversal());
    assert!(!owner.has_current_traversal());
    assert_eq!(owner.mode(), ReachabilityOwnerMode::Current);
    assert_eq!(owner.selected_path(), SelectedConnectivityPath::Offline);
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(replacement)
    );
    let durable = store.snapshot();
    assert_eq!(
        durable.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(replacement)
    );
    assert_eq!(durable.plan().candidates(), &[fixture.initial_candidate]);
    assert_eq!(
        durable.plan().candidate_id_high_watermark(),
        Some(CandidateId::new(1).expect("candidate id"))
    );

    assert_eq!(
        resolve_ready(owner.commit_candidate_publication(
            &fixture.registry,
            &fixture.requester,
            &publication,
            current,
        )),
        Err(ReachabilityOwnerError::StalePublicationFreshness)
    );
}

#[test]
fn durable_recovery_preserves_historical_high_watermark_and_blocks_removed_id_reuse() {
    let fixture = fixture();
    let current = freshness(23);
    let replacement = freshness(24);
    let historical = candidate(2, ConnectivityPathKind::InternetDirect, 52002);
    let mut historical_plan = fixture.initial_plan.clone();
    historical_plan
        .refresh_candidates(vec![historical])
        .expect("advance high-watermark");
    historical_plan
        .refresh_candidates(Vec::new())
        .expect("remove historical candidate");
    assert_eq!(
        historical_plan.candidate_id_high_watermark(),
        Some(CandidateId::new(2).expect("candidate id"))
    );

    let snapshot = ReachabilityDurableSnapshot::new(
        historical_plan.durable_state(),
        CandidatePublicationFreshnessRecord::established(historical_plan.peer().clone(), current),
    )
    .expect("historical durable snapshot");
    let (store, handle) = MemoryStore::seeded(snapshot);
    let mut owner = resolve_ready(ProductionReachabilityOwner::recover(
        store,
        TokenSource::new([replacement]),
        historical_plan.peer(),
    ))
    .expect("recover historical high-watermark");

    assert_eq!(
        owner.plan().candidate_id_high_watermark(),
        Some(CandidateId::new(2).expect("candidate id"))
    );
    let reused = candidate(2, ConnectivityPathKind::Relay, 52003);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![reused],
    )
    .expect("bounded publication");
    assert_eq!(
        resolve_ready(owner.commit_candidate_publication(
            &fixture.registry,
            &fixture.requester,
            &publication,
            current,
        )),
        Err(ReachabilityOwnerError::Candidate(
            prw_remote_bridge::candidate_reachability::CandidateReachabilityError::Connectivity(
                ConnectivityError::CandidateIdRebound
            )
        ))
    );
    assert_eq!(owner.mode(), ReachabilityOwnerMode::Current);
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(current)
    );
    assert_eq!(
        handle.snapshot().plan().candidate_id_high_watermark(),
        Some(CandidateId::new(2).expect("candidate id"))
    );
}

#[test]
fn invalid_durable_high_watermark_fails_recovery_through_snapshot_classification() {
    let fixture = fixture();
    let current = freshness(25);
    let invalid_state = PeerConnectivityPlanDurableState::from_parts(
        fixture.initial_plan.peer().clone(),
        vec![fixture.initial_candidate],
        None,
    );
    let snapshot = ReachabilityDurableSnapshot::new(
        invalid_state,
        CandidatePublicationFreshnessRecord::established(
            fixture.initial_plan.peer().clone(),
            current,
        ),
    )
    .expect("cross-member peer consistency");
    let (store, _handle) = MemoryStore::seeded(snapshot);

    let result = resolve_ready(ProductionReachabilityOwner::recover(
        store,
        TokenSource::new([]),
        fixture.initial_plan.peer(),
    ));
    assert!(matches!(
        result,
        Err(ReachabilityOwnerError::Snapshot(
            ReachabilitySnapshotError::PlanRestoration(
                ConnectivityError::InvalidCandidateIdHighWatermark
            )
        ))
    ));
}

#[test]
fn invalid_durable_reload_enters_recovery_without_partial_freshness_install() {
    let fixture = fixture();
    let current = freshness(26);
    let durable_ahead = freshness(27);
    let (mut owner, store) = owner(&fixture, current, []);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");
    let invalid_state = PeerConnectivityPlanDurableState::from_parts(
        fixture.initial_plan.peer().clone(),
        vec![fixture.initial_candidate],
        None,
    );
    store.replace(
        ReachabilityDurableSnapshot::new(
            invalid_state,
            CandidatePublicationFreshnessRecord::established(
                fixture.initial_plan.peer().clone(),
                durable_ahead,
            ),
        )
        .expect("cross-member peer consistency"),
    );

    assert_eq!(
        resolve_ready(owner.reload_from_store()),
        Err(ReachabilityOwnerError::Snapshot(
            ReachabilitySnapshotError::PlanRestoration(
                ConnectivityError::InvalidCandidateIdHighWatermark
            )
        ))
    );
    assert_eq!(owner.mode(), ReachabilityOwnerMode::RecoveryRequired);
    assert!(!owner.has_current_traversal());
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(current)
    );
    assert_eq!(owner.plan(), &fixture.initial_plan);
}

#[test]
fn candidate_validation_failure_preserves_freshness_store_and_traversal() {
    let fixture = fixture();
    let current = freshness(3);
    let replacement = freshness(4);
    let (mut owner, store) = owner(&fixture, current, [replacement]);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");
    let rebound = candidate(1, ConnectivityPathKind::LocalDirect, 52999);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![rebound],
    )
    .expect("bounded publication");

    assert_eq!(
        resolve_ready(owner.commit_candidate_publication(
            &fixture.registry,
            &fixture.requester,
            &publication,
            current,
        )),
        Err(ReachabilityOwnerError::Candidate(
            prw_remote_bridge::candidate_reachability::CandidateReachabilityError::Connectivity(
                ConnectivityError::CandidateIdRebound
            )
        ))
    );
    assert!(owner.has_current_traversal());
    assert_eq!(owner.mode(), ReachabilityOwnerMode::Current);
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(current)
    );
    assert_eq!(
        store.snapshot().freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(current)
    );
}

#[test]
fn stale_durable_expected_state_forces_recovery_and_authoritative_reload() {
    let fixture = fixture();
    let local = freshness(5);
    let replacement = freshness(6);
    let durable_ahead = freshness(7);
    let (mut owner, store) = owner(&fixture, local, [replacement]);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");

    store.replace(
        ReachabilityDurableSnapshot::new(
            fixture.initial_plan.durable_state(),
            CandidatePublicationFreshnessRecord::established(
                fixture.initial_plan.peer().clone(),
                durable_ahead,
            ),
        )
        .expect("ahead snapshot"),
    );
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![fixture.initial_candidate],
    )
    .expect("publication");

    assert_eq!(
        resolve_ready(owner.commit_candidate_publication(
            &fixture.registry,
            &fixture.requester,
            &publication,
            local,
        )),
        Err(ReachabilityOwnerError::DurableStateOutOfSync)
    );
    assert_eq!(owner.mode(), ReachabilityOwnerMode::RecoveryRequired);
    assert!(!owner.has_current_traversal());
    assert_eq!(
        resolve_ready(owner.reload_from_store()).expect("authoritative reload"),
        ReachabilityOwnerMode::Current
    );
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(durable_ahead)
    );
}

#[test]
fn ambiguous_persistence_result_forces_recovery_without_reactivating_traversal() {
    let fixture = fixture();
    let current = freshness(8);
    let replacement = freshness(9);
    let (mut owner, store) = owner(&fixture, current, [replacement]);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");
    store.make_next_commit_ambiguous();
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![fixture.initial_candidate],
    )
    .expect("publication");

    assert_eq!(
        resolve_ready(owner.commit_candidate_publication(
            &fixture.registry,
            &fixture.requester,
            &publication,
            current,
        )),
        Err(ReachabilityOwnerError::Persistence(
            ReachabilityPersistenceError::UnavailableOrAmbiguous
        ))
    );
    assert_eq!(owner.mode(), ReachabilityOwnerMode::RecoveryRequired);
    assert!(!owner.has_current_traversal());
}

#[test]
fn postcommit_traversal_factory_failure_recovers_forward_without_plan_rollback() {
    let fixture = fixture();
    let current = freshness(10);
    let replacement = freshness(11);
    let (mut owner, _store) = owner(&fixture, current, [replacement]);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![fixture.initial_candidate],
    )
    .expect("publication");
    resolve_ready(owner.commit_candidate_publication(
        &fixture.registry,
        &fixture.requester,
        &publication,
        current,
    ))
    .expect("commit");

    assert_eq!(
        owner.provision_current_traversal(&mut FailingTraversalFactory),
        Err(ReachabilityOwnerError::TraversalFactory(
            ReachabilityTraversalFactoryError::UnavailableOrInvalidCoordination
        ))
    );
    assert_eq!(owner.mode(), ReachabilityOwnerMode::Current);
    assert!(!owner.has_current_traversal());
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(replacement)
    );
    assert_eq!(owner.selected_path(), SelectedConnectivityPath::Offline);
}

#[test]
fn transport_rotation_durably_retires_old_peer_and_drops_traversal() {
    let mut fixture = fixture();
    let current = freshness(12);
    let (mut owner, store) = owner(&fixture, current, []);
    owner
        .provision_current_traversal(&mut NewTraversalFactory)
        .expect("current traversal");
    fixture
        .registry
        .rotate_transport_identity(&fixture.target_device_id, fixture.transport, transport(22))
        .expect("authoritative transport rotation");

    resolve_ready(owner.retire_noncurrent_lifecycle(&fixture.registry))
        .expect("durable retirement");
    assert_eq!(owner.mode(), ReachabilityOwnerMode::Retired);
    assert!(!owner.has_current_traversal());
    assert_eq!(
        owner.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Retired
    );
    let durable = store.snapshot();
    assert_eq!(
        durable.freshness().lifecycle(),
        CandidatePublicationFreshnessLifecycle::Retired
    );
    assert_eq!(durable.plan().candidates(), &[fixture.initial_candidate]);
    assert_eq!(
        durable.plan().candidate_id_high_watermark(),
        Some(CandidateId::new(1).expect("candidate id"))
    );
}
