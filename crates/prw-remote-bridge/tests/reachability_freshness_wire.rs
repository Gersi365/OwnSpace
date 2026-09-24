//! Phase 152 C02e Tranche 5 freshness wire and authenticated resynchronization checks.
//!
//! All durable state is in-memory and all wire work is byte-buffer framing only. No socket,
//! async runtime, network adapter, Agent bootstrap or deployment path is activated.

use std::{
    cell::RefCell,
    future::{Future, ready},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    PeerConnectivityIdentity, PeerConnectivityPlan, TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_registry::{RegistryError, WorkspaceDeviceRegistry, WorkspaceRole};
use prw_remote_bridge::{
    candidate_publication_freshness::{
        CandidatePublicationFreshnessLifecycle, CandidatePublicationFreshnessRecord,
        CandidatePublicationFreshnessToken,
    },
    reachability_freshness_wire::{
        FreshnessResynchronizationError, FreshnessTokenDeliveryReason, FreshnessWireFailureCode,
        ReachabilityFreshnessWireError, ReachabilityFreshnessWireMessage,
        authenticated_current_token_resynchronization, bootstrap_token_delivery,
    },
    reachability_owner::{
        ReachabilityDurableSnapshot, ReachabilityDurableStore, ReachabilityPersistenceCommit,
        ReachabilityPersistenceError,
    },
};
use prw_remote_transport::{ControlFrame, ControlMessageKind};
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
    loads: Rc<RefCell<usize>>,
}

impl MemoryStoreHandle {
    fn replace(&self, snapshot: ReachabilityDurableSnapshot) {
        *self.current.borrow_mut() = Some(snapshot);
    }

    fn clear(&self) {
        *self.current.borrow_mut() = None;
    }

    fn loads(&self) -> usize {
        *self.loads.borrow()
    }
}

struct MemoryStore {
    handle: MemoryStoreHandle,
}

impl MemoryStore {
    fn seeded(snapshot: ReachabilityDurableSnapshot) -> (Self, MemoryStoreHandle) {
        let handle = MemoryStoreHandle {
            current: Rc::new(RefCell::new(Some(snapshot))),
            loads: Rc::new(RefCell::new(0)),
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
        *self.handle.loads.borrow_mut() += 1;
        let result = Ok(self
            .handle
            .current
            .borrow()
            .as_ref()
            .filter(|snapshot| snapshot.plan().peer() == peer)
            .cloned());
        ready(result)
    }

    #[allow(
        clippy::manual_async_fn,
        reason = "test store is intentionally !Send; this explicit future captures no Rc-backed store borrow and still satisfies the production Send-future contract"
    )]
    fn compare_and_commit<'a>(
        &'a mut self,
        _expected_current: CandidatePublicationFreshnessToken,
        _replacement: &'a ReachabilityDurableSnapshot,
    ) -> impl Future<Output = Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError>>
    + Send
    + 'a {
        async { panic!("resynchronization must never compare-and-commit") }
    }
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    target: AuthenticatedDeviceSession,
    other: AuthenticatedDeviceSession,
    target_device_id: DeviceId,
    transport: TransportIdentity,
    plan: PeerConnectivityPlan,
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

fn plan(device: DeviceId, transport_identity: TransportIdentity) -> PeerConnectivityPlan {
    let candidate = ConnectivityCandidate::new(
        CandidateId::new(1).expect("candidate id"),
        ConnectivityPathKind::LocalDirect,
        ConnectivityEndpoint::new("127.0.0.1".parse().expect("ip"), 53001).expect("endpoint"),
    );
    PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(device, transport_identity),
        vec![candidate],
    )
    .expect("plan")
}

fn fixture() -> Fixture {
    let target_signer = signer();
    let other_signer = signer();
    let workspace = WorkspaceId::new("workspace-tranche5-wire").expect("workspace");
    let target_user = UserId::new("target-tranche5-wire").expect("target user");
    let other_user = UserId::new("other-tranche5-wire").expect("other user");
    let target_binding = binding(
        &target_signer,
        workspace.clone(),
        target_user.clone(),
        "target-tranche5-wire",
    );
    let other_binding = binding(
        &other_signer,
        workspace.clone(),
        other_user.clone(),
        "other-tranche5-wire",
    );
    let target = authenticated_session(
        &target_signer,
        &target_binding,
        "session-target-tranche5-wire",
    );
    let other = authenticated_session(&other_signer, &other_binding, "session-other-tranche5-wire");
    let target_device_id = target_binding.device_id.clone();
    let current_transport = transport(31);
    let other_transport = transport(32);
    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace.clone(), target_user, WorkspaceRole::Member)
        .expect("target membership");
    registry
        .add_membership(workspace, other_user, WorkspaceRole::Member)
        .expect("other membership");
    registry
        .register_device(target_binding)
        .expect("target device");
    registry
        .register_device(other_binding.clone())
        .expect("other device");
    registry
        .bind_transport_identity(&target_device_id, current_transport)
        .expect("target transport");
    registry
        .bind_transport_identity(&other_binding.device_id, other_transport)
        .expect("other transport");
    let plan = plan(target_device_id.clone(), current_transport);
    Fixture {
        registry,
        target,
        other,
        target_device_id,
        transport: current_transport,
        plan,
    }
}

fn store_for(
    fixture: &Fixture,
    lifecycle: CandidatePublicationFreshnessLifecycle,
) -> (MemoryStore, MemoryStoreHandle) {
    let record = match lifecycle {
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(token) => {
            CandidatePublicationFreshnessRecord::new_lifecycle_eligible(
                fixture.plan.peer().clone(),
                token,
            )
        }
        CandidatePublicationFreshnessLifecycle::Established(token) => {
            CandidatePublicationFreshnessRecord::established(fixture.plan.peer().clone(), token)
        }
        CandidatePublicationFreshnessLifecycle::RecoveryRequired => {
            CandidatePublicationFreshnessRecord::recovery_required(fixture.plan.peer().clone())
        }
        CandidatePublicationFreshnessLifecycle::Retired => {
            CandidatePublicationFreshnessRecord::retired(fixture.plan.peer().clone())
        }
    };
    let snapshot =
        ReachabilityDurableSnapshot::new(fixture.plan.durable_state(), record).expect("snapshot");
    MemoryStore::seeded(snapshot)
}

#[test]
fn request_delivery_and_failure_round_trip_with_exact_outer_kinds() {
    let transport = transport(41);
    let token = freshness(42);
    let request =
        ReachabilityFreshnessWireMessage::current_token_resynchronization_request(transport);
    let request_frame = request.into_control_frame(7).expect("request frame");
    assert_eq!(request_frame.kind(), ControlMessageKind::Request);
    assert_eq!(request_frame.request_id(), 7);
    assert_eq!(
        ReachabilityFreshnessWireMessage::from_control_frame(&request_frame)
            .expect("decode request"),
        request
    );

    for reason in [
        FreshnessTokenDeliveryReason::Bootstrap,
        FreshnessTokenDeliveryReason::AcceptedPublication,
        FreshnessTokenDeliveryReason::Resynchronization,
    ] {
        let delivery = ReachabilityFreshnessWireMessage::token_delivery(reason, transport, token);
        let frame = delivery.into_control_frame(8).expect("delivery frame");
        assert_eq!(frame.kind(), ControlMessageKind::Response);
        assert_eq!(
            ReachabilityFreshnessWireMessage::from_control_frame(&frame).expect("decode delivery"),
            delivery
        );
    }

    let failure = ReachabilityFreshnessWireMessage::failure(FreshnessWireFailureCode::Retired);
    let frame = failure.into_control_frame(9).expect("failure frame");
    assert_eq!(frame.kind(), ControlMessageKind::Error);
    assert_eq!(
        ReachabilityFreshnessWireMessage::from_control_frame(&frame).expect("decode failure"),
        failure
    );
}

#[test]
fn malformed_or_wrong_outer_kind_payloads_fail_closed() {
    let transport = transport(43);
    let request =
        ReachabilityFreshnessWireMessage::current_token_resynchronization_request(transport);
    let mut payload = request.encode();
    payload[10] = 1;
    assert_eq!(
        ReachabilityFreshnessWireMessage::decode(&payload),
        Err(ReachabilityFreshnessWireError::InvalidPayload)
    );

    let mut zero_transport = request.encode();
    zero_transport[12..44].fill(0);
    assert_eq!(
        ReachabilityFreshnessWireMessage::decode(&zero_transport),
        Err(ReachabilityFreshnessWireError::InvalidPayload)
    );

    let wrong_outer = ControlFrame::new(ControlMessageKind::Response, 11, request.encode())
        .expect("wrong-kind frame");
    assert_eq!(
        ReachabilityFreshnessWireMessage::from_control_frame(&wrong_outer),
        Err(ReachabilityFreshnessWireError::WrongControlMessageKind)
    );
}

#[test]
fn bootstrap_delivery_requires_an_authoritative_bootstrap_record() {
    let fixture = fixture();
    let token = freshness(44);
    let bootstrap = CandidatePublicationFreshnessRecord::new_lifecycle_eligible(
        fixture.plan.peer().clone(),
        token,
    );
    assert_eq!(
        bootstrap_token_delivery(&bootstrap).expect("bootstrap delivery"),
        ReachabilityFreshnessWireMessage::token_delivery(
            FreshnessTokenDeliveryReason::Bootstrap,
            fixture.transport,
            token,
        )
    );

    let established =
        CandidatePublicationFreshnessRecord::established(fixture.plan.peer().clone(), token);
    assert_eq!(
        bootstrap_token_delivery(&established),
        Err(ReachabilityFreshnessWireError::BootstrapRecordRequired)
    );
}

#[test]
fn authenticated_resync_redelivers_exact_authoritative_token_without_commit() {
    let fixture = fixture();
    let token = freshness(45);
    let (mut store, handle) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::Established(token),
    );

    let message = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut store,
    ))
    .expect("authenticated resync");

    assert_eq!(handle.loads(), 1);
    assert_eq!(
        message,
        ReachabilityFreshnessWireMessage::token_delivery(
            FreshnessTokenDeliveryReason::Resynchronization,
            fixture.transport,
            token,
        )
    );
}

#[test]
fn resync_reads_durable_state_each_time_and_returns_the_new_current_token() {
    let fixture = fixture();
    let first = freshness(46);
    let second = freshness(47);
    let (mut store, handle) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::Established(first),
    );

    let first_delivery = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut store,
    ))
    .expect("first resync");
    assert_eq!(
        first_delivery,
        ReachabilityFreshnessWireMessage::token_delivery(
            FreshnessTokenDeliveryReason::Resynchronization,
            fixture.transport,
            first,
        )
    );

    handle.replace(
        ReachabilityDurableSnapshot::new(
            fixture.plan.durable_state(),
            CandidatePublicationFreshnessRecord::established(fixture.plan.peer().clone(), second),
        )
        .expect("replacement snapshot"),
    );
    let second_delivery = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut store,
    ))
    .expect("second resync");
    assert_eq!(handle.loads(), 2);
    assert_eq!(
        second_delivery,
        ReachabilityFreshnessWireMessage::token_delivery(
            FreshnessTokenDeliveryReason::Resynchronization,
            fixture.transport,
            second,
        )
    );
}

#[test]
fn currentness_is_revalidated_before_durable_lookup() {
    let fixture = fixture();
    let token = freshness(48);
    let (mut store, handle) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::Established(token),
    );

    let error = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.other,
        fixture.transport,
        &mut store,
    ))
    .expect_err("other device cannot obtain target token");
    assert!(matches!(
        error,
        FreshnessResynchronizationError::Registry(_)
    ));
    assert_eq!(
        error.wire_failure_code(),
        FreshnessWireFailureCode::CurrentnessRejected
    );
    assert_eq!(handle.loads(), 0);
}

#[test]
fn recovery_retired_and_missing_durable_state_never_disclose_tokens() {
    let fixture = fixture();

    let (mut recovery_store, _) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::RecoveryRequired,
    );
    let recovery = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut recovery_store,
    ))
    .expect_err("recovery state blocks token");
    assert_eq!(recovery, FreshnessResynchronizationError::RecoveryRequired);
    assert_eq!(
        recovery.wire_failure_code(),
        FreshnessWireFailureCode::RecoveryRequired
    );

    let (mut retired_store, _) =
        store_for(&fixture, CandidatePublicationFreshnessLifecycle::Retired);
    let retired = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut retired_store,
    ))
    .expect_err("retired state blocks token");
    assert_eq!(retired, FreshnessResynchronizationError::Retired);
    assert_eq!(
        retired.wire_failure_code(),
        FreshnessWireFailureCode::Retired
    );

    let (mut missing_store, missing_handle) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::Established(freshness(49)),
    );
    missing_handle.clear();
    let missing = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut missing_store,
    ))
    .expect_err("missing state blocks token");
    assert_eq!(
        missing,
        FreshnessResynchronizationError::DurableStateMissing
    );
    assert_eq!(
        missing.wire_failure_code(),
        FreshnessWireFailureCode::DurableStateMissing
    );
}

#[test]
fn registry_transport_rotation_blocks_old_identity_before_store_read() {
    let mut fixture = fixture();
    let token = freshness(50);
    let (mut store, handle) = store_for(
        &fixture,
        CandidatePublicationFreshnessLifecycle::Established(token),
    );
    fixture
        .registry
        .rotate_transport_identity(&fixture.target_device_id, fixture.transport, transport(51))
        .expect("rotate transport");

    let error = resolve_ready(authenticated_current_token_resynchronization(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        &mut store,
    ))
    .expect_err("old transport cannot resync");
    assert!(matches!(
        error,
        FreshnessResynchronizationError::Registry(RegistryError::TransportIdentityMismatch)
    ));
    assert_eq!(handle.loads(), 0);
}
