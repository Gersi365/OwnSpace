//! Phase 152 C02e Tranche 2 integration of the actual Phase 141 Sans-I/O ICE lifecycle.
//!
//! This is test composition only. It opens no socket and selects no production traversal owner.

#[path = "../src/candidate_reachability.rs"]
mod candidate_reachability;

use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

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
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, SelectedConnectivityPath,
    TransportIdentity,
};
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_nat_traversal::{
    CandidateReachabilityUpdate, IceCandidateClass, IceConnectivitySession, TraversalDatagram,
    TraversalError,
};
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreshnessAdmitted;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationError {
    StaleTraversal,
    Traversal(TraversalError),
}

struct Owner {
    plan: PeerConnectivityPlan,
    traversal: Option<Box<IceConnectivitySession>>,
}

impl Owner {
    fn new(plan: PeerConnectivityPlan, traversal: IceConnectivitySession) -> Self {
        Self {
            plan,
            traversal: Some(Box::new(traversal)),
        }
    }

    fn traversal_ptr(&self) -> Option<*const IceConnectivitySession> {
        self.traversal.as_deref().map(std::ptr::from_ref)
    }

    fn traversal_mut(&mut self) -> &mut IceConnectivitySession {
        self.traversal.as_deref_mut().expect("current traversal")
    }

    fn refresh(
        &mut self,
        _freshness: FreshnessAdmitted,
        registry: &WorkspaceDeviceRegistry,
        requester: &AuthenticatedDeviceSession,
        publication: &AuthenticatedCandidatePublication,
    ) -> Result<Option<Box<IceConnectivitySession>>, CandidateReachabilityError> {
        refresh_from_authenticated_publication(registry, requester, publication, &mut self.plan)?;
        Ok(self.traversal.take())
    }

    fn install(&mut self, traversal: IceConnectivitySession) {
        assert!(self.traversal.is_none());
        self.traversal = Some(Box::new(traversal));
    }

    fn replace_plan(
        &mut self,
        replacement: PeerConnectivityPlan,
    ) -> Option<Box<IceConnectivitySession>> {
        let stale = self.traversal.take();
        self.plan = replacement;
        stale
    }

    fn apply(
        &mut self,
        source: *const IceConnectivitySession,
        update: CandidateReachabilityUpdate,
    ) -> Result<(), ObservationError> {
        if self.traversal_ptr() != Some(source) {
            return Err(ObservationError::StaleTraversal);
        }
        update
            .apply(&mut self.plan)
            .map_err(ObservationError::Traversal)
    }
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    target_device_id: DeviceId,
    requester: AuthenticatedDeviceSession,
    target: AuthenticatedDeviceSession,
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

fn endpoint(port: u16) -> ConnectivityEndpoint {
    ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("endpoint")
}

fn candidate(id: u64, kind: ConnectivityPathKind, port: u16) -> ConnectivityCandidate {
    ConnectivityCandidate::new(CandidateId::new(id).expect("id"), kind, endpoint(port))
}

fn fixture() -> Fixture {
    let requester_signer = signer();
    let target_signer = signer();
    let workspace = WorkspaceId::new("workspace-phase141-integration").expect("workspace");
    let requester_user = UserId::new("requester-phase141-integration").expect("user");
    let target_user = UserId::new("target-phase141-integration").expect("user");
    let requester_binding = binding(
        &requester_signer,
        workspace.clone(),
        requester_user.clone(),
        "requester-phase141-integration",
    );
    let target_binding = binding(
        &target_signer,
        workspace.clone(),
        target_user.clone(),
        "target-phase141-integration",
    );
    let target_device_id = target_binding.device_id.clone();
    let requester = authenticated_session(
        &requester_signer,
        &requester_binding,
        "session-requester-phase141-integration",
    );
    let target = authenticated_session(
        &target_signer,
        &target_binding,
        "session-target-phase141-integration",
    );
    let transport = transport(2);
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
    let plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(target_device_id.clone(), transport),
        vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
    )
    .expect("plan");
    Fixture {
        registry,
        target_device_id,
        requester,
        target,
        transport,
        plan,
    }
}

fn ice_pair(
    owner_remote: ConnectivityCandidate,
    owner_local_port: u16,
) -> (IceConnectivitySession, IceConnectivitySession) {
    let owner_local = endpoint(owner_local_port);
    let peer_remote = candidate(
        10_000 + owner_remote.id().get(),
        ConnectivityPathKind::LocalDirect,
        owner_local_port,
    );
    let mut owner = IceConnectivitySession::new().expect("owner ICE");
    let mut peer = IceConnectivitySession::new().expect("peer ICE");
    let owner_credentials = owner.local_credentials().expect("owner credentials");
    let peer_credentials = peer.local_credentials().expect("peer credentials");
    owner
        .add_local_candidate(owner_local, IceCandidateClass::Host, None)
        .expect("owner local");
    peer.add_local_candidate(owner_remote.endpoint(), IceCandidateClass::Host, None)
        .expect("peer local");
    owner
        .add_remote_candidate(owner_remote, IceCandidateClass::Host, None)
        .expect("owner remote");
    peer.add_remote_candidate(peer_remote, IceCandidateClass::Host, None)
        .expect("peer remote");
    owner.start(true, &peer_credentials).expect("start owner");
    peer.start(false, &owner_credentials).expect("start peer");
    (owner, peer)
}

fn drive(
    owner: &mut IceConnectivitySession,
    peer: &mut IceConnectivitySession,
) -> CandidateReachabilityUpdate {
    let base = Instant::now();
    for step in 0..200_u64 {
        let now = base + Duration::from_millis(step * 100);
        if owner
            .poll_timeout()
            .expect("owner timeout")
            .is_some_and(|deadline| deadline <= now)
        {
            let _ = owner.handle_timeout(now);
        }
        if peer
            .poll_timeout()
            .expect("peer timeout")
            .is_some_and(|deadline| deadline <= now)
        {
            let _ = peer.handle_timeout(now);
        }
        for _ in 0..8 {
            let Some(outbound) = owner.poll_transmit().expect("owner transmit") else {
                break;
            };
            let inbound = TraversalDatagram::new(
                outbound.peer(),
                outbound.local(),
                outbound.payload().to_vec(),
            )
            .expect("invert owner datagram");
            let _ = peer.handle_datagram(&inbound, now);
        }
        for _ in 0..8 {
            let Some(outbound) = peer.poll_transmit().expect("peer transmit") else {
                break;
            };
            let inbound = TraversalDatagram::new(
                outbound.peer(),
                outbound.local(),
                outbound.payload().to_vec(),
            )
            .expect("invert peer datagram");
            let _ = owner.handle_datagram(&inbound, now);
        }
        if let Some(update) = owner.poll_reachability().expect("owner event") {
            return update;
        }
        let _ = peer.poll_reachability().expect("peer event");
    }
    panic!("actual Phase 141 pair did not select within bounded in-memory drive");
}

#[test]
fn successful_refresh_stales_queued_phase141_update_and_replacement_becomes_current() {
    let fixture = fixture();
    let retained = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![retained],
    )
    .expect("publication");
    assert_eq!(publication.candidates(), &[retained]);
    let (session, mut peer) = ice_pair(retained, 43001);
    let mut owner = Owner::new(fixture.plan, session);
    let old_ptr = owner.traversal_ptr().expect("old traversal");
    let queued = drive(owner.traversal_mut(), &mut peer);

    let stale = owner
        .refresh(
            FreshnessAdmitted,
            &fixture.registry,
            &fixture.requester,
            &publication,
        )
        .expect("refresh")
        .expect("stale session");
    assert_eq!(std::ptr::from_ref(stale.as_ref()), old_ptr);
    assert_eq!(
        owner.apply(old_ptr, queued),
        Err(ObservationError::StaleTraversal)
    );
    assert_eq!(
        owner.plan.selected_path(),
        SelectedConnectivityPath::Offline
    );

    let (replacement, mut replacement_peer) = ice_pair(retained, 43011);
    owner.install(replacement);
    let replacement_ptr = owner.traversal_ptr().expect("replacement traversal");
    let current = drive(owner.traversal_mut(), &mut replacement_peer);
    owner
        .apply(replacement_ptr, current)
        .expect("current update");
    assert_eq!(
        owner.plan.selected_path(),
        SelectedConnectivityPath::Candidate(retained)
    );
}

#[test]
fn failed_refresh_preserves_session_then_transport_rotation_invalidates_it() {
    let mut fixture = fixture();
    let initial = candidate(1, ConnectivityPathKind::LocalDirect, 2001);
    let rebound = candidate(1, ConnectivityPathKind::LocalDirect, 9001);
    let publication = publish_current_candidates(
        &fixture.registry,
        &fixture.target,
        fixture.transport,
        vec![rebound],
    )
    .expect("bounded publication");
    let (session, mut peer) = ice_pair(initial, 43101);
    let mut owner = Owner::new(fixture.plan, session);
    let old_ptr = owner.traversal_ptr().expect("old traversal");
    let queued = drive(owner.traversal_mut(), &mut peer);
    let queued_after_rotation = queued;

    assert!(matches!(
        owner.refresh(
            FreshnessAdmitted,
            &fixture.registry,
            &fixture.requester,
            &publication,
        ),
        Err(CandidateReachabilityError::Connectivity(
            ConnectivityError::CandidateIdRebound
        ))
    ));
    assert_eq!(owner.traversal_ptr(), Some(old_ptr));
    owner.apply(old_ptr, queued).expect("preserved update");
    assert_eq!(
        owner.plan.selected_path(),
        SelectedConnectivityPath::Candidate(initial)
    );

    let replacement_transport = transport(3);
    fixture
        .registry
        .rotate_transport_identity(
            &fixture.target_device_id,
            fixture.transport,
            replacement_transport,
        )
        .expect("rotate transport");
    let replacement_candidate = candidate(2, ConnectivityPathKind::InternetDirect, 3002);
    let replacement_plan = PeerConnectivityPlan::new(
        PeerConnectivityIdentity::new(fixture.target_device_id, replacement_transport),
        vec![replacement_candidate],
    )
    .expect("replacement plan");
    let stale = owner
        .replace_plan(replacement_plan)
        .expect("rotation stales traversal");
    assert_eq!(std::ptr::from_ref(stale.as_ref()), old_ptr);
    assert_eq!(owner.traversal_ptr(), None);
    assert_eq!(
        owner.apply(old_ptr, queued_after_rotation),
        Err(ObservationError::StaleTraversal)
    );
    assert_eq!(
        owner.plan.selected_path(),
        SelectedConnectivityPath::Offline
    );

    let (replacement, mut replacement_peer) = ice_pair(replacement_candidate, 43111);
    owner.install(replacement);
    let replacement_ptr = owner.traversal_ptr().expect("replacement traversal");
    let replacement_update = drive(owner.traversal_mut(), &mut replacement_peer);
    owner
        .apply(replacement_ptr, replacement_update)
        .expect("replacement update");
    assert_eq!(
        owner.plan.selected_path(),
        SelectedConnectivityPath::Candidate(replacement_candidate)
    );
}
