use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::TransportIdentity;
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_policy::{Capability, Decision, PolicyEvaluator};
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_remote_bridge::remote_session_binding::BoundRemoteSession;
use prw_remote_bridge::{
    AuthorizedCapabilityRequest, BridgeCommand, CapabilityBridge, CapabilityDispatcher,
    RemoteBridgeError,
};
use prw_remote_transport::{ControlFrame, ControlMessageKind};
use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

#[derive(Debug, Clone, Copy)]
struct AgentStatusPolicy;

impl PolicyEvaluator for AgentStatusPolicy {
    fn evaluate(&self, capability: Capability) -> Decision {
        if capability == Capability::AgentStatusRead {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[derive(Debug, Default)]
struct CountingDispatcher {
    calls: usize,
}

impl CapabilityDispatcher for CountingDispatcher {
    type Error = ();

    fn dispatch(&mut self, _request: &AuthorizedCapabilityRequest) -> Result<Vec<u8>, Self::Error> {
        self.calls += 1;
        Ok(b"ok".to_vec())
    }
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    bound: BoundRemoteSession,
    authenticated: AuthenticatedDeviceSession,
    device_id: DeviceId,
    transport_identity: TransportIdentity,
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable C03e device key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("load disposable C03e signer")
}

fn fixture() -> Fixture {
    let signer = signer();
    let workspace_id = WorkspaceId::new("workspace-c03e").expect("workspace id");
    let user_id = UserId::new("user-c03e").expect("user id");
    let device_id = DeviceId::new("device-c03e").expect("device id");
    let binding = DeviceIdentityBinding {
        workspace_id: workspace_id.clone(),
        user_id: user_id.clone(),
        device_id: device_id.clone(),
        public_identity: signer.public_identity().clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    };

    let session_id = SessionId::new("session-c03e").expect("session id");
    let mut authentication = SessionAuthenticationService::new();
    let challenge = authentication
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
        .expect("begin authenticated session");
    let proof = signer
        .sign_session_auth_proof(&binding, &challenge)
        .expect("sign session proof");
    let authenticated = authentication
        .submit_proof(&session_id, &proof, 1_001)
        .expect("authenticate device session");

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace_id, user_id, WorkspaceRole::Member)
        .expect("register active membership");
    registry
        .register_device(binding)
        .expect("register enrolled device");
    let transport_identity = TransportIdentity::new([0x53; 32]).expect("transport identity");
    registry
        .bind_transport_identity(&device_id, transport_identity)
        .expect("bind transport identity");

    let bound = BoundRemoteSession::new(transport_identity, authenticated.clone(), 1_000, 1_200)
        .expect("bind authenticated remote session");

    Fixture {
        registry,
        bound,
        authenticated,
        device_id,
        transport_identity,
    }
}

fn agent_status_request(request_id: u64) -> ControlFrame {
    ControlFrame::new(
        ControlMessageKind::Request,
        request_id,
        BridgeCommand::AgentStatus
            .encode()
            .expect("encode AgentStatus command"),
    )
    .expect("construct control request")
}

#[test]
fn bound_session_preserves_exact_transport_and_authenticated_identity() {
    let fixture = fixture();

    assert_eq!(
        fixture.bound.transport_identity(),
        fixture.transport_identity
    );
    assert_eq!(fixture.bound.session(), &fixture.authenticated);
    assert_eq!(fixture.bound.lease().session(), &fixture.authenticated);
    assert_eq!(fixture.bound.lease().issued_at_unix_seconds(), 1_000);
    assert_eq!(fixture.bound.lease().expires_at_unix_seconds(), 1_200);
}

#[test]
fn bound_session_delegates_to_existing_current_registry_and_policy_authority() {
    let fixture = fixture();
    let policy = AgentStatusPolicy;
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let request = agent_status_request(501);

    let authorized = fixture
        .bound
        .authorize(&bridge, 1_050, &request)
        .expect("current bound session authorizes");

    assert_eq!(authorized.request_id(), 501);
    assert_eq!(authorized.principal().device_id(), &fixture.device_id);
    assert_eq!(authorized.transport_identity(), fixture.transport_identity);
    assert_eq!(authorized.capability(), Capability::AgentStatusRead);
    assert_eq!(authorized.command(), &BridgeCommand::AgentStatus);
}

#[test]
fn registry_transport_rotation_invalidates_existing_bound_transport_snapshot() {
    let mut fixture = fixture();
    let replacement = TransportIdentity::new([0x54; 32]).expect("replacement identity");
    fixture
        .registry
        .rotate_transport_identity(&fixture.device_id, fixture.transport_identity, replacement)
        .expect("rotate current transport identity");
    let policy = AgentStatusPolicy;
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let request = agent_status_request(502);

    assert_eq!(
        fixture.bound.authorize(&bridge, 1_050, &request),
        Err(RemoteBridgeError::TransportIdentityRejected)
    );
}

#[test]
fn lease_expiry_and_invalid_lifetime_preserve_existing_fail_closed_errors() {
    let fixture = fixture();
    let policy = AgentStatusPolicy;
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let request = agent_status_request(503);

    assert_eq!(
        fixture.bound.authorize(&bridge, 1_200, &request),
        Err(RemoteBridgeError::SessionExpired)
    );

    assert_eq!(
        BoundRemoteSession::new(
            fixture.transport_identity,
            fixture.authenticated.clone(),
            2_000,
            2_000,
        ),
        Err(RemoteBridgeError::InvalidSessionLease)
    );
}

#[test]
fn failed_bound_authorization_never_invokes_dispatcher() {
    let mut fixture = fixture();
    let replacement = TransportIdentity::new([0x55; 32]).expect("replacement identity");
    fixture
        .registry
        .rotate_transport_identity(&fixture.device_id, fixture.transport_identity, replacement)
        .expect("rotate current transport identity");
    let policy = AgentStatusPolicy;
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let request = agent_status_request(504);
    let mut dispatcher = CountingDispatcher::default();

    assert_eq!(
        fixture
            .bound
            .process_request(&bridge, 1_050, &request, &mut dispatcher),
        Err(RemoteBridgeError::TransportIdentityRejected)
    );
    assert_eq!(dispatcher.calls, 0);
}
