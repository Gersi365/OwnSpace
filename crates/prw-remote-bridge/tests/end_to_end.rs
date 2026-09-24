use std::net::{IpAddr, Ipv4Addr};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::TransportIdentity;
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
use prw_device_identity_signer::UbuntuEnrollmentSigner;
use prw_file_service::RemotePath;
use prw_file_transfer::{TransferId, UploadPlan};
use prw_forwarding::{ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec};
use prw_policy::{Capability, Decision, PolicyEvaluator};
use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
use prw_remote_bridge::{
    BridgeCommand, CapabilityBridge, CapabilityDispatcher, MAX_BRIDGE_INLINE_BYTES,
    MAX_REMOTE_SESSION_LEASE_SECONDS, RemoteBridgeError, RemoteSessionLease,
};
use prw_remote_transport::{ControlFrame, ControlMessageKind, MAX_CONTROL_PAYLOAD_BYTES};
use prw_session::SessionAuthenticationService;
use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

#[derive(Debug, Clone, Copy)]
struct FixedPolicy {
    allow: Option<Capability>,
}

impl PolicyEvaluator for FixedPolicy {
    fn evaluate(&self, capability: Capability) -> Decision {
        if self.allow == Some(capability) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[derive(Debug, Default)]
struct SpyDispatcher {
    calls: usize,
    response: Vec<u8>,
    fail: bool,
}

impl CapabilityDispatcher for SpyDispatcher {
    type Error = ();

    fn dispatch(
        &mut self,
        _request: &prw_remote_bridge::AuthorizedCapabilityRequest,
    ) -> Result<Vec<u8>, Self::Error> {
        self.calls += 1;
        if self.fail {
            Err(())
        } else {
            Ok(self.response.clone())
        }
    }
}

struct Fixture {
    registry: WorkspaceDeviceRegistry,
    lease: RemoteSessionLease,
    transport: TransportIdentity,
}

fn signer() -> UbuntuEnrollmentSigner {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("generate disposable Phase 143 device key");
    UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
        .expect("load disposable Phase 143 signer")
}

fn fixture(role: WorkspaceRole) -> Fixture {
    let signer = signer();
    let workspace = WorkspaceId::new("workspace-143").expect("workspace");
    let user = UserId::new("user-143").expect("user");
    let device = DeviceId::new("device-143").expect("device");
    let binding = DeviceIdentityBinding {
        workspace_id: workspace.clone(),
        user_id: user.clone(),
        device_id: device.clone(),
        public_identity: signer.public_identity().clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    };

    let mut auth = SessionAuthenticationService::new();
    let session_id = SessionId::new("session-143").expect("session");
    let challenge = auth
        .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
        .expect("begin session authentication");
    let proof = signer
        .sign_session_auth_proof(&binding, &challenge)
        .expect("sign session proof");
    let session = auth
        .submit_proof(&session_id, &proof, 1_001)
        .expect("authenticate session");

    let mut registry = WorkspaceDeviceRegistry::new();
    registry
        .add_membership(workspace, user, role)
        .expect("add current membership");
    registry
        .register_device(binding)
        .expect("register current device");
    let transport = TransportIdentity::new([0x31; 32]).expect("transport identity");
    registry
        .bind_transport_identity(&device, transport)
        .expect("bind current transport identity");

    let lease = RemoteSessionLease::new(session, 1_000, 1_200).expect("remote lease");
    Fixture {
        registry,
        lease,
        transport,
    }
}

fn request_frame(request_id: u64, command: &BridgeCommand) -> ControlFrame {
    ControlFrame::new(
        ControlMessageKind::Request,
        request_id,
        command.encode().expect("encode command"),
    )
    .expect("request control frame")
}

fn path(value: &str) -> RemotePath {
    RemotePath::parse(value).expect("remote path")
}

fn transfer_plan(value: u8) -> UploadPlan {
    UploadPlan::new(
        TransferId::new([value; 16]),
        path("uploads/item.bin"),
        12_345,
        [value.wrapping_add(1); 32],
    )
    .expect("upload plan")
}

fn terminal_id(value: u64) -> TerminalSessionId {
    TerminalSessionId::new(value).expect("terminal id")
}

fn forward_id(value: u64) -> PortForwardId {
    PortForwardId::new(value).expect("forward id")
}

fn commands() -> Vec<BridgeCommand> {
    vec![
        BridgeCommand::AgentStatus,
        BridgeCommand::FileList(path("docs")),
        BridgeCommand::FileStat(path("docs/readme.txt")),
        BridgeCommand::FileCreate {
            path: path("docs/new.txt"),
            contents: b"hello".to_vec(),
        },
        BridgeCommand::DirectoryCreate(path("docs/new-dir")),
        BridgeCommand::UploadBegin(transfer_plan(1)),
        BridgeCommand::UploadResume(transfer_plan(2)),
        BridgeCommand::UploadChunk {
            transfer_id: TransferId::new([3; 16]),
            offset: 77,
            chunk: vec![0xaa, 0xbb, 0xcc],
        },
        BridgeCommand::UploadFinalize(TransferId::new([4; 16])),
        BridgeCommand::UploadAbort(TransferId::new([5; 16])),
        BridgeCommand::DownloadChunk {
            path: path("docs/readme.txt"),
            offset: 10,
            requested_len: 1024,
        },
        BridgeCommand::TerminalOpen {
            session_id: terminal_id(11),
            profile: TerminalProfile::BashShell,
            geometry: TerminalGeometry::new(120, 40).expect("geometry"),
        },
        BridgeCommand::TerminalInput {
            session_id: terminal_id(11),
            bytes: b"pwd\n".to_vec(),
        },
        BridgeCommand::TerminalResize {
            session_id: terminal_id(11),
            geometry: TerminalGeometry::new(100, 35).expect("geometry"),
        },
        BridgeCommand::TerminalRead {
            session_id: terminal_id(11),
            maximum_bytes: 2048,
        },
        BridgeCommand::TerminalClose(terminal_id(11)),
        BridgeCommand::ForwardOpen {
            forward_id: forward_id(17),
            spec: TcpForwardSpec::new(
                LoopbackBind::new(LoopbackFamily::Ipv4, 8080).expect("bind"),
                ForwardTarget::new(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)), 443).expect("target"),
            ),
        },
        BridgeCommand::ForwardClose(forward_id(17)),
    ]
}

#[test]
fn all_operation_codes_round_trip_and_map_to_exact_capabilities() {
    let expected = [
        Capability::AgentStatusRead,
        Capability::FilesRead,
        Capability::FilesRead,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesWrite,
        Capability::FilesRead,
        Capability::TerminalOpen,
        Capability::TerminalExec,
        Capability::TerminalExec,
        Capability::TerminalExec,
        Capability::TerminalExec,
        Capability::ForwardingCreate,
        Capability::ForwardingCreate,
    ];
    let commands = commands();
    assert_eq!(commands.len(), expected.len());
    for (index, (command, capability)) in commands.iter().zip(expected).enumerate() {
        assert_eq!(
            command.operation_code(),
            u16::try_from(index + 1).expect("code")
        );
        assert_eq!(command.required_capability(), capability);
        let encoded = command.encode().expect("encode");
        assert!(encoded.len() <= MAX_CONTROL_PAYLOAD_BYTES);
        assert_eq!(BridgeCommand::decode(&encoded), Ok(command.clone()));
    }
}

#[test]
fn current_transport_binding_is_single_bind_compare_and_rotate() {
    let mut fixture = fixture(WorkspaceRole::Member);
    let device = fixture.lease.session().device_id().clone();
    let replacement = TransportIdentity::new([0x32; 32]).expect("replacement");
    assert!(
        fixture
            .registry
            .bind_transport_identity(&device, replacement)
            .is_err()
    );
    assert!(
        fixture
            .registry
            .rotate_transport_identity(&device, replacement, fixture.transport)
            .is_err()
    );
    fixture
        .registry
        .rotate_transport_identity(&device, fixture.transport, replacement)
        .expect("compare and rotate");
    assert!(
        fixture
            .registry
            .validate_transport_identity(&device, fixture.transport)
            .is_err()
    );
    fixture
        .registry
        .validate_transport_identity(&device, replacement)
        .expect("new transport is current");
}

#[test]
fn valid_full_chain_dispatches_and_correlates_response() {
    let fixture = fixture(WorkspaceRole::Member);
    let command = BridgeCommand::FileList(path("docs"));
    let frame = request_frame(44, &command);
    let policy = FixedPolicy {
        allow: Some(Capability::FilesRead),
    };
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let mut dispatcher = SpyDispatcher {
        response: b"ok".to_vec(),
        ..SpyDispatcher::default()
    };
    let response = bridge
        .process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &frame,
            &mut dispatcher,
        )
        .expect("authorized dispatch");
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(response.kind(), ControlMessageKind::Response);
    assert_eq!(response.request_id(), 44);
    assert_eq!(response.payload(), b"ok");
}

#[test]
fn denied_capability_and_owner_role_never_dispatch() {
    let fixture = fixture(WorkspaceRole::Owner);
    let frame = request_frame(1, &BridgeCommand::AgentStatus);
    let policy = FixedPolicy { allow: None };
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let mut dispatcher = SpyDispatcher::default();
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &frame,
            &mut dispatcher
        ),
        Err(RemoteBridgeError::CapabilityDenied)
    );
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn stale_transport_expired_or_future_session_never_dispatches() {
    let fixture = fixture(WorkspaceRole::Member);
    let frame = request_frame(2, &BridgeCommand::AgentStatus);
    let policy = FixedPolicy {
        allow: Some(Capability::AgentStatusRead),
    };
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let mut dispatcher = SpyDispatcher::default();
    let stale = TransportIdentity::new([0x77; 32]).expect("stale transport");
    assert_eq!(
        bridge.process_request(stale, &fixture.lease, 1_100, &frame, &mut dispatcher),
        Err(RemoteBridgeError::TransportIdentityRejected)
    );
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            999,
            &frame,
            &mut dispatcher
        ),
        Err(RemoteBridgeError::SessionNotYetValid)
    );
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_200,
            &frame,
            &mut dispatcher
        ),
        Err(RemoteBridgeError::SessionExpired)
    );
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn membership_suspension_and_device_revocation_invalidate_unexpired_session() {
    let mut suspended_fixture = fixture(WorkspaceRole::Member);
    let workspace = suspended_fixture.lease.session().workspace_id().clone();
    let user = suspended_fixture.lease.session().user_id().clone();
    let device = suspended_fixture.lease.session().device_id().clone();
    let frame = request_frame(3, &BridgeCommand::AgentStatus);
    let policy = FixedPolicy {
        allow: Some(Capability::AgentStatusRead),
    };

    suspended_fixture
        .registry
        .suspend_membership(&workspace, &user)
        .expect("suspend membership");
    let bridge = CapabilityBridge::new(&suspended_fixture.registry, &policy);
    assert_eq!(
        bridge.authorize(
            suspended_fixture.transport,
            &suspended_fixture.lease,
            1_100,
            &frame
        ),
        Err(RemoteBridgeError::RegistryRejected)
    );

    let mut revoked_fixture = fixture(WorkspaceRole::Member);
    revoked_fixture
        .registry
        .revoke_device(&device)
        .expect("revoke device");
    let revoked_bridge = CapabilityBridge::new(&revoked_fixture.registry, &policy);
    assert_eq!(
        revoked_bridge.authorize(
            revoked_fixture.transport,
            &revoked_fixture.lease,
            1_100,
            &frame
        ),
        Err(RemoteBridgeError::RegistryRejected)
    );
}

#[test]
fn wrong_outer_kind_and_malformed_prwc_never_dispatch() {
    let fixture = fixture(WorkspaceRole::Member);
    let policy = FixedPolicy {
        allow: Some(Capability::AgentStatusRead),
    };
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let mut dispatcher = SpyDispatcher::default();
    let payload = BridgeCommand::AgentStatus.encode().expect("payload");
    let wrong_kind = ControlFrame::new(ControlMessageKind::Heartbeat, 9, payload.clone())
        .expect("heartbeat frame");
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &wrong_kind,
            &mut dispatcher
        ),
        Err(RemoteBridgeError::WrongControlMessageKind)
    );

    let mut malformed = payload;
    malformed[0] ^= 0x01;
    let frame = ControlFrame::new(ControlMessageKind::Request, 10, malformed).expect("frame");
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &frame,
            &mut dispatcher
        ),
        Err(RemoteBridgeError::InvalidRequestPayload)
    );
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn malformed_header_fields_trailing_data_and_invalid_typed_values_fail_closed() {
    let valid = BridgeCommand::AgentStatus.encode().expect("valid");
    for index in [4usize, 6, 8, 10] {
        let mut malformed = valid.clone();
        malformed[index] ^= 0x01;
        assert_eq!(
            BridgeCommand::decode(&malformed),
            Err(RemoteBridgeError::InvalidRequestPayload)
        );
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        BridgeCommand::decode(&trailing),
        Err(RemoteBridgeError::InvalidRequestPayload)
    );

    let oversized_input = BridgeCommand::TerminalInput {
        session_id: terminal_id(1),
        bytes: vec![0; MAX_BRIDGE_INLINE_BYTES + 1],
    };
    assert_eq!(
        oversized_input.encode(),
        Err(RemoteBridgeError::InvalidRequestPayload)
    );
    let invalid_read = BridgeCommand::TerminalRead {
        session_id: terminal_id(1),
        maximum_bytes: 0,
    };
    assert_eq!(
        invalid_read.encode(),
        Err(RemoteBridgeError::InvalidRequestPayload)
    );
}

#[test]
fn lease_bounds_dispatch_failure_and_oversized_response_fail_closed() {
    let fixture = fixture(WorkspaceRole::Member);
    assert_eq!(
        RemoteSessionLease::new(
            fixture.lease.session().clone(),
            10,
            10 + MAX_REMOTE_SESSION_LEASE_SECONDS + 1,
        ),
        Err(RemoteBridgeError::InvalidSessionLease)
    );

    let policy = FixedPolicy {
        allow: Some(Capability::AgentStatusRead),
    };
    let bridge = CapabilityBridge::new(&fixture.registry, &policy);
    let frame = request_frame(12, &BridgeCommand::AgentStatus);
    let mut failing = SpyDispatcher {
        fail: true,
        ..SpyDispatcher::default()
    };
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &frame,
            &mut failing
        ),
        Err(RemoteBridgeError::DispatchFailed)
    );
    assert_eq!(failing.calls, 1);

    let mut oversized = SpyDispatcher {
        response: vec![0; MAX_CONTROL_PAYLOAD_BYTES + 1],
        ..SpyDispatcher::default()
    };
    assert_eq!(
        bridge.process_request(
            fixture.transport,
            &fixture.lease,
            1_100,
            &frame,
            &mut oversized
        ),
        Err(RemoteBridgeError::DispatchResponseTooLarge)
    );
    assert_eq!(oversized.calls, 1);
}
