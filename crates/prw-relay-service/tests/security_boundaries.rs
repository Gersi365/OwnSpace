use std::net::{IpAddr, Ipv4Addr};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    SelectedConnectivityPath, TransportIdentity,
};
use prw_core::DeviceId;
use prw_relay::{
    OpaqueRelayFrame, RelayBackend, RelayPeerIdentity, RelayRouteToken, RelaySessionSpec,
};
use prw_relay_service::{
    DisposableRelayProvider, MAX_QUEUED_RELAY_BYTES, RelayRoutingPacket,
    SharedDisposableRelayService,
};

fn route_token(byte: u8) -> RelayRouteToken {
    RelayRouteToken::new([byte; 32]).expect("non-zero route token")
}

fn relay_spec(
    device: &str,
    transport_byte: u8,
    route_token: RelayRouteToken,
    candidate_id: u64,
) -> RelaySessionSpec {
    let peer = RelayPeerIdentity::new(
        DeviceId::new(device).expect("device identifier"),
        TransportIdentity::new([transport_byte; 32]).expect("transport identity"),
    );
    let selected = SelectedConnectivityPath::Candidate(ConnectivityCandidate::new(
        CandidateId::new(candidate_id).expect("candidate identifier"),
        ConnectivityPathKind::Relay,
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5600).expect("relay endpoint"),
    ));
    RelaySessionSpec::from_selected_path(peer, route_token, selected).expect("relay spec")
}

#[test]
fn route_token_and_session_debug_redact_raw_token() {
    let token = route_token(0xab);
    let token_debug = format!("{token:?}");
    assert!(token_debug.contains("<redacted>"));
    assert!(!token_debug.contains("171"));

    let spec = relay_spec("peer-b", 2, token, 1);
    let spec_debug = format!("{spec:?}");
    assert!(spec_debug.contains("<redacted>"));
    assert!(!spec_debug.contains("171"));
}

#[test]
fn routing_packet_debug_redacts_token_and_payload_bytes() {
    let packet = RelayRoutingPacket::new(
        route_token(0xab),
        OpaqueRelayFrame::new(vec![0xde, 0xad, 0xbe, 0xef]).expect("opaque payload"),
    );
    let rendered = format!("{packet:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("payload_len"));
    assert!(!rendered.contains("171"));
    assert!(!rendered.contains("222"));
    assert!(!rendered.contains("173"));
    assert!(!rendered.contains("190"));
    assert!(!rendered.contains("239"));
}

#[test]
fn byte_queue_capacity_fails_without_dropping_accepted_frames() {
    let service = SharedDisposableRelayService::new();
    let token = route_token(0x31);
    let mut sender = DisposableRelayProvider::new(service.clone());
    let mut receiver = DisposableRelayProvider::new(service);
    let sender_spec = relay_spec("peer-b", 2, token, 1);
    let receiver_spec = relay_spec("peer-a", 1, token, 2);
    let mut sender_handle = sender.open(&sender_spec).expect("sender open");
    let receiver_handle = receiver.open(&receiver_spec).expect("receiver open");

    let frame_bytes = 65_536usize;
    assert_eq!(MAX_QUEUED_RELAY_BYTES % frame_bytes, 0);
    let accepted = MAX_QUEUED_RELAY_BYTES / frame_bytes;
    let frame = OpaqueRelayFrame::new(vec![0x5a; frame_bytes]).expect("bounded frame");
    for _ in 0..accepted {
        sender
            .transmit(&mut sender_handle, &frame)
            .expect("within byte capacity");
    }
    assert!(sender.transmit(&mut sender_handle, &frame).is_err());

    for _ in 0..accepted {
        let queued_frame = receiver
            .poll_receive(receiver_handle)
            .expect("receive poll")
            .expect("accepted queued frame");
        assert_eq!(queued_frame.as_bytes(), frame.as_bytes());
    }
    assert!(
        receiver
            .poll_receive(receiver_handle)
            .expect("empty receive poll")
            .is_none()
    );
}
