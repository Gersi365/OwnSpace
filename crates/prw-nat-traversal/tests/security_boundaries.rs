use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use prw_nat_traversal::{IceCredentials, StunDiscovery, TraversalDatagram, TraversalError};
use rtc_stun::message::{BINDING_REQUEST, Message};
use rtc_stun::xoraddr::XorMappedAddress;

#[test]
fn ice_credentials_debug_redacts_password() {
    let credentials = IceCredentials::new("visible-ufrag", "do-not-log-this-password")
        .expect("valid bounded credentials");
    let rendered = format!("{credentials:?}");
    assert!(rendered.contains("visible-ufrag"));
    assert!(!rendered.contains("do-not-log-this-password"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn stun_non_success_message_with_xor_mapping_fails_closed() {
    let local = SocketAddr::from(([127, 0, 0, 1], 42100));
    let server = SocketAddr::from(([127, 0, 0, 1], 3478));
    let mut discovery = StunDiscovery::new(local, server).expect("discovery");
    let request = discovery
        .poll_transmit()
        .expect("poll request")
        .expect("binding request");

    let mut decoded = Message::new();
    decoded
        .unmarshal_binary(request.payload())
        .expect("decode request");

    let mut invalid_response = Message::new();
    invalid_response
        .build(&[
            Box::new(decoded.transaction_id),
            Box::new(BINDING_REQUEST),
            Box::new(XorMappedAddress {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                port: 54322,
            }),
        ])
        .expect("construct non-success STUN message");

    discovery
        .handle_datagram(
            &TraversalDatagram::new(local, server, invalid_response.raw)
                .expect("bounded response datagram"),
            Instant::now(),
        )
        .expect("deliver syntactically valid STUN message");

    assert_eq!(
        discovery.poll_result(),
        Some(Err(TraversalError::StunTransactionFailed))
    );
}
