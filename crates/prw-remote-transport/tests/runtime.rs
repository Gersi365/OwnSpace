use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use prw_connectivity::TransportIdentity;
use prw_remote_transport::{
    ControlFrame, ControlMessageKind, build_client_config, build_server_config,
    runtime::MeshQuicEndpoint, transport_identity_from_certificate, transport_server_name,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct PeerMaterial {
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
    identity: TransportIdentity,
}

fn private_key(bytes: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(bytes.to_vec()).into()
}

fn make_leaf(ca: &CertifiedIssuer<'_, KeyPair>) -> PeerMaterial {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate test leaf key");
    let mut provisional_params =
        CertificateParams::new(vec!["placeholder.mesh.prw.invalid".to_owned()])
            .expect("valid placeholder name");
    provisional_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    provisional_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let provisional = provisional_params
        .signed_by(&key, ca)
        .expect("sign provisional test leaf");
    let identity =
        transport_identity_from_certificate(provisional.der()).expect("derive transport identity");

    let mut final_params =
        CertificateParams::new(vec![transport_server_name(identity)]).expect("valid transport SAN");
    final_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    final_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = final_params
        .signed_by(&key, ca)
        .expect("sign final test leaf")
        .der()
        .clone();
    assert_eq!(
        transport_identity_from_certificate(&certificate),
        Ok(identity)
    );

    PeerMaterial {
        certificate,
        private_key: key.serialize_der(),
        identity,
    }
}

fn fixtures() -> (CertificateDer<'static>, PeerMaterial, PeerMaterial) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate disposable CA");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-sign disposable CA");
    (ca.der().clone(), make_leaf(&ca), make_leaf(&ca))
}

const fn loopback_any() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

#[tokio::test(flavor = "current_thread")]
async fn reusable_runtime_exchanges_prwm_over_real_udp_quic_mtls() {
    let (root, server_material, client_material) = fixtures();
    let server = MeshQuicEndpoint::bind_server(
        loopback_any(),
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server TLS config"),
    )
    .expect("bind server endpoint");
    let client = MeshQuicEndpoint::bind_client(
        loopback_any(),
        build_client_config(
            vec![root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client TLS config"),
    )
    .expect("bind client endpoint");
    let server_addr = server.local_addr().expect("server local address");

    let server_side = async {
        let connection = server
            .accept_authenticated(client_material.identity)
            .await
            .expect("authenticated server connection");
        assert_eq!(
            connection.peer_transport_identity(),
            client_material.identity
        );
        let mut stream = connection
            .accept_control_stream()
            .await
            .expect("accept control stream");
        let request = stream.receive_frame().await.expect("receive request");
        assert_eq!(request.kind(), ControlMessageKind::Heartbeat);
        assert_eq!(request.request_id(), 77);
        assert_eq!(request.payload(), b"ping");
        let response = ControlFrame::new(ControlMessageKind::Response, 77, b"pong".to_vec())
            .expect("response frame");
        stream.send_frame(&response).await.expect("send response");
        connection
    };

    let client_side = async {
        let connection = client
            .connect_authenticated(server_addr, server_material.identity)
            .await
            .expect("authenticated client connection");
        assert_eq!(
            connection.peer_transport_identity(),
            server_material.identity
        );
        let mut stream = connection
            .open_control_stream()
            .await
            .expect("open control stream");
        let request = ControlFrame::new(ControlMessageKind::Heartbeat, 77, b"ping".to_vec())
            .expect("request frame");
        stream.send_frame(&request).await.expect("send request");
        let response = stream.receive_frame().await.expect("receive response");
        assert_eq!(response.kind(), ControlMessageKind::Response);
        assert_eq!(response.request_id(), 77);
        assert_eq!(response.payload(), b"pong");
        connection
    };

    let (server_connection, client_connection) = tokio::join!(server_side, client_side);
    server_connection.close(0, b"done");
    client_connection.close(0, b"done");
    server.close(0, b"done");
    client.close(0, b"done");
    server.wait_idle().await;
    client.wait_idle().await;
}

#[tokio::test(flavor = "current_thread")]
async fn reusable_runtime_rejects_wrong_expected_peer_transport_identity() {
    let (root, server_material, client_material) = fixtures();
    let server = MeshQuicEndpoint::bind_server(
        loopback_any(),
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server TLS config"),
    )
    .expect("bind server endpoint");
    let client = MeshQuicEndpoint::bind_client(
        loopback_any(),
        build_client_config(
            vec![root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client TLS config"),
    )
    .expect("bind client endpoint");
    let server_addr = server.local_addr().expect("server local address");
    let wrong = TransportIdentity::new([0x7f; 32]).expect("wrong nonzero identity");

    let server_side = server.accept_authenticated(client_material.identity);
    let client_side = client.connect_authenticated(server_addr, wrong);
    let (server_result, client_result) = tokio::join!(server_side, client_side);
    assert!(server_result.is_err() || client_result.is_err());

    server.close(0, b"done");
    client.close(0, b"done");
    server.wait_idle().await;
    client.wait_idle().await;
}
