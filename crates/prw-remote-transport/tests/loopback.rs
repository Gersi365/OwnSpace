use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use prw_connectivity::TransportIdentity;
use prw_remote_transport::{
    CONTROL_HEADER_BYTES, ControlFrame, ControlMessageKind, MESH_ALPN, OPERATION_TIMEOUT,
    build_client_config, build_server_config, endpoint_config, negotiated_alpn,
    peer_transport_identity, require_peer_transport_identity, transport_identity_from_certificate,
    transport_server_name,
};
use quinn::{Endpoint, TokioRuntime};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

struct PeerMaterial {
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
    identity: TransportIdentity,
    server_name: String,
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
    let identity = transport_identity_from_certificate(provisional.der())
        .expect("derive provisional transport identity");
    let server_name = transport_server_name(identity);

    let mut final_params =
        CertificateParams::new(vec![server_name.clone()]).expect("valid transport SAN");
    final_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    final_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = final_params
        .signed_by(&key, ca)
        .expect("sign final test leaf");
    let certificate = certificate.der().clone();
    assert_eq!(
        transport_identity_from_certificate(&certificate),
        Ok(identity),
        "SAN re-issuance with the same key must preserve TransportIdentity"
    );

    PeerMaterial {
        certificate,
        private_key: key.serialize_der(),
        identity,
        server_name,
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
    let root = ca.der().clone();
    let server = make_leaf(&ca);
    let client = make_leaf(&ca);
    (root, server, client)
}

fn endpoint_with_server(config: quinn::ServerConfig) -> Endpoint {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind disposable server UDP socket");
    Endpoint::new(
        endpoint_config(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .expect("construct disposable server endpoint")
}

fn endpoint_with_client(config: quinn::ClientConfig) -> Endpoint {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind disposable client UDP socket");
    let mut endpoint = Endpoint::new(endpoint_config(), None, socket, Arc::new(TokioRuntime))
        .expect("construct disposable client endpoint");
    endpoint.set_default_client_config(config);
    endpoint
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "current_thread")]
async fn loopback_quic_v1_mtls_binds_peer_identity_and_control_frame() {
    let (root, server_material, client_material) = fixtures();
    let server = endpoint_with_server(
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server config"),
    );
    let client = endpoint_with_client(
        build_client_config(
            vec![root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client config"),
    );
    let server_addr = server.local_addr().expect("server address");

    let server_side = async {
        let incoming = timeout(OPERATION_TIMEOUT, server.accept())
            .await
            .expect("accept timeout")
            .expect("incoming connection");
        let connection = timeout(OPERATION_TIMEOUT, incoming)
            .await
            .expect("server handshake timeout")
            .expect("server handshake");
        assert_eq!(
            negotiated_alpn(&connection).expect("server ALPN"),
            MESH_ALPN
        );
        assert_eq!(
            peer_transport_identity(&connection).expect("client transport identity"),
            client_material.identity
        );
        require_peer_transport_identity(&connection, client_material.identity)
            .expect("expected client identity");

        let (mut send, mut recv) = timeout(OPERATION_TIMEOUT, connection.accept_bi())
            .await
            .expect("accept stream timeout")
            .expect("accept stream");
        let bytes = timeout(
            OPERATION_TIMEOUT,
            recv.read_to_end(CONTROL_HEADER_BYTES + 65_536),
        )
        .await
        .expect("read timeout")
        .expect("read frame");
        let frame = ControlFrame::decode(&bytes).expect("decode request");
        assert_eq!(frame.kind(), ControlMessageKind::Heartbeat);
        assert_eq!(frame.request_id(), 41);
        assert_eq!(frame.payload(), b"ping");

        let response = ControlFrame::new(ControlMessageKind::Response, 41, b"pong".to_vec())
            .expect("response frame")
            .encode();
        timeout(OPERATION_TIMEOUT, send.write_all(&response))
            .await
            .expect("write timeout")
            .expect("write response");
        send.finish().expect("finish response");
        connection
    };

    let client_side = async {
        let connection = timeout(
            OPERATION_TIMEOUT,
            client
                .connect(server_addr, &server_material.server_name)
                .expect("start connection"),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake");
        assert_eq!(
            negotiated_alpn(&connection).expect("client ALPN"),
            MESH_ALPN
        );
        assert_eq!(
            peer_transport_identity(&connection).expect("server transport identity"),
            server_material.identity
        );
        require_peer_transport_identity(&connection, server_material.identity)
            .expect("expected server identity");

        let (mut send, mut recv) = timeout(OPERATION_TIMEOUT, connection.open_bi())
            .await
            .expect("open stream timeout")
            .expect("open stream");
        let request = ControlFrame::new(ControlMessageKind::Heartbeat, 41, b"ping".to_vec())
            .expect("request frame")
            .encode();
        timeout(OPERATION_TIMEOUT, send.write_all(&request))
            .await
            .expect("write request timeout")
            .expect("write request");
        send.finish().expect("finish request");

        let bytes = timeout(
            OPERATION_TIMEOUT,
            recv.read_to_end(CONTROL_HEADER_BYTES + 65_536),
        )
        .await
        .expect("response read timeout")
        .expect("read response");
        let response = ControlFrame::decode(&bytes).expect("decode response");
        assert_eq!(response.kind(), ControlMessageKind::Response);
        assert_eq!(response.request_id(), 41);
        assert_eq!(response.payload(), b"pong");
        connection
    };

    let (server_connection, client_connection) = tokio::join!(server_side, client_side);
    server_connection.close(0_u32.into(), b"done");
    client_connection.close(0_u32.into(), b"done");
    server.wait_idle().await;
    client.wait_idle().await;
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_server_name_fails_closed() {
    let (root, server_material, client_material) = fixtures();
    let server = endpoint_with_server(
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server config"),
    );
    let client = endpoint_with_client(
        build_client_config(
            vec![root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client config"),
    );
    let server_addr = server.local_addr().expect("server address");

    let server_task = async {
        let incoming = timeout(OPERATION_TIMEOUT, server.accept())
            .await
            .expect("accept timeout")
            .expect("incoming");
        let _ = timeout(OPERATION_TIMEOUT, incoming).await;
    };
    let client_task = async {
        let result = timeout(
            OPERATION_TIMEOUT,
            client
                .connect(server_addr, "wrong.mesh.prw.invalid")
                .expect("start wrong-name connection"),
        )
        .await
        .expect("wrong-name timeout");
        assert!(result.is_err());
    };
    tokio::join!(server_task, client_task);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_ca_fails_closed() {
    let (server_root, server_material, _) = fixtures();
    let (wrong_root, _, client_material) = fixtures();
    let server = endpoint_with_server(
        build_server_config(
            vec![server_root],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server config"),
    );
    let client = endpoint_with_client(
        build_client_config(
            vec![wrong_root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client config"),
    );
    let server_addr = server.local_addr().expect("server address");
    let server_task = async {
        let incoming = timeout(OPERATION_TIMEOUT, server.accept())
            .await
            .expect("accept timeout")
            .expect("incoming");
        timeout(OPERATION_TIMEOUT, incoming).await
    };
    let client_task = async {
        timeout(
            OPERATION_TIMEOUT,
            client
                .connect(server_addr, &server_material.server_name)
                .expect("start wrong-CA connection"),
        )
        .await
    };
    let (_server_result, client_result) = tokio::join!(server_task, client_task);
    assert!(
        !matches!(client_result, Ok(Ok(_))),
        "wrong CA must never establish a client connection"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_client_certificate_fails_closed() {
    let (root, server_material, _) = fixtures();
    let server = endpoint_with_server(
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server config"),
    );

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).expect("root");
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC crypto");
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.version(1);
    let client = endpoint_with_client(config);
    let server_addr = server.local_addr().expect("server address");

    let server_task = async {
        let incoming = timeout(OPERATION_TIMEOUT, server.accept())
            .await
            .expect("accept timeout")
            .expect("incoming");
        timeout(OPERATION_TIMEOUT, incoming).await
    };
    let client_task = async {
        timeout(
            OPERATION_TIMEOUT,
            client
                .connect(server_addr, &server_material.server_name)
                .expect("start anonymous connection"),
        )
        .await
    };
    let (server_result, client_result) = tokio::join!(server_task, client_task);
    assert!(
        !matches!(server_result, Ok(Ok(_))),
        "server must reject a peer that presents no client certificate"
    );
    if let Ok(Ok(connection)) = client_result {
        timeout(OPERATION_TIMEOUT, connection.closed())
            .await
            .expect("transient anonymous client handle must close within the operation bound");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn prw_expected_identity_mismatch_fails_after_valid_mtls() {
    let (root, server_material, client_material) = fixtures();
    let server = endpoint_with_server(
        build_server_config(
            vec![root.clone()],
            vec![server_material.certificate.clone()],
            private_key(&server_material.private_key),
        )
        .expect("server config"),
    );
    let client = endpoint_with_client(
        build_client_config(
            vec![root],
            vec![client_material.certificate.clone()],
            private_key(&client_material.private_key),
        )
        .expect("client config"),
    );
    let server_addr = server.local_addr().expect("server address");

    let server_task = async {
        let incoming = timeout(OPERATION_TIMEOUT, server.accept())
            .await
            .expect("accept timeout")
            .expect("incoming");
        timeout(OPERATION_TIMEOUT, incoming)
            .await
            .expect("server handshake timeout")
            .expect("server handshake")
    };
    let client_task = async {
        timeout(
            OPERATION_TIMEOUT,
            client
                .connect(server_addr, &server_material.server_name)
                .expect("connect"),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake")
    };
    let (server_connection, client_connection) = tokio::join!(server_task, client_task);

    let wrong = TransportIdentity::new([0x55; 32]).expect("test mismatch identity");
    assert_ne!(wrong, server_material.identity);
    assert_eq!(
        require_peer_transport_identity(&client_connection, wrong),
        Err(prw_remote_transport::RemoteTransportError::PeerIdentityMismatch)
    );

    server_connection.close(0_u32.into(), b"done");
    client_connection.close(0_u32.into(), b"done");
}
