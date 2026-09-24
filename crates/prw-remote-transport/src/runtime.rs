//! Reusable real UDP/QUIC runtime for the PRW mesh transport.
//!
//! This module owns bounded socket/endpoint/connection/stream mechanics only. It does not
//! authenticate a logical PRW device session, grant capabilities, perform reachability lookup,
//! run ICE, select relay fallback, or mutate Agent readiness.

use std::{
    fmt,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use prw_connectivity::TransportIdentity;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TokioRuntime,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

use crate::{
    CONTROL_HEADER_BYTES, ControlFrame, MAX_CONTROL_PAYLOAD_BYTES, MESH_ALPN, OPERATION_TIMEOUT,
    RemoteTransportError, build_server_config, endpoint_config, negotiated_alpn,
    require_peer_transport_identity, transport_server_name,
};

/// Failure at the reusable real-socket QUIC runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeshQuicRuntimeError {
    /// The requested local UDP socket could not be bound.
    BindSocket,
    /// Quinn could not construct an endpoint from the bound UDP socket.
    EndpointConstruction,
    /// The endpoint local socket address could not be read.
    LocalAddress,
    /// The endpoint stopped accepting before a connection arrived.
    EndpointClosed,
    /// A client connection could not be started.
    ConnectionStart,
    /// The QUIC/TLS handshake failed.
    ConnectionFailed,
    /// A bounded network operation exceeded the locked operation timeout.
    OperationTimeout,
    /// The established connection negotiated an unexpected ALPN.
    AlpnMismatch,
    /// A bidirectional stream could not be opened.
    OpenStream,
    /// A peer bidirectional stream could not be accepted.
    AcceptStream,
    /// A bounded PRWM frame could not be read from a stream.
    ReadFrame,
    /// A bounded PRWM frame could not be written to a stream.
    WriteFrame,
    /// A stream could not be cleanly finished after frame transmission.
    FinishStream,
    /// Existing transport validation failed.
    Transport(RemoteTransportError),
}

impl fmt::Display for MeshQuicRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BindSocket => "failed to bind mesh UDP socket",
            Self::EndpointConstruction => "failed to construct mesh QUIC endpoint",
            Self::LocalAddress => "failed to read mesh endpoint local address",
            Self::EndpointClosed => "mesh QUIC endpoint is closed",
            Self::ConnectionStart => "failed to start mesh QUIC connection",
            Self::ConnectionFailed => "mesh QUIC/TLS connection failed",
            Self::OperationTimeout => "mesh network operation timed out",
            Self::AlpnMismatch => "mesh QUIC connection negotiated unexpected ALPN",
            Self::OpenStream => "failed to open mesh bidirectional stream",
            Self::AcceptStream => "failed to accept mesh bidirectional stream",
            Self::ReadFrame => "failed to read bounded PRWM frame",
            Self::WriteFrame => "failed to write bounded PRWM frame",
            Self::FinishStream => "failed to finish mesh send stream",
            Self::Transport(_) => "mesh transport validation failed",
        })
    }
}

impl std::error::Error for MeshQuicRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RemoteTransportError> for MeshQuicRuntimeError {
    fn from(error: RemoteTransportError) -> Self {
        Self::Transport(error)
    }
}

/// Converts one owned root/leaf/PKCS#8 DER set through the existing locked server TLS builder.
///
/// This helper performs only typed DER ownership conversion. It does not bind a socket, publish
/// readiness, authenticate a logical PRW session, or weaken the TLS/QUIC profile owned by
/// [`build_server_config`].
///
/// # Errors
///
/// Propagates the existing locked transport validation when trust-root, certificate, private-key,
/// rustls, or Quinn configuration rejects the supplied material.
pub fn build_server_config_from_der(
    root_certificate_der: Vec<u8>,
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Vec<u8>,
) -> Result<ServerConfig, MeshQuicRuntimeError> {
    let roots = vec![CertificateDer::from(root_certificate_der)];
    let certificate_chain = vec![CertificateDer::from(certificate_der)];
    let private_key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(private_key_pkcs8_der).into();
    build_server_config(roots, certificate_chain, private_key)
        .map_err(MeshQuicRuntimeError::Transport)
}

/// One reusable Quinn endpoint backed by a real bound UDP socket.
#[derive(Debug)]
pub struct MeshQuicEndpoint {
    endpoint: Endpoint,
}

impl MeshQuicEndpoint {
    /// Binds a real UDP socket and constructs a QUIC server endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the UDP bind or Quinn endpoint construction fails.
    pub fn bind_server(
        bind_addr: SocketAddr,
        server_config: ServerConfig,
    ) -> Result<Self, MeshQuicRuntimeError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|_| MeshQuicRuntimeError::BindSocket)?;
        let endpoint = Endpoint::new(
            endpoint_config(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|_| MeshQuicRuntimeError::EndpointConstruction)?;
        Ok(Self { endpoint })
    }

    /// Binds a real UDP socket and constructs a QUIC client endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the UDP bind or Quinn endpoint construction fails.
    pub fn bind_client(
        bind_addr: SocketAddr,
        client_config: ClientConfig,
    ) -> Result<Self, MeshQuicRuntimeError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|_| MeshQuicRuntimeError::BindSocket)?;
        let mut endpoint = Endpoint::new(endpoint_config(), None, socket, Arc::new(TokioRuntime))
            .map_err(|_| MeshQuicRuntimeError::EndpointConstruction)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// Returns the kernel-assigned local UDP address.
    ///
    /// # Errors
    ///
    /// Fails when Quinn cannot read the endpoint address.
    pub fn local_addr(&self) -> Result<SocketAddr, MeshQuicRuntimeError> {
        self.endpoint
            .local_addr()
            .map_err(|_| MeshQuicRuntimeError::LocalAddress)
    }

    /// Accepts one real QUIC/TLS connection and validates ALPN plus expected peer identity.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, endpoint closure, handshake failure, ALPN mismatch, or peer
    /// transport-identity mismatch.
    pub async fn accept_authenticated(
        &self,
        expected_peer: TransportIdentity,
    ) -> Result<MeshQuicConnection, MeshQuicRuntimeError> {
        let incoming = timeout(OPERATION_TIMEOUT, self.endpoint.accept())
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .ok_or(MeshQuicRuntimeError::EndpointClosed)?;
        let connection = timeout(OPERATION_TIMEOUT, incoming)
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .map_err(|_| MeshQuicRuntimeError::ConnectionFailed)?;
        MeshQuicConnection::validate(connection, expected_peer)
    }

    /// Connects to one real peer address and validates ALPN plus expected peer identity.
    ///
    /// # Errors
    ///
    /// Fails closed on connect setup, timeout, handshake, ALPN, or peer-identity failure.
    pub async fn connect_authenticated(
        &self,
        remote_addr: SocketAddr,
        expected_peer: TransportIdentity,
    ) -> Result<MeshQuicConnection, MeshQuicRuntimeError> {
        let server_name = transport_server_name(expected_peer);
        let connecting = self
            .endpoint
            .connect(remote_addr, &server_name)
            .map_err(|_| MeshQuicRuntimeError::ConnectionStart)?;
        let connection = timeout(OPERATION_TIMEOUT, connecting)
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .map_err(|_| MeshQuicRuntimeError::ConnectionFailed)?;
        MeshQuicConnection::validate(connection, expected_peer)
    }

    /// Closes the endpoint and all live connections with a bounded application reason.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.endpoint.close(code.into(), reason);
    }

    /// Waits until all endpoint connections are idle.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// One established mTLS QUIC connection whose expected peer `TransportIdentity` was revalidated.
#[derive(Debug, Clone)]
pub struct MeshQuicConnection {
    connection: Connection,
    peer_transport_identity: TransportIdentity,
}

impl MeshQuicConnection {
    fn validate(
        connection: Connection,
        expected_peer: TransportIdentity,
    ) -> Result<Self, MeshQuicRuntimeError> {
        if negotiated_alpn(&connection)?.as_slice() != MESH_ALPN {
            return Err(MeshQuicRuntimeError::AlpnMismatch);
        }
        require_peer_transport_identity(&connection, expected_peer)?;
        Ok(Self {
            connection,
            peer_transport_identity: expected_peer,
        })
    }

    /// Returns the already revalidated peer transport identity.
    #[must_use]
    pub const fn peer_transport_identity(&self) -> TransportIdentity {
        self.peer_transport_identity
    }

    /// Opens one bidirectional control stream.
    ///
    /// # Errors
    ///
    /// Fails on timeout or stream-open failure.
    pub async fn open_control_stream(&self) -> Result<MeshControlStream, MeshQuicRuntimeError> {
        let (send, recv) = timeout(OPERATION_TIMEOUT, self.connection.open_bi())
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .map_err(|_| MeshQuicRuntimeError::OpenStream)?;
        Ok(MeshControlStream { send, recv })
    }

    /// Accepts one peer-initiated bidirectional control stream.
    ///
    /// # Errors
    ///
    /// Fails on timeout or stream-accept failure.
    pub async fn accept_control_stream(&self) -> Result<MeshControlStream, MeshQuicRuntimeError> {
        let (send, recv) = timeout(OPERATION_TIMEOUT, self.connection.accept_bi())
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .map_err(|_| MeshQuicRuntimeError::AcceptStream)?;
        Ok(MeshControlStream { send, recv })
    }

    /// Closes this connection with an application error code and reason.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
    }
}

/// One real QUIC bidirectional stream carrying bounded PRWM frames.
#[derive(Debug)]
pub struct MeshControlStream {
    send: SendStream,
    recv: RecvStream,
}

impl MeshControlStream {
    /// Writes exactly one bounded PRWM frame and finishes the send direction.
    ///
    /// # Errors
    ///
    /// Fails on timeout, stream write failure, or finish failure.
    pub async fn send_frame(&mut self, frame: &ControlFrame) -> Result<(), MeshQuicRuntimeError> {
        let encoded = frame.encode();
        timeout(OPERATION_TIMEOUT, self.send.write_all(&encoded))
            .await
            .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
            .map_err(|_| MeshQuicRuntimeError::WriteFrame)?;
        self.send
            .finish()
            .map_err(|_| MeshQuicRuntimeError::FinishStream)
    }

    /// Reads exactly one complete bounded PRWM frame from the peer send direction.
    ///
    /// # Errors
    ///
    /// Fails on timeout, stream read/bound failure, or PRWM validation failure.
    pub async fn receive_frame(&mut self) -> Result<ControlFrame, MeshQuicRuntimeError> {
        let bytes = timeout(
            OPERATION_TIMEOUT,
            self.recv
                .read_to_end(CONTROL_HEADER_BYTES + MAX_CONTROL_PAYLOAD_BYTES),
        )
        .await
        .map_err(|_| MeshQuicRuntimeError::OperationTimeout)?
        .map_err(|_| MeshQuicRuntimeError::ReadFrame)?;
        ControlFrame::decode(&bytes).map_err(MeshQuicRuntimeError::Transport)
    }
}
