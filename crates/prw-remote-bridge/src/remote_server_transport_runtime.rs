//! Bridge-owned real QUIC server endpoint wrapper for the authority-gated Agent runtime.
//!
//! C03e-C composes the existing C03e-B DER helper and C03c real-socket endpoint behind one narrow
//! server-runtime owner. C03e-D adds only an opaque handoff for one lower-transport-authenticated
//! peer. It does not authenticate logical sessions, grant capabilities, or publish Agent readiness.

use std::{fmt, net::SocketAddr};

pub use prw_connectivity::TransportIdentity;
use prw_remote_transport::runtime::{
    MeshControlStream, MeshQuicConnection, MeshQuicEndpoint, MeshQuicRuntimeError,
    build_server_config_from_der,
};

/// Failure while constructing, querying, or accepting through one bridge-owned real server endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteServerTransportRuntimeError {
    /// Existing C03c/C03e-B transport validation, TLS construction, or socket runtime failed.
    Transport(MeshQuicRuntimeError),
}

impl fmt::Display for RemoteServerTransportRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("remote server transport runtime failed"),
        }
    }
}

impl std::error::Error for RemoteServerTransportRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for RemoteServerTransportRuntimeError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Transport(error)
    }
}

/// One established lower-transport-authenticated peer accepted by the bridge-owned server endpoint.
///
/// The constructor is intentionally private. Instances exist only after C03c validates the QUIC/TLS
/// handshake, locked ALPN, and the exact expected certificate-derived [`TransportIdentity`]. Holding
/// this value is not logical-session authentication and is not capability authorization.
#[derive(Debug)]
pub struct AuthenticatedRemotePeerConnection {
    connection: MeshQuicConnection,
}

impl AuthenticatedRemotePeerConnection {
    /// Returns the exact peer transport identity already revalidated by C03c.
    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.connection.peer_transport_identity()
    }

    /// Accepts one peer-initiated bounded PRWM control stream.
    ///
    /// This exposes only the existing bounded C03c stream primitive required by the separately
    /// gated C03d logical-session wire adapter. The raw Quinn connection is not exposed.
    ///
    /// # Errors
    ///
    /// Propagates the existing C03c bounded stream-accept failure classification.
    pub async fn accept_control_stream(
        &self,
    ) -> Result<MeshControlStream, RemoteServerTransportRuntimeError> {
        self.connection
            .accept_control_stream()
            .await
            .map_err(Into::into)
    }

    /// Explicitly closes this accepted peer connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code, reason);
    }
}

/// One real bound QUIC server endpoint owned at the remote-bridge boundary.
#[derive(Debug)]
pub struct RemoteServerTransportRuntime {
    endpoint: MeshQuicEndpoint,
}

impl RemoteServerTransportRuntime {
    /// Builds the locked server TLS profile from owned DER and binds one real UDP/QUIC endpoint.
    ///
    /// TLS construction occurs before socket binding. The supplied address is explicit; this path
    /// performs no DNS discovery, reachability lookup, retry, peer acceptance, or readiness
    /// publication.
    ///
    /// # Errors
    ///
    /// Propagates the existing C03c/C03e-B failure through
    /// [`RemoteServerTransportRuntimeError::Transport`].
    pub fn bind_from_der(
        bind_addr: SocketAddr,
        root_certificate_der: Vec<u8>,
        certificate_der: Vec<u8>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Result<Self, RemoteServerTransportRuntimeError> {
        let server_config = build_server_config_from_der(
            root_certificate_der,
            certificate_der,
            private_key_pkcs8_der,
        )?;
        let endpoint = MeshQuicEndpoint::bind_server(bind_addr, server_config)?;
        Ok(Self { endpoint })
    }

    /// Accepts one real QUIC/TLS peer through the existing C03c authenticated transport primitive.
    ///
    /// The expected identity is a transport-level certificate identity, not a logical `DeviceId`
    /// and not an authorization grant. Successful return proves only the already-locked lower
    /// transport checks and yields an opaque bridge-owned peer handle.
    ///
    /// # Errors
    ///
    /// Propagates C03c timeout, endpoint closure, handshake, ALPN, or exact transport-identity
    /// validation failure through [`RemoteServerTransportRuntimeError::Transport`].
    pub async fn accept_authenticated_peer(
        &self,
        expected_peer: TransportIdentity,
    ) -> Result<AuthenticatedRemotePeerConnection, RemoteServerTransportRuntimeError> {
        let connection = self.endpoint.accept_authenticated(expected_peer).await?;
        Ok(AuthenticatedRemotePeerConnection { connection })
    }

    /// Returns the kernel-selected local UDP address of the bound endpoint.
    ///
    /// # Errors
    ///
    /// Propagates the existing C03c endpoint-address failure classification.
    pub fn local_addr(&self) -> Result<SocketAddr, RemoteServerTransportRuntimeError> {
        self.endpoint.local_addr().map_err(Into::into)
    }

    /// Explicitly closes this endpoint and all live connections.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.endpoint.close(code, reason);
    }

    /// Waits until the underlying real QUIC endpoint becomes idle.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use prw_connectivity::TransportIdentity;
    use prw_remote_transport::{RemoteTransportError, runtime::MeshQuicRuntimeError};

    use super::{
        AuthenticatedRemotePeerConnection, RemoteServerTransportRuntime,
        RemoteServerTransportRuntimeError,
    };

    const fn loopback_any() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn assert_peer_public_surface(
        identity: fn(&AuthenticatedRemotePeerConnection) -> TransportIdentity,
        close: fn(&AuthenticatedRemotePeerConnection, u32, &[u8]),
    ) {
        let _ = (identity, close);
    }

    #[test]
    fn malformed_tls_material_fails_before_server_runtime_exists() {
        let result = RemoteServerTransportRuntime::bind_from_der(
            loopback_any(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            result,
            Err(RemoteServerTransportRuntimeError::Transport(
                MeshQuicRuntimeError::Transport(RemoteTransportError::InvalidTrustRoots)
            ))
        ));
    }

    #[test]
    fn accepted_peer_public_surface_exposes_validated_identity_and_explicit_close_only() {
        assert_peer_public_surface(
            AuthenticatedRemotePeerConnection::transport_identity,
            AuthenticatedRemotePeerConnection::close,
        );
    }
}
