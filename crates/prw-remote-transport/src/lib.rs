//! Disposable QUIC/TLS mesh transport foundation for Ownspace.
//!
//! Phase 140 owns only the bounded transport mechanics selected by Phase 139. It does
//! not grant PRW capabilities, perform NAT traversal, resolve DNS, mutate host networking,
//! or integrate the production Agent.

pub mod runtime;

use std::{fmt, sync::Arc, time::Duration};

use aws_lc_rs::digest::{SHA256, digest};
use prw_connectivity::TransportIdentity;
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, EndpointConfig,
    ServerConfig as QuinnServerConfig, TransportConfig, VarInt,
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ParsedCertificate, WebPkiClientVerifier},
};

/// Locked mesh ALPN identifier.
pub const MESH_ALPN: &[u8] = b"prw-mesh/1";
/// QUIC version 1 wire version.
pub const QUIC_VERSION_1: u32 = 1;
/// PRWM application magic.
pub const CONTROL_MAGIC: [u8; 4] = *b"PRWM";
/// Initial mesh protocol major version.
pub const CONTROL_PROTOCOL_MAJOR: u16 = 1;
/// Initial mesh protocol minor version.
pub const CONTROL_PROTOCOL_MINOR: u16 = 0;
/// Fixed PRWM control header size.
pub const CONTROL_HEADER_BYTES: usize = 24;
/// Maximum PRWM control payload size.
pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 65_536;
/// Maximum remotely initiated bidirectional streams.
pub const MAX_REMOTE_BIDI_STREAMS: u32 = 32;
/// Maximum remotely initiated unidirectional streams.
pub const MAX_REMOTE_UNI_STREAMS: u32 = 16;
/// Locked initial QUIC idle timeout.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded disposable operation timeout used by Phase 140 tests/callers.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Failure at the PRW remote-transport boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteTransportError {
    /// A presented certificate could not be parsed or its SPKI could not be used.
    InvalidCertificate,
    /// Derived transport identity was invalid under the existing PRW identity boundary.
    InvalidTransportIdentity,
    /// Local and peer transport identities were equal.
    EqualTransportIdentity,
    /// A derived certificate identity string was rejected by the TLS name type.
    InvalidServerName,
    /// Explicit trust roots were empty or invalid.
    InvalidTrustRoots,
    /// TLS configuration failed under the locked profile.
    TlsConfiguration,
    /// Quinn configuration failed under the locked profile.
    QuinnConfiguration,
    /// Quinn exposed no peer cryptographic identity after establishment.
    MissingPeerIdentity,
    /// Quinn peer identity used an unexpected dynamic type.
    UnexpectedPeerIdentityType,
    /// The authenticated certificate chain contained no leaf certificate.
    EmptyPeerCertificateChain,
    /// The authenticated leaf transport identity differed from the expected registry value.
    PeerIdentityMismatch,
    /// PRWM frame structure or bounds were invalid.
    InvalidControlFrame,
}

impl fmt::Display for RemoteTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCertificate => "invalid transport certificate",
            Self::InvalidTransportIdentity => "invalid transport identity",
            Self::EqualTransportIdentity => "local and peer transport identities are equal",
            Self::InvalidServerName => "invalid transport server name",
            Self::InvalidTrustRoots => "invalid or empty transport trust roots",
            Self::TlsConfiguration => "invalid locked TLS configuration",
            Self::QuinnConfiguration => "invalid locked QUIC configuration",
            Self::MissingPeerIdentity => "missing authenticated peer identity",
            Self::UnexpectedPeerIdentityType => "unexpected authenticated peer identity type",
            Self::EmptyPeerCertificateChain => "authenticated peer certificate chain is empty",
            Self::PeerIdentityMismatch => "authenticated peer transport identity mismatch",
            Self::InvalidControlFrame => "invalid PRWM control frame",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RemoteTransportError {}

/// Initial PRWM control message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ControlMessageKind {
    /// Authenticated application-session proof traffic.
    SessionAuthentication = 1,
    /// Bounded request envelope.
    Request = 2,
    /// Bounded response envelope.
    Response = 3,
    /// Bounded asynchronous event envelope.
    Event = 4,
    /// Heartbeat envelope.
    Heartbeat = 5,
    /// Bounded error envelope.
    Error = 6,
}

impl TryFrom<u16> for ControlMessageKind {
    type Error = RemoteTransportError;

    fn try_from(value: u16) -> Result<Self, RemoteTransportError> {
        match value {
            1 => Ok(Self::SessionAuthentication),
            2 => Ok(Self::Request),
            3 => Ok(Self::Response),
            4 => Ok(Self::Event),
            5 => Ok(Self::Heartbeat),
            6 => Ok(Self::Error),
            _ => Err(RemoteTransportError::InvalidControlFrame),
        }
    }
}

/// One fully validated PRWM v1.0 control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    kind: ControlMessageKind,
    request_id: u64,
    payload: Vec<u8>,
}

impl ControlFrame {
    /// Constructs one bounded PRWM frame.
    ///
    /// # Errors
    ///
    /// Rejects request identifier zero and payloads above 64 KiB.
    pub fn new(
        kind: ControlMessageKind,
        request_id: u64,
        payload: Vec<u8>,
    ) -> Result<Self, RemoteTransportError> {
        if request_id == 0 || payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
            return Err(RemoteTransportError::InvalidControlFrame);
        }
        Ok(Self {
            kind,
            request_id,
            payload,
        })
    }

    /// Returns the message kind.
    #[must_use]
    pub const fn kind(&self) -> ControlMessageKind {
        self.kind
    }

    /// Returns the non-zero request identifier.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the bounded payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the exact 24-byte header followed by payload bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        let mut output = Vec::with_capacity(CONTROL_HEADER_BYTES + self.payload.len());
        output.extend_from_slice(&CONTROL_MAGIC);
        output.extend_from_slice(&CONTROL_PROTOCOL_MAJOR.to_be_bytes());
        output.extend_from_slice(&CONTROL_PROTOCOL_MINOR.to_be_bytes());
        output.extend_from_slice(&(self.kind as u16).to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&self.request_id.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output
    }

    /// Decodes one complete PRWM v1.0 control frame after validating all header fields.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing bytes, invalid magic/version/kind/flags/request identifier,
    /// and payload lengths above the locked bound.
    pub fn decode(input: &[u8]) -> Result<Self, RemoteTransportError> {
        if input.len() < CONTROL_HEADER_BYTES || input[0..4] != CONTROL_MAGIC {
            return Err(RemoteTransportError::InvalidControlFrame);
        }

        let major = u16::from_be_bytes([input[4], input[5]]);
        let minor = u16::from_be_bytes([input[6], input[7]]);
        if major != CONTROL_PROTOCOL_MAJOR || minor != CONTROL_PROTOCOL_MINOR {
            return Err(RemoteTransportError::InvalidControlFrame);
        }

        let kind = ControlMessageKind::try_from(u16::from_be_bytes([input[8], input[9]]))?;
        if u16::from_be_bytes([input[10], input[11]]) != 0 {
            return Err(RemoteTransportError::InvalidControlFrame);
        }

        let request_id = u64::from_be_bytes([
            input[12], input[13], input[14], input[15], input[16], input[17], input[18], input[19],
        ]);
        if request_id == 0 {
            return Err(RemoteTransportError::InvalidControlFrame);
        }

        let payload_len = u32::from_be_bytes([input[20], input[21], input[22], input[23]]) as usize;
        if payload_len > MAX_CONTROL_PAYLOAD_BYTES
            || input.len() != CONTROL_HEADER_BYTES + payload_len
        {
            return Err(RemoteTransportError::InvalidControlFrame);
        }

        Self::new(kind, request_id, input[CONTROL_HEADER_BYTES..].to_vec())
    }
}

/// Derives the locked 32-byte transport identity from canonical leaf SPKI DER.
///
/// # Errors
///
/// Returns an error for malformed certificates or invalid derived identity material.
pub fn transport_identity_from_certificate(
    certificate: &CertificateDer<'_>,
) -> Result<TransportIdentity, RemoteTransportError> {
    let parsed = ParsedCertificate::try_from(certificate)
        .map_err(|_| RemoteTransportError::InvalidCertificate)?;
    let spki = parsed.subject_public_key_info();
    let value = digest(&SHA256, spki.as_ref());
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(value.as_ref());
    TransportIdentity::new(fingerprint).map_err(|_| RemoteTransportError::InvalidTransportIdentity)
}

/// Builds the deterministic certificate DNS SAN/SNI string from the full transport identity.
#[must_use]
pub fn transport_server_name(identity: TransportIdentity) -> String {
    let mut hex = String::with_capacity(64);
    for byte in identity.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("t-{}.{}.mesh.prw.invalid", &hex[..32], &hex[32..])
}

/// Returns whether the local peer is the deterministic application QUIC initiator.
///
/// # Errors
///
/// Equal transport identities fail closed.
pub fn local_is_deterministic_initiator(
    local: TransportIdentity,
    peer: TransportIdentity,
) -> Result<bool, RemoteTransportError> {
    match local.as_bytes().cmp(peer.as_bytes()) {
        std::cmp::Ordering::Less => Ok(true),
        std::cmp::Ordering::Greater => Ok(false),
        std::cmp::Ordering::Equal => Err(RemoteTransportError::EqualTransportIdentity),
    }
}

/// Returns a QUIC-v1-only endpoint configuration.
#[must_use]
pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.supported_versions(vec![QUIC_VERSION_1]);
    config
}

fn transport_config() -> Result<Arc<TransportConfig>, RemoteTransportError> {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_REMOTE_BIDI_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_REMOTE_UNI_STREAMS))
        .max_idle_timeout(Some(
            IDLE_TIMEOUT
                .try_into()
                .map_err(|_| RemoteTransportError::QuinnConfiguration)?,
        ))
        .stream_receive_window(VarInt::from_u32(65_536))
        .receive_window(VarInt::from_u32(1_048_576));
    Ok(Arc::new(config))
}

fn root_store(roots: Vec<CertificateDer<'static>>) -> Result<RootCertStore, RemoteTransportError> {
    if roots.is_empty() {
        return Err(RemoteTransportError::InvalidTrustRoots);
    }
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(root)
            .map_err(|_| RemoteTransportError::InvalidTrustRoots)?;
    }
    Ok(store)
}

/// Builds the locked TLS1.3-only mTLS Quinn client configuration from explicit roots.
///
/// # Errors
///
/// Rejects invalid/empty roots, invalid leaf/key material, or Quinn/rustls conversion failure.
pub fn build_client_config(
    roots: Vec<CertificateDer<'static>>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<QuinnClientConfig, RemoteTransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = RustlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RemoteTransportError::TlsConfiguration)?
        .with_root_certificates(root_store(roots)?)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(|_| RemoteTransportError::TlsConfiguration)?;
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = Resumption::disabled();

    let crypto =
        QuicClientConfig::try_from(tls).map_err(|_| RemoteTransportError::QuinnConfiguration)?;
    let mut config = QuinnClientConfig::new(Arc::new(crypto));
    config.version(QUIC_VERSION_1);
    config.transport_config(transport_config()?);
    Ok(config)
}

/// Builds the locked TLS1.3-only mTLS Quinn server configuration from explicit roots.
///
/// # Errors
///
/// Rejects invalid/empty roots, invalid leaf/key material, verifier construction failure, or
/// Quinn/rustls conversion failure.
pub fn build_server_config(
    roots: Vec<CertificateDer<'static>>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<QuinnServerConfig, RemoteTransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store(roots)?), provider.clone())
            .build()
            .map_err(|_| RemoteTransportError::TlsConfiguration)?;

    let mut tls = RustlsServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RemoteTransportError::TlsConfiguration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|_| RemoteTransportError::TlsConfiguration)?;
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;

    let crypto =
        QuicServerConfig::try_from(tls).map_err(|_| RemoteTransportError::QuinnConfiguration)?;
    let mut config = QuinnServerConfig::with_crypto(Arc::new(crypto));
    config.transport = transport_config()?;
    Ok(config)
}

/// Returns the negotiated rustls ALPN protocol from an established Quinn connection.
///
/// # Errors
///
/// Fails if handshake metadata is unavailable or not from the expected rustls session.
pub fn negotiated_alpn(connection: &Connection) -> Result<Vec<u8>, RemoteTransportError> {
    let data = connection
        .handshake_data()
        .ok_or(RemoteTransportError::TlsConfiguration)?
        .downcast::<HandshakeData>()
        .map_err(|_| RemoteTransportError::TlsConfiguration)?;
    data.protocol
        .clone()
        .ok_or(RemoteTransportError::TlsConfiguration)
}

/// Derives the authenticated peer transport identity from an established Quinn connection.
///
/// # Errors
///
/// Fails on missing/wrong identity type, empty chain, malformed leaf or invalid identity.
pub fn peer_transport_identity(
    connection: &Connection,
) -> Result<TransportIdentity, RemoteTransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(RemoteTransportError::MissingPeerIdentity)?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| RemoteTransportError::UnexpectedPeerIdentityType)?;
    let leaf = chain
        .first()
        .ok_or(RemoteTransportError::EmptyPeerCertificateChain)?;
    transport_identity_from_certificate(leaf)
}

/// Revalidates the authenticated peer certificate identity against the expected registry value.
///
/// # Errors
///
/// Returns [`RemoteTransportError::PeerIdentityMismatch`] when the presented leaf identity differs.
pub fn require_peer_transport_identity(
    connection: &Connection,
    expected: TransportIdentity,
) -> Result<(), RemoteTransportError> {
    if peer_transport_identity(connection)? != expected {
        return Err(RemoteTransportError::PeerIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> TransportIdentity {
        TransportIdentity::new([byte; 32]).expect("non-zero test identity")
    }

    #[test]
    fn deterministic_initiator_orders_transport_identity() {
        assert_eq!(
            local_is_deterministic_initiator(identity(1), identity(2)),
            Ok(true)
        );
        assert_eq!(
            local_is_deterministic_initiator(identity(2), identity(1)),
            Ok(false)
        );
        assert_eq!(
            local_is_deterministic_initiator(identity(1), identity(1)),
            Err(RemoteTransportError::EqualTransportIdentity)
        );
    }

    #[test]
    fn server_name_uses_all_transport_identity_bytes() {
        let name = transport_server_name(identity(0xab));
        assert_eq!(
            name,
            "t-abababababababababababababababab.abababababababababababababababab.mesh.prw.invalid"
        );
    }

    #[test]
    fn control_frame_round_trip() {
        let frame = ControlFrame::new(ControlMessageKind::Request, 7, b"hello".to_vec())
            .expect("valid frame");
        assert_eq!(ControlFrame::decode(&frame.encode()), Ok(frame));
    }

    #[test]
    fn control_frame_rejects_header_and_length_failures() {
        let valid = ControlFrame::new(ControlMessageKind::Event, 9, vec![1, 2, 3])
            .expect("valid frame")
            .encode();
        let mut cases = Vec::new();

        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        cases.push(bad_magic);

        let mut bad_version = valid.clone();
        bad_version[5] = 2;
        cases.push(bad_version);

        let mut bad_kind = valid.clone();
        bad_kind[9] = 99;
        cases.push(bad_kind);

        let mut bad_flags = valid.clone();
        bad_flags[11] = 1;
        cases.push(bad_flags);

        let mut zero_request = valid.clone();
        zero_request[12..20].fill(0);
        cases.push(zero_request);

        let mut oversized = valid.clone();
        oversized[20..24].copy_from_slice(&65_537_u32.to_be_bytes());
        cases.push(oversized);

        cases.push(valid[..valid.len() - 1].to_vec());

        let mut trailing = valid;
        trailing.push(0);
        cases.push(trailing);

        for case in cases {
            assert_eq!(
                ControlFrame::decode(&case),
                Err(RemoteTransportError::InvalidControlFrame)
            );
        }
    }
}
