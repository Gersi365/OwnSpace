//! Phase 152 C02f-BX bounded etcd provider/client bootstrap materialization.
//!
//! C02f-BV selected one immutable logical authority-cluster configuration and two distinct
//! authenticated client identities: live-owner authority and fence-sequence allocation. C02f-BW
//! corrected preparation construction so those roles consume distinct `KvClient` values. This
//! module materializes only the control-plane-owned provider bootstrap between those checkpoints.
//!
//! The bootstrap accepts one exact three-member HTTPS endpoint set, one explicit private trust
//! bundle, and two non-printable role-scoped mTLS identity materials. It connects both roles to the
//! same endpoint set with the same trust bundle, retains only each client's `KvClient`, drops the
//! broad `Client` handles, and returns one `ReachabilityLiveOwnerAcquisitionPreparation`.
//!
//! No endpoint value, certificate, private key, username/password, auth/RBAC mutation, runtime task,
//! retry scheduler, deployment action, or production activation is embedded here.

use std::{collections::HashSet, fmt, net::IpAddr};

use etcd_client::{Certificate, Client, ConnectOptions, Identity, TlsOptions};
use zeroize::Zeroizing;

use super::ReachabilityLiveOwnerAcquisitionPreparation;

const AUTHORITY_MEMBER_COUNT: usize = 3;

/// Runtime-supplied mTLS identity material for exactly one etcd authority role.
///
/// The type deliberately does not implement `Clone` or `Debug`; this prevents accidental duplication
/// or formatting of private-key material through ordinary trait usage. The bytes are consumed by the
/// provider bootstrap and are never exposed through accessors.
pub struct ReachabilityEtcdClientIdentityMaterial {
    certificate_pem: Vec<u8>,
    private_key_pem: Zeroizing<Vec<u8>>,
}

impl ReachabilityEtcdClientIdentityMaterial {
    /// Creates one role-scoped mTLS client identity from non-empty runtime secret material.
    ///
    /// Cryptographic certificate/key parsing remains the responsibility of the rustls-backed etcd
    /// TLS connector during bootstrap. This constructor performs bounded structural checks only and
    /// never logs or formats the supplied bytes.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when either PEM input is empty or ASCII-whitespace-only.
    pub fn new(
        certificate_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, ReachabilityEtcdClientIdentityMaterialError> {
        let private_key_pem = Zeroizing::new(private_key_pem.into());
        Self::new_with_zeroizing_private_key(certificate_pem, private_key_pem)
    }

    /// Creates one role-scoped identity while preserving an existing zeroizing private-key owner.
    ///
    /// This is the selected production custody handoff seam. The private-key buffer is moved by
    /// value and retained directly; it is not cloned, unwrapped, or copied into an ordinary
    /// PRW-owned plaintext buffer.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when either PEM input is empty or ASCII-whitespace-only.
    pub fn new_with_zeroizing_private_key(
        certificate_pem: impl Into<Vec<u8>>,
        private_key_pem: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ReachabilityEtcdClientIdentityMaterialError> {
        let certificate_pem = certificate_pem.into();
        if !contains_non_whitespace(&certificate_pem) {
            return Err(ReachabilityEtcdClientIdentityMaterialError::EmptyCertificate);
        }

        if !contains_non_whitespace(private_key_pem.as_slice()) {
            return Err(ReachabilityEtcdClientIdentityMaterialError::EmptyPrivateKey);
        }

        Ok(Self {
            certificate_pem,
            private_key_pem,
        })
    }
}

/// Structural validation failure for one role-scoped mTLS identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityEtcdClientIdentityMaterialError {
    /// Client certificate material is absent.
    EmptyCertificate,
    /// Client private-key material is absent.
    EmptyPrivateKey,
}

impl fmt::Display for ReachabilityEtcdClientIdentityMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCertificate => {
                formatter.write_str("etcd client identity certificate material is empty")
            }
            Self::EmptyPrivateKey => {
                formatter.write_str("etcd client identity private-key material is empty")
            }
        }
    }
}

impl std::error::Error for ReachabilityEtcdClientIdentityMaterialError {}

/// Validated immutable input for one bounded two-role authority bootstrap.
///
/// One endpoint vector and one trust bundle are shared by construction, so callers cannot silently
/// point the two authenticated roles at different clusters or widen trust for one role. The two
/// client identities remain distinct owned values and are not printable.
pub struct ReachabilityLiveOwnerEtcdBootstrapConfig {
    endpoints: Vec<String>,
    trust_bundle_pem: Vec<u8>,
    live_owner_identity: ReachabilityEtcdClientIdentityMaterial,
    fence_allocator_identity: ReachabilityEtcdClientIdentityMaterial,
}

impl ReachabilityLiveOwnerEtcdBootstrapConfig {
    /// Validates and retains the exact immutable authority-cluster bootstrap material.
    ///
    /// Exactly three unique stable-FQDN HTTPS endpoints are required, matching the selected C02f-AF
    /// voting topology. Paths, queries, fragments, user-info, IP literals, wildcard/localhost names,
    /// malformed ports, and duplicate member hostnames are rejected. The explicit private trust
    /// bundle must be non-empty. Exact client-certificate or private-key byte reuse across the two
    /// authority roles is rejected.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration error before any provider I/O is attempted.
    pub fn new<E, S>(
        endpoints: E,
        trust_bundle_pem: impl Into<Vec<u8>>,
        live_owner_identity: ReachabilityEtcdClientIdentityMaterial,
        fence_allocator_identity: ReachabilityEtcdClientIdentityMaterial,
    ) -> Result<Self, ReachabilityLiveOwnerEtcdBootstrapConfigError>
    where
        E: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
        validate_endpoints(&endpoints)?;

        let trust_bundle_pem = trust_bundle_pem.into();
        if !contains_non_whitespace(&trust_bundle_pem) {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::EmptyTrustBundle);
        }

        if live_owner_identity.certificate_pem == fence_allocator_identity.certificate_pem {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedClientCertificate);
        }
        if live_owner_identity.private_key_pem.as_slice()
            == fence_allocator_identity.private_key_pem.as_slice()
        {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey);
        }

        Ok(Self {
            endpoints,
            trust_bundle_pem,
            live_owner_identity,
            fence_allocator_identity,
        })
    }
}

/// Fail-closed validation error for the immutable authority-cluster bootstrap input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerEtcdBootstrapConfigError {
    /// The selected production authority topology requires exactly three client endpoints.
    EndpointCount,
    /// A configured endpoint is not HTTPS.
    InsecureEndpoint,
    /// Endpoint authority, port, path, query, fragment, or user-info syntax is invalid.
    MalformedEndpoint,
    /// Endpoint host is not a stable FQDN selected for authority-member identity.
    NonFqdnEndpoint,
    /// More than one configured endpoint resolves to the same textual member FQDN.
    DuplicateMemberHost,
    /// The explicit private authority trust bundle is absent.
    EmptyTrustBundle,
    /// Both authority roles were supplied the exact same client certificate bytes.
    ReusedClientCertificate,
    /// Both authority roles were supplied the exact same client private-key bytes.
    ReusedPrivateKey,
}

impl fmt::Display for ReachabilityLiveOwnerEtcdBootstrapConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EndpointCount => "etcd authority bootstrap requires exactly three endpoints",
            Self::InsecureEndpoint => "etcd authority bootstrap endpoint must use https",
            Self::MalformedEndpoint => "etcd authority bootstrap endpoint is malformed",
            Self::NonFqdnEndpoint => "etcd authority bootstrap endpoint host must be a stable fqdn",
            Self::DuplicateMemberHost => {
                "etcd authority bootstrap endpoint member host must be unique"
            }
            Self::EmptyTrustBundle => "etcd authority bootstrap trust bundle is empty",
            Self::ReusedClientCertificate => {
                "etcd authority bootstrap client certificates must be role-separated"
            }
            Self::ReusedPrivateKey => {
                "etcd authority bootstrap client private keys must be role-separated"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReachabilityLiveOwnerEtcdBootstrapConfigError {}

/// Provider connection failure during the bounded two-role bootstrap.
///
/// The underlying provider error is intentionally not retained in this public type, preventing
/// accidental propagation of connection/configuration detail into higher-level semantic APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerEtcdBootstrapError {
    /// The live-owner authority mTLS client could not be established.
    LiveOwnerConnect,
    /// The fence-sequence allocator mTLS client could not be established.
    FenceAllocatorConnect,
}

impl fmt::Display for ReachabilityLiveOwnerEtcdBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveOwnerConnect => {
                formatter.write_str("live-owner etcd authority bootstrap connection failed")
            }
            Self::FenceAllocatorConnect => {
                formatter.write_str("fence-allocator etcd authority bootstrap connection failed")
            }
        }
    }
}

impl std::error::Error for ReachabilityLiveOwnerEtcdBootstrapError {}

/// Connects the two role-scoped mTLS clients and returns the narrow preparation facade.
///
/// Both connections consume the same exact validated endpoint vector and explicit private trust
/// bundle. No native/system roots, plaintext fallback, username/password authentication, dynamic
/// endpoint discovery, or auth/RBAC mutation is added. Only each broad client's `KvClient` is
/// retained; the broad `Client` handle is dropped before the preparation is returned.
///
/// Calling this async function performs provider network I/O. Merely constructing the config and
/// identity material performs none.
///
/// # Errors
///
/// Returns a role-specific fail-closed connection error if either authenticated client cannot be
/// established. A successful live-owner connection is not returned or exposed if the allocator
/// connection subsequently fails.
pub async fn bootstrap_reachability_live_owner_preparation(
    config: ReachabilityLiveOwnerEtcdBootstrapConfig,
) -> Result<ReachabilityLiveOwnerAcquisitionPreparation, ReachabilityLiveOwnerEtcdBootstrapError> {
    let ReachabilityLiveOwnerEtcdBootstrapConfig {
        endpoints,
        trust_bundle_pem,
        live_owner_identity,
        fence_allocator_identity,
    } = config;

    let live_owner_options = connect_options(&trust_bundle_pem, &live_owner_identity);
    let live_owner_client = Client::connect(endpoints.as_slice(), Some(live_owner_options))
        .await
        .map_err(|_| ReachabilityLiveOwnerEtcdBootstrapError::LiveOwnerConnect)?;
    let live_owner_kv = live_owner_client.kv_client();
    drop(live_owner_client);

    let fence_allocator_options = connect_options(&trust_bundle_pem, &fence_allocator_identity);
    let fence_allocator_client =
        Client::connect(endpoints.as_slice(), Some(fence_allocator_options))
            .await
            .map_err(|_| ReachabilityLiveOwnerEtcdBootstrapError::FenceAllocatorConnect)?;
    let fence_allocator_kv = fence_allocator_client.kv_client();
    drop(fence_allocator_client);

    Ok(
        ReachabilityLiveOwnerAcquisitionPreparation::from_role_scoped_clients(
            live_owner_kv,
            fence_allocator_kv,
        ),
    )
}

fn connect_options(
    trust_bundle_pem: &[u8],
    identity: &ReachabilityEtcdClientIdentityMaterial,
) -> ConnectOptions {
    let tls = TlsOptions::new()
        .ca_certificate(Certificate::from_pem(trust_bundle_pem))
        .identity(Identity::from_pem(
            identity.certificate_pem.as_slice(),
            identity.private_key_pem.as_slice(),
        ));
    ConnectOptions::new().with_tls(tls)
}

fn validate_endpoints(
    endpoints: &[String],
) -> Result<(), ReachabilityLiveOwnerEtcdBootstrapConfigError> {
    if endpoints.len() != AUTHORITY_MEMBER_COUNT {
        return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::EndpointCount);
    }

    let mut hosts = HashSet::with_capacity(AUTHORITY_MEMBER_COUNT);
    for endpoint in endpoints {
        let host = validate_endpoint(endpoint)?;
        if !hosts.insert(host) {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::DuplicateMemberHost);
        }
    }

    Ok(())
}

fn validate_endpoint(
    endpoint: &str,
) -> Result<String, ReachabilityLiveOwnerEtcdBootstrapConfigError> {
    let authority = endpoint
        .strip_prefix("https://")
        .ok_or(ReachabilityLiveOwnerEtcdBootstrapConfigError::InsecureEndpoint)?;

    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::MalformedEndpoint);
    }

    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::MalformedEndpoint);
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| ReachabilityLiveOwnerEtcdBootstrapConfigError::MalformedEndpoint)?;
        if port == 0 {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::MalformedEndpoint);
        }
        host
    } else {
        authority
    };

    validate_fqdn(host)?;
    Ok(host.to_ascii_lowercase())
}

fn validate_fqdn(host: &str) -> Result<(), ReachabilityLiveOwnerEtcdBootstrapConfigError> {
    if !host.is_ascii()
        || host.len() > 253
        || !host.contains('.')
        || host.eq_ignore_ascii_case("localhost")
        || host.contains('*')
        || host.parse::<IpAddr>().is_ok()
    {
        return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::NonFqdnEndpoint);
    }

    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::NonFqdnEndpoint);
        }
    }

    Ok(())
}

fn contains_non_whitespace(value: &[u8]) -> bool {
    value.iter().any(|byte| !byte.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        certificate_marker: u8,
        private_key_marker: u8,
    ) -> ReachabilityEtcdClientIdentityMaterial {
        ReachabilityEtcdClientIdentityMaterial::new(
            vec![certificate_marker],
            vec![private_key_marker],
        )
        .expect("non-empty identity material")
    }

    fn endpoints() -> [&'static str; AUTHORITY_MEMBER_COUNT] {
        [
            "https://etcd-a.authority.example:2379",
            "https://etcd-b.authority.example:2379",
            "https://etcd-c.authority.example:2379",
        ]
    }

    fn config<E, S>(
        endpoints: E,
    ) -> Result<
        ReachabilityLiveOwnerEtcdBootstrapConfig,
        ReachabilityLiveOwnerEtcdBootstrapConfigError,
    >
    where
        E: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ReachabilityLiveOwnerEtcdBootstrapConfig::new(
            endpoints,
            b"private-authority-ca".to_vec(),
            identity(1, 2),
            identity(3, 4),
        )
    }

    #[test]
    fn identity_material_rejects_empty_or_whitespace_secret_bytes() {
        assert!(matches!(
            ReachabilityEtcdClientIdentityMaterial::new(Vec::<u8>::new(), vec![1]),
            Err(ReachabilityEtcdClientIdentityMaterialError::EmptyCertificate)
        ));
        assert!(matches!(
            ReachabilityEtcdClientIdentityMaterial::new(vec![1], b" \n\t".to_vec()),
            Err(ReachabilityEtcdClientIdentityMaterialError::EmptyPrivateKey)
        ));
    }

    #[test]
    fn config_accepts_exact_three_member_https_fqdn_topology() {
        assert!(config(endpoints()).is_ok());
    }

    #[test]
    fn config_rejects_wrong_member_count() {
        assert!(matches!(
            config([
                "https://etcd-a.authority.example:2379",
                "https://etcd-b.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::EndpointCount)
        ));
    }

    #[test]
    fn config_rejects_plaintext_ip_wildcard_and_non_endpoint_surfaces() {
        assert!(matches!(
            config([
                "http://etcd-a.authority.example:2379",
                "https://etcd-b.authority.example:2379",
                "https://etcd-c.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::InsecureEndpoint)
        ));
        assert!(matches!(
            config([
                "https://127.0.0.1:2379",
                "https://etcd-b.authority.example:2379",
                "https://etcd-c.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::NonFqdnEndpoint)
        ));
        assert!(matches!(
            config([
                "https://*.authority.example:2379",
                "https://etcd-b.authority.example:2379",
                "https://etcd-c.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::NonFqdnEndpoint)
        ));
        assert!(matches!(
            config([
                "https://etcd-a.authority.example:2379/path",
                "https://etcd-b.authority.example:2379",
                "https://etcd-c.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::MalformedEndpoint)
        ));
    }

    #[test]
    fn config_rejects_duplicate_member_hostname_even_with_different_port() {
        assert!(matches!(
            config([
                "https://etcd-a.authority.example:2379",
                "https://etcd-a.authority.example:2380",
                "https://etcd-c.authority.example:2379",
            ]),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::DuplicateMemberHost)
        ));
    }

    #[test]
    fn config_rejects_missing_trust_and_exact_cross_role_identity_reuse() {
        let empty_trust = ReachabilityLiveOwnerEtcdBootstrapConfig::new(
            endpoints(),
            b" \n".to_vec(),
            identity(1, 2),
            identity(3, 4),
        );
        assert!(matches!(
            empty_trust,
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::EmptyTrustBundle)
        ));

        let reused_certificate = ReachabilityLiveOwnerEtcdBootstrapConfig::new(
            endpoints(),
            b"private-authority-ca".to_vec(),
            identity(7, 8),
            identity(7, 20),
        );
        assert!(matches!(
            reused_certificate,
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedClientCertificate)
        ));

        let reused_private_key = ReachabilityLiveOwnerEtcdBootstrapConfig::new(
            endpoints(),
            b"private-authority-ca".to_vec(),
            identity(7, 8),
            identity(20, 8),
        );
        assert!(matches!(
            reused_private_key,
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey)
        ));
    }
}

/// Validated immutable input for one bounded three-role production authority bootstrap.
///
/// This additive config preserves the existing two-role bootstrap API while adding a dedicated
/// durable-snapshot identity on the same exact endpoint set and explicit trust bundle. All three
/// identities are retained by value and must remain pairwise certificate/key separated.
pub struct ReachabilityProductionEtcdBootstrapConfig {
    endpoints: Vec<String>,
    trust_bundle_pem: Vec<u8>,
    live_owner_identity: ReachabilityEtcdClientIdentityMaterial,
    fence_allocator_identity: ReachabilityEtcdClientIdentityMaterial,
    durable_snapshot_identity: ReachabilityEtcdClientIdentityMaterial,
}

impl ReachabilityProductionEtcdBootstrapConfig {
    /// Validates and retains the selected three-role production bootstrap material.
    ///
    /// Endpoint/trust validation is identical to the existing two-role configuration law. Exact
    /// certificate or private-key byte reuse between any pair of the three roles is rejected.
    ///
    /// # Errors
    ///
    /// Returns the existing bounded configuration error before any provider I/O is attempted.
    pub fn new<E, S>(
        endpoints: E,
        trust_bundle_pem: impl Into<Vec<u8>>,
        live_owner_identity: ReachabilityEtcdClientIdentityMaterial,
        fence_allocator_identity: ReachabilityEtcdClientIdentityMaterial,
        durable_snapshot_identity: ReachabilityEtcdClientIdentityMaterial,
    ) -> Result<Self, ReachabilityLiveOwnerEtcdBootstrapConfigError>
    where
        E: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
        validate_endpoints(&endpoints)?;

        let trust_bundle_pem = trust_bundle_pem.into();
        if !contains_non_whitespace(&trust_bundle_pem) {
            return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::EmptyTrustBundle);
        }

        validate_production_identity_separation(
            &live_owner_identity,
            &fence_allocator_identity,
            &durable_snapshot_identity,
        )?;

        Ok(Self {
            endpoints,
            trust_bundle_pem,
            live_owner_identity,
            fence_allocator_identity,
            durable_snapshot_identity,
        })
    }
}

/// Narrow provider-bootstrap output for the three-role production authority path.
///
/// The carrier retains only the existing live/fence preparation plus one dedicated durable executor.
/// It exposes no broad etcd client, raw `KvClient`, endpoint, trust, certificate, or private-key
/// material.
pub struct ReachabilityProductionEtcdBootstrapPreparation {
    live_owner: ReachabilityLiveOwnerAcquisitionPreparation,
    durable_snapshot:
        crate::reachability_durable_snapshot_etcd::ReachabilityDurableSnapshotEtcdExecutor,
}

impl ReachabilityProductionEtcdBootstrapPreparation {
    /// Consumes the provider-bootstrap carrier into its two already-narrowed role outputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ReachabilityLiveOwnerAcquisitionPreparation,
        crate::reachability_durable_snapshot_etcd::ReachabilityDurableSnapshotEtcdExecutor,
    ) {
        (self.live_owner, self.durable_snapshot)
    }
}

/// Provider connection failure during the bounded three-role production bootstrap.
///
/// Underlying provider errors are intentionally not retained, preventing connection/configuration
/// detail from escaping through the narrow production bootstrap boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityProductionEtcdBootstrapError {
    /// The live-owner authority mTLS client could not be established.
    LiveOwnerConnect,
    /// The fence-sequence allocator mTLS client could not be established.
    FenceAllocatorConnect,
    /// The dedicated durable-snapshot mTLS client could not be established.
    DurableSnapshotConnect,
}

impl fmt::Display for ReachabilityProductionEtcdBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveOwnerConnect => {
                formatter.write_str("live-owner etcd authority bootstrap connection failed")
            }
            Self::FenceAllocatorConnect => {
                formatter.write_str("fence-allocator etcd authority bootstrap connection failed")
            }
            Self::DurableSnapshotConnect => {
                formatter.write_str("durable-snapshot etcd authority bootstrap connection failed")
            }
        }
    }
}

impl std::error::Error for ReachabilityProductionEtcdBootstrapError {}

/// Connects the selected three role-scoped mTLS clients and returns only narrowed provider outputs.
///
/// All three connections use the same exact validated endpoint vector and explicit private trust
/// bundle with distinct role identities. Each broad `Client` is dropped immediately after its
/// role-scoped `KvClient` is acquired. The durable `KvClient` is moved directly into the existing
/// `ReachabilityDurableSnapshotEtcdExecutor`.
///
/// Calling this async function performs provider network I/O. Merely constructing the config does
/// not. No partial preparation or degraded two-role result is returned if any role fails.
///
/// # Errors
///
/// Returns the role-specific bounded connection class for the first failed connection.
pub async fn bootstrap_reachability_production_preparation(
    config: ReachabilityProductionEtcdBootstrapConfig,
) -> Result<ReachabilityProductionEtcdBootstrapPreparation, ReachabilityProductionEtcdBootstrapError>
{
    let ReachabilityProductionEtcdBootstrapConfig {
        endpoints,
        trust_bundle_pem,
        live_owner_identity,
        fence_allocator_identity,
        durable_snapshot_identity,
    } = config;

    let live_owner_options = connect_options(&trust_bundle_pem, &live_owner_identity);
    let live_owner_client = Client::connect(endpoints.as_slice(), Some(live_owner_options))
        .await
        .map_err(|_| ReachabilityProductionEtcdBootstrapError::LiveOwnerConnect)?;
    let live_owner_kv = live_owner_client.kv_client();
    drop(live_owner_client);

    let fence_allocator_options = connect_options(&trust_bundle_pem, &fence_allocator_identity);
    let fence_allocator_client =
        Client::connect(endpoints.as_slice(), Some(fence_allocator_options))
            .await
            .map_err(|_| ReachabilityProductionEtcdBootstrapError::FenceAllocatorConnect)?;
    let fence_allocator_kv = fence_allocator_client.kv_client();
    drop(fence_allocator_client);

    let durable_snapshot_options = connect_options(&trust_bundle_pem, &durable_snapshot_identity);
    let durable_snapshot_client =
        Client::connect(endpoints.as_slice(), Some(durable_snapshot_options))
            .await
            .map_err(|_| ReachabilityProductionEtcdBootstrapError::DurableSnapshotConnect)?;
    let durable_snapshot_kv = durable_snapshot_client.kv_client();
    drop(durable_snapshot_client);

    let live_owner = ReachabilityLiveOwnerAcquisitionPreparation::from_role_scoped_clients(
        live_owner_kv,
        fence_allocator_kv,
    );
    let durable_snapshot =
        crate::reachability_durable_snapshot_etcd::ReachabilityDurableSnapshotEtcdExecutor::new(
            durable_snapshot_kv,
        );

    Ok(ReachabilityProductionEtcdBootstrapPreparation {
        live_owner,
        durable_snapshot,
    })
}

fn validate_production_identity_separation(
    live_owner_identity: &ReachabilityEtcdClientIdentityMaterial,
    fence_allocator_identity: &ReachabilityEtcdClientIdentityMaterial,
    durable_snapshot_identity: &ReachabilityEtcdClientIdentityMaterial,
) -> Result<(), ReachabilityLiveOwnerEtcdBootstrapConfigError> {
    validate_identity_pair(live_owner_identity, fence_allocator_identity)?;
    validate_identity_pair(live_owner_identity, durable_snapshot_identity)?;
    validate_identity_pair(fence_allocator_identity, durable_snapshot_identity)
}

fn validate_identity_pair(
    left: &ReachabilityEtcdClientIdentityMaterial,
    right: &ReachabilityEtcdClientIdentityMaterial,
) -> Result<(), ReachabilityLiveOwnerEtcdBootstrapConfigError> {
    if left.certificate_pem == right.certificate_pem {
        return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedClientCertificate);
    }
    if left.private_key_pem.as_slice() == right.private_key_pem.as_slice() {
        return Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey);
    }
    Ok(())
}

#[cfg(test)]
mod production_tests {
    use super::*;

    fn identity(
        certificate_marker: u8,
        private_key_marker: u8,
    ) -> ReachabilityEtcdClientIdentityMaterial {
        ReachabilityEtcdClientIdentityMaterial::new(
            vec![certificate_marker],
            vec![private_key_marker],
        )
        .expect("non-empty production identity material")
    }

    fn endpoints() -> [&'static str; AUTHORITY_MEMBER_COUNT] {
        [
            "https://etcd-a.authority.example:2379",
            "https://etcd-b.authority.example:2379",
            "https://etcd-c.authority.example:2379",
        ]
    }

    fn production_config(
        live_owner_identity: ReachabilityEtcdClientIdentityMaterial,
        fence_allocator_identity: ReachabilityEtcdClientIdentityMaterial,
        durable_snapshot_identity: ReachabilityEtcdClientIdentityMaterial,
    ) -> Result<
        ReachabilityProductionEtcdBootstrapConfig,
        ReachabilityLiveOwnerEtcdBootstrapConfigError,
    > {
        ReachabilityProductionEtcdBootstrapConfig::new(
            endpoints(),
            b"private-authority-ca".to_vec(),
            live_owner_identity,
            fence_allocator_identity,
            durable_snapshot_identity,
        )
    }

    #[test]
    fn production_config_accepts_three_distinct_role_identities() {
        assert!(production_config(identity(1, 2), identity(3, 4), identity(5, 6)).is_ok());
    }

    #[test]
    fn production_config_rejects_durable_certificate_reuse_with_live_owner() {
        assert!(matches!(
            production_config(identity(1, 2), identity(3, 4), identity(1, 6)),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedClientCertificate)
        ));
    }

    #[test]
    fn production_config_rejects_durable_certificate_reuse_with_fence_allocator() {
        assert!(matches!(
            production_config(identity(1, 2), identity(3, 4), identity(3, 6)),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedClientCertificate)
        ));
    }

    #[test]
    fn production_config_rejects_durable_private_key_reuse_with_live_owner() {
        assert!(matches!(
            production_config(identity(1, 2), identity(3, 4), identity(5, 2)),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey)
        ));
    }

    #[test]
    fn production_config_rejects_durable_private_key_reuse_with_fence_allocator() {
        assert!(matches!(
            production_config(identity(1, 2), identity(3, 4), identity(5, 4)),
            Err(ReachabilityLiveOwnerEtcdBootstrapConfigError::ReusedPrivateKey)
        ));
    }
}
