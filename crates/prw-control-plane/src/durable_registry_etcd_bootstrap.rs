//! C03e-IX production durable-registry etcd provider bootstrap.
//!
//! This module materializes only the C03e-IW-selected control-plane provider boundary. It accepts
//! runtime-supplied validated registry authority endpoints, explicit private trust, and one dedicated
//! registry mTLS identity; performs one provider connection attempt; drops the broad provider client;
//! and returns only the bounded [`DurableRegistryEtcdExecutor`].
//!
//! It does not read systemd credentials, embed endpoint/certificate/private-key values, configure or
//! mutate provider auth/RBAC, create registry records, decode PRWM/PRWD, retry/fallback, scan keys,
//! use Watch/Lease/TTL, compose Agent runtime state, publish readiness, deploy, or migrate data.

use std::{collections::HashSet, fmt, net::IpAddr};

use etcd_client::{Certificate, Client, ConnectOptions, Identity, TlsOptions};
use zeroize::Zeroizing;

use crate::durable_registry_etcd::DurableRegistryEtcdExecutor;

const AUTHORITY_MEMBER_COUNT: usize = 3;

/// Runtime-supplied mTLS identity material for the dedicated durable-registry provider role.
///
/// The type deliberately does not implement `Clone` or `Debug`. Private-key bytes remain in a
/// zeroizing owner and are exposed through no accessor.
pub struct DurableRegistryEtcdClientIdentityMaterial {
    certificate_pem: Vec<u8>,
    private_key_pem: Zeroizing<Vec<u8>>,
}

impl DurableRegistryEtcdClientIdentityMaterial {
    /// Creates one dedicated registry mTLS identity from runtime-supplied material.
    ///
    /// This constructor performs bounded structural non-empty checks only. Provider TLS parsing
    /// remains at the provider connection boundary.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when certificate or private-key material is empty or
    /// ASCII-whitespace-only.
    pub fn new(
        certificate_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, DurableRegistryEtcdClientIdentityMaterialError> {
        Self::new_with_zeroizing_private_key(
            certificate_pem,
            Zeroizing::new(private_key_pem.into()),
        )
    }

    /// Creates one dedicated registry identity while preserving an existing zeroizing key owner.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when certificate or private-key material is empty or
    /// ASCII-whitespace-only.
    pub fn new_with_zeroizing_private_key(
        certificate_pem: impl Into<Vec<u8>>,
        private_key_pem: Zeroizing<Vec<u8>>,
    ) -> Result<Self, DurableRegistryEtcdClientIdentityMaterialError> {
        let certificate_pem = certificate_pem.into();
        if !contains_non_whitespace(&certificate_pem) {
            return Err(DurableRegistryEtcdClientIdentityMaterialError::EmptyCertificate);
        }
        if !contains_non_whitespace(private_key_pem.as_slice()) {
            return Err(DurableRegistryEtcdClientIdentityMaterialError::EmptyPrivateKey);
        }
        Ok(Self {
            certificate_pem,
            private_key_pem,
        })
    }
}

/// Structural validation failure for the dedicated durable-registry mTLS identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRegistryEtcdClientIdentityMaterialError {
    /// Client certificate material is absent.
    EmptyCertificate,
    /// Client private-key material is absent.
    EmptyPrivateKey,
}

impl fmt::Display for DurableRegistryEtcdClientIdentityMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCertificate => {
                formatter.write_str("durable registry etcd client certificate material is empty")
            }
            Self::EmptyPrivateKey => {
                formatter.write_str("durable registry etcd client private-key material is empty")
            }
        }
    }
}

impl std::error::Error for DurableRegistryEtcdClientIdentityMaterialError {}

/// Validated immutable input for one production durable-registry etcd provider connection.
///
/// The config owns one exact three-member HTTPS/FQDN endpoint set, one explicit private authority
/// trust bundle, and one dedicated registry mTLS identity. Construction performs no network I/O.
pub struct DurableRegistryProductionEtcdBootstrapConfig {
    endpoints: Vec<String>,
    trust_bundle_pem: Vec<u8>,
    registry_identity: DurableRegistryEtcdClientIdentityMaterial,
}

impl DurableRegistryProductionEtcdBootstrapConfig {
    /// Validates and retains one registry-specific production provider bootstrap input.
    ///
    /// Exactly three unique stable-FQDN HTTPS endpoints are required. Paths, queries, fragments,
    /// user-info, IP literals, wildcard/localhost names, malformed ports, and duplicate member
    /// hostnames are rejected. The explicit private trust bundle must be non-empty.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration error before provider I/O.
    pub fn new<E, S>(
        endpoints: E,
        trust_bundle_pem: impl Into<Vec<u8>>,
        registry_identity: DurableRegistryEtcdClientIdentityMaterial,
    ) -> Result<Self, DurableRegistryProductionEtcdBootstrapConfigError>
    where
        E: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
        validate_endpoints(&endpoints)?;

        let trust_bundle_pem = trust_bundle_pem.into();
        if !contains_non_whitespace(&trust_bundle_pem) {
            return Err(DurableRegistryProductionEtcdBootstrapConfigError::EmptyTrustBundle);
        }

        Ok(Self {
            endpoints,
            trust_bundle_pem,
            registry_identity,
        })
    }
}

/// Fail-closed structural validation error for registry provider bootstrap configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRegistryProductionEtcdBootstrapConfigError {
    /// Production registry authority requires exactly three client endpoints.
    EndpointCount,
    /// A configured endpoint is not HTTPS.
    InsecureEndpoint,
    /// Endpoint authority, port, path, query, fragment, or user-info syntax is invalid.
    MalformedEndpoint,
    /// Endpoint host is not a stable FQDN.
    NonFqdnEndpoint,
    /// More than one configured endpoint names the same textual member FQDN.
    DuplicateMemberHost,
    /// The explicit private authority trust bundle is absent.
    EmptyTrustBundle,
}

impl fmt::Display for DurableRegistryProductionEtcdBootstrapConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EndpointCount => {
                "durable registry etcd bootstrap requires exactly three endpoints"
            }
            Self::InsecureEndpoint => "durable registry etcd bootstrap endpoint must use https",
            Self::MalformedEndpoint => "durable registry etcd bootstrap endpoint is malformed",
            Self::NonFqdnEndpoint => {
                "durable registry etcd bootstrap endpoint host must be a stable fqdn"
            }
            Self::DuplicateMemberHost => {
                "durable registry etcd bootstrap endpoint member host must be unique"
            }
            Self::EmptyTrustBundle => "durable registry etcd bootstrap trust bundle is empty",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DurableRegistryProductionEtcdBootstrapConfigError {}

/// Bounded provider connection failure during durable-registry production bootstrap.
///
/// The underlying provider error is intentionally not retained, preventing endpoint/security
/// connection detail from escaping through this public boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRegistryProductionEtcdBootstrapError {
    /// The dedicated registry-authority mTLS provider connection could not be established.
    RegistryConnect,
}

impl fmt::Display for DurableRegistryProductionEtcdBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryConnect => {
                formatter.write_str("durable registry etcd provider bootstrap connection failed")
            }
        }
    }
}

impl std::error::Error for DurableRegistryProductionEtcdBootstrapError {}

/// Connects one dedicated production registry mTLS client and returns only the narrowed executor.
///
/// The validated endpoint set, explicit trust bundle and dedicated identity are consumed by value.
/// Exactly one provider `Client::connect` call is attempted. On success, its role-scoped `KvClient`
/// is extracted, the broad `Client` is dropped, and the `KvClient` is moved immediately into
/// [`DurableRegistryEtcdExecutor::new`]. No broad provider handle escapes.
///
/// Calling this function performs provider network I/O. Merely constructing identity/config values
/// performs none. No retry, fallback, record creation, semantic registry operation, or runtime
/// activation occurs here.
///
/// # Errors
///
/// Returns [`DurableRegistryProductionEtcdBootstrapError::RegistryConnect`] if the authenticated
/// provider connection cannot be established. No partial executor is returned.
pub async fn bootstrap_durable_registry_production_executor(
    config: DurableRegistryProductionEtcdBootstrapConfig,
) -> Result<DurableRegistryEtcdExecutor, DurableRegistryProductionEtcdBootstrapError> {
    let DurableRegistryProductionEtcdBootstrapConfig {
        endpoints,
        trust_bundle_pem,
        registry_identity,
    } = config;

    let options = connect_options(&trust_bundle_pem, &registry_identity);
    let client = Client::connect(endpoints.as_slice(), Some(options))
        .await
        .map_err(|_| DurableRegistryProductionEtcdBootstrapError::RegistryConnect)?;
    let kv = client.kv_client();
    drop(client);

    Ok(DurableRegistryEtcdExecutor::new(kv))
}

fn connect_options(
    trust_bundle_pem: &[u8],
    identity: &DurableRegistryEtcdClientIdentityMaterial,
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
) -> Result<(), DurableRegistryProductionEtcdBootstrapConfigError> {
    if endpoints.len() != AUTHORITY_MEMBER_COUNT {
        return Err(DurableRegistryProductionEtcdBootstrapConfigError::EndpointCount);
    }

    let mut hosts = HashSet::with_capacity(AUTHORITY_MEMBER_COUNT);
    for endpoint in endpoints {
        let host = validate_endpoint(endpoint)?;
        if !hosts.insert(host) {
            return Err(DurableRegistryProductionEtcdBootstrapConfigError::DuplicateMemberHost);
        }
    }
    Ok(())
}

fn validate_endpoint(
    endpoint: &str,
) -> Result<String, DurableRegistryProductionEtcdBootstrapConfigError> {
    let authority = endpoint
        .strip_prefix("https://")
        .ok_or(DurableRegistryProductionEtcdBootstrapConfigError::InsecureEndpoint)?;

    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint);
    }

    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint);
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint)?;
        if port == 0 {
            return Err(DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint);
        }
        host
    } else {
        authority
    };

    validate_fqdn(host)?;
    Ok(host.to_ascii_lowercase())
}

fn validate_fqdn(host: &str) -> Result<(), DurableRegistryProductionEtcdBootstrapConfigError> {
    if !host.is_ascii()
        || host.len() > 253
        || !host.contains('.')
        || host.eq_ignore_ascii_case("localhost")
        || host.contains('*')
        || host.parse::<IpAddr>().is_ok()
    {
        return Err(DurableRegistryProductionEtcdBootstrapConfigError::NonFqdnEndpoint);
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
            return Err(DurableRegistryProductionEtcdBootstrapConfigError::NonFqdnEndpoint);
        }
    }
    Ok(())
}

fn contains_non_whitespace(value: &[u8]) -> bool {
    value.iter().any(|byte| !byte.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    fn identity() -> DurableRegistryEtcdClientIdentityMaterial {
        DurableRegistryEtcdClientIdentityMaterial::new(
            b"registry-cert".to_vec(),
            b"registry-key".to_vec(),
        )
        .expect("non-empty identity")
    }

    fn endpoints() -> [&'static str; AUTHORITY_MEMBER_COUNT] {
        [
            "https://registry-etcd-a.authority.example:2379",
            "https://registry-etcd-b.authority.example:2379",
            "https://registry-etcd-c.authority.example:2379",
        ]
    }

    fn config<E, S>(
        endpoints: E,
    ) -> Result<
        DurableRegistryProductionEtcdBootstrapConfig,
        DurableRegistryProductionEtcdBootstrapConfigError,
    >
    where
        E: IntoIterator<Item = S>,
        S: Into<String>,
    {
        DurableRegistryProductionEtcdBootstrapConfig::new(
            endpoints,
            b"registry-private-authority-ca".to_vec(),
            identity(),
        )
    }

    fn assert_bootstrap_signature(config: DurableRegistryProductionEtcdBootstrapConfig) {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    DurableRegistryEtcdExecutor,
                    DurableRegistryProductionEtcdBootstrapError,
                >,
            >,
        {
        }
        assert_future(bootstrap_durable_registry_production_executor(config));
    }

    #[test]
    fn identity_rejects_empty_or_whitespace_material() {
        assert!(matches!(
            DurableRegistryEtcdClientIdentityMaterial::new(Vec::<u8>::new(), vec![1]),
            Err(DurableRegistryEtcdClientIdentityMaterialError::EmptyCertificate)
        ));
        assert!(matches!(
            DurableRegistryEtcdClientIdentityMaterial::new(vec![1], b" \n\t".to_vec()),
            Err(DurableRegistryEtcdClientIdentityMaterialError::EmptyPrivateKey)
        ));
    }

    #[test]
    fn config_accepts_exact_three_member_https_fqdn_topology() {
        assert!(config(endpoints()).is_ok());
    }

    #[test]
    fn config_rejects_wrong_member_count_and_empty_trust() {
        assert!(matches!(
            config([
                "https://registry-etcd-a.authority.example:2379",
                "https://registry-etcd-b.authority.example:2379",
            ]),
            Err(DurableRegistryProductionEtcdBootstrapConfigError::EndpointCount)
        ));
        assert!(matches!(
            DurableRegistryProductionEtcdBootstrapConfig::new(
                endpoints(),
                b" \n".to_vec(),
                identity(),
            ),
            Err(DurableRegistryProductionEtcdBootstrapConfigError::EmptyTrustBundle)
        ));
    }

    #[test]
    fn config_rejects_plaintext_ip_localhost_wildcard_and_non_endpoint_surfaces() {
        let invalid = [
            (
                [
                    "http://registry-etcd-a.authority.example:2379",
                    "https://registry-etcd-b.authority.example:2379",
                    "https://registry-etcd-c.authority.example:2379",
                ],
                DurableRegistryProductionEtcdBootstrapConfigError::InsecureEndpoint,
            ),
            (
                [
                    "https://127.0.0.1:2379",
                    "https://registry-etcd-b.authority.example:2379",
                    "https://registry-etcd-c.authority.example:2379",
                ],
                DurableRegistryProductionEtcdBootstrapConfigError::NonFqdnEndpoint,
            ),
            (
                [
                    "https://localhost:2379",
                    "https://registry-etcd-b.authority.example:2379",
                    "https://registry-etcd-c.authority.example:2379",
                ],
                DurableRegistryProductionEtcdBootstrapConfigError::NonFqdnEndpoint,
            ),
            (
                [
                    "https://*.authority.example:2379",
                    "https://registry-etcd-b.authority.example:2379",
                    "https://registry-etcd-c.authority.example:2379",
                ],
                DurableRegistryProductionEtcdBootstrapConfigError::NonFqdnEndpoint,
            ),
            (
                [
                    "https://registry-etcd-a.authority.example:2379/path",
                    "https://registry-etcd-b.authority.example:2379",
                    "https://registry-etcd-c.authority.example:2379",
                ],
                DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint,
            ),
        ];

        for (endpoints, expected) in invalid {
            assert!(matches!(config(endpoints), Err(error) if error == expected));
        }
    }

    #[test]
    fn config_rejects_invalid_ports_and_duplicate_member_fqdn() {
        assert!(matches!(
            config([
                "https://registry-etcd-a.authority.example:0",
                "https://registry-etcd-b.authority.example:2379",
                "https://registry-etcd-c.authority.example:2379",
            ]),
            Err(DurableRegistryProductionEtcdBootstrapConfigError::MalformedEndpoint)
        ));
        assert!(matches!(
            config([
                "https://registry-etcd-a.authority.example:2379",
                "https://registry-etcd-a.authority.example:2380",
                "https://registry-etcd-c.authority.example:2379",
            ]),
            Err(DurableRegistryProductionEtcdBootstrapConfigError::DuplicateMemberHost)
        ));
    }

    #[test]
    fn bootstrap_boundary_returns_only_narrow_executor_shape() {
        let _ = assert_bootstrap_signature as fn(DurableRegistryProductionEtcdBootstrapConfig);
    }
}
