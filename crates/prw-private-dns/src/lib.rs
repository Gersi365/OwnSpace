//! Typed optional private-DNS configuration for Ownspace.
//!
//! Phase 137 validates bounded configuration only. It performs no DNS queries, opens no
//! sockets, mutates no operating-system resolver state and is not a dependency of basic
//! PRW connectivity.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

/// Maximum explicit custom resolver endpoints.
pub const MAX_PRIVATE_DNS_RESOLVERS: usize = 4;
/// Maximum split-domain suffixes.
pub const MAX_SPLIT_DNS_DOMAINS: usize = 16;
/// Maximum canonical DNS domain length without a trailing dot.
pub const MAX_DNS_DOMAIN_BYTES: usize = 253;
/// Maximum one DNS label length.
pub const MAX_DNS_LABEL_BYTES: usize = 63;

/// Optional private-DNS activation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivateDnsMode {
    /// Configuration is retained but must not be applied.
    #[default]
    Disabled,
    /// An external audited integration layer may apply the validated configuration.
    Enabled,
}

/// Canonical lower-case single DNS label for future PRW device naming.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceDnsLabel(String);

impl DeviceDnsLabel {
    /// Creates a canonical lower-case DNS label.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateDnsError::InvalidDeviceLabel`] when the value is empty, longer than
    /// 63 bytes, non-ASCII, contains characters other than lower-case letters/digits/hyphen,
    /// or begins/ends with a hyphen.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivateDnsError> {
        let value = value.into();
        if !valid_dns_label(&value) {
            return Err(PrivateDnsError::InvalidDeviceLabel);
        }
        Ok(Self(value))
    }

    /// Returns the canonical label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical lower-case DNS domain suffix without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsDomainSuffix(String);

impl DnsDomainSuffix {
    /// Creates a validated canonical DNS suffix.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateDnsError::InvalidDomainSuffix`] when total/label bounds or canonical
    /// lower-case DNS label syntax are violated.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivateDnsError> {
        let value = value.into();
        if !valid_domain_suffix(&value) {
            return Err(PrivateDnsError::InvalidDomainSuffix);
        }
        Ok(Self(value))
    }

    /// Returns the canonical suffix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit IP resolver endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolverEndpoint {
    address: IpAddr,
    port: u16,
}

impl ResolverEndpoint {
    /// Creates a resolver endpoint from an explicit IP address and non-zero port.
    ///
    /// # Errors
    ///
    /// Rejects zero port, unspecified/multicast addresses and IPv4 limited broadcast.
    pub fn new(address: IpAddr, port: u16) -> Result<Self, PrivateDnsError> {
        if port == 0 {
            return Err(PrivateDnsError::InvalidResolverPort);
        }
        let invalid = match address {
            IpAddr::V4(ipv4) => {
                ipv4.is_unspecified() || ipv4.is_multicast() || ipv4 == Ipv4Addr::BROADCAST
            }
            IpAddr::V6(ipv6) => ipv6.is_unspecified() || ipv6.is_multicast(),
        };
        if invalid {
            return Err(PrivateDnsError::InvalidResolverAddress);
        }
        Ok(Self { address, port })
    }

    /// Returns the explicit resolver IP address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns the explicit non-zero resolver port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

/// Fully validated optional private-DNS settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateDnsConfig {
    mode: PrivateDnsMode,
    device_naming: bool,
    device_domain: Option<DnsDomainSuffix>,
    resolvers: Vec<ResolverEndpoint>,
    split_domains: Vec<DnsDomainSuffix>,
}

impl Default for PrivateDnsConfig {
    fn default() -> Self {
        Self {
            mode: PrivateDnsMode::Disabled,
            device_naming: false,
            device_domain: None,
            resolvers: Vec::new(),
            split_domains: Vec::new(),
        }
    }
}

impl PrivateDnsConfig {
    /// Creates a validated configuration without applying it to the operating system.
    ///
    /// Disabled mode may retain valid settings for reversible toggling.
    ///
    /// # Errors
    ///
    /// Rejects configured collection bounds/duplicates, device naming without a device-domain
    /// suffix, or split-domain routing without an explicit resolver endpoint.
    pub fn new(
        mode: PrivateDnsMode,
        device_naming: bool,
        device_domain: Option<DnsDomainSuffix>,
        resolvers: Vec<ResolverEndpoint>,
        split_domains: Vec<DnsDomainSuffix>,
    ) -> Result<Self, PrivateDnsError> {
        if resolvers.len() > MAX_PRIVATE_DNS_RESOLVERS {
            return Err(PrivateDnsError::ResolverCapacity);
        }
        if split_domains.len() > MAX_SPLIT_DNS_DOMAINS {
            return Err(PrivateDnsError::SplitDomainCapacity);
        }
        if device_naming && device_domain.is_none() {
            return Err(PrivateDnsError::DeviceDomainRequired);
        }
        if !split_domains.is_empty() && resolvers.is_empty() {
            return Err(PrivateDnsError::ResolverRequiredForSplitDomain);
        }
        if has_duplicate(&resolvers) {
            return Err(PrivateDnsError::DuplicateResolver);
        }
        if has_duplicate(&split_domains) {
            return Err(PrivateDnsError::DuplicateSplitDomain);
        }

        Ok(Self {
            mode,
            device_naming,
            device_domain,
            resolvers,
            split_domains,
        })
    }

    /// Returns the configured activation mode.
    #[must_use]
    pub const fn mode(&self) -> PrivateDnsMode {
        self.mode
    }

    /// Returns whether the validated config is marked enabled.
    ///
    /// This does not imply that any operating-system resolver state was applied.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.mode == PrivateDnsMode::Enabled
    }

    /// Returns whether PRW device naming is requested.
    #[must_use]
    pub const fn device_naming(&self) -> bool {
        self.device_naming
    }

    /// Returns the configured device-domain suffix, if any.
    #[must_use]
    pub const fn device_domain(&self) -> Option<&DnsDomainSuffix> {
        self.device_domain.as_ref()
    }

    /// Returns retained explicit resolver endpoints.
    #[must_use]
    pub fn resolvers(&self) -> &[ResolverEndpoint] {
        &self.resolvers
    }

    /// Returns retained split-domain suffixes.
    #[must_use]
    pub fn split_domains(&self) -> &[DnsDomainSuffix] {
        &self.split_domains
    }
}

fn valid_dns_label(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_DNS_LABEL_BYTES || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    if !is_dns_alphanumeric(*first) || !is_dns_alphanumeric(*last) {
        return false;
    }
    bytes
        .iter()
        .all(|byte| is_dns_alphanumeric(*byte) || *byte == b'-')
}

fn valid_domain_suffix(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_DNS_DOMAIN_BYTES
        || !value.is_ascii()
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return false;
    }
    value.split('.').all(valid_dns_label)
}

const fn is_dns_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn has_duplicate<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

/// Stable Phase 137 private-DNS validation failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateDnsError {
    /// Device label syntax or bounds are invalid.
    InvalidDeviceLabel,
    /// Domain suffix syntax or bounds are invalid.
    InvalidDomainSuffix,
    /// Resolver port was zero.
    InvalidResolverPort,
    /// Resolver IP address is not allowed.
    InvalidResolverAddress,
    /// Resolver endpoint count exceeded the bound.
    ResolverCapacity,
    /// Split-domain count exceeded the bound.
    SplitDomainCapacity,
    /// Resolver endpoint was duplicated.
    DuplicateResolver,
    /// Split-domain suffix was duplicated.
    DuplicateSplitDomain,
    /// Device naming was enabled without a device-domain suffix.
    DeviceDomainRequired,
    /// Split-domain routing was configured without a resolver endpoint.
    ResolverRequiredForSplitDomain,
}

impl fmt::Display for PrivateDnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDeviceLabel => "device DNS label is invalid",
            Self::InvalidDomainSuffix => "DNS domain suffix is invalid",
            Self::InvalidResolverPort => "DNS resolver port must be non-zero",
            Self::InvalidResolverAddress => "DNS resolver address is not allowed",
            Self::ResolverCapacity => "DNS resolver endpoint capacity exceeded",
            Self::SplitDomainCapacity => "split-DNS domain capacity exceeded",
            Self::DuplicateResolver => "DNS resolver endpoint is duplicated",
            Self::DuplicateSplitDomain => "split-DNS domain is duplicated",
            Self::DeviceDomainRequired => "device naming requires a device-domain suffix",
            Self::ResolverRequiredForSplitDomain => {
                "split-DNS domains require at least one resolver endpoint"
            }
        })
    }
}

impl std::error::Error for PrivateDnsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn resolver(port: u16) -> ResolverEndpoint {
        ResolverEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("resolver")
    }

    fn suffix(value: &str) -> DnsDomainSuffix {
        DnsDomainSuffix::new(value).expect("suffix")
    }

    #[test]
    fn default_configuration_is_disabled_and_empty() {
        let config = PrivateDnsConfig::default();
        assert_eq!(config.mode(), PrivateDnsMode::Disabled);
        assert!(!config.is_active());
        assert!(!config.device_naming());
        assert!(config.device_domain().is_none());
        assert!(config.resolvers().is_empty());
        assert!(config.split_domains().is_empty());
    }

    #[test]
    fn device_labels_are_strictly_canonical_and_bounded() {
        assert!(DeviceDnsLabel::new("ownspace-1").is_ok());
        assert_eq!(
            DeviceDnsLabel::new(""),
            Err(PrivateDnsError::InvalidDeviceLabel)
        );
        assert_eq!(
            DeviceDnsLabel::new("OwnerPC"),
            Err(PrivateDnsError::InvalidDeviceLabel)
        );
        assert_eq!(
            DeviceDnsLabel::new("bad_name"),
            Err(PrivateDnsError::InvalidDeviceLabel)
        );
        assert_eq!(
            DeviceDnsLabel::new("-bad"),
            Err(PrivateDnsError::InvalidDeviceLabel)
        );
        assert_eq!(
            DeviceDnsLabel::new("x".repeat(MAX_DNS_LABEL_BYTES + 1)),
            Err(PrivateDnsError::InvalidDeviceLabel)
        );
    }

    #[test]
    fn domain_suffixes_are_strictly_canonical_and_bounded() {
        assert_eq!(suffix("prw.internal").as_str(), "prw.internal");
        for invalid in [
            "",
            ".prw",
            "prw.",
            "PRW.internal",
            "bad_name.internal",
            "a..b",
        ] {
            assert_eq!(
                DnsDomainSuffix::new(invalid),
                Err(PrivateDnsError::InvalidDomainSuffix)
            );
        }
        let oversized_label = format!("{}.internal", "x".repeat(MAX_DNS_LABEL_BYTES + 1));
        assert_eq!(
            DnsDomainSuffix::new(oversized_label),
            Err(PrivateDnsError::InvalidDomainSuffix)
        );
        assert_eq!(
            DnsDomainSuffix::new("x".repeat(MAX_DNS_DOMAIN_BYTES + 1)),
            Err(PrivateDnsError::InvalidDomainSuffix)
        );
    }

    #[test]
    fn resolver_endpoints_are_explicit_and_bounded() {
        assert_eq!(resolver(53).address(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(resolver(53).port(), 53);
        assert_eq!(
            ResolverEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Err(PrivateDnsError::InvalidResolverPort)
        );
        assert_eq!(
            ResolverEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
            Err(PrivateDnsError::InvalidResolverAddress)
        );
        assert_eq!(
            ResolverEndpoint::new(IpAddr::V4(Ipv4Addr::BROADCAST), 53),
            Err(PrivateDnsError::InvalidResolverAddress)
        );
        assert_eq!(
            ResolverEndpoint::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 53),
            Err(PrivateDnsError::InvalidResolverAddress)
        );
        assert_eq!(
            ResolverEndpoint::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53),
            Err(PrivateDnsError::InvalidResolverAddress)
        );
    }

    #[test]
    fn configuration_collection_bounds_fail_closed() {
        let resolvers = (0..=MAX_PRIVATE_DNS_RESOLVERS)
            .map(|offset| resolver(53 + u16::try_from(offset).expect("small offset")))
            .collect();
        assert_eq!(
            PrivateDnsConfig::new(PrivateDnsMode::Disabled, false, None, resolvers, Vec::new(),),
            Err(PrivateDnsError::ResolverCapacity)
        );

        let split_domains = (0..=MAX_SPLIT_DNS_DOMAINS)
            .map(|offset| suffix(&format!("d{offset}.internal")))
            .collect();
        assert_eq!(
            PrivateDnsConfig::new(
                PrivateDnsMode::Disabled,
                false,
                None,
                vec![resolver(53)],
                split_domains,
            ),
            Err(PrivateDnsError::SplitDomainCapacity)
        );
    }

    #[test]
    fn duplicate_resolvers_and_split_domains_are_rejected() {
        assert_eq!(
            PrivateDnsConfig::new(
                PrivateDnsMode::Disabled,
                false,
                None,
                vec![resolver(53), resolver(53)],
                Vec::new(),
            ),
            Err(PrivateDnsError::DuplicateResolver)
        );
        assert_eq!(
            PrivateDnsConfig::new(
                PrivateDnsMode::Disabled,
                false,
                None,
                vec![resolver(53)],
                vec![suffix("corp.internal"), suffix("corp.internal")],
            ),
            Err(PrivateDnsError::DuplicateSplitDomain)
        );
    }

    #[test]
    fn device_naming_requires_domain_and_split_dns_requires_resolver() {
        assert_eq!(
            PrivateDnsConfig::new(PrivateDnsMode::Enabled, true, None, Vec::new(), Vec::new(),),
            Err(PrivateDnsError::DeviceDomainRequired)
        );
        assert_eq!(
            PrivateDnsConfig::new(
                PrivateDnsMode::Enabled,
                false,
                None,
                Vec::new(),
                vec![suffix("corp.internal")],
            ),
            Err(PrivateDnsError::ResolverRequiredForSplitDomain)
        );
    }

    #[test]
    fn disabled_mode_retains_valid_settings_without_becoming_active() {
        let config = PrivateDnsConfig::new(
            PrivateDnsMode::Disabled,
            true,
            Some(suffix("devices.prw")),
            vec![resolver(53)],
            vec![suffix("corp.internal")],
        )
        .expect("config");
        assert!(!config.is_active());
        assert!(config.device_naming());
        assert_eq!(
            config.device_domain().expect("device domain").as_str(),
            "devices.prw"
        );
        assert_eq!(config.resolvers().len(), 1);
        assert_eq!(config.split_domains().len(), 1);
    }

    #[test]
    fn enabled_mode_is_only_configuration_state() {
        let config = PrivateDnsConfig::new(
            PrivateDnsMode::Enabled,
            false,
            None,
            vec![resolver(53)],
            Vec::new(),
        )
        .expect("config");
        assert!(config.is_active());
        assert_eq!(config.mode(), PrivateDnsMode::Enabled);
    }
}
