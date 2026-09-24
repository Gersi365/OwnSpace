//! Bounded read-only IPC projection of the private-DNS configuration.
//!
//! Phase 026 introduces validation bounds only. It performs no DNS parsing,
//! resolver lookup, system configuration, or byte serialization.

use prw_network::PrivateDnsConfig;

/// Maximum number of resolver strings exposed by one local IPC snapshot.
pub const LOCAL_PRIVATE_DNS_MAX_RESOLVERS: usize = 16;
/// Maximum number of split-domain strings exposed by one local IPC snapshot.
pub const LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS: usize = 64;
/// Maximum UTF-8 byte length of one resolver string in the local IPC snapshot.
pub const LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES: usize = 128;
/// Maximum UTF-8 byte length of one split-domain string in the local IPC snapshot.
pub const LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES: usize = 253;

/// Bounded read-only private-DNS snapshot admitted to the local IPC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrivateDnsSnapshot {
    enabled: bool,
    device_naming: bool,
    resolvers: Vec<String>,
    split_domains: Vec<String>,
}

impl LocalPrivateDnsSnapshot {
    /// Creates a bounded local IPC snapshot from the existing network-domain config.
    ///
    /// # Errors
    ///
    /// Returns [`LocalPrivateDnsSnapshotError`] when a list count or UTF-8 byte
    /// length exceeds the Phase 026 product bound, or when an admitted string is
    /// empty. The source config is not mutated.
    pub fn try_from_config(
        config: &PrivateDnsConfig,
    ) -> Result<Self, LocalPrivateDnsSnapshotError> {
        if config.resolvers.len() > LOCAL_PRIVATE_DNS_MAX_RESOLVERS {
            return Err(LocalPrivateDnsSnapshotError::TooManyResolvers);
        }
        if config.split_domains.len() > LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS {
            return Err(LocalPrivateDnsSnapshotError::TooManySplitDomains);
        }
        for resolver in &config.resolvers {
            if resolver.is_empty() {
                return Err(LocalPrivateDnsSnapshotError::EmptyResolver);
            }
            if resolver.len() > LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES {
                return Err(LocalPrivateDnsSnapshotError::ResolverTooLong);
            }
        }
        for domain in &config.split_domains {
            if domain.is_empty() {
                return Err(LocalPrivateDnsSnapshotError::EmptySplitDomain);
            }
            if domain.len() > LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES {
                return Err(LocalPrivateDnsSnapshotError::SplitDomainTooLong);
            }
        }

        Ok(Self {
            enabled: config.enabled,
            device_naming: config.device_naming,
            resolvers: config.resolvers.clone(),
            split_domains: config.split_domains.clone(),
        })
    }

    /// Returns whether PRW-managed private DNS is enabled in the source config.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns whether PRW device-name resolution is enabled in the source config.
    #[must_use]
    pub const fn device_naming(&self) -> bool {
        self.device_naming
    }

    /// Returns resolver strings in their original order.
    #[must_use]
    pub fn resolvers(&self) -> &[String] {
        &self.resolvers
    }

    /// Returns split-domain strings in their original order.
    #[must_use]
    pub fn split_domains(&self) -> &[String] {
        &self.split_domains
    }
}

/// Fail-closed Phase 026 bounded private-DNS snapshot validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsSnapshotError {
    /// Resolver count exceeds the local IPC snapshot bound.
    TooManyResolvers,
    /// Split-domain count exceeds the local IPC snapshot bound.
    TooManySplitDomains,
    /// A resolver string is empty.
    EmptyResolver,
    /// A resolver string exceeds the local IPC byte-length bound.
    ResolverTooLong,
    /// A split-domain string is empty.
    EmptySplitDomain,
    /// A split-domain string exceeds the local IPC byte-length bound.
    SplitDomainTooLong,
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES, LOCAL_PRIVATE_DNS_MAX_RESOLVERS,
        LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES, LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS,
        LocalPrivateDnsSnapshot, LocalPrivateDnsSnapshotError,
    };
    use prw_network::PrivateDnsConfig;

    #[test]
    fn default_config_projects_without_inventing_values() {
        let config = PrivateDnsConfig::default();
        let snapshot = LocalPrivateDnsSnapshot::try_from_config(&config).expect("default fits");

        assert!(!snapshot.enabled());
        assert!(!snapshot.device_naming());
        assert!(snapshot.resolvers().is_empty());
        assert!(snapshot.split_domains().is_empty());
    }

    #[test]
    fn flags_lists_and_order_are_preserved_exactly() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into(), "fd00::53".into()],
            split_domains: vec!["corp.example".into(), "lab.example".into()],
        };
        let snapshot = LocalPrivateDnsSnapshot::try_from_config(&config).expect("bounded config");

        assert!(snapshot.enabled());
        assert!(snapshot.device_naming());
        assert_eq!(snapshot.resolvers(), config.resolvers.as_slice());
        assert_eq!(snapshot.split_domains(), config.split_domains.as_slice());
    }

    #[test]
    fn exact_count_bounds_are_accepted() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: false,
            resolvers: (0..LOCAL_PRIVATE_DNS_MAX_RESOLVERS)
                .map(|index| format!("10.0.0.{index}"))
                .collect(),
            split_domains: (0..LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS)
                .map(|index| format!("d{index}.example"))
                .collect(),
        };

        LocalPrivateDnsSnapshot::try_from_config(&config).expect("exact list bounds fit");
    }

    #[test]
    fn above_count_bounds_are_rejected() {
        let too_many_resolvers = PrivateDnsConfig {
            resolvers: vec!["10.0.0.1".into(); LOCAL_PRIVATE_DNS_MAX_RESOLVERS + 1],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&too_many_resolvers),
            Err(LocalPrivateDnsSnapshotError::TooManyResolvers)
        );

        let too_many_domains = PrivateDnsConfig {
            split_domains: vec!["example".into(); LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS + 1],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&too_many_domains),
            Err(LocalPrivateDnsSnapshotError::TooManySplitDomains)
        );
    }

    #[test]
    fn exact_string_byte_bounds_are_accepted() {
        let config = PrivateDnsConfig {
            resolvers: vec!["r".repeat(LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES)],
            split_domains: vec!["d".repeat(LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES)],
            ..PrivateDnsConfig::default()
        };

        LocalPrivateDnsSnapshot::try_from_config(&config).expect("exact string bounds fit");
    }

    #[test]
    fn empty_and_oversize_strings_are_rejected() {
        let empty_resolver = PrivateDnsConfig {
            resolvers: vec![String::new()],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&empty_resolver),
            Err(LocalPrivateDnsSnapshotError::EmptyResolver)
        );

        let long_resolver = PrivateDnsConfig {
            resolvers: vec!["r".repeat(LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES + 1)],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&long_resolver),
            Err(LocalPrivateDnsSnapshotError::ResolverTooLong)
        );

        let empty_domain = PrivateDnsConfig {
            split_domains: vec![String::new()],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&empty_domain),
            Err(LocalPrivateDnsSnapshotError::EmptySplitDomain)
        );

        let long_domain = PrivateDnsConfig {
            split_domains: vec!["d".repeat(LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES + 1)],
            ..PrivateDnsConfig::default()
        };
        assert_eq!(
            LocalPrivateDnsSnapshot::try_from_config(&long_domain),
            Err(LocalPrivateDnsSnapshotError::SplitDomainTooLong)
        );
    }
}
