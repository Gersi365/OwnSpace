//! Network-domain configuration types.
//!
//! Phase 001 performs no network I/O and mutates no operating-system
//! networking state.

use prw_core::DeviceId;

/// Optional private-DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivateDnsConfig {
    /// Whether PRW-managed private DNS integration is enabled.
    pub enabled: bool,
    /// Whether enrolled device names may be resolved through PRW naming.
    pub device_naming: bool,
    /// User-specified private resolver addresses.
    pub resolvers: Vec<String>,
    /// Domain suffixes that should use private resolvers.
    pub split_domains: Vec<String>,
}

/// Abstract peer routing information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRoute {
    /// Destination device.
    pub device_id: DeviceId,
    /// Private IPv6 address assigned to the peer.
    pub ipv6_address: Option<String>,
    /// Optional compatibility IPv4 address.
    pub ipv4_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::PrivateDnsConfig;

    #[test]
    fn private_dns_is_disabled_by_default() {
        let config = PrivateDnsConfig::default();
        assert!(!config.enabled);
        assert!(!config.device_naming);
        assert!(config.resolvers.is_empty());
        assert!(config.split_domains.is_empty());
    }
}
