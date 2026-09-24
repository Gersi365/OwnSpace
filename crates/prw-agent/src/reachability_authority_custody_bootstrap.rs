//! Phase 152 C02f-CG Agent-owned reachability custody bootstrap facade.
//!
//! C02f-CE owns the fixed systemd credential custody boundary and C02f-CF owns the opaque-config
//! to provider-bootstrap to bridge-authority composition. This module joins only those two already
//! closed boundaries. It does not select or alter Agent startup/readiness sequencing.
//!
//! Calling the exported async function reads the fixed systemd credential set and, after successful
//! custody validation, performs provider network I/O through the C02f-CF facade. C02f-CG does not
//! invoke the function from `main.rs` or any running Agent surface.

use std::fmt;

use prw_control_plane::reachability_acquisition_evidence::bootstrap::ReachabilityLiveOwnerEtcdBootstrapError;
use prw_reachability_custody::{
    ReachabilityCustodyError,
    load_reachability_live_owner_etcd_bootstrap_config_from_systemd_credentials,
};
use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

use crate::reachability_authority_bootstrap::bootstrap_reachability_live_owner_authority;

/// Bounded Agent-level failure while joining reachability custody to provider bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityAuthorityCustodyBootstrapError {
    /// The fixed systemd reachability credential set failed the C02f-CE custody boundary.
    Custody(ReachabilityCustodyError),
    /// The validated config reached C02f-CF but provider bootstrap failed closed.
    ProviderBootstrap(ReachabilityLiveOwnerEtcdBootstrapError),
}

impl fmt::Display for ReachabilityAuthorityCustodyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custody(_) => {
                formatter.write_str("reachability authority custody bootstrap failed")
            }
            Self::ProviderBootstrap(_) => {
                formatter.write_str("reachability authority provider bootstrap failed")
            }
        }
    }
}

impl std::error::Error for ReachabilityAuthorityCustodyBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Custody(error) => Some(error),
            Self::ProviderBootstrap(error) => Some(error),
        }
    }
}

impl From<ReachabilityCustodyError> for ReachabilityAuthorityCustodyBootstrapError {
    fn from(error: ReachabilityCustodyError) -> Self {
        Self::Custody(error)
    }
}

impl From<ReachabilityLiveOwnerEtcdBootstrapError> for ReachabilityAuthorityCustodyBootstrapError {
    fn from(error: ReachabilityLiveOwnerEtcdBootstrapError) -> Self {
        Self::ProviderBootstrap(error)
    }
}

/// Loads the fixed systemd reachability credentials and composes the live-owner async authority.
///
/// The C02f-CE custody loader is called exactly once. Its opaque validated config is then moved
/// directly into the C02f-CF facade, which performs the bounded provider bootstrap and existing BZ
/// composition. No secret material or provider client is exposed by this API.
///
/// Calling this function performs credential-file reads followed by provider network I/O. C02f-CG
/// does not wire this function into the Agent executable or readiness path.
///
/// # Errors
///
/// Returns [`ReachabilityAuthorityCustodyBootstrapError::Custody`] if systemd custody fails before
/// provider I/O, or [`ReachabilityAuthorityCustodyBootstrapError::ProviderBootstrap`] if the
/// validated config cannot establish the two role-scoped provider clients.
pub async fn bootstrap_reachability_live_owner_authority_from_systemd_credentials()
-> Result<ReachabilityLiveOwnerComposedAsyncAuthority, ReachabilityAuthorityCustodyBootstrapError> {
    let config = load_reachability_live_owner_etcd_bootstrap_config_from_systemd_credentials()?;
    bootstrap_reachability_live_owner_authority(config)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, future::Future};

    use prw_control_plane::reachability_acquisition_evidence::bootstrap::ReachabilityLiveOwnerEtcdBootstrapError;
    use prw_reachability_custody::ReachabilityCustodyError;
    use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

    use super::{
        ReachabilityAuthorityCustodyBootstrapError,
        bootstrap_reachability_live_owner_authority_from_systemd_credentials,
    };

    fn assert_bootstrap_signature<F, Fut>(_bootstrap: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<
            Output = Result<
                ReachabilityLiveOwnerComposedAsyncAuthority,
                ReachabilityAuthorityCustodyBootstrapError,
            >,
        >,
    {
    }

    #[test]
    fn custody_bootstrap_has_exact_no_argument_to_composed_authority_shape() {
        assert_bootstrap_signature(
            bootstrap_reachability_live_owner_authority_from_systemd_credentials,
        );
    }

    #[test]
    fn custody_failure_is_wrapped_without_detail_in_display() {
        let error = ReachabilityAuthorityCustodyBootstrapError::from(
            ReachabilityCustodyError::CredentialsDirectoryMissing,
        );
        assert!(matches!(
            error,
            ReachabilityAuthorityCustodyBootstrapError::Custody(
                ReachabilityCustodyError::CredentialsDirectoryMissing
            )
        ));
        assert_eq!(
            error.to_string(),
            "reachability authority custody bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn provider_failure_is_wrapped_without_detail_in_display() {
        let error = ReachabilityAuthorityCustodyBootstrapError::from(
            ReachabilityLiveOwnerEtcdBootstrapError::LiveOwnerConnect,
        );
        assert!(matches!(
            error,
            ReachabilityAuthorityCustodyBootstrapError::ProviderBootstrap(
                ReachabilityLiveOwnerEtcdBootstrapError::LiveOwnerConnect
            )
        ));
        assert_eq!(
            error.to_string(),
            "reachability authority provider bootstrap failed"
        );
        assert!(error.source().is_some());
    }
}
