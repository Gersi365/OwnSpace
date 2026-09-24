//! Agent-owned production reachability systemd custody join.
//!
//! C03e-HW materializes only the C03e-HV-selected join between the existing bounded production
//! systemd credential loader and the existing C03e-HU production composition seam. The facade
//! accepts only one logical peer identity. It does not accept endpoint, trust, certificate,
//! private-key, credential-directory, raw provider-client, request-id, or IP-address input.
//!
//! Calling the async facade reads the existing fixed production service-credential set and, only
//! after successful custody validation, invokes the existing HU production bootstrap composition.
//! This module does not wire itself into Agent startup/readiness, spawn a task, retry, create a
//! fallback, activate candidate publication or traversal, install a listener, dial a peer, deploy,
//! or mutate production state.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;
use prw_reachability_custody::{
    ReachabilityCustodyError,
    load_reachability_production_etcd_bootstrap_config_from_systemd_credentials,
};

use crate::production_reachability_bootstrap::{
    ProductionReachabilityBootstrapComposition, ProductionReachabilityBootstrapError,
    bootstrap_production_reachability,
};

/// Bounded Agent-level failure while joining production systemd custody to HU composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionReachabilityCustodyBootstrapError {
    /// The fixed production systemd service-credential set failed custody validation.
    Custody(ReachabilityCustodyError),
    /// The validated opaque production config reached HU but composition failed closed.
    Composition(ProductionReachabilityBootstrapError),
}

impl fmt::Display for ProductionReachabilityCustodyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custody(_) => {
                formatter.write_str("production reachability custody bootstrap failed")
            }
            Self::Composition(_) => {
                formatter.write_str("production reachability composition failed")
            }
        }
    }
}

impl std::error::Error for ProductionReachabilityCustodyBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Custody(error) => Some(error),
            Self::Composition(error) => Some(error),
        }
    }
}

impl From<ReachabilityCustodyError> for ProductionReachabilityCustodyBootstrapError {
    fn from(error: ReachabilityCustodyError) -> Self {
        Self::Custody(error)
    }
}

impl From<ProductionReachabilityBootstrapError> for ProductionReachabilityCustodyBootstrapError {
    fn from(error: ProductionReachabilityBootstrapError) -> Self {
        Self::Composition(error)
    }
}

/// Loads the fixed production systemd credentials and composes production reachability for `peer`.
///
/// Custody is attempted exactly once through the existing reachability-custody production loader.
/// Only its validated opaque [`prw_control_plane::reachability_acquisition_evidence::bootstrap::ReachabilityProductionEtcdBootstrapConfig`]
/// is moved into the existing HU facade. Therefore custody failure occurs before provider network
/// I/O, while HU retains sole ownership of provider bootstrap, durable owner recovery, and
/// live-authority composition.
///
/// Calling this function performs the already-existing credential-file reads followed by HU's
/// already-existing provider and durable-recovery I/O. It creates no retry, fallback, runtime task,
/// startup/readiness callsite, listener, dialing path, deployment, or production mutation.
///
/// # Errors
///
/// Returns [`ProductionReachabilityCustodyBootstrapError::Custody`] if bounded systemd custody
/// fails before HU is invoked, or [`ProductionReachabilityCustodyBootstrapError::Composition`] if
/// HU fails closed. No partial or degraded production composition is returned.
pub async fn bootstrap_production_reachability_from_systemd_credentials(
    peer: &PeerConnectivityIdentity,
) -> Result<ProductionReachabilityBootstrapComposition, ProductionReachabilityCustodyBootstrapError>
{
    let config = load_reachability_production_etcd_bootstrap_config_from_systemd_credentials()
        .map_err(ProductionReachabilityCustodyBootstrapError::Custody)?;

    bootstrap_production_reachability(config, peer)
        .await
        .map_err(ProductionReachabilityCustodyBootstrapError::Composition)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, future::Future};

    use prw_connectivity::PeerConnectivityIdentity;
    use prw_reachability_custody::ReachabilityCustodyError;
    use prw_remote_bridge::reachability_owner::ReachabilityOwnerError;

    use super::{
        ProductionReachabilityCustodyBootstrapError,
        bootstrap_production_reachability_from_systemd_credentials,
    };
    use crate::production_reachability_bootstrap::{
        ProductionReachabilityBootstrapComposition, ProductionReachabilityBootstrapError,
    };

    fn assert_bootstrap_signature(peer: &PeerConnectivityIdentity) {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    ProductionReachabilityBootstrapComposition,
                    ProductionReachabilityCustodyBootstrapError,
                >,
            >,
        {
        }

        assert_future(bootstrap_production_reachability_from_systemd_credentials(
            peer,
        ));
    }

    #[test]
    fn production_custody_bootstrap_has_exact_peer_input_shape() {
        let _ = assert_bootstrap_signature as fn(&PeerConnectivityIdentity);
    }

    #[test]
    fn custody_failure_is_wrapped_without_detail_in_display() {
        let error = ProductionReachabilityCustodyBootstrapError::from(
            ReachabilityCustodyError::CredentialsDirectoryMissing,
        );
        assert!(matches!(
            error,
            ProductionReachabilityCustodyBootstrapError::Custody(
                ReachabilityCustodyError::CredentialsDirectoryMissing
            )
        ));
        assert_eq!(
            error.to_string(),
            "production reachability custody bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn composition_failure_is_wrapped_without_detail_in_display() {
        let error = ProductionReachabilityCustodyBootstrapError::from(
            ProductionReachabilityBootstrapError::OwnerRecovery(
                ReachabilityOwnerError::RecoveryRequired,
            ),
        );
        assert!(matches!(
            error,
            ProductionReachabilityCustodyBootstrapError::Composition(
                ProductionReachabilityBootstrapError::OwnerRecovery(
                    ReachabilityOwnerError::RecoveryRequired
                )
            )
        ));
        assert_eq!(
            error.to_string(),
            "production reachability composition failed"
        );
        assert!(error.source().is_some());
    }
}
