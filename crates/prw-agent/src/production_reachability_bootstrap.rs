//! Agent-owned production reachability bootstrap composition seam.
//!
//! C03e-HU materializes only the C03e-HT-selected config-to-composition boundary. It accepts one
//! already-validated opaque production etcd bootstrap config plus one logical peer identity, invokes
//! the existing control-plane production provider bootstrap, recovers the existing durable owner
//! into Agent custody, and only then composes the existing bridge-owned live authority.
//!
//! This module does not read systemd credentials, accept endpoint/certificate/private-key bytes,
//! expose raw provider clients, create a retry/fallback path, spawn a task/runtime, publish
//! readiness, activate candidate publication or traversal, install a listener, dial a peer, mutate
//! startup/shutdown, deploy, or change production state.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
    ReachabilityProductionEtcdBootstrapConfig, ReachabilityProductionEtcdBootstrapError,
    bootstrap_reachability_production_preparation,
};
use prw_remote_bridge::{
    reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority,
    reachability_owner::ReachabilityOwnerError,
};

use crate::{
    production_reachability_owner_composition::{
        ProductionReachabilityEtcdOwnerCustody, recover_production_reachability_owner_custody,
    },
    reachability_authority_composition::compose_reachability_live_owner_authority,
};

/// Agent-owned production composition produced only after provider bootstrap and durable recovery.
pub struct ProductionReachabilityBootstrapComposition {
    live_owner_authority: ReachabilityLiveOwnerComposedAsyncAuthority,
    owner_custody: ProductionReachabilityEtcdOwnerCustody,
}

impl ProductionReachabilityBootstrapComposition {
    /// Consumes the composition carrier into its two semantic Agent-owned values.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ReachabilityLiveOwnerComposedAsyncAuthority,
        ProductionReachabilityEtcdOwnerCustody,
    ) {
        (self.live_owner_authority, self.owner_custody)
    }
}

/// Bounded Agent-level failure while composing production reachability from one opaque config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionReachabilityBootstrapError {
    /// The existing control-plane three-role provider bootstrap failed closed.
    ProviderBootstrap(ReachabilityProductionEtcdBootstrapError),
    /// Authoritative durable recovery failed before live-authority construction.
    OwnerRecovery(ReachabilityOwnerError),
}

impl fmt::Display for ProductionReachabilityBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderBootstrap(_) => {
                formatter.write_str("production reachability provider bootstrap failed")
            }
            Self::OwnerRecovery(_) => {
                formatter.write_str("production reachability owner recovery failed")
            }
        }
    }
}

impl std::error::Error for ProductionReachabilityBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProviderBootstrap(error) => Some(error),
            Self::OwnerRecovery(error) => Some(error),
        }
    }
}

impl From<ReachabilityProductionEtcdBootstrapError> for ProductionReachabilityBootstrapError {
    fn from(error: ReachabilityProductionEtcdBootstrapError) -> Self {
        Self::ProviderBootstrap(error)
    }
}

impl From<ReachabilityOwnerError> for ProductionReachabilityBootstrapError {
    fn from(error: ReachabilityOwnerError) -> Self {
        Self::OwnerRecovery(error)
    }
}

/// Bootstraps one production provider context, recovers its durable owner, then composes live
/// authority ownership for `peer`.
///
/// Provider bootstrap is attempted exactly once through the existing control-plane seam. The
/// resulting preparation is split into the existing live-owner preparation and the already-narrowed
/// dedicated durable executor. Durable owner recovery is awaited before the pure live-authority
/// constructor is called. Therefore owner-recovery failure returns no live-authority object and no
/// partial/degraded production composition.
///
/// Calling this function performs the already-existing provider connection and durable recovery I/O.
/// It creates no systemd credential read, retry loop, runtime/task, fallback, or activation callsite.
///
/// # Errors
///
/// Returns [`ProductionReachabilityBootstrapError::ProviderBootstrap`] when the existing three-role
/// provider bootstrap fails, or [`ProductionReachabilityBootstrapError::OwnerRecovery`] when
/// authoritative durable recovery fails. No partial composition is returned.
pub async fn bootstrap_production_reachability(
    config: ReachabilityProductionEtcdBootstrapConfig,
    peer: &PeerConnectivityIdentity,
) -> Result<ProductionReachabilityBootstrapComposition, ProductionReachabilityBootstrapError> {
    let preparation = bootstrap_reachability_production_preparation(config)
        .await
        .map_err(ProductionReachabilityBootstrapError::ProviderBootstrap)?;
    let (live_preparation, durable_executor) = preparation.into_parts();

    let owner_custody = recover_production_reachability_owner_custody(durable_executor, peer)
        .await
        .map_err(ProductionReachabilityBootstrapError::OwnerRecovery)?;

    let live_owner_authority = compose_reachability_live_owner_authority(live_preparation);

    Ok(ProductionReachabilityBootstrapComposition {
        live_owner_authority,
        owner_custody,
    })
}

#[cfg(test)]
mod tests {
    use std::{error::Error, future::Future};

    use prw_connectivity::PeerConnectivityIdentity;
    use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
        ReachabilityProductionEtcdBootstrapConfig, ReachabilityProductionEtcdBootstrapError,
    };
    use prw_remote_bridge::{
        reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority,
        reachability_owner::ReachabilityOwnerError,
    };

    use super::{
        ProductionReachabilityBootstrapComposition, ProductionReachabilityBootstrapError,
        bootstrap_production_reachability,
    };
    use crate::production_reachability_owner_composition::ProductionReachabilityEtcdOwnerCustody;

    fn assert_bootstrap_signature(
        config: ReachabilityProductionEtcdBootstrapConfig,
        peer: &PeerConnectivityIdentity,
    ) {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    ProductionReachabilityBootstrapComposition,
                    ProductionReachabilityBootstrapError,
                >,
            >,
        {
        }

        assert_future(bootstrap_production_reachability(config, peer));
    }

    fn assert_parts_signature(
        composition: ProductionReachabilityBootstrapComposition,
    ) -> (
        ReachabilityLiveOwnerComposedAsyncAuthority,
        ProductionReachabilityEtcdOwnerCustody,
    ) {
        composition.into_parts()
    }

    #[test]
    fn production_bootstrap_has_exact_config_and_peer_input_shape() {
        let _ = assert_bootstrap_signature
            as fn(ReachabilityProductionEtcdBootstrapConfig, &PeerConnectivityIdentity);
    }

    #[test]
    fn composition_carrier_has_exact_two_part_consuming_shape() {
        let _ = assert_parts_signature
            as fn(
                ProductionReachabilityBootstrapComposition,
            ) -> (
                ReachabilityLiveOwnerComposedAsyncAuthority,
                ProductionReachabilityEtcdOwnerCustody,
            );
    }

    #[test]
    fn provider_failure_is_wrapped_without_detail_in_display() {
        let error = ProductionReachabilityBootstrapError::from(
            ReachabilityProductionEtcdBootstrapError::LiveOwnerConnect,
        );
        assert!(matches!(
            error,
            ProductionReachabilityBootstrapError::ProviderBootstrap(
                ReachabilityProductionEtcdBootstrapError::LiveOwnerConnect
            )
        ));
        assert_eq!(
            error.to_string(),
            "production reachability provider bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn owner_recovery_failure_is_wrapped_without_detail_in_display() {
        let error =
            ProductionReachabilityBootstrapError::from(ReachabilityOwnerError::RecoveryRequired);
        assert!(matches!(
            error,
            ProductionReachabilityBootstrapError::OwnerRecovery(
                ReachabilityOwnerError::RecoveryRequired
            )
        ));
        assert_eq!(
            error.to_string(),
            "production reachability owner recovery failed"
        );
        assert!(error.source().is_some());
    }
}
