//! Phase 152 C02f-CF Agent-owned reachability authority bootstrap composition.
//!
//! C02f-BY selected `prw-agent` as the process-level composition root, C02f-BZ materialized the
//! pure preparation-to-authority handoff, and C02f-CE materialized a separate custody boundary that
//! can produce the opaque validated bootstrap config. This module joins only the already-selected
//! control-plane provider bootstrap to the existing BZ composition seam.
//!
//! Calling the exported async function performs provider network I/O through `prw-control-plane`.
//! Merely compiling or naming the function performs none. This module does not load credentials,
//! alter Agent startup/readiness, create tasks, execute authority lifecycle operations, or wire the
//! function into the running Agent.

use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
    ReachabilityLiveOwnerEtcdBootstrapConfig, ReachabilityLiveOwnerEtcdBootstrapError,
    bootstrap_reachability_live_owner_preparation,
};
use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

use crate::reachability_authority_composition::compose_reachability_live_owner_authority;

/// Bootstraps the bounded provider preparation and composes the bridge-owned async authority.
///
/// The opaque validated config is consumed by value. Provider bootstrap is attempted exactly once;
/// on success the resulting preparation is immediately moved into the existing C02f-BZ composition
/// seam. No raw provider client or secret material is exposed from this boundary.
///
/// Calling this function performs provider network I/O. C02f-CF does not call it from `main.rs` or
/// any runtime/startup path.
///
/// # Errors
///
/// Returns the existing non-secret control-plane bootstrap error when either role-scoped provider
/// client cannot be established. No partially composed authority is returned on failure.
pub async fn bootstrap_reachability_live_owner_authority(
    config: ReachabilityLiveOwnerEtcdBootstrapConfig,
) -> Result<ReachabilityLiveOwnerComposedAsyncAuthority, ReachabilityLiveOwnerEtcdBootstrapError> {
    let preparation = bootstrap_reachability_live_owner_preparation(config).await?;
    Ok(compose_reachability_live_owner_authority(preparation))
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use prw_control_plane::reachability_acquisition_evidence::bootstrap::{
        ReachabilityLiveOwnerEtcdBootstrapConfig, ReachabilityLiveOwnerEtcdBootstrapError,
    };
    use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

    use super::bootstrap_reachability_live_owner_authority;

    fn assert_bootstrap_signature<F, Fut>(_bootstrap: F)
    where
        F: FnOnce(ReachabilityLiveOwnerEtcdBootstrapConfig) -> Fut,
        Fut: Future<
            Output = Result<
                ReachabilityLiveOwnerComposedAsyncAuthority,
                ReachabilityLiveOwnerEtcdBootstrapError,
            >,
        >,
    {
    }

    #[test]
    fn bootstrap_composition_has_exact_opaque_config_to_authority_shape() {
        assert_bootstrap_signature(bootstrap_reachability_live_owner_authority);
    }
}
