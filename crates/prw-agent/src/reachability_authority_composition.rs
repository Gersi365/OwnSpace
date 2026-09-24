//! Phase 152 C02f-BZ Agent-owned reachability authority composition seam.
//!
//! C02f-BY selected `prw-agent` as the process-level composition root while preserving
//! `prw-control-plane` ownership of provider/TLS/client bootstrap and `prw-remote-bridge` ownership
//! of live-owner acquisition/currentness/release semantics. This module materializes only the pure
//! handoff between those already-selected boundaries.
//!
//! The seam accepts one already-created `ReachabilityLiveOwnerAcquisitionPreparation` and wraps it
//! in the bridge-owned `ReachabilityLiveOwnerComposedAsyncAuthority`. Construction performs no
//! provider I/O, accepts no endpoint or secret material, creates no runtime/task, and does not
//! activate the authority in the running Agent.

use prw_control_plane::reachability_acquisition_evidence::ReachabilityLiveOwnerAcquisitionPreparation;
use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

/// Composes one already-prepared provider context into the bridge-owned asynchronous authority.
///
/// This is intentionally a pure ownership handoff. The caller remains responsible for obtaining the
/// preparation through a separately gated provider bootstrap and for deciding if/when the returned
/// authority is integrated into an Agent runtime.
#[must_use]
pub const fn compose_reachability_live_owner_authority(
    preparation: ReachabilityLiveOwnerAcquisitionPreparation,
) -> ReachabilityLiveOwnerComposedAsyncAuthority {
    ReachabilityLiveOwnerComposedAsyncAuthority::new(preparation)
}

#[cfg(test)]
mod tests {
    use prw_control_plane::reachability_acquisition_evidence::ReachabilityLiveOwnerAcquisitionPreparation;
    use prw_remote_bridge::reachability_live_owner_async::{
        ReachabilityLiveOwnerAsyncAuthority, ReachabilityLiveOwnerComposedAsyncAuthority,
    };

    use super::compose_reachability_live_owner_authority;

    fn assert_composition_signature(
        _compose: fn(
            ReachabilityLiveOwnerAcquisitionPreparation,
        ) -> ReachabilityLiveOwnerComposedAsyncAuthority,
    ) {
    }

    fn assert_async_authority<T: ReachabilityLiveOwnerAsyncAuthority>() {}

    #[test]
    fn composition_seam_has_exact_preparation_to_authority_shape() {
        assert_composition_signature(compose_reachability_live_owner_authority);
        assert_async_authority::<ReachabilityLiveOwnerComposedAsyncAuthority>();
    }
}
