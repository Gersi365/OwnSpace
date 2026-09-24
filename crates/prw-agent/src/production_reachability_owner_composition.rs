//! Agent-owned composition seam for one production reachability owner backed by the existing
//! durable-snapshot etcd executor.
//!
//! C03e-HO materializes only the C03e-HN-selected cross-crate handoff after control-plane provider
//! bootstrap has already narrowed a dedicated durable role connection to
//! `ReachabilityDurableSnapshotEtcdExecutor`. This module wraps that executor in the existing bridge
//! semantic store, creates the existing Agent-owned verifier freshness-token source, and moves both
//! directly into the existing Agent-owned custody recovery seam.
//!
//! This module does not connect to etcd, receive endpoints or credential material, expose a raw
//! `Client`/`KvClient`, create a fallback store or owner, spawn a task/runtime, publish readiness,
//! activate candidate publication or traversal, dial a peer, install a listener, mutate startup or
//! shutdown, deploy, or change production state.

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::reachability_durable_snapshot_etcd::ReachabilityDurableSnapshotEtcdExecutor;
use prw_remote_bridge::{
    reachability_durable_snapshot_etcd_store::ReachabilityDurableSnapshotEtcdStore,
    reachability_owner::ReachabilityOwnerError,
};

use crate::{
    production_reachability_freshness_token_source::ProductionReachabilityFreshnessTokenSource,
    production_reachability_owner_custody::ProductionReachabilityOwnerCustody,
};

/// Concrete Agent custody produced by the selected production durable-snapshot composition chain.
pub type ProductionReachabilityEtcdOwnerCustody = ProductionReachabilityOwnerCustody<
    ReachabilityDurableSnapshotEtcdStore,
    ProductionReachabilityFreshnessTokenSource,
>;

/// Consumes one already-narrowed dedicated durable executor and recovers exactly one production
/// reachability owner into Agent custody for `peer`.
///
/// The executor is moved directly into the existing bridge semantic store. The store and one fresh
/// stateless verifier token source are then moved directly into
/// [`ProductionReachabilityOwnerCustody::recover`]. No provider handle or semantic owner escapes the
/// custody boundary.
///
/// Calling this function may perform the existing authoritative durable recovery I/O through the
/// supplied executor. It creates no provider connection, retry loop, task, runtime, or fallback.
///
/// # Errors
///
/// Returns the existing [`ReachabilityOwnerError`] from authoritative durable recovery unchanged.
pub async fn recover_production_reachability_owner_custody(
    provider: ReachabilityDurableSnapshotEtcdExecutor,
    peer: &PeerConnectivityIdentity,
) -> Result<ProductionReachabilityEtcdOwnerCustody, ReachabilityOwnerError> {
    let store = ReachabilityDurableSnapshotEtcdStore::new(provider);
    let token_source = ProductionReachabilityFreshnessTokenSource::new();
    ProductionReachabilityOwnerCustody::recover(store, token_source, peer).await
}
