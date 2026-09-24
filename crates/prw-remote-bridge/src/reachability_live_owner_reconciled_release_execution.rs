//! Phase 152 C02f-BD reconciled release provider execution composition.
//!
//! C02f-BC selected the exact release-side composition from one semantic live-owner grant through
//! the already-materialized C02f-AD linearizable read and C02f-AE bounded reconciliation into the
//! validated C02f-BB semantic mapper. This module materializes only that sequence.
//!
//! The public compatibility entry point still accepts an already-created mutable
//! `ReachabilityLiveOwnerEtcdStore`. C02f-BU additionally exposes one crate-private adapter over the
//! narrow preparation-owned lifecycle capability selected by C02f-BT. Neither path selects
//! endpoints, constructs an etcd client, configures TLS/auth/RBAC, creates a runtime/task, allocates
//! fences or attempt IDs, activates R1-R4 effects, deploys, or merges anything. Provider I/O occurs
//! only when the returned future is polled.

#![allow(clippy::manual_async_fn)]

use std::{future::Future, num::NonZeroU128};

use prw_control_plane::{
    reachability_acquisition_evidence::ReachabilityLiveOwnerLifecycleExecution,
    reachability_live_owner_etcd::ReachabilityLiveOwnerEtcdStore,
};

use crate::{
    reachability_live_owner::{
        ReachabilityLiveOwnerAuthorityError, ReachabilityLiveOwnerGrant,
        ReachabilityLiveOwnerRelease,
    },
    reachability_live_owner_reconciled_release::map_reconciled_live_owner_release,
};

/// Executes the selected reconciled provider release sequence for one exact semantic grant.
///
/// The exact peer and fence are derived only from `grant`. The initial provider read is the C02f-AD
/// default-linearizable exact-key observation. That exact observation is passed directly to C02f-AE
/// `execute_release_with_reconciliation`, and its exact terminal evidence is passed with the same
/// original grant directly to the C02f-BB semantic mapper.
///
/// The explicit `Future + Send` return type preserves the C02f-Y production async contract without
/// transferring runtime ownership into this module.
///
/// # Errors
///
/// Returns [`ReachabilityLiveOwnerAuthorityError::FenceExhausted`] only if the semantic fence cannot
/// be represented as the required non-zero provider fence. Any C02f-AD initial-read error or C02f-AE
/// reconciliation error maps fail-closed to
/// [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`]. C02f-BB mapping errors are
/// returned unchanged.
pub fn execute_reconciled_live_owner_release<'a>(
    store: &'a mut ReachabilityLiveOwnerEtcdStore,
    grant: &'a ReachabilityLiveOwnerGrant,
) -> impl Future<Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>>
+ Send
+ 'a {
    async move {
        let raw_fence = NonZeroU128::new(grant.fence().get())
            .ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;

        let observation = store
            .linearizable_observation(grant.peer())
            .await
            .map_err(map_provider_failure)?;

        let resolved = store
            .execute_release_with_reconciliation(grant.peer(), raw_fence, observation)
            .await
            .map_err(map_provider_failure)?;

        map_reconciled_live_owner_release(grant, &resolved)
    }
}

/// Executes the exact BD release composition through the C02f-BT/BU scoped lifecycle borrow.
///
/// The bridge still owns semantic fence projection, the exact initial observation -> bounded
/// reconciliation sequence, and the C02f-BB semantic mapper. The capability exposes only those
/// provider primitives on the preparation-owned live-owner store.
pub(crate) fn execute_reconciled_live_owner_release_with_prepared_execution<'a>(
    execution: &'a mut ReachabilityLiveOwnerLifecycleExecution<'_>,
    grant: &'a ReachabilityLiveOwnerGrant,
) -> impl Future<Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>>
+ Send
+ 'a {
    async move {
        let raw_fence = NonZeroU128::new(grant.fence().get())
            .ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;

        let observation = execution
            .linearizable_observation(grant.peer())
            .await
            .map_err(map_provider_failure)?;

        let resolved = execution
            .execute_release_with_reconciliation(grant.peer(), raw_fence, observation)
            .await
            .map_err(map_provider_failure)?;

        map_reconciled_live_owner_release(grant, &resolved)
    }
}

fn map_provider_failure<T>(_error: T) -> ReachabilityLiveOwnerAuthorityError {
    ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
}
