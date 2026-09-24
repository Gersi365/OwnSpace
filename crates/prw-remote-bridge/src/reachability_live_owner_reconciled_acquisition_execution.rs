//! Phase 152 C02f-BQ reconciled replacement-acquisition provider execution composition.
//!
//! C02f-AW selected the exact evidence-continuity sequence from one retained C02f-AS acquisition
//! handoff through the already-materialized C02f-AE bounded provider reconciliation into the
//! validated C02f-AV semantic mapper. C02f-BS reuses the same terminal mapping through the narrow
//! preparation-owned acquisition-execution capability selected by C02f-BR.
//!
//! The existing public BQ entry point still accepts one already-created mutable
//! `ReachabilityLiveOwnerEtcdStore` plus one exact retained handoff. The BS crate-private entry point
//! accepts only the scoped preparation-owned acquisition-execution capability plus that same handoff.
//! Neither path selects endpoints, constructs a client, configures TLS/auth/RBAC, creates runtime
//! state, allocates fences/attempt IDs, retries outside AE, activates R1-R4, deploys, or merges.

#![allow(clippy::manual_async_fn)]

use std::future::Future;

use prw_control_plane::{
    reachability_acquisition_evidence::{
        FenceSequenceLiveOwnerAcquisitionHandoff, ReachabilityLiveOwnerAcquisitionExecution,
    },
    reachability_live_owner_etcd::{
        ReachabilityLiveOwnerEtcdStore,
        reconciliation::{
            ReachabilityLiveOwnerReconciliationError, ReachabilityLiveOwnerResolvedMutation,
        },
    },
};

use crate::{
    reachability_live_owner::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
    },
    reachability_live_owner_reconciled_acquisition::map_reconciled_live_owner_acquisition,
};

/// Executes the selected reconciled replacement-acquisition sequence for one exact retained handoff.
///
/// `before` is cloned only from `handoff.observation()` and `successor` only from the exact retained
/// transaction successor. Those values are passed directly to C02f-AE
/// `execute_acquisition_with_reconciliation`; its exact terminal provider evidence is then passed
/// with the same original handoff directly to C02f-AV `map_reconciled_live_owner_acquisition`.
///
/// This composition performs no replanning, direct `execute`, extra provider re-observation,
/// outer retry/reissue loop, evidence reconstruction or semantic result manufacture.
///
/// The explicit `Future + Send` return type preserves the C02f-Y production async contract without
/// transferring runtime ownership into this module.
///
/// # Errors
///
/// Every C02f-AE provider/reconciliation failure maps fail-closed to
/// [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`]. C02f-AV semantic mapping errors,
/// including its reserved `FenceExhausted` conversion failure, are returned unchanged.
pub fn execute_reconciled_live_owner_acquisition<'a>(
    store: &'a mut ReachabilityLiveOwnerEtcdStore,
    handoff: &'a FenceSequenceLiveOwnerAcquisitionHandoff,
) -> impl Future<Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>>
+ Send
+ 'a {
    async move {
        let before = handoff.observation().clone();
        let successor = handoff.acquisition().transaction().successor().clone();
        let resolved = store
            .execute_acquisition_with_reconciliation(before, successor)
            .await;
        map_resolved_replacement(handoff, resolved)
    }
}

/// Executes the same BQ replacement mapping through the exact preparation-owned BS capability.
pub(crate) fn execute_reconciled_live_owner_acquisition_with_prepared_execution<'a>(
    execution: &'a mut ReachabilityLiveOwnerAcquisitionExecution<'_>,
    handoff: &'a FenceSequenceLiveOwnerAcquisitionHandoff,
) -> impl Future<Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>>
+ Send
+ 'a {
    async move {
        let resolved = execution
            .execute_replacement_with_reconciliation(handoff)
            .await;
        map_resolved_replacement(handoff, resolved)
    }
}

fn map_resolved_replacement(
    handoff: &FenceSequenceLiveOwnerAcquisitionHandoff,
    resolved: Result<
        ReachabilityLiveOwnerResolvedMutation,
        ReachabilityLiveOwnerReconciliationError,
    >,
) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
    let resolved = resolved.map_err(map_provider_failure)?;
    map_reconciled_live_owner_acquisition(handoff, &resolved)
}

fn map_provider_failure<T>(_error: T) -> ReachabilityLiveOwnerAuthorityError {
    ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_failure_maps_fail_closed() {
        assert_eq!(
            map_provider_failure(()),
            ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
        );
    }
}
