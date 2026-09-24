//! Phase 152 C02f-BS common live-owner acquisition sub-composition materialization.
//!
//! C02f-BR selected one bridge-owned acquisition composition over the existing C02f-BM preparation
//! facade, C02f-BQ replacement execution/mapping path, and C02f-BP first-owner execution/mapping
//! path. This module materializes only that acquisition subpath. It does not implement currentness,
//! release, a complete `ReachabilityLiveOwnerAsyncAuthority`, provider/client construction, runtime
//! ownership, R1-R4 effect activation, deployment, or merge.

#![allow(clippy::manual_async_fn)]

use std::future::Future;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::reachability_acquisition_evidence::{
    ReachabilityLiveOwnerAcquisitionPreparation, ReachabilityLiveOwnerPreparedAcquisition,
};

use crate::{
    reachability_live_owner::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
    },
    reachability_live_owner_first_owner_acquisition::map_resolved_first_owner_acquisition,
    reachability_live_owner_reconciled_acquisition_execution::execute_reconciled_live_owner_acquisition_with_prepared_execution,
};

/// Executes one complete BR-selected acquisition sub-composition for exactly one peer.
///
/// The operation calls C02f-BM preparation exactly once, then dispatches only on that exact terminal
/// prepared evidence. Replacement uses the exact preparation-owned live-owner provider through the
/// BS scoped capability and the existing BQ/AV terminal mapping. First-owner uses that same provider
/// through the existing BO/BP execution and BP semantic mapper. `Superseded` maps directly to
/// `Contended` without any live-owner provider mutation or read.
///
/// No branch can perform a second preparation, allocate another fence, regenerate attempt IDs,
/// re-plan from caller-controlled state, construct another provider context, or create an outer
/// retry/reissue loop.
///
/// # Errors
///
/// Preparation and provider/reconciliation failures map fail-closed to
/// [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`]. Existing BP/BQ semantic mapper
/// results, including their reserved `FenceExhausted` conversion failure, are returned unchanged.
pub fn acquire_prepared_live_owner<'a>(
    preparation: &'a mut ReachabilityLiveOwnerAcquisitionPreparation,
    peer: &'a PeerConnectivityIdentity,
) -> impl Future<Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>>
+ Send
+ 'a {
    async move {
        let prepared = preparation
            .prepare(peer)
            .await
            .map_err(map_provider_failure)?;

        match prepared {
            ReachabilityLiveOwnerPreparedAcquisition::Superseded => Ok(superseded_acquisition()),
            ReachabilityLiveOwnerPreparedAcquisition::Replacement(handoff) => {
                let mut execution = preparation.acquisition_execution();
                execute_reconciled_live_owner_acquisition_with_prepared_execution(
                    &mut execution,
                    &handoff,
                )
                .await
            }
            ReachabilityLiveOwnerPreparedAcquisition::FirstOwner(handoff) => {
                let mut execution = preparation.acquisition_execution();
                let resolved = execution
                    .execute_first_owner_with_reconciliation(handoff)
                    .await
                    .map_err(map_provider_failure)?;
                map_resolved_first_owner_acquisition(&resolved)
            }
        }
    }
}

const fn superseded_acquisition() -> ReachabilityLiveOwnerAcquisition {
    ReachabilityLiveOwnerAcquisition::Contended
}

fn map_provider_failure<T>(_error: T) -> ReachabilityLiveOwnerAuthorityError {
    ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superseded_preparation_maps_only_to_contended() {
        assert_eq!(
            superseded_acquisition(),
            ReachabilityLiveOwnerAcquisition::Contended
        );
    }

    #[test]
    fn preparation_and_provider_failures_map_fail_closed() {
        assert_eq!(
            map_provider_failure(()),
            ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
        );
    }
}
