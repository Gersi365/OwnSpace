//! Phase 152 C02f-BP pure mapping from resolved first-owner provider evidence to acquisition semantics.
//!
//! C02f-BO selected a deterministic mapper parallel to the C02f-AV replacement mapper. This module
//! performs no provider I/O, re-observation, transaction execution, retry, randomness generation,
//! fence allocation, endpoint/client construction, runtime activation, or deployment.

use std::num::NonZeroU128;

use prw_control_plane::{
    reachability_acquisition_evidence::{
        FenceSequenceAllocationResolvedOutcome, ReachabilityLiveOwnerFirstOwnerTxnCompare,
        ReachabilityLiveOwnerFirstOwnerTxnOperation,
    },
    reachability_live_owner_codec::{
        LiveOwnerLifecycle, encode_live_owner_key, encode_live_owner_record,
    },
    reachability_live_owner_etcd::{
        ReachabilityLiveOwnerFirstOwnerResolvedOutcome, ReachabilityLiveOwnerResolvedFirstOwner,
    },
};

use crate::reachability_live_owner::{
    ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
    ReachabilityLiveOwnerFence, ReachabilityLiveOwnerGrant,
};

/// Maps one exact terminal first-owner provider result into the selected semantic acquisition result.
///
/// The complete retained handoff is revalidated before its terminal provider outcome is interpreted.
/// The mapper never reconstructs peer/fence/attempt/provider evidence from request-controlled input.
///
/// # Errors
///
/// Returns [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`] for any contradiction in
/// retained allocation, transaction, key/value, peer/lifecycle, or terminal observation evidence.
/// Returns [`ReachabilityLiveOwnerAuthorityError::FenceExhausted`] only if the retained canonical
/// provider fence cannot be represented by the existing semantic fence type.
pub fn map_resolved_first_owner_acquisition(
    resolved: &ReachabilityLiveOwnerResolvedFirstOwner,
) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
    let handoff = resolved.handoff();
    let allocation = handoff.allocation();
    let transaction = handoff.transaction();
    let successor = transaction.successor();

    if allocation.outcome() != FenceSequenceAllocationResolvedOutcome::Committed
        || successor.lifecycle() != LiveOwnerLifecycle::Current
    {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    let expected_key = encode_live_owner_key(successor.peer())
        .map_err(|_| ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)?;
    let expected_value = encode_live_owner_record(successor)
        .map_err(|_| ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)?;

    if !matches!(
        transaction.compare(),
        ReachabilityLiveOwnerFirstOwnerTxnCompare::KeyVersionZero { key } if key == &expected_key
    ) || !matches!(
        transaction.success(),
        ReachabilityLiveOwnerFirstOwnerTxnOperation::Put { key, value }
            if key == &expected_key && value == &expected_value
    ) || !matches!(
        transaction.failure(),
        ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key }
            if key == &expected_key
    ) {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    let epoch = u128::from(allocation.plan().predecessor.head.epoch.get());
    let sequence = u128::from(allocation.plan().sequence.get());
    let canonical_fence = NonZeroU128::new((epoch << 64) | sequence)
        .ok_or(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)?;
    if successor.fence() != canonical_fence {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    match resolved.outcome() {
        ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Committed => {
            let fence = ReachabilityLiveOwnerFence::new(successor.fence().get())
                .map_err(|_| ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;
            Ok(ReachabilityLiveOwnerAcquisition::Granted(
                ReachabilityLiveOwnerGrant::from_authority(successor.peer().clone(), fence),
            ))
        }
        ReachabilityLiveOwnerFirstOwnerResolvedOutcome::CompareFailed(observation)
        | ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Superseded(observation) => {
            if observation.key() != expected_key.as_slice()
                || observation.record().peer() != successor.peer()
            {
                return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
            }
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        }
    }
}
