//! Phase 152 C02f-AY pure mapping from reconciled provider evidence to release semantics.
//!
//! C02f-AX selected the provider-neutral mapping from C02f-AE terminal release evidence to the
//! existing semantic release result. This module materializes only that deterministic translation.
//! It performs no provider I/O, transaction execution, re-observation, endpoint/client construction,
//! runtime ownership, retry/reissue, authority activation, R1-R4 effect fencing or deployment.
//!
//! C02f-BA added provider-owned peer/fence evidence to the top-level `NotCurrent` variant while
//! deliberately preserving fail-closed semantic behavior. C02f-BB consumes that evidence only when
//! its exact peer and non-zero fence equal the supplied semantic grant; cross-grant or cross-fence
//! evidence remains fail-closed.

use std::num::NonZeroU128;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::{
    reachability_live_owner_codec::LiveOwnerLifecycle,
    reachability_live_owner_etcd::reconciliation::{
        ReachabilityLiveOwnerResolvedMutationOutcome, ReachabilityLiveOwnerResolvedRelease,
    },
    reachability_live_owner_txn::{
        LiveOwnerProviderCurrentness, LiveOwnerTxnPlan, classify_currentness,
    },
};

use crate::reachability_live_owner::{
    ReachabilityLiveOwnerAuthorityError, ReachabilityLiveOwnerGrant, ReachabilityLiveOwnerRelease,
};

/// Maps one exact semantic grant plus one terminal C02f-AE release result into release semantics.
///
/// A provider-owned top-level `NotCurrent` result maps to semantic `NotCurrent` only when its bound
/// peer/fence exactly match the supplied grant. Contradictory binding fails closed. For a resolved
/// mutation, the retained successor must preserve the exact grant peer/fence and must be `Released`
/// before its terminal outcome is interpreted. `Committed` maps to `Released`, `Superseded` maps to
/// `NotCurrent`, and `CompareFailed` maps to `NotCurrent` only when the authoritative failure
/// observation deterministically proves the supplied grant stale. Contradictory context fails
/// closed.
///
/// # Errors
///
/// Returns [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`] for top-level evidence
/// whose peer/fence do not exactly match the supplied grant, successor-context mismatch, a compare
/// failure that still classifies the supplied grant as current, or deterministic classifier
/// rejection. Returns [`ReachabilityLiveOwnerAuthorityError::FenceExhausted`] if the semantic fence
/// cannot be represented as the non-zero provider fence required for classification.
pub fn map_reconciled_live_owner_release(
    grant: &ReachabilityLiveOwnerGrant,
    resolved: &ReachabilityLiveOwnerResolvedRelease,
) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
    match resolved {
        ReachabilityLiveOwnerResolvedRelease::NotCurrent(evidence) => {
            map_bound_not_current_parts(grant, evidence.peer(), evidence.fence())
        }
        ReachabilityLiveOwnerResolvedRelease::Mutation(mutation) => {
            map_reconciled_release_parts(grant, mutation.plan(), mutation.outcome())
        }
    }
}

fn map_bound_not_current_parts(
    grant: &ReachabilityLiveOwnerGrant,
    evidence_peer: &PeerConnectivityIdentity,
    evidence_fence: NonZeroU128,
) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
    let grant_fence = NonZeroU128::new(grant.fence().get())
        .ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;

    if evidence_peer == grant.peer() && evidence_fence == grant_fence {
        Ok(ReachabilityLiveOwnerRelease::NotCurrent)
    } else {
        Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
    }
}

fn map_reconciled_release_parts(
    grant: &ReachabilityLiveOwnerGrant,
    plan: &LiveOwnerTxnPlan,
    outcome: &ReachabilityLiveOwnerResolvedMutationOutcome,
) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
    let fence = NonZeroU128::new(grant.fence().get())
        .ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;
    let successor = plan.successor();

    if successor.peer() != grant.peer()
        || successor.fence() != fence
        || successor.lifecycle() != LiveOwnerLifecycle::Released
    {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    match outcome {
        ReachabilityLiveOwnerResolvedMutationOutcome::Committed => {
            Ok(ReachabilityLiveOwnerRelease::Released)
        }
        ReachabilityLiveOwnerResolvedMutationOutcome::Superseded => {
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        }
        ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(observation) => {
            match classify_currentness(grant.peer(), fence, Some(observation)) {
                Ok(LiveOwnerProviderCurrentness::Stale) => {
                    Ok(ReachabilityLiveOwnerRelease::NotCurrent)
                }
                Ok(LiveOwnerProviderCurrentness::Current) | Err(_) => {
                    Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU128;

    use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
    use prw_control_plane::{
        reachability_live_owner_codec::{
            AuthorityAttemptId, LiveOwnerLifecycle, ReachabilityLiveOwnerAuthorityRecord,
            encode_live_owner_key, encode_live_owner_record,
        },
        reachability_live_owner_etcd::reconciliation::ReachabilityLiveOwnerResolvedMutationOutcome,
        reachability_live_owner_txn::{LiveOwnerObservation, plan_acquisition, plan_release},
    };
    use prw_core::DeviceId;

    use super::*;
    use crate::reachability_live_owner::ReachabilityLiveOwnerFence;

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero TransportIdentity"),
        )
    }

    fn fence(value: u128) -> NonZeroU128 {
        NonZeroU128::new(value).expect("non-zero fence")
    }

    fn attempt(marker: u8) -> AuthorityAttemptId {
        AuthorityAttemptId::new([marker; 32]).expect("non-zero attempt id")
    }

    fn semantic_grant(
        peer: PeerConnectivityIdentity,
        fence_value: u128,
    ) -> ReachabilityLiveOwnerGrant {
        ReachabilityLiveOwnerGrant::from_authority(
            peer,
            ReachabilityLiveOwnerFence::new(fence_value).expect("semantic fence"),
        )
    }

    fn observation(
        peer: PeerConnectivityIdentity,
        lifecycle: LiveOwnerLifecycle,
        fence_value: u128,
        attempt_marker: u8,
        revision: i64,
    ) -> LiveOwnerObservation {
        let current = ReachabilityLiveOwnerAuthorityRecord::current(
            peer,
            fence(fence_value),
            attempt(attempt_marker),
        );
        let record = if lifecycle == LiveOwnerLifecycle::Current {
            current
        } else {
            current.released_successor()
        };
        let key = encode_live_owner_key(record.peer()).expect("encode key");
        let value = encode_live_owner_record(&record).expect("encode record");
        LiveOwnerObservation::decode(key, value, revision).expect("decode observation")
    }

    fn release_plan(
        peer: &PeerConnectivityIdentity,
        fence_value: u128,
        attempt_marker: u8,
        revision: i64,
    ) -> LiveOwnerTxnPlan {
        let before = observation(
            peer.clone(),
            LiveOwnerLifecycle::Current,
            fence_value,
            attempt_marker,
            revision,
        );
        plan_release(peer, fence(fence_value), Some(&before))
            .expect("release planning")
            .into_transaction()
            .expect("exact-current state requires release transaction")
    }

    #[test]
    fn bound_top_level_not_current_exact_binding_maps_to_not_current() {
        let peer = peer("bb-bound-exact", 1);
        let grant = semantic_grant(peer.clone(), 100);

        assert_eq!(
            map_bound_not_current_parts(&grant, &peer, fence(100)),
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        );
    }

    #[test]
    fn bound_top_level_not_current_cross_peer_fails_closed() {
        let peer_a = peer("bb-bound-peer-a", 2);
        let peer_b = peer("bb-bound-peer-b", 3);
        let grant = semantic_grant(peer_a, 101);

        assert_eq!(
            map_bound_not_current_parts(&grant, &peer_b, fence(101)),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn bound_top_level_not_current_different_fence_fails_closed() {
        let peer = peer("bb-bound-fence", 4);
        let grant = semantic_grant(peer.clone(), 102);

        assert_eq!(
            map_bound_not_current_parts(&grant, &peer, fence(103)),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn committed_exact_release_plan_maps_to_released() {
        let peer = peer("ay-committed", 2);
        let grant = semantic_grant(peer.clone(), 200);
        let plan = release_plan(&peer, 200, 3, 20);

        assert_eq!(
            map_reconciled_release_parts(
                &grant,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Ok(ReachabilityLiveOwnerRelease::Released)
        );
    }

    #[test]
    fn superseded_exact_release_plan_maps_to_not_current() {
        let peer = peer("ay-superseded", 4);
        let grant = semantic_grant(peer.clone(), 300);
        let plan = release_plan(&peer, 300, 5, 30);

        assert_eq!(
            map_reconciled_release_parts(
                &grant,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Superseded,
            ),
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        );
    }

    #[test]
    fn compare_failed_stale_observation_maps_to_not_current() {
        let peer = peer("ay-compare-stale", 6);
        let grant = semantic_grant(peer.clone(), 400);
        let plan = release_plan(&peer, 400, 7, 40);
        let stale = observation(peer, LiveOwnerLifecycle::Released, 400, 7, 41);
        let outcome = ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(stale);

        assert_eq!(
            map_reconciled_release_parts(&grant, &plan, &outcome),
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        );
    }

    #[test]
    fn compare_failed_current_observation_fails_closed() {
        let peer = peer("ay-compare-current", 8);
        let grant = semantic_grant(peer.clone(), 500);
        let plan = release_plan(&peer, 500, 9, 50);
        let current = observation(peer, LiveOwnerLifecycle::Current, 500, 9, 51);
        let outcome = ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(current);

        assert_eq!(
            map_reconciled_release_parts(&grant, &plan, &outcome),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn cross_peer_release_plan_fails_closed() {
        let peer_a = peer("ay-cross-peer-a", 10);
        let peer_b = peer("ay-cross-peer-b", 11);
        let grant = semantic_grant(peer_a, 600);
        let plan = release_plan(&peer_b, 600, 12, 60);

        assert_eq!(
            map_reconciled_release_parts(
                &grant,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn different_fence_release_plan_fails_closed() {
        let peer = peer("ay-fence-mismatch", 13);
        let grant = semantic_grant(peer.clone(), 700);
        let plan = release_plan(&peer, 701, 14, 70);

        assert_eq!(
            map_reconciled_release_parts(
                &grant,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn non_released_successor_fails_closed() {
        let peer = peer("ay-current-successor", 15);
        let grant = semantic_grant(peer.clone(), 801);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 800, 16, 80);
        let current_successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(801), attempt(17));
        let plan = plan_acquisition(&before, current_successor).expect("acquisition plan");

        assert_eq!(
            map_reconciled_release_parts(
                &grant,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn compare_failure_observation_for_another_peer_fails_closed() {
        let peer_a = peer("ay-compare-peer-a", 18);
        let peer_b = peer("ay-compare-peer-b", 19);
        let grant = semantic_grant(peer_a.clone(), 900);
        let plan = release_plan(&peer_a, 900, 20, 90);
        let contradictory = observation(peer_b, LiveOwnerLifecycle::Released, 900, 21, 91);
        let outcome = ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(contradictory);

        assert_eq!(
            map_reconciled_release_parts(&grant, &plan, &outcome),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }
}
