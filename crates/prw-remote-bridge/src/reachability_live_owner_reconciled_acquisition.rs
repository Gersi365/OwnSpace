//! Phase 152 C02f-AV pure mapping from reconciled provider evidence to acquisition semantics.
//!
//! C02f-AT selected the exact semantic mapping and C02f-AU made the retained C02f-AS acquisition
//! evidence externally nameable. This module now materializes only that deterministic translation.
//! It performs no provider I/O, transaction execution, re-observation, endpoint/client/runtime
//! construction, attempt-ID generation, retry, authority activation, R1-R4 effect fencing or
//! deployment.

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::{
    reachability_acquisition_evidence::FenceSequenceLiveOwnerAcquisitionHandoff,
    reachability_live_owner_codec::LiveOwnerLifecycle,
    reachability_live_owner_etcd::reconciliation::{
        ReachabilityLiveOwnerResolvedMutation, ReachabilityLiveOwnerResolvedMutationOutcome,
    },
    reachability_live_owner_txn::LiveOwnerTxnPlan,
};

use crate::reachability_live_owner::{
    ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
    ReachabilityLiveOwnerFence, ReachabilityLiveOwnerGrant,
};

/// Maps one exact C02f-AS handoff plus its terminal C02f-AE resolved mutation into the selected
/// semantic acquisition result.
///
/// The complete resolved transaction plan must equal the exact transaction retained by the handoff
/// before any terminal outcome is interpreted. The retained successor must also remain `Current`
/// and bound to the exact peer encoded by the handoff observation. No peer, fence or successor is
/// reconstructed from request-controlled input.
///
/// `Committed` maps to an exact semantic grant. `CompareFailed` and `Superseded` are definitive
/// non-grant outcomes and map to `Contended`. Any contradictory or mismatched context fails closed.
///
/// # Errors
///
/// Returns [`ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous`] for plan mismatch,
/// peer/lifecycle contradiction, or a compare-failure observation bound to another peer. Returns
/// [`ReachabilityLiveOwnerAuthorityError::FenceExhausted`] if the retained non-zero provider fence
/// cannot be represented by the semantic fence type.
pub fn map_reconciled_live_owner_acquisition(
    handoff: &FenceSequenceLiveOwnerAcquisitionHandoff,
    resolved: &ReachabilityLiveOwnerResolvedMutation,
) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
    map_reconciled_acquisition_parts(
        handoff.observation().record().peer(),
        handoff.acquisition().transaction(),
        resolved.plan(),
        resolved.outcome(),
    )
}

fn map_reconciled_acquisition_parts(
    expected_peer: &PeerConnectivityIdentity,
    retained_plan: &LiveOwnerTxnPlan,
    resolved_plan: &LiveOwnerTxnPlan,
    outcome: &ReachabilityLiveOwnerResolvedMutationOutcome,
) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
    if resolved_plan != retained_plan {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    let successor = retained_plan.successor();
    if successor.peer() != expected_peer || successor.lifecycle() != LiveOwnerLifecycle::Current {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    match outcome {
        ReachabilityLiveOwnerResolvedMutationOutcome::Committed => {
            let fence = ReachabilityLiveOwnerFence::new(successor.fence().get())
                .map_err(|_| ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;
            Ok(ReachabilityLiveOwnerAcquisition::Granted(
                ReachabilityLiveOwnerGrant::from_authority(successor.peer().clone(), fence),
            ))
        }
        ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(observation) => {
            if observation.record().peer() != expected_peer {
                return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
            }
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        }
        ReachabilityLiveOwnerResolvedMutationOutcome::Superseded => {
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU128;

    use prw_connectivity::TransportIdentity;
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

    #[test]
    fn committed_exact_plan_maps_to_exact_semantic_grant() {
        let peer = peer("av-committed", 1);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 100, 2, 10);
        let successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(101), attempt(3));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");

        let result = map_reconciled_acquisition_parts(
            &peer,
            &plan,
            &plan,
            &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
        )
        .expect("semantic mapping");

        let ReachabilityLiveOwnerAcquisition::Granted(grant) = result else {
            panic!("expected exact semantic grant")
        };
        assert_eq!(grant.peer(), &peer);
        assert_eq!(grant.fence().get(), 101);
    }

    #[test]
    fn compare_failed_maps_to_contention_without_grant() {
        let peer = peer("av-compare-failed", 4);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 200, 5, 20);
        let successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(201), attempt(6));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");
        let outcome = ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(before);

        assert_eq!(
            map_reconciled_acquisition_parts(&peer, &plan, &plan, &outcome),
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        );
    }

    #[test]
    fn superseded_maps_to_contention_without_grant() {
        let peer = peer("av-superseded", 7);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 300, 8, 30);
        let successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(301), attempt(9));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");

        assert_eq!(
            map_reconciled_acquisition_parts(
                &peer,
                &plan,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Superseded,
            ),
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        );
    }

    #[test]
    fn resolved_plan_mismatch_fails_closed_before_outcome_mapping() {
        let peer = peer("av-plan-mismatch", 10);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 400, 11, 40);
        let retained = plan_acquisition(
            &before,
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(401), attempt(12)),
        )
        .expect("retained plan");
        let different = plan_acquisition(
            &before,
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(402), attempt(13)),
        )
        .expect("different plan");

        assert_eq!(
            map_reconciled_acquisition_parts(
                &peer,
                &retained,
                &different,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn cross_peer_context_fails_closed() {
        let peer_a = peer("av-cross-peer-a", 14);
        let peer_b = peer("av-cross-peer-b", 15);
        let before = observation(peer_a.clone(), LiveOwnerLifecycle::Released, 500, 16, 50);
        let plan = plan_acquisition(
            &before,
            ReachabilityLiveOwnerAuthorityRecord::current(peer_a, fence(501), attempt(17)),
        )
        .expect("plan acquisition");

        assert_eq!(
            map_reconciled_acquisition_parts(
                &peer_b,
                &plan,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn non_current_successor_fails_closed() {
        let peer = peer("av-released-successor", 18);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 600, 19, 60);
        let plan = plan_release(&peer, fence(600), Some(&before))
            .expect("release plan")
            .into_transaction()
            .expect("current state requires release transaction");

        assert_eq!(
            map_reconciled_acquisition_parts(
                &peer,
                &plan,
                &plan,
                &ReachabilityLiveOwnerResolvedMutationOutcome::Committed,
            ),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn compare_failure_observation_for_another_peer_fails_closed() {
        let peer_a = peer("av-compare-peer-a", 20);
        let peer_b = peer("av-compare-peer-b", 21);
        let before = observation(peer_a.clone(), LiveOwnerLifecycle::Released, 700, 22, 70);
        let plan = plan_acquisition(
            &before,
            ReachabilityLiveOwnerAuthorityRecord::current(peer_a.clone(), fence(701), attempt(23)),
        )
        .expect("plan acquisition");
        let contradictory = observation(peer_b, LiveOwnerLifecycle::Current, 800, 24, 80);
        let outcome = ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(contradictory);

        assert_eq!(
            map_reconciled_acquisition_parts(&peer_a, &plan, &plan, &outcome),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }
}
