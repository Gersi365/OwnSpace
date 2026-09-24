//! Phase 152 C02f-AS staging validation for the retained-observation acquisition handoff capsule.
//!
//! Production modules are included directly so the pure AR -> AS evidence handoff can be compiled,
//! linted and tested without public `lib.rs` export, provider I/O or runtime activation.

use std::{
    convert::Infallible,
    future::Future,
    num::NonZeroU128,
    pin::pin,
    task::{Context, Poll, Waker},
};

use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_core::DeviceId;

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_allocation_etcd.rs"]
pub mod fence_sequence_allocation_etcd;
#[path = "../src/fence_sequence_allocation_orchestrator.rs"]
pub mod fence_sequence_allocation_orchestrator;
#[path = "../src/fence_sequence_live_owner_bridge.rs"]
pub mod fence_sequence_live_owner_bridge;
#[path = "../src/fence_sequence_live_owner_handoff.rs"]
pub mod fence_sequence_live_owner_handoff;
#[path = "../src/reachability_live_owner_codec.rs"]
pub mod reachability_live_owner_codec;
#[path = "../src/reachability_live_owner_txn.rs"]
pub mod reachability_live_owner_txn;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence::{
    FenceSequenceAllocationPlan, FenceSequenceHead, FenceSequenceHeadObservation,
    FenceSequenceReobservation, SequenceAllocationAttemptId, encode_head, plan_allocation,
};
use fence_sequence_allocation_orchestrator::{
    FenceSequenceAllocationAuthority, FenceSequenceAllocationResolved,
    FenceSequenceAllocationResolvedOutcome, FenceSequenceAllocationSubmissionOutcome,
    resolve_fence_sequence_allocation_with_reconciliation,
};
use fence_sequence_live_owner_bridge::{
    FenceSequenceLiveOwnerAcquisitionPlan, plan_live_owner_acquisition_from_allocation,
};
use fence_sequence_live_owner_handoff::{
    FenceSequenceLiveOwnerHandoffError, retain_live_owner_acquisition_handoff,
};
use reachability_live_owner_codec::{
    AuthorityAttemptId, ReachabilityLiveOwnerAuthorityRecord, encode_live_owner_key,
    encode_live_owner_record,
};
use reachability_live_owner_txn::{LiveOwnerObservation, LiveOwnerTxnError};
use recovery_epoch::RecoveryEpoch;

struct DefinitiveAuthority {
    classification: FenceSequenceReobservation,
}

impl FenceSequenceAllocationAuthority for DefinitiveAuthority {
    type Error = Infallible;

    async fn submit_allocation(
        &mut self,
        _plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceAllocationSubmissionOutcome, Self::Error> {
        Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            self.classification,
        ))
    }

    async fn fresh_reobserve(
        &mut self,
        _plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceReobservation, Self::Error> {
        panic!("definitive committed classification must not reobserve")
    }
}

fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
    PeerConnectivityIdentity::new(
        DeviceId::new(device).expect("valid DeviceId"),
        TransportIdentity::new([marker; 32]).expect("non-zero TransportIdentity"),
    )
}

fn epoch(value: u64) -> RecoveryEpoch {
    RecoveryEpoch::new(value).expect("non-zero recovery epoch")
}

fn sequence_attempt(marker: u8) -> SequenceAllocationAttemptId {
    SequenceAllocationAttemptId::new([marker; 32]).expect("non-zero sequence attempt")
}

fn live_owner_attempt(marker: u8) -> AuthorityAttemptId {
    AuthorityAttemptId::new([marker; 32]).expect("non-zero live-owner attempt")
}

fn raw_fence(epoch: u64, sequence: u64) -> NonZeroU128 {
    NonZeroU128::new((u128::from(epoch) << 64) | u128::from(sequence))
        .expect("non-zero canonical fence")
}

fn allocation_plan(
    epoch_value: u64,
    high_water: u64,
    attempt_marker: u8,
) -> FenceSequenceAllocationPlan {
    let predecessor = FenceSequenceHeadObservation::new(
        encode_head(FenceSequenceHead {
            epoch: epoch(epoch_value),
            high_water,
        })
        .to_vec(),
        77,
    )
    .expect("canonical predecessor");
    plan_allocation(predecessor, sequence_attempt(attempt_marker)).expect("allocation plan")
}

fn committed_allocation(
    epoch_value: u64,
    high_water: u64,
    attempt_marker: u8,
) -> FenceSequenceAllocationResolved {
    let plan = allocation_plan(epoch_value, high_water, attempt_marker);
    let mut authority = DefinitiveAuthority {
        classification: FenceSequenceReobservation::Committed,
    };
    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("committed allocation resolution");
    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    resolved
}

fn observation(
    peer: &PeerConnectivityIdentity,
    fence: NonZeroU128,
    attempt_marker: u8,
    revision: i64,
) -> LiveOwnerObservation {
    let record = ReachabilityLiveOwnerAuthorityRecord::current(
        peer.clone(),
        fence,
        live_owner_attempt(attempt_marker),
    );
    let key = encode_live_owner_key(peer).expect("canonical live-owner key");
    let value = encode_live_owner_record(&record).expect("canonical live-owner record");
    LiveOwnerObservation::decode(key, value, revision).expect("live-owner observation")
}

fn ar_plan(
    observed: &LiveOwnerObservation,
    peer: &PeerConnectivityIdentity,
) -> FenceSequenceLiveOwnerAcquisitionPlan {
    plan_live_owner_acquisition_from_allocation(
        observed,
        peer,
        committed_allocation(9, 41, 7),
        live_owner_attempt(4),
    )
    .expect("AR acquisition plan")
}

#[test]
fn exact_observation_and_ar_plan_are_retained_after_exact_replay() {
    let peer = peer("as-exact", 1);
    let observed = observation(&peer, raw_fence(9, 41), 3, 91);
    let planned = ar_plan(&observed, &peer);
    let expected_observation = observed.clone();
    let expected_plan = planned.clone();

    let handoff = retain_live_owner_acquisition_handoff(observed, planned)
        .expect("exact retained observation must reproduce AR plan");

    assert_eq!(handoff.observation(), &expected_observation);
    assert_eq!(handoff.acquisition(), &expected_plan);
    assert_eq!(
        handoff.acquisition().transaction().successor().fence(),
        raw_fence(9, 42)
    );
    assert_eq!(
        handoff.acquisition().allocation().outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
}

#[test]
fn changed_revision_cannot_be_rebound_to_existing_ar_transaction() {
    let peer = peer("as-revision", 2);
    let original = observation(&peer, raw_fence(9, 41), 3, 91);
    let planned = ar_plan(&original, &peer);
    let same_record_new_revision = observation(&peer, raw_fence(9, 41), 3, 92);

    assert_eq!(
        retain_live_owner_acquisition_handoff(same_record_new_revision, planned),
        Err(FenceSequenceLiveOwnerHandoffError::TransactionPlanMismatch)
    );
}

#[test]
fn different_peer_observation_fails_closed_before_handoff() {
    let planned_peer = peer("as-peer-a", 3);
    let other_peer = peer("as-peer-b", 4);
    let original = observation(&planned_peer, raw_fence(9, 41), 3, 91);
    let planned = ar_plan(&original, &planned_peer);
    let other_observation = observation(&other_peer, raw_fence(9, 41), 3, 91);

    assert_eq!(
        retain_live_owner_acquisition_handoff(other_observation, planned),
        Err(FenceSequenceLiveOwnerHandoffError::LiveOwner(
            LiveOwnerTxnError::SuccessorPeerMismatch,
        ))
    );
}

#[test]
fn consuming_handoff_returns_exact_observation_and_ar_plan() {
    let peer = peer("as-parts", 5);
    let observed = observation(&peer, raw_fence(9, 41), 3, 93);
    let planned = ar_plan(&observed, &peer);
    let expected_observation = observed.clone();
    let expected_plan = planned.clone();

    let handoff = retain_live_owner_acquisition_handoff(observed, planned).expect("valid handoff");
    let (returned_observation, returned_plan) = handoff.into_parts();

    assert_eq!(returned_observation, expected_observation);
    assert_eq!(returned_plan, expected_plan);
}

#[test]
fn handoff_preserves_separate_sequence_and_live_owner_attempt_domains() {
    let peer = peer("as-attempt-domain", 6);
    let observed = observation(&peer, raw_fence(9, 41), 3, 94);
    let planned = ar_plan(&observed, &peer);
    let handoff = retain_live_owner_acquisition_handoff(observed, planned).expect("valid handoff");

    assert_ne!(
        handoff
            .acquisition()
            .allocation()
            .plan()
            .attempt_id
            .as_bytes(),
        handoff
            .acquisition()
            .transaction()
            .successor()
            .attempt_id()
            .as_bytes(),
        "sequence allocation and live-owner mutation attempt identities remain separate"
    );
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("scripted future must resolve immediately"),
    }
}
