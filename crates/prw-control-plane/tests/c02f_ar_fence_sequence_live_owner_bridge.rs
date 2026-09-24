//! Phase 152 C02f-AR staging validation for the committed allocation -> live-owner planning bridge.
//!
//! Production source modules are included directly so the bridge can be compiled, linted and tested
//! without public `lib.rs` export, provider I/O, runtime/client construction or live-owner activation.

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
    FenceSequenceLiveOwnerBridgeError, canonical_live_owner_fence,
    plan_live_owner_acquisition_from_allocation,
};
use reachability_live_owner_codec::{
    AuthorityAttemptId, LiveOwnerLifecycle, ReachabilityLiveOwnerAuthorityRecord,
    encode_live_owner_key, encode_live_owner_record,
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
        panic!("definitive committed/superseded classification must not reobserve")
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

fn resolved_allocation(
    classification: FenceSequenceReobservation,
    epoch_value: u64,
    high_water: u64,
    attempt_marker: u8,
) -> FenceSequenceAllocationResolved {
    let plan = allocation_plan(epoch_value, high_water, attempt_marker);
    let mut authority = DefinitiveAuthority { classification };
    ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("definitive allocation resolution")
}

fn live_owner_observation(
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

#[test]
fn committed_allocation_composes_exact_locked_64_64_fence() {
    let allocation = resolved_allocation(FenceSequenceReobservation::Committed, 9, 41, 7);
    assert_eq!(
        allocation.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    assert_eq!(
        canonical_live_owner_fence(&allocation),
        Ok(raw_fence(9, 42))
    );
}

#[test]
fn committed_allocation_builds_exact_current_successor_and_retains_evidence() {
    let peer = peer("ar-committed", 1);
    let observed = live_owner_observation(&peer, raw_fence(9, 41), 3, 91);
    let allocation = resolved_allocation(FenceSequenceReobservation::Committed, 9, 41, 7);
    let expected_allocation = allocation.clone();
    let next_attempt = live_owner_attempt(4);

    let bridged =
        plan_live_owner_acquisition_from_allocation(&observed, &peer, allocation, next_attempt)
            .expect("committed allocation plans live-owner acquisition");

    assert_eq!(bridged.allocation(), &expected_allocation);
    let successor = bridged.transaction().successor();
    assert_eq!(successor.peer(), &peer);
    assert_eq!(successor.lifecycle(), LiveOwnerLifecycle::Current);
    assert_eq!(successor.fence(), raw_fence(9, 42));
    assert_eq!(successor.attempt_id(), next_attempt);
    assert_ne!(
        successor.attempt_id().as_bytes(),
        expected_allocation.plan().attempt_id.as_bytes(),
        "sequence-allocation and live-owner mutation attempt identities remain separate"
    );
}

#[test]
fn superseded_allocation_never_authorizes_live_owner_fence_or_plan() {
    let peer = peer("ar-superseded", 2);
    let observed = live_owner_observation(&peer, raw_fence(9, 41), 3, 92);
    let allocation = resolved_allocation(FenceSequenceReobservation::Superseded, 9, 41, 7);

    assert_eq!(
        allocation.outcome(),
        FenceSequenceAllocationResolvedOutcome::Superseded
    );
    assert_eq!(
        canonical_live_owner_fence(&allocation),
        Err(FenceSequenceLiveOwnerBridgeError::AllocationNotCommitted)
    );
    assert_eq!(
        plan_live_owner_acquisition_from_allocation(
            &observed,
            &peer,
            allocation,
            live_owner_attempt(4),
        ),
        Err(FenceSequenceLiveOwnerBridgeError::AllocationNotCommitted)
    );
}

#[test]
fn older_epoch_allocation_cannot_bypass_live_owner_fence_monotonicity() {
    let peer = peer("ar-monotonic", 3);
    let observed = live_owner_observation(&peer, raw_fence(10, 1), 3, 93);
    let allocation = resolved_allocation(FenceSequenceReobservation::Committed, 9, 41, 7);

    assert_eq!(
        plan_live_owner_acquisition_from_allocation(
            &observed,
            &peer,
            allocation,
            live_owner_attempt(4),
        ),
        Err(FenceSequenceLiveOwnerBridgeError::LiveOwner(
            LiveOwnerTxnError::FenceNotStrictlyNewer,
        ))
    );
}

#[test]
fn exact_peer_binding_is_still_enforced_by_existing_live_owner_planner() {
    let observed_peer = peer("ar-peer-a", 4);
    let requested_peer = peer("ar-peer-b", 5);
    let observed = live_owner_observation(&observed_peer, raw_fence(9, 41), 3, 94);
    let allocation = resolved_allocation(FenceSequenceReobservation::Committed, 9, 41, 7);

    assert_eq!(
        plan_live_owner_acquisition_from_allocation(
            &observed,
            &requested_peer,
            allocation,
            live_owner_attempt(4),
        ),
        Err(FenceSequenceLiveOwnerBridgeError::LiveOwner(
            LiveOwnerTxnError::SuccessorPeerMismatch,
        ))
    );
}

#[test]
fn live_owner_attempt_id_must_remain_fresh_independently_of_sequence_attempt_id() {
    let peer = peer("ar-attempt", 6);
    let observed = live_owner_observation(&peer, raw_fence(9, 41), 4, 95);
    let allocation = resolved_allocation(FenceSequenceReobservation::Committed, 9, 41, 7);

    assert_eq!(
        plan_live_owner_acquisition_from_allocation(
            &observed,
            &peer,
            allocation,
            live_owner_attempt(4),
        ),
        Err(FenceSequenceLiveOwnerBridgeError::LiveOwner(
            LiveOwnerTxnError::AttemptIdReused,
        ))
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
