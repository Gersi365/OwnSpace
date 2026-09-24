//! Phase 152 C02f-AP staging compile harness for the fence-sequence allocation etcd adapter.
//!
//! The source modules are included directly so the concrete `etcd-client` translation can be
//! compiled, linted, and unit-tested without public library exposure, endpoint construction, or
//! provider network I/O.

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_allocation_etcd.rs"]
pub mod fence_sequence_allocation_etcd;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence::{
    FENCE_SEQUENCE_HEAD_KEY, FenceSequenceAllocationPlan, FenceSequenceHead,
    FenceSequenceHeadObservation, FenceSequenceTxnCompare, FenceSequenceTxnOperation,
    SequenceAllocationAttemptId, encode_head, plan_allocation,
};
use fence_sequence_allocation_etcd::{FenceSequenceAllocationEtcdError, build_etcd_transaction};
use recovery_epoch::RecoveryEpoch;

fn epoch(value: u64) -> RecoveryEpoch {
    RecoveryEpoch::new(value).expect("non-zero epoch")
}

fn allocation_plan() -> FenceSequenceAllocationPlan {
    let predecessor = FenceSequenceHeadObservation::new(
        encode_head(FenceSequenceHead {
            epoch: epoch(9),
            high_water: 41,
        })
        .to_vec(),
        77,
    )
    .expect("canonical predecessor");
    let attempt_id = SequenceAllocationAttemptId::new([7_u8; 32]).expect("non-zero attempt id");
    plan_allocation(predecessor, attempt_id).expect("canonical allocation plan")
}

#[test]
fn canonical_allocation_plan_materializes_real_etcd_transaction_without_endpoint() {
    let plan = allocation_plan();
    let _transaction = build_etcd_transaction(&plan).expect("materialize etcd transaction");
}

#[test]
fn unexpected_compare_shape_fails_before_provider_io() {
    let mut plan = allocation_plan();
    plan.compares[2] = FenceSequenceTxnCompare::HeadExactValue(plan.predecessor.value.clone());

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape)
    ));
}

#[test]
fn unexpected_success_branch_shape_fails_before_provider_io() {
    let mut plan = allocation_plan();
    plan.success[0] = FenceSequenceTxnOperation::Get(FENCE_SEQUENCE_HEAD_KEY.to_vec());

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape)
    ));
}

#[test]
fn unexpected_failure_branch_shape_fails_before_provider_io() {
    let mut plan = allocation_plan();
    plan.failure[1] = FenceSequenceTxnOperation::Put(
        plan.reservation_key.clone(),
        vec![0_u8; fence_sequence::FENCE_SEQUENCE_RESERVATION_RECORD_BYTES],
    );

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape)
    ));
}

#[test]
fn mutated_successor_bytes_fail_before_provider_io() {
    let mut plan = allocation_plan();
    let FenceSequenceTxnOperation::Put(_, value) = &mut plan.success[0] else {
        panic!("canonical head success operation must be Put");
    };
    value[21] ^= 1;

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape)
    ));
}
