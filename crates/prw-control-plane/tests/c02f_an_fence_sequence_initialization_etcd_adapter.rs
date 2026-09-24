//! Phase 152 C02f-AN staging compile harness for the fence-sequence initialization etcd adapter.
//!
//! The source modules are included directly so the concrete `etcd-client` translation can be
//! compiled, linted, and unit-tested without public library exposure, endpoint construction, or
//! provider network I/O.

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_initialization.rs"]
pub mod fence_sequence_initialization;
#[path = "../src/fence_sequence_initialization_etcd.rs"]
pub mod fence_sequence_initialization_etcd;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence::{FenceSequenceHead, FenceSequenceHeadObservation, encode_head};
use fence_sequence_initialization::{
    FenceSequenceInitializationOperation, FenceSequenceInitializationPlan, plan_initialization,
};
use fence_sequence_initialization_etcd::{
    FenceSequenceInitializationEtcdError, build_etcd_transaction,
};
use recovery_epoch::RecoveryEpoch;

fn epoch(value: u64) -> RecoveryEpoch {
    RecoveryEpoch::new(value).expect("non-zero epoch")
}

fn observation(epoch_value: u64, high_water: u64, revision: i64) -> FenceSequenceHeadObservation {
    FenceSequenceHeadObservation::new(
        encode_head(FenceSequenceHead {
            epoch: epoch(epoch_value),
            high_water,
        })
        .to_vec(),
        revision,
    )
    .expect("canonical observation")
}

#[test]
fn absent_head_plan_materializes_real_etcd_transaction_without_endpoint() {
    let FenceSequenceInitializationPlan::Mutation(plan) = plan_initialization(epoch(9), None)
    else {
        panic!("absent head must produce a mutation plan");
    };

    let _transaction = build_etcd_transaction(&plan).expect("materialize etcd transaction");
}

#[test]
fn older_epoch_plan_materializes_real_etcd_transaction_without_endpoint() {
    let predecessor = observation(8, 77, 41);
    let FenceSequenceInitializationPlan::Mutation(plan) =
        plan_initialization(epoch(9), Some(predecessor))
    else {
        panic!("older epoch must produce a mutation plan");
    };

    let _transaction = build_etcd_transaction(&plan).expect("materialize etcd transaction");
}

#[test]
fn unexpected_success_branch_shape_fails_before_provider_io() {
    let FenceSequenceInitializationPlan::Mutation(mut plan) = plan_initialization(epoch(9), None)
    else {
        panic!("absent head must produce a mutation plan");
    };
    plan.success = [FenceSequenceInitializationOperation::LinearizableGet {
        key: fence_sequence::FENCE_SEQUENCE_HEAD_KEY.to_vec(),
    }];

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceInitializationEtcdError::UnexpectedPlanShape)
    ));
}

#[test]
fn unexpected_failure_branch_shape_fails_before_provider_io() {
    let FenceSequenceInitializationPlan::Mutation(mut plan) = plan_initialization(epoch(9), None)
    else {
        panic!("absent head must produce a mutation plan");
    };
    plan.failure = [FenceSequenceInitializationOperation::Put {
        key: fence_sequence::FENCE_SEQUENCE_HEAD_KEY.to_vec(),
        value: encode_head(FenceSequenceHead {
            epoch: epoch(9),
            high_water: 0,
        })
        .to_vec(),
    }];

    assert!(matches!(
        build_etcd_transaction(&plan),
        Err(FenceSequenceInitializationEtcdError::UnexpectedPlanShape)
    ));
}
