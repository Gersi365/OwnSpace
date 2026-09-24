//! Phase 152 C02f-AM staging validation for provider-neutral fence-sequence epoch initialization.
//!
//! The source modules are included directly so the deterministic plan can be compiled and tested
//! without public library exposure or any etcd/provider/runtime activation.

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_initialization.rs"]
pub mod fence_sequence_initialization;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence::{
    FENCE_SEQUENCE_HEAD_KEY, FenceSequenceHead, FenceSequenceHeadObservation, encode_head,
};
use fence_sequence_initialization::{
    FenceSequenceInitializationCompare, FenceSequenceInitializationError,
    FenceSequenceInitializationOperation, FenceSequenceInitializationPlan,
    FenceSequenceInitializationReobservation, classify_initialization_reobservation,
    plan_initialization,
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
fn absent_head_plans_version_zero_create_of_epoch_zero_high_water() {
    let target = epoch(9);
    let FenceSequenceInitializationPlan::Mutation(plan) = plan_initialization(target, None) else {
        panic!("absent head must require a mutation plan");
    };

    assert_eq!(plan.predecessor, None);
    assert_eq!(
        plan.compares,
        vec![FenceSequenceInitializationCompare::HeadVersionZero {
            key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
        }]
    );
    assert_eq!(
        plan.success,
        [FenceSequenceInitializationOperation::Put {
            key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
            value: encode_head(FenceSequenceHead {
                epoch: target,
                high_water: 0,
            })
            .to_vec(),
        }]
    );
    assert_eq!(
        plan.failure,
        [FenceSequenceInitializationOperation::LinearizableGet {
            key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
        }]
    );
}

#[test]
fn older_epoch_plans_exact_revision_and_value_cas_replacement() {
    let target = epoch(9);
    let before = observation(8, 77, 41);
    let FenceSequenceInitializationPlan::Mutation(plan) =
        plan_initialization(target, Some(before.clone()))
    else {
        panic!("older epoch must require a mutation plan");
    };

    assert_eq!(plan.predecessor, Some(before.clone()));
    assert_eq!(
        plan.compares,
        vec![
            FenceSequenceInitializationCompare::HeadModRevisionEquals {
                key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
                expected: 41,
            },
            FenceSequenceInitializationCompare::HeadExactValueEquals {
                key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
                expected: before.value,
            },
        ]
    );
    assert_eq!(
        plan.success,
        [FenceSequenceInitializationOperation::Put {
            key: FENCE_SEQUENCE_HEAD_KEY.to_vec(),
            value: encode_head(FenceSequenceHead {
                epoch: target,
                high_water: 0,
            })
            .to_vec(),
        }]
    );
}

#[test]
fn same_epoch_preserves_existing_high_water_without_mutation() {
    let current = observation(9, 1234, 51);
    assert_eq!(
        plan_initialization(epoch(9), Some(current.clone())),
        FenceSequenceInitializationPlan::Preserve(current)
    );
}

#[test]
fn greater_epoch_is_superseded_without_mutation() {
    let newer = observation(10, 3, 61);
    assert_eq!(
        plan_initialization(epoch(9), Some(newer.clone())),
        FenceSequenceInitializationPlan::Superseded(newer)
    );
}

#[test]
fn create_reobservation_is_current_for_target_epoch_even_after_allocations() {
    let target = epoch(9);
    let FenceSequenceInitializationPlan::Mutation(plan) = plan_initialization(target, None) else {
        panic!("mutation plan");
    };
    let advanced = observation(9, 42, 70);

    assert_eq!(
        classify_initialization_reobservation(&plan, Some(&advanced)),
        Ok(FenceSequenceInitializationReobservation::Current)
    );
    assert_eq!(
        classify_initialization_reobservation(&plan, None),
        Ok(FenceSequenceInitializationReobservation::ProvenNotCommitted)
    );
}

#[test]
fn replace_reobservation_requires_exact_predecessor_for_non_commit_proof() {
    let target = epoch(9);
    let predecessor = observation(8, 77, 41);
    let FenceSequenceInitializationPlan::Mutation(plan) =
        plan_initialization(target, Some(predecessor.clone()))
    else {
        panic!("mutation plan");
    };

    assert_eq!(
        classify_initialization_reobservation(&plan, Some(&predecessor)),
        Ok(FenceSequenceInitializationReobservation::ProvenNotCommitted)
    );

    let same_bytes_new_revision = observation(8, 77, 42);
    assert_eq!(
        classify_initialization_reobservation(&plan, Some(&same_bytes_new_revision)),
        Err(FenceSequenceInitializationError::ContradictoryState)
    );
    assert_eq!(
        classify_initialization_reobservation(&plan, None),
        Err(FenceSequenceInitializationError::ContradictoryState)
    );
}

#[test]
fn later_epoch_reobservation_is_superseded() {
    let target = epoch(9);
    let FenceSequenceInitializationPlan::Mutation(plan) = plan_initialization(target, None) else {
        panic!("mutation plan");
    };
    let later = observation(10, 1, 80);

    assert_eq!(
        classify_initialization_reobservation(&plan, Some(&later)),
        Ok(FenceSequenceInitializationReobservation::Superseded)
    );
}
