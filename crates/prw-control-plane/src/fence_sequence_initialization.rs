//! C02f-AM provider-neutral fence-sequence epoch-head initialization planning.
//!
//! This module materializes only the deterministic initialization/rollover decision and
//! re-observation classifier for the existing PRWF head. It performs no etcd RPC, endpoint
//! selection, TLS/auth/RBAC setup, recovery execution, sequence allocation, or runtime activation.

use std::fmt;

use crate::{
    fence_sequence::{
        FENCE_SEQUENCE_HEAD_KEY, FenceSequenceHead, FenceSequenceHeadObservation, encode_head,
    },
    recovery_epoch::RecoveryEpoch,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceSequenceInitializationCompare {
    HeadVersionZero { key: Vec<u8> },
    HeadModRevisionEquals { key: Vec<u8>, expected: i64 },
    HeadExactValueEquals { key: Vec<u8>, expected: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceSequenceInitializationOperation {
    Put { key: Vec<u8>, value: Vec<u8> },
    LinearizableGet { key: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceInitializationTxnPlan {
    pub target_epoch: RecoveryEpoch,
    pub predecessor: Option<FenceSequenceHeadObservation>,
    pub compares: Vec<FenceSequenceInitializationCompare>,
    pub success: [FenceSequenceInitializationOperation; 1],
    pub failure: [FenceSequenceInitializationOperation; 1],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceSequenceInitializationPlan {
    Mutation(FenceSequenceInitializationTxnPlan),
    Preserve(FenceSequenceHeadObservation),
    Superseded(FenceSequenceHeadObservation),
}

/// Plans deterministic initialization of the PRWF head for one globally-current recovery epoch.
///
/// - absent head => compare head version == 0 and create `PRWF(E, 0)`;
/// - older epoch => exact mod-revision + exact-value CAS to `PRWF(E, 0)`;
/// - same epoch => preserve the current high-water without mutation;
/// - greater epoch => report supersession without mutation.
#[must_use]
pub fn plan_initialization(
    target_epoch: RecoveryEpoch,
    observed: Option<FenceSequenceHeadObservation>,
) -> FenceSequenceInitializationPlan {
    let key = FENCE_SEQUENCE_HEAD_KEY.to_vec();
    let target_value = encode_head(FenceSequenceHead {
        epoch: target_epoch,
        high_water: 0,
    })
    .to_vec();

    match observed {
        None => FenceSequenceInitializationPlan::Mutation(FenceSequenceInitializationTxnPlan {
            target_epoch,
            predecessor: None,
            compares: vec![FenceSequenceInitializationCompare::HeadVersionZero {
                key: key.clone(),
            }],
            success: [FenceSequenceInitializationOperation::Put {
                key: key.clone(),
                value: target_value,
            }],
            failure: [FenceSequenceInitializationOperation::LinearizableGet { key }],
        }),
        Some(current) if current.head.epoch < target_epoch => {
            FenceSequenceInitializationPlan::Mutation(FenceSequenceInitializationTxnPlan {
                target_epoch,
                predecessor: Some(current.clone()),
                compares: vec![
                    FenceSequenceInitializationCompare::HeadModRevisionEquals {
                        key: key.clone(),
                        expected: current.mod_revision,
                    },
                    FenceSequenceInitializationCompare::HeadExactValueEquals {
                        key: key.clone(),
                        expected: current.value,
                    },
                ],
                success: [FenceSequenceInitializationOperation::Put {
                    key: key.clone(),
                    value: target_value,
                }],
                failure: [FenceSequenceInitializationOperation::LinearizableGet { key }],
            })
        }
        Some(current) if current.head.epoch == target_epoch => {
            FenceSequenceInitializationPlan::Preserve(current)
        }
        Some(current) => FenceSequenceInitializationPlan::Superseded(current),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceInitializationReobservation {
    Current,
    Superseded,
    ProvenNotCommitted,
}

/// Classifies one fresh linearizable PRWF-head observation after an indeterminate initialization
/// mutation.
///
/// A target-epoch head is functionally current even if another allocator has already advanced its
/// high-water after initialization. A later epoch supersedes the retained target. Proof of
/// non-commit is intentionally narrow: an absent head is proof only for a create plan, while a
/// replace plan requires the exact same predecessor bytes and revision. Every other lower-epoch,
/// missing, changed-revision, or changed-value state fails closed.
///
/// # Errors
///
/// Returns [`FenceSequenceInitializationError::ContradictoryState`] when the observation cannot be
/// reconciled with the exact retained initialization plan.
pub fn classify_initialization_reobservation(
    plan: &FenceSequenceInitializationTxnPlan,
    observed: Option<&FenceSequenceHeadObservation>,
) -> Result<FenceSequenceInitializationReobservation, FenceSequenceInitializationError> {
    match observed {
        Some(current) if current.head.epoch == plan.target_epoch => {
            Ok(FenceSequenceInitializationReobservation::Current)
        }
        Some(current) if current.head.epoch > plan.target_epoch => {
            Ok(FenceSequenceInitializationReobservation::Superseded)
        }
        Some(current) => match plan.predecessor.as_ref() {
            Some(predecessor)
                if current.mod_revision == predecessor.mod_revision
                    && current.value == predecessor.value =>
            {
                Ok(FenceSequenceInitializationReobservation::ProvenNotCommitted)
            }
            Some(_) | None => Err(FenceSequenceInitializationError::ContradictoryState),
        },
        None if plan.predecessor.is_none() => {
            Ok(FenceSequenceInitializationReobservation::ProvenNotCommitted)
        }
        None => Err(FenceSequenceInitializationError::ContradictoryState),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceInitializationError {
    ContradictoryState,
}

impl fmt::Display for FenceSequenceInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("contradictory fence-sequence initialization state")
    }
}

impl std::error::Error for FenceSequenceInitializationError {}
