//! C02f-AS provider-neutral retained-observation handoff for one C02f-AR acquisition plan.
//!
//! C02f-AR deliberately plans from an authoritative live-owner observation but retains only the
//! committed AQ allocation evidence and deterministic C02f-AB transaction plan. C02f-AE
//! reconciliation, by contrast, requires the exact pre-mutation observation. This module closes
//! only that evidence-continuity gap: it couples the exact observation to the exact AR plan after a
//! deterministic C02f-AB replay proves the transaction is byte-for-byte bound to that observation.
//!
//! No provider I/O, transaction execution, endpoint/client/runtime construction, attempt-ID
//! generation, retry/reconciliation, semantic-authority activation, R1-R4 effect fencing or
//! deployment is performed here.

use std::fmt;

use crate::{
    fence_sequence_live_owner_bridge::FenceSequenceLiveOwnerAcquisitionPlan,
    reachability_live_owner_txn::{LiveOwnerObservation, LiveOwnerTxnError, plan_acquisition},
};

/// Exact authoritative observation retained beside one exact C02f-AR acquisition plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceLiveOwnerAcquisitionHandoff {
    observation: LiveOwnerObservation,
    acquisition: FenceSequenceLiveOwnerAcquisitionPlan,
}

impl FenceSequenceLiveOwnerAcquisitionHandoff {
    /// Returns the exact authoritative pre-mutation live-owner observation.
    #[must_use]
    pub const fn observation(&self) -> &LiveOwnerObservation {
        &self.observation
    }

    /// Returns the exact C02f-AR allocation-plus-transaction plan.
    #[must_use]
    pub const fn acquisition(&self) -> &FenceSequenceLiveOwnerAcquisitionPlan {
        &self.acquisition
    }

    /// Consumes the capsule and returns its exact retained evidence parts.
    #[must_use]
    pub fn into_parts(self) -> (LiveOwnerObservation, FenceSequenceLiveOwnerAcquisitionPlan) {
        (self.observation, self.acquisition)
    }
}

/// Fail-closed C02f-AS handoff validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceLiveOwnerHandoffError {
    /// Deterministic C02f-AB replay rejected the retained observation/successor relation.
    LiveOwner(LiveOwnerTxnError),
    /// Replaying C02f-AB from the retained observation did not reproduce the exact AR transaction.
    TransactionPlanMismatch,
}

impl fmt::Display for FenceSequenceLiveOwnerHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveOwner(error) => write!(
                formatter,
                "live-owner handoff observation failed deterministic acquisition replay: {error}"
            ),
            Self::TransactionPlanMismatch => formatter.write_str(
                "live-owner handoff observation does not reproduce the exact retained acquisition transaction plan",
            ),
        }
    }
}

impl std::error::Error for FenceSequenceLiveOwnerHandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LiveOwner(error) => Some(error),
            Self::TransactionPlanMismatch => None,
        }
    }
}

impl From<LiveOwnerTxnError> for FenceSequenceLiveOwnerHandoffError {
    fn from(value: LiveOwnerTxnError) -> Self {
        Self::LiveOwner(value)
    }
}

/// Retains one exact authoritative observation beside one exact C02f-AR acquisition plan.
///
/// Before accepting the pair, C02f-AS deterministically replays existing C02f-AB
/// [`plan_acquisition`] using the supplied observation and the exact retained AR successor. The
/// replay must reproduce the complete retained transaction plan exactly. This binds the observation
/// revision/value/key evidence to the same dual-CAS transaction that AR produced, without executing
/// the transaction or contacting a provider.
///
/// # Errors
///
/// Returns a fail-closed error when C02f-AB rejects the observation/successor relation or when the
/// replayed transaction is not exactly equal to the retained AR transaction plan.
pub fn retain_live_owner_acquisition_handoff(
    observation: LiveOwnerObservation,
    acquisition: FenceSequenceLiveOwnerAcquisitionPlan,
) -> Result<FenceSequenceLiveOwnerAcquisitionHandoff, FenceSequenceLiveOwnerHandoffError> {
    let replayed = plan_acquisition(&observation, acquisition.transaction().successor().clone())?;
    if &replayed != acquisition.transaction() {
        return Err(FenceSequenceLiveOwnerHandoffError::TransactionPlanMismatch);
    }

    Ok(FenceSequenceLiveOwnerAcquisitionHandoff {
        observation,
        acquisition,
    })
}
