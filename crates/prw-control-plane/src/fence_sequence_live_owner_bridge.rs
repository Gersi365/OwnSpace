//! C02f-AR provider-neutral bridge from one committed fence-sequence allocation to live-owner planning.
//!
//! This module performs only deterministic typed composition. It accepts one already-resolved
//! C02f-AQ allocation, maps the locked recovery ordering `fence = (epoch << 64) | sequence`, builds
//! one canonical Current live-owner successor, and delegates to the existing C02f-AB deterministic
//! acquisition planner. It performs no provider I/O, endpoint/client construction, randomness,
//! retry, runtime activation, live-owner transaction execution, R1-R4 effect fencing, or deployment.

use std::{fmt, num::NonZeroU128};

use prw_connectivity::PeerConnectivityIdentity;

use crate::{
    fence_sequence_allocation_orchestrator::{
        FenceSequenceAllocationResolved, FenceSequenceAllocationResolvedOutcome,
    },
    reachability_live_owner_codec::{AuthorityAttemptId, ReachabilityLiveOwnerAuthorityRecord},
    reachability_live_owner_txn::{
        LiveOwnerObservation, LiveOwnerTxnError, LiveOwnerTxnPlan, plan_acquisition,
    },
};

/// Exact committed allocation retained alongside the deterministic live-owner acquisition plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceLiveOwnerAcquisitionPlan {
    allocation: FenceSequenceAllocationResolved,
    transaction: LiveOwnerTxnPlan,
}

impl FenceSequenceLiveOwnerAcquisitionPlan {
    /// Returns the exact C02f-AQ allocation resolution that authorized fence composition.
    #[must_use]
    pub const fn allocation(&self) -> &FenceSequenceAllocationResolved {
        &self.allocation
    }

    /// Returns the deterministic C02f-AB live-owner acquisition transaction plan.
    #[must_use]
    pub const fn transaction(&self) -> &LiveOwnerTxnPlan {
        &self.transaction
    }

    /// Consumes the bridge result and returns both retained allocation evidence and transaction plan.
    #[must_use]
    pub fn into_parts(self) -> (FenceSequenceAllocationResolved, LiveOwnerTxnPlan) {
        (self.allocation, self.transaction)
    }
}

/// Fail-closed C02f-AR bridge failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceLiveOwnerBridgeError {
    /// AQ did not resolve the retained sequence allocation as committed.
    AllocationNotCommitted,
    /// The locked epoch/sequence composition unexpectedly failed to produce a non-zero fence.
    InvalidCanonicalFence,
    /// Existing C02f-AB live-owner planning rejected the proposed successor.
    LiveOwner(LiveOwnerTxnError),
}

impl fmt::Display for FenceSequenceLiveOwnerBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationNotCommitted => formatter.write_str(
                "fence-sequence allocation is not committed and cannot authorize live-owner planning",
            ),
            Self::InvalidCanonicalFence => formatter.write_str(
                "committed fence-sequence allocation did not compose a canonical non-zero live-owner fence",
            ),
            Self::LiveOwner(error) => write!(formatter, "live-owner acquisition planning failed: {error}"),
        }
    }
}

impl std::error::Error for FenceSequenceLiveOwnerBridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LiveOwner(error) => Some(error),
            Self::AllocationNotCommitted | Self::InvalidCanonicalFence => None,
        }
    }
}

impl From<LiveOwnerTxnError> for FenceSequenceLiveOwnerBridgeError {
    fn from(value: LiveOwnerTxnError) -> Self {
        Self::LiveOwner(value)
    }
}

/// Composes the locked canonical PRW live-owner fence from one committed AQ allocation.
///
/// The selected ordering is exact: the high 64 bits are the non-zero recovery epoch and the low
/// 64 bits are the non-zero within-epoch sequence. A superseded AQ allocation never authorizes a
/// fence because its reservation belongs to another allocation attempt.
///
/// # Errors
///
/// Returns [`FenceSequenceLiveOwnerBridgeError::AllocationNotCommitted`] unless AQ resolved the
/// exact retained allocation as committed. The typed epoch/sequence representation makes a zero
/// result unreachable for valid state, but the conversion remains explicitly fail-closed.
pub fn canonical_live_owner_fence(
    allocation: &FenceSequenceAllocationResolved,
) -> Result<NonZeroU128, FenceSequenceLiveOwnerBridgeError> {
    if allocation.outcome() != FenceSequenceAllocationResolvedOutcome::Committed {
        return Err(FenceSequenceLiveOwnerBridgeError::AllocationNotCommitted);
    }

    let plan = allocation.plan();
    let epoch = u128::from(plan.predecessor.head.epoch.get());
    let sequence = u128::from(plan.sequence.get());
    let raw = (epoch << 64) | sequence;
    NonZeroU128::new(raw).ok_or(FenceSequenceLiveOwnerBridgeError::InvalidCanonicalFence)
}

/// Plans one deterministic live-owner acquisition from one committed AQ sequence allocation.
///
/// The caller supplies the exact authoritative live-owner observation, exact peer namespace and a
/// separately generated live-owner authority-attempt identifier. C02f-AR deliberately does not
/// reuse the sequence-allocation attempt identifier as the live-owner mutation attempt identifier.
/// The existing C02f-AB planner remains authoritative for exact-peer binding, strict fence
/// monotonicity, attempt-ID freshness and canonical transaction construction.
///
/// # Errors
///
/// Fails closed when the allocation is not committed, canonical fence composition fails, or C02f-AB
/// rejects the successor because the peer, fence ordering, attempt identifier or record encoding is
/// invalid.
pub fn plan_live_owner_acquisition_from_allocation(
    observed: &LiveOwnerObservation,
    peer: &PeerConnectivityIdentity,
    allocation: FenceSequenceAllocationResolved,
    attempt_id: AuthorityAttemptId,
) -> Result<FenceSequenceLiveOwnerAcquisitionPlan, FenceSequenceLiveOwnerBridgeError> {
    let fence = canonical_live_owner_fence(&allocation)?;
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence, attempt_id);
    let transaction = plan_acquisition(observed, successor)?;
    Ok(FenceSequenceLiveOwnerAcquisitionPlan {
        allocation,
        transaction,
    })
}
