//! Phase 152 C02f-BK provider-neutral first-owner live-owner bootstrap plan and evidence.
//!
//! C02f-BI selected absent-key creation semantics and C02f-BJ selected the narrow acquisition
//! preparation boundary. This module materializes only the deterministic first-owner transaction
//! shape and its retained committed-allocation evidence. It performs no provider I/O, attempt-ID
//! generation, retry/reconciliation, endpoint/client construction, runtime activation or deployment.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;

use crate::{
    fence_sequence_allocation_orchestrator::FenceSequenceAllocationResolved,
    fence_sequence_live_owner_bridge::{
        FenceSequenceLiveOwnerBridgeError, canonical_live_owner_fence,
    },
    reachability_live_owner_codec::{
        AuthorityAttemptId, ReachabilityLiveOwnerAuthorityRecord, ReachabilityLiveOwnerCodecError,
        encode_live_owner_key, encode_live_owner_record,
    },
};

/// Exact provider-neutral compare selected for first-owner creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerFirstOwnerTxnCompare {
    /// Requires the exact live-owner key to remain absent (`version == 0`).
    KeyVersionZero {
        /// Exact canonical live-owner key.
        key: Vec<u8>,
    },
}

/// One deterministic operation in a first-owner transaction branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerFirstOwnerTxnOperation {
    /// Writes the complete intended canonical `Current` record.
    Put {
        /// Exact canonical live-owner key.
        key: Vec<u8>,
        /// Exact canonical `PRWL` bytes.
        value: Vec<u8>,
    },
    /// Reads the exact key using latest/linearizable semantics.
    LinearizableGet {
        /// Exact canonical live-owner key.
        key: Vec<u8>,
    },
}

/// Deterministic create-only transaction plan for an authoritatively absent live-owner key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerFirstOwnerTxnPlan {
    compare: ReachabilityLiveOwnerFirstOwnerTxnCompare,
    success: ReachabilityLiveOwnerFirstOwnerTxnOperation,
    failure: ReachabilityLiveOwnerFirstOwnerTxnOperation,
    successor: ReachabilityLiveOwnerAuthorityRecord,
}

impl ReachabilityLiveOwnerFirstOwnerTxnPlan {
    /// Returns the exact `version == 0` absence compare.
    #[must_use]
    pub const fn compare(&self) -> &ReachabilityLiveOwnerFirstOwnerTxnCompare {
        &self.compare
    }

    /// Returns the exact one-Put success branch.
    #[must_use]
    pub const fn success(&self) -> &ReachabilityLiveOwnerFirstOwnerTxnOperation {
        &self.success
    }

    /// Returns the exact one-Get compare-failure branch.
    #[must_use]
    pub const fn failure(&self) -> &ReachabilityLiveOwnerFirstOwnerTxnOperation {
        &self.failure
    }

    /// Returns the exact canonical `Current` successor retained by this create plan.
    #[must_use]
    pub const fn successor(&self) -> &ReachabilityLiveOwnerAuthorityRecord {
        &self.successor
    }
}

/// Retained first-owner evidence coupling one committed fence allocation to one exact create plan.
///
/// Construction is private to the control-plane preparation path. Downstream consumers may inspect
/// the exact allocation and transaction but cannot mint arbitrary first-owner evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerFirstOwnerHandoff {
    allocation: FenceSequenceAllocationResolved,
    transaction: ReachabilityLiveOwnerFirstOwnerTxnPlan,
}

impl ReachabilityLiveOwnerFirstOwnerHandoff {
    /// Returns the exact committed C02f-AQ allocation authorizing the successor fence.
    #[must_use]
    pub const fn allocation(&self) -> &FenceSequenceAllocationResolved {
        &self.allocation
    }

    /// Returns the exact create-only transaction plan bound to that allocation.
    #[must_use]
    pub const fn transaction(&self) -> &ReachabilityLiveOwnerFirstOwnerTxnPlan {
        &self.transaction
    }

    /// Consumes the retained evidence and returns its exact parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FenceSequenceAllocationResolved,
        ReachabilityLiveOwnerFirstOwnerTxnPlan,
    ) {
        (self.allocation, self.transaction)
    }
}

/// Fail-closed deterministic first-owner planning error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReachabilityLiveOwnerFirstOwnerPlanError {
    /// The supplied allocation did not authorize a canonical committed live-owner fence.
    Allocation(FenceSequenceLiveOwnerBridgeError),
    /// Canonical live-owner key/record encoding failed.
    Codec(ReachabilityLiveOwnerCodecError),
}

impl fmt::Display for ReachabilityLiveOwnerFirstOwnerPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation(error) => {
                write!(formatter, "first-owner allocation is invalid: {error}")
            }
            Self::Codec(error) => {
                write!(formatter, "first-owner live-owner encoding failed: {error}")
            }
        }
    }
}

impl std::error::Error for ReachabilityLiveOwnerFirstOwnerPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Codec(error) => Some(error),
        }
    }
}

impl From<FenceSequenceLiveOwnerBridgeError> for ReachabilityLiveOwnerFirstOwnerPlanError {
    fn from(value: FenceSequenceLiveOwnerBridgeError) -> Self {
        Self::Allocation(value)
    }
}

impl From<ReachabilityLiveOwnerCodecError> for ReachabilityLiveOwnerFirstOwnerPlanError {
    fn from(value: ReachabilityLiveOwnerCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Builds one exact create-only first-owner handoff from already-authoritative typed inputs.
///
/// The supplied allocation must already be C02f-AQ `Committed`; its canonical 64/64 fence is reused
/// exactly once in the intended `Current` successor. `attempt_id` is supplied by the later C02f-BH
/// generation boundary. This function does not generate randomness, read provider state or execute
/// the returned plan.
///
/// # Errors
///
/// Returns a fail-closed error when the allocation is not committed/canonical or when exact key or
/// record encoding fails.
pub(super) fn plan_first_owner_from_allocation(
    peer: &PeerConnectivityIdentity,
    allocation: FenceSequenceAllocationResolved,
    attempt_id: AuthorityAttemptId,
) -> Result<ReachabilityLiveOwnerFirstOwnerHandoff, ReachabilityLiveOwnerFirstOwnerPlanError> {
    let fence = canonical_live_owner_fence(&allocation)?;
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence, attempt_id);
    let key = encode_live_owner_key(peer)?;
    let value = encode_live_owner_record(&successor)?;

    let transaction = ReachabilityLiveOwnerFirstOwnerTxnPlan {
        compare: ReachabilityLiveOwnerFirstOwnerTxnCompare::KeyVersionZero { key: key.clone() },
        success: ReachabilityLiveOwnerFirstOwnerTxnOperation::Put {
            key: key.clone(),
            value,
        },
        failure: ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key },
        successor,
    };

    Ok(ReachabilityLiveOwnerFirstOwnerHandoff {
        allocation,
        transaction,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Future,
        task::{Context, Poll, Waker},
        thread,
    };

    use prw_connectivity::TransportIdentity;
    use prw_core::DeviceId;

    use super::*;
    use crate::{
        fence_sequence::{
            FenceSequenceHead, FenceSequenceHeadObservation, FenceSequenceReobservation,
            SequenceAllocationAttemptId, encode_head, plan_allocation,
        },
        fence_sequence_allocation_orchestrator::{
            FenceSequenceAllocationAuthority, FenceSequenceAllocationResolvedOutcome,
            FenceSequenceAllocationSubmissionOutcome,
            resolve_fence_sequence_allocation_with_reconciliation,
        },
        reachability_live_owner_codec::{LiveOwnerLifecycle, encode_live_owner_key},
        recovery_epoch::RecoveryEpoch,
    };

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => thread::yield_now(),
            }
        }
    }

    struct AllocationAuthority {
        first: FenceSequenceAllocationSubmissionOutcome,
    }

    impl FenceSequenceAllocationAuthority for AllocationAuthority {
        type Error = Infallible;

        async fn submit_allocation(
            &mut self,
            _plan: crate::fence_sequence::FenceSequenceAllocationPlan,
        ) -> Result<FenceSequenceAllocationSubmissionOutcome, Self::Error> {
            Ok(self.first)
        }

        async fn fresh_reobserve(
            &mut self,
            _plan: crate::fence_sequence::FenceSequenceAllocationPlan,
        ) -> Result<FenceSequenceReobservation, Self::Error> {
            Ok(FenceSequenceReobservation::Committed)
        }
    }

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero TransportIdentity"),
        )
    }

    fn allocation_plan() -> crate::fence_sequence::FenceSequenceAllocationPlan {
        let epoch = RecoveryEpoch::new(7).expect("non-zero epoch");
        let head = FenceSequenceHead {
            epoch,
            high_water: 40,
        };
        let predecessor = FenceSequenceHeadObservation::new(encode_head(head).to_vec(), 17)
            .expect("valid head observation");
        plan_allocation(
            predecessor,
            SequenceAllocationAttemptId::new([3; 32]).expect("non-zero allocation attempt"),
        )
        .expect("allocation plan")
    }

    fn resolved_allocation(
        outcome: FenceSequenceAllocationSubmissionOutcome,
    ) -> FenceSequenceAllocationResolved {
        let mut authority = AllocationAuthority { first: outcome };
        block_on(resolve_fence_sequence_allocation_with_reconciliation(
            &mut authority,
            allocation_plan(),
        ))
        .expect("terminal allocation")
    }

    #[test]
    fn committed_allocation_builds_exact_version_zero_create_plan() {
        let allocation = resolved_allocation(FenceSequenceAllocationSubmissionOutcome::Applied);
        assert_eq!(
            allocation.outcome(),
            FenceSequenceAllocationResolvedOutcome::Committed
        );
        let peer = peer("bk-first-owner", 5);
        let attempt = AuthorityAttemptId::new([6; 32]).expect("non-zero authority attempt");
        let expected_fence = canonical_live_owner_fence(&allocation).expect("canonical fence");
        let expected_key = encode_live_owner_key(&peer).expect("canonical key");

        let handoff = plan_first_owner_from_allocation(&peer, allocation, attempt)
            .expect("first-owner handoff");
        let transaction = handoff.transaction();

        assert_eq!(transaction.successor().peer(), &peer);
        assert_eq!(
            transaction.successor().lifecycle(),
            LiveOwnerLifecycle::Current
        );
        assert_eq!(transaction.successor().fence(), expected_fence);
        assert_eq!(transaction.successor().attempt_id(), attempt);
        assert_eq!(
            transaction.compare(),
            &ReachabilityLiveOwnerFirstOwnerTxnCompare::KeyVersionZero {
                key: expected_key.clone()
            }
        );
        assert!(matches!(
            transaction.success(),
            ReachabilityLiveOwnerFirstOwnerTxnOperation::Put { key, .. } if key == &expected_key
        ));
        assert_eq!(
            transaction.failure(),
            &ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key: expected_key }
        );
    }

    #[test]
    fn success_put_bytes_are_exact_canonical_successor_bytes() {
        let allocation = resolved_allocation(FenceSequenceAllocationSubmissionOutcome::Applied);
        let peer = peer("bk-canonical-put", 7);
        let attempt = AuthorityAttemptId::new([8; 32]).expect("non-zero authority attempt");
        let handoff = plan_first_owner_from_allocation(&peer, allocation, attempt)
            .expect("first-owner handoff");

        let ReachabilityLiveOwnerFirstOwnerTxnOperation::Put { value, .. } =
            handoff.transaction().success()
        else {
            panic!("first-owner success branch must be Put")
        };
        assert_eq!(
            value,
            &encode_live_owner_record(handoff.transaction().successor())
                .expect("canonical successor bytes")
        );
    }

    #[test]
    fn superseded_allocation_cannot_mint_first_owner_evidence() {
        let allocation =
            resolved_allocation(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::Superseded,
            ));
        assert_eq!(
            allocation.outcome(),
            FenceSequenceAllocationResolvedOutcome::Superseded
        );
        let peer = peer("bk-superseded", 9);
        let attempt = AuthorityAttemptId::new([10; 32]).expect("non-zero authority attempt");

        assert!(matches!(
            plan_first_owner_from_allocation(&peer, allocation, attempt),
            Err(ReachabilityLiveOwnerFirstOwnerPlanError::Allocation(
                FenceSequenceLiveOwnerBridgeError::AllocationNotCommitted
            ))
        ));
    }
}
