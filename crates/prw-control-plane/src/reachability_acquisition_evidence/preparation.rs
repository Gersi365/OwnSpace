//! Phase 152 C02f-BM narrow live-owner acquisition-handoff preparation facade.
//!
//! C02f-BJ selected one control-plane preparation boundary whose public operation accepts only an
//! exact `PeerConnectivityIdentity`. C02f-BL materialized production generation for the two typed
//! attempt-ID domains. This module composes those already-validated seams with the existing
//! live-owner read, fence-sequence allocation, replacement planning/retention, and first-owner
//! evidence primitives.
//!
//! C02f-BW corrects the deferred provider-construction boundary: preparation no longer accepts one
//! `KvClient` that is cloned into both authority roles. A crate-private constructor instead accepts
//! explicit live-owner and fence-allocator role-scoped clients. The later control-plane provider
//! bootstrap remains responsible for deriving both clients from one validated immutable logical
//! authority-cluster configuration. Endpoint selection, TLS materialization, credential loading and
//! `Client::connect` remain outside this boundary. C02f-BS adds a lifetime-bounded acquisition
//! execution capability over the exact live-owner store already owned here. C02f-BU adds a separate
//! lifetime-bounded lifecycle execution capability over that same store for only BF currentness and
//! BD release provider primitives. Neither capability exposes a raw store/client/configuration
//! handle or can outlive the mutable preparation borrow that created it.

use std::{fmt, num::NonZeroU128};

use etcd_client::KvClient;
use prw_connectivity::PeerConnectivityIdentity;

use super::{
    FenceSequenceLiveOwnerAcquisitionHandoff, ReachabilityLiveOwnerFirstOwnerHandoff,
    attempt_id_generation::{
        ReachabilityAttemptIdGenerationError, generate_authority_attempt_id,
        generate_sequence_allocation_attempt_id,
    },
    first_owner::plan_first_owner_from_allocation,
};
use crate::{
    fence_sequence::{
        FenceSequenceAllocationPlan, FenceSequenceHeadObservation, SequenceAllocationAttemptId,
        plan_allocation,
    },
    fence_sequence_allocation_etcd::FenceSequenceAllocationEtcdStore,
    fence_sequence_allocation_orchestrator::{
        FenceSequenceAllocationResolved, FenceSequenceAllocationResolvedOutcome,
        resolve_fence_sequence_allocation_with_reconciliation,
    },
    fence_sequence_live_owner_bridge::plan_live_owner_acquisition_from_allocation,
    fence_sequence_live_owner_handoff::retain_live_owner_acquisition_handoff,
    reachability_live_owner_codec::{AuthorityAttemptId, ReachabilityLiveOwnerAuthorityRecord},
    reachability_live_owner_etcd::{
        ReachabilityLiveOwnerEtcdError, ReachabilityLiveOwnerEtcdStore,
        ReachabilityLiveOwnerFirstOwnerExecutionError, ReachabilityLiveOwnerResolvedFirstOwner,
        reconciliation::{
            ReachabilityLiveOwnerReconciliationError, ReachabilityLiveOwnerResolvedMutation,
            ReachabilityLiveOwnerResolvedRelease,
        },
    },
    reachability_live_owner_txn::{LiveOwnerObservation, LiveOwnerProviderCurrentness},
};

/// Provider-neutral terminal preparation result selected by C02f-BJ.
///
/// The evidence variants intentionally retain their already-validated handoff objects by value so
/// the selected public result shape and ownership semantics remain unchanged at this checkpoint.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerPreparedAcquisition {
    /// Exact retained replacement evidence for later live-owner provider execution.
    Replacement(FenceSequenceLiveOwnerAcquisitionHandoff),
    /// Exact retained absent-key creation evidence for later first-owner provider execution.
    FirstOwner(ReachabilityLiveOwnerFirstOwnerHandoff),
    /// The exact AQ allocation was authoritatively superseded; this logical preparation is terminal.
    Superseded,
}

/// Bounded fail-closed preparation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerPreparationError {
    /// The authoritative live-owner predecessor-or-absence read was unavailable or invalid.
    LiveOwnerRead,
    /// The initialized PRWF head read was unavailable or invalid.
    FenceSequenceHeadRead,
    /// Normal preparation found no initialized PRWF head.
    MissingFenceSequenceHead,
    /// Fresh sequence-allocation attempt-ID generation failed closed.
    SequenceAttemptIdGeneration,
    /// Deterministic AJ allocation planning rejected the exact head/attempt pair.
    AllocationPlanning,
    /// AQ allocation execution/reconciliation failed before a terminal committed/superseded result.
    AllocationResolution,
    /// Fresh independent live-owner authority attempt-ID generation failed closed.
    AuthorityAttemptIdGeneration,
    /// Existing AR replacement planning rejected the retained inputs.
    ReplacementPlanning,
    /// Existing AS replacement evidence retention rejected the retained observation/plan pair.
    ReplacementRetention,
    /// Existing BK first-owner plan/evidence construction rejected the retained inputs.
    FirstOwnerPlanning,
}

impl fmt::Display for ReachabilityLiveOwnerPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::LiveOwnerRead => "live-owner preparation predecessor read failed",
            Self::FenceSequenceHeadRead => "live-owner preparation fence-sequence head read failed",
            Self::MissingFenceSequenceHead => {
                "live-owner preparation requires an initialized fence-sequence head"
            }
            Self::SequenceAttemptIdGeneration => {
                "live-owner preparation sequence-allocation attempt-ID generation failed"
            }
            Self::AllocationPlanning => "live-owner preparation allocation planning failed",
            Self::AllocationResolution => "live-owner preparation allocation resolution failed",
            Self::AuthorityAttemptIdGeneration => {
                "live-owner preparation authority attempt-ID generation failed"
            }
            Self::ReplacementPlanning => "live-owner replacement preparation planning failed",
            Self::ReplacementRetention => "live-owner replacement preparation retention failed",
            Self::FirstOwnerPlanning => "live-owner first-owner preparation planning failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReachabilityLiveOwnerPreparationError {}

/// Narrow C02f-BJ preparation facade with C02f-BW role-separated provider construction.
///
/// The raw provider pairing seam is crate-private to `prw-control-plane`. It accepts distinct
/// role-scoped clients so one authenticated context is never cloned across live-owner and
/// fence-allocation authority roles. A later provider-bootstrap tranche must derive both clients
/// from one validated immutable logical authority-cluster configuration before constructing this
/// facade. The preparation itself exposes no raw client or provider configuration handle.
pub struct ReachabilityLiveOwnerAcquisitionPreparation {
    live_owner: ReachabilityLiveOwnerEtcdStore,
    allocation: FenceSequenceAllocationEtcdStore,
}

/// C02f-BS scoped provider-execution capability borrowed from one preparation facade.
///
/// Construction is private to [`ReachabilityLiveOwnerAcquisitionPreparation`]. The capability owns
/// no provider handle and exposes no raw store, `KvClient`, endpoint/configuration state, generic
/// transaction entry point, currentness, or release operation. It can execute only the exact
/// replacement and first-owner acquisition evidence shapes already selected before C02f-BS.
#[must_use = "the acquisition execution capability must remain scoped to its preparation borrow"]
pub struct ReachabilityLiveOwnerAcquisitionExecution<'a> {
    live_owner: &'a mut ReachabilityLiveOwnerEtcdStore,
}

impl ReachabilityLiveOwnerAcquisitionExecution<'_> {
    /// Executes one exact retained replacement handoff through the existing C02f-AE reconciliation.
    ///
    /// `before` and `successor` are projected only from the retained handoff. No independent caller
    /// input can replace either value through this capability.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed C02f-AE provider/reconciliation error unchanged.
    pub async fn execute_replacement_with_reconciliation(
        &mut self,
        handoff: &FenceSequenceLiveOwnerAcquisitionHandoff,
    ) -> Result<ReachabilityLiveOwnerResolvedMutation, ReachabilityLiveOwnerReconciliationError>
    {
        let before = handoff.observation().clone();
        let successor: ReachabilityLiveOwnerAuthorityRecord =
            handoff.acquisition().transaction().successor().clone();
        self.live_owner
            .execute_acquisition_with_reconciliation(before, successor)
            .await
    }

    /// Executes one exact retained first-owner handoff through the existing C02f-BO/BP path.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed first-owner provider/reconciliation error unchanged.
    pub async fn execute_first_owner_with_reconciliation(
        &mut self,
        handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
    ) -> Result<
        ReachabilityLiveOwnerResolvedFirstOwner,
        ReachabilityLiveOwnerFirstOwnerExecutionError,
    > {
        self.live_owner
            .execute_first_owner_with_reconciliation(handoff)
            .await
    }
}

/// C02f-BU scoped lifecycle provider capability borrowed from one preparation facade.
///
/// This capability is deliberately separate from C02f-BS acquisition execution. It owns no provider
/// handle, exposes no raw store/client/configuration or generic transaction API, and can invoke only
/// the provider primitives already consumed by BF currentness and BD release. It cannot outlive the
/// mutable preparation borrow that created it.
#[must_use = "the lifecycle execution capability must remain scoped to its preparation borrow"]
pub struct ReachabilityLiveOwnerLifecycleExecution<'a> {
    live_owner: &'a mut ReachabilityLiveOwnerEtcdStore,
}

impl ReachabilityLiveOwnerLifecycleExecution<'_> {
    /// Executes the exact existing C02f-AD authoritative currentness primitive.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed C02f-AD provider/classification error unchanged.
    pub async fn currentness(
        &mut self,
        peer: &PeerConnectivityIdentity,
        fence: NonZeroU128,
    ) -> Result<LiveOwnerProviderCurrentness, ReachabilityLiveOwnerEtcdError> {
        self.live_owner.currentness(peer, fence).await
    }

    /// Performs the exact existing C02f-AD default-linearizable live-owner observation.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed C02f-AD read/decode error unchanged.
    pub async fn linearizable_observation(
        &mut self,
        peer: &PeerConnectivityIdentity,
    ) -> Result<Option<LiveOwnerObservation>, ReachabilityLiveOwnerEtcdError> {
        self.live_owner.linearizable_observation(peer).await
    }

    /// Executes the exact existing C02f-AE bounded release reconciliation primitive.
    ///
    /// The bridge remains responsible for obtaining and retaining the initial observation and for
    /// semantic result mapping. This method does not perform an additional observation on its own.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed C02f-AE provider/reconciliation error unchanged.
    pub async fn execute_release_with_reconciliation(
        &mut self,
        peer: &PeerConnectivityIdentity,
        fence: NonZeroU128,
        observation: Option<LiveOwnerObservation>,
    ) -> Result<ReachabilityLiveOwnerResolvedRelease, ReachabilityLiveOwnerReconciliationError>
    {
        self.live_owner
            .execute_release_with_reconciliation(peer, fence, observation)
            .await
    }
}

impl ReachabilityLiveOwnerAcquisitionPreparation {
    /// Wraps the two already-created role-scoped etcd KV contexts without endpoint contact.
    ///
    /// The caller must be a `prw-control-plane` provider-bootstrap seam that derived both clients
    /// from one validated immutable logical authority-cluster configuration. The live-owner client
    /// is consumed only by the live-owner store and the fence-allocator client only by the
    /// fence-sequence allocation store; neither client is cloned across authority roles.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn from_role_scoped_clients(
        live_owner_kv: KvClient,
        fence_allocator_kv: KvClient,
    ) -> Self {
        Self {
            live_owner: ReachabilityLiveOwnerEtcdStore::new(live_owner_kv),
            allocation: FenceSequenceAllocationEtcdStore::new(fence_allocator_kv),
        }
    }

    /// Borrows only the acquisition execution capability for this exact preparation-owned provider.
    ///
    /// The returned value cannot outlive this mutable borrow and provides no accessor to the raw
    /// live-owner store or client. Creating the capability performs no provider I/O.
    pub const fn acquisition_execution(&mut self) -> ReachabilityLiveOwnerAcquisitionExecution<'_> {
        ReachabilityLiveOwnerAcquisitionExecution {
            live_owner: &mut self.live_owner,
        }
    }

    /// Borrows only the lifecycle execution capability for this exact preparation-owned provider.
    ///
    /// The returned value cannot outlive this mutable borrow and provides no accessor to the raw
    /// live-owner store or client. Creating the capability performs no provider I/O.
    pub const fn lifecycle_execution(&mut self) -> ReachabilityLiveOwnerLifecycleExecution<'_> {
        ReachabilityLiveOwnerLifecycleExecution {
            live_owner: &mut self.live_owner,
        }
    }

    /// Prepares one bounded live-owner acquisition attempt for exactly one peer.
    ///
    /// The operation preserves the selected BJ order: retain the initial live-owner observation,
    /// read the initialized PRWF head, generate one fresh sequence-allocation attempt ID, resolve
    /// exactly that AJ plan through AQ, then (only for a committed allocation) generate one fresh
    /// independent authority attempt ID and build either replacement or first-owner evidence.
    ///
    /// `Superseded` terminates this logical preparation without generating a live-owner authority
    /// attempt ID or automatically planning another allocation. A committed allocation is consumed
    /// even if subsequent attempt-ID generation or deterministic live-owner preparation fails.
    ///
    /// # Errors
    ///
    /// Returns a bounded fail-closed error for provider read/allocation failure, missing initialized
    /// PRWF state, attempt-ID generation failure, or deterministic evidence-construction failure.
    pub async fn prepare(
        &mut self,
        peer: &PeerConnectivityIdentity,
    ) -> Result<ReachabilityLiveOwnerPreparedAcquisition, ReachabilityLiveOwnerPreparationError>
    {
        let observation = self
            .live_owner
            .linearizable_observation(peer)
            .await
            .map_err(|_| ReachabilityLiveOwnerPreparationError::LiveOwnerRead)?;

        let head = self
            .allocation
            .linearizable_head()
            .await
            .map_err(|_| ReachabilityLiveOwnerPreparationError::FenceSequenceHeadRead)?
            .ok_or(ReachabilityLiveOwnerPreparationError::MissingFenceSequenceHead)?;

        let allocation_plan = plan_allocation_with(head, generate_sequence_allocation_attempt_id)?;
        let allocation = resolve_fence_sequence_allocation_with_reconciliation(
            &mut self.allocation,
            allocation_plan,
        )
        .await
        .map_err(|_| ReachabilityLiveOwnerPreparationError::AllocationResolution)?;

        finish_preparation_with(peer, observation, allocation, generate_authority_attempt_id)
    }
}

fn plan_allocation_with(
    predecessor: FenceSequenceHeadObservation,
    generate_attempt_id: impl FnOnce() -> Result<
        SequenceAllocationAttemptId,
        ReachabilityAttemptIdGenerationError,
    >,
) -> Result<FenceSequenceAllocationPlan, ReachabilityLiveOwnerPreparationError> {
    let attempt_id = generate_attempt_id()
        .map_err(|_| ReachabilityLiveOwnerPreparationError::SequenceAttemptIdGeneration)?;
    plan_allocation(predecessor, attempt_id)
        .map_err(|_| ReachabilityLiveOwnerPreparationError::AllocationPlanning)
}

fn finish_preparation_with(
    peer: &PeerConnectivityIdentity,
    observation: Option<LiveOwnerObservation>,
    allocation: FenceSequenceAllocationResolved,
    generate_attempt_id: impl FnOnce()
        -> Result<AuthorityAttemptId, ReachabilityAttemptIdGenerationError>,
) -> Result<ReachabilityLiveOwnerPreparedAcquisition, ReachabilityLiveOwnerPreparationError> {
    if allocation.outcome() == FenceSequenceAllocationResolvedOutcome::Superseded {
        return Ok(ReachabilityLiveOwnerPreparedAcquisition::Superseded);
    }

    let attempt_id = generate_attempt_id()
        .map_err(|_| ReachabilityLiveOwnerPreparationError::AuthorityAttemptIdGeneration)?;

    if let Some(observation) = observation {
        let acquisition =
            plan_live_owner_acquisition_from_allocation(&observation, peer, allocation, attempt_id)
                .map_err(|_| ReachabilityLiveOwnerPreparationError::ReplacementPlanning)?;
        let handoff = retain_live_owner_acquisition_handoff(observation, acquisition)
            .map_err(|_| ReachabilityLiveOwnerPreparationError::ReplacementRetention)?;
        Ok(ReachabilityLiveOwnerPreparedAcquisition::Replacement(
            handoff,
        ))
    } else {
        let handoff = plan_first_owner_from_allocation(peer, allocation, attempt_id)
            .map_err(|_| ReachabilityLiveOwnerPreparationError::FirstOwnerPlanning)?;
        Ok(ReachabilityLiveOwnerPreparedAcquisition::FirstOwner(
            handoff,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        convert::Infallible,
        future::Future,
        num::NonZeroU128,
        task::{Context, Poll, Waker},
        thread,
    };

    use prw_connectivity::TransportIdentity;
    use prw_core::DeviceId;

    use super::*;
    use crate::{
        fence_sequence::{FenceSequenceHead, FenceSequenceReobservation, encode_head},
        fence_sequence_allocation_orchestrator::{
            FenceSequenceAllocationAuthority, FenceSequenceAllocationSubmissionOutcome,
        },
        reachability_live_owner_codec::{
            ReachabilityLiveOwnerAuthorityRecord, encode_live_owner_key, encode_live_owner_record,
        },
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
            _plan: FenceSequenceAllocationPlan,
        ) -> Result<FenceSequenceAllocationSubmissionOutcome, Self::Error> {
            Ok(self.first)
        }

        async fn fresh_reobserve(
            &mut self,
            _plan: FenceSequenceAllocationPlan,
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

    fn head() -> FenceSequenceHeadObservation {
        let head = FenceSequenceHead {
            epoch: RecoveryEpoch::new(7).expect("non-zero epoch"),
            high_water: 40,
        };
        FenceSequenceHeadObservation::new(encode_head(head).to_vec(), 17)
            .expect("valid head observation")
    }

    fn resolved_allocation(
        outcome: FenceSequenceAllocationSubmissionOutcome,
        sequence_attempt: [u8; 32],
    ) -> FenceSequenceAllocationResolved {
        let plan = plan_allocation(
            head(),
            SequenceAllocationAttemptId::new(sequence_attempt).expect("non-zero sequence attempt"),
        )
        .expect("allocation plan");
        let mut authority = AllocationAuthority { first: outcome };
        block_on(resolve_fence_sequence_allocation_with_reconciliation(
            &mut authority,
            plan,
        ))
        .expect("terminal allocation")
    }

    fn observation(peer: PeerConnectivityIdentity) -> LiveOwnerObservation {
        let current = ReachabilityLiveOwnerAuthorityRecord::current(
            peer,
            NonZeroU128::new(5).expect("non-zero fence"),
            AuthorityAttemptId::new([8; 32]).expect("non-zero authority attempt"),
        );
        let released = current.released_successor();
        let key = encode_live_owner_key(released.peer()).expect("canonical key");
        let value = encode_live_owner_record(&released).expect("canonical record");
        LiveOwnerObservation::decode(key, value, 11).expect("valid observation")
    }

    #[test]
    fn allocation_planning_calls_sequence_generator_once_and_retains_exact_bytes() {
        let calls = Cell::new(0_u8);
        let expected = [3_u8; 32];
        let plan = plan_allocation_with(head(), || {
            calls.set(calls.get() + 1);
            Ok(SequenceAllocationAttemptId::new(expected).expect("non-zero attempt"))
        })
        .expect("allocation plan");

        assert_eq!(calls.get(), 1);
        assert_eq!(plan.attempt_id.as_bytes(), &expected);
    }

    #[test]
    fn replacement_preparation_retains_exact_peer_allocation_and_independent_authority_attempt() {
        let peer = peer("bm-replacement", 1);
        let observed = observation(peer.clone());
        let sequence_attempt = [3_u8; 32];
        let authority_attempt = [9_u8; 32];
        let allocation = resolved_allocation(
            FenceSequenceAllocationSubmissionOutcome::Applied,
            sequence_attempt,
        );
        let calls = Cell::new(0_u8);

        let prepared = finish_preparation_with(&peer, Some(observed.clone()), allocation, || {
            calls.set(calls.get() + 1);
            Ok(AuthorityAttemptId::new(authority_attempt).expect("non-zero authority attempt"))
        })
        .expect("replacement preparation");

        assert_eq!(calls.get(), 1);
        let ReachabilityLiveOwnerPreparedAcquisition::Replacement(handoff) = prepared else {
            panic!("expected replacement preparation")
        };
        assert_eq!(handoff.observation(), &observed);
        assert_eq!(
            handoff
                .acquisition()
                .allocation()
                .plan()
                .attempt_id
                .as_bytes(),
            &sequence_attempt
        );
        assert_eq!(
            handoff.acquisition().transaction().successor().peer(),
            &peer
        );
        assert_eq!(
            handoff
                .acquisition()
                .transaction()
                .successor()
                .attempt_id()
                .as_bytes(),
            &authority_attempt
        );
        assert_ne!(sequence_attempt, authority_attempt);
    }

    #[test]
    fn first_owner_preparation_retains_exact_peer_allocation_and_independent_authority_attempt() {
        let peer = peer("bm-first-owner", 2);
        let sequence_attempt = [4_u8; 32];
        let authority_attempt = [10_u8; 32];
        let allocation = resolved_allocation(
            FenceSequenceAllocationSubmissionOutcome::Applied,
            sequence_attempt,
        );

        let prepared = finish_preparation_with(&peer, None, allocation, || {
            Ok(AuthorityAttemptId::new(authority_attempt).expect("non-zero authority attempt"))
        })
        .expect("first-owner preparation");

        let ReachabilityLiveOwnerPreparedAcquisition::FirstOwner(handoff) = prepared else {
            panic!("expected first-owner preparation")
        };
        assert_eq!(
            handoff.allocation().plan().attempt_id.as_bytes(),
            &sequence_attempt
        );
        assert_eq!(handoff.transaction().successor().peer(), &peer);
        assert_eq!(
            handoff.transaction().successor().attempt_id().as_bytes(),
            &authority_attempt
        );
        assert_ne!(sequence_attempt, authority_attempt);
    }

    #[test]
    fn superseded_allocation_stops_without_authority_attempt_generation() {
        let peer = peer("bm-superseded", 3);
        let allocation = resolved_allocation(
            FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::Superseded,
            ),
            [5_u8; 32],
        );
        let calls = Cell::new(0_u8);

        let prepared = finish_preparation_with(&peer, None, allocation, || {
            calls.set(calls.get() + 1);
            Ok(AuthorityAttemptId::new([11; 32]).expect("non-zero authority attempt"))
        })
        .expect("superseded terminal preparation");

        assert_eq!(calls.get(), 0);
        assert_eq!(
            prepared,
            ReachabilityLiveOwnerPreparedAcquisition::Superseded
        );
    }

    #[test]
    fn attempt_id_generation_failures_remain_fail_closed() {
        assert_eq!(
            plan_allocation_with(head(), || {
                Err(ReachabilityAttemptIdGenerationError::RandomnessUnavailable)
            }),
            Err(ReachabilityLiveOwnerPreparationError::SequenceAttemptIdGeneration)
        );

        let peer = peer("bm-authority-failure", 4);
        let allocation = resolved_allocation(
            FenceSequenceAllocationSubmissionOutcome::Applied,
            [6_u8; 32],
        );
        assert_eq!(
            finish_preparation_with(&peer, None, allocation, || {
                Err(ReachabilityAttemptIdGenerationError::RandomnessUnavailable)
            }),
            Err(ReachabilityLiveOwnerPreparationError::AuthorityAttemptIdGeneration)
        );
    }
}
