//! Phase 152 C02f-BP dedicated first-owner etcd execution and bounded reconciliation.
//!
//! C02f-BO selected this provider-owned path for the already-prepared first-owner handoff. The
//! operation uses the existing [`ReachabilityLiveOwnerEtcdStore`] KV client, submits only the exact
//! retained `version == 0` create transaction, and performs mandatory fresh linearizable
//! re-observation before the one permitted exact reissue. It does not select endpoints, construct an
//! etcd client, allocate fences, generate attempt IDs, re-enter acquisition preparation, activate a
//! runtime, or compose the full asynchronous authority.

use std::{fmt, future::Future};

use etcd_client::{Compare, CompareOp, Txn, TxnOp, TxnOpResponse};
use prw_connectivity::PeerConnectivityIdentity;

use super::{ReachabilityLiveOwnerEtcdError, ReachabilityLiveOwnerEtcdStore, decode_exact_get};
use crate::{
    fence_sequence_allocation_orchestrator::FenceSequenceAllocationResolvedOutcome,
    fence_sequence_live_owner_bridge::{
        FenceSequenceLiveOwnerBridgeError, canonical_live_owner_fence,
    },
    reachability_acquisition_evidence::{
        ReachabilityLiveOwnerFirstOwnerHandoff, ReachabilityLiveOwnerFirstOwnerTxnCompare,
        ReachabilityLiveOwnerFirstOwnerTxnOperation, ReachabilityLiveOwnerFirstOwnerTxnPlan,
    },
    reachability_live_owner_codec::{
        LiveOwnerLifecycle, ReachabilityLiveOwnerCodecError, encode_live_owner_key,
        encode_live_owner_record,
    },
    reachability_live_owner_txn::LiveOwnerObservation,
};

/// Provider-owned terminal first-owner outcome after a definitive response or bounded reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerFirstOwnerResolvedOutcome {
    /// The exact retained first-owner create is authoritatively proven committed.
    Committed,
    /// A definitive `version == 0` compare failure returned authoritative exact-key state.
    CompareFailed(LiveOwnerObservation),
    /// A fresh authoritative re-observation found another valid record for the same exact peer.
    Superseded(LiveOwnerObservation),
}

/// Exact retained first-owner handoff plus its terminal provider-owned outcome.
///
/// Construction is private to this provider module. Downstream code may inspect the exact retained
/// evidence and terminal outcome but cannot arbitrarily mint resolved provider evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerResolvedFirstOwner {
    handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
    outcome: ReachabilityLiveOwnerFirstOwnerResolvedOutcome,
}

impl ReachabilityLiveOwnerResolvedFirstOwner {
    /// Returns the exact first-owner handoff consumed by provider execution.
    #[must_use]
    pub const fn handoff(&self) -> &ReachabilityLiveOwnerFirstOwnerHandoff {
        &self.handoff
    }

    /// Returns the terminal provider-owned first-owner outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ReachabilityLiveOwnerFirstOwnerResolvedOutcome {
        &self.outcome
    }
}

/// Fail-closed first-owner provider execution/reconciliation error.
#[derive(Debug)]
pub enum ReachabilityLiveOwnerFirstOwnerExecutionError {
    /// Existing exact-key etcd read/codec validation failed.
    Etcd(ReachabilityLiveOwnerEtcdError),
    /// The retained committed allocation could not reproduce its canonical live-owner fence.
    Allocation(FenceSequenceLiveOwnerBridgeError),
    /// Canonical live-owner key/value reconstruction failed while validating retained evidence.
    Codec(ReachabilityLiveOwnerCodecError),
    /// Retained handoff/transaction evidence contradicts the BO-selected create-only shape.
    InvalidRetainedHandoff,
    /// A definitive compare-failure branch did not return the required authoritative observation.
    MissingCompareFailureObservation,
    /// A scripted/provider observation was not bound to the exact retained first-owner peer/key.
    InvalidReobservation,
    /// The one permitted exact reissue remained authoritatively proven not committed.
    ReissueLimitReached,
    /// A definitive etcd transaction response did not contain exactly the selected branch response.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for ReachabilityLiveOwnerFirstOwnerExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Etcd(error) => write!(formatter, "{error}"),
            Self::Allocation(error) => write!(formatter, "{error}"),
            Self::Codec(error) => write!(formatter, "{error}"),
            Self::InvalidRetainedHandoff => formatter.write_str(
                "retained first-owner handoff contradicts the selected create-only transaction",
            ),
            Self::MissingCompareFailureObservation => formatter.write_str(
                "first-owner compare failure returned no authoritative exact-key observation",
            ),
            Self::InvalidReobservation => formatter.write_str(
                "first-owner re-observation was not bound to the exact retained peer/key",
            ),
            Self::ReissueLimitReached => formatter.write_str(
                "first-owner create remained proven not committed after the one permitted exact reissue",
            ),
            Self::UnexpectedTxnResponseShape => formatter.write_str(
                "first-owner etcd Txn returned an unexpected branch response shape",
            ),
        }
    }
}

impl std::error::Error for ReachabilityLiveOwnerFirstOwnerExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Etcd(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::InvalidRetainedHandoff
            | Self::MissingCompareFailureObservation
            | Self::InvalidReobservation
            | Self::ReissueLimitReached
            | Self::UnexpectedTxnResponseShape => None,
        }
    }
}

impl From<ReachabilityLiveOwnerEtcdError> for ReachabilityLiveOwnerFirstOwnerExecutionError {
    fn from(value: ReachabilityLiveOwnerEtcdError) -> Self {
        Self::Etcd(value)
    }
}

impl From<FenceSequenceLiveOwnerBridgeError> for ReachabilityLiveOwnerFirstOwnerExecutionError {
    fn from(value: FenceSequenceLiveOwnerBridgeError) -> Self {
        Self::Allocation(value)
    }
}

impl From<ReachabilityLiveOwnerCodecError> for ReachabilityLiveOwnerFirstOwnerExecutionError {
    fn from(value: ReachabilityLiveOwnerCodecError) -> Self {
        Self::Codec(value)
    }
}

impl ReachabilityLiveOwnerEtcdStore {
    /// Executes one exact retained first-owner handoff with bounded BO-selected reconciliation.
    ///
    /// A non-definitive transaction RPC outcome never triggers immediate retransmission. The exact
    /// key is first re-observed through a fresh default-linearizable Get. Only authoritative absence
    /// (`ProvenNotCommitted`) permits one deliberate reissue of the identical retained transaction.
    /// A second indeterminate submission is re-observed once more and can never cause a third Txn.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for contradictory retained evidence, provider/read/codec failure,
    /// malformed transaction response shape, invalid re-observation, or exhaustion of the single
    /// exact-reissue budget.
    pub async fn execute_first_owner_with_reconciliation(
        &mut self,
        handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
    ) -> Result<
        ReachabilityLiveOwnerResolvedFirstOwner,
        ReachabilityLiveOwnerFirstOwnerExecutionError,
    > {
        validate_first_owner_handoff(&handoff)?;
        let mut io = EtcdFirstOwnerIo { store: self };
        resolve_first_owner(&mut io, handoff).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FirstOwnerDefinitiveMutation {
    Committed,
    CompareFailed(LiveOwnerObservation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FirstOwnerMutationExecution {
    Definitive(FirstOwnerDefinitiveMutation),
    Indeterminate,
}

trait FirstOwnerMutationIo {
    fn execute<'a>(
        &'a mut self,
        plan: &'a ReachabilityLiveOwnerFirstOwnerTxnPlan,
    ) -> impl Future<
        Output = Result<FirstOwnerMutationExecution, ReachabilityLiveOwnerFirstOwnerExecutionError>,
    > + 'a;

    fn linearizable_observation<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<
            Option<LiveOwnerObservation>,
            ReachabilityLiveOwnerFirstOwnerExecutionError,
        >,
    > + 'a;
}

struct EtcdFirstOwnerIo<'a> {
    store: &'a mut ReachabilityLiveOwnerEtcdStore,
}

impl FirstOwnerMutationIo for EtcdFirstOwnerIo<'_> {
    async fn execute<'a>(
        &'a mut self,
        plan: &'a ReachabilityLiveOwnerFirstOwnerTxnPlan,
    ) -> Result<FirstOwnerMutationExecution, ReachabilityLiveOwnerFirstOwnerExecutionError> {
        let transaction = build_first_owner_etcd_transaction(plan)?;
        let Ok(response) = self.store.kv.txn(transaction).await else {
            return Ok(FirstOwnerMutationExecution::Indeterminate);
        };
        classify_first_owner_transaction_response(plan, &response)
            .map(FirstOwnerMutationExecution::Definitive)
    }

    async fn linearizable_observation<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> Result<Option<LiveOwnerObservation>, ReachabilityLiveOwnerFirstOwnerExecutionError> {
        self.store
            .linearizable_observation(peer)
            .await
            .map_err(ReachabilityLiveOwnerFirstOwnerExecutionError::Etcd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FirstOwnerReobservation {
    Committed,
    ProvenNotCommitted,
    Superseded(LiveOwnerObservation),
}

async fn resolve_first_owner<I>(
    io: &mut I,
    handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
) -> Result<ReachabilityLiveOwnerResolvedFirstOwner, ReachabilityLiveOwnerFirstOwnerExecutionError>
where
    I: FirstOwnerMutationIo,
{
    match io.execute(handoff.transaction()).await? {
        FirstOwnerMutationExecution::Definitive(outcome) => {
            return resolve_definitive_first_owner(handoff, outcome);
        }
        FirstOwnerMutationExecution::Indeterminate => {}
    }

    let first_observation = io
        .linearizable_observation(handoff.transaction().successor().peer())
        .await?;
    match classify_first_owner_reobservation(&handoff, first_observation)? {
        FirstOwnerReobservation::Committed => {
            return Ok(resolved_first_owner(
                handoff,
                ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Committed,
            ));
        }
        FirstOwnerReobservation::Superseded(observation) => {
            return Ok(resolved_first_owner(
                handoff,
                ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Superseded(observation),
            ));
        }
        FirstOwnerReobservation::ProvenNotCommitted => {}
    }

    match io.execute(handoff.transaction()).await? {
        FirstOwnerMutationExecution::Definitive(outcome) => {
            return resolve_definitive_first_owner(handoff, outcome);
        }
        FirstOwnerMutationExecution::Indeterminate => {}
    }

    let second_observation = io
        .linearizable_observation(handoff.transaction().successor().peer())
        .await?;
    match classify_first_owner_reobservation(&handoff, second_observation)? {
        FirstOwnerReobservation::Committed => Ok(resolved_first_owner(
            handoff,
            ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Committed,
        )),
        FirstOwnerReobservation::Superseded(observation) => Ok(resolved_first_owner(
            handoff,
            ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Superseded(observation),
        )),
        FirstOwnerReobservation::ProvenNotCommitted => {
            Err(ReachabilityLiveOwnerFirstOwnerExecutionError::ReissueLimitReached)
        }
    }
}

fn resolve_definitive_first_owner(
    handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
    outcome: FirstOwnerDefinitiveMutation,
) -> Result<ReachabilityLiveOwnerResolvedFirstOwner, ReachabilityLiveOwnerFirstOwnerExecutionError>
{
    let outcome = match outcome {
        FirstOwnerDefinitiveMutation::Committed => {
            ReachabilityLiveOwnerFirstOwnerResolvedOutcome::Committed
        }
        FirstOwnerDefinitiveMutation::CompareFailed(observation) => {
            validate_terminal_observation(&handoff, &observation)?;
            ReachabilityLiveOwnerFirstOwnerResolvedOutcome::CompareFailed(observation)
        }
    };
    Ok(resolved_first_owner(handoff, outcome))
}

const fn resolved_first_owner(
    handoff: ReachabilityLiveOwnerFirstOwnerHandoff,
    outcome: ReachabilityLiveOwnerFirstOwnerResolvedOutcome,
) -> ReachabilityLiveOwnerResolvedFirstOwner {
    ReachabilityLiveOwnerResolvedFirstOwner { handoff, outcome }
}

fn classify_first_owner_reobservation(
    handoff: &ReachabilityLiveOwnerFirstOwnerHandoff,
    observation: Option<LiveOwnerObservation>,
) -> Result<FirstOwnerReobservation, ReachabilityLiveOwnerFirstOwnerExecutionError> {
    let Some(observation) = observation else {
        return Ok(FirstOwnerReobservation::ProvenNotCommitted);
    };
    validate_terminal_observation(handoff, &observation)?;
    if observation.record() == handoff.transaction().successor() {
        Ok(FirstOwnerReobservation::Committed)
    } else {
        Ok(FirstOwnerReobservation::Superseded(observation))
    }
}

fn validate_terminal_observation(
    handoff: &ReachabilityLiveOwnerFirstOwnerHandoff,
    observation: &LiveOwnerObservation,
) -> Result<(), ReachabilityLiveOwnerFirstOwnerExecutionError> {
    let expected_peer = handoff.transaction().successor().peer();
    let expected_key = encode_live_owner_key(expected_peer)?;
    if observation.key() != expected_key.as_slice() || observation.record().peer() != expected_peer
    {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidReobservation);
    }
    Ok(())
}

fn validate_first_owner_handoff(
    handoff: &ReachabilityLiveOwnerFirstOwnerHandoff,
) -> Result<(), ReachabilityLiveOwnerFirstOwnerExecutionError> {
    if handoff.allocation().outcome() != FenceSequenceAllocationResolvedOutcome::Committed {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }
    let expected_fence = canonical_live_owner_fence(handoff.allocation())?;
    let successor = handoff.transaction().successor();
    if successor.lifecycle() != LiveOwnerLifecycle::Current || successor.fence() != expected_fence {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }
    validate_first_owner_transaction_plan(handoff.transaction())
}

fn validate_first_owner_transaction_plan(
    plan: &ReachabilityLiveOwnerFirstOwnerTxnPlan,
) -> Result<(), ReachabilityLiveOwnerFirstOwnerExecutionError> {
    let successor = plan.successor();
    if successor.lifecycle() != LiveOwnerLifecycle::Current {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }

    let expected_key = encode_live_owner_key(successor.peer())?;
    let expected_value = encode_live_owner_record(successor)?;

    if !matches!(
        plan.compare(),
        ReachabilityLiveOwnerFirstOwnerTxnCompare::KeyVersionZero { key } if key == &expected_key
    ) {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }
    if !matches!(
        plan.success(),
        ReachabilityLiveOwnerFirstOwnerTxnOperation::Put { key, value }
            if key == &expected_key && value == &expected_value
    ) {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }
    if !matches!(
        plan.failure(),
        ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key }
            if key == &expected_key
    ) {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::InvalidRetainedHandoff);
    }

    Ok(())
}

fn build_first_owner_etcd_transaction(
    plan: &ReachabilityLiveOwnerFirstOwnerTxnPlan,
) -> Result<Txn, ReachabilityLiveOwnerFirstOwnerExecutionError> {
    validate_first_owner_transaction_plan(plan)?;

    let ReachabilityLiveOwnerFirstOwnerTxnCompare::KeyVersionZero { key: compare_key } =
        plan.compare();
    let ReachabilityLiveOwnerFirstOwnerTxnOperation::Put { key, value } = plan.success() else {
        unreachable!("validated first-owner success branch is Put")
    };
    let ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key: failure_key } =
        plan.failure()
    else {
        unreachable!("validated first-owner failure branch is linearizable Get")
    };

    Ok(Txn::new()
        .when(vec![Compare::version(
            compare_key.clone(),
            CompareOp::Equal,
            0,
        )])
        .and_then(vec![TxnOp::put(key.clone(), value.clone(), None)])
        .or_else(vec![TxnOp::get(failure_key.clone(), None)]))
}

fn classify_first_owner_transaction_response(
    plan: &ReachabilityLiveOwnerFirstOwnerTxnPlan,
    response: &etcd_client::TxnResponse,
) -> Result<FirstOwnerDefinitiveMutation, ReachabilityLiveOwnerFirstOwnerExecutionError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::UnexpectedTxnResponseShape);
        }
        return Ok(FirstOwnerDefinitiveMutation::Committed);
    }

    let [TxnOpResponse::Get(get_response)] = responses.as_slice() else {
        return Err(ReachabilityLiveOwnerFirstOwnerExecutionError::UnexpectedTxnResponseShape);
    };
    let ReachabilityLiveOwnerFirstOwnerTxnOperation::LinearizableGet { key } = plan.failure()
    else {
        unreachable!("validated first-owner failure branch is linearizable Get")
    };
    let observation = decode_exact_get(key, get_response)?
        .ok_or(ReachabilityLiveOwnerFirstOwnerExecutionError::MissingCompareFailureObservation)?;
    Ok(FirstOwnerDefinitiveMutation::CompareFailed(observation))
}
