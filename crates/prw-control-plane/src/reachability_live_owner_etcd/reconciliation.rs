//! Phase 152 C02f-AE bounded indeterminate-mutation reconciliation orchestration.
//!
//! C02f-Z selected mandatory linearizable re-observation and no blind mutation retry. C02f-AB
//! materialized the deterministic `Committed` / `ProvenNotCommitted` / `Superseded` classifiers,
//! while C02f-AD materialized real etcd Get/Txn wiring and classifies non-definitive Txn RPC errors
//! as `MutationIndeterminate`.
//!
//! This module connects those already-selected pieces without selecting endpoints, TLS/auth/RBAC,
//! runtime ownership, background tasks, recovery/bootstrap, fence allocation or attempt-ID
//! generation. One top-level mutation may deliberately reissue the exact retained transaction at
//! most once, and only after a fresh linearizable exact-key observation proves the first attempt did
//! not commit.

use std::{fmt, future::Future, num::NonZeroU128};

use prw_connectivity::PeerConnectivityIdentity;

use super::{ReachabilityLiveOwnerEtcdError, ReachabilityLiveOwnerEtcdStore};
use crate::{
    reachability_live_owner_codec::ReachabilityLiveOwnerAuthorityRecord,
    reachability_live_owner_txn::{
        LiveOwnerDefinitiveMutation, LiveOwnerObservation, LiveOwnerReconciliation,
        LiveOwnerTxnError, LiveOwnerTxnPlan, plan_acquisition, plan_release,
        reconcile_indeterminate_acquisition, reconcile_indeterminate_release,
    },
};

/// Provider-owned terminal outcome after a mutation is either answered definitively or reconciled.
///
/// `Committed` does not claim that the client received a successful etcd `TxnResponse`; it may also
/// mean a later authoritative linearizable observation proved that the retained intended successor
/// committed and remains the relevant terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerResolvedMutationOutcome {
    /// The exact intended mutation is proven committed.
    Committed,
    /// A definitive transaction compare failure returned authoritative exact-key state.
    CompareFailed(LiveOwnerObservation),
    /// A later authoritative state superseded the unresolved logical mutation.
    Superseded,
}

/// Exact retained transaction context plus its terminal C02f-AE provider-owned outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerResolvedMutation {
    plan: LiveOwnerTxnPlan,
    outcome: ReachabilityLiveOwnerResolvedMutationOutcome,
}

impl ReachabilityLiveOwnerResolvedMutation {
    /// Returns the exact deterministic transaction plan associated with this logical mutation.
    #[must_use]
    pub const fn plan(&self) -> &LiveOwnerTxnPlan {
        &self.plan
    }

    /// Returns the terminal provider-owned reconciliation outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ReachabilityLiveOwnerResolvedMutationOutcome {
        &self.outcome
    }
}

/// Provider-owned proof that one exact requested release was already not current.
///
/// The binding is intentionally minimal: only the exact logical peer and requested non-zero fence
/// survive the deterministic no-mutation classification. Construction is private to this module so
/// downstream consumers can observe, but cannot arbitrarily mint, provider-owned terminal evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerResolvedNotCurrent {
    peer: PeerConnectivityIdentity,
    fence: NonZeroU128,
}

impl ReachabilityLiveOwnerResolvedNotCurrent {
    const fn new(peer: PeerConnectivityIdentity, fence: NonZeroU128) -> Self {
        Self { peer, fence }
    }

    /// Returns the exact logical peer supplied to the validated release classification.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the exact non-zero fence supplied to the validated release classification.
    #[must_use]
    pub const fn fence(&self) -> NonZeroU128 {
        self.fence
    }
}

/// Terminal release result after pre-read classification and any bounded mutation reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerResolvedRelease {
    /// The supplied exact peer/fence was already not current, so no mutation was attempted.
    NotCurrent(ReachabilityLiveOwnerResolvedNotCurrent),
    /// A release mutation was attempted and reached a terminal provider-owned result.
    Mutation(Box<ReachabilityLiveOwnerResolvedMutation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LiveOwnerPlannedRelease {
    NotCurrent(ReachabilityLiveOwnerResolvedNotCurrent),
    Mutation(Box<LiveOwnerTxnPlan>),
}

fn plan_resolved_release(
    peer: &PeerConnectivityIdentity,
    fence: NonZeroU128,
    before: &LiveOwnerObservation,
) -> Result<LiveOwnerPlannedRelease, LiveOwnerTxnError> {
    let release = plan_release(peer, fence, Some(before))?;
    Ok(release.into_transaction().map_or_else(
        || {
            LiveOwnerPlannedRelease::NotCurrent(ReachabilityLiveOwnerResolvedNotCurrent::new(
                peer.clone(),
                fence,
            ))
        },
        |plan| LiveOwnerPlannedRelease::Mutation(Box::new(plan)),
    ))
}

/// Fail-closed C02f-AE real-provider orchestration error.
#[derive(Debug)]
pub enum ReachabilityLiveOwnerReconciliationError {
    /// Real etcd Get/Txn wiring failed outside the specifically reconciled indeterminate signal.
    Etcd(ReachabilityLiveOwnerEtcdError),
    /// Deterministic planning or re-observation classification rejected the state.
    Transaction(LiveOwnerTxnError),
    /// The one permitted deliberate reissue was again proven not committed after re-observation.
    ReissueLimitReached,
}

impl fmt::Display for ReachabilityLiveOwnerReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Etcd(error) => write!(formatter, "{error}"),
            Self::Transaction(error) => write!(formatter, "{error}"),
            Self::ReissueLimitReached => formatter.write_str(
                "live-owner mutation remained proven not committed after the one permitted reissue",
            ),
        }
    }
}

impl std::error::Error for ReachabilityLiveOwnerReconciliationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Etcd(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::ReissueLimitReached => None,
        }
    }
}

impl From<LiveOwnerTxnError> for ReachabilityLiveOwnerReconciliationError {
    fn from(value: LiveOwnerTxnError) -> Self {
        Self::Transaction(value)
    }
}

impl ReachabilityLiveOwnerEtcdStore {
    /// Executes one acquisition/replacement plan with bounded C02f-AE reconciliation.
    ///
    /// A non-definitive Txn RPC result never triggers an immediate retransmission. The exact key is
    /// first re-observed through a fresh linearizable Get. Only `ProvenNotCommitted` permits one
    /// deliberate reissue of the exact retained plan, including the same successor bytes, fence and
    /// authority-attempt ID. A second indeterminate result is re-observed again; it can never cause a
    /// third transaction submission.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for invalid planning, unavailable/corrupt/impossible
    /// re-observation, non-indeterminate provider failure, or exhaustion of the one-reissue bound.
    pub async fn execute_acquisition_with_reconciliation(
        &mut self,
        before: LiveOwnerObservation,
        successor: ReachabilityLiveOwnerAuthorityRecord,
    ) -> Result<ReachabilityLiveOwnerResolvedMutation, ReachabilityLiveOwnerReconciliationError>
    {
        let pending = LiveOwnerPendingMutation::acquisition(before, successor)?;
        let mut io = EtcdMutationIo { store: self };
        resolve_pending_mutation(&mut io, pending)
            .await
            .map_err(map_etcd_orchestration_error)
    }

    /// Executes one release with bounded C02f-AE reconciliation when the supplied owner is current.
    ///
    /// A stale/already-released peer/fence returns bound `NotCurrent` evidence without a mutation.
    /// An indeterminate release follows the same mandatory linearizable re-observation and one-reissue
    /// bound as acquisition, preserving the exact fence and authority-attempt ID in the canonical
    /// Released successor.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for missing established state, peer mismatch, unavailable/corrupt
    /// re-observation, non-indeterminate provider failure, or exhaustion of the one-reissue bound.
    pub async fn execute_release_with_reconciliation(
        &mut self,
        peer: &PeerConnectivityIdentity,
        fence: NonZeroU128,
        observation: Option<LiveOwnerObservation>,
    ) -> Result<ReachabilityLiveOwnerResolvedRelease, ReachabilityLiveOwnerReconciliationError>
    {
        let before = observation.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
        let plan = match plan_resolved_release(peer, fence, &before)? {
            LiveOwnerPlannedRelease::NotCurrent(evidence) => {
                return Ok(ReachabilityLiveOwnerResolvedRelease::NotCurrent(evidence));
            }
            LiveOwnerPlannedRelease::Mutation(plan) => *plan,
        };
        let pending = LiveOwnerPendingMutation::release(before, plan);
        let mut io = EtcdMutationIo { store: self };
        resolve_pending_mutation(&mut io, pending)
            .await
            .map(|mutation| ReachabilityLiveOwnerResolvedRelease::Mutation(Box::new(mutation)))
            .map_err(map_etcd_orchestration_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveOwnerPendingMutationKind {
    Acquisition,
    Release,
}

/// Non-clone operation-local capsule retaining one exact logical mutation until it resolves.
#[derive(Debug)]
struct LiveOwnerPendingMutation {
    kind: LiveOwnerPendingMutationKind,
    before: LiveOwnerObservation,
    plan: LiveOwnerTxnPlan,
}

impl LiveOwnerPendingMutation {
    fn acquisition(
        before: LiveOwnerObservation,
        successor: ReachabilityLiveOwnerAuthorityRecord,
    ) -> Result<Self, LiveOwnerTxnError> {
        let plan = plan_acquisition(&before, successor)?;
        Ok(Self {
            kind: LiveOwnerPendingMutationKind::Acquisition,
            before,
            plan,
        })
    }

    const fn release(before: LiveOwnerObservation, plan: LiveOwnerTxnPlan) -> Self {
        Self {
            kind: LiveOwnerPendingMutationKind::Release,
            before,
            plan,
        }
    }

    const fn peer(&self) -> &PeerConnectivityIdentity {
        self.before.record().peer()
    }

    fn reconcile(
        &self,
        observation: Option<&LiveOwnerObservation>,
    ) -> Result<LiveOwnerReconciliation, LiveOwnerTxnError> {
        match self.kind {
            LiveOwnerPendingMutationKind::Acquisition => reconcile_indeterminate_acquisition(
                &self.before,
                self.plan.successor(),
                observation,
            ),
            LiveOwnerPendingMutationKind::Release => {
                reconcile_indeterminate_release(&self.before, observation)
            }
        }
    }

    fn resolved(
        self,
        outcome: ReachabilityLiveOwnerResolvedMutationOutcome,
    ) -> ReachabilityLiveOwnerResolvedMutation {
        ReachabilityLiveOwnerResolvedMutation {
            plan: self.plan,
            outcome,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LiveOwnerMutationIoExecution {
    Definitive(LiveOwnerDefinitiveMutation),
    Indeterminate,
}

trait LiveOwnerMutationIo {
    type Error;

    fn execute<'a>(
        &'a mut self,
        plan: &'a LiveOwnerTxnPlan,
    ) -> impl Future<Output = Result<LiveOwnerMutationIoExecution, Self::Error>> + 'a;

    fn linearizable_observation<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<Output = Result<Option<LiveOwnerObservation>, Self::Error>> + 'a;
}

struct EtcdMutationIo<'a> {
    store: &'a mut ReachabilityLiveOwnerEtcdStore,
}

impl LiveOwnerMutationIo for EtcdMutationIo<'_> {
    type Error = ReachabilityLiveOwnerEtcdError;

    async fn execute<'a>(
        &'a mut self,
        plan: &'a LiveOwnerTxnPlan,
    ) -> Result<LiveOwnerMutationIoExecution, Self::Error> {
        match self.store.execute(plan).await {
            Ok(outcome) => Ok(LiveOwnerMutationIoExecution::Definitive(outcome)),
            Err(ReachabilityLiveOwnerEtcdError::MutationIndeterminate(_)) => {
                Ok(LiveOwnerMutationIoExecution::Indeterminate)
            }
            Err(error) => Err(error),
        }
    }

    fn linearizable_observation<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<Output = Result<Option<LiveOwnerObservation>, Self::Error>> + 'a {
        self.store.linearizable_observation(peer)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LiveOwnerOrchestrationError<E> {
    Provider(E),
    Transaction(LiveOwnerTxnError),
    ReissueLimitReached,
}

async fn resolve_pending_mutation<I>(
    io: &mut I,
    pending: LiveOwnerPendingMutation,
) -> Result<ReachabilityLiveOwnerResolvedMutation, LiveOwnerOrchestrationError<I::Error>>
where
    I: LiveOwnerMutationIo,
{
    match io
        .execute(&pending.plan)
        .await
        .map_err(LiveOwnerOrchestrationError::Provider)?
    {
        LiveOwnerMutationIoExecution::Definitive(outcome) => {
            return Ok(resolve_definitive(pending, outcome));
        }
        LiveOwnerMutationIoExecution::Indeterminate => {}
    }

    let first_observation = io
        .linearizable_observation(pending.peer())
        .await
        .map_err(LiveOwnerOrchestrationError::Provider)?;
    match pending
        .reconcile(first_observation.as_ref())
        .map_err(LiveOwnerOrchestrationError::Transaction)?
    {
        LiveOwnerReconciliation::Committed => {
            return Ok(pending.resolved(ReachabilityLiveOwnerResolvedMutationOutcome::Committed));
        }
        LiveOwnerReconciliation::Superseded => {
            return Ok(pending.resolved(ReachabilityLiveOwnerResolvedMutationOutcome::Superseded));
        }
        LiveOwnerReconciliation::ProvenNotCommitted => {}
    }

    match io
        .execute(&pending.plan)
        .await
        .map_err(LiveOwnerOrchestrationError::Provider)?
    {
        LiveOwnerMutationIoExecution::Definitive(outcome) => {
            return Ok(resolve_definitive(pending, outcome));
        }
        LiveOwnerMutationIoExecution::Indeterminate => {}
    }

    let second_observation = io
        .linearizable_observation(pending.peer())
        .await
        .map_err(LiveOwnerOrchestrationError::Provider)?;
    match pending
        .reconcile(second_observation.as_ref())
        .map_err(LiveOwnerOrchestrationError::Transaction)?
    {
        LiveOwnerReconciliation::Committed => {
            Ok(pending.resolved(ReachabilityLiveOwnerResolvedMutationOutcome::Committed))
        }
        LiveOwnerReconciliation::Superseded => {
            Ok(pending.resolved(ReachabilityLiveOwnerResolvedMutationOutcome::Superseded))
        }
        LiveOwnerReconciliation::ProvenNotCommitted => {
            Err(LiveOwnerOrchestrationError::ReissueLimitReached)
        }
    }
}

fn resolve_definitive(
    pending: LiveOwnerPendingMutation,
    outcome: LiveOwnerDefinitiveMutation,
) -> ReachabilityLiveOwnerResolvedMutation {
    let outcome = match outcome {
        LiveOwnerDefinitiveMutation::Committed => {
            ReachabilityLiveOwnerResolvedMutationOutcome::Committed
        }
        LiveOwnerDefinitiveMutation::CompareFailed(observation) => {
            ReachabilityLiveOwnerResolvedMutationOutcome::CompareFailed(observation)
        }
    };
    pending.resolved(outcome)
}

fn map_etcd_orchestration_error(
    error: LiveOwnerOrchestrationError<ReachabilityLiveOwnerEtcdError>,
) -> ReachabilityLiveOwnerReconciliationError {
    match error {
        LiveOwnerOrchestrationError::Provider(error) => {
            ReachabilityLiveOwnerReconciliationError::Etcd(error)
        }
        LiveOwnerOrchestrationError::Transaction(error) => {
            ReachabilityLiveOwnerReconciliationError::Transaction(error)
        }
        LiveOwnerOrchestrationError::ReissueLimitReached => {
            ReachabilityLiveOwnerReconciliationError::ReissueLimitReached
        }
    }
}

#[cfg(test)]
mod tests;
