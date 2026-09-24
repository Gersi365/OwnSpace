//! Phase 152 C02e Tranche 4 production reachability composition owner.
//!
//! This module owns the one-shot composition boundary across authenticated candidate admission,
//! verifier-owned publication freshness, the current connectivity plan, durable compare-and-
//! commit, and at most one current Phase 141 Sans-I/O traversal session. It deliberately owns no
//! socket, async runtime, DNS resolver, network adapter, control-plane wire codec, persistence
//! serialization format, database product, Agent bootstrap activation, or deployment behavior.

#![allow(clippy::manual_async_fn)]

use std::{fmt, future::Future};

use prw_connectivity::{
    CandidateId, ConnectivityError, PeerConnectivityIdentity, PeerConnectivityPlan,
    PeerConnectivityPlanDurableState, SelectedConnectivityPath,
};
use prw_nat_traversal::{IceConnectivitySession, TraversalError};
use prw_registry::{RegistryError, WorkspaceDeviceRegistry};
use prw_session::AuthenticatedDeviceSession;

use crate::candidate_publication_freshness::{
    CandidatePublicationFreshnessLifecycle, CandidatePublicationFreshnessRecord,
    CandidatePublicationFreshnessToken,
};
use crate::candidate_reachability::{
    AuthenticatedCandidatePublication, CandidateReachabilityError,
    validate_authenticated_publication_admission,
};

/// Operational state of one production reachability owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityOwnerMode {
    /// Durable state and local state agree and one-shot operations may proceed.
    Current,
    /// State may be stale or ambiguous; all mutation/observation paths fail closed until reload.
    RecoveryRequired,
    /// The exact peer lifecycle is a durable historical tombstone.
    Retired,
}

/// Definite result of a durable expected-current compare-and-commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityPersistenceCommit {
    /// The replacement snapshot is durably current.
    Committed,
    /// The durable current state no longer matches the caller's expected freshness token.
    StaleExpected,
}

/// Persistence failures where commit status cannot safely be inferred by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityPersistenceError {
    /// Storage/transaction outcome is unavailable or ambiguous and therefore requires recovery.
    UnavailableOrAmbiguous,
}

impl fmt::Display for ReachabilityPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnavailableOrAmbiguous => {
                "reachability persistence result is unavailable or ambiguous"
            }
        })
    }
}

impl std::error::Error for ReachabilityPersistenceError {}

/// Exact committed state carried through the persistence transaction seam.
///
/// The plan member is provider-neutral durable semantic state rather than a live plan. Production
/// stores therefore cannot accidentally persist transient reachability observations. Recovery and
/// reload validate and restore this state through `PeerConnectivityPlan::from_durable_state(...)`
/// before it can become local owner state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityDurableSnapshot {
    plan: PeerConnectivityPlanDurableState,
    freshness: CandidatePublicationFreshnessRecord,
}

impl ReachabilityDurableSnapshot {
    /// Creates one peer-consistent durable snapshot from typed durable plan state.
    ///
    /// Semantic plan validation occurs only when the plan state is restored. This constructor
    /// enforces the cross-member exact-peer invariant before a persistence operation can observe the
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Rejects a plan/freshness peer mismatch.
    pub fn new(
        plan: PeerConnectivityPlanDurableState,
        freshness: CandidatePublicationFreshnessRecord,
    ) -> Result<Self, ReachabilitySnapshotError> {
        if plan.peer() != freshness.peer() {
            return Err(ReachabilitySnapshotError::PeerMismatch);
        }
        Ok(Self { plan, freshness })
    }

    /// Returns the exact committed provider-neutral durable connectivity-plan state.
    #[must_use]
    pub const fn plan(&self) -> &PeerConnectivityPlanDurableState {
        &self.plan
    }

    /// Returns verifier-owned freshness state for the same exact peer lifecycle.
    #[must_use]
    pub const fn freshness(&self) -> &CandidatePublicationFreshnessRecord {
        &self.freshness
    }
}

/// Structural or semantic durable-snapshot failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilitySnapshotError {
    /// Plan state and freshness record refer to different logical/transport peer identities.
    PeerMismatch,
    /// Decoded typed durable plan state violated connectivity restoration invariants.
    PlanRestoration(ConnectivityError),
}

impl fmt::Display for ReachabilitySnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerMismatch => {
                formatter.write_str("reachability durable snapshot peer mismatch")
            }
            Self::PlanRestoration(error) => {
                write!(
                    formatter,
                    "reachability durable plan restoration failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ReachabilitySnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PlanRestoration(error) => Some(error),
            Self::PeerMismatch => None,
        }
    }
}

/// Awaitable durable compare-and-commit boundary used by the production owner.
///
/// The concrete database, serialization, replication and transaction implementation remain
/// outside this tranche. Implementations must make `compare_and_commit` linearizable for one
/// exact peer lifecycle: only the durable state holding `expected_current` may be replaced. The
/// returned futures are polled by the caller; this trait owns no executor or async runtime.
pub trait ReachabilityDurableStore {
    /// Loads the exact durable current snapshot for one peer lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an ambiguous/unavailable classification rather than treating storage absence or
    /// uncertainty as new-lifecycle authority.
    fn load_current<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<Option<ReachabilityDurableSnapshot>, ReachabilityPersistenceError>,
    > + Send
    + 'a;

    /// Atomically compares current durable freshness and commits the complete replacement.
    ///
    /// # Errors
    ///
    /// `StaleExpected` is a definite non-commit. Any returned error is treated by the owner as
    /// potentially ambiguous and forces fail-closed recovery.
    fn compare_and_commit<'a>(
        &'a mut self,
        expected_current: CandidatePublicationFreshnessToken,
        replacement: &'a ReachabilityDurableSnapshot,
    ) -> impl Future<Output = Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError>>
    + Send
    + 'a;
}

/// Failure of verifier-owned production freshness-token generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FreshnessTokenSourceError {
    /// A fresh cryptographically secure verifier token could not be produced.
    Unavailable,
}

impl fmt::Display for FreshnessTokenSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate publication freshness token source unavailable")
    }
}

impl std::error::Error for FreshnessTokenSourceError {}

/// Verifier-owned source of opaque production freshness tokens.
///
/// Implementations must use a cryptographically secure verifier-owned entropy source and must not
/// derive replacement tokens from publisher input, clocks, request IDs, candidate IDs or endpoints.
pub trait CandidatePublicationFreshnessTokenSource {
    /// Issues one non-zero opaque freshness token.
    ///
    /// # Errors
    ///
    /// Fails without mutating accepted reachability state when secure issuance is unavailable.
    fn issue_token(
        &mut self,
    ) -> Result<CandidatePublicationFreshnessToken, FreshnessTokenSourceError>;
}

/// Failure of current-plan Phase 141 traversal construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityTraversalFactoryError {
    /// Current authenticated coordination data cannot construct a valid replacement session.
    UnavailableOrInvalidCoordination,
}

impl fmt::Display for ReachabilityTraversalFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("current traversal coordination is unavailable or invalid")
    }
}

impl std::error::Error for ReachabilityTraversalFactoryError {}

/// Factory seam for a replacement Phase 141 session derived from the exact current plan.
///
/// The owner calls this factory only after the corresponding plan is already current. The factory
/// may build Sans-I/O protocol state from authenticated coordination metadata, but it must not open
/// sockets, spawn tasks, or make an older traversal lifecycle current again.
pub trait ReachabilityTraversalFactory {
    /// Builds one replacement Sans-I/O traversal session for `plan`.
    ///
    /// # Errors
    ///
    /// Failure leaves the already-committed plan/freshness current with no traversal session.
    fn build_for_current_plan(
        &mut self,
        plan: &PeerConnectivityPlan,
    ) -> Result<IceConnectivitySession, ReachabilityTraversalFactoryError>;
}

/// Evidence returned after one successful publication commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachabilityCommitOutcome {
    replacement_freshness: CandidatePublicationFreshnessToken,
    invalidated_traversal: bool,
}

impl ReachabilityCommitOutcome {
    /// Returns the verifier-issued token that became current at the commit point.
    #[must_use]
    pub const fn replacement_freshness(self) -> CandidatePublicationFreshnessToken {
        self.replacement_freshness
    }

    /// Reports whether a previously current traversal session was invalidated by the commit.
    #[must_use]
    pub const fn invalidated_traversal(self) -> bool {
        self.invalidated_traversal
    }
}

/// Stable production-owner failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityOwnerError {
    /// Authenticated publication admission or candidate validation failed before commit.
    Candidate(CandidateReachabilityError),
    /// Durable snapshot structure or typed plan restoration was invalid.
    Snapshot(ReachabilitySnapshotError),
    /// Caller-presented freshness is not the owner's exact current verifier token.
    StalePublicationFreshness,
    /// Current lifecycle does not carry a usable freshness token.
    FreshnessUnavailable,
    /// Token source returned the exact current token rather than a distinct replacement.
    ReplacementFreshnessUnchanged,
    /// Verifier-owned secure token generation failed before commit.
    TokenSource(FreshnessTokenSourceError),
    /// Durable transaction result is unavailable/ambiguous.
    Persistence(ReachabilityPersistenceError),
    /// Durable store definitely rejected the local expected state as stale.
    DurableStateOutOfSync,
    /// No durable state exists for an already-established/recovering owner lifecycle.
    DurableStateMissing,
    /// Owner is blocked pending authoritative durable recovery.
    RecoveryRequired,
    /// Exact peer lifecycle is retired and cannot accept new publications or observations.
    Retired,
    /// A traversal session is already current for this owner.
    TraversalAlreadyCurrent,
    /// No traversal session is current for an observation poll.
    NoCurrentTraversal,
    /// Phase 141 Sans-I/O traversal processing failed.
    Traversal(TraversalError),
    /// Replacement traversal factory failed without rolling back accepted publication state.
    TraversalFactory(ReachabilityTraversalFactoryError),
    /// Registry currentness changed for the exact plan transport identity.
    Registry(RegistryError),
    /// Retirement was requested while the plan transport identity is still registry-current.
    TransportStillCurrent,
}

impl fmt::Display for ReachabilityOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => write!(
                formatter,
                "reachability candidate transition failed: {error}"
            ),
            Self::Snapshot(error) => write!(formatter, "reachability snapshot rejected: {error}"),
            Self::StalePublicationFreshness => {
                formatter.write_str("candidate publication freshness is stale")
            }
            Self::FreshnessUnavailable => {
                formatter.write_str("current reachability freshness is unavailable")
            }
            Self::ReplacementFreshnessUnchanged => {
                formatter.write_str("replacement reachability freshness must change")
            }
            Self::TokenSource(error) => {
                write!(formatter, "reachability token source failed: {error}")
            }
            Self::Persistence(error) => {
                write!(formatter, "reachability persistence failed: {error}")
            }
            Self::DurableStateOutOfSync => {
                formatter.write_str("durable reachability state is ahead of the local owner")
            }
            Self::DurableStateMissing => {
                formatter.write_str("durable reachability state is missing")
            }
            Self::RecoveryRequired => formatter.write_str("reachability recovery is required"),
            Self::Retired => formatter.write_str("reachability lifecycle is retired"),
            Self::TraversalAlreadyCurrent => {
                formatter.write_str("a current traversal session already exists")
            }
            Self::NoCurrentTraversal => formatter.write_str("no current traversal session exists"),
            Self::Traversal(error) => write!(formatter, "current traversal failed: {error}"),
            Self::TraversalFactory(error) => {
                write!(
                    formatter,
                    "replacement traversal construction failed: {error}"
                )
            }
            Self::Registry(error) => write!(
                formatter,
                "current reachability registry check failed: {error}"
            ),
            Self::TransportStillCurrent => {
                formatter.write_str("reachability transport identity is still current")
            }
        }
    }
}

impl std::error::Error for ReachabilityOwnerError {}

/// Production upper owner for one exact peer reachability lifecycle.
///
/// `&mut self` serializes one in-process owner operation. The durable store's expected-current CAS
/// is the cross-owner/process arbitration seam. A definite stale CAS or any ambiguous storage
/// result invalidates the local traversal and blocks the owner until authoritative reload.
pub struct ProductionReachabilityOwner<S, T> {
    store: S,
    token_source: T,
    plan: PeerConnectivityPlan,
    freshness: CandidatePublicationFreshnessRecord,
    traversal: Option<IceConnectivitySession>,
    mode: ReachabilityOwnerMode,
}

impl<S, T> ProductionReachabilityOwner<S, T>
where
    S: ReachabilityDurableStore,
    T: CandidatePublicationFreshnessTokenSource,
{
    /// Recovers one owner only from existing authoritative durable state.
    ///
    /// Storage absence never creates `NewLifecycleEligible`; bootstrap authorization must have
    /// been durably established by the separate lifecycle authority before this call.
    /// Loaded plan state is validated through the connectivity-owned durable restoration boundary
    /// before an owner is constructed.
    ///
    /// # Errors
    ///
    /// Fails closed on missing/ambiguous storage, a snapshot for a different exact peer, or invalid
    /// typed durable plan state. No partially restored owner is returned.
    pub async fn recover(
        mut store: S,
        token_source: T,
        peer: &PeerConnectivityIdentity,
    ) -> Result<Self, ReachabilityOwnerError> {
        let snapshot = store
            .load_current(peer)
            .await
            .map_err(ReachabilityOwnerError::Persistence)?
            .ok_or(ReachabilityOwnerError::DurableStateMissing)?;
        if snapshot.plan.peer() != peer || snapshot.freshness.peer() != peer {
            return Err(ReachabilityOwnerError::Snapshot(
                ReachabilitySnapshotError::PeerMismatch,
            ));
        }
        let ReachabilityDurableSnapshot { plan, freshness } = snapshot;
        let plan = PeerConnectivityPlan::from_durable_state(plan).map_err(|error| {
            ReachabilityOwnerError::Snapshot(ReachabilitySnapshotError::PlanRestoration(error))
        })?;
        let mode = mode_for_lifecycle(freshness.lifecycle());
        Ok(Self {
            store,
            token_source,
            plan,
            freshness,
            traversal: None,
            mode,
        })
    }

    /// Returns the owner operational mode. This mode dominates any cached local token value.
    #[must_use]
    pub const fn mode(&self) -> ReachabilityOwnerMode {
        self.mode
    }

    /// Returns the exact current local connectivity plan snapshot.
    #[must_use]
    pub const fn plan(&self) -> &PeerConnectivityPlan {
        &self.plan
    }

    /// Returns the locally cached verifier freshness record.
    ///
    /// In `RecoveryRequired`, this value is only the last locally known state and is not authority
    /// until a successful durable reload returns the owner to `Current`.
    #[must_use]
    pub const fn freshness(&self) -> &CandidatePublicationFreshnessRecord {
        &self.freshness
    }

    /// Returns whether this owner currently holds one Phase 141 traversal session.
    #[must_use]
    pub const fn has_current_traversal(&self) -> bool {
        self.traversal.is_some()
    }

    /// Returns the deterministic path selection from the current local plan.
    #[must_use]
    pub fn selected_path(&self) -> SelectedConnectivityPath {
        self.plan.selected_path()
    }

    /// Processes one authenticated candidate publication through one durable commit boundary.
    ///
    /// Ordering is fixed: current owner -> identity/workspace/transport admission -> exact current
    /// freshness -> complete candidate validation on a staged live plan -> fresh verifier token ->
    /// typed durable-plan projection -> durable CAS -> local live plan/freshness install plus
    /// old-traversal invalidation.
    ///
    /// # Errors
    ///
    /// Any failure before durable commit preserves local plan/freshness/traversal state. A stale
    /// durable expected value or ambiguous persistence result invalidates traversal and enters
    /// `RecoveryRequired` because another writer or uncertain commit may have moved authority.
    pub async fn commit_candidate_publication(
        &mut self,
        registry: &WorkspaceDeviceRegistry,
        requester_session: &AuthenticatedDeviceSession,
        publication: &AuthenticatedCandidatePublication,
        presented_freshness: CandidatePublicationFreshnessToken,
    ) -> Result<ReachabilityCommitOutcome, ReachabilityOwnerError> {
        self.require_current()?;
        validate_authenticated_publication_admission(
            registry,
            requester_session,
            publication,
            &self.plan,
        )
        .map_err(ReachabilityOwnerError::Candidate)?;

        let expected_current = self.expected_current_token()?;
        if presented_freshness != expected_current {
            return Err(ReachabilityOwnerError::StalePublicationFreshness);
        }

        let mut staged_plan = self.plan.clone();
        staged_plan
            .refresh_candidates(publication.candidates().to_vec())
            .map_err(|error| {
                ReachabilityOwnerError::Candidate(CandidateReachabilityError::Connectivity(error))
            })?;

        let replacement_freshness = self
            .token_source
            .issue_token()
            .map_err(ReachabilityOwnerError::TokenSource)?;
        if replacement_freshness == expected_current {
            return Err(ReachabilityOwnerError::ReplacementFreshnessUnchanged);
        }
        let staged_freshness = CandidatePublicationFreshnessRecord::established(
            staged_plan.peer().clone(),
            replacement_freshness,
        );
        let staged_snapshot =
            ReachabilityDurableSnapshot::new(staged_plan.durable_state(), staged_freshness.clone())
                .map_err(ReachabilityOwnerError::Snapshot)?;

        match self
            .store
            .compare_and_commit(expected_current, &staged_snapshot)
            .await
        {
            Ok(ReachabilityPersistenceCommit::Committed) => {
                let invalidated_traversal = self.traversal.take().is_some();
                self.plan = staged_plan;
                self.freshness = staged_freshness;
                self.mode = ReachabilityOwnerMode::Current;
                Ok(ReachabilityCommitOutcome {
                    replacement_freshness,
                    invalidated_traversal,
                })
            }
            Ok(ReachabilityPersistenceCommit::StaleExpected) => {
                self.enter_recovery();
                Err(ReachabilityOwnerError::DurableStateOutOfSync)
            }
            Err(error) => {
                self.enter_recovery();
                Err(ReachabilityOwnerError::Persistence(error))
            }
        }
    }

    /// Builds and installs one replacement traversal session for the exact current plan.
    ///
    /// # Errors
    ///
    /// Construction failure is post-commit forward recovery: accepted plan/freshness remain current
    /// and no old traversal is resurrected. An already-current traversal cannot be overwritten.
    pub fn provision_current_traversal<F>(
        &mut self,
        factory: &mut F,
    ) -> Result<(), ReachabilityOwnerError>
    where
        F: ReachabilityTraversalFactory,
    {
        self.require_current()?;
        if self.traversal.is_some() {
            return Err(ReachabilityOwnerError::TraversalAlreadyCurrent);
        }
        let traversal = factory
            .build_for_current_plan(&self.plan)
            .map_err(ReachabilityOwnerError::TraversalFactory)?;
        self.traversal = Some(traversal);
        Ok(())
    }

    /// Polls and applies at most one reachability observation from the currently owned traversal.
    ///
    /// The Phase 141 update never leaves the serialized owner boundary. Current transport identity
    /// is revalidated immediately before polling/application so a transport rotation cannot admit
    /// an old traversal observation merely because the candidate ID still exists.
    ///
    /// # Errors
    ///
    /// Registry currentness loss invalidates the traversal and enters fail-closed recovery.
    pub fn poll_and_apply_current_reachability(
        &mut self,
        registry: &WorkspaceDeviceRegistry,
    ) -> Result<Option<CandidateId>, ReachabilityOwnerError> {
        self.require_current()?;
        if let Err(error) = registry.validate_transport_identity(
            self.plan.peer().device_id(),
            self.plan.peer().transport_identity(),
        ) {
            self.enter_recovery();
            return Err(ReachabilityOwnerError::Registry(error));
        }
        let traversal = self
            .traversal
            .as_mut()
            .ok_or(ReachabilityOwnerError::NoCurrentTraversal)?;
        let Some(update) = traversal
            .poll_reachability()
            .map_err(ReachabilityOwnerError::Traversal)?
        else {
            return Ok(None);
        };
        let candidate_id = update.candidate_id();
        update
            .apply(&mut self.plan)
            .map_err(ReachabilityOwnerError::Traversal)?;
        Ok(Some(candidate_id))
    }

    /// Durably tombstones this exact peer lifecycle after registry currentness has ended.
    ///
    /// This does not create a replacement peer lifecycle. A new `TransportIdentity` requires its
    /// own separately authorized bootstrap state; storage absence or same-byte reuse is never an
    /// implicit rebaseline.
    ///
    /// # Errors
    ///
    /// Refuses retirement while the exact transport remains current. Stale/ambiguous durable CAS
    /// results enter recovery rather than guessing whether retirement committed.
    pub async fn retire_noncurrent_lifecycle(
        &mut self,
        registry: &WorkspaceDeviceRegistry,
    ) -> Result<(), ReachabilityOwnerError> {
        if self.mode == ReachabilityOwnerMode::Retired {
            return Err(ReachabilityOwnerError::Retired);
        }
        if registry
            .validate_transport_identity(
                self.plan.peer().device_id(),
                self.plan.peer().transport_identity(),
            )
            .is_ok()
        {
            return Err(ReachabilityOwnerError::TransportStillCurrent);
        }
        let expected_current = self.expected_current_token_even_during_recovery()?;
        let retired = CandidatePublicationFreshnessRecord::retired(self.plan.peer().clone());
        let snapshot = ReachabilityDurableSnapshot::new(self.plan.durable_state(), retired.clone())
            .map_err(ReachabilityOwnerError::Snapshot)?;
        match self
            .store
            .compare_and_commit(expected_current, &snapshot)
            .await
        {
            Ok(ReachabilityPersistenceCommit::Committed) => {
                self.traversal = None;
                self.freshness = retired;
                self.mode = ReachabilityOwnerMode::Retired;
                Ok(())
            }
            Ok(ReachabilityPersistenceCommit::StaleExpected) => {
                self.enter_recovery();
                Err(ReachabilityOwnerError::DurableStateOutOfSync)
            }
            Err(error) => {
                self.enter_recovery();
                Err(ReachabilityOwnerError::Persistence(error))
            }
        }
    }

    /// Reloads authoritative durable state for this exact peer and drops any local traversal on a
    /// failed or successful authoritative replacement.
    ///
    /// # Errors
    ///
    /// Missing/ambiguous/mismatched/semantically invalid durable state leaves the owner in
    /// `RecoveryRequired`. Loaded plan and freshness are installed only as one fully restored pair.
    pub async fn reload_from_store(
        &mut self,
    ) -> Result<ReachabilityOwnerMode, ReachabilityOwnerError> {
        let peer = self.plan.peer().clone();
        let snapshot = match self.store.load_current(&peer).await {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                self.enter_recovery();
                return Err(ReachabilityOwnerError::DurableStateMissing);
            }
            Err(error) => {
                self.enter_recovery();
                return Err(ReachabilityOwnerError::Persistence(error));
            }
        };
        if snapshot.plan.peer() != &peer || snapshot.freshness.peer() != &peer {
            self.enter_recovery();
            return Err(ReachabilityOwnerError::Snapshot(
                ReachabilitySnapshotError::PeerMismatch,
            ));
        }
        let ReachabilityDurableSnapshot { plan, freshness } = snapshot;
        let plan = match PeerConnectivityPlan::from_durable_state(plan) {
            Ok(plan) => plan,
            Err(error) => {
                self.enter_recovery();
                return Err(ReachabilityOwnerError::Snapshot(
                    ReachabilitySnapshotError::PlanRestoration(error),
                ));
            }
        };
        self.traversal = None;
        self.plan = plan;
        self.freshness = freshness;
        self.mode = mode_for_lifecycle(self.freshness.lifecycle());
        Ok(self.mode)
    }

    const fn require_current(&self) -> Result<(), ReachabilityOwnerError> {
        match self.mode {
            ReachabilityOwnerMode::Current => Ok(()),
            ReachabilityOwnerMode::RecoveryRequired => {
                Err(ReachabilityOwnerError::RecoveryRequired)
            }
            ReachabilityOwnerMode::Retired => Err(ReachabilityOwnerError::Retired),
        }
    }

    fn expected_current_token(
        &self,
    ) -> Result<CandidatePublicationFreshnessToken, ReachabilityOwnerError> {
        self.require_current()?;
        self.expected_current_token_even_during_recovery()
    }

    fn expected_current_token_even_during_recovery(
        &self,
    ) -> Result<CandidatePublicationFreshnessToken, ReachabilityOwnerError> {
        self.freshness
            .lifecycle()
            .current_token()
            .ok_or(ReachabilityOwnerError::FreshnessUnavailable)
    }

    fn enter_recovery(&mut self) {
        self.traversal = None;
        self.mode = ReachabilityOwnerMode::RecoveryRequired;
    }
}

const fn mode_for_lifecycle(
    lifecycle: CandidatePublicationFreshnessLifecycle,
) -> ReachabilityOwnerMode {
    match lifecycle {
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(_)
        | CandidatePublicationFreshnessLifecycle::Established(_) => ReachabilityOwnerMode::Current,
        CandidatePublicationFreshnessLifecycle::RecoveryRequired => {
            ReachabilityOwnerMode::RecoveryRequired
        }
        CandidatePublicationFreshnessLifecycle::Retired => ReachabilityOwnerMode::Retired,
    }
}
