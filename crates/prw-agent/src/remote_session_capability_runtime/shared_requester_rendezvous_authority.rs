//! Shared Agent-owned synchronization for requester/rendezvous authority.
//!
//! C03e-FP materializes the C03e-FO-selected cloneable Tokio-async-mutex wrapper around one
//! existing process-local requester/rendezvous runtime owner. The wrapper serializes the exact
//! requester DR registration critical section, nests the existing shared-current registry/policy
//! read only after requester-authority lock acquisition, and releases requester-authority custody
//! before requester acknowledgement framing or response I/O. C03e-FY adds only the FX-selected
//! candidate-publication grant/commit/cleanup custody split: candidate admission occurs before the
//! requester lock, one grant is selected under the lock, the lock is released before durable
//! reachability commit, and exact record cleanup reacquires the lock only after definite commit
//! success. C03e-GC adds only pure terminal frame composition over the existing bridge codec while
//! preserving post-commit cleanup disposition separately. C03e-GK adds the GJ-selected dormant
//! envelope-neutral current-Mesh semantic decomposition: initial owned publication admission,
//! requester grant release, fresh commit-time current-authority read, exact GI owner lookup,
//! lexical durable commit, and post-commit requester cleanup. C03e-GR propagates the GQ-selected
//! durable awaitability through those existing dormant commit callsites while retaining the same
//! current-authority read and exact production-owner custody across the durable await. It exposes no
//! raw provider, mutex, guard or production owner and activates no listener/network runtime.

use std::{fmt, sync::Arc};

use prw_core::{DeviceId, SessionId};
use prw_policy::PolicyEvaluator;
use prw_registry::WorkspaceDeviceRegistry;
use prw_remote_bridge::{
    candidate_publication_control_frame::CandidatePublicationControlFrame,
    candidate_publication_execution::CandidatePublicationExecutionError,
    candidate_publication_result_wire::{
        CandidatePublicationResultFrameComposition,
        encode_candidate_publication_execution_result_frame,
    },
    candidate_publication_wire::CandidatePublicationWireSubmission,
    candidate_reachability::publish_current_candidates,
    prwc_connection_authentication::AuthenticatedPrwcConnection,
    reachability_owner::{
        CandidatePublicationFreshnessTokenSource, ProductionReachabilityOwner,
        ReachabilityCommitOutcome, ReachabilityDurableStore,
    },
    requester_rendezvous_authority::{
        AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
    },
    requester_rendezvous_in_memory_provider::RequesterRendezvousLifecycleError,
};
use prw_session::AuthenticatedDeviceSession;
use tokio::sync::Mutex;

use super::SharedCurrentCapabilityAuthority;
use crate::{
    candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner,
    candidate_publication_requester_rendezvous_start_intent::{
        RequesterRendezvousStartIntent,
        composition::{
            RequesterRendezvousStartCompositionError,
            validate_authorize_and_register_requester_rendezvous_start,
        },
        policy_admission::{
            RequesterRendezvousStartPolicyAuthorizationError,
            policy_authorize_requester_rendezvous_start,
        },
        policy_source::{
            RequesterRendezvousStartPolicySource, RequesterRendezvousStartPolicySourceError,
        },
        registry_validation::{
            RequesterRendezvousStartRegistryValidationError,
            validate_current_requester_rendezvous_start_intent,
        },
    },
    production_reachability_owner_custody::{
        ProductionReachabilityOwnerCustodyLookupError, ProductionReachabilityOwnerCustodyMap,
    },
};

/// Non-authorizing exact lifecycle identity preserved from one selected requester grant.
///
/// Possession of this value cannot authorize candidate publication, requester registration,
/// reconnect, retry, dialing, or any new session. It exists only so a definite successful durable
/// publication can retire and remove the same exact requester record afterward.
#[derive(Debug, PartialEq, Eq)]
struct RequesterRendezvousCommittedCleanupIdentity {
    requester_session_id: SessionId,
    expected_publisher_device_id: DeviceId,
}

impl RequesterRendezvousCommittedCleanupIdentity {
    fn from_grant(grant: &AuthorizedRequesterRendezvous) -> Self {
        Self {
            requester_session_id: grant.requester_session().session_id().clone(),
            expected_publisher_device_id: grant.expected_publisher_device_id().clone(),
        }
    }
}

/// Definite durable candidate-publication success plus independent post-commit cleanup disposition.
///
/// A cleanup error never rewrites the already-committed publication into
/// [`CandidatePublicationExecutionError`]. Callers can project the exact successful reachability
/// outcome for existing Accepted response framing while handling cleanup disposition separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatePublicationPostCommitRequesterCleanupOutcome {
    reachability_commit: ReachabilityCommitOutcome,
    cleanup: Result<(), RequesterRendezvousLifecycleError>,
}

impl CandidatePublicationPostCommitRequesterCleanupOutcome {
    /// Returns the definite successful durable reachability commit outcome.
    #[must_use]
    pub(crate) const fn reachability_commit(self) -> ReachabilityCommitOutcome {
        self.reachability_commit
    }

    /// Returns the independent exact-record cleanup disposition.
    pub(crate) const fn cleanup_result(self) -> Result<(), RequesterRendezvousLifecycleError> {
        self.cleanup
    }

    /// Transfers both post-commit result components without flattening either classification.
    pub(crate) const fn into_parts(
        self,
    ) -> (
        ReachabilityCommitOutcome,
        Result<(), RequesterRendezvousLifecycleError>,
    ) {
        (self.reachability_commit, self.cleanup)
    }
}

/// Agent-side projection of one completed FY candidate-publication attempt.
///
/// `semantic_result` is exactly the provider-neutral bridge input used by the existing terminal
/// result codec. `cleanup` is present only after a definite durable commit and remains internal;
/// its failure cannot rewrite the semantic result into `Rejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatePublicationTerminalResultProjection {
    semantic_result: Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
    cleanup: Option<Result<(), RequesterRendezvousLifecycleError>>,
}

impl CandidatePublicationTerminalResultProjection {
    /// Returns the exact bridge-compatible candidate-publication semantic result.
    pub(crate) const fn semantic_result(
        self,
    ) -> Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError> {
        self.semantic_result
    }

    /// Returns post-commit requester cleanup disposition when a durable commit occurred.
    pub(crate) const fn cleanup_result(
        self,
    ) -> Option<Result<(), RequesterRendezvousLifecycleError>> {
        self.cleanup
    }

    /// Transfers both projection channels without flattening either classification.
    pub(crate) const fn into_parts(
        self,
    ) -> (
        Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
        Option<Result<(), RequesterRendezvousLifecycleError>>,
    ) {
        (self.semantic_result, self.cleanup)
    }
}

/// Agent-owned pure composition of an existing candidate-publication frame result and the exact
/// optional post-commit requester cleanup disposition.
///
/// The bridge-owned generic carrier owns the concrete control-frame type, so Agent does not add a
/// direct transport dependency merely to name that type. The disposition remains opaque to bridge
/// framing and is never serialized.
pub type CandidatePublicationTerminalFrameComposition = CandidatePublicationResultFrameComposition<
    Option<Result<(), RequesterRendezvousLifecycleError>>,
>;

fn project_candidate_publication_terminal_parts<T, E, C>(
    result: Result<(T, C), E>,
) -> (Result<T, E>, Option<C>) {
    match result {
        Ok((committed, cleanup)) => (Ok(committed), Some(cleanup)),
        Err(error) => (Err(error), None),
    }
}

/// Projects one completed FY execution into the existing bridge semantic result plus independent
/// post-commit cleanup disposition.
///
/// This helper performs no frame encoding or I/O, requester mutation, reachability mutation, retry,
/// task/runtime drive, activation, or dialing. A successful FY outcome always remains bridge
/// semantic success even when its exact post-commit cleanup disposition is an error.
pub fn project_candidate_publication_terminal_result(
    result: Result<
        CandidatePublicationPostCommitRequesterCleanupOutcome,
        CandidatePublicationExecutionError,
    >,
) -> CandidatePublicationTerminalResultProjection {
    let (semantic_result, cleanup) = project_candidate_publication_terminal_parts(
        result.map(CandidatePublicationPostCommitRequesterCleanupOutcome::into_parts),
    );

    CandidatePublicationTerminalResultProjection {
        semantic_result,
        cleanup,
    }
}

/// Constructs one terminal candidate-publication frame through the existing bridge codec while
/// preserving the exact GA cleanup channel beside the local frame-construction result.
///
/// The exact decoded command remains the sole request-correlation source. Cleanup disposition is
/// transferred unchanged into the bridge-owned generic carrier and cannot affect Accepted/Rejected
/// framing. This helper performs no frame write, stream custody, semantic execution, requester or
/// reachability mutation, retry, runtime drive, activation, or dialing.
#[must_use]
pub fn compose_candidate_publication_terminal_result_frame(
    command: &CandidatePublicationControlFrame,
    projection: CandidatePublicationTerminalResultProjection,
) -> CandidatePublicationTerminalFrameComposition {
    let (semantic_result, cleanup) = projection.into_parts();
    CandidatePublicationResultFrameComposition::new(
        encode_candidate_publication_execution_result_frame(command, semantic_result),
        cleanup,
    )
}

/// Agent-local failure while executing the dormant current-Mesh candidate semantic decomposition.
///
/// Existing candidate semantic failures remain unchanged under [`Self::Semantic`]. Exact GI
/// production-owner association failures remain separate under [`Self::OwnerLookup`] and therefore
/// cannot be flattened into requester authority, reachability commit, or peer-visible result
/// semantics before a later separately gated response-mapping checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CurrentMeshCandidatePublicationExecutionError {
    /// Existing provider-neutral candidate semantic failure.
    Semantic(CandidatePublicationExecutionError),
    /// Exact GI production-owner association lookup failed before commit.
    OwnerLookup(ProductionReachabilityOwnerCustodyLookupError),
}

impl fmt::Display for CurrentMeshCandidatePublicationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semantic(error) => {
                write!(
                    formatter,
                    "current-Mesh candidate semantic execution failed: {error}"
                )
            }
            Self::OwnerLookup(error) => {
                write!(
                    formatter,
                    "current-Mesh candidate owner lookup failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for CurrentMeshCandidatePublicationExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Semantic(error) => Some(error),
            Self::OwnerLookup(error) => Some(error),
        }
    }
}

impl From<CandidatePublicationExecutionError> for CurrentMeshCandidatePublicationExecutionError {
    fn from(error: CandidatePublicationExecutionError) -> Self {
        Self::Semantic(error)
    }
}

impl From<ProductionReachabilityOwnerCustodyLookupError>
    for CurrentMeshCandidatePublicationExecutionError
{
    fn from(error: ProductionReachabilityOwnerCustodyLookupError) -> Self {
        Self::OwnerLookup(error)
    }
}

/// Bounded construction failure for one shared requester/rendezvous authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedRequesterRendezvousAuthorityConstructionError(
    expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError,
);

impl fmt::Display for SharedRequesterRendezvousAuthorityConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("shared requester/rendezvous scheduling-consumption construction failed")
    }
}

impl std::error::Error for SharedRequesterRendezvousAuthorityConstructionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// One irreversibly consumed, operation-scoped expected-device scheduling authority.
///
/// This carrier is constructed only after the exact requester-session/target key has been inserted
/// into the terminal scheduling-consumption ledger. It is intentionally neither `Copy` nor `Clone`.
/// It contains no endpoint, transport identity, request ID, admission session ID, timing value,
/// dispatcher, sender, candidate payload, or reachability authority.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExpectedDeviceSchedulingAuthorityGrant {
    requester_session_id: SessionId,
    target_device_id: DeviceId,
}

#[allow(
    dead_code,
    reason = "C03e-NS materializes the one-shot scheduling grant before separately gated caller/result-custody integration"
)]
impl ExpectedDeviceSchedulingAuthorityGrant {
    const fn new(requester_session_id: SessionId, target_device_id: DeviceId) -> Self {
        Self {
            requester_session_id,
            target_device_id,
        }
    }

    #[must_use]
    pub(super) const fn requester_session_id(&self) -> &SessionId {
        &self.requester_session_id
    }

    #[must_use]
    pub(super) const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }

    #[must_use]
    pub(super) fn into_parts(self) -> (SessionId, DeviceId) {
        (self.requester_session_id, self.target_device_id)
    }
}

/// Fail-closed stage classification for dormant post-registration scheduling-authority derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum ExpectedDeviceSchedulingAuthorityDerivationError {
    /// Exactly one current requester/rendezvous relationship could not be established.
    RequesterRendezvousAuthority(RequesterRendezvousAuthorityError),
    /// Provider-selected requester-session/target identity did not match the exact operation key.
    OperationIdentityMismatch,
    /// Fresh current-registry validation failed.
    RegistryValidation(RequesterRendezvousStartRegistryValidationError),
    /// Fresh requester-aware policy resolution failed.
    PolicySource(RequesterRendezvousStartPolicySourceError),
    /// Fresh requester-start policy authorization denied the operation.
    PolicyAuthorization(RequesterRendezvousStartPolicyAuthorizationError),
    /// The exact scheduling-consumption key was already terminally committed.
    AlreadyConsumed,
    /// A distinct scheduling-consumption key cannot be retained because the ledger is full.
    CapacityExhausted,
    /// A constructor-only consumption-state classification surfaced after valid owner construction.
    ConsumptionStateInvariant,
}

impl fmt::Display for ExpectedDeviceSchedulingAuthorityDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequesterRendezvousAuthority(_) => {
                "expected-device scheduling derivation requester authority failed"
            }
            Self::OperationIdentityMismatch => {
                "expected-device scheduling derivation operation identity mismatch"
            }
            Self::RegistryValidation(_) => {
                "expected-device scheduling derivation registry validation failed"
            }
            Self::PolicySource(_) => "expected-device scheduling derivation policy source failed",
            Self::PolicyAuthorization(_) => {
                "expected-device scheduling derivation policy authorization failed"
            }
            Self::AlreadyConsumed => "expected-device scheduling authority already consumed",
            Self::CapacityExhausted => "expected-device scheduling-consumption capacity exhausted",
            Self::ConsumptionStateInvariant => {
                "expected-device scheduling-consumption invariant state failed"
            }
        })
    }
}

impl std::error::Error for ExpectedDeviceSchedulingAuthorityDerivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequesterRendezvousAuthority(error) => Some(error),
            Self::RegistryValidation(error) => Some(error),
            Self::PolicySource(error) => Some(error),
            Self::PolicyAuthorization(error) => Some(error),
            Self::OperationIdentityMismatch
            | Self::AlreadyConsumed
            | Self::CapacityExhausted
            | Self::ConsumptionStateInvariant => None,
        }
    }
}

const fn map_expected_device_scheduling_consumption_error(
    error: expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError,
) -> ExpectedDeviceSchedulingAuthorityDerivationError {
    match error {
        expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError::InvalidCapacity => {
            ExpectedDeviceSchedulingAuthorityDerivationError::ConsumptionStateInvariant
        }
        expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError::AlreadyConsumed => {
            ExpectedDeviceSchedulingAuthorityDerivationError::AlreadyConsumed
        }
        expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError::CapacityExhausted => {
            ExpectedDeviceSchedulingAuthorityDerivationError::CapacityExhausted
        }
    }
}

/// Process-local requester/rendezvous plus terminal scheduling-consumption state under one mutex.
struct SharedRequesterRendezvousState {
    runtime_owner: CandidatePublicationRequesterRendezvousRuntimeOwner,
    expected_device_scheduling_consumption_ledger:
        expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedger,
}

/// Cloneable handle to exactly one process-local requester/rendezvous composite authority state.
///
/// Clones share only the outer [`Arc`]. The existing runtime owner, provider state and terminal
/// scheduling-consumption state are never cloned or snapshotted. Operation callers cannot obtain the
/// raw mutex, guard, runtime owner, provider, or scheduling ledger.
pub struct SharedRequesterRendezvousAuthority {
    state: Arc<Mutex<SharedRequesterRendezvousState>>,
}

impl Clone for SharedRequesterRendezvousAuthority {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl SharedRequesterRendezvousAuthority {
    /// Takes by-value custody of the exact existing requester/rendezvous runtime owner and explicit
    /// scheduling-consumption capacity.
    ///
    /// The exact capacity is forwarded unchanged to the existing C03e-NO ledger constructor once.
    /// Construction performs no registration, authorization, I/O, task creation, readiness
    /// publication, peer disposition, provider cloning, scheduling grant creation or ledger commit.
    ///
    /// # Errors
    ///
    /// Returns a bounded construction error when the existing ledger constructor rejects the exact
    /// scheduling-consumption capacity. No partial shared owner escapes.
    pub fn new(
        runtime_owner: CandidatePublicationRequesterRendezvousRuntimeOwner,
        expected_device_scheduling_consumption_max_records: usize,
    ) -> Result<Self, SharedRequesterRendezvousAuthorityConstructionError> {
        let expected_device_scheduling_consumption_ledger =
            expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedger::new(
                expected_device_scheduling_consumption_max_records,
            )
            .map_err(SharedRequesterRendezvousAuthorityConstructionError)?;
        Ok(Self {
            state: Arc::new(Mutex::new(SharedRequesterRendezvousState {
                runtime_owner,
                expected_device_scheduling_consumption_ledger,
            })),
        })
    }

    /// Runs the exact DI -> DP -> DK -> DN requester-start composition under FO lock ordering.
    ///
    /// The requester/rendezvous mutex is acquired first. While that guard remains held, the exact
    /// existing shared-current registry/policy read is acquired and the synchronous existing DR
    /// composition runs once. The current-authority guard is released by
    /// `with_current_authority(...)`, then this method releases the requester-authority guard before
    /// returning to FB. Consequently FD/FH response framing and I/O occur after both authority
    /// guards have been released.
    ///
    /// # Errors
    ///
    /// Returns the exact existing requester/rendezvous start composition error without translation,
    /// retry, fallback, replacement registration, provider reset, or peer close.
    pub async fn validate_authorize_and_register_requester_rendezvous_start<
        P: PolicyEvaluator + Send + Sync,
        S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    >(
        &self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: &S,
        intent: RequesterRendezvousStartIntent,
    ) -> Result<(), RequesterRendezvousStartCompositionError> {
        let mut state = self.state.lock().await;

        authority
            .with_current_authority(|registry, _current_capability_policy| {
                validate_authorize_and_register_requester_rendezvous_start(
                    registry,
                    policy_source,
                    &mut state.runtime_owner,
                    intent,
                )
            })
            .await
    }

    /// Derives one dormant one-shot expected-device scheduling authority after registration success.
    ///
    /// Requester/target inputs are non-authorizing operation selectors only. The requester mutex is
    /// acquired first. Existing provider authorization is used only as an ephemeral exactly-one
    /// current relationship witness; its candidate-publication grant is confined to a lexical block
    /// and dropped before fresh scheduling registry/policy reauthorization. While requester custody
    /// remains held, one fresh shared-current read spans registry validation, requester-aware
    /// `RequesterRendezvousStart` policy authorization, terminal scheduling-consumption insertion and
    /// infallible one-shot grant construction. Both locks are released before this method returns.
    ///
    /// This method performs no requester registration, candidate publication, provider cleanup,
    /// response I/O, request construction, channel send, task spawn, retry, remint, listener/runtime
    /// activation or deployment.
    ///
    /// # Errors
    ///
    /// Fails closed when unique current requester authority cannot be established, the provider-held
    /// relationship does not match the exact operation selectors, fresh registry/policy gates fail,
    /// the terminal key was already consumed, finite consumption capacity is exhausted, or an
    /// impossible constructor-only consumption-state classification is observed.
    #[allow(
        dead_code,
        clippy::significant_drop_tightening,
        reason = "C03e-NS intentionally retains the requester guard across fresh current-authority reauthorization and terminal consumption to preserve the NR-selected lock order and atomic derivation boundary"
    )]
    pub(super) async fn derive_expected_device_scheduling_authority<
        P: PolicyEvaluator + Send + Sync,
        S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    >(
        &self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: &S,
        requester_session_id: &SessionId,
        target_device_id: &DeviceId,
    ) -> Result<
        ExpectedDeviceSchedulingAuthorityGrant,
        ExpectedDeviceSchedulingAuthorityDerivationError,
    > {
        let mut state = self.state.lock().await;

        let (requester_session, exact_target_device_id) = {
            let relationship = state
                .runtime_owner
                .authorize_current_requester_rendezvous_for_publisher(target_device_id)
                .map_err(
                    ExpectedDeviceSchedulingAuthorityDerivationError::RequesterRendezvousAuthority,
                )?;

            if relationship.requester_session().session_id() != requester_session_id
                || relationship.expected_publisher_device_id() != target_device_id
            {
                return Err(
                    ExpectedDeviceSchedulingAuthorityDerivationError::OperationIdentityMismatch,
                );
            }

            (
                relationship.requester_session().clone(),
                relationship.expected_publisher_device_id().clone(),
            )
        };

        authority
            .with_current_authority(|registry, _current_capability_policy| {
                let validated = validate_current_requester_rendezvous_start_intent(
                    registry,
                    RequesterRendezvousStartIntent::new(requester_session, exact_target_device_id),
                )
                .map_err(ExpectedDeviceSchedulingAuthorityDerivationError::RegistryValidation)?;

                let evaluator = policy_source
                    .evaluator_for_requester(validated.requester_session())
                    .map_err(ExpectedDeviceSchedulingAuthorityDerivationError::PolicySource)?;

                let committed_requester_session_id =
                    validated.requester_session().session_id().clone();
                let committed_target_device_id = validated.target_device_id().clone();

                {
                    let _authorized =
                        policy_authorize_requester_rendezvous_start(validated, evaluator).map_err(
                            ExpectedDeviceSchedulingAuthorityDerivationError::PolicyAuthorization,
                        )?;
                }

                state
                    .expected_device_scheduling_consumption_ledger
                    .commit_requester_target_if_absent(
                        committed_requester_session_id.clone(),
                        committed_target_device_id.clone(),
                    )
                    .map_err(map_expected_device_scheduling_consumption_error)?;

                Ok(ExpectedDeviceSchedulingAuthorityGrant::new(
                    committed_requester_session_id,
                    committed_target_device_id,
                ))
            })
            .await
    }

    /// Selects one current requester/rendezvous grant under bounded shared-authority custody.
    ///
    /// The requester mutex is held only for the synchronous provider authorization call and is
    /// released before this async method returns. No durable reachability work or response I/O is
    /// executed while the guard exists.
    async fn authorize_current_for_publisher(
        &self,
        publisher_device_id: &DeviceId,
    ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> {
        let mut state = self.state.lock().await;
        state
            .runtime_owner
            .authorize_current_requester_rendezvous_for_publisher(publisher_device_id)
    }

    /// Reacquires shared requester authority only to retire and remove one exact committed record.
    ///
    /// This operation is called only after definite durable reachability commit success. It holds
    /// the requester mutex across the synchronous exact `retire -> remove_retired` pair and releases
    /// it before returning. It performs no retry, rollback, response I/O, or publisher peer action.
    async fn cleanup_committed_requester_rendezvous_record(
        &self,
        identity: RequesterRendezvousCommittedCleanupIdentity,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        let mut state = self.state.lock().await;
        state
            .runtime_owner
            .cleanup_committed_requester_rendezvous_record(
                &identity.requester_session_id,
                &identity.expected_publisher_device_id,
            )
    }

    async fn commit_then_cleanup<T, E, C>(
        &self,
        identity: RequesterRendezvousCommittedCleanupIdentity,
        commit: C,
    ) -> Result<(T, Result<(), RequesterRendezvousLifecycleError>), E>
    where
        C: AsyncFnOnce() -> Result<T, E>,
    {
        let committed = commit().await?;
        let cleanup = self
            .cleanup_committed_requester_rendezvous_record(identity)
            .await;
        Ok((committed, cleanup))
    }

    /// Executes the GJ-selected dormant envelope-neutral current-Mesh candidate semantic phases.
    ///
    /// The method deliberately accepts no historical PRWC connection or historical candidate
    /// command envelope, no current-Mesh stream and no request ID. Publisher identity comes only
    /// from `publisher_session`; candidate transport/freshness/candidates come only from the strict
    /// typed `submission`.
    ///
    /// Ordering is exact:
    ///
    /// 1. one bounded current-authority read creates an owned registry-current publication;
    /// 2. that read is released before requester authority selects one exact current grant;
    /// 3. expected publisher equality is checked after requester lock release;
    /// 4. a second fresh current-authority read is acquired for commit-time currentness;
    /// 5. while that same read remains held, exact GI `publication.peer()` lookup obtains one lexical
    ///    production-owner mutable borrow and the existing durable commit is awaited;
    /// 6. only after durable completion are production-owner and current-authority custody released;
    /// 7. only definite durable commit success reacquires requester authority for exact cleanup.
    ///
    /// The same current-authority read and the exact selected production-owner mutable borrow now
    /// cross only the durable commit `.await`, as required by GR. This adds no map synchronization,
    /// task, response I/O, retry, peer-close behavior, runtime activation, traversal or dialing.
    ///
    /// # Errors
    ///
    /// Existing semantic failures are preserved under
    /// [`CurrentMeshCandidatePublicationExecutionError::Semantic`]. Exact GI missing/ambiguous
    /// association failures are preserved under
    /// [`CurrentMeshCandidatePublicationExecutionError::OwnerLookup`]. No failure is translated into
    /// a wire result or fallback owner selection.
    #[allow(
        dead_code,
        reason = "C03e-GK materializes dormant current-Mesh semantic decomposition before separately gated higher-owner handoff and response custody"
    )]
    pub async fn execute_current_mesh_candidate_publication_with_post_commit_cleanup<P, S, T>(
        &self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        publisher_session: &AuthenticatedDeviceSession,
        submission: &CandidatePublicationWireSubmission,
        owner_map: &mut ProductionReachabilityOwnerCustodyMap<S, T>,
    ) -> Result<
        CandidatePublicationPostCommitRequesterCleanupOutcome,
        CurrentMeshCandidatePublicationExecutionError,
    >
    where
        P: PolicyEvaluator + Send + Sync,
        S: ReachabilityDurableStore + Send,
        T: CandidatePublicationFreshnessTokenSource + Send,
    {
        let publication = authority
            .with_current_authority(|registry, _policy| {
                publish_current_candidates(
                    registry,
                    publisher_session,
                    submission.presented_transport_identity(),
                    submission.candidates().to_vec(),
                )
            })
            .await
            .map_err(CandidatePublicationExecutionError::Candidate)?;

        let publisher_device_id = publication.peer().device_id();
        let grant = self
            .authorize_current_for_publisher(publisher_device_id)
            .await
            .map_err(CandidatePublicationExecutionError::RequesterAuthority)?;
        if grant.expected_publisher_device_id() != publisher_device_id {
            return Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch.into());
        }

        let cleanup_identity = RequesterRendezvousCommittedCleanupIdentity::from_grant(&grant);
        let commit_result = authority
            .with_current_authority_async(async |registry, _policy| {
                owner_map
                    .with_owner_mut_for_peer_async(publication.peer(), async |owner| {
                        owner
                            .commit_candidate_publication(
                                registry,
                                grant.requester_session(),
                                &publication,
                                submission.presented_freshness(),
                            )
                            .await
                            .map_err(CandidatePublicationExecutionError::Reachability)
                    })
                    .await
            })
            .await;

        let reachability_commit = commit_result??;
        let cleanup = self
            .cleanup_committed_requester_rendezvous_record(cleanup_identity)
            .await;

        Ok(CandidatePublicationPostCommitRequesterCleanupOutcome {
            reachability_commit,
            cleanup,
        })
    }

    /// Executes one candidate-publication semantic attempt with FX-selected post-commit cleanup.
    ///
    /// Ordering is exact and fail-closed:
    ///
    /// 1. authenticated publisher/session/transport/candidate admission occurs without requester
    ///    mutex custody;
    /// 2. the requester mutex is acquired only long enough to select one exact current grant;
    /// 3. exact expected-publisher equality is checked after the grant-selection guard is released;
    /// 4. the existing durable reachability owner commits while no requester mutex guard exists;
    /// 5. only after definite commit success is requester authority reacquired for exact
    ///    `retire -> remove_retired` cleanup;
    /// 6. the committed reachability outcome and cleanup disposition are returned separately.
    ///
    /// Candidate admission, requester authorization, expected-publisher mismatch, or reachability
    /// commit failure returns the existing [`CandidatePublicationExecutionError`] and performs no
    /// cleanup. Cleanup failure after commit remains inside the successful post-commit outcome and
    /// therefore cannot become a generic wire-level Rejected result for an already-committed
    /// publication.
    ///
    /// This seam reads/writes no frame, allocates no request ID, spawns no task, starts no command
    /// loop, selects no target dialing, and activates no listener/network runtime.
    ///
    /// # Errors
    ///
    /// Returns the existing candidate-publication execution error classes only for failures before
    /// or at durable commit. Exact post-commit cleanup errors are preserved separately in the
    /// successful return value.
    pub(crate) async fn execute_authenticated_candidate_publication_with_post_commit_cleanup<S, T>(
        &self,
        connection: &AuthenticatedPrwcConnection,
        command: &CandidatePublicationControlFrame,
        registry: &WorkspaceDeviceRegistry,
        owner: &mut ProductionReachabilityOwner<S, T>,
    ) -> Result<
        CandidatePublicationPostCommitRequesterCleanupOutcome,
        CandidatePublicationExecutionError,
    >
    where
        S: ReachabilityDurableStore,
        T: CandidatePublicationFreshnessTokenSource,
    {
        let submission = command.submission();
        let publication = publish_current_candidates(
            registry,
            connection.session(),
            submission.presented_transport_identity(),
            submission.candidates().to_vec(),
        )
        .map_err(CandidatePublicationExecutionError::Candidate)?;

        let publisher_device_id = publication.peer().device_id();
        let grant = self
            .authorize_current_for_publisher(publisher_device_id)
            .await
            .map_err(CandidatePublicationExecutionError::RequesterAuthority)?;
        if grant.expected_publisher_device_id() != publisher_device_id {
            return Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch);
        }

        let cleanup_identity = RequesterRendezvousCommittedCleanupIdentity::from_grant(&grant);
        let (reachability_commit, cleanup) = self
            .commit_then_cleanup(cleanup_identity, async || {
                owner
                    .commit_candidate_publication(
                        registry,
                        grant.requester_session(),
                        &publication,
                        submission.presented_freshness(),
                    )
                    .await
                    .map_err(CandidatePublicationExecutionError::Reachability)
            })
            .await?;

        Ok(CandidatePublicationPostCommitRequesterCleanupOutcome {
            reachability_commit,
            cleanup,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, sync::Arc};

    use prw_core::{DeviceId, SessionId};
    use prw_remote_bridge::{
        candidate_publication_execution::CandidatePublicationExecutionError,
        candidate_publication_result_wire::CandidatePublicationResultWireError,
        requester_rendezvous_authority::RequesterRendezvousAuthorityError,
        requester_rendezvous_in_memory_provider::{
            InMemoryRequesterRendezvousAuthorityProvider, RequesterRendezvousLifecycleError,
        },
    };
    use tokio::runtime::Builder;

    use super::{
        CandidatePublicationPostCommitRequesterCleanupOutcome,
        CandidatePublicationTerminalFrameComposition, CandidatePublicationTerminalResultProjection,
        CurrentMeshCandidatePublicationExecutionError,
        ExpectedDeviceSchedulingAuthorityDerivationError, ExpectedDeviceSchedulingAuthorityGrant,
        RequesterRendezvousCommittedCleanupIdentity, SharedRequesterRendezvousAuthority,
        compose_candidate_publication_terminal_result_frame,
        map_expected_device_scheduling_consumption_error,
        project_candidate_publication_terminal_parts,
        project_candidate_publication_terminal_result,
    };
    use crate::{
        candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner,
        production_reachability_owner_custody::ProductionReachabilityOwnerCustodyLookupError,
    };

    fn block_on<F: Future>(future: F) -> F::Output {
        Builder::new_current_thread()
            .build()
            .expect("construct FY test runtime")
            .block_on(future)
    }

    fn authority_with_capacity(capacity: usize) -> SharedRequesterRendezvousAuthority {
        let provider = InMemoryRequesterRendezvousAuthorityProvider::new(capacity)
            .expect("explicit non-zero provider capacity");
        SharedRequesterRendezvousAuthority::new(
            CandidatePublicationRequesterRendezvousRuntimeOwner::new(provider),
            capacity,
        )
        .expect("explicit non-zero scheduling-consumption capacity")
    }

    fn unknown_cleanup_identity() -> RequesterRendezvousCommittedCleanupIdentity {
        RequesterRendezvousCommittedCleanupIdentity {
            requester_session_id: SessionId::new("fy-cleanup-requester-unknown")
                .expect("valid requester session id"),
            expected_publisher_device_id: DeviceId::new("fy-cleanup-publisher-unknown")
                .expect("valid publisher device id"),
        }
    }

    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}

    #[test]
    fn shared_authority_is_clone_send_sync() {
        assert_clone_send_sync::<SharedRequesterRendezvousAuthority>();
    }

    #[test]
    fn clone_shares_one_runtime_owner_allocation() {
        let authority = authority_with_capacity(2);
        let clone = authority.clone();

        assert!(Arc::ptr_eq(&authority.state, &clone.state));
    }

    #[test]
    fn shared_authority_rejects_zero_scheduling_consumption_capacity() {
        let provider = InMemoryRequesterRendezvousAuthorityProvider::new(1)
            .expect("explicit non-zero provider capacity");
        assert!(
            SharedRequesterRendezvousAuthority::new(
                CandidatePublicationRequesterRendezvousRuntimeOwner::new(provider),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn scheduling_authority_grant_preserves_exact_terminal_identity() {
        let requester_session_id =
            SessionId::new("ns-requester-session").expect("valid requester session id");
        let target_device_id = DeviceId::new("ns-target-device").expect("valid target device id");
        let grant = ExpectedDeviceSchedulingAuthorityGrant::new(
            requester_session_id.clone(),
            target_device_id.clone(),
        );

        assert_eq!(grant.requester_session_id(), &requester_session_id);
        assert_eq!(grant.target_device_id(), &target_device_id);
        assert_eq!(grant.into_parts(), (requester_session_id, target_device_id));
    }

    #[test]
    fn scheduling_consumption_errors_map_to_bounded_derivation_outcomes() {
        use super::expected_device_scheduling_consumption_ledger::ExpectedDeviceSchedulingConsumptionLedgerError;

        assert_eq!(
            map_expected_device_scheduling_consumption_error(
                ExpectedDeviceSchedulingConsumptionLedgerError::AlreadyConsumed,
            ),
            ExpectedDeviceSchedulingAuthorityDerivationError::AlreadyConsumed
        );
        assert_eq!(
            map_expected_device_scheduling_consumption_error(
                ExpectedDeviceSchedulingConsumptionLedgerError::CapacityExhausted,
            ),
            ExpectedDeviceSchedulingAuthorityDerivationError::CapacityExhausted
        );
        assert_eq!(
            map_expected_device_scheduling_consumption_error(
                ExpectedDeviceSchedulingConsumptionLedgerError::InvalidCapacity,
            ),
            ExpectedDeviceSchedulingAuthorityDerivationError::ConsumptionStateInvariant
        );
    }

    #[test]
    fn current_grant_selection_releases_requester_mutex_before_return() {
        let authority = authority_with_capacity(1);
        let publisher_device_id =
            DeviceId::new("fy-missing-publisher").expect("valid publisher device id");

        assert_eq!(
            block_on(authority.authorize_current_for_publisher(&publisher_device_id)),
            Err(RequesterRendezvousAuthorityError::Missing)
        );
        assert!(authority.state.try_lock().is_ok());
    }

    #[test]
    fn commit_runs_without_requester_guard_and_cleanup_failure_preserves_committed_value() {
        let authority = authority_with_capacity(1);
        let identity = unknown_cleanup_identity();

        let result = block_on(authority.commit_then_cleanup(identity, async || {
            assert!(authority.state.try_lock().is_ok());
            Ok::<u8, ()>(7)
        }));

        assert_eq!(
            result,
            Ok((7, Err(RequesterRendezvousLifecycleError::RecordUnknown)))
        );
        assert!(authority.state.try_lock().is_ok());
    }

    #[test]
    fn commit_failure_returns_before_cleanup_phase() {
        let authority = authority_with_capacity(1);
        let identity = unknown_cleanup_identity();

        let result = block_on(authority.commit_then_cleanup(identity, async || {
            assert!(authority.state.try_lock().is_ok());
            Err::<u8, _>("commit failed")
        }));

        assert_eq!(result, Err("commit failed"));
        assert!(authority.state.try_lock().is_ok());
    }

    #[test]
    fn current_mesh_owner_lookup_missing_remains_separate_from_semantic_error() {
        let error = CurrentMeshCandidatePublicationExecutionError::from(
            ProductionReachabilityOwnerCustodyLookupError::Missing,
        );

        assert_eq!(
            error,
            CurrentMeshCandidatePublicationExecutionError::OwnerLookup(
                ProductionReachabilityOwnerCustodyLookupError::Missing
            )
        );
    }

    #[test]
    fn current_mesh_owner_lookup_ambiguous_remains_distinguishable() {
        let error = CurrentMeshCandidatePublicationExecutionError::from(
            ProductionReachabilityOwnerCustodyLookupError::Ambiguous,
        );

        assert_eq!(
            error,
            CurrentMeshCandidatePublicationExecutionError::OwnerLookup(
                ProductionReachabilityOwnerCustodyLookupError::Ambiguous
            )
        );
    }

    #[test]
    fn current_mesh_semantic_error_remains_separate_from_owner_lookup() {
        let error = CurrentMeshCandidatePublicationExecutionError::from(
            CandidatePublicationExecutionError::ExpectedPublisherMismatch,
        );

        assert_eq!(
            error,
            CurrentMeshCandidatePublicationExecutionError::Semantic(
                CandidatePublicationExecutionError::ExpectedPublisherMismatch
            )
        );
    }

    #[test]
    fn terminal_projection_preserves_pre_commit_error_and_absent_cleanup() {
        let result: Result<
            (u8, Result<(), RequesterRendezvousLifecycleError>),
            CandidatePublicationExecutionError,
        > = Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch);

        let (semantic_result, cleanup) = project_candidate_publication_terminal_parts(result);

        assert_eq!(
            semantic_result,
            Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch)
        );
        assert_eq!(cleanup, None);
    }

    #[test]
    fn terminal_projection_preserves_committed_success_and_cleanup_success() {
        let result: Result<
            (u8, Result<(), RequesterRendezvousLifecycleError>),
            CandidatePublicationExecutionError,
        > = Ok((7, Ok(())));

        let (semantic_result, cleanup) = project_candidate_publication_terminal_parts(result);

        assert_eq!(semantic_result, Ok(7));
        assert_eq!(cleanup, Some(Ok(())));
    }

    #[test]
    fn terminal_projection_cleanup_failure_cannot_rewrite_committed_success() {
        let cleanup_error = RequesterRendezvousLifecycleError::RecordUnknown;
        let result: Result<
            (u8, Result<(), RequesterRendezvousLifecycleError>),
            CandidatePublicationExecutionError,
        > = Ok((11, Err(cleanup_error)));

        let (semantic_result, cleanup) = project_candidate_publication_terminal_parts(result);

        assert_eq!(semantic_result, Ok(11));
        assert_eq!(cleanup, Some(Err(cleanup_error)));
    }

    #[test]
    fn real_terminal_projection_adapter_has_exact_fy_to_bridge_signature() {
        let adapter: fn(
            Result<
                CandidatePublicationPostCommitRequesterCleanupOutcome,
                CandidatePublicationExecutionError,
            >,
        ) -> CandidatePublicationTerminalResultProjection =
            project_candidate_publication_terminal_result;

        std::hint::black_box(adapter);
    }

    #[test]
    fn terminal_frame_composition_preserves_typed_cleanup_when_frame_construction_failed() {
        let cleanup_error = RequesterRendezvousLifecycleError::RecordUnknown;
        let composition = CandidatePublicationTerminalFrameComposition::new(
            Err(CandidatePublicationResultWireError::InvalidPayload),
            Some(Err(cleanup_error)),
        );

        let (frame_result, cleanup) = composition.into_parts();

        assert!(matches!(
            frame_result,
            Err(CandidatePublicationResultWireError::InvalidPayload)
        ));
        assert_eq!(cleanup, Some(Err(cleanup_error)));
    }

    #[test]
    fn real_terminal_frame_composition_adapter_has_exact_command_projection_shape() {
        let adapter: fn(
            &prw_remote_bridge::candidate_publication_control_frame::CandidatePublicationControlFrame,
            CandidatePublicationTerminalResultProjection,
        ) -> CandidatePublicationTerminalFrameComposition =
            compose_candidate_publication_terminal_result_frame;

        std::hint::black_box(adapter);
    }
}

/// Dormant process-local representation of terminal expected-device scheduling consumption.
///
/// C03e-NO materializes the C03e-NL/NM-selected private representation primitive. C03e-NQ attaches
/// one instance to the shared requester/rendezvous composite state without exposing a scheduling
/// mint/commit API. The module performs no environment read, requester/rendezvous provider mutation,
/// scheduling grant creation, expected-device request construction, runtime activation, persistence,
/// eviction or cleanup.
#[allow(
    dead_code,
    reason = "C03e-NQ integrates the selected scheduling-consumption ledger under shared requester custody before separately gated scheduling-authority derivation"
)]
mod expected_device_scheduling_consumption_ledger {
    use prw_core::{DeviceId, SessionId};

    /// Exact terminal-consumption identity selected by C03e-NL.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ExpectedDeviceSchedulingConsumptionKey {
        requester_session_id: SessionId,
        target_device_id: DeviceId,
    }

    impl ExpectedDeviceSchedulingConsumptionKey {
        const fn new(requester_session_id: SessionId, target_device_id: DeviceId) -> Self {
            Self {
                requester_session_id,
                target_device_id,
            }
        }
    }

    /// Bounded representation-level failure for terminal scheduling-consumption state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum ExpectedDeviceSchedulingConsumptionLedgerError {
        /// Zero is not a usable terminal-consumption ledger capacity.
        InvalidCapacity,
        /// The exact requester-session plus target-device key was already committed.
        AlreadyConsumed,
        /// A new distinct key cannot be retained because the finite bound is full.
        CapacityExhausted,
    }

    impl std::fmt::Display for ExpectedDeviceSchedulingConsumptionLedgerError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(match self {
                Self::InvalidCapacity => "expected-device scheduling-consumption capacity invalid",
                Self::AlreadyConsumed => "expected-device scheduling authority already consumed",
                Self::CapacityExhausted => {
                    "expected-device scheduling-consumption capacity exhausted"
                }
            })
        }
    }

    impl std::error::Error for ExpectedDeviceSchedulingConsumptionLedgerError {}

    /// Finite process-local identity set for terminal expected-device scheduling consumption.
    ///
    /// Records are never removed, evicted, expired or compacted by this representation. The
    /// semantic linearization point is successful insertion by [`Self::commit_if_absent`].
    #[derive(Debug)]
    pub(super) struct ExpectedDeviceSchedulingConsumptionLedger {
        max_records: usize,
        consumed: Vec<ExpectedDeviceSchedulingConsumptionKey>,
    }

    impl ExpectedDeviceSchedulingConsumptionLedger {
        pub(super) const fn new(
            max_records: usize,
        ) -> Result<Self, ExpectedDeviceSchedulingConsumptionLedgerError> {
            if max_records == 0 {
                return Err(ExpectedDeviceSchedulingConsumptionLedgerError::InvalidCapacity);
            }

            Ok(Self {
                max_records,
                consumed: Vec::new(),
            })
        }

        pub(super) fn commit_requester_target_if_absent(
            &mut self,
            requester_session_id: SessionId,
            target_device_id: DeviceId,
        ) -> Result<(), ExpectedDeviceSchedulingConsumptionLedgerError> {
            self.commit_if_absent(ExpectedDeviceSchedulingConsumptionKey::new(
                requester_session_id,
                target_device_id,
            ))
        }

        fn commit_if_absent(
            &mut self,
            key: ExpectedDeviceSchedulingConsumptionKey,
        ) -> Result<(), ExpectedDeviceSchedulingConsumptionLedgerError> {
            if self.consumed.iter().any(|existing| existing == &key) {
                return Err(ExpectedDeviceSchedulingConsumptionLedgerError::AlreadyConsumed);
            }
            if self.consumed.len() >= self.max_records {
                return Err(ExpectedDeviceSchedulingConsumptionLedgerError::CapacityExhausted);
            }

            self.consumed.push(key);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use prw_core::{DeviceId, SessionId};

        use super::{
            ExpectedDeviceSchedulingConsumptionKey, ExpectedDeviceSchedulingConsumptionLedger,
            ExpectedDeviceSchedulingConsumptionLedgerError,
        };

        fn key(requester: &str, target: &str) -> ExpectedDeviceSchedulingConsumptionKey {
            ExpectedDeviceSchedulingConsumptionKey::new(
                SessionId::new(requester).expect("valid requester session id"),
                DeviceId::new(target).expect("valid target device id"),
            )
        }

        #[test]
        fn constructor_rejects_zero_capacity_and_accepts_positive_capacity() {
            assert!(matches!(
                ExpectedDeviceSchedulingConsumptionLedger::new(0),
                Err(ExpectedDeviceSchedulingConsumptionLedgerError::InvalidCapacity)
            ));
            assert!(ExpectedDeviceSchedulingConsumptionLedger::new(1).is_ok());
        }

        #[test]
        fn exact_requester_session_and_target_device_pair_is_the_only_key_identity() {
            let mut ledger =
                ExpectedDeviceSchedulingConsumptionLedger::new(3).expect("positive capacity");

            assert_eq!(
                ledger.commit_if_absent(key("requester-a", "target-a")),
                Ok(())
            );
            assert_eq!(
                ledger.commit_if_absent(key("requester-a", "target-b")),
                Ok(())
            );
            assert_eq!(
                ledger.commit_if_absent(key("requester-b", "target-a")),
                Ok(())
            );
            assert_eq!(ledger.consumed.len(), 3);
        }

        #[test]
        fn duplicate_is_classified_before_capacity_exhaustion() {
            let mut ledger =
                ExpectedDeviceSchedulingConsumptionLedger::new(1).expect("positive capacity");
            let consumed = key("requester-a", "target-a");

            assert_eq!(ledger.commit_if_absent(consumed.clone()), Ok(()));
            assert_eq!(
                ledger.commit_if_absent(consumed),
                Err(ExpectedDeviceSchedulingConsumptionLedgerError::AlreadyConsumed)
            );
            assert_eq!(
                ledger.commit_if_absent(key("requester-b", "target-b")),
                Err(ExpectedDeviceSchedulingConsumptionLedgerError::CapacityExhausted)
            );
            assert_eq!(ledger.consumed.len(), 1);
        }

        #[test]
        fn failed_commits_do_not_mutate_terminal_consumption_state() {
            let mut ledger =
                ExpectedDeviceSchedulingConsumptionLedger::new(1).expect("positive capacity");

            assert_eq!(
                ledger.commit_if_absent(key("requester-a", "target-a")),
                Ok(())
            );
            assert_eq!(
                ledger.commit_if_absent(key("requester-b", "target-b")),
                Err(ExpectedDeviceSchedulingConsumptionLedgerError::CapacityExhausted)
            );
            assert_eq!(ledger.consumed, vec![key("requester-a", "target-a")]);
        }
    }
}
