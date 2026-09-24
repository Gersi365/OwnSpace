//! Phase 152 C02f-AB deterministic live-owner transaction planning and reconciliation.
//!
//! This module materializes the provider-owned, runtime-independent transaction semantics selected by
//! C02f-Z. It does not call `etcd-client`, open an endpoint, create a runtime, perform network I/O,
//! generate randomness, allocate fences or activate production authority. Instead it builds canonical
//! mutation plans from validated `PRWL` records and classifies definitive or re-observed outcomes.

use std::{fmt, num::NonZeroU128};

use prw_connectivity::PeerConnectivityIdentity;

use crate::reachability_live_owner_codec::{
    LiveOwnerLifecycle, ReachabilityLiveOwnerAuthorityRecord, ReachabilityLiveOwnerCodecError,
    decode_bound_live_owner_record, encode_live_owner_key, encode_live_owner_record,
};

/// One validated exact-key authority observation from a linearizable provider read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOwnerObservation {
    key: Vec<u8>,
    value: Vec<u8>,
    mod_revision: i64,
    record: ReachabilityLiveOwnerAuthorityRecord,
}

impl LiveOwnerObservation {
    /// Decodes one existing exact-key authority observation.
    ///
    /// # Errors
    ///
    /// Returns an error when `mod_revision` is not positive or key/value bytes fail canonical
    /// decoding and exact-peer binding.
    pub fn decode(
        key: Vec<u8>,
        value: Vec<u8>,
        mod_revision: i64,
    ) -> Result<Self, LiveOwnerTxnError> {
        if mod_revision <= 0 {
            return Err(LiveOwnerTxnError::InvalidModRevision);
        }
        let record = decode_bound_live_owner_record(&key, &value)?;
        Ok(Self {
            key,
            value,
            mod_revision,
            record,
        })
    }

    /// Returns the exact encoded etcd key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the exact canonical record bytes observed at `mod_revision`.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the positive etcd `mod_revision` captured by the linearizable read.
    #[must_use]
    pub const fn mod_revision(&self) -> i64 {
        self.mod_revision
    }

    /// Returns the decoded exact-peer authority record.
    #[must_use]
    pub const fn record(&self) -> &ReachabilityLiveOwnerAuthorityRecord {
        &self.record
    }

    fn same_state_as(&self, other: &Self) -> bool {
        self.key == other.key
            && self.value == other.value
            && self.mod_revision == other.mod_revision
            && self.record == other.record
    }
}

/// One exact compare in the selected conjunctive mutation guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveOwnerTxnCompare {
    /// Requires the exact key's `mod_revision` to equal the observed revision.
    ModRevisionEquals {
        /// Exact binary authority key.
        key: Vec<u8>,
        /// Observed positive `mod_revision`.
        expected: i64,
    },
    /// Requires the exact key's value bytes to remain byte-identical.
    ExactValueEquals {
        /// Exact binary authority key.
        key: Vec<u8>,
        /// Canonical authority bytes from the preceding linearizable read.
        expected: Vec<u8>,
    },
}

/// One deterministic operation in a live-owner transaction branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveOwnerTxnOperation {
    /// Writes one complete canonical successor record.
    Put {
        /// Exact binary authority key.
        key: Vec<u8>,
        /// Complete canonical successor bytes.
        value: Vec<u8>,
    },
    /// Reads the exact key using latest/linearizable semantics.
    LinearizableGet {
        /// Exact binary authority key.
        key: Vec<u8>,
    },
}

/// Canonical dual-CAS mutation plan selected by C02f-Z.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOwnerTxnPlan {
    compares: [LiveOwnerTxnCompare; 2],
    success: LiveOwnerTxnOperation,
    failure: LiveOwnerTxnOperation,
    successor: ReachabilityLiveOwnerAuthorityRecord,
}

impl LiveOwnerTxnPlan {
    /// Returns the exact two conjunctive compares in provider order.
    #[must_use]
    pub const fn compares(&self) -> &[LiveOwnerTxnCompare; 2] {
        &self.compares
    }

    /// Returns the success branch, which is exactly one canonical `Put`.
    #[must_use]
    pub const fn success(&self) -> &LiveOwnerTxnOperation {
        &self.success
    }

    /// Returns the failure branch, which is exactly one linearizable `Get`.
    #[must_use]
    pub const fn failure(&self) -> &LiveOwnerTxnOperation {
        &self.failure
    }

    /// Returns the decoded successor represented by the success branch bytes.
    #[must_use]
    pub const fn successor(&self) -> &ReachabilityLiveOwnerAuthorityRecord {
        &self.successor
    }

    fn key(&self) -> &[u8] {
        match &self.success {
            LiveOwnerTxnOperation::Put { key, .. } => key,
            LiveOwnerTxnOperation::LinearizableGet { .. } => {
                unreachable!("canonical success branch is always Put")
            }
        }
    }
}

/// Definitive outcome from one provider transaction response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveOwnerDefinitiveMutation {
    /// Both selected compares passed and the canonical successor `Put` committed.
    Committed,
    /// At least one compare failed; the failure branch returned authoritative exact-key state.
    CompareFailed(LiveOwnerObservation),
}

/// Provider-level currentness result for one exact peer/fence pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOwnerProviderCurrentness {
    /// Persisted state is `Current` with the exact requested fence.
    Current,
    /// Persisted state is valid but no longer exact-current for the requested fence.
    Stale,
}

/// Release planning result before any provider mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOwnerReleasePlan {
    transaction: Option<LiveOwnerTxnPlan>,
}

impl LiveOwnerReleasePlan {
    /// Returns whether the supplied peer/fence was not current and therefore has no mutation plan.
    #[must_use]
    pub const fn is_not_current(&self) -> bool {
        self.transaction.is_none()
    }

    /// Returns the selected dual-CAS release transaction when the supplied owner was current.
    #[must_use]
    pub const fn transaction(&self) -> Option<&LiveOwnerTxnPlan> {
        self.transaction.as_ref()
    }

    /// Consumes the result and returns the selected transaction when one is permitted.
    #[must_use]
    pub fn into_transaction(self) -> Option<LiveOwnerTxnPlan> {
        self.transaction
    }
}

/// Classification after re-observing an indeterminate mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOwnerReconciliation {
    /// The intended mutation is still exact-current in authoritative state.
    Committed,
    /// The exact pre-mutation state and revision remain, proving the mutation did not commit.
    ProvenNotCommitted,
    /// A valid newer/successor state proves the intended operation is no longer authoritative.
    Superseded,
}

/// Fail-closed deterministic transaction planning or reconciliation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOwnerTxnError {
    /// Canonical key/value validation failed.
    Codec(ReachabilityLiveOwnerCodecError),
    /// Existing etcd state used a non-positive `mod_revision`.
    InvalidModRevision,
    /// Requested peer differs from the exact peer encoded in authoritative state.
    PeerMismatch,
    /// A mutation successor does not preserve the exact peer namespace.
    SuccessorPeerMismatch,
    /// Acquisition/replacement successor is not a `Current` record.
    SuccessorNotCurrent,
    /// Acquisition/replacement successor fence is not strictly newer.
    FenceNotStrictlyNewer,
    /// Acquisition/replacement reused the preceding authority attempt identifier.
    AttemptIdReused,
    /// Established authority state was unexpectedly absent.
    MissingEstablishedState,
    /// A definitive compare failure omitted its authoritative failure-branch `Get`.
    MissingFailureObservation,
    /// A definitive success unexpectedly included failure-branch observation data.
    UnexpectedFailureObservation,
    /// A transaction failure observation was for another exact key.
    FailureObservationKeyMismatch,
    /// Re-observed state would require fence rollback/reuse or another impossible transition.
    ImpossibleReobservedState,
}

impl fmt::Display for LiveOwnerTxnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Codec(error) => return write!(formatter, "{error}"),
            Self::InvalidModRevision => "live-owner mod_revision must be positive",
            Self::PeerMismatch => "live-owner requested peer does not match authoritative state",
            Self::SuccessorPeerMismatch => "live-owner successor changes exact peer namespace",
            Self::SuccessorNotCurrent => "live-owner acquisition successor must be Current",
            Self::FenceNotStrictlyNewer => "live-owner acquisition fence is not strictly newer",
            Self::AttemptIdReused => "live-owner acquisition reused authority attempt ID",
            Self::MissingEstablishedState => "established live-owner authority state is missing",
            Self::MissingFailureObservation => "compare failure omitted authoritative Get state",
            Self::UnexpectedFailureObservation => "successful transaction returned failure state",
            Self::FailureObservationKeyMismatch => {
                "transaction failure observation used another live-owner key"
            }
            Self::ImpossibleReobservedState => {
                "re-observed live-owner state violates monotonic authority history"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LiveOwnerTxnError {}

impl From<ReachabilityLiveOwnerCodecError> for LiveOwnerTxnError {
    fn from(value: ReachabilityLiveOwnerCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Builds the selected dual-CAS acquisition/replacement plan from an existing exact state.
///
/// The caller supplies an already-allocated strictly newer fence and fresh attempt identifier inside
/// `successor`; this function validates those invariants but performs no allocation or randomness.
///
/// # Errors
///
/// Returns an error for cross-peer successors, non-`Current` successors, non-increasing fences,
/// attempt-ID reuse or canonical encoding failure.
pub fn plan_acquisition(
    observed: &LiveOwnerObservation,
    successor: ReachabilityLiveOwnerAuthorityRecord,
) -> Result<LiveOwnerTxnPlan, LiveOwnerTxnError> {
    if successor.peer() != observed.record.peer() {
        return Err(LiveOwnerTxnError::SuccessorPeerMismatch);
    }
    if successor.lifecycle() != LiveOwnerLifecycle::Current {
        return Err(LiveOwnerTxnError::SuccessorNotCurrent);
    }
    if successor.fence() <= observed.record.fence() {
        return Err(LiveOwnerTxnError::FenceNotStrictlyNewer);
    }
    if successor.attempt_id() == observed.record.attempt_id() {
        return Err(LiveOwnerTxnError::AttemptIdReused);
    }
    build_mutation_plan(observed, successor)
}

/// Classifies currentness from one authoritative linearizable exact-key observation.
///
/// # Errors
///
/// Returns an error for missing established state or a requested peer that differs from the
/// authoritative exact-peer namespace.
pub fn classify_currentness(
    peer: &PeerConnectivityIdentity,
    fence: NonZeroU128,
    observation: Option<&LiveOwnerObservation>,
) -> Result<LiveOwnerProviderCurrentness, LiveOwnerTxnError> {
    let observed = observation.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
    if observed.record.peer() != peer {
        return Err(LiveOwnerTxnError::PeerMismatch);
    }
    if observed.record.lifecycle() == LiveOwnerLifecycle::Current
        && observed.record.fence() == fence
    {
        Ok(LiveOwnerProviderCurrentness::Current)
    } else {
        Ok(LiveOwnerProviderCurrentness::Stale)
    }
}

/// Builds a release plan only when the supplied exact peer/fence is still current.
///
/// # Errors
///
/// Returns an error for missing established state, peer mismatch or canonical successor encoding
/// failure. A stale/released fence is returned with no mutation transaction.
pub fn plan_release(
    peer: &PeerConnectivityIdentity,
    fence: NonZeroU128,
    observation: Option<&LiveOwnerObservation>,
) -> Result<LiveOwnerReleasePlan, LiveOwnerTxnError> {
    let observed = observation.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
    if observed.record.peer() != peer {
        return Err(LiveOwnerTxnError::PeerMismatch);
    }
    if observed.record.lifecycle() != LiveOwnerLifecycle::Current
        || observed.record.fence() != fence
    {
        return Ok(LiveOwnerReleasePlan { transaction: None });
    }

    let successor = observed.record.released_successor();
    Ok(LiveOwnerReleasePlan {
        transaction: Some(build_mutation_plan(observed, successor)?),
    })
}

/// Converts one definitive provider transaction response into a fail-closed mutation outcome.
///
/// `succeeded=true` admits no failure-branch observation. `succeeded=false` requires the exact
/// authoritative `Get` result from the transaction failure branch.
///
/// # Errors
///
/// Returns an error for structurally impossible response combinations, missing established state or
/// a failure observation for another exact key.
pub fn classify_definitive_mutation(
    plan: &LiveOwnerTxnPlan,
    succeeded: bool,
    failure_observation: Option<LiveOwnerObservation>,
) -> Result<LiveOwnerDefinitiveMutation, LiveOwnerTxnError> {
    if succeeded {
        if failure_observation.is_some() {
            return Err(LiveOwnerTxnError::UnexpectedFailureObservation);
        }
        return Ok(LiveOwnerDefinitiveMutation::Committed);
    }

    let observed = failure_observation.ok_or(LiveOwnerTxnError::MissingFailureObservation)?;
    if observed.key() != plan.key() {
        return Err(LiveOwnerTxnError::FailureObservationKeyMismatch);
    }
    Ok(LiveOwnerDefinitiveMutation::CompareFailed(observed))
}

/// Reconciles an indeterminate acquisition only after a new linearizable exact-key observation.
///
/// # Errors
///
/// Returns an error for missing established state, peer mismatch or a re-observed state that would
/// require fence rollback/reuse.
pub fn reconcile_indeterminate_acquisition(
    before: &LiveOwnerObservation,
    intended: &ReachabilityLiveOwnerAuthorityRecord,
    observation: Option<&LiveOwnerObservation>,
) -> Result<LiveOwnerReconciliation, LiveOwnerTxnError> {
    let observed = observation.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
    if observed.record.peer() != before.record.peer() || intended.peer() != before.record.peer() {
        return Err(LiveOwnerTxnError::PeerMismatch);
    }

    if observed.record == *intended {
        if intended.lifecycle() != LiveOwnerLifecycle::Current {
            return Err(LiveOwnerTxnError::SuccessorNotCurrent);
        }
        return Ok(LiveOwnerReconciliation::Committed);
    }
    if observed.same_state_as(before) {
        return Ok(LiveOwnerReconciliation::ProvenNotCommitted);
    }
    classify_superseding_state(intended, observed.record())
}

/// Reconciles an indeterminate release only after a new linearizable exact-key observation.
///
/// # Errors
///
/// Returns an error for missing established state, peer mismatch or a re-observed state that would
/// require fence rollback/reuse.
pub fn reconcile_indeterminate_release(
    before: &LiveOwnerObservation,
    observation: Option<&LiveOwnerObservation>,
) -> Result<LiveOwnerReconciliation, LiveOwnerTxnError> {
    let observed = observation.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
    if observed.record.peer() != before.record.peer() {
        return Err(LiveOwnerTxnError::PeerMismatch);
    }
    let intended = before.record.released_successor();

    if observed.record == intended {
        return Ok(LiveOwnerReconciliation::Committed);
    }
    if observed.same_state_as(before) {
        return Ok(LiveOwnerReconciliation::ProvenNotCommitted);
    }
    classify_superseding_state(&intended, observed.record())
}

fn build_mutation_plan(
    observed: &LiveOwnerObservation,
    successor: ReachabilityLiveOwnerAuthorityRecord,
) -> Result<LiveOwnerTxnPlan, LiveOwnerTxnError> {
    if successor.peer() != observed.record.peer() {
        return Err(LiveOwnerTxnError::SuccessorPeerMismatch);
    }

    let successor_key = encode_live_owner_key(successor.peer())?;
    if successor_key != observed.key {
        return Err(LiveOwnerTxnError::SuccessorPeerMismatch);
    }
    let successor_value = encode_live_owner_record(&successor)?;

    Ok(LiveOwnerTxnPlan {
        compares: [
            LiveOwnerTxnCompare::ModRevisionEquals {
                key: observed.key.clone(),
                expected: observed.mod_revision,
            },
            LiveOwnerTxnCompare::ExactValueEquals {
                key: observed.key.clone(),
                expected: observed.value.clone(),
            },
        ],
        success: LiveOwnerTxnOperation::Put {
            key: observed.key.clone(),
            value: successor_value,
        },
        failure: LiveOwnerTxnOperation::LinearizableGet {
            key: observed.key.clone(),
        },
        successor,
    })
}

fn classify_superseding_state(
    intended: &ReachabilityLiveOwnerAuthorityRecord,
    observed: &ReachabilityLiveOwnerAuthorityRecord,
) -> Result<LiveOwnerReconciliation, LiveOwnerTxnError> {
    if observed.fence() > intended.fence() {
        return Ok(LiveOwnerReconciliation::Superseded);
    }

    if observed.fence() == intended.fence()
        && observed.attempt_id() == intended.attempt_id()
        && observed.lifecycle() == LiveOwnerLifecycle::Released
    {
        return Ok(LiveOwnerReconciliation::Superseded);
    }

    Err(LiveOwnerTxnError::ImpossibleReobservedState)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use prw_connectivity::TransportIdentity;
    use prw_core::DeviceId;

    use super::*;
    use crate::reachability_live_owner_codec::AuthorityAttemptId;

    #[derive(Debug)]
    struct ScriptedKv {
        state: LiveOwnerObservation,
        scripted_compare_success: VecDeque<bool>,
    }

    impl ScriptedKv {
        fn new(state: LiveOwnerObservation) -> Self {
            Self {
                state,
                scripted_compare_success: VecDeque::new(),
            }
        }

        fn push_compare_result(&mut self, succeeds: bool) {
            self.scripted_compare_success.push_back(succeeds);
        }

        fn transact(
            &mut self,
            plan: &LiveOwnerTxnPlan,
        ) -> Result<LiveOwnerDefinitiveMutation, LiveOwnerTxnError> {
            let compare_succeeds = self
                .scripted_compare_success
                .pop_front()
                .expect("scripted transaction result");
            if !compare_succeeds {
                return classify_definitive_mutation(plan, false, Some(self.state.clone()));
            }

            let LiveOwnerTxnOperation::Put { key, value } = plan.success() else {
                panic!("canonical success branch must be Put");
            };
            let next_revision = self.state.mod_revision() + 1;
            self.state = LiveOwnerObservation::decode(key.clone(), value.clone(), next_revision)?;
            classify_definitive_mutation(plan, true, None)
        }

        fn observation(&self) -> &LiveOwnerObservation {
            &self.state
        }
    }

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid test DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero test TransportIdentity"),
        )
    }

    fn attempt(marker: u8) -> AuthorityAttemptId {
        AuthorityAttemptId::new([marker; 32]).expect("non-zero test attempt ID")
    }

    fn fence(value: u128) -> NonZeroU128 {
        NonZeroU128::new(value).expect("non-zero test fence")
    }

    fn observation(
        peer: PeerConnectivityIdentity,
        lifecycle: LiveOwnerLifecycle,
        fence_value: u128,
        attempt_marker: u8,
        revision: i64,
    ) -> LiveOwnerObservation {
        let current = ReachabilityLiveOwnerAuthorityRecord::current(
            peer,
            fence(fence_value),
            attempt(attempt_marker),
        );
        let record = if lifecycle == LiveOwnerLifecycle::Current {
            current
        } else {
            current.released_successor()
        };
        let key = encode_live_owner_key(record.peer()).expect("encode test key");
        let value = encode_live_owner_record(&record).expect("encode test record");
        LiveOwnerObservation::decode(key, value, revision).expect("decode test observation")
    }

    #[test]
    fn acquisition_plan_is_exact_dual_cas_with_put_and_failure_get() {
        let peer = peer("txn-plan", 7);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Released, 40, 8, 12);
        let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(41), attempt(9));
        let plan = plan_acquisition(&observed, successor.clone()).expect("plan acquisition");

        assert_eq!(
            plan.compares(),
            &[
                LiveOwnerTxnCompare::ModRevisionEquals {
                    key: observed.key().to_vec(),
                    expected: 12,
                },
                LiveOwnerTxnCompare::ExactValueEquals {
                    key: observed.key().to_vec(),
                    expected: observed.value().to_vec(),
                },
            ]
        );
        assert_eq!(
            plan.success(),
            &LiveOwnerTxnOperation::Put {
                key: observed.key().to_vec(),
                value: encode_live_owner_record(&successor).expect("encode successor"),
            }
        );
        assert_eq!(
            plan.failure(),
            &LiveOwnerTxnOperation::LinearizableGet {
                key: observed.key().to_vec(),
            }
        );
    }

    #[test]
    fn acquisition_rejects_non_new_fence_and_attempt_reuse() {
        let peer = peer("txn-monotonic", 11);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Current, 90, 12, 20);

        let same_fence =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(90), attempt(13));
        assert_eq!(
            plan_acquisition(&observed, same_fence),
            Err(LiveOwnerTxnError::FenceNotStrictlyNewer)
        );

        let reused_attempt =
            ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(91), attempt(12));
        assert_eq!(
            plan_acquisition(&observed, reused_attempt),
            Err(LiveOwnerTxnError::AttemptIdReused)
        );
    }

    #[test]
    fn compare_failure_never_maps_to_committed_and_performs_no_write() {
        let peer = peer("txn-failure", 15);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Current, 5, 16, 30);
        let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(6), attempt(17));
        let plan = plan_acquisition(&observed, successor).expect("plan acquisition");
        let mut kv = ScriptedKv::new(observed.clone());
        kv.push_compare_result(false);

        let outcome = kv.transact(&plan).expect("definitive compare failure");
        assert_eq!(
            outcome,
            LiveOwnerDefinitiveMutation::CompareFailed(observed.clone())
        );
        assert_eq!(kv.observation(), &observed);
    }

    #[test]
    fn successful_scripted_transaction_commits_canonical_successor() {
        let peer = peer("txn-success", 19);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Released, 7, 20, 40);
        let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(8), attempt(21));
        let plan = plan_acquisition(&observed, successor.clone()).expect("plan acquisition");
        let mut kv = ScriptedKv::new(observed);
        kv.push_compare_result(true);

        assert_eq!(
            kv.transact(&plan).expect("definitive transaction"),
            LiveOwnerDefinitiveMutation::Committed
        );
        assert_eq!(kv.observation().record(), &successor);
    }

    #[test]
    fn currentness_requires_exact_current_peer_and_fence() {
        let peer = peer("currentness", 23);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Current, 12, 24, 50);

        assert_eq!(
            classify_currentness(&peer, fence(12), Some(&observed)),
            Ok(LiveOwnerProviderCurrentness::Current)
        );
        assert_eq!(
            classify_currentness(&peer, fence(11), Some(&observed)),
            Ok(LiveOwnerProviderCurrentness::Stale)
        );
        assert_eq!(
            classify_currentness(&peer, fence(12), None),
            Err(LiveOwnerTxnError::MissingEstablishedState)
        );
    }

    #[test]
    fn stale_release_returns_not_current_without_mutation_plan() {
        let peer = peer("release-stale", 27);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Current, 21, 28, 60);

        let release =
            plan_release(&peer, fence(20), Some(&observed)).expect("stale release classification");
        assert!(release.is_not_current());
        assert!(release.transaction().is_none());
    }

    #[test]
    fn release_plan_preserves_peer_fence_and_attempt_id() {
        let peer = peer("release-ready", 31);
        let observed = observation(peer.clone(), LiveOwnerLifecycle::Current, 30, 32, 70);
        let plan = plan_release(&peer, fence(30), Some(&observed))
            .expect("release plan")
            .into_transaction()
            .expect("current owner must be releasable");

        assert_eq!(plan.successor().lifecycle(), LiveOwnerLifecycle::Released);
        assert_eq!(plan.successor().peer(), observed.record().peer());
        assert_eq!(plan.successor().fence(), observed.record().fence());
        assert_eq!(
            plan.successor().attempt_id(),
            observed.record().attempt_id()
        );
    }

    #[test]
    fn indeterminate_acquisition_reconciles_committed_not_committed_and_superseded() {
        let peer = peer("reconcile-acquire", 35);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 100, 36, 80);
        let intended =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(101), attempt(37));
        let committed = observation(peer.clone(), LiveOwnerLifecycle::Current, 101, 37, 81);
        let newer = observation(peer, LiveOwnerLifecycle::Current, 102, 38, 82);

        assert_eq!(
            reconcile_indeterminate_acquisition(&before, &intended, Some(&committed)),
            Ok(LiveOwnerReconciliation::Committed)
        );
        assert_eq!(
            reconcile_indeterminate_acquisition(&before, &intended, Some(&before)),
            Ok(LiveOwnerReconciliation::ProvenNotCommitted)
        );
        assert_eq!(
            reconcile_indeterminate_acquisition(&before, &intended, Some(&newer)),
            Ok(LiveOwnerReconciliation::Superseded)
        );
    }

    #[test]
    fn indeterminate_acquisition_released_after_commit_is_not_authority() {
        let peer = peer("reconcile-release-after-acquire", 39);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 200, 40, 90);
        let intended =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(201), attempt(41));
        let released = observation(peer, LiveOwnerLifecycle::Released, 201, 41, 92);

        assert_eq!(
            reconcile_indeterminate_acquisition(&before, &intended, Some(&released)),
            Ok(LiveOwnerReconciliation::Superseded)
        );
    }

    #[test]
    fn indeterminate_release_cannot_clear_newer_owner() {
        let peer = peer("reconcile-release", 43);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 300, 44, 100);
        let released = observation(peer.clone(), LiveOwnerLifecycle::Released, 300, 44, 101);
        let newer = observation(peer, LiveOwnerLifecycle::Current, 301, 45, 102);

        assert_eq!(
            reconcile_indeterminate_release(&before, Some(&released)),
            Ok(LiveOwnerReconciliation::Committed)
        );
        assert_eq!(
            reconcile_indeterminate_release(&before, Some(&before)),
            Ok(LiveOwnerReconciliation::ProvenNotCommitted)
        );
        assert_eq!(
            reconcile_indeterminate_release(&before, Some(&newer)),
            Ok(LiveOwnerReconciliation::Superseded)
        );
    }

    #[test]
    fn same_bytes_at_new_revision_do_not_prove_non_commit() {
        let peer = peer("reconcile-aba", 47);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 400, 48, 110);
        let intended =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(401), attempt(49));
        let same_bytes_new_revision = observation(peer, LiveOwnerLifecycle::Current, 400, 48, 112);

        assert_eq!(
            reconcile_indeterminate_acquisition(&before, &intended, Some(&same_bytes_new_revision)),
            Err(LiveOwnerTxnError::ImpossibleReobservedState)
        );
    }
}
