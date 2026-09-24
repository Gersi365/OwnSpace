//! Agent-owned custody for recovered production reachability owners.
//!
//! C03e-GG materializes only the C03e-GF-selected fail-closed recovery/custody boundary around
//! the existing `ProductionReachabilityOwner`. Construction performs one authoritative durable
//! recovery for one exact peer lifecycle. C03e-GI adds only the C03e-GH-selected exact peer-keyed
//! association/lookup boundary over already-recovered custodies. C03e-GR adds bounded async owner
//! operations so one exact mutable owner custody can remain lexical across an explicitly awaitable
//! durable operation. The retained owners are not cloneable or exposed directly, and this module
//! performs no requester mutation, response I/O, traversal activation, listener/readiness
//! publication, dialing, deployment, or process recovery.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;
use prw_remote_bridge::reachability_owner::{
    CandidatePublicationFreshnessTokenSource, ProductionReachabilityOwner,
    ReachabilityDurableStore, ReachabilityOwnerError,
};

/// Agent-owned exclusive custody of one recovered production reachability owner.
///
/// The wrapper intentionally has no `Clone` implementation. Store and verifier token-source
/// ownership remain encapsulated inside the existing production owner. Later separately gated
/// composition may operate through bounded sync/async closure seams without obtaining a raw owner
/// handle.
pub struct ProductionReachabilityOwnerCustody<S, T> {
    owner: ProductionReachabilityOwner<S, T>,
}

impl<S, T> ProductionReachabilityOwnerCustody<S, T>
where
    S: ReachabilityDurableStore,
    T: CandidatePublicationFreshnessTokenSource,
{
    /// Recovers and retains exactly one production owner for `peer`.
    ///
    /// This delegates once to the existing authoritative awaitable durable recovery law. Missing,
    /// ambiguous, mismatched, recovery-required, or retired durable state is preserved exactly as
    /// classified by `ProductionReachabilityOwner::recover`; no default/rebaseline owner exists.
    /// The caller owns polling; custody construction creates no runtime or background task.
    ///
    /// # Errors
    ///
    /// Returns the exact existing [`ReachabilityOwnerError`] produced by authoritative recovery.
    pub async fn recover(
        store: S,
        token_source: T,
        peer: &PeerConnectivityIdentity,
    ) -> Result<Self, ReachabilityOwnerError> {
        let owner = ProductionReachabilityOwner::recover(store, token_source, peer).await?;
        Ok(Self { owner })
    }

    /// Runs one bounded synchronous operation with exclusive mutable access to the retained owner.
    ///
    /// The higher-ranked closure cannot return a reference tied to the owner borrow, so mutable
    /// owner custody cannot escape this lexical call. This seam performs no operation by itself;
    /// the caller-provided operation remains separately gated.
    pub fn with_owner_mut<R>(
        &mut self,
        operation: impl for<'owner> FnOnce(&'owner mut ProductionReachabilityOwner<S, T>) -> R,
    ) -> R {
        operation(&mut self.owner)
    }

    /// Runs one bounded awaitable operation with exclusive mutable access to the retained owner.
    ///
    /// The async closure may borrow the exact owner only for the lexical duration of this call. The
    /// owner, store and token source cannot escape, no alias is created, and no runtime/task/channel
    /// is owned here. This is the awaitable counterpart required when the existing durable owner
    /// operation itself crosses persistence I/O.
    pub async fn with_owner_mut_async<R, F>(&mut self, operation: F) -> R
    where
        F: for<'owner> AsyncFnOnce(&'owner mut ProductionReachabilityOwner<S, T>) -> R,
    {
        operation(&mut self.owner).await
    }
}

/// Failure while composing an exact peer-keyed production-owner custody map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductionReachabilityOwnerCustodyAssociationError {
    /// More than one retained custody resolved to the same exact two-part peer lifecycle.
    DuplicatePeer,
}

impl fmt::Display for ProductionReachabilityOwnerCustodyAssociationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePeer => {
                formatter.write_str("duplicate production reachability-owner peer custody")
            }
        }
    }
}

impl std::error::Error for ProductionReachabilityOwnerCustodyAssociationError {}

/// Failure while selecting one exact production-owner custody by peer lifecycle key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductionReachabilityOwnerCustodyLookupError {
    /// No retained custody matched the exact logical-device plus transport identity key.
    Missing,
    /// More than one retained custody matched the exact key, so selection is fail-closed.
    Ambiguous,
}

impl fmt::Display for ProductionReachabilityOwnerCustodyLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "production reachability-owner custody is missing for exact peer",
            Self::Ambiguous => "production reachability-owner custody is ambiguous for exact peer",
        })
    }
}

impl std::error::Error for ProductionReachabilityOwnerCustodyLookupError {}

/// Agent-owned exact peer-keyed association of already-recovered production-owner custodies.
///
/// The representation is deliberately a private `Vec`: `PeerConnectivityIdentity` already carries
/// the complete two-part key, no hash contract is required by current source, and no synchronization
/// primitive is invented. Exact peer keys are derived transiently from the retained owners during
/// construction/lookup and are not duplicated as separately authoritative stored snapshots.
///
/// Construction rejects duplicate exact peer ownership. Lookup remains defensive and also rejects
/// any ambiguous match instead of selecting an arbitrary first entry. Successful mutation continues
/// to occur only through bounded custody operations, so no raw owner, store, token source,
/// collection entry, or guard escapes.
pub struct ProductionReachabilityOwnerCustodyMap<S, T> {
    entries: Vec<ProductionReachabilityOwnerCustody<S, T>>,
}

impl<S, T> ProductionReachabilityOwnerCustodyMap<S, T>
where
    S: ReachabilityDurableStore,
    T: CandidatePublicationFreshnessTokenSource,
{
    /// Composes exact peer-keyed association over already-recovered custodies.
    ///
    /// This operation performs no durable recovery, reload, candidate execution, requester mutation,
    /// response I/O, or networking. Each exact owner peer is observed only through the existing GG
    /// bounded custody seam, and no peer snapshot is retained outside the production owner after
    /// construction returns.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionReachabilityOwnerCustodyAssociationError::DuplicatePeer`] when two
    /// supplied custodies resolve to the same exact `PeerConnectivityIdentity`. No first/last-match
    /// normalization or DeviceId-only/transport-only fallback is performed.
    pub fn try_new(
        mut entries: Vec<ProductionReachabilityOwnerCustody<S, T>>,
    ) -> Result<Self, ProductionReachabilityOwnerCustodyAssociationError> {
        let mut peer_keys = Vec::with_capacity(entries.len());
        for custody in &mut entries {
            let peer = custody.with_owner_mut(|owner| owner.plan().peer().clone());
            if peer_keys.contains(&peer) {
                return Err(ProductionReachabilityOwnerCustodyAssociationError::DuplicatePeer);
            }
            peer_keys.push(peer);
        }

        Ok(Self { entries })
    }

    /// Runs one bounded operation against the custody for the exact two-part peer lifecycle key.
    ///
    /// Exact equality uses both `PeerConnectivityIdentity` components. A logical-device-only match,
    /// transport-only match, alternate transport for the same device, or single-entry fallback is
    /// never selected. The operation is invoked only after exactly one match is proven.
    ///
    /// This lookup performs no durable load/recovery, current-registry validation, candidate
    /// execution, requester/rendezvous authorization, freshness commit, response construction/write,
    /// retry, peer close, runtime activation, or dialing.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionReachabilityOwnerCustodyLookupError::Missing`] for zero exact matches and
    /// [`ProductionReachabilityOwnerCustodyLookupError::Ambiguous`] for more than one exact match.
    /// Ambiguity is checked defensively even though [`Self::try_new`] rejects duplicate keys.
    pub fn with_owner_mut_for_peer<R>(
        &mut self,
        peer: &PeerConnectivityIdentity,
        operation: impl for<'owner> FnOnce(&'owner mut ProductionReachabilityOwner<S, T>) -> R,
    ) -> Result<R, ProductionReachabilityOwnerCustodyLookupError> {
        let mut matching_index = None;

        for (index, custody) in self.entries.iter_mut().enumerate() {
            if custody.with_owner_mut(|owner| owner.plan().peer() == peer) {
                match matching_index {
                    Some(_) => {
                        return Err(ProductionReachabilityOwnerCustodyLookupError::Ambiguous);
                    }
                    None => matching_index = Some(index),
                }
            }
        }

        let index = matching_index.ok_or(ProductionReachabilityOwnerCustodyLookupError::Missing)?;
        Ok(self.entries[index].with_owner_mut(operation))
    }

    /// Runs one bounded awaitable operation against the custody for the exact two-part peer key.
    ///
    /// Exact lookup is completed before the operation is invoked. Once selected, the exact map entry
    /// and its mutable production owner remain lexically borrowed until the supplied async operation
    /// completes. No owner reference, map entry, guard, task or runtime escapes this method.
    ///
    /// # Errors
    ///
    /// Preserves the same exact missing/ambiguous classifications as the synchronous lookup and does
    /// not invoke `operation` unless exactly one peer custody is selected.
    pub async fn with_owner_mut_for_peer_async<R, F>(
        &mut self,
        peer: &PeerConnectivityIdentity,
        operation: F,
    ) -> Result<R, ProductionReachabilityOwnerCustodyLookupError>
    where
        F: for<'owner> AsyncFnOnce(&'owner mut ProductionReachabilityOwner<S, T>) -> R,
    {
        let mut matching_index = None;

        for (index, custody) in self.entries.iter_mut().enumerate() {
            if custody.with_owner_mut(|owner| owner.plan().peer() == peer) {
                match matching_index {
                    Some(_) => {
                        return Err(ProductionReachabilityOwnerCustodyLookupError::Ambiguous);
                    }
                    None => matching_index = Some(index),
                }
            }
        }

        let index = matching_index.ok_or(ProductionReachabilityOwnerCustodyLookupError::Missing)?;
        Ok(self.entries[index].with_owner_mut_async(operation).await)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, ready},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    use prw_connectivity::{PeerConnectivityIdentity, PeerConnectivityPlan, TransportIdentity};
    use prw_core::DeviceId;
    use prw_remote_bridge::{
        candidate_publication_freshness::{
            CandidatePublicationFreshnessRecord, CandidatePublicationFreshnessToken,
        },
        reachability_owner::{
            CandidatePublicationFreshnessTokenSource, FreshnessTokenSourceError,
            ReachabilityDurableSnapshot, ReachabilityDurableStore, ReachabilityOwnerError,
            ReachabilityOwnerMode, ReachabilityPersistenceCommit, ReachabilityPersistenceError,
        },
    };

    use super::{
        ProductionReachabilityOwnerCustody, ProductionReachabilityOwnerCustodyAssociationError,
        ProductionReachabilityOwnerCustodyLookupError, ProductionReachabilityOwnerCustodyMap,
    };

    fn resolve_ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    struct CountingStore {
        expected_peer: PeerConnectivityIdentity,
        snapshot: Option<ReachabilityDurableSnapshot>,
        load_error: Option<ReachabilityPersistenceError>,
        load_calls: Arc<AtomicUsize>,
        commit_calls: Arc<AtomicUsize>,
    }

    impl ReachabilityDurableStore for CountingStore {
        fn load_current<'a>(
            &'a mut self,
            peer: &'a PeerConnectivityIdentity,
        ) -> impl Future<
            Output = Result<Option<ReachabilityDurableSnapshot>, ReachabilityPersistenceError>,
        > + Send
        + 'a {
            assert_eq!(peer, &self.expected_peer);
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            let result = match self.load_error {
                Some(error) => Err(error),
                None => Ok(self.snapshot.clone()),
            };
            ready(result)
        }

        fn compare_and_commit<'a>(
            &'a mut self,
            _expected_current: CandidatePublicationFreshnessToken,
            _replacement: &'a ReachabilityDurableSnapshot,
        ) -> impl Future<
            Output = Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError>,
        > + Send
        + 'a {
            self.commit_calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(ReachabilityPersistenceCommit::Committed))
        }
    }

    struct CountingTokenSource {
        issue_calls: Arc<AtomicUsize>,
    }

    impl CandidatePublicationFreshnessTokenSource for CountingTokenSource {
        fn issue_token(
            &mut self,
        ) -> Result<CandidatePublicationFreshnessToken, FreshnessTokenSourceError> {
            self.issue_calls.fetch_add(1, Ordering::SeqCst);
            Err(FreshnessTokenSourceError::Unavailable)
        }
    }

    fn test_peer_with_transport(seed: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new("gg-production-reachability-peer").expect("valid device id"),
            TransportIdentity::new([seed; 32]).expect("non-zero transport identity"),
        )
    }

    fn test_peer() -> PeerConnectivityIdentity {
        test_peer_with_transport(0x31)
    }

    fn established_snapshot(peer: &PeerConnectivityIdentity) -> ReachabilityDurableSnapshot {
        let plan =
            PeerConnectivityPlan::new(peer.clone(), Vec::new()).expect("empty plan is valid");
        let freshness = CandidatePublicationFreshnessRecord::established(
            peer.clone(),
            CandidatePublicationFreshnessToken::new([0x47; 32]).expect("non-zero freshness token"),
        );
        ReachabilityDurableSnapshot::new(plan.durable_state(), freshness)
            .expect("peer-consistent snapshot")
    }

    fn counts() -> (Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        )
    }

    fn recovered_custody(
        peer: &PeerConnectivityIdentity,
        load_calls: &Arc<AtomicUsize>,
        commit_calls: &Arc<AtomicUsize>,
        issue_calls: &Arc<AtomicUsize>,
    ) -> ProductionReachabilityOwnerCustody<CountingStore, CountingTokenSource> {
        resolve_ready(ProductionReachabilityOwnerCustody::recover(
            CountingStore {
                expected_peer: peer.clone(),
                snapshot: Some(established_snapshot(peer)),
                load_error: None,
                load_calls: Arc::clone(load_calls),
                commit_calls: Arc::clone(commit_calls),
            },
            CountingTokenSource {
                issue_calls: Arc::clone(issue_calls),
            },
            peer,
        ))
        .unwrap_or_else(|error| panic!("authoritative recovery should succeed: {error}"))
    }

    #[test]
    fn successful_custody_construction_recovers_once_without_semantic_execution() {
        let peer = test_peer();
        let (load_calls, commit_calls, issue_calls) = counts();
        let store = CountingStore {
            expected_peer: peer.clone(),
            snapshot: Some(established_snapshot(&peer)),
            load_error: None,
            load_calls: Arc::clone(&load_calls),
            commit_calls: Arc::clone(&commit_calls),
        };
        let token_source = CountingTokenSource {
            issue_calls: Arc::clone(&issue_calls),
        };

        let mut custody = resolve_ready(ProductionReachabilityOwnerCustody::recover(
            store,
            token_source,
            &peer,
        ))
        .unwrap_or_else(|error| panic!("authoritative recovery should succeed: {error}"));

        assert_eq!(load_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            custody.with_owner_mut(|owner| owner.mode()),
            ReachabilityOwnerMode::Current
        );
        assert_eq!(
            custody.with_owner_mut(|owner| owner.plan().peer().clone()),
            peer
        );
        assert_eq!(load_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_durable_state_is_preserved_exactly() {
        let peer = test_peer();
        let (load_calls, commit_calls, issue_calls) = counts();
        let result = resolve_ready(ProductionReachabilityOwnerCustody::recover(
            CountingStore {
                expected_peer: peer.clone(),
                snapshot: None,
                load_error: None,
                load_calls: Arc::clone(&load_calls),
                commit_calls: Arc::clone(&commit_calls),
            },
            CountingTokenSource {
                issue_calls: Arc::clone(&issue_calls),
            },
            &peer,
        ));

        assert!(matches!(
            result,
            Err(ReachabilityOwnerError::DurableStateMissing)
        ));
        assert_eq!(load_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ambiguous_durable_load_is_preserved_exactly() {
        let peer = test_peer();
        let (load_calls, commit_calls, issue_calls) = counts();
        let result = resolve_ready(ProductionReachabilityOwnerCustody::recover(
            CountingStore {
                expected_peer: peer.clone(),
                snapshot: None,
                load_error: Some(ReachabilityPersistenceError::UnavailableOrAmbiguous),
                load_calls: Arc::clone(&load_calls),
                commit_calls: Arc::clone(&commit_calls),
            },
            CountingTokenSource {
                issue_calls: Arc::clone(&issue_calls),
            },
            &peer,
        ));

        assert!(matches!(
            result,
            Err(ReachabilityOwnerError::Persistence(
                ReachabilityPersistenceError::UnavailableOrAmbiguous
            ))
        ));
        assert_eq!(load_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn association_rejects_duplicate_exact_peer_without_owner_aliasing() {
        let peer = test_peer();
        let (first_load, first_commit, first_issue) = counts();
        let (second_load, second_commit, second_issue) = counts();
        let first = recovered_custody(&peer, &first_load, &first_commit, &first_issue);
        let second = recovered_custody(&peer, &second_load, &second_commit, &second_issue);

        assert!(matches!(
            ProductionReachabilityOwnerCustodyMap::try_new(vec![first, second]),
            Err(ProductionReachabilityOwnerCustodyAssociationError::DuplicatePeer)
        ));
        assert_eq!(first_load.load(Ordering::SeqCst), 1);
        assert_eq!(second_load.load(Ordering::SeqCst), 1);
        assert_eq!(first_commit.load(Ordering::SeqCst), 0);
        assert_eq!(second_commit.load(Ordering::SeqCst), 0);
        assert_eq!(first_issue.load(Ordering::SeqCst), 0);
        assert_eq!(second_issue.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lookup_requires_exact_device_and_transport_without_fallback() {
        let first_peer = test_peer_with_transport(0x31);
        let second_peer = test_peer_with_transport(0x32);
        let absent_transport_peer = test_peer_with_transport(0x33);
        let (first_load, first_commit, first_issue) = counts();
        let (second_load, second_commit, second_issue) = counts();
        let first = recovered_custody(&first_peer, &first_load, &first_commit, &first_issue);
        let second = recovered_custody(&second_peer, &second_load, &second_commit, &second_issue);
        let mut map = ProductionReachabilityOwnerCustodyMap::try_new(vec![first, second])
            .expect("distinct exact peer keys must compose");

        let observed = map
            .with_owner_mut_for_peer(&second_peer, |owner| owner.plan().peer().clone())
            .expect("exact two-part peer lookup must succeed");
        assert_eq!(observed, second_peer);
        assert_eq!(
            map.with_owner_mut_for_peer(&absent_transport_peer, |_| ()),
            Err(ProductionReachabilityOwnerCustodyLookupError::Missing)
        );
        assert_eq!(first_load.load(Ordering::SeqCst), 1);
        assert_eq!(second_load.load(Ordering::SeqCst), 1);
        assert_eq!(first_commit.load(Ordering::SeqCst), 0);
        assert_eq!(second_commit.load(Ordering::SeqCst), 0);
        assert_eq!(first_issue.load(Ordering::SeqCst), 0);
        assert_eq!(second_issue.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn async_lookup_retains_exact_device_and_transport_without_fallback() {
        let first_peer = test_peer_with_transport(0x31);
        let second_peer = test_peer_with_transport(0x32);
        let (first_load, first_commit, first_issue) = counts();
        let (second_load, second_commit, second_issue) = counts();
        let first = recovered_custody(&first_peer, &first_load, &first_commit, &first_issue);
        let second = recovered_custody(&second_peer, &second_load, &second_commit, &second_issue);
        let mut map = ProductionReachabilityOwnerCustodyMap::try_new(vec![first, second])
            .expect("distinct exact peer keys must compose");

        let observed = resolve_ready(
            map.with_owner_mut_for_peer_async(&second_peer, async |owner| {
                owner.plan().peer().clone()
            }),
        )
        .expect("exact async two-part peer lookup must succeed");

        assert_eq!(observed, second_peer);
        assert_eq!(first_commit.load(Ordering::SeqCst), 0);
        assert_eq!(second_commit.load(Ordering::SeqCst), 0);
        assert_eq!(first_issue.load(Ordering::SeqCst), 0);
        assert_eq!(second_issue.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn defensive_lookup_rejects_ambiguous_exact_peer() {
        let peer = test_peer();
        let (first_load, first_commit, first_issue) = counts();
        let (second_load, second_commit, second_issue) = counts();
        let first = recovered_custody(&peer, &first_load, &first_commit, &first_issue);
        let second = recovered_custody(&peer, &second_load, &second_commit, &second_issue);
        let mut map = ProductionReachabilityOwnerCustodyMap {
            entries: vec![first, second],
        };

        assert_eq!(
            map.with_owner_mut_for_peer(&peer, |_| ()),
            Err(ProductionReachabilityOwnerCustodyLookupError::Ambiguous)
        );
        assert_eq!(first_load.load(Ordering::SeqCst), 1);
        assert_eq!(second_load.load(Ordering::SeqCst), 1);
        assert_eq!(first_commit.load(Ordering::SeqCst), 0);
        assert_eq!(second_commit.load(Ordering::SeqCst), 0);
        assert_eq!(first_issue.load(Ordering::SeqCst), 0);
        assert_eq!(second_issue.load(Ordering::SeqCst), 0);
    }
}
