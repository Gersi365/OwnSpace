//! Phase 152 C02f-AC bridge wrapper from definitive provider outcomes to async authority semantics.
//!
//! The wrapper performs no provider I/O itself. It delegates to an orchestration-side lower port
//! that returns the deterministic C02f-AB control-plane outcomes, then maps only definitive typed
//! results into the already-selected C02f-Y async semantic authority port.
//!
//! A future concrete `prw-control-plane` etcd provider remains lower-level and does not depend on
//! `prw-remote-bridge`; an adapter owned on this side may satisfy the lower port. This module opens no
//! endpoint, creates no runtime/task, and activates no TLS, Watch, lease, TTL or network behavior.

use std::{future::Future, num::NonZeroU128};

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::{
    reachability_live_owner_codec::LiveOwnerLifecycle,
    reachability_live_owner_txn::{
        LiveOwnerDefinitiveMutation, LiveOwnerProviderCurrentness, LiveOwnerTxnPlan,
        classify_currentness,
    },
};

use crate::{
    reachability_live_owner::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
        ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerFence, ReachabilityLiveOwnerGrant,
        ReachabilityLiveOwnerRelease,
    },
    reachability_live_owner_async::ReachabilityLiveOwnerAsyncAuthority,
};

/// Fail-closed lower-provider failure classification consumed by the bridge wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerProviderFailure {
    /// Authority state or mutation outcome cannot be safely proven.
    UnavailableOrAmbiguous,
    /// The selected ordered-generation source cannot issue a strictly newer safe fence.
    FenceExhausted,
}

/// One definitive provider mutation context produced from the C02f-AB transaction contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerDefinitiveMutation {
    plan: LiveOwnerTxnPlan,
    outcome: LiveOwnerDefinitiveMutation,
}

impl ReachabilityLiveOwnerDefinitiveMutation {
    /// Couples one validated deterministic transaction plan with its definitive provider result.
    #[must_use]
    pub const fn new(plan: LiveOwnerTxnPlan, outcome: LiveOwnerDefinitiveMutation) -> Self {
        Self { plan, outcome }
    }

    /// Returns the deterministic transaction plan that produced this result.
    #[must_use]
    pub const fn plan(&self) -> &LiveOwnerTxnPlan {
        &self.plan
    }

    /// Returns the definitive provider mutation classification.
    #[must_use]
    pub const fn outcome(&self) -> &LiveOwnerDefinitiveMutation {
        &self.outcome
    }
}

/// Definitive lower-provider release result before semantic bridge mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerDefinitiveRelease {
    /// Linearizable pre-read proved the supplied peer/fence was already not current.
    NotCurrent,
    /// A release transaction was attempted and returned a definitive result.
    Mutation(Box<ReachabilityLiveOwnerDefinitiveMutation>),
}

/// Orchestration-side lower port that a future control-plane provider adapter may satisfy.
///
/// The concrete provider remains owned by `prw-control-plane`; it must not depend on this trait.
/// A bridge-side adapter may call that provider and return only the already-validated C02f-AB
/// definitive outcomes through this contract. Indeterminate/unavailable/corrupt states fail through
/// [`ReachabilityLiveOwnerProviderFailure::UnavailableOrAmbiguous`] instead of manufacturing
/// semantic authority.
pub trait ReachabilityLiveOwnerDefinitiveProviderPort {
    /// Returns one definitive acquisition/replacement transaction result for `peer`.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed provider failure when a definitive authority outcome cannot be proven.
    fn acquire<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<
            ReachabilityLiveOwnerDefinitiveMutation,
            ReachabilityLiveOwnerProviderFailure,
        >,
    > + Send
    + 'a;

    /// Returns one definitive linearizable currentness classification for `peer + fence`.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed provider failure when currentness cannot be proven authoritatively.
    fn currentness<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
        fence: NonZeroU128,
    ) -> impl Future<
        Output = Result<LiveOwnerProviderCurrentness, ReachabilityLiveOwnerProviderFailure>,
    > + Send
    + 'a;

    /// Returns one definitive release pre-read/mutation result for `peer + fence`.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed provider failure when release status cannot be proven definitively.
    fn release<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
        fence: NonZeroU128,
    ) -> impl Future<
        Output = Result<
            ReachabilityLiveOwnerDefinitiveRelease,
            ReachabilityLiveOwnerProviderFailure,
        >,
    > + Send
    + 'a;
}

/// Adapter from the lower definitive-provider port into the C02f-Y async semantic authority port.
pub struct ReachabilityLiveOwnerProviderBridge<P> {
    provider: P,
}

impl<P> ReachabilityLiveOwnerProviderBridge<P> {
    /// Wraps one lower provider adapter without performing I/O.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Consumes the wrapper and returns the lower provider adapter.
    #[must_use]
    pub fn into_inner(self) -> P {
        self.provider
    }
}

impl<P> ReachabilityLiveOwnerAsyncAuthority for ReachabilityLiveOwnerProviderBridge<P>
where
    P: ReachabilityLiveOwnerDefinitiveProviderPort + Send,
{
    fn acquire<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        async move {
            let definitive = self
                .provider
                .acquire(peer)
                .await
                .map_err(map_provider_failure)?;
            map_definitive_acquisition(peer, &definitive)
        }
    }

    fn currentness<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        async move {
            let raw_fence = raw_fence(grant)?;
            match self
                .provider
                .currentness(grant.peer(), raw_fence)
                .await
                .map_err(map_provider_failure)?
            {
                LiveOwnerProviderCurrentness::Current => {
                    Ok(ReachabilityLiveOwnerCurrentness::Current)
                }
                LiveOwnerProviderCurrentness::Stale => Ok(ReachabilityLiveOwnerCurrentness::Stale),
            }
        }
    }

    fn release<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        async move {
            let raw_fence = raw_fence(grant)?;
            let definitive = self
                .provider
                .release(grant.peer(), raw_fence)
                .await
                .map_err(map_provider_failure)?;
            map_definitive_release(grant, &definitive)
        }
    }
}

fn map_definitive_acquisition(
    peer: &PeerConnectivityIdentity,
    definitive: &ReachabilityLiveOwnerDefinitiveMutation,
) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
    let successor = definitive.plan().successor();
    if successor.peer() != peer || successor.lifecycle() != LiveOwnerLifecycle::Current {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    match definitive.outcome() {
        LiveOwnerDefinitiveMutation::Committed => {
            let fence = semantic_fence(successor.fence())?;
            Ok(ReachabilityLiveOwnerAcquisition::Granted(
                ReachabilityLiveOwnerGrant::from_authority(peer.clone(), fence),
            ))
        }
        LiveOwnerDefinitiveMutation::CompareFailed(_) => {
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        }
    }
}

fn map_definitive_release(
    grant: &ReachabilityLiveOwnerGrant,
    definitive: &ReachabilityLiveOwnerDefinitiveRelease,
) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
    let ReachabilityLiveOwnerDefinitiveRelease::Mutation(mutation) = definitive else {
        return Ok(ReachabilityLiveOwnerRelease::NotCurrent);
    };

    let successor = mutation.plan().successor();
    let expected_fence = raw_fence(grant)?;
    if successor.peer() != grant.peer()
        || successor.fence() != expected_fence
        || successor.lifecycle() != LiveOwnerLifecycle::Released
    {
        return Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous);
    }

    match mutation.outcome() {
        LiveOwnerDefinitiveMutation::Committed => Ok(ReachabilityLiveOwnerRelease::Released),
        LiveOwnerDefinitiveMutation::CompareFailed(observation) => {
            match classify_currentness(grant.peer(), expected_fence, Some(observation))
                .map_err(|_| ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)?
            {
                LiveOwnerProviderCurrentness::Current => {
                    Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
                }
                LiveOwnerProviderCurrentness::Stale => Ok(ReachabilityLiveOwnerRelease::NotCurrent),
            }
        }
    }
}

fn raw_fence(
    grant: &ReachabilityLiveOwnerGrant,
) -> Result<NonZeroU128, ReachabilityLiveOwnerAuthorityError> {
    NonZeroU128::new(grant.fence().get()).ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)
}

fn semantic_fence(
    raw_fence: NonZeroU128,
) -> Result<ReachabilityLiveOwnerFence, ReachabilityLiveOwnerAuthorityError> {
    ReachabilityLiveOwnerFence::new(raw_fence.get())
        .map_err(|_| ReachabilityLiveOwnerAuthorityError::FenceExhausted)
}

const fn map_provider_failure(
    failure: ReachabilityLiveOwnerProviderFailure,
) -> ReachabilityLiveOwnerAuthorityError {
    match failure {
        ReachabilityLiveOwnerProviderFailure::UnavailableOrAmbiguous => {
            ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous
        }
        ReachabilityLiveOwnerProviderFailure::FenceExhausted => {
            ReachabilityLiveOwnerAuthorityError::FenceExhausted
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, future::ready};

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        reachability_live_owner_codec::{
            AuthorityAttemptId, LiveOwnerLifecycle, ReachabilityLiveOwnerAuthorityRecord,
            encode_live_owner_key, encode_live_owner_record,
        },
        reachability_live_owner_txn::{
            LiveOwnerObservation, classify_definitive_mutation, plan_acquisition, plan_release,
        },
    };
    use prw_core::DeviceId;

    use super::*;

    struct ScriptedProvider {
        acquisitions: VecDeque<
            Result<ReachabilityLiveOwnerDefinitiveMutation, ReachabilityLiveOwnerProviderFailure>,
        >,
        currentness:
            VecDeque<Result<LiveOwnerProviderCurrentness, ReachabilityLiveOwnerProviderFailure>>,
        releases: VecDeque<
            Result<ReachabilityLiveOwnerDefinitiveRelease, ReachabilityLiveOwnerProviderFailure>,
        >,
    }

    impl ScriptedProvider {
        fn new() -> Self {
            Self {
                acquisitions: VecDeque::new(),
                currentness: VecDeque::new(),
                releases: VecDeque::new(),
            }
        }
    }

    impl ReachabilityLiveOwnerDefinitiveProviderPort for ScriptedProvider {
        fn acquire<'a>(
            &'a mut self,
            _peer: &'a PeerConnectivityIdentity,
        ) -> impl Future<
            Output = Result<
                ReachabilityLiveOwnerDefinitiveMutation,
                ReachabilityLiveOwnerProviderFailure,
            >,
        > + Send
        + 'a {
            ready(self.acquisitions.pop_front().expect("scripted acquisition"))
        }

        fn currentness<'a>(
            &'a mut self,
            _peer: &'a PeerConnectivityIdentity,
            _fence: NonZeroU128,
        ) -> impl Future<
            Output = Result<LiveOwnerProviderCurrentness, ReachabilityLiveOwnerProviderFailure>,
        > + Send
        + 'a {
            ready(self.currentness.pop_front().expect("scripted currentness"))
        }

        fn release<'a>(
            &'a mut self,
            _peer: &'a PeerConnectivityIdentity,
            _fence: NonZeroU128,
        ) -> impl Future<
            Output = Result<
                ReachabilityLiveOwnerDefinitiveRelease,
                ReachabilityLiveOwnerProviderFailure,
            >,
        > + Send
        + 'a {
            ready(self.releases.pop_front().expect("scripted release"))
        }
    }

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero TransportIdentity"),
        )
    }

    fn fence(value: u128) -> NonZeroU128 {
        NonZeroU128::new(value).expect("non-zero fence")
    }

    fn attempt(marker: u8) -> AuthorityAttemptId {
        AuthorityAttemptId::new([marker; 32]).expect("non-zero attempt id")
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
        let key = encode_live_owner_key(record.peer()).expect("encode key");
        let value = encode_live_owner_record(&record).expect("encode record");
        LiveOwnerObservation::decode(key, value, revision).expect("decode observation")
    }

    fn mutation(
        plan: LiveOwnerTxnPlan,
        outcome: LiveOwnerDefinitiveMutation,
    ) -> ReachabilityLiveOwnerDefinitiveMutation {
        ReachabilityLiveOwnerDefinitiveMutation::new(plan, outcome)
    }

    fn run_ready<F: Future>(future: F) -> F::Output {
        use std::{
            pin::pin,
            task::{Context, Poll, Waker},
        };

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("scripted future must be immediately ready"),
        }
    }

    #[test]
    fn committed_acquisition_maps_to_exact_semantic_grant() {
        let peer = peer("acquire-commit", 1);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 40, 2, 10);
        let successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(41), attempt(3));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");
        let outcome = classify_definitive_mutation(&plan, true, None).expect("definitive success");
        let mut provider = ScriptedProvider::new();
        provider.acquisitions.push_back(Ok(mutation(plan, outcome)));
        let mut bridge = ReachabilityLiveOwnerProviderBridge::new(provider);

        let acquisition = run_ready(bridge.acquire(&peer)).expect("semantic acquisition");
        let ReachabilityLiveOwnerAcquisition::Granted(grant) = acquisition else {
            panic!("expected granted acquisition")
        };
        assert_eq!(grant.peer(), &peer);
        assert_eq!(grant.fence().get(), 41);
    }

    #[test]
    fn definitive_acquisition_compare_failure_maps_to_contention() {
        let peer = peer("acquire-contended", 4);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 50, 5, 11);
        let successor =
            ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(51), attempt(6));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");
        let outcome = classify_definitive_mutation(&plan, false, Some(before))
            .expect("definitive compare failure");
        let mut provider = ScriptedProvider::new();
        provider.acquisitions.push_back(Ok(mutation(plan, outcome)));
        let mut bridge = ReachabilityLiveOwnerProviderBridge::new(provider);

        assert_eq!(
            run_ready(bridge.acquire(&peer)),
            Ok(ReachabilityLiveOwnerAcquisition::Contended)
        );
    }

    #[test]
    fn currentness_maps_only_definitive_current_or_stale() {
        let peer = peer("currentness", 7);
        let grant = ReachabilityLiveOwnerGrant::from_authority(
            peer,
            ReachabilityLiveOwnerFence::new(60).expect("semantic fence"),
        );
        let mut provider = ScriptedProvider::new();
        provider
            .currentness
            .push_back(Ok(LiveOwnerProviderCurrentness::Current));
        provider
            .currentness
            .push_back(Ok(LiveOwnerProviderCurrentness::Stale));
        let mut bridge = ReachabilityLiveOwnerProviderBridge::new(provider);

        assert_eq!(
            run_ready(bridge.currentness(&grant)),
            Ok(ReachabilityLiveOwnerCurrentness::Current)
        );
        assert_eq!(
            run_ready(bridge.currentness(&grant)),
            Ok(ReachabilityLiveOwnerCurrentness::Stale)
        );
    }

    #[test]
    fn committed_release_maps_to_released() {
        let peer = peer("release-commit", 10);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 70, 11, 20);
        let release_plan = plan_release(&peer, fence(70), Some(&before)).expect("plan release");
        let plan = release_plan
            .into_transaction()
            .expect("current release transaction");
        let outcome = classify_definitive_mutation(&plan, true, None).expect("definitive success");
        let grant = ReachabilityLiveOwnerGrant::from_authority(
            peer,
            ReachabilityLiveOwnerFence::new(70).expect("semantic fence"),
        );
        let mut provider = ScriptedProvider::new();
        provider
            .releases
            .push_back(Ok(ReachabilityLiveOwnerDefinitiveRelease::Mutation(
                Box::new(mutation(plan, outcome)),
            )));
        let mut bridge = ReachabilityLiveOwnerProviderBridge::new(provider);

        assert_eq!(
            run_ready(bridge.release(&grant)),
            Ok(ReachabilityLiveOwnerRelease::Released)
        );
    }

    #[test]
    fn release_compare_failure_maps_stale_to_not_current_and_current_to_error() {
        let peer = peer("release-compare", 13);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 80, 14, 30);
        let release_plan = plan_release(&peer, fence(80), Some(&before)).expect("plan release");
        let plan = release_plan
            .into_transaction()
            .expect("current release transaction");
        let grant = ReachabilityLiveOwnerGrant::from_authority(
            peer.clone(),
            ReachabilityLiveOwnerFence::new(80).expect("semantic fence"),
        );

        let newer = observation(peer, LiveOwnerLifecycle::Current, 81, 15, 31);
        let stale_outcome = classify_definitive_mutation(&plan, false, Some(newer))
            .expect("definitive compare failure");
        let mut stale_provider = ScriptedProvider::new();
        stale_provider
            .releases
            .push_back(Ok(ReachabilityLiveOwnerDefinitiveRelease::Mutation(
                Box::new(mutation(plan.clone(), stale_outcome)),
            )));
        let mut stale_bridge = ReachabilityLiveOwnerProviderBridge::new(stale_provider);
        assert_eq!(
            run_ready(stale_bridge.release(&grant)),
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        );

        let current_outcome = classify_definitive_mutation(&plan, false, Some(before))
            .expect("definitive compare failure");
        let mut current_provider = ScriptedProvider::new();
        current_provider
            .releases
            .push_back(Ok(ReachabilityLiveOwnerDefinitiveRelease::Mutation(
                Box::new(mutation(plan, current_outcome)),
            )));
        let mut current_bridge = ReachabilityLiveOwnerProviderBridge::new(current_provider);
        assert_eq!(
            run_ready(current_bridge.release(&grant)),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn provider_failures_preserve_selected_semantic_error_mapping() {
        let peer = peer("provider-failure", 16);
        let mut unavailable = ScriptedProvider::new();
        unavailable.acquisitions.push_back(Err(
            ReachabilityLiveOwnerProviderFailure::UnavailableOrAmbiguous,
        ));
        let mut unavailable_bridge = ReachabilityLiveOwnerProviderBridge::new(unavailable);
        assert_eq!(
            run_ready(unavailable_bridge.acquire(&peer)),
            Err(ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous)
        );

        let mut exhausted = ScriptedProvider::new();
        exhausted
            .acquisitions
            .push_back(Err(ReachabilityLiveOwnerProviderFailure::FenceExhausted));
        let mut exhausted_bridge = ReachabilityLiveOwnerProviderBridge::new(exhausted);
        assert_eq!(
            run_ready(exhausted_bridge.acquire(&peer)),
            Err(ReachabilityLiveOwnerAuthorityError::FenceExhausted)
        );
    }
}
