use std::{
    collections::VecDeque,
    future::pending,
    pin::pin,
    task::{Context, Poll, Waker},
};

use prw_connectivity::TransportIdentity;
use prw_core::DeviceId;

use super::*;
use crate::{
    reachability_live_owner_codec::{
        AuthorityAttemptId, LiveOwnerLifecycle, encode_live_owner_key, encode_live_owner_record,
    },
    reachability_live_owner_txn::classify_definitive_mutation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScriptedProviderError;

#[derive(Debug)]
struct ScriptedExecution {
    outcome: Result<LiveOwnerMutationIoExecution, ScriptedProviderError>,
    actual_submission: bool,
}

#[derive(Debug)]
enum ScriptedObservation {
    Ready(Result<Option<LiveOwnerObservation>, ScriptedProviderError>),
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptedEvent {
    Execute,
    LinearizableObserve,
}

#[derive(Debug)]
struct ScriptedIo {
    executions: VecDeque<ScriptedExecution>,
    observations: VecDeque<ScriptedObservation>,
    actual_submissions: usize,
    executed_plans: Vec<LiveOwnerTxnPlan>,
    events: Vec<ScriptedEvent>,
}

impl ScriptedIo {
    fn new(
        executions: impl IntoIterator<Item = ScriptedExecution>,
        observations: impl IntoIterator<Item = ScriptedObservation>,
    ) -> Self {
        Self {
            executions: executions.into_iter().collect(),
            observations: observations.into_iter().collect(),
            actual_submissions: 0,
            executed_plans: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl LiveOwnerMutationIo for ScriptedIo {
    type Error = ScriptedProviderError;

    fn execute<'a>(
        &'a mut self,
        plan: &'a LiveOwnerTxnPlan,
    ) -> impl Future<Output = Result<LiveOwnerMutationIoExecution, Self::Error>> + 'a {
        self.events.push(ScriptedEvent::Execute);
        self.executed_plans.push(plan.clone());
        let scripted = self
            .executions
            .pop_front()
            .expect("scripted execution outcome");
        if scripted.actual_submission {
            self.actual_submissions += 1;
        }
        async move { scripted.outcome }
    }

    fn linearizable_observation<'a>(
        &'a mut self,
        _peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<Output = Result<Option<LiveOwnerObservation>, Self::Error>> + 'a {
        self.events.push(ScriptedEvent::LinearizableObserve);
        let scripted = self
            .observations
            .pop_front()
            .expect("scripted observation outcome");
        async move {
            match scripted {
                ScriptedObservation::Ready(result) => result,
                ScriptedObservation::Pending => pending().await,
            }
        }
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

fn committed(plan: &LiveOwnerTxnPlan) -> LiveOwnerMutationIoExecution {
    LiveOwnerMutationIoExecution::Definitive(
        classify_definitive_mutation(plan, true, None).expect("definitive commit"),
    )
}

#[test]
fn stale_release_resolution_binds_exact_not_current_evidence() {
    let requested_peer = peer("ba-stale", 30);
    let before = observation(
        requested_peer.clone(),
        LiveOwnerLifecycle::Current,
        200,
        31,
        210,
    );

    let resolved = plan_resolved_release(&requested_peer, fence(199), &before)
        .expect("stale release classification");
    let LiveOwnerPlannedRelease::NotCurrent(evidence) = resolved else {
        panic!("stale release must not produce a mutation plan");
    };

    assert_eq!(evidence.peer(), &requested_peer);
    assert_eq!(evidence.fence(), fence(199));
}

#[test]
fn released_exact_fence_resolution_binds_exact_not_current_evidence() {
    let requested_peer = peer("ba-released", 32);
    let before = observation(
        requested_peer.clone(),
        LiveOwnerLifecycle::Released,
        220,
        33,
        230,
    );

    let resolved = plan_resolved_release(&requested_peer, fence(220), &before)
        .expect("released release classification");
    let LiveOwnerPlannedRelease::NotCurrent(evidence) = resolved else {
        panic!("already released state must not produce a mutation plan");
    };

    assert_eq!(evidence.peer(), &requested_peer);
    assert_eq!(evidence.fence(), fence(220));
}

#[test]
fn peer_mismatch_rejects_before_not_current_evidence_can_be_minted() {
    let requested_peer = peer("ba-peer-request", 34);
    let observed_peer = peer("ba-peer-observed", 35);
    let before = observation(observed_peer, LiveOwnerLifecycle::Released, 240, 36, 250);

    assert_eq!(
        plan_resolved_release(&requested_peer, fence(240), &before),
        Err(LiveOwnerTxnError::PeerMismatch)
    );
}

#[test]
fn exact_current_release_resolution_preserves_mutation_path() {
    let requested_peer = peer("ba-current", 37);
    let before = observation(
        requested_peer.clone(),
        LiveOwnerLifecycle::Current,
        260,
        38,
        270,
    );

    let resolved = plan_resolved_release(&requested_peer, fence(260), &before)
        .expect("current release classification");
    let LiveOwnerPlannedRelease::Mutation(plan) = resolved else {
        panic!("exact-current release must retain the mutation path");
    };

    assert_eq!(plan.successor().peer(), &requested_peer);
    assert_eq!(plan.successor().fence(), fence(260));
    assert_eq!(plan.successor().lifecycle(), LiveOwnerLifecycle::Released);
}

#[test]
fn indeterminate_commit_is_reobserved_without_reissue() {
    let peer = peer("ae-commit", 1);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 10, 2, 20);
    let successor =
        ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(11), attempt(3));
    let committed_observation = observation(peer, LiveOwnerLifecycle::Current, 11, 3, 21);
    let pending =
        LiveOwnerPendingMutation::acquisition(before, successor).expect("pending acquisition");
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Ready(Ok(Some(committed_observation)))],
    );

    let resolved = futures_poll_ready(resolve_pending_mutation(&mut io, pending))
        .expect("resolved committed acquisition");
    assert_eq!(
        resolved.outcome(),
        &ReachabilityLiveOwnerResolvedMutationOutcome::Committed
    );
    assert_eq!(io.actual_submissions, 1);
    assert_eq!(
        io.events,
        [ScriptedEvent::Execute, ScriptedEvent::LinearizableObserve,]
    );
}

#[test]
fn proven_not_committed_allows_exactly_one_exact_plan_reissue() {
    let peer = peer("ae-reissue", 4);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 30, 5, 40);
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(31), attempt(6));
    let pending = LiveOwnerPendingMutation::acquisition(before.clone(), successor)
        .expect("pending acquisition");
    let expected_plan = pending.plan.clone();
    let mut io = ScriptedIo::new(
        [
            ScriptedExecution {
                outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
                actual_submission: false,
            },
            ScriptedExecution {
                outcome: Ok(committed(&expected_plan)),
                actual_submission: true,
            },
        ],
        [ScriptedObservation::Ready(Ok(Some(before)))],
    );

    let resolved = futures_poll_ready(resolve_pending_mutation(&mut io, pending))
        .expect("resolved reissued acquisition");
    assert_eq!(
        resolved.outcome(),
        &ReachabilityLiveOwnerResolvedMutationOutcome::Committed
    );
    assert_eq!(io.actual_submissions, 1);
    assert_eq!(io.executed_plans, [expected_plan.clone(), expected_plan]);
    assert_eq!(
        io.events,
        [
            ScriptedEvent::Execute,
            ScriptedEvent::LinearizableObserve,
            ScriptedEvent::Execute,
        ]
    );
}

#[test]
fn superseded_indeterminate_acquisition_never_reissues() {
    let peer = peer("ae-superseded", 7);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 50, 8, 60);
    let successor =
        ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(51), attempt(9));
    let newer = observation(peer, LiveOwnerLifecycle::Current, 52, 10, 62);
    let pending =
        LiveOwnerPendingMutation::acquisition(before, successor).expect("pending acquisition");
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Ready(Ok(Some(newer)))],
    );

    let resolved = futures_poll_ready(resolve_pending_mutation(&mut io, pending))
        .expect("resolved superseded acquisition");
    assert_eq!(
        resolved.outcome(),
        &ReachabilityLiveOwnerResolvedMutationOutcome::Superseded
    );
    assert_eq!(io.executed_plans.len(), 1);
}

#[test]
fn second_indeterminate_is_reobserved_but_never_submitted_a_third_time() {
    let peer = peer("ae-bound", 11);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 70, 12, 80);
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(71), attempt(13));
    let pending =
        LiveOwnerPendingMutation::acquisition(before.clone(), successor).expect("pending");
    let mut io = ScriptedIo::new(
        [
            ScriptedExecution {
                outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
                actual_submission: false,
            },
            ScriptedExecution {
                outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
                actual_submission: false,
            },
        ],
        [
            ScriptedObservation::Ready(Ok(Some(before.clone()))),
            ScriptedObservation::Ready(Ok(Some(before))),
        ],
    );

    assert_eq!(
        futures_poll_ready(resolve_pending_mutation(&mut io, pending)),
        Err(LiveOwnerOrchestrationError::ReissueLimitReached)
    );
    assert_eq!(io.executed_plans.len(), 2);
    assert_eq!(
        io.events,
        [
            ScriptedEvent::Execute,
            ScriptedEvent::LinearizableObserve,
            ScriptedEvent::Execute,
            ScriptedEvent::LinearizableObserve,
        ]
    );
}

#[test]
fn same_bytes_at_new_revision_fail_closed_without_reissue() {
    let peer = peer("ae-aba", 15);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 90, 16, 100);
    let successor =
        ReachabilityLiveOwnerAuthorityRecord::current(peer.clone(), fence(91), attempt(17));
    let same_bytes_new_revision = observation(peer, LiveOwnerLifecycle::Current, 90, 16, 102);
    let pending =
        LiveOwnerPendingMutation::acquisition(before, successor).expect("pending acquisition");
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Ready(Ok(Some(
            same_bytes_new_revision,
        )))],
    );

    assert_eq!(
        futures_poll_ready(resolve_pending_mutation(&mut io, pending)),
        Err(LiveOwnerOrchestrationError::Transaction(
            LiveOwnerTxnError::ImpossibleReobservedState
        ))
    );
    assert_eq!(io.executed_plans.len(), 1);
}

#[test]
fn indeterminate_release_commit_is_reobserved_without_second_release() {
    let peer = peer("ae-release", 19);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Current, 110, 20, 120);
    let release_plan = plan_release(&peer, fence(110), Some(&before))
        .expect("release plan")
        .into_transaction()
        .expect("current owner release");
    let released = observation(peer, LiveOwnerLifecycle::Released, 110, 20, 121);
    let pending = LiveOwnerPendingMutation::release(before, release_plan);
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Ready(Ok(Some(released)))],
    );

    let resolved =
        futures_poll_ready(resolve_pending_mutation(&mut io, pending)).expect("resolved release");
    assert_eq!(
        resolved.outcome(),
        &ReachabilityLiveOwnerResolvedMutationOutcome::Committed
    );
    assert_eq!(io.actual_submissions, 1);
}

#[test]
fn unavailable_reobservation_fails_closed_without_reissue() {
    let peer = peer("ae-unavailable", 23);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 130, 24, 140);
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(131), attempt(25));
    let pending =
        LiveOwnerPendingMutation::acquisition(before, successor).expect("pending acquisition");
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Ready(Err(ScriptedProviderError))],
    );

    assert_eq!(
        futures_poll_ready(resolve_pending_mutation(&mut io, pending)),
        Err(LiveOwnerOrchestrationError::Provider(ScriptedProviderError))
    );
    assert_eq!(io.executed_plans.len(), 1);
}

#[test]
fn dropping_pending_reconciliation_does_not_spawn_detached_reissue() {
    let peer = peer("ae-cancel", 27);
    let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 150, 28, 160);
    let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(151), attempt(29));
    let pending =
        LiveOwnerPendingMutation::acquisition(before, successor).expect("pending acquisition");
    let mut io = ScriptedIo::new(
        [ScriptedExecution {
            outcome: Ok(LiveOwnerMutationIoExecution::Indeterminate),
            actual_submission: true,
        }],
        [ScriptedObservation::Pending],
    );

    {
        let future = resolve_pending_mutation(&mut io, pending);
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    }

    assert_eq!(io.executed_plans.len(), 1);
    assert_eq!(io.actual_submissions, 1);
    assert_eq!(
        io.events,
        [ScriptedEvent::Execute, ScriptedEvent::LinearizableObserve,]
    );
}

fn futures_poll_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("scripted future must resolve immediately"),
    }
}
