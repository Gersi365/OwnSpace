//! Phase 152 C02f-AQ staging validation for bounded fence-sequence allocation reconciliation.
//!
//! Production source modules are included directly so the AJ+AP reconciliation state machine can
//! be compiled, linted, and tested without public-library export, endpoint/client construction,
//! attempt-ID generation, provider network I/O, or runtime activation.

use std::{
    collections::VecDeque,
    fmt,
    future::{Future, pending},
    pin::pin,
    task::{Context, Poll, Waker},
};

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_allocation_etcd.rs"]
pub mod fence_sequence_allocation_etcd;
#[path = "../src/fence_sequence_allocation_orchestrator.rs"]
pub mod fence_sequence_allocation_orchestrator;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence::{
    FenceSequenceAllocationPlan, FenceSequenceError, FenceSequenceHead,
    FenceSequenceHeadObservation, FenceSequenceReobservation, SequenceAllocationAttemptId,
    encode_head, plan_allocation,
};
use fence_sequence_allocation_orchestrator::{
    FenceSequenceAllocationAuthority, FenceSequenceAllocationOrchestrationError,
    FenceSequenceAllocationResolvedOutcome, FenceSequenceAllocationSubmissionOutcome,
    resolve_fence_sequence_allocation_with_reconciliation,
};
use recovery_epoch::RecoveryEpoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScriptedAuthorityError;

impl fmt::Display for ScriptedAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scripted allocation authority error")
    }
}

impl std::error::Error for ScriptedAuthorityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Submit,
    Reobserve,
}

#[derive(Debug)]
enum Reobserve {
    Ready(Result<FenceSequenceReobservation, ScriptedAuthorityError>),
    Pending,
}

#[derive(Debug)]
struct Authority {
    submits: VecDeque<Result<FenceSequenceAllocationSubmissionOutcome, ScriptedAuthorityError>>,
    reobserves: VecDeque<Reobserve>,
    submitted: Vec<FenceSequenceAllocationPlan>,
    events: Vec<Event>,
}

impl Authority {
    fn new(
        submits: impl IntoIterator<
            Item = Result<FenceSequenceAllocationSubmissionOutcome, ScriptedAuthorityError>,
        >,
        reobserves: impl IntoIterator<Item = Reobserve>,
    ) -> Self {
        Self {
            submits: submits.into_iter().collect(),
            reobserves: reobserves.into_iter().collect(),
            submitted: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl FenceSequenceAllocationAuthority for Authority {
    type Error = ScriptedAuthorityError;

    async fn submit_allocation(
        &mut self,
        plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceAllocationSubmissionOutcome, Self::Error> {
        self.events.push(Event::Submit);
        self.submitted.push(plan);
        self.submits.pop_front().expect("scripted submit")
    }

    async fn fresh_reobserve(
        &mut self,
        _plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceReobservation, Self::Error> {
        self.events.push(Event::Reobserve);
        let scripted = self.reobserves.pop_front().expect("scripted reobserve");
        match scripted {
            Reobserve::Ready(result) => result,
            Reobserve::Pending => pending().await,
        }
    }
}

fn epoch(value: u64) -> RecoveryEpoch {
    RecoveryEpoch::new(value).expect("non-zero epoch")
}

fn retained_plan() -> FenceSequenceAllocationPlan {
    let predecessor = FenceSequenceHeadObservation::new(
        encode_head(FenceSequenceHead {
            epoch: epoch(9),
            high_water: 41,
        })
        .to_vec(),
        77,
    )
    .expect("canonical predecessor");
    let attempt_id = SequenceAllocationAttemptId::new([7_u8; 32]).expect("non-zero attempt id");
    plan_allocation(predecessor, attempt_id).expect("canonical allocation plan")
}

#[test]
fn definitive_apply_requires_fresh_committed_reobservation() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceAllocationSubmissionOutcome::Applied)],
        [Reobserve::Ready(Ok(FenceSequenceReobservation::Committed))],
    );

    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("committed");

    assert_eq!(resolved.plan(), &expected);
    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit, Event::Reobserve]);
}

#[test]
fn definitive_compare_failure_committed_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Committed,
        ))],
        [],
    );

    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("committed");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit]);
}

#[test]
fn definitive_compare_failure_superseded_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Superseded,
        ))],
        [],
    );

    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("superseded");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Superseded
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit]);
}

#[test]
fn definitive_non_commit_requires_fresh_proof_before_exact_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::ProvenNotCommitted,
            )),
            Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::Committed,
            )),
        ],
        [Reobserve::Ready(Ok(
            FenceSequenceReobservation::ProvenNotCommitted,
        ))],
    );

    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("exact reissue");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
    assert_eq!(
        authority.events,
        [Event::Submit, Event::Reobserve, Event::Submit]
    );
}

#[test]
fn indeterminate_proven_not_committed_allows_one_exact_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceAllocationSubmissionOutcome::MutationIndeterminate),
            Ok(FenceSequenceAllocationSubmissionOutcome::Applied),
        ],
        [
            Reobserve::Ready(Ok(FenceSequenceReobservation::ProvenNotCommitted)),
            Reobserve::Ready(Ok(FenceSequenceReobservation::Committed)),
        ],
    );

    let resolved = ready(resolve_fence_sequence_allocation_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("exact reissue");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceAllocationResolvedOutcome::Committed
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
    assert_eq!(
        authority.events,
        [
            Event::Submit,
            Event::Reobserve,
            Event::Submit,
            Event::Reobserve
        ]
    );
}

#[test]
fn second_definitive_non_commit_has_no_third_submit() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::ProvenNotCommitted,
            )),
            Ok(FenceSequenceAllocationSubmissionOutcome::CompareFailed(
                FenceSequenceReobservation::ProvenNotCommitted,
            )),
        ],
        [Reobserve::Ready(Ok(
            FenceSequenceReobservation::ProvenNotCommitted,
        ))],
    );

    assert_eq!(
        ready(resolve_fence_sequence_allocation_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceAllocationOrchestrationError::ReissueLimitReached)
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
    assert_eq!(
        authority.events,
        [Event::Submit, Event::Reobserve, Event::Submit]
    );
}

#[test]
fn definitive_apply_followed_by_non_commit_proof_fails_closed() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceAllocationSubmissionOutcome::Applied)],
        [Reobserve::Ready(Ok(
            FenceSequenceReobservation::ProvenNotCommitted,
        ))],
    );

    assert_eq!(
        ready(resolve_fence_sequence_allocation_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceAllocationOrchestrationError::Domain(
            FenceSequenceError::ContradictoryState,
        ))
    );
    assert_eq!(authority.submitted, [expected]);
}

#[test]
fn dropping_pending_reobservation_spawns_no_detached_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(
            FenceSequenceAllocationSubmissionOutcome::MutationIndeterminate,
        )],
        [Reobserve::Pending],
    );

    {
        let future = resolve_fence_sequence_allocation_with_reconciliation(&mut authority, plan);
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    }

    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit, Event::Reobserve]);
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("scripted future must resolve immediately"),
    }
}
