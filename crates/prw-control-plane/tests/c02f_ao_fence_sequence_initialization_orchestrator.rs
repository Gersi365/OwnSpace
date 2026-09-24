//! Phase 152 C02f-AO staging validation for bounded fence-sequence initialization reconciliation.
//!
//! Production source modules are included directly so the AM+AN reconciliation state machine can
//! be compiled, linted, and tested without public-library export, endpoint/client construction, or
//! provider network I/O.

use std::{
    collections::VecDeque,
    fmt,
    future::{Future, pending},
    pin::pin,
    task::{Context, Poll, Waker},
};

#[path = "../src/fence_sequence.rs"]
pub mod fence_sequence;
#[path = "../src/fence_sequence_initialization.rs"]
pub mod fence_sequence_initialization;
#[path = "../src/fence_sequence_initialization_etcd.rs"]
pub mod fence_sequence_initialization_etcd;
#[path = "../src/fence_sequence_initialization_orchestrator.rs"]
pub mod fence_sequence_initialization_orchestrator;
#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;

use fence_sequence_initialization::{
    FenceSequenceInitializationError, FenceSequenceInitializationPlan,
    FenceSequenceInitializationReobservation, FenceSequenceInitializationTxnPlan,
    plan_initialization,
};
use fence_sequence_initialization_orchestrator::{
    FenceSequenceInitializationAuthority, FenceSequenceInitializationOrchestrationError,
    FenceSequenceInitializationResolvedOutcome, FenceSequenceInitializationSubmissionOutcome,
    resolve_fence_sequence_initialization_with_reconciliation,
};
use recovery_epoch::RecoveryEpoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScriptedAuthorityError;

impl fmt::Display for ScriptedAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scripted initialization authority error")
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
    Ready(Result<FenceSequenceInitializationReobservation, ScriptedAuthorityError>),
    Pending,
}

#[derive(Debug)]
struct Authority {
    submits: VecDeque<Result<FenceSequenceInitializationSubmissionOutcome, ScriptedAuthorityError>>,
    reobserves: VecDeque<Reobserve>,
    submitted: Vec<FenceSequenceInitializationTxnPlan>,
    events: Vec<Event>,
}

impl Authority {
    fn new(
        submits: impl IntoIterator<
            Item = Result<FenceSequenceInitializationSubmissionOutcome, ScriptedAuthorityError>,
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

impl FenceSequenceInitializationAuthority for Authority {
    type Error = ScriptedAuthorityError;

    async fn submit_initialization(
        &mut self,
        plan: FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationSubmissionOutcome, Self::Error> {
        self.events.push(Event::Submit);
        self.submitted.push(plan);
        self.submits.pop_front().expect("scripted submit")
    }

    async fn fresh_reobserve(
        &mut self,
        _plan: FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationReobservation, Self::Error> {
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

fn retained_plan() -> FenceSequenceInitializationTxnPlan {
    let FenceSequenceInitializationPlan::Mutation(plan) = plan_initialization(epoch(9), None)
    else {
        panic!("absent head must produce a mutation plan");
    };
    plan
}

#[test]
fn definitive_apply_requires_fresh_current_reobservation() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceInitializationSubmissionOutcome::Applied)],
        [Reobserve::Ready(Ok(
            FenceSequenceInitializationReobservation::Current,
        ))],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("current");

    assert_eq!(resolved.plan(), &expected);
    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Current
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit, Event::Reobserve]);
}

#[test]
fn definitive_compare_failure_current_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(
            FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::Current,
            ),
        )],
        [],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("current");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Current
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit]);
}

#[test]
fn definitive_compare_failure_superseded_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(
            FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::Superseded,
            ),
        )],
        [],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("superseded");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Superseded
    );
    assert_eq!(authority.submitted, [expected]);
}

#[test]
fn indeterminate_current_is_reobserved_without_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(
            FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate,
        )],
        [Reobserve::Ready(Ok(
            FenceSequenceInitializationReobservation::Current,
        ))],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("reobserved current");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Current
    );
    assert_eq!(authority.submitted, [expected]);
    assert_eq!(authority.events, [Event::Submit, Event::Reobserve]);
}

#[test]
fn indeterminate_proven_not_committed_allows_one_exact_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate),
            Ok(FenceSequenceInitializationSubmissionOutcome::Applied),
        ],
        [
            Reobserve::Ready(Ok(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
            Reobserve::Ready(Ok(FenceSequenceInitializationReobservation::Current)),
        ],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("exact reissue");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Current
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
fn definitive_non_commit_allows_one_exact_reissue() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
            Ok(FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::Current,
            )),
        ],
        [],
    );

    let resolved = ready(resolve_fence_sequence_initialization_with_reconciliation(
        &mut authority,
        plan,
    ))
    .expect("exact reissue");

    assert_eq!(
        resolved.outcome(),
        FenceSequenceInitializationResolvedOutcome::Current
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
    assert_eq!(authority.events, [Event::Submit, Event::Submit]);
}

#[test]
fn second_indeterminate_proven_not_committed_has_no_third_submit() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate),
            Ok(FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate),
        ],
        [
            Reobserve::Ready(Ok(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
            Reobserve::Ready(Ok(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
        ],
    );

    assert_eq!(
        ready(resolve_fence_sequence_initialization_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceInitializationOrchestrationError::ReissueLimitReached)
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
}

#[test]
fn second_definitive_non_commit_has_no_third_submit() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [
            Ok(FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
            Ok(FenceSequenceInitializationSubmissionOutcome::CompareFailed(
                FenceSequenceInitializationReobservation::ProvenNotCommitted,
            )),
        ],
        [],
    );

    assert_eq!(
        ready(resolve_fence_sequence_initialization_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceInitializationOrchestrationError::ReissueLimitReached)
    );
    assert_eq!(authority.submitted, [expected.clone(), expected]);
}

#[test]
fn definitive_apply_followed_by_non_commit_proof_fails_closed() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(FenceSequenceInitializationSubmissionOutcome::Applied)],
        [Reobserve::Ready(Ok(
            FenceSequenceInitializationReobservation::ProvenNotCommitted,
        ))],
    );

    assert_eq!(
        ready(resolve_fence_sequence_initialization_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceInitializationOrchestrationError::Domain(
            FenceSequenceInitializationError::ContradictoryState,
        ))
    );
    assert_eq!(authority.submitted, [expected]);
}

#[test]
fn authority_failure_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new([Err(ScriptedAuthorityError)], []);

    assert_eq!(
        ready(resolve_fence_sequence_initialization_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceInitializationOrchestrationError::Authority(
            ScriptedAuthorityError,
        ))
    );
    assert_eq!(authority.submitted, [expected]);
}

#[test]
fn failed_fresh_reobservation_never_reissues() {
    let plan = retained_plan();
    let expected = plan.clone();
    let mut authority = Authority::new(
        [Ok(
            FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate,
        )],
        [Reobserve::Ready(Err(ScriptedAuthorityError))],
    );

    assert_eq!(
        ready(resolve_fence_sequence_initialization_with_reconciliation(
            &mut authority,
            plan,
        )),
        Err(FenceSequenceInitializationOrchestrationError::Authority(
            ScriptedAuthorityError,
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
            FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate,
        )],
        [Reobserve::Pending],
    );

    {
        let future =
            resolve_fence_sequence_initialization_with_reconciliation(&mut authority, plan);
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
