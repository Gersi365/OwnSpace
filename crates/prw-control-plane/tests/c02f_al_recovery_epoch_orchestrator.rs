//! Phase 152 C02f-AL staging validation for the recovery-epoch reconciliation orchestrator.
//!
//! The production source modules are included directly so the provider-neutral state machine can be
//! compiled, linted, and tested without exporting it through the control-plane public module surface
//! or constructing any Spanner client, credentials, endpoints, or runtime authority.

use std::{
    collections::VecDeque,
    fmt,
    future::{Future, pending},
    pin::pin,
    task::{Context, Poll, Waker},
};

#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;
#[path = "../src/recovery_epoch_orchestrator.rs"]
pub mod recovery_epoch_orchestrator;

use recovery_epoch::{
    RecoveryEpoch, RecoveryEpochAttemptId, RecoveryEpochHeadRecord, RecoveryEpochIssuancePlan,
    RecoveryEpochIssuanceRecord, RecoveryEpochLedgerAuthority, RecoveryEpochSubmissionOutcome,
    RecoveryEpochValue,
};
use recovery_epoch_orchestrator::{
    RecoveryEpochOrchestrationError, RecoveryEpochResolvedOutcome,
    resolve_recovery_epoch_issuance_with_reconciliation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScriptedProviderError;

impl fmt::Display for ScriptedProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scripted provider error")
    }
}

impl std::error::Error for ScriptedProviderError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Submit,
    StrongHead,
    StrongReobserve,
}

#[derive(Debug)]
enum Reobserve {
    Ready(
        Result<
            (RecoveryEpochHeadRecord, Option<RecoveryEpochIssuanceRecord>),
            ScriptedProviderError,
        >,
    ),
    Pending,
}

#[derive(Debug)]
struct Ledger {
    submits: VecDeque<Result<RecoveryEpochSubmissionOutcome, ScriptedProviderError>>,
    heads: VecDeque<Result<RecoveryEpochHeadRecord, ScriptedProviderError>>,
    reobserves: VecDeque<Reobserve>,
    submitted: Vec<RecoveryEpochIssuancePlan>,
    events: Vec<Event>,
}

impl Ledger {
    fn new(
        submits: impl IntoIterator<Item = Result<RecoveryEpochSubmissionOutcome, ScriptedProviderError>>,
        heads: impl IntoIterator<Item = Result<RecoveryEpochHeadRecord, ScriptedProviderError>>,
        reobserves: impl IntoIterator<Item = Reobserve>,
    ) -> Self {
        Self {
            submits: submits.into_iter().collect(),
            heads: heads.into_iter().collect(),
            reobserves: reobserves.into_iter().collect(),
            submitted: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl RecoveryEpochLedgerAuthority for Ledger {
    type Error = ScriptedProviderError;

    fn strong_head(
        &mut self,
    ) -> impl Future<Output = Result<RecoveryEpochHeadRecord, Self::Error>> + Send {
        self.events.push(Event::StrongHead);
        let result = self.heads.pop_front().expect("scripted strong head");
        async move { result }
    }

    fn submit_issuance(
        &mut self,
        plan: RecoveryEpochIssuancePlan,
    ) -> impl Future<Output = Result<RecoveryEpochSubmissionOutcome, Self::Error>> + Send {
        self.events.push(Event::Submit);
        self.submitted.push(plan);
        let result = self.submits.pop_front().expect("scripted submit");
        async move { result }
    }

    fn strong_reobserve(
        &mut self,
        _proposed: RecoveryEpoch,
    ) -> impl Future<
        Output = Result<
            (RecoveryEpochHeadRecord, Option<RecoveryEpochIssuanceRecord>),
            Self::Error,
        >,
    > + Send {
        self.events.push(Event::StrongReobserve);
        let scripted = self.reobserves.pop_front().expect("scripted reobserve");
        async move {
            match scripted {
                Reobserve::Ready(result) => result,
                Reobserve::Pending => pending().await,
            }
        }
    }
}

fn epoch(value: u64) -> RecoveryEpoch {
    RecoveryEpoch::new(value).expect("non-zero epoch")
}

fn attempt(marker: u8) -> RecoveryEpochAttemptId {
    RecoveryEpochAttemptId::new([marker; 32]).expect("non-zero attempt")
}

fn plan(previous: u64, marker: u8) -> RecoveryEpochIssuancePlan {
    let previous = if previous == 0 {
        RecoveryEpochValue::Bootstrap
    } else {
        RecoveryEpochValue::Issued(epoch(previous))
    };
    RecoveryEpochIssuancePlan::new(previous, attempt(marker)).expect("plan")
}

const fn current(plan: RecoveryEpochIssuancePlan) -> RecoveryEpochHeadRecord {
    RecoveryEpochHeadRecord::Issued {
        epoch: plan.proposed_epoch(),
        last_attempt_id: plan.attempt_id(),
    }
}

const fn history(plan: RecoveryEpochIssuancePlan) -> RecoveryEpochIssuanceRecord {
    RecoveryEpochIssuanceRecord {
        epoch: plan.proposed_epoch(),
        previous_epoch: plan.previous_epoch(),
        attempt_id: plan.attempt_id(),
    }
}

#[test]
fn definitive_commit_requires_fresh_current_head_proof() {
    let plan = plan(4, 1);
    let mut ledger = Ledger::new(
        [Ok(RecoveryEpochSubmissionOutcome::CommittedCurrent)],
        [Ok(current(plan))],
        [],
    );
    let resolved = ready(resolve_recovery_epoch_issuance_with_reconciliation(
        &mut ledger,
        plan,
    ))
    .expect("current");
    assert_eq!(resolved.plan(), plan);
    assert_eq!(resolved.outcome(), RecoveryEpochResolvedOutcome::Current);
    assert_eq!(ledger.events, [Event::Submit, Event::StrongHead]);
}

#[test]
fn indeterminate_exact_commit_is_reobserved_without_reissue() {
    let plan = plan(20, 4);
    let mut ledger = Ledger::new(
        [Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate)],
        [],
        [Reobserve::Ready(Ok((current(plan), Some(history(plan)))))],
    );
    let resolved = ready(resolve_recovery_epoch_issuance_with_reconciliation(
        &mut ledger,
        plan,
    ))
    .expect("reobserved commit");
    assert_eq!(resolved.outcome(), RecoveryEpochResolvedOutcome::Current);
    assert_eq!(ledger.submitted, [plan]);
}

#[test]
fn proven_not_committed_allows_one_exact_reissue() {
    let plan = plan(30, 5);
    let predecessor = RecoveryEpochHeadRecord::Issued {
        epoch: epoch(30),
        last_attempt_id: attempt(9),
    };
    let mut ledger = Ledger::new(
        [
            Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate),
            Ok(RecoveryEpochSubmissionOutcome::CommittedCurrent),
        ],
        [Ok(current(plan))],
        [Reobserve::Ready(Ok((predecessor, None)))],
    );
    let resolved = ready(resolve_recovery_epoch_issuance_with_reconciliation(
        &mut ledger,
        plan,
    ))
    .expect("exact reissue");
    assert_eq!(resolved.outcome(), RecoveryEpochResolvedOutcome::Current);
    assert_eq!(ledger.submitted, [plan, plan]);
}

#[test]
fn second_indeterminate_proven_not_committed_has_no_third_submit() {
    let plan = plan(40, 6);
    let predecessor = RecoveryEpochHeadRecord::Issued {
        epoch: epoch(40),
        last_attempt_id: attempt(10),
    };
    let mut ledger = Ledger::new(
        [
            Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate),
            Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate),
        ],
        [],
        [
            Reobserve::Ready(Ok((predecessor, None))),
            Reobserve::Ready(Ok((predecessor, None))),
        ],
    );
    assert_eq!(
        ready(resolve_recovery_epoch_issuance_with_reconciliation(
            &mut ledger,
            plan,
        )),
        Err(RecoveryEpochOrchestrationError::ReissueLimitReached)
    );
    assert_eq!(ledger.submitted, [plan, plan]);
}

#[test]
fn superseded_and_provider_failure_never_reissue() {
    let plan = plan(50, 7);
    let other = attempt(8);
    let head = RecoveryEpochHeadRecord::Issued {
        epoch: plan.proposed_epoch(),
        last_attempt_id: other,
    };
    let row = RecoveryEpochIssuanceRecord {
        epoch: plan.proposed_epoch(),
        previous_epoch: plan.previous_epoch(),
        attempt_id: other,
    };
    let mut superseded = Ledger::new(
        [Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate)],
        [],
        [Reobserve::Ready(Ok((head, Some(row))))],
    );
    let resolved = ready(resolve_recovery_epoch_issuance_with_reconciliation(
        &mut superseded,
        plan,
    ))
    .expect("superseded");
    assert_eq!(resolved.outcome(), RecoveryEpochResolvedOutcome::Superseded);
    assert_eq!(superseded.submitted, [plan]);

    let mut unavailable = Ledger::new(
        [Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate)],
        [],
        [Reobserve::Ready(Err(ScriptedProviderError))],
    );
    assert_eq!(
        ready(resolve_recovery_epoch_issuance_with_reconciliation(
            &mut unavailable,
            plan,
        )),
        Err(RecoveryEpochOrchestrationError::Provider(
            ScriptedProviderError
        ))
    );
    assert_eq!(unavailable.submitted, [plan]);
}

#[test]
fn dropping_pending_reobservation_spawns_no_detached_reissue() {
    let plan = plan(80, 13);
    let mut ledger = Ledger::new(
        [Ok(RecoveryEpochSubmissionOutcome::MutationIndeterminate)],
        [],
        [Reobserve::Pending],
    );
    {
        let future = resolve_recovery_epoch_issuance_with_reconciliation(&mut ledger, plan);
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    }
    assert_eq!(ledger.submitted, [plan]);
    assert_eq!(ledger.events, [Event::Submit, Event::StrongReobserve]);
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
