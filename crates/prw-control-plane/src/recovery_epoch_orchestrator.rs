//! C02f-AL provider-neutral recovery-epoch issuance reconciliation orchestration.
//!
//! This module owns one exact retained `(H, N, A)` issuance plan from submission through terminal
//! reconciliation. It performs no attempt-ID generation, provider construction, credential lookup,
//! endpoint selection, cloud resource/schema mutation, recovery execution, or runtime activation.
//! A mutation-indeterminate result is always strongly re-observed before any retransmission. Only
//! `ProvenNotCommitted` permits one deliberate reissue of the exact same plan, and a second
//! indeterminate result can never cause a third submission.

use std::fmt;

use crate::recovery_epoch::{
    RecoveryEpochError, RecoveryEpochHeadRecord, RecoveryEpochIssuancePlan,
    RecoveryEpochLedgerAuthority, RecoveryEpochReissueBudget, RecoveryEpochReobservation,
    RecoveryEpochSubmissionOutcome, classify_reobservation,
};

/// Terminal provider-neutral result for one exact recovery-epoch issuance plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEpochResolvedOutcome {
    /// The exact proposed epoch is proven to be the current global epoch high-water.
    Current,
    /// The exact plan committed, but a later epoch is already globally current.
    CommittedButSuperseded,
    /// Durable state proves that this exact retained plan does not own the proposed epoch.
    Superseded,
    /// The provider definitively reported that the submitted transaction did not commit.
    Aborted,
}

/// Exact retained issuance plan plus its terminal C02f-AL orchestration outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEpochResolvedIssuance {
    plan: RecoveryEpochIssuancePlan,
    outcome: RecoveryEpochResolvedOutcome,
}

impl RecoveryEpochResolvedIssuance {
    /// Returns the exact retained `(H, N, A)` plan used for every submission in this operation.
    #[must_use]
    pub const fn plan(self) -> RecoveryEpochIssuancePlan {
        self.plan
    }

    /// Returns the terminal provider-neutral orchestration outcome.
    #[must_use]
    pub const fn outcome(self) -> RecoveryEpochResolvedOutcome {
        self.outcome
    }
}

/// Fail-closed provider-neutral recovery-epoch orchestration error.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryEpochOrchestrationError<E> {
    /// The authority provider failed while submitting or strongly observing durable state.
    Provider(E),
    /// Canonical recovery-epoch state was malformed, contradictory, or otherwise invalid.
    Domain(RecoveryEpochError),
    /// Both permitted submissions were proven not committed; a third submit is forbidden.
    ReissueLimitReached,
}

impl<E: fmt::Display> fmt::Display for RecoveryEpochOrchestrationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(formatter, "recovery-epoch provider error: {error}"),
            Self::Domain(error) => write!(formatter, "recovery-epoch domain error: {error}"),
            Self::ReissueLimitReached => formatter.write_str(
                "recovery-epoch issuance remained proven not committed after the one permitted exact reissue",
            ),
        }
    }
}

impl<E> std::error::Error for RecoveryEpochOrchestrationError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Domain(error) => Some(error),
            Self::ReissueLimitReached => None,
        }
    }
}

/// Resolves one exact recovery-epoch issuance plan with bounded indeterminate reconciliation.
///
/// The caller supplies an already-retained `(H, N, A)` plan. This function never replans and never
/// changes the attempt ID. `MutationIndeterminate` always triggers a fresh strong head-plus-history
/// observation. Only `ProvenNotCommitted` consumes the one-reissue budget and permits the same plan
/// to be submitted a second time. A second indeterminate result is strongly re-observed again; if
/// it is again proven not committed, the function fails closed and does not submit a third time.
///
/// A provider-reported successful commit is followed by a fresh strong head read before `Current`
/// can be returned. Thus epoch `N` is authoritative only while `N` is still the global high-water.
///
/// # Errors
///
/// Returns a provider error for failed I/O, a domain error for contradictory durable state, or
/// `ReissueLimitReached` after the one permitted exact reissue is exhausted.
pub async fn resolve_recovery_epoch_issuance_with_reconciliation<A>(
    authority: &mut A,
    plan: RecoveryEpochIssuancePlan,
) -> Result<RecoveryEpochResolvedIssuance, RecoveryEpochOrchestrationError<A::Error>>
where
    A: RecoveryEpochLedgerAuthority,
{
    let mut budget = RecoveryEpochReissueBudget::default();

    match submit(authority, plan).await? {
        RecoveryEpochSubmissionOutcome::CommittedCurrent => {
            return confirm_definitive_commit(authority, plan).await;
        }
        RecoveryEpochSubmissionOutcome::Aborted => {
            return Ok(resolved(plan, RecoveryEpochResolvedOutcome::Aborted));
        }
        RecoveryEpochSubmissionOutcome::MutationIndeterminate => {}
    }

    match strong_reobserve(authority, plan).await? {
        RecoveryEpochReobservation::CommittedCurrent => {
            return Ok(resolved(plan, RecoveryEpochResolvedOutcome::Current));
        }
        RecoveryEpochReobservation::CommittedButSuperseded => {
            return Ok(resolved(
                plan,
                RecoveryEpochResolvedOutcome::CommittedButSuperseded,
            ));
        }
        RecoveryEpochReobservation::Superseded => {
            return Ok(resolved(plan, RecoveryEpochResolvedOutcome::Superseded));
        }
        RecoveryEpochReobservation::ProvenNotCommitted => {
            consume_reissue_budget(&mut budget)?;
        }
    }

    match submit(authority, plan).await? {
        RecoveryEpochSubmissionOutcome::CommittedCurrent => {
            confirm_definitive_commit(authority, plan).await
        }
        RecoveryEpochSubmissionOutcome::Aborted => {
            Ok(resolved(plan, RecoveryEpochResolvedOutcome::Aborted))
        }
        RecoveryEpochSubmissionOutcome::MutationIndeterminate => {
            match strong_reobserve(authority, plan).await? {
                RecoveryEpochReobservation::CommittedCurrent => {
                    Ok(resolved(plan, RecoveryEpochResolvedOutcome::Current))
                }
                RecoveryEpochReobservation::CommittedButSuperseded => Ok(resolved(
                    plan,
                    RecoveryEpochResolvedOutcome::CommittedButSuperseded,
                )),
                RecoveryEpochReobservation::Superseded => {
                    Ok(resolved(plan, RecoveryEpochResolvedOutcome::Superseded))
                }
                RecoveryEpochReobservation::ProvenNotCommitted => {
                    Err(RecoveryEpochOrchestrationError::ReissueLimitReached)
                }
            }
        }
    }
}

async fn submit<A>(
    authority: &mut A,
    plan: RecoveryEpochIssuancePlan,
) -> Result<RecoveryEpochSubmissionOutcome, RecoveryEpochOrchestrationError<A::Error>>
where
    A: RecoveryEpochLedgerAuthority,
{
    authority
        .submit_issuance(plan)
        .await
        .map_err(RecoveryEpochOrchestrationError::Provider)
}

async fn strong_reobserve<A>(
    authority: &mut A,
    plan: RecoveryEpochIssuancePlan,
) -> Result<RecoveryEpochReobservation, RecoveryEpochOrchestrationError<A::Error>>
where
    A: RecoveryEpochLedgerAuthority,
{
    let (head, history) = authority
        .strong_reobserve(plan.proposed_epoch())
        .await
        .map_err(RecoveryEpochOrchestrationError::Provider)?;
    classify_reobservation(plan, head, history).map_err(RecoveryEpochOrchestrationError::Domain)
}

async fn confirm_definitive_commit<A>(
    authority: &mut A,
    plan: RecoveryEpochIssuancePlan,
) -> Result<RecoveryEpochResolvedIssuance, RecoveryEpochOrchestrationError<A::Error>>
where
    A: RecoveryEpochLedgerAuthority,
{
    let head = authority
        .strong_head()
        .await
        .map_err(RecoveryEpochOrchestrationError::Provider)?;
    let outcome = classify_definitive_commit_head(plan, head)
        .map_err(RecoveryEpochOrchestrationError::Domain)?;
    Ok(resolved(plan, outcome))
}

fn classify_definitive_commit_head(
    plan: RecoveryEpochIssuancePlan,
    head: RecoveryEpochHeadRecord,
) -> Result<RecoveryEpochResolvedOutcome, RecoveryEpochError> {
    let proposed = plan.proposed_epoch().get();
    let current = head.epoch().get();
    if current < proposed {
        return Err(RecoveryEpochError::ContradictoryState);
    }
    if current > proposed {
        return Ok(RecoveryEpochResolvedOutcome::CommittedButSuperseded);
    }
    match head {
        RecoveryEpochHeadRecord::Issued {
            epoch,
            last_attempt_id,
        } if epoch == plan.proposed_epoch() && last_attempt_id == plan.attempt_id() => {
            Ok(RecoveryEpochResolvedOutcome::Current)
        }
        RecoveryEpochHeadRecord::Bootstrap | RecoveryEpochHeadRecord::Issued { .. } => {
            Err(RecoveryEpochError::ContradictoryState)
        }
    }
}

fn consume_reissue_budget<E>(
    budget: &mut RecoveryEpochReissueBudget,
) -> Result<(), RecoveryEpochOrchestrationError<E>> {
    match budget.consume(RecoveryEpochReobservation::ProvenNotCommitted) {
        Ok(()) => Ok(()),
        Err(RecoveryEpochError::ReissueLimitReached) => {
            Err(RecoveryEpochOrchestrationError::ReissueLimitReached)
        }
        Err(error) => Err(RecoveryEpochOrchestrationError::Domain(error)),
    }
}

const fn resolved(
    plan: RecoveryEpochIssuancePlan,
    outcome: RecoveryEpochResolvedOutcome,
) -> RecoveryEpochResolvedIssuance {
    RecoveryEpochResolvedIssuance { plan, outcome }
}
