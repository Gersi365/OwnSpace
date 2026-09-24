//! C02f-AQ bounded fence-sequence allocation reconciliation orchestration.
//!
//! This module owns one exact retained C02f-AJ allocation plan from first AP submission through
//! terminal reconciliation. It performs no initial head read, allocation planning, attempt-ID
//! generation, endpoint/client construction, credential lookup, TLS/auth/RBAC selection, recovery
//! execution, live-owner activation, or runtime activation. Any path that could deliberately reissue
//! the retained allocation first performs explicit fresh AP re-observation. Only fresh
//! `ProvenNotCommitted` may consume the existing one-reissue AJ budget, and there is no third-submit
//! path.

use std::{fmt, future::Future};

use crate::{
    fence_sequence::{
        FenceSequenceAllocationPlan, FenceSequenceError, FenceSequenceReissueBudget,
        FenceSequenceReobservation,
    },
    fence_sequence_allocation_etcd::{
        FenceSequenceAllocationDefinitiveMutation, FenceSequenceAllocationEtcdError,
        FenceSequenceAllocationEtcdStore,
    },
};

/// Submission-level result consumed by the bounded C02f-AQ reconciliation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceAllocationSubmissionOutcome {
    /// The retained AP transaction returned a definitive successful two-Put response.
    Applied,
    /// The retained AP transaction definitively took its compare-failure branch.
    CompareFailed(FenceSequenceReobservation),
    /// The provider returned no definitive transaction outcome.
    MutationIndeterminate,
}

/// Static-dispatch authority seam used by the C02f-AQ reconciliation state machine.
pub trait FenceSequenceAllocationAuthority {
    type Error;

    fn submit_allocation(
        &mut self,
        plan: FenceSequenceAllocationPlan,
    ) -> impl Future<Output = Result<FenceSequenceAllocationSubmissionOutcome, Self::Error>> + Send;

    fn fresh_reobserve(
        &mut self,
        plan: FenceSequenceAllocationPlan,
    ) -> impl Future<Output = Result<FenceSequenceReobservation, Self::Error>> + Send;
}

impl FenceSequenceAllocationAuthority for FenceSequenceAllocationEtcdStore {
    type Error = FenceSequenceAllocationEtcdError;

    async fn submit_allocation(
        &mut self,
        plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceAllocationSubmissionOutcome, Self::Error> {
        match self.execute(&plan).await {
            Ok(FenceSequenceAllocationDefinitiveMutation::Applied) => {
                Ok(FenceSequenceAllocationSubmissionOutcome::Applied)
            }
            Ok(FenceSequenceAllocationDefinitiveMutation::CompareFailed(classification)) => Ok(
                FenceSequenceAllocationSubmissionOutcome::CompareFailed(classification),
            ),
            Err(FenceSequenceAllocationEtcdError::MutationIndeterminate(_)) => {
                Ok(FenceSequenceAllocationSubmissionOutcome::MutationIndeterminate)
            }
            Err(error) => Err(error),
        }
    }

    async fn fresh_reobserve(
        &mut self,
        plan: FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceReobservation, Self::Error> {
        self.reobserve(&plan).await
    }
}

/// Terminal result for one exact retained fence-sequence allocation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceAllocationResolvedOutcome {
    /// The retained allocation attempt is authoritatively committed.
    Committed,
    /// The retained sequence/reservation slot is authoritatively owned by another attempt.
    Superseded,
}

/// Exact retained AJ plan plus its terminal C02f-AQ reconciliation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceAllocationResolved {
    plan: FenceSequenceAllocationPlan,
    outcome: FenceSequenceAllocationResolvedOutcome,
}

impl FenceSequenceAllocationResolved {
    /// Returns the exact retained AJ allocation plan used for every submission in this operation.
    #[must_use]
    pub const fn plan(&self) -> &FenceSequenceAllocationPlan {
        &self.plan
    }

    /// Returns the terminal reconciliation outcome.
    #[must_use]
    pub const fn outcome(&self) -> FenceSequenceAllocationResolvedOutcome {
        self.outcome
    }

    /// Consumes the terminal result and returns the exact retained AJ allocation plan.
    #[must_use]
    pub fn into_plan(self) -> FenceSequenceAllocationPlan {
        self.plan
    }
}

/// Fail-closed C02f-AQ orchestration error.
#[derive(Debug, PartialEq, Eq)]
pub enum FenceSequenceAllocationOrchestrationError<E> {
    /// The underlying authority failed outside the explicitly classified indeterminate-submit path.
    Authority(E),
    /// AJ reconciliation/budget semantics rejected a state transition.
    Domain(FenceSequenceError),
    /// Both permitted submissions ended without authoritative commit/supersession; a third submit is forbidden.
    ReissueLimitReached,
}

impl<E: fmt::Display> fmt::Display for FenceSequenceAllocationOrchestrationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => {
                write!(formatter, "fence-sequence allocation authority error: {error}")
            }
            Self::Domain(error) => {
                write!(formatter, "fence-sequence allocation domain error: {error}")
            }
            Self::ReissueLimitReached => formatter.write_str(
                "fence-sequence allocation remained proven not committed after the one permitted exact reissue",
            ),
        }
    }
}

impl<E> std::error::Error for FenceSequenceAllocationOrchestrationError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Domain(error) => Some(error),
            Self::ReissueLimitReached => None,
        }
    }
}

/// Resolves one exact retained AJ allocation plan with bounded AP reconciliation.
///
/// The caller supplies an already-retained allocation plan. This function never performs the initial
/// PRWF head read, never calls `plan_allocation`, never generates a new attempt ID, and never changes
/// the retained plan between submissions.
///
/// The first submission is reconciled as follows:
///
/// - definitive `Applied` => one fresh re-observation; only `Committed` may return authority;
/// - definitive compare failure classified `Committed`/`Superseded` => terminal result;
/// - definitive compare failure classified `ProvenNotCommitted` => one fresh re-observation before
///   any possible reissue;
/// - `MutationIndeterminate` => one fresh re-observation before any possible reissue.
///
/// Only a *fresh* `ProvenNotCommitted` observation consumes the existing AJ one-reissue budget and
/// permits the second exact submission. The second submission is terminal. Another proof of
/// non-commit returns `ReissueLimitReached`, and there is no third-submit path.
///
/// # Errors
///
/// Returns an authority error for fatal adapter/provider failure, a domain error when a fresh
/// observation contradicts a prior definitive successful apply or AJ budget semantics reject the
/// transition, or `ReissueLimitReached` after the one permitted exact reissue is exhausted.
pub async fn resolve_fence_sequence_allocation_with_reconciliation<A>(
    authority: &mut A,
    plan: FenceSequenceAllocationPlan,
) -> Result<FenceSequenceAllocationResolved, FenceSequenceAllocationOrchestrationError<A::Error>>
where
    A: FenceSequenceAllocationAuthority,
{
    let mut budget = FenceSequenceReissueBudget::default();

    match submit(authority, plan.clone()).await? {
        FenceSequenceAllocationSubmissionOutcome::Applied => {
            return confirm_applied(authority, plan).await;
        }
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Committed,
        ) => {
            return Ok(resolved(
                plan,
                FenceSequenceAllocationResolvedOutcome::Committed,
            ));
        }
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Superseded,
        ) => {
            return Ok(resolved(
                plan,
                FenceSequenceAllocationResolvedOutcome::Superseded,
            ));
        }
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::ProvenNotCommitted,
        )
        | FenceSequenceAllocationSubmissionOutcome::MutationIndeterminate => {
            match reobserve(authority, plan.clone()).await? {
                FenceSequenceReobservation::Committed => {
                    return Ok(resolved(
                        plan,
                        FenceSequenceAllocationResolvedOutcome::Committed,
                    ));
                }
                FenceSequenceReobservation::Superseded => {
                    return Ok(resolved(
                        plan,
                        FenceSequenceAllocationResolvedOutcome::Superseded,
                    ));
                }
                observed @ FenceSequenceReobservation::ProvenNotCommitted => {
                    budget
                        .consume(observed)
                        .map_err(FenceSequenceAllocationOrchestrationError::Domain)?;
                }
            }
        }
    }

    match submit(authority, plan.clone()).await? {
        FenceSequenceAllocationSubmissionOutcome::Applied => confirm_applied(authority, plan).await,
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Committed,
        ) => Ok(resolved(
            plan,
            FenceSequenceAllocationResolvedOutcome::Committed,
        )),
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::Superseded,
        ) => Ok(resolved(
            plan,
            FenceSequenceAllocationResolvedOutcome::Superseded,
        )),
        FenceSequenceAllocationSubmissionOutcome::CompareFailed(
            FenceSequenceReobservation::ProvenNotCommitted,
        ) => Err(FenceSequenceAllocationOrchestrationError::ReissueLimitReached),
        FenceSequenceAllocationSubmissionOutcome::MutationIndeterminate => {
            match reobserve(authority, plan.clone()).await? {
                FenceSequenceReobservation::Committed => Ok(resolved(
                    plan,
                    FenceSequenceAllocationResolvedOutcome::Committed,
                )),
                FenceSequenceReobservation::Superseded => Ok(resolved(
                    plan,
                    FenceSequenceAllocationResolvedOutcome::Superseded,
                )),
                FenceSequenceReobservation::ProvenNotCommitted => {
                    Err(FenceSequenceAllocationOrchestrationError::ReissueLimitReached)
                }
            }
        }
    }
}

async fn submit<A>(
    authority: &mut A,
    plan: FenceSequenceAllocationPlan,
) -> Result<
    FenceSequenceAllocationSubmissionOutcome,
    FenceSequenceAllocationOrchestrationError<A::Error>,
>
where
    A: FenceSequenceAllocationAuthority,
{
    authority
        .submit_allocation(plan)
        .await
        .map_err(FenceSequenceAllocationOrchestrationError::Authority)
}

async fn reobserve<A>(
    authority: &mut A,
    plan: FenceSequenceAllocationPlan,
) -> Result<FenceSequenceReobservation, FenceSequenceAllocationOrchestrationError<A::Error>>
where
    A: FenceSequenceAllocationAuthority,
{
    authority
        .fresh_reobserve(plan)
        .await
        .map_err(FenceSequenceAllocationOrchestrationError::Authority)
}

async fn confirm_applied<A>(
    authority: &mut A,
    plan: FenceSequenceAllocationPlan,
) -> Result<FenceSequenceAllocationResolved, FenceSequenceAllocationOrchestrationError<A::Error>>
where
    A: FenceSequenceAllocationAuthority,
{
    match reobserve(authority, plan.clone()).await? {
        FenceSequenceReobservation::Committed => Ok(resolved(
            plan,
            FenceSequenceAllocationResolvedOutcome::Committed,
        )),
        FenceSequenceReobservation::Superseded | FenceSequenceReobservation::ProvenNotCommitted => {
            Err(FenceSequenceAllocationOrchestrationError::Domain(
                FenceSequenceError::ContradictoryState,
            ))
        }
    }
}

const fn resolved(
    plan: FenceSequenceAllocationPlan,
    outcome: FenceSequenceAllocationResolvedOutcome,
) -> FenceSequenceAllocationResolved {
    FenceSequenceAllocationResolved { plan, outcome }
}
