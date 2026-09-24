//! C02f-AO bounded fence-sequence initialization reconciliation orchestration.
//!
//! This module owns one exact retained C02f-AM initialization transaction plan from first AN
//! submission through terminal reconciliation. It performs no initial planning, endpoint/client
//! construction, credential lookup, TLS/auth/RBAC selection, sequence allocation, recovery
//! execution, or runtime activation. A mutation-indeterminate result is always freshly re-observed
//! before any retransmission. Only `ProvenNotCommitted` permits one deliberate exact reissue, and a
//! second non-commit proof can never cause a third submission.

use std::{fmt, future::Future};

use crate::{
    fence_sequence_initialization::{
        FenceSequenceInitializationError, FenceSequenceInitializationReobservation,
        FenceSequenceInitializationTxnPlan,
    },
    fence_sequence_initialization_etcd::{
        FenceSequenceInitializationDefinitiveMutation, FenceSequenceInitializationEtcdError,
        FenceSequenceInitializationEtcdStore,
    },
};

/// Submission-level result consumed by the bounded C02f-AO reconciliation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceInitializationSubmissionOutcome {
    /// The retained AN transaction returned a definitive successful Put response.
    Applied,
    /// The retained AN transaction definitively took its compare-failure branch.
    CompareFailed(FenceSequenceInitializationReobservation),
    /// The provider returned no definitive transaction outcome.
    MutationIndeterminate,
}

/// Static-dispatch authority seam used by the C02f-AO reconciliation state machine.
pub trait FenceSequenceInitializationAuthority {
    type Error;

    fn submit_initialization(
        &mut self,
        plan: FenceSequenceInitializationTxnPlan,
    ) -> impl Future<Output = Result<FenceSequenceInitializationSubmissionOutcome, Self::Error>> + Send;

    fn fresh_reobserve(
        &mut self,
        plan: FenceSequenceInitializationTxnPlan,
    ) -> impl Future<Output = Result<FenceSequenceInitializationReobservation, Self::Error>> + Send;
}

impl FenceSequenceInitializationAuthority for FenceSequenceInitializationEtcdStore {
    type Error = FenceSequenceInitializationEtcdError;

    async fn submit_initialization(
        &mut self,
        plan: FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationSubmissionOutcome, Self::Error> {
        match self.execute(&plan).await {
            Ok(FenceSequenceInitializationDefinitiveMutation::Applied) => {
                Ok(FenceSequenceInitializationSubmissionOutcome::Applied)
            }
            Ok(FenceSequenceInitializationDefinitiveMutation::CompareFailed(classification)) => Ok(
                FenceSequenceInitializationSubmissionOutcome::CompareFailed(classification),
            ),
            Err(FenceSequenceInitializationEtcdError::MutationIndeterminate(_)) => {
                Ok(FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate)
            }
            Err(error) => Err(error),
        }
    }

    async fn fresh_reobserve(
        &mut self,
        plan: FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationReobservation, Self::Error> {
        self.reobserve(&plan).await
    }
}

/// Terminal result for one exact retained fence-sequence initialization transaction plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceInitializationResolvedOutcome {
    /// The target recovery epoch is the freshly observed current PRWF epoch.
    Current,
    /// A later recovery epoch has already superseded the retained target.
    Superseded,
}

/// Exact retained AM plan plus its terminal C02f-AO reconciliation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceInitializationResolved {
    plan: FenceSequenceInitializationTxnPlan,
    outcome: FenceSequenceInitializationResolvedOutcome,
}

impl FenceSequenceInitializationResolved {
    /// Returns the exact retained AM transaction plan used for every submission in this operation.
    #[must_use]
    pub const fn plan(&self) -> &FenceSequenceInitializationTxnPlan {
        &self.plan
    }

    /// Returns the terminal reconciliation outcome.
    #[must_use]
    pub const fn outcome(&self) -> FenceSequenceInitializationResolvedOutcome {
        self.outcome
    }

    /// Consumes the terminal result and returns the exact retained plan.
    #[must_use]
    pub fn into_plan(self) -> FenceSequenceInitializationTxnPlan {
        self.plan
    }
}

/// Fail-closed C02f-AO orchestration error.
#[derive(Debug, PartialEq, Eq)]
pub enum FenceSequenceInitializationOrchestrationError<E> {
    /// The underlying authority failed outside the explicitly classified indeterminate-submit path.
    Authority(E),
    /// A fresh observation contradicted a prior definitive successful apply.
    Domain(FenceSequenceInitializationError),
    /// Both permitted submissions were proven not committed; a third submit is forbidden.
    ReissueLimitReached,
}

impl<E: fmt::Display> fmt::Display for FenceSequenceInitializationOrchestrationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => {
                write!(formatter, "fence-sequence initialization authority error: {error}")
            }
            Self::Domain(error) => {
                write!(formatter, "fence-sequence initialization domain error: {error}")
            }
            Self::ReissueLimitReached => formatter.write_str(
                "fence-sequence initialization remained proven not committed after the one permitted exact reissue",
            ),
        }
    }
}

impl<E> std::error::Error for FenceSequenceInitializationOrchestrationError<E>
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

/// Resolves one exact retained AM initialization transaction with bounded AN reconciliation.
///
/// The caller supplies an already-retained mutation plan. This function never performs the initial
/// PRWF head read, never calls `plan_initialization`, and never changes the retained plan between
/// submissions. The first submission is reconciled as follows:
///
/// - definitive `Applied` => one fresh linearizable re-observation before returning authority;
/// - definitive compare failure classified `Current`/`Superseded` => terminal result;
/// - definitive compare failure classified `ProvenNotCommitted` => one exact reissue;
/// - `MutationIndeterminate` => one fresh linearizable re-observation before any possible reissue.
///
/// Only a `ProvenNotCommitted` classification permits the second exact submission. The second
/// submission is terminal: another proof of non-commit returns `ReissueLimitReached` and there is no
/// third-submit path.
///
/// # Errors
///
/// Returns an authority error for fatal adapter/provider failure, a domain error when a fresh
/// observation contradicts a prior definitive successful apply, or `ReissueLimitReached` after the
/// one permitted exact reissue is exhausted.
pub async fn resolve_fence_sequence_initialization_with_reconciliation<A>(
    authority: &mut A,
    plan: FenceSequenceInitializationTxnPlan,
) -> Result<
    FenceSequenceInitializationResolved,
    FenceSequenceInitializationOrchestrationError<A::Error>,
>
where
    A: FenceSequenceInitializationAuthority,
{
    match submit(authority, plan.clone()).await? {
        FenceSequenceInitializationSubmissionOutcome::Applied => {
            return confirm_applied(authority, plan).await;
        }
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::Current,
        ) => {
            return Ok(resolved(
                plan,
                FenceSequenceInitializationResolvedOutcome::Current,
            ));
        }
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::Superseded,
        ) => {
            return Ok(resolved(
                plan,
                FenceSequenceInitializationResolvedOutcome::Superseded,
            ));
        }
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::ProvenNotCommitted,
        ) => {}
        FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate => {
            match reobserve(authority, plan.clone()).await? {
                FenceSequenceInitializationReobservation::Current => {
                    return Ok(resolved(
                        plan,
                        FenceSequenceInitializationResolvedOutcome::Current,
                    ));
                }
                FenceSequenceInitializationReobservation::Superseded => {
                    return Ok(resolved(
                        plan,
                        FenceSequenceInitializationResolvedOutcome::Superseded,
                    ));
                }
                FenceSequenceInitializationReobservation::ProvenNotCommitted => {}
            }
        }
    }

    match submit(authority, plan.clone()).await? {
        FenceSequenceInitializationSubmissionOutcome::Applied => {
            confirm_applied(authority, plan).await
        }
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::Current,
        ) => Ok(resolved(
            plan,
            FenceSequenceInitializationResolvedOutcome::Current,
        )),
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::Superseded,
        ) => Ok(resolved(
            plan,
            FenceSequenceInitializationResolvedOutcome::Superseded,
        )),
        FenceSequenceInitializationSubmissionOutcome::CompareFailed(
            FenceSequenceInitializationReobservation::ProvenNotCommitted,
        ) => Err(FenceSequenceInitializationOrchestrationError::ReissueLimitReached),
        FenceSequenceInitializationSubmissionOutcome::MutationIndeterminate => {
            match reobserve(authority, plan.clone()).await? {
                FenceSequenceInitializationReobservation::Current => Ok(resolved(
                    plan,
                    FenceSequenceInitializationResolvedOutcome::Current,
                )),
                FenceSequenceInitializationReobservation::Superseded => Ok(resolved(
                    plan,
                    FenceSequenceInitializationResolvedOutcome::Superseded,
                )),
                FenceSequenceInitializationReobservation::ProvenNotCommitted => {
                    Err(FenceSequenceInitializationOrchestrationError::ReissueLimitReached)
                }
            }
        }
    }
}

async fn submit<A>(
    authority: &mut A,
    plan: FenceSequenceInitializationTxnPlan,
) -> Result<
    FenceSequenceInitializationSubmissionOutcome,
    FenceSequenceInitializationOrchestrationError<A::Error>,
>
where
    A: FenceSequenceInitializationAuthority,
{
    authority
        .submit_initialization(plan)
        .await
        .map_err(FenceSequenceInitializationOrchestrationError::Authority)
}

async fn reobserve<A>(
    authority: &mut A,
    plan: FenceSequenceInitializationTxnPlan,
) -> Result<
    FenceSequenceInitializationReobservation,
    FenceSequenceInitializationOrchestrationError<A::Error>,
>
where
    A: FenceSequenceInitializationAuthority,
{
    authority
        .fresh_reobserve(plan)
        .await
        .map_err(FenceSequenceInitializationOrchestrationError::Authority)
}

async fn confirm_applied<A>(
    authority: &mut A,
    plan: FenceSequenceInitializationTxnPlan,
) -> Result<
    FenceSequenceInitializationResolved,
    FenceSequenceInitializationOrchestrationError<A::Error>,
>
where
    A: FenceSequenceInitializationAuthority,
{
    match reobserve(authority, plan.clone()).await? {
        FenceSequenceInitializationReobservation::Current => Ok(resolved(
            plan,
            FenceSequenceInitializationResolvedOutcome::Current,
        )),
        FenceSequenceInitializationReobservation::Superseded => Ok(resolved(
            plan,
            FenceSequenceInitializationResolvedOutcome::Superseded,
        )),
        FenceSequenceInitializationReobservation::ProvenNotCommitted => {
            Err(FenceSequenceInitializationOrchestrationError::Domain(
                FenceSequenceInitializationError::ContradictoryState,
            ))
        }
    }
}

const fn resolved(
    plan: FenceSequenceInitializationTxnPlan,
    outcome: FenceSequenceInitializationResolvedOutcome,
) -> FenceSequenceInitializationResolved {
    FenceSequenceInitializationResolved { plan, outcome }
}
