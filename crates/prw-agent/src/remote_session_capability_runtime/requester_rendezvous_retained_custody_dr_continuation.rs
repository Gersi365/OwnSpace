//! Agent-owned retained-custody requester/rendezvous DR continuation, terminal response composition,
//! isolated post-terminal serial lifecycle, and cancellation-aware higher-owner worker.
//!
//! C03e-FB materializes the C03e-FA-selected continuation from one exact C03e-EZ response-stream
//! custody handoff through the existing shared-current authority read and existing C03e-DR
//! DI -> DP -> DK -> DN composition. The exact bridge requester transaction survives both DR success
//! and DR failure. C03e-FH adds only the C03e-FG-selected Agent-owned terminal composition from that
//! exact retained DR result through the existing C03e-FD pure acknowledgement framing boundary into
//! the existing C03e-FF consuming same-stream send surface. C03e-FJ adds only the C03e-FI-selected
//! isolated serial lifecycle that resumes the existing EV/EX mixed-family ingress after FH success
//! and fail-stops on existing ingress or requester-response failure. C03e-FL adds only the
//! C03e-FK-selected cancellation-aware higher-owner worker around those exact serial transaction
//! boundaries. This module still performs no automatic peer close, candidate/reachability selection,
//! dialing, runtime activation, deployment or merge.

use std::{
    fmt,
    future::{Future, poll_fn},
    task::Poll,
};

use prw_policy::PolicyEvaluator;
use prw_remote_bridge::{
    CapabilityDispatcher,
    post_auth_control_stream_ingress::{
        PostAuthRequesterRendezvousTransaction, RequesterRendezvousDrAcknowledgementResponseIoError,
    },
    requester_rendezvous_dr_acknowledgement_wire::{
        RequesterRendezvousDrAcknowledgementWireError,
        encode_requester_rendezvous_dr_result_for_transaction,
    },
};

use super::authenticated_remote_session_runtime::{
    AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
    AuthenticatedRemoteSessionRuntimeOwner,
};
use super::shared_requester_rendezvous_authority::{
    ExpectedDeviceSchedulingAuthorityDerivationError, ExpectedDeviceSchedulingAuthorityGrant,
};
use super::{
    AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    RequesterRendezvousResponseStreamCustodyHandoff, SharedCurrentCapabilityAuthority,
    SharedRequesterRendezvousAuthority,
};
use crate::candidate_publication_requester_rendezvous_start_intent::{
    composition::RequesterRendezvousStartCompositionError,
    policy_source::RequesterRendezvousStartPolicySource,
};

/// Terminal C03e-FB custody after exactly one existing DR authority composition.
///
/// The bridge requester transaction is retained by value regardless of whether DR returned `Ok(())`
/// or one exact [`RequesterRendezvousStartCompositionError`]. Possession of this value does not
/// imply endpoint selection, reachability, rendezvous completion, response delivery or transport
/// establishment.
pub(super) struct RequesterRendezvousRetainedCustodyDrContinuation {
    requester_transaction: PostAuthRequesterRendezvousTransaction,
    dr_result: Result<(), RequesterRendezvousStartCompositionError>,
}

impl RequesterRendezvousRetainedCustodyDrContinuation {
    /// Borrows the exact bridge requester transaction retained across DR.
    #[must_use]
    pub(super) const fn requester_transaction(&self) -> &PostAuthRequesterRendezvousTransaction {
        &self.requester_transaction
    }

    /// Borrows the exact terminal DR result without translating or flattening its failure class.
    pub(super) const fn dr_result(&self) -> &Result<(), RequesterRendezvousStartCompositionError> {
        &self.dr_result
    }

    /// Transfers the exact requester transaction and exact terminal DR result by value.
    ///
    /// This is custody transfer only and performs no stream I/O or response construction.
    pub(super) fn into_parts(
        self,
    ) -> (
        PostAuthRequesterRendezvousTransaction,
        Result<(), RequesterRendezvousStartCompositionError>,
    ) {
        (self.requester_transaction, self.dr_result)
    }
}

/// Failure while completing one exact retained requester/rendezvous DR acknowledgement response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError {
    /// Existing C03e-FD pure acknowledgement framing failed before any response write attempt.
    Frame(RequesterRendezvousDrAcknowledgementWireError),
    /// Existing C03e-FF exact same-stream response write or send-direction finish failed.
    ResponseIo(RequesterRendezvousDrAcknowledgementResponseIoError),
}

impl fmt::Display for RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Frame(_) => "requester rendezvous DR acknowledgement framing failed",
            Self::ResponseIo(_) => "requester rendezvous DR acknowledgement response I/O failed",
        })
    }
}

impl std::error::Error for RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::ResponseIo(error) => Some(error),
        }
    }
}

impl From<RequesterRendezvousDrAcknowledgementWireError>
    for RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError
{
    fn from(error: RequesterRendezvousDrAcknowledgementWireError) -> Self {
        Self::Frame(error)
    }
}

impl From<RequesterRendezvousDrAcknowledgementResponseIoError>
    for RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError
{
    fn from(error: RequesterRendezvousDrAcknowledgementResponseIoError) -> Self {
        Self::ResponseIo(error)
    }
}

/// Failure while running the isolated C03e-FI-selected serial post-terminal requester lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RequesterRendezvousPostTerminalResponseSerialLifecycleError {
    /// Existing EV/EX mixed-family ingress failed before a requester response transaction completed.
    Ingress(AuthenticatedRemoteSessionPostAuthIngressTransactionError),
    /// Existing FH requester terminal response composition failed after one requester handoff.
    RequesterResponse(RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError),
}

impl fmt::Display for RequesterRendezvousPostTerminalResponseSerialLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ingress(_) => "post-authenticated mixed-family ingress failed",
            Self::RequesterResponse(_) => "requester rendezvous terminal response failed",
        })
    }
}

impl std::error::Error for RequesterRendezvousPostTerminalResponseSerialLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ingress(error) => Some(error),
            Self::RequesterResponse(error) => Some(error),
        }
    }
}

impl From<AuthenticatedRemoteSessionPostAuthIngressTransactionError>
    for RequesterRendezvousPostTerminalResponseSerialLifecycleError
{
    fn from(error: AuthenticatedRemoteSessionPostAuthIngressTransactionError) -> Self {
        Self::Ingress(error)
    }
}

impl From<RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>
    for RequesterRendezvousPostTerminalResponseSerialLifecycleError
{
    fn from(error: RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError) -> Self {
        Self::RequesterResponse(error)
    }
}

/// Terminal higher-owner result of the C03e-FK-selected cancellation-aware serial lifecycle worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop {
    /// Caller-owned cancellation won at one selected cancellation-safe lifecycle boundary.
    Cancelled,
    /// Existing FJ lifecycle semantics reached one exact typed ingress or requester-response failure.
    Failed(RequesterRendezvousPostTerminalResponseSerialLifecycleError),
}

/// Failure while running the QV fallible-verifier-time production-durable requester lifecycle.
#[allow(
    dead_code,
    reason = "C03e-QV materializes the QU-selected fallible requester lifecycle error before separately gated scheduling-aware or higher-owner propagation"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError {
    /// Exact QT verifier-time or production-durable ingress failure before requester handoff.
    Ingress(AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError),
    /// Existing FH requester terminal response composition failed after one requester handoff.
    RequesterResponse(RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError),
}

impl fmt::Display
    for RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ingress(_) => "fallible production-durable requester lifecycle ingress failed",
            Self::RequesterResponse(_) => "requester rendezvous terminal response failed",
        })
    }
}

impl std::error::Error
    for RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ingress(error) => Some(error),
            Self::RequesterResponse(error) => Some(error),
        }
    }
}

impl From<AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError>
    for RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError
{
    fn from(
        error: AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
    ) -> Self {
        Self::Ingress(error)
    }
}

impl From<RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>
    for RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError
{
    fn from(error: RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError) -> Self {
        Self::RequesterResponse(error)
    }
}

/// Terminal result for the QV fallible-verifier-time production-durable requester worker.
#[allow(
    dead_code,
    reason = "C03e-QV materializes the QU-selected dormant fallible requester lifecycle stop before separately gated scheduling-aware or higher-owner propagation"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop
{
    /// Caller-owned cancellation won at one selected cancellation-safe lifecycle boundary.
    Cancelled,
    /// Exact QT ingress or existing requester-response failure terminated the lifecycle.
    Failed(RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError),
}

/// Orthogonal terminal custody produced after one successful requester/rendezvous DR registration.
///
/// The scheduling channel owns the exact C03e-NS one-shot grant or exact derivation error by value.
/// The acknowledgement channel independently records the existing requester acknowledgement
/// composition/I/O disposition. This carrier is intentionally neither `Copy` nor `Clone`; it owns no
/// requester transaction, stream, channel, dispatcher, timing value, admission session ID, PRWM
/// request ID, endpoint, or reachability authority.
#[derive(Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NW materializes dormant scheduling-terminal caller custody before separately gated higher-owner propagation"
)]
pub(super) struct RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome {
    scheduling_result: Result<
        ExpectedDeviceSchedulingAuthorityGrant,
        ExpectedDeviceSchedulingAuthorityDerivationError,
    >,
    acknowledgement_result:
        Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
}

#[allow(
    dead_code,
    reason = "C03e-NW retains exact orthogonal scheduling and acknowledgement channels for a separately gated higher owner"
)]
impl RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome {
    const fn new(
        scheduling_result: Result<
            ExpectedDeviceSchedulingAuthorityGrant,
            ExpectedDeviceSchedulingAuthorityDerivationError,
        >,
        acknowledgement_result: Result<
            (),
            RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
        >,
    ) -> Self {
        Self {
            scheduling_result,
            acknowledgement_result,
        }
    }

    pub(super) const fn scheduling_result(
        &self,
    ) -> &Result<
        ExpectedDeviceSchedulingAuthorityGrant,
        ExpectedDeviceSchedulingAuthorityDerivationError,
    > {
        &self.scheduling_result
    }

    pub(super) const fn acknowledgement_result(
        &self,
    ) -> &Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError> {
        &self.acknowledgement_result
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        Result<
            ExpectedDeviceSchedulingAuthorityGrant,
            ExpectedDeviceSchedulingAuthorityDerivationError,
        >,
        Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
    ) {
        (self.scheduling_result, self.acknowledgement_result)
    }
}

/// Production-specific terminal result for the dormant scheduling-aware requester worker.
///
/// The historical requester worker stop remains unchanged and `Copy`/`Clone`. This distinct result
/// can instead own the non-Clone scheduling terminal carrier by value without retrofitting scheduling
/// semantics into historical callers.
#[derive(Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NW materializes the dormant production scheduling-aware worker stop before separately gated higher-owner propagation"
)]
pub(super) enum RequesterRendezvousProductionDurableSchedulingWorkerStop {
    /// Caller-owned cancellation won before any scheduling result existed.
    Cancelled,
    /// Existing ingress/requester-response lifecycle failed before any scheduling result existed.
    Failed(RequesterRendezvousPostTerminalResponseSerialLifecycleError),
    /// Requester/rendezvous DR succeeded and exact scheduling plus acknowledgement custody exists.
    SchedulingTerminal(RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome),
}

/// Production-specific terminal result for the QW-selected fallible scheduling-aware requester worker.
///
/// This distinct stop preserves the exact QV fallible lifecycle failure channel while reusing the
/// existing non-Clone scheduling terminal carrier by value. It introduces no scheduling error
/// flattening or alternate terminal custody representation.
#[derive(Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-QX materializes the QW-selected dormant fallible scheduling-aware requester worker before separately gated higher-owner propagation"
)]
pub(super) enum RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop {
    /// Caller-owned cancellation won before any scheduling result existed.
    Cancelled,
    /// Exact fallible ingress/requester-response lifecycle failed before scheduling custody existed.
    Failed(RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError),
    /// Requester/rendezvous DR succeeded and exact scheduling plus acknowledgement custody exists.
    SchedulingTerminal(RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome),
}

/// Consumes one exact retained DR continuation and completes exactly one terminal acknowledgement
/// response through the existing FD framing and FF same-stream send boundaries.
///
/// The continuation is borrowed only long enough for FD to project the exact already-completed DR
/// result and echo the exact original PRWM request correlation. A semantic DR `Err(_)` therefore
/// remains one valid generic rejected acknowledgement rather than becoming a composition failure.
/// After successful framing, the continuation is consumed by value and exact requester transaction
/// custody is transferred exactly once into FF. No result path returns retry-capable continuation,
/// transaction or raw-stream custody.
///
/// # Errors
///
/// Returns [`RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError::Frame`] if the
/// existing FD framing boundary fails. No response write is attempted on that path and the consumed
/// continuation is not returned for retry.
///
/// Returns [`RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError::ResponseIo`] if
/// the existing FF same-stream write/finish fails. FF consumes exact requester transaction custody;
/// no retry, resend, replacement stream or duplicate acknowledgement is attempted.
pub(super) async fn complete_requester_rendezvous_terminal_dr_acknowledgement_response(
    continuation: RequesterRendezvousRetainedCustodyDrContinuation,
) -> Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError> {
    let acknowledgement_frame = encode_requester_rendezvous_dr_result_for_transaction(
        continuation.requester_transaction(),
        continuation.dr_result(),
    )?;

    let (requester_transaction, _) = continuation.into_parts();
    requester_transaction
        .send_dr_acknowledgement_frame(&acknowledgement_frame)
        .await?;

    Ok(())
}

/// Consumes one exact EZ handoff and runs exactly one existing DR composition under current authority.
///
/// The exact EZ `RequesterRendezvousStartIntent` is consumed directly; this seam does not extract a
/// target-only `DeviceId` or call the C03e-DV convenience method that would reconstruct a second
/// start intent. The principal-agnostic capability policy yielded by current authority is ignored;
/// the supplied requester-aware policy source remains the sole DP requester policy source.
///
/// The bridge requester transaction remains outside the authority closure and therefore survives
/// unchanged on both DR success and failure. The current-authority read guard spans only the
/// synchronous DR call and is released before this function returns. No response I/O occurs here.
pub(super) async fn continue_requester_rendezvous_retained_custody_through_dr<
    P: PolicyEvaluator + Send + Sync,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
>(
    authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    handoff: RequesterRendezvousResponseStreamCustodyHandoff,
) -> RequesterRendezvousRetainedCustodyDrContinuation {
    let RequesterRendezvousResponseStreamCustodyHandoff {
        requester_transaction,
        start_intent,
    } = handoff;

    let dr_result = requester_rendezvous_authority
        .validate_authorize_and_register_requester_rendezvous_start(
            authority,
            policy_source,
            start_intent,
        )
        .await;

    RequesterRendezvousRetainedCustodyDrContinuation {
        requester_transaction,
        dr_result,
    }
}

/// Runs the isolated C03e-FI-selected requester-aware serial post-authenticated lifecycle.
///
/// The existing EV/EX mixed-family ingress remains the only stream-accept/read loop. It runs until
/// either the first ingress failure or one requester/rendezvous handoff. A requester handoff is
/// consumed exactly once by existing FB DR continuation and then exactly once by existing FH terminal
/// acknowledgement composition. Only FH success reaches the next EV/EX cycle. A successfully sent
/// generic rejected acknowledgement is therefore transaction-complete and also resumes serial
/// ingress. No EV/EX cycle overlaps requester DR/response custody.
///
/// This seam creates no second acceptor, task, channel, queue, retry, resend, replacement stream,
/// duplicate acknowledgement, automatic peer close, cancellation race, candidate/reachability
/// continuation, target dial, runtime/listener activation, deployment or merge behavior.
///
/// # Errors
///
/// Returns [`RequesterRendezvousPostTerminalResponseSerialLifecycleError::Ingress`] for the exact
/// first existing EV/EX ingress failure. Returns
/// [`RequesterRendezvousPostTerminalResponseSerialLifecycleError::RequesterResponse`] for the exact
/// existing FH `Frame` or `ResponseIo` failure. Either failure stops this serial lifecycle before
/// another EV/EX ingress cycle begins.
pub(super) async fn run_requester_rendezvous_post_terminal_response_serial_lifecycle<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> u64 + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
) -> Result<(), RequesterRendezvousPostTerminalResponseSerialLifecycleError> {
    loop {
        let handoff = session_owner
            .run_repeated_post_auth_control_stream_ingress(
                authority,
                &mut verifier_time_unix_seconds,
                dispatcher,
            )
            .await?;

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await?;
    }
}

/// Runs one cancellation-aware higher-owner worker over the existing requester-aware serial lifecycle.
///
/// Before requester handoff, the exact EX repeated-ingress future is polled first and caller
/// cancellation is polled second. Therefore an already-ready requester handoff or ingress failure
/// preserves the existing EX classification; cancellation wins only while ingress remains pending.
///
/// Once one requester handoff exists, cancellation is deliberately not polled while exact FB DR
/// continuation and exact FH terminal acknowledgement response composition run to one typed terminal
/// result. This prevents caller cancellation from becoming a new response-abandonment path after
/// requester authorization/registration may already have committed. Existing bounded transport
/// timeouts remain authoritative inside FH.
///
/// After FH success, cancellation is polled once before another EX cycle can begin. If cancellation
/// became ready during FB/FH, this worker returns `Cancelled` before the next verifier-time sample,
/// stream accept or frame receive. Otherwise the next serial EX cycle begins normally.
///
/// No path closes the authenticated peer, retries ingress/DR/response work, allocates a replacement
/// stream, duplicates an acknowledgement, widens capability close codes, starts a task/channel/queue,
/// selects candidate/reachability state, dials target traffic, activates a runtime/listener, deploys,
/// or merges anything.
pub(super) async fn run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> u64 + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    C: Future<Output = ()> + Send,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
    cancellation: C,
) -> RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop {
    let mut cancellation = Box::pin(cancellation);

    loop {
        let ingress_result: Result<
            Option<RequesterRendezvousResponseStreamCustodyHandoff>,
            AuthenticatedRemoteSessionPostAuthIngressTransactionError,
        > = {
            let mut ingress =
                Box::pin(session_owner.run_repeated_post_auth_control_stream_ingress(
                    authority,
                    &mut verifier_time_unix_seconds,
                    dispatcher,
                ));

            poll_fn(|context| {
                match ingress.as_mut().poll(context) {
                    Poll::Ready(Ok(handoff)) => return Poll::Ready(Ok(Some(handoff))),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }

                match cancellation.as_mut().poll(context) {
                    Poll::Ready(()) => Poll::Ready(Ok(None)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        };

        let handoff = match ingress_result {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
            }
            Err(error) => {
                return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                    error.into(),
                );
            }
        };

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        if let Err(error) =
            complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await
        {
            return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                error.into(),
            );
        }

        let cancellation_ready = poll_fn(|context| {
            Poll::Ready(matches!(
                cancellation.as_mut().poll(context),
                Poll::Ready(())
            ))
        })
        .await;

        if cancellation_ready {
            return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
        }
    }
}

/// Runs the KR-selected requester-aware serial lifecycle with distinct durable-capability and
/// requester-DR authority lanes.
///
/// Before requester handoff, the existing KQ durable cancellation worker owns the exact
/// ingress/cancellation race. The durable capability authority is passed only to that worker, while
/// the existing shared-current requester authority remains reserved for DR continuation after one
/// requester handoff. One pinned caller cancellation future is retained across every serial cycle;
/// each KQ invocation receives only a temporary polling adapter over that retained future.
///
/// Cancellation is deliberately not polled during requester DR or terminal acknowledgement response
/// composition. After one successful terminal response it is checked exactly once before another KQ
/// cycle can sample verifier time or accept another stream. No task, channel, queue, peer close,
/// requester retry, candidate continuation, runtime activation, deployment or merge behavior is
/// introduced here.
#[allow(
    dead_code,
    reason = "C03e-KS materializes the KR-selected dormant dual-authority FI worker before separately gated FQ/FU ownership propagation"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "KR keeps durable capability ingress authority and requester DR authority as explicit distinct inputs"
)]
pub(super) async fn run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> u64 + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    C: Future<Output = ()> + Send,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    capability_authority: &crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
    cancellation: C,
) -> RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop {
    let mut cancellation = Box::pin(cancellation);

    loop {
        let cancellation_adapter = poll_fn(|context| cancellation.as_mut().poll(context));
        let ingress_result = session_owner
            .run_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability(
                capability_authority,
                &mut verifier_time_unix_seconds,
                dispatcher,
                cancellation_adapter,
            )
            .await;

        let handoff = match ingress_result {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
            }
            Err(error) => {
                return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                    error.into(),
                );
            }
        };

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            requester_dr_authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        if let Err(error) =
            complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await
        {
            return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                error.into(),
            );
        }

        let cancellation_ready = poll_fn(|context| {
            Poll::Ready(matches!(
                cancellation.as_mut().poll(context),
                Poll::Ready(())
            ))
        })
        .await;

        if cancellation_ready {
            return RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
        }
    }
}

/// Runs the QU-selected requester-aware serial lifecycle with fallible verifier-time production-durable
/// ingress while preserving the existing requester DR and terminal-response custody law.
///
/// Before requester handoff, the exact QT fallible durable cancellation worker owns verifier-time
/// acquisition plus the ingress/cancellation race. One pinned caller cancellation future is retained
/// across every serial cycle; each QT invocation receives only a temporary polling adapter over that
/// retained future and a mutable reborrow of the caller-owned fallible verifier-time source.
///
/// Once one requester handoff exists, cancellation is deliberately not polled while exact existing DR
/// continuation and terminal acknowledgement response composition run. After response success,
/// cancellation is polled exactly once before another QT cycle may sample verifier time or accept a
/// stream. Exact QT verifier-time/ingress failures and exact requester-response failures remain typed
/// under distinct lifecycle channels.
///
/// This sibling samples no verifier time directly, accepts/reads no stream directly, creates no task,
/// channel, queue, retry, fallback/default time, peer close, scheduling derivation, runtime activation,
/// deployment or merge behavior.
#[allow(
    dead_code,
    reason = "C03e-QV materializes the QU-selected dormant fallible verifier-time requester lifecycle before separately gated scheduling-aware or higher-owner propagation"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "QU preserves distinct durable ingress and requester DR authority lanes as explicit inputs"
)]
pub(super) async fn run_fallible_verifier_time_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError> + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    C: Future<Output = ()> + Send,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    capability_authority: &crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
    cancellation: C,
) -> RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop {
    let mut cancellation = Box::pin(cancellation);

    loop {
        let cancellation_adapter = poll_fn(|context| cancellation.as_mut().poll(context));
        let ingress_result = session_owner
            .run_fallible_verifier_time_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability(
                capability_authority,
                &mut verifier_time_unix_seconds,
                dispatcher,
                cancellation_adapter,
            )
            .await;

        let handoff = match ingress_result {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                return RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
            }
            Err(error) => {
                return RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop::Failed(
                    error.into(),
                );
            }
        };

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            requester_dr_authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        if let Err(error) =
            complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await
        {
            return RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop::Failed(
                error.into(),
            );
        }

        let cancellation_ready = poll_fn(|context| {
            Poll::Ready(matches!(
                cancellation.as_mut().poll(context),
                Poll::Ready(())
            ))
        })
        .await;

        if cancellation_ready {
            return RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleWorkerStop::Cancelled;
        }
    }
}

/// Runs the NV-selected dormant production-durable requester lifecycle that may derive exactly one
/// expected-device scheduling authority after successful requester/rendezvous DR registration.
///
/// This sibling deliberately leaves the existing production-durable worker above unchanged. Before
/// requester handoff it reuses the exact durable ingress/cancellation race. After handoff it preserves
/// requester `SessionId` and target `DeviceId` only as non-authorizing operation selectors, runs the
/// exact existing DR continuation once, and branches on the already-completed DR result.
///
/// A DR failure never invokes scheduling derivation: the existing rejected acknowledgement is
/// completed exactly as today, then the historical post-ack cancellation/next-ingress behavior is
/// preserved. A DR success invokes the existing C03e-NS scheduling derivation exactly once before
/// acknowledgement framing/I/O, retains the grant or typed derivation error by value, attempts the
/// unchanged requester acknowledgement exactly once, and returns both terminal channels upward
/// before any cancellation poll or next ingress cycle.
///
/// This seam constructs no expected-device admission request, sender, channel, admission `SessionId`,
/// PRWM request ID or timing value, and performs no peer close, higher-owner migration, runtime
/// activation, retry/remint, deployment or merge.
#[allow(
    dead_code,
    reason = "C03e-NW materializes the NV-selected dormant scheduling-aware sibling before separately gated higher-owner propagation"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "C03e-NW preserves distinct durable ingress, requester DR and scheduling-derivation authority inputs without introducing an aggregate"
)]
pub(super) async fn run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> u64 + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    C: Future<Output = ()> + Send,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    capability_authority: &crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
    cancellation: C,
) -> RequesterRendezvousProductionDurableSchedulingWorkerStop {
    let mut cancellation = Box::pin(cancellation);

    loop {
        let cancellation_adapter = poll_fn(|context| cancellation.as_mut().poll(context));
        let ingress_result = session_owner
            .run_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability(
                capability_authority,
                &mut verifier_time_unix_seconds,
                dispatcher,
                cancellation_adapter,
            )
            .await;

        let handoff = match ingress_result {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                return RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled;
            }
            Err(error) => {
                return RequesterRendezvousProductionDurableSchedulingWorkerStop::Failed(
                    error.into(),
                );
            }
        };

        let requester_session_id = handoff
            .start_intent
            .requester_session()
            .session_id()
            .clone();
        let target_device_id = handoff.start_intent.target_device_id().clone();

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            requester_dr_authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        if continuation.dr_result().is_err() {
            if let Err(error) =
                complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation)
                    .await
            {
                return RequesterRendezvousProductionDurableSchedulingWorkerStop::Failed(
                    error.into(),
                );
            }

            let cancellation_ready = poll_fn(|context| {
                Poll::Ready(matches!(
                    cancellation.as_mut().poll(context),
                    Poll::Ready(())
                ))
            })
            .await;

            if cancellation_ready {
                return RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled;
            }

            continue;
        }

        let scheduling_result = requester_rendezvous_authority
            .derive_expected_device_scheduling_authority(
                requester_dr_authority,
                policy_source,
                &requester_session_id,
                &target_device_id,
            )
            .await;

        let acknowledgement_result =
            complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await;

        return RequesterRendezvousProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome::new(
                scheduling_result,
                acknowledgement_result,
            ),
        );
    }
}

/// Runs the QW-selected scheduling-aware requester lifecycle with fallible verifier-time
/// production-durable ingress while preserving the existing scheduling terminal custody law.
///
/// Before requester handoff, the exact QT fallible durable cancellation worker owns verifier-time
/// acquisition and the ingress/cancellation race. After handoff, this sibling retains only the same
/// requester `SessionId` and target `DeviceId` operation selectors used by the historical scheduling
/// sibling, runs exact existing DR continuation once, and branches on the completed DR result.
///
/// A DR failure never invokes scheduling derivation: the rejected acknowledgement is completed once,
/// then retained cancellation is checked exactly once before another QT cycle. A DR success invokes
/// existing scheduling derivation exactly once before acknowledgement framing/I/O, retains the exact
/// grant or typed derivation error by value, completes acknowledgement once, and returns the existing
/// orthogonal scheduling/acknowledgement terminal carrier immediately.
///
/// This sibling samples no verifier time directly, accepts/reads no stream directly, constructs no
/// admission request, sender, channel, admission `SessionId`, PRWM request ID or timing value, and
/// performs no peer close, retry, fallback/default time, higher-owner migration, runtime activation,
/// deployment or merge behavior.
#[allow(
    dead_code,
    reason = "C03e-QX materializes the QW-selected dormant fallible scheduling-aware requester sibling before separately gated higher-owner propagation"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "QW preserves distinct durable ingress, requester DR and scheduling-derivation authority inputs without introducing an aggregate"
)]
pub(super) async fn run_fallible_verifier_time_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling<
    P: PolicyEvaluator + Send + Sync,
    D: CapabilityDispatcher + Send,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError> + Send,
    S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    C: Future<Output = ()> + Send,
>(
    session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
    capability_authority: &crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &S,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
    mut verifier_time_unix_seconds: T,
    dispatcher: &mut D,
    cancellation: C,
) -> RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop {
    let mut cancellation = Box::pin(cancellation);

    loop {
        let cancellation_adapter = poll_fn(|context| cancellation.as_mut().poll(context));
        let ingress_result = session_owner
            .run_fallible_verifier_time_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability(
                capability_authority,
                &mut verifier_time_unix_seconds,
                dispatcher,
                cancellation_adapter,
            )
            .await;

        let handoff = match ingress_result {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                return RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Cancelled;
            }
            Err(error) => {
                return RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                    error.into(),
                );
            }
        };

        let requester_session_id = handoff
            .start_intent
            .requester_session()
            .session_id()
            .clone();
        let target_device_id = handoff.start_intent.target_device_id().clone();

        let continuation = continue_requester_rendezvous_retained_custody_through_dr(
            requester_dr_authority,
            policy_source,
            requester_rendezvous_authority,
            handoff,
        )
        .await;

        if continuation.dr_result().is_err() {
            if let Err(error) =
                complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation)
                    .await
            {
                return RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                    error.into(),
                );
            }

            let cancellation_ready = poll_fn(|context| {
                Poll::Ready(matches!(
                    cancellation.as_mut().poll(context),
                    Poll::Ready(())
                ))
            })
            .await;

            if cancellation_ready {
                return RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Cancelled;
            }

            continue;
        }

        let scheduling_result = requester_rendezvous_authority
            .derive_expected_device_scheduling_authority(
                requester_dr_authority,
                policy_source,
                &requester_session_id,
                &target_device_id,
            )
            .await;

        let acknowledgement_result =
            complete_requester_rendezvous_terminal_dr_acknowledgement_response(continuation).await;

        return RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome::new(
                scheduling_result,
                acknowledgement_result,
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use prw_remote_bridge::{
        post_auth_control_stream_ingress::RequesterRendezvousDrAcknowledgementResponseIoError,
        requester_rendezvous_dr_acknowledgement_wire::RequesterRendezvousDrAcknowledgementWireError,
    };

    use super::{
        RequesterRendezvousPostTerminalResponseSerialLifecycleError,
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome,
        RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
        complete_requester_rendezvous_terminal_dr_acknowledgement_response,
    };
    use crate::remote_session_capability_runtime::{
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
        shared_requester_rendezvous_authority::ExpectedDeviceSchedulingAuthorityDerivationError,
    };

    fn assert_frame_error_conversion(
        conversion: fn(
            RequesterRendezvousDrAcknowledgementWireError,
        )
            -> RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
    ) {
        let _ = conversion;
    }

    fn assert_response_io_error_conversion(
        conversion: fn(
            RequesterRendezvousDrAcknowledgementResponseIoError,
        )
            -> RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
    ) {
        let _ = conversion;
    }

    fn assert_ingress_lifecycle_error_conversion(
        conversion: fn(
            AuthenticatedRemoteSessionPostAuthIngressTransactionError,
        ) -> RequesterRendezvousPostTerminalResponseSerialLifecycleError,
    ) {
        let _ = conversion;
    }

    fn assert_requester_response_lifecycle_error_conversion(
        conversion: fn(
            RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
        ) -> RequesterRendezvousPostTerminalResponseSerialLifecycleError,
    ) {
        let _ = conversion;
    }

    #[test]
    fn terminal_dr_acknowledgement_response_composition_surface_is_materialized() {
        let _ = complete_requester_rendezvous_terminal_dr_acknowledgement_response;
    }

    #[test]
    fn terminal_response_error_family_preserves_exact_two_lower_categories() {
        assert_frame_error_conversion(
            RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError::from,
        );
        assert_response_io_error_conversion(
            RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError::from,
        );
    }

    #[test]
    fn serial_lifecycle_error_family_preserves_ingress_and_requester_response_categories() {
        assert_ingress_lifecycle_error_conversion(
            RequesterRendezvousPostTerminalResponseSerialLifecycleError::from,
        );
        assert_requester_response_lifecycle_error_conversion(
            RequesterRendezvousPostTerminalResponseSerialLifecycleError::from,
        );
    }

    #[test]
    fn cancellation_aware_worker_stop_exposes_local_cancelled_class() {
        assert_eq!(
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled,
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled
        );
    }

    #[test]
    fn scheduling_terminal_custody_preserves_derivation_and_acknowledgement_channels() {
        let outcome = RequesterRendezvousSchedulingAuthorityCallerTerminalOutcome::new(
            Err(ExpectedDeviceSchedulingAuthorityDerivationError::AlreadyConsumed),
            Ok(()),
        );

        assert_eq!(
            outcome.scheduling_result(),
            &Err(ExpectedDeviceSchedulingAuthorityDerivationError::AlreadyConsumed)
        );
        assert_eq!(outcome.acknowledgement_result(), &Ok(()));

        let (scheduling_result, acknowledgement_result) = outcome.into_parts();
        assert_eq!(
            scheduling_result,
            Err(ExpectedDeviceSchedulingAuthorityDerivationError::AlreadyConsumed)
        );
        assert_eq!(acknowledgement_result, Ok(()));
    }

    #[test]
    fn scheduling_worker_stop_keeps_pre_derivation_cancellation_distinct() {
        assert_eq!(
            RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled,
            RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled
        );
    }
}
