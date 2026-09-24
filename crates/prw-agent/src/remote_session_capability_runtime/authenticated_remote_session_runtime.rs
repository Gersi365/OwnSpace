//! Agent-owned lifetime boundary for one connected authenticated remote application session.
//!
//! C03e-I selected this outer ownership shape. C03e-K materializes the by-value owner that retains
//! the already-authenticated live peer together with the C03e-J capability owner. C03e-L adds the
//! post-authentication binding/composition transaction, C03e-O adds exactly one serialized
//! capability request transaction over the C03e-N bridge-owned wire adapter, C03e-Q adds the
//! C03e-P-selected borrowed serial request loop, and C03e-S adds the C03e-R-selected executor-neutral
//! cancellation-aware single-worker seam. C03e-KG adds only one dormant production durable
//! capability transaction composition over an already-read same-stream capability transaction. It
//! does not spawn tasks, publish readiness, retry/reconnect, or wire the Agent binary.

use std::{
    fmt,
    future::{Future, poll_fn},
    ops::Range,
    task::Poll,
};

use prw_core::DeviceId;
use prw_policy::PolicyEvaluator;
use prw_remote_bridge::{
    CapabilityBridge, CapabilityDispatcher, DurableCapabilityBridgeError, RemoteBridgeError,
    authorized_request_dispatch::dispatch_authorized_request,
    capability_request_wire::{
        CapabilityRequestWireError, receive_capability_request_frame,
        send_capability_response_frame,
    },
    post_auth_control_stream_ingress::PostAuthCapabilityTransaction,
    remote_server_transport_runtime::{
        AuthenticatedRemotePeerConnection, RemoteServerTransportRuntimeError,
    },
    remote_session_binding::BoundRemoteSession,
};
use prw_session::AuthenticatedDeviceSession;
use prw_session::prwa_verifier_source::PrwaVerifierSourceError;

use super::{RemoteSessionCapabilityRuntimeOwner, SharedCurrentCapabilityAuthority};
use crate::{
    candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner,
    candidate_publication_requester_rendezvous_start_intent::{
        RequesterRendezvousStartIntent, RequesterRendezvousTargetIntent,
        composition::{
            RequesterRendezvousStartCompositionError,
            validate_authorize_and_register_requester_rendezvous_start,
        },
        policy_source::RequesterRendezvousStartPolicySource,
    },
    production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
};

#[allow(
    dead_code,
    reason = "C03e-L stages the binding composition seam before separately gated operation-surface exposure"
)]
const REMOTE_SESSION_BINDING_FAILURE_CLOSE_CODE: u32 = 2;
#[allow(
    dead_code,
    reason = "C03e-L stages the binding composition seam before separately gated operation-surface exposure"
)]
const REMOTE_SESSION_BINDING_FAILURE_CLOSE_REASON: &[u8] = b"remote session binding failed";

/// Closes one already-authenticated peer with the existing binding-stage failure diagnostic.
///
/// This helper owns no error construction, pending-session abort, authenticated-session deletion,
/// retry, lease construction, timing acquisition, policy selection or runtime activation.
pub(super) fn close_authenticated_remote_session_binding_failure(
    peer: &AuthenticatedRemotePeerConnection,
) {
    peer.close(
        REMOTE_SESSION_BINDING_FAILURE_CLOSE_CODE,
        REMOTE_SESSION_BINDING_FAILURE_CLOSE_REASON,
    );
}

const REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE: u32 = 3;
const REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON: &[u8] =
    b"remote capability session terminated";
const REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE: u32 = 4;
const REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON: &[u8] =
    b"remote capability session shutdown";

/// Failure while processing exactly one capability request on one authenticated remote session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedRemoteSessionCapabilityTransactionError {
    /// Accepting the next bounded control stream from the retained authenticated peer failed.
    Accept(RemoteServerTransportRuntimeError),
    /// Receiving or sending the one bounded PRWM frame failed.
    Wire(CapabilityRequestWireError),
    /// Current bound-session authorization or capability dispatch failed.
    Bridge(RemoteBridgeError),
}

impl fmt::Display for AuthenticatedRemoteSessionCapabilityTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(_) => formatter.write_str("remote capability stream acceptance failed"),
            Self::Wire(_) => formatter.write_str("remote capability wire transaction failed"),
            Self::Bridge(_) => formatter.write_str("remote capability bridge transaction failed"),
        }
    }
}

impl std::error::Error for AuthenticatedRemoteSessionCapabilityTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Bridge(error) => Some(error),
        }
    }
}

impl From<RemoteServerTransportRuntimeError>
    for AuthenticatedRemoteSessionCapabilityTransactionError
{
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Accept(error)
    }
}

impl From<CapabilityRequestWireError> for AuthenticatedRemoteSessionCapabilityTransactionError {
    fn from(error: CapabilityRequestWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<RemoteBridgeError> for AuthenticatedRemoteSessionCapabilityTransactionError {
    fn from(error: RemoteBridgeError) -> Self {
        Self::Bridge(error)
    }
}

/// Bounded terminal failure for the dormant fallible verifier-time capability-session loop.
#[allow(
    dead_code,
    reason = "C03e-PB materializes the PA-selected fallible verifier-time loop before separately gated caller migration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError {
    /// Acquiring verifier time from the existing PRWA source failed.
    VerifierTime(PrwaVerifierSourceError),
    /// The existing one-request capability transaction failed.
    Transaction(AuthenticatedRemoteSessionCapabilityTransactionError),
}

impl fmt::Display for AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VerifierTime(_) => "remote capability verifier time acquisition failed",
            Self::Transaction(_) => "remote capability request transaction failed",
        })
    }
}

impl std::error::Error for AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::VerifierTime(error) => Some(error),
            Self::Transaction(error) => Some(error),
        }
    }
}

impl From<PrwaVerifierSourceError>
    for AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError
{
    fn from(error: PrwaVerifierSourceError) -> Self {
        Self::VerifierTime(error)
    }
}

impl From<AuthenticatedRemoteSessionCapabilityTransactionError>
    for AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError
{
    fn from(error: AuthenticatedRemoteSessionCapabilityTransactionError) -> Self {
        Self::Transaction(error)
    }
}

/// Bounded failure while composing one already-read capability transaction through production
/// durable authority, dispatch and exact same-stream response custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductionDurableCapabilityTransactionError {
    /// Current durable capability authorization failed.
    Authority(DurableCapabilityBridgeError),
    /// Dispatch of the successfully authorized request failed.
    Dispatch(RemoteBridgeError),
    /// Sending the already-constructed response on the retained stream failed.
    Response(CapabilityRequestWireError),
}

impl fmt::Display for ProductionDurableCapabilityTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authority(_) => "production durable capability authorization failed",
            Self::Dispatch(_) => "production durable capability dispatch failed",
            Self::Response(_) => "production durable capability response transmission failed",
        })
    }
}

impl std::error::Error for ProductionDurableCapabilityTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Dispatch(error) => Some(error),
            Self::Response(error) => Some(error),
        }
    }
}

impl From<DurableCapabilityBridgeError> for ProductionDurableCapabilityTransactionError {
    fn from(error: DurableCapabilityBridgeError) -> Self {
        Self::Authority(error)
    }
}

impl From<RemoteBridgeError> for ProductionDurableCapabilityTransactionError {
    fn from(error: RemoteBridgeError) -> Self {
        Self::Dispatch(error)
    }
}

impl From<CapabilityRequestWireError> for ProductionDurableCapabilityTransactionError {
    fn from(error: CapabilityRequestWireError) -> Self {
        Self::Response(error)
    }
}

/// Terminal result of the executor-neutral C03e-S single-worker seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedRemoteSessionWorkerStop {
    /// External worker cancellation won and the retained peer was closed with the code-4 diagnostic.
    Cancelled,
    /// The existing C03e-Q loop failed first and preserved its original typed transaction failure.
    Failed(AuthenticatedRemoteSessionCapabilityTransactionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedRemoteSessionWorkerRaceOutcome {
    Cancelled,
    Failed(AuthenticatedRemoteSessionCapabilityTransactionError),
}

/// Terminal result for the dormant fallible verifier-time cancellation-aware worker.
#[allow(
    dead_code,
    reason = "C03e-PD materializes the PC-selected fallible worker before separately gated executor migration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop {
    /// Caller-owned cancellation won while the fallible request loop remained pending.
    Cancelled,
    /// The PB request loop failed first and its exact typed error is preserved unchanged.
    Failed(AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError),
}

async fn await_fallible_capability_request_worker_stop<L, C>(
    request_loop: L,
    cancellation: C,
) -> AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop
where
    L: Future<Output = Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError>>
        + Send,
    C: Future<Output = ()> + Send,
{
    let mut request_loop = Box::pin(request_loop);
    let mut cancellation = Box::pin(cancellation);
    let mut request_loop_completed_cleanly = false;

    poll_fn(|context| {
        if !request_loop_completed_cleanly {
            match request_loop.as_mut().poll(context) {
                Poll::Ready(Ok(())) => request_loop_completed_cleanly = true,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(
                        AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(error),
                    );
                }
                Poll::Pending => {}
            }
        }

        match cancellation.as_mut().poll(context) {
            Poll::Ready(()) => {
                Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled)
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// Retains one authenticated peer and its bound capability lifetime under one Agent owner.
pub struct AuthenticatedRemoteSessionRuntimeOwner {
    peer: AuthenticatedRemotePeerConnection,
    capability_owner: RemoteSessionCapabilityRuntimeOwner,
}

impl AuthenticatedRemoteSessionRuntimeOwner {
    /// Composes ownership only; construction performs no I/O or authorization.
    #[must_use]
    pub const fn new(
        peer: AuthenticatedRemotePeerConnection,
        capability_owner: RemoteSessionCapabilityRuntimeOwner,
    ) -> Self {
        Self {
            peer,
            capability_owner,
        }
    }

    /// Returns the authenticated logical `DeviceId` retained by this runtime owner.
    ///
    /// This Agent-internal accessor derives identity only from the already-bound authenticated
    /// session. It performs no I/O, registry lookup, policy evaluation or transport selection.
    #[must_use]
    pub(super) const fn logical_device_id(&self) -> &DeviceId {
        self.capability_owner.bound_session.session().device_id()
    }

    /// Constructs one non-authoritative requester/rendezvous start intent from this authenticated
    /// remote-session owner and one caller-nominated logical target `DeviceId`.
    ///
    /// Requester identity is derived only from the exact authenticated application session retained
    /// by the existing `BoundRemoteSession`. The session clone is owned-custody adaptation for the
    /// existing intent type only; it performs no authentication, registry validation, policy
    /// evaluation, provider mutation, I/O, synchronization, runtime activation or networking.
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-DT materializes authenticated-session start-intent construction before separately gated caller activation"
    )]
    pub(crate) fn requester_rendezvous_start_intent(
        &self,
        target_device_id: DeviceId,
    ) -> RequesterRendezvousStartIntent {
        RequesterRendezvousStartIntent::new(
            self.capability_owner.bound_session.session().clone(),
            target_device_id,
        )
    }

    /// Adapts one typed caller-nominated rendezvous target into the existing authenticated-session
    /// requester/rendezvous start-intent construction boundary.
    ///
    /// The logical target comes only from the consumed `RequesterRendezvousTargetIntent`; requester
    /// identity continues to come only from this owner's retained authenticated application session
    /// through the existing C03e-DT helper. This adaptation performs no registry lookup, policy
    /// evaluation, provider mutation, I/O, synchronization, wire handling, or runtime activation.
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-EH materializes typed target-intent authenticated-session adaptation before separately gated caller activation"
    )]
    pub(crate) fn requester_rendezvous_start_intent_from_target_intent(
        &self,
        target_intent: RequesterRendezvousTargetIntent,
    ) -> RequesterRendezvousStartIntent {
        self.requester_rendezvous_start_intent(target_intent.into_target_device_id())
    }

    /// Validates and registers one requester/rendezvous start through current registry authority.
    ///
    /// The requester is derived only through the existing authenticated-session start-intent helper.
    /// Current registry authority is borrowed only through one existing
    /// [`SharedCurrentCapabilityAuthority::with_current_authority`] read. The principal-agnostic
    /// capability policy yielded by that owner is deliberately ignored for requester/rendezvous
    /// policy; the separately supplied requester-aware source remains the sole DP policy source.
    ///
    /// The shared-current read guard spans only one synchronous DR composition call. This method
    /// performs no network I/O, dispatcher execution, cancellation wait, task lifecycle work,
    /// blocking storage operation or external process interaction while that guard is held.
    ///
    /// # Errors
    ///
    /// Returns the existing [`RequesterRendezvousStartCompositionError`] unchanged. No retry,
    /// fallback, replacement, suppression, translation or fabricated success is performed.
    #[allow(
        dead_code,
        reason = "C03e-DV materializes authenticated-session current-authority caller composition before separately gated runtime activation"
    )]
    pub(crate) async fn register_requester_rendezvous_start<
        P: PolicyEvaluator + Send + Sync,
        S: RequesterRendezvousStartPolicySource + Sync + ?Sized,
    >(
        &self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: &S,
        runtime_owner: &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
        target_device_id: DeviceId,
    ) -> Result<(), RequesterRendezvousStartCompositionError> {
        let intent = self.requester_rendezvous_start_intent(target_device_id);
        authority
            .with_current_authority(|registry, _current_capability_policy| {
                validate_authorize_and_register_requester_rendezvous_start(
                    registry,
                    policy_source,
                    runtime_owner,
                    intent,
                )
            })
            .await
    }

    /// Processes one already-read same-stream capability transaction through production durable
    /// authority, dispatch and response composition.
    ///
    /// Presented transport evidence and the authenticated lease are sourced only from the exact
    /// retained [`BoundRemoteSession`]. The caller supplies verifier time, a dispatcher, the dormant
    /// production durable authority, and ownership of one already-read [`PostAuthCapabilityTransaction`].
    /// No stream is accepted and no second frame is read.
    ///
    /// Durable authorization completes before dispatch begins. The existing durable-authority method
    /// releases its registry mutex before it returns, so neither dispatcher execution nor response
    /// I/O occurs while durable-registry custody is locked. Only successful authorization reaches
    /// dispatch, and only successful dispatch consumes the exact transaction to send one response on
    /// the retained stream.
    ///
    /// # Errors
    ///
    /// Preserves durable-authority, dispatch and same-stream response failures under the exact bounded
    /// [`ProductionDurableCapabilityTransactionError`] stage. No retry, fallback, alternate stream,
    /// fabricated negative response, degraded authority or whole-peer close is performed.
    #[allow(
        dead_code,
        reason = "C03e-KG materializes the KF-selected durable post-auth transaction seam before separately gated runtime caller migration"
    )]
    pub(crate) async fn process_production_durable_capability_transaction<
        D: CapabilityDispatcher + Send,
    >(
        &self,
        authority: &ProductionDurableCapabilityAuthority,
        now_unix_seconds: u64,
        dispatcher: &mut D,
        transaction: PostAuthCapabilityTransaction,
    ) -> Result<(), ProductionDurableCapabilityTransactionError> {
        let bound_session = &self.capability_owner.bound_session;
        let authorized = authority
            .authorize_capability_transaction(
                bound_session.transport_identity(),
                bound_session.lease(),
                now_unix_seconds,
                &transaction,
            )
            .await?;
        let response = dispatch_authorized_request(&authorized, dispatcher)?;
        transaction.send_response_frame(&response).await?;
        Ok(())
    }

    /// Processes exactly one capability request on exactly one newly accepted control stream.
    ///
    /// The mutable owner borrow deliberately serializes this operation boundary. The retained peer
    /// accepts one stream, the C03e-N adapter receives one bounded PRWM frame, and the retained
    /// bound session delegates exactly once to the current [`CapabilityBridge`] using caller-supplied
    /// verifier time and mutable dispatcher. Only bridge success is sent as one response frame on
    /// the same stream.
    ///
    /// No transport identity, logical identity, lease, registry result or policy result is selected
    /// by this method. The retained [`BoundRemoteSession`] continues to supply its bound transport
    /// identity and lease internally, while the bridge performs current registry/policy validation.
    ///
    /// # Errors
    ///
    /// Returns the existing bounded stream-accept failure, C03e-N wire failure or existing
    /// [`RemoteBridgeError`] through [`AuthenticatedRemoteSessionCapabilityTransactionError`].
    /// Failure produces no fabricated success response, retry, replacement stream/session/lease,
    /// pending-session abort, authenticated-session deletion or automatic whole-peer close.
    pub async fn process_one_capability_request<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        now_unix_seconds: u64,
        dispatcher: &mut D,
    ) -> Result<(), AuthenticatedRemoteSessionCapabilityTransactionError> {
        let mut stream = self.peer.accept_control_stream().await?;
        let request = receive_capability_request_frame(&mut stream).await?;
        let bound_session = &self.capability_owner.bound_session;
        let authorized = authority
            .with_current_authority(|registry, policy| {
                let bridge = CapabilityBridge::new(registry, policy);
                bound_session.authorize(&bridge, now_unix_seconds, &request)
            })
            .await?;
        let response = dispatch_authorized_request(&authorized, dispatcher)?;
        send_capability_response_frame(&mut stream, &response).await?;
        Ok(())
    }

    /// Runs the C03e-P-selected serial capability-session request loop.
    ///
    /// The verifier-time provider is sampled exactly once immediately before each existing C03e-O
    /// transaction. Only a successful transaction reaches the next iteration. The first transaction
    /// failure closes the same retained peer exactly once with the fixed capability-session
    /// termination diagnostic and returns that original typed failure unchanged.
    ///
    /// This borrowed loop owns no task, cancellation token, drain deadline, join handle, retry,
    /// replacement session, concurrent request admission or readiness state.
    ///
    /// # Errors
    ///
    /// Returns the first [`AuthenticatedRemoteSessionCapabilityTransactionError`] emitted by the
    /// existing one-request transaction after explicitly closing the retained peer.
    pub async fn run_capability_request_loop<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        mut verifier_time_unix_seconds: T,
        dispatcher: &mut D,
    ) -> Result<(), AuthenticatedRemoteSessionCapabilityTransactionError> {
        loop {
            let now_unix_seconds = verifier_time_unix_seconds();
            if let Err(error) = self
                .process_one_capability_request(authority, now_unix_seconds, dispatcher)
                .await
            {
                self.peer.close(
                    REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE,
                    REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON,
                );
                return Err(error);
            }
        }
    }

    /// Runs the PA-selected dormant capability-session loop with fallible verifier-time acquisition.
    ///
    /// The verifier-time provider is sampled exactly once immediately before each attempted existing
    /// one-request capability transaction. A successful sample is forwarded unchanged. A verifier-time
    /// source failure performs no transaction attempt, closes the retained peer exactly once with the
    /// existing capability-session termination diagnostic, and returns the exact source error under
    /// the bounded loop error. Existing transaction failure preserves the same close discipline and
    /// exact transaction error. No retry, second sample, fallback, cache, saturation, clamping,
    /// replacement session or alternate source is introduced.
    ///
    /// # Errors
    ///
    /// Returns either the exact [`PrwaVerifierSourceError`] or the exact existing
    /// [`AuthenticatedRemoteSessionCapabilityTransactionError`] under the bounded sibling-loop error.
    #[allow(
        dead_code,
        reason = "C03e-PB materializes the PA-selected dormant fallible verifier-time loop before separately gated caller migration"
    )]
    pub(super) async fn run_fallible_verifier_time_capability_request_loop<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> Result<u64, PrwaVerifierSourceError> + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        mut verifier_time_unix_seconds: T,
        dispatcher: &mut D,
    ) -> Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError> {
        loop {
            let now_unix_seconds = match verifier_time_unix_seconds() {
                Ok(now_unix_seconds) => now_unix_seconds,
                Err(error) => {
                    self.peer.close(
                        REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE,
                        REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON,
                    );
                    return Err(error.into());
                }
            };

            if let Err(error) = self
                .process_one_capability_request(authority, now_unix_seconds, dispatcher)
                .await
            {
                self.peer.close(
                    REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE,
                    REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON,
                );
                return Err(error.into());
            }
        }
    }

    /// Runs one cancellation-aware remote-session worker body without spawning a task.
    ///
    /// The caller supplies an executor-neutral cancellation future. This method polls the existing
    /// C03e-Q loop before cancellation on each wake, so an already-ready terminal Q failure retains
    /// its original code-3 close/error classification. Cancellation wins only while Q remains
    /// pending. When cancellation wins, the in-flight Q future is dropped first; after that mutable
    /// owner borrow is released, this method closes the same retained peer exactly once with the
    /// fixed code-4 shutdown diagnostic and returns [`AuthenticatedRemoteSessionWorkerStop::Cancelled`].
    ///
    /// A clean `Ok(())` return from the current Q loop is not a selected lifecycle completion. If a
    /// future Q implementation ever produces it, this seam stops polling that completed loop and
    /// remains pending solely on the caller-owned cancellation future rather than fabricating a
    /// success or failure classification.
    ///
    /// This method creates no channel, task, runtime, join handle, registry entry, retry or readiness
    /// state and does not expose the retained peer.
    pub async fn run_capability_request_worker<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> AuthenticatedRemoteSessionWorkerStop {
        let outcome = {
            let mut request_loop = Box::pin(self.run_capability_request_loop(
                authority,
                verifier_time_unix_seconds,
                dispatcher,
            ));
            let mut cancellation = Box::pin(cancellation);
            let mut request_loop_completed_cleanly = false;

            poll_fn(|context| {
                if !request_loop_completed_cleanly {
                    match request_loop.as_mut().poll(context) {
                        Poll::Ready(Ok(())) => request_loop_completed_cleanly = true,
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(
                                AuthenticatedRemoteSessionWorkerRaceOutcome::Failed(error),
                            );
                        }
                        Poll::Pending => {}
                    }
                }

                match cancellation.as_mut().poll(context) {
                    Poll::Ready(()) => {
                        Poll::Ready(AuthenticatedRemoteSessionWorkerRaceOutcome::Cancelled)
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        };

        match outcome {
            AuthenticatedRemoteSessionWorkerRaceOutcome::Cancelled => {
                self.peer.close(
                    REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE,
                    REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
                );
                AuthenticatedRemoteSessionWorkerStop::Cancelled
            }
            AuthenticatedRemoteSessionWorkerRaceOutcome::Failed(error) => {
                AuthenticatedRemoteSessionWorkerStop::Failed(error)
            }
        }
    }
}

impl AuthenticatedRemoteSessionRuntimeOwner {
    /// Runs the PC-selected dormant cancellation-aware worker around the existing PB fallible loop.
    ///
    /// The existing PB loop is constructed exactly once and owns all verifier-time sampling and
    /// capability-transaction failure closure. The race helper polls that loop before cancellation on
    /// every wake. A PB failure is returned unchanged without an additional close. Cancellation can
    /// win only while the PB loop is pending (or after its defensive clean-return latch), and the
    /// actual request-loop storage is destroyed before this method reuses peer custody to apply the
    /// existing code-4 shutdown close exactly once.
    ///
    /// This method creates no task, runtime, cancellation source, retry, replacement session, time
    /// source, dispatcher, request carrier, readiness state or production caller activation.
    #[allow(
        dead_code,
        reason = "C03e-PD materializes the PC-selected fallible worker before separately gated executor migration"
    )]
    pub(super) async fn run_fallible_verifier_time_capability_request_worker<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> Result<u64, PrwaVerifierSourceError> + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop {
        let stop = {
            let request_loop = self.run_fallible_verifier_time_capability_request_loop(
                authority,
                verifier_time_unix_seconds,
                dispatcher,
            );
            await_fallible_capability_request_worker_stop(request_loop, cancellation).await
        };

        match stop {
            AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled => {
                self.peer.close(
                    REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE,
                    REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
                );
                AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled
            }
            AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(error) => {
                AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(error)
            }
        }
    }
}

/// Binds one already-authenticated logical session to its same live peer and application lease.
///
/// The peer's already-revalidated [`prw_remote_bridge::remote_server_transport_runtime::TransportIdentity`]
/// is snapshotted exactly once before delegating lease validation and binding construction to the
/// existing [`BoundRemoteSession::new`] implementation. The verifier supplies the application lease
/// interval independently of authentication-challenge timing.
///
/// On binding failure, the same peer is explicitly closed with a fixed non-secret diagnostic and the
/// existing [`RemoteBridgeError`] is returned unchanged. Pending-session abort is intentionally not
/// invoked because successful authentication already consumed the pending challenge.
///
/// # Errors
///
/// Returns the existing [`RemoteBridgeError`] produced by [`BoundRemoteSession::new`], including its
/// current invalid-lease classification. No retry, replacement session, replacement lease, or
/// authenticated-session deletion is attempted.
#[allow(
    dead_code,
    reason = "C03e-L stages the binding composition seam before separately gated operation-surface exposure"
)]
pub fn compose_authenticated_remote_session(
    peer: AuthenticatedRemotePeerConnection,
    session: AuthenticatedDeviceSession,
    application_lease_unix_seconds: Range<u64>,
) -> Result<AuthenticatedRemoteSessionRuntimeOwner, RemoteBridgeError> {
    let transport_identity = peer.transport_identity();
    let bound_session = match BoundRemoteSession::new(
        transport_identity,
        session,
        application_lease_unix_seconds.start,
        application_lease_unix_seconds.end,
    ) {
        Ok(bound_session) => bound_session,
        Err(error) => {
            close_authenticated_remote_session_binding_failure(&peer);
            return Err(error);
        }
    };
    let capability_owner = RemoteSessionCapabilityRuntimeOwner::new(bound_session);
    Ok(AuthenticatedRemoteSessionRuntimeOwner::new(
        peer,
        capability_owner,
    ))
}

#[cfg(test)]
mod tests {
    use std::{error::Error, ops::Range};

    use prw_core::DeviceId;
    use prw_remote_bridge::{
        DurableCapabilityBridgeError, RemoteBridgeError,
        capability_request_wire::CapabilityRequestWireError,
        remote_server_transport_runtime::AuthenticatedRemotePeerConnection,
    };
    use prw_session::AuthenticatedDeviceSession;
    use prw_session::prwa_verifier_source::PrwaVerifierSourceError;

    use super::{
        AuthenticatedRemoteSessionCapabilityTransactionError,
        AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError,
        AuthenticatedRemoteSessionRuntimeOwner, AuthenticatedRemoteSessionWorkerStop,
        ProductionDurableCapabilityTransactionError, REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE,
        REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
        REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE,
        REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON,
        REMOTE_SESSION_BINDING_FAILURE_CLOSE_CODE, REMOTE_SESSION_BINDING_FAILURE_CLOSE_REASON,
        close_authenticated_remote_session_binding_failure, compose_authenticated_remote_session,
    };
    use crate::{
        candidate_publication_requester_rendezvous_start_intent::{
            RequesterRendezvousStartIntent, RequesterRendezvousTargetIntent,
        },
        remote_session_capability_runtime::RemoteSessionCapabilityRuntimeOwner,
    };

    fn assert_constructor_signature(
        constructor: fn(
            AuthenticatedRemotePeerConnection,
            RemoteSessionCapabilityRuntimeOwner,
        ) -> AuthenticatedRemoteSessionRuntimeOwner,
    ) {
        let _ = constructor;
    }

    fn assert_composition_signature(
        composition: fn(
            AuthenticatedRemotePeerConnection,
            AuthenticatedDeviceSession,
            Range<u64>,
        )
            -> Result<AuthenticatedRemoteSessionRuntimeOwner, RemoteBridgeError>,
    ) {
        let _ = composition;
    }

    fn assert_binding_failure_close_signature(close: fn(&AuthenticatedRemotePeerConnection)) {
        let _ = close;
    }

    fn assert_requester_rendezvous_start_intent_signature(
        construction: fn(
            &AuthenticatedRemoteSessionRuntimeOwner,
            DeviceId,
        ) -> RequesterRendezvousStartIntent,
    ) {
        let _ = construction;
    }

    fn assert_requester_rendezvous_target_intent_adaptation_signature(
        adaptation: fn(
            &AuthenticatedRemoteSessionRuntimeOwner,
            RequesterRendezvousTargetIntent,
        ) -> RequesterRendezvousStartIntent,
    ) {
        let _ = adaptation;
    }

    fn assert_durable_authority_error_conversion(
        conversion: fn(DurableCapabilityBridgeError) -> ProductionDurableCapabilityTransactionError,
    ) {
        let _ = conversion;
    }

    fn assert_durable_dispatch_error_conversion(
        conversion: fn(RemoteBridgeError) -> ProductionDurableCapabilityTransactionError,
    ) {
        let _ = conversion;
    }

    fn assert_durable_response_error_conversion(
        conversion: fn(CapabilityRequestWireError) -> ProductionDurableCapabilityTransactionError,
    ) {
        let _ = conversion;
    }

    #[test]
    fn outer_owner_consumes_exact_peer_and_capability_owner_shape() {
        assert_constructor_signature(AuthenticatedRemoteSessionRuntimeOwner::new);
    }

    #[test]
    fn post_auth_composition_requires_peer_session_and_separate_lease_interval() {
        assert_composition_signature(compose_authenticated_remote_session);
    }

    #[test]
    fn binding_failure_close_helper_reuses_exact_code_two_surface() {
        assert_binding_failure_close_signature(close_authenticated_remote_session_binding_failure);
        assert_eq!(REMOTE_SESSION_BINDING_FAILURE_CLOSE_CODE, 2);
        assert_eq!(
            REMOTE_SESSION_BINDING_FAILURE_CLOSE_REASON,
            b"remote session binding failed"
        );
    }

    #[test]
    fn requester_rendezvous_start_intent_construction_has_selected_authenticated_owner_shape() {
        assert_requester_rendezvous_start_intent_signature(
            AuthenticatedRemoteSessionRuntimeOwner::requester_rendezvous_start_intent,
        );
    }

    #[test]
    fn requester_rendezvous_target_intent_adaptation_has_selected_authenticated_owner_shape() {
        assert_requester_rendezvous_target_intent_adaptation_signature(
            AuthenticatedRemoteSessionRuntimeOwner::requester_rendezvous_start_intent_from_target_intent,
        );
    }

    #[test]
    fn durable_transaction_error_preserves_selected_stage_conversions() {
        assert_durable_authority_error_conversion(
            ProductionDurableCapabilityTransactionError::from,
        );
        assert_durable_dispatch_error_conversion(ProductionDurableCapabilityTransactionError::from);
        assert_durable_response_error_conversion(ProductionDurableCapabilityTransactionError::from);
    }

    #[test]
    fn durable_transaction_error_display_and_source_are_stage_bounded() {
        let inner = RemoteBridgeError::SessionExpired;
        let error = ProductionDurableCapabilityTransactionError::from(inner);

        assert_eq!(
            error.to_string(),
            "production durable capability dispatch failed"
        );
        assert!(error.source().is_some());
        assert_eq!(
            error,
            ProductionDurableCapabilityTransactionError::Dispatch(inner)
        );
    }

    #[test]
    fn fallible_loop_error_preserves_exact_verifier_time_source() {
        let inner = PrwaVerifierSourceError::VerifierTime;
        let error = AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::from(inner);

        assert_eq!(
            error.to_string(),
            "remote capability verifier time acquisition failed"
        );
        assert_eq!(
            error,
            AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::VerifierTime(inner)
        );
        assert_eq!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<PrwaVerifierSourceError>()),
            Some(&inner)
        );
    }

    #[test]
    fn fallible_loop_error_preserves_exact_transaction_source() {
        let inner = AuthenticatedRemoteSessionCapabilityTransactionError::Bridge(
            RemoteBridgeError::SessionExpired,
        );
        let error = AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::from(inner);

        assert_eq!(
            error.to_string(),
            "remote capability request transaction failed"
        );
        assert_eq!(
            error,
            AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::Transaction(inner)
        );
        assert_eq!(
            error.source().and_then(|source| {
                source.downcast_ref::<AuthenticatedRemoteSessionCapabilityTransactionError>()
            }),
            Some(&inner)
        );
    }

    #[test]
    fn binding_failure_peer_close_diagnostic_is_fixed_nonzero_and_nonempty() {
        assert_ne!(REMOTE_SESSION_BINDING_FAILURE_CLOSE_CODE, 0);
        assert!(!REMOTE_SESSION_BINDING_FAILURE_CLOSE_REASON.is_empty());
    }

    #[test]
    fn capability_session_termination_close_diagnostic_is_fixed_nonzero_and_nonempty() {
        assert_eq!(REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_CODE, 3);
        assert!(!REMOTE_CAPABILITY_SESSION_TERMINATION_CLOSE_REASON.is_empty());
    }

    #[test]
    fn capability_session_shutdown_close_diagnostic_is_fixed_nonzero_and_nonempty() {
        assert_eq!(REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE, 4);
        assert!(!REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON.is_empty());
    }

    #[test]
    fn bridge_failure_classification_is_preserved() {
        let error = RemoteBridgeError::SessionExpired;
        assert_eq!(
            AuthenticatedRemoteSessionCapabilityTransactionError::from(error),
            AuthenticatedRemoteSessionCapabilityTransactionError::Bridge(error)
        );
    }

    #[test]
    fn worker_failure_preserves_exact_transaction_error() {
        let error = AuthenticatedRemoteSessionCapabilityTransactionError::Bridge(
            RemoteBridgeError::SessionExpired,
        );
        let stop = AuthenticatedRemoteSessionWorkerStop::Failed(error);

        match stop {
            AuthenticatedRemoteSessionWorkerStop::Failed(observed) => {
                assert_eq!(observed, error);
            }
            AuthenticatedRemoteSessionWorkerStop::Cancelled => {
                panic!("worker failure must not be reclassified as cancellation");
            }
        }
    }
}

#[cfg(test)]
mod fallible_verifier_time_worker_tests {
    use std::{
        future::{Future, pending, ready},
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use prw_remote_bridge::RemoteBridgeError;
    use prw_session::prwa_verifier_source::PrwaVerifierSourceError;

    use super::{
        AuthenticatedRemoteSessionCapabilityTransactionError,
        AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError,
        AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
        await_fallible_capability_request_worker_stop,
    };

    struct CountingWake {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct RecordingReadyCancellation {
        polled: Arc<AtomicBool>,
    }

    impl Future for RecordingReadyCancellation {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polled.store(true, Ordering::SeqCst);
            Poll::Ready(())
        }
    }

    struct RecordingPendingLoop {
        polls: Arc<AtomicUsize>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl Future for RecordingPendingLoop {
        type Output = Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError>;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            *self.waker.lock().expect("record loop waker") = Some(context.waker().clone());
            Poll::Pending
        }
    }

    struct SignalledCancellation {
        ready: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl Future for SignalledCancellation {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                *self.waker.lock().expect("record cancellation waker") =
                    Some(context.waker().clone());
                Poll::Pending
            }
        }
    }

    struct CountedCleanLoop {
        polls: Arc<AtomicUsize>,
    }

    impl Future for CountedCleanLoop {
        type Output = Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    struct PendingThenReadyCancellation {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PendingThenReadyCancellation {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    struct DropTrackedPendingLoop {
        dropped: Arc<AtomicBool>,
    }

    impl Future for DropTrackedPendingLoop {
        type Output = Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for DropTrackedPendingLoop {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn test_waker() -> (Arc<CountingWake>, Waker) {
        let wake = Arc::new(CountingWake {
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&wake));
        (wake, waker)
    }

    #[test]
    fn ready_verifier_time_failure_wins_without_polling_ready_cancellation() {
        let error = AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::VerifierTime(
            PrwaVerifierSourceError::VerifierTime,
        );
        let cancellation_polled = Arc::new(AtomicBool::new(false));
        let cancellation = RecordingReadyCancellation {
            polled: Arc::clone(&cancellation_polled),
        };
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            ready(Err(error)),
            cancellation,
        ));
        let (_wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(error))
        );
        assert!(!cancellation_polled.load(Ordering::SeqCst));
    }

    #[test]
    fn ready_transaction_failure_wins_without_polling_ready_cancellation() {
        let transaction_error = AuthenticatedRemoteSessionCapabilityTransactionError::Bridge(
            RemoteBridgeError::SessionExpired,
        );
        let error = AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::Transaction(
            transaction_error,
        );
        let cancellation_polled = Arc::new(AtomicBool::new(false));
        let cancellation = RecordingReadyCancellation {
            polled: Arc::clone(&cancellation_polled),
        };
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            ready(Err(error)),
            cancellation,
        ));
        let (_wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(error))
        );
        assert!(!cancellation_polled.load(Ordering::SeqCst));
    }

    #[test]
    fn pending_loop_allows_ready_cancellation_to_win() {
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            pending::<Result<(), AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError>>(),
            ready(()),
        ));
        let (_wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled)
        );
    }

    #[test]
    fn both_pending_futures_receive_context_and_cancellation_wakeup_resumes_race() {
        let loop_polls = Arc::new(AtomicUsize::new(0));
        let loop_waker = Arc::new(Mutex::new(None));
        let cancellation_ready = Arc::new(AtomicBool::new(false));
        let cancellation_polls = Arc::new(AtomicUsize::new(0));
        let cancellation_waker = Arc::new(Mutex::new(None));

        let request_loop = RecordingPendingLoop {
            polls: Arc::clone(&loop_polls),
            waker: Arc::clone(&loop_waker),
        };
        let cancellation = SignalledCancellation {
            ready: Arc::clone(&cancellation_ready),
            polls: Arc::clone(&cancellation_polls),
            waker: Arc::clone(&cancellation_waker),
        };
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            request_loop,
            cancellation,
        ));
        let (wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(loop_polls.load(Ordering::SeqCst), 1);
        assert_eq!(cancellation_polls.load(Ordering::SeqCst), 1);
        assert!(
            loop_waker
                .lock()
                .expect("read loop waker")
                .as_ref()
                .is_some_and(|registered| registered.will_wake(&waker))
        );
        assert!(
            cancellation_waker
                .lock()
                .expect("read cancellation waker")
                .as_ref()
                .is_some_and(|registered| registered.will_wake(&waker))
        );

        cancellation_ready.store(true, Ordering::SeqCst);
        cancellation_waker
            .lock()
            .expect("take cancellation waker")
            .take()
            .expect("cancellation registered waker")
            .wake();
        assert_eq!(wake.wakes.load(Ordering::SeqCst), 1);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled)
        );
        assert_eq!(loop_polls.load(Ordering::SeqCst), 2);
        assert_eq!(cancellation_polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn clean_loop_is_polled_once_and_cancellation_alone_completes_later() {
        let loop_polls = Arc::new(AtomicUsize::new(0));
        let cancellation_polls = Arc::new(AtomicUsize::new(0));
        let request_loop = CountedCleanLoop {
            polls: Arc::clone(&loop_polls),
        };
        let cancellation = PendingThenReadyCancellation {
            polls: Arc::clone(&cancellation_polls),
        };
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            request_loop,
            cancellation,
        ));
        let (_wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(loop_polls.load(Ordering::SeqCst), 1);
        assert_eq!(cancellation_polls.load(Ordering::SeqCst), 1);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled)
        );
        assert_eq!(loop_polls.load(Ordering::SeqCst), 1);
        assert_eq!(cancellation_polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancellation_drops_request_loop_storage_before_helper_returns() {
        let dropped = Arc::new(AtomicBool::new(false));
        let request_loop = DropTrackedPendingLoop {
            dropped: Arc::clone(&dropped),
        };
        let mut future = Box::pin(await_fallible_capability_request_worker_stop(
            request_loop,
            ready(()),
        ));
        let (_wake, waker) = test_waker();
        let mut context = Context::from_waker(&waker);

        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled)
        );
        assert!(dropped.load(Ordering::SeqCst));
    }
}

impl AuthenticatedRemoteSessionRuntimeOwner {
    /// Consumes an authenticated owner completed after orderly supervisor shutdown already latched.
    ///
    /// No capability request is polled and no worker task is created. The retained peer is closed
    /// exactly once with the existing fixed C03e-S code-4 shutdown diagnostic before ownership is
    /// released.
    pub(super) fn close_for_orderly_shutdown(self) {
        self.peer.close(
            REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE,
            REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
        );
    }
}

#[cfg(test)]
mod orderly_shutdown_close_tests {
    use super::{
        AuthenticatedRemoteSessionRuntimeOwner, REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE,
        REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
    };

    fn assert_consuming_close_signature(close: fn(AuthenticatedRemoteSessionRuntimeOwner)) {
        let _ = close;
    }

    #[test]
    fn orderly_shutdown_owner_close_is_consuming_and_reuses_code_four_diagnostic() {
        assert_consuming_close_signature(
            AuthenticatedRemoteSessionRuntimeOwner::close_for_orderly_shutdown,
        );
        assert_eq!(REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_CODE, 4);
        assert_eq!(
            REMOTE_CAPABILITY_SESSION_SHUTDOWN_CLOSE_REASON,
            b"remote capability session shutdown"
        );
    }
}

mod requester_rendezvous_one_shot_transaction;
pub(super) use requester_rendezvous_one_shot_transaction::AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError;
