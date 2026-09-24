//! Isolated Agent-owned requester/rendezvous one-shot target-request composition.
//!
//! C03e-ER materializes only the C03e-EP-selected one-shot composition after C03e-EQ provided the
//! bridge-owned requester-specific receive adapter. C03e-EV additionally materializes the separately
//! selected single-owner one-transaction post-authenticated ingress seam while leaving the ER method
//! itself unchanged and uninvoked. C03e-EX adds the isolated C03e-EW-selected repeated ingress loop
//! and executor-neutral cancellation-aware worker seam without integrating either into active runtime
//! ownership. C03e-EZ threads the C03e-EY-selected exact requester response-stream custody only
//! through the ET -> EV -> EX handoff while keeping the continuation uninvoked. C03e-GE adds only an
//! explicit fail-closed compatibility arm when current-Mesh candidate publication reaches this
//! still-dormant Agent transaction before any candidate handoff/execution semantics have been selected.
//! The existing capability loop and worker do not invoke these seams. None of these seams activates
//! requester/candidate authority/provider execution, candidate or requester response semantics, retry,
//! peer-close policy, dialing, readiness publication, or runtime activation.

use std::{
    future::{Future, poll_fn},
    task::Poll,
};

use prw_policy::PolicyEvaluator;
use prw_remote_bridge::{
    CapabilityBridge, CapabilityDispatcher,
    authorized_request_dispatch::dispatch_authorized_request,
    post_auth_control_stream_ingress::{
        PostAuthControlStreamIngress, receive_post_auth_control_stream_ingress,
    },
    requester_rendezvous_target_request_io::receive_requester_rendezvous_target_request,
};

use super::super::{
    AuthenticatedRemoteSessionPostAuthIngressOutcome,
    AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    RequesterRendezvousCorrelatedStartIntent, RequesterRendezvousOneShotTransactionError,
    RequesterRendezvousResponseStreamCustodyHandoff, SharedCurrentCapabilityAuthority,
    adapt_decoded_requester_rendezvous_target_device_id,
    adapt_post_auth_requester_rendezvous_target_intent,
};
use super::AuthenticatedRemoteSessionRuntimeOwner;
use crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority;

const REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_CODE: u32 = 6;
const REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_REASON: &[u8] =
    b"remote requester-aware session terminated";

/// Bounded terminal failure for the dormant fallible-verifier-time production-durable repeated
/// post-authenticated ingress loop.
#[allow(
    dead_code,
    reason = "C03e-QR materializes the QQ-selected typed fallible verifier-time ingress error before separately gated cancellation and higher-worker propagation"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError {
    /// Acquiring verifier time from the caller-supplied fallible source failed before stream accept.
    VerifierTime(prw_session::prwa_verifier_source::PrwaVerifierSourceError),
    /// The existing C03e-KM production-durable one-transaction ingress seam failed.
    Ingress(AuthenticatedRemoteSessionPostAuthIngressTransactionError),
}

impl std::fmt::Display
    for AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::VerifierTime(_) => {
                "production-durable post-auth verifier time acquisition failed"
            }
            Self::Ingress(_) => "production-durable post-auth ingress transaction failed",
        })
    }
}

impl std::error::Error
    for AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::VerifierTime(error) => Some(error),
            Self::Ingress(error) => Some(error),
        }
    }
}

impl From<prw_session::prwa_verifier_source::PrwaVerifierSourceError>
    for AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError
{
    fn from(error: prw_session::prwa_verifier_source::PrwaVerifierSourceError) -> Self {
        Self::VerifierTime(error)
    }
}

impl From<AuthenticatedRemoteSessionPostAuthIngressTransactionError>
    for AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError
{
    fn from(error: AuthenticatedRemoteSessionPostAuthIngressTransactionError) -> Self {
        Self::Ingress(error)
    }
}

impl AuthenticatedRemoteSessionRuntimeOwner {
    /// Processes one already-read typed post-authenticated ingress through production durable
    /// capability authority while preserving existing requester and candidate family semantics.
    ///
    /// The caller transfers ownership of one exact [`PostAuthControlStreamIngress`] that has already
    /// been accepted and decoded elsewhere. This method does not call `accept_control_stream()` and
    /// does not call `receive_post_auth_control_stream_ingress(...)`; it therefore cannot accept a
    /// second stream or consume a second family-ingress frame.
    ///
    /// Capability transactions delegate by value to the existing C03e-KG durable transaction helper.
    /// Requester/rendezvous transactions preserve the exact current EV target adaptation and
    /// response-stream custody handoff. Candidate-publication transactions preserve the existing
    /// explicit fail-closed higher-owner barrier.
    ///
    /// # Errors
    ///
    /// Durable capability failures retain the exact nested KG `Authority`, `Dispatch` or `Response`
    /// provenance under [`AuthenticatedRemoteSessionPostAuthIngressTransactionError::ProductionDurableCapability`].
    /// Candidate-publication ingress returns the existing
    /// [`AuthenticatedRemoteSessionPostAuthIngressTransactionError::CandidatePublicationHandoffNotSelected`]
    /// classification. No retry, fallback, second read, provider execution or response fabrication is
    /// performed.
    #[allow(
        dead_code,
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-KK materializes the KJ-selected dormant durable typed-ingress processor before separately gated accept/read caller migration"
    )]
    pub(crate) async fn process_existing_post_auth_control_stream_ingress_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        now_unix_seconds: u64,
        dispatcher: &mut D,
        ingress: PostAuthControlStreamIngress,
    ) -> Result<
        AuthenticatedRemoteSessionPostAuthIngressOutcome,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        match ingress {
            PostAuthControlStreamIngress::Capability(transaction) => {
                self.process_production_durable_capability_transaction(
                    authority,
                    now_unix_seconds,
                    dispatcher,
                    transaction,
                )
                .await?;
                Ok(AuthenticatedRemoteSessionPostAuthIngressOutcome::CapabilityProcessed)
            }
            PostAuthControlStreamIngress::RequesterRendezvous(transaction) => {
                let target_intent = adapt_decoded_requester_rendezvous_target_device_id(
                    transaction.request().target_device_id().clone(),
                );
                let start_intent =
                    adapt_post_auth_requester_rendezvous_target_intent(self, target_intent);
                Ok(
                    AuthenticatedRemoteSessionPostAuthIngressOutcome::RequesterRendezvous(
                        Box::new(RequesterRendezvousResponseStreamCustodyHandoff::new(
                            transaction,
                            start_intent,
                        )),
                    ),
                )
            }
            PostAuthControlStreamIngress::CandidatePublication(_transaction) => Err(
                AuthenticatedRemoteSessionPostAuthIngressTransactionError::CandidatePublicationHandoffNotSelected,
            ),
        }
    }

    /// Accepts and processes exactly one post-authenticated control stream through production
    /// durable capability authority while preserving the existing typed family ingress semantics.
    ///
    /// The retained authenticated peer supplies the only stream acceptance authority. This wrapper
    /// accepts exactly one control stream, transfers it by value into the existing typed family
    /// ingress decoder for exactly one bounded read/classification, then transfers the exact typed
    /// ingress by value into the existing C03e-KK processor. It performs no family-specific logic,
    /// retry, second accept, second read, fallback, queueing, provider execution or runtime activation.
    ///
    /// # Errors
    ///
    /// Preserves the existing parent error surface: authenticated accept failure remains `Accept`,
    /// typed ingress failure remains `Ingress`, and durable capability failure remains the existing
    /// nested `ProductionDurableCapability` error with exact KG `Authority` / `Dispatch` / `Response`
    /// provenance. Requester/rendezvous and candidate-publication outcomes are returned unchanged from
    /// the C03e-KK processor.
    #[allow(
        dead_code,
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-KM materializes the KL-selected dormant one-transaction durable accept/read wrapper before separately gated higher caller integration"
    )]
    pub(crate) async fn process_one_post_auth_control_stream_ingress_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        now_unix_seconds: u64,
        dispatcher: &mut D,
    ) -> Result<
        AuthenticatedRemoteSessionPostAuthIngressOutcome,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        let stream = self.peer.accept_control_stream().await?;
        let ingress = receive_post_auth_control_stream_ingress(stream).await?;
        self.process_existing_post_auth_control_stream_ingress_with_production_durable_capability(
            authority,
            now_unix_seconds,
            dispatcher,
            ingress,
        )
        .await
    }

    /// Repeats the production-durable one-transaction post-authenticated ingress seam serially.
    ///
    /// Verifier time is sampled exactly once immediately before each C03e-KM wrapper invocation.
    /// Capability success alone advances to another iteration. The first requester/rendezvous handoff
    /// is returned by value, and the first typed ingress failure terminates the loop unchanged.
    ///
    /// This loop does not call `accept_control_stream()` or
    /// `receive_post_auth_control_stream_ingress(...)` directly; those bounded ownership/read actions
    /// remain exclusively inside the existing C03e-KM one-transaction wrapper. It creates no task,
    /// queue, retry, reconnect, cancellation race, requester DR work, candidate provider work or
    /// runtime activation.
    ///
    /// # Errors
    ///
    /// Returns the first exact [`AuthenticatedRemoteSessionPostAuthIngressTransactionError`] emitted
    /// by the C03e-KM wrapper without suppression, flattening, retry or replacement.
    #[allow(
        dead_code,
        reason = "C03e-KO materializes the KN-selected dormant durable repeated-ingress loop before separately gated cancellation or higher caller integration"
    )]
    pub(crate) async fn run_repeated_post_auth_control_stream_ingress_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        mut verifier_time_unix_seconds: T,
        dispatcher: &mut D,
    ) -> Result<
        RequesterRendezvousResponseStreamCustodyHandoff,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        loop {
            let now_unix_seconds = verifier_time_unix_seconds();
            match self
                .process_one_post_auth_control_stream_ingress_with_production_durable_capability(
                    authority,
                    now_unix_seconds,
                    dispatcher,
                )
                .await?
            {
                AuthenticatedRemoteSessionPostAuthIngressOutcome::CapabilityProcessed => {}
                AuthenticatedRemoteSessionPostAuthIngressOutcome::RequesterRendezvous(handoff) => {
                    return Ok(*handoff);
                }
            }
        }
    }

    /// Repeats the production-durable one-transaction post-authenticated ingress seam with a fallible
    /// verifier-time source while preserving the exact C03e-KM transaction boundary.
    ///
    /// The fallible source is sampled exactly once immediately before each prospective C03e-KM
    /// invocation. A verifier-time failure terminates before KM can accept a stream. A successful
    /// sample is forwarded unchanged as KM's existing concrete `u64`; capability success alone starts
    /// another serial iteration and a requester/rendezvous outcome returns exact handoff custody.
    ///
    /// This sibling does not modify or reimplement KM, add cancellation, run requester DR or
    /// scheduling derivation, create a task/channel, retry a failed sample, cache/default verifier
    /// time, or activate a runtime caller.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError::VerifierTime`]
    /// for the exact first verifier-time source failure before stream acceptance. Returns
    /// [`AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError::Ingress`]
    /// for the exact first existing C03e-KM transaction error without flattening its nested provenance.
    #[allow(
        dead_code,
        reason = "C03e-QR materializes the QQ-selected dormant fallible verifier-time production-durable repeated ingress loop before separately gated cancellation or higher-worker propagation"
    )]
    pub(crate) async fn run_fallible_verifier_time_repeated_post_auth_control_stream_ingress_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError> + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        mut verifier_time_unix_seconds: T,
        dispatcher: &mut D,
    ) -> Result<
        RequesterRendezvousResponseStreamCustodyHandoff,
        AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
    > {
        loop {
            let now_unix_seconds = verifier_time_unix_seconds()?;
            match self
                .process_one_post_auth_control_stream_ingress_with_production_durable_capability(
                    authority,
                    now_unix_seconds,
                    dispatcher,
                )
                .await?
            {
                AuthenticatedRemoteSessionPostAuthIngressOutcome::CapabilityProcessed => {}
                AuthenticatedRemoteSessionPostAuthIngressOutcome::RequesterRendezvous(handoff) => {
                    return Ok(*handoff);
                }
            }
        }
    }

    /// Runs one executor-neutral cancellation-aware production-durable ingress worker without spawning.
    ///
    /// The worker owns exactly one C03e-KO durable repeated-ingress future and one caller-supplied
    /// cancellation future. The ingress loop is polled first on every wake so an already-ready
    /// requester handoff or mixed-family ingress failure retains its exact classification.
    /// Cancellation is polled only while the durable loop is pending and returns only `Ok(None)`.
    ///
    /// The lexical race block ensures the in-flight KO loop future is dropped before a cancellation
    /// result leaves this method, releasing the exclusive mutable session-owner borrow first. This
    /// method samples no verifier time directly, performs no stream accept/read, creates no task,
    /// queue, retry, reconnect, peer close, requester DR work, candidate work or runtime activation.
    ///
    /// # Errors
    ///
    /// Returns the first exact [`AuthenticatedRemoteSessionPostAuthIngressTransactionError`] emitted
    /// by the KO durable repeated loop without suppression, flattening, retry or replacement.
    #[allow(
        dead_code,
        reason = "C03e-KQ materializes the KP-selected dormant durable cancellation-aware worker before separately gated higher caller integration"
    )]
    pub(crate) async fn run_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> Result<
        Option<RequesterRendezvousResponseStreamCustodyHandoff>,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        {
            let mut ingress_loop = Box::pin(
                self.run_repeated_post_auth_control_stream_ingress_with_production_durable_capability(
                    authority,
                    verifier_time_unix_seconds,
                    dispatcher,
                ),
            );
            let mut cancellation = Box::pin(cancellation);

            poll_fn(|context| {
                match ingress_loop.as_mut().poll(context) {
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
        }
    }

    /// Runs one executor-neutral cancellation-aware production-durable ingress worker with a fallible
    /// verifier-time source without spawning.
    ///
    /// The worker owns exactly one C03e-QR fallible repeated-ingress future and one caller-supplied
    /// cancellation future. The ingress loop is polled first on every wake so an already-ready
    /// requester handoff, verifier-time failure, or mixed-family ingress failure retains its exact
    /// classification. Cancellation is polled only while the fallible durable loop is pending and
    /// returns only `Ok(None)`.
    ///
    /// The lexical race block ensures the in-flight QR loop future is dropped before a cancellation
    /// result leaves this method, releasing the exclusive mutable session-owner borrow first. This
    /// method samples no verifier time directly, performs no stream accept/read, creates no task,
    /// queue, retry, reconnect, peer close, requester DR work, candidate work or runtime activation.
    ///
    /// # Errors
    ///
    /// Returns the first exact
    /// [`AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError`] emitted
    /// by the QR fallible repeated loop without suppression, flattening, retry or replacement.
    #[allow(
        dead_code,
        reason = "C03e-QT materializes the QS-selected dormant fallible verifier-time production-durable cancellation-aware worker before separately gated higher caller propagation"
    )]
    pub(crate) async fn run_fallible_verifier_time_repeated_post_auth_control_stream_ingress_worker_with_production_durable_capability<
        D: CapabilityDispatcher + Send,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError> + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        authority: &ProductionDurableCapabilityAuthority,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> Result<
        Option<RequesterRendezvousResponseStreamCustodyHandoff>,
        AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
    > {
        {
            let mut ingress_loop = Box::pin(
                self.run_fallible_verifier_time_repeated_post_auth_control_stream_ingress_with_production_durable_capability(
                    authority,
                    verifier_time_unix_seconds,
                    dispatcher,
                ),
            );
            let mut cancellation = Box::pin(cancellation);

            poll_fn(|context| {
                match ingress_loop.as_mut().poll(context) {
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
        }
    }

    /// Processes exactly one post-authenticated control stream through the C03e-ET family ingress.
    ///
    /// This C03e-EV seam is the single Agent-owned acceptance point for one isolated transaction. It
    /// accepts exactly one stream from the retained authenticated peer and transfers that stream by
    /// value into `receive_post_auth_control_stream_ingress(...)`, which performs exactly one bounded
    /// PRWM frame read and typed family classification.
    ///
    /// Capability-family processing reuses the exact already-read frame, the existing bound-session
    /// registry/policy authorization path, the existing authorized dispatcher, and the exact same
    /// stream retained by the bridge custody envelope for response I/O. No request re-read or stream
    /// replacement occurs.
    ///
    /// Requester/rendezvous-family processing keeps the strict decoded request together with the exact
    /// same ET stream, reads the nominated logical target only from that request, composes it through
    /// the existing C03e-EO then C03e-EJ helpers, and returns one C03e-EZ response-stream custody
    /// handoff. The request's outer `request_id` remains correlation only inside the retained strict
    /// request. Processing stops before C03e-DV, registry/requester-policy/provider execution,
    /// candidate selection, requester response construction/write, or dialing.
    ///
    /// Candidate-publication ingress is recognized as a distinct family but C03e-GE selects no Agent
    /// candidate handoff or execution. This dormant seam therefore fails closed with the explicit
    /// `CandidatePublicationHandoffNotSelected` classification. It does not reinterpret the request as
    /// capability/requester traffic, call FY/GA/GC, write a candidate response, or accept another
    /// stream.
    ///
    /// The method performs one transaction only. It does not replace or invoke the existing
    /// capability loop/worker, does not invoke the isolated C03e-ER accept seam, and does not create a
    /// repeated combined loop, task, queue, retry, reconnect, fairness policy, backpressure policy,
    /// peer-close policy, readiness state, listener activation, deployment, or merge behavior.
    ///
    /// # Errors
    ///
    /// Preserves distinguishable failure classes for one authenticated stream accept, strict typed
    /// ingress, existing capability authorization/dispatch, same-stream capability response I/O, and
    /// the explicit unselected candidate-publication higher-owner handoff barrier. No failure is
    /// translated into fabricated success or a requester/candidate response frame.
    #[allow(
        dead_code,
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-EV intentionally preserves the C03e-EU-selected exclusive mutable-owner transaction custody before separately gated combined-loop integration"
    )]
    pub(crate) async fn process_one_post_auth_control_stream_ingress<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        now_unix_seconds: u64,
        dispatcher: &mut D,
    ) -> Result<
        AuthenticatedRemoteSessionPostAuthIngressOutcome,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        let stream = self.peer.accept_control_stream().await?;
        let ingress = receive_post_auth_control_stream_ingress(stream).await?;

        match ingress {
            PostAuthControlStreamIngress::Capability(transaction) => {
                let bound_session = &self.capability_owner.bound_session;
                let authorized = authority
                    .with_current_authority(|registry, policy| {
                        let bridge = CapabilityBridge::new(registry, policy);
                        bound_session.authorize(
                            &bridge,
                            now_unix_seconds,
                            transaction.request_frame(),
                        )
                    })
                    .await?;
                let response = dispatch_authorized_request(&authorized, dispatcher)?;
                transaction.send_response_frame(&response).await?;
                Ok(AuthenticatedRemoteSessionPostAuthIngressOutcome::CapabilityProcessed)
            }
            PostAuthControlStreamIngress::RequesterRendezvous(transaction) => {
                let target_intent = adapt_decoded_requester_rendezvous_target_device_id(
                    transaction.request().target_device_id().clone(),
                );
                let start_intent =
                    adapt_post_auth_requester_rendezvous_target_intent(self, target_intent);
                Ok(
                    AuthenticatedRemoteSessionPostAuthIngressOutcome::RequesterRendezvous(
                        Box::new(RequesterRendezvousResponseStreamCustodyHandoff::new(
                            transaction,
                            start_intent,
                        )),
                    ),
                )
            }
            PostAuthControlStreamIngress::CandidatePublication(_transaction) => Err(
                AuthenticatedRemoteSessionPostAuthIngressTransactionError::CandidatePublicationHandoffNotSelected,
            ),
        }
    }

    /// Runs the isolated C03e-EW-selected repeated post-authenticated ingress loop.
    ///
    /// Exactly one C03e-EV transaction is in flight per iteration. Verifier time is sampled once
    /// immediately before each EV invocation. Capability success is the only outcome that reaches the
    /// next iteration. One requester/rendezvous result is a typed C03e-EZ handoff barrier retaining
    /// the strict request, exact response stream and session-derived start intent without accepting
    /// another stream. The first EV transaction failure — including the explicit GE unselected
    /// candidate-publication handoff barrier — terminates the loop unchanged.
    ///
    /// This method never calls `accept_control_stream()` directly and never invokes the historical
    /// capability-only `process_one_capability_request(...)` path. It therefore introduces no second
    /// authenticated acceptor, family-specific queue, speculative pre-accept, concurrent transaction,
    /// retry, reconnect, provider execution, requester response, peer close, dialing, readiness or
    /// runtime activation.
    ///
    /// # Errors
    ///
    /// Returns the first [`AuthenticatedRemoteSessionPostAuthIngressTransactionError`] emitted by the
    /// exact C03e-EV transaction seam. No retry, fallback, suppression or replacement is performed.
    #[allow(
        dead_code,
        reason = "C03e-EX materializes the isolated EW-selected repeated ingress loop before separately gated runtime integration"
    )]
    pub(crate) async fn run_repeated_post_auth_control_stream_ingress<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
    >(
        &mut self,
        authority: &SharedCurrentCapabilityAuthority<P>,
        mut verifier_time_unix_seconds: T,
        dispatcher: &mut D,
    ) -> Result<
        RequesterRendezvousResponseStreamCustodyHandoff,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        loop {
            let now_unix_seconds = verifier_time_unix_seconds();
            match self
                .process_one_post_auth_control_stream_ingress(
                    authority,
                    now_unix_seconds,
                    dispatcher,
                )
                .await?
            {
                AuthenticatedRemoteSessionPostAuthIngressOutcome::CapabilityProcessed => {}
                AuthenticatedRemoteSessionPostAuthIngressOutcome::RequesterRendezvous(handoff) => {
                    return Ok(*handoff);
                }
            }
        }
    }

    /// Runs one executor-neutral cancellation-aware C03e-EX worker body without spawning a task.
    ///
    /// The worker owns exactly one repeated C03e-EX loop future and one caller-supplied cancellation
    /// future. The loop is polled first on each wake so an already-ready requester handoff or EV
    /// failure retains its exact classification. Cancellation wins only while the repeated loop is
    /// pending. The in-flight loop future is dropped when the lexical race block exits before the
    /// cancellation result leaves this method, releasing the exclusive mutable owner borrow first.
    ///
    /// Return classes are intentionally minimal and distinguishable:
    ///
    /// - `Ok(Some(handoff))` is the requester/rendezvous response-stream custody handoff barrier;
    /// - `Ok(None)` is caller-owned cancellation;
    /// - `Err(error)` is the first unchanged C03e-EV transaction failure.
    ///
    /// Cancellation performs no whole-peer close in this checkpoint. The existing capability-only
    /// code-4 diagnostic is not widened to mixed-family traffic, and no replacement close code is
    /// invented. No task, channel, queue, retry, reconnect, provider action, requester response,
    /// dialing, readiness state, listener activation or deployment is created.
    ///
    /// # Errors
    ///
    /// Returns the exact first repeated-loop C03e-EV transaction error without reclassification.
    #[allow(
        dead_code,
        reason = "C03e-EX materializes the isolated EW-selected executor-neutral worker before separately gated runtime integration"
    )]
    pub(crate) async fn run_repeated_post_auth_control_stream_ingress_worker<
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
    ) -> Result<
        Option<RequesterRendezvousResponseStreamCustodyHandoff>,
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
    > {
        {
            let mut ingress_loop = Box::pin(self.run_repeated_post_auth_control_stream_ingress(
                authority,
                verifier_time_unix_seconds,
                dispatcher,
            ));
            let mut cancellation = Box::pin(cancellation);

            poll_fn(|context| {
                match ingress_loop.as_mut().poll(context) {
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
        }
    }

    /// Receives and composes exactly one requester/rendezvous target request on one new stream.
    ///
    /// The retained authenticated peer supplies the only stream acceptance authority. The bridge
    /// receives and strictly decodes exactly one bounded PRWM/PRWZ target request. Outer
    /// `request_id` is copied only into the separate correlation tuple element; it is never used as
    /// requester, target, session, transport, registry, policy, or provider identity.
    ///
    /// The decoded logical target is transferred by value through the existing C03e-EO adaptation
    /// and then through the existing C03e-EJ authenticated-session adaptation. Successful return
    /// proves only correlation preservation plus construction of the non-authoritative
    /// `RequesterRendezvousStartIntent`.
    ///
    /// This method does not invoke C03e-DV, current registry/requester policy/provider execution,
    /// candidate selection, response construction or stream write. It does not retry, loop, close
    /// the peer, or integrate with the existing capability worker. The method remains uninvoked by
    /// runtime source until deterministic control-stream demultiplexing is separately selected.
    ///
    /// # Errors
    ///
    /// Preserves authenticated-peer stream-accept failure as
    /// [`RequesterRendezvousOneShotTransactionError::Accept`] and the existing C03e-EQ
    /// receive/decode failure as [`RequesterRendezvousOneShotTransactionError::Wire`]. No failure
    /// is translated into a response frame or rendezvous authority result.
    #[allow(
        dead_code,
        reason = "C03e-ER materializes the isolated one-shot transaction before separately gated deterministic stream demultiplexing/runtime invocation"
    )]
    pub(crate) async fn receive_requester_rendezvous_start_intent_once(
        &self,
    ) -> Result<RequesterRendezvousCorrelatedStartIntent, RequesterRendezvousOneShotTransactionError>
    {
        let mut stream = self.peer.accept_control_stream().await?;
        let request = receive_requester_rendezvous_target_request(&mut stream).await?;
        let request_id = request.request_id();
        let target_intent =
            adapt_decoded_requester_rendezvous_target_device_id(request.into_target_device_id());
        let start_intent = adapt_post_auth_requester_rendezvous_target_intent(self, target_intent);
        Ok((request_id, start_intent))
    }

    /// Consumes one recovered authenticated owner after requester-aware FL or join failure.
    ///
    /// This C03e-FW seam performs terminal peer disposition only. It closes the exact retained peer
    /// once with the fixed non-secret requester-aware code-6 diagnostic. It performs no requester
    /// record cleanup, session deletion, retry/reconnect, peer reuse, worker restart, candidate or
    /// reachability work, target dialing, runtime activation, deployment, or merge.
    pub(in super::super) fn close_for_requester_aware_terminal_failure(self) {
        self.peer.close(
            REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_CODE,
            REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_REASON,
        );
    }
}

#[cfg(test)]
mod fw_requester_aware_terminal_close_tests {
    use super::{
        AuthenticatedRemoteSessionRuntimeOwner,
        REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_CODE,
        REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_REASON,
    };

    fn assert_consuming_close_signature(close: fn(AuthenticatedRemoteSessionRuntimeOwner)) {
        let _ = close;
    }

    #[test]
    fn requester_aware_terminal_failure_close_is_consuming() {
        assert_consuming_close_signature(
            AuthenticatedRemoteSessionRuntimeOwner::close_for_requester_aware_terminal_failure,
        );
    }

    #[test]
    fn requester_aware_terminal_failure_close_uses_fixed_code_six_diagnostic() {
        assert_eq!(REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_CODE, 6);
        assert_eq!(
            REMOTE_REQUESTER_AWARE_SESSION_TERMINATION_CLOSE_REASON,
            b"remote requester-aware session terminated"
        );
    }
}
