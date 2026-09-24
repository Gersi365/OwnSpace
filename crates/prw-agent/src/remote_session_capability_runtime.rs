//! Agent-owned lifetime boundary for one bound remote-session capability context.
//!
//! C03f selected this ownership boundary. C03e-J materializes only the source-level by-value
//! wrapper on the current post-authentication C03e-I lineage. C03e-U adds the separately selected
//! executor-custody owner, C03e-X adds the C03e-W-selected shared-current registry/policy authority
//! owner, C03e-AB adds one lexically-contained spawned-and-joined worker seam, and C03e-AD adds one
//! single-worker orderly cancellation pair. C03e-AH adds the first pre-listener persistent
//! current-thread worker collection seam, C03e-AJ adds one bounded expected-device real remote
//! admission transaction, C03e-AL composes repeated expected-device admission with that persistent
//! collection under the same private current-thread runtime, C03e-AP adds the AO-selected
//! executor-before-bind endpoint lifecycle startup plus explicit remote-supervisor shutdown control,
//! C03e-AT adds the AS-selected crate-internal one-thread process-lifecycle handoff/join control, and
//! C03e-BB adds the BA-selected read-only observation of the exact already-bound endpoint address.
//! C03e-GE adds only an explicit fail-closed compatibility classification when the newly typed Mesh
//! candidate-publication ingress reaches this still-dormant higher-owner seam before any candidate
//! handoff/execution semantics have been selected. This module still does not wire the Agent binary,
//! publish readiness, or activate a production listener lifecycle.

mod admission_timing_failure;
mod authenticated_remote_session_runtime;
mod real_remote_admission_transaction;
mod remote_session_endpoint_lifecycle_runtime;
mod remote_session_executor_runtime;
#[allow(
    dead_code,
    reason = "C03e-AT materializes process-lifecycle control for a separately gated consumer"
)]
pub(crate) mod remote_session_process_lifecycle_control;
mod remote_session_worker_cancellation;
#[allow(
    dead_code,
    reason = "C03e-FB materializes retained-custody DR continuation before separately gated response mapping"
)]
mod requester_rendezvous_retained_custody_dr_continuation;
mod shared_current_capability_authority;
#[allow(
    dead_code,
    reason = "C03e-FP materializes shared requester/rendezvous authority before separately gated spawned/persistent custody"
)]
mod shared_requester_rendezvous_authority;

pub(crate) use admission_timing_failure::{
    RemoteSessionAdmissionTimingFailure, RemoteSessionAdmissionTimingSourceError,
};
pub use authenticated_remote_session_runtime::AuthenticatedRemoteSessionRuntimeOwner;
pub use real_remote_admission_transaction::{
    RemoteSessionApplicationLeasePolicy, RemoteSessionApplicationLeasePolicyError,
    RemoteSessionRealAdmissionError, admit_expected_remote_device_session,
    admit_expected_remote_device_session_with_fresh_verifier_time_and_application_lease_policy,
};
#[allow(
    unused_imports,
    reason = "C03e-PV materializes the C03e-PU-selected crate-visible fallible verifier-time completion projection before separately gated higher-owner caller migration"
)]
pub(crate) use remote_session_endpoint_lifecycle_runtime::RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection;
#[allow(
    unused_imports,
    reason = "C03e-LP materializes the LO-reselected crate-visible completion projection before separately gated higher-owner caller migration"
)]
pub(crate) use remote_session_endpoint_lifecycle_runtime::RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection;
pub use remote_session_endpoint_lifecycle_runtime::{
    RemoteSessionEndpointBoundAddressError, RemoteSessionEndpointLifecycleRuntime,
    RemoteSessionEndpointLifecycleStartupError, RemoteSessionEndpointLifecycleStartupFailure,
    RemoteSessionSupervisorShutdownController,
};
#[allow(
    unused_imports,
    reason = "C03e-SD materializes the SC-selected bounded expected-device handoff observation family before separately gated higher-owner caller integration"
)]
pub(crate) use remote_session_endpoint_lifecycle_runtime::{
    RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection,
    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
    RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection,
};
pub use remote_session_executor_runtime::{
    RemoteSessionExecutorRuntime, RemoteSessionExecutorRuntimeCreateError,
    RemoteSessionExpectedDeviceAdmissionRejection,
    RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionPersistentCollectionConfigError,
    RemoteSessionProductionPreAjTiming, RemoteSessionRealAdmissionTiming,
    RemoteSessionRegisteredWorkerCompletion, RemoteSessionRepeatedAdmissionFailure,
    RemoteSessionSpawnedWorkerJoinError, RemoteSessionWorkerAdmission,
    RemoteSessionWorkerAdmissionRejection, RemoteSessionWorkerAdmissionRejectionReason,
};
pub use remote_session_worker_cancellation::{
    RemoteSessionWorkerCancellationController, RemoteSessionWorkerCancellationSignal,
    remote_session_worker_cancellation_pair,
};
pub use shared_current_capability_authority::SharedCurrentCapabilityAuthority;
pub(crate) use shared_requester_rendezvous_authority::SharedRequesterRendezvousAuthority;

use authenticated_remote_session_runtime::ProductionDurableCapabilityTransactionError;
use std::fmt;

use prw_core::DeviceId;
use prw_remote_bridge::{
    RemoteBridgeError,
    capability_request_wire::CapabilityRequestWireError,
    post_auth_control_stream_ingress::{
        PostAuthControlStreamIngressError, PostAuthRequesterRendezvousTransaction,
    },
    remote_server_transport_runtime::RemoteServerTransportRuntimeError,
    remote_session_binding::BoundRemoteSession,
    requester_rendezvous_target_request_io::RequesterRendezvousTargetRequestIoError,
};

use crate::candidate_publication_requester_rendezvous_start_intent::{
    RequesterRendezvousStartIntent, RequesterRendezvousTargetIntent,
};

/// Agent-owned lifetime boundary for one already-bound remote session.
///
/// Construction performs ownership composition only. The retained binding remains private until a
/// separately gated Agent-internal operation seam is selected and materialized.
pub struct RemoteSessionCapabilityRuntimeOwner {
    #[allow(
        dead_code,
        reason = "C03e-J retains the bound session for a separately gated operation seam"
    )]
    bound_session: BoundRemoteSession,
}

impl RemoteSessionCapabilityRuntimeOwner {
    /// Consumes one existing bound remote session without performing I/O or authorization.
    #[must_use]
    pub const fn new(bound_session: BoundRemoteSession) -> Self {
        Self { bound_session }
    }
}

/// Historical ER correlation remains separate from the authenticated requester/rendezvous intent.
pub(crate) type RequesterRendezvousCorrelatedStartIntent = (u64, RequesterRendezvousStartIntent);

/// One C03e-EZ requester handoff retaining the strict ET transaction and session-derived intent.
///
/// The retained ET transaction owns both the exact strict requester request, whose outer request ID
/// remains correlation only, and the exact same already-accepted control stream. `start_intent`
/// derives requester identity only from the authenticated PRW application session. This carrier
/// performs no C03e-DV invocation, provider mutation, response construction/write, second read,
/// retry, close, candidate selection, dialing or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-EZ materializes response-stream custody before separately gated requester continuation and response semantics"
)]
pub(crate) struct RequesterRendezvousResponseStreamCustodyHandoff {
    requester_transaction: PostAuthRequesterRendezvousTransaction,
    start_intent: RequesterRendezvousStartIntent,
}

impl RequesterRendezvousResponseStreamCustodyHandoff {
    /// Composes exact ET requester/stream custody with the existing session-derived start intent.
    #[must_use]
    pub(crate) const fn new(
        requester_transaction: PostAuthRequesterRendezvousTransaction,
        start_intent: RequesterRendezvousStartIntent,
    ) -> Self {
        Self {
            requester_transaction,
            start_intent,
        }
    }
}

/// Typed successful result of one C03e-EV post-authenticated ingress transaction.
#[allow(
    dead_code,
    reason = "C03e-EV materializes the one-transaction outcome before separately gated combined-loop integration"
)]
pub(crate) enum AuthenticatedRemoteSessionPostAuthIngressOutcome {
    /// Existing capability authorization, dispatch and same-stream response completed successfully.
    CapabilityProcessed,
    /// One strict requester/rendezvous target plus exact same-stream custody reached the handoff.
    RequesterRendezvous(Box<RequesterRendezvousResponseStreamCustodyHandoff>),
}

/// Failure while processing exactly one C03e-EV post-authenticated ingress transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum AuthenticatedRemoteSessionPostAuthIngressTransactionError {
    /// Accepting exactly one control stream from the retained authenticated peer failed.
    Accept(RemoteServerTransportRuntimeError),
    /// C03e-ET one-read ingress or strict requester/rendezvous/candidate wire handling failed.
    Ingress(PostAuthControlStreamIngressError),
    /// Existing capability authorization or typed dispatch failed.
    Bridge(RemoteBridgeError),
    /// Existing same-stream capability response I/O failed.
    CapabilityResponse(CapabilityRequestWireError),
    /// Production durable capability authorization, dispatch or same-stream response failed.
    ProductionDurableCapability(ProductionDurableCapabilityTransactionError),
    /// Candidate ingress succeeded, but no Agent candidate handoff/execution semantics are selected.
    CandidatePublicationHandoffNotSelected,
}

impl fmt::Display for AuthenticatedRemoteSessionPostAuthIngressTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accept(_) => "post-authenticated control-stream acceptance failed",
            Self::Ingress(_) => "post-authenticated control-stream ingress failed",
            Self::Bridge(_) => "post-authenticated capability bridge transaction failed",
            Self::CapabilityResponse(_) => {
                "post-authenticated capability response transmission failed"
            }
            Self::ProductionDurableCapability(_) => {
                "production durable capability post-auth transaction failed"
            }
            Self::CandidatePublicationHandoffNotSelected => {
                "candidate-publication post-authenticated handoff is not selected"
            }
        })
    }
}

impl std::error::Error for AuthenticatedRemoteSessionPostAuthIngressTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(error) => Some(error),
            Self::Ingress(error) => Some(error),
            Self::Bridge(error) => Some(error),
            Self::CapabilityResponse(error) => Some(error),
            Self::ProductionDurableCapability(error) => Some(error),
            Self::CandidatePublicationHandoffNotSelected => None,
        }
    }
}

impl From<RemoteServerTransportRuntimeError>
    for AuthenticatedRemoteSessionPostAuthIngressTransactionError
{
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Accept(error)
    }
}

impl From<PostAuthControlStreamIngressError>
    for AuthenticatedRemoteSessionPostAuthIngressTransactionError
{
    fn from(error: PostAuthControlStreamIngressError) -> Self {
        Self::Ingress(error)
    }
}

impl From<RemoteBridgeError> for AuthenticatedRemoteSessionPostAuthIngressTransactionError {
    fn from(error: RemoteBridgeError) -> Self {
        Self::Bridge(error)
    }
}

impl From<CapabilityRequestWireError>
    for AuthenticatedRemoteSessionPostAuthIngressTransactionError
{
    fn from(error: CapabilityRequestWireError) -> Self {
        Self::CapabilityResponse(error)
    }
}

impl From<ProductionDurableCapabilityTransactionError>
    for AuthenticatedRemoteSessionPostAuthIngressTransactionError
{
    fn from(error: ProductionDurableCapabilityTransactionError) -> Self {
        Self::ProductionDurableCapability(error)
    }
}

/// Failure while composing exactly one requester/rendezvous target request through an authenticated owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum RequesterRendezvousOneShotTransactionError {
    /// Accepting one bounded control stream from the retained authenticated peer failed.
    Accept(RemoteServerTransportRuntimeError),
    /// Receiving or strictly decoding the requester/rendezvous target request failed.
    Wire(RequesterRendezvousTargetRequestIoError),
}

impl fmt::Display for RequesterRendezvousOneShotTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accept(_) => "requester rendezvous control-stream acceptance failed",
            Self::Wire(_) => "requester rendezvous target-request receive/decode failed",
        })
    }
}

impl std::error::Error for RequesterRendezvousOneShotTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(error) => Some(error),
            Self::Wire(error) => Some(error),
        }
    }
}

impl From<RemoteServerTransportRuntimeError> for RequesterRendezvousOneShotTransactionError {
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Accept(error)
    }
}

impl From<RequesterRendezvousTargetRequestIoError> for RequesterRendezvousOneShotTransactionError {
    fn from(error: RequesterRendezvousTargetRequestIoError) -> Self {
        Self::Wire(error)
    }
}

/// Adapts one already-decoded caller-nominated logical target into the existing Agent target intent.
///
/// This crate-private helper performs exact by-value typing/ownership transfer only. The target
/// remains nomination rather than requester authorization or current-registration authority.
#[must_use]
#[allow(
    dead_code,
    reason = "C03e-EO materializes decoded requester-rendezvous target adaptation before separately gated wire transaction activation"
)]
pub(crate) const fn adapt_decoded_requester_rendezvous_target_device_id(
    target_device_id: DeviceId,
) -> RequesterRendezvousTargetIntent {
    RequesterRendezvousTargetIntent::new(target_device_id)
}

/// Adapts one already-typed caller-nominated target through the exact authenticated-session owner.
///
/// This crate-private caller seam performs ownership/typing composition only. Requester identity
/// remains sourced exclusively by the existing C03e-EH adapter from the retained authenticated
/// application session; target identity remains exactly the consumed target intent.
#[must_use]
#[allow(
    dead_code,
    reason = "C03e-EJ materializes requester-specific post-auth target-intent caller ingress before separately gated control/wire activation"
)]
pub(crate) fn adapt_post_auth_requester_rendezvous_target_intent(
    session_owner: &AuthenticatedRemoteSessionRuntimeOwner,
    target_intent: RequesterRendezvousTargetIntent,
) -> RequesterRendezvousStartIntent {
    session_owner.requester_rendezvous_start_intent_from_target_intent(target_intent)
}

#[cfg(test)]
mod tests {
    use prw_core::DeviceId;
    use prw_remote_bridge::remote_session_binding::BoundRemoteSession;

    use super::{
        RemoteSessionCapabilityRuntimeOwner, adapt_decoded_requester_rendezvous_target_device_id,
    };

    fn assert_constructor_signature(
        constructor: fn(BoundRemoteSession) -> RemoteSessionCapabilityRuntimeOwner,
    ) {
        let _ = constructor;
    }

    #[test]
    fn runtime_owner_consumes_exact_bound_remote_session_shape() {
        assert_constructor_signature(RemoteSessionCapabilityRuntimeOwner::new);
    }

    #[test]
    fn decoded_target_adaptation_preserves_exact_logical_device_id() {
        let expected = DeviceId::new("device-target-eo").expect("valid test target");
        let target_intent = adapt_decoded_requester_rendezvous_target_device_id(expected.clone());

        assert_eq!(target_intent.target_device_id(), &expected);
    }
}
