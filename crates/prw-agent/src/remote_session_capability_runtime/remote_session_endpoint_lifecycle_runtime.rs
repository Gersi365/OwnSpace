//! Agent-owned startup and shutdown-control composition for one remote endpoint lifecycle.
//!
//! C03e-AO selected executor-before-bind startup, recoverable reachability-authority custody on
//! startup failure, one remote-specific explicit supervisor-shutdown pair, and delegation to the
//! existing C03e-AN endpoint lifecycle. C03e-AP materializes only those source seams. C03e-AR adds
//! the separately selected Agent-internal path that consumes an already-created executor before
//! the same existing endpoint bind. C03e-BB adds only the BA-selected read-only observation of the
//! exact local address reported by that already-bound retained endpoint. This module does not wire
//! Agent `main.rs`, publish readiness, consume process signals, retry startup, or activate an
//! endpoint from an executable path.

use std::{
    fmt,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_core::{DeviceId, SessionId};
use prw_policy::PolicyEvaluator;
use prw_remote_bridge::CapabilityDispatcher;
use prw_session::SessionAuthenticationService;
use tokio::sync::{Notify, mpsc};

use super::authenticated_remote_session_runtime::{
    AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError,
    AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
    AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
};
use super::remote_session_executor_runtime::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion;
use super::requester_rendezvous_retained_custody_dr_continuation::{
    RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError,
    RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
    RequesterRendezvousPostTerminalResponseSerialLifecycleError,
    RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
    RequesterRendezvousProductionDurableSchedulingWorkerStop,
    RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
};
use super::shared_requester_rendezvous_authority::ExpectedDeviceSchedulingAuthorityGrant;
use super::{
    RemoteSessionExecutorRuntime, RemoteSessionExecutorRuntimeCreateError,
    RemoteSessionExpectedDeviceAdmissionRejection,
    RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionPersistentCollectionConfigError,
    RemoteSessionRealAdmissionError, RemoteSessionRealAdmissionTiming,
    RemoteSessionRegisteredWorkerCompletion, RemoteSessionRepeatedAdmissionFailure,
    RemoteSessionSpawnedWorkerJoinError, SharedCurrentCapabilityAuthority,
    SharedRequesterRendezvousAuthority,
};
use crate::remote_session_capability_runtime::{
    RemoteSessionAdmissionTimingFailure, RemoteSessionAdmissionTimingSourceError,
    RemoteSessionApplicationLeasePolicy, RemoteSessionProductionPreAjTiming,
};
use crate::{
    candidate_publication_requester_rendezvous_start_intent::policy_source::RequesterRendezvousStartPolicySource,
    production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    reachability_authority_admission::ReachabilityAuthorityRuntimeOwner,
    remote_transport_runtime::{AgentRemoteTransportBindError, AgentRemoteTransportRuntime},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointStartupCompositionError<ExecutorError, TransportError> {
    Executor(ExecutorError),
    Transport(TransportError),
}

type EndpointStartupCompositionFailure<Authority, ExecutorError, TransportError> = (
    Box<Authority>,
    EndpointStartupCompositionError<ExecutorError, TransportError>,
);

type EndpointStartupCompositionResult<
    Authority,
    Executor,
    Transport,
    ExecutorError,
    TransportError,
> = Result<
    (Executor, Transport),
    EndpointStartupCompositionFailure<Authority, ExecutorError, TransportError>,
>;

type EndpointBindCompositionResult<Authority, Executor, Transport, TransportError> =
    Result<(Executor, Transport), (Box<Authority>, TransportError)>;

fn compose_endpoint_bind_with_executor<Authority, Executor, Transport, TransportError>(
    executor: Executor,
    authority: Authority,
    bind_transport: impl FnOnce(Authority) -> Result<Transport, (Box<Authority>, TransportError)>,
) -> EndpointBindCompositionResult<Authority, Executor, Transport, TransportError> {
    let transport = bind_transport(authority)?;
    Ok((executor, transport))
}

fn compose_endpoint_startup<Authority, Executor, Transport, ExecutorError, TransportError>(
    authority: Authority,
    construct_executor: impl FnOnce() -> Result<Executor, ExecutorError>,
    bind_transport: impl FnOnce(Authority) -> Result<Transport, (Box<Authority>, TransportError)>,
) -> EndpointStartupCompositionResult<Authority, Executor, Transport, ExecutorError, TransportError>
{
    let executor = match construct_executor() {
        Ok(executor) => executor,
        Err(error) => {
            return Err((
                Box::new(authority),
                EndpointStartupCompositionError::Executor(error),
            ));
        }
    };

    compose_endpoint_bind_with_executor(executor, authority, bind_transport).map_err(
        |(authority, error)| (authority, EndpointStartupCompositionError::Transport(error)),
    )
}

fn map_bound_addr_observation<E>(
    observation: Result<SocketAddr, E>,
) -> Result<SocketAddr, RemoteSessionEndpointBoundAddressError> {
    observation.map_err(|_| RemoteSessionEndpointBoundAddressError::Unavailable)
}

/// Stable failure class while observing the exact local address of one already-bound endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteSessionEndpointBoundAddressError {
    /// The retained lower transport could not report its already-bound local address.
    Unavailable,
}

impl fmt::Display for RemoteSessionEndpointBoundAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("remote endpoint bound address unavailable"),
        }
    }
}

impl std::error::Error for RemoteSessionEndpointBoundAddressError {}

/// Stable failure class while composing one Agent-owned remote endpoint lifecycle runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteSessionEndpointLifecycleStartupError {
    /// Construction of the existing private current-thread executor failed before endpoint bind.
    Executor(RemoteSessionExecutorRuntimeCreateError),
    /// Existing fixed-credential/TLS/socket endpoint bind failed after executor construction.
    Transport(AgentRemoteTransportBindError),
}

impl fmt::Display for RemoteSessionEndpointLifecycleStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executor(_) => {
                formatter.write_str("remote endpoint executor construction failed")
            }
            Self::Transport(_) => formatter.write_str("remote endpoint bind failed"),
        }
    }
}

impl std::error::Error for RemoteSessionEndpointLifecycleStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Executor(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

/// Bounded crate-visible terminal family for one requester-aware endpoint worker completion.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "C03e-LP preserves the exact LO-selected pub(crate) completion projection in the private child before separately gated higher-owner caller migration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection {
    /// Caller-owned cancellation won at one selected requester lifecycle cancellation boundary.
    Cancelled,
    /// The existing requester-aware serial lifecycle stopped on one ingress failure.
    IngressFailure,
    /// The existing requester-aware serial lifecycle stopped on one requester response failure.
    RequesterResponseFailure,
    /// Tokio reported abnormal completion for the retained requester-aware worker task.
    AbnormalTaskCompletion,
}

/// Bounded crate-visible terminal family for one fallible verifier-time endpoint worker completion.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "C03e-PV preserves the exact C03e-PU-selected pub(crate) completion projection in the private child before separately gated higher-owner caller migration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection {
    /// Caller-owned cancellation won at the existing fallible verifier-time worker boundary.
    Cancelled,
    /// The existing PRWA verifier-time source failed.
    VerifierTimeFailure,
    /// The existing capability transaction failed after verifier-time acquisition.
    TransactionFailure,
    /// Tokio reported abnormal completion for the retained worker task.
    AbnormalTaskCompletion,
}

/// Bounded observation of requester acknowledgement completion at the expected-device handoff seam.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "C03e-SD materializes only the SC-selected authority-free acknowledgement observation before separately gated higher-owner integration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection {
    Succeeded,
    Failed,
}

/// Bounded authority-free observation of one eligible expected-device handoff disposition.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "C03e-SD materializes only the SC-selected handoff-disposition observation before separately gated higher-owner integration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection {
    Enqueued,
    ConstructionFailed,
    ChannelClosed,
    SuppressedOnShutdown,
}

/// Bounded higher observation for one fallible-verifier-time expected-device handoff receipt.
///
/// This projection carries only requester correlation-adjacent terminal semantics. It owns no
/// scheduling grant, request, dispatcher, sender, receiver, endpoint, verifier-time provider,
/// retry authority, continuation, stream, task handle, or raw lower error payload.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "C03e-SD materializes the SC-selected bounded higher-observation family before separately gated higher-owner caller integration"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection
{
    Cancelled,
    VerifierTimeFailure,
    IngressFailure,
    RequesterResponseFailure,
    SchedulingDerivationFailure {
        acknowledgement: RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection,
    },
    AbnormalTaskCompletion,
    EligibleTerminal {
        acknowledgement: RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection,
        disposition: RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection,
    },
}

/// Bounded terminal disposition for one eligible expected-device admission handoff attempt.
///
/// These variants classify only the handoff boundary itself. `Enqueued` means queue acceptance,
/// while the remaining variants are terminal for the already-consumed one-shot continuation. This
/// value owns no scheduling grant, request, identifier, dispatcher, timing source, sender, endpoint,
/// retry handle, or other authority-bearing payload.
#[allow(
    dead_code,
    reason = "C03e-OR materializes the OQ-selected dormant bounded handoff disposition before separately gated completion classification and producer composition"
)]
enum RemoteSessionExpectedDeviceAdmissionHandoffDisposition {
    Enqueued,
    ConstructionFailed,
    ChannelClosed,
    SuppressedOnShutdown,
}

/// Private terminal receipt outcome for one scheduling-aware requester completion.
///
/// `Ineligible` retains the exact original scheduling-stop/join result by value. A later separately
/// gated classifier must prove that this value is not an eligible scheduling terminal before
/// constructing that variant. `EligibleTerminal` retains only the exact requester acknowledgement
/// result and one bounded handoff disposition; it cannot retain or reconstruct the consumed
/// scheduling grant.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-OR preserves the exact OQ-selected by-value ineligible completion custody instead of boxing or projecting authority-bearing scheduling state"
)]
enum RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome {
    Ineligible(
        Result<
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ),
    EligibleTerminal {
        acknowledgement_result:
            Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
        disposition: RemoteSessionExpectedDeviceAdmissionHandoffDisposition,
    },
}

/// Boundary-private concrete receipt for one expected-device admission handoff outcome.
///
/// The requester `DeviceId` is correlation only. Target expected-device identity remains obtainable
/// only from a consumed construction-eligible scheduling grant and is intentionally absent here.
/// This carrier is neither `Copy` nor `Clone` and owns exactly one private terminal outcome.
#[allow(
    dead_code,
    reason = "C03e-OR materializes only the OQ-selected dormant concrete receipt representation before separately gated classifier, suppression mapper, producer specialization and runtime wiring"
)]
struct RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
    requester_device_id: DeviceId,
    outcome: RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome,
}

/// Private terminal receipt outcome for one fallible-verifier-time scheduling-aware requester completion.
///
/// `Ineligible` retains the exact original fallible scheduling-stop/join result by value. A later
/// separately gated classifier must prove that this value is not an eligible scheduling terminal
/// before constructing that variant. `EligibleTerminal` retains only the exact requester
/// acknowledgement result and the existing bounded handoff disposition; it cannot retain or
/// reconstruct the consumed scheduling grant.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-RP preserves the RO-selected exact by-value fallible ineligible completion custody while reusing the existing bounded handoff disposition"
)]
enum RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome {
    Ineligible(
        Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ),
    EligibleTerminal {
        acknowledgement_result:
            Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
        disposition: RemoteSessionExpectedDeviceAdmissionHandoffDisposition,
    },
}

/// Boundary-private concrete receipt for one fallible-verifier-time expected-device handoff outcome.
///
/// The requester `DeviceId` is correlation only. Target expected-device identity remains obtainable
/// only from a consumed construction-eligible scheduling grant and is intentionally absent here.
/// This carrier is neither `Copy` nor `Clone` and owns exactly one private fallible terminal outcome.
#[allow(
    dead_code,
    reason = "C03e-RP materializes only the RO-selected dormant fallible concrete receipt representation before separately gated classifier, suppression mapper, producer specialization and runtime wiring"
)]
struct RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
    requester_device_id: DeviceId,
    outcome: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome,
}

const fn project_remote_session_expected_device_admission_acknowledgement(
    acknowledgement_result: Result<
        (),
        RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError,
    >,
) -> RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection {
    if acknowledgement_result.is_ok() {
        RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection::Succeeded
    } else {
        RemoteSessionExpectedDeviceAdmissionAcknowledgementObservationProjection::Failed
    }
}

const fn project_remote_session_expected_device_admission_handoff_disposition(
    disposition: &RemoteSessionExpectedDeviceAdmissionHandoffDisposition,
) -> RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection {
    match disposition {
        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::Enqueued => {
            RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection::Enqueued
        }
        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ConstructionFailed => {
            RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection::ConstructionFailed
        }
        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ChannelClosed => {
            RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection::ChannelClosed
        }
        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::SuppressedOnShutdown => {
            RemoteSessionExpectedDeviceAdmissionHandoffDispositionObservationProjection::SuppressedOnShutdown
        }
    }
}

/// Consumes one private fallible handoff receipt and returns only requester correlation plus the
/// SC-selected bounded terminal observation.
///
/// C03e-RR proves that `SchedulingTerminal + Ok(grant)` is eligible and therefore cannot be stored
/// in an `Ineligible` receipt. The single unreachable arm below asserts that already-selected
/// classifier invariant; it does not create fallback, retry, remint, replay, refund, rollback, or
/// alternate authority semantics.
fn project_remote_session_expected_device_admission_fallible_verifier_time_handoff_receipt(
    receipt: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt,
) -> (
    DeviceId,
    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
) {
    let RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
        requester_device_id,
        outcome,
    } = receipt;

    let projection = match outcome {
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::Ineligible(
            completion,
        ) => match completion {
            Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Cancelled) => {
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::Cancelled
            }
            Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError::Ingress(
                    AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError::VerifierTime(_),
                ),
            )) => {
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::VerifierTimeFailure
            }
            Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError::Ingress(
                    AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError::Ingress(_),
                ),
            )) => {
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::IngressFailure
            }
            Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError::RequesterResponse(_),
            )) => {
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::RequesterResponseFailure
            }
            Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::SchedulingTerminal(
                terminal_outcome,
            )) => {
                let (scheduling_result, acknowledgement_result) = terminal_outcome.into_parts();
                if scheduling_result.is_ok() {
                    unreachable!(
                        "C03e-RR guarantees an issued scheduling grant cannot enter an Ineligible receipt"
                    );
                }
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::SchedulingDerivationFailure {
                    acknowledgement:
                        project_remote_session_expected_device_admission_acknowledgement(
                            acknowledgement_result,
                        ),
                }
            }
            Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion) => {
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::AbnormalTaskCompletion
            }
        },
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::EligibleTerminal {
            acknowledgement_result,
            disposition,
        } => {
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection::EligibleTerminal {
                acknowledgement:
                    project_remote_session_expected_device_admission_acknowledgement(
                        acknowledgement_result,
                    ),
                disposition:
                    project_remote_session_expected_device_admission_handoff_disposition(&disposition),
            }
        }
    };

    (requester_device_id, projection)
}

/// One exact construction-eligible scheduling continuation retained above the generic producer seam.
///
/// The requester `DeviceId` remains requester-side correlation only. Target expected identity and
/// requester scheduling-session provenance remain sealed inside the exact one-shot scheduling grant.
/// The acknowledgement result is retained orthogonally and cannot revoke or reconstruct that grant.
#[allow(
    dead_code,
    reason = "C03e-OT materializes only the OS-selected dormant eligible-continuation custody before separately gated request construction, suppression and producer specialization"
)]
struct RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
    requester_device_id: DeviceId,
    scheduling_grant: ExpectedDeviceSchedulingAuthorityGrant,
    acknowledgement_result:
        Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
}

/// Exact live-completion classification before any expected-device request construction attempt.
///
/// Ineligible completions are retained through the existing C03e-OR receipt without projection.
/// Eligible custody exists only for a scheduling terminal that owns one exact issued grant.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-OT preserves exact by-value ineligible completion and one-shot eligible grant custody instead of boxing or projecting either authority-bearing family"
)]
enum RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification {
    Ineligible(RemoteSessionExpectedDeviceAdmissionHandoffReceipt),
    Eligible(RemoteSessionExpectedDeviceAdmissionEligibleContinuation),
}

/// Classifies one exact scheduling-aware requester worker completion without side effects.
///
/// Only `SchedulingTerminal` with an `Ok` scheduling result is eligible. The scheduling-result
/// discriminant is inspected by borrow first so every ineligible value, including a scheduling
/// derivation error and its orthogonal acknowledgement result, can move untouched into the existing
/// C03e-OR receipt. Only the eligible branch consumes terminal `into_parts()` once; the grant itself
/// remains opaque and uninspected.
#[allow(
    dead_code,
    reason = "C03e-OT materializes the OS-selected pure live-completion classifier before separately gated shutdown suppression, request construction and producer specialization"
)]
fn classify_remote_session_expected_device_admission_live_completion(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification {
    let is_eligible = matches!(
        &completion,
        Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            terminal_outcome
        )) if terminal_outcome.scheduling_result().is_ok()
    );

    if !is_eligible {
        return RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Ineligible(
            RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
                requester_device_id,
                outcome: RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome::Ineligible(
                    completion,
                ),
            },
        );
    }

    let Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::SchedulingTerminal(
        terminal_outcome,
    )) = completion
    else {
        unreachable!("borrowed eligibility check requires a scheduling terminal")
    };
    let (scheduling_result, acknowledgement_result) = terminal_outcome.into_parts();
    let Ok(scheduling_grant) = scheduling_result else {
        unreachable!("borrowed eligibility check requires an issued scheduling grant")
    };

    RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Eligible(
        RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant,
            acknowledgement_result,
        },
    )
}

/// Exact fallible-verifier-time live-completion classification before any request construction.
///
/// Ineligible completions are retained through the existing C03e-RP fallible receipt without
/// projection. Eligible custody reuses the existing verifier-time-agnostic continuation and exists
/// only for a scheduling terminal that owns one exact issued grant.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-RR preserves exact by-value fallible ineligible completion and reuses the existing one-shot eligible continuation instead of projecting either authority-bearing family"
)]
enum RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification {
    Ineligible(RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt),
    Eligible(RemoteSessionExpectedDeviceAdmissionEligibleContinuation),
}

/// Classifies one exact fallible-verifier-time scheduling-aware requester completion without side effects.
///
/// Only `SchedulingTerminal` with an `Ok` scheduling result is eligible. The scheduling-result
/// discriminant is inspected by borrow first so every ineligible value, including a fallible
/// lifecycle failure or scheduling derivation error with its orthogonal acknowledgement result,
/// can move untouched into the existing C03e-RP receipt. Only the eligible branch consumes terminal
/// `into_parts()` once; the grant itself remains opaque and uninspected.
#[allow(
    dead_code,
    reason = "C03e-RR materializes the RQ-selected pure fallible live-completion classifier before separately gated shutdown suppression, request construction and producer specialization"
)]
fn classify_remote_session_expected_device_admission_fallible_verifier_time_live_completion(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification {
    let is_eligible = matches!(
        &completion,
        Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            terminal_outcome
        )) if terminal_outcome.scheduling_result().is_ok()
    );

    if !is_eligible {
        return RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Ineligible(
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
                requester_device_id,
                outcome:
                    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::Ineligible(
                        completion,
                    ),
            },
        );
    }

    let Ok(
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            terminal_outcome,
        ),
    ) = completion
    else {
        unreachable!("borrowed eligibility check requires a scheduling terminal")
    };
    let (scheduling_result, acknowledgement_result) = terminal_outcome.into_parts();
    let Ok(scheduling_grant) = scheduling_result else {
        unreachable!("borrowed eligibility check requires an issued scheduling grant")
    };

    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Eligible(
        RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant,
            acknowledgement_result,
        },
    )
}

/// Maps one shutdown-recovered fallible-verifier-time scheduling completion into the concrete
/// expected-device handoff receipt without performing any lifecycle or producer work.
///
/// Ineligible classification returns the exact existing fallible receipt unchanged. Eligible
/// classification consumes the continuation once, terminally disposes the one-shot scheduling grant
/// by value without binding or observing either grant field, preserves the acknowledgement result
/// unchanged, and emits only the bounded `SuppressedOnShutdown` terminal disposition.
#[allow(
    dead_code,
    reason = "C03e-RT materializes only the RS-selected synchronous fallible shutdown-suppression receipt mapper before separately gated request construction and producer specialization"
)]
fn map_remote_session_expected_device_admission_fallible_verifier_time_shutdown_suppression(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
    match classify_remote_session_expected_device_admission_fallible_verifier_time_live_completion(
        requester_device_id,
        completion,
    ) {
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Ineligible(
            receipt,
        ) => receipt,
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Eligible(
            continuation,
        ) => {
            let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
                requester_device_id,
                scheduling_grant: _,
                acknowledgement_result,
            } = continuation;

            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
                requester_device_id,
                outcome:
                    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::EligibleTerminal {
                        acknowledgement_result,
                        disposition:
                            RemoteSessionExpectedDeviceAdmissionHandoffDisposition::SuppressedOnShutdown,
                    },
            }
        }
    }
}

/// Maps one shutdown-recovered scheduling completion into the concrete expected-device handoff
/// receipt without performing any lifecycle or producer work.
///
/// Ineligible classification returns the exact existing receipt unchanged. Eligible classification
/// consumes the continuation once, terminally disposes the one-shot scheduling grant by value
/// without binding or observing either grant field, preserves the acknowledgement result unchanged,
/// and emits only the bounded `SuppressedOnShutdown` terminal disposition.
#[allow(
    dead_code,
    reason = "C03e-OV materializes only the OU-selected synchronous shutdown-suppression receipt mapper before separately gated request construction and producer specialization"
)]
fn map_remote_session_expected_device_admission_shutdown_suppression(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
    match classify_remote_session_expected_device_admission_live_completion(
        requester_device_id,
        completion,
    ) {
        RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Ineligible(receipt) => {
            receipt
        }
        RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Eligible(
            continuation,
        ) => {
            let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
                requester_device_id,
                scheduling_grant: _,
                acknowledgement_result,
            } = continuation;

            RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
                requester_device_id,
                outcome: RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome::EligibleTerminal {
                    acknowledgement_result,
                    disposition:
                        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::SuppressedOnShutdown,
                },
            }
        }
    }
}

const REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_RANDOM_BYTES: usize = 32;
const REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_HEX_BYTES: usize = 64;
const REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_LOWER_HEX: &[u8; 16] =
    b"0123456789abcdef";

/// Fail-closed source failure for one fresh target-admission `SessionId`.
#[allow(
    dead_code,
    reason = "C03e-OX materializes only the OW-selected private target-admission SessionId source before separately gated request construction"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError {
    Randomness,
    Construction,
}

impl fmt::Display for RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Randomness => "expected-device admission target SessionId randomness failed",
            Self::Construction => "expected-device admission target SessionId construction failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError {}

/// Generates exactly one fresh server-local target-admission `SessionId`.
///
/// This source performs exactly one OS-backed CSPRNG fill of 32 bytes, encodes those bytes as
/// exactly 64 lowercase hexadecimal ASCII characters, and invokes typed `SessionId::new(...)`
/// exactly once. It performs no retry, collision replacement, persistence, registry lookup,
/// scheduling-grant access, request construction, network, channel, producer, dispatcher, timing,
/// authentication, or lifecycle work.
#[allow(
    dead_code,
    reason = "C03e-OX materializes only the OW-selected dormant target-admission SessionId source before separately gated construction composition"
)]
fn new_remote_session_expected_device_admission_target_session_id()
-> Result<SessionId, RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError> {
    let mut random_bytes =
        [0_u8; REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_RANDOM_BYTES];
    SystemRandom::new()
        .fill(&mut random_bytes)
        .map_err(|_| RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError::Randomness)?;

    let mut encoded =
        String::with_capacity(REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_HEX_BYTES);
    for byte in random_bytes {
        encoded.push(char::from(
            REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_LOWER_HEX
                [usize::from(byte >> 4)],
        ));
        encoded.push(char::from(
            REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_LOWER_HEX
                [usize::from(byte & 0x0f)],
        ));
    }
    debug_assert_eq!(
        encoded.len(),
        REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_TARGET_SESSION_ID_HEX_BYTES
    );

    SessionId::new(encoded)
        .map_err(|_| RemoteSessionExpectedDeviceAdmissionTargetSessionIdSourceError::Construction)
}

const REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_AUTHENTICATION_REQUEST_ID_RANDOM_BYTES: usize = 8;

/// Fail-closed source failure for one fresh expected-device PRWM authentication request ID.
#[allow(
    dead_code,
    reason = "C03e-OZ materializes only the OY-selected private expected-device PRWM authentication request-ID source before separately gated request construction"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError {
    Randomness,
    Zero,
}

impl fmt::Display for RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Randomness => {
                "expected-device admission authentication request-ID randomness failed"
            }
            Self::Zero => "expected-device admission authentication request-ID was zero",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError {}

/// Generates exactly one fresh nonzero expected-device PRWM authentication request ID.
///
/// This source performs exactly one OS-backed CSPRNG fill of eight bytes, converts those exact
/// bytes to one `u64` through `u64::from_be_bytes(...)`, and fails closed if the result is zero.
/// It performs no retry, redraw, increment, wrap, fallback, persistence, shared/static counter,
/// PRWC reuse, `SessionId` derivation, scheduling-grant access, request construction, channel,
/// producer, dispatcher, timing, authentication, or lifecycle work.
#[allow(
    dead_code,
    reason = "C03e-OZ materializes only the OY-selected dormant expected-device PRWM authentication request-ID source before separately gated construction composition"
)]
fn new_remote_session_expected_device_authentication_request_id()
-> Result<u64, RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError> {
    let mut random_bytes =
        [0_u8; REMOTE_SESSION_EXPECTED_DEVICE_ADMISSION_AUTHENTICATION_REQUEST_ID_RANDOM_BYTES];
    SystemRandom::new().fill(&mut random_bytes).map_err(|_| {
        RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError::Randomness
    })?;

    let request_id = u64::from_be_bytes(random_bytes);
    if request_id == 0 {
        return Err(RemoteSessionExpectedDeviceAdmissionAuthenticationRequestIdSourceError::Zero);
    }

    Ok(request_id)
}

/// Concrete fallible verifier-time provider installed into one constructed expected-device request.
///
/// This is the existing PRWA verifier wall-clock source carried as a function pointer. Constructing
/// the request does not call or sample the provider.
#[allow(
    dead_code,
    reason = "C03e-QH materializes the QG-selected concrete fallible verifier-time function-pointer type before separately gated producer/send composition"
)]
type RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource =
    fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>;

/// Post-construction custody for exactly one expected-device admission request.
///
/// Requester `DeviceId` remains requester-side correlation only. The acknowledgement result remains
/// orthogonal to request construction. This carrier owns no scheduling grant, sender, channel,
/// retry authority, endpoint, runtime, or second request.
#[allow(
    dead_code,
    reason = "C03e-QH materializes only the QG-selected dormant constructed-handoff custody before separately gated asynchronous send composition"
)]
struct RemoteSessionExpectedDeviceAdmissionConstructedHandoff<D> {
    requester_device_id: DeviceId,
    acknowledgement_result:
        Result<(), RequesterRendezvousTerminalDrAcknowledgementResponseCompositionError>,
    request: RemoteSessionExpectedDeviceAdmissionRequest<
        D,
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
    >,
}

/// Exact local result of one eligible expected-device request-construction attempt.
///
/// `Constructed` means only that one typed request exists under local ownership; it does not mean
/// queue acceptance. `ConstructionFailed` retains only the existing bounded terminal receipt after
/// terminal disposal of the still-sealed one-shot scheduling grant.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-QH materializes only the QG-selected dormant construction outcome before separately gated channel/send composition"
)]
enum RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome<D> {
    Constructed(RemoteSessionExpectedDeviceAdmissionConstructedHandoff<D>),
    ConstructionFailed(RemoteSessionExpectedDeviceAdmissionHandoffReceipt),
}

/// Constructs exactly one expected-device admission request from one eligible continuation.
///
/// The two independent identifier sources run before the one-shot scheduling grant is opened. On
/// either source failure, the grant is terminally disposed without field extraction and the exact
/// requester correlation plus acknowledgement result are projected into the existing
/// `ConstructionFailed` receipt. Only after both identifiers succeed is the grant consumed exactly
/// once; target identity comes only from that grant while requester scheduling `SessionId`
/// provenance is discarded. The existing fallible PRWA verifier-time function is installed as a
/// function pointer without being sampled. This helper performs no channel, send, authentication,
/// admission, runtime, endpoint, retry, dispatcher construction, or lifecycle work.
#[allow(
    dead_code,
    reason = "C03e-QH materializes only the QG-selected synchronous request-construction composition before separately gated producer/send composition"
)]
fn construct_remote_session_expected_device_admission_request_with_fallible_verifier_time<D>(
    continuation: RemoteSessionExpectedDeviceAdmissionEligibleContinuation,
    dispatcher: D,
) -> RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome<D>
where
    D: CapabilityDispatcher + Send + 'static,
{
    let Ok(session_id) = new_remote_session_expected_device_admission_target_session_id() else {
        let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant: _,
            acknowledgement_result,
        } = continuation;
        return RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome::ConstructionFailed(
            RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
                requester_device_id,
                outcome: RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome::EligibleTerminal {
                    acknowledgement_result,
                    disposition:
                        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ConstructionFailed,
                },
            },
        );
    };

    let Ok(authentication_request_id) =
        new_remote_session_expected_device_authentication_request_id()
    else {
        let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant: _,
            acknowledgement_result,
        } = continuation;
        return RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome::ConstructionFailed(
            RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
                requester_device_id,
                outcome:
                    RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome::EligibleTerminal {
                        acknowledgement_result,
                        disposition: RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ConstructionFailed,
                    },
            },
        );
    };

    let verifier_time_unix_seconds: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource =
        prw_session::prwa_verifier_source::current_prwa_verifier_unix_seconds;

    let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
        requester_device_id,
        scheduling_grant,
        acknowledgement_result,
    } = continuation;
    let (_, expected_device_id) = scheduling_grant.into_parts();

    let request = RemoteSessionExpectedDeviceAdmissionRequest::new(
        expected_device_id,
        session_id,
        authentication_request_id,
        dispatcher,
        verifier_time_unix_seconds,
    );

    RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome::Constructed(
        RemoteSessionExpectedDeviceAdmissionConstructedHandoff {
            requester_device_id,
            acknowledgement_result,
            request,
        },
    )
}

/// Exact local result of one eligible fallible-verifier-time expected-device request-construction attempt.
///
/// `Constructed` reuses the existing verifier-time-agnostic constructed-handoff custody.
/// `ConstructionFailed` retains only the existing fallible terminal handoff receipt.
#[allow(
    dead_code,
    clippy::large_enum_variant,
    reason = "C03e-RV materializes only the RU-selected fallible request-construction outcome before separately gated async producer/send composition"
)]
enum RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome<D> {
    Constructed(RemoteSessionExpectedDeviceAdmissionConstructedHandoff<D>),
    ConstructionFailed(RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt),
}

/// Constructs exactly one expected-device admission request from one eligible continuation.
///
/// The two independent identifier sources run before the one-shot scheduling grant is opened. On
/// either source failure, the grant is terminally disposed without field extraction and the exact
/// requester correlation plus acknowledgement result are projected into the existing
/// `ConstructionFailed` receipt. Only after both identifiers succeed is the grant consumed exactly
/// once; target identity comes only from that grant while requester scheduling `SessionId`
/// provenance is discarded. The existing fallible PRWA verifier-time function is installed as a
/// function pointer without being sampled. This helper performs no channel, send, authentication,
/// admission, runtime, endpoint, retry, dispatcher construction, or lifecycle work.
#[allow(
    dead_code,
    reason = "C03e-RV materializes only the RU-selected synchronous fallible-receipt request-construction composition before separately gated producer/send composition"
)]
fn construct_remote_session_expected_device_admission_request_with_fallible_verifier_time_and_fallible_receipt<
    D,
>(
    continuation: RemoteSessionExpectedDeviceAdmissionEligibleContinuation,
    dispatcher: D,
) -> RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome<D>
where
    D: CapabilityDispatcher + Send + 'static,
{
    let Ok(session_id) = new_remote_session_expected_device_admission_target_session_id() else {
        let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant: _,
            acknowledgement_result,
        } = continuation;
        return RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome::ConstructionFailed(
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
                requester_device_id,
                outcome: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::EligibleTerminal {
                    acknowledgement_result,
                    disposition:
                        RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ConstructionFailed,
                },
            },
        );
    };

    let Ok(authentication_request_id) =
        new_remote_session_expected_device_authentication_request_id()
    else {
        let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
            requester_device_id,
            scheduling_grant: _,
            acknowledgement_result,
        } = continuation;
        return RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome::ConstructionFailed(
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
                requester_device_id,
                outcome:
                    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::EligibleTerminal {
                        acknowledgement_result,
                        disposition: RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ConstructionFailed,
                    },
            },
        );
    };

    let verifier_time_unix_seconds: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource =
        prw_session::prwa_verifier_source::current_prwa_verifier_unix_seconds;

    let RemoteSessionExpectedDeviceAdmissionEligibleContinuation {
        requester_device_id,
        scheduling_grant,
        acknowledgement_result,
    } = continuation;
    let (_, expected_device_id) = scheduling_grant.into_parts();

    let request = RemoteSessionExpectedDeviceAdmissionRequest::new(
        expected_device_id,
        session_id,
        authentication_request_id,
        dispatcher,
        verifier_time_unix_seconds,
    );

    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome::Constructed(
        RemoteSessionExpectedDeviceAdmissionConstructedHandoff {
            requester_device_id,
            acknowledgement_result,
            request,
        },
    )
}

/// Produces at most one live expected-device admission request and returns one terminal handoff receipt.
///
/// Ineligible requester completions return their exact existing receipt without constructing a
/// dispatcher. Eligible custody creates exactly one caller-supplied dispatcher and invokes the
/// existing QH fallible-verifier-time request constructor exactly once. Construction failure returns
/// the exact existing receipt without enqueue. A constructed request is offered exactly once through
/// the borrowed production sender using ordinary asynchronous Tokio backpressure. Only successful
/// queue acceptance maps to `Enqueued`; receiver closure terminally drops the returned unsent request
/// and maps only to `ChannelClosed`.
#[allow(
    dead_code,
    reason = "C03e-QN materializes only the QM-selected dormant async producer send/receipt composition before separately gated dispatcher-source capture, channel ownership split and generic producer specialization"
)]
async fn produce_remote_session_expected_device_admission_with_fallible_verifier_time<D, F>(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
    dispatcher_factory: &mut F,
    sender: &mpsc::Sender<
        RemoteSessionExpectedDeviceAdmissionRequest<
            D,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
        >,
    >,
) -> RemoteSessionExpectedDeviceAdmissionHandoffReceipt
where
    D: CapabilityDispatcher + Send + 'static,
    F: FnMut() -> D,
{
    let continuation = match classify_remote_session_expected_device_admission_live_completion(
        requester_device_id,
        completion,
    ) {
        RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Ineligible(receipt) => {
            return receipt;
        }
        RemoteSessionExpectedDeviceAdmissionLiveCompletionClassification::Eligible(
            continuation,
        ) => continuation,
    };

    let dispatcher = dispatcher_factory();
    let handoff =
        match construct_remote_session_expected_device_admission_request_with_fallible_verifier_time(
            continuation,
            dispatcher,
        ) {
            RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome::ConstructionFailed(
                receipt,
            ) => return receipt,
            RemoteSessionExpectedDeviceAdmissionRequestConstructionOutcome::Constructed(
                handoff,
            ) => handoff,
        };

    let RemoteSessionExpectedDeviceAdmissionConstructedHandoff {
        requester_device_id,
        acknowledgement_result,
        request,
    } = handoff;

    let disposition = match sender.send(request).await {
        Ok(()) => RemoteSessionExpectedDeviceAdmissionHandoffDisposition::Enqueued,
        Err(mpsc::error::SendError(_)) => {
            RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ChannelClosed
        }
    };

    RemoteSessionExpectedDeviceAdmissionHandoffReceipt {
        requester_device_id,
        outcome: RemoteSessionExpectedDeviceAdmissionHandoffReceiptOutcome::EligibleTerminal {
            acknowledgement_result,
            disposition,
        },
    }
}

/// Produces at most one live fallible-verifier-time expected-device admission request and returns one fallible terminal handoff receipt.
///
/// Ineligible requester completions return their exact existing fallible receipt without constructing
/// a dispatcher. Eligible custody creates exactly one caller-supplied dispatcher and invokes the
/// existing RV fallible-receipt request constructor exactly once. Construction failure returns the
/// exact existing fallible receipt without enqueue. A constructed request is offered exactly once
/// through the borrowed production sender using ordinary asynchronous Tokio backpressure. Only
/// successful queue acceptance maps to `Enqueued`; receiver closure terminally drops the returned
/// unsent request and maps only to `ChannelClosed`.
#[allow(
    dead_code,
    reason = "C03e-RX materializes only the RW-selected dormant fallible async producer send/receipt composition before separately gated dispatcher-source capture, channel ownership split and generic producer specialization"
)]
async fn produce_remote_session_expected_device_admission_with_fallible_verifier_time_and_fallible_receipt<
    D,
    F,
>(
    requester_device_id: DeviceId,
    completion: Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
    dispatcher_factory: &mut F,
    sender: &mpsc::Sender<
        RemoteSessionExpectedDeviceAdmissionRequest<
            D,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
        >,
    >,
) -> RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt
where
    D: CapabilityDispatcher + Send + 'static,
    F: FnMut() -> D,
{
    let continuation =
        match classify_remote_session_expected_device_admission_fallible_verifier_time_live_completion(
            requester_device_id,
            completion,
        ) {
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Ineligible(
                receipt,
            ) => return receipt,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeLiveCompletionClassification::Eligible(
                continuation,
            ) => continuation,
        };

    let dispatcher = dispatcher_factory();
    let handoff = match construct_remote_session_expected_device_admission_request_with_fallible_verifier_time_and_fallible_receipt(
        continuation,
        dispatcher,
    ) {
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome::ConstructionFailed(
            receipt,
        ) => return receipt,
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeRequestConstructionOutcome::Constructed(
            handoff,
        ) => handoff,
    };

    let RemoteSessionExpectedDeviceAdmissionConstructedHandoff {
        requester_device_id,
        acknowledgement_result,
        request,
    } = handoff;

    let disposition = match sender.send(request).await {
        Ok(()) => RemoteSessionExpectedDeviceAdmissionHandoffDisposition::Enqueued,
        Err(mpsc::error::SendError(_)) => {
            RemoteSessionExpectedDeviceAdmissionHandoffDisposition::ChannelClosed
        }
    };

    RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt {
        requester_device_id,
        outcome: RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceiptOutcome::EligibleTerminal {
            acknowledgement_result,
            disposition,
        },
    }
}

/// Recoverable failed startup transaction retaining the exact admitted reachability authority.
pub struct RemoteSessionEndpointLifecycleStartupFailure {
    authority_owner: Box<ReachabilityAuthorityRuntimeOwner>,
    error: RemoteSessionEndpointLifecycleStartupError,
}

impl fmt::Debug for RemoteSessionEndpointLifecycleStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSessionEndpointLifecycleStartupFailure")
            .field("authority_owner", &"<retained>")
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for RemoteSessionEndpointLifecycleStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for RemoteSessionEndpointLifecycleStartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl RemoteSessionEndpointLifecycleStartupFailure {
    const fn new(
        authority_owner: Box<ReachabilityAuthorityRuntimeOwner>,
        error: RemoteSessionEndpointLifecycleStartupError,
    ) -> Self {
        Self {
            authority_owner,
            error,
        }
    }

    /// Returns the stable bounded startup failure without exposing authority internals.
    #[must_use]
    pub const fn error(&self) -> RemoteSessionEndpointLifecycleStartupError {
        self.error
    }

    /// Recovers the exact admitted reachability-authority owner after failed startup.
    #[must_use]
    pub fn into_authority_owner(self) -> ReachabilityAuthorityRuntimeOwner {
        *self.authority_owner
    }
}

struct RemoteSessionSupervisorShutdownState {
    requested: AtomicBool,
    wake: Notify,
}

/// Explicit non-cloneable authority for requesting orderly shutdown of one remote supervisor.
pub struct RemoteSessionSupervisorShutdownController {
    state: Arc<RemoteSessionSupervisorShutdownState>,
}

struct RemoteSessionSupervisorShutdownSignal {
    state: Arc<RemoteSessionSupervisorShutdownState>,
}

fn remote_session_supervisor_shutdown_pair() -> (
    RemoteSessionSupervisorShutdownController,
    RemoteSessionSupervisorShutdownSignal,
) {
    let state = Arc::new(RemoteSessionSupervisorShutdownState {
        requested: AtomicBool::new(false),
        wake: Notify::new(),
    });

    (
        RemoteSessionSupervisorShutdownController {
            state: Arc::clone(&state),
        },
        RemoteSessionSupervisorShutdownSignal { state },
    )
}

impl RemoteSessionSupervisorShutdownController {
    /// Requests orderly shutdown of the paired remote-session supervisor.
    ///
    /// The request is monotonic and idempotent. This method only makes the paired supervisor future
    /// ready; it does not close the endpoint, cancel workers directly, abort tasks, mutate authority
    /// state, or publish readiness.
    pub fn request_shutdown(&self) {
        self.state.requested.store(true, Ordering::Release);
        self.state.wake.notify_one();
    }
}

impl RemoteSessionSupervisorShutdownSignal {
    async fn into_shutdown(self) {
        while !self.state.requested.load(Ordering::Acquire) {
            self.state.wake.notified().await;
        }
    }
}

/// Agent-owned lifecycle composition for one already-authorized real remote endpoint startup.
pub struct RemoteSessionEndpointLifecycleRuntime {
    executor: RemoteSessionExecutorRuntime,
    transport: AgentRemoteTransportRuntime,
    supervisor_shutdown: RemoteSessionSupervisorShutdownSignal,
}

impl RemoteSessionEndpointLifecycleRuntime {
    /// Constructs the private executor before attempting the existing real remote endpoint bind.
    ///
    /// The admitted reachability-authority owner is retained in the returned failure for both
    /// executor-construction and endpoint-bind failure. Successful startup creates one private
    /// supervisor-shutdown signal and returns its separate non-cloneable controller beside the
    /// lifecycle owner.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionEndpointLifecycleStartupFailure`] when executor construction or the
    /// existing fixed-credential/TLS/socket bind transaction fails. No retry, fallback runtime,
    /// alternate bind, or automatic reachability re-bootstrap is attempted.
    pub fn bind_from_systemd_credentials(
        authority_owner: ReachabilityAuthorityRuntimeOwner,
        bind_addr: SocketAddr,
    ) -> Result<
        (Self, RemoteSessionSupervisorShutdownController),
        RemoteSessionEndpointLifecycleStartupFailure,
    > {
        let startup = compose_endpoint_startup(
            authority_owner,
            RemoteSessionExecutorRuntime::new,
            |authority_owner| {
                AgentRemoteTransportRuntime::bind_from_systemd_credentials(
                    authority_owner,
                    bind_addr,
                )
                .map_err(|failure| {
                    let error = failure.error();
                    let authority_owner = failure.into_authority_owner();
                    (Box::new(authority_owner), error)
                })
            },
        );

        let (executor, transport) = match startup {
            Ok(parts) => parts,
            Err((authority_owner, error)) => {
                let error = match error {
                    EndpointStartupCompositionError::Executor(error) => {
                        RemoteSessionEndpointLifecycleStartupError::Executor(error)
                    }
                    EndpointStartupCompositionError::Transport(error) => {
                        RemoteSessionEndpointLifecycleStartupError::Transport(error)
                    }
                };
                return Err(RemoteSessionEndpointLifecycleStartupFailure::new(
                    authority_owner,
                    error,
                ));
            }
        };

        let (shutdown_controller, supervisor_shutdown) = remote_session_supervisor_shutdown_pair();

        Ok((
            Self {
                executor,
                transport,
                supervisor_shutdown,
            },
            shutdown_controller,
        ))
    }

    /// Binds the existing real remote endpoint using an already-created private executor.
    ///
    /// This Agent-internal seam consumes the exact supplied executor and admitted reachability
    /// authority. It attempts the existing fixed-credential/TLS/socket bind once and creates the
    /// existing supervisor-shutdown pair only after bind succeeds. It never constructs a replacement
    /// executor.
    ///
    /// # Errors
    ///
    /// Returns the existing AP startup-failure owner with the exact reachability authority retained
    /// and the existing transport failure classification. No retry, alternate bind, executor
    /// replacement, reachability re-bootstrap or readiness publication is performed.
    #[allow(
        dead_code,
        reason = "C03e-AR materializes the AQ-selected source seam for a separately gated process consumer"
    )]
    pub(crate) fn bind_with_executor_from_systemd_credentials(
        executor: RemoteSessionExecutorRuntime,
        authority_owner: ReachabilityAuthorityRuntimeOwner,
        bind_addr: SocketAddr,
    ) -> Result<
        (Self, RemoteSessionSupervisorShutdownController),
        RemoteSessionEndpointLifecycleStartupFailure,
    > {
        let startup =
            compose_endpoint_bind_with_executor(executor, authority_owner, |authority_owner| {
                AgentRemoteTransportRuntime::bind_from_systemd_credentials(
                    authority_owner,
                    bind_addr,
                )
                .map_err(|failure| {
                    let error = failure.error();
                    let authority_owner = failure.into_authority_owner();
                    (Box::new(authority_owner), error)
                })
            });

        let (executor, transport) = match startup {
            Ok(parts) => parts,
            Err((authority_owner, error)) => {
                return Err(RemoteSessionEndpointLifecycleStartupFailure::new(
                    authority_owner,
                    RemoteSessionEndpointLifecycleStartupError::Transport(error),
                ));
            }
        };

        let (shutdown_controller, supervisor_shutdown) = remote_session_supervisor_shutdown_pair();

        Ok((
            Self {
                executor,
                transport,
                supervisor_shutdown,
            },
            shutdown_controller,
        ))
    }

    /// Returns the exact local socket address reported by the retained already-bound endpoint.
    ///
    /// This is a synchronous read-only observation. It does not use the original bind input as an
    /// authoritative substitute, create a connectivity candidate, publish reachability, retry,
    /// rebind, close the endpoint, request shutdown, or mutate lifecycle ownership.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionEndpointBoundAddressError::Unavailable`] when the existing retained
    /// lower transport cannot report its already-bound local address.
    pub fn bound_addr(&self) -> Result<SocketAddr, RemoteSessionEndpointBoundAddressError> {
        map_bound_addr_observation(self.transport.local_addr())
    }

    /// Consumes this startup owner and drives exactly one repeated-admission endpoint lifecycle.
    ///
    /// The stored supervisor-shutdown signal is consumed exactly once. All admission, worker,
    /// shutdown, endpoint-close and idle-drain behavior is delegated to the existing C03e-AN
    /// executor lifecycle; AP does not copy or replace those state machines.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged after the C03e-AN
    /// lifecycle has still closed the bound endpoint and driven it idle.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-AP forwards the exact existing C03e-AN lifecycle inputs"
    )]
    pub fn drive_repeated_real_remote_admission_endpoint_lifecycle<P, D, T, F, C, R, E>(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
        E: FnMut(RemoteSessionRepeatedAdmissionFailure),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor.drive_repeated_real_remote_admission_endpoint_lifecycle(
            max_active_workers,
            &transport,
            authority,
            session_authentication,
            expected_requests,
            supervisor_shutdown.into_shutdown(),
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
    }

    /// Consumes this startup owner and delegates exactly once to the C03e-PP fallible
    /// verifier-time repeated-admission endpoint lifecycle.
    ///
    /// The retained endpoint transport and the existing supervisor-shutdown signal are forwarded
    /// unchanged into the executor boundary. Endpoint close and idle-drain ordering remain owned
    /// exclusively by C03e-PP; this wrapper adds no second teardown path or error envelope.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-PR materializes the PQ-selected dormant fallible verifier-time endpoint-owner wrapper before separately gated provider and higher-caller wiring"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-PR forwards the exact C03e-PP fallible endpoint-lifecycle inputs without introducing a new aggregate"
    )]
    pub(super) fn drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
        E: FnMut(RemoteSessionRepeatedAdmissionFailure),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor.drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle(
            max_active_workers,
            &transport,
            authority,
            session_authentication,
            expected_requests,
            supervisor_shutdown.into_shutdown(),
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
    }

    /// Consumes this endpoint owner and exposes only the C03e-PU-selected bounded fallible
    /// verifier-time completion family.
    ///
    /// The existing C03e-PT lifecycle remains sole owner of endpoint/executor behavior. This
    /// adapter invokes it exactly once, forwards every non-completion input and callback
    /// unchanged, and projects only the raw persistent-worker completion while preserving the
    /// authenticated owner-derived `DeviceId` unchanged.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-PV materializes the C03e-PU-selected dormant completion projection before separately gated provider installation and higher-owner caller migration"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-PV preserves the exact C03e-PT lifecycle inputs while projecting only completion"
    )]
    pub(crate) fn drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle_with_completion_projection<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        mut on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(DeviceId, RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection),
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
        E: FnMut(RemoteSessionRepeatedAdmissionFailure),
    {
        self.drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle(
            max_active_workers,
            authority,
            session_authentication,
            expected_requests,
            admission_timing,
            |completion| {
                let (device_id, result) = completion.into_parts();
                let projection = match result {
                    Ok(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Cancelled) => {
                        RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection::Cancelled
                    }
                    Ok(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(
                        AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::VerifierTime(_),
                    )) => {
                        RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection::VerifierTimeFailure
                    }
                    Ok(AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop::Failed(
                        AuthenticatedRemoteSessionFallibleCapabilityRequestLoopError::Transaction(_),
                    )) => {
                        RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection::TransactionFailure
                    }
                    Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion) => {
                        RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection::AbnormalTaskCompletion
                    }
                };
                on_completion(device_id, projection);
            },
            on_rejection,
            on_admission_failure,
        )
    }

    /// Consumes this startup owner and delegates one dormant production-durable repeated-admission
    /// endpoint lifecycle to the exact C03e-LK executor boundary.
    ///
    /// The retained endpoint transport is borrowed only for that one executor invocation, and the
    /// retained supervisor-shutdown signal is converted exactly once. The distinct requester-DR and
    /// production durable capability authorities are forwarded unchanged. Endpoint close and idle
    /// drain remain owned exclusively by the LK executor method.
    ///
    /// This seam performs no durable-authority bootstrap or population, callback projection,
    /// requester-lifecycle visibility widening, executable caller migration, runtime activation,
    /// endpoint bind, retry, merge, or deployment.
    #[allow(
        dead_code,
        reason = "C03e-LM materializes the LL-selected dormant durable endpoint-owner caller adaptation before separately gated higher-owner projection and production authority population"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-LM forwards the exact LL-selected durable executor boundary inputs without introducing a new aggregate"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability<
        P,
        D,
        T,
        PS,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ),
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            )
    }

    /// Consumes this endpoint owner and delegates once to the existing scheduling-aware durable
    /// executor endpoint lifecycle while preserving exact scheduling terminal custody.
    ///
    /// The retained endpoint transport is borrowed only for that one executor invocation and the
    /// retained supervisor-shutdown signal is consumed exactly once. This dormant propagation seam
    /// constructs no expected-device request, channel, identifier, dispatcher, timing source, task,
    /// listener, readiness state, or executable activation. It does not project, clone, reconstruct,
    /// remint, or otherwise widen the existing scheduling terminal/grant custody.
    #[allow(
        dead_code,
        reason = "C03e-OD materializes the OC-selected dormant scheduling-aware endpoint-owner propagation before separately gated producer/channel composition"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-OD forwards the exact existing scheduling-aware executor boundary inputs without introducing a new aggregate"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_scheduling<
        P,
        D,
        T,
        PS,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ),
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_scheduling(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            )
    }

    /// Consumes this endpoint owner and forwards the exact borrowed cooperative producer boundary.
    ///
    /// The endpoint owner consumes its retained executor, transport and supervisor-shutdown signal
    /// exactly once, then delegates once to the C03e-OM executor producer endpoint lifecycle. The
    /// producer remains caller-owned and only mutably borrowed for that invocation; receipt custody
    /// remains generic. Endpoint close and idle drain remain exclusively owned by the executor seam.
    ///
    /// This dormant forwarding seam constructs no channel, sender, expected-device request,
    /// concrete receipt, identifier, dispatcher, timing source, task, listener, readiness state or
    /// executable activation.
    #[allow(
        dead_code,
        reason = "C03e-OP materializes only the ON-selected dormant higher endpoint-owner producer forwarding before separately gated concrete receipt and producer/channel composition"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-OP forwards the exact ON-selected generic producer endpoint boundary without introducing a new aggregate"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_scheduling_producer<
        P,
        D,
        T,
        PS,
        H,
        Q,
        O,
        Receipt,
        F,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        producer: &mut H,
        suppress_on_shutdown: Q,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        H: std::ops::AsyncFnMut(
                DeviceId,
                Result<
                    RequesterRendezvousProductionDurableSchedulingWorkerStop,
                    RemoteSessionSpawnedWorkerJoinError,
                >,
            ) -> Receipt,
        Q: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ) -> Receipt,
        O: FnMut(Receipt),
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_scheduling_producer(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                producer,
                suppress_on_shutdown,
                observe_receipt,
                admission_timing,
                on_rejection,
                on_admission_failure,
            )
    }

    /// Consumes this endpoint owner and forwards the exact fallible-verifier-time borrowed
    /// cooperative producer boundary.
    ///
    /// This endpoint owner consumes its retained executor, transport and supervisor-shutdown signal
    /// exactly once, then delegates once to the C03e-RL executor producer endpoint lifecycle. The
    /// producer remains caller-owned and only mutably borrowed; receipt custody remains generic.
    /// Endpoint close and idle drain remain exclusively owned by the lower executor seam.
    ///
    /// This dormant forwarding seam constructs no channel, sender, expected-device request,
    /// concrete receipt, identifier, dispatcher, timing source, task, listener, readiness state or
    /// executable activation.
    #[allow(
        dead_code,
        reason = "C03e-RN materializes only the RM-selected dormant fallible higher endpoint-owner producer forwarding before separately gated fallible concrete receipt and producer/channel composition"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-RN forwards the exact RM-selected fallible generic producer endpoint boundary without introducing a new aggregate"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer<
        P,
        D,
        T,
        PS,
        H,
        Q,
        O,
        Receipt,
        F,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        producer: &mut H,
        suppress_on_shutdown: Q,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        H: std::ops::AsyncFnMut(
                DeviceId,
                Result<
                    RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                    RemoteSessionSpawnedWorkerJoinError,
                >,
            ) -> Receipt,
        Q: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ) -> Receipt,
        O: FnMut(Receipt),
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                producer,
                suppress_on_shutdown,
                observe_receipt,
                admission_timing,
                on_rejection,
                on_admission_failure,
            )
    }

    /// Forwards the selected fallible admission-timing source and failure custodian unchanged.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-SX adds only Cause/K and result-valued admission timing to the existing S4 forwarding boundary"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_fallible_admission_timing<
        P,
        D,
        T,
        PS,
        H,
        Q,
        O,
        Receipt,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        producer: &mut H,
        suppress_on_shutdown: Q,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        H: std::ops::AsyncFnMut(
                DeviceId,
                Result<
                    RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                    RemoteSessionSpawnedWorkerJoinError,
                >,
            ) -> Receipt,
        Q: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ) -> Receipt,
        O: FnMut(Receipt),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionRealAdmissionTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                T,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_fallible_admission_timing(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                producer,
                suppress_on_shutdown,
                observe_receipt,
                admission_timing,
                on_rejection,
                on_admission_failure,
                on_timing_failure,
            )
    }

    /// Forwards the TE-selected challenge-only timing source plus validated lease policy unchanged.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-TF preserves endpoint ownership while forwarding only the selected timing and typed lease policy"
    )]
    pub(super) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_pre_aj_timing_and_application_lease_policy<
        P,
        D,
        T,
        PS,
        H,
        Q,
        O,
        Receipt,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        application_lease_policy: RemoteSessionApplicationLeasePolicy,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        producer: &mut H,
        suppress_on_shutdown: Q,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        H: std::ops::AsyncFnMut(
                DeviceId,
                Result<
                    RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                    RemoteSessionSpawnedWorkerJoinError,
                >,
            ) -> Receipt,
        Q: FnMut(
            DeviceId,
            Result<
                RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ) -> Receipt,
        O: FnMut(Receipt),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionProductionPreAjTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                T,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let Self {
            mut executor,
            transport,
            supervisor_shutdown,
        } = self;

        executor
            .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_pre_aj_timing_and_application_lease_policy(
                max_active_workers,
                &transport,
                authority,
                capability_authority,
                policy_source,
                requester_rendezvous_authority,
                application_lease_policy,
                session_authentication,
                expected_requests,
                supervisor_shutdown.into_shutdown(),
                producer,
                suppress_on_shutdown,
                observe_receipt,
                admission_timing,
                on_rejection,
                on_admission_failure,
                on_timing_failure,
            )
    }

    /// Specializes the existing fallible producer seam to the concrete fallible expected-device
    /// handoff receipt without taking ownership of dispatcher or sender authority.
    #[allow(
        dead_code,
        reason = "C03e-RZ materializes only the RY-selected dormant fallible generic producer specialization before separately gated dispatcher-source capture, channel construction and higher-owner integration"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-RZ preserves the existing RN endpoint boundary plus borrowed dispatcher-factory and sender authority without introducing a new aggregate"
    )]
    fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt),
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let mut producer = async |requester_device_id: DeviceId,
                                  completion: Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >| {
            produce_remote_session_expected_device_admission_with_fallible_verifier_time_and_fallible_receipt(
                requester_device_id,
                completion,
                &mut *dispatcher_factory,
                sender,
            )
            .await
        };

        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            session_authentication,
            expected_requests,
            &mut producer,
            map_remote_session_expected_device_admission_fallible_verifier_time_shutdown_suppression,
            observe_receipt,
            admission_timing,
            on_rejection,
            on_admission_failure,
        )
    }

    /// Specializes the existing expected-device producer without capturing timing-failure custody.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-SX preserves the S3 producer closure and forwards K only to the lower fallible timing sibling"
    )]
    fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_fallible_admission_timing<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionRealAdmissionTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let mut producer = async |requester_device_id: DeviceId,
                                  completion: Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >| {
            produce_remote_session_expected_device_admission_with_fallible_verifier_time_and_fallible_receipt(
                requester_device_id,
                completion,
                &mut *dispatcher_factory,
                sender,
            )
            .await
        };

        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_fallible_admission_timing(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            session_authentication,
            expected_requests,
            &mut producer,
            map_remote_session_expected_device_admission_fallible_verifier_time_shutdown_suppression,
            observe_receipt,
            admission_timing,
            on_rejection,
            on_admission_failure,
            on_timing_failure,
        )
    }

    /// Specializes the fallible expected-device producer for challenge-only pre-AJ timing and typed lease policy.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-TF preserves the expected-device producer closure while forwarding the selected policy separately"
    )]
    fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_pre_aj_timing_and_application_lease_policy<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        application_lease_policy: RemoteSessionApplicationLeasePolicy,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffReceipt),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionProductionPreAjTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeSource,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let mut producer = async |requester_device_id: DeviceId,
                                  completion: Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >| {
            produce_remote_session_expected_device_admission_with_fallible_verifier_time_and_fallible_receipt(
                requester_device_id,
                completion,
                &mut *dispatcher_factory,
                sender,
            )
            .await
        };

        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_scheduling_producer_with_pre_aj_timing_and_application_lease_policy(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            application_lease_policy,
            session_authentication,
            expected_requests,
            &mut producer,
            map_remote_session_expected_device_admission_fallible_verifier_time_shutdown_suppression,
            observe_receipt,
            admission_timing,
            on_rejection,
            on_admission_failure,
            on_timing_failure,
        )
    }

    /// Consumes this endpoint owner and exposes only the bounded C03e-LO-selected terminal family.
    ///
    /// The existing C03e-LM durable endpoint method remains the sole owner of endpoint/executor
    /// lifecycle behavior. This adapter invokes it exactly once, forwards all non-completion inputs
    /// and callbacks unchanged, and projects requester-private terminal payloads into four bounded
    /// crate-visible families without widening those private types.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-LP materializes the LO-reselected dormant projection adapter before separately gated higher-owner caller migration"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-LP preserves the exact C03e-LM durable endpoint inputs while projecting only completion"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability_projection<
        P,
        D,
        T,
        PS,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        mut on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(DeviceId, RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection),
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            session_authentication,
            expected_requests,
            admission_timing,
            |device_id, completion_result| {
                let projection = match completion_result {
                    Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled) => {
                        RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection::Cancelled
                    }
                    Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                        RequesterRendezvousPostTerminalResponseSerialLifecycleError::Ingress(_),
                    )) => {
                        RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection::IngressFailure
                    }
                    Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(
                        RequesterRendezvousPostTerminalResponseSerialLifecycleError::RequesterResponse(_),
                    )) => {
                        RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection::RequesterResponseFailure
                    }
                    Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion) => {
                        RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection::AbnormalTaskCompletion
                    }
                };
                on_completion(device_id, projection);
            },
            on_rejection,
            on_admission_failure,
        )
    }
}

impl RemoteSessionEndpointLifecycleRuntime {
    /// Consumes this endpoint owner and exposes only the SC-selected bounded higher observation for
    /// the existing private C03e-RZ fallible expected-device producer specialization.
    ///
    /// The raw receipt remains confined to this private child. Each receipt is consumed exactly once,
    /// synchronously projected to requester `DeviceId` plus the bounded authority-free family, and
    /// forwarded exactly once to the caller observer. Dispatcher factory and sender authority remain
    /// borrowed exactly as in RZ; expected-request receiver transfer and shutdown suppression remain
    /// unchanged. This adapter constructs no channel, clones no sender, invokes no higher owner, and
    /// activates no runtime behavior by itself.
    #[allow(
        dead_code,
        reason = "C03e-SD materializes only the SC-selected bounded higher-observation adapter before separately gated higher-owner integration"
    )]
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-SD preserves the exact RZ inputs while replacing only raw receipt observation with the bounded SC-selected projection"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        mut observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            session_authentication,
            expected_requests,
            dispatcher_factory,
            sender,
            |receipt| {
                let (requester_device_id, projection) =
                    project_remote_session_expected_device_admission_fallible_verifier_time_handoff_receipt(
                        receipt,
                    );
                observe_receipt(requester_device_id, projection);
            },
            admission_timing,
            on_rejection,
            on_admission_failure,
        )
    }

    /// Preserves the bounded receipt projection while forwarding timing failure on its own K path.
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-SX changes only admission timing and failure custody at the S2 forwarding boundary"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_fallible_admission_timing<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        mut observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionRealAdmissionTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_fallible_admission_timing(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            session_authentication,
            expected_requests,
            dispatcher_factory,
            sender,
            |receipt| {
                let (requester_device_id, projection) =
                    project_remote_session_expected_device_admission_fallible_verifier_time_handoff_receipt(
                        receipt,
                    );
                observe_receipt(requester_device_id, projection);
            },
            admission_timing,
            on_rejection,
            on_admission_failure,
            on_timing_failure,
        )
    }

    /// Preserves the bounded higher observation while forwarding TE timing and lease policy on separate lanes.
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-TF keeps projection, E and K custody unchanged while adding the selected timing carrier and policy"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_pre_aj_timing_and_application_lease_policy<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        application_lease_policy: RemoteSessionApplicationLeasePolicy,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        mut observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionProductionPreAjTiming,
            RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            RemoteSessionAdmissionTimingFailure<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
                RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        self.drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_pre_aj_timing_and_application_lease_policy(
            max_active_workers,
            authority,
            capability_authority,
            policy_source,
            requester_rendezvous_authority,
            application_lease_policy,
            session_authentication,
            expected_requests,
            dispatcher_factory,
            sender,
            |receipt| {
                let (requester_device_id, projection) =
                    project_remote_session_expected_device_admission_fallible_verifier_time_handoff_receipt(
                        receipt,
                    );
                observe_receipt(requester_device_id, projection);
            },
            admission_timing,
            on_rejection,
            on_admission_failure,
            on_timing_failure,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::{
        EndpointStartupCompositionError, RemoteSessionEndpointBoundAddressError,
        RemoteSessionEndpointLifecycleRuntime, RemoteSessionEndpointLifecycleStartupFailure,
        RemoteSessionExecutorRuntime, RemoteSessionSupervisorShutdownController,
        compose_endpoint_bind_with_executor, compose_endpoint_startup, map_bound_addr_observation,
        remote_session_supervisor_shutdown_pair,
    };
    use crate::{
        reachability_authority_admission::ReachabilityAuthorityRuntimeOwner,
        reachability_authority_custody_bootstrap::ReachabilityAuthorityCustodyBootstrapError,
    };

    #[derive(Default)]
    struct WakeFlag {
        woken: AtomicBool,
    }

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.woken.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.woken.store(true, Ordering::SeqCst);
        }
    }

    fn test_context() -> (Arc<WakeFlag>, Waker) {
        let flag = Arc::new(WakeFlag::default());
        let waker = Waker::from(Arc::clone(&flag));
        (flag, waker)
    }

    fn assert_send_static_shutdown_future<F>(future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        drop(future);
    }

    fn assert_constructor_signature(
        constructor: fn(
            ReachabilityAuthorityRuntimeOwner,
            SocketAddr,
        ) -> Result<
            (
                RemoteSessionEndpointLifecycleRuntime,
                RemoteSessionSupervisorShutdownController,
            ),
            RemoteSessionEndpointLifecycleStartupFailure,
        >,
    ) {
        let _ = constructor;
    }

    fn assert_bound_addr_signature(
        observation: fn(
            &RemoteSessionEndpointLifecycleRuntime,
        ) -> Result<SocketAddr, RemoteSessionEndpointBoundAddressError>,
    ) {
        let _ = observation;
    }

    #[expect(
        clippy::type_complexity,
        reason = "C03e-AR test intentionally states the exact Agent-internal same-executor constructor shape"
    )]
    fn assert_same_executor_constructor_signature(
        constructor: fn(
            RemoteSessionExecutorRuntime,
            ReachabilityAuthorityRuntimeOwner,
            SocketAddr,
        ) -> Result<
            (
                RemoteSessionEndpointLifecycleRuntime,
                RemoteSessionSupervisorShutdownController,
            ),
            RemoteSessionEndpointLifecycleStartupFailure,
        >,
    ) {
        let _ = constructor;
    }

    fn assert_reachability_bootstrap_signature(
        bootstrap: fn(
            &RemoteSessionExecutorRuntime,
        ) -> Result<
            ReachabilityAuthorityRuntimeOwner,
            ReachabilityAuthorityCustodyBootstrapError,
        >,
    ) {
        let _ = bootstrap;
    }

    #[test]
    fn bound_addr_mapping_preserves_exact_socket_addr() {
        let bound_addr = SocketAddr::from(([127, 0, 0, 1], 43_121));

        assert_eq!(
            map_bound_addr_observation::<()>(Ok(bound_addr)),
            Ok(bound_addr)
        );
    }

    #[test]
    fn bound_addr_mapping_collapses_lower_error_to_unavailable() {
        assert_eq!(
            map_bound_addr_observation::<&'static str>(Err("lower address unavailable")),
            Err(RemoteSessionEndpointBoundAddressError::Unavailable)
        );
    }

    #[test]
    fn shutdown_requested_before_poll_completes_from_durable_state() {
        let (controller, signal) = remote_session_supervisor_shutdown_pair();
        controller.request_shutdown();

        let mut future = Box::pin(signal.into_shutdown());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn pending_shutdown_signal_is_woken_and_then_completes() {
        let (controller, signal) = remote_session_supervisor_shutdown_pair();
        let mut future = Box::pin(signal.into_shutdown());
        let (wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert!(!wake_flag.woken.load(Ordering::SeqCst));

        controller.request_shutdown();

        assert!(wake_flag.woken.load(Ordering::SeqCst));
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn repeated_shutdown_requests_are_idempotent() {
        let (controller, signal) = remote_session_supervisor_shutdown_pair();
        controller.request_shutdown();
        controller.request_shutdown();

        let mut future = Box::pin(signal.into_shutdown());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn dropping_controller_without_request_leaves_signal_pending() {
        let (controller, signal) = remote_session_supervisor_shutdown_pair();
        let mut future = Box::pin(signal.into_shutdown());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        drop(controller);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
    }

    #[test]
    fn shutdown_future_matches_existing_supervisor_bound() {
        let (_controller, signal) = remote_session_supervisor_shutdown_pair();
        assert_send_static_shutdown_future(signal.into_shutdown());
    }

    #[test]
    fn startup_composition_constructs_executor_before_bind() {
        let events = RefCell::new(Vec::<&'static str>::new());

        let result = compose_endpoint_startup(
            7_u8,
            || {
                events.borrow_mut().push("executor");
                Ok::<_, &'static str>(11_u8)
            },
            |authority| {
                events.borrow_mut().push("bind");
                Ok::<_, (Box<u8>, &'static str)>((authority, 13_u8))
            },
        );

        assert_eq!(result, Ok((11_u8, (7_u8, 13_u8))));
        assert_eq!(*events.borrow(), vec!["executor", "bind"]);
    }

    #[test]
    fn executor_failure_retains_authority_and_prevents_bind_attempt() {
        let bind_called = Cell::new(false);

        let result = compose_endpoint_startup(
            17_u8,
            || Err::<u8, _>("executor failed"),
            |authority| {
                bind_called.set(true);
                Ok::<_, (Box<u8>, &'static str)>((authority, 19_u8))
            },
        );

        assert!(!bind_called.get());
        assert_eq!(
            result,
            Err((
                Box::new(17_u8),
                EndpointStartupCompositionError::Executor("executor failed")
            ))
        );
    }

    #[test]
    fn bind_failure_retains_exact_authority_without_retry() {
        let bind_calls = Cell::new(0_u8);

        let result = compose_endpoint_startup(
            23_u8,
            || Ok::<_, &'static str>(29_u8),
            |authority| {
                bind_calls.set(bind_calls.get() + 1);
                Err::<(u8, u8), _>((Box::new(authority), "bind failed"))
            },
        );

        assert_eq!(bind_calls.get(), 1);
        assert_eq!(
            result,
            Err((
                Box::new(23_u8),
                EndpointStartupCompositionError::Transport("bind failed")
            ))
        );
    }

    #[test]
    fn supplied_executor_is_preserved_through_successful_fake_bind() {
        let bind_calls = Cell::new(0_u8);

        let result = compose_endpoint_bind_with_executor(31_u8, 37_u8, |authority| {
            bind_calls.set(bind_calls.get() + 1);
            Ok::<_, (Box<u8>, &'static str)>((authority, 41_u8))
        });

        assert_eq!(bind_calls.get(), 1);
        assert_eq!(result, Ok((31_u8, (37_u8, 41_u8))));
    }

    #[test]
    fn supplied_executor_bind_failure_retains_exact_authority_without_retry() {
        let bind_calls = Cell::new(0_u8);

        let result = compose_endpoint_bind_with_executor(43_u8, 47_u8, |authority| {
            bind_calls.set(bind_calls.get() + 1);
            Err::<(u8, u8), _>((Box::new(authority), "bind failed"))
        });

        assert_eq!(bind_calls.get(), 1);
        assert_eq!(result, Err((Box::new(47_u8), "bind failed")));
    }

    #[test]
    fn production_constructors_and_bootstrap_have_exact_selected_shapes() {
        assert_constructor_signature(
            RemoteSessionEndpointLifecycleRuntime::bind_from_systemd_credentials,
        );
        assert_same_executor_constructor_signature(
            RemoteSessionEndpointLifecycleRuntime::bind_with_executor_from_systemd_credentials,
        );
        assert_reachability_bootstrap_signature(
            RemoteSessionExecutorRuntime::bootstrap_reachability_authority_from_systemd_credentials,
        );
        assert_bound_addr_signature(RemoteSessionEndpointLifecycleRuntime::bound_addr);
    }
}
