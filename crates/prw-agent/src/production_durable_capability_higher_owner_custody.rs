//! Dormant process-level custody for the production durable capability authority.
//!
//! C03e-LD materializes only the C03e-LC-selected modular source layout for the C03e-LB
//! higher-owner custody semantics. One existing production/reachability/requester-rendezvous
//! aggregate is retained by value beside exactly one outer `Arc<ProductionDurableCapabilityAuthority>`.
//! Construction performs only the selected ownership adaptation and activates no runtime behavior.

#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;

use prw_core::DeviceId;
use prw_policy::{PolicyEvaluator, ProductionRemoteCapabilityDenyAllPolicy};
use prw_registry::WorkspaceDeviceRegistry;
use prw_remote_bridge::{
    CapabilityDispatcher,
    requester_rendezvous_in_memory_provider::{
        InMemoryRequesterRendezvousAuthorityProvider, RequesterRendezvousLifecycleError,
    },
};
use prw_session::{
    SessionAuthenticationService,
    prwa_verifier_source::{
        PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS, PrwaVerifierSourceError,
        current_prwa_verifier_unix_seconds,
    },
};
use tokio::{runtime::Builder, sync::mpsc};

use crate::candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner;
use crate::candidate_publication_requester_rendezvous_start_intent::policy_source::BoundedRequesterRendezvousStartPolicySource;
use crate::linux_bootstrap::{
    LinuxAgentBootstrapStartFailure, LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionReachabilityRemoteProcessOperationInputs,
    LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs,
    LinuxAgentProductionRemoteProcessInputPopulationError,
    LinuxAgentRemoteApplicationLeasePolicySourceError,
    LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError,
    LinuxAgentRemotePeerDeviceSourceError,
    LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError,
    LinuxAgentRemoteSupervisorShutdownPublisher,
    linux_agent_production_reachability_requester_rendezvous_remote_process_operation,
    linux_agent_production_reachability_requester_rendezvous_remote_process_operation_with_production_durable_capability_projection,
    linux_agent_remote_process_operation_inputs_from_production_worker_limit,
    load_linux_agent_remote_application_lease_policy_from_env,
    load_linux_agent_remote_expected_device_scheduling_consumption_max_records_from_env,
    load_linux_agent_remote_peer_device_id_from_env,
    load_linux_agent_remote_requester_rendezvous_max_records_from_env,
    run_with_remote_process_companion,
};
use crate::production_durable_registry_custody_bootstrap::{
    ProductionDurablePeerCapabilityAuthorityPopulationError,
    bootstrap_production_peer_and_durable_capability_authority_from_systemd_credentials,
};
use crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority;
use crate::remote_session_capability_runtime::{
    RemoteSessionAdmissionTimingFailure, RemoteSessionAdmissionTimingSourceError,
    RemoteSessionApplicationLeasePolicy, RemoteSessionExpectedDeviceAdmissionRejection,
    RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionProductionPreAjTiming,
    RemoteSessionRealAdmissionError, RemoteSessionRealAdmissionTiming,
    RemoteSessionRegisteredWorkerCompletion, RemoteSessionRepeatedAdmissionFailure,
    RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection,
    SharedCurrentCapabilityAuthority, SharedRequesterRendezvousAuthority,
};

/// Non-cloneable dormant pre-requester owner for one same-custody production reachability pair.
#[allow(
    dead_code,
    reason = "C03e-MB materializes the MA-selected pre-requester same-custody ownership carrier before separately gated population and requester/rendezvous join"
)]
pub(crate) struct LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
> {
    production_inputs:
        LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    capability_authority: ProductionDurableCapabilityAuthority,
}

/// Bounded Agent-local failure while populating one pre-requester same-custody durable owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-MD materializes the MC-selected bounded population error before separately gated caller wiring"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError {
    /// Existing production worker-limit/bind input population failed.
    RemoteProcessInputs(LinuxAgentProductionRemoteProcessInputPopulationError),
    /// Fixed process logical-peer source failed before durable-registry/provider work.
    PeerDeviceSource(LinuxAgentRemotePeerDeviceSourceError),
    /// Single-custody peer plus durable capability-authority population failed.
    SameCustodyPeerCapabilityAuthority(ProductionDurablePeerCapabilityAuthorityPopulationError),
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RemoteProcessInputs(_) => {
                "production durable reachability remote-process input population failed"
            }
            Self::PeerDeviceSource(_) => {
                "production durable reachability peer-device source failed"
            }
            Self::SameCustodyPeerCapabilityAuthority(_) => {
                "production durable reachability same-custody peer capability authority population failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RemoteProcessInputs(error) => Some(error),
            Self::PeerDeviceSource(error) => Some(error),
            Self::SameCustodyPeerCapabilityAuthority(error) => Some(error),
        }
    }
}

impl From<LinuxAgentProductionRemoteProcessInputPopulationError>
    for LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentProductionRemoteProcessInputPopulationError) -> Self {
        Self::RemoteProcessInputs(error)
    }
}

impl From<LinuxAgentRemotePeerDeviceSourceError>
    for LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentRemotePeerDeviceSourceError) -> Self {
        Self::PeerDeviceSource(error)
    }
}

impl From<ProductionDurablePeerCapabilityAuthorityPopulationError>
    for LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError
{
    fn from(error: ProductionDurablePeerCapabilityAuthorityPopulationError) -> Self {
        Self::SameCustodyPeerCapabilityAuthority(error)
    }
}

/// Populates one dormant pre-requester durable owner from existing production sources.
///
/// The helper first reuses the existing production worker-limit/bind input population. Only after
/// that succeeds does it load the fixed logical peer `DeviceId`. Only after both stages succeed does
/// it invoke the C03e-LZ same-custody helper exactly once. The returned current peer and raw durable
/// capability authority therefore share one exact durable-registry/runtime-custody lineage. The peer
/// is moved once into the existing production reachability owner, and that owner plus the exact raw
/// authority are moved directly into the C03e-MB pre-requester owner.
///
/// This helper does not invoke the legacy production peer helper or JR worker+peer composite helper,
/// performs no second durable-registry/provider bootstrap, constructs no requester/rendezvous
/// custody, wraps no durable authority in `Arc`, adds no invocation site, and activates no runtime,
/// listener, readiness, endpoint or network behavior.
///
/// # Errors
///
/// Fails before the next stage on production worker-limit/bind population failure, logical-peer
/// source failure, or same-custody peer/capability-authority population failure. Underlying errors
/// remain available through the bounded composite source chain. No retry, fallback, alternate peer,
/// cache, synthetic authority, degraded authority or partial owner is returned.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-MD materializes the MC-selected dormant pre-requester same-custody owner population before separately gated requester/rendezvous and caller wiring"
)]
pub(crate) async fn linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    capability_authority: SharedCurrentCapabilityAuthority<P>,
    session_authentication: SessionAuthenticationService,
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
> {
    let remote_process_inputs =
        linux_agent_remote_process_operation_inputs_from_production_worker_limit(
            capability_authority,
            session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )?;
    let device_id = load_linux_agent_remote_peer_device_id_from_env()?;
    let (peer, capability_authority) =
        bootstrap_production_peer_and_durable_capability_authority_from_systemd_credentials(
            device_id,
        )
        .await?;
    let production_inputs = LinuxAgentProductionReachabilityRemoteProcessOperationInputs::new(
        peer,
        remote_process_inputs,
    );
    Ok(
        LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs {
            production_inputs,
            capability_authority,
        },
    )
}

/// Populates one dormant pre-requester durable owner with one fresh process-local session service.
///
/// This wrapper constructs exactly one existing empty fail-closed [`SessionAuthenticationService`]
/// and moves that exact value by value into the existing C03e-MD production population helper
/// exactly once. It does not begin a session, generate challenge randomness, select authentication
/// timing, construct a service per admission/worker/session, clone or share the service, choose
/// capability-policy provenance, create an expected-request channel, construct requester/rendezvous
/// custody, add an invocation site, or activate runtime/listener/network behavior.
///
/// # Errors
///
/// Returns the existing C03e-MD population error unchanged. Service construction itself is
/// infallible, so this wrapper adds no error variant, retry, fallback or recovery path.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-MF materializes the ME-selected dormant session-authentication population wrapper before separately gated remaining production provenance and caller wiring"
)]
pub(crate) async fn linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources_with_session_authentication<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    capability_authority: SharedCurrentCapabilityAuthority<P>,
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
> {
    let session_authentication = SessionAuthenticationService::new();
    linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources(
        capability_authority,
        session_authentication,
        expected_requests,
        admission_timing,
        on_completion,
        on_rejection,
        on_admission_failure,
    )
    .await
}

/// Populates one dormant pre-requester durable owner with a fail-closed current capability authority.
///
/// This wrapper constructs exactly one empty [`WorkspaceDeviceRegistry`] and exactly one
/// [`ProductionRemoteCapabilityDenyAllPolicy`], composes those exact values into one
/// [`SharedCurrentCapabilityAuthority`], and moves that exact authority by value into the existing
/// C03e-MF session-authentication population wrapper exactly once. The resulting current authority
/// therefore contains no populated membership/device state and grants no represented capability.
///
/// This helper does not hydrate or synchronize the current registry, load an allow-bearing policy,
/// adapt durable-registry custody into current authority, create an expected-request channel,
/// select admission timing or callbacks, construct requester/rendezvous custody, add an invocation
/// site, or activate runtime/listener/network behavior.
///
/// # Errors
///
/// Returns the existing C03e-MD population error unchanged. Empty-registry, deny-all-policy and
/// shared-current-authority construction are infallible, so no new error variant, retry, fallback or
/// recovery path is added.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-MH materializes the MG-selected dormant fail-closed current capability-authority population wrapper before separately gated remaining production provenance and caller wiring"
)]
pub(crate) async fn linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources_with_fail_closed_current_capability_authority<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<
        ProductionRemoteCapabilityDenyAllPolicy,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
> {
    let capability_authority = SharedCurrentCapabilityAuthority::new(
        WorkspaceDeviceRegistry::new(),
        ProductionRemoteCapabilityDenyAllPolicy,
    );
    linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources_with_session_authentication(
        capability_authority,
        expected_requests,
        admission_timing,
        on_completion,
        on_rejection,
        on_admission_failure,
    )
    .await
}

/// Non-cloneable dormant custody joining one populated pre-requester durable owner with one exact
/// fail-closed requester/rendezvous start policy source.
#[allow(
    dead_code,
    reason = "C03e-MJ materializes the MI-selected private empty requester-policy custody before separately gated provider/runtime join"
)]
pub(crate) struct LinuxAgentProductionDurableReachabilityRequesterPolicyRemoteProcessOperationInputs<
    D,
    T,
    F,
    C,
    R,
    E,
> {
    production_inputs: LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<
        ProductionRemoteCapabilityDenyAllPolicy,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    requester_policy_source: BoundedRequesterRendezvousStartPolicySource,
}

/// Populates one dormant pre-requester owner plus one explicit empty requester policy source.
///
/// This wrapper first invokes the existing C03e-MH requester-policy population exactly once. Only
/// after that succeeds does it construct exactly one empty [`BoundedRequesterRendezvousStartPolicySource`]
/// through `Default`. The exact successful MH owner and exact empty source are then moved by value
/// into one private non-cloneable carrier. No requester binding is added and no policy lookup is
/// performed during population.
///
/// This helper constructs no requester/rendezvous provider or runtime owner, selects no provider
/// capacity, performs no provider registration, constructs no final requester/rendezvous aggregate,
/// adds no invocation site, and activates no runtime/listener/network behavior.
///
/// # Errors
///
/// Returns the existing C03e-MD population error unchanged. Empty requester-policy source
/// construction is infallible, so this wrapper adds no error variant, retry, fallback or recovery path.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-MJ materializes the MI-selected dormant empty requester-policy population wrapper before separately gated provider/runtime provenance and final join"
)]
pub(crate) async fn linux_agent_production_durable_reachability_requester_policy_remote_process_operation_inputs_from_production_sources<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentProductionDurableReachabilityRequesterPolicyRemoteProcessOperationInputs<
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
> {
    let production_inputs = linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources_with_fail_closed_current_capability_authority(
        expected_requests,
        admission_timing,
        on_completion,
        on_rejection,
        on_admission_failure,
    )
    .await?;
    let requester_policy_source = BoundedRequesterRendezvousStartPolicySource::default();
    Ok(
        LinuxAgentProductionDurableReachabilityRequesterPolicyRemoteProcessOperationInputs {
            production_inputs,
            requester_policy_source,
        },
    )
}

/// Populates one dormant requester/rendezvous runtime owner from one explicit caller-owned capacity.
///
/// The helper invokes the existing bounded in-memory provider constructor exactly once. Only after
/// successful provider construction does it move that exact provider by value into the existing
/// runtime-owner constructor exactly once. It performs no requester-policy evaluation, provider
/// registration, current-grant selection, cleanup, final requester/rendezvous join, caller wiring,
/// listener/readiness publication, or runtime/network activation.
///
/// # Errors
///
/// Returns the existing [`RequesterRendezvousLifecycleError`] unchanged. Zero capacity therefore
/// remains invalid through the provider constructor. No defaulting, clamping, retry, fallback,
/// alternate capacity, or partial runtime owner is produced.
#[allow(
    dead_code,
    reason = "C03e-ML materializes the MK-selected dormant explicit-capacity requester/rendezvous provider-runtime population before separately gated final join and caller wiring"
)]
pub(crate) fn linux_agent_production_requester_rendezvous_runtime_owner_from_explicit_nonzero_capacity(
    max_records: usize,
) -> Result<CandidatePublicationRequesterRendezvousRuntimeOwner, RequesterRendezvousLifecycleError>
{
    let provider = InMemoryRequesterRendezvousAuthorityProvider::new(max_records)?;
    Ok(CandidatePublicationRequesterRendezvousRuntimeOwner::new(
        provider,
    ))
}

/// Joins existing requester-policy and one preconstructed shared requester/rendezvous authority
/// into the existing production durable requester/rendezvous owner without invoking either lane.
#[allow(
    dead_code,
    reason = "C03e-NQ migrates the existing-custody join to one preconstructed shared requester authority before separately gated scheduling-authority derivation"
)]
pub(crate) fn linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_existing_custody<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    requester_policy_inputs:
        LinuxAgentProductionDurableReachabilityRequesterPolicyRemoteProcessOperationInputs<
            D, T, F, C, R, E,
        >,
    requester_rendezvous_authority: SharedRequesterRendezvousAuthority,
) -> LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
    ProductionRemoteCapabilityDenyAllPolicy,
    D,
    T,
    F,
    C,
    R,
    E,
> {
    let LinuxAgentProductionDurableReachabilityRequesterPolicyRemoteProcessOperationInputs {
        production_inputs,
        requester_policy_source,
    } = requester_policy_inputs;
    let LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs {
        production_inputs,
        capability_authority,
    } = production_inputs;
    let requester_rendezvous_inputs =
        LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs::new(
            production_inputs,
            requester_policy_source,
            requester_rendezvous_authority,
        );
    LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs::new(
        requester_rendezvous_inputs,
        capability_authority,
    )
}

/// Bounded Agent-local failure while populating one final dormant durable requester/rendezvous owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NQ extends the existing combined population error with one bounded shared-owner construction lane"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError
{
    /// Existing requester-policy production-source population failed.
    ProductionSources(LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError),
    /// Explicit requester/rendezvous runtime-owner construction failed.
    RequesterRendezvousRuntime(RequesterRendezvousLifecycleError),
    /// Shared requester/rendezvous scheduling-consumption owner construction failed.
    SharedRequesterRendezvousAuthorityConstruction,
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ProductionSources(_) => {
                "production durable requester/rendezvous source population failed"
            }
            Self::RequesterRendezvousRuntime(_) => {
                "production requester/rendezvous runtime population failed"
            }
            Self::SharedRequesterRendezvousAuthorityConstruction => {
                "production shared requester/rendezvous authority construction failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProductionSources(error) => Some(error),
            Self::RequesterRendezvousRuntime(error) => Some(error),
            Self::SharedRequesterRendezvousAuthorityConstruction => None,
        }
    }
}

impl From<LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
    ) -> Self {
        Self::ProductionSources(error)
    }
}

impl From<RequesterRendezvousLifecycleError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError
{
    fn from(error: RequesterRendezvousLifecycleError) -> Self {
        Self::RequesterRendezvousRuntime(error)
    }
}

/// Populates one final dormant durable requester/rendezvous owner from existing production sources
/// plus explicit requester-provider and scheduling-consumption capacities.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-NQ integrates explicit requester and scheduling capacities into one preconstructed shared authority without activating scheduling"
)]
pub(crate) async fn linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_production_sources_with_explicit_nonzero_capacity<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
    max_records: usize,
    expected_device_scheduling_consumption_max_records: usize,
) -> Result<
    LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        ProductionRemoteCapabilityDenyAllPolicy,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError,
> {
    let requester_policy_inputs =
        linux_agent_production_durable_reachability_requester_policy_remote_process_operation_inputs_from_production_sources(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
        .await?;
    let requester_rendezvous_runtime_owner =
        linux_agent_production_requester_rendezvous_runtime_owner_from_explicit_nonzero_capacity(
            max_records,
        )?;
    let requester_rendezvous_authority = SharedRequesterRendezvousAuthority::new(
        requester_rendezvous_runtime_owner,
        expected_device_scheduling_consumption_max_records,
    )
    .map_err(|_| {
        LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError::SharedRequesterRendezvousAuthorityConstruction
    })?;
    Ok(
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_existing_custody(
            requester_policy_inputs,
            requester_rendezvous_authority,
        ),
    )
}

/// Bounded failure while composing configured requester/rendezvous and scheduling-consumption
/// capacities with production population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NQ extends configured population with the independently selected scheduling-consumption capacity source"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    /// Fixed requester/rendezvous max-records source failed before production population.
    RequesterRendezvousMaxRecordsSource(LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError),
    /// Fixed expected-device scheduling-consumption max-records source failed before production population.
    ExpectedDeviceSchedulingConsumptionMaxRecordsSource(
        LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError,
    ),
    /// Existing explicit-capacity combined production population failed.
    Population(
        LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError,
    ),
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RequesterRendezvousMaxRecordsSource(_) => {
                "production requester/rendezvous max-records source failed"
            }
            Self::ExpectedDeviceSchedulingConsumptionMaxRecordsSource(_) => {
                "production expected-device scheduling-consumption max-records source failed"
            }
            Self::Population(_) => {
                "production durable requester/rendezvous configured population failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequesterRendezvousMaxRecordsSource(error) => Some(error),
            Self::ExpectedDeviceSchedulingConsumptionMaxRecordsSource(error) => Some(error),
            Self::Population(error) => Some(error),
        }
    }
}

impl From<LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    fn from(error: LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError) -> Self {
        Self::RequesterRendezvousMaxRecordsSource(error)
    }
}

impl From<LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    fn from(
        error: LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError,
    ) -> Self {
        Self::ExpectedDeviceSchedulingConsumptionMaxRecordsSource(error)
    }
}

impl
    From<
        LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError,
    > for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessInputPopulationError,
    ) -> Self {
        Self::Population(error)
    }
}

/// Populates one dormant durable requester/rendezvous owner from both fixed configured capacities.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-NQ materializes the selected requester-capacity then scheduling-capacity configured population order before separately gated scheduling-authority derivation"
)]
pub(crate) async fn linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_configured_production_sources<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        ProductionRemoteCapabilityDenyAllPolicy,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError,
> {
    let max_records = load_linux_agent_remote_requester_rendezvous_max_records_from_env()?;
    let expected_device_scheduling_consumption_max_records =
        load_linux_agent_remote_expected_device_scheduling_consumption_max_records_from_env()?;
    let inputs =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_production_sources_with_explicit_nonzero_capacity(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
            max_records,
            expected_device_scheduling_consumption_max_records,
        )
        .await?;
    Ok(inputs)
}

/// Non-cloneable dormant process-lifetime owner for one production durable capability authority.
pub(crate) struct LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
> {
    requester_rendezvous_inputs:
        LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
            P,
            D,
            T,
            F,
            C,
            R,
            E,
        >,
    capability_authority: Arc<ProductionDurableCapabilityAuthority>,
}

impl<P, D, T, F, C, R, E>
    LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >
{
    /// Consumes the existing production aggregate and one raw durable authority into dormant custody.
    #[must_use]
    pub(crate) fn new(
        requester_rendezvous_inputs:
            LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
                P,
                D,
                T,
                F,
                C,
                R,
                E,
            >,
        capability_authority: ProductionDurableCapabilityAuthority,
    ) -> Self {
        Self {
            requester_rendezvous_inputs,
            capability_authority: Arc::new(capability_authority),
        }
    }
}

/// Builds one dormant pre-requester higher-owner operation for the fallible verifier-time projection lane.
///
/// Factory construction consumes the existing same-custody pre-requester owner by value, builds
/// exactly one C03e-PZ production-reachability operation from its retained production inputs, and
/// keeps the exact raw durable capability authority captured by the returned one-shot closure.
/// The authority is released only after the delegated lower operation returns.
///
/// This wrapper performs no authority clone or `Arc` adaptation, durable authorization, verifier-time
/// provider invocation, expected-request construction, requester/rendezvous join, callback remapping,
/// companion assembly, second runtime/teardown, readiness publication, or executable activation.
#[allow(
    dead_code,
    reason = "C03e-QB materializes the QA-selected pre-requester higher-owner fallible verifier-time operation before separately gated companion and producer composition"
)]
pub(crate) fn linux_agent_production_durable_reachability_remote_process_operation_with_fallible_verifier_time_completion_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<
        P, D, T, F, C, R, E,
    >,
) -> impl FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
        + Send
        + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection,
        ) + Send
        + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    let LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs {
        production_inputs,
        capability_authority,
    } = inputs;
    let operation =
        crate::linux_bootstrap::linux_agent_production_reachability_remote_process_operation_with_fallible_verifier_time_completion_projection(
            production_inputs,
        );

    move |publisher| {
        operation(publisher);
        drop(capability_authority);
    }
}

/// Runs the existing Linux remote companion with one dormant pre-requester higher-owner
/// fallible-verifier-time operation.
///
/// This crate-private assembly consumes exactly one already-typed pre-requester same-custody input
/// aggregate by value. It constructs the existing C03e-QB higher-owner fallible-verifier-time
/// one-shot operation exactly once and passes that exact operation directly to the existing generic
/// Linux remote-companion runner exactly once. It adds no verifier-time provider sampling,
/// expected-request construction, requester/rendezvous join, durable authorization, callback
/// remapping, configured-source population, executable invocation site or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-QD materializes the QC-selected dormant higher-owner fallible-verifier-time companion assembly before separately gated configured-source and executable caller composition"
)]
pub(crate) fn run_with_production_durable_reachability_remote_process_companion_with_fallible_verifier_time_completion_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionDurableReachabilityRemoteProcessOperationInputs<
        P, D, T, F, C, R, E,
    >,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
        + Send
        + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection,
        ) + Send
        + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    let operation =
        linux_agent_production_durable_reachability_remote_process_operation_with_fallible_verifier_time_completion_projection(
            inputs,
        );
    run_with_remote_process_companion(operation)
}

/// Bounded failure while composing fail-closed production-source population with the existing
/// higher-owner fallible-verifier-time companion assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-QF materializes the QE-selected two-stage production-source population companion error before separately gated expected-request, verifier-time provider, dispatcher and executable caller composition"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError
{
    /// Existing fail-closed production-source population failed before companion assembly.
    Population(LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError),
    /// Existing higher-owner Linux remote-companion assembly failed after population success.
    Bootstrap(LinuxAgentBootstrapStartFailure),
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Population(_) => {
                "production durable reachability fallible-verifier-time population failed before companion assembly"
            }
            Self::Bootstrap(_) => {
                "production durable reachability fallible-verifier-time companion assembly failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Population(error) => Some(error),
            Self::Bootstrap(_) => None,
        }
    }
}

impl From<LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError>
    for LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRemoteProcessInputPopulationError,
    ) -> Self {
        Self::Population(error)
    }
}

impl From<LinuxAgentBootstrapStartFailure>
    for LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError
{
    fn from(error: LinuxAgentBootstrapStartFailure) -> Self {
        Self::Bootstrap(error)
    }
}

/// Populates one fail-closed pre-requester higher-owner input and runs the existing fallible-verifier-time companion.
///
/// The helper invokes the existing C03e-MH production-source population exactly once and awaits it
/// exactly once. Population failure short-circuits before C03e-QD. Only after successful population
/// does it move the exact returned higher-owner input by value into the existing C03e-QD
/// fallible-verifier-time companion assembly exactly once.
///
/// Expected-request receiver, admission timing and completion/rejection/failure callbacks remain
/// caller-supplied and are forwarded unchanged. This helper constructs no expected-request channel,
/// selects no dispatcher or verifier-time provider provenance, performs no verifier-time sampling,
/// joins no requester/rendezvous custody, invokes no durable authorization, remaps no callback,
/// adds no executable caller, and activates no listener/readiness/runtime/network behavior.
///
/// # Errors
///
/// Returns one bounded two-stage error. Existing production-source population failures are preserved
/// in `Population`. Existing Linux bootstrap-start failures are preserved in `Bootstrap`. No retry,
/// fallback, alternate population, synthetic owner, degraded authority, second companion or recovery
/// path is introduced.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-QF materializes the QE-selected dormant production-source population to higher-owner fallible-verifierTime companion composition before separately gated expected-request, verifier-time provider, dispatcher and executable caller wiring"
)]
pub(crate) async fn run_with_production_durable_reachability_remote_process_companion_with_fallible_verifier_time_completion_projection_from_production_sources<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityFallibleVerifierTimePopulationCompanionError,
>
where
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
        + Send
        + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection,
        ) + Send
        + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    let inputs =
        linux_agent_production_durable_reachability_remote_process_operation_inputs_from_production_sources_with_fail_closed_current_capability_authority(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
         )
        .await?;
    run_with_production_durable_reachability_remote_process_companion_with_fallible_verifier_time_completion_projection(
        inputs,
    )
    .map_err(Into::into)
}

/// Builds one dormant production operation that retains durable capability-authority custody.
#[allow(
    dead_code,
    reason = "C03e-LF materializes the LE-selected operation-boundary durable-authority lifetime custody before separately gated caller migration and propagation"
)]
pub(crate) fn linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
) -> impl FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(RemoteSessionRegisteredWorkerCompletion) + Send + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    let LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        requester_rendezvous_inputs,
        capability_authority,
    } = inputs;
    let operation =
        linux_agent_production_reachability_requester_rendezvous_remote_process_operation(
            requester_rendezvous_inputs,
        );

    move |publisher| {
        operation(publisher);
        drop(capability_authority);
    }
}

/// Builds one dormant higher-owner production operation that transfers durable-authority custody
/// into the existing production durable callback projection operation.
///
/// Factory construction performs ownership transfer only. The existing requester/rendezvous
/// production aggregate and the one retained outer durable-capability `Arc` are consumed by value
/// and delegated exactly once to the C03e-LT projection-capable Linux operation. No additional Arc
/// construction/clone, callback translation, provider I/O, endpoint bind, publication, retry,
/// reconnect, executable caller or runtime activation is added.
#[allow(
    dead_code,
    reason = "C03e-LV materializes the LU-selected dormant higher-owner callback projection caller migration before separately gated executable assembly"
)]
pub(crate) fn linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_with_production_durable_capability_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
) -> impl FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(DeviceId, RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection)
        + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
{
    let LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        requester_rendezvous_inputs,
        capability_authority,
    } = inputs;

    linux_agent_production_reachability_requester_rendezvous_remote_process_operation_with_production_durable_capability_projection(
        requester_rendezvous_inputs,
        capability_authority,
    )
}

/// Runs the existing Linux remote companion with one dormant higher-owner durable projection operation.
///
/// This crate-private assembly consumes only already-typed higher-owner inputs. It constructs the
/// existing C03e-LV projection-capable one-shot operation exactly once and passes that operation
/// directly to the existing generic Linux remote-companion runner exactly once. It adds no concrete
/// production input population, callback policy, executable invocation site or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-LX materializes the LW-selected dormant higher-owner projection companion assembly before separately gated executable caller population"
)]
pub(crate) fn run_with_production_durable_reachability_requester_rendezvous_remote_process_companion_with_production_durable_capability_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(DeviceId, RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection)
        + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
{
    let operation =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_with_production_durable_capability_projection(
            inputs,
        );
    run_with_remote_process_companion(operation)
}

/// Bounded failure while composing configured production population with higher-owner companion assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-MV materializes the MU-selected two-stage configured-population companion error before separately gated executable caller wiring"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError
{
    /// Existing configured production population failed before companion assembly.
    ConfiguredPopulation(
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError,
    ),
    /// Existing higher-owner Linux remote-companion assembly failed after population success.
    Bootstrap(LinuxAgentBootstrapStartFailure),
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConfiguredPopulation(_) => {
                "production durable requester/rendezvous configured population failed before companion assembly"
            }
            Self::Bootstrap(_) => {
                "production durable requester/rendezvous higher-owner companion assembly failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfiguredPopulation(error) => Some(error),
            Self::Bootstrap(_) => None,
        }
    }
}

impl From<LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError,
    ) -> Self {
        Self::ConfiguredPopulation(error)
    }
}

impl From<LinuxAgentBootstrapStartFailure>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError
{
    fn from(error: LinuxAgentBootstrapStartFailure) -> Self {
        Self::Bootstrap(error)
    }
}

/// Populates configured production inputs and assembles the existing dormant higher-owner companion.
///
/// The helper invokes the existing configured production-population helper exactly once and awaits
/// it exactly once. Population failure short-circuits before C03e-LX. Only after successful
/// population does it move the exact returned higher-owner inputs by value into the existing C03e-LX
/// projection-capable companion assembly exactly once. No alternate population path, retry,
/// fallback, synthetic channel, executable invocation site, listener/readiness publication, or
/// runtime/network activation is introduced.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-MV materializes dormant configured-population to higher-owner companion composition; C03e-NQ preserves that caller boundary unchanged"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_remote_process_companion_from_configured_production_sources<
    D,
    T,
    F,
    C,
    R,
    E,
>(
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
>
where
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(DeviceId, RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection)
        + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
{
    let inputs =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_configured_production_sources(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
        .await?;
    run_with_production_durable_reachability_requester_rendezvous_remote_process_companion_with_production_durable_capability_projection(
        inputs,
    )
    .map_err(Into::into)
}

/// Non-cloneable dormant capacity-one expected-device admission channel custody.
///
/// This owner creates exactly one bounded Tokio MPSC pair with capacity `1`, retains the exact
/// returned sender and receiver without cloning either endpoint, and performs no send, request
/// construction, dispatcher construction, scheduling-grant handling, receipt mapping, task spawn,
/// companion invocation or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-QL materializes only the QK-selected capacity-one expected-request channel and sole-sender custody before separately gated producer/send/receiver wiring"
)]
struct LinuxAgentProductionExpectedDeviceAdmissionChannel<D, T> {
    sender: mpsc::Sender<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    receiver: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
}

#[allow(clippy::type_complexity)]
impl<D, T> LinuxAgentProductionExpectedDeviceAdmissionChannel<D, T> {
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-QL materializes dormant construction before separately gated ownership transfer"
    )]
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self { sender, receiver }
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-QL exposes only consuming ownership decomposition before separately gated producer and QF invocation wiring"
    )]
    fn into_parts(
        self,
    ) -> (
        mpsc::Sender<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    ) {
        (self.sender, self.receiver)
    }
}

/// Integrates one dormant capacity-one expected-request channel with the configured higher owner.
///
/// This wrapper constructs exactly one existing capacity-one channel custody and consumes it exactly
/// once into its sole sender and receiver. The receiver moves once into the existing configured
/// production-source population path. Only after successful population does the returned aggregate
/// split into the exact requester/rendezvous inputs plus durable capability authority and move those
/// values, together with the sole sender, into the existing C03e-SF runtime-input-aware Linux seam.
/// No sender clone, spare endpoint, second channel, retry/requeue, dispatcher construction, verifier-
/// time sampling, executable caller, listener/readiness publication, or runtime/network activation is
/// added by this higher-owner seam.
///
/// # Errors
///
/// Configured population failures retain the existing `ConfiguredPopulation` classification and
/// short-circuit before C03e-SF. Existing Linux bootstrap-start failures retain the existing
/// `Bootstrap` classification. No new error type, retry, fallback, or recovery path is introduced.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-SJ materializes the SI-selected dormant higher-owner capacity-one expected-request channel integration before separately gated executable caller wiring"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources<
    F,
    C,
    R,
    E,
>(
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
>
where
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
            >,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
{
    let expected_request_channel = LinuxAgentProductionExpectedDeviceAdmissionChannel::<
        crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
    >::new();
    let (expected_request_sender, expected_requests) = expected_request_channel.into_parts();
    let inputs =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_configured_production_sources(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
        .await?;
    let LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        requester_rendezvous_inputs,
        capability_authority,
    } = inputs;
    crate::linux_bootstrap::run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion(
        requester_rendezvous_inputs,
        capability_authority,
        expected_request_sender,
    )
    .map_err(Into::into)
}

/// Integrates the selected fallible admission-timing source while keeping K outside population.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-SX preserves the S0 capacity-one population path and forwards K only after population succeeds"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources_with_fallible_admission_timing<
    F,
    C,
    R,
    E,
    Cause,
    K,
>(
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
    on_timing_failure: K,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
>
where
    Cause: std::error::Error + Send + 'static,
    F: FnMut(&DeviceId) -> Result<
            RemoteSessionRealAdmissionTiming,
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
        > + Send
        + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
            >,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
    K: FnMut(
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingFailure<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ) + Send
        + 'static,
{
    let expected_request_channel = LinuxAgentProductionExpectedDeviceAdmissionChannel::<
        crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
    >::new();
    let (expected_request_sender, expected_requests) = expected_request_channel.into_parts();
    let inputs =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_configured_production_sources(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
        .await?;
    let LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        requester_rendezvous_inputs,
        capability_authority,
    } = inputs;
    crate::linux_bootstrap::run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_with_fallible_admission_timing(
        requester_rendezvous_inputs,
        capability_authority,
        expected_request_sender,
        on_timing_failure,
    )
    .map_err(Into::into)
}

/// TE-selected configured higher-owner sibling propagating one already-validated lease policy by value.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-TF preserves configured population and K custody while forwarding the separate typed lease policy only after population succeeds"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources_with_pre_aj_timing_and_application_lease_policy<
    F,
    C,
    R,
    E,
    Cause,
    K,
>(
    admission_timing: F,
    application_lease_policy: RemoteSessionApplicationLeasePolicy,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
    on_timing_failure: K,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
>
where
    Cause: std::error::Error + Send + 'static,
    F: FnMut(&DeviceId) -> Result<
            RemoteSessionProductionPreAjTiming,
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
        > + Send
        + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
            >,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
    K: FnMut(
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingFailure<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ) + Send
        + 'static,
{
    let expected_request_channel = LinuxAgentProductionExpectedDeviceAdmissionChannel::<
        crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
    >::new();
    let (expected_request_sender, expected_requests) = expected_request_channel.into_parts();
    let inputs =
        linux_agent_production_durable_reachability_requester_rendezvous_remote_process_operation_inputs_from_configured_production_sources(
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        )
        .await?;
    let LinuxAgentProductionDurableReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        requester_rendezvous_inputs,
        capability_authority,
    } = inputs;
    crate::linux_bootstrap::run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_with_pre_aj_timing_and_application_lease_policy(
        requester_rendezvous_inputs,
        capability_authority,
        application_lease_policy,
        expected_request_sender,
        on_timing_failure,
    )
    .map_err(Into::into)
}

/// TG-selected bounded failure for configured application-lease source custody above the TF sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-TH materializes the TG-selected source-versus-existing-companion custody without activating an executable caller"
)]
pub(crate) enum LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError
{
    /// Fixed application-lease policy source failed before any expected-request channel exists.
    ApplicationLeasePolicySource(LinuxAgentRemoteApplicationLeasePolicySourceError),
    /// Existing TF configured-population/bootstrap companion failed after source success.
    Companion(LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError),
}

impl std::fmt::Display
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ApplicationLeasePolicySource(_) => {
                "production application-lease policy source failed"
            }
            Self::Companion(_) => {
                "production configured application-lease companion failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ApplicationLeasePolicySource(error) => Some(error),
            Self::Companion(error) => Some(error),
        }
    }
}

impl From<LinuxAgentRemoteApplicationLeasePolicySourceError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError
{
    fn from(error: LinuxAgentRemoteApplicationLeasePolicySourceError) -> Self {
        Self::ApplicationLeasePolicySource(error)
    }
}

impl From<LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError>
    for LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
    ) -> Self {
        Self::Companion(error)
    }
}

/// Loads one configured application-lease policy, then delegates exactly once to the existing TF sibling.
///
/// Source acquisition and semantic policy validation happen before the TF sibling constructs the
/// expected-request channel or starts configured production population. Source failure therefore has
/// process-configuration custody and cannot invoke request-owned K or admission E callbacks.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-TH materializes the TG-selected configured-lease higher-owner source wrapper before separately gated executable caller activation"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources_with_pre_aj_timing_and_configured_application_lease_policy<
    F,
    C,
    R,
    E,
    Cause,
    K,
>(
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
    on_timing_failure: K,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
>
where
    Cause: std::error::Error + Send + 'static,
    F: FnMut(&DeviceId) -> Result<
            RemoteSessionProductionPreAjTiming,
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
        > + Send
        + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
            >,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
    K: FnMut(
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingFailure<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ) + Send
        + 'static,
{
    let application_lease_policy = load_linux_agent_remote_application_lease_policy_from_env()?;
    run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources_with_pre_aj_timing_and_application_lease_policy(
        admission_timing,
        application_lease_policy,
        on_completion,
        on_rejection,
        on_admission_failure,
        on_timing_failure,
    )
    .await
    .map_err(Into::into)
}

/// Builds the selected fresh challenge-only pre-AJ timing from one verifier-clock observation.
fn production_remote_session_pre_aj_timing_from_verifier_clock_with<Clock>(
    mut verifier_clock: Clock,
) -> Result<
    RemoteSessionProductionPreAjTiming,
    RemoteSessionAdmissionTimingSourceError<PrwaVerifierSourceError>,
>
where
    Clock: FnMut() -> Result<u64, PrwaVerifierSourceError>,
{
    let issued_at_unix_seconds =
        verifier_clock().map_err(RemoteSessionAdmissionTimingSourceError::Acquisition)?;
    let expires_at_unix_seconds = issued_at_unix_seconds
        .checked_add(PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS)
        .ok_or(RemoteSessionAdmissionTimingSourceError::ArithmeticOverflow)?;
    Ok(RemoteSessionProductionPreAjTiming::new(
        issued_at_unix_seconds..expires_at_unix_seconds,
    ))
}

/// Samples the selected server-local verifier clock once for one eligible pre-AJ challenge window.
fn production_remote_session_pre_aj_timing_from_verifier_clock(
    expected_device_id: &DeviceId,
) -> Result<
    RemoteSessionProductionPreAjTiming,
    RemoteSessionAdmissionTimingSourceError<PrwaVerifierSourceError>,
> {
    let _ = expected_device_id;
    production_remote_session_pre_aj_timing_from_verifier_clock_with(
        current_prwa_verifier_unix_seconds,
    )
}

/// Terminally consumes one exact pre-AJ timing failure and its untouched request.
#[allow(clippy::type_complexity)]
fn dispose_production_remote_session_admission_timing_failure(
    failure: RemoteSessionAdmissionTimingFailure<
        crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, PrwaVerifierSourceError>,
        RemoteSessionAdmissionTimingSourceError<PrwaVerifierSourceError>,
    >,
) {
    let (_error, _request) = failure.into_parts();
}

/// Terminally consumes one bounded real-admission failure observation after lower cleanup custody.
fn dispose_production_remote_session_real_admission_failure(
    expected_device_id: DeviceId,
    error: RemoteSessionRealAdmissionError,
) {
    let (_expected_device_id, _error) = (expected_device_id, error);
}

/// Binds the TI-selected concrete F/E/K helpers while leaving C/R policy hooks caller supplied.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-TJ materializes only the TI-selected caller-ready adapter before separately gated async execution ownership and executable activation"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_timing_and_failure_custody<
    C,
    R,
>(
    on_completion: C,
    on_rejection: R,
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
>
where
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<u64, PrwaVerifierSourceError>,
            >,
        ) + Send
        + 'static,
{
    run_with_production_durable_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_from_configured_production_sources_with_pre_aj_timing_and_configured_application_lease_policy(
        production_remote_session_pre_aj_timing_from_verifier_clock,
        on_completion,
        on_rejection,
        dispose_production_remote_session_real_admission_failure,
        dispose_production_remote_session_admission_timing_failure,
    )
    .await
}

/// Terminally consumes one authority-free expected-device handoff completion observation.
fn dispose_production_remote_session_handoff_completion_observation(
    requester_device_id: DeviceId,
    observation: crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
) {
    let (_requester_device_id, _observation) = (requester_device_id, observation);
}

/// Terminally consumes one bounded expected-device rejection and its exact untouched request.
fn dispose_production_remote_session_expected_device_admission_rejection(
    reason: RemoteSessionExpectedDeviceAdmissionRejectionReason,
    request: RemoteSessionExpectedDeviceAdmissionRequest<
        crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, PrwaVerifierSourceError>,
    >,
) {
    let (_reason, _request) = (reason, request);
}

/// Binds the TK-selected terminal C/R dispositions into the existing TJ caller-ready adapter.
#[allow(
    clippy::future_not_send,
    dead_code,
    reason = "C03e-TL materializes the TK-selected no-argument async composition before separately gated executable activation"
)]
pub(crate) async fn run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_disposition(
) -> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
>{
    run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_timing_and_failure_custody(
        dispose_production_remote_session_handoff_completion_observation,
        dispose_production_remote_session_expected_device_admission_rejection,
    )
    .await
}

/// Bounded top-level failure for the TK-selected caller-owned async runtime driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-TL materializes the TK-selected executable-custody failure family before separately gated main.rs activation"
)]
pub(crate) enum LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError {
    /// Dedicated caller-owned current-thread Tokio runtime construction failed before polling.
    RuntimeConstruction,
    /// Existing TJ/TH configured application-lease companion failed after runtime construction.
    Companion(
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
    ),
}

impl std::fmt::Display
    for LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RuntimeConstruction => {
                "production configured application-lease async runtime construction failed"
            }
            Self::Companion(_) => {
                "production configured application-lease selected companion failed"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RuntimeConstruction => None,
            Self::Companion(error) => Some(error),
        }
    }
}

impl From<LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError>
    for LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError
{
    fn from(
        error: LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
    ) -> Self {
        Self::Companion(error)
    }
}

/// Drives one selected no-argument configured application-lease composition on one caller-owned runtime.
#[allow(
    dead_code,
    reason = "C03e-TL materializes only the TK-selected synchronous runtime driver; main.rs invocation remains separately gated"
)]
pub(crate) fn run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_executable_custody()
-> Result<
    LinuxAgentBootstrapWithRemoteReport,
    LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::RuntimeConstruction
        })?;

    runtime
        .block_on(
            run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_disposition(),
        )
        .map_err(Into::into)
}

#[cfg(test)]
mod selected_disposition_and_executable_custody_tests {
    use std::{error::Error as _, future::Future};

    use prw_core::DeviceId;
    use prw_session::prwa_verifier_source::PrwaVerifierSourceError;

    use super::{
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
        dispose_production_remote_session_expected_device_admission_rejection,
        dispose_production_remote_session_handoff_completion_observation,
        run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_disposition,
        run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_executable_custody,
    };
    use crate::linux_bootstrap::{
        LinuxAgentBootstrapWithRemoteReport, LinuxAgentRemoteApplicationLeasePolicySourceError,
    };
    use crate::remote_session_capability_runtime::{
        RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        RemoteSessionExpectedDeviceAdmissionRejectionReason,
        RemoteSessionExpectedDeviceAdmissionRequest,
    };

    #[test]
    #[allow(clippy::type_complexity)]
    fn selected_c_r_and_driver_signatures_are_exact() {
        let c: fn(
            DeviceId,
            RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) = dispose_production_remote_session_handoff_completion_observation;
        let r: fn(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<u64, PrwaVerifierSourceError>,
            >,
        ) = dispose_production_remote_session_expected_device_admission_rejection;
        let driver: fn() -> Result<
            LinuxAgentBootstrapWithRemoteReport,
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
        > = run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_executable_custody;

        let _ = (c, r, driver);
    }

    #[test]
    fn selected_no_argument_async_wrapper_has_exact_output_without_polling() {
        fn assert_future_shape<F>(future: F)
        where
            F: Future<
                Output = Result<
                    LinuxAgentBootstrapWithRemoteReport,
                    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
                >,
            >,
        {
            drop(future);
        }

        assert_future_shape(
            run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_disposition(),
        );
    }

    #[test]
    fn selected_driver_error_preserves_bounded_runtime_and_companion_custody() {
        let runtime =
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::RuntimeConstruction;
        assert!(runtime.source().is_none());

        let companion =
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::ApplicationLeasePolicySource(
                LinuxAgentRemoteApplicationLeasePolicySourceError::Missing,
            );
        let wrapped =
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::from(
                companion,
            );
        assert!(wrapped.source().is_some());
    }
}

#[cfg(test)]
mod selected_timing_and_failure_custody_tests {
    use prw_core::DeviceId;
    use prw_session::prwa_verifier_source::{
        PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS, PrwaVerifierSourceError,
    };

    use super::{
        dispose_production_remote_session_admission_timing_failure,
        dispose_production_remote_session_real_admission_failure,
        production_remote_session_pre_aj_timing_from_verifier_clock,
        production_remote_session_pre_aj_timing_from_verifier_clock_with,
    };
    use crate::remote_session_capability_runtime::{
        RemoteSessionAdmissionTimingFailure, RemoteSessionAdmissionTimingSourceError,
        RemoteSessionProductionPreAjTiming, RemoteSessionRealAdmissionError,
    };

    #[test]
    fn selected_pre_aj_timing_constructs_exact_locked_window_from_one_sample() {
        let mut calls = 0_u8;
        let timing = production_remote_session_pre_aj_timing_from_verifier_clock_with(|| {
            calls += 1;
            Ok(1_000)
        })
        .expect("deterministic verifier sample should construct pre-AJ timing");

        assert_eq!(calls, 1);
        assert_eq!(
            timing.into_challenge_validity_unix_seconds(),
            1_000..1_000 + PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS
        );
    }

    #[test]
    fn selected_pre_aj_timing_preserves_acquisition_error() {
        let error = production_remote_session_pre_aj_timing_from_verifier_clock_with(|| {
            Err(PrwaVerifierSourceError::VerifierTime)
        })
        .expect_err("verifier acquisition failure must fail closed");

        assert!(matches!(
            error,
            RemoteSessionAdmissionTimingSourceError::Acquisition(
                PrwaVerifierSourceError::VerifierTime
            )
        ));
    }

    #[test]
    fn selected_pre_aj_timing_maps_checked_expiry_overflow() {
        let error = production_remote_session_pre_aj_timing_from_verifier_clock_with(|| {
            Ok(u64::MAX - PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS + 1)
        })
        .expect_err("challenge expiry overflow must fail closed");

        assert!(matches!(
            error,
            RemoteSessionAdmissionTimingSourceError::ArithmeticOverflow
        ));
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn selected_helper_signatures_pin_exact_f_e_k_types() {
        let f: fn(
            &DeviceId,
        ) -> Result<
            RemoteSessionProductionPreAjTiming,
            RemoteSessionAdmissionTimingSourceError<PrwaVerifierSourceError>,
        > = production_remote_session_pre_aj_timing_from_verifier_clock;
        let e: fn(DeviceId, RemoteSessionRealAdmissionError) =
            dispose_production_remote_session_real_admission_failure;
        let k: fn(
            RemoteSessionAdmissionTimingFailure<
                crate::linux_bootstrap::LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<u64, PrwaVerifierSourceError>,
                RemoteSessionAdmissionTimingSourceError<PrwaVerifierSourceError>,
            >,
        ) = dispose_production_remote_session_admission_timing_failure;

        let _ = (f, e, k);
    }
}

#[cfg(test)]
mod configured_application_lease_policy_source_custody_tests {
    use std::error::Error as _;

    use super::{
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
    };
    use crate::linux_bootstrap::LinuxAgentRemoteApplicationLeasePolicySourceError;
    use crate::remote_session_capability_runtime::RemoteSessionApplicationLeasePolicyError;

    #[test]
    fn configured_application_lease_wrapper_error_preserves_source_and_companion_families() {
        fn assert_companion_conversion(
            convert: fn(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
            ) -> LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
        ) {
            let _ = convert;
        }

        let source =
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::from(
                LinuxAgentRemoteApplicationLeasePolicySourceError::Policy(
                    RemoteSessionApplicationLeasePolicyError::InvalidLifetime,
                ),
            );
        assert!(source.source().is_some());
        assert_eq!(
            source.to_string(),
            "production application-lease policy source failed"
        );
        assert_companion_conversion(
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::from,
        );
    }
}
