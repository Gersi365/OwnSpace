//! Narrow public Linux Agent binary-bootstrap facade.
//!
//! Phase 102 keeps the internal Linux lifecycle/readiness/signal/worker graph
//! crate-private. This module exposes only the fixed initial bootstrap profile,
//! bounded startup/terminal classifications, and one call into the already-
//! validated Phase 098 signal-aware runtime.

use std::{
    ffi::OsString,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use prw_connectivity::PeerConnectivityIdentity;
use prw_core::DeviceId;
use prw_network::PrivateDnsConfig;
use prw_policy::{BoundedLocalReadPolicy, PolicyEvaluator};
use prw_remote_bridge::{AuthorizedCapabilityRequest, BridgeCommand, CapabilityDispatcher};
use prw_session::SessionAuthenticationService;
use tokio::sync::mpsc;

use crate::candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner;
use crate::candidate_publication_requester_rendezvous_start_intent::policy_source::BoundedRequesterRendezvousStartPolicySource;
use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
use crate::linux_identity::production_lifecycle::LocalLinuxProductionLifecycleAssemblyError;
use crate::linux_identity::production_runtime_loop::LocalLinuxProductionRuntimeInputs;
use crate::linux_identity::production_runtime_types::{
    LocalLinuxProductionRuntimeCleanup, LocalLinuxProductionRuntimeConfig,
    LocalLinuxProductionRuntimeCounters,
};
use crate::linux_identity::signal_aware_runtime::{
    LocalLinuxSignalAwareRuntimeStartError, LocalLinuxSignalAwareRuntimeTerminalReason,
    run_signal_aware_linux_production_runtime_from_env_with_agent_status_management,
    run_signal_aware_linux_production_runtime_from_env_with_agent_status_management_and_companion,
    run_signal_aware_linux_production_runtime_from_env_with_companion,
};
use crate::linux_identity::termination_signal::{
    LocalLinuxTerminationSignal, LocalLinuxTerminationSignalMaskRestore,
    LocalLinuxTerminationSignalSourceCreateError,
};
use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::AgentInstanceLockError;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::{
    LocalAgentRuntimeState, LocalAgentStatusSnapshot, codec::encode_status_snapshot,
};
use crate::production_durable_capability_higher_owner_custody::{
    LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
    run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_executable_custody,
};
use crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority;
use crate::remote_session_capability_runtime::{
    RemoteSessionApplicationLeasePolicy, RemoteSessionApplicationLeasePolicyError,
    RemoteSessionEndpointLifecycleRuntime, RemoteSessionExecutorRuntime,
    RemoteSessionExpectedDeviceAdmissionRejection,
    RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest,
    RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection,
    RemoteSessionProductionPreAjTiming, RemoteSessionRealAdmissionError,
    RemoteSessionRealAdmissionTiming, RemoteSessionRegisteredWorkerCompletion,
    RemoteSessionRepeatedAdmissionFailure,
    RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection,
    RemoteSessionSupervisorShutdownController, SharedCurrentCapabilityAuthority,
    SharedRequesterRendezvousAuthority,
    remote_session_process_lifecycle_control::{
        RemoteSessionProcessControllerFinalization, RemoteSessionProcessLifecycleFinalization,
        RemoteSessionProcessLifecycleOwner, RemoteSessionProcessLifecycleSpawnError,
        RemoteSessionProcessThreadFinalization, RemoteSessionSupervisorShutdownPublish,
        RemoteSessionSupervisorShutdownPublisher,
    },
};

/// Dormant production status-snapshot custody selected by C03e-QI.
///
/// This private source captures only the exact immutable status snapshot already owned by the
/// production runtime-input bundle. It does not mint a second snapshot, inspect host/runtime state,
/// or own requester, admission, channel, endpoint, or retry authority.
#[allow(
    dead_code,
    reason = "C03e-QJ materializes the QI-selected dormant dispatcher-source custody before separately gated producer/channel composition"
)]
struct LinuxAgentProductionRemoteCapabilityDispatcherSource {
    status_snapshot: LocalAgentStatusSnapshot,
}

impl LinuxAgentProductionRemoteCapabilityDispatcherSource {
    #[allow(
        dead_code,
        reason = "C03e-QJ captures only the existing production runtime-input snapshot before separately gated producer/channel composition"
    )]
    const fn from_runtime_inputs(inputs: LocalLinuxProductionRuntimeInputs<'_>) -> Self {
        Self {
            status_snapshot: inputs.status_snapshot(),
        }
    }

    #[allow(
        dead_code,
        reason = "C03e-QJ constructs only a fresh existing NB dispatcher before separately gated request construction/send composition"
    )]
    const fn new_dispatcher(&self) -> LinuxAgentProductionRemoteCapabilityDispatcher {
        LinuxAgentProductionRemoteCapabilityDispatcher::new(self.status_snapshot)
    }
}

/// Dormant producer-owned dispatcher factory selected by C03e-SA.
#[allow(
    dead_code,
    reason = "C03e-SB captures the existing dispatcher source before separately gated producer/channel composition"
)]
fn linux_agent_production_remote_capability_dispatcher_factory_from_runtime_inputs(
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
) -> impl FnMut() -> LinuxAgentProductionRemoteCapabilityDispatcher + use<> {
    let source = LinuxAgentProductionRemoteCapabilityDispatcherSource::from_runtime_inputs(inputs);
    move || source.new_dispatcher()
}

/// Dormant owned status-only adapter selected by C03e-NA.
#[allow(
    dead_code,
    reason = "C03e-NB materializes the owned dispatcher before separately gated caller composition"
)]
pub(crate) struct LinuxAgentProductionRemoteCapabilityDispatcher {
    status_snapshot: LocalAgentStatusSnapshot,
}

impl LinuxAgentProductionRemoteCapabilityDispatcher {
    #[allow(
        dead_code,
        reason = "production dispatcher construction remains deferred after C03e-NB"
    )]
    pub(crate) const fn new(status_snapshot: LocalAgentStatusSnapshot) -> Self {
        Self { status_snapshot }
    }

    // Keep the pure command projection testable without constructing transport/session authority.
    #[allow(
        dead_code,
        reason = "C03e-NB command projection remains dormant until separately gated caller composition"
    )]
    fn dispatch_command(
        &self,
        command: &BridgeCommand,
    ) -> Result<Vec<u8>, LinuxAgentProductionRemoteCapabilityDispatchError> {
        match command {
            BridgeCommand::AgentStatus => Ok(encode_status_snapshot(self.status_snapshot).to_vec()),
            BridgeCommand::FileList(_)
            | BridgeCommand::FileStat(_)
            | BridgeCommand::FileCreate { .. }
            | BridgeCommand::DirectoryCreate(_)
            | BridgeCommand::UploadBegin(_)
            | BridgeCommand::UploadResume(_)
            | BridgeCommand::UploadChunk { .. }
            | BridgeCommand::UploadFinalize(_)
            | BridgeCommand::UploadAbort(_)
            | BridgeCommand::DownloadChunk { .. }
            | BridgeCommand::TerminalOpen { .. }
            | BridgeCommand::TerminalInput { .. }
            | BridgeCommand::TerminalResize { .. }
            | BridgeCommand::TerminalRead { .. }
            | BridgeCommand::TerminalClose(_)
            | BridgeCommand::ForwardOpen { .. }
            | BridgeCommand::ForwardClose(_) => {
                Err(LinuxAgentProductionRemoteCapabilityDispatchError::UnsupportedProviderFamily)
            }
        }
    }
}

/// Bounded zero-data failure for provider-backed commands outside the selected adapter surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NB dispatch errors remain dormant until separately gated caller composition"
)]
pub(crate) enum LinuxAgentProductionRemoteCapabilityDispatchError {
    UnsupportedProviderFamily,
}

impl std::fmt::Display for LinuxAgentProductionRemoteCapabilityDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("remote capability provider family unsupported")
    }
}

impl std::error::Error for LinuxAgentProductionRemoteCapabilityDispatchError {}

impl CapabilityDispatcher for LinuxAgentProductionRemoteCapabilityDispatcher {
    type Error = LinuxAgentProductionRemoteCapabilityDispatchError;

    fn dispatch(&mut self, request: &AuthorizedCapabilityRequest) -> Result<Vec<u8>, Self::Error> {
        self.dispatch_command(request.command())
    }
}

/// Fixed non-secret process configuration name for selecting the Agent executable lane.
pub const PRW_AGENT_EXECUTION_MODE_ENV: &str = prw_agent_configuration::PRW_AGENT_EXECUTION_MODE;

/// Explicit process-owned Agent executable lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentExecutionMode {
    /// Preserve the historical local-only Linux bootstrap lane.
    LocalOnly,
    /// Enter the configured-production remote companion lane.
    ConfiguredRemote,
}

/// Bounded failure while acquiring the explicit process execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinuxAgentExecutionModeSourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured representation is not one of the two exact selected tokens.
    InvalidValue,
}

impl std::fmt::Display for LinuxAgentExecutionModeSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "agent execution mode configuration missing",
            Self::NonUnicode => "agent execution mode configuration encoding invalid",
            Self::InvalidValue => "agent execution mode configuration invalid",
        })
    }
}

impl std::error::Error for LinuxAgentExecutionModeSourceError {}

fn parse_linux_agent_execution_mode_value(
    value: Option<OsString>,
) -> Result<LinuxAgentExecutionMode, LinuxAgentExecutionModeSourceError> {
    let value = value.ok_or(LinuxAgentExecutionModeSourceError::Missing)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentExecutionModeSourceError::NonUnicode)?;
    let mode = prw_agent_configuration::validate_agent_execution_mode(&value)
        .map_err(|_| LinuxAgentExecutionModeSourceError::InvalidValue)?;
    Ok(match mode {
        prw_agent_configuration::AgentExecutionMode::LocalOnly => {
            LinuxAgentExecutionMode::LocalOnly
        }
        prw_agent_configuration::AgentExecutionMode::ConfiguredRemote => {
            LinuxAgentExecutionMode::ConfiguredRemote
        }
    })
}

/// Loads the explicit process execution mode from the fixed non-secret environment source.
///
/// The value must be exactly `local_only` or `configured_remote`. This loader performs one
/// environment read and no trimming, case folding, aliasing, defaulting, inference, retry, or
/// fallback. It does not start either executable lane.
///
/// # Errors
///
/// Fails closed when the fixed source is missing, non-Unicode, or not one of the exact selected
/// values. Raw configured values are never included in the bounded error surface.
pub fn load_linux_agent_execution_mode_from_env()
-> Result<LinuxAgentExecutionMode, LinuxAgentExecutionModeSourceError> {
    parse_linux_agent_execution_mode_value(std::env::var_os(PRW_AGENT_EXECUTION_MODE_ENV))
}

/// Fixed non-secret process configuration name for the production remote endpoint bind address.
pub const PRW_REMOTE_BIND_ADDR_ENV: &str = prw_agent_configuration::PRW_REMOTE_BIND_ADDR;

/// Fixed non-secret process configuration name for the production remote peer logical device.
pub const PRW_REMOTE_PEER_DEVICE_ID_ENV: &str = prw_agent_configuration::PRW_REMOTE_PEER_DEVICE_ID;

/// Fixed non-secret process configuration name for the production remote active-worker bound.
pub const PRW_REMOTE_MAX_ACTIVE_WORKERS_ENV: &str =
    prw_agent_configuration::PRW_REMOTE_MAX_ACTIVE_WORKERS;

/// Fixed non-secret process configuration name for the production application-session lease lifetime.
#[allow(
    dead_code,
    reason = "C03e-TH materializes the TG-selected fixed application-lease environment source before separately gated executable caller activation"
)]
pub(crate) const PRW_REMOTE_APPLICATION_LEASE_SECONDS_ENV: &str =
    prw_agent_configuration::PRW_REMOTE_APPLICATION_LEASE_SECONDS;

/// Fixed non-secret process configuration name for the production requester/rendezvous record bound.
#[allow(
    dead_code,
    reason = "C03e-MR materializes the MQ-selected fixed requester/rendezvous max-records environment source before separately gated population composition"
)]
pub(crate) const PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS_ENV: &str =
    prw_agent_configuration::PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS;

/// Stable failure while acquiring or validating production remote bind-address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinuxAgentRemoteBindAddressSourceError {
    /// The fixed configuration value is absent or empty.
    Unavailable,
    /// The operating-system value is not valid Unicode.
    EncodingInvalid,
    /// The configured value is not an exact `SocketAddr`.
    SocketAddressInvalid,
    /// The parsed address is not eligible for this explicit bind-and-observe lane.
    AddressNotBindAdvertisable,
}

impl std::fmt::Display for LinuxAgentRemoteBindAddressSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "remote bind-address configuration unavailable",
            Self::EncodingInvalid => "remote bind-address configuration encoding invalid",
            Self::SocketAddressInvalid => "remote bind-address socket address invalid",
            Self::AddressNotBindAdvertisable => "remote bind-address is not bind-advertisable",
        })
    }
}

impl std::error::Error for LinuxAgentRemoteBindAddressSourceError {}

fn parse_linux_agent_remote_bind_addr_value(
    value: Option<OsString>,
) -> Result<SocketAddr, LinuxAgentRemoteBindAddressSourceError> {
    let value = value.ok_or(LinuxAgentRemoteBindAddressSourceError::Unavailable)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentRemoteBindAddressSourceError::EncodingInvalid)?;
    prw_agent_configuration::validate_remote_bind_addr(&value).map_err(|error| match error {
        prw_agent_configuration::RemoteBindAddressValidationError::Unavailable => {
            LinuxAgentRemoteBindAddressSourceError::Unavailable
        }
        prw_agent_configuration::RemoteBindAddressValidationError::SocketAddressInvalid => {
            LinuxAgentRemoteBindAddressSourceError::SocketAddressInvalid
        }
        prw_agent_configuration::RemoteBindAddressValidationError::AddressNotBindAdvertisable => {
            LinuxAgentRemoteBindAddressSourceError::AddressNotBindAdvertisable
        }
    })
}

/// Loads the explicitly configured production remote bind address from the process environment.
///
/// The fixed value is parsed directly as [`SocketAddr`]. This function performs no DNS lookup,
/// interface enumeration, route inspection, public-address discovery, socket bind or fallback.
/// Port `0` remains valid pre-bind so the retained endpoint may report the kernel-selected port
/// through the separately materialized bound-address observation after a successful bind.
///
/// Configuration validity is not identity, authentication, authorization, readiness, reachability,
/// publication provenance or public-routability evidence.
///
/// # Errors
///
/// Fails closed when the fixed configuration is absent/empty, non-Unicode, malformed, unspecified,
/// multicast, or IPv4 limited broadcast. The error classification does not expose the configured
/// value.
pub fn load_linux_agent_remote_bind_addr_from_env()
-> Result<SocketAddr, LinuxAgentRemoteBindAddressSourceError> {
    parse_linux_agent_remote_bind_addr_value(std::env::var_os(PRW_REMOTE_BIND_ADDR_ENV))
}

/// Stable failure while acquiring or validating the production remote peer logical device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinuxAgentRemotePeerDeviceSourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured value does not satisfy the existing `DeviceId` contract.
    InvalidIdentifier,
}

impl std::fmt::Display for LinuxAgentRemotePeerDeviceSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "remote peer-device configuration missing",
            Self::NonUnicode => "remote peer-device configuration encoding invalid",
            Self::InvalidIdentifier => "remote peer-device identifier invalid",
        })
    }
}

impl std::error::Error for LinuxAgentRemotePeerDeviceSourceError {}

fn parse_linux_agent_remote_peer_device_id_value(
    value: Option<OsString>,
) -> Result<DeviceId, LinuxAgentRemotePeerDeviceSourceError> {
    let value = value.ok_or(LinuxAgentRemotePeerDeviceSourceError::Missing)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentRemotePeerDeviceSourceError::NonUnicode)?;
    prw_agent_configuration::validate_remote_peer_device_id(&value)
        .map_err(|_| LinuxAgentRemotePeerDeviceSourceError::InvalidIdentifier)
}

/// Loads the explicitly configured production remote peer logical device from the process environment.
///
/// The exact Unicode value is passed directly to [`DeviceId::new`] without trimming,
/// normalization, case conversion, delimiter parsing or endpoint interpretation. This source
/// performs no registry/provider I/O and does not construct a [`PeerConnectivityIdentity`].
///
/// Configuration validity is process peer intent only; current same-device transport authority
/// remains the responsibility of the separately materialized durable-registry lookup.
///
/// # Errors
///
/// Fails closed when the fixed configuration is missing, non-Unicode, empty, or whitespace-only.
/// The bounded error surface does not expose the configured identifier value.
pub fn load_linux_agent_remote_peer_device_id_from_env()
-> Result<DeviceId, LinuxAgentRemotePeerDeviceSourceError> {
    parse_linux_agent_remote_peer_device_id_value(std::env::var_os(PRW_REMOTE_PEER_DEVICE_ID_ENV))
}

/// Stable failure while acquiring or validating the production remote active-worker bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinuxAgentRemoteMaxActiveWorkersSourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured value is not a strictly-positive target-`usize` ASCII decimal integer.
    InvalidValue,
}

impl std::fmt::Display for LinuxAgentRemoteMaxActiveWorkersSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "remote max-active-workers configuration missing",
            Self::NonUnicode => "remote max-active-workers configuration encoding invalid",
            Self::InvalidValue => "remote max-active-workers configuration invalid",
        })
    }
}

impl std::error::Error for LinuxAgentRemoteMaxActiveWorkersSourceError {}

fn parse_linux_agent_remote_max_active_workers_value(
    value: Option<OsString>,
) -> Result<NonZeroUsize, LinuxAgentRemoteMaxActiveWorkersSourceError> {
    let value = value.ok_or(LinuxAgentRemoteMaxActiveWorkersSourceError::Missing)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentRemoteMaxActiveWorkersSourceError::NonUnicode)?;
    prw_agent_configuration::validate_remote_max_active_workers(&value)
        .map_err(|_| LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
}

/// Loads the explicitly configured production remote active-worker bound from the process environment.
///
/// The exact Unicode value must contain ASCII decimal digits only and is converted fail-closed into
/// the existing [`NonZeroUsize`] input domain. This source performs no trimming, normalization,
/// fallback, retry, alternate-variable lookup, dynamic refresh, or host-derived auto-sizing.
///
/// # Errors
///
/// Fails closed when the fixed configuration is missing, non-Unicode, empty, malformed, zero, or
/// out of range for target `usize`. The bounded error surface does not expose the configured value.
pub fn load_linux_agent_remote_max_active_workers_from_env()
-> Result<NonZeroUsize, LinuxAgentRemoteMaxActiveWorkersSourceError> {
    parse_linux_agent_remote_max_active_workers_value(std::env::var_os(
        PRW_REMOTE_MAX_ACTIVE_WORKERS_ENV,
    ))
}

/// Bounded failure while acquiring or validating production application-lease configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-TH materializes the TG-selected bounded application-lease source error before separately gated executable caller activation"
)]
pub(crate) enum LinuxAgentRemoteApplicationLeasePolicySourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured representation is empty, malformed, or outside `u64`.
    InvalidValue,
    /// The parsed whole-second value violates the authoritative lease-policy bounds.
    Policy(RemoteSessionApplicationLeasePolicyError),
}

impl std::fmt::Display for LinuxAgentRemoteApplicationLeasePolicySourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "remote application-lease configuration missing",
            Self::NonUnicode => "remote application-lease configuration encoding invalid",
            Self::InvalidValue => "remote application-lease configuration invalid",
            Self::Policy(_) => "remote application-lease policy invalid",
        })
    }
}

impl std::error::Error for LinuxAgentRemoteApplicationLeasePolicySourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Missing | Self::NonUnicode | Self::InvalidValue => None,
        }
    }
}

#[allow(
    dead_code,
    reason = "C03e-TH materializes the TG-selected strict ASCII-decimal application-lease parser before separately gated executable caller activation"
)]
fn parse_linux_agent_remote_application_lease_policy_value(
    value: Option<OsString>,
) -> Result<RemoteSessionApplicationLeasePolicy, LinuxAgentRemoteApplicationLeasePolicySourceError>
{
    let value = value.ok_or(LinuxAgentRemoteApplicationLeasePolicySourceError::Missing)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentRemoteApplicationLeasePolicySourceError::NonUnicode)?;
    let lifetime_seconds = prw_agent_configuration::validate_remote_application_lease_seconds(
        &value,
    )
    .map_err(|error| match error {
        prw_agent_configuration::ApplicationLeaseValidationError::InvalidValue => {
            LinuxAgentRemoteApplicationLeasePolicySourceError::InvalidValue
        }
        prw_agent_configuration::ApplicationLeaseValidationError::OutOfRange => {
            LinuxAgentRemoteApplicationLeasePolicySourceError::Policy(
                RemoteSessionApplicationLeasePolicyError::InvalidLifetime,
            )
        }
    })?;
    RemoteSessionApplicationLeasePolicy::new(lifetime_seconds)
        .map_err(LinuxAgentRemoteApplicationLeasePolicySourceError::Policy)
}

/// Loads and validates the explicitly configured production application-session lease policy.
///
/// The exact Unicode value must contain ASCII decimal digits only. The parsed `u64` is passed
/// unchanged to [`RemoteSessionApplicationLeasePolicy::new`], which remains the sole semantic
/// authority for the accepted lifetime range. This source performs no trimming, fallback, retry,
/// alternate-variable lookup, cache, refresh, request construction, admission, or runtime activation.
///
/// # Errors
///
/// Fails closed when the fixed configuration is missing, non-Unicode, empty, malformed, outside
/// `u64`, or rejected by the authoritative application-lease policy constructor. Configured values
/// are not included in the bounded error surface.
#[allow(
    dead_code,
    reason = "C03e-TH materializes the TG-selected typed application-lease environment loader before separately gated executable caller activation"
)]
pub(crate) fn load_linux_agent_remote_application_lease_policy_from_env()
-> Result<RemoteSessionApplicationLeasePolicy, LinuxAgentRemoteApplicationLeasePolicySourceError> {
    parse_linux_agent_remote_application_lease_policy_value(std::env::var_os(
        PRW_REMOTE_APPLICATION_LEASE_SECONDS_ENV,
    ))
}

/// Bounded failure while acquiring or validating requester/rendezvous record capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-MR materializes the MQ-selected fixed requester/rendezvous max-records environment source before separately gated population composition"
)]
pub(crate) enum LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured value is empty, malformed, or outside target `usize`.
    InvalidValue,
}

impl std::fmt::Display for LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "remote requester/rendezvous max-records configuration missing",
            Self::NonUnicode => {
                "remote requester/rendezvous max-records configuration encoding invalid"
            }
            Self::InvalidValue => "remote requester/rendezvous max-records configuration invalid",
        })
    }
}

impl std::error::Error for LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError {}

#[allow(
    dead_code,
    reason = "C03e-MR materializes the MQ-selected strict ASCII-decimal requester/rendezvous max-records parser before separately gated population composition"
)]
fn parse_linux_agent_remote_requester_rendezvous_max_records_value(
    value: Option<OsString>,
) -> Result<usize, LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError> {
    let value = value.ok_or(LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::Missing)?;
    let value = value
        .into_string()
        .map_err(|_| LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::NonUnicode)?;
    prw_agent_configuration::validate_remote_requester_rendezvous_max_records(&value)
        .map_err(|_| LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::InvalidValue)
}

/// Loads the explicitly configured production requester/rendezvous record bound.
///
/// The exact Unicode value must contain ASCII decimal digits only and is converted fail-closed to
/// target `usize`. Zero is returned unchanged; the existing requester/rendezvous provider
/// constructor remains the sole semantic authority for the non-zero capacity invariant. This
/// source performs no trimming, fallback, retry, alternate-variable lookup, worker-limit aliasing,
/// cache, refresh, provider construction, population composition, or runtime activation.
///
/// # Errors
///
/// Fails closed when the fixed configuration is missing, non-Unicode, empty, malformed, or outside
/// target `usize`. The bounded error surface does not expose the configured value.
#[allow(
    dead_code,
    reason = "C03e-MR materializes the MQ-selected fixed requester/rendezvous max-records environment loader before separately gated population composition"
)]
pub(crate) fn load_linux_agent_remote_requester_rendezvous_max_records_from_env()
-> Result<usize, LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError> {
    parse_linux_agent_remote_requester_rendezvous_max_records_value(std::env::var_os(
        PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS_ENV,
    ))
}

/// Stable high-level terminal class exposed to the Agent binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentBootstrapTerminal {
    /// Programmatic monotonic shutdown completed the runtime loop.
    ProgrammaticShutdown,
    /// A handled `SIGTERM` initiated orderly shutdown.
    SigTerm,
    /// A handled `SIGINT` initiated orderly shutdown.
    SigInt,
    /// Signal-aware readiness failed closed.
    ReadinessFatal,
    /// Runtime scheduling failed under the locked fail-stop policy.
    RuntimeFatal,
}

impl LinuxAgentBootstrapTerminal {
    /// Returns the bounded token used by the initial stderr summary contract.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ProgrammaticShutdown => "programmatic_shutdown",
            Self::SigTerm => "sigterm",
            Self::SigInt => "sigint",
            Self::ReadinessFatal => "readiness_fatal",
            Self::RuntimeFatal => "runtime_fatal",
        }
    }

    const fn is_normal(self) -> bool {
        matches!(
            self,
            Self::ProgrammaticShutdown | Self::SigTerm | Self::SigInt
        )
    }
}

/// Listener/socket cleanup class exposed to the Agent binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentBootstrapCleanup {
    /// Exact validated listener/socket cleanup completed.
    Clean,
    /// Listener/socket cleanup failed after the terminal cause was established.
    Failed,
}

impl LinuxAgentBootstrapCleanup {
    /// Returns the bounded token used by the initial stderr summary contract.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Failed => "failed",
        }
    }
}

/// Signal-mask restoration evidence exposed to the Agent binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentBootstrapSignalMaskRestore {
    /// No signal mask had been changed on this failure path.
    NotApplicable,
    /// The exact prior calling-thread signal mask was restored.
    Restored,
    /// Restoring the prior calling-thread signal mask failed.
    Failed,
}

impl LinuxAgentBootstrapSignalMaskRestore {
    /// Returns the bounded token used by the initial stderr failure contract.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Restored => "restored",
            Self::Failed => "failed",
        }
    }
}

/// Memory-bounded process-lifetime counters exposed by the bootstrap facade.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinuxAgentBootstrapCounters {
    readiness_steps: u64,
    listener_armed_steps: u64,
    runtime_wakes: u64,
    wait_interruptions: u64,
    scheduling_attempts: u64,
    workers_registered: u64,
    worker_completions: u64,
    peer_rejections: u64,
}

impl LinuxAgentBootstrapCounters {
    /// Returns the number of readiness-step attempts.
    #[must_use]
    pub const fn readiness_steps(self) -> u64 {
        self.readiness_steps
    }

    /// Returns the number of listener-ready transitions.
    #[must_use]
    pub const fn listener_armed_steps(self) -> u64 {
        self.listener_armed_steps
    }

    /// Returns the number of wake-descriptor observations.
    #[must_use]
    pub const fn runtime_wakes(self) -> u64 {
        self.runtime_wakes
    }

    /// Returns the number of interrupted blocking waits.
    #[must_use]
    pub const fn wait_interruptions(self) -> u64 {
        self.wait_interruptions
    }

    /// Returns the number of bounded scheduling attempts.
    #[must_use]
    pub const fn scheduling_attempts(self) -> u64 {
        self.scheduling_attempts
    }

    /// Returns the number of registered local workers.
    #[must_use]
    pub const fn workers_registered(self) -> u64 {
        self.workers_registered
    }

    /// Returns the number of observed worker completions.
    #[must_use]
    pub const fn worker_completions(self) -> u64 {
        self.worker_completions
    }

    /// Returns the number of accepted peers rejected before worker registration.
    #[must_use]
    pub const fn peer_rejections(self) -> u64 {
        self.peer_rejections
    }
}

/// Final bounded report returned to the standalone Agent binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxAgentBootstrapReport {
    terminal: LinuxAgentBootstrapTerminal,
    counters: LinuxAgentBootstrapCounters,
    cleanup: LinuxAgentBootstrapCleanup,
    signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore,
}

impl LinuxAgentBootstrapReport {
    /// Returns the bounded high-level terminal class.
    #[must_use]
    pub const fn terminal(self) -> LinuxAgentBootstrapTerminal {
        self.terminal
    }

    /// Returns the memory-bounded process counters.
    #[must_use]
    pub const fn counters(self) -> LinuxAgentBootstrapCounters {
        self.counters
    }

    /// Returns the listener/socket cleanup result.
    #[must_use]
    pub const fn cleanup(self) -> LinuxAgentBootstrapCleanup {
        self.cleanup
    }

    /// Returns the signal-mask restoration result.
    #[must_use]
    pub const fn signal_mask_restore(self) -> LinuxAgentBootstrapSignalMaskRestore {
        self.signal_mask_restore
    }

    /// Returns whether the fixed initial process profile considers the report successful.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.terminal.is_normal()
            && matches!(self.cleanup, LinuxAgentBootstrapCleanup::Clean)
            && matches!(
                self.signal_mask_restore,
                LinuxAgentBootstrapSignalMaskRestore::Restored
            )
    }
}

/// Bounded startup-failure class exposed to the standalone Agent binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentBootstrapStartKind {
    /// Default private-DNS config could not project into the bounded local snapshot.
    PrivateDnsSnapshot,
    /// Safe `SIGTERM`/`SIGINT` signal source could not be established.
    SignalSource,
    /// `$XDG_RUNTIME_DIR` validation failed.
    RuntimeRoot,
    /// The fixed PRW runtime child could not be safely prepared.
    RuntimeDirectory,
    /// Another conforming Agent instance already holds the instance lock.
    AlreadyRunning,
    /// The instance lock failed for a reason other than an existing Agent.
    InstanceLock,
    /// The validated local Agent socket could not be bound.
    Bind,
    /// The bound socket could not enter listening state.
    Listen,
    /// The listener could not enter verified nonblocking accept-ready state.
    AcceptReady,
    /// The shared runtime wake descriptor could not be created.
    RuntimeWake,
}

impl LinuxAgentBootstrapStartKind {
    /// Returns the bounded token used by the initial stderr failure contract.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::PrivateDnsSnapshot => "private_dns_snapshot",
            Self::SignalSource => "signal_source",
            Self::RuntimeRoot => "runtime_root",
            Self::RuntimeDirectory => "runtime_directory",
            Self::AlreadyRunning => "already_running",
            Self::InstanceLock => "instance_lock",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::AcceptReady => "accept_ready",
            Self::RuntimeWake => "runtime_wake",
        }
    }
}

/// Startup failure plus any signal-mask rollback evidence available on that path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxAgentBootstrapStartFailure {
    kind: LinuxAgentBootstrapStartKind,
    signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore,
}

impl LinuxAgentBootstrapStartFailure {
    const fn new(
        kind: LinuxAgentBootstrapStartKind,
        signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore,
    ) -> Self {
        Self {
            kind,
            signal_mask_restore,
        }
    }

    /// Returns the bounded startup-failure class.
    #[must_use]
    pub const fn kind(self) -> LinuxAgentBootstrapStartKind {
        self.kind
    }

    /// Returns signal-mask rollback evidence for the startup-failure path.
    #[must_use]
    pub const fn signal_mask_restore(self) -> LinuxAgentBootstrapSignalMaskRestore {
        self.signal_mask_restore
    }
}

/// Bounded startup-failure class for the configured production remote executable facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentConfiguredProductionRemoteStartKind {
    /// The dedicated caller-owned Tokio runtime could not be constructed.
    RemoteRuntime,
    /// The fixed production application-lease configuration failed validation.
    RemoteApplicationLease,
    /// Remaining configured production population failed before Linux bootstrap assembly.
    RemoteConfiguration,
    /// Existing Linux bootstrap assembly failed after configured production population succeeded.
    Bootstrap(LinuxAgentBootstrapStartKind),
}

impl LinuxAgentConfiguredProductionRemoteStartKind {
    /// Returns the bounded token selected for executable startup diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::RemoteRuntime => "remote_runtime",
            Self::RemoteApplicationLease => "remote_application_lease",
            Self::RemoteConfiguration => "remote_configuration",
            Self::Bootstrap(kind) => kind.token(),
        }
    }
}

/// Bounded public failure projection for configured production remote startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxAgentConfiguredProductionRemoteStartFailure {
    kind: LinuxAgentConfiguredProductionRemoteStartKind,
    signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore,
}

impl LinuxAgentConfiguredProductionRemoteStartFailure {
    const fn new(
        kind: LinuxAgentConfiguredProductionRemoteStartKind,
        signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore,
    ) -> Self {
        Self {
            kind,
            signal_mask_restore,
        }
    }

    /// Returns the bounded configured-production startup class.
    #[must_use]
    pub const fn kind(self) -> LinuxAgentConfiguredProductionRemoteStartKind {
        self.kind
    }

    /// Returns existing signal-mask rollback evidence when Linux bootstrap owned it.
    #[must_use]
    pub const fn signal_mask_restore(self) -> LinuxAgentBootstrapSignalMaskRestore {
        self.signal_mask_restore
    }
}

impl std::fmt::Display for LinuxAgentConfiguredProductionRemoteStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("configured production remote startup failed")
    }
}

impl std::error::Error for LinuxAgentConfiguredProductionRemoteStartFailure {}

const fn map_configured_production_remote_start_failure(
    error: LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
) -> LinuxAgentConfiguredProductionRemoteStartFailure {
    match error {
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::RuntimeConstruction => {
            LinuxAgentConfiguredProductionRemoteStartFailure::new(
                LinuxAgentConfiguredProductionRemoteStartKind::RemoteRuntime,
                LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
            )
        }
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::ApplicationLeasePolicySource(_),
        ) => LinuxAgentConfiguredProductionRemoteStartFailure::new(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteApplicationLease,
            LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
        ),
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::Companion(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError::ConfiguredPopulation(_),
            ),
        ) => LinuxAgentConfiguredProductionRemoteStartFailure::new(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteConfiguration,
            LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
        ),
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::Companion(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError::Bootstrap(failure),
            ),
        ) => LinuxAgentConfiguredProductionRemoteStartFailure::new(
            LinuxAgentConfiguredProductionRemoteStartKind::Bootstrap(failure.kind()),
            failure.signal_mask_restore(),
        ),
    }
}

/// Bounded result of publishing the existing one-shot remote supervisor shutdown controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentRemoteSupervisorShutdownPublish {
    /// The exact controller moved to process-side ownership.
    Published,
    /// Process-side ownership disappeared and orderly shutdown was requested on the recovered controller.
    ReceiverGoneShutdownRequested,
}

/// Non-cloneable bootstrap-facing one-shot publisher for the existing remote shutdown controller.
pub struct LinuxAgentRemoteSupervisorShutdownPublisher {
    publisher: RemoteSessionSupervisorShutdownPublisher,
}

impl LinuxAgentRemoteSupervisorShutdownPublisher {
    /// Consumes this wrapper and publishes the exact existing remote supervisor shutdown controller.
    #[must_use]
    pub fn publish(
        self,
        controller: RemoteSessionSupervisorShutdownController,
    ) -> LinuxAgentRemoteSupervisorShutdownPublish {
        map_remote_shutdown_publish(self.publisher.publish(controller))
    }
}

fn run_remote_process_operation_composition<
    Executor,
    Authority,
    Endpoint,
    Controller,
    Publication,
    ExecutorError,
    BootstrapError,
    EndpointError,
>(
    construct_executor: impl FnOnce() -> Result<Executor, ExecutorError>,
    bootstrap_authority: impl FnOnce(&Executor) -> Result<Authority, BootstrapError>,
    start_endpoint: impl FnOnce(Executor, Authority) -> Result<(Endpoint, Controller), EndpointError>,
    publish_controller: impl FnOnce(Controller) -> Publication,
    drive_lifecycle: impl FnOnce(Endpoint, Publication),
) -> bool {
    let Ok(executor) = construct_executor() else {
        return false;
    };
    let Ok(authority) = bootstrap_authority(&executor) else {
        return false;
    };
    let Ok((endpoint, controller)) = start_endpoint(executor, authority) else {
        return false;
    };
    let publication = publish_controller(controller);
    drive_lifecycle(endpoint, publication);
    true
}

/// Injected values required to build one library-owned remote process operation.
///
/// Construction owns only already-typed inputs. It performs no credential read, provider I/O,
/// endpoint bind, authentication, authorization, task spawn, readiness publication or process
/// lifecycle mutation. The owner is intentionally non-cloneable.
pub struct LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E> {
    bind_addr: SocketAddr,
    max_active_workers: NonZeroUsize,
    capability_authority: SharedCurrentCapabilityAuthority<P>,
    session_authentication: SessionAuthenticationService,
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
}

impl<P, D, T, F, C, R, E> LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E> {
    /// Consumes the exact injected remote-operation values without starting remote work.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-AZ keeps the selected injected remote-operation inputs explicit and typed"
    )]
    pub const fn new(
        bind_addr: SocketAddr,
        max_active_workers: NonZeroUsize,
        capability_authority: SharedCurrentCapabilityAuthority<P>,
        session_authentication: SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Self {
        Self {
            bind_addr,
            max_active_workers,
            capability_authority,
            session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        }
    }
}

/// Populates the existing remote-operation owner from the selected production bind-address source.
///
/// This crate-private helper performs exactly one existing process-environment bind-address load and
/// otherwise only moves already-typed remote-operation inputs into the existing owner constructor.
/// It does not construct peer identity, requester/rendezvous custody or any executable caller.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-IM materializes the IL-selected production bind-address input population before separately gated remaining production provenance"
)]
pub(crate) fn linux_agent_remote_process_operation_inputs_from_production_bind_addr<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    max_active_workers: NonZeroUsize,
    capability_authority: SharedCurrentCapabilityAuthority<P>,
    session_authentication: SessionAuthenticationService,
    expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
    admission_timing: F,
    on_completion: C,
    on_rejection: R,
    on_admission_failure: E,
) -> Result<
    LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentRemoteBindAddressSourceError,
> {
    let bind_addr = load_linux_agent_remote_bind_addr_from_env()?;
    Ok(LinuxAgentRemoteProcessOperationInputs::new(
        bind_addr,
        max_active_workers,
        capability_authority,
        session_authentication,
        expected_requests,
        admission_timing,
        on_completion,
        on_rejection,
        on_admission_failure,
    ))
}

/// Bounded Agent-local failure while populating production worker-limit and bind-address inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxAgentProductionRemoteProcessInputPopulationError {
    /// The fixed production worker-limit source failed before bind-address acquisition.
    WorkerLimitSource(LinuxAgentRemoteMaxActiveWorkersSourceError),
    /// The existing production bind-address source failed after worker-limit acquisition.
    BindAddressSource(LinuxAgentRemoteBindAddressSourceError),
}

impl std::fmt::Display for LinuxAgentProductionRemoteProcessInputPopulationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::WorkerLimitSource(_) => "production worker-limit source failed",
            Self::BindAddressSource(_) => "production bind-address source failed",
        })
    }
}

impl std::error::Error for LinuxAgentProductionRemoteProcessInputPopulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WorkerLimitSource(error) => Some(error),
            Self::BindAddressSource(error) => Some(error),
        }
    }
}

impl From<LinuxAgentRemoteMaxActiveWorkersSourceError>
    for LinuxAgentProductionRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentRemoteMaxActiveWorkersSourceError) -> Self {
        Self::WorkerLimitSource(error)
    }
}

impl From<LinuxAgentRemoteBindAddressSourceError>
    for LinuxAgentProductionRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentRemoteBindAddressSourceError) -> Self {
        Self::BindAddressSource(error)
    }
}

/// Populates the existing remote-process owner from production worker-limit and bind sources.
///
/// The helper loads the fixed worker limit exactly once, then delegates exactly once to the existing
/// bind-address population helper with that exact `NonZeroUsize`. All remaining typed inputs move
/// unchanged. It performs no peer lookup, operation construction, runtime activation or fallback.
///
/// # Errors
///
/// Fails closed on worker-limit source failure before bind-address acquisition, or on the existing
/// bind-address source failure after worker-limit acquisition. The bounded stage error preserves the
/// exact underlying source error without exposing configured values.
#[allow(
    clippy::type_complexity,
    dead_code,
    reason = "C03e-JP materializes the JO-selected production worker-limit input population before separately gated remaining production provenance"
)]
pub(crate) fn linux_agent_remote_process_operation_inputs_from_production_worker_limit<
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
    LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentProductionRemoteProcessInputPopulationError,
> {
    let max_active_workers = load_linux_agent_remote_max_active_workers_from_env()?;
    let inputs = linux_agent_remote_process_operation_inputs_from_production_bind_addr(
        max_active_workers,
        capability_authority,
        session_authentication,
        expected_requests,
        admission_timing,
        on_completion,
        on_rejection,
        on_admission_failure,
    )?;
    Ok(inputs)
}

/// Crate-private production process-operation inputs selected by C03e-IF.
///
/// This owner retains one typed logical peer identity beside the existing injected remote-process
/// inputs. Construction is side-effect-free: it performs no credential read, provider I/O,
/// endpoint bind, listener activation, readiness publication or durable-owner mutation.
#[allow(
    dead_code,
    reason = "C03e-IG materializes the IF-selected production process-operation input owner before separately gated executable assembly"
)]
pub(crate) struct LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>
{
    peer: PeerConnectivityIdentity,
    remote_process_inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
}

impl<P, D, T, F, C, R, E>
    LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>
{
    /// Consumes the exact typed peer identity and existing remote-process inputs without starting work.
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-IG materializes the IF-selected production process-operation input owner before separately gated executable assembly"
    )]
    pub(crate) const fn new(
        peer: PeerConnectivityIdentity,
        remote_process_inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    ) -> Self {
        Self {
            peer,
            remote_process_inputs,
        }
    }
}

/// Bounded Agent-local failure while populating one production peer input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxAgentProductionPeerInputPopulationError {
    /// The fixed process logical-peer source failed before provider/bootstrap work.
    PeerDeviceSource(LinuxAgentRemotePeerDeviceSourceError),
    /// Existing production durable-registry custody/provider bootstrap failed.
    DurableRegistryBootstrap(
        crate::production_durable_registry_custody_bootstrap::ProductionDurableRegistryCustodyBootstrapError,
    ),
    /// Existing current same-device durable-registry peer lookup failed.
    DurableRegistryLookup(prw_registry::durable_registry_authority::DurableRegistryAuthorityError),
}

impl std::fmt::Display for LinuxAgentProductionPeerInputPopulationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PeerDeviceSource(_) => "production peer-device source failed",
            Self::DurableRegistryBootstrap(_) => "production durable-registry bootstrap failed",
            Self::DurableRegistryLookup(_) => "production durable-registry peer lookup failed",
        })
    }
}

impl std::error::Error for LinuxAgentProductionPeerInputPopulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerDeviceSource(error) => Some(error),
            Self::DurableRegistryBootstrap(error) => Some(error),
            Self::DurableRegistryLookup(error) => Some(error),
        }
    }
}

impl From<LinuxAgentRemotePeerDeviceSourceError> for LinuxAgentProductionPeerInputPopulationError {
    fn from(error: LinuxAgentRemotePeerDeviceSourceError) -> Self {
        Self::PeerDeviceSource(error)
    }
}

impl From<
    crate::production_durable_registry_custody_bootstrap::ProductionDurableRegistryCustodyBootstrapError,
> for LinuxAgentProductionPeerInputPopulationError
{
    fn from(
        error: crate::production_durable_registry_custody_bootstrap::ProductionDurableRegistryCustodyBootstrapError,
    ) -> Self {
        Self::DurableRegistryBootstrap(error)
    }
}

impl From<prw_registry::durable_registry_authority::DurableRegistryAuthorityError>
    for LinuxAgentProductionPeerInputPopulationError
{
    fn from(
        error: prw_registry::durable_registry_authority::DurableRegistryAuthorityError,
    ) -> Self {
        Self::DurableRegistryLookup(error)
    }
}

/// Populates only the existing production reachability `peer` field from current registry authority.
///
/// The helper loads one fixed process logical [`DeviceId`], bootstraps the existing production
/// durable-registry provider once, adapts its neutral authority into the existing Agent runtime custody,
/// resolves one current same-device [`PeerConnectivityIdentity`], and then moves the already-built
/// remote-process inputs unchanged into the existing production owner. It selects no caller and
/// performs no reachability recovery, endpoint bind, readiness publication or remote lifecycle work.
///
/// # Errors
///
/// Fails before the next stage on peer-device source, durable-registry bootstrap or current-peer
/// lookup failure. No retry, fallback, alternate peer, cache or degraded owner is produced.
#[allow(
    clippy::future_not_send,
    dead_code,
    reason = "C03e-JK materializes the JJ-selected production peer input population before separately gated remaining production provenance"
)]
pub(crate) async fn linux_agent_production_reachability_remote_process_operation_inputs_from_production_peer<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    remote_process_inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
) -> Result<
    LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentProductionPeerInputPopulationError,
> {
    let device_id = load_linux_agent_remote_peer_device_id_from_env()?;
    let store = crate::production_durable_registry_custody_bootstrap::bootstrap_production_durable_registry_from_systemd_credentials().await?;
    let mut registry_custody =
        crate::production_durable_registry_runtime_custody::ProductionDurableRegistryRuntimeCustody::from_authority(store);
    let peer = registry_custody
        .peer_connectivity_identity(device_id)
        .await?;
    Ok(
        LinuxAgentProductionReachabilityRemoteProcessOperationInputs::new(
            peer,
            remote_process_inputs,
        ),
    )
}

/// Bounded Agent-local failure while composing production remote-process and peer input population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxAgentProductionReachabilityRemoteProcessInputPopulationError {
    /// Existing production worker-limit and bind-address input population failed.
    RemoteProcessInputs(LinuxAgentProductionRemoteProcessInputPopulationError),
    /// Existing production peer input population failed after remote-process inputs were built.
    PeerInput(LinuxAgentProductionPeerInputPopulationError),
}

impl std::fmt::Display for LinuxAgentProductionReachabilityRemoteProcessInputPopulationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RemoteProcessInputs(_) => "production remote-process input population failed",
            Self::PeerInput(_) => "production peer input population failed",
        })
    }
}

impl std::error::Error for LinuxAgentProductionReachabilityRemoteProcessInputPopulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RemoteProcessInputs(error) => Some(error),
            Self::PeerInput(error) => Some(error),
        }
    }
}

impl From<LinuxAgentProductionRemoteProcessInputPopulationError>
    for LinuxAgentProductionReachabilityRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentProductionRemoteProcessInputPopulationError) -> Self {
        Self::RemoteProcessInputs(error)
    }
}

impl From<LinuxAgentProductionPeerInputPopulationError>
    for LinuxAgentProductionReachabilityRemoteProcessInputPopulationError
{
    fn from(error: LinuxAgentProductionPeerInputPopulationError) -> Self {
        Self::PeerInput(error)
    }
}

/// Composes the existing production worker-limit/bind and peer input-population stages.
///
/// The helper first builds the existing remote-process inputs from the fixed worker-limit and bind
/// sources. Only after that succeeds does it invoke the existing peer population helper. The exact
/// remote-process owner is moved unchanged into the peer stage. No source logic is duplicated and no
/// operation factory, requester/rendezvous custody, runtime, listener or network lifecycle is invoked.
///
/// # Errors
///
/// Fails closed with the exact underlying remote-process or peer population error preserved through
/// the bounded two-stage composite error. No retry, fallback, alternate peer/source or degraded
/// partial owner is produced.
#[allow(
    clippy::future_not_send,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-JR materializes the JQ-selected production reachability input population composition before separately gated remaining production provenance"
)]
pub(crate) async fn linux_agent_production_reachability_remote_process_operation_inputs_from_production_worker_limit_and_peer<
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
    LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    LinuxAgentProductionReachabilityRemoteProcessInputPopulationError,
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
    let production_inputs =
        linux_agent_production_reachability_remote_process_operation_inputs_from_production_peer(
            remote_process_inputs,
        )
        .await?;
    Ok(production_inputs)
}

/// Builds one side-effect-free injected remote operation compatible with the AX bootstrap facade.
///
/// Factory construction performs ownership composition only. Remote credential/provider I/O and
/// endpoint startup occur only if a caller later invokes the returned closure. The operation uses
/// one exact private executor for reachability bootstrap and the complete endpoint/session lifecycle.
/// It does not select a production bind-address source, expected-device producer, dispatcher,
/// registry/policy source, timing source, readiness policy or executable process-exit policy.
pub fn linux_agent_remote_process_operation<P, D, T, F, C, R, E>(
    inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
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
    move |publisher| {
        let LinuxAgentRemoteProcessOperationInputs {
            bind_addr,
            max_active_workers,
            capability_authority,
            mut session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        } = inputs;

        let _ = run_remote_process_operation_composition(
            RemoteSessionExecutorRuntime::new,
            RemoteSessionExecutorRuntime::bootstrap_reachability_authority_from_systemd_credentials,
            move |executor, authority_owner| {
                RemoteSessionEndpointLifecycleRuntime::bind_with_executor_from_systemd_credentials(
                    executor,
                    authority_owner,
                    bind_addr,
                )
            },
            move |controller| publisher.publish(controller),
            move |lifecycle, _publication| {
                let _ = lifecycle.drive_repeated_real_remote_admission_endpoint_lifecycle(
                    max_active_workers,
                    &capability_authority,
                    &mut session_authentication,
                    expected_requests,
                    admission_timing,
                    on_completion,
                    on_rejection,
                    on_admission_failure,
                );
            },
        );
    }
}

/// Builds one dormant production-reachability remote process operation selected by C03e-IF.
///
/// Factory construction only moves already-typed values into a one-shot closure. Credential/provider
/// bootstrap, endpoint bind, shutdown-controller publication and endpoint drive occur only if a
/// separately gated caller later invokes that closure. The operation preserves one exact executor
/// across production bootstrap and endpoint startup and retains durable production-owner custody
/// through the production endpoint wrapper's complete lifecycle drive.
#[allow(
    dead_code,
    reason = "C03e-IG materializes the IF-selected production process operation before separately gated executable assembly"
)]
pub(crate) fn linux_agent_production_reachability_remote_process_operation<P, D, T, F, C, R, E>(
    inputs: LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
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
    move |publisher| {
        let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
            peer,
            remote_process_inputs,
        } = inputs;
        let LinuxAgentRemoteProcessOperationInputs {
            bind_addr,
            max_active_workers,
            capability_authority,
            mut session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        } = remote_process_inputs;

        let _ = run_remote_process_operation_composition(
            RemoteSessionExecutorRuntime::new,
            move |executor| {
                executor.bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                    &peer,
                )
            },
            move |executor, runtime_custody| {
                runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                    executor, bind_addr,
                )
            },
            move |controller| publisher.publish(controller),
            move |lifecycle, _publication| {
                let _ = lifecycle.drive_repeated_real_remote_admission_endpoint_lifecycle(
                    max_active_workers,
                    &capability_authority,
                    &mut session_authentication,
                    expected_requests,
                    admission_timing,
                    on_completion,
                    on_rejection,
                    on_admission_failure,
                );
            },
        );
    }
}

/// Builds one dormant production-reachability operation with fallible verifier-time completion projection.
///
/// Factory construction moves only the already-typed production inputs into one one-shot closure.
/// Provider sampling, endpoint bind, controller publication and lifecycle drive remain deferred until a
/// separately gated caller invokes that closure. Runtime invocation preserves the existing production
/// reachability composition order and delegates exactly once to the C03e-PX projection-capable wrapper.
///
/// No verifier-time provider installation or sampling, completion remapping, expected-request
/// construction, requester/durable fusion, retry, second runtime, second teardown path, readiness
/// publication or executable activation is added here.
#[allow(
    dead_code,
    reason = "C03e-PZ materializes the PY-selected dormant Linux fallible verifier-time projection operation before separately gated higher-owner composition"
)]
pub(crate) fn linux_agent_production_reachability_remote_process_operation_with_fallible_verifier_time_completion_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionReachabilityRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
) -> impl FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
        + Send
        + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(DeviceId, RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection)
        + Send
        + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    move |publisher| {
        let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
            peer,
            remote_process_inputs,
        } = inputs;
        let LinuxAgentRemoteProcessOperationInputs {
            bind_addr,
            max_active_workers,
            capability_authority,
            mut session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        } = remote_process_inputs;

        let _ = run_remote_process_operation_composition(
            RemoteSessionExecutorRuntime::new,
            move |executor| {
                executor.bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                    &peer,
                )
            },
            move |executor, runtime_custody| {
                runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                    executor, bind_addr,
                )
            },
            move |controller| publisher.publish(controller),
            move |lifecycle, _publication| {
                let _ = lifecycle
                    .drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle_with_completion_projection(
                        max_active_workers,
                        &capability_authority,
                        &mut session_authentication,
                        expected_requests,
                        admission_timing,
                        on_completion,
                        on_rejection,
                        on_admission_failure,
                    );
            },
        );
    }
}

/// Crate-private production requester/rendezvous process-operation lifetime custody selected by C03e-IH.
///
/// C03e-NQ migrates only the production durable lineage from raw runtime-owner custody to one
/// already-constructed shared requester/rendezvous authority. Construction remains side-effect-free
/// and activates no requester policy, provider, scheduling authority, listener, or runtime behavior.
#[allow(
    dead_code,
    reason = "C03e-NQ migrates production requester/rendezvous custody to one preconstructed shared authority"
)]
pub(crate) struct LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
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
    requester_rendezvous_start_policy_source: BoundedRequesterRendezvousStartPolicySource,
    requester_rendezvous_authority: SharedRequesterRendezvousAuthority,
}

impl<P, D, T, F, C, R, E>
    LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >
{
    /// Consumes the exact production operation inputs and preconstructed requester/rendezvous custody.
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-NQ retains one preconstructed shared requester authority without invoking it"
    )]
    pub(crate) const fn new(
        production_inputs: LinuxAgentProductionReachabilityRemoteProcessOperationInputs<
            P,
            D,
            T,
            F,
            C,
            R,
            E,
        >,
        requester_rendezvous_start_policy_source: BoundedRequesterRendezvousStartPolicySource,
        requester_rendezvous_authority: SharedRequesterRendezvousAuthority,
    ) -> Self {
        Self {
            production_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_authority,
        }
    }
}

/// Builds one dormant production operation that retains requester/rendezvous custody by value.
///
/// Factory construction delegates exactly once to the existing C03e-IG production operation and
/// otherwise performs ownership composition only. Requester-policy and shared requester/rendezvous
/// authority behavior remain uninvoked; the returned one-shot closure explicitly releases those
/// custody values immediately before delegating to the unchanged production operation.
#[allow(
    dead_code,
    reason = "C03e-NQ preserves dormant non-projection production custody with the preconstructed shared authority"
)]
pub(crate) fn linux_agent_production_reachability_requester_rendezvous_remote_process_operation<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
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
    let LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        production_inputs,
        requester_rendezvous_start_policy_source,
        requester_rendezvous_authority,
    } = inputs;
    let operation = linux_agent_production_reachability_remote_process_operation(production_inputs);

    move |publisher| {
        drop(requester_rendezvous_authority);
        drop(requester_rendezvous_start_policy_source);
        operation(publisher);
    }
}

/// Builds one dormant production requester/rendezvous operation that drives the durable
/// capability callback projection selected by C03e-LS.
///
/// Factory construction performs ownership adaptation only: the retained bounded requester policy
/// source is wrapped once in `Arc`, while the already-preconstructed shared authority is retained
/// unchanged. Credential/provider I/O, endpoint bind, controller publication and lifecycle drive
/// remain deferred until a separately gated caller invokes the returned one-shot closure.
///
/// Runtime invocation preserves the existing production stage ordering and calls the C03e-LR
/// projection-capable production endpoint lifecycle exactly once. Completion, rejection and
/// admission-failure callbacks are forwarded unchanged; no legacy aggregate reconstruction,
/// callback policy, retry, reconnect, readiness publication or executable activation is added.
#[allow(
    dead_code,
    reason = "C03e-NQ removes duplicate shared-authority construction from dormant projection operation assembly"
)]
pub(crate) fn linux_agent_production_reachability_requester_rendezvous_remote_process_operation_with_production_durable_capability_projection<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >,
    production_durable_capability_authority: Arc<ProductionDurableCapabilityAuthority>,
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
    let LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs {
        production_inputs,
        requester_rendezvous_start_policy_source,
        requester_rendezvous_authority,
    } = inputs;
    let requester_rendezvous_start_policy_source =
        Arc::new(requester_rendezvous_start_policy_source);

    move |publisher| {
        let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
            peer,
            remote_process_inputs,
        } = production_inputs;
        let LinuxAgentRemoteProcessOperationInputs {
            bind_addr,
            max_active_workers,
            capability_authority,
            mut session_authentication,
            expected_requests,
            admission_timing,
            on_completion,
            on_rejection,
            on_admission_failure,
        } = remote_process_inputs;

        let _ = run_remote_process_operation_composition(
            RemoteSessionExecutorRuntime::new,
            move |executor| {
                executor.bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                    &peer,
                )
            },
            move |executor, runtime_custody| {
                runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                    executor, bind_addr,
                )
            },
            move |controller| publisher.publish(controller),
            move |lifecycle, _publication| {
                let _ = lifecycle
                    .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability_projection(
                        max_active_workers,
                        &capability_authority,
                        production_durable_capability_authority,
                        requester_rendezvous_start_policy_source,
                        &requester_rendezvous_authority,
                        &mut session_authentication,
                        expected_requests,
                        admission_timing,
                        on_completion,
                        on_rejection,
                        on_admission_failure,
                    );
            },
        );
    }
}

/// Crate-private process-operation lifetime custody for one concrete requester-aware policy source.
#[allow(
    dead_code,
    reason = "C03e-EB materializes requester-policy custody before separately gated production assembly"
)]
pub(crate) struct LinuxAgentRequesterRendezvousRemoteProcessOperationInputs<P, D, T, F, C, R, E> {
    remote_process_inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
    requester_rendezvous_start_policy_source: BoundedRequesterRendezvousStartPolicySource,
    requester_rendezvous_runtime_owner: CandidatePublicationRequesterRendezvousRuntimeOwner,
}

impl<P, D, T, F, C, R, E>
    LinuxAgentRequesterRendezvousRemoteProcessOperationInputs<P, D, T, F, C, R, E>
{
    /// Owns the existing remote-process inputs and one already-constructed requester-policy source.
    #[must_use]
    #[allow(
        dead_code,
        reason = "C03e-EB materializes requester-policy custody before separately gated production assembly"
    )]
    pub(crate) const fn new(
        remote_process_inputs: LinuxAgentRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
        requester_rendezvous_start_policy_source: BoundedRequesterRendezvousStartPolicySource,
        requester_rendezvous_runtime_owner: CandidatePublicationRequesterRendezvousRuntimeOwner,
    ) -> Self {
        Self {
            remote_process_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_runtime_owner,
        }
    }
}

/// Builds one crate-private remote operation that retains requester-policy source custody.
#[allow(
    dead_code,
    reason = "C03e-EB materializes requester-policy custody before separately gated production assembly"
)]
pub(crate) fn linux_agent_requester_rendezvous_remote_process_operation<P, D, T, F, C, R, E>(
    inputs: LinuxAgentRequesterRendezvousRemoteProcessOperationInputs<P, D, T, F, C, R, E>,
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
    let LinuxAgentRequesterRendezvousRemoteProcessOperationInputs {
        remote_process_inputs,
        requester_rendezvous_start_policy_source,
        requester_rendezvous_runtime_owner,
    } = inputs;
    let operation = linux_agent_remote_process_operation(remote_process_inputs);

    move |publisher| {
        drop(requester_rendezvous_runtime_owner);
        drop(requester_rendezvous_start_policy_source);
        operation(publisher);
    }
}

/// Bounded process-side controller finalization evidence for the injected remote companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentRemoteProcessControllerFinalization {
    /// The handed-off controller received the orderly shutdown request.
    ShutdownRequested,
    /// The remote lane ended before publishing a shutdown controller.
    UnavailableBeforeEndpointStartup,
}

/// Bounded OS-thread finalization evidence for the injected remote companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentRemoteProcessThreadFinalization {
    /// The exact join-owned remote thread returned normally.
    Joined,
    /// The exact join-owned remote thread panicked; payload and thread identity were discarded.
    Panicked,
}

/// Secondary bounded finalization evidence for the injected remote companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxAgentRemoteProcessCompanionFinalization {
    /// The remote process thread could not be created; local bootstrap semantics remain primary.
    SpawnFailed,
    /// The existing AT process owner finalized the controller handoff and exact join-owned thread.
    Finalized {
        /// Bounded process-side controller finalization evidence.
        controller: LinuxAgentRemoteProcessControllerFinalization,
        /// Bounded exact-thread join evidence.
        thread: LinuxAgentRemoteProcessThreadFinalization,
    },
}

impl LinuxAgentRemoteProcessCompanionFinalization {
    /// Returns the bounded configured-executable diagnostic token for remote finalization.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::SpawnFailed => "spawn_failed",
            Self::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            } => "shutdown_requested_joined",
            Self::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested,
                thread: LinuxAgentRemoteProcessThreadFinalization::Panicked,
            } => "shutdown_requested_panicked",
            Self::Finalized {
                controller:
                    LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            } => "unavailable_before_endpoint_startup_joined",
            Self::Finalized {
                controller:
                    LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup,
                thread: LinuxAgentRemoteProcessThreadFinalization::Panicked,
            } => "unavailable_before_endpoint_startup_panicked",
        }
    }

    /// Returns whether remote finalization satisfies the selected executable success law.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(
            self,
            Self::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            }
        )
    }
}

/// Existing local bootstrap report plus secondary injected-remote-companion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxAgentBootstrapWithRemoteReport {
    local: LinuxAgentBootstrapReport,
    remote: LinuxAgentRemoteProcessCompanionFinalization,
}

impl LinuxAgentBootstrapWithRemoteReport {
    /// Returns the existing primary local bootstrap report unchanged.
    #[must_use]
    pub const fn local(self) -> LinuxAgentBootstrapReport {
        self.local
    }

    /// Returns bounded secondary remote companion finalization evidence.
    #[must_use]
    pub const fn remote(self) -> LinuxAgentRemoteProcessCompanionFinalization {
        self.remote
    }
}

fn with_initial_runtime_inputs<R>(
    operation: impl FnOnce(
        LocalLinuxProductionRuntimeInputs<'_>,
    ) -> Result<R, LinuxAgentBootstrapStartFailure>,
) -> Result<R, LinuxAgentBootstrapStartFailure> {
    let private_dns_config = PrivateDnsConfig::default();
    let private_dns_snapshot = LocalPrivateDnsSnapshot::try_from_config(&private_dns_config)
        .map_err(|_| {
            LinuxAgentBootstrapStartFailure::new(
                LinuxAgentBootstrapStartKind::PrivateDnsSnapshot,
                LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
            )
        })?;

    let inputs = LocalLinuxProductionRuntimeInputs::new(
        initial_runtime_config(),
        BoundedLocalReadPolicy::allow_local_reads(),
        LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready),
        &private_dns_snapshot,
    );

    operation(inputs)
}

/// Runs the fixed initial standalone Linux Agent bootstrap profile.
///
/// The facade builds only the Phase 101 locked immutable profile and delegates
/// to the already-validated Phase 098 signal-aware runtime. It performs no
/// systemd installation/activation and opens no public or remote listener.
///
/// # Errors
///
/// Returns a bounded startup failure when snapshot construction, safe signal
/// setup, or descriptor-anchored local lifecycle assembly cannot complete.
pub fn run() -> Result<LinuxAgentBootstrapReport, LinuxAgentBootstrapStartFailure> {
    with_initial_runtime_inputs(|inputs| {
        run_signal_aware_linux_production_runtime_from_env_with_agent_status_management(
            inputs,
            |_| {},
        )
        .map(|report| map_terminal_report(&report))
        .map_err(map_start_failure)
    })
}

/// Runs the same fixed initial Linux Agent profile with one injected remote process companion.
///
/// The remote operation remains caller-supplied. This facade creates no production remote inputs,
/// selects no bind address, performs no reachability bootstrap, and does not define executable exit
/// policy for the returned secondary remote evidence.
///
/// # Errors
///
/// Returns the existing local bootstrap startup failure unchanged. Remote process-thread spawn
/// failure remains secondary evidence on successful local lifecycle completion.
pub fn run_with_remote_process_companion<F>(
    operation: F,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    F: FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static,
{
    with_initial_runtime_inputs(|inputs| {
        run_with_remote_process_companion_inputs(inputs, operation)
            .map(|(local, remote)| LinuxAgentBootstrapWithRemoteReport { local, remote })
    })
}

/// Runs the selected configured production remote companion behind the public Linux bootstrap facade.
///
/// This facade delegates exactly once to the existing C03e-TL synchronous higher-owner driver and
/// projects its crate-private error family into the bounded public startup classification selected
/// by C03e-TM. It constructs no additional runtime, performs no retry or fallback, and remains
/// dormant until a separately authorized `main.rs` activation checkpoint.
///
/// # Errors
///
/// Returns a bounded configured-production startup failure without exposing private source chains,
/// raw configuration values, transport coordinates, request/session identifiers, or verifier time.
pub fn run_with_configured_production_remote_companion()
-> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentConfiguredProductionRemoteStartFailure> {
    run_with_production_durable_reachability_requester_rendezvous_configured_application_lease_companion_with_selected_executable_custody()
        .map_err(map_configured_production_remote_start_failure)
}

#[cfg(test)]
mod configured_production_remote_facade_tests {
    use std::error::Error as _;

    use super::{
        LinuxAgentBootstrapSignalMaskRestore, LinuxAgentBootstrapStartFailure,
        LinuxAgentBootstrapStartKind, LinuxAgentBootstrapWithRemoteReport,
        LinuxAgentConfiguredProductionRemoteStartFailure,
        LinuxAgentConfiguredProductionRemoteStartKind,
        LinuxAgentRemoteApplicationLeasePolicySourceError,
        LinuxAgentRemoteProcessCompanionFinalization,
        LinuxAgentRemoteProcessControllerFinalization, LinuxAgentRemoteProcessThreadFinalization,
        LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError,
        map_configured_production_remote_start_failure,
        run_with_configured_production_remote_companion,
    };
    use crate::production_durable_capability_higher_owner_custody::{
        LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError,
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError,
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError,
        LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError,
    };

    #[test]
    fn public_facade_has_exact_selected_result_shape_without_invocation() {
        let entry: fn() -> Result<
            LinuxAgentBootstrapWithRemoteReport,
            LinuxAgentConfiguredProductionRemoteStartFailure,
        > = run_with_configured_production_remote_companion;
        let _ = entry;
    }

    #[test]
    fn configured_start_tokens_and_failure_surface_are_bounded() {
        assert_eq!(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteRuntime.token(),
            "remote_runtime"
        );
        assert_eq!(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteApplicationLease.token(),
            "remote_application_lease"
        );
        assert_eq!(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteConfiguration.token(),
            "remote_configuration"
        );
        assert_eq!(
            LinuxAgentConfiguredProductionRemoteStartKind::Bootstrap(
                LinuxAgentBootstrapStartKind::RuntimeRoot
            )
            .token(),
            "runtime_root"
        );
        let failure = LinuxAgentConfiguredProductionRemoteStartFailure::new(
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteRuntime,
            LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
        );
        assert_eq!(
            failure.to_string(),
            "configured production remote startup failed"
        );
        assert!(failure.source().is_none());
    }

    #[test]
    fn private_driver_failures_map_to_selected_public_classes() {
        let runtime = map_configured_production_remote_start_failure(
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::RuntimeConstruction,
        );
        assert_eq!(
            runtime.kind(),
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteRuntime
        );
        assert_eq!(
            runtime.signal_mask_restore(),
            LinuxAgentBootstrapSignalMaskRestore::NotApplicable
        );

        let application_lease = map_configured_production_remote_start_failure(
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::ApplicationLeasePolicySource(
                    LinuxAgentRemoteApplicationLeasePolicySourceError::Missing,
                ),
            ),
        );
        assert_eq!(
            application_lease.kind(),
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteApplicationLease
        );

        let configured_population =
            LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationError::RequesterRendezvousMaxRecordsSource(
                LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::Missing,
            );
        let remote_configuration = map_configured_production_remote_start_failure(
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::Companion(
                    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError::ConfiguredPopulation(configured_population),
                ),
            ),
        );
        assert_eq!(
            remote_configuration.kind(),
            LinuxAgentConfiguredProductionRemoteStartKind::RemoteConfiguration
        );
        assert_eq!(
            remote_configuration.signal_mask_restore(),
            LinuxAgentBootstrapSignalMaskRestore::NotApplicable
        );

        let bootstrap = LinuxAgentBootstrapStartFailure::new(
            LinuxAgentBootstrapStartKind::RuntimeDirectory,
            LinuxAgentBootstrapSignalMaskRestore::Restored,
        );
        let bootstrap_projection = map_configured_production_remote_start_failure(
            LinuxAgentProductionConfiguredApplicationLeaseSelectedExecutableCustodyError::Companion(
                LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredApplicationLeaseCompanionError::Companion(
                    LinuxAgentProductionDurableReachabilityRequesterRendezvousConfiguredPopulationCompanionError::Bootstrap(bootstrap),
                ),
            ),
        );
        assert_eq!(
            bootstrap_projection.kind(),
            LinuxAgentConfiguredProductionRemoteStartKind::Bootstrap(
                LinuxAgentBootstrapStartKind::RuntimeDirectory
            )
        );
        assert_eq!(
            bootstrap_projection.signal_mask_restore(),
            LinuxAgentBootstrapSignalMaskRestore::Restored
        );
    }

    #[test]
    fn remote_finalization_tokens_and_success_law_are_exact() {
        let cases = [
            (LinuxAgentRemoteProcessCompanionFinalization::SpawnFailed, "spawn_failed", false),
            (LinuxAgentRemoteProcessCompanionFinalization::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            }, "shutdown_requested_joined", true),
            (LinuxAgentRemoteProcessCompanionFinalization::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested,
                thread: LinuxAgentRemoteProcessThreadFinalization::Panicked,
            }, "shutdown_requested_panicked", false),
            (LinuxAgentRemoteProcessCompanionFinalization::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            }, "unavailable_before_endpoint_startup_joined", false),
            (LinuxAgentRemoteProcessCompanionFinalization::Finalized {
                controller: LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup,
                thread: LinuxAgentRemoteProcessThreadFinalization::Panicked,
            }, "unavailable_before_endpoint_startup_panicked", false),
        ];
        for (finalization, token, success) in cases {
            assert_eq!(finalization.token(), token);
            assert_eq!(finalization.is_success(), success);
        }
    }
}

/// Runs the fixed local profile with the already-typed production/requester-rendezvous companion.
///
/// This crate-private assembly boundary only composes the existing C03e-II operation factory with
/// the existing injected remote-companion runner. It constructs no real production inputs and is
/// not invoked by `run()` or the Agent executable.
#[allow(
    dead_code,
    reason = "C03e-IK materializes the IJ-selected dormant executable assembly before separately gated caller/input assembly"
)]
pub(crate) fn run_with_production_reachability_requester_rendezvous_remote_process_companion<
    P,
    D,
    T,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
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
    C: FnMut(RemoteSessionRegisteredWorkerCompletion) + Send + 'static,
    R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>) + Send + 'static,
    E: FnMut(RemoteSessionRepeatedAdmissionFailure) + Send + 'static,
{
    let operation =
        linux_agent_production_reachability_requester_rendezvous_remote_process_operation(inputs);
    run_with_remote_process_companion(operation)
}

fn run_with_remote_process_companion_inputs<F>(
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
    operation: F,
) -> Result<
    (
        LinuxAgentBootstrapReport,
        LinuxAgentRemoteProcessCompanionFinalization,
    ),
    LinuxAgentBootstrapStartFailure,
>
where
    F: FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static,
{
    let mut remote_finalization = None;
    let report = run_signal_aware_linux_production_runtime_from_env_with_companion(
        inputs,
        |_| {},
        || {
            RemoteSessionProcessLifecycleOwner::spawn(move |publisher| {
                operation(LinuxAgentRemoteSupervisorShutdownPublisher { publisher });
            })
        },
        |companion| {
            remote_finalization = Some(finalize_remote_process_companion(companion));
        },
    )
    .map_err(map_start_failure)?;

    let remote_finalization = remote_finalization
        .expect("signal-aware companion finalizer runs before successful bootstrap return");

    Ok((map_terminal_report(&report), remote_finalization))
}

/// Runs the active configured-production remote process companion with the VY `AgentStatus` worker.
///
/// The generic injected-remote companion path remains bound to the legacy read-only worker.
fn run_with_agent_status_management_remote_process_companion_inputs<F>(
    inputs: LocalLinuxProductionRuntimeInputs<'_>,
    operation: F,
) -> Result<
    (
        LinuxAgentBootstrapReport,
        LinuxAgentRemoteProcessCompanionFinalization,
    ),
    LinuxAgentBootstrapStartFailure,
>
where
    F: FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static,
{
    let mut remote_finalization = None;
    let report =
        run_signal_aware_linux_production_runtime_from_env_with_agent_status_management_and_companion(
            inputs,
            |_| {},
            || {
                RemoteSessionProcessLifecycleOwner::spawn(move |publisher| {
                    operation(LinuxAgentRemoteSupervisorShutdownPublisher { publisher });
                })
            },
            |companion| {
                remote_finalization = Some(finalize_remote_process_companion(companion));
            },
        )
        .map_err(map_start_failure)?;

    let remote_finalization = remote_finalization
        .expect("signal-aware companion finalizer runs before successful bootstrap return");

    Ok((map_terminal_report(&report), remote_finalization))
}

const fn map_remote_shutdown_publish(
    publish: RemoteSessionSupervisorShutdownPublish,
) -> LinuxAgentRemoteSupervisorShutdownPublish {
    match publish {
        RemoteSessionSupervisorShutdownPublish::Published => {
            LinuxAgentRemoteSupervisorShutdownPublish::Published
        }
        RemoteSessionSupervisorShutdownPublish::ReceiverGoneShutdownRequested => {
            LinuxAgentRemoteSupervisorShutdownPublish::ReceiverGoneShutdownRequested
        }
    }
}

const fn map_remote_process_controller_finalization(
    controller: RemoteSessionProcessControllerFinalization,
) -> LinuxAgentRemoteProcessControllerFinalization {
    match controller {
        RemoteSessionProcessControllerFinalization::ShutdownRequested => {
            LinuxAgentRemoteProcessControllerFinalization::ShutdownRequested
        }
        RemoteSessionProcessControllerFinalization::UnavailableBeforeEndpointStartup => {
            LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup
        }
    }
}

const fn map_remote_process_thread_finalization(
    thread: RemoteSessionProcessThreadFinalization,
) -> LinuxAgentRemoteProcessThreadFinalization {
    match thread {
        RemoteSessionProcessThreadFinalization::Joined => {
            LinuxAgentRemoteProcessThreadFinalization::Joined
        }
        RemoteSessionProcessThreadFinalization::Panicked => {
            LinuxAgentRemoteProcessThreadFinalization::Panicked
        }
    }
}

const fn map_remote_process_finalization(
    finalization: RemoteSessionProcessLifecycleFinalization,
) -> LinuxAgentRemoteProcessCompanionFinalization {
    LinuxAgentRemoteProcessCompanionFinalization::Finalized {
        controller: map_remote_process_controller_finalization(finalization.controller()),
        thread: map_remote_process_thread_finalization(finalization.thread()),
    }
}

fn finalize_remote_process_companion(
    companion: Result<RemoteSessionProcessLifecycleOwner, RemoteSessionProcessLifecycleSpawnError>,
) -> LinuxAgentRemoteProcessCompanionFinalization {
    companion.map_or(
        LinuxAgentRemoteProcessCompanionFinalization::SpawnFailed,
        |owner| map_remote_process_finalization(owner.finalize()),
    )
}

fn initial_runtime_config() -> LocalLinuxProductionRuntimeConfig {
    LocalLinuxProductionRuntimeConfig::new(
        NonZeroUsize::new(2).expect("Phase 101 worker capacity is non-zero"),
        NonZeroU16::new(8).expect("Phase 101 listener backlog is non-zero"),
        NonZeroUsize::new(2).expect("Phase 101 scheduling budget is non-zero"),
        NonZeroUsize::new(1).expect("Phase 101 request budget is non-zero"),
        LocalLinuxIoBudget::try_new(Duration::from_secs(2))
            .expect("Phase 101 read I/O budget is non-zero"),
        LocalLinuxIoBudget::try_new(Duration::from_secs(2))
            .expect("Phase 101 write I/O budget is non-zero"),
    )
}

const fn map_terminal_report(
    report: &crate::linux_identity::signal_aware_runtime::LocalLinuxSignalAwareRuntimeTerminalReport,
) -> LinuxAgentBootstrapReport {
    LinuxAgentBootstrapReport {
        terminal: match report.reason() {
            LocalLinuxSignalAwareRuntimeTerminalReason::ProgrammaticShutdown => {
                LinuxAgentBootstrapTerminal::ProgrammaticShutdown
            }
            LocalLinuxSignalAwareRuntimeTerminalReason::TerminationSignal(
                LocalLinuxTerminationSignal::SigTerm,
            ) => LinuxAgentBootstrapTerminal::SigTerm,
            LocalLinuxSignalAwareRuntimeTerminalReason::TerminationSignal(
                LocalLinuxTerminationSignal::SigInt,
            ) => LinuxAgentBootstrapTerminal::SigInt,
            LocalLinuxSignalAwareRuntimeTerminalReason::ReadinessFatal(_) => {
                LinuxAgentBootstrapTerminal::ReadinessFatal
            }
            LocalLinuxSignalAwareRuntimeTerminalReason::RuntimeFatal(_) => {
                LinuxAgentBootstrapTerminal::RuntimeFatal
            }
        },
        counters: map_counters(report.counters()),
        cleanup: map_cleanup(report.cleanup()),
        signal_mask_restore: map_signal_mask_restore(report.mask_restore()),
    }
}

const fn map_counters(
    counters: LocalLinuxProductionRuntimeCounters,
) -> LinuxAgentBootstrapCounters {
    LinuxAgentBootstrapCounters {
        readiness_steps: counters.readiness_steps(),
        listener_armed_steps: counters.listener_armed_steps(),
        runtime_wakes: counters.runtime_wakes(),
        wait_interruptions: counters.wait_interruptions(),
        scheduling_attempts: counters.scheduling_attempts(),
        workers_registered: counters.workers_registered(),
        worker_completions: counters.worker_completions(),
        peer_rejections: counters.peer_rejections(),
    }
}

const fn map_cleanup(cleanup: LocalLinuxProductionRuntimeCleanup) -> LinuxAgentBootstrapCleanup {
    match cleanup {
        LocalLinuxProductionRuntimeCleanup::Clean => LinuxAgentBootstrapCleanup::Clean,
        LocalLinuxProductionRuntimeCleanup::Failed(_) => LinuxAgentBootstrapCleanup::Failed,
    }
}

const fn map_signal_mask_restore(
    restore: LocalLinuxTerminationSignalMaskRestore,
) -> LinuxAgentBootstrapSignalMaskRestore {
    match restore {
        LocalLinuxTerminationSignalMaskRestore::Restored => {
            LinuxAgentBootstrapSignalMaskRestore::Restored
        }
        LocalLinuxTerminationSignalMaskRestore::Failed => {
            LinuxAgentBootstrapSignalMaskRestore::Failed
        }
    }
}

const fn map_start_failure(
    error: LocalLinuxSignalAwareRuntimeStartError,
) -> LinuxAgentBootstrapStartFailure {
    match error {
        LocalLinuxSignalAwareRuntimeStartError::SignalSource(error) => match error {
            LocalLinuxTerminationSignalSourceCreateError::MaskBlockFailed => {
                LinuxAgentBootstrapStartFailure::new(
                    LinuxAgentBootstrapStartKind::SignalSource,
                    LinuxAgentBootstrapSignalMaskRestore::NotApplicable,
                )
            }
            LocalLinuxTerminationSignalSourceCreateError::DescriptorCreateFailed {
                mask_restore,
            } => LinuxAgentBootstrapStartFailure::new(
                LinuxAgentBootstrapStartKind::SignalSource,
                map_signal_mask_restore(mask_restore),
            ),
        },
        LocalLinuxSignalAwareRuntimeStartError::Lifecycle {
            error,
            mask_restore,
        } => LinuxAgentBootstrapStartFailure::new(
            map_lifecycle_start_kind(error),
            map_signal_mask_restore(mask_restore),
        ),
    }
}

const fn map_lifecycle_start_kind(
    error: LocalLinuxProductionLifecycleAssemblyError,
) -> LinuxAgentBootstrapStartKind {
    match error {
        LocalLinuxProductionLifecycleAssemblyError::RuntimeRoot(_) => {
            LinuxAgentBootstrapStartKind::RuntimeRoot
        }
        LocalLinuxProductionLifecycleAssemblyError::RuntimeDirectory(_) => {
            LinuxAgentBootstrapStartKind::RuntimeDirectory
        }
        LocalLinuxProductionLifecycleAssemblyError::InstanceLock(
            AgentInstanceLockError::AlreadyRunning,
        ) => LinuxAgentBootstrapStartKind::AlreadyRunning,
        LocalLinuxProductionLifecycleAssemblyError::InstanceLock(_) => {
            LinuxAgentBootstrapStartKind::InstanceLock
        }
        LocalLinuxProductionLifecycleAssemblyError::Bind(_) => LinuxAgentBootstrapStartKind::Bind,
        LocalLinuxProductionLifecycleAssemblyError::Listen { .. } => {
            LinuxAgentBootstrapStartKind::Listen
        }
        LocalLinuxProductionLifecycleAssemblyError::AcceptReady { .. } => {
            LinuxAgentBootstrapStartKind::AcceptReady
        }
        LocalLinuxProductionLifecycleAssemblyError::RuntimeWake { .. } => {
            LinuxAgentBootstrapStartKind::RuntimeWake
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        ffi::OsString,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        num::NonZeroUsize,
    };

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
    use prw_core::DeviceId;
    use prw_policy::{BoundedLocalReadPolicy, Capability, Decision, PolicyEvaluator};
    use prw_registry::WorkspaceDeviceRegistry;
    use prw_remote_bridge::{AuthorizedCapabilityRequest, CapabilityDispatcher};
    use prw_session::SessionAuthenticationService;
    use tokio::sync::mpsc;

    use super::{
        LinuxAgentBootstrapCleanup, LinuxAgentBootstrapCounters, LinuxAgentBootstrapReport,
        LinuxAgentBootstrapSignalMaskRestore, LinuxAgentBootstrapStartFailure,
        LinuxAgentBootstrapStartKind, LinuxAgentBootstrapTerminal,
        LinuxAgentBootstrapWithRemoteReport, LinuxAgentExecutionMode,
        LinuxAgentExecutionModeSourceError,
        LinuxAgentProductionReachabilityRemoteProcessOperationInputs,
        LinuxAgentRemoteApplicationLeasePolicySourceError, LinuxAgentRemoteBindAddressSourceError,
        LinuxAgentRemoteMaxActiveWorkersSourceError, LinuxAgentRemotePeerDeviceSourceError,
        LinuxAgentRemoteProcessCompanionFinalization,
        LinuxAgentRemoteProcessControllerFinalization, LinuxAgentRemoteProcessOperationInputs,
        LinuxAgentRemoteProcessThreadFinalization, LinuxAgentRemoteSupervisorShutdownPublish,
        LinuxAgentRemoteSupervisorShutdownPublisher, PRW_AGENT_EXECUTION_MODE_ENV,
        PRW_REMOTE_APPLICATION_LEASE_SECONDS_ENV, PRW_REMOTE_BIND_ADDR_ENV,
        PRW_REMOTE_MAX_ACTIVE_WORKERS_ENV, PRW_REMOTE_PEER_DEVICE_ID_ENV,
        finalize_remote_process_companion, initial_runtime_config,
        linux_agent_production_reachability_remote_process_operation,
        linux_agent_remote_process_operation, load_linux_agent_execution_mode_from_env,
        load_linux_agent_remote_application_lease_policy_from_env,
        load_linux_agent_remote_bind_addr_from_env,
        load_linux_agent_remote_max_active_workers_from_env,
        load_linux_agent_remote_peer_device_id_from_env, map_lifecycle_start_kind,
        map_remote_shutdown_publish, parse_linux_agent_execution_mode_value,
        parse_linux_agent_remote_application_lease_policy_value,
        parse_linux_agent_remote_bind_addr_value,
        parse_linux_agent_remote_max_active_workers_value,
        parse_linux_agent_remote_peer_device_id_value, run,
        run_remote_process_operation_composition, run_with_remote_process_companion,
    };
    use crate::linux_identity::production_lifecycle::LocalLinuxProductionLifecycleAssemblyError;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::linux_identity::xdg_runtime_root::prw_runtime_directory::agent_instance_lock::AgentInstanceLockError;
    use crate::remote_session_capability_runtime::{
        RemoteSessionApplicationLeasePolicy, RemoteSessionExpectedDeviceAdmissionRejection,
        RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionRealAdmissionTiming,
        RemoteSessionRegisteredWorkerCompletion, RemoteSessionRepeatedAdmissionFailure,
        RemoteSessionSupervisorShutdownController, SharedCurrentCapabilityAuthority,
        SharedRequesterRendezvousAuthority,
        remote_session_process_lifecycle_control::{
            RemoteSessionProcessLifecycleOwner, RemoteSessionProcessLifecycleSpawnError,
            RemoteSessionSupervisorShutdownPublish,
        },
    };

    mod production_remote_capability_dispatcher {
        use std::net::{IpAddr, Ipv4Addr};

        use prw_file_service::RemotePath;
        use prw_file_transfer::{TransferId, UploadPlan};
        use prw_forwarding::{
            ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec,
        };
        use prw_remote_bridge::{BridgeCommand, CapabilityDispatcher};
        use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

        use super::super::{
            LinuxAgentProductionRemoteCapabilityDispatchError,
            LinuxAgentProductionRemoteCapabilityDispatcher,
        };
        use crate::local_commands::status_snapshot::{
            LocalAgentRuntimeState, LocalAgentStatusSnapshot,
            codec::{decode_status_snapshot, encode_status_snapshot},
        };

        #[test]
        fn owned_snapshot_satisfies_worker_dispatcher_bound_after_caller_scope_ends() {
            fn assert_worker_bound<D: CapabilityDispatcher + Send + 'static>(dispatcher: D) -> D {
                dispatcher
            }

            let dispatcher = {
                let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Degraded);
                assert_worker_bound(LinuxAgentProductionRemoteCapabilityDispatcher::new(
                    snapshot,
                ))
            };
            assert_eq!(
                dispatcher.dispatch_command(&BridgeCommand::AgentStatus),
                Ok(vec![3, 0, 1, 0, 0])
            );
        }

        #[test]
        fn every_status_state_returns_exact_existing_five_byte_body_without_framing() {
            for state in [
                LocalAgentRuntimeState::Starting,
                LocalAgentRuntimeState::Ready,
                LocalAgentRuntimeState::Degraded,
                LocalAgentRuntimeState::Stopping,
            ] {
                let snapshot = LocalAgentStatusSnapshot::current(state);
                let dispatcher = LinuxAgentProductionRemoteCapabilityDispatcher::new(snapshot);
                let result = dispatcher
                    .dispatch_command(&BridgeCommand::AgentStatus)
                    .expect("status projection");

                assert_eq!(result.len(), 5);
                assert_eq!(result, encode_status_snapshot(snapshot));
                assert_eq!(decode_status_snapshot(&result), Ok(snapshot));
            }
        }

        #[test]
        fn every_provider_backed_command_fails_closed_with_zero_data_error() {
            let path = RemotePath::parse("unavailable/item").expect("relative path");
            let transfer_id = TransferId::new([0x31; 16]);
            let plan =
                UploadPlan::new(transfer_id, path.clone(), 1, [0x32; 32]).expect("upload plan");
            let session_id = TerminalSessionId::new(17).expect("terminal id");
            let geometry = TerminalGeometry::new(80, 24).expect("terminal geometry");
            let forward_id = PortForwardId::new(19).expect("forward id");
            let spec = TcpForwardSpec::new(
                LoopbackBind::new(LoopbackFamily::Ipv4, 8080).expect("loopback bind"),
                ForwardTarget::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443)
                    .expect("forward target"),
            );
            let commands = [
                BridgeCommand::FileList(path.clone()),
                BridgeCommand::FileStat(path.clone()),
                BridgeCommand::FileCreate {
                    path: path.clone(),
                    contents: b"private contents".to_vec(),
                },
                BridgeCommand::DirectoryCreate(path.clone()),
                BridgeCommand::UploadBegin(plan.clone()),
                BridgeCommand::UploadResume(plan),
                BridgeCommand::UploadChunk {
                    transfer_id,
                    offset: 0,
                    chunk: vec![1],
                },
                BridgeCommand::UploadFinalize(transfer_id),
                BridgeCommand::UploadAbort(transfer_id),
                BridgeCommand::DownloadChunk {
                    path,
                    offset: 0,
                    requested_len: 1,
                },
                BridgeCommand::TerminalOpen {
                    session_id,
                    profile: TerminalProfile::BashShell,
                    geometry,
                },
                BridgeCommand::TerminalInput {
                    session_id,
                    bytes: b"private input".to_vec(),
                },
                BridgeCommand::TerminalResize {
                    session_id,
                    geometry,
                },
                BridgeCommand::TerminalRead {
                    session_id,
                    maximum_bytes: 1,
                },
                BridgeCommand::TerminalClose(session_id),
                BridgeCommand::ForwardOpen { forward_id, spec },
                BridgeCommand::ForwardClose(forward_id),
            ];
            let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Stopping);
            let dispatcher = LinuxAgentProductionRemoteCapabilityDispatcher::new(snapshot);

            for command in commands {
                let error = dispatcher
                    .dispatch_command(&command)
                    .expect_err("unsupported family");
                assert_eq!(
                    error,
                    LinuxAgentProductionRemoteCapabilityDispatchError::UnsupportedProviderFamily
                );
                assert_eq!(
                    error.to_string(),
                    "remote capability provider family unsupported"
                );
                assert!(std::error::Error::source(&error).is_none());
            }
            assert_eq!(
                dispatcher.dispatch_command(&BridgeCommand::AgentStatus),
                Ok(encode_status_snapshot(snapshot).to_vec())
            );
        }
    }

    struct TestDispatcher;

    impl CapabilityDispatcher for TestDispatcher {
        type Error = ();

        fn dispatch(
            &mut self,
            _request: &AuthorizedCapabilityRequest,
        ) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }
    }

    type TestExpectedRequest =
        RemoteSessionExpectedDeviceAdmissionRequest<TestDispatcher, fn() -> u64>;
    type TestExpectedRejection =
        RemoteSessionExpectedDeviceAdmissionRejection<TestDispatcher, fn() -> u64>;

    fn test_verifier_time() -> u64 {
        1
    }

    fn test_admission_timing(_device_id: &DeviceId) -> RemoteSessionRealAdmissionTiming {
        RemoteSessionRealAdmissionTiming::new(1..2, 1, 1..2)
    }

    fn test_completion(_completion: RemoteSessionRegisteredWorkerCompletion) {}

    fn test_rejection(_rejection: TestExpectedRejection) {}

    fn test_admission_failure(_failure: RemoteSessionRepeatedAdmissionFailure) {}

    fn assert_remote_operation_shape<F>(operation: F)
    where
        F: FnOnce(LinuxAgentRemoteSupervisorShutdownPublisher) + Send + 'static,
    {
        drop(operation);
    }

    #[test]
    fn execution_mode_source_public_reader_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<LinuxAgentExecutionMode, LinuxAgentExecutionModeSourceError>,
        ) {
            let _ = reader;
        }

        assert_eq!(PRW_AGENT_EXECUTION_MODE_ENV, "PRW_AGENT_EXECUTION_MODE");
        assert_signature(load_linux_agent_execution_mode_from_env);
    }

    #[test]
    fn execution_mode_source_accepts_only_exact_selected_values() {
        assert_eq!(
            parse_linux_agent_execution_mode_value(Some(OsString::from("local_only"))),
            Ok(LinuxAgentExecutionMode::LocalOnly)
        );
        assert_eq!(
            parse_linux_agent_execution_mode_value(Some(OsString::from("configured_remote"))),
            Ok(LinuxAgentExecutionMode::ConfiguredRemote)
        );

        for rejected in [
            "",
            "local",
            "remote",
            "LOCAL_ONLY",
            "CONFIGURED_REMOTE",
            "local-only",
            "configured-remote",
            " local_only",
            "local_only ",
            " configured_remote",
            "configured_remote ",
        ] {
            assert_eq!(
                parse_linux_agent_execution_mode_value(Some(OsString::from(rejected))),
                Err(LinuxAgentExecutionModeSourceError::InvalidValue)
            );
        }
        assert_eq!(
            parse_linux_agent_execution_mode_value(None),
            Err(LinuxAgentExecutionModeSourceError::Missing)
        );
    }

    #[cfg(unix)]
    #[test]
    fn execution_mode_source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_execution_mode_value(Some(OsString::from_vec(vec![0xff]))),
            Err(LinuxAgentExecutionModeSourceError::NonUnicode)
        );
    }

    #[test]
    fn execution_mode_source_errors_are_bounded_and_source_free() {
        for (error, expected) in [
            (
                LinuxAgentExecutionModeSourceError::Missing,
                "agent execution mode configuration missing",
            ),
            (
                LinuxAgentExecutionModeSourceError::NonUnicode,
                "agent execution mode configuration encoding invalid",
            ),
            (
                LinuxAgentExecutionModeSourceError::InvalidValue,
                "agent execution mode configuration invalid",
            ),
        ] {
            assert_eq!(error.to_string(), expected);
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn remote_bind_source_public_reader_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<SocketAddr, LinuxAgentRemoteBindAddressSourceError>,
        ) {
            let _ = reader;
        }

        assert_eq!(PRW_REMOTE_BIND_ADDR_ENV, "PRW_REMOTE_BIND_ADDR");
        assert_signature(load_linux_agent_remote_bind_addr_from_env);
    }

    #[test]
    fn remote_bind_source_rejects_missing_empty_and_malformed_values() {
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(None),
            Err(LinuxAgentRemoteBindAddressSourceError::Unavailable)
        );
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::new())),
            Err(LinuxAgentRemoteBindAddressSourceError::Unavailable)
        );
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from("example.invalid:4433"))),
            Err(LinuxAgentRemoteBindAddressSourceError::SocketAddressInvalid)
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_bind_source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from_vec(vec![0xff]))),
            Err(LinuxAgentRemoteBindAddressSourceError::EncodingInvalid)
        );
    }

    #[test]
    fn remote_bind_source_preserves_exact_ipv4_ipv6_loopback_and_port_zero() {
        let ipv4 = SocketAddr::from(([192, 0, 2, 10], 4433));
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from(ipv4.to_string()))),
            Ok(ipv4)
        );

        let ipv6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 10), 4434));
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from(ipv6.to_string()))),
            Ok(ipv6)
        );

        let port_zero = SocketAddr::from(([192, 0, 2, 10], 0));
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from(port_zero.to_string()))),
            Ok(port_zero)
        );

        let loopback = SocketAddr::from(([127, 0, 0, 1], 4435));
        assert_eq!(
            parse_linux_agent_remote_bind_addr_value(Some(OsString::from(loopback.to_string()))),
            Ok(loopback)
        );
    }

    #[test]
    fn remote_bind_source_rejects_non_advertisable_address_classes() {
        for rejected in [
            SocketAddr::from(([0, 0, 0, 0], 4433)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 4433)),
            SocketAddr::from(([224, 0, 0, 1], 4433)),
            SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 4433)),
            SocketAddr::from((Ipv4Addr::BROADCAST, 4433)),
        ] {
            assert_eq!(
                parse_linux_agent_remote_bind_addr_value(Some(OsString::from(
                    rejected.to_string()
                ))),
                Err(LinuxAgentRemoteBindAddressSourceError::AddressNotBindAdvertisable)
            );
        }
    }

    #[test]
    fn remote_peer_device_source_public_reader_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<DeviceId, LinuxAgentRemotePeerDeviceSourceError>,
        ) {
            let _ = reader;
        }

        assert_eq!(PRW_REMOTE_PEER_DEVICE_ID_ENV, "PRW_REMOTE_PEER_DEVICE_ID");
        assert_signature(load_linux_agent_remote_peer_device_id_from_env);
    }

    #[test]
    fn remote_peer_device_source_rejects_missing_empty_and_whitespace_values() {
        assert_eq!(
            parse_linux_agent_remote_peer_device_id_value(None),
            Err(LinuxAgentRemotePeerDeviceSourceError::Missing)
        );
        assert_eq!(
            parse_linux_agent_remote_peer_device_id_value(Some(OsString::new())),
            Err(LinuxAgentRemotePeerDeviceSourceError::InvalidIdentifier)
        );
        assert_eq!(
            parse_linux_agent_remote_peer_device_id_value(Some(OsString::from("   "))),
            Err(LinuxAgentRemotePeerDeviceSourceError::InvalidIdentifier)
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_peer_device_source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_remote_peer_device_id_value(Some(OsString::from_vec(vec![0xff]))),
            Err(LinuxAgentRemotePeerDeviceSourceError::NonUnicode)
        );
    }

    #[test]
    fn remote_peer_device_source_preserves_exact_non_empty_identifier() {
        let ordinary =
            parse_linux_agent_remote_peer_device_id_value(Some(OsString::from("peer-device-1")))
                .expect("ordinary peer device identifier");
        assert_eq!(ordinary.as_str(), "peer-device-1");

        let spaced = parse_linux_agent_remote_peer_device_id_value(Some(OsString::from(
            "  peer-device-1  ",
        )))
        .expect("non-empty spaced peer device identifier");
        assert_eq!(spaced.as_str(), "  peer-device-1  ");
    }

    #[test]
    fn remote_max_active_workers_source_public_reader_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<NonZeroUsize, LinuxAgentRemoteMaxActiveWorkersSourceError>,
        ) {
            let _ = reader;
        }

        assert_eq!(
            PRW_REMOTE_MAX_ACTIVE_WORKERS_ENV,
            "PRW_REMOTE_MAX_ACTIVE_WORKERS"
        );
        assert_signature(load_linux_agent_remote_max_active_workers_from_env);
    }

    #[test]
    fn remote_max_active_workers_source_rejects_missing_empty_and_malformed_values() {
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(None),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::Missing)
        );
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::new())),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
        );

        for malformed in [" 1", "1 ", "+1", "-1", "1.0", "1_0", "1e1", "1a"] {
            assert_eq!(
                parse_linux_agent_remote_max_active_workers_value(Some(OsString::from(malformed))),
                Err(LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn remote_max_active_workers_source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from_vec(vec![0xff]))),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::NonUnicode)
        );
    }

    #[test]
    fn remote_max_active_workers_source_rejects_zero_and_target_usize_overflow() {
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from("0"))),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
        );
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from("0000"))),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
        );

        let overflow = format!("{}0", usize::MAX);
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from(overflow))),
            Err(LinuxAgentRemoteMaxActiveWorkersSourceError::InvalidValue)
        );
    }

    #[test]
    fn remote_max_active_workers_source_preserves_positive_magnitude_and_leading_zeroes() {
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from("17")))
                .expect("positive worker bound")
                .get(),
            17
        );
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from("00017")))
                .expect("leading-zero positive worker bound")
                .get(),
            17
        );
        assert_eq!(
            parse_linux_agent_remote_max_active_workers_value(Some(OsString::from(
                usize::MAX.to_string(),
            )))
            .expect("target-usize maximum is a valid positive worker bound")
            .get(),
            usize::MAX
        );
    }

    #[test]
    fn remote_application_lease_source_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<
                RemoteSessionApplicationLeasePolicy,
                LinuxAgentRemoteApplicationLeasePolicySourceError,
            >,
        ) {
            let _ = reader;
        }

        assert_eq!(
            PRW_REMOTE_APPLICATION_LEASE_SECONDS_ENV,
            "PRW_REMOTE_APPLICATION_LEASE_SECONDS"
        );
        assert_signature(load_linux_agent_remote_application_lease_policy_from_env);
    }

    #[test]
    fn remote_application_lease_source_rejects_missing_empty_and_malformed_values() {
        assert_eq!(
            parse_linux_agent_remote_application_lease_policy_value(None),
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::Missing)
        );
        assert_eq!(
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::new())),
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::InvalidValue)
        );
        for malformed in [
            " 1", "1 ", "+1", "-1", "1.0", "1_0", "1e1", "1s", "1a", "\t1",
        ] {
            assert_eq!(
                parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from(
                    malformed,
                ))),
                Err(LinuxAgentRemoteApplicationLeasePolicySourceError::InvalidValue)
            );
        }
        let overflow = format!("{}0", u64::MAX);
        assert_eq!(
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from(overflow))),
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::InvalidValue)
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_application_lease_source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from_vec(
                vec![0xff,]
            ))),
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::NonUnicode)
        );
    }

    #[test]
    fn remote_application_lease_source_preserves_policy_semantics_and_leading_zeroes() {
        let zero =
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from("0")));
        assert_eq!(
            zero,
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::Policy(
                crate::remote_session_capability_runtime::RemoteSessionApplicationLeasePolicyError::InvalidLifetime,
            ))
        );
        let zero_padded =
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from("0000")));
        assert_eq!(zero_padded, zero);

        for (raw, expected) in [("1", 1), ("0001", 1), ("3600", 3600), ("003600", 3600)] {
            assert_eq!(
                parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from(raw)))
                    .expect("selected application-lease policy value")
                    .lifetime_seconds(),
                expected
            );
        }

        assert_eq!(
            parse_linux_agent_remote_application_lease_policy_value(Some(OsString::from("3601"))),
            Err(LinuxAgentRemoteApplicationLeasePolicySourceError::Policy(
                crate::remote_session_capability_runtime::RemoteSessionApplicationLeasePolicyError::InvalidLifetime,
            ))
        );
    }

    #[test]
    fn remote_application_lease_source_error_preserves_only_policy_source_chain() {
        use std::error::Error as _;

        for error in [
            LinuxAgentRemoteApplicationLeasePolicySourceError::Missing,
            LinuxAgentRemoteApplicationLeasePolicySourceError::NonUnicode,
            LinuxAgentRemoteApplicationLeasePolicySourceError::InvalidValue,
        ] {
            assert!(error.source().is_none());
            assert!(!error.to_string().contains("3600"));
        }
        let policy = LinuxAgentRemoteApplicationLeasePolicySourceError::Policy(
            crate::remote_session_capability_runtime::RemoteSessionApplicationLeasePolicyError::InvalidLifetime,
        );
        assert!(policy.source().is_some());
        assert_eq!(
            policy.to_string(),
            "remote application-lease policy invalid"
        );
    }

    #[test]
    fn remote_requester_rendezvous_max_records_source_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<
                usize,
                super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError,
            >,
        ) {
            let _ = reader;
        }

        assert_eq!(
            super::PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS_ENV,
            "PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS"
        );
        assert_signature(super::load_linux_agent_remote_requester_rendezvous_max_records_from_env);
    }

    #[test]
    fn remote_requester_rendezvous_max_records_source_rejects_missing_empty_and_malformed_values() {
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(None),
            Err(super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::Missing)
        );
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::new(),
            )),
            Err(super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::InvalidValue)
        );

        for malformed in [" 1", "1 ", "+1", "-1", "1.0", "1_0", "1e1", "1a"] {
            assert_eq!(
                super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                    OsString::from(malformed),
                )),
                Err(super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::InvalidValue)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn remote_requester_rendezvous_max_records_source_rejects_non_unicode_value() {
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from_vec(vec![0xff]),
            )),
            Err(super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::NonUnicode)
        );
    }

    #[test]
    fn remote_requester_rendezvous_max_records_source_preserves_zero_and_exact_magnitude() {
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from("0"),
            )),
            Ok(0)
        );
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from("0000"),
            )),
            Ok(0)
        );
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from("17"),
            )),
            Ok(17)
        );
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from("00017"),
            )),
            Ok(17)
        );
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from(usize::MAX.to_string()),
            )),
            Ok(usize::MAX)
        );
    }

    #[test]
    fn remote_requester_rendezvous_max_records_source_rejects_target_usize_overflow() {
        let overflow = format!("{}0", usize::MAX);
        assert_eq!(
            super::parse_linux_agent_remote_requester_rendezvous_max_records_value(Some(
                OsString::from(overflow),
            )),
            Err(super::LinuxAgentRemoteRequesterRendezvousMaxRecordsSourceError::InvalidValue)
        );
    }

    #[test]
    fn production_remote_process_input_population_error_preserves_selected_stage_types() {
        fn assert_worker_source_conversion(
            convert: fn(
                LinuxAgentRemoteMaxActiveWorkersSourceError,
            )
                -> super::LinuxAgentProductionRemoteProcessInputPopulationError,
        ) {
            let _ = convert;
        }

        fn assert_bind_source_conversion(
            convert: fn(
                LinuxAgentRemoteBindAddressSourceError,
            )
                -> super::LinuxAgentProductionRemoteProcessInputPopulationError,
        ) {
            let _ = convert;
        }

        assert_worker_source_conversion(
            super::LinuxAgentProductionRemoteProcessInputPopulationError::from,
        );
        assert_bind_source_conversion(
            super::LinuxAgentProductionRemoteProcessInputPopulationError::from,
        );

        let worker = super::LinuxAgentProductionRemoteProcessInputPopulationError::from(
            LinuxAgentRemoteMaxActiveWorkersSourceError::Missing,
        );
        assert!(matches!(
            worker,
            super::LinuxAgentProductionRemoteProcessInputPopulationError::WorkerLimitSource(
                LinuxAgentRemoteMaxActiveWorkersSourceError::Missing
            )
        ));
        assert_eq!(worker.to_string(), "production worker-limit source failed");
        assert!(std::error::Error::source(&worker).is_some());

        let bind = super::LinuxAgentProductionRemoteProcessInputPopulationError::from(
            LinuxAgentRemoteBindAddressSourceError::Unavailable,
        );
        assert!(matches!(
            bind,
            super::LinuxAgentProductionRemoteProcessInputPopulationError::BindAddressSource(
                LinuxAgentRemoteBindAddressSourceError::Unavailable
            )
        ));
        assert_eq!(bind.to_string(), "production bind-address source failed");
        assert!(std::error::Error::source(&bind).is_some());
    }

    #[test]
    fn production_worker_limit_input_population_helper_has_selected_type_shape() {
        #[allow(clippy::type_complexity)]
        fn assert_signature(
            entry: fn(
                SharedCurrentCapabilityAuthority<BoundedLocalReadPolicy>,
                SessionAuthenticationService,
                mpsc::Receiver<TestExpectedRequest>,
                fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
                fn(RemoteSessionRegisteredWorkerCompletion),
                fn(TestExpectedRejection),
                fn(RemoteSessionRepeatedAdmissionFailure),
            ) -> Result<
                LinuxAgentRemoteProcessOperationInputs<
                    BoundedLocalReadPolicy,
                    TestDispatcher,
                    fn() -> u64,
                    fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
                    fn(RemoteSessionRegisteredWorkerCompletion),
                    fn(TestExpectedRejection),
                    fn(RemoteSessionRepeatedAdmissionFailure),
                >,
                super::LinuxAgentProductionRemoteProcessInputPopulationError,
            >,
        ) {
            let _ = entry;
        }

        assert_signature(
            super::linux_agent_remote_process_operation_inputs_from_production_worker_limit::<
                BoundedLocalReadPolicy,
                TestDispatcher,
                fn() -> u64,
                fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
                fn(RemoteSessionRegisteredWorkerCompletion),
                fn(TestExpectedRejection),
                fn(RemoteSessionRepeatedAdmissionFailure),
            >,
        );
    }

    #[test]
    fn production_peer_input_population_error_preserves_selected_stage_types() {
        fn assert_peer_source_conversion(
            convert: fn(
                LinuxAgentRemotePeerDeviceSourceError,
            ) -> super::LinuxAgentProductionPeerInputPopulationError,
        ) {
            let _ = convert;
        }

        fn assert_bootstrap_conversion(
            convert: fn(
                crate::production_durable_registry_custody_bootstrap::ProductionDurableRegistryCustodyBootstrapError,
            ) -> super::LinuxAgentProductionPeerInputPopulationError,
        ) {
            let _ = convert;
        }

        fn assert_lookup_conversion(
            convert: fn(
                prw_registry::durable_registry_authority::DurableRegistryAuthorityError,
            ) -> super::LinuxAgentProductionPeerInputPopulationError,
        ) {
            let _ = convert;
        }

        assert_peer_source_conversion(super::LinuxAgentProductionPeerInputPopulationError::from);
        assert_bootstrap_conversion(super::LinuxAgentProductionPeerInputPopulationError::from);
        assert_lookup_conversion(super::LinuxAgentProductionPeerInputPopulationError::from);

        let peer_source = super::LinuxAgentProductionPeerInputPopulationError::from(
            LinuxAgentRemotePeerDeviceSourceError::Missing,
        );
        assert!(matches!(
            peer_source,
            super::LinuxAgentProductionPeerInputPopulationError::PeerDeviceSource(
                LinuxAgentRemotePeerDeviceSourceError::Missing
            )
        ));
        assert_eq!(
            peer_source.to_string(),
            "production peer-device source failed"
        );
        assert!(std::error::Error::source(&peer_source).is_some());

        let lookup = super::LinuxAgentProductionPeerInputPopulationError::from(
            prw_registry::durable_registry_authority::DurableRegistryAuthorityError::ReadUnavailable,
        );
        assert!(matches!(
            lookup,
            super::LinuxAgentProductionPeerInputPopulationError::DurableRegistryLookup(
                prw_registry::durable_registry_authority::DurableRegistryAuthorityError::ReadUnavailable
            )
        ));
        assert_eq!(
            lookup.to_string(),
            "production durable-registry peer lookup failed"
        );
        assert!(std::error::Error::source(&lookup).is_some());
    }

    #[test]
    fn production_peer_input_population_helper_future_is_dormant_until_polled() {
        let (_sender, receiver) = mpsc::channel::<TestExpectedRequest>(1);
        let remote_process_inputs = LinuxAgentRemoteProcessOperationInputs::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            NonZeroUsize::new(1).expect("nonzero test worker bound"),
            SharedCurrentCapabilityAuthority::new(
                WorkspaceDeviceRegistry::new(),
                BoundedLocalReadPolicy::allow_local_reads(),
            ),
            SessionAuthenticationService::new(),
            receiver,
            test_admission_timing as fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            test_completion as fn(RemoteSessionRegisteredWorkerCompletion),
            test_rejection as fn(TestExpectedRejection),
            test_admission_failure as fn(RemoteSessionRepeatedAdmissionFailure),
        );

        let future = super::linux_agent_production_reachability_remote_process_operation_inputs_from_production_peer(
            remote_process_inputs,
        );
        drop(future);
    }

    #[test]
    fn initial_profile_matches_phase_101_lock() {
        let config = initial_runtime_config();
        assert_eq!(config.worker_capacity().get(), 2);
        assert_eq!(config.listener_backlog().get(), 8);
        assert_eq!(config.scheduling_attempt_budget().get(), 2);
        assert_eq!(config.worker_config().request_budget().get(), 1);
        assert_eq!(config.worker_config().read_budget().duration().as_secs(), 2);
        assert_eq!(
            config.worker_config().write_budget().duration().as_secs(),
            2
        );
        let capacity = LocalLinuxWorkerCapacity::new(config.worker_capacity());
        assert_eq!(capacity.max_workers(), 2);
    }

    #[test]
    fn phase_101_policy_allows_only_existing_local_reads() {
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        assert_eq!(
            policy.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Allow
        );
        for denied in [
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::FilesDelete,
            Capability::ForwardingCreate,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(denied), Decision::Deny);
        }
    }

    #[test]
    fn success_requires_normal_terminal_clean_cleanup_and_restored_mask() {
        let success = LinuxAgentBootstrapReport {
            terminal: LinuxAgentBootstrapTerminal::SigTerm,
            counters: LinuxAgentBootstrapCounters::default(),
            cleanup: LinuxAgentBootstrapCleanup::Clean,
            signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore::Restored,
        };
        assert!(success.is_success());

        for report in [
            LinuxAgentBootstrapReport {
                terminal: LinuxAgentBootstrapTerminal::RuntimeFatal,
                ..success
            },
            LinuxAgentBootstrapReport {
                cleanup: LinuxAgentBootstrapCleanup::Failed,
                ..success
            },
            LinuxAgentBootstrapReport {
                signal_mask_restore: LinuxAgentBootstrapSignalMaskRestore::Failed,
                ..success
            },
        ] {
            assert!(!report.is_success());
        }
    }

    #[test]
    fn second_instance_maps_to_stable_already_running_class() {
        assert_eq!(
            map_lifecycle_start_kind(LocalLinuxProductionLifecycleAssemblyError::InstanceLock(
                AgentInstanceLockError::AlreadyRunning,
            )),
            LinuxAgentBootstrapStartKind::AlreadyRunning
        );
    }

    #[test]
    fn public_run_retains_exact_no_companion_signature() {
        fn assert_run_signature(
            entry: fn() -> Result<LinuxAgentBootstrapReport, LinuxAgentBootstrapStartFailure>,
        ) {
            let _ = entry;
        }

        assert_run_signature(run);
    }

    #[test]
    fn public_remote_companion_facade_has_exact_injected_operation_shape() {
        type RemoteCompanionEntry =
            fn(
                fn(LinuxAgentRemoteSupervisorShutdownPublisher),
            )
                -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>;

        fn operation(_: LinuxAgentRemoteSupervisorShutdownPublisher) {}
        fn assert_signature(entry: RemoteCompanionEntry) {
            let _ = entry;
        }

        assert_signature(
            run_with_remote_process_companion::<fn(LinuxAgentRemoteSupervisorShutdownPublisher)>,
        );
        let _ = operation;
    }

    #[test]
    fn public_shutdown_publisher_has_exact_consuming_method_shape() {
        fn assert_signature(
            publish: fn(
                LinuxAgentRemoteSupervisorShutdownPublisher,
                RemoteSessionSupervisorShutdownController,
            ) -> LinuxAgentRemoteSupervisorShutdownPublish,
        ) {
            let _ = publish;
        }

        assert_signature(LinuxAgentRemoteSupervisorShutdownPublisher::publish);
    }

    #[test]
    fn injected_operation_factory_construction_is_side_effect_free_and_send_static() {
        let (_sender, receiver) = mpsc::channel::<TestExpectedRequest>(1);
        let inputs = LinuxAgentRemoteProcessOperationInputs::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            NonZeroUsize::new(1).expect("nonzero test worker bound"),
            SharedCurrentCapabilityAuthority::new(
                WorkspaceDeviceRegistry::new(),
                BoundedLocalReadPolicy::allow_local_reads(),
            ),
            SessionAuthenticationService::new(),
            receiver,
            test_admission_timing as fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            test_completion as fn(RemoteSessionRegisteredWorkerCompletion),
            test_rejection as fn(TestExpectedRejection),
            test_admission_failure as fn(RemoteSessionRepeatedAdmissionFailure),
        );

        let operation = linux_agent_remote_process_operation(inputs);
        assert_remote_operation_shape(operation);
        let _ = test_verifier_time as fn() -> u64;
    }

    #[test]
    fn production_operation_factory_construction_is_side_effect_free_and_send_static() {
        let peer = PeerConnectivityIdentity::new(
            DeviceId::new("c03e-ig-peer").expect("device"),
            TransportIdentity::new([0x49; 32]).expect("transport"),
        );
        let (_sender, receiver) = mpsc::channel::<TestExpectedRequest>(1);
        let remote_process_inputs = LinuxAgentRemoteProcessOperationInputs::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            NonZeroUsize::new(1).expect("nonzero test worker bound"),
            SharedCurrentCapabilityAuthority::new(
                WorkspaceDeviceRegistry::new(),
                BoundedLocalReadPolicy::allow_local_reads(),
            ),
            SessionAuthenticationService::new(),
            receiver,
            test_admission_timing as fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            test_completion as fn(RemoteSessionRegisteredWorkerCompletion),
            test_rejection as fn(TestExpectedRejection),
            test_admission_failure as fn(RemoteSessionRepeatedAdmissionFailure),
        );
        let inputs = LinuxAgentProductionReachabilityRemoteProcessOperationInputs::new(
            peer,
            remote_process_inputs,
        );

        let operation = linux_agent_production_reachability_remote_process_operation(inputs);
        assert_remote_operation_shape(operation);
    }

    #[test]
    fn production_requester_rendezvous_join_factory_construction_is_side_effect_free_and_send_static()
     {
        let peer = PeerConnectivityIdentity::new(
            DeviceId::new("c03e-ii-peer").expect("device"),
            TransportIdentity::new([0x52; 32]).expect("transport"),
        );
        let (_sender, receiver) = mpsc::channel::<TestExpectedRequest>(1);
        let remote_process_inputs = LinuxAgentRemoteProcessOperationInputs::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            NonZeroUsize::new(1).expect("nonzero test worker bound"),
            SharedCurrentCapabilityAuthority::new(
                WorkspaceDeviceRegistry::new(),
                BoundedLocalReadPolicy::allow_local_reads(),
            ),
            SessionAuthenticationService::new(),
            receiver,
            test_admission_timing as fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            test_completion as fn(RemoteSessionRegisteredWorkerCompletion),
            test_rejection as fn(TestExpectedRejection),
            test_admission_failure as fn(RemoteSessionRepeatedAdmissionFailure),
        );
        let production_inputs = LinuxAgentProductionReachabilityRemoteProcessOperationInputs::new(
            peer,
            remote_process_inputs,
        );
        let requester_rendezvous_start_policy_source =
            super::BoundedRequesterRendezvousStartPolicySource::default();
        let requester_rendezvous_authority = SharedRequesterRendezvousAuthority::new(
            super::CandidatePublicationRequesterRendezvousRuntimeOwner::new(
                prw_remote_bridge::requester_rendezvous_in_memory_provider::InMemoryRequesterRendezvousAuthorityProvider::new(1)
                    .expect("explicit non-zero requester/rendezvous provider capacity"),
            ),
            1,
        )
        .expect("explicit non-zero scheduling-consumption capacity");
        let inputs = super::LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs::new(
            production_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_authority,
        );

        let operation = super::linux_agent_production_reachability_requester_rendezvous_remote_process_operation(inputs);
        assert_remote_operation_shape(operation);
    }

    #[test]
    fn synthetic_composition_preserves_same_executor_and_exact_stage_order() {
        let events = RefCell::new(Vec::new());

        let completed = run_remote_process_operation_composition(
            || {
                events.borrow_mut().push("executor");
                Ok::<_, ()>(31_u8)
            },
            |executor| {
                events.borrow_mut().push("bootstrap");
                assert_eq!(*executor, 31);
                Ok::<_, ()>(37_u8)
            },
            |executor, authority| {
                events.borrow_mut().push("endpoint");
                assert_eq!(executor, 31);
                assert_eq!(authority, 37);
                Ok::<_, ()>((41_u8, 43_u8))
            },
            |controller| {
                events.borrow_mut().push("publish");
                assert_eq!(controller, 43);
                LinuxAgentRemoteSupervisorShutdownPublish::Published
            },
            |endpoint, publication| {
                events.borrow_mut().push("lifecycle");
                assert_eq!(endpoint, 41);
                assert_eq!(
                    publication,
                    LinuxAgentRemoteSupervisorShutdownPublish::Published
                );
            },
        );

        assert!(completed);
        assert_eq!(
            *events.borrow(),
            ["executor", "bootstrap", "endpoint", "publish", "lifecycle"]
        );
    }

    #[test]
    fn synthetic_failures_suppress_all_later_stages() {
        let later = Cell::new(0_u8);
        let completed = run_remote_process_operation_composition(
            || Err::<u8, _>(()),
            |_executor| {
                later.set(later.get() + 1);
                Ok::<_, ()>(2_u8)
            },
            |_executor, _authority| {
                later.set(later.get() + 1);
                Ok::<_, ()>((3_u8, 4_u8))
            },
            |_controller| {
                later.set(later.get() + 1);
                5_u8
            },
            |_endpoint, _publication| later.set(later.get() + 1),
        );
        assert!(!completed);
        assert_eq!(later.get(), 0);

        let later = Cell::new(0_u8);
        let completed = run_remote_process_operation_composition(
            || Ok::<_, ()>(1_u8),
            |_executor| Err::<u8, _>(()),
            |_executor, _authority| {
                later.set(later.get() + 1);
                Ok::<_, ()>((3_u8, 4_u8))
            },
            |_controller| {
                later.set(later.get() + 1);
                5_u8
            },
            |_endpoint, _publication| later.set(later.get() + 1),
        );
        assert!(!completed);
        assert_eq!(later.get(), 0);

        let later = Cell::new(0_u8);
        let completed = run_remote_process_operation_composition(
            || Ok::<_, ()>(1_u8),
            |_executor| Ok::<_, ()>(2_u8),
            |_executor, _authority| Err::<(u8, u8), _>(()),
            |_controller| {
                later.set(later.get() + 1);
                5_u8
            },
            |_endpoint, _publication| later.set(later.get() + 1),
        );
        assert!(!completed);
        assert_eq!(later.get(), 0);
    }

    #[test]
    fn receiver_gone_publication_equivalent_still_drives_same_lifecycle_stage() {
        let lifecycle_called = Cell::new(false);

        let completed = run_remote_process_operation_composition(
            || Ok::<_, ()>(1_u8),
            |_executor| Ok::<_, ()>(2_u8),
            |_executor, _authority| Ok::<_, ()>((3_u8, 4_u8)),
            |_controller| LinuxAgentRemoteSupervisorShutdownPublish::ReceiverGoneShutdownRequested,
            |_endpoint, publication| {
                assert_eq!(
                    publication,
                    LinuxAgentRemoteSupervisorShutdownPublish::ReceiverGoneShutdownRequested
                );
                lifecycle_called.set(true);
            },
        );

        assert!(completed);
        assert!(lifecycle_called.get());
    }

    #[test]
    fn internal_publication_outcomes_map_to_bounded_public_classes() {
        assert_eq!(
            map_remote_shutdown_publish(RemoteSessionSupervisorShutdownPublish::Published),
            LinuxAgentRemoteSupervisorShutdownPublish::Published
        );
        assert_eq!(
            map_remote_shutdown_publish(
                RemoteSessionSupervisorShutdownPublish::ReceiverGoneShutdownRequested
            ),
            LinuxAgentRemoteSupervisorShutdownPublish::ReceiverGoneShutdownRequested
        );
    }

    #[test]
    fn synthetic_remote_process_spawn_failure_remains_secondary_evidence() {
        assert_eq!(
            finalize_remote_process_companion(Err(RemoteSessionProcessLifecycleSpawnError)),
            LinuxAgentRemoteProcessCompanionFinalization::SpawnFailed
        );
    }

    #[test]
    fn injected_remote_process_owner_maps_to_bounded_public_join_evidence() {
        let owner = RemoteSessionProcessLifecycleOwner::spawn(drop)
            .expect("injected non-networking remote process thread spawns");

        assert_eq!(
            finalize_remote_process_companion(Ok(owner)),
            LinuxAgentRemoteProcessCompanionFinalization::Finalized {
                controller:
                    LinuxAgentRemoteProcessControllerFinalization::UnavailableBeforeEndpointStartup,
                thread: LinuxAgentRemoteProcessThreadFinalization::Joined,
            }
        );
    }
}

/// Fixed non-secret process configuration name for the production expected-device
/// scheduling-consumption terminal-record bound.
#[allow(
    dead_code,
    reason = "C03e-NN materializes the NM-selected fixed expected-device scheduling-consumption max-records environment source before separately gated ledger representation and population composition"
)]
pub(crate) const PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS_ENV: &str =
    prw_agent_configuration::PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS;

/// Bounded failure while acquiring or validating expected-device scheduling-consumption capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-NN materializes the NM-selected bounded scheduling-consumption capacity source error before separately gated ledger representation"
)]
pub(crate) enum LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError {
    /// The fixed configuration value is absent.
    Missing,
    /// The operating-system value is not valid Unicode.
    NonUnicode,
    /// The configured value is empty, malformed, or outside target `usize`.
    InvalidValue,
}

impl std::fmt::Display
    for LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => {
                "remote expected-device scheduling-consumption max-records configuration missing"
            }
            Self::NonUnicode => {
                "remote expected-device scheduling-consumption max-records configuration encoding invalid"
            }
            Self::InvalidValue => {
                "remote expected-device scheduling-consumption max-records configuration invalid"
            }
        })
    }
}

impl std::error::Error
    for LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError
{
}

#[allow(
    dead_code,
    reason = "C03e-NN materializes the NM-selected strict ASCII-decimal scheduling-consumption max-records parser before separately gated ledger representation"
)]
fn parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(
    value: Option<OsString>,
) -> Result<usize, LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError> {
    let value = value
        .ok_or(LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::Missing)?;
    let value = value.into_string().map_err(|_| {
        LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::NonUnicode
    })?;
    prw_agent_configuration::validate_remote_expected_device_scheduling_consumption_max_records(
        &value,
    )
    .map_err(|_| {
        LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::InvalidValue
    })
}

/// Loads the explicitly configured production expected-device scheduling-consumption record bound.
///
/// The exact Unicode value must contain ASCII decimal digits only and is converted fail-closed to
/// target `usize`. Zero is returned unchanged; the separately gated future scheduling-consumption
/// ledger constructor remains the sole semantic authority for its non-zero capacity invariant.
/// This source performs no trimming, fallback, retry, alternate-variable lookup, requester-provider
/// capacity aliasing, worker-limit aliasing, channel-capacity aliasing, cache, refresh, ledger
/// construction, population composition, or runtime activation.
///
/// # Errors
///
/// Fails closed when the fixed configuration is missing, non-Unicode, empty, malformed, or outside
/// target `usize`. The bounded error surface does not expose the configured value.
#[allow(
    dead_code,
    reason = "C03e-NN materializes the NM-selected fixed scheduling-consumption max-records environment loader before separately gated ledger representation and population composition"
)]
pub(crate) fn load_linux_agent_remote_expected_device_scheduling_consumption_max_records_from_env()
-> Result<usize, LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError> {
    parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(
        std::env::var_os(PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS_ENV),
    )
}

#[cfg(test)]
mod expected_device_scheduling_consumption_capacity_source_tests {
    use std::ffi::OsString;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::{
        LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError,
        PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS_ENV,
        load_linux_agent_remote_expected_device_scheduling_consumption_max_records_from_env,
        parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value,
    };

    #[test]
    fn source_has_exact_selected_shape() {
        fn assert_signature(
            reader: fn() -> Result<
                usize,
                LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError,
            >,
        ) {
            let _ = reader;
        }

        assert_eq!(
            PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS_ENV,
            "PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS"
        );
        assert_signature(
            load_linux_agent_remote_expected_device_scheduling_consumption_max_records_from_env,
        );
    }

    #[test]
    fn source_rejects_missing_empty_and_malformed_values() {
        assert_eq!(
            parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(None),
            Err(LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::Missing)
        );
        assert_eq!(
            parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(Some(
                OsString::new(),
            )),
            Err(
                LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::InvalidValue
            )
        );

        for malformed in [" 1", "1 ", "+1", "-1", "1.0", "1_0", "1e1", "1a"] {
            assert_eq!(
                parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(
                    Some(OsString::from(malformed)),
                ),
                Err(
                    LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::InvalidValue
                )
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_rejects_non_unicode_value() {
        assert_eq!(
            parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(Some(
                OsString::from_vec(vec![0xff]),
            )),
            Err(
                LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::NonUnicode
            )
        );
    }

    #[test]
    fn source_preserves_zero_and_exact_magnitude() {
        for (value, expected) in [("0", 0), ("0000", 0), ("17", 17), ("00017", 17)] {
            assert_eq!(
                parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(
                    Some(OsString::from(value)),
                ),
                Ok(expected)
            );
        }
        assert_eq!(
            parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(
                Some(OsString::from(usize::MAX.to_string()),)
            ),
            Ok(usize::MAX)
        );
    }

    #[test]
    fn source_rejects_target_usize_overflow() {
        let overflow = format!("{}0", usize::MAX);
        assert_eq!(
            parse_linux_agent_remote_expected_device_scheduling_consumption_max_records_value(Some(
                OsString::from(overflow),
            )),
            Err(
                LinuxAgentRemoteExpectedDeviceSchedulingConsumptionMaxRecordsSourceError::InvalidValue
            )
        );
    }
}

/// Dormant C03e-SF runtime-input-aware Linux composition selected by evidence-closed C03e-SE.
///
/// This crate-private seam receives already-separated sender custody from a future caller. It
/// derives the status-only dispatcher factory from the exact immutable runtime-input bundle, keeps
/// that factory inside one remote operation, and passes the same runtime-input bundle into the
/// existing companion runner. Construction/split of the capacity-one expected-request channel and
/// higher-owner invocation remain separately gated. This function is not invoked by `run()` or the
/// Agent executable.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-SF materializes the SE-selected dormant runtime-input-aware Linux operation seam before separately gated higher-owner channel integration"
)]
pub(crate) fn run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion<
    P,
    F,
    C,
    R,
    E,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        F,
        C,
        R,
        E,
    >,
    production_durable_capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    expected_request_sender: mpsc::Sender<
        RemoteSessionExpectedDeviceAdmissionRequest<
            LinuxAgentProductionRemoteCapabilityDispatcher,
            fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        >,
    >,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    P: PolicyEvaluator + Send + Sync + 'static,
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming + Send + 'static,
    C: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ) + Send
        + 'static,
    R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
            >,
        ) + Send
        + 'static,
    E: FnMut(DeviceId, RemoteSessionRealAdmissionError) + Send + 'static,
{
    with_initial_runtime_inputs(move |runtime_inputs| {
        let mut dispatcher_factory =
            linux_agent_production_remote_capability_dispatcher_factory_from_runtime_inputs(
                runtime_inputs,
            );
        let LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs {
            production_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_authority,
        } = inputs;
        let requester_rendezvous_start_policy_source =
            Arc::new(requester_rendezvous_start_policy_source);

        let operation = move |publisher: LinuxAgentRemoteSupervisorShutdownPublisher| {
            let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
                peer,
                remote_process_inputs,
            } = production_inputs;
            let LinuxAgentRemoteProcessOperationInputs {
                bind_addr,
                max_active_workers,
                capability_authority,
                mut session_authentication,
                expected_requests,
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            } = remote_process_inputs;

            let _ = run_remote_process_operation_composition(
                RemoteSessionExecutorRuntime::new,
                move |executor| {
                    executor
                        .bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                            &peer,
                        )
                },
                move |executor, runtime_custody| {
                    runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                        executor, bind_addr,
                    )
                },
                move |controller| publisher.publish(controller),
                move |lifecycle, _publication| {
                    let _ = lifecycle
                        .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection(
                            max_active_workers,
                            &capability_authority,
                            production_durable_capability_authority,
                            requester_rendezvous_start_policy_source,
                            &requester_rendezvous_authority,
                            &mut session_authentication,
                            expected_requests,
                            &mut dispatcher_factory,
                            &expected_request_sender,
                            on_completion,
                            admission_timing,
                            on_rejection,
                            on_admission_failure,
                        );
                },
            );
        };

        run_with_remote_process_companion_inputs(runtime_inputs, operation)
            .map(|(local, remote)| LinuxAgentBootstrapWithRemoteReport { local, remote })
    })
}

/// Fallible-admission-timing companion preserving the existing remote-process composition.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-SX adds only Cause/K and result-valued timing to the existing S1 Linux composition"
)]
pub(crate) fn run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_with_fallible_admission_timing<
    P,
    F,
    C,
    R,
    E,
    Cause,
    K,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        F,
        C,
        R,
        E,
    >,
    production_durable_capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    expected_request_sender: mpsc::Sender<
        RemoteSessionExpectedDeviceAdmissionRequest<
            LinuxAgentProductionRemoteCapabilityDispatcher,
            fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        >,
    >,
    on_timing_failure: K,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    P: PolicyEvaluator + Send + Sync + 'static,
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
                LinuxAgentProductionRemoteCapabilityDispatcher,
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
                LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ) + Send
        + 'static,
{
    with_initial_runtime_inputs(move |runtime_inputs| {
        let mut dispatcher_factory =
            linux_agent_production_remote_capability_dispatcher_factory_from_runtime_inputs(
                runtime_inputs,
            );
        let LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs {
            production_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_authority,
        } = inputs;
        let requester_rendezvous_start_policy_source =
            Arc::new(requester_rendezvous_start_policy_source);

        let operation = move |publisher: LinuxAgentRemoteSupervisorShutdownPublisher| {
            let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
                peer,
                remote_process_inputs,
            } = production_inputs;
            let LinuxAgentRemoteProcessOperationInputs {
                bind_addr,
                max_active_workers,
                capability_authority,
                mut session_authentication,
                expected_requests,
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            } = remote_process_inputs;

            let _ = run_remote_process_operation_composition(
                RemoteSessionExecutorRuntime::new,
                move |executor| {
                    executor
                        .bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                            &peer,
                        )
                },
                move |executor, runtime_custody| {
                    runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                        executor, bind_addr,
                    )
                },
                move |controller| publisher.publish(controller),
                move |lifecycle, _publication| {
                    let _ = lifecycle
                        .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_fallible_admission_timing(
                            max_active_workers,
                            &capability_authority,
                            production_durable_capability_authority,
                            requester_rendezvous_start_policy_source,
                            &requester_rendezvous_authority,
                            &mut session_authentication,
                            expected_requests,
                            &mut dispatcher_factory,
                            &expected_request_sender,
                            on_completion,
                            admission_timing,
                            on_rejection,
                            on_admission_failure,
                            on_timing_failure,
                        );
                },
            );
        };

        run_with_remote_process_companion_inputs(runtime_inputs, operation)
            .map(|(local, remote)| LinuxAgentBootstrapWithRemoteReport { local, remote })
    })
}

/// TE-selected Linux composition sibling carrying one already-validated application lease policy.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "C03e-TF forwards the typed lease policy and challenge-only timing source without selecting raw configuration or activation"
)]
pub(crate) fn run_with_production_reachability_requester_rendezvous_fallible_verifier_time_expected_device_admission_remote_process_companion_with_pre_aj_timing_and_application_lease_policy<
    P,
    F,
    C,
    R,
    E,
    Cause,
    K,
>(
    inputs: LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs<
        P,
        LinuxAgentProductionRemoteCapabilityDispatcher,
        fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        F,
        C,
        R,
        E,
    >,
    production_durable_capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    application_lease_policy: RemoteSessionApplicationLeasePolicy,
    expected_request_sender: mpsc::Sender<
        RemoteSessionExpectedDeviceAdmissionRequest<
            LinuxAgentProductionRemoteCapabilityDispatcher,
            fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
        >,
    >,
    on_timing_failure: K,
) -> Result<LinuxAgentBootstrapWithRemoteReport, LinuxAgentBootstrapStartFailure>
where
    P: PolicyEvaluator + Send + Sync + 'static,
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
                LinuxAgentProductionRemoteCapabilityDispatcher,
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
                LinuxAgentProductionRemoteCapabilityDispatcher,
                fn() -> Result<
                    u64,
                    prw_session::prwa_verifier_source::PrwaVerifierSourceError,
                >,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ) + Send
        + 'static,
{
    with_initial_runtime_inputs(move |runtime_inputs| {
        let mut dispatcher_factory =
            linux_agent_production_remote_capability_dispatcher_factory_from_runtime_inputs(
                runtime_inputs,
            );
        let LinuxAgentProductionReachabilityRequesterRendezvousRemoteProcessOperationInputs {
            production_inputs,
            requester_rendezvous_start_policy_source,
            requester_rendezvous_authority,
        } = inputs;
        let requester_rendezvous_start_policy_source =
            Arc::new(requester_rendezvous_start_policy_source);

        let operation = move |publisher: LinuxAgentRemoteSupervisorShutdownPublisher| {
            let LinuxAgentProductionReachabilityRemoteProcessOperationInputs {
                peer,
                remote_process_inputs,
            } = production_inputs;
            let LinuxAgentRemoteProcessOperationInputs {
                bind_addr,
                max_active_workers,
                capability_authority,
                mut session_authentication,
                expected_requests,
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            } = remote_process_inputs;

            let _ = run_remote_process_operation_composition(
                RemoteSessionExecutorRuntime::new,
                move |executor| {
                    executor
                        .bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
                            &peer,
                        )
                },
                move |executor, runtime_custody| {
                    runtime_custody.bind_remote_endpoint_with_executor_from_systemd_credentials(
                        executor, bind_addr,
                    )
                },
                move |controller| publisher.publish(controller),
                move |lifecycle, _publication| {
                    let _ = lifecycle
                        .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_pre_aj_timing_and_application_lease_policy(
                            max_active_workers,
                            &capability_authority,
                            production_durable_capability_authority,
                            requester_rendezvous_start_policy_source,
                            &requester_rendezvous_authority,
                            application_lease_policy,
                            &mut session_authentication,
                            expected_requests,
                            &mut dispatcher_factory,
                            &expected_request_sender,
                            on_completion,
                            admission_timing,
                            on_rejection,
                            on_admission_failure,
                            on_timing_failure,
                        );
                },
            );
        };

        run_with_agent_status_management_remote_process_companion_inputs(runtime_inputs, operation)
            .map(|(local, remote)| LinuxAgentBootstrapWithRemoteReport { local, remote })
    })
}
