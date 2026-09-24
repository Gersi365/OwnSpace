//! Shared, side-effect-free Agent configuration authority selected by C03e-TV.
//!
//! This crate owns exact process-configuration names, pure value validation, canonical TT/TU
//! systemd serialization, and (on Linux) the separately testable managed-file writer. It does not
//! read the Agent process environment and does not activate or reload systemd services.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
};

use prw_core::DeviceId;
use prw_remote_bridge::MAX_REMOTE_SESSION_LEASE_SECONDS;

#[cfg(target_os = "linux")]
pub mod linux_systemd;

/// Fixed non-secret process configuration name selecting the Agent executable lane.
pub const PRW_AGENT_EXECUTION_MODE: &str = "PRW_AGENT_EXECUTION_MODE";
/// Fixed non-secret production remote bind-address name.
pub const PRW_REMOTE_BIND_ADDR: &str = "PRW_REMOTE_BIND_ADDR";
/// Fixed non-secret production remote peer logical-device name.
pub const PRW_REMOTE_PEER_DEVICE_ID: &str = "PRW_REMOTE_PEER_DEVICE_ID";
/// Fixed non-secret production remote active-worker bound name.
pub const PRW_REMOTE_MAX_ACTIVE_WORKERS: &str = "PRW_REMOTE_MAX_ACTIVE_WORKERS";
/// Fixed non-secret production application-session lease lifetime name.
pub const PRW_REMOTE_APPLICATION_LEASE_SECONDS: &str = "PRW_REMOTE_APPLICATION_LEASE_SECONDS";
/// Fixed non-secret requester/rendezvous record-bound name.
pub const PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS: &str =
    "PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS";
/// Fixed non-secret expected-device scheduling-consumption record-bound name.
pub const PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS: &str =
    "PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS";

const LOCAL_ONLY_DROPIN: &str = "[Service]\nEnvironment=PRW_AGENT_EXECUTION_MODE=local_only\n";
const CONFIGURED_REMOTE_DROPIN: &str =
    "[Service]\nEnvironment=PRW_AGENT_EXECUTION_MODE=configured_remote\n";

/// Explicit validated Agent executable lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExecutionMode {
    /// Historical local-only lane.
    LocalOnly,
    /// Configured production remote lane.
    ConfiguredRemote,
}

impl AgentExecutionMode {
    /// Returns the exact semantic token selected by C03e-TQ/TT.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::ConfiguredRemote => "configured_remote",
        }
    }
}

/// Exact execution-mode text is not one of the two selected tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionModeValidationError;

impl fmt::Display for ExecutionModeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("agent execution mode value invalid")
    }
}

impl std::error::Error for ExecutionModeValidationError {}

/// Validates exact execution-mode semantic text without source acquisition or normalization.
///
/// # Errors
///
/// Returns [`ExecutionModeValidationError`] for every value other than `local_only` or
/// `configured_remote`.
pub fn validate_agent_execution_mode(
    value: &str,
) -> Result<AgentExecutionMode, ExecutionModeValidationError> {
    match value {
        "local_only" => Ok(AgentExecutionMode::LocalOnly),
        "configured_remote" => Ok(AgentExecutionMode::ConfiguredRemote),
        _ => Err(ExecutionModeValidationError),
    }
}

/// Pure remote bind-address validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteBindAddressValidationError {
    /// Empty semantic text.
    Unavailable,
    /// Text is not an exact [`SocketAddr`].
    SocketAddressInvalid,
    /// Address class is not eligible for this explicit bind-and-observe lane.
    AddressNotBindAdvertisable,
}

impl fmt::Display for RemoteBindAddressValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "remote bind-address value unavailable",
            Self::SocketAddressInvalid => "remote bind-address value malformed",
            Self::AddressNotBindAdvertisable => "remote bind-address value not bind-advertisable",
        })
    }
}

impl std::error::Error for RemoteBindAddressValidationError {}

/// Validates exact production remote bind-address semantic text.
///
/// # Errors
///
/// Rejects empty/malformed text, unspecified and multicast addresses, and IPv4 limited broadcast.
pub fn validate_remote_bind_addr(
    value: &str,
) -> Result<SocketAddr, RemoteBindAddressValidationError> {
    if value.is_empty() {
        return Err(RemoteBindAddressValidationError::Unavailable);
    }
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| RemoteBindAddressValidationError::SocketAddressInvalid)?;
    let ip = address.ip();
    if ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ipv4) if ipv4 == Ipv4Addr::BROADCAST)
    {
        return Err(RemoteBindAddressValidationError::AddressNotBindAdvertisable);
    }
    Ok(address)
}

/// Exact peer-device semantic text violates the existing [`DeviceId`] contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemotePeerDeviceValidationError;

impl fmt::Display for RemotePeerDeviceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote peer-device value invalid")
    }
}

impl std::error::Error for RemotePeerDeviceValidationError {}

/// Validates exact peer-device semantic text while preserving otherwise accepted bytes.
///
/// # Errors
///
/// Rejects empty or whitespace-only text under the existing [`DeviceId`] contract.
pub fn validate_remote_peer_device_id(
    value: &str,
) -> Result<DeviceId, RemotePeerDeviceValidationError> {
    DeviceId::new(value).map_err(|_| RemotePeerDeviceValidationError)
}

/// Strict ASCII-decimal `usize` validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsizeValueValidationError;

impl fmt::Display for UsizeValueValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ASCII-decimal usize value invalid")
    }
}

impl std::error::Error for UsizeValueValidationError {}

fn validate_usize_ascii_decimal(value: &str) -> Result<usize, UsizeValueValidationError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UsizeValueValidationError);
    }
    value.parse().map_err(|_| UsizeValueValidationError)
}

/// Validates the exact positive production remote worker-bound text.
///
/// # Errors
///
/// Rejects empty/non-ASCII-decimal text, overflow and zero.
pub fn validate_remote_max_active_workers(
    value: &str,
) -> Result<NonZeroUsize, UsizeValueValidationError> {
    NonZeroUsize::new(validate_usize_ascii_decimal(value)?).ok_or(UsizeValueValidationError)
}

/// Validates exact requester/rendezvous record-bound text, preserving current zero semantics.
///
/// # Errors
///
/// Rejects empty/non-ASCII-decimal text or target-`usize` overflow.
pub fn validate_remote_requester_rendezvous_max_records(
    value: &str,
) -> Result<usize, UsizeValueValidationError> {
    validate_usize_ascii_decimal(value)
}

/// Validates exact scheduling-consumption record-bound text, preserving current zero semantics.
///
/// # Errors
///
/// Rejects empty/non-ASCII-decimal text or target-`usize` overflow.
pub fn validate_remote_expected_device_scheduling_consumption_max_records(
    value: &str,
) -> Result<usize, UsizeValueValidationError> {
    validate_usize_ascii_decimal(value)
}

/// Pure application-lease semantic validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationLeaseValidationError {
    /// Text is empty, malformed, or outside `u64`.
    InvalidValue,
    /// Parsed whole seconds violate the existing remote-session lease ceiling.
    OutOfRange,
}

impl fmt::Display for ApplicationLeaseValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidValue => "remote application-lease value invalid",
            Self::OutOfRange => "remote application-lease value outside policy bounds",
        })
    }
}

impl std::error::Error for ApplicationLeaseValidationError {}

/// Validates strict ASCII-decimal application-lease seconds against the existing shared ceiling.
///
/// # Errors
///
/// Rejects malformed/overflow text, zero, and values above `MAX_REMOTE_SESSION_LEASE_SECONDS`.
pub fn validate_remote_application_lease_seconds(
    value: &str,
) -> Result<u64, ApplicationLeaseValidationError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApplicationLeaseValidationError::InvalidValue);
    }
    let seconds = value
        .parse::<u64>()
        .map_err(|_| ApplicationLeaseValidationError::InvalidValue)?;
    if seconds == 0 || seconds > MAX_REMOTE_SESSION_LEASE_SECONDS {
        return Err(ApplicationLeaseValidationError::OutOfRange);
    }
    Ok(seconds)
}

/// Stage-specific failure while validating one complete six-value configured-remote bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredRemoteBundleValidationError {
    /// Bind-address semantic validation failed.
    BindAddress(RemoteBindAddressValidationError),
    /// Peer-device semantic validation failed.
    PeerDevice(RemotePeerDeviceValidationError),
    /// Worker-bound semantic validation failed.
    MaxActiveWorkers(UsizeValueValidationError),
    /// Application-lease semantic validation failed.
    ApplicationLease(ApplicationLeaseValidationError),
    /// Requester/rendezvous capacity validation failed.
    RequesterRendezvousMaxRecords(UsizeValueValidationError),
    /// Scheduling-consumption capacity validation failed.
    SchedulingConsumptionMaxRecords(UsizeValueValidationError),
}

impl fmt::Display for ConfiguredRemoteBundleValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BindAddress(_) => "configured-remote bind-address validation failed",
            Self::PeerDevice(_) => "configured-remote peer-device validation failed",
            Self::MaxActiveWorkers(_) => "configured-remote worker-bound validation failed",
            Self::ApplicationLease(_) => "configured-remote application-lease validation failed",
            Self::RequesterRendezvousMaxRecords(_) => {
                "configured-remote requester/rendezvous capacity validation failed"
            }
            Self::SchedulingConsumptionMaxRecords(_) => {
                "configured-remote scheduling-consumption capacity validation failed"
            }
        })
    }
}

impl std::error::Error for ConfiguredRemoteBundleValidationError {}

/// Validated configured-remote values retaining exact semantic text plus typed projections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredRemoteBundle {
    bind_addr_text: String,
    bind_addr: SocketAddr,
    peer_device_id_text: String,
    peer_device_id: DeviceId,
    max_active_workers_text: String,
    max_active_workers: NonZeroUsize,
    application_lease_seconds_text: String,
    application_lease_seconds: u64,
    requester_rendezvous_max_records_text: String,
    requester_rendezvous_max_records: usize,
    scheduling_consumption_max_records_text: String,
    scheduling_consumption_max_records: usize,
}

impl ConfiguredRemoteBundle {
    /// Validates and retains exactly the six TU semantic values.
    ///
    /// # Errors
    ///
    /// Returns the exact field stage whose historical semantic law rejects the supplied text.
    pub fn try_new(
        bind_addr: &str,
        peer_device_id: &str,
        max_active_workers: &str,
        application_lease_seconds: &str,
        requester_rendezvous_max_records: &str,
        scheduling_consumption_max_records: &str,
    ) -> Result<Self, ConfiguredRemoteBundleValidationError> {
        Ok(Self {
            bind_addr_text: bind_addr.to_owned(),
            bind_addr: validate_remote_bind_addr(bind_addr)
                .map_err(ConfiguredRemoteBundleValidationError::BindAddress)?,
            peer_device_id_text: peer_device_id.to_owned(),
            peer_device_id: validate_remote_peer_device_id(peer_device_id)
                .map_err(ConfiguredRemoteBundleValidationError::PeerDevice)?,
            max_active_workers_text: max_active_workers.to_owned(),
            max_active_workers: validate_remote_max_active_workers(max_active_workers)
                .map_err(ConfiguredRemoteBundleValidationError::MaxActiveWorkers)?,
            application_lease_seconds_text: application_lease_seconds.to_owned(),
            application_lease_seconds: validate_remote_application_lease_seconds(
                application_lease_seconds,
            )
            .map_err(ConfiguredRemoteBundleValidationError::ApplicationLease)?,
            requester_rendezvous_max_records_text: requester_rendezvous_max_records.to_owned(),
            requester_rendezvous_max_records: validate_remote_requester_rendezvous_max_records(
                requester_rendezvous_max_records,
            )
            .map_err(ConfiguredRemoteBundleValidationError::RequesterRendezvousMaxRecords)?,
            scheduling_consumption_max_records_text: scheduling_consumption_max_records.to_owned(),
            scheduling_consumption_max_records:
                validate_remote_expected_device_scheduling_consumption_max_records(
                    scheduling_consumption_max_records,
                )
                .map_err(ConfiguredRemoteBundleValidationError::SchedulingConsumptionMaxRecords)?,
        })
    }

    /// Returns exact bind-address semantic text.
    #[must_use]
    pub fn bind_addr_text(&self) -> &str {
        &self.bind_addr_text
    }
    /// Returns validated bind-address projection.
    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
    /// Returns exact peer-device semantic text.
    #[must_use]
    pub fn peer_device_id_text(&self) -> &str {
        &self.peer_device_id_text
    }
    /// Returns validated peer-device projection.
    #[must_use]
    pub const fn peer_device_id(&self) -> &DeviceId {
        &self.peer_device_id
    }
    /// Returns exact worker-bound semantic text.
    #[must_use]
    pub fn max_active_workers_text(&self) -> &str {
        &self.max_active_workers_text
    }
    /// Returns validated worker-bound projection.
    #[must_use]
    pub const fn max_active_workers(&self) -> NonZeroUsize {
        self.max_active_workers
    }
    /// Returns exact application-lease semantic text.
    #[must_use]
    pub fn application_lease_seconds_text(&self) -> &str {
        &self.application_lease_seconds_text
    }
    /// Returns validated application-lease whole seconds.
    #[must_use]
    pub const fn application_lease_seconds(&self) -> u64 {
        self.application_lease_seconds
    }
    /// Returns exact requester/rendezvous capacity semantic text.
    #[must_use]
    pub fn requester_rendezvous_max_records_text(&self) -> &str {
        &self.requester_rendezvous_max_records_text
    }
    /// Returns validated requester/rendezvous capacity projection.
    #[must_use]
    pub const fn requester_rendezvous_max_records(&self) -> usize {
        self.requester_rendezvous_max_records
    }
    /// Returns exact scheduling-consumption capacity semantic text.
    #[must_use]
    pub fn scheduling_consumption_max_records_text(&self) -> &str {
        &self.scheduling_consumption_max_records_text
    }
    /// Returns validated scheduling-consumption capacity projection.
    #[must_use]
    pub const fn scheduling_consumption_max_records(&self) -> usize {
        self.scheduling_consumption_max_records
    }
}

/// Canonical systemd serialization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdSerializationError {
    /// Semantic text contains a control/non-printable scalar rejected by TU.
    NonPrintableValue,
}

impl fmt::Display for SystemdSerializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("configured-remote value is not printable systemd semantic text")
    }
}

impl std::error::Error for SystemdSerializationError {}

/// Returns exact canonical TT mode-drop-in bytes as UTF-8 text.
#[must_use]
pub const fn render_execution_mode_drop_in(mode: AgentExecutionMode) -> &'static str {
    match mode {
        AgentExecutionMode::LocalOnly => LOCAL_ONLY_DROPIN,
        AgentExecutionMode::ConfiguredRemote => CONFIGURED_REMOTE_DROPIN,
    }
}

fn encode_systemd_value(value: &str) -> Result<String, SystemdSerializationError> {
    let mut encoded = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            return Err(SystemdSerializationError::NonPrintableValue);
        }
        match character {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            '%' => encoded.push_str("%%"),
            _ => encoded.push(character),
        }
    }
    Ok(encoded)
}

/// Renders exact canonical TU `40-configured-remote-inputs.conf` text.
///
/// # Errors
///
/// Rejects control/non-printable semantic text before producing any output.
pub fn render_configured_remote_drop_in(
    bundle: &ConfiguredRemoteBundle,
) -> Result<String, SystemdSerializationError> {
    let values = [
        (PRW_REMOTE_BIND_ADDR, bundle.bind_addr_text()),
        (PRW_REMOTE_PEER_DEVICE_ID, bundle.peer_device_id_text()),
        (
            PRW_REMOTE_MAX_ACTIVE_WORKERS,
            bundle.max_active_workers_text(),
        ),
        (
            PRW_REMOTE_APPLICATION_LEASE_SECONDS,
            bundle.application_lease_seconds_text(),
        ),
        (
            PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
            bundle.requester_rendezvous_max_records_text(),
        ),
        (
            PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
            bundle.scheduling_consumption_max_records_text(),
        ),
    ];
    let mut rendered = String::from("[Service]\n");
    for (name, value) in values {
        rendered.push_str("Environment=\"");
        rendered.push_str(name);
        rendered.push('=');
        rendered.push_str(&encode_systemd_value(value)?);
        rendered.push_str("\"\n");
    }
    Ok(rendered)
}

/// Canonical managed-drop-in recognition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdRecognitionError {
    /// File bytes are not UTF-8 or do not match the selected exact structure/escaping.
    InvalidStructure,
    /// Decoded six-value semantics fail the shared validators.
    InvalidSemanticValue,
    /// Structurally valid content is not byte-for-byte canonical when re-rendered.
    NonCanonical,
}

impl fmt::Display for SystemdRecognitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStructure => "managed systemd drop-in structure invalid",
            Self::InvalidSemanticValue => "managed systemd drop-in semantic value invalid",
            Self::NonCanonical => "managed systemd drop-in is not canonical",
        })
    }
}

impl std::error::Error for SystemdRecognitionError {}

/// Recognizes only the two exact canonical TT mode-drop-in byte sequences.
///
/// # Errors
///
/// Returns [`SystemdRecognitionError::NonCanonical`] for every other byte sequence.
pub fn recognize_execution_mode_drop_in(
    bytes: &[u8],
) -> Result<AgentExecutionMode, SystemdRecognitionError> {
    if bytes == LOCAL_ONLY_DROPIN.as_bytes() {
        Ok(AgentExecutionMode::LocalOnly)
    } else if bytes == CONFIGURED_REMOTE_DROPIN.as_bytes() {
        Ok(AgentExecutionMode::ConfiguredRemote)
    } else {
        Err(SystemdRecognitionError::NonCanonical)
    }
}

fn decode_systemd_value(value: &str) -> Result<String, SystemdRecognitionError> {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character.is_control() {
            return Err(SystemdRecognitionError::InvalidStructure);
        }
        match character {
            '\\' => match characters.next() {
                Some('\\') => decoded.push('\\'),
                Some('"') => decoded.push('"'),
                _ => return Err(SystemdRecognitionError::InvalidStructure),
            },
            '%' => match characters.next() {
                Some('%') => decoded.push('%'),
                _ => return Err(SystemdRecognitionError::InvalidStructure),
            },
            _ => decoded.push(character),
        }
    }
    Ok(decoded)
}

/// Recognizes one exact canonical TU configured-remote drop-in and returns its validated bundle.
///
/// # Errors
///
/// Rejects malformed/extra/duplicate directives, invalid escaping, invalid semantic values, and
/// any content whose decoded bundle does not re-render byte-for-byte identically.
pub fn recognize_configured_remote_drop_in(
    bytes: &[u8],
) -> Result<ConfiguredRemoteBundle, SystemdRecognitionError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SystemdRecognitionError::InvalidStructure)?;
    let body = text
        .strip_suffix('\n')
        .ok_or(SystemdRecognitionError::InvalidStructure)?;
    if body.ends_with('\n') {
        return Err(SystemdRecognitionError::InvalidStructure);
    }
    let lines: Vec<_> = body.split('\n').collect();
    if lines.len() != 7 || lines[0] != "[Service]" {
        return Err(SystemdRecognitionError::InvalidStructure);
    }
    let names = [
        PRW_REMOTE_BIND_ADDR,
        PRW_REMOTE_PEER_DEVICE_ID,
        PRW_REMOTE_MAX_ACTIVE_WORKERS,
        PRW_REMOTE_APPLICATION_LEASE_SECONDS,
        PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
        PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
    ];
    let mut decoded = Vec::with_capacity(6);
    for (line, name) in lines[1..].iter().zip(names) {
        let prefix = format!("Environment=\"{name}=");
        let encoded = line
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or(SystemdRecognitionError::InvalidStructure)?;
        decoded.push(decode_systemd_value(encoded)?);
    }
    let bundle = ConfiguredRemoteBundle::try_new(
        &decoded[0],
        &decoded[1],
        &decoded[2],
        &decoded[3],
        &decoded[4],
        &decoded[5],
    )
    .map_err(|_| SystemdRecognitionError::InvalidSemanticValue)?;
    let rerendered = render_configured_remote_drop_in(&bundle)
        .map_err(|_| SystemdRecognitionError::InvalidSemanticValue)?;
    if rerendered.as_bytes() != bytes {
        return Err(SystemdRecognitionError::NonCanonical);
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle(peer: &str) -> ConfiguredRemoteBundle {
        ConfiguredRemoteBundle::try_new("127.0.0.1:0", peer, "0002", "003600", "0007", "0009")
            .expect("valid sample bundle")
    }

    #[test]
    fn execution_mode_accepts_only_exact_selected_tokens() {
        assert_eq!(
            validate_agent_execution_mode("local_only"),
            Ok(AgentExecutionMode::LocalOnly)
        );
        assert_eq!(
            validate_agent_execution_mode("configured_remote"),
            Ok(AgentExecutionMode::ConfiguredRemote)
        );
        for rejected in ["", "local", "LOCAL_ONLY", " local_only", "local_only "] {
            assert_eq!(
                validate_agent_execution_mode(rejected),
                Err(ExecutionModeValidationError)
            );
        }
    }

    #[test]
    fn historical_numeric_and_bind_semantics_are_preserved() {
        assert_eq!(
            validate_remote_bind_addr("127.0.0.1:0").expect("loopback remains valid"),
            "127.0.0.1:0".parse::<SocketAddr>().expect("socket")
        );
        assert_eq!(
            validate_remote_bind_addr("0.0.0.0:1"),
            Err(RemoteBindAddressValidationError::AddressNotBindAdvertisable)
        );
        assert_eq!(
            validate_remote_max_active_workers("00017")
                .expect("leading-zero worker bound")
                .get(),
            17
        );
        assert_eq!(
            validate_remote_max_active_workers("0"),
            Err(UsizeValueValidationError)
        );
        assert_eq!(
            validate_remote_requester_rendezvous_max_records("0000"),
            Ok(0)
        );
        assert_eq!(
            validate_remote_expected_device_scheduling_consumption_max_records("00017"),
            Ok(17)
        );
        assert_eq!(
            validate_remote_application_lease_seconds("003600"),
            Ok(3600)
        );
        assert_eq!(
            validate_remote_application_lease_seconds("0"),
            Err(ApplicationLeaseValidationError::OutOfRange)
        );
        assert_eq!(
            validate_remote_application_lease_seconds("3601"),
            Err(ApplicationLeaseValidationError::OutOfRange)
        );
    }

    #[test]
    fn peer_device_validation_preserves_exact_non_empty_text() {
        let device = validate_remote_peer_device_id("  peer-device-1  ").expect("valid peer");
        assert_eq!(device.as_str(), "  peer-device-1  ");
        assert_eq!(
            validate_remote_peer_device_id("   "),
            Err(RemotePeerDeviceValidationError)
        );
    }

    #[test]
    fn configured_bundle_preserves_leading_zero_text_and_typed_projections() {
        let bundle = sample_bundle("peer-device-1");
        assert_eq!(bundle.max_active_workers_text(), "0002");
        assert_eq!(bundle.max_active_workers().get(), 2);
        assert_eq!(bundle.application_lease_seconds_text(), "003600");
        assert_eq!(bundle.application_lease_seconds(), 3600);
        assert_eq!(bundle.requester_rendezvous_max_records_text(), "0007");
        assert_eq!(bundle.requester_rendezvous_max_records(), 7);
    }

    #[test]
    fn tu_serialization_round_trips_special_printable_text_exactly() {
        let peer = " peer\\\"%%$ unicode-λ ";
        let bundle = sample_bundle(peer);
        let rendered = render_configured_remote_drop_in(&bundle).expect("canonical render");
        assert!(rendered.contains("peer\\\\\\\"%%%%$ unicode-λ"));
        let recognized = recognize_configured_remote_drop_in(rendered.as_bytes())
            .expect("canonical content recognized");
        assert_eq!(recognized.peer_device_id_text(), peer);
        assert_eq!(
            render_configured_remote_drop_in(&recognized).expect("rerender"),
            rendered
        );
    }

    #[test]
    fn tu_serialization_rejects_control_values() {
        for peer in ["peer\nvalue", "peer\tvalue", "peer\0value"] {
            let bundle = sample_bundle(peer);
            assert_eq!(
                render_configured_remote_drop_in(&bundle),
                Err(SystemdSerializationError::NonPrintableValue)
            );
        }
    }

    #[test]
    fn canonical_mode_recognition_is_byte_exact() {
        for mode in [
            AgentExecutionMode::LocalOnly,
            AgentExecutionMode::ConfiguredRemote,
        ] {
            let canonical = render_execution_mode_drop_in(mode);
            assert_eq!(
                recognize_execution_mode_drop_in(canonical.as_bytes()),
                Ok(mode)
            );
            let mut noncanonical = canonical.as_bytes().to_vec();
            noncanonical.push(b'\n');
            assert_eq!(
                recognize_execution_mode_drop_in(&noncanonical),
                Err(SystemdRecognitionError::NonCanonical)
            );
        }
    }

    #[test]
    fn canonical_remote_recognition_rejects_extra_or_reordered_content() {
        let rendered = render_configured_remote_drop_in(&sample_bundle("peer-device-1"))
            .expect("canonical render");
        let extra = format!("{rendered}Environment=\"EXTRA=value\"\n");
        assert_eq!(
            recognize_configured_remote_drop_in(extra.as_bytes()),
            Err(SystemdRecognitionError::InvalidStructure)
        );
        let reordered = rendered.replacen(
            "Environment=\"PRW_REMOTE_BIND_ADDR=127.0.0.1:0\"\nEnvironment=\"PRW_REMOTE_PEER_DEVICE_ID=peer-device-1\"",
            "Environment=\"PRW_REMOTE_PEER_DEVICE_ID=peer-device-1\"\nEnvironment=\"PRW_REMOTE_BIND_ADDR=127.0.0.1:0\"",
            1,
        );
        assert_eq!(
            recognize_configured_remote_drop_in(reordered.as_bytes()),
            Err(SystemdRecognitionError::InvalidStructure)
        );
    }
}
