//! Provider-neutral local IPC contracts for the Ubuntu PRW Agent.
//!
//! Phase 006 records the local endpoint and authorization boundary. Phase 007
//! records bounded stream framing and protocol-version metadata. The local IPC
//! contract surface itself performs no socket I/O and creates no filesystem objects.

pub mod candidate_publication_requester_rendezvous_runtime;
#[allow(
    dead_code,
    reason = "C03e-DD materializes start-intent carrier for separately gated validation"
)]
pub(crate) mod candidate_publication_requester_rendezvous_start_intent;
pub mod frame_codec;
pub mod frame_object;
#[cfg(target_os = "linux")]
pub mod linux_bootstrap;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "pre-runtime Linux identity adapter is intentionally crate-internal"
)]
pub(crate) mod linux_identity;
pub mod local_commands;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "established-startup authority is active through the gate while additional crate-internal proof helpers remain intentionally bounded"
)]
pub(crate) mod owner_established_startup_authority;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority is active through the dispatcher while legacy helper entrypoints remain crate-internal"
)]
pub(crate) mod owner_first_run_orchestration;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "setup-intent reader/classifier is active while writer and compatibility helper seams remain separately bounded"
)]
pub(crate) mod owner_first_run_setup_intent;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority uses the selected bootstrap composition while additional pure helper seams remain crate-internal"
)]
pub(crate) mod owner_first_setup_bootstrap_input_composition;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority uses selected bootstrap inputs while auxiliary loaders and codecs remain crate-internal"
)]
pub(crate) mod owner_first_setup_bootstrap_inputs;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority uses the custody-policy plan while auxiliary policy helpers remain crate-internal"
)]
pub(crate) mod owner_first_setup_custody_policy_orchestration;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority reaches transport composition while validation-only helper seams remain crate-internal"
)]
pub(crate) mod owner_first_setup_execution_composition;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "local-authority bootstrap is active only through validated first-run dispatch while helper seams remain crate-internal"
)]
pub(crate) mod owner_first_setup_local_authority_bootstrap_execution;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run authority uses retry classification while auxiliary retry helpers remain crate-internal"
)]
pub(crate) mod owner_first_setup_retry_call_site_composition;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "first-run retry may recover established transport custody while auxiliary recovery helpers remain crate-internal"
)]
pub(crate) mod owner_first_setup_transport_identity_recovery;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "transport provisioning is reachable only through validated first-run authority while the module remains crate-internal"
)]
pub(crate) mod owner_first_setup_transport_provisioning_execution;
#[cfg(target_os = "linux")]
pub(crate) mod owner_startup_state_dispatch;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "C03e-LD materializes the LC-selected dormant production durable-capability higher-owner Arc custody before separately gated propagation and caller migration"
)]
pub(crate) mod production_durable_capability_higher_owner_custody;
#[allow(
    dead_code,
    reason = "C03e-JB materializes Agent production durable-registry custody composition before separately gated runtime activation"
)]
pub(crate) mod production_durable_registry_custody_bootstrap;
#[allow(
    dead_code,
    reason = "C03e-JD materializes Agent production durable-registry runtime custody before separately gated operation-specific use and runtime activation"
)]
pub(crate) mod production_durable_registry_runtime_custody;
#[allow(
    dead_code,
    reason = "C03e-HU materializes Agent production bootstrap composition before separately gated systemd custody join and runtime activation"
)]
pub(crate) mod production_reachability_bootstrap;
#[allow(
    dead_code,
    reason = "C03e-HW materializes Agent production systemd custody join before separately gated runtime activation"
)]
pub(crate) mod production_reachability_custody_bootstrap;
#[allow(
    dead_code,
    reason = "C03e-IA materializes production endpoint lifecycle custody before separately gated runtime drive and activation"
)]
pub(crate) mod production_reachability_endpoint_lifecycle;
#[allow(
    dead_code,
    reason = "C03e-GT materializes the production freshness-token source before separately gated production-owner composition"
)]
pub(crate) mod production_reachability_freshness_token_source;
#[allow(
    dead_code,
    reason = "C03e-HO materializes the Agent durable-owner composition seam before separately gated provider bootstrap and runtime activation"
)]
pub(crate) mod production_reachability_owner_composition;
#[allow(
    dead_code,
    reason = "C03e-GG materializes production reachability-owner custody before separately gated candidate execution"
)]
pub(crate) mod production_reachability_owner_custody;
#[allow(
    dead_code,
    reason = "C03e-HY materializes joint production reachability runtime custody before separately gated endpoint/process integration"
)]
pub(crate) mod production_reachability_runtime_custody;
#[cfg(target_os = "linux")]
pub mod prw_first_run;
pub mod reachability_authority_admission;
pub mod reachability_authority_bootstrap;
pub mod reachability_authority_composition;
pub mod reachability_authority_custody_bootstrap;
pub mod remote_session_authentication_transaction;
pub mod remote_session_capability_runtime;
pub mod remote_transport_runtime;

#[cfg(target_os = "linux")]
/// Bounded executable failure stage for the owner startup-authority gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerStartupAuthorityFailureStage {
    /// Setup-intent presence could not be classified safely.
    SetupIntentClassification,
    /// A validated pending first-run transaction failed.
    FirstRun,
    /// Exact validated setup-intent absence reached established-restart proof, which failed.
    EstablishedRestart,
}

#[cfg(target_os = "linux")]
impl OwnerStartupAuthorityFailureStage {
    /// Returns the stable bounded diagnostic token emitted by executable startup.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::SetupIntentClassification => "setup_intent_classification",
            Self::FirstRun => "first_run",
            Self::EstablishedRestart => "established_restart",
        }
    }
}

#[cfg(target_os = "linux")]
/// Proves or completes owner startup authority before executable runtime-lane selection.
///
/// The underlying dispatcher remains crate-private so its detailed first-run and established-state
/// outcome/error types do not become part of the public library interface.
///
/// # Errors
///
/// Returns only the bounded authority failure stage. Detailed internal errors remain inside the
/// authority implementation boundary and are not exposed by the executable-facing API.
pub fn gate_owner_startup_authority(
    public_device_identity: &prw_control_plane::PublicIdentityMaterial,
) -> Result<(), OwnerStartupAuthorityFailureStage> {
    match owner_startup_state_dispatch::dispatch_owner_startup_authority(public_device_identity) {
        Ok(_) => Ok(()),
        Err(
            owner_startup_state_dispatch::OwnerStartupStateDispatchError::SetupIntentClassification(
                _,
            ),
        ) => Err(OwnerStartupAuthorityFailureStage::SetupIntentClassification),
        Err(owner_startup_state_dispatch::OwnerStartupStateDispatchError::FirstRun(_)) => {
            Err(OwnerStartupAuthorityFailureStage::FirstRun)
        }
        Err(owner_startup_state_dispatch::OwnerStartupStateDispatchError::EstablishedRestart(
            _,
        )) => Err(OwnerStartupAuthorityFailureStage::EstablishedRestart),
    }
}

use std::fmt;
use std::path::{Path, PathBuf};

/// Application directory below `$XDG_RUNTIME_DIR`.
pub const AGENT_RUNTIME_SUBDIRECTORY: &str = "private-remote-workspace";
/// Agent socket filename.
pub const AGENT_SOCKET_FILENAME: &str = "agent.sock";
/// Required Unix mode for the PRW-owned runtime subdirectory.
pub const AGENT_RUNTIME_DIRECTORY_MODE: u32 = 0o700;
/// Required Unix mode for the filesystem-backed Agent socket.
pub const AGENT_SOCKET_MODE: u32 = 0o600;
/// Four-byte fixed frame magic used by local IPC version 1.
pub const LOCAL_IPC_FRAME_MAGIC: [u8; 4] = *b"PRW\0";
/// Fixed local IPC frame-header length in bytes.
pub const LOCAL_IPC_FRAME_HEADER_LENGTH: u32 = 24;
/// Maximum opaque payload length accepted by the local control channel.
pub const LOCAL_IPC_MAX_PAYLOAD_LENGTH: u32 = 1_048_576;
/// Current local IPC protocol major version.
pub const LOCAL_IPC_PROTOCOL_MAJOR: u16 = 1;
/// Current local IPC protocol minor version.
pub const LOCAL_IPC_PROTOCOL_MINOR: u16 = 0;

/// Local transport used between Ubuntu clients and the unprivileged PRW Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcTransport {
    /// Filesystem-backed Unix-domain `SOCK_STREAM` socket.
    UnixDomainStream,
}

/// Kernel-backed source used to authenticate a connected local peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPeerCredentialSource {
    /// Linux `SO_PEERCRED` on a connected Unix-domain stream socket.
    LinuxSoPeerCred,
}

/// Baseline local authorization rule after peer credentials are obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPeerAuthorization {
    /// Accept only a peer whose kernel-reported UID matches the Agent UID.
    SameUserId,
}

/// Provider-neutral Ubuntu local IPC security contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIpcContract {
    /// Local transport family and socket semantics.
    pub transport: LocalIpcTransport,
    /// Kernel-backed peer-credential source.
    pub peer_credentials: LocalPeerCredentialSource,
    /// Baseline authorization rule applied to peer credentials.
    pub authorization: LocalPeerAuthorization,
    /// Required Unix mode for the PRW runtime subdirectory.
    pub runtime_directory_mode: u32,
    /// Required Unix mode for the filesystem-backed Agent socket.
    pub socket_mode: u32,
}

impl LocalIpcContract {
    /// Returns the locked Phase 006 Ubuntu local IPC baseline.
    #[must_use]
    pub const fn baseline() -> Self {
        Self {
            transport: LocalIpcTransport::UnixDomainStream,
            peer_credentials: LocalPeerCredentialSource::LinuxSoPeerCred,
            authorization: LocalPeerAuthorization::SameUserId,
            runtime_directory_mode: AGENT_RUNTIME_DIRECTORY_MODE,
            socket_mode: AGENT_SOCKET_MODE,
        }
    }

    /// Returns the Agent socket path beneath a supplied XDG runtime directory.
    #[must_use]
    pub fn socket_path(xdg_runtime_dir: &Path) -> PathBuf {
        xdg_runtime_dir
            .join(AGENT_RUNTIME_SUBDIRECTORY)
            .join(AGENT_SOCKET_FILENAME)
    }
}

/// Version tuple carried by each local IPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIpcProtocolVersion {
    major: u16,
    minor: u16,
}

impl LocalIpcProtocolVersion {
    /// Returns the current protocol version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: LOCAL_IPC_PROTOCOL_MAJOR,
            minor: LOCAL_IPC_PROTOCOL_MINOR,
        }
    }

    /// Constructs a version tuple parsed from a future wire decoder.
    #[must_use]
    pub const fn from_parts(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the protocol major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the protocol minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Returns whether the exact version is currently supported.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.major == LOCAL_IPC_PROTOCOL_MAJOR && self.minor == LOCAL_IPC_PROTOCOL_MINOR
    }
}

/// Message direction/result class encoded in a local IPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalIpcMessageKind {
    /// Client request to the Agent.
    Request = 1,
    /// Successful Agent response to a request.
    Response = 2,
    /// Agent error response associated with a request.
    Error = 3,
}

/// Non-zero correlation identifier for a local IPC request/response exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalIpcRequestId(u64);

impl LocalIpcRequestId {
    /// Creates a non-zero request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcRequestIdError::Zero`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, LocalIpcRequestIdError> {
        if value == 0 {
            return Err(LocalIpcRequestIdError::Zero);
        }
        Ok(Self(value))
    }

    /// Returns the numeric request identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Invalid local IPC request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcRequestIdError {
    /// Request identifier zero is reserved and invalid.
    Zero,
}

impl fmt::Display for LocalIpcRequestIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("local IPC request id must be non-zero"),
        }
    }
}

impl std::error::Error for LocalIpcRequestIdError {}

/// Validated metadata for one bounded local IPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIpcFrameHeader {
    version: LocalIpcProtocolVersion,
    kind: LocalIpcMessageKind,
    request_id: LocalIpcRequestId,
    payload_length: u32,
}

impl LocalIpcFrameHeader {
    /// Creates validated frame metadata.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcFrameHeaderError::UnsupportedVersion`] when `version`
    /// is not the exact current version, or
    /// [`LocalIpcFrameHeaderError::PayloadTooLarge`] when `payload_length`
    /// exceeds [`LOCAL_IPC_MAX_PAYLOAD_LENGTH`].
    pub const fn new(
        version: LocalIpcProtocolVersion,
        kind: LocalIpcMessageKind,
        request_id: LocalIpcRequestId,
        payload_length: u32,
    ) -> Result<Self, LocalIpcFrameHeaderError> {
        if !version.is_supported() {
            return Err(LocalIpcFrameHeaderError::UnsupportedVersion);
        }
        if payload_length > LOCAL_IPC_MAX_PAYLOAD_LENGTH {
            return Err(LocalIpcFrameHeaderError::PayloadTooLarge);
        }
        Ok(Self {
            version,
            kind,
            request_id,
            payload_length,
        })
    }

    /// Returns the validated frame header.
    #[must_use]
    pub const fn version(self) -> LocalIpcProtocolVersion {
        self.version
    }

    /// Returns the frame message kind.
    #[must_use]
    pub const fn kind(self) -> LocalIpcMessageKind {
        self.kind
    }

    /// Returns the correlation request identifier.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the opaque payload length.
    #[must_use]
    pub const fn payload_length(self) -> u32 {
        self.payload_length
    }

    /// Returns the fixed header plus payload length for the complete frame.
    #[must_use]
    pub const fn frame_length(self) -> u32 {
        LOCAL_IPC_FRAME_HEADER_LENGTH + self.payload_length
    }
}

/// Invalid local IPC frame-header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcFrameHeaderError {
    /// The protocol version is not the exact currently supported version.
    UnsupportedVersion,
    /// The declared payload length exceeds the local control-channel limit.
    PayloadTooLarge,
}

impl fmt::Display for LocalIpcFrameHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                formatter.write_str("unsupported local IPC protocol version")
            }
            Self::PayloadTooLarge => {
                formatter.write_str("local IPC payload exceeds maximum length")
            }
        }
    }
}

impl std::error::Error for LocalIpcFrameHeaderError {}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        AGENT_RUNTIME_DIRECTORY_MODE, AGENT_SOCKET_MODE, LOCAL_IPC_FRAME_HEADER_LENGTH,
        LOCAL_IPC_FRAME_MAGIC, LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcContract, LocalIpcFrameHeader,
        LocalIpcFrameHeaderError, LocalIpcMessageKind, LocalIpcProtocolVersion, LocalIpcRequestId,
        LocalIpcRequestIdError, LocalIpcTransport, LocalPeerAuthorization,
        LocalPeerCredentialSource,
    };

    #[test]
    fn baseline_contract_is_same_user_unix_socket() {
        let contract = LocalIpcContract::baseline();

        assert_eq!(contract.transport, LocalIpcTransport::UnixDomainStream);
        assert_eq!(
            contract.peer_credentials,
            LocalPeerCredentialSource::LinuxSoPeerCred
        );
        assert_eq!(contract.authorization, LocalPeerAuthorization::SameUserId);
        assert_eq!(
            contract.runtime_directory_mode,
            AGENT_RUNTIME_DIRECTORY_MODE
        );
        assert_eq!(contract.socket_mode, AGENT_SOCKET_MODE);
        assert_eq!(contract.runtime_directory_mode, 0o700);
        assert_eq!(contract.socket_mode, 0o600);
    }

    #[test]
    fn socket_path_is_beneath_xdg_runtime_dir() {
        assert_eq!(
            LocalIpcContract::socket_path(Path::new("/run/user/1000")),
            PathBuf::from("/run/user/1000/private-remote-workspace/agent.sock")
        );
    }

    #[test]
    fn protocol_constants_are_locked() {
        assert_eq!(LOCAL_IPC_FRAME_MAGIC, *b"PRW\0");
        assert_eq!(LOCAL_IPC_FRAME_HEADER_LENGTH, 24);
        assert_eq!(LOCAL_IPC_MAX_PAYLOAD_LENGTH, 1_048_576);
        assert_eq!(LocalIpcProtocolVersion::current().major(), 1);
        assert_eq!(LocalIpcProtocolVersion::current().minor(), 0);
    }

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let request_id = LocalIpcRequestId::new(1).expect("non-zero request id");

        assert_eq!(
            LocalIpcFrameHeader::new(
                LocalIpcProtocolVersion::from_parts(2, 0),
                LocalIpcMessageKind::Request,
                request_id,
                0,
            ),
            Err(LocalIpcFrameHeaderError::UnsupportedVersion)
        );
    }

    #[test]
    fn request_id_zero_is_rejected() {
        assert_eq!(LocalIpcRequestId::new(0), Err(LocalIpcRequestIdError::Zero));
    }

    #[test]
    fn payload_length_is_bounded() {
        let request_id = LocalIpcRequestId::new(7).expect("non-zero request id");
        let valid = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            request_id,
            LOCAL_IPC_MAX_PAYLOAD_LENGTH,
        )
        .expect("maximum payload is valid");

        assert_eq!(valid.request_id().get(), 7);
        assert_eq!(valid.kind(), LocalIpcMessageKind::Request);
        assert_eq!(valid.version(), LocalIpcProtocolVersion::current());
        assert_eq!(valid.payload_length(), LOCAL_IPC_MAX_PAYLOAD_LENGTH);
        assert_eq!(
            valid.frame_length(),
            LOCAL_IPC_FRAME_HEADER_LENGTH + LOCAL_IPC_MAX_PAYLOAD_LENGTH
        );
        assert_eq!(
            LocalIpcFrameHeader::new(
                LocalIpcProtocolVersion::current(),
                LocalIpcMessageKind::Request,
                request_id,
                LOCAL_IPC_MAX_PAYLOAD_LENGTH + 1,
            ),
            Err(LocalIpcFrameHeaderError::PayloadTooLarge)
        );
    }
}
