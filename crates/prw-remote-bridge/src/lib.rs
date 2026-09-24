//! Source/disposable end-to-end authenticated capability bridge for PRW.
//!
//! Phase 143 joins already-validated transport identity, application-session proof,
//! current registry state and capability policy before exposing typed existing capability
//! commands. This crate owns no socket, process, shell, filesystem root, PTY, DNS resolver,
//! firewall, route, TUN/TAP or production runtime activation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use prw_connectivity::TransportIdentity;
use prw_file_service::RemotePath;
use prw_file_transfer::{TransferId, UploadPlan};
use prw_forwarding::{ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec};
use prw_policy::{Capability, Decision, PolicyEvaluator};
use prw_registry::{
    RegistryValidatedPrincipal, WorkspaceDeviceRegistry,
    durable_registry_authority::{DurableRegistryAuthority, DurableRegistryAuthorityError},
};
use prw_remote_transport::{ControlFrame, ControlMessageKind, MAX_CONTROL_PAYLOAD_BYTES};
use prw_session::AuthenticatedDeviceSession;
use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

/// Phase 143 PRWC payload magic.
pub const BRIDGE_MAGIC: [u8; 4] = *b"PRWC";
/// Phase 143 request protocol major version.
pub const BRIDGE_PROTOCOL_MAJOR: u16 = 1;
/// Phase 143 request protocol minor version.
pub const BRIDGE_PROTOCOL_MINOR: u16 = 0;
/// Fixed request header bytes inside a Phase 140 PRWM control frame.
pub const BRIDGE_HEADER_BYTES: usize = 12;
/// Maximum one inline remote data chunk after operation metadata.
pub const MAX_BRIDGE_INLINE_BYTES: usize = 60_000;
/// Maximum Phase 143 application-session lease lifetime.
pub const MAX_REMOTE_SESSION_LEASE_SECONDS: u64 = 3_600;

/// A Phase 128 authenticated session with verifier-owned remote admission lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSessionLease {
    session: AuthenticatedDeviceSession,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl RemoteSessionLease {
    /// Creates one bounded remote application-session lease.
    ///
    /// # Errors
    ///
    /// Rejects a zero/reversed lifetime and any lifetime above one hour.
    pub fn new(
        session: AuthenticatedDeviceSession,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, RemoteBridgeError> {
        let lifetime = expires_at_unix_seconds
            .checked_sub(issued_at_unix_seconds)
            .ok_or(RemoteBridgeError::InvalidSessionLease)?;
        if lifetime == 0 || lifetime > MAX_REMOTE_SESSION_LEASE_SECONDS {
            return Err(RemoteBridgeError::InvalidSessionLease);
        }
        Ok(Self {
            session,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        })
    }

    /// Returns the immutable Phase 128 authenticated identity.
    #[must_use]
    pub const fn session(&self) -> &AuthenticatedDeviceSession {
        &self.session
    }

    /// Returns the verifier-owned issue time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the verifier-owned expiry time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    const fn validate_time(&self, now_unix_seconds: u64) -> Result<(), RemoteBridgeError> {
        if now_unix_seconds < self.issued_at_unix_seconds {
            return Err(RemoteBridgeError::SessionNotYetValid);
        }
        if now_unix_seconds >= self.expires_at_unix_seconds {
            return Err(RemoteBridgeError::SessionExpired);
        }
        Ok(())
    }
}

/// Exact typed operation admitted by the initial remote capability bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeCommand {
    /// Read the bounded Agent status snapshot.
    AgentStatus,
    /// List one validated relative directory.
    FileList(RemotePath),
    /// Stat one validated relative path.
    FileStat(RemotePath),
    /// Create one file with bounded inline content.
    FileCreate { path: RemotePath, contents: Vec<u8> },
    /// Create one directory.
    DirectoryCreate(RemotePath),
    /// Begin one create-only resumable upload.
    UploadBegin(UploadPlan),
    /// Resume one create-only resumable upload.
    UploadResume(UploadPlan),
    /// Append one exact sequential upload chunk.
    UploadChunk {
        transfer_id: TransferId,
        offset: u64,
        chunk: Vec<u8>,
    },
    /// Finalize one upload after existing integrity checks.
    UploadFinalize(TransferId),
    /// Abort one active upload transaction.
    UploadAbort(TransferId),
    /// Read one bounded download chunk.
    DownloadChunk {
        path: RemotePath,
        offset: u64,
        requested_len: usize,
    },
    /// Open one named terminal profile.
    TerminalOpen {
        session_id: TerminalSessionId,
        profile: TerminalProfile,
        geometry: TerminalGeometry,
    },
    /// Write bounded terminal input.
    TerminalInput {
        session_id: TerminalSessionId,
        bytes: Vec<u8>,
    },
    /// Resize one terminal using validated geometry.
    TerminalResize {
        session_id: TerminalSessionId,
        geometry: TerminalGeometry,
    },
    /// Request bounded terminal output.
    TerminalRead {
        session_id: TerminalSessionId,
        maximum_bytes: usize,
    },
    /// Close one terminal session.
    TerminalClose(TerminalSessionId),
    /// Open one loopback-to-explicit-IP TCP forward.
    ForwardOpen {
        forward_id: PortForwardId,
        spec: TcpForwardSpec,
    },
    /// Close one forwarding session.
    ForwardClose(PortForwardId),
}

impl BridgeCommand {
    /// Returns the stable Phase 143 operation code.
    #[must_use]
    pub const fn operation_code(&self) -> u16 {
        match self {
            Self::AgentStatus => 1,
            Self::FileList(_) => 2,
            Self::FileStat(_) => 3,
            Self::FileCreate { .. } => 4,
            Self::DirectoryCreate(_) => 5,
            Self::UploadBegin(_) => 6,
            Self::UploadResume(_) => 7,
            Self::UploadChunk { .. } => 8,
            Self::UploadFinalize(_) => 9,
            Self::UploadAbort(_) => 10,
            Self::DownloadChunk { .. } => 11,
            Self::TerminalOpen { .. } => 12,
            Self::TerminalInput { .. } => 13,
            Self::TerminalResize { .. } => 14,
            Self::TerminalRead { .. } => 15,
            Self::TerminalClose(_) => 16,
            Self::ForwardOpen { .. } => 17,
            Self::ForwardClose(_) => 18,
        }
    }

    /// Returns the exact policy capability required by this operation.
    #[must_use]
    pub const fn required_capability(&self) -> Capability {
        match self {
            Self::AgentStatus => Capability::AgentStatusRead,
            Self::FileList(_) | Self::FileStat(_) | Self::DownloadChunk { .. } => {
                Capability::FilesRead
            }
            Self::FileCreate { .. }
            | Self::DirectoryCreate(_)
            | Self::UploadBegin(_)
            | Self::UploadResume(_)
            | Self::UploadChunk { .. }
            | Self::UploadFinalize(_)
            | Self::UploadAbort(_) => Capability::FilesWrite,
            Self::TerminalOpen { .. } => Capability::TerminalOpen,
            Self::TerminalInput { .. }
            | Self::TerminalResize { .. }
            | Self::TerminalRead { .. }
            | Self::TerminalClose(_) => Capability::TerminalExec,
            Self::ForwardOpen { .. } | Self::ForwardClose(_) => Capability::ForwardingCreate,
        }
    }

    /// Encodes one typed operation into the bounded PRWC request payload.
    ///
    /// # Errors
    ///
    /// Rejects any direct enum construction that exceeds Phase 143 inline bounds.
    pub fn encode(&self) -> Result<Vec<u8>, RemoteBridgeError> {
        let mut body = Vec::new();
        match self {
            Self::AgentStatus => {}
            Self::FileList(path) | Self::FileStat(path) | Self::DirectoryCreate(path) => {
                write_path(&mut body, path)?;
            }
            Self::FileCreate { path, contents } => {
                write_path(&mut body, path)?;
                write_inline_bytes(&mut body, contents, true)?;
            }
            Self::UploadBegin(plan) | Self::UploadResume(plan) => {
                body.extend_from_slice(plan.transfer_id().as_bytes());
                write_path(&mut body, plan.destination())?;
                body.extend_from_slice(&plan.total_bytes().to_be_bytes());
                body.extend_from_slice(plan.sha256());
            }
            Self::UploadChunk {
                transfer_id,
                offset,
                chunk,
            } => {
                body.extend_from_slice(transfer_id.as_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                write_inline_bytes(&mut body, chunk, false)?;
            }
            Self::UploadFinalize(transfer_id) | Self::UploadAbort(transfer_id) => {
                body.extend_from_slice(transfer_id.as_bytes());
            }
            Self::DownloadChunk {
                path,
                offset,
                requested_len,
            } => {
                validate_nonzero_inline_length(*requested_len)?;
                write_path(&mut body, path)?;
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(
                    &u32::try_from(*requested_len)
                        .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?
                        .to_be_bytes(),
                );
            }
            Self::TerminalOpen {
                session_id,
                profile,
                geometry,
            } => {
                body.extend_from_slice(&session_id.get().to_be_bytes());
                body.push(terminal_profile_code(*profile));
                body.extend_from_slice(&geometry.columns().to_be_bytes());
                body.extend_from_slice(&geometry.rows().to_be_bytes());
            }
            Self::TerminalInput { session_id, bytes } => {
                body.extend_from_slice(&session_id.get().to_be_bytes());
                write_inline_bytes(&mut body, bytes, false)?;
            }
            Self::TerminalResize {
                session_id,
                geometry,
            } => {
                body.extend_from_slice(&session_id.get().to_be_bytes());
                body.extend_from_slice(&geometry.columns().to_be_bytes());
                body.extend_from_slice(&geometry.rows().to_be_bytes());
            }
            Self::TerminalRead {
                session_id,
                maximum_bytes,
            } => {
                validate_nonzero_inline_length(*maximum_bytes)?;
                body.extend_from_slice(&session_id.get().to_be_bytes());
                body.extend_from_slice(
                    &u32::try_from(*maximum_bytes)
                        .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?
                        .to_be_bytes(),
                );
            }
            Self::TerminalClose(session_id) => {
                body.extend_from_slice(&session_id.get().to_be_bytes());
            }
            Self::ForwardOpen { forward_id, spec } => {
                body.extend_from_slice(&forward_id.get().to_be_bytes());
                write_loopback_bind(&mut body, spec.bind());
                write_forward_target(&mut body, spec.target());
            }
            Self::ForwardClose(forward_id) => {
                body.extend_from_slice(&forward_id.get().to_be_bytes());
            }
        }

        let mut payload = Vec::with_capacity(BRIDGE_HEADER_BYTES + body.len());
        payload.extend_from_slice(&BRIDGE_MAGIC);
        payload.extend_from_slice(&BRIDGE_PROTOCOL_MAJOR.to_be_bytes());
        payload.extend_from_slice(&BRIDGE_PROTOCOL_MINOR.to_be_bytes());
        payload.extend_from_slice(&self.operation_code().to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&body);
        if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
            return Err(RemoteBridgeError::InvalidRequestPayload);
        }
        Ok(payload)
    }

    /// Decodes one complete PRWC payload into existing typed domain values.
    ///
    /// # Errors
    ///
    /// Malformed metadata, fields, constructors, bounds, truncation or trailing bytes fail closed.
    pub fn decode(payload: &[u8]) -> Result<Self, RemoteBridgeError> {
        if payload.len() < BRIDGE_HEADER_BYTES || payload[..4] != BRIDGE_MAGIC {
            return Err(RemoteBridgeError::InvalidRequestPayload);
        }
        let major = u16::from_be_bytes([payload[4], payload[5]]);
        let minor = u16::from_be_bytes([payload[6], payload[7]]);
        if major != BRIDGE_PROTOCOL_MAJOR || minor != BRIDGE_PROTOCOL_MINOR {
            return Err(RemoteBridgeError::InvalidRequestPayload);
        }
        let operation = u16::from_be_bytes([payload[8], payload[9]]);
        if u16::from_be_bytes([payload[10], payload[11]]) != 0 {
            return Err(RemoteBridgeError::InvalidRequestPayload);
        }
        let mut reader = Reader::new(&payload[BRIDGE_HEADER_BYTES..]);
        let command = match operation {
            1 => Self::AgentStatus,
            2 => Self::FileList(reader.path()?),
            3 => Self::FileStat(reader.path()?),
            4 => Self::FileCreate {
                path: reader.path()?,
                contents: reader.inline_bytes(true)?,
            },
            5 => Self::DirectoryCreate(reader.path()?),
            6 | 7 => {
                let transfer_id = TransferId::new(reader.array::<16>()?);
                let destination = reader.path()?;
                let total_bytes = reader.u64()?;
                let sha256 = reader.array::<32>()?;
                let plan = UploadPlan::new(transfer_id, destination, total_bytes, sha256)
                    .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
                if operation == 6 {
                    Self::UploadBegin(plan)
                } else {
                    Self::UploadResume(plan)
                }
            }
            8 => Self::UploadChunk {
                transfer_id: TransferId::new(reader.array::<16>()?),
                offset: reader.u64()?,
                chunk: reader.inline_bytes(false)?,
            },
            9 => Self::UploadFinalize(TransferId::new(reader.array::<16>()?)),
            10 => Self::UploadAbort(TransferId::new(reader.array::<16>()?)),
            11 => {
                let path = reader.path()?;
                let offset = reader.u64()?;
                let requested_len = reader.inline_length()?;
                Self::DownloadChunk {
                    path,
                    offset,
                    requested_len,
                }
            }
            12 => {
                let session_id = terminal_session_id(reader.u64()?)?;
                let profile = decode_terminal_profile(reader.u8()?)?;
                let geometry = terminal_geometry(reader.u16()?, reader.u16()?)?;
                Self::TerminalOpen {
                    session_id,
                    profile,
                    geometry,
                }
            }
            13 => Self::TerminalInput {
                session_id: terminal_session_id(reader.u64()?)?,
                bytes: reader.inline_bytes(false)?,
            },
            14 => Self::TerminalResize {
                session_id: terminal_session_id(reader.u64()?)?,
                geometry: terminal_geometry(reader.u16()?, reader.u16()?)?,
            },
            15 => Self::TerminalRead {
                session_id: terminal_session_id(reader.u64()?)?,
                maximum_bytes: reader.inline_length()?,
            },
            16 => Self::TerminalClose(terminal_session_id(reader.u64()?)?),
            17 => {
                let forward_id = PortForwardId::new(reader.u64()?)
                    .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
                let bind = decode_loopback_bind(&mut reader)?;
                let target = decode_forward_target(&mut reader)?;
                Self::ForwardOpen {
                    forward_id,
                    spec: TcpForwardSpec::new(bind, target),
                }
            }
            18 => Self::ForwardClose(
                PortForwardId::new(reader.u64()?)
                    .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?,
            ),
            _ => return Err(RemoteBridgeError::InvalidRequestPayload),
        };
        reader.finish()?;
        Ok(command)
    }
}

/// Request that passed transport, session, current-registry, codec and capability policy gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCapabilityRequest {
    request_id: u64,
    principal: RegistryValidatedPrincipal,
    transport_identity: TransportIdentity,
    capability: Capability,
    command: BridgeCommand,
}

impl AuthorizedCapabilityRequest {
    /// Returns the Phase 140 request identifier.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the current-registry principal snapshot.
    #[must_use]
    pub const fn principal(&self) -> &RegistryValidatedPrincipal {
        &self.principal
    }

    /// Returns the current verified transport identity.
    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.transport_identity
    }

    /// Returns the exact granted capability for this operation.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the validated typed command.
    #[must_use]
    pub const fn command(&self) -> &BridgeCommand {
        &self.command
    }
}

/// Dispatcher boundary that can receive only fully authorized Phase 143 requests.
pub trait CapabilityDispatcher {
    /// Backend-specific bounded dispatch error.
    type Error;

    /// Dispatches one already-authorized typed request.
    ///
    /// # Errors
    ///
    /// Returns the backend-specific bounded dispatch error without weakening bridge authorization.
    fn dispatch(&mut self, request: &AuthorizedCapabilityRequest) -> Result<Vec<u8>, Self::Error>;
}

/// Current-registry and policy gate around Phase 140 remote control frames.
pub struct CapabilityBridge<'a, P: PolicyEvaluator> {
    registry: &'a WorkspaceDeviceRegistry,
    policy: &'a P,
}

impl<'a, P: PolicyEvaluator> CapabilityBridge<'a, P> {
    /// Creates a bridge over current registry and already-selected principal policy.
    #[must_use]
    pub const fn new(registry: &'a WorkspaceDeviceRegistry, policy: &'a P) -> Self {
        Self { registry, policy }
    }

    /// Authorizes one Phase 140 request frame without executing a capability.
    ///
    /// # Errors
    ///
    /// Fails before dispatch on outer-kind, lease, current registry, transport binding,
    /// request codec or exact capability denial.
    pub fn authorize(
        &self,
        presented_transport_identity: TransportIdentity,
        lease: &RemoteSessionLease,
        now_unix_seconds: u64,
        frame: &ControlFrame,
    ) -> Result<AuthorizedCapabilityRequest, RemoteBridgeError> {
        if frame.kind() != ControlMessageKind::Request {
            return Err(RemoteBridgeError::WrongControlMessageKind);
        }
        lease.validate_time(now_unix_seconds)?;
        let principal = self
            .registry
            .validate_authenticated_session(lease.session())
            .map_err(|_| RemoteBridgeError::RegistryRejected)?;
        self.registry
            .validate_transport_identity(principal.device_id(), presented_transport_identity)
            .map_err(|_| RemoteBridgeError::TransportIdentityRejected)?;
        let command = BridgeCommand::decode(frame.payload())?;
        let capability = command.required_capability();
        if self.policy.evaluate(capability) != Decision::Allow {
            return Err(RemoteBridgeError::CapabilityDenied);
        }
        Ok(AuthorizedCapabilityRequest {
            request_id: frame.request_id(),
            principal,
            transport_identity: presented_transport_identity,
            capability,
            command,
        })
    }

    /// Authorizes, dispatches and correlates one bounded response frame.
    ///
    /// # Errors
    ///
    /// Authentication/authorization errors prevent dispatcher invocation. Dispatcher failure or
    /// an oversized response fails closed without creating a successful response frame.
    pub fn process_request<D: CapabilityDispatcher>(
        &self,
        presented_transport_identity: TransportIdentity,
        lease: &RemoteSessionLease,
        now_unix_seconds: u64,
        frame: &ControlFrame,
        dispatcher: &mut D,
    ) -> Result<ControlFrame, RemoteBridgeError> {
        let authorized =
            self.authorize(presented_transport_identity, lease, now_unix_seconds, frame)?;
        crate::authorized_request_dispatch::dispatch_authorized_request(&authorized, dispatcher)
    }
}

/// Stable Phase 143 failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteBridgeError {
    /// Remote session lifetime was zero/reversed or above the locked bound.
    InvalidSessionLease,
    /// Verifier time is before the lease issue time.
    SessionNotYetValid,
    /// Verifier time is at/after lease expiry.
    SessionExpired,
    /// Outer PRWM frame is not a request.
    WrongControlMessageKind,
    /// Current membership/device/session registry state rejected the request.
    RegistryRejected,
    /// Presented transport identity is absent, stale, mismatched or revoked.
    TransportIdentityRejected,
    /// PRWC metadata/body or an existing typed constructor rejected the payload.
    InvalidRequestPayload,
    /// Exact required capability was denied.
    CapabilityDenied,
    /// Typed capability dispatcher failed.
    DispatchFailed,
    /// Dispatcher returned a payload above the Phase 140 control ceiling.
    DispatchResponseTooLarge,
    /// Phase 140 response-frame construction failed.
    ResponseFrameRejected,
}

impl fmt::Display for RemoteBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionLease => "invalid remote session lease",
            Self::SessionNotYetValid => "remote session is not yet valid",
            Self::SessionExpired => "remote session expired",
            Self::WrongControlMessageKind => "remote bridge requires a request control frame",
            Self::RegistryRejected => "current registry rejected authenticated session",
            Self::TransportIdentityRejected => "current transport identity rejected",
            Self::InvalidRequestPayload => "invalid remote capability request payload",
            Self::CapabilityDenied => "remote capability denied",
            Self::DispatchFailed => "remote capability dispatch failed",
            Self::DispatchResponseTooLarge => "remote capability response exceeds control bound",
            Self::ResponseFrameRejected => "remote capability response frame rejected",
        })
    }
}

impl std::error::Error for RemoteBridgeError {}

const fn validate_nonzero_inline_length(length: usize) -> Result<(), RemoteBridgeError> {
    if length == 0 || length > MAX_BRIDGE_INLINE_BYTES {
        return Err(RemoteBridgeError::InvalidRequestPayload);
    }
    Ok(())
}

fn write_inline_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    allow_empty: bool,
) -> Result<(), RemoteBridgeError> {
    if bytes.len() > MAX_BRIDGE_INLINE_BYTES || (!allow_empty && bytes.is_empty()) {
        return Err(RemoteBridgeError::InvalidRequestPayload);
    }
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| RemoteBridgeError::InvalidRequestPayload)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_path(output: &mut Vec<u8>, path: &RemotePath) -> Result<(), RemoteBridgeError> {
    let encoded = path.components().join("/");
    let length =
        u16::try_from(encoded.len()).map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(encoded.as_bytes());
    Ok(())
}

const fn terminal_profile_code(profile: TerminalProfile) -> u8 {
    match profile {
        TerminalProfile::PosixShell => 1,
        TerminalProfile::BashShell => 2,
    }
}

const fn decode_terminal_profile(value: u8) -> Result<TerminalProfile, RemoteBridgeError> {
    match value {
        1 => Ok(TerminalProfile::PosixShell),
        2 => Ok(TerminalProfile::BashShell),
        _ => Err(RemoteBridgeError::InvalidRequestPayload),
    }
}

fn terminal_session_id(value: u64) -> Result<TerminalSessionId, RemoteBridgeError> {
    TerminalSessionId::new(value).map_err(|_| RemoteBridgeError::InvalidRequestPayload)
}

fn terminal_geometry(columns: u16, rows: u16) -> Result<TerminalGeometry, RemoteBridgeError> {
    TerminalGeometry::new(columns, rows).map_err(|_| RemoteBridgeError::InvalidRequestPayload)
}

fn write_loopback_bind(output: &mut Vec<u8>, bind: LoopbackBind) {
    output.push(match bind.family() {
        LoopbackFamily::Ipv4 => 1,
        LoopbackFamily::Ipv6 => 2,
    });
    output.extend_from_slice(&bind.port().to_be_bytes());
}

fn decode_loopback_bind(reader: &mut Reader<'_>) -> Result<LoopbackBind, RemoteBridgeError> {
    let family = match reader.u8()? {
        1 => LoopbackFamily::Ipv4,
        2 => LoopbackFamily::Ipv6,
        _ => return Err(RemoteBridgeError::InvalidRequestPayload),
    };
    LoopbackBind::new(family, reader.u16()?).map_err(|_| RemoteBridgeError::InvalidRequestPayload)
}

fn write_forward_target(output: &mut Vec<u8>, target: ForwardTarget) {
    match target.address() {
        IpAddr::V4(address) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.push(2);
            output.extend_from_slice(&address.octets());
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
}

fn decode_forward_target(reader: &mut Reader<'_>) -> Result<ForwardTarget, RemoteBridgeError> {
    let address = match reader.u8()? {
        1 => IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
        2 => IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
        _ => return Err(RemoteBridgeError::InvalidRequestPayload),
    };
    ForwardTarget::new(address, reader.u16()?).map_err(|_| RemoteBridgeError::InvalidRequestPayload)
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RemoteBridgeError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(bytes);
        self.offset = end;
        Ok(output)
    }

    fn u8(&mut self) -> Result<u8, RemoteBridgeError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, RemoteBridgeError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, RemoteBridgeError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, RemoteBridgeError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn path(&mut self) -> Result<RemotePath, RemoteBridgeError> {
        let length = usize::from(self.u16()?);
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        let encoded =
            std::str::from_utf8(bytes).map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
        self.offset = end;
        RemotePath::parse(encoded).map_err(|_| RemoteBridgeError::InvalidRequestPayload)
    }

    fn inline_length(&mut self) -> Result<usize, RemoteBridgeError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
        validate_nonzero_inline_length(length)?;
        Ok(length)
    }

    fn inline_bytes(&mut self, allow_empty: bool) -> Result<Vec<u8>, RemoteBridgeError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| RemoteBridgeError::InvalidRequestPayload)?;
        if length > MAX_BRIDGE_INLINE_BYTES || (!allow_empty && length == 0) {
            return Err(RemoteBridgeError::InvalidRequestPayload);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(RemoteBridgeError::InvalidRequestPayload)?;
        self.offset = end;
        Ok(bytes.to_vec())
    }

    const fn finish(self) -> Result<(), RemoteBridgeError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(RemoteBridgeError::InvalidRequestPayload)
        }
    }
}

/// Provider-neutral current-registry and policy gate around Phase 140 remote control frames.
pub struct DurableCapabilityBridge<
    'a,
    S: DurableRegistryAuthority + ?Sized,
    P: PolicyEvaluator + Sync,
> {
    registry: &'a mut S,
    policy: &'a P,
}

impl<'a, S: DurableRegistryAuthority + ?Sized, P: PolicyEvaluator + Sync>
    DurableCapabilityBridge<'a, S, P>
{
    /// Creates a durable bridge over one semantic registry store and already-selected policy.
    #[must_use]
    pub const fn new(registry: &'a mut S, policy: &'a P) -> Self {
        Self { registry, policy }
    }

    /// Authorizes one Phase 140 request against one durable session/transport observation.
    ///
    /// # Errors
    ///
    /// Preserves ordinary Phase 143 request, lease, semantic registry/transport, codec and policy
    /// rejection while keeping non-semantic durable authority failures distinct.
    pub async fn authorize(
        &mut self,
        presented_transport_identity: TransportIdentity,
        lease: &RemoteSessionLease,
        now_unix_seconds: u64,
        frame: &ControlFrame,
    ) -> Result<AuthorizedCapabilityRequest, DurableCapabilityBridgeError> {
        if frame.kind() != ControlMessageKind::Request {
            return Err(DurableCapabilityBridgeError::Bridge(
                RemoteBridgeError::WrongControlMessageKind,
            ));
        }
        lease
            .validate_time(now_unix_seconds)
            .map_err(DurableCapabilityBridgeError::Bridge)?;
        let principal = self
            .registry
            .validate_authenticated_session_and_transport_identity(
                lease.session(),
                presented_transport_identity,
            )
            .await
            .map_err(map_durable_capability_authority_error)?;
        let command =
            BridgeCommand::decode(frame.payload()).map_err(DurableCapabilityBridgeError::Bridge)?;
        let capability = command.required_capability();
        if self.policy.evaluate(capability) != Decision::Allow {
            return Err(DurableCapabilityBridgeError::Bridge(
                RemoteBridgeError::CapabilityDenied,
            ));
        }
        Ok(AuthorizedCapabilityRequest {
            request_id: frame.request_id(),
            principal,
            transport_identity: presented_transport_identity,
            capability,
            command,
        })
    }
}

/// Failure envelope for provider-aware durable capability authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableCapabilityBridgeError {
    /// Existing Phase 143 request, lease, semantic registry/transport, codec or policy rejection.
    Bridge(RemoteBridgeError),
    /// Durable provider/currentness/canonical authority could not be established.
    Authority(DurableRegistryAuthorityError),
}

impl fmt::Display for DurableCapabilityBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bridge(_) => "durable capability bridge rejected request",
            Self::Authority(_) => "durable capability authority failed",
        })
    }
}

impl std::error::Error for DurableCapabilityBridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bridge(error) => Some(error),
            Self::Authority(error) => Some(error),
        }
    }
}

const fn map_durable_capability_authority_error(
    error: DurableRegistryAuthorityError,
) -> DurableCapabilityBridgeError {
    match error {
        DurableRegistryAuthorityError::Semantic(
            prw_registry::RegistryError::TransportIdentityMissing
            | prw_registry::RegistryError::TransportIdentityMismatch,
        ) => DurableCapabilityBridgeError::Bridge(RemoteBridgeError::TransportIdentityRejected),
        DurableRegistryAuthorityError::Semantic(_) => {
            DurableCapabilityBridgeError::Bridge(RemoteBridgeError::RegistryRejected)
        }
        error => DurableCapabilityBridgeError::Authority(error),
    }
}

#[cfg(test)]
mod durable_capability_bridge_tests {
    use super::*;
    #[test]
    fn durable_authority_error_mapping_preserves_selected_semantic_boundary() {
        assert_eq!(
            map_durable_capability_authority_error(DurableRegistryAuthorityError::Semantic(
                prw_registry::RegistryError::TransportIdentityMissing,
            )),
            DurableCapabilityBridgeError::Bridge(RemoteBridgeError::TransportIdentityRejected)
        );
        assert_eq!(
            map_durable_capability_authority_error(DurableRegistryAuthorityError::Semantic(
                prw_registry::RegistryError::TransportIdentityMismatch,
            )),
            DurableCapabilityBridgeError::Bridge(RemoteBridgeError::TransportIdentityRejected)
        );
        assert_eq!(
            map_durable_capability_authority_error(DurableRegistryAuthorityError::Semantic(
                prw_registry::RegistryError::SessionBindingMismatch,
            )),
            DurableCapabilityBridgeError::Bridge(RemoteBridgeError::RegistryRejected)
        );
        assert_eq!(
            map_durable_capability_authority_error(DurableRegistryAuthorityError::ReadUnavailable),
            DurableCapabilityBridgeError::Authority(DurableRegistryAuthorityError::ReadUnavailable)
        );
    }

    #[test]
    fn durable_bridge_error_display_is_bounded_and_source_preserves_stage() {
        let bridge = DurableCapabilityBridgeError::Bridge(RemoteBridgeError::CapabilityDenied);
        assert_eq!(
            bridge.to_string(),
            "durable capability bridge rejected request"
        );
        assert!(std::error::Error::source(&bridge).is_some());

        let authority = DurableCapabilityBridgeError::Authority(
            DurableRegistryAuthorityError::InvalidAuthority,
        );
        assert_eq!(authority.to_string(), "durable capability authority failed");
        assert!(std::error::Error::source(&authority).is_some());
    }
}
