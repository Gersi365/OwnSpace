//! Typed TCP port-forwarding foundation for Ownspace.
//!
//! Phase 134 defines bounded forwarding lifecycle and backend contracts only. It does not
//! open sockets, bind listeners, connect to targets, mutate firewalls, perform DNS, or grant
//! forwarding capability by itself.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use prw_core::{DeviceId, SessionId, UserId, WorkspaceId};
use prw_registry::RegistryValidatedPrincipal;

/// Maximum forwarding sessions tracked by one broker.
pub const MAX_ACTIVE_PORT_FORWARDS: usize = 32;

/// Stable broker-scoped forwarding identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortForwardId(u64);

impl PortForwardId {
    /// Creates a non-zero forwarding identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardingError::InvalidIdentifier`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, ForwardingError> {
        if value == 0 {
            return Err(ForwardingError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the raw broker-scoped identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Loopback-only bind family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopbackFamily {
    /// IPv4 loopback (`127.0.0.1` semantics).
    Ipv4,
    /// IPv6 loopback (`::1` semantics).
    Ipv6,
}

/// Validated loopback-only bind endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopbackBind {
    family: LoopbackFamily,
    port: u16,
}

impl LoopbackBind {
    /// Creates a loopback-only bind endpoint with an explicit non-zero TCP port.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardingError::InvalidBindPort`] when `port` is zero.
    pub const fn new(family: LoopbackFamily, port: u16) -> Result<Self, ForwardingError> {
        if port == 0 {
            return Err(ForwardingError::InvalidBindPort);
        }
        Ok(Self { family, port })
    }

    /// Returns the named loopback family.
    #[must_use]
    pub const fn family(self) -> LoopbackFamily {
        self.family
    }

    /// Returns the explicit bind TCP port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

/// Validated target IP address and non-zero TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForwardTarget {
    address: IpAddr,
    port: u16,
}

impl ForwardTarget {
    /// Creates an explicit target endpoint.
    ///
    /// # Errors
    ///
    /// Rejects port zero, unspecified addresses, multicast addresses and IPv4 limited
    /// broadcast. No hostname or resolver input exists in this API.
    pub fn new(address: IpAddr, port: u16) -> Result<Self, ForwardingError> {
        if port == 0 {
            return Err(ForwardingError::InvalidTargetPort);
        }

        let invalid_address = match address {
            IpAddr::V4(ipv4) => {
                ipv4.is_unspecified() || ipv4.is_multicast() || ipv4 == Ipv4Addr::BROADCAST
            }
            IpAddr::V6(ipv6) => ipv6.is_unspecified() || ipv6.is_multicast(),
        };
        if invalid_address {
            return Err(ForwardingError::InvalidTargetAddress);
        }

        Ok(Self { address, port })
    }

    /// Returns the explicit target IP address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns the explicit target TCP port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

/// Fully validated TCP forwarding specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpForwardSpec {
    bind: LoopbackBind,
    target: ForwardTarget,
}

impl TcpForwardSpec {
    /// Creates a TCP forwarding specification from validated endpoint types.
    #[must_use]
    pub const fn new(bind: LoopbackBind, target: ForwardTarget) -> Self {
        Self { bind, target }
    }

    /// Returns the loopback-only bind endpoint.
    #[must_use]
    pub const fn bind(self) -> LoopbackBind {
        self.bind
    }

    /// Returns the target endpoint.
    #[must_use]
    pub const fn target(self) -> ForwardTarget {
        self.target
    }
}

/// Registry-current identity snapshot attached immutably to one forwarding session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingPrincipal {
    workspace: WorkspaceId,
    user: UserId,
    device: DeviceId,
    authenticated_session: SessionId,
}

impl ForwardingPrincipal {
    /// Captures current-registry identity plus the authenticated PRW session identifier.
    #[must_use]
    pub fn from_registry(principal: &RegistryValidatedPrincipal, session_id: SessionId) -> Self {
        Self {
            workspace: principal.workspace_id().clone(),
            user: principal.user_id().clone(),
            device: principal.device_id().clone(),
            authenticated_session: session_id,
        }
    }

    /// Returns the immutable workspace identifier.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace
    }

    /// Returns the immutable user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user
    }

    /// Returns the immutable device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device
    }

    /// Returns the immutable authenticated PRW session identifier.
    #[must_use]
    pub const fn authenticated_session_id(&self) -> &SessionId {
        &self.authenticated_session
    }
}

/// Same-UID local Linux principal for one Agent-authenticated forwarding session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalForwardingPrincipal {
    uid: u32,
}

impl LocalForwardingPrincipal {
    /// Captures the kernel-authenticated local UID selected by the Agent.
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        Self { uid }
    }

    /// Returns the authenticated local UID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }
}

/// Identity domain attached immutably to one forwarding broker record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardingSessionPrincipal {
    /// Registry-current authenticated PRW session identity.
    Registry(ForwardingPrincipal),
    /// Kernel-authenticated local same-UID identity.
    LocalSameUid(LocalForwardingPrincipal),
}

impl From<ForwardingPrincipal> for ForwardingSessionPrincipal {
    fn from(principal: ForwardingPrincipal) -> Self {
        Self::Registry(principal)
    }
}

impl From<LocalForwardingPrincipal> for ForwardingSessionPrincipal {
    fn from(principal: LocalForwardingPrincipal) -> Self {
        Self::LocalSameUid(principal)
    }
}

impl ForwardingSessionPrincipal {
    /// Returns registry identity only for the registry-derived variant.
    #[must_use]
    pub const fn registry(&self) -> Option<&ForwardingPrincipal> {
        match self {
            Self::Registry(principal) => Some(principal),
            Self::LocalSameUid(_) => None,
        }
    }

    /// Returns local same-UID identity only for the local variant.
    #[must_use]
    pub const fn local_same_uid(&self) -> Option<LocalForwardingPrincipal> {
        match self {
            Self::Registry(_) => None,
            Self::LocalSameUid(principal) => Some(*principal),
        }
    }
}

/// Port-forward lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingState {
    /// Provider opening is in progress.
    Opening,
    /// Forwarding provider opened successfully.
    Active,
    /// Explicit provider close is in progress.
    Closing,
    /// Provider close completed successfully.
    Closed,
    /// A provider operation failed and the record cannot silently resume.
    Failed,
}

/// Provider-neutral forwarding backend contract.
///
/// No method accepts shell text, executable paths, DNS names, arbitrary bind addresses,
/// interface names, firewall instructions, socket-option bags or privilege instructions.
pub trait PortForwardBackend {
    /// Backend-owned forwarding handle.
    type Handle;

    /// Opens one already-validated TCP forwarding specification.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot open the forwarding resource.
    fn open(&mut self, spec: TcpForwardSpec) -> Result<Self::Handle, ForwardingError>;

    /// Closes one provider-owned forwarding handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot close the forwarding resource.
    fn close(&mut self, handle: &mut Self::Handle) -> Result<(), ForwardingError>;
}

/// Provider-neutral forwarding record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForwardSession {
    id: PortForwardId,
    principal: ForwardingSessionPrincipal,
    spec: TcpForwardSpec,
    state: ForwardingState,
}

impl PortForwardSession {
    const fn opening(
        id: PortForwardId,
        principal: ForwardingSessionPrincipal,
        spec: TcpForwardSpec,
    ) -> Self {
        Self {
            id,
            principal,
            spec,
            state: ForwardingState::Opening,
        }
    }

    /// Returns the broker-scoped forwarding identifier.
    #[must_use]
    pub const fn id(&self) -> PortForwardId {
        self.id
    }

    /// Returns the immutable registry/authenticated-session identity snapshot.
    #[must_use]
    pub const fn principal(&self) -> &ForwardingSessionPrincipal {
        &self.principal
    }

    /// Returns the immutable validated forwarding specification.
    #[must_use]
    pub const fn spec(&self) -> TcpForwardSpec {
        self.spec
    }

    /// Returns current forwarding lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ForwardingState {
        self.state
    }

    const fn mark_active(&mut self) {
        self.state = ForwardingState::Active;
    }

    const fn mark_closing(&mut self) {
        self.state = ForwardingState::Closing;
    }

    const fn mark_closed(&mut self) {
        self.state = ForwardingState::Closed;
    }

    const fn mark_failed(&mut self) {
        self.state = ForwardingState::Failed;
    }

    fn require_active(&self) -> Result<(), ForwardingError> {
        if self.state != ForwardingState::Active {
            return Err(ForwardingError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BrokerForward<H> {
    record: PortForwardSession,
    handle: Option<H>,
}

/// Bounded forwarding broker around one typed backend.
///
/// Phase 134 enforces identity/spec/lifecycle bounds but deliberately performs no real
/// networking itself and does not evaluate production forwarding capability.
#[derive(Debug)]
pub struct PortForwardBroker<B: PortForwardBackend> {
    backend: B,
    sessions: HashMap<PortForwardId, BrokerForward<B::Handle>>,
}

impl<B: PortForwardBackend> PortForwardBroker<B> {
    /// Creates an empty forwarding broker around one backend instance.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            sessions: HashMap::new(),
        }
    }

    /// Returns the number of tracked active or failed forwarding records.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns whether no forwarding records are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns one current forwarding record without exposing the backend handle.
    #[must_use]
    pub fn session(&self, id: PortForwardId) -> Option<&PortForwardSession> {
        self.sessions.get(&id).map(|forward| &forward.record)
    }

    /// Opens one validated loopback-to-target TCP forwarding record.
    ///
    /// # Errors
    ///
    /// Duplicate identifiers and broker capacity fail before backend mutation. Backend open
    /// failure returns [`ForwardingError::Backend`] and creates no tracked session.
    pub fn open_session<P: Into<ForwardingSessionPrincipal>>(
        &mut self,
        id: PortForwardId,
        principal: P,
        spec: TcpForwardSpec,
    ) -> Result<&PortForwardSession, ForwardingError> {
        let principal = principal.into();
        let at_capacity = self.sessions.len() >= MAX_ACTIVE_PORT_FORWARDS;
        match self.sessions.entry(id) {
            Entry::Occupied(_) => Err(ForwardingError::DuplicateSession),
            Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(ForwardingError::SessionCapacity);
                }
                let handle = self
                    .backend
                    .open(spec)
                    .map_err(|_| ForwardingError::Backend)?;
                let mut record = PortForwardSession::opening(id, principal, spec);
                record.mark_active();
                Ok(&entry
                    .insert(BrokerForward {
                        record,
                        handle: Some(handle),
                    })
                    .record)
            }
        }
    }

    /// Explicitly closes one active forwarding record.
    ///
    /// # Errors
    ///
    /// Unknown/non-active sessions are rejected. Backend close failure retains the session in
    /// `Failed` state. Successful close returns a terminal `Closed` record and removes it.
    pub fn close_session(
        &mut self,
        id: PortForwardId,
    ) -> Result<PortForwardSession, ForwardingError> {
        let mut forward = self
            .sessions
            .remove(&id)
            .ok_or(ForwardingError::UnknownSession)?;
        if let Err(error) = forward.record.require_active() {
            self.sessions.insert(id, forward);
            return Err(error);
        }
        forward.record.mark_closing();

        let Some(handle) = forward.handle.as_mut() else {
            forward.record.mark_failed();
            self.sessions.insert(id, forward);
            return Err(ForwardingError::InvalidState);
        };

        if self.backend.close(handle).is_err() {
            forward.record.mark_failed();
            self.sessions.insert(id, forward);
            return Err(ForwardingError::Backend);
        }

        forward.handle = None;
        forward.record.mark_closed();
        Ok(forward.record)
    }

    /// Retries provider cleanup for one retained failed forwarding record.
    ///
    /// This operation is teardown-only. It never reactivates forwarding. On backend
    /// failure the same failed record and handle remain tracked for a later cleanup
    /// attempt. On success the handle is cleared, the record becomes `Closed`, and the
    /// broker removes it.
    ///
    /// # Errors
    ///
    /// Rejects unknown or non-`Failed` records before calling the backend. A missing
    /// retained handle is an invalid state. Backend close failure preserves `Failed`.
    pub fn retry_failed_close(
        &mut self,
        id: PortForwardId,
    ) -> Result<PortForwardSession, ForwardingError> {
        let mut forward = self
            .sessions
            .remove(&id)
            .ok_or(ForwardingError::UnknownSession)?;
        if forward.record.state() != ForwardingState::Failed {
            self.sessions.insert(id, forward);
            return Err(ForwardingError::InvalidState);
        }

        let Some(handle) = forward.handle.as_mut() else {
            self.sessions.insert(id, forward);
            return Err(ForwardingError::InvalidState);
        };

        if self.backend.close(handle).is_err() {
            forward.record.mark_failed();
            self.sessions.insert(id, forward);
            return Err(ForwardingError::Backend);
        }

        forward.handle = None;
        forward.record.mark_closed();
        Ok(forward.record)
    }
}

/// Stable Phase 134 forwarding failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardingError {
    /// Forwarding identifier was zero.
    InvalidIdentifier,
    /// Loopback bind port was zero.
    InvalidBindPort,
    /// Target port was zero.
    InvalidTargetPort,
    /// Target address was unspecified, multicast or IPv4 limited broadcast.
    InvalidTargetAddress,
    /// Forward identifier is already tracked.
    DuplicateSession,
    /// Broker already tracks the maximum forwarding-session count.
    SessionCapacity,
    /// Forward identifier is not currently tracked.
    UnknownSession,
    /// Operation is invalid for current forwarding state.
    InvalidState,
    /// Provider operation failed.
    Backend,
}

impl fmt::Display for ForwardingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "port-forward identifier must be non-zero",
            Self::InvalidBindPort => "loopback bind port must be non-zero",
            Self::InvalidTargetPort => "target port must be non-zero",
            Self::InvalidTargetAddress => "target address is not allowed",
            Self::DuplicateSession => "port-forward identifier already exists",
            Self::SessionCapacity => "port-forward broker capacity reached",
            Self::UnknownSession => "port-forward identifier is not tracked",
            Self::InvalidState => "port-forward operation is invalid for current state",
            Self::Backend => "port-forward backend operation failed",
        })
    }
}

impl std::error::Error for ForwardingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    enum FailureMode {
        #[default]
        None,
        Open,
        Close,
    }

    #[derive(Debug, Default)]
    struct SpyBackend {
        open_calls: usize,
        close_calls: usize,
        failure: FailureMode,
        last_spec: Option<TcpForwardSpec>,
    }

    impl PortForwardBackend for SpyBackend {
        type Handle = u64;

        fn open(&mut self, spec: TcpForwardSpec) -> Result<Self::Handle, ForwardingError> {
            self.open_calls += 1;
            self.last_spec = Some(spec);
            if self.failure == FailureMode::Open {
                return Err(ForwardingError::Backend);
            }
            Ok(u64::try_from(self.open_calls).expect("test open count fits u64"))
        }

        fn close(&mut self, _handle: &mut Self::Handle) -> Result<(), ForwardingError> {
            self.close_calls += 1;
            if self.failure == FailureMode::Close {
                return Err(ForwardingError::Backend);
            }
            Ok(())
        }
    }

    fn principal() -> ForwardingPrincipal {
        ForwardingPrincipal {
            workspace: WorkspaceId::new("workspace-1").expect("workspace"),
            user: UserId::new("user-1").expect("user"),
            device: DeviceId::new("device-1").expect("device"),
            authenticated_session: SessionId::new("session-1").expect("session"),
        }
    }

    fn id(value: u64) -> PortForwardId {
        PortForwardId::new(value).expect("forward id")
    }

    fn spec(port: u16) -> TcpForwardSpec {
        TcpForwardSpec::new(
            LoopbackBind::new(LoopbackFamily::Ipv4, port).expect("bind"),
            ForwardTarget::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22).expect("target"),
        )
    }

    #[test]
    fn identifiers_and_ports_are_non_zero() {
        assert_eq!(
            PortForwardId::new(0),
            Err(ForwardingError::InvalidIdentifier)
        );
        assert_eq!(
            LoopbackBind::new(LoopbackFamily::Ipv4, 0),
            Err(ForwardingError::InvalidBindPort)
        );
        assert_eq!(
            ForwardTarget::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Err(ForwardingError::InvalidTargetPort)
        );
    }

    #[test]
    fn invalid_target_address_classes_are_rejected() {
        assert_eq!(
            ForwardTarget::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
            Err(ForwardingError::InvalidTargetAddress)
        );
        assert_eq!(
            ForwardTarget::new(IpAddr::V4(Ipv4Addr::BROADCAST), 80),
            Err(ForwardingError::InvalidTargetAddress)
        );
        assert_eq!(
            ForwardTarget::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 80),
            Err(ForwardingError::InvalidTargetAddress)
        );
        assert_eq!(
            ForwardTarget::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80),
            Err(ForwardingError::InvalidTargetAddress)
        );
        assert_eq!(
            ForwardTarget::new(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), 80),
            Err(ForwardingError::InvalidTargetAddress)
        );
    }

    #[test]
    fn loopback_targets_and_named_bind_families_are_supported() {
        let ipv4 = ForwardTarget::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22).expect("ipv4");
        let ipv6 = ForwardTarget::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443).expect("ipv6");
        assert_eq!(ipv4.address(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(ipv6.address(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            LoopbackBind::new(LoopbackFamily::Ipv6, 8443)
                .expect("bind")
                .family(),
            LoopbackFamily::Ipv6
        );
    }

    #[test]
    fn backend_receives_exact_validated_spec_and_identity_is_preserved() {
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        let expected = spec(2200);
        let session = broker
            .open_session(id(1), principal(), expected)
            .expect("open");
        assert_eq!(session.spec(), expected);
        assert_eq!(session.state(), ForwardingState::Active);
        let registry = session.principal().registry().expect("registry principal");
        assert_eq!(registry.workspace_id().as_str(), "workspace-1");
        assert_eq!(registry.user_id().as_str(), "user-1");
        assert_eq!(registry.device_id().as_str(), "device-1");
        assert_eq!(registry.authenticated_session_id().as_str(), "session-1");
        assert!(session.principal().local_same_uid().is_none());
        assert_eq!(broker.backend.last_spec, Some(expected));
    }

    #[test]
    fn local_same_uid_principal_is_distinct_from_registry_identity() {
        let local = LocalForwardingPrincipal::new(1000);
        assert_ne!(
            ForwardingSessionPrincipal::from(local),
            ForwardingSessionPrincipal::from(principal())
        );
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        let session = broker
            .open_session(id(99), local, spec(2299))
            .expect("local open");
        assert_eq!(session.principal().local_same_uid(), Some(local));
        assert!(session.principal().registry().is_none());
    }

    #[test]
    fn duplicate_identifier_fails_before_backend_call() {
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        broker
            .open_session(id(1), principal(), spec(2200))
            .expect("first");
        assert!(matches!(
            broker.open_session(id(1), principal(), spec(2201)),
            Err(ForwardingError::DuplicateSession)
        ));
        assert_eq!(broker.backend.open_calls, 1);
    }

    #[test]
    fn capacity_fails_before_backend_call() {
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        for value in 1..=u64::try_from(MAX_ACTIVE_PORT_FORWARDS).expect("capacity fits u64") {
            broker
                .open_session(
                    id(value),
                    principal(),
                    spec(3000 + u16::try_from(value).expect("port offset fits u16")),
                )
                .expect("within capacity");
        }
        assert_eq!(broker.session_count(), MAX_ACTIVE_PORT_FORWARDS);
        let calls = broker.backend.open_calls;
        assert!(matches!(
            broker.open_session(id(100), principal(), spec(4000)),
            Err(ForwardingError::SessionCapacity)
        ));
        assert_eq!(broker.backend.open_calls, calls);
    }

    #[test]
    fn backend_open_failure_creates_no_session() {
        let mut broker = PortForwardBroker::new(SpyBackend {
            failure: FailureMode::Open,
            ..SpyBackend::default()
        });
        assert!(matches!(
            broker.open_session(id(1), principal(), spec(2200)),
            Err(ForwardingError::Backend)
        ));
        assert!(broker.is_empty());
        assert_eq!(broker.backend.open_calls, 1);
    }

    #[test]
    fn successful_close_returns_closed_and_removes_record() {
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        broker
            .open_session(id(1), principal(), spec(2200))
            .expect("open");
        let closed = broker.close_session(id(1)).expect("close");
        assert_eq!(closed.state(), ForwardingState::Closed);
        assert!(broker.session(id(1)).is_none());
        assert_eq!(broker.backend.close_calls, 1);
        assert_eq!(
            broker.close_session(id(1)),
            Err(ForwardingError::UnknownSession)
        );
    }

    #[test]
    fn backend_close_failure_retains_failed_record() {
        let mut broker = PortForwardBroker::new(SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        });
        broker
            .open_session(id(1), principal(), spec(2200))
            .expect("open");
        assert_eq!(broker.close_session(id(1)), Err(ForwardingError::Backend));
        assert_eq!(
            broker.session(id(1)).expect("retained").state(),
            ForwardingState::Failed
        );
        assert_eq!(
            broker.close_session(id(1)),
            Err(ForwardingError::InvalidState)
        );
    }

    #[test]
    fn failed_close_can_be_retried_to_closed_and_removed() {
        let mut broker = PortForwardBroker::new(SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        });
        broker
            .open_session(id(2), principal(), spec(2201))
            .expect("open");
        assert_eq!(broker.close_session(id(2)), Err(ForwardingError::Backend));
        assert_eq!(broker.backend.close_calls, 1);
        assert_eq!(
            broker.session(id(2)).expect("retained").state(),
            ForwardingState::Failed
        );

        broker.backend.failure = FailureMode::None;
        let closed = broker.retry_failed_close(id(2)).expect("retry close");
        assert_eq!(closed.state(), ForwardingState::Closed);
        assert_eq!(broker.backend.close_calls, 2);
        assert!(broker.session(id(2)).is_none());
        assert_eq!(
            broker.close_session(id(2)),
            Err(ForwardingError::UnknownSession)
        );
    }

    #[test]
    fn failed_close_retry_failure_retains_failed_record() {
        let mut broker = PortForwardBroker::new(SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        });
        broker
            .open_session(id(3), principal(), spec(2202))
            .expect("open");
        assert_eq!(broker.close_session(id(3)), Err(ForwardingError::Backend));
        assert_eq!(
            broker.retry_failed_close(id(3)),
            Err(ForwardingError::Backend)
        );
        assert_eq!(broker.backend.close_calls, 2);
        assert_eq!(
            broker.session(id(3)).expect("retained").state(),
            ForwardingState::Failed
        );
    }

    #[test]
    fn failed_close_retry_rejects_active_or_unknown_before_backend_call() {
        let mut broker = PortForwardBroker::new(SpyBackend::default());
        broker
            .open_session(id(4), principal(), spec(2203))
            .expect("open");
        assert_eq!(
            broker.retry_failed_close(id(4)),
            Err(ForwardingError::InvalidState)
        );
        assert_eq!(
            broker.retry_failed_close(id(5)),
            Err(ForwardingError::UnknownSession)
        );
        assert_eq!(broker.backend.close_calls, 0);
        assert_eq!(
            broker.session(id(4)).expect("active retained").state(),
            ForwardingState::Active
        );
    }
}
