//! Provider-neutral relay fallback foundation for Ownspace.
//!
//! Phase 136 models fallback-only relay sessions and bounded opaque frames. It performs no
//! socket I/O, relay dialing, encryption/decryption, payload parsing, DNS, firewall mutation
//! or production-network activation.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use prw_connectivity::{
    CandidateId, ConnectivityEndpoint, ConnectivityPathKind, SelectedConnectivityPath,
    TransportIdentity,
};
use prw_core::DeviceId;

/// Maximum simultaneously tracked relay sessions in one broker.
pub const MAX_ACTIVE_RELAY_SESSIONS: usize = 32;
/// Maximum one opaque relay frame payload.
pub const MAX_RELAY_FRAME_BYTES: usize = 65_536;

/// Stable broker-scoped relay session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelaySessionId(u64);

impl RelaySessionId {
    /// Creates a non-zero relay session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidSessionId`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, RelayError> {
        if value == 0 {
            return Err(RelayError::InvalidSessionId);
        }
        Ok(Self(value))
    }

    /// Returns the raw broker-scoped identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque non-zero relay routing token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayRouteToken([u8; 32]);

impl fmt::Debug for RelayRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayRouteToken(<redacted>)")
    }
}

impl RelayRouteToken {
    /// Creates a non-zero 32-byte routing token.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidRouteToken`] for the all-zero token.
    pub fn new(bytes: [u8; 32]) -> Result<Self, RelayError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RelayError::InvalidRouteToken);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque token bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Logical peer identity plus distinct transport identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPeerIdentity {
    device: DeviceId,
    transport: TransportIdentity,
}

impl RelayPeerIdentity {
    /// Creates a relay peer identity from already-validated components.
    #[must_use]
    pub const fn new(device: DeviceId, transport: TransportIdentity) -> Self {
        Self { device, transport }
    }

    /// Returns the logical device identity.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device
    }

    /// Returns the distinct transport identity.
    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.transport
    }
}

/// Relay session specification derived only from an already-selected relay candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionSpec {
    peer: RelayPeerIdentity,
    candidate_id: CandidateId,
    endpoint: ConnectivityEndpoint,
    route_token: RelayRouteToken,
}

impl RelaySessionSpec {
    /// Creates a relay specification from the Phase 135 selected path.
    ///
    /// # Errors
    ///
    /// Rejects direct or offline selections. Only a selected candidate with path kind `Relay`
    /// can cross this boundary.
    pub fn from_selected_path(
        peer: RelayPeerIdentity,
        route_token: RelayRouteToken,
        selected: SelectedConnectivityPath,
    ) -> Result<Self, RelayError> {
        let SelectedConnectivityPath::Candidate(candidate) = selected else {
            return Err(RelayError::RelayNotSelected);
        };
        if candidate.kind() != ConnectivityPathKind::Relay {
            return Err(RelayError::RelayNotSelected);
        }
        Ok(Self {
            peer,
            candidate_id: candidate.id(),
            endpoint: candidate.endpoint(),
            route_token,
        })
    }

    /// Returns the immutable peer identity.
    #[must_use]
    pub const fn peer(&self) -> &RelayPeerIdentity {
        &self.peer
    }

    /// Returns the selected relay candidate identifier.
    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    /// Returns the explicit selected relay endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> ConnectivityEndpoint {
        self.endpoint
    }

    /// Returns the opaque route token.
    #[must_use]
    pub const fn route_token(&self) -> RelayRouteToken {
        self.route_token
    }
}

/// Bounded application-opaque relay payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRelayFrame(Vec<u8>);

impl OpaqueRelayFrame {
    /// Creates a non-empty relay frame no larger than 64 KiB.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::EmptyFrame`] for empty data and [`RelayError::FrameTooLarge`]
    /// when the payload exceeds [`MAX_RELAY_FRAME_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, RelayError> {
        if bytes.is_empty() {
            return Err(RelayError::EmptyFrame);
        }
        if bytes.len() > MAX_RELAY_FRAME_BYTES {
            return Err(RelayError::FrameTooLarge);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque bytes without interpreting them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Relay session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    /// Provider open is in progress.
    Opening,
    /// Relay provider opened successfully.
    Active,
    /// Explicit provider close is in progress.
    Closing,
    /// Provider close completed successfully.
    Closed,
    /// Provider operation failed and the record cannot silently resume.
    Failed,
}

/// Provider-neutral relay backend boundary.
///
/// The backend receives only a validated relay spec, an opaque frame and its own handle. No
/// application parser, decryption key, private identity key, hostname or shell instruction is
/// part of this interface.
pub trait RelayBackend {
    /// Backend-owned relay handle.
    type Handle;

    /// Opens one already-validated relay fallback specification.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot open the relay resource.
    fn open(&mut self, spec: &RelaySessionSpec) -> Result<Self::Handle, RelayError>;

    /// Transmits one already-bounded opaque frame unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot transmit the frame.
    fn transmit(
        &mut self,
        handle: &mut Self::Handle,
        frame: &OpaqueRelayFrame,
    ) -> Result<(), RelayError>;

    /// Closes the provider-owned relay handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot close the relay resource.
    fn close(&mut self, handle: &mut Self::Handle) -> Result<(), RelayError>;
}

/// Provider-neutral relay session record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySession {
    id: RelaySessionId,
    spec: RelaySessionSpec,
    state: RelayState,
}

impl RelaySession {
    const fn opening(id: RelaySessionId, spec: RelaySessionSpec) -> Self {
        Self {
            id,
            spec,
            state: RelayState::Opening,
        }
    }

    /// Returns the broker-scoped relay session identifier.
    #[must_use]
    pub const fn id(&self) -> RelaySessionId {
        self.id
    }

    /// Returns the immutable relay specification.
    #[must_use]
    pub const fn spec(&self) -> &RelaySessionSpec {
        &self.spec
    }

    /// Returns the current relay lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RelayState {
        self.state
    }

    fn require_active(&self) -> Result<(), RelayError> {
        if self.state != RelayState::Active {
            return Err(RelayError::InvalidState);
        }
        Ok(())
    }

    const fn mark_active(&mut self) {
        self.state = RelayState::Active;
    }

    const fn mark_closing(&mut self) {
        self.state = RelayState::Closing;
    }

    const fn mark_closed(&mut self) {
        self.state = RelayState::Closed;
    }

    const fn mark_failed(&mut self) {
        self.state = RelayState::Failed;
    }
}

#[derive(Debug)]
struct BrokerRelay<H> {
    record: RelaySession,
    handle: Option<H>,
}

/// Bounded relay fallback broker around one typed provider.
#[derive(Debug)]
pub struct RelayBroker<B: RelayBackend> {
    backend: B,
    sessions: HashMap<RelaySessionId, BrokerRelay<B::Handle>>,
}

impl<B: RelayBackend> RelayBroker<B> {
    /// Creates an empty relay broker.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            sessions: HashMap::new(),
        }
    }

    /// Returns the current number of tracked relay records.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns whether no relay records are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns one current relay record without exposing the provider handle.
    #[must_use]
    pub fn session(&self, id: RelaySessionId) -> Option<&RelaySession> {
        self.sessions.get(&id).map(|relay| &relay.record)
    }

    /// Opens one relay session already proven to be the selected fallback path.
    ///
    /// # Errors
    ///
    /// Duplicate identifiers and broker capacity fail before provider mutation. Provider open
    /// failure creates no tracked session.
    pub fn open_session(
        &mut self,
        id: RelaySessionId,
        spec: RelaySessionSpec,
    ) -> Result<&RelaySession, RelayError> {
        let at_capacity = self.sessions.len() >= MAX_ACTIVE_RELAY_SESSIONS;
        match self.sessions.entry(id) {
            Entry::Occupied(_) => Err(RelayError::DuplicateSession),
            Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(RelayError::SessionCapacity);
                }
                let handle = self.backend.open(&spec).map_err(|_| RelayError::Backend)?;
                let mut record = RelaySession::opening(id, spec);
                record.mark_active();
                Ok(&entry
                    .insert(BrokerRelay {
                        record,
                        handle: Some(handle),
                    })
                    .record)
            }
        }
    }

    /// Transmits one bounded opaque frame through an active relay session.
    ///
    /// # Errors
    ///
    /// Unknown/non-active sessions fail closed. Provider transmit failure retains the session
    /// as `Failed` and later transmit attempts are rejected.
    pub fn transmit(
        &mut self,
        id: RelaySessionId,
        frame: &OpaqueRelayFrame,
    ) -> Result<(), RelayError> {
        let (backend, sessions) = (&mut self.backend, &mut self.sessions);
        let relay = sessions.get_mut(&id).ok_or(RelayError::UnknownSession)?;
        relay.record.require_active()?;
        let handle = relay.handle.as_mut().ok_or(RelayError::InvalidState)?;
        if backend.transmit(handle, frame).is_err() {
            relay.record.mark_failed();
            return Err(RelayError::Backend);
        }
        Ok(())
    }

    /// Explicitly closes one active relay session.
    ///
    /// # Errors
    ///
    /// Provider close failure retains a `Failed` record. Successful close returns `Closed` and
    /// removes the record from the broker.
    pub fn close_session(&mut self, id: RelaySessionId) -> Result<RelaySession, RelayError> {
        let mut relay = self
            .sessions
            .remove(&id)
            .ok_or(RelayError::UnknownSession)?;
        if let Err(error) = relay.record.require_active() {
            self.sessions.insert(id, relay);
            return Err(error);
        }
        relay.record.mark_closing();

        let Some(handle) = relay.handle.as_mut() else {
            relay.record.mark_failed();
            self.sessions.insert(id, relay);
            return Err(RelayError::InvalidState);
        };
        if self.backend.close(handle).is_err() {
            relay.record.mark_failed();
            self.sessions.insert(id, relay);
            return Err(RelayError::Backend);
        }
        relay.handle = None;
        relay.record.mark_closed();
        Ok(relay.record)
    }
}

/// Stable Phase 136 relay failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayError {
    /// Relay session identifier was zero.
    InvalidSessionId,
    /// Route token was all zero.
    InvalidRouteToken,
    /// Phase 135 did not select a relay candidate.
    RelayNotSelected,
    /// Relay frame was empty.
    EmptyFrame,
    /// Relay frame exceeded 64 KiB.
    FrameTooLarge,
    /// Relay session identifier is already tracked.
    DuplicateSession,
    /// Relay broker capacity was reached.
    SessionCapacity,
    /// Relay session identifier is not tracked.
    UnknownSession,
    /// Operation is invalid for current relay state.
    InvalidState,
    /// Provider operation failed.
    Backend,
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionId => "relay session identifier must be non-zero",
            Self::InvalidRouteToken => "relay route token must not be all zero",
            Self::RelayNotSelected => "relay path was not selected",
            Self::EmptyFrame => "relay frame must not be empty",
            Self::FrameTooLarge => "relay frame exceeds bound",
            Self::DuplicateSession => "relay session identifier already exists",
            Self::SessionCapacity => "relay session capacity reached",
            Self::UnknownSession => "relay session identifier is not tracked",
            Self::InvalidState => "relay operation is invalid for current state",
            Self::Backend => "relay backend operation failed",
        })
    }
}

impl std::error::Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;
    use prw_connectivity::{
        CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    enum FailureMode {
        #[default]
        None,
        Open,
        Transmit,
        Close,
    }

    #[derive(Debug, Default)]
    struct SpyBackend {
        open_calls: usize,
        transmit_calls: usize,
        close_calls: usize,
        failure: FailureMode,
        last_spec: Option<RelaySessionSpec>,
        last_frame: Vec<u8>,
    }

    impl RelayBackend for SpyBackend {
        type Handle = u64;

        fn open(&mut self, spec: &RelaySessionSpec) -> Result<Self::Handle, RelayError> {
            self.open_calls += 1;
            self.last_spec = Some(spec.clone());
            if self.failure == FailureMode::Open {
                return Err(RelayError::Backend);
            }
            Ok(u64::try_from(self.open_calls).expect("test open count fits u64"))
        }

        fn transmit(
            &mut self,
            _handle: &mut Self::Handle,
            frame: &OpaqueRelayFrame,
        ) -> Result<(), RelayError> {
            self.transmit_calls += 1;
            self.last_frame = frame.as_bytes().to_vec();
            if self.failure == FailureMode::Transmit {
                return Err(RelayError::Backend);
            }
            Ok(())
        }

        fn close(&mut self, _handle: &mut Self::Handle) -> Result<(), RelayError> {
            self.close_calls += 1;
            if self.failure == FailureMode::Close {
                return Err(RelayError::Backend);
            }
            Ok(())
        }
    }

    fn transport() -> TransportIdentity {
        TransportIdentity::new([1; 32]).expect("transport")
    }

    fn peer() -> RelayPeerIdentity {
        RelayPeerIdentity::new(DeviceId::new("device-1").expect("device"), transport())
    }

    fn token() -> RelayRouteToken {
        RelayRouteToken::new([2; 32]).expect("token")
    }

    fn session_id(value: u64) -> RelaySessionId {
        RelaySessionId::new(value).expect("session id")
    }

    fn selected(kind: ConnectivityPathKind, candidate_value: u64) -> SelectedConnectivityPath {
        SelectedConnectivityPath::Candidate(ConnectivityCandidate::new(
            CandidateId::new(candidate_value).expect("candidate id"),
            kind,
            ConnectivityEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                4000 + u16::try_from(candidate_value).expect("candidate test port fits u16"),
            )
            .expect("endpoint"),
        ))
    }

    fn relay_spec(candidate_value: u64) -> RelaySessionSpec {
        RelaySessionSpec::from_selected_path(
            peer(),
            token(),
            selected(ConnectivityPathKind::Relay, candidate_value),
        )
        .expect("relay selected")
    }

    #[test]
    fn identifiers_tokens_and_frames_are_bounded() {
        assert_eq!(RelaySessionId::new(0), Err(RelayError::InvalidSessionId));
        assert_eq!(
            RelayRouteToken::new([0; 32]),
            Err(RelayError::InvalidRouteToken)
        );
        assert_eq!(
            OpaqueRelayFrame::new(Vec::new()),
            Err(RelayError::EmptyFrame)
        );
        assert_eq!(
            OpaqueRelayFrame::new(vec![0; MAX_RELAY_FRAME_BYTES + 1]),
            Err(RelayError::FrameTooLarge)
        );
    }

    #[test]
    fn only_selected_relay_path_can_construct_spec() {
        assert_eq!(
            RelaySessionSpec::from_selected_path(
                peer(),
                token(),
                selected(ConnectivityPathKind::LocalDirect, 1),
            ),
            Err(RelayError::RelayNotSelected)
        );
        assert_eq!(
            RelaySessionSpec::from_selected_path(
                peer(),
                token(),
                selected(ConnectivityPathKind::InternetDirect, 2),
            ),
            Err(RelayError::RelayNotSelected)
        );
        assert_eq!(
            RelaySessionSpec::from_selected_path(
                peer(),
                token(),
                SelectedConnectivityPath::Offline
            ),
            Err(RelayError::RelayNotSelected)
        );
        let spec = relay_spec(3);
        assert_eq!(spec.candidate_id().get(), 3);
        assert_eq!(spec.endpoint().port(), 4003);
    }

    #[test]
    fn logical_device_and_transport_identity_remain_distinct() {
        let spec = relay_spec(1);
        assert_eq!(spec.peer().device_id().as_str(), "device-1");
        assert_eq!(spec.peer().transport_identity(), transport());
        assert_eq!(spec.route_token(), token());
    }

    #[test]
    fn duplicate_and_capacity_fail_before_backend_open() {
        let mut broker = RelayBroker::new(SpyBackend::default());
        broker
            .open_session(session_id(1), relay_spec(1))
            .expect("first");
        assert!(matches!(
            broker.open_session(session_id(1), relay_spec(2)),
            Err(RelayError::DuplicateSession)
        ));
        assert_eq!(broker.backend.open_calls, 1);

        for value in 2..=u64::try_from(MAX_ACTIVE_RELAY_SESSIONS).expect("capacity fits u64") {
            broker
                .open_session(session_id(value), relay_spec(value))
                .expect("within capacity");
        }
        let calls = broker.backend.open_calls;
        assert!(matches!(
            broker.open_session(session_id(100), relay_spec(100)),
            Err(RelayError::SessionCapacity)
        ));
        assert_eq!(broker.backend.open_calls, calls);
    }

    #[test]
    fn backend_open_failure_creates_no_session() {
        let mut broker = RelayBroker::new(SpyBackend {
            failure: FailureMode::Open,
            ..SpyBackend::default()
        });
        assert!(matches!(
            broker.open_session(session_id(1), relay_spec(1)),
            Err(RelayError::Backend)
        ));
        assert!(broker.is_empty());
    }

    #[test]
    fn opaque_frame_reaches_backend_byte_for_byte() {
        let mut broker = RelayBroker::new(SpyBackend::default());
        broker
            .open_session(session_id(1), relay_spec(1))
            .expect("open");
        let frame = OpaqueRelayFrame::new(vec![0x10, 0x22, 0x7f, 0x00, 0xff]).expect("frame");
        broker.transmit(session_id(1), &frame).expect("transmit");
        assert_eq!(broker.backend.last_frame, frame.as_bytes());
        assert_eq!(broker.backend.transmit_calls, 1);
    }

    #[test]
    fn transmit_failure_retains_failed_record() {
        let mut broker = RelayBroker::new(SpyBackend {
            failure: FailureMode::Transmit,
            ..SpyBackend::default()
        });
        broker
            .open_session(session_id(1), relay_spec(1))
            .expect("open");
        let frame = OpaqueRelayFrame::new(vec![1]).expect("frame");
        assert_eq!(
            broker.transmit(session_id(1), &frame),
            Err(RelayError::Backend)
        );
        assert_eq!(
            broker.session(session_id(1)).expect("retained").state(),
            RelayState::Failed
        );
        assert_eq!(
            broker.transmit(session_id(1), &frame),
            Err(RelayError::InvalidState)
        );
    }

    #[test]
    fn successful_close_returns_closed_and_removes_record() {
        let mut broker = RelayBroker::new(SpyBackend::default());
        broker
            .open_session(session_id(1), relay_spec(1))
            .expect("open");
        let closed = broker.close_session(session_id(1)).expect("close");
        assert_eq!(closed.state(), RelayState::Closed);
        assert!(broker.session(session_id(1)).is_none());
        assert_eq!(broker.backend.close_calls, 1);
    }

    #[test]
    fn close_failure_retains_failed_record() {
        let mut broker = RelayBroker::new(SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        });
        broker
            .open_session(session_id(1), relay_spec(1))
            .expect("open");
        assert_eq!(
            broker.close_session(session_id(1)),
            Err(RelayError::Backend)
        );
        assert_eq!(
            broker.session(session_id(1)).expect("retained").state(),
            RelayState::Failed
        );
    }
}
