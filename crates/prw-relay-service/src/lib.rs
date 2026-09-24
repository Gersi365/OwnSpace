//! Disposable, in-memory PRW relay protocol/service reference implementation.
//!
//! This crate validates Phase 142 routing/provider semantics without owning sockets, DNS,
//! an async runtime, process execution, tunnels, firewall state, routes or production secrets.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fmt,
    rc::Rc,
};

use prw_relay::{
    MAX_RELAY_FRAME_BYTES, OpaqueRelayFrame, RelayBackend, RelayError, RelayRouteToken,
    RelaySessionSpec,
};

const RELAY_MAGIC: [u8; 4] = *b"PRWR";
const RELAY_PROTOCOL_MAJOR: u16 = 1;
const RELAY_PROTOCOL_MINOR: u16 = 0;
const RELAY_KIND_DATA: u16 = 1;
const RELAY_FLAGS_NONE: u16 = 0;
/// Exact fixed header length for the Phase 142 reference relay envelope.
pub const RELAY_HEADER_BYTES: usize = 48;
/// Maximum active route records in one disposable service.
pub const MAX_DISPOSABLE_RELAY_ROUTES: usize = 32;
/// Maximum queued frames for one participant.
pub const MAX_QUEUED_RELAY_FRAMES: usize = 64;
/// Maximum queued opaque payload bytes for one participant.
pub const MAX_QUEUED_RELAY_BYTES: usize = 1024 * 1024;

/// Provider-local participant handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayProviderHandle(u64);

impl RelayProviderHandle {
    /// Returns the non-zero provider-local identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One validated Phase 142 relay-routing packet.
#[derive(PartialEq, Eq)]
pub struct RelayRoutingPacket {
    route_token: RelayRouteToken,
    payload: OpaqueRelayFrame,
}

impl RelayRoutingPacket {
    /// Builds a routing packet around one already-bounded opaque frame.
    #[must_use]
    pub const fn new(route_token: RelayRouteToken, payload: OpaqueRelayFrame) -> Self {
        Self {
            route_token,
            payload,
        }
    }

    /// Returns the opaque route token without exposing it through Debug output.
    #[must_use]
    pub const fn route_token(&self) -> RelayRouteToken {
        self.route_token
    }

    /// Returns the application-opaque payload.
    #[must_use]
    pub const fn payload(&self) -> &OpaqueRelayFrame {
        &self.payload
    }

    /// Encodes the fixed Phase 142 routing envelope.
    ///
    /// # Panics
    ///
    /// Panics only if the Phase 136 frame ceiling stops fitting in `u32`; the locked 65,536-byte bound fits.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = u32::try_from(self.payload.as_bytes().len())
            .expect("Phase 136 relay frame bound always fits u32");
        let mut encoded = Vec::with_capacity(RELAY_HEADER_BYTES + self.payload.as_bytes().len());
        encoded.extend_from_slice(&RELAY_MAGIC);
        encoded.extend_from_slice(&RELAY_PROTOCOL_MAJOR.to_be_bytes());
        encoded.extend_from_slice(&RELAY_PROTOCOL_MINOR.to_be_bytes());
        encoded.extend_from_slice(&RELAY_KIND_DATA.to_be_bytes());
        encoded.extend_from_slice(&RELAY_FLAGS_NONE.to_be_bytes());
        encoded.extend_from_slice(self.route_token.as_bytes());
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(self.payload.as_bytes());
        encoded
    }

    /// Decodes and validates one exact relay-routing envelope.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata, invalid route tokens, empty/oversized payloads, truncation and
    /// trailing bytes inconsistent with the declared payload length.
    pub fn decode(encoded: &[u8]) -> Result<Self, RelayServiceError> {
        if encoded.len() < RELAY_HEADER_BYTES {
            return Err(RelayServiceError::TruncatedPacket);
        }
        if encoded[..4] != RELAY_MAGIC {
            return Err(RelayServiceError::InvalidMagic);
        }
        let major = u16::from_be_bytes([encoded[4], encoded[5]]);
        let minor = u16::from_be_bytes([encoded[6], encoded[7]]);
        if major != RELAY_PROTOCOL_MAJOR || minor != RELAY_PROTOCOL_MINOR {
            return Err(RelayServiceError::UnsupportedVersion);
        }
        let kind = u16::from_be_bytes([encoded[8], encoded[9]]);
        if kind != RELAY_KIND_DATA {
            return Err(RelayServiceError::UnknownKind);
        }
        let flags = u16::from_be_bytes([encoded[10], encoded[11]]);
        if flags != RELAY_FLAGS_NONE {
            return Err(RelayServiceError::UnsupportedFlags);
        }
        let mut token_bytes = [0u8; 32];
        token_bytes.copy_from_slice(&encoded[12..44]);
        let route_token =
            RelayRouteToken::new(token_bytes).map_err(|_| RelayServiceError::InvalidRouteToken)?;
        let declared = u32::from_be_bytes([encoded[44], encoded[45], encoded[46], encoded[47]]);
        let declared = usize::try_from(declared).map_err(|_| RelayServiceError::InvalidLength)?;
        if declared == 0 {
            return Err(RelayServiceError::EmptyPayload);
        }
        if declared > MAX_RELAY_FRAME_BYTES {
            return Err(RelayServiceError::PayloadTooLarge);
        }
        let expected = RELAY_HEADER_BYTES
            .checked_add(declared)
            .ok_or(RelayServiceError::InvalidLength)?;
        if encoded.len() < expected {
            return Err(RelayServiceError::TruncatedPacket);
        }
        if encoded.len() != expected {
            return Err(RelayServiceError::TrailingBytes);
        }
        let payload = OpaqueRelayFrame::new(encoded[RELAY_HEADER_BYTES..].to_vec())
            .map_err(|_| RelayServiceError::InvalidLength)?;
        Ok(Self {
            route_token,
            payload,
        })
    }
}

impl fmt::Debug for RelayRoutingPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayRoutingPacket")
            .field("route_token", &"<redacted>")
            .field("payload_len", &self.payload.as_bytes().len())
            .finish()
    }
}

struct Participant {
    handle: RelayProviderHandle,
    peer_transport: [u8; 32],
    queued: VecDeque<OpaqueRelayFrame>,
    queued_bytes: usize,
}

struct RouteRecord {
    endpoint: prw_connectivity::ConnectivityEndpoint,
    participants: Vec<Participant>,
}

/// In-memory disposable relay service used to prove Phase 142 provider semantics.
pub struct DisposableRelayService {
    routes: HashMap<RelayRouteToken, RouteRecord>,
    handle_routes: HashMap<RelayProviderHandle, RelayRouteToken>,
    next_handle: u64,
}

impl DisposableRelayService {
    /// Creates an empty disposable relay service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            handle_routes: HashMap::new(),
            next_handle: 1,
        }
    }

    /// Returns the active route count.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Returns the registered participant count.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.handle_routes.len()
    }

    fn register(
        &mut self,
        spec: &RelaySessionSpec,
    ) -> Result<RelayProviderHandle, RelayServiceError> {
        let token = spec.route_token();
        let endpoint = spec.endpoint();
        let transport = *spec.peer().transport_identity().as_bytes();
        let new_route = !self.routes.contains_key(&token);
        if new_route && self.routes.len() >= MAX_DISPOSABLE_RELAY_ROUTES {
            return Err(RelayServiceError::RouteCapacity);
        }
        if let Some(route) = self.routes.get(&token) {
            if route.endpoint != endpoint {
                return Err(RelayServiceError::RouteEndpointMismatch);
            }
            if route.participants.len() >= 2 {
                return Err(RelayServiceError::RouteFull);
            }
            if route
                .participants
                .iter()
                .any(|participant| participant.peer_transport == transport)
            {
                return Err(RelayServiceError::DuplicateParticipant);
            }
        }

        let handle = self.allocate_handle()?;
        let participant = Participant {
            handle,
            peer_transport: transport,
            queued: VecDeque::new(),
            queued_bytes: 0,
        };
        self.routes
            .entry(token)
            .or_insert_with(|| RouteRecord {
                endpoint,
                participants: Vec::new(),
            })
            .participants
            .push(participant);
        self.handle_routes.insert(handle, token);
        Ok(handle)
    }

    fn allocate_handle(&mut self) -> Result<RelayProviderHandle, RelayServiceError> {
        for _ in 0..=self.handle_routes.len() {
            let raw = self.next_handle;
            self.next_handle = self.next_handle.checked_add(1).unwrap_or(1);
            if raw != 0 {
                let handle = RelayProviderHandle(raw);
                if !self.handle_routes.contains_key(&handle) {
                    return Ok(handle);
                }
            }
        }
        Err(RelayServiceError::HandleExhausted)
    }

    fn forward(
        &mut self,
        sender: RelayProviderHandle,
        encoded: &[u8],
    ) -> Result<(), RelayServiceError> {
        let bound_token = *self
            .handle_routes
            .get(&sender)
            .ok_or(RelayServiceError::UnknownParticipant)?;
        let packet = RelayRoutingPacket::decode(encoded)?;
        if packet.route_token() != bound_token {
            return Err(RelayServiceError::RouteTokenMismatch);
        }
        let route = self
            .routes
            .get_mut(&bound_token)
            .ok_or(RelayServiceError::UnknownRoute)?;
        if route.participants.len() != 2 {
            return Err(RelayServiceError::RouteNotPaired);
        }
        let receiver = route
            .participants
            .iter_mut()
            .find(|participant| participant.handle != sender)
            .ok_or(RelayServiceError::RouteNotPaired)?;
        let payload_len = packet.payload().as_bytes().len();
        if receiver.queued.len() >= MAX_QUEUED_RELAY_FRAMES {
            return Err(RelayServiceError::QueueFrameCapacity);
        }
        let next_bytes = receiver
            .queued_bytes
            .checked_add(payload_len)
            .ok_or(RelayServiceError::QueueByteCapacity)?;
        if next_bytes > MAX_QUEUED_RELAY_BYTES {
            return Err(RelayServiceError::QueueByteCapacity);
        }
        receiver.queued.push_back(packet.payload);
        receiver.queued_bytes = next_bytes;
        Ok(())
    }

    fn poll_receive(
        &mut self,
        handle: RelayProviderHandle,
    ) -> Result<Option<OpaqueRelayFrame>, RelayServiceError> {
        let token = *self
            .handle_routes
            .get(&handle)
            .ok_or(RelayServiceError::UnknownParticipant)?;
        let route = self
            .routes
            .get_mut(&token)
            .ok_or(RelayServiceError::UnknownRoute)?;
        let participant = route
            .participants
            .iter_mut()
            .find(|participant| participant.handle == handle)
            .ok_or(RelayServiceError::UnknownParticipant)?;
        let frame = participant.queued.pop_front();
        if let Some(frame) = frame.as_ref() {
            participant.queued_bytes = participant
                .queued_bytes
                .checked_sub(frame.as_bytes().len())
                .ok_or(RelayServiceError::QueueAccounting)?;
        }
        Ok(frame)
    }

    fn unregister(&mut self, handle: RelayProviderHandle) -> Result<(), RelayServiceError> {
        let token = self
            .handle_routes
            .remove(&handle)
            .ok_or(RelayServiceError::UnknownParticipant)?;
        let remove_route = {
            let route = self
                .routes
                .get_mut(&token)
                .ok_or(RelayServiceError::UnknownRoute)?;
            let before = route.participants.len();
            route
                .participants
                .retain(|participant| participant.handle != handle);
            if route.participants.len() == before {
                return Err(RelayServiceError::UnknownParticipant);
            }
            route.participants.is_empty()
        };
        if remove_route {
            self.routes.remove(&token);
        }
        Ok(())
    }
}

impl Default for DisposableRelayService {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared disposable service reference used by multiple provider instances in tests/integration.
#[derive(Clone)]
pub struct SharedDisposableRelayService(Rc<RefCell<DisposableRelayService>>);

impl SharedDisposableRelayService {
    /// Creates a new isolated service.
    #[must_use]
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(DisposableRelayService::new())))
    }

    /// Returns the current route count for validation/observability.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.0.borrow().route_count()
    }

    /// Returns the participant count for validation/observability.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.0.borrow().participant_count()
    }
}

impl Default for SharedDisposableRelayService {
    fn default() -> Self {
        Self::new()
    }
}

/// Disposable provider implementing the Phase 136 backend boundary.
pub struct DisposableRelayProvider {
    service: SharedDisposableRelayService,
}

impl DisposableRelayProvider {
    /// Creates a provider attached to one shared disposable service.
    #[must_use]
    pub const fn new(service: SharedDisposableRelayService) -> Self {
        Self { service }
    }

    /// Polls one exact opaque frame queued for the provider handle.
    ///
    /// # Errors
    ///
    /// Returns a stable provider error when the handle is unknown or queue accounting fails.
    pub fn poll_receive(
        &mut self,
        handle: RelayProviderHandle,
    ) -> Result<Option<OpaqueRelayFrame>, RelayServiceError> {
        self.service.0.borrow_mut().poll_receive(handle)
    }

    /// Encodes one already-bounded frame for the provider routing protocol.
    #[must_use]
    pub fn encode_frame(spec: &RelaySessionSpec, frame: OpaqueRelayFrame) -> Vec<u8> {
        RelayRoutingPacket::new(spec.route_token(), frame).encode()
    }
}

impl RelayBackend for DisposableRelayProvider {
    type Handle = RelayProviderHandle;

    fn open(&mut self, spec: &RelaySessionSpec) -> Result<Self::Handle, RelayError> {
        self.service
            .0
            .borrow_mut()
            .register(spec)
            .map_err(|_| RelayError::Backend)
    }

    fn transmit(
        &mut self,
        handle: &mut Self::Handle,
        frame: &OpaqueRelayFrame,
    ) -> Result<(), RelayError> {
        let token = *self
            .service
            .0
            .borrow()
            .handle_routes
            .get(handle)
            .ok_or(RelayError::Backend)?;
        let encoded = RelayRoutingPacket::new(
            token,
            OpaqueRelayFrame::new(frame.as_bytes().to_vec()).map_err(|_| RelayError::Backend)?,
        )
        .encode();
        self.service
            .0
            .borrow_mut()
            .forward(*handle, &encoded)
            .map_err(|_| RelayError::Backend)
    }

    fn close(&mut self, handle: &mut Self::Handle) -> Result<(), RelayError> {
        self.service
            .0
            .borrow_mut()
            .unregister(*handle)
            .map_err(|_| RelayError::Backend)
    }
}

/// Stable disposable relay-service failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayServiceError {
    /// Packet was shorter than its fixed header or declared payload.
    TruncatedPacket,
    /// Routing magic was not `PRWR`.
    InvalidMagic,
    /// Routing protocol version is unsupported.
    UnsupportedVersion,
    /// Message kind is unknown.
    UnknownKind,
    /// Non-zero flags are unsupported.
    UnsupportedFlags,
    /// Route token was invalid.
    InvalidRouteToken,
    /// Declared or computed packet length was invalid.
    InvalidLength,
    /// Routing payload was empty.
    EmptyPayload,
    /// Routing payload exceeded the Phase 136 frame bound.
    PayloadTooLarge,
    /// Encoded packet contained trailing bytes beyond the declared payload.
    TrailingBytes,
    /// Service route capacity was reached.
    RouteCapacity,
    /// Existing route is bound to a different explicit relay endpoint.
    RouteEndpointMismatch,
    /// Route already has two participants.
    RouteFull,
    /// The same remote transport identity was registered twice on one route.
    DuplicateParticipant,
    /// Provider-local handle space could not allocate a unique non-zero identifier.
    HandleExhausted,
    /// Provider handle is unknown.
    UnknownParticipant,
    /// Route record is missing.
    UnknownRoute,
    /// Packet route token did not match the sender's bound route.
    RouteTokenMismatch,
    /// Route does not yet have exactly two participants.
    RouteNotPaired,
    /// Receiver frame queue capacity was reached.
    QueueFrameCapacity,
    /// Receiver byte queue capacity was reached.
    QueueByteCapacity,
    /// Internal queue byte accounting would underflow.
    QueueAccounting,
}

impl fmt::Display for RelayServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TruncatedPacket => "relay routing packet is truncated",
            Self::InvalidMagic => "relay routing magic is invalid",
            Self::UnsupportedVersion => "relay routing version is unsupported",
            Self::UnknownKind => "relay routing message kind is unknown",
            Self::UnsupportedFlags => "relay routing flags are unsupported",
            Self::InvalidRouteToken => "relay routing token is invalid",
            Self::InvalidLength => "relay routing payload length is invalid",
            Self::EmptyPayload => "relay routing payload must not be empty",
            Self::PayloadTooLarge => "relay routing payload exceeds bound",
            Self::TrailingBytes => "relay routing packet contains trailing bytes",
            Self::RouteCapacity => "disposable relay route capacity reached",
            Self::RouteEndpointMismatch => "relay route endpoint does not match",
            Self::RouteFull => "relay route already has two participants",
            Self::DuplicateParticipant => "relay route participant is duplicated",
            Self::HandleExhausted => "relay provider handle space exhausted",
            Self::UnknownParticipant => "relay provider participant is unknown",
            Self::UnknownRoute => "relay route is unknown",
            Self::RouteTokenMismatch => "relay packet token does not match sender route",
            Self::RouteNotPaired => "relay route is not paired",
            Self::QueueFrameCapacity => "relay receiver frame queue is full",
            Self::QueueByteCapacity => "relay receiver byte queue is full",
            Self::QueueAccounting => "relay queue accounting is inconsistent",
        })
    }
}

impl std::error::Error for RelayServiceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use prw_connectivity::{
        CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
        SelectedConnectivityPath, TransportIdentity,
    };
    use prw_core::DeviceId;
    use prw_relay::{RelayPeerIdentity, RelaySessionSpec};
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(port: u16) -> ConnectivityEndpoint {
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("endpoint")
    }

    fn token(value: u8) -> RelayRouteToken {
        RelayRouteToken::new([value; 32]).expect("token")
    }

    fn spec(
        peer_name: &str,
        transport_byte: u8,
        route_token: RelayRouteToken,
        relay_port: u16,
        candidate_id: u64,
    ) -> RelaySessionSpec {
        let peer = RelayPeerIdentity::new(
            DeviceId::new(peer_name).expect("device"),
            TransportIdentity::new([transport_byte; 32]).expect("transport"),
        );
        let selected = SelectedConnectivityPath::Candidate(ConnectivityCandidate::new(
            CandidateId::new(candidate_id).expect("candidate"),
            ConnectivityPathKind::Relay,
            endpoint(relay_port),
        ));
        RelaySessionSpec::from_selected_path(peer, route_token, selected).expect("relay spec")
    }

    #[test]
    fn routing_envelope_has_exact_layout_and_round_trip() {
        let payload = OpaqueRelayFrame::new(vec![0x10, 0x20, 0x30]).expect("frame");
        let packet = RelayRoutingPacket::new(token(7), payload);
        let encoded = packet.encode();
        assert_eq!(encoded.len(), RELAY_HEADER_BYTES + 3);
        assert_eq!(&encoded[..4], b"PRWR");
        assert_eq!(&encoded[4..6], &1u16.to_be_bytes());
        assert_eq!(&encoded[6..8], &0u16.to_be_bytes());
        assert_eq!(&encoded[8..10], &1u16.to_be_bytes());
        assert_eq!(&encoded[10..12], &0u16.to_be_bytes());
        assert_eq!(&encoded[12..44], &[7; 32]);
        assert_eq!(&encoded[44..48], &3u32.to_be_bytes());
        assert_eq!(&encoded[48..], &[0x10, 0x20, 0x30]);
        let decoded = RelayRoutingPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded.route_token(), token(7));
        assert_eq!(decoded.payload().as_bytes(), &[0x10, 0x20, 0x30]);
    }

    #[test]
    fn routing_envelope_rejects_malformed_metadata_and_lengths() {
        let packet =
            RelayRoutingPacket::new(token(9), OpaqueRelayFrame::new(vec![1, 2]).expect("frame"));
        let valid = packet.encode();
        for (index, expected) in [
            (0usize, RelayServiceError::InvalidMagic),
            (5, RelayServiceError::UnsupportedVersion),
            (9, RelayServiceError::UnknownKind),
            (11, RelayServiceError::UnsupportedFlags),
        ] {
            let mut invalid = valid.clone();
            invalid[index] ^= 0x01;
            assert_eq!(RelayRoutingPacket::decode(&invalid), Err(expected));
        }
        let mut zero_token = valid.clone();
        zero_token[12..44].fill(0);
        assert_eq!(
            RelayRoutingPacket::decode(&zero_token),
            Err(RelayServiceError::InvalidRouteToken)
        );
        assert_eq!(
            RelayRoutingPacket::decode(&valid[..47]),
            Err(RelayServiceError::TruncatedPacket)
        );
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            RelayRoutingPacket::decode(&trailing),
            Err(RelayServiceError::TrailingBytes)
        );
        let mut empty = valid.clone();
        empty[44..48].copy_from_slice(&0u32.to_be_bytes());
        empty.truncate(RELAY_HEADER_BYTES);
        assert_eq!(
            RelayRoutingPacket::decode(&empty),
            Err(RelayServiceError::EmptyPayload)
        );
        let mut oversized = valid;
        let too_large = u32::try_from(MAX_RELAY_FRAME_BYTES + 1).expect("bound fits u32");
        oversized[44..48].copy_from_slice(&too_large.to_be_bytes());
        assert_eq!(
            RelayRoutingPacket::decode(&oversized),
            Err(RelayServiceError::PayloadTooLarge)
        );
    }

    #[test]
    fn two_providers_transfer_opaque_bytes_bidirectionally() {
        let service = SharedDisposableRelayService::new();
        let mut a = DisposableRelayProvider::new(service.clone());
        let mut b = DisposableRelayProvider::new(service.clone());
        let route = token(3);
        let a_spec = spec("device-b", 2, route, 5000, 1);
        let b_spec = spec("device-a", 1, route, 5000, 2);
        let mut a_handle = a.open(&a_spec).expect("open a");
        let mut b_handle = b.open(&b_spec).expect("open b");
        assert_eq!(service.route_count(), 1);
        assert_eq!(service.participant_count(), 2);

        let first = OpaqueRelayFrame::new(vec![0x00, 0xff, 0x41, 0x10]).expect("first");
        a.transmit(&mut a_handle, &first).expect("a transmit");
        let received = b.poll_receive(b_handle).expect("b poll").expect("b frame");
        assert_eq!(received.as_bytes(), first.as_bytes());

        let second = OpaqueRelayFrame::new(vec![7, 8, 9]).expect("second");
        b.transmit(&mut b_handle, &second).expect("b transmit");
        let received = a.poll_receive(a_handle).expect("a poll").expect("a frame");
        assert_eq!(received.as_bytes(), second.as_bytes());

        a.close(&mut a_handle).expect("close a");
        b.close(&mut b_handle).expect("close b");
        assert_eq!(service.route_count(), 0);
        assert_eq!(service.participant_count(), 0);
    }

    #[test]
    fn route_token_mismatch_and_unpaired_forwarding_fail_closed() {
        let service = SharedDisposableRelayService::new();
        let mut provider = DisposableRelayProvider::new(service.clone());
        let route = token(4);
        let spec = spec("device-b", 2, route, 5001, 1);
        let handle = provider.open(&spec).expect("open");
        let packet =
            RelayRoutingPacket::new(token(5), OpaqueRelayFrame::new(vec![1]).expect("frame"))
                .encode();
        assert_eq!(
            service.0.borrow_mut().forward(handle, &packet),
            Err(RelayServiceError::RouteTokenMismatch)
        );
        let correct =
            RelayRoutingPacket::new(route, OpaqueRelayFrame::new(vec![1]).expect("frame")).encode();
        assert_eq!(
            service.0.borrow_mut().forward(handle, &correct),
            Err(RelayServiceError::RouteNotPaired)
        );
    }

    #[test]
    fn third_participant_and_unrelated_routes_are_isolated() {
        let service = SharedDisposableRelayService::new();
        let route = token(6);
        let mut a = DisposableRelayProvider::new(service.clone());
        let mut b = DisposableRelayProvider::new(service.clone());
        let mut c = DisposableRelayProvider::new(service.clone());
        let mut d = DisposableRelayProvider::new(service);
        let a_spec = spec("device-b", 2, route, 5100, 1);
        let b_spec = spec("device-a", 1, route, 5100, 2);
        let c_spec = spec("device-c", 3, route, 5100, 3);
        let mut a_handle = a.open(&a_spec).expect("a");
        let b_handle = b.open(&b_spec).expect("b");
        assert_eq!(c.open(&c_spec), Err(RelayError::Backend));

        let other = token(8);
        let d_spec = spec("device-e", 5, other, 5200, 4);
        let d_handle = d.open(&d_spec).expect("d");
        let frame = OpaqueRelayFrame::new(vec![0xaa]).expect("frame");
        a.transmit(&mut a_handle, &frame).expect("transmit");
        assert_eq!(
            b.poll_receive(b_handle)
                .expect("b poll")
                .expect("b frame")
                .as_bytes(),
            &[0xaa]
        );
        assert!(d.poll_receive(d_handle).expect("d poll").is_none());
    }

    #[test]
    fn queue_limits_fail_without_dropping_earlier_frames() {
        let service = SharedDisposableRelayService::new();
        let route = token(10);
        let mut a = DisposableRelayProvider::new(service.clone());
        let mut b = DisposableRelayProvider::new(service);
        let a_spec = spec("device-b", 2, route, 5300, 1);
        let b_spec = spec("device-a", 1, route, 5300, 2);
        let mut a_handle = a.open(&a_spec).expect("a");
        let b_handle = b.open(&b_spec).expect("b");
        for value in 0..MAX_QUEUED_RELAY_FRAMES {
            let byte = u8::try_from(value).expect("queue bound fits u8");
            let frame = OpaqueRelayFrame::new(vec![byte]).expect("frame");
            a.transmit(&mut a_handle, &frame).expect("within capacity");
        }
        let overflow = OpaqueRelayFrame::new(vec![0xff]).expect("overflow frame");
        assert_eq!(
            a.transmit(&mut a_handle, &overflow),
            Err(RelayError::Backend)
        );
        for value in 0..MAX_QUEUED_RELAY_FRAMES {
            let byte = u8::try_from(value).expect("queue bound fits u8");
            let received = b
                .poll_receive(b_handle)
                .expect("poll")
                .expect("queued frame");
            assert_eq!(received.as_bytes(), &[byte]);
        }
    }

    #[test]
    fn debug_output_redacts_token_and_payload() {
        let payload = OpaqueRelayFrame::new(vec![0xde, 0xad, 0xbe, 0xef]).expect("payload");
        let packet = RelayRoutingPacket::new(token(0xab), payload);
        let rendered = format!("{packet:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("payload_len"));
        assert!(!rendered.contains("171"));
        assert!(!rendered.contains("222"));
    }
}
