//! Sans-I/O native UDP traversal foundation for Ownspace.
//!
//! This crate owns only bounded protocol/state-machine logic. It deliberately owns no socket,
//! async runtime, DNS resolver, STUN/TURN client, relay, TUN/TAP, route, firewall, router,
//! process, shell or production-listener capability.

use std::{
    fmt,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityPlan, ReachabilityObservation,
};

/// Exact byte length of one `PRW_PROBE` v1 packet.
pub const PROBE_PACKET_LEN: usize = 40;
/// Routing-tag byte length.
pub const ROUTING_TAG_LEN: usize = 16;
/// Probe-nonce byte length.
pub const PROBE_NONCE_LEN: usize = 16;
/// Previous receive-side tag overlap after committed rotation.
pub const ROUTING_TAG_OVERLAP_MILLIS: u64 = 60 * 60 * 1_000;
/// Maximum active outbound probe nonces retained for one peer.
pub const MAX_OUTSTANDING_PROBES_PER_PEER: usize = 64;
/// Maximum lifetime of one outstanding probe nonce.
pub const PROBE_NONCE_TTL_MILLIS: u64 = 60 * 1_000;
/// Initial bounded probe-attempt offsets.
pub const PROBE_SCHEDULE_MILLIS: [u64; 3] = [0, 250, 750];
/// Maximum durable endpoint candidates retained for one paired peer.
pub const MAX_RETAINED_ENDPOINTS_PER_PEER: usize = 4;
/// Endpoint remains fresh through this authenticated-success age.
pub const ENDPOINT_FRESH_MILLIS: u64 = 24 * 60 * 60 * 1_000;
/// Endpoint becomes old only after this authenticated-success age.
pub const ENDPOINT_OLD_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;
/// Default authenticated active-path idle threshold.
pub const ACTIVE_PATH_IDLE_THRESHOLD_MILLIS: u64 = 25_000;
/// Android reconnect schedule: immediate, 1s, 2s, 5s, 10s, 30s, 60s steady-state.
pub const ANDROID_RECONNECT_DELAYS_MILLIS: [u64; 7] =
    [0, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000];

const PROBE_MAGIC: [u8; 4] = *b"PRWP";
const PROBE_VERSION: u8 = 1;

/// Opaque directional per-peer routing tag.
///
/// Randomness is supplied by the caller/platform boundary. The Sans-I/O core does not own a
/// random-number generator or long-lived secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingTag([u8; ROUTING_TAG_LEN]);

impl RoutingTag {
    /// Wraps exactly 16 caller-provided bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ROUTING_TAG_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact routing-tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ROUTING_TAG_LEN] {
        &self.0
    }
}

/// Fresh per-probe nonce supplied by the caller/platform random source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeNonce([u8; PROBE_NONCE_LEN]);

impl ProbeNonce {
    /// Wraps exactly 16 caller-provided bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROBE_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROBE_NONCE_LEN] {
        &self.0
    }
}

/// `PRW_PROBE` v1 message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeMessageKind {
    /// Outbound NAT-punching probe.
    Probe = 1,
    /// Equal-size acknowledgement echoing the probe nonce.
    Ack = 2,
}

impl TryFrom<u8> for ProbeMessageKind {
    type Error = TraversalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Probe),
            2 => Ok(Self::Ack),
            _ => Err(TraversalError::UnsupportedProbeType),
        }
    }
}

/// Parsed `PRW_PROBE` v1 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePacket {
    kind: ProbeMessageKind,
    destination_tag: RoutingTag,
    nonce: ProbeNonce,
}

impl ProbePacket {
    /// Creates a probe packet.
    #[must_use]
    pub const fn probe(destination_tag: RoutingTag, nonce: ProbeNonce) -> Self {
        Self {
            kind: ProbeMessageKind::Probe,
            destination_tag,
            nonce,
        }
    }

    /// Creates an acknowledgement packet.
    #[must_use]
    pub const fn ack(destination_tag: RoutingTag, nonce: ProbeNonce) -> Self {
        Self {
            kind: ProbeMessageKind::Ack,
            destination_tag,
            nonce,
        }
    }

    /// Returns the packet kind.
    #[must_use]
    pub const fn kind(self) -> ProbeMessageKind {
        self.kind
    }

    /// Returns the destination receive-side routing tag.
    #[must_use]
    pub const fn destination_tag(self) -> RoutingTag {
        self.destination_tag
    }

    /// Returns the probe nonce.
    #[must_use]
    pub const fn nonce(self) -> ProbeNonce {
        self.nonce
    }

    /// Encodes the exact fixed-size v1 wire packet.
    #[must_use]
    pub fn encode(self) -> [u8; PROBE_PACKET_LEN] {
        let mut output = [0_u8; PROBE_PACKET_LEN];
        output[0..4].copy_from_slice(&PROBE_MAGIC);
        output[4] = PROBE_VERSION;
        output[5] = self.kind as u8;
        output[6..8].copy_from_slice(&0_u16.to_be_bytes());
        output[8..24].copy_from_slice(self.destination_tag.as_bytes());
        output[24..40].copy_from_slice(self.nonce.as_bytes());
        output
    }

    /// Decodes and validates one exact v1 packet.
    ///
    /// # Errors
    ///
    /// Fails closed on a wrong size, magic, version, message type or non-zero v1 flags.
    pub fn decode(input: &[u8]) -> Result<Self, TraversalError> {
        if input.len() != PROBE_PACKET_LEN {
            return Err(TraversalError::InvalidPacketLength);
        }
        if input[0..4] != PROBE_MAGIC {
            return Err(TraversalError::InvalidPacketMagic);
        }
        if input[4] != PROBE_VERSION {
            return Err(TraversalError::UnsupportedProbeVersion);
        }
        let kind = ProbeMessageKind::try_from(input[5])?;
        if u16::from_be_bytes([input[6], input[7]]) != 0 {
            return Err(TraversalError::UnsupportedProbeFlags);
        }

        let mut tag = [0_u8; ROUTING_TAG_LEN];
        tag.copy_from_slice(&input[8..24]);
        let mut nonce = [0_u8; PROBE_NONCE_LEN];
        nonce.copy_from_slice(&input[24..40]);

        Ok(Self {
            kind,
            destination_tag: RoutingTag::from_bytes(tag),
            nonce: ProbeNonce::from_bytes(nonce),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreviousRoutingTag {
    tag: RoutingTag,
    valid_until_millis: u64,
}

/// Receive-side routing-tag state with transactional one-tag rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveRoutingTags {
    current: Option<RoutingTag>,
    previous: Option<PreviousRoutingTag>,
    pending: Option<RoutingTag>,
}

impl ReceiveRoutingTags {
    /// Creates active receive-side routing state.
    #[must_use]
    pub const fn new(current: RoutingTag) -> Self {
        Self {
            current: Some(current),
            previous: None,
            pending: None,
        }
    }

    /// Returns the current committed tag, or None after revocation.
    #[must_use]
    pub const fn current(&self) -> Option<RoutingTag> {
        self.current
    }

    /// Returns a not-yet-committed replacement tag.
    #[must_use]
    pub const fn pending(&self) -> Option<RoutingTag> {
        self.pending
    }

    /// Starts a transactional rotation.
    ///
    /// # Errors
    ///
    /// Rejects rotation after revocation, a second simultaneous rotation, or a replacement that
    /// is already the committed current/previous tag.
    pub fn begin_rotation(&mut self, replacement: RoutingTag) -> Result<(), TraversalError> {
        let Some(current) = self.current else {
            return Err(TraversalError::RoutingTagRevoked);
        };
        if self.pending.is_some() {
            return Err(TraversalError::RoutingTagRotationInProgress);
        }
        if replacement == current
            || self
                .previous
                .is_some_and(|previous| previous.tag == replacement)
        {
            return Err(TraversalError::RoutingTagAlreadyKnown);
        }
        self.pending = Some(replacement);
        Ok(())
    }

    /// Commits the exact pending replacement after the peer acknowledged durable storage.
    ///
    /// # Errors
    ///
    /// Rejects a missing/mismatched pending replacement or revoked routing state.
    pub fn acknowledge_rotation(
        &mut self,
        replacement: RoutingTag,
        now_millis: u64,
    ) -> Result<(), TraversalError> {
        let Some(current) = self.current else {
            return Err(TraversalError::RoutingTagRevoked);
        };
        match self.pending {
            None => return Err(TraversalError::RoutingTagRotationMissing),
            Some(pending) if pending != replacement => {
                return Err(TraversalError::RoutingTagRotationMismatch);
            }
            Some(_) => {}
        }

        self.previous = Some(PreviousRoutingTag {
            tag: current,
            valid_until_millis: now_millis.saturating_add(ROUTING_TAG_OVERLAP_MILLIS),
        });
        self.current = Some(replacement);
        self.pending = None;
        Ok(())
    }

    /// Cancels an incomplete replacement while keeping the last committed tag.
    pub const fn cancel_rotation(&mut self) {
        self.pending = None;
    }

    /// Returns whether a tag is currently accepted, retiring an expired previous tag first.
    pub fn accepts(&mut self, tag: RoutingTag, now_millis: u64) -> bool {
        self.retire_expired_previous(now_millis);
        self.current == Some(tag) || self.previous.is_some_and(|previous| previous.tag == tag)
    }

    /// Revokes all current, previous and pending receive-side tags.
    pub const fn revoke(&mut self) {
        self.current = None;
        self.previous = None;
        self.pending = None;
    }

    fn retire_expired_previous(&mut self, now_millis: u64) {
        if self
            .previous
            .is_some_and(|previous| now_millis > previous.valid_until_millis)
        {
            self.previous = None;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutstandingProbe {
    nonce: ProbeNonce,
    candidate_id: CandidateId,
    expires_at_millis: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ProbeLedger {
    entries: Vec<OutstandingProbe>,
}

impl ProbeLedger {
    fn record(
        &mut self,
        nonce: ProbeNonce,
        candidate_id: CandidateId,
        now_millis: u64,
    ) -> Result<(), TraversalError> {
        self.prune(now_millis);
        if self.entries.iter().any(|entry| entry.nonce == nonce) {
            return Err(TraversalError::DuplicateOutstandingNonce);
        }
        if self.entries.len() >= MAX_OUTSTANDING_PROBES_PER_PEER {
            return Err(TraversalError::OutstandingProbeCapacity);
        }
        self.entries.push(OutstandingProbe {
            nonce,
            candidate_id,
            expires_at_millis: now_millis.saturating_add(PROBE_NONCE_TTL_MILLIS),
        });
        Ok(())
    }

    fn consume_ack(
        &mut self,
        nonce: ProbeNonce,
        candidate_id: CandidateId,
        now_millis: u64,
    ) -> bool {
        self.prune(now_millis);
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.nonce == nonce && entry.candidate_id == candidate_id)
        else {
            return false;
        };
        self.entries.swap_remove(index);
        true
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    const fn len(&self) -> usize {
        self.entries.len()
    }

    fn prune(&mut self, now_millis: u64) {
        self.entries
            .retain(|entry| entry.expires_at_millis > now_millis);
    }
}

/// One outbound Sans-I/O traversal datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalDatagram {
    destination: SocketAddr,
    packet: ProbePacket,
}

impl TraversalDatagram {
    /// Returns the explicit destination supplied by the current peer candidate/source observation.
    #[must_use]
    pub const fn destination(self) -> SocketAddr {
        self.destination
    }

    /// Returns the typed probe packet.
    #[must_use]
    pub const fn packet(self) -> ProbePacket {
        self.packet
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeAttempt {
    candidate: ConnectivityCandidate,
    started_at_millis: u64,
    next_probe_index: usize,
}

impl ProbeAttempt {
    const fn new(candidate: ConnectivityCandidate, started_at_millis: u64) -> Self {
        Self {
            candidate,
            started_at_millis,
            next_probe_index: 0,
        }
    }

    fn next_due_millis(self) -> Option<u64> {
        PROBE_SCHEDULE_MILLIS
            .get(self.next_probe_index)
            .map(|offset| self.started_at_millis.saturating_add(*offset))
    }

    const fn candidate(self) -> ConnectivityCandidate {
        self.candidate
    }

    const fn is_exhausted(self) -> bool {
        self.next_probe_index >= PROBE_SCHEDULE_MILLIS.len()
    }

    fn emit_due(
        &mut self,
        now_millis: u64,
        nonce: ProbeNonce,
        destination_tag: RoutingTag,
        ledger: &mut ProbeLedger,
    ) -> Result<Option<TraversalDatagram>, TraversalError> {
        let Some(due) = self.next_due_millis() else {
            return Ok(None);
        };
        if now_millis < due {
            return Ok(None);
        }

        ledger.record(nonce, self.candidate.id(), now_millis)?;
        self.next_probe_index += 1;
        Ok(Some(TraversalDatagram {
            destination: socket_addr(self.candidate),
            packet: ProbePacket::probe(destination_tag, nonce),
        }))
    }
}

/// Explicit native traversal state.
///
/// `PathValidated` is deliberately unreachable until transport authentication and PRW session
/// authorization have both succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalState {
    /// No prepared candidate.
    Idle,
    /// A direct candidate is prepared but probing has not started.
    CandidatesReady,
    /// Bounded native UDP probes are active.
    Probing,
    /// A nonce-correlated ACK proved only current packet reachability.
    ProbeResponsive,
    /// Caller has started QUIC establishment.
    QuicHandshake,
    /// QUIC/TLS/mTLS and expected current transport identity succeeded.
    TransportAuthenticated,
    /// PRW application/session authorization succeeded.
    SessionAuthenticated,
    /// The endpoint may now become authoritative reachable routing data.
    PathValidated,
    /// Authenticated application path is active.
    Active,
    /// No current usable candidate/path.
    Offline,
}

/// Result of consuming one inbound UDP datagram at the Sans-I/O boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundDisposition {
    /// Malformed, unknown, stale or context-mismatched input caused no response/promotion.
    Ignored,
    /// One valid inbound probe may receive exactly one equal-size ACK.
    Acknowledge {
        /// ACK datagram to send to the observed source endpoint.
        datagram: TraversalDatagram,
        /// Actual UDP source observed by the runtime adapter.
        observed_source: SocketAddr,
        /// Whether an independently active local attempt still has outbound probe budget.
        reverse_probe_eligible: bool,
    },
    /// A currently outstanding nonce was acknowledged for the active candidate.
    ProbeResponsive {
        /// Candidate whose attempt nonce was acknowledged.
        candidate: ConnectivityCandidate,
        /// Actual source endpoint of the ACK.
        observed_source: SocketAddr,
    },
}

/// Per-peer native traversal coordinator with no network I/O ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTraversal {
    receive_tags: ReceiveRoutingTags,
    peer_destination_tag: RoutingTag,
    prepared_candidate: Option<ConnectivityCandidate>,
    attempt: Option<ProbeAttempt>,
    outstanding: ProbeLedger,
    state: TraversalState,
}

impl PeerTraversal {
    /// Creates traversal state for one already-paired peer relationship.
    #[must_use]
    pub const fn new(local_receive_tag: RoutingTag, peer_destination_tag: RoutingTag) -> Self {
        Self {
            receive_tags: ReceiveRoutingTags::new(local_receive_tag),
            peer_destination_tag,
            prepared_candidate: None,
            attempt: None,
            outstanding: ProbeLedger {
                entries: Vec::new(),
            },
            state: TraversalState::Idle,
        }
    }

    /// Returns the current traversal state.
    #[must_use]
    pub const fn state(&self) -> TraversalState {
        self.state
    }

    /// Returns the number of currently outstanding bounded probe nonces.
    #[must_use]
    pub const fn outstanding_probe_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns the next locally scheduled probe time for the active attempt.
    #[must_use]
    pub fn next_probe_due_millis(&self) -> Option<u64> {
        self.attempt.and_then(ProbeAttempt::next_due_millis)
    }

    /// Returns whether the active attempt spent all three initial probe slots.
    #[must_use]
    pub fn probe_attempt_exhausted(&self) -> bool {
        self.attempt.is_some_and(ProbeAttempt::is_exhausted)
    }

    /// Updates the peer's committed receive-side tag learned through an authenticated channel.
    pub const fn set_peer_destination_tag(&mut self, tag: RoutingTag) {
        self.peer_destination_tag = tag;
    }

    /// Starts local receive-tag rotation.
    ///
    /// # Errors
    ///
    /// Propagates the bounded transactional routing-tag state errors.
    pub fn begin_receive_tag_rotation(
        &mut self,
        replacement: RoutingTag,
    ) -> Result<(), TraversalError> {
        self.receive_tags.begin_rotation(replacement)
    }

    /// Commits local receive-tag rotation after authenticated peer acknowledgement.
    ///
    /// # Errors
    ///
    /// Propagates missing/mismatched/revoked routing-tag state errors.
    pub fn acknowledge_receive_tag_rotation(
        &mut self,
        replacement: RoutingTag,
        now_millis: u64,
    ) -> Result<(), TraversalError> {
        self.receive_tags
            .acknowledge_rotation(replacement, now_millis)
    }

    /// Cancels an incomplete local receive-tag replacement.
    pub const fn cancel_receive_tag_rotation(&mut self) {
        self.receive_tags.cancel_rotation();
    }

    /// Revokes all receive-side routing tags for this peer.
    pub const fn revoke_receive_tags(&mut self) {
        self.receive_tags.revoke();
    }

    /// Prepares one direct candidate for a bounded probe attempt.
    ///
    /// # Errors
    ///
    /// Rejects relay candidates because the future native runtime is direct-only.
    pub fn prepare_candidate(
        &mut self,
        candidate: ConnectivityCandidate,
    ) -> Result<(), TraversalError> {
        if candidate.kind() == ConnectivityPathKind::Relay {
            return Err(TraversalError::RelayCandidateUnsupported);
        }
        self.prepared_candidate = Some(candidate);
        self.attempt = None;
        self.outstanding.clear();
        self.state = TraversalState::CandidatesReady;
        Ok(())
    }

    /// Starts probing the prepared candidate.
    ///
    /// # Errors
    ///
    /// Requires `CandidatesReady` state and a prepared candidate.
    pub fn start_probing(&mut self, now_millis: u64) -> Result<(), TraversalError> {
        if self.state != TraversalState::CandidatesReady {
            return Err(TraversalError::InvalidStateTransition);
        }
        let Some(candidate) = self.prepared_candidate else {
            return Err(TraversalError::InvalidStateTransition);
        };
        self.attempt = Some(ProbeAttempt::new(candidate, now_millis));
        self.outstanding.clear();
        self.state = TraversalState::Probing;
        Ok(())
    }

    /// Emits at most one currently due probe and records its nonce.
    ///
    /// # Errors
    ///
    /// Requires an active probing attempt and fails if nonce state exceeds its bound or a live
    /// nonce is duplicated.
    pub fn poll_probe(
        &mut self,
        now_millis: u64,
        nonce: ProbeNonce,
    ) -> Result<Option<TraversalDatagram>, TraversalError> {
        if self.state != TraversalState::Probing {
            return Err(TraversalError::InvalidStateTransition);
        }
        let Some(attempt) = self.attempt.as_mut() else {
            return Err(TraversalError::InvalidStateTransition);
        };
        attempt.emit_due(
            now_millis,
            nonce,
            self.peer_destination_tag,
            &mut self.outstanding,
        )
    }

    /// Consumes one UDP datagram supplied by the runtime adapter.
    ///
    /// Malformed packets and unknown routing tags are intentionally converted to Ignored so
    /// unauthenticated Internet input receives no detailed remote error behavior.
    pub fn handle_datagram(
        &mut self,
        input: &[u8],
        observed_source: SocketAddr,
        now_millis: u64,
    ) -> InboundDisposition {
        let Ok(packet) = ProbePacket::decode(input) else {
            return InboundDisposition::Ignored;
        };
        if !self
            .receive_tags
            .accepts(packet.destination_tag(), now_millis)
        {
            return InboundDisposition::Ignored;
        }

        match packet.kind() {
            ProbeMessageKind::Probe => {
                let reverse_probe_eligible = self.state == TraversalState::Probing
                    && self.attempt.is_some_and(|attempt| !attempt.is_exhausted());
                InboundDisposition::Acknowledge {
                    datagram: TraversalDatagram {
                        destination: observed_source,
                        packet: ProbePacket::ack(self.peer_destination_tag, packet.nonce()),
                    },
                    observed_source,
                    reverse_probe_eligible,
                }
            }
            ProbeMessageKind::Ack => self.handle_ack(packet, observed_source, now_millis),
        }
    }

    /// Moves from probe responsiveness to the QUIC handshake boundary.
    ///
    /// # Errors
    ///
    /// Requires `ProbeResponsive`.
    pub fn begin_quic_handshake(&mut self) -> Result<(), TraversalError> {
        self.transition(
            TraversalState::ProbeResponsive,
            TraversalState::QuicHandshake,
        )
    }

    /// Records successful QUIC/TLS/mTLS/current-transport-identity authentication.
    ///
    /// # Errors
    ///
    /// Requires `QuicHandshake`. This step does not yet produce `PathValidated`.
    pub fn confirm_transport_authenticated(&mut self) -> Result<(), TraversalError> {
        self.transition(
            TraversalState::QuicHandshake,
            TraversalState::TransportAuthenticated,
        )
    }

    /// Records successful PRW session/application authorization.
    ///
    /// # Errors
    ///
    /// Requires `TransportAuthenticated`. This step still does not update Phase 135.
    pub fn confirm_session_authenticated(&mut self) -> Result<(), TraversalError> {
        self.transition(
            TraversalState::TransportAuthenticated,
            TraversalState::SessionAuthenticated,
        )
    }

    /// Promotes the active candidate only after transport and session authentication succeeded.
    ///
    /// # Errors
    ///
    /// Requires `SessionAuthenticated` and an active candidate that still exists in the supplied
    /// Phase 135 plan.
    pub fn promote_path_validated(
        &mut self,
        plan: &mut PeerConnectivityPlan,
    ) -> Result<(), TraversalError> {
        if self.state != TraversalState::SessionAuthenticated {
            return Err(TraversalError::InvalidStateTransition);
        }
        let Some(attempt) = self.attempt else {
            return Err(TraversalError::InvalidStateTransition);
        };
        plan.set_observation(attempt.candidate().id(), ReachabilityObservation::Reachable)
            .map_err(TraversalError::Connectivity)?;
        self.state = TraversalState::PathValidated;
        Ok(())
    }

    /// Marks an already validated path active.
    ///
    /// # Errors
    ///
    /// Requires `PathValidated`.
    pub fn activate(&mut self) -> Result<(), TraversalError> {
        self.transition(TraversalState::PathValidated, TraversalState::Active)
    }

    /// Clears transient attempt/nonce state and reports no current path.
    pub fn mark_offline(&mut self) {
        self.prepared_candidate = None;
        self.attempt = None;
        self.outstanding.clear();
        self.state = TraversalState::Offline;
    }

    /// Clears transient network assumptions after a material local-network change.
    pub fn reset_for_network_change(&mut self) {
        self.prepared_candidate = None;
        self.attempt = None;
        self.outstanding.clear();
        self.state = TraversalState::Idle;
    }

    fn handle_ack(
        &mut self,
        packet: ProbePacket,
        observed_source: SocketAddr,
        now_millis: u64,
    ) -> InboundDisposition {
        if self.state != TraversalState::Probing {
            return InboundDisposition::Ignored;
        }
        let Some(attempt) = self.attempt else {
            return InboundDisposition::Ignored;
        };
        if !self
            .outstanding
            .consume_ack(packet.nonce(), attempt.candidate().id(), now_millis)
        {
            return InboundDisposition::Ignored;
        }

        self.state = TraversalState::ProbeResponsive;
        InboundDisposition::ProbeResponsive {
            candidate: attempt.candidate(),
            observed_source,
        }
    }

    fn transition(
        &mut self,
        expected: TraversalState,
        next: TraversalState,
    ) -> Result<(), TraversalError> {
        if self.state != expected {
            return Err(TraversalError::InvalidStateTransition);
        }
        self.state = next;
        Ok(())
    }
}

const fn socket_addr(candidate: ConnectivityCandidate) -> SocketAddr {
    let endpoint = candidate.endpoint();
    match endpoint.address() {
        std::net::IpAddr::V4(address) => {
            SocketAddr::V4(SocketAddrV4::new(address, endpoint.port()))
        }
        std::net::IpAddr::V6(address) => {
            SocketAddr::V6(SocketAddrV6::new(address, endpoint.port(), 0, 0))
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Endpoint-cache and reconnect policy
////////////////////////////////////////////////////////////////////////////////

/// Address family recorded explicitly with one retained endpoint candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointAddressFamily {
    /// IPv4 endpoint.
    Ipv4,
    /// IPv6 endpoint.
    Ipv6,
}

/// Product routing scope for one retained endpoint candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointScope {
    /// Candidate is expected on the peer's local LAN.
    Lan,
    /// Candidate is expected through direct Internet reachability.
    Public,
}

/// How PRW learned one retained endpoint candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointProvenance {
    /// Local LAN discovery produced the endpoint.
    LanDiscovery,
    /// UDP receive metadata exposed the remote source endpoint.
    DirectSocketObserved,
    /// An authenticated peer reported the endpoint as routing metadata.
    AuthenticatedPeerReported,
    /// The owner supplied the endpoint for cold recovery.
    ManualBootstrap,
}

/// Durable validation state for one retained endpoint candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointValidationState {
    /// Candidate is routing metadata but has not completed authenticated path validation.
    Reported,
    /// Candidate completed transport plus session authentication on this endpoint.
    PathValidated,
}

/// Freshness derived only from the age of the last authenticated successful use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointFreshness {
    /// Last authenticated success is at most 24 hours old.
    Fresh,
    /// Last authenticated success is older than 24 hours but not older than seven days.
    Stale,
    /// Last authenticated success is older than seven days.
    Old,
}

/// Privacy-preserving opaque peer network generation identifier.
///
/// Generation/randomness belongs to the platform boundary. This value contains no SSID, carrier,
/// location, ASN or other descriptive network metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkEpoch([u8; 16]);

impl NetworkEpoch {
    /// Wraps one caller-provided opaque network-generation value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Minimal retained routing metadata for one peer endpoint.
///
/// Time values are caller-supplied milliseconds for policy comparison only. This source-only
/// carrier does not define the final on-disk timestamp encoding or persistence format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerEndpointCandidate {
    endpoint: ConnectivityEndpoint,
    address_family: EndpointAddressFamily,
    scope: EndpointScope,
    provenance: EndpointProvenance,
    validation_state: EndpointValidationState,
    network_epoch: NetworkEpoch,
    first_seen_at_millis: u64,
    last_seen_at_millis: u64,
    last_success_at_millis: Option<u64>,
}

impl PeerEndpointCandidate {
    const fn reported(
        endpoint: ConnectivityEndpoint,
        scope: EndpointScope,
        provenance: EndpointProvenance,
        network_epoch: NetworkEpoch,
        now_millis: u64,
    ) -> Self {
        Self {
            endpoint,
            address_family: address_family(endpoint),
            scope,
            provenance,
            validation_state: EndpointValidationState::Reported,
            network_epoch,
            first_seen_at_millis: now_millis,
            last_seen_at_millis: now_millis,
            last_success_at_millis: None,
        }
    }

    /// Returns the explicit IP/UDP endpoint.
    #[must_use]
    pub const fn endpoint(self) -> ConnectivityEndpoint {
        self.endpoint
    }

    /// Returns the explicitly recorded address family.
    #[must_use]
    pub const fn address_family(self) -> EndpointAddressFamily {
        self.address_family
    }

    /// Returns LAN/public routing scope.
    #[must_use]
    pub const fn scope(self) -> EndpointScope {
        self.scope
    }

    /// Returns how the current routing observation was learned.
    #[must_use]
    pub const fn provenance(self) -> EndpointProvenance {
        self.provenance
    }

    /// Returns durable validation state.
    #[must_use]
    pub const fn validation_state(self) -> EndpointValidationState {
        self.validation_state
    }

    /// Returns the opaque peer network epoch.
    #[must_use]
    pub const fn network_epoch(self) -> NetworkEpoch {
        self.network_epoch
    }

    /// Returns first-observed policy timestamp.
    #[must_use]
    pub const fn first_seen_at_millis(self) -> u64 {
        self.first_seen_at_millis
    }

    /// Returns most-recently-observed policy timestamp.
    #[must_use]
    pub const fn last_seen_at_millis(self) -> u64 {
        self.last_seen_at_millis
    }

    /// Returns most recent authenticated successful-use timestamp, when any.
    #[must_use]
    pub const fn last_success_at_millis(self) -> Option<u64> {
        self.last_success_at_millis
    }

    /// Classifies freshness from authenticated success only.
    #[must_use]
    pub const fn freshness(self, now_millis: u64) -> Option<EndpointFreshness> {
        let Some(last_success) = self.last_success_at_millis else {
            return None;
        };
        let age = now_millis.saturating_sub(last_success);
        if age > ENDPOINT_OLD_MILLIS {
            Some(EndpointFreshness::Old)
        } else if age > ENDPOINT_FRESH_MILLIS {
            Some(EndpointFreshness::Stale)
        } else {
            Some(EndpointFreshness::Fresh)
        }
    }

    const fn record_seen(
        &mut self,
        scope: EndpointScope,
        provenance: EndpointProvenance,
        network_epoch: NetworkEpoch,
        now_millis: u64,
    ) {
        self.scope = scope;
        self.provenance = provenance;
        self.network_epoch = network_epoch;
        self.last_seen_at_millis = now_millis;
    }

    const fn record_authenticated_success(
        &mut self,
        scope: EndpointScope,
        provenance: EndpointProvenance,
        network_epoch: NetworkEpoch,
        now_millis: u64,
    ) {
        self.record_seen(scope, provenance, network_epoch, now_millis);
        self.validation_state = EndpointValidationState::PathValidated;
        self.last_success_at_millis = Some(now_millis);
    }

    const fn priority_recency(self) -> u64 {
        match self.last_success_at_millis {
            Some(value) => value,
            None => self.last_seen_at_millis,
        }
    }
}

/// Bounded per-peer endpoint cache.
///
/// Ordering is recomputed from product policy; address/age never becomes trust or authorization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EndpointCandidateCache {
    entries: Vec<PeerEndpointCandidate>,
}

impl EndpointCandidateCache {
    /// Creates an empty peer endpoint cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns retained candidate count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no endpoint hints are retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns retained entries in their current stored order.
    #[must_use]
    pub fn entries(&self) -> &[PeerEndpointCandidate] {
        &self.entries
    }

    /// Inserts or refreshes an unvalidated routing observation.
    ///
    /// An existing `PathValidated` candidate is never downgraded by a later reported observation.
    pub fn observe_reported(
        &mut self,
        endpoint: ConnectivityEndpoint,
        scope: EndpointScope,
        provenance: EndpointProvenance,
        network_epoch: NetworkEpoch,
        now_millis: u64,
    ) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.endpoint == endpoint)
        {
            existing.record_seen(scope, provenance, network_epoch, now_millis);
        } else {
            self.entries.push(PeerEndpointCandidate::reported(
                endpoint,
                scope,
                provenance,
                network_epoch,
                now_millis,
            ));
        }
        self.trim_to_policy(now_millis);
    }

    /// Records authenticated success and promotes/refreshes one endpoint to `PathValidated`.
    pub fn record_authenticated_success(
        &mut self,
        endpoint: ConnectivityEndpoint,
        scope: EndpointScope,
        provenance: EndpointProvenance,
        network_epoch: NetworkEpoch,
        now_millis: u64,
    ) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.endpoint == endpoint)
        {
            existing.record_authenticated_success(scope, provenance, network_epoch, now_millis);
        } else {
            let mut candidate = PeerEndpointCandidate::reported(
                endpoint,
                scope,
                provenance,
                network_epoch,
                now_millis,
            );
            candidate.record_authenticated_success(scope, provenance, network_epoch, now_millis);
            self.entries.push(candidate);
        }
        self.trim_to_policy(now_millis);
    }

    /// Returns a reconnect-ordered copy without granting reachability or authorization.
    #[must_use]
    pub fn ordered_candidates(&self, now_millis: u64) -> Vec<PeerEndpointCandidate> {
        let mut ordered = self.entries.clone();
        ordered.sort_by_key(|candidate| endpoint_priority_key(*candidate, now_millis));
        ordered
    }

    /// Removes all retained endpoint hints, as required by unpair/revoke.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn trim_to_policy(&mut self, now_millis: u64) {
        self.entries
            .sort_by_key(|candidate| endpoint_priority_key(*candidate, now_millis));
        self.entries.truncate(MAX_RETAINED_ENDPOINTS_PER_PEER);
    }
}

/// Pure Android reconnect-backoff state.
///
/// It owns no timer or wake-lock. A platform scheduler consumes the returned delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AndroidReconnectBackoff {
    failed_attempts: usize,
}

impl AndroidReconnectBackoff {
    /// Creates the initial immediate-attempt state.
    #[must_use]
    pub const fn new() -> Self {
        Self { failed_attempts: 0 }
    }

    /// Returns the delay before the next attempt.
    #[must_use]
    pub const fn next_delay_millis(self) -> u64 {
        let last_index = ANDROID_RECONNECT_DELAYS_MILLIS.len() - 1;
        let index = if self.failed_attempts > last_index {
            last_index
        } else {
            self.failed_attempts
        };
        ANDROID_RECONNECT_DELAYS_MILLIS[index]
    }

    /// Advances after one failed bounded connection attempt.
    pub const fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
    }

    /// Relevant network change resets to an immediate attempt.
    pub const fn reset_for_network_change(&mut self) {
        self.failed_attempts = 0;
    }

    /// Explicit user action requiring the peer resets to an immediate attempt.
    pub const fn reset_for_user_action(&mut self) {
        self.failed_attempts = 0;
    }

    /// Successful authenticated reconnect clears backoff state.
    pub const fn reset_after_success(&mut self) {
        self.failed_attempts = 0;
    }
}

/// Pure active-path idle tracker for the default 25-second authenticated keepalive policy.
///
/// The caller must use this only for an authenticated active path. The tracker owns no clock,
/// socket, task or timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivePathIdlePolicy {
    last_valid_traffic_millis: u64,
    last_keepalive_emitted_millis: u64,
}

impl ActivePathIdlePolicy {
    /// Starts an active-path idle window at the supplied caller time.
    #[must_use]
    pub const fn new(now_millis: u64) -> Self {
        Self {
            last_valid_traffic_millis: now_millis,
            last_keepalive_emitted_millis: now_millis,
        }
    }

    /// Records ordinary valid PRW traffic and suppresses unnecessary keepalive.
    pub const fn record_valid_traffic(&mut self, now_millis: u64) {
        self.last_valid_traffic_millis = now_millis;
    }

    /// Records one bounded authenticated keepalive emission.
    pub const fn record_keepalive_emitted(&mut self, now_millis: u64) {
        self.last_keepalive_emitted_millis = now_millis;
    }

    /// Returns whether the active authenticated path has been idle long enough for keepalive.
    #[must_use]
    pub const fn should_emit_keepalive(self, now_millis: u64) -> bool {
        let last_activity = if self.last_valid_traffic_millis > self.last_keepalive_emitted_millis {
            self.last_valid_traffic_millis
        } else {
            self.last_keepalive_emitted_millis
        };
        now_millis.saturating_sub(last_activity) >= ACTIVE_PATH_IDLE_THRESHOLD_MILLIS
    }
}

const fn address_family(endpoint: ConnectivityEndpoint) -> EndpointAddressFamily {
    match endpoint.address() {
        IpAddr::V4(_) => EndpointAddressFamily::Ipv4,
        IpAddr::V6(_) => EndpointAddressFamily::Ipv6,
    }
}

const fn endpoint_priority_key(
    candidate: PeerEndpointCandidate,
    now_millis: u64,
) -> (u8, u8, u8, u64) {
    let scope_rank = match candidate.scope {
        EndpointScope::Lan => 0,
        EndpointScope::Public => 1,
    };
    let validation_rank = match candidate.validation_state {
        EndpointValidationState::PathValidated => 0,
        EndpointValidationState::Reported => 1,
    };
    let freshness_rank = match candidate.freshness(now_millis) {
        Some(EndpointFreshness::Fresh) => 0,
        Some(EndpointFreshness::Stale) => 1,
        Some(EndpointFreshness::Old) => 2,
        None => 3,
    };
    let newest_first = u64::MAX.saturating_sub(candidate.priority_recency());
    (scope_rank, validation_rank, freshness_rank, newest_first)
}

/// Stable native traversal failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraversalError {
    /// Packet was not exactly 40 bytes.
    InvalidPacketLength,
    /// Packet magic was not PRWP.
    InvalidPacketMagic,
    /// Probe version was not v1.
    UnsupportedProbeVersion,
    /// Probe message type was not recognized.
    UnsupportedProbeType,
    /// v1 flags were non-zero.
    UnsupportedProbeFlags,
    /// A tag replacement is already pending.
    RoutingTagRotationInProgress,
    /// No pending tag exists to acknowledge.
    RoutingTagRotationMissing,
    /// Acknowledgement did not match the pending replacement.
    RoutingTagRotationMismatch,
    /// Proposed replacement duplicates a current/previous tag.
    RoutingTagAlreadyKnown,
    /// Receive-side tag state was revoked.
    RoutingTagRevoked,
    /// A live outstanding nonce was duplicated.
    DuplicateOutstandingNonce,
    /// Per-peer outstanding probe bound was reached.
    OutstandingProbeCapacity,
    /// Native traversal does not accept relay candidates.
    RelayCandidateUnsupported,
    /// State-machine operation was attempted from the wrong state.
    InvalidStateTransition,
    /// Existing Phase 135 candidate/observation boundary rejected the update.
    Connectivity(ConnectivityError),
}

impl fmt::Display for TraversalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacketLength => formatter.write_str("probe packet length is invalid"),
            Self::InvalidPacketMagic => formatter.write_str("probe packet magic is invalid"),
            Self::UnsupportedProbeVersion => {
                formatter.write_str("probe packet version is unsupported")
            }
            Self::UnsupportedProbeType => {
                formatter.write_str("probe packet message type is unsupported")
            }
            Self::UnsupportedProbeFlags => {
                formatter.write_str("probe packet flags are unsupported")
            }
            Self::RoutingTagRotationInProgress => {
                formatter.write_str("routing tag rotation is already in progress")
            }
            Self::RoutingTagRotationMissing => {
                formatter.write_str("routing tag rotation has no pending replacement")
            }
            Self::RoutingTagRotationMismatch => {
                formatter.write_str("routing tag acknowledgement does not match pending state")
            }
            Self::RoutingTagAlreadyKnown => {
                formatter.write_str("routing tag replacement is already known")
            }
            Self::RoutingTagRevoked => formatter.write_str("routing tag state is revoked"),
            Self::DuplicateOutstandingNonce => {
                formatter.write_str("probe nonce is already outstanding")
            }
            Self::OutstandingProbeCapacity => {
                formatter.write_str("outstanding probe nonce capacity exceeded")
            }
            Self::RelayCandidateUnsupported => {
                formatter.write_str("native traversal does not support relay candidates")
            }
            Self::InvalidStateTransition => {
                formatter.write_str("native traversal state transition is invalid")
            }
            Self::Connectivity(error) => write!(formatter, "connectivity update failed: {error}"),
        }
    }
}

impl std::error::Error for TraversalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use prw_connectivity::{
        ConnectivityEndpoint, PeerConnectivityIdentity, SelectedConnectivityPath, TransportIdentity,
    };
    use prw_core::DeviceId;

    fn tag(seed: u8) -> RoutingTag {
        RoutingTag::from_bytes([seed; ROUTING_TAG_LEN])
    }

    fn nonce(seed: u8) -> ProbeNonce {
        ProbeNonce::from_bytes([seed; PROBE_NONCE_LEN])
    }

    fn candidate(id: u64, port: u16) -> ConnectivityCandidate {
        ConnectivityCandidate::new(
            CandidateId::new(id).expect("non-zero candidate id"),
            ConnectivityPathKind::InternetDirect,
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .expect("valid test endpoint"),
        )
    }

    fn relay_candidate(id: u64, port: u16) -> ConnectivityCandidate {
        ConnectivityCandidate::new(
            CandidateId::new(id).expect("non-zero candidate id"),
            ConnectivityPathKind::Relay,
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                .expect("valid test endpoint"),
        )
    }

    fn plan(candidate: ConnectivityCandidate) -> PeerConnectivityPlan {
        let peer = PeerConnectivityIdentity::new(
            DeviceId::new("native-peer").expect("device id"),
            TransportIdentity::new([7; 32]).expect("transport identity"),
        );
        PeerConnectivityPlan::new(peer, vec![candidate]).expect("peer plan")
    }

    #[test]
    fn probe_v1_has_exact_wire_vector_and_round_trips() {
        let packet = ProbePacket::probe(tag(0x11), nonce(0x22));
        let encoded = packet.encode();

        assert_eq!(encoded.len(), PROBE_PACKET_LEN);
        assert_eq!(&encoded[0..4], b"PRWP");
        assert_eq!(encoded[4], 1);
        assert_eq!(encoded[5], 1);
        assert_eq!(&encoded[6..8], &[0, 0]);
        assert_eq!(&encoded[8..24], &[0x11; 16]);
        assert_eq!(&encoded[24..40], &[0x22; 16]);
        assert_eq!(ProbePacket::decode(&encoded), Ok(packet));

        let ack = ProbePacket::ack(tag(0x33), nonce(0x44));
        assert_eq!(ack.encode().len(), PROBE_PACKET_LEN);
        assert_eq!(ProbePacket::decode(&ack.encode()), Ok(ack));
    }

    #[test]
    fn malformed_probe_headers_fail_closed() {
        let packet = ProbePacket::probe(tag(1), nonce(2)).encode();

        assert_eq!(
            ProbePacket::decode(&packet[..39]),
            Err(TraversalError::InvalidPacketLength)
        );

        let mut wrong_magic = packet;
        wrong_magic[0] = b'X';
        assert_eq!(
            ProbePacket::decode(&wrong_magic),
            Err(TraversalError::InvalidPacketMagic)
        );

        let mut wrong_version = packet;
        wrong_version[4] = 2;
        assert_eq!(
            ProbePacket::decode(&wrong_version),
            Err(TraversalError::UnsupportedProbeVersion)
        );

        let mut wrong_type = packet;
        wrong_type[5] = 9;
        assert_eq!(
            ProbePacket::decode(&wrong_type),
            Err(TraversalError::UnsupportedProbeType)
        );

        let mut wrong_flags = packet;
        wrong_flags[7] = 1;
        assert_eq!(
            ProbePacket::decode(&wrong_flags),
            Err(TraversalError::UnsupportedProbeFlags)
        );
    }

    #[test]
    fn routing_tag_rotation_is_transactional_and_overlap_is_bounded() {
        let mut tags = ReceiveRoutingTags::new(tag(1));

        tags.begin_rotation(tag(2)).expect("begin rotation");
        assert_eq!(tags.current(), Some(tag(1)));
        assert_eq!(tags.pending(), Some(tag(2)));
        assert!(tags.accepts(tag(1), 10));
        assert!(!tags.accepts(tag(2), 10));

        assert_eq!(
            tags.acknowledge_rotation(tag(3), 10),
            Err(TraversalError::RoutingTagRotationMismatch)
        );
        assert_eq!(tags.current(), Some(tag(1)));

        tags.acknowledge_rotation(tag(2), 10)
            .expect("commit rotation");
        assert!(tags.accepts(tag(1), 10 + ROUTING_TAG_OVERLAP_MILLIS));
        assert!(tags.accepts(tag(2), 10 + ROUTING_TAG_OVERLAP_MILLIS));
        assert!(!tags.accepts(tag(1), 11 + ROUTING_TAG_OVERLAP_MILLIS));
        assert!(tags.accepts(tag(2), 11 + ROUTING_TAG_OVERLAP_MILLIS));

        tags.revoke();
        assert!(!tags.accepts(tag(2), 12 + ROUTING_TAG_OVERLAP_MILLIS));
        assert_eq!(
            tags.begin_rotation(tag(4)),
            Err(TraversalError::RoutingTagRevoked)
        );
    }

    #[test]
    fn cancelled_rotation_preserves_committed_tag() {
        let mut tags = ReceiveRoutingTags::new(tag(1));
        tags.begin_rotation(tag(2)).expect("begin");
        tags.cancel_rotation();
        assert_eq!(tags.current(), Some(tag(1)));
        assert_eq!(tags.pending(), None);
        assert!(tags.accepts(tag(1), 0));
    }

    #[test]
    fn outstanding_nonce_state_is_bounded_and_replay_fails_closed() {
        let candidate_id = CandidateId::new(1).expect("candidate id");
        let mut ledger = ProbeLedger::default();

        for value in 0..MAX_OUTSTANDING_PROBES_PER_PEER {
            let seed = u8::try_from(value).expect("test bound fits u8");
            ledger
                .record(nonce(seed), candidate_id, 0)
                .expect("within capacity");
        }
        assert_eq!(ledger.len(), MAX_OUTSTANDING_PROBES_PER_PEER);
        assert_eq!(
            ledger.record(nonce(200), candidate_id, 0),
            Err(TraversalError::OutstandingProbeCapacity)
        );

        assert!(ledger.consume_ack(nonce(1), candidate_id, 1));
        assert!(!ledger.consume_ack(nonce(1), candidate_id, 1));
        assert!(!ledger.consume_ack(nonce(2), candidate_id, PROBE_NONCE_TTL_MILLIS));
    }

    #[test]
    fn duplicate_live_nonce_is_rejected() {
        let candidate_id = CandidateId::new(1).expect("candidate id");
        let mut ledger = ProbeLedger::default();
        ledger.record(nonce(1), candidate_id, 0).expect("first");
        assert_eq!(
            ledger.record(nonce(1), candidate_id, 1),
            Err(TraversalError::DuplicateOutstandingNonce)
        );
    }

    #[test]
    fn probe_schedule_emits_only_three_bounded_packets() {
        let candidate = candidate(1, 63636);
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        peer.prepare_candidate(candidate).expect("candidate");
        peer.start_probing(1_000).expect("start");

        assert_eq!(peer.next_probe_due_millis(), Some(1_000));
        let first = peer
            .poll_probe(1_000, nonce(1))
            .expect("poll")
            .expect("first");
        assert_eq!(first.destination().port(), 63636);
        assert_eq!(peer.poll_probe(1_100, nonce(2)).expect("early"), None);
        assert!(peer.poll_probe(1_250, nonce(2)).expect("second").is_some());
        assert!(peer.poll_probe(1_749, nonce(3)).expect("early").is_none());
        assert!(peer.poll_probe(1_750, nonce(3)).expect("third").is_some());
        assert!(peer.probe_attempt_exhausted());
        assert_eq!(peer.poll_probe(2_000, nonce(4)).expect("done"), None);
        assert_eq!(peer.outstanding_probe_count(), 3);
    }

    #[test]
    fn unknown_directional_tag_produces_no_ack_or_promotion() {
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        let source: SocketAddr = "198.51.100.20:63636".parse().expect("source");
        let wrong_direction = ProbePacket::probe(tag(2), nonce(9)).encode();

        assert_eq!(
            peer.handle_datagram(&wrong_direction, source, 0),
            InboundDisposition::Ignored
        );
        assert_eq!(peer.state(), TraversalState::Idle);
    }

    #[test]
    fn inbound_probe_gets_one_equal_size_ack_without_creating_reverse_budget() {
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        let source: SocketAddr = "198.51.100.20:63636".parse().expect("source");
        let inbound = ProbePacket::probe(tag(1), nonce(9)).encode();

        let InboundDisposition::Acknowledge {
            datagram,
            observed_source,
            reverse_probe_eligible,
        } = peer.handle_datagram(&inbound, source, 0)
        else {
            panic!("expected acknowledgement");
        };

        assert_eq!(observed_source, source);
        assert_eq!(datagram.destination(), source);
        assert_eq!(datagram.packet().kind(), ProbeMessageKind::Ack);
        assert_eq!(datagram.packet().nonce(), nonce(9));
        assert_eq!(datagram.packet().destination_tag(), tag(2));
        assert_eq!(datagram.packet().encode().len(), PROBE_PACKET_LEN);
        assert!(!reverse_probe_eligible);
    }

    #[test]
    fn active_local_attempt_may_expose_only_reverse_probe_eligibility() {
        let candidate = candidate(1, 63636);
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        peer.prepare_candidate(candidate).expect("candidate");
        peer.start_probing(0).expect("start");

        let source: SocketAddr = "198.51.100.20:63636".parse().expect("source");
        let inbound = ProbePacket::probe(tag(1), nonce(9)).encode();

        let InboundDisposition::Acknowledge {
            reverse_probe_eligible,
            ..
        } = peer.handle_datagram(&inbound, source, 0)
        else {
            panic!("expected acknowledgement");
        };
        assert!(reverse_probe_eligible);
        assert_eq!(peer.outstanding_probe_count(), 0);
    }

    #[test]
    fn nonce_correlated_ack_reaches_only_probe_responsive() {
        let candidate = candidate(1, 63636);
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        peer.prepare_candidate(candidate).expect("candidate");
        peer.start_probing(0).expect("start");
        peer.poll_probe(0, nonce(7)).expect("probe").expect("due");

        let source: SocketAddr = "198.51.100.20:63636".parse().expect("source");
        let wrong = ProbePacket::ack(tag(1), nonce(8)).encode();
        assert_eq!(
            peer.handle_datagram(&wrong, source, 1),
            InboundDisposition::Ignored
        );
        assert_eq!(peer.state(), TraversalState::Probing);

        let correct = ProbePacket::ack(tag(1), nonce(7)).encode();
        let InboundDisposition::ProbeResponsive {
            candidate: responsive,
            observed_source,
        } = peer.handle_datagram(&correct, source, 2)
        else {
            panic!("expected responsive path");
        };
        assert_eq!(responsive, candidate);
        assert_eq!(observed_source, source);
        assert_eq!(peer.state(), TraversalState::ProbeResponsive);

        assert_eq!(
            peer.handle_datagram(&correct, source, 3),
            InboundDisposition::Ignored
        );
    }

    #[test]
    fn path_becomes_reachable_only_after_transport_and_session_authentication() {
        let candidate = candidate(1, 63636);
        let mut plan = plan(candidate);
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        peer.prepare_candidate(candidate).expect("candidate");
        peer.start_probing(0).expect("start");
        peer.poll_probe(0, nonce(7)).expect("probe").expect("due");

        let source: SocketAddr = "198.51.100.20:63636".parse().expect("source");
        let ack = ProbePacket::ack(tag(1), nonce(7)).encode();
        assert!(matches!(
            peer.handle_datagram(&ack, source, 1),
            InboundDisposition::ProbeResponsive { .. }
        ));
        assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);

        peer.begin_quic_handshake().expect("quic");
        peer.confirm_transport_authenticated().expect("transport");
        assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);
        assert_eq!(
            peer.promote_path_validated(&mut plan),
            Err(TraversalError::InvalidStateTransition)
        );

        peer.confirm_session_authenticated().expect("session");
        assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);
        peer.promote_path_validated(&mut plan).expect("validated");
        assert_eq!(peer.state(), TraversalState::PathValidated);
        assert_eq!(
            plan.selected_path(),
            SelectedConnectivityPath::Candidate(candidate)
        );

        peer.activate().expect("active");
        assert_eq!(peer.state(), TraversalState::Active);
    }

    #[test]
    fn invalid_authentication_order_fails_closed() {
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        assert_eq!(
            peer.confirm_transport_authenticated(),
            Err(TraversalError::InvalidStateTransition)
        );
        assert_eq!(
            peer.confirm_session_authenticated(),
            Err(TraversalError::InvalidStateTransition)
        );
        assert_eq!(peer.activate(), Err(TraversalError::InvalidStateTransition));
    }

    #[test]
    fn native_traversal_rejects_relay_candidates() {
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        assert_eq!(
            peer.prepare_candidate(relay_candidate(1, 63636)),
            Err(TraversalError::RelayCandidateUnsupported)
        );
        assert_eq!(peer.state(), TraversalState::Idle);
    }

    #[test]
    fn network_change_clears_only_transient_attempt_state() {
        let candidate = candidate(1, 63636);
        let mut peer = PeerTraversal::new(tag(1), tag(2));
        peer.prepare_candidate(candidate).expect("candidate");
        peer.start_probing(0).expect("start");
        peer.poll_probe(0, nonce(1)).expect("probe").expect("due");
        assert_eq!(peer.outstanding_probe_count(), 1);

        peer.reset_for_network_change();

        assert_eq!(peer.state(), TraversalState::Idle);
        assert_eq!(peer.outstanding_probe_count(), 0);
        assert_eq!(peer.next_probe_due_millis(), None);
    }

    fn cached_endpoint(last_octet: u8, port: u16) -> ConnectivityEndpoint {
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet)), port)
            .expect("valid cached endpoint")
    }

    fn epoch(seed: u8) -> NetworkEpoch {
        NetworkEpoch::from_bytes([seed; 16])
    }

    #[test]
    fn endpoint_freshness_uses_only_authenticated_success_age() {
        let endpoint = cached_endpoint(1, 63636);
        let mut cache = EndpointCandidateCache::new();

        cache.observe_reported(
            endpoint,
            EndpointScope::Public,
            EndpointProvenance::ManualBootstrap,
            epoch(1),
            100,
        );
        let reported = cache.entries()[0];
        assert_eq!(
            reported.validation_state(),
            EndpointValidationState::Reported
        );
        assert_eq!(reported.freshness(100 + ENDPOINT_OLD_MILLIS + 1), None);

        cache.record_authenticated_success(
            endpoint,
            EndpointScope::Public,
            EndpointProvenance::DirectSocketObserved,
            epoch(1),
            1_000,
        );
        let validated = cache.entries()[0];
        assert_eq!(
            validated.validation_state(),
            EndpointValidationState::PathValidated
        );
        assert_eq!(
            validated.freshness(1_000 + ENDPOINT_FRESH_MILLIS),
            Some(EndpointFreshness::Fresh)
        );
        assert_eq!(
            validated.freshness(1_001 + ENDPOINT_FRESH_MILLIS),
            Some(EndpointFreshness::Stale)
        );
        assert_eq!(
            validated.freshness(1_000 + ENDPOINT_OLD_MILLIS),
            Some(EndpointFreshness::Stale)
        );
        assert_eq!(
            validated.freshness(1_001 + ENDPOINT_OLD_MILLIS),
            Some(EndpointFreshness::Old)
        );
    }

    #[test]
    fn cache_is_bounded_and_reported_public_candidate_does_not_displace_proven_paths() {
        let mut cache = EndpointCandidateCache::new();

        for value in 1..=4 {
            cache.record_authenticated_success(
                cached_endpoint(value, 63636),
                EndpointScope::Public,
                EndpointProvenance::DirectSocketObserved,
                epoch(value),
                u64::from(value) * 100,
            );
        }
        assert_eq!(cache.len(), MAX_RETAINED_ENDPOINTS_PER_PEER);

        let reported = cached_endpoint(9, 63636);
        cache.observe_reported(
            reported,
            EndpointScope::Public,
            EndpointProvenance::AuthenticatedPeerReported,
            epoch(9),
            10_000,
        );

        assert_eq!(cache.len(), MAX_RETAINED_ENDPOINTS_PER_PEER);
        assert!(
            cache
                .entries()
                .iter()
                .all(|candidate| candidate.endpoint() != reported)
        );

        let lan = cached_endpoint(10, 63636);
        cache.observe_reported(
            lan,
            EndpointScope::Lan,
            EndpointProvenance::LanDiscovery,
            epoch(10),
            10_001,
        );
        let ordered = cache.ordered_candidates(10_001);
        assert_eq!(ordered.len(), MAX_RETAINED_ENDPOINTS_PER_PEER);
        assert_eq!(ordered[0].endpoint(), lan);
        assert_eq!(ordered[0].scope(), EndpointScope::Lan);
        assert_eq!(
            ordered[0].validation_state(),
            EndpointValidationState::Reported
        );
    }

    #[test]
    fn cache_keeps_minimal_metadata_and_clears_on_unpair_or_revoke() {
        let endpoint = cached_endpoint(20, 63636);
        let mut cache = EndpointCandidateCache::new();
        cache.observe_reported(
            endpoint,
            EndpointScope::Public,
            EndpointProvenance::ManualBootstrap,
            epoch(7),
            500,
        );

        let candidate = cache.entries()[0];
        assert_eq!(candidate.endpoint(), endpoint);
        assert_eq!(candidate.address_family(), EndpointAddressFamily::Ipv4);
        assert_eq!(candidate.scope(), EndpointScope::Public);
        assert_eq!(candidate.provenance(), EndpointProvenance::ManualBootstrap);
        assert_eq!(candidate.network_epoch(), epoch(7));
        assert_eq!(candidate.first_seen_at_millis(), 500);
        assert_eq!(candidate.last_seen_at_millis(), 500);
        assert_eq!(candidate.last_success_at_millis(), None);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn authenticated_success_upgrades_existing_report_without_new_identity_trust() {
        let endpoint = cached_endpoint(21, 63636);
        let mut cache = EndpointCandidateCache::new();
        cache.observe_reported(
            endpoint,
            EndpointScope::Public,
            EndpointProvenance::AuthenticatedPeerReported,
            epoch(1),
            100,
        );
        cache.record_authenticated_success(
            endpoint,
            EndpointScope::Public,
            EndpointProvenance::DirectSocketObserved,
            epoch(2),
            200,
        );

        assert_eq!(cache.len(), 1);
        let candidate = cache.entries()[0];
        assert_eq!(
            candidate.validation_state(),
            EndpointValidationState::PathValidated
        );
        assert_eq!(
            candidate.provenance(),
            EndpointProvenance::DirectSocketObserved
        );
        assert_eq!(candidate.network_epoch(), epoch(2));
        assert_eq!(candidate.first_seen_at_millis(), 100);
        assert_eq!(candidate.last_seen_at_millis(), 200);
        assert_eq!(candidate.last_success_at_millis(), Some(200));
    }

    #[test]
    fn android_reconnect_backoff_matches_locked_schedule_and_resets() {
        let mut backoff = AndroidReconnectBackoff::new();
        let expected = [0, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 60_000];

        for delay in expected {
            assert_eq!(backoff.next_delay_millis(), delay);
            backoff.record_failure();
        }

        backoff.reset_for_network_change();
        assert_eq!(backoff.next_delay_millis(), 0);
        backoff.record_failure();
        assert_eq!(backoff.next_delay_millis(), 1_000);

        backoff.reset_for_user_action();
        assert_eq!(backoff.next_delay_millis(), 0);
        backoff.record_failure();
        backoff.reset_after_success();
        assert_eq!(backoff.next_delay_millis(), 0);
    }

    #[test]
    fn active_path_keepalive_waits_25_seconds_and_valid_traffic_resets_idle() {
        let mut idle = ActivePathIdlePolicy::new(1_000);

        assert!(!idle.should_emit_keepalive(25_999));
        assert!(idle.should_emit_keepalive(26_000));

        idle.record_valid_traffic(20_000);
        assert!(!idle.should_emit_keepalive(44_999));
        assert!(idle.should_emit_keepalive(45_000));

        idle.record_keepalive_emitted(45_000);
        assert!(!idle.should_emit_keepalive(69_999));
        assert!(idle.should_emit_keepalive(70_000));
    }
}
