//! Standards-based, Sans-I/O NAT traversal for Ownspace.
//!
//! Phase 141 owns STUN/ICE protocol state only. This crate deliberately owns no socket,
//! async runtime, DNS resolver, process, tunnel, route or firewall mutation surface.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    PeerConnectivityPlan, ReachabilityObservation,
};
use rtc_ice::{
    Agent, Credentials, Event,
    agent::agent_config::AgentConfig,
    candidate::{
        Candidate, CandidateConfig, CandidateType, candidate_host::CandidateHostConfig,
        candidate_server_reflexive::CandidateServerReflexiveConfig,
    },
    mdns::MulticastDnsMode,
    network_type::NetworkType,
};
use rtc_shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};
use rtc_stun::{
    agent::StunEvent,
    client::{Client, ClientBuilder},
    message::{BINDING_REQUEST, BINDING_SUCCESS, Getter, Message, TransactionId},
    xoraddr::XorMappedAddress,
};
use sansio::Protocol;

/// Maximum number of bytes accepted or emitted by one traversal datagram.
pub const MAX_TRAVERSAL_DATAGRAM_BYTES: usize = 2048;
/// Maximum local ICE candidates retained by one session.
pub const MAX_LOCAL_ICE_CANDIDATES: usize = 16;
/// Maximum remote ICE candidates retained by one session.
pub const MAX_REMOTE_ICE_CANDIDATES: usize = 16;
/// Maximum ICE username-fragment length accepted by the PRW wrapper.
pub const MAX_ICE_UFRAG_BYTES: usize = 256;
/// Maximum ICE password length accepted by the PRW wrapper.
pub const MAX_ICE_PASSWORD_BYTES: usize = 256;

/// A bounded UDP datagram emitted or consumed by the Sans-I/O traversal layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalDatagram {
    local: SocketAddr,
    peer: SocketAddr,
    payload: Vec<u8>,
}

impl TraversalDatagram {
    /// Creates a bounded traversal datagram with validated endpoints.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for invalid endpoints, empty payloads or payloads
    /// larger than [`MAX_TRAVERSAL_DATAGRAM_BYTES`].
    pub fn new(
        local: SocketAddr,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<Self, TraversalError> {
        validate_socket_endpoint(local)?;
        validate_socket_endpoint(peer)?;
        if payload.is_empty() {
            return Err(TraversalError::EmptyDatagram);
        }
        if payload.len() > MAX_TRAVERSAL_DATAGRAM_BYTES {
            return Err(TraversalError::DatagramTooLarge);
        }
        Ok(Self {
            local,
            peer,
            payload,
        })
    }

    /// Returns the local endpoint associated with the datagram.
    #[must_use]
    pub const fn local(&self) -> SocketAddr {
        self.local
    }

    /// Returns the peer endpoint associated with the datagram.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the bounded payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Validated ICE credentials used only for traversal checks.
#[derive(Clone, PartialEq, Eq)]
pub struct IceCredentials {
    ufrag: String,
    password: String,
}

impl fmt::Debug for IceCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl IceCredentials {
    /// Creates bounded non-empty traversal credentials.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized values.
    pub fn new(
        ufrag: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, TraversalError> {
        let ufrag = ufrag.into();
        let password = password.into();
        if ufrag.is_empty()
            || ufrag.len() > MAX_ICE_UFRAG_BYTES
            || password.is_empty()
            || password.len() > MAX_ICE_PASSWORD_BYTES
        {
            return Err(TraversalError::InvalidIceCredentials);
        }
        Ok(Self { ufrag, password })
    }

    /// Returns the ICE username fragment.
    #[must_use]
    pub fn ufrag(&self) -> &str {
        &self.ufrag
    }

    /// Returns the ICE password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// ICE candidate representation admitted by the initial PRW traversal profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceCandidateClass {
    /// Direct address owned by a local interface or supplied for a peer.
    Host,
    /// Address discovered through a STUN server mapping.
    ServerReflexive,
}

/// A Phase 135 observation produced by a selected ICE pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateReachabilityUpdate {
    candidate_id: CandidateId,
    observation: ReachabilityObservation,
}

impl CandidateReachabilityUpdate {
    /// Returns the correlated Phase 135 candidate identifier.
    #[must_use]
    pub const fn candidate_id(self) -> CandidateId {
        self.candidate_id
    }

    /// Returns the reachability observation.
    #[must_use]
    pub const fn observation(self) -> ReachabilityObservation {
        self.observation
    }

    /// Applies this observation through the existing Phase 135 plan API.
    ///
    /// # Errors
    ///
    /// Fails closed if the candidate no longer exists in the current plan.
    pub fn apply(self, plan: &mut PeerConnectivityPlan) -> Result<(), TraversalError> {
        plan.set_observation(self.candidate_id, self.observation)
            .map_err(|_| TraversalError::UnknownConnectivityCandidate)
    }
}

/// One bounded, Sans-I/O STUN Binding discovery transaction.
pub struct StunDiscovery {
    local: SocketAddr,
    server: SocketAddr,
    client: Client,
    finished: bool,
}

impl StunDiscovery {
    /// Starts a STUN Binding transaction against one explicit server socket address.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoints or an upstream protocol-initialization failure.
    pub fn new(local: SocketAddr, server: SocketAddr) -> Result<Self, TraversalError> {
        validate_socket_endpoint(local)?;
        validate_socket_endpoint(server)?;

        let mut client = ClientBuilder::new()
            .with_buffer_size(8)
            .build(local, server, TransportProtocol::UDP)
            .map_err(|_| TraversalError::StunProtocol)?;
        let mut request = Message::new();
        request
            .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
            .map_err(|_| TraversalError::StunProtocol)?;
        client
            .handle_write(request)
            .map_err(|_| TraversalError::StunProtocol)?;

        Ok(Self {
            local,
            server,
            client,
            finished: false,
        })
    }

    /// Returns the next bounded datagram to send to the configured STUN server.
    ///
    /// # Errors
    ///
    /// Fails if the upstream engine emits an endpoint or payload outside the PRW boundary.
    pub fn poll_transmit(&mut self) -> Result<Option<TraversalDatagram>, TraversalError> {
        self.client
            .poll_write()
            .map(|transmit| {
                TraversalDatagram::new(
                    transmit.transport.local_addr,
                    transmit.transport.peer_addr,
                    transmit.message.to_vec(),
                )
            })
            .transpose()
    }

    /// Returns the next STUN transaction timeout deadline.
    #[must_use]
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.client.poll_timeout()
    }

    /// Advances the STUN transaction clock.
    ///
    /// # Errors
    ///
    /// Maps upstream protocol failures to a bounded PRW classification.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), TraversalError> {
        self.client
            .handle_timeout(now)
            .map_err(|_| TraversalError::StunProtocol)
    }

    /// Supplies one received STUN datagram.
    ///
    /// # Errors
    ///
    /// Rejects datagrams not addressed to this local endpoint or not sourced by the configured
    /// STUN server before passing bytes to the protocol engine.
    pub fn handle_datagram(
        &mut self,
        datagram: &TraversalDatagram,
        now: Instant,
    ) -> Result<(), TraversalError> {
        if datagram.local != self.local {
            return Err(TraversalError::UnexpectedDatagramLocal);
        }
        if datagram.peer != self.server {
            return Err(TraversalError::UnexpectedDatagramSource);
        }
        self.client
            .handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: datagram.local,
                    peer_addr: datagram.peer,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.payload.as_slice().into(),
            })
            .map_err(|_| TraversalError::StunProtocol)
    }

    /// Polls a completed server-reflexive result.
    ///
    /// # Errors
    ///
    /// A terminal STUN event that is not a valid Binding success with XOR-MAPPED-ADDRESS fails
    /// closed.
    pub fn poll_result(&mut self) -> Option<Result<ConnectivityEndpoint, TraversalError>> {
        if self.finished {
            return None;
        }
        self.client.poll_event().map(|event| {
            self.finished = true;
            let StunEvent::Message(message) = event else {
                return Err(TraversalError::StunTransactionFailed);
            };
            if message.typ != BINDING_SUCCESS {
                return Err(TraversalError::StunTransactionFailed);
            }
            let mut mapped = XorMappedAddress::default();
            mapped
                .get_from(&message)
                .map_err(|_| TraversalError::StunTransactionFailed)?;
            ConnectivityEndpoint::new(mapped.ip, mapped.port)
                .map_err(|_| TraversalError::InvalidMappedEndpoint)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RemoteCorrelation {
    candidate: ConnectivityCandidate,
    endpoint: SocketAddr,
}

/// Bounded Sans-I/O ICE connectivity-check session.
pub struct IceConnectivitySession {
    agent: Agent,
    local_endpoints: Vec<SocketAddr>,
    remote_candidates: Vec<RemoteCorrelation>,
    started: bool,
}

impl IceConnectivitySession {
    /// Creates an ICE session using the fixed PRW UDP-only, mDNS-disabled profile.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol error if the upstream ICE agent cannot be initialized.
    pub fn new() -> Result<Self, TraversalError> {
        let config = AgentConfig {
            multicast_dns_mode: MulticastDnsMode::Disabled,
            disconnected_timeout: Some(Duration::from_secs(5)),
            failed_timeout: Some(Duration::from_secs(15)),
            keepalive_interval: Some(Duration::from_secs(2)),
            candidate_types: vec![CandidateType::Host, CandidateType::ServerReflexive],
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            check_interval: Duration::from_millis(100),
            max_binding_requests: Some(7),
            insecure_skip_verify: false,
            ..Default::default()
        };
        let agent = Agent::new(Arc::new(config)).map_err(|_| TraversalError::IceProtocol)?;
        Ok(Self {
            agent,
            local_endpoints: Vec::new(),
            remote_candidates: Vec::new(),
            started: false,
        })
    }

    /// Returns locally generated ICE credentials for authenticated coordination exchange.
    ///
    /// # Errors
    ///
    /// Fails only if upstream-generated credentials violate the PRW wrapper bounds.
    pub fn local_credentials(&self) -> Result<IceCredentials, TraversalError> {
        let Credentials { ufrag, pwd } = self.agent.get_local_credentials();
        IceCredentials::new(ufrag, pwd)
    }

    /// Adds one local UDP ICE candidate.
    ///
    /// # Errors
    ///
    /// Rejects invalid, duplicate or over-capacity endpoints and invalid server-reflexive base
    /// information.
    pub fn add_local_candidate(
        &mut self,
        endpoint: ConnectivityEndpoint,
        class: IceCandidateClass,
        related_base: Option<ConnectivityEndpoint>,
    ) -> Result<(), TraversalError> {
        if self.local_endpoints.len() >= MAX_LOCAL_ICE_CANDIDATES {
            return Err(TraversalError::CandidateCapacity);
        }
        let endpoint = connectivity_socket(endpoint);
        if self.local_endpoints.contains(&endpoint) {
            return Err(TraversalError::DuplicateCandidate);
        }
        let candidate = build_ice_candidate(
            format!("prw-local-{}", self.local_endpoints.len() + 1),
            endpoint,
            class,
            related_base.map(connectivity_socket),
        )?;
        self.agent
            .add_local_candidate(candidate)
            .map_err(|_| TraversalError::IceProtocol)?;
        self.local_endpoints.push(endpoint);
        if let Some(base) = related_base.map(connectivity_socket)
            && !self.local_endpoints.contains(&base)
        {
            if self.local_endpoints.len() >= MAX_LOCAL_ICE_CANDIDATES {
                return Err(TraversalError::CandidateCapacity);
            }
            self.local_endpoints.push(base);
        }
        Ok(())
    }

    /// Adds one remote candidate correlated to an existing Phase 135 candidate.
    ///
    /// # Errors
    ///
    /// Relay paths are rejected in Phase 141; Phase 142 owns relay allocation/provider state.
    pub fn add_remote_candidate(
        &mut self,
        candidate: ConnectivityCandidate,
        class: IceCandidateClass,
        related_base: Option<ConnectivityEndpoint>,
    ) -> Result<(), TraversalError> {
        if candidate.kind() == ConnectivityPathKind::Relay {
            return Err(TraversalError::RelayDeferred);
        }
        if self.remote_candidates.len() >= MAX_REMOTE_ICE_CANDIDATES {
            return Err(TraversalError::CandidateCapacity);
        }
        let endpoint = connectivity_socket(candidate.endpoint());
        if self.remote_candidates.iter().any(|existing| {
            existing.candidate.id() == candidate.id() || existing.endpoint == endpoint
        }) {
            return Err(TraversalError::DuplicateCandidate);
        }
        let upstream = build_ice_candidate(
            format!("prw-remote-{}", candidate.id().get()),
            endpoint,
            class,
            related_base.map(connectivity_socket),
        )?;
        self.agent
            .add_remote_candidate(upstream)
            .map_err(|_| TraversalError::IceProtocol)?;
        self.remote_candidates.push(RemoteCorrelation {
            candidate,
            endpoint,
        });
        Ok(())
    }

    /// Starts ICE checks after remote traversal credentials have been authenticated/coordinated.
    ///
    /// # Errors
    ///
    /// A session can be started only once.
    pub fn start(
        &mut self,
        controlling: bool,
        remote: &IceCredentials,
    ) -> Result<(), TraversalError> {
        if self.started {
            return Err(TraversalError::AlreadyStarted);
        }
        self.agent
            .start_connectivity_checks(controlling, remote.ufrag.clone(), remote.password.clone())
            .map_err(|_| TraversalError::IceProtocol)?;
        self.started = true;
        Ok(())
    }

    /// Returns the next bounded ICE datagram to transmit.
    ///
    /// # Errors
    ///
    /// Rejects any upstream transmit not attributable to configured local/remote endpoints or
    /// outside the PRW datagram bound.
    pub fn poll_transmit(&mut self) -> Result<Option<TraversalDatagram>, TraversalError> {
        if !self.started {
            return Err(TraversalError::NotStarted);
        }
        self.agent
            .poll_write()
            .map(|transmit| {
                if !self
                    .local_endpoints
                    .contains(&transmit.transport.local_addr)
                {
                    return Err(TraversalError::UnexpectedDatagramLocal);
                }
                if !self
                    .remote_candidates
                    .iter()
                    .any(|candidate| candidate.endpoint == transmit.transport.peer_addr)
                {
                    return Err(TraversalError::UnexpectedDatagramSource);
                }
                TraversalDatagram::new(
                    transmit.transport.local_addr,
                    transmit.transport.peer_addr,
                    transmit.message.to_vec(),
                )
            })
            .transpose()
    }

    /// Supplies one bounded inbound ICE datagram.
    ///
    /// # Errors
    ///
    /// Endpoint attribution is checked before protocol processing.
    pub fn handle_datagram(
        &mut self,
        datagram: &TraversalDatagram,
        now: Instant,
    ) -> Result<(), TraversalError> {
        if !self.started {
            return Err(TraversalError::NotStarted);
        }
        if !self.local_endpoints.contains(&datagram.local) {
            return Err(TraversalError::UnexpectedDatagramLocal);
        }
        if !self
            .remote_candidates
            .iter()
            .any(|candidate| candidate.endpoint == datagram.peer)
        {
            return Err(TraversalError::UnexpectedDatagramSource);
        }
        self.agent
            .handle_read(TransportMessage {
                now,
                transport: TransportContext {
                    local_addr: datagram.local,
                    peer_addr: datagram.peer,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.payload.as_slice().into(),
            })
            .map_err(|_| TraversalError::IceProtocol)
    }

    /// Returns the next ICE timeout deadline.
    ///
    /// # Errors
    ///
    /// The session must have been started.
    pub fn poll_timeout(&mut self) -> Result<Option<Instant>, TraversalError> {
        if !self.started {
            return Err(TraversalError::NotStarted);
        }
        Ok(self.agent.poll_timeout())
    }

    /// Advances the ICE protocol clock.
    ///
    /// # Errors
    ///
    /// Maps upstream protocol failures to a stable PRW classification.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), TraversalError> {
        if !self.started {
            return Err(TraversalError::NotStarted);
        }
        self.agent
            .handle_timeout(now)
            .map_err(|_| TraversalError::IceProtocol)
    }

    /// Polls for a selected-pair reachability update correlated to Phase 135.
    ///
    /// # Errors
    ///
    /// A selected upstream peer address not present in the current PRW candidate set fails
    /// closed rather than inventing a new authorized candidate.
    pub fn poll_reachability(
        &mut self,
    ) -> Result<Option<CandidateReachabilityUpdate>, TraversalError> {
        while let Some(event) = self.agent.poll_event() {
            if let Event::SelectedCandidatePairChange(_, remote) = event {
                let endpoint = remote.addr();
                let correlation = self
                    .remote_candidates
                    .iter()
                    .find(|candidate| candidate.endpoint == endpoint)
                    .ok_or(TraversalError::UncorrelatedSelectedPair)?;
                return Ok(Some(CandidateReachabilityUpdate {
                    candidate_id: correlation.candidate.id(),
                    observation: ReachabilityObservation::Reachable,
                }));
            }
        }
        Ok(None)
    }
}

fn build_ice_candidate(
    candidate_id: String,
    endpoint: SocketAddr,
    class: IceCandidateClass,
    related_base: Option<SocketAddr>,
) -> Result<Candidate, TraversalError> {
    validate_socket_endpoint(endpoint)?;
    let network = "udp".to_owned();
    let base_config = CandidateConfig {
        candidate_id,
        network,
        address: endpoint.ip().to_string(),
        port: endpoint.port(),
        component: 1,
        ..Default::default()
    };
    match class {
        IceCandidateClass::Host => {
            if related_base.is_some() {
                return Err(TraversalError::UnexpectedRelatedAddress);
            }
            CandidateHostConfig {
                base_config,
                ..Default::default()
            }
            .new_candidate_host()
            .map_err(|_| TraversalError::IceProtocol)
        }
        IceCandidateClass::ServerReflexive => {
            let related = related_base.ok_or(TraversalError::MissingRelatedAddress)?;
            validate_socket_endpoint(related)?;
            CandidateServerReflexiveConfig {
                base_config,
                rel_addr: related.ip().to_string(),
                rel_port: related.port(),
                url: None,
            }
            .new_candidate_server_reflexive()
            .map_err(|_| TraversalError::IceProtocol)
        }
    }
}

const fn connectivity_socket(endpoint: ConnectivityEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.address(), endpoint.port())
}

fn validate_socket_endpoint(endpoint: SocketAddr) -> Result<(), TraversalError> {
    if endpoint.port() == 0 {
        return Err(TraversalError::InvalidEndpoint);
    }
    let invalid = match endpoint.ip() {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    };
    if invalid {
        return Err(TraversalError::InvalidEndpoint);
    }
    Ok(())
}

/// Stable Phase 141 traversal failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraversalError {
    /// Endpoint has a zero port or forbidden address class.
    InvalidEndpoint,
    /// Traversal datagram payload was empty.
    EmptyDatagram,
    /// Traversal datagram exceeded the 2048-byte boundary.
    DatagramTooLarge,
    /// Datagram was not addressed to a local endpoint owned by this session.
    UnexpectedDatagramLocal,
    /// Datagram source/destination peer was not configured for this session.
    UnexpectedDatagramSource,
    /// STUN protocol initialization or processing failed.
    StunProtocol,
    /// STUN transaction completed without a valid Binding success result.
    StunTransactionFailed,
    /// STUN mapped endpoint was invalid for PRW connectivity.
    InvalidMappedEndpoint,
    /// ICE protocol initialization or processing failed.
    IceProtocol,
    /// ICE candidate capacity was exceeded.
    CandidateCapacity,
    /// Duplicate candidate identifier or endpoint was supplied.
    DuplicateCandidate,
    /// Initial Phase 141 does not accept relay allocation as an ICE candidate source.
    RelayDeferred,
    /// ICE traversal credentials were empty or oversized.
    InvalidIceCredentials,
    /// Session was started more than once.
    AlreadyStarted,
    /// Operation requires a started ICE session.
    NotStarted,
    /// Server-reflexive candidate requires a related base endpoint.
    MissingRelatedAddress,
    /// Host candidate unexpectedly supplied a related endpoint.
    UnexpectedRelatedAddress,
    /// Selected ICE pair could not be correlated to a current Phase 135 candidate.
    UncorrelatedSelectedPair,
    /// Reachability update referenced a candidate absent from the current Phase 135 plan.
    UnknownConnectivityCandidate,
}

impl fmt::Display for TraversalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "invalid traversal endpoint",
            Self::EmptyDatagram => "traversal datagram must not be empty",
            Self::DatagramTooLarge => "traversal datagram exceeds configured bound",
            Self::UnexpectedDatagramLocal => "traversal datagram local endpoint is unexpected",
            Self::UnexpectedDatagramSource => "traversal datagram peer endpoint is unexpected",
            Self::StunProtocol => "STUN protocol processing failed",
            Self::StunTransactionFailed => "STUN transaction did not produce a mapped endpoint",
            Self::InvalidMappedEndpoint => "STUN mapped endpoint is invalid",
            Self::IceProtocol => "ICE protocol processing failed",
            Self::CandidateCapacity => "ICE candidate capacity exceeded",
            Self::DuplicateCandidate => "ICE candidate is duplicated",
            Self::RelayDeferred => "relay allocation is deferred to Phase 142",
            Self::InvalidIceCredentials => "ICE traversal credentials are invalid",
            Self::AlreadyStarted => "ICE session is already started",
            Self::NotStarted => "ICE session is not started",
            Self::MissingRelatedAddress => "server-reflexive candidate requires a related base",
            Self::UnexpectedRelatedAddress => "host candidate must not have a related base",
            Self::UncorrelatedSelectedPair => "selected ICE pair is not a current PRW candidate",
            Self::UnknownConnectivityCandidate => "reachability candidate is not in current plan",
        })
    }
}

impl std::error::Error for TraversalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use prw_connectivity::{PeerConnectivityIdentity, SelectedConnectivityPath, TransportIdentity};
    use prw_core::DeviceId;
    use rtc_stun::message::{BINDING_SUCCESS, Message};

    fn endpoint(port: u16) -> ConnectivityEndpoint {
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("endpoint")
    }

    fn candidate(id: u64, port: u16) -> ConnectivityCandidate {
        ConnectivityCandidate::new(
            CandidateId::new(id).expect("candidate id"),
            ConnectivityPathKind::LocalDirect,
            endpoint(port),
        )
    }

    #[test]
    fn datagram_and_credentials_are_bounded() {
        let local = SocketAddr::from(([127, 0, 0, 1], 41000));
        let peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        assert_eq!(
            TraversalDatagram::new(local, peer, Vec::new()),
            Err(TraversalError::EmptyDatagram)
        );
        assert_eq!(
            TraversalDatagram::new(local, peer, vec![0; MAX_TRAVERSAL_DATAGRAM_BYTES + 1]),
            Err(TraversalError::DatagramTooLarge)
        );
        assert_eq!(
            IceCredentials::new("", "password"),
            Err(TraversalError::InvalidIceCredentials)
        );
    }

    #[test]
    fn synthetic_stun_binding_success_yields_mapped_endpoint() {
        let local = SocketAddr::from(([127, 0, 0, 1], 42000));
        let server = SocketAddr::from(([127, 0, 0, 1], 3478));
        let mut discovery = StunDiscovery::new(local, server).expect("discovery");
        let request = discovery
            .poll_transmit()
            .expect("poll")
            .expect("binding request");
        assert_eq!(request.local(), local);
        assert_eq!(request.peer(), server);
        assert!(request.payload().len() <= MAX_TRAVERSAL_DATAGRAM_BYTES);

        let mut decoded = Message::new();
        decoded
            .unmarshal_binary(request.payload())
            .expect("decode request");
        let mut response = Message::new();
        response
            .build(&[
                Box::new(decoded.transaction_id),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                    port: 54321,
                }),
            ])
            .expect("binding response");
        discovery
            .handle_datagram(
                &TraversalDatagram::new(local, server, response.raw).expect("response datagram"),
                Instant::now(),
            )
            .expect("handle response");
        let mapped = discovery
            .poll_result()
            .expect("terminal event")
            .expect("mapped endpoint");
        assert_eq!(mapped.address(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(mapped.port(), 54321);
    }

    #[test]
    fn stun_wrong_source_is_rejected_before_protocol() {
        let local = SocketAddr::from(([127, 0, 0, 1], 42010));
        let server = SocketAddr::from(([127, 0, 0, 1], 3478));
        let attacker = SocketAddr::from(([127, 0, 0, 1], 3479));
        let mut discovery = StunDiscovery::new(local, server).expect("discovery");
        assert_eq!(
            discovery.handle_datagram(
                &TraversalDatagram::new(local, attacker, vec![1]).expect("datagram"),
                Instant::now(),
            ),
            Err(TraversalError::UnexpectedDatagramSource)
        );
    }

    fn build_ice_pair(
        wrong_password: bool,
    ) -> (
        IceConnectivitySession,
        IceConnectivitySession,
        PeerConnectivityPlan,
        PeerConnectivityPlan,
    ) {
        let a_addr = endpoint(43001);
        let b_addr = endpoint(43002);
        let mut a = IceConnectivitySession::new().expect("a");
        let mut b = IceConnectivitySession::new().expect("b");
        let a_credentials = a.local_credentials().expect("a credentials");
        let b_credentials = b.local_credentials().expect("b credentials");

        a.add_local_candidate(a_addr, IceCandidateClass::Host, None)
            .expect("a local");
        b.add_local_candidate(b_addr, IceCandidateClass::Host, None)
            .expect("b local");
        let a_remote = candidate(11, 43002);
        let b_remote = candidate(12, 43001);
        a.add_remote_candidate(a_remote, IceCandidateClass::Host, None)
            .expect("a remote");
        b.add_remote_candidate(b_remote, IceCandidateClass::Host, None)
            .expect("b remote");

        let b_for_a = if wrong_password {
            IceCredentials::new(b_credentials.ufrag(), "deliberately-wrong-password")
                .expect("wrong credentials")
        } else {
            b_credentials
        };
        a.start(true, &b_for_a).expect("start a");
        b.start(false, &a_credentials).expect("start b");

        let a_peer = PeerConnectivityIdentity::new(
            DeviceId::new("device-b").expect("device"),
            TransportIdentity::new([2; 32]).expect("transport"),
        );
        let b_peer = PeerConnectivityIdentity::new(
            DeviceId::new("device-a").expect("device"),
            TransportIdentity::new([1; 32]).expect("transport"),
        );
        let a_plan = PeerConnectivityPlan::new(a_peer, vec![a_remote]).expect("a plan");
        let b_plan = PeerConnectivityPlan::new(b_peer, vec![b_remote]).expect("b plan");
        (a, b, a_plan, b_plan)
    }

    fn drive_pair(
        a: &mut IceConnectivitySession,
        b: &mut IceConnectivitySession,
        steps: usize,
    ) -> (
        Option<CandidateReachabilityUpdate>,
        Option<CandidateReachabilityUpdate>,
    ) {
        let base = Instant::now();
        let mut a_update = None;
        let mut b_update = None;
        for step in 0..steps {
            let millis = u64::try_from(step).expect("bounded test step") * 100;
            let now = base + Duration::from_millis(millis);
            if a.poll_timeout()
                .expect("a timeout")
                .is_some_and(|deadline| deadline <= now)
            {
                let _ = a.handle_timeout(now);
            }
            if b.poll_timeout()
                .expect("b timeout")
                .is_some_and(|deadline| deadline <= now)
            {
                let _ = b.handle_timeout(now);
            }

            for _ in 0..8 {
                let Some(outbound) = a.poll_transmit().expect("a transmit") else {
                    break;
                };
                let inbound = TraversalDatagram::new(
                    outbound.peer(),
                    outbound.local(),
                    outbound.payload().to_vec(),
                )
                .expect("invert a datagram");
                let _ = b.handle_datagram(&inbound, now);
            }
            for _ in 0..8 {
                let Some(outbound) = b.poll_transmit().expect("b transmit") else {
                    break;
                };
                let inbound = TraversalDatagram::new(
                    outbound.peer(),
                    outbound.local(),
                    outbound.payload().to_vec(),
                )
                .expect("invert b datagram");
                let _ = a.handle_datagram(&inbound, now);
            }

            if a_update.is_none() {
                a_update = a.poll_reachability().expect("a event");
            }
            if b_update.is_none() {
                b_update = b.poll_reachability().expect("b event");
            }
            if a_update.is_some() && b_update.is_some() {
                break;
            }
        }
        (a_update, b_update)
    }

    #[test]
    fn in_memory_ice_pair_selects_and_updates_phase135_plan() {
        let (mut a, mut b, mut a_plan, mut b_plan) = build_ice_pair(false);
        let (a_update, b_update) = drive_pair(&mut a, &mut b, 200);
        let a_update = a_update.expect("a selected pair");
        let b_update = b_update.expect("b selected pair");
        assert_eq!(a_update.candidate_id().get(), 11);
        assert_eq!(b_update.candidate_id().get(), 12);
        a_update.apply(&mut a_plan).expect("apply a");
        b_update.apply(&mut b_plan).expect("apply b");
        assert!(matches!(
            a_plan.selected_path(),
            SelectedConnectivityPath::Candidate(selected) if selected.id().get() == 11
        ));
        assert!(matches!(
            b_plan.selected_path(),
            SelectedConnectivityPath::Candidate(selected) if selected.id().get() == 12
        ));
    }

    #[test]
    fn wrong_remote_ice_password_never_selects_pair() {
        let (mut a, mut b, _, _) = build_ice_pair(true);
        let (a_update, b_update) = drive_pair(&mut a, &mut b, 250);
        assert!(a_update.is_none());
        assert!(b_update.is_none());
    }

    #[test]
    fn relay_and_candidate_duplicates_fail_closed() {
        let mut session = IceConnectivitySession::new().expect("session");
        session
            .add_local_candidate(endpoint(44001), IceCandidateClass::Host, None)
            .expect("local");
        assert_eq!(
            session.add_local_candidate(endpoint(44001), IceCandidateClass::Host, None),
            Err(TraversalError::DuplicateCandidate)
        );
        let relay = ConnectivityCandidate::new(
            CandidateId::new(99).expect("id"),
            ConnectivityPathKind::Relay,
            endpoint(44002),
        );
        assert_eq!(
            session.add_remote_candidate(relay, IceCandidateClass::Host, None),
            Err(TraversalError::RelayDeferred)
        );
    }

    #[test]
    fn candidate_capacity_is_bounded() {
        let mut session = IceConnectivitySession::new().expect("session");
        for index in 0..MAX_LOCAL_ICE_CANDIDATES {
            let offset = u16::try_from(index).expect("small index");
            session
                .add_local_candidate(endpoint(45000 + offset), IceCandidateClass::Host, None)
                .expect("candidate within capacity");
        }
        assert_eq!(
            session.add_local_candidate(endpoint(46000), IceCandidateClass::Host, None),
            Err(TraversalError::CandidateCapacity)
        );
    }
}
