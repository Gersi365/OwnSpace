//! Provider-neutral private-mesh connectivity foundation for Ownspace.
//!
//! Phase 135 models bounded candidates, provider observations and deterministic path
//! selection. Phase 152 C02e additionally permits transactional refresh of transient
//! candidate endpoints while preserving the authenticated logical/transport peer identity.
//! It performs no socket I/O, probing, NAT traversal, tunneling, routing, DNS,
//! firewall mutation or production-network activation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use prw_core::DeviceId;

/// Maximum transport candidates accepted for one peer plan.
pub const MAX_CONNECTIVITY_CANDIDATES: usize = 16;

/// Stable plan-scoped candidate identifier.
///
/// Within one plan lifetime, a removed identifier must never be reused. Newly introduced
/// identifiers advance above the plan's previous high-water mark; an identifier retained across
/// refresh is valid only for the exact same path kind and endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(u64);

impl CandidateId {
    /// Creates a non-zero candidate identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectivityError::InvalidCandidateId`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, ConnectivityError> {
        if value == 0 {
            return Err(ConnectivityError::InvalidCandidateId);
        }
        Ok(Self(value))
    }

    /// Returns the raw plan-scoped identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque transport/network identity, distinct from logical device identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportIdentity([u8; 32]);

impl TransportIdentity {
    /// Creates an opaque non-zero 32-byte transport identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectivityError::InvalidTransportIdentity`] for the all-zero value.
    pub fn new(bytes: [u8; 32]) -> Result<Self, ConnectivityError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ConnectivityError::InvalidTransportIdentity);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Logical peer identity plus an independently rotatable transport identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnectivityIdentity {
    device: DeviceId,
    transport: TransportIdentity,
}

impl PeerConnectivityIdentity {
    /// Creates a peer connectivity identity from already-validated components.
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

/// Explicit IP endpoint used by a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectivityEndpoint {
    address: IpAddr,
    port: u16,
}

impl ConnectivityEndpoint {
    /// Creates an explicit endpoint with a non-zero port.
    ///
    /// # Errors
    ///
    /// Rejects zero port, unspecified addresses, multicast addresses and IPv4 limited
    /// broadcast. No hostname or resolver input exists in this API.
    pub fn new(address: IpAddr, port: u16) -> Result<Self, ConnectivityError> {
        if port == 0 {
            return Err(ConnectivityError::InvalidEndpointPort);
        }
        let invalid = match address {
            IpAddr::V4(ipv4) => {
                ipv4.is_unspecified() || ipv4.is_multicast() || ipv4 == Ipv4Addr::BROADCAST
            }
            IpAddr::V6(ipv6) => ipv6.is_unspecified() || ipv6.is_multicast(),
        };
        if invalid {
            return Err(ConnectivityError::InvalidEndpointAddress);
        }
        Ok(Self { address, port })
    }

    /// Returns the explicit IP address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns the explicit non-zero port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

/// Product-level connectivity path class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectivityPathKind {
    /// Direct path expected to be local to the peer environment.
    LocalDirect,
    /// Direct path across Internet reachability.
    InternetDirect,
    /// Relay fallback candidate. Byte relaying is owned by Phase 136.
    Relay,
}

impl ConnectivityPathKind {
    const fn selection_rank(self) -> u8 {
        match self {
            Self::LocalDirect => 0,
            Self::InternetDirect => 1,
            Self::Relay => 2,
        }
    }
}

/// One validated connectivity candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectivityCandidate {
    id: CandidateId,
    kind: ConnectivityPathKind,
    endpoint: ConnectivityEndpoint,
}

impl ConnectivityCandidate {
    /// Creates a candidate from validated typed components.
    #[must_use]
    pub const fn new(
        id: CandidateId,
        kind: ConnectivityPathKind,
        endpoint: ConnectivityEndpoint,
    ) -> Self {
        Self { id, kind, endpoint }
    }

    /// Returns the candidate identifier.
    #[must_use]
    pub const fn id(self) -> CandidateId {
        self.id
    }

    /// Returns the path class.
    #[must_use]
    pub const fn kind(self) -> ConnectivityPathKind {
        self.kind
    }

    /// Returns the explicit endpoint.
    #[must_use]
    pub const fn endpoint(self) -> ConnectivityEndpoint {
        self.endpoint
    }
}

/// Provider-owned reachability observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityObservation {
    /// Candidate has not been probed or has no usable current observation.
    Unknown,
    /// Provider reports that the candidate is currently reachable.
    Reachable,
    /// Provider reports that the candidate is currently unreachable.
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateState {
    candidate: ConnectivityCandidate,
    observation: ReachabilityObservation,
}

/// Deterministic selector result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedConnectivityPath {
    /// One reachable candidate selected by the fixed product ordering.
    Candidate(ConnectivityCandidate),
    /// No candidate is currently observed reachable.
    Offline,
}

/// Provider-neutral durable semantic projection of one peer connectivity plan.
///
/// This carrier deliberately omits transient reachability observations. It preserves only the
/// exact peer, the current configured candidate vector, and historical candidate-ID anti-reuse
/// state required to reconstruct one plan across durable recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnectivityPlanDurableState {
    peer: PeerConnectivityIdentity,
    candidates: Vec<ConnectivityCandidate>,
    candidate_id_high_watermark: Option<CandidateId>,
}

impl PeerConnectivityPlanDurableState {
    /// Creates a typed durable-state carrier from decoded/provider-neutral parts.
    ///
    /// Semantic consistency is validated only when the state is restored into a
    /// [`PeerConnectivityPlan`]. This constructor performs no I/O and assigns no candidate IDs.
    #[must_use]
    pub const fn from_parts(
        peer: PeerConnectivityIdentity,
        candidates: Vec<ConnectivityCandidate>,
        candidate_id_high_watermark: Option<CandidateId>,
    ) -> Self {
        Self {
            peer,
            candidates,
            candidate_id_high_watermark,
        }
    }

    /// Returns the exact logical/transport peer identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the current configured candidates in exact plan order.
    #[must_use]
    pub fn candidates(&self) -> &[ConnectivityCandidate] {
        &self.candidates
    }

    /// Returns the exact historical candidate-ID high-watermark.
    #[must_use]
    pub const fn candidate_id_high_watermark(&self) -> Option<CandidateId> {
        self.candidate_id_high_watermark
    }
}

/// Bounded peer candidate plan and observation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnectivityPlan {
    peer: PeerConnectivityIdentity,
    candidates: Vec<CandidateState>,
    candidate_id_high_watermark: u64,
}

impl PeerConnectivityPlan {
    /// Creates a bounded plan. Initial observations are `Unknown`.
    ///
    /// # Errors
    ///
    /// Rejects more than 16 candidates, duplicate candidate identifiers and duplicate exact
    /// `(path kind, endpoint)` candidates.
    pub fn new(
        peer: PeerConnectivityIdentity,
        candidates: Vec<ConnectivityCandidate>,
    ) -> Result<Self, ConnectivityError> {
        if candidates.len() > MAX_CONNECTIVITY_CANDIDATES {
            return Err(ConnectivityError::CandidateCapacity);
        }

        for (index, candidate) in candidates.iter().enumerate() {
            for existing in &candidates[..index] {
                if existing.id == candidate.id {
                    return Err(ConnectivityError::DuplicateCandidateId);
                }
                if existing.kind == candidate.kind && existing.endpoint == candidate.endpoint {
                    return Err(ConnectivityError::DuplicateCandidateEndpoint);
                }
            }
        }

        let candidate_id_high_watermark = candidates
            .iter()
            .map(|candidate| candidate.id.get())
            .max()
            .unwrap_or(0);
        let candidates = candidates
            .into_iter()
            .map(|candidate| CandidateState {
                candidate,
                observation: ReachabilityObservation::Unknown,
            })
            .collect();
        Ok(Self {
            peer,
            candidates,
            candidate_id_high_watermark,
        })
    }

    /// Restores one plan from provider-neutral durable semantic state.
    ///
    /// Every restored reachability observation is `Unknown`; persisted reachability observations
    /// are not part of the durable carrier and cannot become authority after recovery.
    ///
    /// # Errors
    ///
    /// Rejects invalid candidate sets using the same structural classifications as [`Self::new`]
    /// and fails with [`ConnectivityError::InvalidCandidateIdHighWatermark`] when the persisted
    /// high-watermark is missing for active candidates or falls below the active maximum.
    pub fn from_durable_state(
        state: PeerConnectivityPlanDurableState,
    ) -> Result<Self, ConnectivityError> {
        let PeerConnectivityPlanDurableState {
            peer,
            candidates,
            candidate_id_high_watermark,
        } = state;

        if candidates.len() > MAX_CONNECTIVITY_CANDIDATES {
            return Err(ConnectivityError::CandidateCapacity);
        }

        for (index, candidate) in candidates.iter().enumerate() {
            for existing in &candidates[..index] {
                if existing.id == candidate.id {
                    return Err(ConnectivityError::DuplicateCandidateId);
                }
                if existing.kind == candidate.kind && existing.endpoint == candidate.endpoint {
                    return Err(ConnectivityError::DuplicateCandidateEndpoint);
                }
            }
        }

        let active_maximum = candidates.iter().map(|candidate| candidate.id.get()).max();
        let candidate_id_high_watermark = match (active_maximum, candidate_id_high_watermark) {
            (None, None) => 0,
            (Some(_), None) => return Err(ConnectivityError::InvalidCandidateIdHighWatermark),
            (Some(active_maximum), Some(high_watermark))
                if high_watermark.get() < active_maximum =>
            {
                return Err(ConnectivityError::InvalidCandidateIdHighWatermark);
            }
            (None | Some(_), Some(high_watermark)) => high_watermark.get(),
        };

        let candidates = candidates
            .into_iter()
            .map(|candidate| CandidateState {
                candidate,
                observation: ReachabilityObservation::Unknown,
            })
            .collect();

        Ok(Self {
            peer,
            candidates,
            candidate_id_high_watermark,
        })
    }

    /// Returns the logical/transport peer identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the number of configured candidates.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Returns the highest candidate identifier ever accepted by this plan lifetime.
    ///
    /// `None` means no non-zero candidate identifier has ever been accepted. A returned
    /// identifier is historical anti-reuse state and is not necessarily a currently active
    /// candidate. This observation does not allocate, reserve, publish, or classify a candidate.
    #[must_use]
    pub const fn candidate_id_high_watermark(&self) -> Option<CandidateId> {
        if self.candidate_id_high_watermark == 0 {
            None
        } else {
            Some(CandidateId(self.candidate_id_high_watermark))
        }
    }

    /// Projects this plan into provider-neutral durable semantic state.
    ///
    /// Transient reachability observations are intentionally omitted. Projection performs no
    /// mutation, provider call, I/O, candidate allocation, or freshness transition.
    #[must_use]
    pub fn durable_state(&self) -> PeerConnectivityPlanDurableState {
        PeerConnectivityPlanDurableState {
            peer: self.peer.clone(),
            candidates: self
                .candidates
                .iter()
                .map(|state| state.candidate)
                .collect(),
            candidate_id_high_watermark: self.candidate_id_high_watermark(),
        }
    }

    /// Atomically replaces transient network candidates while preserving peer identity.
    ///
    /// Every refreshed candidate starts with an `Unknown` observation so reachability evidence
    /// from a previous Wi-Fi, mobile-data, NAT, or relay path cannot be inherited by a newly
    /// signaled endpoint set. Existing candidate identifiers may be retained only for the exact
    /// same candidate. A newly introduced candidate must use an identifier above the plan's
    /// prior high-water mark, so an identifier removed by an earlier refresh cannot later return.
    ///
    /// # Errors
    ///
    /// Rejects the same invalid candidate sets as [`Self::new`], rejects rebinding an existing
    /// candidate identifier to a different path/endpoint, and rejects reuse of an identifier at
    /// or below the plan's prior high-water mark when that identifier is not an exact retained
    /// candidate. Validation completes before mutation, so an error preserves the complete
    /// previous candidate/observation/high-watermark state.
    pub fn refresh_candidates(
        &mut self,
        candidates: Vec<ConnectivityCandidate>,
    ) -> Result<(), ConnectivityError> {
        if candidates.len() > MAX_CONNECTIVITY_CANDIDATES {
            return Err(ConnectivityError::CandidateCapacity);
        }

        for (index, candidate) in candidates.iter().enumerate() {
            match self
                .candidates
                .iter()
                .find(|existing| existing.candidate.id == candidate.id)
            {
                Some(existing) if existing.candidate != *candidate => {
                    return Err(ConnectivityError::CandidateIdRebound);
                }
                None if candidate.id.get() <= self.candidate_id_high_watermark => {
                    return Err(ConnectivityError::CandidateIdRebound);
                }
                Some(_) | None => {}
            }
            for existing in &candidates[..index] {
                if existing.id == candidate.id {
                    return Err(ConnectivityError::DuplicateCandidateId);
                }
                if existing.kind == candidate.kind && existing.endpoint == candidate.endpoint {
                    return Err(ConnectivityError::DuplicateCandidateEndpoint);
                }
            }
        }

        let next_candidate_id_high_watermark = candidates
            .iter()
            .map(|candidate| candidate.id.get())
            .max()
            .unwrap_or(0)
            .max(self.candidate_id_high_watermark);
        let refreshed = candidates
            .into_iter()
            .map(|candidate| CandidateState {
                candidate,
                observation: ReachabilityObservation::Unknown,
            })
            .collect();
        self.candidates = refreshed;
        self.candidate_id_high_watermark = next_candidate_id_high_watermark;
        Ok(())
    }

    /// Records a provider observation for an existing candidate.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectivityError::UnknownCandidate`] when `id` is not in this plan.
    pub fn set_observation(
        &mut self,
        id: CandidateId,
        observation: ReachabilityObservation,
    ) -> Result<(), ConnectivityError> {
        let state = self
            .candidates
            .iter_mut()
            .find(|state| state.candidate.id == id)
            .ok_or(ConnectivityError::UnknownCandidate)?;
        state.observation = observation;
        Ok(())
    }

    /// Selects the best currently reachable candidate deterministically.
    #[must_use]
    pub fn selected_path(&self) -> SelectedConnectivityPath {
        self.candidates
            .iter()
            .filter(|state| state.observation == ReachabilityObservation::Reachable)
            .min_by_key(|state| {
                (
                    state.candidate.kind.selection_rank(),
                    state.candidate.id.get(),
                )
            })
            .map_or(SelectedConnectivityPath::Offline, |state| {
                SelectedConnectivityPath::Candidate(state.candidate)
            })
    }
}

/// Stable Phase 135 validation failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectivityError {
    /// Candidate identifier was zero.
    InvalidCandidateId,
    /// Transport identity was all zero.
    InvalidTransportIdentity,
    /// Endpoint port was zero.
    InvalidEndpointPort,
    /// Endpoint address was unspecified, multicast or IPv4 limited broadcast.
    InvalidEndpointAddress,
    /// Candidate count exceeded the plan bound.
    CandidateCapacity,
    /// Candidate identifier was duplicated.
    DuplicateCandidateId,
    /// Exact path-kind and endpoint tuple was duplicated.
    DuplicateCandidateEndpoint,
    /// An existing or retired plan-scoped candidate identifier was rebound/reused.
    CandidateIdRebound,
    /// Durable candidate-ID high-watermark is missing or lower than the active maximum.
    InvalidCandidateIdHighWatermark,
    /// Observation referenced a candidate not in the plan.
    UnknownCandidate,
}

impl fmt::Display for ConnectivityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCandidateId => "candidate identifier must be non-zero",
            Self::InvalidTransportIdentity => "transport identity must not be all zero",
            Self::InvalidEndpointPort => "connectivity endpoint port must be non-zero",
            Self::InvalidEndpointAddress => "connectivity endpoint address is not allowed",
            Self::CandidateCapacity => "connectivity candidate capacity exceeded",
            Self::DuplicateCandidateId => "connectivity candidate identifier is duplicated",
            Self::DuplicateCandidateEndpoint => "connectivity candidate endpoint is duplicated",
            Self::CandidateIdRebound => {
                "connectivity candidate identifier cannot be rebound or reused"
            }
            Self::InvalidCandidateIdHighWatermark => {
                "connectivity candidate identifier high-watermark is inconsistent"
            }
            Self::UnknownCandidate => "connectivity candidate is unknown",
        })
    }
}

impl std::error::Error for ConnectivityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn transport(seed: u8) -> TransportIdentity {
        TransportIdentity::new([seed; 32]).expect("non-zero transport identity")
    }

    fn peer() -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(DeviceId::new("device-1").expect("device"), transport(1))
    }

    fn id(value: u64) -> CandidateId {
        CandidateId::new(value).expect("candidate id")
    }

    fn endpoint(port: u16) -> ConnectivityEndpoint {
        ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).expect("endpoint")
    }

    fn candidate(value: u64, kind: ConnectivityPathKind, port: u16) -> ConnectivityCandidate {
        ConnectivityCandidate::new(id(value), kind, endpoint(port))
    }

    #[test]
    fn identifiers_transport_and_endpoints_are_bounded() {
        assert_eq!(
            CandidateId::new(0),
            Err(ConnectivityError::InvalidCandidateId)
        );
        assert_eq!(
            TransportIdentity::new([0; 32]),
            Err(ConnectivityError::InvalidTransportIdentity)
        );
        assert_eq!(
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Err(ConnectivityError::InvalidEndpointPort)
        );
        assert_eq!(
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
            Err(ConnectivityError::InvalidEndpointAddress)
        );
        assert_eq!(
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::BROADCAST), 1),
            Err(ConnectivityError::InvalidEndpointAddress)
        );
        assert_eq!(
            ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 1),
            Err(ConnectivityError::InvalidEndpointAddress)
        );
        assert_eq!(
            ConnectivityEndpoint::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
            Err(ConnectivityError::InvalidEndpointAddress)
        );
    }

    #[test]
    fn candidate_capacity_is_enforced() {
        let candidates = (1..=17)
            .map(|value| {
                candidate(
                    value,
                    ConnectivityPathKind::InternetDirect,
                    2000 + u16::try_from(value).expect("capacity test value fits u16"),
                )
            })
            .collect();
        assert_eq!(
            PeerConnectivityPlan::new(peer(), candidates),
            Err(ConnectivityError::CandidateCapacity)
        );
    }

    #[test]
    fn duplicate_ids_and_exact_kind_endpoints_are_rejected() {
        let duplicate_id = vec![
            candidate(1, ConnectivityPathKind::LocalDirect, 2000),
            candidate(1, ConnectivityPathKind::InternetDirect, 2001),
        ];
        assert_eq!(
            PeerConnectivityPlan::new(peer(), duplicate_id),
            Err(ConnectivityError::DuplicateCandidateId)
        );

        let duplicate_endpoint = vec![
            candidate(1, ConnectivityPathKind::InternetDirect, 2000),
            candidate(2, ConnectivityPathKind::InternetDirect, 2000),
        ];
        assert_eq!(
            PeerConnectivityPlan::new(peer(), duplicate_endpoint),
            Err(ConnectivityError::DuplicateCandidateEndpoint)
        );
    }

    #[test]
    fn unknown_observation_target_fails_closed() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::LocalDirect, 2000)],
        )
        .expect("plan");
        assert_eq!(
            plan.set_observation(id(2), ReachabilityObservation::Reachable),
            Err(ConnectivityError::UnknownCandidate)
        );
    }

    #[test]
    fn unknown_and_unreachable_candidates_produce_offline() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                candidate(1, ConnectivityPathKind::LocalDirect, 2000),
                candidate(2, ConnectivityPathKind::Relay, 2001),
            ],
        )
        .expect("plan");
        plan.set_observation(id(2), ReachabilityObservation::Unreachable)
            .expect("observation");
        assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);
    }

    #[test]
    fn local_direct_beats_internet_direct_and_relay() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                candidate(3, ConnectivityPathKind::Relay, 2003),
                candidate(2, ConnectivityPathKind::InternetDirect, 2002),
                candidate(1, ConnectivityPathKind::LocalDirect, 2001),
            ],
        )
        .expect("plan");
        for value in 1..=3 {
            plan.set_observation(id(value), ReachabilityObservation::Reachable)
                .expect("observation");
        }
        assert_eq!(
            plan.selected_path(),
            SelectedConnectivityPath::Candidate(candidate(
                1,
                ConnectivityPathKind::LocalDirect,
                2001
            ))
        );
    }

    #[test]
    fn internet_direct_beats_relay_when_local_is_unavailable() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                candidate(1, ConnectivityPathKind::LocalDirect, 2001),
                candidate(2, ConnectivityPathKind::InternetDirect, 2002),
                candidate(3, ConnectivityPathKind::Relay, 2003),
            ],
        )
        .expect("plan");
        plan.set_observation(id(1), ReachabilityObservation::Unreachable)
            .expect("local");
        plan.set_observation(id(2), ReachabilityObservation::Reachable)
            .expect("internet");
        plan.set_observation(id(3), ReachabilityObservation::Reachable)
            .expect("relay");
        assert_eq!(
            plan.selected_path(),
            SelectedConnectivityPath::Candidate(candidate(
                2,
                ConnectivityPathKind::InternetDirect,
                2002
            ))
        );
    }

    #[test]
    fn relay_is_fallback_only_when_direct_candidates_are_not_reachable() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                candidate(1, ConnectivityPathKind::LocalDirect, 2001),
                candidate(2, ConnectivityPathKind::InternetDirect, 2002),
                candidate(3, ConnectivityPathKind::Relay, 2003),
            ],
        )
        .expect("plan");
        plan.set_observation(id(1), ReachabilityObservation::Unreachable)
            .expect("local");
        plan.set_observation(id(2), ReachabilityObservation::Unreachable)
            .expect("internet");
        plan.set_observation(id(3), ReachabilityObservation::Reachable)
            .expect("relay");
        assert_eq!(
            plan.selected_path(),
            SelectedConnectivityPath::Candidate(candidate(3, ConnectivityPathKind::Relay, 2003))
        );
    }

    #[test]
    fn selection_is_insertion_order_independent_and_same_kind_uses_lowest_id() {
        let candidates_a = vec![
            candidate(9, ConnectivityPathKind::InternetDirect, 2009),
            candidate(4, ConnectivityPathKind::InternetDirect, 2004),
        ];
        let candidates_b = vec![candidates_a[1], candidates_a[0]];
        let mut first = PeerConnectivityPlan::new(peer(), candidates_a).expect("first");
        let mut second = PeerConnectivityPlan::new(peer(), candidates_b).expect("second");
        for plan in [&mut first, &mut second] {
            plan.set_observation(id(9), ReachabilityObservation::Reachable)
                .expect("nine");
            plan.set_observation(id(4), ReachabilityObservation::Reachable)
                .expect("four");
        }
        let expected = SelectedConnectivityPath::Candidate(candidate(
            4,
            ConnectivityPathKind::InternetDirect,
            2004,
        ));
        assert_eq!(first.selected_path(), expected);
        assert_eq!(second.selected_path(), expected);
    }

    #[test]
    fn candidate_refresh_preserves_identity_and_replaces_transient_endpoints() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
        )
        .expect("initial plan");
        plan.set_observation(id(1), ReachabilityObservation::Reachable)
            .expect("initial reachability");
        let expected_identity = plan.peer().clone();

        plan.refresh_candidates(vec![
            candidate(2, ConnectivityPathKind::InternetDirect, 3002),
            candidate(3, ConnectivityPathKind::Relay, 3003),
        ])
        .expect("valid refreshed candidate set");

        assert_eq!(plan.peer(), &expected_identity);
        assert_eq!(plan.candidate_count(), 2);
        assert_eq!(plan.selected_path(), SelectedConnectivityPath::Offline);
        assert_eq!(
            plan.set_observation(id(1), ReachabilityObservation::Reachable),
            Err(ConnectivityError::UnknownCandidate)
        );

        plan.set_observation(id(2), ReachabilityObservation::Reachable)
            .expect("new internet candidate");
        assert_eq!(
            plan.selected_path(),
            SelectedConnectivityPath::Candidate(candidate(
                2,
                ConnectivityPathKind::InternetDirect,
                3002
            ))
        );
    }

    #[test]
    fn candidate_refresh_rejects_rebinding_existing_id_to_new_endpoint() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::InternetDirect, 2001)],
        )
        .expect("initial plan");
        plan.set_observation(id(1), ReachabilityObservation::Reachable)
            .expect("initial reachability");
        let before = plan.clone();

        assert_eq!(
            plan.refresh_candidates(vec![candidate(
                1,
                ConnectivityPathKind::InternetDirect,
                3001,
            )]),
            Err(ConnectivityError::CandidateIdRebound)
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn candidate_refresh_rejects_reuse_after_candidate_removal() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::InternetDirect, 2001)],
        )
        .expect("initial plan");
        plan.refresh_candidates(vec![candidate(
            2,
            ConnectivityPathKind::InternetDirect,
            3002,
        )])
        .expect("fresh replacement candidate");
        let before = plan.clone();

        assert_eq!(
            plan.refresh_candidates(vec![candidate(
                1,
                ConnectivityPathKind::InternetDirect,
                2001,
            )]),
            Err(ConnectivityError::CandidateIdRebound)
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn invalid_candidate_refresh_preserves_previous_state() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::InternetDirect, 2001)],
        )
        .expect("initial plan");
        plan.set_observation(id(1), ReachabilityObservation::Reachable)
            .expect("initial reachability");
        let before = plan.clone();

        assert_eq!(
            plan.refresh_candidates(vec![
                candidate(2, ConnectivityPathKind::LocalDirect, 3001),
                candidate(2, ConnectivityPathKind::Relay, 3002),
            ]),
            Err(ConnectivityError::DuplicateCandidateId)
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn candidate_id_high_watermark_is_none_for_plan_without_candidates() {
        let plan = PeerConnectivityPlan::new(peer(), Vec::new()).expect("empty plan");

        assert_eq!(plan.candidate_id_high_watermark(), None);
    }

    #[test]
    fn candidate_id_high_watermark_reports_maximum_initial_identifier() {
        let plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                candidate(2, ConnectivityPathKind::LocalDirect, 2002),
                candidate(7, ConnectivityPathKind::InternetDirect, 2007),
            ],
        )
        .expect("initial plan");

        assert_eq!(plan.candidate_id_high_watermark(), Some(id(7)));
    }

    #[test]
    fn candidate_id_high_watermark_does_not_decrease_when_higher_candidate_is_removed() {
        let retained = candidate(2, ConnectivityPathKind::LocalDirect, 2002);
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![
                retained,
                candidate(7, ConnectivityPathKind::InternetDirect, 2007),
            ],
        )
        .expect("initial plan");

        plan.refresh_candidates(vec![retained])
            .expect("retaining exact lower candidate is valid");

        assert_eq!(plan.candidate_id_high_watermark(), Some(id(7)));
    }

    #[test]
    fn candidate_id_high_watermark_advances_after_accepting_higher_identifier() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(2, ConnectivityPathKind::LocalDirect, 2002)],
        )
        .expect("initial plan");

        plan.refresh_candidates(vec![candidate(
            8,
            ConnectivityPathKind::InternetDirect,
            3008,
        )])
        .expect("higher candidate identifier is valid");

        assert_eq!(plan.candidate_id_high_watermark(), Some(id(8)));
    }

    #[test]
    fn failed_candidate_refresh_preserves_candidate_id_high_watermark() {
        let mut plan = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(7, ConnectivityPathKind::InternetDirect, 2007)],
        )
        .expect("initial plan");
        let before = plan.candidate_id_high_watermark();

        assert_eq!(
            plan.refresh_candidates(vec![candidate(6, ConnectivityPathKind::Relay, 3006,)]),
            Err(ConnectivityError::CandidateIdRebound)
        );
        assert_eq!(plan.candidate_id_high_watermark(), before);
    }

    #[test]
    fn durable_state_round_trip_preserves_empty_never_used_plan() {
        let original = PeerConnectivityPlan::new(peer(), Vec::new()).expect("empty plan");
        let state = original.durable_state();

        assert_eq!(state.peer(), original.peer());
        assert!(state.candidates().is_empty());
        assert_eq!(state.candidate_id_high_watermark(), None);

        let restored = PeerConnectivityPlan::from_durable_state(state).expect("restore empty plan");
        assert_eq!(restored.peer(), original.peer());
        assert_eq!(restored.candidate_count(), 0);
        assert_eq!(restored.candidate_id_high_watermark(), None);
        assert_eq!(restored.selected_path(), SelectedConnectivityPath::Offline);
    }

    #[test]
    fn durable_state_round_trip_preserves_active_candidates_order_and_high_water() {
        let expected_candidates = vec![
            candidate(5, ConnectivityPathKind::Relay, 2005),
            candidate(2, ConnectivityPathKind::LocalDirect, 2002),
        ];
        let original =
            PeerConnectivityPlan::new(peer(), expected_candidates.clone()).expect("initial plan");
        let state = original.durable_state();

        assert_eq!(state.candidates(), expected_candidates.as_slice());
        assert_eq!(state.candidate_id_high_watermark(), Some(id(5)));

        let restored =
            PeerConnectivityPlan::from_durable_state(state).expect("restore active plan");
        let restored_state = restored.durable_state();
        assert_eq!(restored_state.peer(), original.peer());
        assert_eq!(restored_state.candidates(), expected_candidates.as_slice());
        assert_eq!(restored_state.candidate_id_high_watermark(), Some(id(5)));
    }

    #[test]
    fn durable_state_drops_transient_observations_on_restore() {
        let mut original = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(1, ConnectivityPathKind::LocalDirect, 2001)],
        )
        .expect("initial plan");
        original
            .set_observation(id(1), ReachabilityObservation::Reachable)
            .expect("reachable observation");
        assert!(matches!(
            original.selected_path(),
            SelectedConnectivityPath::Candidate(_)
        ));

        let restored = PeerConnectivityPlan::from_durable_state(original.durable_state())
            .expect("restore without transient observation");
        assert_eq!(restored.selected_path(), SelectedConnectivityPath::Offline);
    }

    #[test]
    fn durable_state_round_trip_preserves_historical_high_water_above_active_maximum() {
        let retained = candidate(2, ConnectivityPathKind::LocalDirect, 2002);
        let mut original = PeerConnectivityPlan::new(
            peer(),
            vec![
                retained,
                candidate(7, ConnectivityPathKind::InternetDirect, 2007),
            ],
        )
        .expect("initial plan");
        original
            .refresh_candidates(vec![retained])
            .expect("retain lower candidate");

        let state = original.durable_state();
        assert_eq!(state.candidates(), &[retained]);
        assert_eq!(state.candidate_id_high_watermark(), Some(id(7)));

        let restored =
            PeerConnectivityPlan::from_durable_state(state).expect("restore historical high-water");
        assert_eq!(restored.candidate_id_high_watermark(), Some(id(7)));
        assert_eq!(restored.durable_state().candidates(), &[retained]);
    }

    #[test]
    fn durable_state_round_trip_preserves_empty_plan_with_historical_high_water() {
        let mut original = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(7, ConnectivityPathKind::InternetDirect, 2007)],
        )
        .expect("initial plan");
        original
            .refresh_candidates(Vec::new())
            .expect("remove all current candidates");

        let state = original.durable_state();
        assert!(state.candidates().is_empty());
        assert_eq!(state.candidate_id_high_watermark(), Some(id(7)));

        let restored =
            PeerConnectivityPlan::from_durable_state(state).expect("restore empty historical plan");
        assert_eq!(restored.candidate_count(), 0);
        assert_eq!(restored.candidate_id_high_watermark(), Some(id(7)));
        assert_eq!(restored.selected_path(), SelectedConnectivityPath::Offline);
    }

    #[test]
    fn durable_state_rejects_high_water_below_active_maximum() {
        let state = PeerConnectivityPlanDurableState::from_parts(
            peer(),
            vec![candidate(7, ConnectivityPathKind::InternetDirect, 2007)],
            Some(id(6)),
        );

        assert_eq!(
            PeerConnectivityPlan::from_durable_state(state),
            Err(ConnectivityError::InvalidCandidateIdHighWatermark)
        );
    }

    #[test]
    fn durable_state_rejects_missing_high_water_for_active_candidates() {
        let state = PeerConnectivityPlanDurableState::from_parts(
            peer(),
            vec![candidate(1, ConnectivityPathKind::InternetDirect, 2001)],
            None,
        );

        assert_eq!(
            PeerConnectivityPlan::from_durable_state(state),
            Err(ConnectivityError::InvalidCandidateIdHighWatermark)
        );
    }

    #[test]
    fn restored_plan_rejects_reuse_of_historical_removed_candidate_id() {
        let retained = candidate(8, ConnectivityPathKind::InternetDirect, 3008);
        let mut original = PeerConnectivityPlan::new(
            peer(),
            vec![candidate(7, ConnectivityPathKind::InternetDirect, 2007)],
        )
        .expect("initial plan");
        original
            .refresh_candidates(vec![retained])
            .expect("advance candidate namespace");

        let mut restored = PeerConnectivityPlan::from_durable_state(original.durable_state())
            .expect("restore historical namespace");
        assert_eq!(restored.candidate_id_high_watermark(), Some(id(8)));
        assert_eq!(
            restored.refresh_candidates(vec![candidate(
                7,
                ConnectivityPathKind::InternetDirect,
                2007,
            )]),
            Err(ConnectivityError::CandidateIdRebound)
        );
    }

    #[test]
    fn logical_device_and_transport_identity_are_independent() {
        let identity = peer();
        assert_eq!(identity.device_id().as_str(), "device-1");
        assert_eq!(identity.transport_identity(), transport(1));
        assert_eq!(identity.transport_identity().as_bytes(), &[1; 32]);
    }
}
