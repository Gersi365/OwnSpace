//! Authenticated candidate-publication semantics for PRW dynamic reachability.
//!
//! Phase 152 C02e factors the locked provenance/admission ordering into one bounded semantic
//! adapter. Tranche 4 exports this adapter as an input to the production reachability owner while
//! still defining no candidate wire encoding, socket operation, discovery authority or runtime
//! activation. Publication freshness remains a separate verifier-owned input to the upper owner.

use std::{fmt, net::SocketAddr};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
    ConnectivityPathKind, PeerConnectivityIdentity, PeerConnectivityPlan, TransportIdentity,
};
use prw_registry::{RegistryError, WorkspaceDeviceRegistry};
use prw_session::AuthenticatedDeviceSession;

/// Projects one already-observed bound socket address into the existing validated connectivity
/// endpoint domain type.
///
/// This semantic adapter performs no socket operation, interface discovery, address rewrite,
/// candidate construction, publication or provider mutation. It delegates the exact observed IP
/// address and port to [`ConnectivityEndpoint::new`], whose existing validation remains
/// authoritative.
///
/// # Errors
///
/// Returns the existing [`ConnectivityError`] when the observed address or port is not a valid
/// connectivity endpoint. No fallback address is attempted.
pub fn project_observed_socket_addr_to_connectivity_endpoint(
    observed: SocketAddr,
) -> Result<ConnectivityEndpoint, ConnectivityError> {
    ConnectivityEndpoint::new(observed.ip(), observed.port())
}

/// Assembles one connectivity candidate from already-typed explicit components.
///
/// This adapter does not allocate a candidate identifier, infer or rewrite a path kind, discover
/// an endpoint, mutate a connectivity plan, publish a candidate, or perform network I/O. The
/// caller remains responsible for the separately gated provenance of the supplied candidate ID
/// and path kind. The existing [`ConnectivityCandidate::new`] constructor remains authoritative
/// for the typed composition itself.
#[must_use]
pub const fn assemble_explicit_connectivity_candidate(
    candidate_id: CandidateId,
    path_kind: ConnectivityPathKind,
    endpoint: ConnectivityEndpoint,
) -> ConnectivityCandidate {
    ConnectivityCandidate::new(candidate_id, path_kind, endpoint)
}

/// Stable source-level failure classification for candidate publication/admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateReachabilityError {
    /// A current registry/session/transport identity check failed.
    Registry(RegistryError),
    /// Requester and publisher are not in the same current workspace.
    WorkspaceMismatch,
    /// Publication identity does not exactly match the target connectivity plan.
    PublicationTargetMismatch,
    /// Candidate validation or transactional refresh failed.
    Connectivity(ConnectivityError),
}

impl fmt::Display for CandidateReachabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => {
                write!(formatter, "candidate registry admission failed: {error}")
            }
            Self::WorkspaceMismatch => {
                formatter.write_str("candidate publisher and requester workspace mismatch")
            }
            Self::PublicationTargetMismatch => {
                formatter.write_str("candidate publication target identity mismatch")
            }
            Self::Connectivity(error) => {
                write!(
                    formatter,
                    "candidate connectivity validation failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for CandidateReachabilityError {}

/// Candidate set whose peer identity is derived from a registry-current authenticated publisher.
///
/// This object is a semantic snapshot only. It intentionally carries no generic control-frame
/// request identifier and makes no freshness/replay claim. The production owner requires a
/// separately presented verifier freshness token before this publication can commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCandidatePublication {
    publisher_session: AuthenticatedDeviceSession,
    peer: PeerConnectivityIdentity,
    candidates: Vec<ConnectivityCandidate>,
}

impl AuthenticatedCandidatePublication {
    /// Returns the authenticated publisher session snapshot used to derive provenance.
    #[must_use]
    pub const fn publisher_session(&self) -> &AuthenticatedDeviceSession {
        &self.publisher_session
    }

    /// Returns the exact logical/transport identity derived for the publisher.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the bounded validated candidate vector.
    #[must_use]
    pub fn candidates(&self) -> &[ConnectivityCandidate] {
        &self.candidates
    }
}

/// Creates one bounded candidate publication from a current authenticated publisher.
///
/// The caller cannot supply an arbitrary target `DeviceId`: the logical target is derived from
/// the publisher session after current-registry validation. The presented transport identity is
/// separately revalidated for that exact publisher device. The complete candidate set is checked
/// before a publication object can exist.
///
/// # Errors
///
/// Fails closed on stale publisher session/registry state, stale transport identity, or invalid
/// candidate-set semantics.
pub fn publish_current_candidates(
    registry: &WorkspaceDeviceRegistry,
    publisher_session: &AuthenticatedDeviceSession,
    presented_transport_identity: TransportIdentity,
    candidates: Vec<ConnectivityCandidate>,
) -> Result<AuthenticatedCandidatePublication, CandidateReachabilityError> {
    let publisher = registry
        .validate_authenticated_session(publisher_session)
        .map_err(CandidateReachabilityError::Registry)?;
    registry
        .validate_transport_identity(publisher.device_id(), presented_transport_identity)
        .map_err(CandidateReachabilityError::Registry)?;

    let peer =
        PeerConnectivityIdentity::new(publisher.device_id().clone(), presented_transport_identity);
    PeerConnectivityPlan::new(peer.clone(), candidates.clone())
        .map_err(CandidateReachabilityError::Connectivity)?;

    Ok(AuthenticatedCandidatePublication {
        publisher_session: publisher_session.clone(),
        peer,
        candidates,
    })
}

/// Revalidates requester, publisher, workspace and exact target currentness without mutating the
/// target connectivity plan.
///
/// The production upper owner places its independent publication-freshness comparison after this
/// current identity/workspace admission and before candidate-plan mutation.
///
/// Admission order is intentionally fixed:
///
/// 1. requester authenticated session is registry-current;
/// 2. publisher authenticated session is registry-current;
/// 3. requester and publisher share the same current workspace;
/// 4. publication peer exactly matches the target plan and publisher device;
/// 5. target transport identity remains registry-current.
///
/// # Errors
///
/// Fails closed on stale/cross-workspace/retargeted identity. The supplied plan is never mutated.
pub fn validate_authenticated_publication_admission(
    registry: &WorkspaceDeviceRegistry,
    requester_session: &AuthenticatedDeviceSession,
    publication: &AuthenticatedCandidatePublication,
    plan: &PeerConnectivityPlan,
) -> Result<(), CandidateReachabilityError> {
    let requester = registry
        .validate_authenticated_session(requester_session)
        .map_err(CandidateReachabilityError::Registry)?;
    let publisher = registry
        .validate_authenticated_session(publication.publisher_session())
        .map_err(CandidateReachabilityError::Registry)?;

    if requester.workspace_id() != publisher.workspace_id() {
        return Err(CandidateReachabilityError::WorkspaceMismatch);
    }
    if publisher.device_id() != publication.peer().device_id() || plan.peer() != publication.peer()
    {
        return Err(CandidateReachabilityError::PublicationTargetMismatch);
    }

    registry
        .validate_transport_identity(
            publication.peer().device_id(),
            publication.peer().transport_identity(),
        )
        .map_err(CandidateReachabilityError::Registry)
}

/// Applies one publication only after requester, publisher, workspace and target currentness.
///
/// Admission order is intentionally fixed:
///
/// 1. requester authenticated session is registry-current;
/// 2. publisher authenticated session is registry-current;
/// 3. requester and publisher share the same current workspace;
/// 4. publication peer exactly matches the target plan and publisher device;
/// 5. target transport identity remains registry-current;
/// 6. only then may the connectivity plan transactionally validate and replace candidates.
///
/// Any failure before the final step leaves the target plan untouched. Candidate-ID non-rebinding
/// and full-vector transactional validation are delegated to `PeerConnectivityPlan`.
///
/// The production Tranche 4 owner does not call this mutation helper directly because it stages a
/// cloned plan before durable CAS; the helper remains useful for bounded source/test composition.
///
/// # Errors
///
/// Fails closed on stale/cross-workspace/retargeted identity or invalid refresh semantics.
pub fn refresh_from_authenticated_publication(
    registry: &WorkspaceDeviceRegistry,
    requester_session: &AuthenticatedDeviceSession,
    publication: &AuthenticatedCandidatePublication,
    plan: &mut PeerConnectivityPlan,
) -> Result<(), CandidateReachabilityError> {
    validate_authenticated_publication_admission(registry, requester_session, publication, plan)?;

    plan.refresh_candidates(publication.candidates.clone())
        .map_err(CandidateReachabilityError::Connectivity)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use prw_connectivity::{
        CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityError,
        ConnectivityPathKind,
    };

    use super::{
        assemble_explicit_connectivity_candidate,
        project_observed_socket_addr_to_connectivity_endpoint,
    };

    fn assert_projection_signature(
        projection: fn(SocketAddr) -> Result<ConnectivityEndpoint, ConnectivityError>,
    ) {
        let _ = projection;
    }

    fn assert_assembly_signature(
        assembly: fn(
            CandidateId,
            ConnectivityPathKind,
            ConnectivityEndpoint,
        ) -> ConnectivityCandidate,
    ) {
        let _ = assembly;
    }

    #[test]
    fn projection_has_exact_selected_shape() {
        assert_projection_signature(project_observed_socket_addr_to_connectivity_endpoint);
    }

    #[test]
    fn projection_preserves_exact_ipv4_address_and_port() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
        let observed = SocketAddr::new(address, 43_210);

        let projected = project_observed_socket_addr_to_connectivity_endpoint(observed)
            .expect("documentation IPv4 endpoint is valid");

        assert_eq!(projected.address(), address);
        assert_eq!(projected.port(), 43_210);
    }

    #[test]
    fn projection_preserves_exact_ipv6_address_and_port() {
        let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 41));
        let observed = SocketAddr::new(address, 43_211);

        let projected = project_observed_socket_addr_to_connectivity_endpoint(observed)
            .expect("documentation IPv6 endpoint is valid");

        assert_eq!(projected.address(), address);
        assert_eq!(projected.port(), 43_211);
    }

    #[test]
    fn projection_preserves_existing_zero_port_rejection() {
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        assert_eq!(
            project_observed_socket_addr_to_connectivity_endpoint(observed),
            Err(ConnectivityError::InvalidEndpointPort)
        );
    }

    #[test]
    fn projection_preserves_existing_unspecified_address_rejection() {
        for address in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ] {
            assert_eq!(
                project_observed_socket_addr_to_connectivity_endpoint(SocketAddr::new(address, 1)),
                Err(ConnectivityError::InvalidEndpointAddress)
            );
        }
    }

    #[test]
    fn projection_preserves_existing_multicast_address_rejection() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(
                project_observed_socket_addr_to_connectivity_endpoint(SocketAddr::new(address, 1)),
                Err(ConnectivityError::InvalidEndpointAddress)
            );
        }
    }

    #[test]
    fn projection_preserves_existing_ipv4_limited_broadcast_rejection() {
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 1);

        assert_eq!(
            project_observed_socket_addr_to_connectivity_endpoint(observed),
            Err(ConnectivityError::InvalidEndpointAddress)
        );
    }

    #[test]
    fn explicit_candidate_assembly_has_exact_selected_shape() {
        assert_assembly_signature(assemble_explicit_connectivity_candidate);
    }

    #[test]
    fn explicit_candidate_assembly_preserves_candidate_id_and_endpoint() {
        let candidate_id = CandidateId::new(73).expect("non-zero candidate id");
        let endpoint = ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 73)), 43_273)
            .expect("documentation endpoint is valid");

        let candidate = assemble_explicit_connectivity_candidate(
            candidate_id,
            ConnectivityPathKind::LocalDirect,
            endpoint,
        );

        assert_eq!(candidate.id(), candidate_id);
        assert_eq!(candidate.endpoint(), endpoint);
    }

    #[test]
    fn explicit_candidate_assembly_preserves_each_explicit_path_kind() {
        let candidate_id = CandidateId::new(74).expect("non-zero candidate id");
        let endpoint = ConnectivityEndpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 43_274)
            .expect("loopback endpoint is valid for typed disposable validation");

        for path_kind in [
            ConnectivityPathKind::LocalDirect,
            ConnectivityPathKind::InternetDirect,
            ConnectivityPathKind::Relay,
        ] {
            let candidate =
                assemble_explicit_connectivity_candidate(candidate_id, path_kind, endpoint);

            assert_eq!(candidate.id(), candidate_id);
            assert_eq!(candidate.kind(), path_kind);
            assert_eq!(candidate.endpoint(), endpoint);
        }
    }
}
