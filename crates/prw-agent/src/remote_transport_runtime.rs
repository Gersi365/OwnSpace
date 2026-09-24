//! Authority-gated real remote transport owner for the Ubuntu PRW Agent.
//!
//! C03e-C is the first Agent-owned composition that can bind a real mesh QUIC server endpoint. The
//! constructor requires the opaque reachability-authority runtime owner and retains it for the full
//! endpoint lifetime. C03e-D adds one lower-transport-authenticated accepted-peer handoff. C03e-E
//! adds only registry-bound logical-session challenge preparation. This module does not execute the
//! logical-session wire exchange, dispatch capabilities, spawn tasks, or publish remote readiness.

use std::{fmt, net::SocketAddr, ops::Range};

use prw_control_plane::session_auth::SessionAuthChallenge;
use prw_core::{DeviceId, SessionId};
use prw_reachability_custody::mesh_transport_custody::{
    MeshTransportCustodyError, load_mesh_transport_credentials_from_systemd,
};
use prw_registry::{RegistryError, WorkspaceDeviceRegistry};
use prw_remote_bridge::remote_server_transport_runtime::{
    AuthenticatedRemotePeerConnection, RemoteServerTransportRuntime,
    RemoteServerTransportRuntimeError, TransportIdentity,
};
use prw_session::{SessionAuthenticationService, SessionServiceError};

use crate::reachability_authority_admission::ReachabilityAuthorityRuntimeOwner;

/// Stable failure class while constructing the authority-gated Agent remote endpoint owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentRemoteTransportBindError {
    /// Fixed systemd mesh credential custody failed before transport construction.
    Credential(MeshTransportCustodyError),
    /// Locked TLS construction or the real UDP/QUIC endpoint bind failed.
    Transport(RemoteServerTransportRuntimeError),
}

impl fmt::Display for AgentRemoteTransportBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential(_) => {
                formatter.write_str("Agent mesh transport credential load failed")
            }
            Self::Transport(_) => formatter.write_str("Agent remote transport bind failed"),
        }
    }
}

impl std::error::Error for AgentRemoteTransportBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Credential(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

impl From<MeshTransportCustodyError> for AgentRemoteTransportBindError {
    fn from(error: MeshTransportCustodyError) -> Self {
        Self::Credential(error)
    }
}

impl From<RemoteServerTransportRuntimeError> for AgentRemoteTransportBindError {
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Transport(error)
    }
}

/// Stable failure class while accepting one authenticated lower-transport peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentRemotePeerAcceptError {
    /// Existing bridge/C03c peer acceptance or transport-identity validation failed.
    Transport(RemoteServerTransportRuntimeError),
}

impl fmt::Display for AgentRemotePeerAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Agent remote peer accept failed"),
        }
    }
}

impl std::error::Error for AgentRemotePeerAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
        }
    }
}

impl From<RemoteServerTransportRuntimeError> for AgentRemotePeerAcceptError {
    fn from(error: RemoteServerTransportRuntimeError) -> Self {
        Self::Transport(error)
    }
}

/// Stable failure while preparing one registry-bound logical-session challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentRemoteSessionChallengeError {
    /// Current registry state rejected the selected logical device/transport pair.
    Registry(RegistryError),
    /// Existing Phase 128 session challenge preparation failed.
    Session(SessionServiceError),
}

impl fmt::Display for AgentRemoteSessionChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(_) => {
                formatter.write_str("Agent remote session registry binding failed")
            }
            Self::Session(_) => formatter.write_str("Agent remote session challenge failed"),
        }
    }
}

impl std::error::Error for AgentRemoteSessionChallengeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Session(error) => Some(error),
        }
    }
}

impl From<RegistryError> for AgentRemoteSessionChallengeError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<SessionServiceError> for AgentRemoteSessionChallengeError {
    fn from(error: SessionServiceError) -> Self {
        Self::Session(error)
    }
}

/// Failed bind transaction that retains the already-admitted authority owner.
pub struct AgentRemoteTransportBindFailure {
    authority_owner: Box<ReachabilityAuthorityRuntimeOwner>,
    error: AgentRemoteTransportBindError,
}

impl fmt::Debug for AgentRemoteTransportBindFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRemoteTransportBindFailure")
            .field("authority_owner", &"<retained>")
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for AgentRemoteTransportBindFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AgentRemoteTransportBindFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl AgentRemoteTransportBindFailure {
    fn new(
        authority_owner: ReachabilityAuthorityRuntimeOwner,
        error: AgentRemoteTransportBindError,
    ) -> Self {
        Self {
            authority_owner: Box::new(authority_owner),
            error,
        }
    }

    /// Returns the stable underlying bind failure without exposing authority internals.
    #[must_use]
    pub const fn error(&self) -> AgentRemoteTransportBindError {
        self.error
    }

    /// Recovers the exact admitted authority owner after a failed endpoint transaction.
    #[must_use]
    pub fn into_authority_owner(self) -> ReachabilityAuthorityRuntimeOwner {
        *self.authority_owner
    }
}

/// Agent-owned proof that authority admission and one real QUIC server bind both succeeded.
pub struct AgentRemoteTransportRuntime {
    authority_owner: ReachabilityAuthorityRuntimeOwner,
    transport: RemoteServerTransportRuntime,
}

impl AgentRemoteTransportRuntime {
    /// Loads the fixed mesh credentials and binds one real server endpoint behind authority admission.
    ///
    /// The admitted authority owner is consumed on entry. Any custody/TLS/socket failure returns it
    /// inside [`AgentRemoteTransportBindFailure`], so failure never fabricates a runtime and does not
    /// require an automatic authority re-bootstrap. The private PKCS#8 key is moved, not cloned, out
    /// of its C03e-B zeroizing transfer container immediately before transport-owned TLS conversion.
    ///
    /// # Errors
    ///
    /// Returns [`AgentRemoteTransportBindFailure`] on fixed credential custody failure, locked TLS
    /// construction failure, or real UDP/QUIC endpoint bind failure.
    pub fn bind_from_systemd_credentials(
        authority_owner: ReachabilityAuthorityRuntimeOwner,
        bind_addr: SocketAddr,
    ) -> Result<Self, AgentRemoteTransportBindFailure> {
        let credentials = match load_mesh_transport_credentials_from_systemd() {
            Ok(credentials) => credentials,
            Err(error) => {
                return Err(AgentRemoteTransportBindFailure::new(
                    authority_owner,
                    AgentRemoteTransportBindError::Credential(error),
                ));
            }
        };
        let (root_certificate_der, certificate_der, mut private_key_pkcs8_der) =
            credentials.into_transport_tls_der();
        let private_key_pkcs8_der = std::mem::take(&mut *private_key_pkcs8_der);
        let transport = match RemoteServerTransportRuntime::bind_from_der(
            bind_addr,
            root_certificate_der,
            certificate_der,
            private_key_pkcs8_der,
        ) {
            Ok(transport) => transport,
            Err(error) => {
                return Err(AgentRemoteTransportBindFailure::new(
                    authority_owner,
                    AgentRemoteTransportBindError::Transport(error),
                ));
            }
        };
        Ok(Self {
            authority_owner,
            transport,
        })
    }

    /// Returns the retained admitted authority owner by immutable reference.
    #[must_use]
    pub const fn authority_owner(&self) -> &ReachabilityAuthorityRuntimeOwner {
        &self.authority_owner
    }

    /// Accepts one peer only after the existing C03c lower-transport identity checks succeed.
    ///
    /// The expected peer value is a certificate-derived transport identity, not a logical device
    /// identity and not a capability grant. The endpoint-level reachability authority owner remains
    /// retained by `self` whether acceptance succeeds or fails.
    ///
    /// # Errors
    ///
    /// Returns [`AgentRemotePeerAcceptError`] for C03c/bridge timeout, endpoint, handshake, ALPN, or
    /// exact expected transport-identity validation failure.
    pub async fn accept_authenticated_peer(
        &self,
        expected_peer: TransportIdentity,
    ) -> Result<AuthenticatedRemotePeerConnection, AgentRemotePeerAcceptError> {
        self.transport
            .accept_authenticated_peer(expected_peer)
            .await
            .map_err(Into::into)
    }

    /// Begins one Phase 128 logical-session challenge from the current registry-owned binding.
    ///
    /// The caller selects only an exact logical [`DeviceId`] and typed [`SessionId`]. The accepted
    /// peer supplies the already-revalidated lower-transport identity. The current registry must
    /// confirm that exact device/transport pair before this method clones the registered device
    /// binding and delegates challenge creation to the existing [`SessionAuthenticationService`].
    /// The verifier supplies one half-open Unix-second validity range whose start/end are forwarded
    /// unchanged as the existing Phase 128 issue/expiry boundary. No caller-supplied
    /// `DeviceIdentityBinding` is accepted.
    ///
    /// This method performs no stream I/O and therefore introduces no partial-I/O pending-session
    /// cleanup policy. A successful return means only that the existing Phase 128 service now owns
    /// one pending challenge; it is not authentication success and is not authorization.
    ///
    /// # Errors
    ///
    /// Returns [`AgentRemoteSessionChallengeError::Registry`] when current device lifecycle or
    /// transport binding is invalid, and [`AgentRemoteSessionChallengeError::Session`] when the
    /// existing Phase 128 challenge service rejects challenge creation.
    pub fn begin_registry_bound_session_challenge(
        &self,
        peer: &AuthenticatedRemotePeerConnection,
        registry: &WorkspaceDeviceRegistry,
        session_authentication: &mut SessionAuthenticationService,
        device_id: &DeviceId,
        session_id: SessionId,
        validity_window_unix_seconds: Range<u64>,
    ) -> Result<SessionAuthChallenge, AgentRemoteSessionChallengeError> {
        registry.validate_transport_identity(device_id, peer.transport_identity())?;
        let binding = registry
            .device(device_id)
            .ok_or(RegistryError::DeviceUnknown)?
            .binding()
            .clone();
        session_authentication
            .begin_session(
                binding,
                session_id,
                validity_window_unix_seconds.start,
                validity_window_unix_seconds.end,
            )
            .map_err(Into::into)
    }

    /// Returns the kernel-selected local UDP address of the real mesh endpoint.
    ///
    /// # Errors
    ///
    /// Propagates the existing bridge/transport endpoint-address failure.
    pub fn local_addr(&self) -> Result<SocketAddr, AgentRemoteTransportBindError> {
        self.transport
            .local_addr()
            .map_err(AgentRemoteTransportBindError::Transport)
    }

    /// Explicitly closes the remote endpoint without affecting existing local Agent readiness.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.transport.close(code, reason);
    }

    /// Waits until all remote endpoint connections are idle.
    pub async fn wait_idle(&self) {
        self.transport.wait_idle().await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use prw_registry::RegistryError;
    use prw_remote_bridge::remote_server_transport_runtime::RemoteServerTransportRuntimeError;
    use prw_session::SessionServiceError;

    use super::{
        AgentRemotePeerAcceptError, AgentRemoteSessionChallengeError,
        AgentRemoteTransportBindError, AgentRemoteTransportBindFailure,
        AgentRemoteTransportRuntime,
    };
    use crate::reachability_authority_admission::ReachabilityAuthorityRuntimeOwner;

    fn assert_constructor_signature(
        constructor: fn(
            ReachabilityAuthorityRuntimeOwner,
            SocketAddr,
        )
            -> Result<AgentRemoteTransportRuntime, AgentRemoteTransportBindFailure>,
    ) {
        let _ = constructor;
    }

    fn assert_failure_accessors(
        error: fn(&AgentRemoteTransportBindFailure) -> AgentRemoteTransportBindError,
        recover: fn(AgentRemoteTransportBindFailure) -> ReachabilityAuthorityRuntimeOwner,
    ) {
        let _ = (error, recover);
    }

    fn assert_peer_error_mapping(
        mapping: fn(RemoteServerTransportRuntimeError) -> AgentRemotePeerAcceptError,
    ) {
        let _ = mapping;
    }

    fn assert_session_challenge_error_mappings(
        registry: fn(RegistryError) -> AgentRemoteSessionChallengeError,
        session: fn(SessionServiceError) -> AgentRemoteSessionChallengeError,
    ) {
        let _ = (registry, session);
    }

    #[test]
    fn remote_endpoint_constructor_requires_exact_authority_owner() {
        assert_constructor_signature(AgentRemoteTransportRuntime::bind_from_systemd_credentials);
    }

    #[test]
    fn failed_bind_surface_preserves_recoverable_authority_ownership() {
        assert_failure_accessors(
            AgentRemoteTransportBindFailure::error,
            AgentRemoteTransportBindFailure::into_authority_owner,
        );
    }

    #[test]
    fn accepted_peer_failure_uses_narrow_transport_error_mapping() {
        assert_peer_error_mapping(AgentRemotePeerAcceptError::from);
    }

    #[test]
    fn registry_bound_challenge_requires_peer_registry_and_typed_session_inputs() {
        let _ = AgentRemoteTransportRuntime::begin_registry_bound_session_challenge;
    }

    #[test]
    fn registry_bound_challenge_preserves_registry_and_session_error_classes() {
        assert_session_challenge_error_mappings(
            AgentRemoteSessionChallengeError::from,
            AgentRemoteSessionChallengeError::from,
        );
    }
}
