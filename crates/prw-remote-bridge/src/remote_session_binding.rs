//! Opaque binding between one authenticated transport peer and one logical remote session lease.
//!
//! Phase 152 C03e prevents later runtime callers from independently selecting a transport
//! identity for every capability request. The current registry and existing `CapabilityBridge`
//! remain authoritative on every request; this module adds no authorization rule of its own.

use prw_connectivity::TransportIdentity;
use prw_policy::PolicyEvaluator;
use prw_remote_transport::ControlFrame;
use prw_session::AuthenticatedDeviceSession;

use crate::{
    AuthorizedCapabilityRequest, CapabilityBridge, CapabilityDispatcher, RemoteBridgeError,
    RemoteSessionLease,
};

/// One immutable transport-identity snapshot bound to one verifier-owned remote session lease.
///
/// Construction does not prove that the transport identity currently belongs to the logical
/// device. Current-registry validation remains mandatory inside [`CapabilityBridge`] for every
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRemoteSession {
    transport_identity: TransportIdentity,
    lease: RemoteSessionLease,
}

impl BoundRemoteSession {
    /// Binds one already-authenticated transport identity to one authenticated logical session.
    ///
    /// Lease validation is delegated exactly once to [`RemoteSessionLease::new`]. This constructor
    /// performs no network I/O, registry mutation, policy evaluation or capability dispatch.
    ///
    /// # Errors
    ///
    /// Returns the existing [`RemoteBridgeError::InvalidSessionLease`] classification when the
    /// verifier-owned lease interval is zero, reversed or exceeds the locked maximum lifetime.
    pub fn new(
        transport_identity: TransportIdentity,
        session: AuthenticatedDeviceSession,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, RemoteBridgeError> {
        let lease =
            RemoteSessionLease::new(session, issued_at_unix_seconds, expires_at_unix_seconds)?;
        Ok(Self {
            transport_identity,
            lease,
        })
    }

    /// Returns the immutable transport identity selected for this remote session context.
    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.transport_identity
    }

    /// Returns the immutable verifier-owned remote session lease.
    #[must_use]
    pub const fn lease(&self) -> &RemoteSessionLease {
        &self.lease
    }

    /// Returns the immutable authenticated logical session identity carried by the lease.
    #[must_use]
    pub const fn session(&self) -> &AuthenticatedDeviceSession {
        self.lease.session()
    }

    /// Delegates authorization to the existing current-registry and policy bridge.
    ///
    /// The stored transport identity is supplied internally, so callers cannot present a second
    /// independently selected transport identity for this bound session context.
    ///
    /// # Errors
    ///
    /// Propagates the existing [`RemoteBridgeError`] returned by [`CapabilityBridge::authorize`]
    /// without translation.
    pub fn authorize<P: PolicyEvaluator>(
        &self,
        bridge: &CapabilityBridge<'_, P>,
        now_unix_seconds: u64,
        frame: &ControlFrame,
    ) -> Result<AuthorizedCapabilityRequest, RemoteBridgeError> {
        bridge.authorize(
            self.transport_identity,
            &self.lease,
            now_unix_seconds,
            frame,
        )
    }

    /// Delegates authorization and dispatch to the existing capability bridge.
    ///
    /// The stored transport identity and lease are always supplied as one pair. This method owns
    /// no dispatcher, socket, connection, task, retry loop or remote-readiness state.
    ///
    /// # Errors
    ///
    /// Propagates the existing [`RemoteBridgeError`] returned by
    /// [`CapabilityBridge::process_request`] without translation.
    pub fn process_request<P: PolicyEvaluator, D: CapabilityDispatcher>(
        &self,
        bridge: &CapabilityBridge<'_, P>,
        now_unix_seconds: u64,
        frame: &ControlFrame,
        dispatcher: &mut D,
    ) -> Result<ControlFrame, RemoteBridgeError> {
        bridge.process_request(
            self.transport_identity,
            &self.lease,
            now_unix_seconds,
            frame,
            dispatcher,
        )
    }
}
