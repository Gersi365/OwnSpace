//! Agent-owned runtime custody for one production durable-registry semantic store.
//!
//! C03e-JD materializes only the C03e-JC-selected side-effect-free ownership adaptation. One
//! already-produced provider-neutral durable registry authority is consumed exactly once and retained
//! privately by Agent runtime custody for a later separately gated operation-specific use site.
//!
//! C03e-JF adds only the C03e-JE-selected operation-specific production peer-identity lookup. It
//! resolves one explicitly supplied logical [`DeviceId`] through the privately held durable registry's
//! authoritative current same-device transport binding and returns one [`PeerConnectivityIdentity`].
//!
//! C03e-KA adds only the C03e-JZ-selected dormant production durable capability-authority custody.
//! One existing durable-registry runtime custody is shared through one outer `Arc<Mutex<_>>` beside
//! the fixed fail-closed [`ProductionRemoteCapabilityDenyAllPolicy`].
//!
//! C03e-KC adds only the C03e-KB-selected dormant authorization invocation seam. It borrows one
//! existing post-auth capability transaction, acquires the existing durable-registry custody mutex,
//! invokes the existing provider-aware durable capability bridge exactly once, and releases the guard
//! before any downstream dispatch or response work.
//!
//! This module does not load credentials, bootstrap a provider, expose a generic store/executor
//! extraction seam, register global state, publish readiness, wire startup, create a background task,
//! activate networking, deploy, mutate registry state, or mutate production state.

use std::sync::Arc;

use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_core::DeviceId;
use prw_policy::ProductionRemoteCapabilityDenyAllPolicy;
use prw_registry::durable_registry_authority::{
    DurableRegistryAuthority, DurableRegistryAuthorityError,
};
use prw_remote_bridge::post_auth_control_stream_ingress::PostAuthCapabilityTransaction;
use prw_remote_bridge::{
    AuthorizedCapabilityRequest, DurableCapabilityBridge, DurableCapabilityBridgeError,
    RemoteSessionLease,
};
use tokio::sync::Mutex;

/// Agent-owned dormant runtime custody of one production durable-registry semantic store.
///
/// The contained store remains private and non-cloneable. Later separately gated checkpoints may add
/// only operation-specific methods needed by exact runtime use cases; this owner intentionally exposes
/// no generic store getter or extraction path.
pub struct ProductionDurableRegistryRuntimeCustody {
    authority: Box<dyn DurableRegistryAuthority>,
}

impl ProductionDurableRegistryRuntimeCustody {
    /// Consumes one already-composed provider-neutral durable-registry authority into Agent custody.
    ///
    /// This method performs ownership adaptation only. It does not read credentials, perform network
    /// I/O, issue provider operations, validate registry state, publish readiness, register global
    /// state, or create a runtime task.
    #[must_use]
    pub fn from_authority<A>(authority: A) -> Self
    where
        A: DurableRegistryAuthority + 'static,
    {
        Self {
            authority: Box::new(authority),
        }
    }

    /// Resolves one production peer identity from the durable registry's current same-device binding.
    ///
    /// The caller supplies only the logical device identity. The current transport identity is read
    /// exactly once from the privately held semantic store and cannot be supplied or substituted by
    /// the caller. Construction of the returned peer occurs only after that authoritative read
    /// succeeds.
    ///
    /// # Errors
    ///
    /// Propagates the existing provider-neutral durable-registry semantic/read authority failure
    /// unchanged. No fallback peer, retry, stale cache, alternate device or alternate transport source
    /// is used.
    pub(crate) async fn peer_connectivity_identity(
        &mut self,
        device_id: DeviceId,
    ) -> Result<PeerConnectivityIdentity, DurableRegistryAuthorityError> {
        let current_transport = self
            .authority
            .current_transport_identity(&device_id)
            .await?;
        Ok(PeerConnectivityIdentity::new(device_id, current_transport))
    }
}

/// Dormant Agent custody for the production durable capability-authority prerequisites.
///
/// The durable-registry runtime custody remains private behind one shared asynchronous mutex. The
/// policy is the concrete production deny-all baseline and therefore cannot carry positive grants.
/// Authorization is exposed only through one operation-specific bridge invocation and no inner-store
/// access seam is exposed.
pub struct ProductionDurableCapabilityAuthority {
    registry_custody: Arc<Mutex<ProductionDurableRegistryRuntimeCustody>>,
    policy: ProductionRemoteCapabilityDenyAllPolicy,
}

impl ProductionDurableCapabilityAuthority {
    /// Consumes one exact durable-registry custody into dormant production capability-authority
    /// ownership.
    ///
    /// Construction is synchronous and side-effect-free: it performs no lock acquisition, provider
    /// I/O, registry operation, policy lookup, authorization, task spawn or runtime activation.
    #[must_use]
    pub fn from_registry_custody(
        registry_custody: ProductionDurableRegistryRuntimeCustody,
    ) -> Self {
        Self {
            registry_custody: Arc::new(Mutex::new(registry_custody)),
            policy: ProductionRemoteCapabilityDenyAllPolicy,
        }
    }

    /// Authorizes one already-read post-auth capability transaction through current durable authority.
    ///
    /// The exact capability transaction remains owned by the caller and is only borrowed for access
    /// to its already-received request frame. The presented transport identity is transport evidence,
    /// the lease is an already-authenticated logical-session lease, and `now_unix_seconds` is
    /// verifier-owned time. This method does not read another frame, consume same-stream custody,
    /// duplicate bridge authorization logic, dispatch the authorized request, or write a response.
    ///
    /// The durable-registry mutex is held only across the single provider-aware bridge authorization
    /// transaction and is released before this method returns.
    ///
    /// # Errors
    ///
    /// Propagates the existing [`DurableCapabilityBridgeError`] unchanged, preserving ordinary bridge
    /// rejection separately from non-semantic durable-authority failure.
    pub async fn authorize_capability_transaction(
        &self,
        presented_transport_identity: TransportIdentity,
        lease: &RemoteSessionLease,
        now_unix_seconds: u64,
        transaction: &PostAuthCapabilityTransaction,
    ) -> Result<AuthorizedCapabilityRequest, DurableCapabilityBridgeError> {
        let mut registry_custody = self.registry_custody.lock().await;
        let result = {
            let mut bridge =
                DurableCapabilityBridge::new(&mut *registry_custody.authority, &self.policy);
            bridge
                .authorize(
                    presented_transport_identity,
                    lease,
                    now_unix_seconds,
                    transaction.request_frame(),
                )
                .await
        };
        drop(registry_custody);
        result
    }
}

#[cfg(test)]
mod tests {
    use prw_connectivity::TransportIdentity;
    use prw_core::DeviceId;
    use prw_registry::{
        RegistryValidatedPrincipal,
        durable_registry_authority::{
            DurableRegistryAuthority, DurableRegistryAuthorityError, DurableRegistryAuthorityFuture,
        },
    };
    use prw_session::AuthenticatedDeviceSession;

    use super::{ProductionDurableCapabilityAuthority, ProductionDurableRegistryRuntimeCustody};

    struct TestAuthority;

    impl DurableRegistryAuthority for TestAuthority {
        fn current_transport_identity<'a>(
            &'a mut self,
            _device_id: &'a DeviceId,
        ) -> DurableRegistryAuthorityFuture<'a, TransportIdentity> {
            Box::pin(async { Err(DurableRegistryAuthorityError::ReadUnavailable) })
        }

        fn validate_authenticated_session_and_transport_identity<'a>(
            &'a mut self,
            _session: &'a AuthenticatedDeviceSession,
            _presented: TransportIdentity,
        ) -> DurableRegistryAuthorityFuture<'a, RegistryValidatedPrincipal> {
            Box::pin(async { Err(DurableRegistryAuthorityError::ReadUnavailable) })
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn runtime_custody_accepts_provider_neutral_authority() {
        let _ = ProductionDurableRegistryRuntimeCustody::from_authority(TestAuthority);
    }

    #[test]
    fn capability_authority_constructor_consumes_exact_registry_custody_by_value() {
        let custody = ProductionDurableRegistryRuntimeCustody::from_authority(TestAuthority);
        let _ = ProductionDurableCapabilityAuthority::from_registry_custody(custody);
    }

    #[test]
    fn capability_authority_custody_is_send_sync() {
        assert_send_sync::<ProductionDurableCapabilityAuthority>();
    }

    #[test]
    fn capability_authority_exposes_selected_authorization_method() {
        let _ = ProductionDurableCapabilityAuthority::authorize_capability_transaction;
    }
}
