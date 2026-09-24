//! Phase 152 C02f-Y asynchronous production live-owner authority port staging.
//!
//! This module materializes the C02f-X API/orchestration selection without activating a concrete
//! etcd endpoint, runtime, task, socket, TLS profile, storage schema or network effect. C02f-BU adds
//! the C02f-BT-selected concrete bridge-owned lifecycle composition over one already-constructed
//! C02f-BM preparation facade; provider/bootstrap construction remains outside this module. The
//! existing synchronous `reachability_live_owner` seam remains the deterministic/Sans-I/O semantic
//! reference.
//!
//! The production port is intentionally separate and honest about asynchronous provider I/O:
//! methods return `impl Future + Send`, use static dispatch and borrow the authority with `&mut self`.
//! Provider-specific etcd code remains owned by `prw-control-plane`; this module owns only the
//! provider-neutral orchestration-facing contract and the selected BS/BF/BD lifecycle delegation.

#![allow(clippy::manual_async_fn)]

use std::future::Future;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::reachability_acquisition_evidence::ReachabilityLiveOwnerAcquisitionPreparation;

use crate::{
    reachability_live_owner::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
        ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerGrant, ReachabilityLiveOwnerRelease,
    },
    reachability_live_owner_acquisition_composition::acquire_prepared_live_owner,
    reachability_live_owner_currentness_execution::execute_live_owner_currentness_with_prepared_execution,
    reachability_live_owner_reconciled_release_execution::execute_reconciled_live_owner_release_with_prepared_execution,
};

/// Explicit asynchronous production authority port for one exact reachability live-owner lifecycle.
///
/// This port complements rather than replaces the synchronous semantic/reference seam. A production
/// provider may perform network I/O only after the returned Future is polled by an external executor.
/// The bridge itself does not own or create an async runtime by defining this trait.
///
/// Safety requirements inherited from the live-owner authority contract:
///
/// - every successful acquisition for one exact `DeviceId + TransportIdentity` namespace must use a
///   strictly newer authority fence than every prior successful generation for that namespace;
/// - ambiguous or unavailable provider state must fail closed;
/// - authoritative currentness cannot be proven from stale/local cache state or advisory watches;
/// - stale release must not clear a newer owner;
/// - dropping/cancelling a pending operation must never be interpreted as successful ownership;
/// - effect-side stale-fence rejection remains mandatory at R1-R4 and is not satisfied merely by
///   awaiting a bridge-level currentness check once.
///
/// The exact etcd key/value schema, Txn compare guard, indeterminate-commit reconciliation details,
/// TLS/auth/RBAC profile, recovery epoch provider and process-level executor remain separate gates.
pub trait ReachabilityLiveOwnerAsyncAuthority {
    /// Asynchronously attempts to establish one current grant for `peer`.
    ///
    /// A definitive `Granted` result means all older grants for this exact peer lifecycle are stale.
    /// No caller may treat construction, polling cancellation or an ambiguous provider outcome as a
    /// successful acquisition.
    ///
    /// # Errors
    ///
    /// Returns an authority error when acquisition/currentness cannot be proven or the ordered fence
    /// space cannot safely advance.
    fn acquire<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a;

    /// Asynchronously establishes whether `grant` is still exact-current.
    ///
    /// # Errors
    ///
    /// Ambiguous/unavailable authority state must be returned as an error rather than `Current`.
    fn currentness<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a;

    /// Asynchronously releases the exact current grant when supported by the provider.
    ///
    /// Release remains a liveness operation only; stale-owner safety must hold even if the owner
    /// crashes or the release Future is never completed.
    ///
    /// # Errors
    ///
    /// Ambiguous release state is reported rather than converted into success/currentness proof.
    fn release<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a;
}

/// C02f-BU concrete async-authority composition over one exact preparation-owned provider context.
///
/// Construction accepts only an already-created C02f-BM preparation facade. It does not accept or
/// create an etcd client, endpoint, TLS/auth/RBAC configuration, runtime/executor, recovery provider,
/// retry scheduler, background task, or alternate provider handle. The same preparation-owned
/// live-owner store is therefore used by acquisition, currentness, and release.
pub struct ReachabilityLiveOwnerComposedAsyncAuthority {
    preparation: ReachabilityLiveOwnerAcquisitionPreparation,
}

impl ReachabilityLiveOwnerComposedAsyncAuthority {
    /// Wraps one already-created preparation facade without performing provider I/O.
    #[must_use]
    pub const fn new(preparation: ReachabilityLiveOwnerAcquisitionPreparation) -> Self {
        Self { preparation }
    }
}

impl ReachabilityLiveOwnerAsyncAuthority for ReachabilityLiveOwnerComposedAsyncAuthority {
    fn acquire<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        acquire_prepared_live_owner(&mut self.preparation, peer)
    }

    fn currentness<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        async move {
            let mut execution = self.preparation.lifecycle_execution();
            execute_live_owner_currentness_with_prepared_execution(&mut execution, grant).await
        }
    }

    fn release<'a>(
        &'a mut self,
        grant: &'a ReachabilityLiveOwnerGrant,
    ) -> impl Future<
        Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>,
    > + Send
    + 'a {
        async move {
            let mut execution = self.preparation.lifecycle_execution();
            execute_reconciled_live_owner_release_with_prepared_execution(&mut execution, grant)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, ready};

    use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
    use prw_core::DeviceId;

    use super::{ReachabilityLiveOwnerAsyncAuthority, ReachabilityLiveOwnerComposedAsyncAuthority};
    use crate::reachability_live_owner::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError,
        ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerFence, ReachabilityLiveOwnerGrant,
        ReachabilityLiveOwnerRelease,
    };

    /// Runtime-independent fail-closed reference used only to prove the selected async port shape.
    struct FailClosedReferenceAuthority;

    impl ReachabilityLiveOwnerAsyncAuthority for FailClosedReferenceAuthority {
        fn acquire<'a>(
            &'a mut self,
            _peer: &'a PeerConnectivityIdentity,
        ) -> impl Future<
            Output = Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>,
        > + Send
        + 'a {
            ready(Err(
                ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous,
            ))
        }

        fn currentness<'a>(
            &'a mut self,
            _grant: &'a ReachabilityLiveOwnerGrant,
        ) -> impl Future<
            Output = Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError>,
        > + Send
        + 'a {
            ready(Err(
                ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous,
            ))
        }

        fn release<'a>(
            &'a mut self,
            _grant: &'a ReachabilityLiveOwnerGrant,
        ) -> impl Future<
            Output = Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>,
        > + Send
        + 'a {
            ready(Err(
                ReachabilityLiveOwnerAuthorityError::UnavailableOrAmbiguous,
            ))
        }
    }

    fn peer() -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new("c02f-y-device").expect("valid device id"),
            TransportIdentity::new([9_u8; 32]).expect("non-zero transport identity"),
        )
    }

    fn assert_send_future<F: Future + Send>(future: F) {
        drop(future);
    }

    fn assert_async_authority<T: ReachabilityLiveOwnerAsyncAuthority>() {}

    #[test]
    fn selected_async_port_exposes_send_futures_with_static_mutable_borrowing() {
        let peer = peer();
        let fence = ReachabilityLiveOwnerFence::new(1).expect("non-zero fence");
        let grant = ReachabilityLiveOwnerGrant::from_authority(peer.clone(), fence);
        let mut authority = FailClosedReferenceAuthority;

        assert_send_future(authority.acquire(&peer));
        assert_send_future(authority.currentness(&grant));
        assert_send_future(authority.release(&grant));
    }

    #[test]
    fn composed_authority_implements_selected_async_port() {
        assert_async_authority::<ReachabilityLiveOwnerComposedAsyncAuthority>();
    }
}
