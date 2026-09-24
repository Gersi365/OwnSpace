//! Agent-owned runtime custody for one production reachability bootstrap composition.
//!
//! C03e-HY materializes only the C03e-HX-selected side-effect-free ownership adaptation. One
//! already-produced [`ProductionReachabilityBootstrapComposition`] is consumed exactly once; its
//! live composed authority is adapted into the existing Agent runtime-authority owner while its
//! recovered durable production owner remains retained beside that authority owner. C03e-IA adds
//! only the C03e-HZ-selected endpoint-startup custody transaction over this complete owner. C03e-IE
//! adds only the C03e-ID-selected supplied-executor sibling for the same production startup law.
//!
//! This module reads no credentials during ownership adaptation, creates no background task,
//! publishes no readiness, activates no candidate publication or traversal, dials no peer, mutates
//! no executable startup/shutdown callsite, and exposes no generic extraction seam. The endpoint
//! transactions call existing endpoint-bind seams only when separately invoked.

use std::net::SocketAddr;

use crate::{
    production_reachability_bootstrap::ProductionReachabilityBootstrapComposition,
    production_reachability_endpoint_lifecycle::{
        ProductionReachabilityEndpointLifecycleRuntime,
        ProductionReachabilityEndpointLifecycleStartupFailure,
    },
    production_reachability_owner_composition::ProductionReachabilityEtcdOwnerCustody,
    reachability_authority_admission::ReachabilityAuthorityRuntimeOwner,
    remote_session_capability_runtime::{
        RemoteSessionEndpointLifecycleRuntime, RemoteSessionExecutorRuntime,
        RemoteSessionSupervisorShutdownController,
    },
};

/// Agent-owned joint custody of the production live authority and recovered durable owner.
///
/// Both semantic values remain private and non-cloneable. A later separately gated endpoint/process
/// transaction may consume this owner without first exposing or dropping either component.
pub struct ProductionReachabilityRuntimeCustody {
    authority_owner: ReachabilityAuthorityRuntimeOwner,
    owner_custody: ProductionReachabilityEtcdOwnerCustody,
}

impl ProductionReachabilityRuntimeCustody {
    /// Consumes one production bootstrap composition into joint runtime custody.
    ///
    /// This method performs ownership adaptation only. The bootstrap composition has already
    /// completed all credential/provider/durable work before entry. Its two semantic parts are
    /// immediately re-owned here; neither part is returned or registered globally.
    #[must_use]
    pub fn from_bootstrap_composition(
        composition: ProductionReachabilityBootstrapComposition,
    ) -> Self {
        let (live_owner_authority, owner_custody) = composition.into_parts();
        let authority_owner =
            ReachabilityAuthorityRuntimeOwner::from_composed_authority(live_owner_authority);

        Self {
            authority_owner,
            owner_custody,
        }
    }

    /// Starts one existing remote endpoint while preserving complete production custody.
    ///
    /// The existing endpoint startup is attempted exactly once. On success, the live authority
    /// moves into the existing endpoint lifecycle and the untouched durable owner custody moves
    /// beside that endpoint into [`ProductionReachabilityEndpointLifecycleRuntime`]. On failure,
    /// the exact live authority recovered from the existing startup failure is recombined with the
    /// untouched durable custody and returned as complete production runtime custody.
    ///
    /// No retry, replacement endpoint, provider re-bootstrap, durable recovery, two-role fallback,
    /// readiness publication or executable startup wiring is performed here.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionReachabilityEndpointLifecycleStartupFailure`] with the existing bounded
    /// endpoint startup classification and the complete reconstructed pre-bind runtime custody.
    pub fn bind_remote_endpoint_from_systemd_credentials(
        self,
        bind_addr: SocketAddr,
    ) -> Result<
        (
            ProductionReachabilityEndpointLifecycleRuntime,
            RemoteSessionSupervisorShutdownController,
        ),
        ProductionReachabilityEndpointLifecycleStartupFailure,
    > {
        let Self {
            authority_owner,
            owner_custody,
        } = self;

        match RemoteSessionEndpointLifecycleRuntime::bind_from_systemd_credentials(
            authority_owner,
            bind_addr,
        ) {
            Ok((endpoint, shutdown_controller)) => Ok((
                ProductionReachabilityEndpointLifecycleRuntime::new(endpoint, owner_custody),
                shutdown_controller,
            )),
            Err(failure) => {
                let error = failure.error();
                let authority_owner = failure.into_authority_owner();
                let runtime_custody = Self {
                    authority_owner,
                    owner_custody,
                };
                Err(ProductionReachabilityEndpointLifecycleStartupFailure::new(
                    runtime_custody,
                    error,
                ))
            }
        }
    }

    /// Starts the production endpoint with one exact already-created remote-session executor.
    ///
    /// The supplied executor is consumed exactly once through the existing lower same-executor bind.
    /// No replacement executor is constructed. Success retains the untouched durable production
    /// owner beside the lower endpoint; failure recovers the exact live authority and recombines it
    /// with that untouched durable custody into complete production runtime custody.
    ///
    /// The existing lower supplied-executor failure path consumes/drops the executor. This method
    /// therefore performs no executor recovery, retry, rebind, provider re-bootstrap or fallback.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionReachabilityEndpointLifecycleStartupFailure`] with the existing bounded
    /// endpoint startup classification and the complete reconstructed production runtime custody.
    pub(crate) fn bind_remote_endpoint_with_executor_from_systemd_credentials(
        self,
        executor: RemoteSessionExecutorRuntime,
        bind_addr: SocketAddr,
    ) -> Result<
        (
            ProductionReachabilityEndpointLifecycleRuntime,
            RemoteSessionSupervisorShutdownController,
        ),
        ProductionReachabilityEndpointLifecycleStartupFailure,
    > {
        let Self {
            authority_owner,
            owner_custody,
        } = self;

        match RemoteSessionEndpointLifecycleRuntime::bind_with_executor_from_systemd_credentials(
            executor,
            authority_owner,
            bind_addr,
        ) {
            Ok((endpoint, shutdown_controller)) => Ok((
                ProductionReachabilityEndpointLifecycleRuntime::new(endpoint, owner_custody),
                shutdown_controller,
            )),
            Err(failure) => {
                let error = failure.error();
                let authority_owner = failure.into_authority_owner();
                let runtime_custody = Self {
                    authority_owner,
                    owner_custody,
                };
                Err(ProductionReachabilityEndpointLifecycleStartupFailure::new(
                    runtime_custody,
                    error,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::ProductionReachabilityRuntimeCustody;
    use crate::{
        production_reachability_bootstrap::ProductionReachabilityBootstrapComposition,
        production_reachability_endpoint_lifecycle::{
            ProductionReachabilityEndpointLifecycleRuntime,
            ProductionReachabilityEndpointLifecycleStartupFailure,
        },
        remote_session_capability_runtime::{
            RemoteSessionExecutorRuntime, RemoteSessionSupervisorShutdownController,
        },
    };

    fn assert_constructor_signature(
        constructor: fn(
            ProductionReachabilityBootstrapComposition,
        ) -> ProductionReachabilityRuntimeCustody,
    ) {
        let _ = constructor;
    }

    fn assert_endpoint_startup_signature(
        startup: fn(
            ProductionReachabilityRuntimeCustody,
            SocketAddr,
        ) -> Result<
            (
                ProductionReachabilityEndpointLifecycleRuntime,
                RemoteSessionSupervisorShutdownController,
            ),
            ProductionReachabilityEndpointLifecycleStartupFailure,
        >,
    ) {
        let _ = startup;
    }

    #[allow(
        clippy::type_complexity,
        reason = "C03e-IE test helper preserves the exact supplied-executor startup signature"
    )]
    fn assert_same_executor_endpoint_startup_signature(
        startup: fn(
            ProductionReachabilityRuntimeCustody,
            RemoteSessionExecutorRuntime,
            SocketAddr,
        ) -> Result<
            (
                ProductionReachabilityEndpointLifecycleRuntime,
                RemoteSessionSupervisorShutdownController,
            ),
            ProductionReachabilityEndpointLifecycleStartupFailure,
        >,
    ) {
        let _ = startup;
    }

    #[test]
    fn runtime_custody_constructor_consumes_exact_bootstrap_composition_shape() {
        assert_constructor_signature(
            ProductionReachabilityRuntimeCustody::from_bootstrap_composition,
        );
    }

    #[test]
    fn endpoint_startup_consumes_complete_runtime_custody_by_value() {
        assert_endpoint_startup_signature(
            ProductionReachabilityRuntimeCustody::bind_remote_endpoint_from_systemd_credentials,
        );
    }

    #[test]
    fn same_executor_endpoint_startup_consumes_exact_executor_by_value() {
        assert_same_executor_endpoint_startup_signature(
            ProductionReachabilityRuntimeCustody::bind_remote_endpoint_with_executor_from_systemd_credentials,
        );
    }
}
