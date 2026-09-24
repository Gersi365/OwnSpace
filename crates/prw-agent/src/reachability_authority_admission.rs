//! Phase 152 C02f-CI Agent-owned reachability authority admission seam.
//!
//! C02f-CH preserves the existing local Agent readiness meaning and requires successful
//! reachability authority construction before future authority-dependent remote admission. This
//! module materializes the source-level admission token and callable bootstrap/admission seam.
//! C02f-CK additionally materializes the Agent-owned lifetime boundary for one admitted authority.
//! Neither path is wired into `main.rs`, runtime readiness, remote transport, or background/retry
//! lifecycle.

use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

use crate::reachability_authority_custody_bootstrap::{
    ReachabilityAuthorityCustodyBootstrapError,
    bootstrap_reachability_live_owner_authority_from_systemd_credentials,
};

/// Opaque Agent-owned proof that reachability authority bootstrap completed successfully.
pub struct ReachabilityLiveOwnerAuthorityAdmission {
    authority: ReachabilityLiveOwnerComposedAsyncAuthority,
}

impl ReachabilityLiveOwnerAuthorityAdmission {
    const fn from_authority(authority: ReachabilityLiveOwnerComposedAsyncAuthority) -> Self {
        Self { authority }
    }

    /// Returns the admitted bridge-owned composed authority by immutable reference.
    #[must_use]
    pub const fn authority(&self) -> &ReachabilityLiveOwnerComposedAsyncAuthority {
        &self.authority
    }
}

/// Agent-owned lifetime boundary for one successfully admitted reachability authority.
///
/// Construction performs only ownership composition. The owner retains the opaque admission token
/// and exposes mutable authority access only inside `prw-agent` for a future separately gated
/// reachability operation consumer.
pub struct ReachabilityAuthorityRuntimeOwner {
    admission: ReachabilityLiveOwnerAuthorityAdmission,
}

impl ReachabilityAuthorityRuntimeOwner {
    /// Consumes one successful admission token without performing I/O.
    #[must_use]
    pub const fn new(admission: ReachabilityLiveOwnerAuthorityAdmission) -> Self {
        Self { admission }
    }

    /// Adapts one already-composed live authority directly into the existing runtime owner.
    ///
    /// This crate-internal constructor performs ownership composition only. It does not read
    /// credentials, bootstrap a provider, perform network I/O, publish readiness or expose the
    /// private admission wrapper.
    #[must_use]
    pub(crate) const fn from_composed_authority(
        authority: ReachabilityLiveOwnerComposedAsyncAuthority,
    ) -> Self {
        Self::new(ReachabilityLiveOwnerAuthorityAdmission::from_authority(
            authority,
        ))
    }

    /// Returns the admitted composed authority for a separately gated Agent operation seam.
    #[allow(
        dead_code,
        reason = "C02f-CK materializes a source-only seam for a separately gated consumer"
    )]
    pub(crate) const fn authority_mut(
        &mut self,
    ) -> &mut ReachabilityLiveOwnerComposedAsyncAuthority {
        &mut self.admission.authority
    }
}

/// Bootstraps and admits the reachability live-owner authority through the existing C02f-CG seam.
///
/// Calling this function performs the fixed C02f-CE credential reads and subsequent provider
/// network I/O already owned by C02f-CG/CF. The existing bounded C02f-CG error is propagated
/// unchanged. Only successful authority construction can produce the opaque admission token.
///
/// C02f-CI does not invoke this function from the Agent binary or runtime and does not add retry,
/// background work, remote transport readiness, recovery, PRWF initialization, or R1-R4 effects.
///
/// # Errors
///
/// Returns the existing [`ReachabilityAuthorityCustodyBootstrapError`] when fixed credential
/// custody or provider bootstrap fails. Failure never produces an admission token.
pub async fn bootstrap_and_admit_reachability_live_owner_authority_from_systemd_credentials()
-> Result<ReachabilityLiveOwnerAuthorityAdmission, ReachabilityAuthorityCustodyBootstrapError> {
    bootstrap_reachability_live_owner_authority_from_systemd_credentials()
        .await
        .map(ReachabilityLiveOwnerAuthorityAdmission::from_authority)
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use prw_remote_bridge::reachability_live_owner_async::ReachabilityLiveOwnerComposedAsyncAuthority;

    use super::{
        ReachabilityAuthorityRuntimeOwner, ReachabilityLiveOwnerAuthorityAdmission,
        bootstrap_and_admit_reachability_live_owner_authority_from_systemd_credentials,
    };
    use crate::reachability_authority_custody_bootstrap::ReachabilityAuthorityCustodyBootstrapError;

    fn assert_admission_signature<F, Fut>(_bootstrap: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<
            Output = Result<
                ReachabilityLiveOwnerAuthorityAdmission,
                ReachabilityAuthorityCustodyBootstrapError,
            >,
        >,
    {
    }

    fn assert_runtime_owner_constructor(
        constructor: fn(
            ReachabilityLiveOwnerAuthorityAdmission,
        ) -> ReachabilityAuthorityRuntimeOwner,
    ) {
        let _ = constructor;
    }

    fn assert_runtime_owner_composed_authority_constructor(
        constructor: fn(
            ReachabilityLiveOwnerComposedAsyncAuthority,
        ) -> ReachabilityAuthorityRuntimeOwner,
    ) {
        let _ = constructor;
    }

    fn assert_runtime_owner_authority_accessor(
        accessor: for<'a> fn(
            &'a mut ReachabilityAuthorityRuntimeOwner,
        ) -> &'a mut ReachabilityLiveOwnerComposedAsyncAuthority,
    ) {
        let _ = accessor;
    }

    #[test]
    fn admission_bootstrap_has_exact_no_argument_to_admission_shape() {
        assert_admission_signature(
            bootstrap_and_admit_reachability_live_owner_authority_from_systemd_credentials,
        );
    }

    #[test]
    fn runtime_owner_has_exact_admission_and_mutable_authority_shapes() {
        assert_runtime_owner_constructor(ReachabilityAuthorityRuntimeOwner::new);
        assert_runtime_owner_composed_authority_constructor(
            ReachabilityAuthorityRuntimeOwner::from_composed_authority,
        );
        assert_runtime_owner_authority_accessor(ReachabilityAuthorityRuntimeOwner::authority_mut);
    }
}
