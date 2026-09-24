//! Agent-owned endpoint lifecycle custody for production reachability.
//!
//! C03e-IA materializes only the C03e-HZ-selected endpoint-startup custody transaction. The
//! wrapper retains the existing remote endpoint lifecycle beside the recovered durable production
//! reachability owner. A startup failure retains the complete pre-bind production runtime custody.
//! C03e-IC adds only the C03e-IB-selected dormant runtime-drive delegation while retaining durable
//! owner custody until the existing lower endpoint lifecycle returns after close and idle drain.
//!
//! This module adds no executable callsite, readiness publication, candidate publication, traversal
//! activation, peer dial, retry, provider re-bootstrap, durable-owner operation, systemd unit/package
//! mutation, deployment, or production-state mutation.

use std::{fmt, net::SocketAddr, num::NonZeroUsize, sync::Arc};

use prw_core::DeviceId;
use prw_policy::PolicyEvaluator;
use prw_remote_bridge::CapabilityDispatcher;
use prw_session::SessionAuthenticationService;
use tokio::sync::mpsc;

use crate::{
    candidate_publication_requester_rendezvous_start_intent::policy_source::RequesterRendezvousStartPolicySource,
    production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    production_reachability_owner_composition::ProductionReachabilityEtcdOwnerCustody,
    production_reachability_runtime_custody::ProductionReachabilityRuntimeCustody,
    remote_session_capability_runtime::{
        RemoteSessionApplicationLeasePolicy, RemoteSessionEndpointBoundAddressError,
        RemoteSessionEndpointLifecycleRuntime, RemoteSessionEndpointLifecycleStartupError,
        RemoteSessionExpectedDeviceAdmissionRejection,
        RemoteSessionExpectedDeviceAdmissionRejectionReason,
        RemoteSessionExpectedDeviceAdmissionRequest,
        RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection,
        RemoteSessionPersistentCollectionConfigError, RemoteSessionProductionPreAjTiming,
        RemoteSessionRealAdmissionError, RemoteSessionRealAdmissionTiming,
        RemoteSessionRegisteredWorkerCompletion, RemoteSessionRepeatedAdmissionFailure,
        RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection,
        SharedCurrentCapabilityAuthority, SharedRequesterRendezvousAuthority,
    },
};

type EndpointStartupCustodyResult<Authority, Durable, Endpoint, Controller, Error> =
    Result<((Endpoint, Durable), Controller), ((Authority, Durable), Error)>;

pub fn compose_endpoint_startup_custody<Authority, Durable, Endpoint, Controller, Error>(
    authority: Authority,
    durable: Durable,
    bind: impl FnOnce(Authority) -> Result<(Endpoint, Controller), (Authority, Error)>,
) -> EndpointStartupCustodyResult<Authority, Durable, Endpoint, Controller, Error> {
    match bind(authority) {
        Ok((endpoint, controller)) => Ok(((endpoint, durable), controller)),
        Err((authority, error)) => Err(((authority, durable), error)),
    }
}

fn drive_with_retained_custody<Endpoint, Custody, Output>(
    endpoint: Endpoint,
    custody: Custody,
    drive: impl FnOnce(Endpoint) -> Output,
) -> Output {
    let output = drive(endpoint);
    drop(custody);
    output
}

/// Joint production custody for one successfully started remote endpoint lifecycle.
///
/// The existing endpoint lifecycle retains the live reachability authority. The recovered durable
/// production-owner custody remains retained beside it and is not cloneable or independently
/// extractable from this wrapper.
pub struct ProductionReachabilityEndpointLifecycleRuntime {
    endpoint: RemoteSessionEndpointLifecycleRuntime,
    owner_custody: ProductionReachabilityEtcdOwnerCustody,
}

impl ProductionReachabilityEndpointLifecycleRuntime {
    #[must_use]
    pub(super) const fn new(
        endpoint: RemoteSessionEndpointLifecycleRuntime,
        owner_custody: ProductionReachabilityEtcdOwnerCustody,
    ) -> Self {
        Self {
            endpoint,
            owner_custody,
        }
    }

    /// Returns the exact local socket address reported by the retained already-bound endpoint.
    ///
    /// This delegates to the existing read-only endpoint observation and performs no candidate
    /// construction/publication, retry, bind, rebind, close or readiness mutation.
    ///
    /// # Errors
    ///
    /// Returns the existing bounded endpoint observation error unchanged.
    pub fn bound_addr(&self) -> Result<SocketAddr, RemoteSessionEndpointBoundAddressError> {
        self.endpoint.bound_addr()
    }

    /// Drives the existing repeated-admission endpoint lifecycle while retaining durable custody.
    ///
    /// This wrapper is consumed exactly once. Durable production-owner custody remains lexically
    /// alive for the complete delegated lower endpoint-drive call and is released only after that
    /// call returns. The lower lifecycle remains solely responsible for admission, worker,
    /// supervisor-shutdown, endpoint-close and idle-drain behavior.
    ///
    /// No durable-owner operation, retry, re-bootstrap, replacement endpoint, readiness publication,
    /// candidate publication, traversal activation or executable process wiring is performed here.
    ///
    /// # Errors
    ///
    /// Returns the existing [`RemoteSessionPersistentCollectionConfigError`] unchanged after the
    /// lower endpoint lifecycle has completed its existing close and idle-drain law.
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-IC forwards the exact existing lower endpoint-lifecycle inputs"
    )]
    pub fn drive_repeated_real_remote_admission_endpoint_lifecycle<P, D, T, F, C, R, E>(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
        E: FnMut(RemoteSessionRepeatedAdmissionFailure),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint.drive_repeated_real_remote_admission_endpoint_lifecycle(
                max_active_workers,
                authority,
                session_authentication,
                expected_requests,
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            )
        })
    }

    /// Drives the requester-aware durable endpoint projection while retaining reachability custody.
    ///
    /// This dormant crate-internal sibling consumes the production wrapper once, retains the
    /// distinct durable production reachability owner for the complete lower C03e-LP drive, and
    /// forwards the existing requester-aware durable capability inputs unchanged. Completion
    /// projection remains owned entirely by the C03e-LP raw endpoint adapter.
    ///
    /// No higher-owner caller migration, authority bootstrap/population, callback remapping, retry,
    /// endpoint rebind, readiness publication, or executable activation is performed here.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-LR materializes the LQ-selected dormant production-wrapper propagation before separately gated higher-owner caller migration"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-LR forwards the exact C03e-LP durable projection inputs through retained production reachability custody"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability_projection<
        P,
        D,
        T,
        PS,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(DeviceId, RemoteSessionRequesterAwareEndpointLifecycleCompletionProjection),
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint
                .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_capability_projection(
                    max_active_workers,
                    authority,
                    capability_authority,
                    policy_source,
                    requester_rendezvous_authority,
                    session_authentication,
                    expected_requests,
                    admission_timing,
                    on_completion,
                    on_rejection,
                    on_admission_failure,
                )
        })
    }

    /// Drives the fallible verifier-time endpoint completion projection while retaining reachability custody.
    ///
    /// This dormant crate-internal sibling consumes the production wrapper once, retains the
    /// distinct durable production reachability owner for the complete lower C03e-PV drive, and
    /// forwards every existing non-custody lifecycle input unchanged. Completion projection remains
    /// owned entirely by the C03e-PV raw endpoint adapter.
    ///
    /// No provider sampling, callback remapping, higher-owner caller migration, retry, endpoint
    /// rebind, readiness publication, requester/durable fusion, or executable activation occurs here.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-PX materializes the PW-selected dormant production-wrapper propagation before separately gated higher-owner composition"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "C03e-PX forwards the exact C03e-PV fallible verifier-time projection inputs through retained production reachability custody"
    )]
    pub(crate) fn drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle_with_completion_projection<
        P,
        D,
        T,
        F,
        C,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        admission_timing: F,
        on_completion: C,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(DeviceId, RemoteSessionFallibleVerifierTimeEndpointLifecycleCompletionProjection),
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
        E: FnMut(RemoteSessionRepeatedAdmissionFailure),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint
                .drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle_with_completion_projection(
                    max_active_workers,
                    authority,
                    session_authentication,
                    expected_requests,
                    admission_timing,
                    on_completion,
                    on_rejection,
                    on_admission_failure,
                )
        })
    }

    /// Drives the fallible-verifier-time expected-device higher-observation projection while
    /// retaining production reachability custody.
    ///
    /// This dormant crate-internal sibling consumes the production wrapper once, retains the
    /// distinct durable production reachability owner for the complete lower C03e-SD drive, and
    /// forwards the existing expected-device producer inputs unchanged. The lower SD adapter
    /// remains sole owner of raw receipt projection; this wrapper widens no raw receipt or error
    /// payload.
    ///
    /// No channel construction/split/clone, sender minting, higher-owner invocation, provider
    /// sampling, endpoint rebind, readiness publication, executable caller migration, or runtime
    /// activation occurs here.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error unchanged.
    #[allow(
        dead_code,
        reason = "C03e-SH materializes only the SG-selected dormant production-wrapper forwarding sibling before separately gated higher-owner/channel integration"
    )]
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-SH forwards the exact existing SD higher-observation inputs through retained production reachability custody"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint
                .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection(
                    max_active_workers,
                    authority,
                    capability_authority,
                    policy_source,
                    requester_rendezvous_authority,
                    session_authentication,
                    expected_requests,
                    dispatcher_factory,
                    sender,
                    observe_receipt,
                    admission_timing,
                    on_rejection,
                    on_admission_failure,
                )
        })
    }

    /// Forwards fallible admission timing through the retained production-reachability custody layer.
    #[allow(
        dead_code,
        reason = "C03e-SX adds only the SW-selected fallible timing forwarding sibling while preserving retained production reachability custody"
    )]
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-SX preserves the existing higher-observation production-wrapper inputs and adds only Cause/K timing failure custody"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_fallible_admission_timing<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionRealAdmissionTiming,
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingFailure<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint
                .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_fallible_admission_timing(
                    max_active_workers,
                    authority,
                    capability_authority,
                    policy_source,
                    requester_rendezvous_authority,
                    session_authentication,
                    expected_requests,
                    dispatcher_factory,
                    sender,
                    observe_receipt,
                    admission_timing,
                    on_rejection,
                    on_admission_failure,
                    on_timing_failure,
                )
        })
    }

    /// Forwards the TF production pre-AJ timing and validated lease policy through retained reachability custody.
    #[allow(
        dead_code,
        reason = "C03e-TF adds only the separately authorized retained-custody forwarding seam for the TE-selected timing/policy lane"
    )]
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "C03e-TF preserves the exact higher-observation inputs while forwarding one typed lease policy and pre-AJ timing carrier"
    )]
    pub(crate) fn drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_pre_aj_timing_and_application_lease_policy<
        P,
        D,
        PS,
        DF,
        O,
        F,
        R,
        E,
        Cause,
        K,
    >(
        self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        application_lease_policy: RemoteSessionApplicationLeasePolicy,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        dispatcher_factory: &mut DF,
        sender: &mpsc::Sender<
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        >,
        observe_receipt: O,
        admission_timing: F,
        on_rejection: R,
        on_admission_failure: E,
        on_timing_failure: K,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        DF: FnMut() -> D,
        O: FnMut(
            DeviceId,
            crate::remote_session_capability_runtime::RemoteSessionExpectedDeviceAdmissionFallibleVerifierTimeHandoffObservationProjection,
        ),
        Cause: std::error::Error + Send + 'static,
        F: FnMut(
            &DeviceId,
        ) -> Result<
            RemoteSessionProductionPreAjTiming,
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
        >,
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
            >,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
        K: FnMut(
            crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingFailure<
                D,
                fn() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
                crate::remote_session_capability_runtime::RemoteSessionAdmissionTimingSourceError<Cause>,
            >,
        ),
    {
        let Self {
            endpoint,
            owner_custody,
        } = self;

        drive_with_retained_custody(endpoint, owner_custody, |endpoint| {
            endpoint
                .drive_repeated_real_remote_admission_endpoint_lifecycle_with_production_durable_fallible_verifier_time_expected_device_admission_producer_with_higher_observation_projection_with_pre_aj_timing_and_application_lease_policy(
                    max_active_workers,
                    authority,
                    capability_authority,
                    policy_source,
                    requester_rendezvous_authority,
                    application_lease_policy,
                    session_authentication,
                    expected_requests,
                    dispatcher_factory,
                    sender,
                    observe_receipt,
                    admission_timing,
                    on_rejection,
                    on_admission_failure,
                    on_timing_failure,
                )
        })
    }
}

/// Recoverable production endpoint-startup failure retaining complete pre-bind runtime custody.
pub struct ProductionReachabilityEndpointLifecycleStartupFailure {
    runtime_custody: Box<ProductionReachabilityRuntimeCustody>,
    error: RemoteSessionEndpointLifecycleStartupError,
}

impl fmt::Debug for ProductionReachabilityEndpointLifecycleStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionReachabilityEndpointLifecycleStartupFailure")
            .field("runtime_custody", &"<retained>")
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for ProductionReachabilityEndpointLifecycleStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ProductionReachabilityEndpointLifecycleStartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl ProductionReachabilityEndpointLifecycleStartupFailure {
    #[must_use]
    pub(super) fn new(
        runtime_custody: ProductionReachabilityRuntimeCustody,
        error: RemoteSessionEndpointLifecycleStartupError,
    ) -> Self {
        Self {
            runtime_custody: Box::new(runtime_custody),
            error,
        }
    }

    /// Returns the existing bounded endpoint startup classification.
    #[must_use]
    pub const fn error(&self) -> RemoteSessionEndpointLifecycleStartupError {
        self.error
    }

    /// Recovers the complete production runtime custody after failed endpoint startup.
    #[must_use]
    pub fn into_runtime_custody(self) -> ProductionReachabilityRuntimeCustody {
        *self.runtime_custody
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        net::SocketAddr,
        num::NonZeroUsize,
        rc::Rc,
    };

    use prw_core::DeviceId;
    use prw_policy::BoundedLocalReadPolicy;
    use prw_remote_bridge::{AuthorizedCapabilityRequest, CapabilityDispatcher};
    use prw_session::SessionAuthenticationService;
    use tokio::sync::mpsc;

    use super::{
        ProductionReachabilityEndpointLifecycleRuntime, compose_endpoint_startup_custody,
        drive_with_retained_custody,
    };
    use crate::remote_session_capability_runtime::{
        RemoteSessionEndpointBoundAddressError, RemoteSessionExpectedDeviceAdmissionRejection,
        RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionPersistentCollectionConfigError,
        RemoteSessionRealAdmissionTiming, RemoteSessionRegisteredWorkerCompletion,
        RemoteSessionRepeatedAdmissionFailure, SharedCurrentCapabilityAuthority,
    };

    struct TestDispatcher;

    impl CapabilityDispatcher for TestDispatcher {
        type Error = ();

        fn dispatch(
            &mut self,
            _request: &AuthorizedCapabilityRequest,
        ) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }
    }

    type TestExpectedRequest =
        RemoteSessionExpectedDeviceAdmissionRequest<TestDispatcher, fn() -> u64>;
    type TestExpectedRejection =
        RemoteSessionExpectedDeviceAdmissionRejection<TestDispatcher, fn() -> u64>;

    struct DropProbe {
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.events.borrow_mut().push("custody_drop");
        }
    }

    fn assert_bound_addr_signature(
        observation: fn(
            &ProductionReachabilityEndpointLifecycleRuntime,
        ) -> Result<SocketAddr, RemoteSessionEndpointBoundAddressError>,
    ) {
        let _ = observation;
    }

    #[expect(
        clippy::type_complexity,
        reason = "C03e-IC test states the exact selected production wrapper drive shape"
    )]
    fn assert_drive_signature(
        drive: fn(
            ProductionReachabilityEndpointLifecycleRuntime,
            NonZeroUsize,
            &SharedCurrentCapabilityAuthority<BoundedLocalReadPolicy>,
            &mut SessionAuthenticationService,
            mpsc::Receiver<TestExpectedRequest>,
            fn(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            fn(RemoteSessionRegisteredWorkerCompletion),
            fn(TestExpectedRejection),
            fn(RemoteSessionRepeatedAdmissionFailure),
        ) -> Result<(), RemoteSessionPersistentCollectionConfigError>,
    ) {
        let _ = drive;
    }

    #[test]
    fn success_routes_endpoint_and_durable_custody_without_retry() {
        let calls = Cell::new(0_u8);
        let result = compose_endpoint_startup_custody(11_u8, 22_u8, |authority| {
            calls.set(calls.get() + 1);
            assert_eq!(authority, 11);
            Ok::<_, (u8, u8)>((33_u8, 44_u8))
        });

        assert_eq!(result, Ok(((33, 22), 44)));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn failure_recombines_authority_and_durable_custody_without_retry() {
        let calls = Cell::new(0_u8);
        let result = compose_endpoint_startup_custody(11_u8, 22_u8, |authority| {
            calls.set(calls.get() + 1);
            Err::<(u8, u8), _>((authority, 55_u8))
        });

        assert_eq!(result, Err(((11, 22), 55)));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retained_custody_drops_only_after_delegated_drive_returns() {
        let events = Rc::new(RefCell::new(Vec::<&'static str>::new()));
        let custody = DropProbe {
            events: Rc::clone(&events),
        };

        let result = drive_with_retained_custody(7_u8, custody, |endpoint| {
            assert_eq!(endpoint, 7);
            events.borrow_mut().push("drive");
            assert_eq!(*events.borrow(), vec!["drive"]);
            Err::<(), _>("lower_error")
        });

        assert_eq!(result, Err("lower_error"));
        assert_eq!(*events.borrow(), vec!["drive", "custody_drop"]);
    }

    #[test]
    fn production_endpoint_bound_address_has_exact_read_only_shape() {
        assert_bound_addr_signature(ProductionReachabilityEndpointLifecycleRuntime::bound_addr);
    }

    #[test]
    fn production_endpoint_drive_consumes_wrapper_with_exact_lower_shape() {
        assert_drive_signature(
            ProductionReachabilityEndpointLifecycleRuntime::drive_repeated_real_remote_admission_endpoint_lifecycle,
        );
    }
}
