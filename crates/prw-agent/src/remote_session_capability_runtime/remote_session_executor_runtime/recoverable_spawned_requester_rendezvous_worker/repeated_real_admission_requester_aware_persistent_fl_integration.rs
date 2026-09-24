//! Repeated real-admission integration for recoverable requester-aware persistent FL custody.
//!
//! C03e-FU materializes only the C03e-FT-selected composition of the existing repeated expected-device
//! AJ supervisor with exact C03e-FS recoverable persistent custody and exact C03e-FL requester-aware
//! worker execution. The existing AJ transaction remains unchanged, authenticated `DeviceId` remains
//! the active-map key, ready completion recovery remains first, and orderly shutdown reuses the exact
//! FS cancellation/drain law. This module does not close/reuse a completed worker peer, clean requester
//! records, select candidate/reachability state, dial targets, activate a listener/bootstrap/readiness
//! path, deploy, restart/recover the process, or merge.

mod production_durable_repeated_real_admission_collection;
use std::{
    collections::{HashMap, hash_map::Entry},
    future::{Future, poll_fn},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use prw_core::DeviceId;
use prw_policy::PolicyEvaluator;
use prw_remote_bridge::CapabilityDispatcher;
use prw_session::SessionAuthenticationService;
use tokio::sync::{Mutex, mpsc};

use super::super::{
    RemoteSessionExecutorRuntime, RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionPersistentCollectionConfigError,
    RemoteSessionRealAdmissionTiming, RemoteSessionWorkerAdmission,
    validate_persistent_worker_capacity,
};
use super::{
    RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
    RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion,
    RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion,
    recoverable_persistent_requester_rendezvous_worker::{
        RecoverablePersistentWorkerCompletion, RecoverablePersistentWorkerEntry,
        RecoverableRequesterAwareWorkerCompletion, RecoverableRequesterAwareWorkerEntry,
        drain_recoverable_workers, poll_one_ready_recoverable_worker,
        reap_ready_recoverable_workers, request_all_recoverable_worker_cancellations,
    },
};
use crate::{
    candidate_publication_requester_rendezvous_start_intent::policy_source::RequesterRendezvousStartPolicySource,
    production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    remote_session_capability_runtime::{
        AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionRealAdmissionError,
        SharedCurrentCapabilityAuthority, SharedRequesterRendezvousAuthority,
        admit_expected_remote_device_session, remote_session_worker_cancellation_pair,
        requester_rendezvous_retained_custody_dr_continuation::{
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            run_fallible_verifier_time_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling,
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker,
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability,
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling,
        },
    },
    remote_transport_runtime::AgentRemoteTransportRuntime,
};

type ActiveRecoverableRequesterAwareWorkers =
    HashMap<DeviceId, RecoverableRequesterAwareWorkerEntry>;

type RecoverableSchedulingRequesterAwareWorkerEntry = RecoverablePersistentWorkerEntry<
    AuthenticatedRemoteSessionRuntimeOwner,
    RequesterRendezvousProductionDurableSchedulingWorkerStop,
>;

type RecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkerEntry =
    RecoverablePersistentWorkerEntry<
        AuthenticatedRemoteSessionRuntimeOwner,
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
    >;

type RecoverableSchedulingRequesterAwareWorkerCompletion = RecoverablePersistentWorkerCompletion<
    DeviceId,
    AuthenticatedRemoteSessionRuntimeOwner,
    RequesterRendezvousProductionDurableSchedulingWorkerStop,
>;

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling generic completion custody before separately gated collection-driver migration"
)]
type RecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkerCompletion =
    RecoverablePersistentWorkerCompletion<
        DeviceId,
        AuthenticatedRemoteSessionRuntimeOwner,
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
    >;

type ActiveRecoverableSchedulingRequesterAwareWorkers =
    HashMap<DeviceId, RecoverableSchedulingRequesterAwareWorkerEntry>;

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling active-map custody before separately gated collection-driver migration"
)]
type ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers =
    HashMap<DeviceId, RecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkerEntry>;

enum RepeatedRecoverableSupervisorEvent<C> {
    Shutdown,
    Request(C),
}

enum RecoverableInFlightAdmissionEvent<R> {
    Shutdown,
    Complete(R),
}

fn poll_shutdown_or_expected_request<C, S>(
    active_len: usize,
    max_active_workers: usize,
    request_source_open: &mut bool,
    requests: &mut mpsc::Receiver<C>,
    mut supervisor_shutdown: Pin<&mut S>,
    context: &mut Context<'_>,
) -> Poll<RepeatedRecoverableSupervisorEvent<C>>
where
    S: Future<Output = ()>,
{
    if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
        return Poll::Ready(RepeatedRecoverableSupervisorEvent::Shutdown);
    }

    if *request_source_open && active_len < max_active_workers {
        match Pin::new(requests).poll_recv(context) {
            Poll::Ready(Some(request)) => {
                return Poll::Ready(RepeatedRecoverableSupervisorEvent::Request(request));
            }
            Poll::Ready(None) => *request_source_open = false,
            Poll::Pending => {}
        }
    }

    Poll::Pending
}

fn poll_shutdown_or_inflight_admission<S, A>(
    mut supervisor_shutdown: Pin<&mut S>,
    mut admission: Pin<&mut A>,
    context: &mut Context<'_>,
) -> Poll<RecoverableInFlightAdmissionEvent<A::Output>>
where
    S: Future<Output = ()>,
    A: Future,
{
    if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
        return Poll::Ready(RecoverableInFlightAdmissionEvent::Shutdown);
    }

    admission
        .as_mut()
        .poll(context)
        .map(RecoverableInFlightAdmissionEvent::Complete)
}

fn prepare_expected_request<D, T, V, F, R>(
    active: &HashMap<DeviceId, V>,
    request: RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    admission_timing: &mut F,
    on_rejection: &mut R,
) -> Option<(
    RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    RemoteSessionRealAdmissionTiming,
)>
where
    F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
    R: FnMut(
        RemoteSessionExpectedDeviceAdmissionRejectionReason,
        RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    ),
{
    let expected_device_id = request.expected_device_id().clone();
    if active.contains_key(&expected_device_id) {
        on_rejection(
            RemoteSessionExpectedDeviceAdmissionRejectionReason::DuplicateActiveDevice,
            request,
        );
        return None;
    }

    let timing = admission_timing(&expected_device_id);
    Some((request, timing))
}

fn publish_recoverable_completion<C>(
    completion: RecoverableRequesterAwareWorkerCompletion,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion),
{
    let (device_id, session_owner, result) = completion.into_parts();
    on_completion(
        RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion::new(
            device_id,
            session_owner,
            result,
        ),
    );
}

fn reap_requester_aware_workers<C>(
    active: &mut ActiveRecoverableRequesterAwareWorkers,
    context: &mut Context<'_>,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion),
{
    let mut publish = |completion| publish_recoverable_completion(completion, on_completion);
    reap_ready_recoverable_workers(active, context, &mut publish);
}

fn request_all_requester_aware_worker_cancellations(
    active: &ActiveRecoverableRequesterAwareWorkers,
) {
    request_all_recoverable_worker_cancellations(active);
}

async fn drain_requester_aware_workers<C>(
    active: &mut ActiveRecoverableRequesterAwareWorkers,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion),
{
    let mut publish = |completion| publish_recoverable_completion(completion, on_completion);
    drain_recoverable_workers(active, &mut publish).await;
}

async fn drain_inflight_admission<A, C>(
    active: &mut ActiveRecoverableRequesterAwareWorkers,
    mut admission: Pin<&mut A>,
    on_completion: &mut C,
) -> A::Output
where
    A: Future,
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion),
{
    poll_fn(|context| {
        reap_requester_aware_workers(active, context, on_completion);
        admission.as_mut().poll(context)
    })
    .await
}

fn publish_recoverable_scheduling_completion<C>(
    completion: RecoverableSchedulingRequesterAwareWorkerCompletion,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion),
{
    let (device_id, session_owner, result) = completion.into_parts();
    on_completion(
        RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion::new(
            device_id,
            session_owner,
            result,
        ),
    );
}

#[allow(
    dead_code,
    reason = "C03e-OI materializes the OH-selected dormant scheduling-specific single-completion adapter before separately gated producer-driver migration"
)]
fn poll_one_requester_aware_scheduling_worker(
    active: &mut ActiveRecoverableSchedulingRequesterAwareWorkers,
    context: &mut Context<'_>,
) -> Poll<RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion> {
    match poll_one_ready_recoverable_worker(active, context) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(completion) => {
            let (device_id, session_owner, result) = completion.into_parts();
            Poll::Ready(
                RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion::new(
                    device_id,
                    session_owner,
                    result,
                ),
            )
        }
    }
}

fn reap_requester_aware_scheduling_workers<C>(
    active: &mut ActiveRecoverableSchedulingRequesterAwareWorkers,
    context: &mut Context<'_>,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion),
{
    let mut publish =
        |completion| publish_recoverable_scheduling_completion(completion, on_completion);
    reap_ready_recoverable_workers(active, context, &mut publish);
}

fn request_all_requester_aware_scheduling_worker_cancellations(
    active: &ActiveRecoverableSchedulingRequesterAwareWorkers,
) {
    request_all_recoverable_worker_cancellations(active);
}

async fn drain_requester_aware_scheduling_workers<C>(
    active: &mut ActiveRecoverableSchedulingRequesterAwareWorkers,
    on_completion: &mut C,
) where
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion),
{
    let mut publish =
        |completion| publish_recoverable_scheduling_completion(completion, on_completion);
    drain_recoverable_workers(active, &mut publish).await;
}

async fn drain_inflight_scheduling_admission<A, C>(
    active: &mut ActiveRecoverableSchedulingRequesterAwareWorkers,
    mut admission: Pin<&mut A>,
    on_completion: &mut C,
) -> A::Output
where
    A: Future,
    C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion),
{
    poll_fn(|context| {
        reap_requester_aware_scheduling_workers(active, context, on_completion);
        admission.as_mut().poll(context)
    })
    .await
}

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling completion publisher before separately gated collection-driver migration"
)]
fn publish_recoverable_fallible_verifier_time_scheduling_completion<C>(
    completion: RecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkerCompletion,
    on_completion: &mut C,
) where
    C: FnMut(
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
    ),
{
    let (device_id, session_owner, result) = completion.into_parts();
    on_completion(
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion::new(
            device_id,
            session_owner,
            result,
        ),
    );
}

#[allow(
    dead_code,
    reason = "C03e-RH materializes the RG-selected dormant fallible scheduling single-completion adapter before separately gated cooperative collection-driver migration"
)]
fn poll_one_requester_aware_fallible_verifier_time_scheduling_worker(
    active: &mut ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers,
    context: &mut Context<'_>,
) -> Poll<
    RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
> {
    match poll_one_ready_recoverable_worker(active, context) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(completion) => {
            let (device_id, session_owner, result) = completion.into_parts();
            Poll::Ready(
                RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion::new(
                    device_id,
                    session_owner,
                    result,
                ),
            )
        }
    }
}

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling ready-reap adapter before separately gated collection-driver migration"
)]
fn reap_requester_aware_fallible_verifier_time_scheduling_workers<C>(
    active: &mut ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers,
    context: &mut Context<'_>,
    on_completion: &mut C,
) where
    C: FnMut(
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
    ),
{
    let mut publish = |completion| {
        publish_recoverable_fallible_verifier_time_scheduling_completion(completion, on_completion);
    };
    reap_ready_recoverable_workers(active, context, &mut publish);
}

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling cancellation fan-out adapter before separately gated collection-driver migration"
)]
fn request_all_requester_aware_fallible_verifier_time_scheduling_worker_cancellations(
    active: &ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers,
) {
    request_all_recoverable_worker_cancellations(active);
}

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling full-drain adapter before separately gated collection-driver migration"
)]
async fn drain_requester_aware_fallible_verifier_time_scheduling_workers<C>(
    active: &mut ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers,
    on_completion: &mut C,
) where
    C: FnMut(
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
    ),
{
    let mut publish = |completion| {
        publish_recoverable_fallible_verifier_time_scheduling_completion(completion, on_completion);
    };
    drain_recoverable_workers(active, &mut publish).await;
}

#[allow(
    dead_code,
    reason = "C03e-RF materializes the RE-selected dormant fallible scheduling in-flight-admission drain adapter before separately gated collection-driver migration"
)]
async fn drain_inflight_fallible_verifier_time_scheduling_admission<A, C>(
    active: &mut ActiveRecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkers,
    mut admission: Pin<&mut A>,
    on_completion: &mut C,
) -> A::Output
where
    A: Future,
    C: FnMut(
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
    ),
{
    poll_fn(|context| {
        reap_requester_aware_fallible_verifier_time_scheduling_workers(
            active,
            context,
            on_completion,
        );
        admission.as_mut().poll(context)
    })
    .await
}

fn spawn_recoverable_requester_aware_worker<P, D, T, S>(
    admission: RemoteSessionWorkerAdmission<D, T>,
    authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &Arc<S>,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
) -> RecoverableRequesterAwareWorkerEntry
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
{
    let authority = (*authority).clone();
    let policy_source = Arc::clone(policy_source);
    let requester_rendezvous_authority = requester_rendezvous_authority.clone();
    let (session_owner, mut dispatcher, verifier_time_unix_seconds) = admission.into_parts();
    let owner_cell = Arc::new(Mutex::new(Some(session_owner)));
    let worker_owner_cell = Arc::clone(&owner_cell);
    let (cancellation_controller, cancellation_signal) = remote_session_worker_cancellation_pair();

    let worker_handle = tokio::spawn(async move {
        let mut owner_guard = worker_owner_cell.lock().await;
        let session_owner = owner_guard.as_mut().expect(
            "persistent requester-aware worker must borrow retained authenticated-session owner",
        );
        let result = run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker(
            session_owner,
            &authority,
            policy_source.as_ref(),
            &requester_rendezvous_authority,
            verifier_time_unix_seconds,
            &mut dispatcher,
            cancellation_signal.into_cancelled(),
        )
        .await;
        drop(owner_guard);
        result
    });

    RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
}

#[allow(
    dead_code,
    clippy::needless_pass_by_value,
    reason = "C03e-KW materializes the KV-selected dormant production-durable persistent worker entry constructor before separately gated repeated-admission caller migration"
)]
fn spawn_recoverable_requester_aware_worker_with_production_durable_capability<P, D, T, S>(
    admission: RemoteSessionWorkerAdmission<D, T>,
    capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &Arc<S>,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
) -> RecoverableRequesterAwareWorkerEntry
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
{
    let requester_dr_authority = (*requester_dr_authority).clone();
    let policy_source = Arc::clone(policy_source);
    let requester_rendezvous_authority = requester_rendezvous_authority.clone();
    let (session_owner, mut dispatcher, verifier_time_unix_seconds) = admission.into_parts();
    let owner_cell = Arc::new(Mutex::new(Some(session_owner)));
    let worker_owner_cell = Arc::clone(&owner_cell);
    let (cancellation_controller, cancellation_signal) = remote_session_worker_cancellation_pair();

    let worker_handle = tokio::spawn(async move {
        let mut owner_guard = worker_owner_cell.lock().await;
        let session_owner = owner_guard.as_mut().expect(
            "persistent requester-aware worker must borrow retained authenticated-session owner",
        );
        let result =
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability(
                session_owner,
                capability_authority.as_ref(),
                &requester_dr_authority,
                policy_source.as_ref(),
                &requester_rendezvous_authority,
                verifier_time_unix_seconds,
                &mut dispatcher,
                cancellation_signal.into_cancelled(),
            )
            .await;
        drop(owner_guard);
        result
    });

    RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
}

#[allow(
    dead_code,
    clippy::needless_pass_by_value,
    reason = "C03e-NY materializes the NX-selected dormant scheduling-specific production-durable persistent worker entry without migrating historical callers"
)]
fn spawn_recoverable_requester_aware_worker_with_production_durable_scheduling<P, D, T, S>(
    admission: RemoteSessionWorkerAdmission<D, T>,
    capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &Arc<S>,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
) -> RecoverableSchedulingRequesterAwareWorkerEntry
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> u64 + Send + 'static,
    S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
{
    let requester_dr_authority = (*requester_dr_authority).clone();
    let policy_source = Arc::clone(policy_source);
    let requester_rendezvous_authority = requester_rendezvous_authority.clone();
    let (session_owner, mut dispatcher, verifier_time_unix_seconds) = admission.into_parts();
    let owner_cell = Arc::new(Mutex::new(Some(session_owner)));
    let worker_owner_cell = Arc::clone(&owner_cell);
    let (cancellation_controller, cancellation_signal) = remote_session_worker_cancellation_pair();

    let worker_handle = tokio::spawn(async move {
        let mut owner_guard = worker_owner_cell.lock().await;
        let session_owner = owner_guard.as_mut().expect(
            "persistent scheduling-aware requester worker must borrow retained authenticated-session owner",
        );
        let result =
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling(
                session_owner,
                capability_authority.as_ref(),
                &requester_dr_authority,
                policy_source.as_ref(),
                &requester_rendezvous_authority,
                verifier_time_unix_seconds,
                &mut dispatcher,
                cancellation_signal.into_cancelled(),
            )
            .await;
        drop(owner_guard);
        result
    });

    RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
}

#[allow(
    dead_code,
    clippy::needless_pass_by_value,
    reason = "C03e-QZ materializes the QY-selected dormant fallible scheduling-specific production-durable persistent worker entry without migrating historical callers"
)]
fn spawn_recoverable_fallible_verifier_time_requester_aware_worker_with_production_durable_scheduling<
    P,
    D,
    T,
    S,
>(
    admission: RemoteSessionWorkerAdmission<D, T>,
    capability_authority: Arc<ProductionDurableCapabilityAuthority>,
    requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
    policy_source: &Arc<S>,
    requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
) -> RecoverableFallibleVerifierTimeSchedulingRequesterAwareWorkerEntry
where
    P: PolicyEvaluator + Send + Sync + 'static,
    D: CapabilityDispatcher + Send + 'static,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
        + Send
        + 'static,
    S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
{
    let requester_dr_authority = (*requester_dr_authority).clone();
    let policy_source = Arc::clone(policy_source);
    let requester_rendezvous_authority = requester_rendezvous_authority.clone();
    let (session_owner, mut dispatcher, verifier_time_unix_seconds) = admission.into_parts();
    let owner_cell = Arc::new(Mutex::new(Some(session_owner)));
    let worker_owner_cell = Arc::clone(&owner_cell);
    let (cancellation_controller, cancellation_signal) = remote_session_worker_cancellation_pair();

    let worker_handle = tokio::spawn(async move {
        let mut owner_guard = worker_owner_cell.lock().await;
        let session_owner = owner_guard.as_mut().expect(
            "persistent fallible scheduling-aware requester worker must borrow retained authenticated-session owner",
        );
        let result =
            run_fallible_verifier_time_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_scheduling(
                session_owner,
                capability_authority.as_ref(),
                &requester_dr_authority,
                policy_source.as_ref(),
                &requester_rendezvous_authority,
                verifier_time_unix_seconds,
                &mut dispatcher,
                cancellation_signal.into_cancelled(),
            )
            .await;
        drop(owner_guard);
        result
    });

    RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
}

impl RemoteSessionExecutorRuntime {
    /// Drives repeated expected-device real admission into exact recoverable requester-aware FL
    /// worker custody on the same private current-thread runtime.
    ///
    /// Ready recoverable completions are reaped before same-wake shutdown or request admission.
    /// Duplicate expected `DeviceId` requests are rejected before timing or AJ work. AJ remains the
    /// exact existing single in-flight transaction; successful authentication derives the active key
    /// from the returned session owner and inserts exactly one C03e-FS recoverable entry whose task
    /// runs exact FL with shared current authority, shared requester authority, requester-specific
    /// policy source, and the existing cooperative cancellation signal.
    ///
    /// If shutdown wins while AJ is pending, all already-active worker cancellations are requested,
    /// the AJ future is retained and drained while ready active workers continue to recover owner
    /// custody, and a post-shutdown AJ success follows the existing orderly-close seam without worker
    /// insertion. Remaining active entries then reuse exact FS owner-recovering drain semantics.
    ///
    /// Requester-aware worker completion itself performs no peer close/reuse/restart and no requester
    /// cleanup. Candidate/reachability continuation, target dialing, endpoint activation and process
    /// lifecycle wiring remain separately gated.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent collection configuration error before runtime work when the
    /// requested active-worker bound exceeds the registered-device ceiling.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        clippy::needless_pass_by_value,
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "C03e-FU preserves exclusive executor custody and supervisor-owned shared policy lifetime while materializing the FT-selected explicit repeated-AJ integration surface"
    )]
    pub(in super::super) fn drive_recoverable_repeated_real_remote_admission_collection<
        P,
        D,
        T,
        PS,
        SH,
        F,
        C,
        R,
        E,
    >(
        &mut self,
        max_active_workers: NonZeroUsize,
        transport_runtime: &AgentRemoteTransportRuntime,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: Arc<PS>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        session_authentication: &mut SessionAuthenticationService,
        expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
        supervisor_shutdown: SH,
        mut admission_timing: F,
        mut on_completion: C,
        mut on_rejection: R,
        mut on_admission_failure: E,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        PS: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        SH: Future<Output = ()> + Send,
        F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
        C: FnMut(RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion),
        R: FnMut(
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
        ),
        E: FnMut(DeviceId, RemoteSessionRealAdmissionError),
    {
        let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;
        let mut expected_requests = expected_requests;

        self.runtime.block_on(async {
            let mut active = ActiveRecoverableRequesterAwareWorkers::new();
            let mut supervisor_shutdown = Box::pin(supervisor_shutdown);
            let mut request_source_open = true;

            loop {
                let event = poll_fn(|context| {
                    reap_requester_aware_workers(&mut active, context, &mut on_completion);
                    poll_shutdown_or_expected_request(
                        active.len(),
                        max_active_workers,
                        &mut request_source_open,
                        &mut expected_requests,
                        supervisor_shutdown.as_mut(),
                        context,
                    )
                })
                .await;

                let RepeatedRecoverableSupervisorEvent::Request(request) = event else {
                    request_all_requester_aware_worker_cancellations(&active);
                    drain_requester_aware_workers(&mut active, &mut on_completion).await;
                    return;
                };

                let Some((request, timing)) = prepare_expected_request(
                    &active,
                    request,
                    &mut admission_timing,
                    &mut on_rejection,
                ) else {
                    continue;
                };

                let (
                    expected_device_id,
                    session_id,
                    authentication_request_id,
                    dispatcher,
                    verifier_time_unix_seconds,
                ) = request.into_parts();
                let (
                    challenge_validity_unix_seconds,
                    authentication_now_unix_seconds,
                    application_lease_unix_seconds,
                ) = timing.into_parts();

                let mut admission = Box::pin(admit_expected_remote_device_session(
                    transport_runtime,
                    authority,
                    session_authentication,
                    &expected_device_id,
                    session_id,
                    challenge_validity_unix_seconds,
                    authentication_request_id,
                    authentication_now_unix_seconds,
                    application_lease_unix_seconds,
                ));

                let admission_event = poll_fn(|context| {
                    reap_requester_aware_workers(&mut active, context, &mut on_completion);
                    poll_shutdown_or_inflight_admission(
                        supervisor_shutdown.as_mut(),
                        admission.as_mut(),
                        context,
                    )
                })
                .await;

                match admission_event {
                    RecoverableInFlightAdmissionEvent::Complete(result) => {
                        drop(admission);
                        match result {
                            Ok(session_owner) => {
                                let authenticated_device_id =
                                    session_owner.logical_device_id().clone();
                                debug_assert_eq!(
                                    authenticated_device_id,
                                    expected_device_id,
                                    "AJ success must retain the expected authenticated DeviceId"
                                );
                                let worker_admission = RemoteSessionWorkerAdmission::new(
                                    session_owner,
                                    dispatcher,
                                    verifier_time_unix_seconds,
                                );
                                match active.entry(authenticated_device_id) {
                                    Entry::Vacant(slot) => {
                                        slot.insert(spawn_recoverable_requester_aware_worker(
                                            worker_admission,
                                            authority,
                                            &policy_source,
                                            requester_rendezvous_authority,
                                        ));
                                    }
                                    Entry::Occupied(_) => {
                                        unreachable!(
                                            "single in-flight preflight guarantees a vacant post-auth DeviceId"
                                        );
                                    }
                                }
                            }
                            Err(error) => on_admission_failure(expected_device_id, error),
                        }
                    }
                    RecoverableInFlightAdmissionEvent::Shutdown => {
                        request_all_requester_aware_worker_cancellations(&active);
                        let result = drain_inflight_admission(
                            &mut active,
                            admission.as_mut(),
                            &mut on_completion,
                        )
                        .await;
                        drop(admission);

                        match result {
                            Ok(session_owner) => session_owner.close_for_orderly_shutdown(),
                            Err(error) => on_admission_failure(expected_device_id, error),
                        }

                        drain_requester_aware_workers(&mut active, &mut on_completion).await;
                        return;
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::{pending, ready},
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use prw_core::{DeviceId, SessionId};
    use tokio::sync::mpsc;

    use super::{
        RemoteSessionExpectedDeviceAdmissionRejectionReason,
        RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionRealAdmissionTiming,
        poll_shutdown_or_expected_request, prepare_expected_request,
    };

    fn device_id(value: &str) -> DeviceId {
        DeviceId::new(value).expect("test device id")
    }

    fn test_request(
        device: &str,
        value: u8,
    ) -> RemoteSessionExpectedDeviceAdmissionRequest<u8, u8> {
        RemoteSessionExpectedDeviceAdmissionRequest::new(
            device_id(device),
            SessionId::new(format!("session-{value}")).expect("test session id"),
            u64::from(value),
            value,
            value,
        )
    }

    fn test_timing() -> RemoteSessionRealAdmissionTiming {
        RemoteSessionRealAdmissionTiming::new(10..20, 12, 10..30)
    }

    #[test]
    fn duplicate_expected_device_is_rejected_before_timing_sampling() {
        let mut active = HashMap::new();
        active.insert(device_id("device-fu"), 1_u8);
        let request = test_request("device-fu", 7);
        let mut timing_samples = 0_usize;
        let mut rejection = None;

        let prepared = prepare_expected_request(
            &active,
            request,
            &mut |_device_id| {
                timing_samples += 1;
                test_timing()
            },
            &mut |reason, request| {
                let (device_id, _session_id, _request_id, dispatcher, verifier) =
                    request.into_parts();
                rejection = Some((reason, device_id, dispatcher, verifier));
            },
        );

        assert!(prepared.is_none());
        assert_eq!(timing_samples, 0);
        assert_eq!(
            rejection,
            Some((
                RemoteSessionExpectedDeviceAdmissionRejectionReason::DuplicateActiveDevice,
                device_id("device-fu"),
                7,
                7,
            ))
        );
    }

    #[test]
    fn vacant_expected_device_samples_timing_once_and_preserves_request() {
        let active = HashMap::<DeviceId, u8>::new();
        let request = test_request("device-fu-vacant", 9);
        let mut timing_samples = 0_usize;
        let mut rejection_count = 0_usize;

        let (prepared, timing) = prepare_expected_request(
            &active,
            request,
            &mut |_device_id| {
                timing_samples += 1;
                test_timing()
            },
            &mut |_reason, _request| rejection_count += 1,
        )
        .expect("vacant request prepares");

        let (prepared_device_id, _session_id, request_id, dispatcher, verifier) =
            prepared.into_parts();
        assert_eq!(prepared_device_id, device_id("device-fu-vacant"));
        assert_eq!(request_id, 9);
        assert_eq!(dispatcher, 9);
        assert_eq!(verifier, 9);
        assert_eq!(timing.into_parts(), (10..20, 12, 10..30));
        assert_eq!(timing_samples, 1);
        assert_eq!(rejection_count, 0);
    }

    #[test]
    fn full_capacity_does_not_poll_expected_request_source() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(sender.try_send(41_u8).is_ok());
        let mut request_source_open = true;
        let mut shutdown = Box::pin(pending::<()>());
        let mut context = Context::from_waker(Waker::noop());

        let event = poll_shutdown_or_expected_request(
            1,
            1,
            &mut request_source_open,
            &mut receiver,
            shutdown.as_mut(),
            &mut context,
        );

        assert!(matches!(event, Poll::Pending));
        assert_eq!(receiver.try_recv(), Ok(41_u8));
    }

    #[test]
    fn shutdown_wins_before_prequeued_expected_request() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(sender.try_send(43_u8).is_ok());
        let mut request_source_open = true;
        let mut shutdown = Box::pin(ready(()));
        let mut context = Context::from_waker(Waker::noop());

        let event = poll_shutdown_or_expected_request(
            0,
            1,
            &mut request_source_open,
            &mut receiver,
            Pin::as_mut(&mut shutdown),
            &mut context,
        );

        assert!(matches!(
            event,
            Poll::Ready(super::RepeatedRecoverableSupervisorEvent::Shutdown)
        ));
        assert_eq!(receiver.try_recv(), Ok(43_u8));
    }
}
