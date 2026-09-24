//! Agent-owned executor custody for the staged remote-session runtime path.
//!
//! C03e-T selected the narrow first executor shape: one explicit non-cloneable Tokio
//! current-thread runtime owner. C03e-U materializes that construction/custody boundary, C03e-V
//! adds one borrowed domain-specific drive seam for the existing C03e-S worker body, C03e-AB
//! adds one lexically-contained spawned-and-joined worker seam, C03e-AF adds one bounded
//! current-thread single-worker supervisor, and C03e-AH adds the first pre-listener persistent
//! current-thread worker collection. It does not bind remote transport, publish readiness, or wire
//! the Agent binary.

use std::{
    collections::{HashMap, hash_map::Entry as HashMapEntry},
    fmt,
    future::{Future, poll_fn},
    hash::Hash,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use prw_core::DeviceId;
use prw_policy::PolicyEvaluator;
use prw_registry::MAX_REGISTERED_DEVICES;
use prw_remote_bridge::CapabilityDispatcher;
use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc,
    task::JoinHandle,
};

use super::{
    RemoteSessionWorkerCancellationController, SharedCurrentCapabilityAuthority,
    authenticated_remote_session_runtime::{
        AuthenticatedRemoteSessionRuntimeOwner, AuthenticatedRemoteSessionWorkerStop,
    },
    remote_session_worker_cancellation_pair,
};

/// Failure while constructing the Agent-owned remote-session executor runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionExecutorRuntimeCreateError {
    /// Tokio could not construct the selected current-thread runtime with I/O/time drivers.
    Construction,
}

impl fmt::Display for RemoteSessionExecutorRuntimeCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to construct remote session executor runtime")
    }
}

impl std::error::Error for RemoteSessionExecutorRuntimeCreateError {}

/// Failure while joining the one lexically-contained spawned remote-session worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionSpawnedWorkerJoinError {
    /// Tokio reported abnormal completion for the one local worker task.
    AbnormalTaskCompletion,
}

impl fmt::Display for RemoteSessionSpawnedWorkerJoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("spawned remote session worker completed abnormally")
    }
}

impl std::error::Error for RemoteSessionSpawnedWorkerJoinError {}

/// Invalid configuration for the bounded persistent remote-worker collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteSessionPersistentCollectionConfigError {
    /// The configured active-worker bound exceeds the existing registered-device ceiling.
    CapacityExceedsRegisteredDeviceLimit,
}

impl fmt::Display for RemoteSessionPersistentCollectionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote session worker capacity exceeds registered device limit")
    }
}

impl std::error::Error for RemoteSessionPersistentCollectionConfigError {}

/// One already-authenticated candidate for the pre-listener persistent worker collection.
pub struct RemoteSessionWorkerAdmission<D, T> {
    session_owner: AuthenticatedRemoteSessionRuntimeOwner,
    dispatcher: D,
    verifier_time_unix_seconds: T,
}

impl<D, T> RemoteSessionWorkerAdmission<D, T> {
    /// Creates one ownership-only admission item with no caller-supplied logical identity.
    #[must_use]
    pub const fn new(
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        dispatcher: D,
        verifier_time_unix_seconds: T,
    ) -> Self {
        Self {
            session_owner,
            dispatcher,
            verifier_time_unix_seconds,
        }
    }

    const fn logical_device_id(&self) -> &DeviceId {
        self.session_owner.logical_device_id()
    }

    /// Recovers the untouched owned candidate parts for explicit caller cleanup or custody.
    #[must_use]
    pub fn into_parts(self) -> (AuthenticatedRemoteSessionRuntimeOwner, D, T) {
        (
            self.session_owner,
            self.dispatcher,
            self.verifier_time_unix_seconds,
        )
    }
}

/// Bounded reason that an already-authenticated worker candidate was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteSessionWorkerAdmissionRejectionReason {
    /// One active worker already owns the same authenticated logical `DeviceId` key.
    DuplicateActiveDevice,
}

/// Owns one rejected already-authenticated candidate together with its bounded reason.
pub struct RemoteSessionWorkerAdmissionRejection<D, T> {
    reason: RemoteSessionWorkerAdmissionRejectionReason,
    admission: RemoteSessionWorkerAdmission<D, T>,
}

impl<D, T> RemoteSessionWorkerAdmissionRejection<D, T> {
    /// Returns the bounded rejection reason.
    #[must_use]
    pub const fn reason(&self) -> RemoteSessionWorkerAdmissionRejectionReason {
        self.reason
    }

    /// Returns the untouched rejected admission item.
    #[must_use]
    pub const fn admission(&self) -> &RemoteSessionWorkerAdmission<D, T> {
        &self.admission
    }

    /// Returns ownership of the untouched rejected admission item.
    #[must_use]
    pub fn into_admission(self) -> RemoteSessionWorkerAdmission<D, T> {
        self.admission
    }
}

/// One explicitly reaped persistent-worker completion associated with its logical `DeviceId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSessionRegisteredWorkerCompletion {
    device_id: DeviceId,
    result: Result<AuthenticatedRemoteSessionWorkerStop, RemoteSessionSpawnedWorkerJoinError>,
}

impl RemoteSessionRegisteredWorkerCompletion {
    /// Returns the authenticated logical `DeviceId` that keyed the retained worker entry.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the existing bounded worker/join terminal result.
    ///
    /// # Errors
    ///
    /// Returns the stored bounded join error when Tokio reported abnormal worker completion.
    pub const fn result(
        &self,
    ) -> Result<AuthenticatedRemoteSessionWorkerStop, RemoteSessionSpawnedWorkerJoinError> {
        self.result
    }
}

async fn await_supervised_worker<T, S>(
    mut worker_handle: JoinHandle<T>,
    cancellation_controller: RemoteSessionWorkerCancellationController,
    supervisor_shutdown: S,
) -> Result<T, RemoteSessionSpawnedWorkerJoinError>
where
    S: Future<Output = ()> + Send,
{
    let mut supervisor_shutdown = Box::pin(supervisor_shutdown);

    let completed_worker = poll_fn(|context| {
        if let Poll::Ready(worker_result) = Pin::new(&mut worker_handle).poll(context) {
            return Poll::Ready(Some(worker_result));
        }

        if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
            return Poll::Ready(None);
        }

        Poll::Pending
    })
    .await;

    if let Some(worker_result) = completed_worker {
        return worker_result
            .map_err(|_| RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion);
    }

    cancellation_controller.request_cancellation();
    worker_handle
        .await
        .map_err(|_| RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
}

struct RemoteSessionPersistentWorkerEntry<T> {
    cancellation_controller: RemoteSessionWorkerCancellationController,
    worker_handle: JoinHandle<T>,
}

enum RemoteSessionPersistentSupervisorEvent<C> {
    Shutdown,
    Admission(C),
}

const fn validate_persistent_worker_capacity(
    max_active_workers: NonZeroUsize,
) -> Result<usize, RemoteSessionPersistentCollectionConfigError> {
    let max_active_workers = max_active_workers.get();
    if max_active_workers > MAX_REGISTERED_DEVICES {
        return Err(
            RemoteSessionPersistentCollectionConfigError::CapacityExceedsRegisteredDeviceLimit,
        );
    }
    Ok(max_active_workers)
}

fn map_worker_join_result<T>(
    result: Result<T, tokio::task::JoinError>,
) -> Result<T, RemoteSessionSpawnedWorkerJoinError> {
    result.map_err(|_| RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
}

fn reap_ready_persistent_workers<K, T, C>(
    active: &mut HashMap<K, RemoteSessionPersistentWorkerEntry<T>>,
    context: &mut Context<'_>,
    on_completion: &mut C,
) where
    K: Eq + Hash + Clone,
    C: FnMut(K, Result<T, RemoteSessionSpawnedWorkerJoinError>),
{
    active.retain(
        |key, entry| match Pin::new(&mut entry.worker_handle).poll(context) {
            Poll::Ready(result) => {
                on_completion(key.clone(), map_worker_join_result(result));
                false
            }
            Poll::Pending => true,
        },
    );
}

async fn run_persistent_worker_collection<K, Candidate, T, S, Kf, Sf, Cf, Rf>(
    max_active_workers: usize,
    mut admissions: mpsc::Receiver<Candidate>,
    supervisor_shutdown: S,
    mut key_for_candidate: Kf,
    mut spawn_worker: Sf,
    mut on_completion: Cf,
    mut on_rejection: Rf,
) where
    K: Eq + Hash + Clone,
    S: Future<Output = ()>,
    Kf: FnMut(&Candidate) -> K,
    Sf: FnMut(Candidate) -> (RemoteSessionWorkerCancellationController, JoinHandle<T>),
    Cf: FnMut(K, Result<T, RemoteSessionSpawnedWorkerJoinError>),
    Rf: FnMut(RemoteSessionWorkerAdmissionRejectionReason, Candidate),
{
    let mut active = HashMap::<K, RemoteSessionPersistentWorkerEntry<T>>::new();
    let mut supervisor_shutdown = Box::pin(supervisor_shutdown);
    let mut admission_open = true;

    loop {
        let event = poll_fn(|context| {
            reap_ready_persistent_workers(&mut active, context, &mut on_completion);

            if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
                return Poll::Ready(RemoteSessionPersistentSupervisorEvent::Shutdown);
            }

            if admission_open && active.len() < max_active_workers {
                match Pin::new(&mut admissions).poll_recv(context) {
                    Poll::Ready(Some(candidate)) => {
                        return Poll::Ready(RemoteSessionPersistentSupervisorEvent::Admission(
                            candidate,
                        ));
                    }
                    Poll::Ready(None) => admission_open = false,
                    Poll::Pending => {}
                }
            }

            Poll::Pending
        })
        .await;

        match event {
            RemoteSessionPersistentSupervisorEvent::Shutdown => break,
            RemoteSessionPersistentSupervisorEvent::Admission(candidate) => {
                let key = key_for_candidate(&candidate);
                match active.entry(key) {
                    HashMapEntry::Occupied(_) => on_rejection(
                        RemoteSessionWorkerAdmissionRejectionReason::DuplicateActiveDevice,
                        candidate,
                    ),
                    HashMapEntry::Vacant(slot) => {
                        let (cancellation_controller, worker_handle) = spawn_worker(candidate);
                        slot.insert(RemoteSessionPersistentWorkerEntry {
                            cancellation_controller,
                            worker_handle,
                        });
                    }
                }
            }
        }
    }

    for entry in active.values() {
        entry.cancellation_controller.request_cancellation();
    }

    poll_fn(|context| {
        reap_ready_persistent_workers(&mut active, context, &mut on_completion);
        if active.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

/// Explicit Agent-owned Tokio custody for remote transport/session async work.
///
/// The raw Tokio runtime remains private. C03e-V exposes the borrowed
/// [`Self::drive_capability_request_worker`] seam, C03e-AB adds the bounded
/// [`Self::drive_spawned_capability_request_worker`] seam, C03e-AF adds the bounded
/// [`Self::drive_supervised_capability_request_worker`] seam, and C03e-AH adds the pre-listener
/// [`Self::drive_persistent_remote_worker_collection`] seam. No generic `block_on`, runtime handle,
/// network bind, peer acceptance/authentication, readiness or production activation surface is
/// exposed.
pub struct RemoteSessionExecutorRuntime {
    runtime: Runtime,
}

impl RemoteSessionExecutorRuntime {
    /// Constructs the C03e-T-selected current-thread Tokio runtime with I/O/time drivers enabled.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionExecutorRuntimeCreateError::Construction`] when Tokio rejects runtime
    /// construction. No retry, process exit, network bind, task spawn or readiness publication is
    /// performed by this constructor.
    pub fn new() -> Result<Self, RemoteSessionExecutorRuntimeCreateError> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| Self { runtime })
            .map_err(|_| RemoteSessionExecutorRuntimeCreateError::Construction)
    }

    /// Drives exactly one borrowed C03e-S remote-session worker body to its terminal stop.
    ///
    /// The executor owner and authenticated-session owner are both mutably borrowed for the whole
    /// synchronous drive call. The existing C03e-S worker remains the sole authority for the race
    /// between the C03e-Q request loop and caller-supplied cancellation, including its existing
    /// code-3 failure close, code-4 cancellation close and exact terminal classification.
    ///
    /// This seam intentionally uses the private Tokio runtime only through one internal `block_on`
    /// call. It does not expose a generic future-driving API, spawn a task, construct a cancellation
    /// controller, clone a runtime handle, retain a join handle, admit a second session, bind remote
    /// transport, wire `main.rs`, or publish readiness.
    pub fn drive_capability_request_worker<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> AuthenticatedRemoteSessionWorkerStop {
        self.runtime
            .block_on(session_owner.run_capability_request_worker(
                authority,
                verifier_time_unix_seconds,
                dispatcher,
                cancellation,
            ))
    }

    /// Spawns and joins exactly one owned remote-session worker under this private runtime.
    ///
    /// The authenticated-session owner, dispatcher, verifier-time provider and cancellation future
    /// move into one `async move` task. Exactly one clone of the shared-current authority moves into
    /// the same task. The one local join handle is awaited before this bounded drive returns; it is
    /// never returned, stored, detached, aborted or inserted into a collection.
    ///
    /// The task delegates to the existing C03e-S/Z worker body, preserving fresh shared-current
    /// authorization and the existing request-loop/cancellation ordering. The executor remains
    /// mutably borrowed for the entire synchronous drive, so this seam does not admit a second
    /// concurrent worker through the same owner.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion`] if Tokio reports an
    /// abnormal join result. Raw Tokio join errors, panic payloads and task/runtime identifiers are
    /// not exposed. No retry, replacement task or replacement session is attempted.
    pub fn drive_spawned_capability_request_worker<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        C: Future<Output = ()> + Send + 'static,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        cancellation: C,
    ) -> Result<AuthenticatedRemoteSessionWorkerStop, RemoteSessionSpawnedWorkerJoinError> {
        let authority = (*authority).clone();

        self.runtime.block_on(async move {
            let worker_handle = tokio::spawn(async move {
                let mut session_owner = session_owner;
                let mut dispatcher = dispatcher;

                session_owner
                    .run_capability_request_worker(
                        &authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation,
                    )
                    .await
            });

            worker_handle
                .await
                .map_err(|_| RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        })
    }

    /// Supervises exactly one spawned remote-session worker under this private current-thread
    /// runtime until worker completion or orderly supervisor shutdown.
    ///
    /// The supervisor creates one C03e-AD cancellation pair and retains the controller beside the
    /// one local worker join handle. The paired signal is moved into the worker. Worker completion
    /// is polled before supervisor shutdown on every race wake. If shutdown wins while the worker is
    /// still pending, the supervisor requests cancellation once and then continues driving the same
    /// worker handle to terminal completion before returning.
    ///
    /// Supervisor shutdown readiness does not fabricate a cancelled worker result. The existing
    /// C03e-S worker remains authoritative for whether orderly cancellation or a real request-loop
    /// failure wins, including its existing code-4/code-3 peer-close behavior.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion`] only when Tokio
    /// reports abnormal completion for the one supervised worker task. No raw join error, task ID,
    /// panic payload or runtime identity is exposed.
    pub fn drive_supervised_capability_request_worker<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        S: Future<Output = ()> + Send,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        supervisor_shutdown: S,
    ) -> Result<AuthenticatedRemoteSessionWorkerStop, RemoteSessionSpawnedWorkerJoinError> {
        let authority = (*authority).clone();

        self.runtime.block_on(async move {
            let (cancellation_controller, cancellation_signal) =
                remote_session_worker_cancellation_pair();

            let worker_handle = tokio::spawn(async move {
                let mut session_owner = session_owner;
                let mut dispatcher = dispatcher;

                session_owner
                    .run_capability_request_worker(
                        &authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation_signal.into_cancelled(),
                    )
                    .await
            });

            await_supervised_worker(worker_handle, cancellation_controller, supervisor_shutdown)
                .await
        })
    }

    /// Drives the first bounded persistent remote-worker collection on the private current-thread
    /// runtime using an injected already-authenticated admission source.
    ///
    /// The complete collection lifetime remains inside one private `Runtime::block_on`. Active
    /// workers are keyed only by the `DeviceId` derived from each authenticated runtime owner. The
    /// injected bounded mpsc receiver is not polled while the collection is at capacity. Ready
    /// worker completions are reaped before shutdown and admission work on every supervisor poll.
    ///
    /// Duplicate `DeviceId` candidates are rejected before worker spawn and returned intact through
    /// `on_rejection`. Reaped worker results are reported immediately through `on_completion` and
    /// are not accumulated by the supervisor. When orderly shutdown wins, admission stops, every
    /// retained controller is asked to cancel before any remaining handle is drained, and the same
    /// current-thread runtime stays driven until the active map is empty.
    ///
    /// Closing the injected admission source does not cancel active workers or end this method; the
    /// separately supplied supervisor-shutdown future remains authoritative for orderly shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteSessionPersistentCollectionConfigError::CapacityExceedsRegisteredDeviceLimit`]
    /// before runtime work when `max_active_workers` exceeds [`MAX_REGISTERED_DEVICES`].
    pub fn drive_persistent_remote_worker_collection<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        S: Future<Output = ()> + Send,
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
        R: FnMut(RemoteSessionWorkerAdmissionRejection<D, T>),
    >(
        &mut self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        admissions: mpsc::Receiver<RemoteSessionWorkerAdmission<D, T>>,
        supervisor_shutdown: S,
        mut on_completion: C,
        mut on_rejection: R,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError> {
        let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;

        self.runtime.block_on(run_persistent_worker_collection(
            max_active_workers,
            admissions,
            supervisor_shutdown,
            |admission| admission.logical_device_id().clone(),
            |admission| {
                let authority = (*authority).clone();
                let (mut session_owner, mut dispatcher, verifier_time_unix_seconds) =
                    admission.into_parts();
                let (cancellation_controller, cancellation_signal) =
                    remote_session_worker_cancellation_pair();
                let worker_handle = tokio::spawn(async move {
                    session_owner
                        .run_capability_request_worker(
                            &authority,
                            verifier_time_unix_seconds,
                            &mut dispatcher,
                            cancellation_signal.into_cancelled(),
                        )
                        .await
                });
                (cancellation_controller, worker_handle)
            },
            |device_id, result| {
                on_completion(RemoteSessionRegisteredWorkerCompletion { device_id, result });
            },
            |reason, admission| {
                on_rejection(RemoteSessionWorkerAdmissionRejection { reason, admission });
            },
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, pending, ready},
        num::NonZeroUsize,
        task::{Context, Poll, Waker},
    };

    use prw_registry::MAX_REGISTERED_DEVICES;
    use tokio::{
        runtime::{Builder, Runtime},
        sync::{mpsc, oneshot},
    };

    use super::{
        AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionExecutorRuntime,
        RemoteSessionExecutorRuntimeCreateError, RemoteSessionPersistentCollectionConfigError,
        RemoteSessionSpawnedWorkerJoinError, RemoteSessionWorkerAdmissionRejectionReason,
        await_supervised_worker, remote_session_worker_cancellation_pair,
        run_persistent_worker_collection, validate_persistent_worker_capacity,
    };

    #[derive(Debug)]
    struct TestAdmission {
        key: u8,
        value: u8,
    }

    fn assert_constructor_signature(
        constructor: fn() -> Result<
            RemoteSessionExecutorRuntime,
            RemoteSessionExecutorRuntimeCreateError,
        >,
    ) {
        let _ = constructor;
    }

    fn assert_send_static<T: Send + 'static>() {}

    fn current_thread_runtime() -> Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime constructs")
    }

    #[test]
    fn executor_owner_constructor_has_exact_fallible_shape() {
        assert_constructor_signature(RemoteSessionExecutorRuntime::new);
    }

    #[test]
    fn selected_current_thread_runtime_constructs_without_running_remote_work() {
        let runtime =
            RemoteSessionExecutorRuntime::new().expect("current-thread runtime constructs");
        drop(runtime);
    }

    #[test]
    fn authenticated_remote_session_owner_is_spawn_compatible() {
        assert_send_static::<AuthenticatedRemoteSessionRuntimeOwner>();
    }

    #[test]
    fn supervisor_shutdown_cancels_pending_worker_and_joins_same_handle() {
        let runtime = current_thread_runtime();

        let result = runtime.block_on(async {
            let (controller, signal) = remote_session_worker_cancellation_pair();
            let worker_handle = tokio::spawn(async move {
                signal.into_cancelled().await;
                7_u8
            });

            await_supervised_worker(worker_handle, controller, ready(())).await
        });

        assert_eq!(result, Ok(7_u8));
    }

    #[test]
    fn completed_worker_wins_while_supervisor_shutdown_remains_pending() {
        let runtime = current_thread_runtime();

        let result = runtime.block_on(async {
            let (controller, _signal) = remote_session_worker_cancellation_pair();
            let worker_handle = tokio::spawn(async { 11_u8 });

            await_supervised_worker(worker_handle, controller, pending()).await
        });

        assert_eq!(result, Ok(11_u8));
    }

    #[test]
    fn already_completed_worker_wins_same_poll_tie_without_requesting_cancellation() {
        let runtime = current_thread_runtime();

        let (result, signal) = runtime.block_on(async {
            let (controller, signal) = remote_session_worker_cancellation_pair();
            let worker_handle = tokio::spawn(async { 13_u8 });
            tokio::task::yield_now().await;

            let result = await_supervised_worker(worker_handle, controller, ready(())).await;
            (result, signal)
        });

        assert_eq!(result, Ok(13_u8));

        let mut cancellation = Box::pin(signal.into_cancelled());
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(cancellation.as_mut().poll(&mut context), Poll::Pending);
    }

    #[test]
    fn abnormal_supervised_worker_completion_maps_to_bounded_join_error() {
        let runtime = current_thread_runtime();

        let result = runtime.block_on(async {
            let (controller, _signal) = remote_session_worker_cancellation_pair();
            let worker_handle = tokio::spawn(async {
                panic!("intentional supervised-worker test panic");
            });

            await_supervised_worker(worker_handle, controller, pending()).await
        });

        assert_eq!(
            result,
            Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        );
    }

    #[test]
    fn persistent_collection_rejects_duplicate_before_second_spawn() {
        let runtime = current_thread_runtime();

        let (spawn_count, rejected, completions) = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(4);
            assert!(sender.try_send(TestAdmission { key: 1, value: 10 }).is_ok());
            assert!(sender.try_send(TestAdmission { key: 1, value: 11 }).is_ok());
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut spawn_count = 0_usize;
            let mut rejected = Vec::new();
            let mut completions = Vec::new();

            run_persistent_worker_collection(
                2,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let handle = tokio::spawn(async move {
                        signal.into_cancelled().await;
                        candidate.value
                    });
                    (controller, handle)
                },
                |key, result| completions.push((key, result)),
                |reason, candidate| {
                    rejected.push((reason, candidate.value));
                    if let Some(sender) = shutdown_sender.take() {
                        let _ = sender.send(());
                    }
                },
            )
            .await;

            (spawn_count, rejected, completions)
        });

        assert_eq!(spawn_count, 1);
        assert_eq!(
            rejected,
            vec![(
                RemoteSessionWorkerAdmissionRejectionReason::DuplicateActiveDevice,
                11
            )]
        );
        assert_eq!(completions, vec![(1, Ok(10))]);
    }

    #[test]
    fn persistent_collection_reaps_completed_key_before_same_device_readmission() {
        let runtime = current_thread_runtime();

        let (spawn_count, rejection_count, completions) = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(4);
            assert!(sender.try_send(TestAdmission { key: 2, value: 20 }).is_ok());
            assert!(sender.try_send(TestAdmission { key: 2, value: 21 }).is_ok());
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut spawn_count = 0_usize;
            let mut rejection_count = 0_usize;
            let mut completions = Vec::new();

            run_persistent_worker_collection(
                1,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let handle = tokio::spawn(async move {
                        drop(signal);
                        candidate.value
                    });
                    (controller, handle)
                },
                |key, result| {
                    completions.push((key, result));
                    if completions.len() == 2
                        && let Some(sender) = shutdown_sender.take()
                    {
                        let _ = sender.send(());
                    }
                },
                |_reason, _candidate| rejection_count += 1,
            )
            .await;

            (spawn_count, rejection_count, completions)
        });

        assert_eq!(spawn_count, 2);
        assert_eq!(rejection_count, 0);
        assert_eq!(completions, vec![(2, Ok(20)), (2, Ok(21))]);
    }

    #[test]
    fn persistent_collection_shutdown_wins_before_prequeued_admission() {
        let runtime = current_thread_runtime();

        let (spawn_count, rejection_count, completion_count) = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(1);
            assert!(sender.try_send(TestAdmission { key: 3, value: 30 }).is_ok());
            drop(sender);

            let mut spawn_count = 0_usize;
            let mut rejection_count = 0_usize;
            let mut completion_count = 0_usize;

            run_persistent_worker_collection(
                1,
                receiver,
                ready(()),
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let handle = tokio::spawn(async move {
                        signal.into_cancelled().await;
                        candidate.value
                    });
                    (controller, handle)
                },
                |_key, _result| completion_count += 1,
                |_reason, _candidate| rejection_count += 1,
            )
            .await;

            (spawn_count, rejection_count, completion_count)
        });

        assert_eq!(spawn_count, 0);
        assert_eq!(rejection_count, 0);
        assert_eq!(completion_count, 0);
    }

    #[test]
    fn persistent_collection_shutdown_cancels_and_drains_all_retained_workers() {
        let runtime = current_thread_runtime();

        let (spawn_count, rejection_count, mut completions) = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(4);
            assert!(sender.try_send(TestAdmission { key: 4, value: 40 }).is_ok());
            assert!(sender.try_send(TestAdmission { key: 5, value: 50 }).is_ok());
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut spawn_count = 0_usize;
            let mut rejection_count = 0_usize;
            let mut completions = Vec::new();

            run_persistent_worker_collection(
                2,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let handle = tokio::spawn(async move {
                        signal.into_cancelled().await;
                        candidate.value
                    });
                    if spawn_count == 2
                        && let Some(sender) = shutdown_sender.take()
                    {
                        let _ = sender.send(());
                    }
                    (controller, handle)
                },
                |key, result| completions.push((key, result)),
                |_reason, _candidate| rejection_count += 1,
            )
            .await;

            (spawn_count, rejection_count, completions)
        });

        completions.sort_by_key(|(key, _)| *key);
        assert_eq!(spawn_count, 2);
        assert_eq!(rejection_count, 0);
        assert_eq!(completions, vec![(4, Ok(40)), (5, Ok(50))]);
    }

    #[test]
    fn closed_admission_source_does_not_end_persistent_supervisor() {
        let runtime = current_thread_runtime();

        runtime.block_on(async {
            let (sender, receiver) = mpsc::channel::<TestAdmission>(1);
            drop(sender);
            let (shutdown_sender, shutdown_receiver) = oneshot::channel();

            let supervisor = tokio::spawn(run_persistent_worker_collection(
                1,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let handle = tokio::spawn(async move {
                        signal.into_cancelled().await;
                        candidate.value
                    });
                    (controller, handle)
                },
                |_key, _result| {},
                |_reason, _candidate| {},
            ));

            tokio::task::yield_now().await;
            assert!(!supervisor.is_finished());
            assert!(shutdown_sender.send(()).is_ok());
            assert!(supervisor.await.is_ok());
        });
    }

    #[test]
    fn persistent_collection_capacity_rejects_only_values_above_registry_ceiling() {
        let maximum = NonZeroUsize::new(MAX_REGISTERED_DEVICES).expect("nonzero registry limit");
        assert_eq!(
            validate_persistent_worker_capacity(maximum),
            Ok(MAX_REGISTERED_DEVICES)
        );

        let above_maximum =
            NonZeroUsize::new(MAX_REGISTERED_DEVICES + 1).expect("nonzero larger limit");
        assert_eq!(
            validate_persistent_worker_capacity(above_maximum),
            Err(RemoteSessionPersistentCollectionConfigError::CapacityExceedsRegisteredDeviceLimit)
        );
    }
}

pub use repeated_real_admission_supervisor::{
    RemoteSessionExpectedDeviceAdmissionRejection,
    RemoteSessionExpectedDeviceAdmissionRejectionReason,
    RemoteSessionExpectedDeviceAdmissionRequest, RemoteSessionProductionPreAjTiming,
    RemoteSessionRealAdmissionTiming, RemoteSessionRepeatedAdmissionFailure,
};

mod repeated_real_admission_supervisor {
    use std::{
        collections::{HashMap, hash_map::Entry},
        future::{Future, poll_fn},
        num::NonZeroUsize,
        ops::Range,
        pin::Pin,
        task::{Context, Poll},
    };

    use prw_core::{DeviceId, SessionId};
    use prw_policy::PolicyEvaluator;
    use prw_remote_bridge::CapabilityDispatcher;
    use prw_session::SessionAuthenticationService;
    use tokio::sync::mpsc;

    use super::{
        AuthenticatedRemoteSessionWorkerStop, RemoteSessionExecutorRuntime,
        RemoteSessionPersistentCollectionConfigError, RemoteSessionPersistentWorkerEntry,
        RemoteSessionRegisteredWorkerCompletion, RemoteSessionWorkerAdmission,
        SharedCurrentCapabilityAuthority, reap_ready_persistent_workers,
        remote_session_worker_cancellation_pair, validate_persistent_worker_capacity,
    };
    use crate::{
        remote_session_capability_runtime::{
            RemoteSessionRealAdmissionError, admit_expected_remote_device_session,
        },
        remote_transport_runtime::AgentRemoteTransportRuntime,
    };

    type ActiveRemoteWorkers =
        HashMap<DeviceId, RemoteSessionPersistentWorkerEntry<AuthenticatedRemoteSessionWorkerStop>>;

    const REMOTE_ENDPOINT_SHUTDOWN_CODE: u32 = 0;
    const REMOTE_ENDPOINT_SHUTDOWN_REASON: &[u8] = b"remote endpoint shutdown";

    fn finish_remote_endpoint_shutdown<R, C, W>(
        executor: &RemoteSessionExecutorRuntime,
        result: R,
        close_endpoint: C,
        wait_idle: W,
    ) -> R
    where
        C: FnOnce(u32, &[u8]),
        W: Future<Output = ()>,
    {
        close_endpoint(
            REMOTE_ENDPOINT_SHUTDOWN_CODE,
            REMOTE_ENDPOINT_SHUTDOWN_REASON,
        );
        executor.runtime.block_on(wait_idle);
        result
    }

    /// One bounded pre-authentication request for the repeated real-admission supervisor.
    pub struct RemoteSessionExpectedDeviceAdmissionRequest<D, T> {
        expected_device_id: DeviceId,
        session_id: SessionId,
        authentication_request_id: u64,
        dispatcher: D,
        verifier_time_unix_seconds: T,
    }

    impl<D, T> RemoteSessionExpectedDeviceAdmissionRequest<D, T> {
        /// Creates one expected-device request without any caller-supplied transport identity.
        #[must_use]
        pub const fn new(
            expected_device_id: DeviceId,
            session_id: SessionId,
            authentication_request_id: u64,
            dispatcher: D,
            verifier_time_unix_seconds: T,
        ) -> Self {
            Self {
                expected_device_id,
                session_id,
                authentication_request_id,
                dispatcher,
                verifier_time_unix_seconds,
            }
        }

        /// Returns the pre-authentication logical `DeviceId` used only for scheduling the AJ attempt.
        #[must_use]
        pub const fn expected_device_id(&self) -> &DeviceId {
            &self.expected_device_id
        }

        /// Recovers every owned request component unchanged.
        #[must_use]
        pub fn into_parts(self) -> (DeviceId, SessionId, u64, D, T) {
            (
                self.expected_device_id,
                self.session_id,
                self.authentication_request_id,
                self.dispatcher,
                self.verifier_time_unix_seconds,
            )
        }
    }

    /// Fresh timing inputs sampled only when one expected-device AJ attempt actually starts.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[expect(
        clippy::struct_field_names,
        reason = "C03e-AL keeps explicit unix-second units on every AJ timing input"
    )]
    pub struct RemoteSessionRealAdmissionTiming {
        challenge_validity_unix_seconds: Range<u64>,
        authentication_now_unix_seconds: u64,
        application_lease_unix_seconds: Range<u64>,
    }

    impl RemoteSessionRealAdmissionTiming {
        /// Creates one owned timing bundle for exactly one AJ transaction.
        #[must_use]
        pub const fn new(
            challenge_validity_unix_seconds: Range<u64>,
            authentication_now_unix_seconds: u64,
            application_lease_unix_seconds: Range<u64>,
        ) -> Self {
            Self {
                challenge_validity_unix_seconds,
                authentication_now_unix_seconds,
                application_lease_unix_seconds,
            }
        }

        /// Consumes the timing bundle into the exact existing AJ timing inputs.
        #[must_use]
        pub const fn into_parts(self) -> (Range<u64>, u64, Range<u64>) {
            (
                self.challenge_validity_unix_seconds,
                self.authentication_now_unix_seconds,
                self.application_lease_unix_seconds,
            )
        }
    }

    /// Fresh challenge timing owned only by the future production pre-AJ admission sibling.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RemoteSessionProductionPreAjTiming {
        challenge_validity_unix_seconds: Range<u64>,
    }

    impl RemoteSessionProductionPreAjTiming {
        /// Creates one production pre-AJ timing value containing only challenge validity.
        #[must_use]
        pub const fn new(challenge_validity_unix_seconds: Range<u64>) -> Self {
            Self {
                challenge_validity_unix_seconds,
            }
        }

        /// Consumes the value into the exact challenge-validity range.
        #[must_use]
        pub const fn into_challenge_validity_unix_seconds(self) -> Range<u64> {
            self.challenge_validity_unix_seconds
        }
    }

    /// Bounded reason an expected-device request was rejected before any AJ/network work.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum RemoteSessionExpectedDeviceAdmissionRejectionReason {
        /// One active authenticated worker already owns the same logical `DeviceId`.
        DuplicateActiveDevice,
    }

    /// Owns one untouched pre-authentication request rejected before AJ construction.
    pub struct RemoteSessionExpectedDeviceAdmissionRejection<D, T> {
        reason: RemoteSessionExpectedDeviceAdmissionRejectionReason,
        request: RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    }

    impl<D, T> RemoteSessionExpectedDeviceAdmissionRejection<D, T> {
        /// Returns the bounded pre-authentication rejection reason.
        #[must_use]
        pub const fn reason(&self) -> RemoteSessionExpectedDeviceAdmissionRejectionReason {
            self.reason
        }

        /// Returns the untouched rejected request by reference.
        #[must_use]
        pub const fn request(&self) -> &RemoteSessionExpectedDeviceAdmissionRequest<D, T> {
            &self.request
        }

        /// Recovers ownership of the untouched rejected request.
        #[must_use]
        pub fn into_request(self) -> RemoteSessionExpectedDeviceAdmissionRequest<D, T> {
            self.request
        }
    }

    /// One bounded AJ failure reported by the repeated supervisor without terminating it.
    #[derive(Debug)]
    pub struct RemoteSessionRepeatedAdmissionFailure {
        expected_device_id: DeviceId,
        error: RemoteSessionRealAdmissionError,
    }

    impl RemoteSessionRepeatedAdmissionFailure {
        /// Returns the logical `DeviceId` that selected the failed AJ attempt.
        #[must_use]
        pub const fn expected_device_id(&self) -> &DeviceId {
            &self.expected_device_id
        }

        /// Returns the exact existing AJ error unchanged.
        #[must_use]
        pub const fn error(&self) -> &RemoteSessionRealAdmissionError {
            &self.error
        }

        /// Recovers the logical `DeviceId` and exact existing AJ error.
        #[must_use]
        pub fn into_parts(self) -> (DeviceId, RemoteSessionRealAdmissionError) {
            (self.expected_device_id, self.error)
        }
    }

    enum RepeatedSupervisorEvent<C> {
        Shutdown,
        Request(C),
    }

    enum InFlightAdmissionEvent<R> {
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
    ) -> Poll<RepeatedSupervisorEvent<C>>
    where
        S: Future<Output = ()>,
    {
        if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
            return Poll::Ready(RepeatedSupervisorEvent::Shutdown);
        }

        if *request_source_open && active_len < max_active_workers {
            match Pin::new(requests).poll_recv(context) {
                Poll::Ready(Some(request)) => {
                    return Poll::Ready(RepeatedSupervisorEvent::Request(request));
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
    ) -> Poll<InFlightAdmissionEvent<A::Output>>
    where
        S: Future<Output = ()>,
        A: Future,
    {
        if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
            return Poll::Ready(InFlightAdmissionEvent::Shutdown);
        }

        admission
            .as_mut()
            .poll(context)
            .map(InFlightAdmissionEvent::Complete)
    }

    fn reap_registered_workers<C>(
        active: &mut ActiveRemoteWorkers,
        context: &mut Context<'_>,
        on_completion: &mut C,
    ) where
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
    {
        let mut report = |device_id, result| {
            on_completion(RemoteSessionRegisteredWorkerCompletion { device_id, result });
        };
        reap_ready_persistent_workers(active, context, &mut report);
    }

    fn request_all_worker_cancellations(active: &ActiveRemoteWorkers) {
        for entry in active.values() {
            entry.cancellation_controller.request_cancellation();
        }
    }

    async fn drain_registered_workers<C>(active: &mut ActiveRemoteWorkers, on_completion: &mut C)
    where
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
    {
        poll_fn(|context| {
            reap_registered_workers(active, context, on_completion);
            if active.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    async fn drain_inflight_admission<A, C>(
        active: &mut ActiveRemoteWorkers,
        mut admission: Pin<&mut A>,
        on_completion: &mut C,
    ) -> A::Output
    where
        A: Future,
        C: FnMut(RemoteSessionRegisteredWorkerCompletion),
    {
        poll_fn(|context| {
            reap_registered_workers(active, context, on_completion);
            admission.as_mut().poll(context)
        })
        .await
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
        R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
    {
        let expected_device_id = request.expected_device_id().clone();
        if active.contains_key(&expected_device_id) {
            on_rejection(RemoteSessionExpectedDeviceAdmissionRejection {
                reason: RemoteSessionExpectedDeviceAdmissionRejectionReason::DuplicateActiveDevice,
                request,
            });
            return None;
        }

        let timing = admission_timing(&expected_device_id);
        Some((request, timing))
    }

    fn spawn_registered_worker<P, D, T>(
        admission: RemoteSessionWorkerAdmission<D, T>,
        authority: &SharedCurrentCapabilityAuthority<P>,
    ) -> RemoteSessionPersistentWorkerEntry<AuthenticatedRemoteSessionWorkerStop>
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
    {
        let authority = (*authority).clone();
        let (mut session_owner, mut dispatcher, verifier_time_unix_seconds) =
            admission.into_parts();
        let (cancellation_controller, cancellation_signal) =
            remote_session_worker_cancellation_pair();
        let worker_handle = tokio::spawn(async move {
            session_owner
                .run_capability_request_worker(
                    &authority,
                    verifier_time_unix_seconds,
                    &mut dispatcher,
                    cancellation_signal.into_cancelled(),
                )
                .await
        });

        RemoteSessionPersistentWorkerEntry {
            cancellation_controller,
            worker_handle,
        }
    }

    type FallibleVerifierTimeActiveRemoteWorkers = HashMap<
    DeviceId,
    RemoteSessionPersistentWorkerEntry<
        crate::remote_session_capability_runtime::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
    >,
>;

    fn reap_fallible_verifier_time_registered_workers<C>(
        active: &mut FallibleVerifierTimeActiveRemoteWorkers,
        context: &mut Context<'_>,
        on_completion: &mut C,
    ) where
        C: FnMut(super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
    {
        let mut report = |device_id, result| {
            on_completion(
                super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion {
                    device_id,
                    result,
                },
            );
        };
        reap_ready_persistent_workers(active, context, &mut report);
    }

    fn request_all_fallible_verifier_time_worker_cancellations(
        active: &FallibleVerifierTimeActiveRemoteWorkers,
    ) {
        for entry in active.values() {
            entry.cancellation_controller.request_cancellation();
        }
    }

    async fn drain_fallible_verifier_time_registered_workers<C>(
        active: &mut FallibleVerifierTimeActiveRemoteWorkers,
        on_completion: &mut C,
    ) where
        C: FnMut(super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
    {
        poll_fn(|context| {
            reap_fallible_verifier_time_registered_workers(active, context, on_completion);
            if active.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    async fn drain_fallible_verifier_time_inflight_admission<A, C>(
        active: &mut FallibleVerifierTimeActiveRemoteWorkers,
        mut admission: Pin<&mut A>,
        on_completion: &mut C,
    ) -> A::Output
    where
        A: Future,
        C: FnMut(super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
    {
        poll_fn(|context| {
            reap_fallible_verifier_time_registered_workers(active, context, on_completion);
            admission.as_mut().poll(context)
        })
        .await
    }

    fn spawn_fallible_verifier_time_registered_worker<P, D, T>(
        admission: RemoteSessionWorkerAdmission<D, T>,
        authority: &SharedCurrentCapabilityAuthority<P>,
    ) -> RemoteSessionPersistentWorkerEntry<
        crate::remote_session_capability_runtime::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
    >
    where
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<
                u64,
                prw_session::prwa_verifier_source::PrwaVerifierSourceError,
            > + Send
            + 'static,
    {
        let authority = (*authority).clone();
        let (mut session_owner, mut dispatcher, verifier_time_unix_seconds) =
            admission.into_parts();
        let (cancellation_controller, cancellation_signal) =
            remote_session_worker_cancellation_pair();
        let worker_handle = tokio::spawn(async move {
            session_owner
                .run_fallible_verifier_time_capability_request_worker(
                    &authority,
                    verifier_time_unix_seconds,
                    &mut dispatcher,
                    cancellation_signal.into_cancelled(),
                )
                .await
        });

        RemoteSessionPersistentWorkerEntry {
            cancellation_controller,
            worker_handle,
        }
    }

    impl RemoteSessionExecutorRuntime {
        /// Drives repeated expected-device real admission with the dormant fallible verifier-time
        /// persistent worker collection inside the same private current-thread runtime lifetime.
        ///
        /// The existing AJ/request polling helpers remain authoritative for duplicate preflight,
        /// timing sampling, one-AJ-in-flight custody and shutdown precedence. Active authenticated
        /// workers are keyed only by authenticated owner-derived `DeviceId` and use the existing
        /// cancellation/join custody. Fallible verifier time is moved untouched into each worker and
        /// sampled only by the existing C03e-PD worker path.
        ///
        /// `Cancelled` and `Failed(exact PB error)` remain normal completion values. Only abnormal
        /// Tokio task completion uses the existing bounded join error. Endpoint lifecycle, provider
        /// installation and production caller activation remain separately gated.
        ///
        /// # Errors
        ///
        /// Returns the existing persistent-collection configuration error before runtime work when
        /// `max_active_workers` exceeds the registered-device ceiling.
        #[allow(
            dead_code,
            reason = "C03e-PN materializes the PM-selected repeated real-admission fallible verifier-time compatibility seam before separately gated endpoint lifecycle composition"
        )]
        #[expect(
            clippy::too_many_arguments,
            clippy::too_many_lines,
            clippy::needless_pass_by_ref_mut,
            reason = "C03e-PN mirrors the existing repeated real-admission supervisor input surface while changing only fallible worker/result custody"
        )]
        pub(super) fn drive_repeated_real_fallible_verifier_time_remote_admission_collection<
            P,
            D,
            T,
            S,
            F,
            C,
            R,
            E,
        >(
            &mut self,
            max_active_workers: NonZeroUsize,
            transport_runtime: &AgentRemoteTransportRuntime,
            authority: &SharedCurrentCapabilityAuthority<P>,
            session_authentication: &mut SessionAuthenticationService,
            expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
            supervisor_shutdown: S,
            mut admission_timing: F,
            mut on_completion: C,
            mut on_rejection: R,
            mut on_admission_failure: E,
        ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
        where
            P: PolicyEvaluator + Send + Sync + 'static,
            D: CapabilityDispatcher + Send + 'static,
            T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
                + Send
                + 'static,
            S: Future<Output = ()> + Send,
            F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            C: FnMut(super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
            R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
            E: FnMut(RemoteSessionRepeatedAdmissionFailure),
        {
            let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;
            let mut expected_requests = expected_requests;

            self.runtime.block_on(async {
                let mut active = FallibleVerifierTimeActiveRemoteWorkers::new();
                let mut supervisor_shutdown = Box::pin(supervisor_shutdown);
                let mut request_source_open = true;

                loop {
                    let event = poll_fn(|context| {
                        reap_fallible_verifier_time_registered_workers(
                            &mut active,
                            context,
                            &mut on_completion,
                        );
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

                    let RepeatedSupervisorEvent::Request(request) = event else {
                        request_all_fallible_verifier_time_worker_cancellations(&active);
                        drain_fallible_verifier_time_registered_workers(
                            &mut active,
                            &mut on_completion,
                        )
                        .await;
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
                        reap_fallible_verifier_time_registered_workers(
                            &mut active,
                            context,
                            &mut on_completion,
                        );
                        poll_shutdown_or_inflight_admission(
                            supervisor_shutdown.as_mut(),
                            admission.as_mut(),
                            context,
                        )
                    })
                    .await;

                    match admission_event {
                        InFlightAdmissionEvent::Complete(result) => {
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
                                            slot.insert(
                                                spawn_fallible_verifier_time_registered_worker(
                                                    worker_admission,
                                                    authority,
                                                ),
                                            );
                                        }
                                        Entry::Occupied(_) => {
                                            unreachable!(
                                                "single in-flight preflight guarantees a vacant post-auth DeviceId"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    on_admission_failure(RemoteSessionRepeatedAdmissionFailure {
                                        expected_device_id,
                                        error,
                                    });
                                }
                            }
                        }
                        InFlightAdmissionEvent::Shutdown => {
                            request_all_fallible_verifier_time_worker_cancellations(
                                &active,
                            );
                            let result = drain_fallible_verifier_time_inflight_admission(
                                &mut active,
                                admission.as_mut(),
                                &mut on_completion,
                            )
                            .await;
                            drop(admission);

                            match result {
                                Ok(session_owner) => {
                                    session_owner.close_for_orderly_shutdown();
                                }
                                Err(error) => {
                                    on_admission_failure(RemoteSessionRepeatedAdmissionFailure {
                                        expected_device_id,
                                        error,
                                    });
                                }
                            }

                            drain_fallible_verifier_time_registered_workers(
                                &mut active,
                                &mut on_completion,
                            )
                            .await;
                            return;
                        }
                    }
                }
            });

            Ok(())
        }
    }

    impl RemoteSessionExecutorRuntime {
        /// Drives the dormant fallible verifier-time repeated supervisor to full return and then
        /// deterministically closes and drains the already-bound remote endpoint on the same private
        /// current-thread runtime.
        ///
        /// The C03e-PN fallible repeated collection remains authoritative for request/admission,
        /// authenticated identity, worker cancellation/join custody and fallible verifier-time worker
        /// completion. This outer seam captures its exact result without early propagation, then reuses
        /// the existing endpoint teardown helper so close occurs exactly once before `wait_idle()` and
        /// the original collection result is returned unchanged.
        ///
        /// # Errors
        ///
        /// Returns the existing persistent-collection configuration error unchanged after endpoint close
        /// and idle drain when the fallible repeated collection rejects its worker-capacity configuration.
        #[allow(
            dead_code,
            reason = "C03e-PP materializes the PO-selected dormant fallible verifier-time endpoint lifecycle composition before separately gated production caller wiring"
        )]
        #[expect(
            clippy::too_many_arguments,
            reason = "C03e-PP composes the exact C03e-PN fallible repeated-collection inputs with the existing endpoint teardown helper"
        )]
        pub(in crate::remote_session_capability_runtime) fn drive_repeated_real_fallible_verifier_time_remote_admission_endpoint_lifecycle<
            P,
            D,
            T,
            S,
            F,
            C,
            R,
            E,
        >(
            &mut self,
            max_active_workers: NonZeroUsize,
            transport_runtime: &AgentRemoteTransportRuntime,
            authority: &SharedCurrentCapabilityAuthority<P>,
            session_authentication: &mut SessionAuthenticationService,
            expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
            supervisor_shutdown: S,
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
            S: Future<Output = ()> + Send,
            F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            C: FnMut(super::RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
            R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
            E: FnMut(RemoteSessionRepeatedAdmissionFailure),
        {
            let result = self
                .drive_repeated_real_fallible_verifier_time_remote_admission_collection(
                    max_active_workers,
                    transport_runtime,
                    authority,
                    session_authentication,
                    expected_requests,
                    supervisor_shutdown,
                    admission_timing,
                    on_completion,
                    on_rejection,
                    on_admission_failure,
                );

            finish_remote_endpoint_shutdown(
                self,
                result,
                |code, reason| transport_runtime.close(code, reason),
                transport_runtime.wait_idle(),
            )
        }
    }

    impl RemoteSessionExecutorRuntime {
        /// Drives repeated expected-device real admission and the persistent worker collection inside
        /// the same private current-thread runtime lifetime.
        ///
        /// Ready worker completions are reaped first. Supervisor shutdown is polled before either a
        /// new expected request or the one in-flight AJ transaction. Requests are not polled while
        /// the active collection is full, duplicate expected `DeviceId` values are rejected before timing or
        /// network work, and at most one AJ future exists at a time.
        ///
        /// When shutdown latches during AJ, all active worker cancellations are requested and the AJ
        /// future is retained and drained rather than dropped. A post-shutdown AJ success is consumed
        /// through the code-4 authenticated-owner close seam without worker spawn/insertion.
        ///
        /// # Errors
        ///
        /// Returns the existing persistent-collection configuration error before runtime work when
        /// `max_active_workers` exceeds the registered-device ceiling.
        #[expect(
            clippy::too_many_arguments,
            clippy::too_many_lines,
            reason = "C03e-AL intentionally materializes the AK-selected explicit supervisor inputs and callbacks"
        )]
        pub fn drive_repeated_real_remote_admission_collection<P, D, T, S, F, C, R, E>(
            &mut self,
            max_active_workers: NonZeroUsize,
            transport_runtime: &AgentRemoteTransportRuntime,
            authority: &SharedCurrentCapabilityAuthority<P>,
            session_authentication: &mut SessionAuthenticationService,
            expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
            supervisor_shutdown: S,
            mut admission_timing: F,
            mut on_completion: C,
            mut on_rejection: R,
            mut on_admission_failure: E,
        ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
        where
            P: PolicyEvaluator + Send + Sync + 'static,
            D: CapabilityDispatcher + Send + 'static,
            T: FnMut() -> u64 + Send + 'static,
            S: Future<Output = ()> + Send,
            F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            C: FnMut(RemoteSessionRegisteredWorkerCompletion),
            R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
            E: FnMut(RemoteSessionRepeatedAdmissionFailure),
        {
            let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;
            let mut expected_requests = expected_requests;

            self.runtime.block_on(async {
                let mut active = ActiveRemoteWorkers::new();
                let mut supervisor_shutdown = Box::pin(supervisor_shutdown);
                let mut request_source_open = true;

                loop {
                    let event = poll_fn(|context| {
                        reap_registered_workers(&mut active, context, &mut on_completion);
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

                    let RepeatedSupervisorEvent::Request(request) = event else {
                        request_all_worker_cancellations(&active);
                        drain_registered_workers(&mut active, &mut on_completion).await;
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
                        reap_registered_workers(&mut active, context, &mut on_completion);
                        poll_shutdown_or_inflight_admission(
                            supervisor_shutdown.as_mut(),
                            admission.as_mut(),
                            context,
                        )
                    })
                    .await;

                    match admission_event {
                        InFlightAdmissionEvent::Complete(result) => {
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
                                            slot.insert(spawn_registered_worker(
                                                worker_admission,
                                                authority,
                                            ));
                                        }
                                        Entry::Occupied(_) => {
                                            unreachable!(
                                                "single in-flight preflight guarantees a vacant post-auth DeviceId"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    on_admission_failure(RemoteSessionRepeatedAdmissionFailure {
                                        expected_device_id,
                                        error,
                                    });
                                }
                            }
                        }
                        InFlightAdmissionEvent::Shutdown => {
                            request_all_worker_cancellations(&active);
                            let result = drain_inflight_admission(
                                &mut active,
                                admission.as_mut(),
                                &mut on_completion,
                            )
                            .await;
                            drop(admission);

                            match result {
                                Ok(session_owner) => session_owner.close_for_orderly_shutdown(),
                                Err(error) => {
                                    on_admission_failure(RemoteSessionRepeatedAdmissionFailure {
                                        expected_device_id,
                                        error,
                                    });
                                }
                            }

                            drain_registered_workers(&mut active, &mut on_completion).await;
                            return;
                        }
                    }
                }
            });

            Ok(())
        }
        /// Drives the repeated remote-session supervisor and then deterministically closes and
        /// drains the already-bound remote endpoint on the same private current-thread runtime.
        ///
        /// The existing C03e-AL supervisor is driven to full return before whole-endpoint close.
        /// Its result is captured without early propagation so even pre-drive configuration
        /// failure still closes the endpoint once and drives `wait_idle()` before the exact
        /// original result is returned.
        ///
        /// This domain-specific seam uses only sequential private runtime drives. It exposes no
        /// generic `block_on`, runtime handle, second runtime, readiness or activation surface.
        ///
        /// # Errors
        ///
        /// Returns the existing persistent-collection configuration error unchanged after the
        /// deterministic endpoint close and idle drain when the C03e-AL drive rejects its worker
        /// capacity configuration.
        #[expect(
            clippy::too_many_arguments,
            reason = "C03e-AN composes the exact existing C03e-AL inputs with endpoint teardown"
        )]
        pub fn drive_repeated_real_remote_admission_endpoint_lifecycle<P, D, T, S, F, C, R, E>(
            &mut self,
            max_active_workers: NonZeroUsize,
            transport_runtime: &AgentRemoteTransportRuntime,
            authority: &SharedCurrentCapabilityAuthority<P>,
            session_authentication: &mut SessionAuthenticationService,
            expected_requests: mpsc::Receiver<RemoteSessionExpectedDeviceAdmissionRequest<D, T>>,
            supervisor_shutdown: S,
            admission_timing: F,
            on_completion: C,
            on_rejection: R,
            on_admission_failure: E,
        ) -> Result<(), RemoteSessionPersistentCollectionConfigError>
        where
            P: PolicyEvaluator + Send + Sync + 'static,
            D: CapabilityDispatcher + Send + 'static,
            T: FnMut() -> u64 + Send + 'static,
            S: Future<Output = ()> + Send,
            F: FnMut(&DeviceId) -> RemoteSessionRealAdmissionTiming,
            C: FnMut(RemoteSessionRegisteredWorkerCompletion),
            R: FnMut(RemoteSessionExpectedDeviceAdmissionRejection<D, T>),
            E: FnMut(RemoteSessionRepeatedAdmissionFailure),
        {
            let result = self.drive_repeated_real_remote_admission_collection(
                max_active_workers,
                transport_runtime,
                authority,
                session_authentication,
                expected_requests,
                supervisor_shutdown,
                admission_timing,
                on_completion,
                on_rejection,
                on_admission_failure,
            );

            finish_remote_endpoint_shutdown(
                self,
                result,
                |code, reason| transport_runtime.close(code, reason),
                transport_runtime.wait_idle(),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            cell::{Cell, RefCell},
            collections::HashMap,
            future::{Future, pending, ready},
            pin::Pin,
            rc::Rc,
            task::{Context, Poll, Waker},
        };

        use prw_core::{DeviceId, SessionId};
        use prw_registry::RegistryError;
        use tokio::{runtime::Builder, sync::mpsc};

        use super::{
            ActiveRemoteWorkers, InFlightAdmissionEvent, REMOTE_ENDPOINT_SHUTDOWN_CODE,
            REMOTE_ENDPOINT_SHUTDOWN_REASON, RemoteSessionExecutorRuntime,
            RemoteSessionExpectedDeviceAdmissionRejectionReason,
            RemoteSessionExpectedDeviceAdmissionRequest,
            RemoteSessionPersistentCollectionConfigError, RemoteSessionPersistentWorkerEntry,
            RemoteSessionProductionPreAjTiming, RemoteSessionRealAdmissionError,
            RemoteSessionRealAdmissionTiming, RemoteSessionRepeatedAdmissionFailure,
            RepeatedSupervisorEvent, drain_registered_workers, finish_remote_endpoint_shutdown,
            poll_shutdown_or_expected_request, poll_shutdown_or_inflight_admission,
            prepare_expected_request, remote_session_worker_cancellation_pair,
            request_all_worker_cancellations,
        };
        use crate::remote_session_capability_runtime::authenticated_remote_session_runtime::AuthenticatedRemoteSessionWorkerStop;

        fn device_id(value: &str) -> DeviceId {
            DeviceId::new(value).expect("test DeviceId is nonempty")
        }

        fn session_id(value: &str) -> SessionId {
            SessionId::new(value).expect("test SessionId is nonempty")
        }

        fn test_timing() -> RemoteSessionRealAdmissionTiming {
            RemoteSessionRealAdmissionTiming::new(10..20, 12, 10..30)
        }

        #[test]
        fn production_pre_aj_timing_owns_only_challenge_validity_range() {
            let timing = RemoteSessionProductionPreAjTiming::new(40..50);
            assert_eq!(timing.into_challenge_validity_unix_seconds(), 40..50);
        }

        #[test]
        fn endpoint_finish_closes_once_before_idle_and_preserves_original_error() {
            let executor = RemoteSessionExecutorRuntime::new()
                .expect("test current-thread executor constructs");
            let events = Rc::new(RefCell::new(Vec::<&'static str>::new()));
            let close_events = Rc::clone(&events);
            let idle_events = Rc::clone(&events);
            let original: Result<(), RemoteSessionPersistentCollectionConfigError> = Err(
                RemoteSessionPersistentCollectionConfigError::CapacityExceedsRegisteredDeviceLimit,
            );

            let result = finish_remote_endpoint_shutdown(
                &executor,
                original,
                move |code, reason| {
                    assert_eq!(code, REMOTE_ENDPOINT_SHUTDOWN_CODE);
                    assert_eq!(code, 0);
                    assert_eq!(reason, REMOTE_ENDPOINT_SHUTDOWN_REASON);
                    assert_eq!(reason, b"remote endpoint shutdown");
                    close_events.borrow_mut().push("close");
                },
                async move {
                    idle_events.borrow_mut().push("idle");
                },
            );

            assert_eq!(
            result,
            Err(RemoteSessionPersistentCollectionConfigError::CapacityExceedsRegisteredDeviceLimit)
        );
            assert_eq!(events.borrow().as_slice(), ["close", "idle"]);
        }

        struct TrackedReadyFuture {
            polls: Rc<Cell<usize>>,
            drops: Rc<Cell<usize>>,
        }

        impl Future for TrackedReadyFuture {
            type Output = u8;

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
                self.polls.set(self.polls.get() + 1);
                Poll::Ready(7)
            }
        }

        impl Drop for TrackedReadyFuture {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }

        #[test]
        fn full_capacity_does_not_poll_expected_request_source() {
            let (sender, mut receiver) = mpsc::channel(1);
            assert!(sender.try_send(41_u8).is_ok());
            let mut request_source_open = true;
            let mut shutdown = Box::pin(pending::<()>());
            let mut context = Context::from_waker(Waker::noop());

            let result = poll_shutdown_or_expected_request(
                1,
                1,
                &mut request_source_open,
                &mut receiver,
                shutdown.as_mut(),
                &mut context,
            );

            assert!(matches!(result, Poll::Pending));
            assert_eq!(receiver.try_recv(), Ok(41_u8));
        }

        #[test]
        fn closed_expected_request_source_does_not_fabricate_shutdown() {
            let (sender, mut receiver) = mpsc::channel::<u8>(1);
            drop(sender);
            let mut request_source_open = true;
            let mut shutdown = Box::pin(pending::<()>());
            let mut context = Context::from_waker(Waker::noop());

            let result = poll_shutdown_or_expected_request(
                0,
                1,
                &mut request_source_open,
                &mut receiver,
                shutdown.as_mut(),
                &mut context,
            );

            assert!(matches!(result, Poll::Pending));
            assert!(!request_source_open);
        }

        #[test]
        fn duplicate_expected_device_is_rejected_before_timing_sample() {
            let duplicate = device_id("duplicate-device");
            let mut active = HashMap::<DeviceId, u8>::new();
            active.insert(duplicate.clone(), 1_u8);
            let request = RemoteSessionExpectedDeviceAdmissionRequest::new(
                duplicate.clone(),
                session_id("duplicate-session"),
                1,
                9_u8,
                10_u8,
            );
            let timing_samples = Rc::new(Cell::new(0_usize));
            let timing_samples_for_factory = Rc::clone(&timing_samples);
            let mut timing_factory = move |_device_id: &DeviceId| {
                timing_samples_for_factory.set(timing_samples_for_factory.get() + 1);
                test_timing()
            };
            let mut rejection = None;

            let prepared =
                prepare_expected_request(&active, request, &mut timing_factory, &mut |observed| {
                    rejection = Some(observed);
                });

            assert!(prepared.is_none());
            assert_eq!(timing_samples.get(), 0);
            let rejection = rejection.expect("duplicate request rejected");
            assert_eq!(
                rejection.reason(),
                RemoteSessionExpectedDeviceAdmissionRejectionReason::DuplicateActiveDevice
            );
            assert_eq!(rejection.request().expected_device_id(), &duplicate);
        }

        #[test]
        fn timing_is_sampled_once_only_for_request_that_can_start() {
            let expected = device_id("fresh-device");
            let active = HashMap::<DeviceId, u8>::new();
            let request = RemoteSessionExpectedDeviceAdmissionRequest::new(
                expected,
                session_id("fresh-session"),
                2,
                11_u8,
                12_u8,
            );
            let timing_samples = Rc::new(Cell::new(0_usize));
            let timing_samples_for_factory = Rc::clone(&timing_samples);
            let mut timing_factory = move |_device_id: &DeviceId| {
                timing_samples_for_factory.set(timing_samples_for_factory.get() + 1);
                test_timing()
            };

            let prepared = prepare_expected_request(
                &active,
                request,
                &mut timing_factory,
                &mut |_rejection| panic!("fresh DeviceId must not be rejected"),
            );

            assert!(prepared.is_some());
            assert_eq!(timing_samples.get(), 1);
        }

        #[test]
        fn shutdown_wins_same_poll_without_polling_or_dropping_ready_admission() {
            let polls = Rc::new(Cell::new(0_usize));
            let drops = Rc::new(Cell::new(0_usize));
            let mut admission = Box::pin(TrackedReadyFuture {
                polls: Rc::clone(&polls),
                drops: Rc::clone(&drops),
            });
            let mut shutdown = Box::pin(ready(()));
            let mut context = Context::from_waker(Waker::noop());

            let result = poll_shutdown_or_inflight_admission(
                shutdown.as_mut(),
                admission.as_mut(),
                &mut context,
            );

            assert!(matches!(
                result,
                Poll::Ready(InFlightAdmissionEvent::Shutdown)
            ));
            assert_eq!(polls.get(), 0);
            assert_eq!(drops.get(), 0);

            let mut pending_shutdown = Box::pin(pending::<()>());
            let result = poll_shutdown_or_inflight_admission(
                pending_shutdown.as_mut(),
                admission.as_mut(),
                &mut context,
            );
            assert!(matches!(
                result,
                Poll::Ready(InFlightAdmissionEvent::Complete(7))
            ));
            assert_eq!(polls.get(), 1);
            assert_eq!(drops.get(), 0);
            drop(admission);
            assert_eq!(drops.get(), 1);
        }

        #[test]
        fn ready_shutdown_wins_before_prequeued_expected_request() {
            let (sender, mut receiver) = mpsc::channel(1);
            assert!(sender.try_send(77_u8).is_ok());
            let mut request_source_open = true;
            let mut shutdown = Box::pin(ready(()));
            let mut context = Context::from_waker(Waker::noop());

            let result = poll_shutdown_or_expected_request(
                0,
                1,
                &mut request_source_open,
                &mut receiver,
                shutdown.as_mut(),
                &mut context,
            );

            assert!(matches!(
                result,
                Poll::Ready(RepeatedSupervisorEvent::Shutdown)
            ));
            assert_eq!(receiver.try_recv(), Ok(77_u8));
        }

        #[test]
        fn all_active_controllers_are_requested_before_drain() {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime constructs");

            runtime.block_on(async {
                let mut active = ActiveRemoteWorkers::new();
                for value in [1_u8, 2_u8] {
                    let (controller, signal) = remote_session_worker_cancellation_pair();
                    let worker_handle = tokio::spawn(async move {
                        signal.into_cancelled().await;
                        AuthenticatedRemoteSessionWorkerStop::Cancelled
                    });
                    active.insert(
                        device_id(&format!("shutdown-device-{value}")),
                        RemoteSessionPersistentWorkerEntry {
                            cancellation_controller: controller,
                            worker_handle,
                        },
                    );
                }

                request_all_worker_cancellations(&active);
                let mut completions = Vec::new();
                drain_registered_workers(&mut active, &mut |completion| {
                    completions.push(completion);
                })
                .await;

                assert!(active.is_empty());
                assert_eq!(completions.len(), 2);
                assert!(completions.into_iter().all(|completion| {
                    completion.result() == Ok(AuthenticatedRemoteSessionWorkerStop::Cancelled)
                }));
            });
        }

        #[test]
        fn repeated_failure_preserves_expected_device_and_original_aj_variant() {
            let expected = device_id("failed-device");
            let failure = RemoteSessionRepeatedAdmissionFailure {
                expected_device_id: expected.clone(),
                error: RemoteSessionRealAdmissionError::Registry(RegistryError::DeviceUnknown),
            };

            assert_eq!(failure.expected_device_id(), &expected);
            assert!(matches!(
                failure.error(),
                RemoteSessionRealAdmissionError::Registry(RegistryError::DeviceUnknown)
            ));
        }
    }
}

impl RemoteSessionExecutorRuntime {
    /// Drives one existing reachability-authority admission transaction on this private executor.
    ///
    /// The existing async custody/provider bootstrap seam is executed exactly once inside the
    /// already-owned current-thread Tokio runtime. Success is immediately converted into the
    /// existing opaque Agent-owned runtime owner. No runtime handle, generic future driver,
    /// provider client or secret material is returned.
    ///
    /// # Errors
    ///
    /// Returns the existing reachability custody/provider bootstrap error unchanged. No retry,
    /// endpoint bind, readiness publication or local-runtime shutdown is performed.
    #[allow(
        dead_code,
        reason = "C03e-AR materializes the AQ-selected source seam for a separately gated process consumer"
    )]
    pub(crate) fn bootstrap_reachability_authority_from_systemd_credentials(
        &self,
    ) -> Result<
        crate::reachability_authority_admission::ReachabilityAuthorityRuntimeOwner,
        crate::reachability_authority_custody_bootstrap::ReachabilityAuthorityCustodyBootstrapError,
    > {
        self.runtime
            .block_on(
                crate::reachability_authority_admission::bootstrap_and_admit_reachability_live_owner_authority_from_systemd_credentials(),
            )
            .map(crate::reachability_authority_admission::ReachabilityAuthorityRuntimeOwner::new)
    }
}

impl RemoteSessionExecutorRuntime {
    /// Drives exactly one existing C03e-FL requester-aware cancellation-aware serial lifecycle
    /// worker on this already-owned private current-thread executor.
    ///
    /// The authenticated-session owner remains mutable caller custody while the shared
    /// requester/rendezvous authority handle is borrowed for the entire synchronous drive. The exact FL
    /// worker remains the sole authority for cancellation ordering and terminal stop classification.
    /// This seam performs no peer close, owner drop, restart/reuse, task spawn, cancellation-pair
    /// construction, persistent-collection mutation, requester-authority synchronization,
    /// candidate/reachability continuation, target dialing, listener activation or readiness.
    #[allow(
        dead_code,
        reason = "C03e-FP adapts the FN borrowed executor seam to the FO-selected shared requester/rendezvous authority"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        clippy::too_many_arguments,
        reason = "C03e-FN preserves the FM-selected mutable executor custody boundary and exact FL input surface"
    )]
    pub(super) fn drive_requester_rendezvous_post_terminal_response_serial_lifecycle_worker<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> u64 + Send,
        S: crate::candidate_publication_requester_rendezvous_start_intent::policy_source::RequesterRendezvousStartPolicySource
            + Sync
            + ?Sized,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: &S,
        requester_rendezvous_authority: &super::SharedRequesterRendezvousAuthority,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> super::requester_rendezvous_retained_custody_dr_continuation::RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop{
        self.runtime.block_on(
            super::requester_rendezvous_retained_custody_dr_continuation::run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker(
                session_owner,
                authority,
                policy_source,
                requester_rendezvous_authority,
                verifier_time_unix_seconds,
                dispatcher,
                cancellation,
            ),
        )
    }
}

mod recoverable_spawned_requester_rendezvous_worker;

impl RemoteSessionExecutorRuntime {
    /// Drives exactly one production reachability custody/bootstrap transaction on this executor.
    ///
    /// The existing asynchronous production systemd custody/bootstrap seam is polled only by this
    /// already-owned private current-thread runtime. Success is immediately adapted into the
    /// existing joint production runtime custody. The runtime itself remains privately owned here;
    /// no generic future driver, runtime handle, provider client or secret material is exposed.
    ///
    /// # Errors
    ///
    /// Returns the existing production custody/bootstrap error unchanged. The borrowed executor
    /// remains caller-owned after failure; no endpoint bind, retry, fallback or second runtime is
    /// created by this method.
    #[allow(
        dead_code,
        reason = "C03e-IE materializes the ID-selected production private-executor bootstrap before separately gated process composition"
    )]
    pub(crate) fn bootstrap_production_reachability_runtime_custody_from_systemd_credentials(
        &self,
        peer: &prw_connectivity::PeerConnectivityIdentity,
    ) -> Result<
        crate::production_reachability_runtime_custody::ProductionReachabilityRuntimeCustody,
        crate::production_reachability_custody_bootstrap::ProductionReachabilityCustodyBootstrapError,
    >{
        self.runtime
            .block_on(
                crate::production_reachability_custody_bootstrap::bootstrap_production_reachability_from_systemd_credentials(peer),
            )
            .map(
                crate::production_reachability_runtime_custody::ProductionReachabilityRuntimeCustody::from_bootstrap_composition,
            )
    }
}

impl RemoteSessionExecutorRuntime {
    /// Drives exactly one borrowed dormant fallible verifier-time worker through the existing private runtime.
    ///
    /// The authenticated-session owner and dispatcher remain borrowed for the whole synchronous drive.
    /// The verifier-time provider and cancellation future are forwarded unchanged into exactly one
    /// C03e-PD worker invocation. That worker remains sole authority for verifier-time sampling,
    /// request-loop/cancellation ordering, peer closure, and exact terminal classification.
    ///
    /// This bridge introduces no executor error wrapper, spawn/join behavior, supervisor propagation,
    /// persistent result retyping, admission/request-carrier migration, provider installation, or
    /// production caller activation.
    #[allow(
        dead_code,
        reason = "C03e-PF materializes the PE-selected borrowed executor compatibility seam before separately gated spawned propagation"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-PF preserves the PE-selected mutable executor custody boundary for this borrowed compatibility seam"
    )]
    pub(super) fn drive_fallible_verifier_time_capability_request_worker<
        P: PolicyEvaluator + Send + Sync,
        D: CapabilityDispatcher + Send,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError> + Send,
        C: Future<Output = ()> + Send,
    >(
        &mut self,
        session_owner: &mut AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: &mut D,
        cancellation: C,
    ) -> super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop{
        self.runtime.block_on(
            session_owner.run_fallible_verifier_time_capability_request_worker(
                authority,
                verifier_time_unix_seconds,
                dispatcher,
                cancellation,
            ),
        )
    }
}

impl RemoteSessionExecutorRuntime {
    /// Spawns and joins exactly one owned dormant fallible verifier-time worker under this private runtime.
    ///
    /// The authenticated-session owner, dispatcher, verifier-time provider and cancellation future move
    /// into one `async move` task. Exactly one clone of the shared-current authority moves into that task.
    /// The task delegates directly to the C03e-PD fallible verifier-time worker; it does not re-enter the
    /// C03e-PF synchronous borrowed bridge from inside the task.
    ///
    /// `Cancelled` and `Failed` remain normal worker terminals. Only abnormal Tokio task completion is
    /// mapped to the existing bounded [`RemoteSessionSpawnedWorkerJoinError`].
    #[allow(
        dead_code,
        reason = "C03e-PH materializes the PG-selected spawned executor compatibility seam before separately gated supervisor propagation"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-PH preserves the PG-selected mutable executor custody boundary for this spawned compatibility seam"
    )]
    pub(super) fn drive_spawned_fallible_verifier_time_capability_request_worker<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        C: Future<Output = ()> + Send + 'static,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        cancellation: C,
    ) -> Result<
        super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >{
        let authority = (*authority).clone();

        self.runtime.block_on(async move {
            let worker_handle = tokio::spawn(async move {
                let mut session_owner = session_owner;
                let mut dispatcher = dispatcher;

                session_owner
                    .run_fallible_verifier_time_capability_request_worker(
                        &authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation,
                    )
                    .await
            });

            worker_handle
                .await
                .map_err(|_| RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        })
    }
}

impl RemoteSessionExecutorRuntime {
    /// Supervises exactly one owned dormant fallible verifier-time worker under this private runtime.
    ///
    /// The supervisor mirrors the existing bounded single-worker custody shape: it clones the
    /// shared-current authority once, creates one existing cancellation pair, spawns one worker,
    /// then delegates the worker handle and retained controller to the generic
    /// `await_supervised_worker` helper. The worker delegates directly to the C03e-PD fallible
    /// verifier-time worker rather than re-entering either synchronous fallible executor bridge.
    ///
    /// `Cancelled` and `Failed` remain normal worker terminals. Supervisor shutdown only requests
    /// cancellation while the worker is still pending; worker-first race precedence and abnormal
    /// join mapping remain owned by `await_supervised_worker`.
    #[allow(
        dead_code,
        reason = "C03e-PJ materializes the PI-selected supervised executor compatibility seam before separately gated persistent propagation"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-PJ preserves the PI-selected mutable executor custody boundary for this supervised compatibility seam"
    )]
    pub(super) fn drive_supervised_fallible_verifier_time_capability_request_worker<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        S: Future<Output = ()> + Send,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        supervisor_shutdown: S,
    ) -> Result<
        super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >{
        let authority = (*authority).clone();

        self.runtime.block_on(async move {
            let (cancellation_controller, cancellation_signal) =
                remote_session_worker_cancellation_pair();

            let worker_handle = tokio::spawn(async move {
                let mut session_owner = session_owner;
                let mut dispatcher = dispatcher;

                session_owner
                    .run_fallible_verifier_time_capability_request_worker(
                        &authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation_signal.into_cancelled(),
                    )
                    .await
            });

            await_supervised_worker(worker_handle, cancellation_controller, supervisor_shutdown)
                .await
        })
    }
}

/// One explicitly reaped fallible verifier-time persistent-worker completion with logical identity.
#[allow(
    dead_code,
    reason = "C03e-PL materializes the PK-selected persistent result/ownership compatibility seam before separately gated admission propagation"
)]
pub(super) struct RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion {
    device_id: DeviceId,
    result: Result<
        super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
}

#[allow(
    dead_code,
    reason = "C03e-PL exposes only bounded same-module access to the selected persistent completion custody"
)]
impl RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion {
    /// Returns the authenticated logical `DeviceId` that keyed the retained worker entry.
    #[must_use]
    pub(super) const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the exact fallible worker/join terminal result by reference.
    pub(super) const fn result(
        &self,
    ) -> &Result<
        super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >{
        &self.result
    }

    /// Recovers the logical identity and exact fallible worker/join terminal result.
    pub(super) fn into_parts(
        self,
    ) -> (
        DeviceId,
        Result<
            super::authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ){
        (self.device_id, self.result)
    }
}

impl RemoteSessionExecutorRuntime {
    /// Drives the bounded persistent collection with the dormant fallible verifier-time worker.
    ///
    /// The existing generic collection remains sole authority for capacity, duplicate rejection,
    /// completion reaping, cancellation-controller custody, join-handle custody and orderly drain.
    /// Each admitted worker receives exactly one authority clone, one existing cancellation pair,
    /// and one direct C03e-PD fallible worker invocation. No synchronous PF/PH/PJ bridge is nested.
    ///
    /// `Cancelled` and `Failed(exact PB error)` remain normal worker completion values. Only
    /// abnormal Tokio completion is represented by the existing bounded join error.
    ///
    /// # Errors
    ///
    /// Returns the existing persistent-collection configuration error before runtime work when
    /// `max_active_workers` exceeds the registered-device ceiling.
    #[allow(
        dead_code,
        reason = "C03e-PL materializes the PK-selected persistent compatibility seam before separately gated admission/request-carrier propagation"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "C03e-PL preserves the PK-selected mutable executor custody shape of the historical persistent drive"
    )]
    pub(super) fn drive_persistent_fallible_verifier_time_remote_worker_collection<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>
            + Send
            + 'static,
        S: Future<Output = ()> + Send,
        C: FnMut(RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion),
        R: FnMut(RemoteSessionWorkerAdmissionRejection<D, T>),
    >(
        &mut self,
        max_active_workers: NonZeroUsize,
        authority: &SharedCurrentCapabilityAuthority<P>,
        admissions: mpsc::Receiver<RemoteSessionWorkerAdmission<D, T>>,
        supervisor_shutdown: S,
        mut on_completion: C,
        mut on_rejection: R,
    ) -> Result<(), RemoteSessionPersistentCollectionConfigError> {
        let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;

        self.runtime.block_on(run_persistent_worker_collection(
            max_active_workers,
            admissions,
            supervisor_shutdown,
            |admission| admission.logical_device_id().clone(),
            |admission| {
                let authority = (*authority).clone();
                let (mut session_owner, mut dispatcher, verifier_time_unix_seconds) =
                    admission.into_parts();
                let (cancellation_controller, cancellation_signal) =
                    remote_session_worker_cancellation_pair();
                let worker_handle = tokio::spawn(async move {
                    session_owner
                        .run_fallible_verifier_time_capability_request_worker(
                            &authority,
                            verifier_time_unix_seconds,
                            &mut dispatcher,
                            cancellation_signal.into_cancelled(),
                        )
                        .await
                });
                (cancellation_controller, worker_handle)
            },
            |device_id, result| {
                on_completion(
                    RemoteSessionFallibleVerifierTimeRegisteredWorkerCompletion {
                        device_id,
                        result,
                    },
                );
            },
            |reason, admission| {
                on_rejection(RemoteSessionWorkerAdmissionRejection { reason, admission });
            },
        ));

        Ok(())
    }
}
