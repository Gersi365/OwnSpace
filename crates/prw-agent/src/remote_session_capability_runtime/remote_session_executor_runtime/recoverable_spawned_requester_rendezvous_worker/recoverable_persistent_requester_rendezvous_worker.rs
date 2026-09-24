//! Pre-production recoverable persistent requester-aware worker custody.
//!
//! C03e-FS materializes only the C03e-FR-selected persistent entry/completion ownership primitives
//! and one injected collection seam. The exact authenticated-session owner remains recoverable
//! outside the task, exact FL stop/join classification is preserved, ready completions recover owner
//! custody before publication, and orderly shutdown requests cooperative cancellation before draining
//! the same retained handles. This module does not substitute FL into real admission, close/reuse a
//! peer, clean requester records, select reachability, dial targets, activate a listener, deploy,
//! restart/recover the process, or merge.

use std::{
    collections::{HashMap, hash_map::Entry as HashMapEntry},
    future::{Future, poll_fn},
    hash::Hash,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use prw_core::DeviceId;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

use super::super::{map_worker_join_result, validate_persistent_worker_capacity};
use super::{
    AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionSpawnedWorkerJoinError,
    RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
};
use crate::remote_session_capability_runtime::{
    RemoteSessionPersistentCollectionConfigError, RemoteSessionWorkerAdmissionRejectionReason,
    RemoteSessionWorkerCancellationController,
};

type RecoverableOwnerCell<O> = Arc<Mutex<Option<O>>>;

/// One active pre-production recoverable persistent worker entry.
///
/// The supervisor owns the recoverable owner-cell handle, the sole cancellation controller, and the
/// exact join handle. The spawned task may hold another owner-cell handle, but the owned value itself
/// is never cloned by this custody type.
#[allow(
    dead_code,
    reason = "C03e-FS materializes the FR-selected entry primitive before separately gated real-admission integration"
)]
pub(super) struct RecoverablePersistentWorkerEntry<O, T> {
    owner_cell: RecoverableOwnerCell<O>,
    cancellation_controller: RemoteSessionWorkerCancellationController,
    worker_handle: JoinHandle<T>,
}

#[allow(
    dead_code,
    reason = "C03e-FS materializes exact entry construction for a separately gated persistent requester-aware integration consumer"
)]
impl<O, T> RecoverablePersistentWorkerEntry<O, T> {
    pub(super) const fn new(
        owner_cell: RecoverableOwnerCell<O>,
        cancellation_controller: RemoteSessionWorkerCancellationController,
        worker_handle: JoinHandle<T>,
    ) -> Self {
        Self {
            owner_cell,
            cancellation_controller,
            worker_handle,
        }
    }
}

/// Ownership-bearing terminal custody after one persistent entry is detached from the active map.
#[allow(
    dead_code,
    reason = "C03e-FS materializes the FR-selected completion primitive before separately gated higher-owner integration"
)]
pub(super) struct RecoverablePersistentWorkerCompletion<K, O, T> {
    key: K,
    owner: O,
    result: Result<T, RemoteSessionSpawnedWorkerJoinError>,
}

#[allow(
    dead_code,
    reason = "C03e-FS materializes completion accessors before separately gated persistent requester-aware integration"
)]
impl<K, O, T> RecoverablePersistentWorkerCompletion<K, O, T> {
    #[must_use]
    pub(super) const fn key(&self) -> &K {
        &self.key
    }

    #[must_use]
    pub(super) const fn owner(&self) -> &O {
        &self.owner
    }

    pub(super) const fn result(&self) -> &Result<T, RemoteSessionSpawnedWorkerJoinError> {
        &self.result
    }

    pub(super) fn into_parts(self) -> (K, O, Result<T, RemoteSessionSpawnedWorkerJoinError>) {
        (self.key, self.owner, self.result)
    }
}

/// Exact FR-selected requester-aware active-entry specialization.
#[allow(
    dead_code,
    reason = "C03e-FS materializes exact requester-aware entry custody before separately gated real-admission substitution"
)]
pub(super) type RecoverableRequesterAwareWorkerEntry = RecoverablePersistentWorkerEntry<
    AuthenticatedRemoteSessionRuntimeOwner,
    RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
>;

/// Exact FR-selected requester-aware completion specialization.
#[allow(
    dead_code,
    reason = "C03e-FS materializes exact requester-aware completion custody before separately gated higher-owner consumption"
)]
pub(super) type RecoverableRequesterAwareWorkerCompletion = RecoverablePersistentWorkerCompletion<
    DeviceId,
    AuthenticatedRemoteSessionRuntimeOwner,
    RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
>;

enum RecoverablePersistentSupervisorEvent<C> {
    Shutdown,
    Admission(C),
}

fn recover_owner_after_terminal_join<O>(owner_cell: &RecoverableOwnerCell<O>) -> O {
    let mut owner_guard = owner_cell
        .try_lock()
        .expect("terminal persistent worker must release recoverable owner-cell guard before join readiness");
    let owner = owner_guard
        .take()
        .expect("terminal persistent worker must leave exact owner in retained cell");
    drop(owner_guard);
    owner
}

pub(super) fn reap_ready_recoverable_workers<K, O, T, C>(
    active: &mut HashMap<K, RecoverablePersistentWorkerEntry<O, T>>,
    context: &mut Context<'_>,
    on_completion: &mut C,
) where
    K: Eq + Hash + Clone,
    C: FnMut(RecoverablePersistentWorkerCompletion<K, O, T>),
{
    let mut ready = Vec::new();

    for (key, entry) in active.iter_mut() {
        if let Poll::Ready(result) = Pin::new(&mut entry.worker_handle).poll(context) {
            ready.push((key.clone(), result));
        }
    }

    for (key, join_result) in ready {
        let entry = active
            .remove(&key)
            .expect("ready persistent worker entry must remain present until detachment");
        let owner = recover_owner_after_terminal_join(&entry.owner_cell);
        let result = map_worker_join_result(join_result);
        on_completion(RecoverablePersistentWorkerCompletion { key, owner, result });
    }
}

/// Polls active recoverable workers and detaches at most one terminal completion.
///
/// The scan stops at the first ready join so no second completed handle is consumed in the same
/// call. Empty or entirely pending maps return [`Poll::Pending`] after registering the supplied
/// context with every polled join handle. Owner and terminal-result custody move by value exactly
/// once through the existing recovery and join-result mapping helpers.
#[allow(
    dead_code,
    reason = "C03e-OG materializes the OF-selected one-at-a-time extraction prerequisite before separately gated async producer handoff integration"
)]
pub(super) fn poll_one_ready_recoverable_worker<K, O, T>(
    active: &mut HashMap<K, RecoverablePersistentWorkerEntry<O, T>>,
    context: &mut Context<'_>,
) -> Poll<RecoverablePersistentWorkerCompletion<K, O, T>>
where
    K: Eq + Hash + Clone,
{
    let mut ready = None;

    for (key, entry) in active.iter_mut() {
        if let Poll::Ready(join_result) = Pin::new(&mut entry.worker_handle).poll(context) {
            ready = Some((key.clone(), join_result));
            break;
        }
    }

    let Some((key, join_result)) = ready else {
        return Poll::Pending;
    };

    let entry = active
        .remove(&key)
        .expect("ready persistent worker entry must remain present until single detachment");
    let owner = recover_owner_after_terminal_join(&entry.owner_cell);
    let result = map_worker_join_result(join_result);

    Poll::Ready(RecoverablePersistentWorkerCompletion { key, owner, result })
}

pub(super) fn request_all_recoverable_worker_cancellations<K, O, T>(
    active: &HashMap<K, RecoverablePersistentWorkerEntry<O, T>>,
) {
    for entry in active.values() {
        entry.cancellation_controller.request_cancellation();
    }
}

pub(super) async fn drain_recoverable_workers<K, O, T, C>(
    active: &mut HashMap<K, RecoverablePersistentWorkerEntry<O, T>>,
    on_completion: &mut C,
) where
    K: Eq + Hash + Clone,
    C: FnMut(RecoverablePersistentWorkerCompletion<K, O, T>),
{
    poll_fn(|context| {
        reap_ready_recoverable_workers(active, context, on_completion);
        if active.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn run_recoverable_persistent_worker_collection<K, Candidate, O, T, S, Kf, Sf, Cf, Rf>(
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
    Sf: FnMut(Candidate) -> RecoverablePersistentWorkerEntry<O, T>,
    Cf: FnMut(RecoverablePersistentWorkerCompletion<K, O, T>),
    Rf: FnMut(RemoteSessionWorkerAdmissionRejectionReason, Candidate),
{
    let mut active = HashMap::<K, RecoverablePersistentWorkerEntry<O, T>>::new();
    let mut supervisor_shutdown = Box::pin(supervisor_shutdown);
    let mut admission_open = true;

    loop {
        let event = poll_fn(|context| {
            reap_ready_recoverable_workers(&mut active, context, &mut on_completion);

            if supervisor_shutdown.as_mut().poll(context) == Poll::Ready(()) {
                return Poll::Ready(RecoverablePersistentSupervisorEvent::Shutdown);
            }

            if admission_open && active.len() < max_active_workers {
                match Pin::new(&mut admissions).poll_recv(context) {
                    Poll::Ready(Some(candidate)) => {
                        return Poll::Ready(RecoverablePersistentSupervisorEvent::Admission(
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
            RecoverablePersistentSupervisorEvent::Shutdown => break,
            RecoverablePersistentSupervisorEvent::Admission(candidate) => {
                let key = key_for_candidate(&candidate);
                match active.entry(key) {
                    HashMapEntry::Occupied(_) => on_rejection(
                        RemoteSessionWorkerAdmissionRejectionReason::DuplicateActiveDevice,
                        candidate,
                    ),
                    HashMapEntry::Vacant(slot) => {
                        slot.insert(spawn_worker(candidate));
                    }
                }
            }
        }
    }

    request_all_recoverable_worker_cancellations(&active);
    drain_recoverable_workers(&mut active, &mut on_completion).await;
}

/// Runs one injected pre-production requester-aware persistent collection using FR-selected custody.
///
/// The caller supplies candidate identity extraction and exact entry construction. This seam only
/// owns active-map scheduling, duplicate-active rejection, ready completion recovery, cooperative
/// shutdown cancellation, and drain. It does not perform real admission or activate production FL.
#[allow(
    dead_code,
    reason = "C03e-FS materializes the FR-selected pre-production collection seam before separately gated real-admission integration"
)]
pub(super) async fn run_recoverable_persistent_requester_aware_worker_collection<
    Candidate,
    S,
    Kf,
    Sf,
    Cf,
    Rf,
>(
    max_active_workers: NonZeroUsize,
    admissions: mpsc::Receiver<Candidate>,
    supervisor_shutdown: S,
    key_for_candidate: Kf,
    spawn_worker: Sf,
    on_completion: Cf,
    on_rejection: Rf,
) -> Result<(), RemoteSessionPersistentCollectionConfigError>
where
    S: Future<Output = ()>,
    Kf: FnMut(&Candidate) -> DeviceId,
    Sf: FnMut(Candidate) -> RecoverableRequesterAwareWorkerEntry,
    Cf: FnMut(RecoverableRequesterAwareWorkerCompletion),
    Rf: FnMut(RemoteSessionWorkerAdmissionRejectionReason, Candidate),
{
    let max_active_workers = validate_persistent_worker_capacity(max_active_workers)?;
    run_recoverable_persistent_worker_collection(
        max_active_workers,
        admissions,
        supervisor_shutdown,
        key_for_candidate,
        spawn_worker,
        on_completion,
        on_rejection,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, num::NonZeroUsize, sync::Arc, task::Poll};

    use tokio::{
        runtime::Builder,
        sync::{Mutex, mpsc, oneshot},
    };

    use super::{
        RecoverablePersistentWorkerEntry, RemoteSessionSpawnedWorkerJoinError,
        RemoteSessionWorkerAdmissionRejectionReason, poll_one_ready_recoverable_worker,
        reap_ready_recoverable_workers, run_recoverable_persistent_worker_collection,
    };
    use crate::remote_session_capability_runtime::remote_session_worker_cancellation_pair;

    #[derive(Debug)]
    struct TestAdmission {
        key: u8,
        owner: u8,
        result: u8,
    }

    #[derive(Debug, Clone, Copy)]
    enum TestWorkerMode {
        Immediate,
        WaitForCancellation,
        Panic,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct NonCloneOwner(u8);

    #[derive(Debug, PartialEq, Eq)]
    struct NonCloneResult(u8);

    #[allow(
        clippy::significant_drop_tightening,
        reason = "C03e-FS tests intentionally keep the recoverable owner-cell guard across the worker lifetime, including cancellation wait and panic unwind"
    )]
    fn spawn_test_entry(
        owner: u8,
        result: u8,
        mode: TestWorkerMode,
    ) -> RecoverablePersistentWorkerEntry<u8, u8> {
        let owner_cell = Arc::new(Mutex::new(Some(owner)));
        let worker_owner_cell = Arc::clone(&owner_cell);
        let (cancellation_controller, cancellation_signal) =
            remote_session_worker_cancellation_pair();
        let worker_handle = tokio::spawn(async move {
            let owner_guard = worker_owner_cell.lock().await;
            assert_eq!(owner_guard.as_ref(), Some(&owner));

            match mode {
                TestWorkerMode::Immediate => {
                    drop(owner_guard);
                    result
                }
                TestWorkerMode::WaitForCancellation => {
                    cancellation_signal.into_cancelled().await;
                    drop(owner_guard);
                    result
                }
                TestWorkerMode::Panic => {
                    panic!("intentional recoverable persistent-worker test panic");
                }
            }
        });

        RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "C03e-OG wakeup test intentionally retains owner custody while the injected release signal keeps the join pending"
    )]
    fn spawn_signalled_test_entry(
        owner: u8,
        result: u8,
        release: oneshot::Receiver<()>,
    ) -> RecoverablePersistentWorkerEntry<u8, u8> {
        let owner_cell = Arc::new(Mutex::new(Some(owner)));
        let worker_owner_cell = Arc::clone(&owner_cell);
        let (cancellation_controller, _cancellation_signal) =
            remote_session_worker_cancellation_pair();
        let worker_handle = tokio::spawn(async move {
            let owner_guard = worker_owner_cell.lock().await;
            assert_eq!(owner_guard.as_ref(), Some(&owner));
            let _ = release.await;
            drop(owner_guard);
            result
        });

        RecoverablePersistentWorkerEntry::new(owner_cell, cancellation_controller, worker_handle)
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test current-thread runtime constructs")
    }

    #[test]
    fn ready_normal_entry_is_detached_then_owner_and_result_are_published() {
        let runtime = test_runtime();
        let completion = runtime.block_on(async {
            let mut active = std::collections::HashMap::new();
            active.insert(1_u8, spawn_test_entry(41, 7, TestWorkerMode::Immediate));
            tokio::task::yield_now().await;

            let mut completions = Vec::new();
            poll_fn(|context| {
                reap_ready_recoverable_workers(&mut active, context, &mut |completion| {
                    completions.push(completion);
                });
                if active.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;

            assert!(active.is_empty());
            assert_eq!(completions.len(), 1);
            completions.pop().expect("one completion exists")
        });

        let (key, owner, result) = completion.into_parts();
        assert_eq!(key, 1);
        assert_eq!(owner, 41);
        assert_eq!(result, Ok(7));
    }

    #[test]
    fn abnormal_join_detaches_entry_and_recovers_exact_owner_without_fake_worker_stop() {
        let runtime = test_runtime();
        let completion = runtime.block_on(async {
            let mut active = std::collections::HashMap::new();
            active.insert(2_u8, spawn_test_entry(53, 9, TestWorkerMode::Panic));
            tokio::task::yield_now().await;

            let mut completions = Vec::new();
            poll_fn(|context| {
                reap_ready_recoverable_workers(&mut active, context, &mut |completion| {
                    completions.push(completion);
                });
                if active.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;

            completions.pop().expect("one completion exists")
        });

        let (key, owner, result) = completion.into_parts();
        assert_eq!(key, 2);
        assert_eq!(owner, 53);
        assert_eq!(
            result,
            Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        );
    }

    #[test]
    fn single_ready_extraction_empty_map_is_pending() {
        let runtime = test_runtime();
        runtime.block_on(async {
            let mut active =
                std::collections::HashMap::<u8, RecoverablePersistentWorkerEntry<u8, u8>>::new();

            poll_fn(|context| {
                assert!(poll_one_ready_recoverable_worker(&mut active, context).is_pending());
                Poll::Ready(())
            })
            .await;
        });
    }

    #[test]
    fn single_ready_extraction_registers_wakeup_for_pending_join() {
        let runtime = test_runtime();
        let (completion, saw_pending) = runtime.block_on(async {
            let mut active = std::collections::HashMap::new();
            let (release_sender, release_receiver) = oneshot::channel();
            let mut release_sender = Some(release_sender);
            let mut saw_pending = false;

            active.insert(7_u8, spawn_signalled_test_entry(91, 41, release_receiver));

            let completion =
                poll_fn(
                    |context| match poll_one_ready_recoverable_worker(&mut active, context) {
                        Poll::Ready(completion) => Poll::Ready(completion),
                        Poll::Pending => {
                            if !saw_pending {
                                saw_pending = true;
                                let sender = release_sender
                                    .take()
                                    .expect("release sender exists for first pending poll");
                                assert!(sender.send(()).is_ok());
                            }
                            Poll::Pending
                        }
                    },
                )
                .await;

            (completion, saw_pending)
        });

        assert!(saw_pending);
        let (key, owner, result) = completion.into_parts();
        assert_eq!(key, 7);
        assert_eq!(owner, 91);
        assert_eq!(result, Ok(41));
    }

    #[test]
    fn single_ready_extraction_detaches_only_one_ready_entry_per_call() {
        let runtime = test_runtime();
        let mut completions = runtime.block_on(async {
            let mut active = std::collections::HashMap::new();
            active.insert(8_u8, spawn_test_entry(101, 51, TestWorkerMode::Immediate));
            active.insert(9_u8, spawn_test_entry(102, 52, TestWorkerMode::Immediate));
            tokio::task::yield_now().await;

            let first =
                poll_fn(|context| poll_one_ready_recoverable_worker(&mut active, context)).await;
            assert_eq!(active.len(), 1);

            let second =
                poll_fn(|context| poll_one_ready_recoverable_worker(&mut active, context)).await;
            assert!(active.is_empty());

            vec![first.into_parts(), second.into_parts()]
        });

        completions.sort_by_key(|(key, _, _)| *key);
        assert_eq!(completions, vec![(8, 101, Ok(51)), (9, 102, Ok(52))]);
    }

    #[test]
    fn single_ready_extraction_moves_non_clone_owner_and_result() {
        let runtime = test_runtime();
        let completion = runtime.block_on(async {
            let owner_cell = Arc::new(Mutex::new(Some(NonCloneOwner(111))));
            let worker_owner_cell = Arc::clone(&owner_cell);
            let (cancellation_controller, _cancellation_signal) =
                remote_session_worker_cancellation_pair();
            let worker_handle = tokio::spawn(async move {
                let owner_guard = worker_owner_cell.lock().await;
                assert_eq!(owner_guard.as_ref().map(|owner| owner.0), Some(111));
                drop(owner_guard);
                NonCloneResult(61)
            });

            let mut active = std::collections::HashMap::new();
            active.insert(
                10_u8,
                RecoverablePersistentWorkerEntry::new(
                    owner_cell,
                    cancellation_controller,
                    worker_handle,
                ),
            );

            poll_fn(|context| poll_one_ready_recoverable_worker(&mut active, context)).await
        });

        let (key, owner, result) = completion.into_parts();
        assert_eq!(key, 10);
        assert_eq!(owner, NonCloneOwner(111));
        assert_eq!(result, Ok(NonCloneResult(61)));
    }

    #[test]
    fn single_ready_extraction_preserves_abnormal_join_mapping() {
        let runtime = test_runtime();
        let completion = runtime.block_on(async {
            let mut active = std::collections::HashMap::new();
            active.insert(11_u8, spawn_test_entry(121, 71, TestWorkerMode::Panic));
            tokio::task::yield_now().await;

            poll_fn(|context| poll_one_ready_recoverable_worker(&mut active, context)).await
        });

        let (key, owner, result) = completion.into_parts();
        assert_eq!(key, 11);
        assert_eq!(owner, 121);
        assert_eq!(
            result,
            Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        );
    }

    #[test]
    fn duplicate_active_device_is_rejected_before_second_spawn_and_shutdown_recovers_owner() {
        let runtime = test_runtime();

        let (spawn_count, rejected, completions) = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(4);
            assert!(
                sender
                    .try_send(TestAdmission {
                        key: 3,
                        owner: 61,
                        result: 11
                    })
                    .is_ok()
            );
            assert!(
                sender
                    .try_send(TestAdmission {
                        key: 3,
                        owner: 62,
                        result: 12
                    })
                    .is_ok()
            );
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut spawn_count = 0_usize;
            let mut rejected = Vec::new();
            let mut completions = Vec::new();

            run_recoverable_persistent_worker_collection(
                2,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    spawn_test_entry(
                        candidate.owner,
                        candidate.result,
                        TestWorkerMode::WaitForCancellation,
                    )
                },
                |completion| completions.push(completion.into_parts()),
                |reason, candidate| {
                    rejected.push((reason, candidate.owner));
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
                62
            )]
        );
        assert_eq!(completions, vec![(3, 61, Ok(11))]);
    }

    #[test]
    fn ready_completion_is_recovered_before_same_wake_shutdown_observation() {
        let runtime = test_runtime();

        let completions = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(1);
            assert!(
                sender
                    .try_send(TestAdmission {
                        key: 4,
                        owner: 71,
                        result: 21
                    })
                    .is_ok()
            );
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut completions = Vec::new();

            run_recoverable_persistent_worker_collection(
                1,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_test_entry(candidate.owner, candidate.result, TestWorkerMode::Immediate)
                },
                |completion| {
                    completions.push(completion.into_parts());
                    if let Some(sender) = shutdown_sender.take() {
                        let _ = sender.send(());
                    }
                },
                |_reason, _candidate| panic!("no duplicate rejection expected"),
            )
            .await;

            completions
        });

        assert_eq!(completions, vec![(4, 71, Ok(21))]);
    }

    #[test]
    fn shutdown_requests_all_cancellations_and_drains_exact_handles_with_owner_recovery() {
        let runtime = test_runtime();

        let mut completions = runtime.block_on(async {
            let (sender, receiver) = mpsc::channel(4);
            assert!(
                sender
                    .try_send(TestAdmission {
                        key: 5,
                        owner: 81,
                        result: 31
                    })
                    .is_ok()
            );
            assert!(
                sender
                    .try_send(TestAdmission {
                        key: 6,
                        owner: 82,
                        result: 32
                    })
                    .is_ok()
            );
            drop(sender);

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let mut shutdown_sender = Some(shutdown_sender);
            let mut spawn_count = 0_usize;
            let mut completions = Vec::new();

            run_recoverable_persistent_worker_collection(
                2,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_count += 1;
                    let entry = spawn_test_entry(
                        candidate.owner,
                        candidate.result,
                        TestWorkerMode::WaitForCancellation,
                    );
                    if spawn_count == 2
                        && let Some(sender) = shutdown_sender.take()
                    {
                        let _ = sender.send(());
                    }
                    entry
                },
                |completion| completions.push(completion.into_parts()),
                |_reason, _candidate| panic!("no duplicate rejection expected"),
            )
            .await;

            assert_eq!(spawn_count, 2);
            completions
        });

        completions.sort_by_key(|(key, _, _)| *key);
        assert_eq!(completions, vec![(5, 81, Ok(31)), (6, 82, Ok(32))]);
    }

    #[test]
    fn closed_admission_source_does_not_end_supervisor_before_shutdown() {
        let runtime = test_runtime();

        runtime.block_on(async {
            let (sender, receiver) = mpsc::channel::<TestAdmission>(1);
            drop(sender);
            let (shutdown_sender, shutdown_receiver) = oneshot::channel();

            let supervisor = tokio::spawn(run_recoverable_persistent_worker_collection(
                1,
                receiver,
                async move {
                    let _ = shutdown_receiver.await;
                },
                |candidate: &TestAdmission| candidate.key,
                |candidate| {
                    spawn_test_entry(candidate.owner, candidate.result, TestWorkerMode::Immediate)
                },
                |_completion| {},
                |_reason, _candidate| {},
            ));

            tokio::task::yield_now().await;
            assert!(!supervisor.is_finished());
            assert!(shutdown_sender.send(()).is_ok());
            assert!(supervisor.await.is_ok());
        });
    }

    #[test]
    fn exact_wrapper_capacity_guard_keeps_existing_registered_device_ceiling() {
        let maximum = NonZeroUsize::new(prw_registry::MAX_REGISTERED_DEVICES)
            .expect("registered-device limit is nonzero");
        assert!(super::validate_persistent_worker_capacity(maximum).is_ok());
    }
}
