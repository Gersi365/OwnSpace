//! Join-owned process-lifecycle control for one separately supplied remote capability lane.
//!
//! C03e-AS selected one bounded controller handoff and one explicitly joined OS thread beneath the
//! existing signal-aware local lifecycle. C03e-AT materializes only that control surface. This
//! module does not invoke reachability bootstrap, bind an endpoint, publish readiness, consume
//! process signals, create a Tokio runtime, retry remote startup, or wire the Agent executable.

use std::{
    fmt,
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread::{self, JoinHandle},
};

use super::RemoteSessionSupervisorShutdownController;

trait OrderlyRemoteShutdown {
    fn request_orderly_shutdown(&self);
}

impl OrderlyRemoteShutdown for RemoteSessionSupervisorShutdownController {
    fn request_orderly_shutdown(&self) {
        self.request_shutdown();
    }
}

/// Result of the one-shot remote supervisor-controller ownership handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionSupervisorShutdownPublish {
    /// The exact controller moved to process-side ownership.
    Published,
    /// Process-side ownership disappeared; the recovered exact controller requested orderly shutdown.
    ReceiverGoneShutdownRequested,
}

fn publish_or_request_shutdown<C: OrderlyRemoteShutdown>(
    sender: &SyncSender<C>,
    controller: C,
) -> RemoteSessionSupervisorShutdownPublish {
    match sender.send(controller) {
        Ok(()) => RemoteSessionSupervisorShutdownPublish::Published,
        Err(error) => {
            let controller = error.0;
            controller.request_orderly_shutdown();
            RemoteSessionSupervisorShutdownPublish::ReceiverGoneShutdownRequested
        }
    }
}

/// One-shot lane-side authority for publishing the existing non-cloneable shutdown controller.
pub struct RemoteSessionSupervisorShutdownPublisher {
    sender: SyncSender<RemoteSessionSupervisorShutdownController>,
}

impl RemoteSessionSupervisorShutdownPublisher {
    /// Moves the exact AP shutdown controller to process ownership once.
    ///
    /// If process ownership has already disappeared, the failed send returns the exact controller
    /// to this lane-side operation and orderly shutdown is requested immediately through that same
    /// controller. No replacement authority, thread abort, endpoint close, or retry is performed.
    pub fn publish(
        self,
        controller: RemoteSessionSupervisorShutdownController,
    ) -> RemoteSessionSupervisorShutdownPublish {
        publish_or_request_shutdown(&self.sender, controller)
    }
}

/// Bounded controller observation during process-side finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionProcessControllerFinalization {
    /// The handed-off AP controller received the orderly shutdown request.
    ShutdownRequested,
    /// The remote lane terminated before publishing an AP controller.
    UnavailableBeforeEndpointStartup,
}

/// Bounded join evidence for the one remote capability OS thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionProcessThreadFinalization {
    /// The exact join-owned remote capability thread returned normally.
    Joined,
    /// The exact thread terminated by panic; payload/thread identity is intentionally discarded.
    Panicked,
}

/// Secondary bounded evidence from finalizing one remote capability process companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSessionProcessLifecycleFinalization {
    controller: RemoteSessionProcessControllerFinalization,
    thread: RemoteSessionProcessThreadFinalization,
}

impl RemoteSessionProcessLifecycleFinalization {
    #[must_use]
    pub const fn controller(self) -> RemoteSessionProcessControllerFinalization {
        self.controller
    }

    #[must_use]
    pub const fn thread(self) -> RemoteSessionProcessThreadFinalization {
        self.thread
    }
}

fn finalize_controller_and_join<C: OrderlyRemoteShutdown>(
    controller: &Receiver<C>,
    thread: JoinHandle<()>,
) -> RemoteSessionProcessLifecycleFinalization {
    let controller = controller.recv().map_or(
        RemoteSessionProcessControllerFinalization::UnavailableBeforeEndpointStartup,
        |controller| {
            controller.request_orderly_shutdown();
            RemoteSessionProcessControllerFinalization::ShutdownRequested
        },
    );

    let thread = match thread.join() {
        Ok(()) => RemoteSessionProcessThreadFinalization::Joined,
        Err(_) => RemoteSessionProcessThreadFinalization::Panicked,
    };

    RemoteSessionProcessLifecycleFinalization { controller, thread }
}

/// Bounded thread-construction failure for the remote process companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSessionProcessLifecycleSpawnError;

impl fmt::Display for RemoteSessionProcessLifecycleSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote capability process thread could not be created")
    }
}

impl std::error::Error for RemoteSessionProcessLifecycleSpawnError {}

/// Non-cloneable process owner for exactly one joinable remote capability OS thread.
pub struct RemoteSessionProcessLifecycleOwner {
    controller: Receiver<RemoteSessionSupervisorShutdownController>,
    thread: JoinHandle<()>,
}

impl RemoteSessionProcessLifecycleOwner {
    /// Starts exactly one join-owned OS thread around a separately supplied remote-lane operation.
    ///
    /// The operation receives one one-shot publisher for the existing AP shutdown controller. The
    /// caller remains responsible for the separately gated remote executor/bootstrap/endpoint inputs;
    /// this seam supplies no production network configuration and creates no async runtime itself.
    ///
    /// # Errors
    ///
    /// Returns a bounded remote-capability-unavailable classification if OS-thread creation fails.
    pub fn spawn<F>(operation: F) -> Result<Self, RemoteSessionProcessLifecycleSpawnError>
    where
        F: FnOnce(RemoteSessionSupervisorShutdownPublisher) + Send + 'static,
    {
        let (sender, controller) = sync_channel(1);
        let thread = thread::Builder::new()
            .spawn(move || operation(RemoteSessionSupervisorShutdownPublisher { sender }))
            .map_err(|_| RemoteSessionProcessLifecycleSpawnError)?;

        Ok(Self { controller, thread })
    }

    /// Consumes process ownership, requests orderly shutdown when an AP controller exists, and joins.
    ///
    /// If local termination reaches this finalizer before endpoint startup has published a controller,
    /// the blocking receive waits until either the exact controller arrives or the lane terminates and
    /// drops its sender. The exact remote thread is then joined explicitly. No hard cancellation,
    /// signal injection, detached fallback, or replacement shutdown authority is used.
    #[must_use]
    pub fn finalize(self) -> RemoteSessionProcessLifecycleFinalization {
        finalize_controller_and_join(&self.controller, self.thread)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc::{self, sync_channel},
        },
        thread,
    };

    use super::{
        OrderlyRemoteShutdown, RemoteSessionProcessControllerFinalization,
        RemoteSessionProcessLifecycleFinalization, RemoteSessionProcessLifecycleOwner,
        RemoteSessionProcessLifecycleSpawnError, RemoteSessionProcessThreadFinalization,
        RemoteSessionSupervisorShutdownPublish, finalize_controller_and_join,
        publish_or_request_shutdown,
    };

    #[derive(Clone)]
    struct FakeController {
        requests: Arc<AtomicUsize>,
    }

    impl OrderlyRemoteShutdown for FakeController {
        fn request_orderly_shutdown(&self) {
            self.requests.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fake_controller() -> (FakeController, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        (
            FakeController {
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }

    fn assert_spawn_shape<F>(spawn: F)
    where
        F: FnOnce(
            fn(super::RemoteSessionSupervisorShutdownPublisher),
        ) -> Result<
            RemoteSessionProcessLifecycleOwner,
            RemoteSessionProcessLifecycleSpawnError,
        >,
    {
        let _ = spawn;
    }

    #[test]
    fn remote_process_owner_spawn_has_bounded_injected_operation_shape() {
        fn operation(_: super::RemoteSessionSupervisorShutdownPublisher) {}
        assert_spawn_shape(RemoteSessionProcessLifecycleOwner::spawn);
        let _ = operation;
    }

    #[test]
    fn published_controller_is_requested_once_before_join_returns() {
        let (controller_tx, controller_rx) = sync_channel(1);
        let (controller, requests) = fake_controller();
        let thread_requests = Arc::clone(&requests);

        let lane = thread::spawn(move || {
            controller_tx
                .send(controller)
                .expect("controller publishes");
            while thread_requests.load(Ordering::SeqCst) == 0 {
                thread::yield_now();
            }
        });

        let finalization = finalize_controller_and_join(&controller_rx, lane);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            finalization.controller(),
            RemoteSessionProcessControllerFinalization::ShutdownRequested
        );
        assert_eq!(
            finalization.thread(),
            RemoteSessionProcessThreadFinalization::Joined
        );
    }

    #[test]
    fn finalizer_waits_for_controller_or_lane_terminal_without_fabricating_authority() {
        let (controller_tx, controller_rx) = sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let (controller, requests) = fake_controller();
        let lane_requests = Arc::clone(&requests);

        let lane = thread::spawn(move || {
            release_rx.recv().expect("lane release arrives");
            controller_tx
                .send(controller)
                .expect("controller publishes");
            while lane_requests.load(Ordering::SeqCst) == 0 {
                thread::yield_now();
            }
        });

        let finalizer = thread::spawn(move || {
            let finalization = finalize_controller_and_join(&controller_rx, lane);
            done_tx.send(finalization).expect("finalization publishes");
        });

        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release_tx.send(()).expect("lane releases");
        let finalization = done_rx.recv().expect("finalization completes");
        finalizer.join().expect("finalizer helper joins");

        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            finalization,
            RemoteSessionProcessLifecycleFinalization {
                controller: RemoteSessionProcessControllerFinalization::ShutdownRequested,
                thread: RemoteSessionProcessThreadFinalization::Joined,
            }
        );
    }

    #[test]
    fn lane_terminal_before_controller_yields_unavailable_then_explicit_join() {
        let (controller_tx, controller_rx) = sync_channel::<FakeController>(1);
        let lane = thread::spawn(move || drop(controller_tx));

        let finalization = finalize_controller_and_join(&controller_rx, lane);
        assert_eq!(
            finalization.controller(),
            RemoteSessionProcessControllerFinalization::UnavailableBeforeEndpointStartup
        );
        assert_eq!(
            finalization.thread(),
            RemoteSessionProcessThreadFinalization::Joined
        );
    }

    #[test]
    fn receiver_drop_recovers_exact_controller_and_requests_orderly_shutdown_once() {
        let (sender, receiver) = sync_channel(1);
        drop(receiver);
        let (controller, requests) = fake_controller();

        assert_eq!(
            publish_or_request_shutdown(&sender, controller),
            RemoteSessionSupervisorShutdownPublish::ReceiverGoneShutdownRequested
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abnormal_lane_join_is_bounded_without_panic_payload_exposure() {
        let (controller_tx, controller_rx) = sync_channel::<FakeController>(1);
        let lane = thread::spawn(move || {
            drop(controller_tx);
            panic!("private fake panic payload");
        });

        let finalization = finalize_controller_and_join(&controller_rx, lane);
        assert_eq!(
            finalization.controller(),
            RemoteSessionProcessControllerFinalization::UnavailableBeforeEndpointStartup
        );
        assert_eq!(
            finalization.thread(),
            RemoteSessionProcessThreadFinalization::Panicked
        );
    }
}
