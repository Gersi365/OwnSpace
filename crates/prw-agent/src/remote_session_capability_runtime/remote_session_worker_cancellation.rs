//! Single-worker orderly cancellation pair for the staged remote-session runtime.
//!
//! C03e-AC selected one explicit controller and one signal backed by durable monotonic state plus
//! one Tokio async wake. C03e-AD materializes only that pair. It does not clone cancellation
//! authority, retain worker handles, fan out shutdown, wire process signals, or activate transport.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::Notify;

struct RemoteSessionWorkerCancellationState {
    requested: AtomicBool,
    wake: Notify,
}

/// Explicit orderly-cancellation authority for one remote-session worker.
pub struct RemoteSessionWorkerCancellationController {
    state: Arc<RemoteSessionWorkerCancellationState>,
}

/// Single waiter that becomes ready only after explicit orderly cancellation is requested.
pub struct RemoteSessionWorkerCancellationSignal {
    state: Arc<RemoteSessionWorkerCancellationState>,
}

/// Creates one controller/signal pair for exactly one remote-session worker.
///
/// Construction performs only in-process synchronization allocation. Neither public half is
/// cloneable, and construction does not spawn work, touch transport, or alter runtime state.
#[must_use]
pub fn remote_session_worker_cancellation_pair() -> (
    RemoteSessionWorkerCancellationController,
    RemoteSessionWorkerCancellationSignal,
) {
    let state = Arc::new(RemoteSessionWorkerCancellationState {
        requested: AtomicBool::new(false),
        wake: Notify::new(),
    });

    (
        RemoteSessionWorkerCancellationController {
            state: Arc::clone(&state),
        },
        RemoteSessionWorkerCancellationSignal { state },
    )
}

impl RemoteSessionWorkerCancellationController {
    /// Requests orderly cancellation for the paired single worker.
    ///
    /// The transition is monotonic and idempotent. This method does not wait for worker completion,
    /// close transport, abort a task, or expose the underlying synchronization primitives.
    pub fn request_cancellation(&self) {
        self.state.requested.store(true, Ordering::Release);
        self.state.wake.notify_one();
    }
}

impl RemoteSessionWorkerCancellationSignal {
    /// Consumes this single signal and returns a `'static` orderly-cancellation future.
    ///
    /// The monotonic flag is the lifecycle state. `Notify` is only the async wake mechanism. A
    /// notification racing between the flag check and waiter registration is retained as a Tokio
    /// permit, so the single waiter cannot permanently miss an explicit cancellation request.
    pub async fn into_cancelled(self) {
        while !self.state.requested.load(Ordering::Acquire) {
            self.state.wake.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::remote_session_worker_cancellation_pair;

    #[derive(Default)]
    struct WakeFlag {
        woken: AtomicBool,
    }

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.woken.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.woken.store(true, Ordering::SeqCst);
        }
    }

    fn test_context() -> (Arc<WakeFlag>, Waker) {
        let flag = Arc::new(WakeFlag::default());
        let waker = Waker::from(Arc::clone(&flag));
        (flag, waker)
    }

    fn assert_send_static_cancellation_future<F>(future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        drop(future);
    }

    #[test]
    fn cancellation_requested_before_poll_completes_from_durable_state() {
        let (controller, signal) = remote_session_worker_cancellation_pair();
        controller.request_cancellation();

        let mut future = Box::pin(signal.into_cancelled());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn pending_signal_is_woken_by_explicit_request_and_then_completes() {
        let (controller, signal) = remote_session_worker_cancellation_pair();
        let mut future = Box::pin(signal.into_cancelled());
        let (wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert!(!wake_flag.woken.load(Ordering::SeqCst));

        controller.request_cancellation();

        assert!(wake_flag.woken.load(Ordering::SeqCst));
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn repeated_requests_are_idempotent() {
        let (controller, signal) = remote_session_worker_cancellation_pair();
        controller.request_cancellation();
        controller.request_cancellation();

        let mut future = Box::pin(signal.into_cancelled());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn dropping_controller_without_request_does_not_cancel_signal() {
        let (controller, signal) = remote_session_worker_cancellation_pair();
        let mut future = Box::pin(signal.into_cancelled());
        let (_wake_flag, waker) = test_context();
        let mut context = Context::from_waker(&waker);

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        drop(controller);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
    }

    #[test]
    fn cancellation_future_matches_spawned_worker_generic_bound() {
        let (_controller, signal) = remote_session_worker_cancellation_pair();
        assert_send_static_cancellation_future(signal.into_cancelled());
    }
}
