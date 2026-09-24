//! Bounded active-worker capacity accounting for future Linux Agent sessions.
//!
//! Phase 075 owns only thread-safe in-memory accounting. It does not spawn a
//! thread, accept a connection, process a Request, or activate the Agent runtime.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Shared caller-bounded capacity for future authenticated session workers.
#[derive(Debug, Clone)]
pub struct LocalLinuxWorkerCapacity {
    inner: Arc<LocalLinuxWorkerCapacityInner>,
}

#[derive(Debug)]
struct LocalLinuxWorkerCapacityInner {
    max_workers: usize,
    active_workers: AtomicUsize,
}

impl LocalLinuxWorkerCapacity {
    /// Creates shared worker-capacity accounting from a strictly positive bound.
    #[must_use]
    pub fn new(max_workers: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(LocalLinuxWorkerCapacityInner {
                max_workers: max_workers.get(),
                active_workers: AtomicUsize::new(0),
            }),
        }
    }

    /// Returns the configured maximum number of active worker permits.
    #[must_use]
    pub fn max_workers(&self) -> usize {
        self.inner.max_workers
    }

    /// Returns the currently acquired worker-permit count.
    #[must_use]
    pub fn active_workers(&self) -> usize {
        self.inner.active_workers.load(Ordering::Acquire)
    }

    /// Acquires one worker slot without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxWorkerCapacityError::AtCapacity`] when all configured
    /// worker slots are already represented by live permits.
    pub fn try_acquire(&self) -> Result<LocalLinuxWorkerPermit, LocalLinuxWorkerCapacityError> {
        let mut observed = self.inner.active_workers.load(Ordering::Acquire);

        loop {
            if observed >= self.inner.max_workers {
                return Err(LocalLinuxWorkerCapacityError::AtCapacity);
            }

            match self.inner.active_workers.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(LocalLinuxWorkerPermit {
                        inner: Arc::clone(&self.inner),
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }
}

/// Exclusive accounting token for one future active authenticated-session worker.
#[derive(Debug)]
pub struct LocalLinuxWorkerPermit {
    inner: Arc<LocalLinuxWorkerCapacityInner>,
}

impl Drop for LocalLinuxWorkerPermit {
    fn drop(&mut self) {
        let previous = self.inner.active_workers.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "worker permit accounting underflow");
    }
}

/// Bounded worker-capacity acquisition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxWorkerCapacityError {
    /// Every configured worker slot is already represented by a live permit.
    AtCapacity,
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::{LocalLinuxWorkerCapacity, LocalLinuxWorkerCapacityError, LocalLinuxWorkerPermit};

    fn capacity(value: usize) -> LocalLinuxWorkerCapacity {
        LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(value).expect("test worker capacity is non-zero"),
        )
    }

    #[test]
    fn capacity_starts_empty_and_reports_caller_bound() {
        let workers = capacity(3);

        assert_eq!(workers.max_workers(), 3);
        assert_eq!(workers.active_workers(), 0);
    }

    #[test]
    fn acquisition_stops_exactly_at_capacity() {
        let workers = capacity(2);
        let first = workers.try_acquire().expect("first slot acquires");
        let second = workers.try_acquire().expect("second slot acquires");

        assert_eq!(workers.active_workers(), 2);
        assert_eq!(
            workers.try_acquire().unwrap_err(),
            LocalLinuxWorkerCapacityError::AtCapacity
        );

        drop(first);
        drop(second);
    }

    #[test]
    fn dropping_permit_releases_exactly_one_slot() {
        let workers = capacity(2);
        let first = workers.try_acquire().expect("first slot acquires");
        let second = workers.try_acquire().expect("second slot acquires");
        assert_eq!(workers.active_workers(), 2);

        drop(first);
        assert_eq!(workers.active_workers(), 1);

        let replacement = workers.try_acquire().expect("released slot reacquires");
        assert_eq!(workers.active_workers(), 2);

        drop(second);
        assert_eq!(workers.active_workers(), 1);
        drop(replacement);
        assert_eq!(workers.active_workers(), 0);
    }

    #[test]
    fn cloned_capacity_handles_share_the_same_accounting() {
        let workers = capacity(1);
        let observer = workers.clone();
        let permit = workers.try_acquire().expect("shared slot acquires");

        assert_eq!(observer.active_workers(), 1);
        assert_eq!(
            observer.try_acquire().unwrap_err(),
            LocalLinuxWorkerCapacityError::AtCapacity
        );

        drop(permit);
        assert_eq!(observer.active_workers(), 0);
    }

    #[test]
    fn capacity_and_permit_are_thread_transfer_compatible() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}

        assert_send_sync::<LocalLinuxWorkerCapacity>();
        assert_send::<LocalLinuxWorkerPermit>();
    }
}
