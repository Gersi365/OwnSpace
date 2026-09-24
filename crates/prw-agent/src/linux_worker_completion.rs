//! Explicit scoped-worker completion classification.
//!
//! Phase 079 consumes one Phase 078 scoped join handle and classifies normal
//! worker stop, bounded worker failure, or thread panic. It spawns no thread.

use std::thread::ScopedJoinHandle;

use super::session_worker::{LocalLinuxSessionWorkerError, LocalLinuxSessionWorkerStop};
use super::session_worker_thread::LocalLinuxScopedWorkerResult;

/// Fully classified terminal outcome of one joined scoped session worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxScopedWorkerCompletion {
    /// The finite Phase 076 worker body reached a normal stop condition.
    Stopped(LocalLinuxSessionWorkerStop),
    /// The finite Phase 076 worker body returned its bounded processing failure.
    WorkerError(LocalLinuxSessionWorkerError),
    /// The scoped OS thread panicked before producing a worker result.
    Panicked,
}

/// Joins one scoped session worker and classifies every terminal path.
///
/// The join handle is consumed exactly once. Panic payload contents are not
/// exposed through the local runtime contract; they are reduced to the bounded
/// [`LocalLinuxScopedWorkerCompletion::Panicked`] classification.
#[must_use]
pub fn join_authenticated_session_worker(
    handle: ScopedJoinHandle<'_, LocalLinuxScopedWorkerResult>,
) -> LocalLinuxScopedWorkerCompletion {
    match handle.join() {
        Ok(Ok(stop)) => LocalLinuxScopedWorkerCompletion::Stopped(stop),
        Ok(Err(error)) => LocalLinuxScopedWorkerCompletion::WorkerError(error),
        Err(_) => LocalLinuxScopedWorkerCompletion::Panicked,
    }
}

#[cfg(test)]
mod tests {
    use std::thread::{self, Builder};

    use super::{LocalLinuxScopedWorkerCompletion, join_authenticated_session_worker};
    use crate::linux_identity::authenticated_session::LocalLinuxDeadlineSessionProcessError;
    use crate::linux_identity::deadline_io::LocalLinuxDeadlineStartError;
    use crate::linux_identity::session_worker::{
        LocalLinuxSessionWorkerError, LocalLinuxSessionWorkerStop,
    };
    use crate::linux_identity::session_worker_thread::LocalLinuxScopedWorkerResult;

    #[test]
    fn normal_worker_stop_is_preserved() {
        thread::scope(|scope| {
            let handle = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    Ok(LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 3,
                    })
                })
                .expect("test scoped worker spawns");

            assert_eq!(
                join_authenticated_session_worker(handle),
                LocalLinuxScopedWorkerCompletion::Stopped(LocalLinuxSessionWorkerStop::CleanEof {
                    responses_written: 3,
                })
            );
        });
    }

    #[test]
    fn bounded_worker_error_is_preserved() {
        thread::scope(|scope| {
            let expected = LocalLinuxSessionWorkerError::Processing {
                responses_written: 2,
                error: LocalLinuxDeadlineSessionProcessError::ReadDeadlineStart(
                    LocalLinuxDeadlineStartError::DeadlineOverflow,
                ),
            };
            let handle = Builder::new()
                .spawn_scoped(scope, move || -> LocalLinuxScopedWorkerResult {
                    Err(expected)
                })
                .expect("test scoped worker spawns");

            assert_eq!(
                join_authenticated_session_worker(handle),
                LocalLinuxScopedWorkerCompletion::WorkerError(expected)
            );
        });
    }

    #[test]
    fn worker_panic_is_bounded_to_panicked_classification() {
        thread::scope(|scope| {
            let handle = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    panic!("planned Phase 079 worker panic")
                })
                .expect("test scoped worker spawns");

            assert_eq!(
                join_authenticated_session_worker(handle),
                LocalLinuxScopedWorkerCompletion::Panicked
            );
        });
    }
}
