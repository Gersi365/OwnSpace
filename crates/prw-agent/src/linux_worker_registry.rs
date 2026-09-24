//! Scoped worker registry with explicit completion reaping and cancellation authority.
//!
//! Phase 080 retains Phase 078 scoped join handles and routes every explicit
//! join through Phase 079 completion classification. Phase 082 pairs every
//! retained handle with one authenticated-stream cancellation authority.

use std::thread::ScopedJoinHandle;

use super::session_worker_thread::LocalLinuxScopedWorkerResult;
use super::worker_cancellation::{LocalLinuxWorkerCancellation, LocalLinuxWorkerCancellationError};
use super::worker_completion::{
    LocalLinuxScopedWorkerCompletion, join_authenticated_session_worker,
};

#[derive(Debug)]
struct LocalLinuxScopedWorkerEntry<'scope> {
    handle: ScopedJoinHandle<'scope, LocalLinuxScopedWorkerResult>,
    cancellation: LocalLinuxWorkerCancellation,
}

/// Result of one registered worker cancellation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRegisteredWorkerCancellation {
    /// `shutdown(Both)` succeeded for this registered worker connection.
    Cancelled,
    /// The retained cancellation descriptor rejected `shutdown(Both)`.
    Failed(LocalLinuxWorkerCancellationError),
}

/// Scoped worker handle + cancellation owner for future runtime scheduling.
///
/// Runtime orchestration is expected to reap finished workers during normal
/// operation and, at shutdown, call [`Self::cancel_all`] before consuming the
/// registry with [`Self::join_all`].
#[derive(Debug, Default)]
#[must_use = "worker handles/cancellation authorities must be reaped or joined before scope exit"]
pub struct LocalLinuxScopedWorkerRegistry<'scope> {
    entries: Vec<LocalLinuxScopedWorkerEntry<'scope>>,
}

impl<'scope> LocalLinuxScopedWorkerRegistry<'scope> {
    /// Creates an empty scoped worker registry.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Registers one already-spawned scoped worker and its matching cancellation authority.
    pub fn register(
        &mut self,
        handle: ScopedJoinHandle<'scope, LocalLinuxScopedWorkerResult>,
        cancellation: LocalLinuxWorkerCancellation,
    ) {
        self.entries.push(LocalLinuxScopedWorkerEntry {
            handle,
            cancellation,
        });
    }

    /// Returns the currently retained worker-entry count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no scoped worker entries remain registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns whether any retained scoped handle is kernel/thread-finished.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn has_finished_worker_for_test(&self) -> bool {
        self.entries.iter().any(|entry| entry.handle.is_finished())
    }

    /// Issues terminal socket shutdown to every currently registered worker.
    ///
    /// The registry and join handles remain intact. A shutdown syscall failure is
    /// reported per entry and does not remove or skip later joining of that worker.
    #[must_use]
    pub fn cancel_all(&self) -> Vec<LocalLinuxRegisteredWorkerCancellation> {
        self.entries
            .iter()
            .map(|entry| match entry.cancellation.cancel() {
                Ok(()) => LocalLinuxRegisteredWorkerCancellation::Cancelled,
                Err(error) => LocalLinuxRegisteredWorkerCancellation::Failed(error),
            })
            .collect()
    }

    /// Non-blockingly joins every worker whose main function has already finished.
    ///
    /// Handles still running remain registered together with their cancellation
    /// authority. Reaped entries drop that authority only after the worker result
    /// is explicitly classified.
    #[must_use]
    pub fn reap_finished(&mut self) -> Vec<LocalLinuxScopedWorkerCompletion> {
        let mut completions = Vec::new();
        let mut index = 0;

        while index < self.entries.len() {
            if self.entries[index].handle.is_finished() {
                let entry = self.entries.remove(index);
                let LocalLinuxScopedWorkerEntry {
                    handle,
                    cancellation,
                } = entry;
                let completion = join_authenticated_session_worker(handle);
                drop(cancellation);
                completions.push(completion);
            } else {
                index += 1;
            }
        }

        completions
    }

    /// Joins and classifies every remaining registered worker.
    ///
    /// This operation may block until all remaining scoped workers terminate and
    /// is intended for the explicit shutdown/join boundary after `cancel_all()`.
    #[must_use]
    pub fn join_all(mut self) -> Vec<LocalLinuxScopedWorkerCompletion> {
        self.entries
            .drain(..)
            .map(|entry| {
                let LocalLinuxScopedWorkerEntry {
                    handle,
                    cancellation,
                } = entry;
                let completion = join_authenticated_session_worker(handle);
                drop(cancellation);
                completion
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Barrier};
    use std::thread::{self, Builder};
    use std::time::{Duration, Instant};

    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    use super::{LocalLinuxRegisteredWorkerCancellation, LocalLinuxScopedWorkerRegistry};
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::session_worker::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop,
    };
    use crate::linux_identity::session_worker_thread::{
        LocalLinuxScopedWorkerResult, spawn_authenticated_session_worker,
    };
    use crate::linux_identity::worker_cancellation::LocalLinuxWorkerCancellation;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::linux_identity::worker_completion::LocalLinuxScopedWorkerCompletion;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    fn cancellation() -> (LocalLinuxWorkerCancellation, UnixStream) {
        let (server, client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID test stream authenticates");
        let cancellation =
            LocalLinuxWorkerCancellation::try_from_authenticated_connection(&connection)
                .expect("cancellation clone creates");
        drop(connection);
        (cancellation, client)
    }

    #[test]
    fn registry_starts_empty_and_tracks_paired_registration() {
        thread::scope(|scope| {
            let handle = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    Ok(LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 0,
                    })
                })
                .expect("test scoped worker spawns");
            let (cancellation, _peer) = cancellation();
            let mut registry = LocalLinuxScopedWorkerRegistry::new();

            assert!(registry.is_empty());
            registry.register(handle, cancellation);
            assert_eq!(registry.len(), 1);

            assert_eq!(registry.join_all().len(), 1);
        });
    }

    #[test]
    fn reap_finished_leaves_running_worker_and_cancellation_registered() {
        thread::scope(|scope| {
            let release = Arc::new(Barrier::new(2));
            let release_worker = Arc::clone(&release);
            let finished = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    Ok(LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 1,
                    })
                })
                .expect("finished test worker spawns");
            let running = Builder::new()
                .spawn_scoped(scope, move || -> LocalLinuxScopedWorkerResult {
                    release_worker.wait();
                    Ok(LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 2,
                    })
                })
                .expect("running test worker spawns");
            let (finished_cancel, _finished_peer) = cancellation();
            let (running_cancel, _running_peer) = cancellation();
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            registry.register(finished, finished_cancel);
            registry.register(running, running_cancel);

            let reaped = loop {
                let reaped = registry.reap_finished();
                if !reaped.is_empty() {
                    break reaped;
                }
                thread::yield_now();
            };

            assert_eq!(
                reaped,
                vec![LocalLinuxScopedWorkerCompletion::Stopped(
                    LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 1,
                    }
                )]
            );
            assert_eq!(registry.len(), 1);
            assert_eq!(
                registry.cancel_all(),
                vec![LocalLinuxRegisteredWorkerCancellation::Cancelled]
            );

            release.wait();
            assert_eq!(
                registry.join_all(),
                vec![LocalLinuxScopedWorkerCompletion::Stopped(
                    LocalLinuxSessionWorkerStop::CleanEof {
                        responses_written: 2,
                    }
                )]
            );
        });
    }

    #[test]
    fn join_all_classifies_every_remaining_worker_in_registration_order() {
        thread::scope(|scope| {
            let first = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                        responses_written: 4,
                    })
                })
                .expect("first test worker spawns");
            let second = Builder::new()
                .spawn_scoped(scope, || -> LocalLinuxScopedWorkerResult {
                    panic!("planned Phase 082 registry worker panic")
                })
                .expect("second test worker spawns");
            let (first_cancel, _first_peer) = cancellation();
            let (second_cancel, _second_peer) = cancellation();
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            registry.register(first, first_cancel);
            registry.register(second, second_cancel);

            assert_eq!(
                registry.join_all(),
                vec![
                    LocalLinuxScopedWorkerCompletion::Stopped(
                        LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                            responses_written: 4,
                        }
                    ),
                    LocalLinuxScopedWorkerCompletion::Panicked,
                ]
            );
        });
    }

    struct AlwaysAllow;

    impl PolicyEvaluator for AlwaysAllow {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Allow
        }
    }

    #[test]
    fn cancel_all_wakes_worker_blocked_on_long_request_read_and_releases_capacity() {
        let (server, _client) = UnixStream::pair().expect("anonymous Unix pair creates");
        let connection = AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID test stream authenticates");
        let cancellation =
            LocalLinuxWorkerCancellation::try_from_authenticated_connection(&connection)
                .expect("cancellation clone creates before session move");
        let session = AuthenticatedLocalLinuxSession::new(connection);
        let capacity = LocalLinuxWorkerCapacity::new(
            NonZeroUsize::new(1).expect("test worker capacity is non-zero"),
        );
        let permit = capacity.try_acquire().expect("worker slot acquires");
        let policy = AlwaysAllow;
        let dns = LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded");
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let config = LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("test Request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(5))
                .expect("long read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_millis(500))
                .expect("write budget is non-zero"),
        );

        thread::scope(|scope| {
            let handle = spawn_authenticated_session_worker(
                scope, session, permit, &policy, status, &dns, config,
            )
            .expect("scoped worker spawns");
            let mut registry = LocalLinuxScopedWorkerRegistry::new();
            registry.register(handle, cancellation);

            thread::sleep(Duration::from_millis(50));
            let cancel_started = Instant::now();
            assert_eq!(
                registry.cancel_all(),
                vec![LocalLinuxRegisteredWorkerCancellation::Cancelled]
            );
            let completions = registry.join_all();

            assert!(cancel_started.elapsed() < Duration::from_secs(2));
            assert_eq!(capacity.active_workers(), 0);
            assert_eq!(completions.len(), 1);
            assert!(matches!(
                completions[0],
                LocalLinuxScopedWorkerCompletion::Stopped(LocalLinuxSessionWorkerStop::CleanEof {
                    responses_written: 0
                }) | LocalLinuxScopedWorkerCompletion::WorkerError(_)
            ));
        });
    }
}
