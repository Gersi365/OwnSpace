//! One-step signal-aware Linux production runtime readiness.
//!
//! Phase 098 extends the validated Phase 091 capacity-aware wait set with one
//! thread-affine termination `SignalFd`. Each invocation performs exactly one
//! blocking `poll` and applies strict semantic precedence: termination signal,
//! runtime wake, then listener readiness. No outer loop lives in this module.

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;

use super::accept_ready::AcceptReadyAgentSocket;
use super::bounded_scheduler_cycle::LocalLinuxSchedulerControl;
use super::runtime_wake::{LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeDrainError};
use super::termination_signal::{
    LocalLinuxTerminationSignal, LocalLinuxTerminationSignalRead,
    LocalLinuxTerminationSignalReadError, LocalLinuxTerminationSignalSource,
};
use super::worker_capacity::LocalLinuxWorkerCapacity;
use super::worker_completion::LocalLinuxScopedWorkerCompletion;
use super::worker_registry::LocalLinuxScopedWorkerRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxSignalAwarePollCall {
    Ready(usize),
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxSignalAwarePollDescriptor {
    Signal,
    Wake,
    Listener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLinuxSignalAwareReadyPath {
    Signal,
    Wake,
    Listener,
}

/// Successful result of one signal-aware blocking readiness invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxSignalAwareReadinessOutcome {
    /// Terminal scheduler shutdown was already committed or observed after wake.
    ShutdownObserved,
    /// One synchronous SIGTERM/SIGINT termination event won readiness precedence.
    TerminationSignal(LocalLinuxTerminationSignal),
    /// Runtime wake was handled without eligible listener dispatch.
    RuntimeWake,
    /// The single blocking `poll` or `SignalFd` read was interrupted.
    WaitInterrupted,
    /// Listener readiness survived signal/wake precedence and capacity revalidation.
    ListenerReady,
}

/// Evidence returned by one signal-aware readiness invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalLinuxSignalAwareReadinessReport {
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    outcome: LocalLinuxSignalAwareReadinessOutcome,
}

impl LocalLinuxSignalAwareReadinessReport {
    /// Returns worker completions reaped during wake-first processing.
    #[must_use]
    pub fn completions(&self) -> &[LocalLinuxScopedWorkerCompletion] {
        &self.completions
    }

    /// Returns whether listener interest was armed for this exact wait.
    #[must_use]
    pub const fn listener_armed(&self) -> bool {
        self.listener_armed
    }

    /// Returns the terminal outcome of this one-step readiness invocation.
    #[must_use]
    pub const fn outcome(&self) -> LocalLinuxSignalAwareReadinessOutcome {
        self.outcome
    }
}

/// Bounded fail-closed signal-aware readiness failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxSignalAwareReadinessError {
    /// Kernel `poll` failed for a reason other than EINTR.
    WaitFailed,
    /// `poll` returned an impossible zero/count/readiness combination.
    InvalidWaitReturn,
    /// The termination descriptor reported ERR/HUP/NVAL.
    SignalDescriptorFailed,
    /// The runtime-wake descriptor reported ERR/HUP/NVAL.
    WakeDescriptorFailed,
    /// The listener descriptor reported ERR/HUP/NVAL.
    ListenerDescriptorFailed,
    /// The termination descriptor returned flags outside exact readable readiness.
    InvalidSignalReadiness,
    /// The runtime-wake descriptor returned flags outside exact readable readiness.
    InvalidWakeReadiness,
    /// The listener returned flags outside exact readable readiness.
    InvalidListenerReadiness,
    /// `SignalFd` readiness could not be consumed under the locked read contract.
    SignalRead(LocalLinuxTerminationSignalReadError),
    /// Phase 089 runtime wake could not be drained under the locked contract.
    WakeDrain(LocalLinuxRuntimeWakeDrainError),
    /// Listener readiness survived polling while capacity had become full.
    ListenerCapacityInvariant,
}

/// Performs exactly one capacity-aware blocking wait across signal/wake/listener.
///
/// Listener interest is omitted whenever worker capacity is full. If several
/// descriptors become ready in one kernel result, semantic precedence is always:
/// termination signal, runtime wake, listener. A consumed termination signal
/// commits monotonic scheduler shutdown before this function returns.
///
/// # Errors
///
/// Returns a bounded fail-closed error for impossible `poll` results, descriptor
/// error/unknown flags, signal-read failure, wake-drain failure, or a listener
/// capacity invariant violation.
pub fn wait_once_for_signal_aware_linux_runtime_readiness(
    listener: &AcceptReadyAgentSocket<'_>,
    signal_source: &LocalLinuxTerminationSignalSource,
    wake: &LocalLinuxRuntimeWake,
    capacity: &LocalLinuxWorkerCapacity,
    registry: &mut LocalLinuxScopedWorkerRegistry<'_>,
    control: &LocalLinuxSchedulerControl,
) -> Result<LocalLinuxSignalAwareReadinessReport, LocalLinuxSignalAwareReadinessError> {
    if control.is_shutdown_requested() {
        return Ok(report(
            Vec::new(),
            false,
            LocalLinuxSignalAwareReadinessOutcome::ShutdownObserved,
        ));
    }

    let listener_armed = capacity.active_workers() < capacity.max_workers();
    let mut descriptors = vec![
        PollFd::new(signal_source, PollFlags::IN),
        PollFd::new(wake, PollFlags::IN),
    ];
    if listener_armed {
        descriptors.push(PollFd::new(listener, PollFlags::IN));
    }

    let poll_call = classify_poll_call(poll(&mut descriptors, None), descriptors.len())?;
    if poll_call == LocalLinuxSignalAwarePollCall::Interrupted {
        return Ok(report(
            Vec::new(),
            listener_armed,
            LocalLinuxSignalAwareReadinessOutcome::WaitInterrupted,
        ));
    }

    let LocalLinuxSignalAwarePollCall::Ready(ready_count) = poll_call else {
        unreachable!("interrupted signal-aware poll returned above");
    };

    let signal_revents = descriptors[0].revents();
    let wake_revents = descriptors[1].revents();
    let listener_revents = if listener_armed {
        descriptors[2].revents()
    } else {
        PollFlags::empty()
    };

    validate_ready_count(
        ready_count,
        signal_revents,
        wake_revents,
        listener_revents,
        listener_armed,
    )?;

    let signal_ready =
        classify_descriptor_revents(signal_revents, LocalLinuxSignalAwarePollDescriptor::Signal)?;
    let wake_ready =
        classify_descriptor_revents(wake_revents, LocalLinuxSignalAwarePollDescriptor::Wake)?;
    let listener_ready = if listener_armed {
        classify_descriptor_revents(
            listener_revents,
            LocalLinuxSignalAwarePollDescriptor::Listener,
        )?
    } else {
        false
    };

    match select_ready_path(signal_ready, wake_ready, listener_ready) {
        Some(LocalLinuxSignalAwareReadyPath::Signal) => {
            return consume_termination_signal(signal_source, listener_armed, control);
        }
        Some(LocalLinuxSignalAwareReadyPath::Wake) => {
            wake.drain()
                .map_err(LocalLinuxSignalAwareReadinessError::WakeDrain)?;
            let completions = registry.reap_finished();

            if control.is_shutdown_requested() {
                return Ok(report(
                    completions,
                    listener_armed,
                    LocalLinuxSignalAwareReadinessOutcome::ShutdownObserved,
                ));
            }

            if listener_ready && capacity.active_workers() < capacity.max_workers() {
                return Ok(report(
                    completions,
                    listener_armed,
                    LocalLinuxSignalAwareReadinessOutcome::ListenerReady,
                ));
            }

            return Ok(report(
                completions,
                listener_armed,
                LocalLinuxSignalAwareReadinessOutcome::RuntimeWake,
            ));
        }
        Some(LocalLinuxSignalAwareReadyPath::Listener) => {
            if control.is_shutdown_requested() {
                return Ok(report(
                    Vec::new(),
                    listener_armed,
                    LocalLinuxSignalAwareReadinessOutcome::ShutdownObserved,
                ));
            }
            if capacity.active_workers() >= capacity.max_workers() {
                return Err(LocalLinuxSignalAwareReadinessError::ListenerCapacityInvariant);
            }
            return Ok(report(
                Vec::new(),
                listener_armed,
                LocalLinuxSignalAwareReadinessOutcome::ListenerReady,
            ));
        }
        None => {}
    }

    Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn)
}

fn consume_termination_signal(
    signal_source: &LocalLinuxTerminationSignalSource,
    listener_armed: bool,
    control: &LocalLinuxSchedulerControl,
) -> Result<LocalLinuxSignalAwareReadinessReport, LocalLinuxSignalAwareReadinessError> {
    match signal_source
        .read_signal()
        .map_err(LocalLinuxSignalAwareReadinessError::SignalRead)?
    {
        LocalLinuxTerminationSignalRead::Signal(signal) => {
            control.request_shutdown();
            Ok(report(
                Vec::new(),
                listener_armed,
                LocalLinuxSignalAwareReadinessOutcome::TerminationSignal(signal),
            ))
        }
        LocalLinuxTerminationSignalRead::Interrupted => Ok(report(
            Vec::new(),
            listener_armed,
            LocalLinuxSignalAwareReadinessOutcome::WaitInterrupted,
        )),
        LocalLinuxTerminationSignalRead::WouldBlock => {
            Err(LocalLinuxSignalAwareReadinessError::InvalidSignalReadiness)
        }
    }
}

const fn report(
    completions: Vec<LocalLinuxScopedWorkerCompletion>,
    listener_armed: bool,
    outcome: LocalLinuxSignalAwareReadinessOutcome,
) -> LocalLinuxSignalAwareReadinessReport {
    LocalLinuxSignalAwareReadinessReport {
        completions,
        listener_armed,
        outcome,
    }
}

const fn classify_poll_call(
    result: Result<usize, Errno>,
    descriptor_count: usize,
) -> Result<LocalLinuxSignalAwarePollCall, LocalLinuxSignalAwareReadinessError> {
    match result {
        Ok(0) => Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn),
        Ok(count) if count > descriptor_count => {
            Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn)
        }
        Ok(count) => Ok(LocalLinuxSignalAwarePollCall::Ready(count)),
        Err(Errno::INTR) => Ok(LocalLinuxSignalAwarePollCall::Interrupted),
        Err(_) => Err(LocalLinuxSignalAwareReadinessError::WaitFailed),
    }
}

fn validate_ready_count(
    ready_count: usize,
    signal_revents: PollFlags,
    wake_revents: PollFlags,
    listener_revents: PollFlags,
    listener_armed: bool,
) -> Result<(), LocalLinuxSignalAwareReadinessError> {
    let observed = usize::from(!signal_revents.is_empty())
        + usize::from(!wake_revents.is_empty())
        + usize::from(listener_armed && !listener_revents.is_empty());
    if observed != ready_count {
        return Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn);
    }
    Ok(())
}

fn classify_descriptor_revents(
    revents: PollFlags,
    descriptor: LocalLinuxSignalAwarePollDescriptor,
) -> Result<bool, LocalLinuxSignalAwareReadinessError> {
    let errors = PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL;
    if revents.intersects(errors) {
        return Err(match descriptor {
            LocalLinuxSignalAwarePollDescriptor::Signal => {
                LocalLinuxSignalAwareReadinessError::SignalDescriptorFailed
            }
            LocalLinuxSignalAwarePollDescriptor::Wake => {
                LocalLinuxSignalAwareReadinessError::WakeDescriptorFailed
            }
            LocalLinuxSignalAwarePollDescriptor::Listener => {
                LocalLinuxSignalAwareReadinessError::ListenerDescriptorFailed
            }
        });
    }

    if !revents.difference(PollFlags::IN).is_empty() {
        return Err(match descriptor {
            LocalLinuxSignalAwarePollDescriptor::Signal => {
                LocalLinuxSignalAwareReadinessError::InvalidSignalReadiness
            }
            LocalLinuxSignalAwarePollDescriptor::Wake => {
                LocalLinuxSignalAwareReadinessError::InvalidWakeReadiness
            }
            LocalLinuxSignalAwarePollDescriptor::Listener => {
                LocalLinuxSignalAwareReadinessError::InvalidListenerReadiness
            }
        });
    }

    Ok(revents.contains(PollFlags::IN))
}

const fn select_ready_path(
    signal_ready: bool,
    wake_ready: bool,
    listener_ready: bool,
) -> Option<LocalLinuxSignalAwareReadyPath> {
    if signal_ready {
        Some(LocalLinuxSignalAwareReadyPath::Signal)
    } else if wake_ready {
        Some(LocalLinuxSignalAwareReadyPath::Wake)
    } else if listener_ready {
        Some(LocalLinuxSignalAwareReadyPath::Listener)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::PollFlags;
    use rustix::io::Errno;

    use super::{
        LocalLinuxSignalAwarePollCall, LocalLinuxSignalAwarePollDescriptor,
        LocalLinuxSignalAwareReadinessError, LocalLinuxSignalAwareReadyPath,
        classify_descriptor_revents, classify_poll_call, select_ready_path, validate_ready_count,
    };

    #[test]
    fn semantic_precedence_is_signal_then_wake_then_listener() {
        assert_eq!(
            select_ready_path(true, true, true),
            Some(LocalLinuxSignalAwareReadyPath::Signal)
        );
        assert_eq!(
            select_ready_path(false, true, true),
            Some(LocalLinuxSignalAwareReadyPath::Wake)
        );
        assert_eq!(
            select_ready_path(false, false, true),
            Some(LocalLinuxSignalAwareReadyPath::Listener)
        );
        assert_eq!(select_ready_path(false, false, false), None);
    }

    #[test]
    fn poll_classifier_surfaces_interrupt_without_retry() {
        assert_eq!(
            classify_poll_call(Err(Errno::INTR), 3),
            Ok(LocalLinuxSignalAwarePollCall::Interrupted)
        );
        assert_eq!(
            classify_poll_call(Ok(0), 3),
            Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn)
        );
        assert_eq!(
            classify_poll_call(Ok(4), 3),
            Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn)
        );
    }

    #[test]
    fn ready_count_matches_exact_three_descriptor_observation() {
        assert_eq!(
            validate_ready_count(3, PollFlags::IN, PollFlags::IN, PollFlags::IN, true,),
            Ok(())
        );
        assert_eq!(
            validate_ready_count(2, PollFlags::IN, PollFlags::IN, PollFlags::IN, false),
            Ok(())
        );
        assert_eq!(
            validate_ready_count(3, PollFlags::IN, PollFlags::IN, PollFlags::IN, false),
            Err(LocalLinuxSignalAwareReadinessError::InvalidWaitReturn)
        );
    }

    #[test]
    fn descriptor_classifier_fails_closed_by_descriptor_kind() {
        assert_eq!(
            classify_descriptor_revents(
                PollFlags::ERR,
                LocalLinuxSignalAwarePollDescriptor::Signal,
            ),
            Err(LocalLinuxSignalAwareReadinessError::SignalDescriptorFailed)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::HUP, LocalLinuxSignalAwarePollDescriptor::Wake,),
            Err(LocalLinuxSignalAwareReadinessError::WakeDescriptorFailed)
        );
        assert_eq!(
            classify_descriptor_revents(
                PollFlags::NVAL,
                LocalLinuxSignalAwarePollDescriptor::Listener,
            ),
            Err(LocalLinuxSignalAwareReadinessError::ListenerDescriptorFailed)
        );
        assert_eq!(
            classify_descriptor_revents(
                PollFlags::OUT,
                LocalLinuxSignalAwarePollDescriptor::Signal,
            ),
            Err(LocalLinuxSignalAwareReadinessError::InvalidSignalReadiness)
        );
        assert_eq!(
            classify_descriptor_revents(PollFlags::IN, LocalLinuxSignalAwarePollDescriptor::Signal),
            Ok(true)
        );
    }
}
