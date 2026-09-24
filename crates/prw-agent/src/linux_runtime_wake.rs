//! Linux runtime wake transport for finite readiness orchestration.
//!
//! Phase 089 owns one non-semaphore `eventfd` plus cloneable write-only
//! notifiers. It does not own shutdown semantics, worker completion state,
//! listener readiness, an outer event loop, or Agent bootstrap activation.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use rustix::event::{EventfdFlags, eventfd};
use rustix::io::{Errno, read, write};

const WAKE_VALUE_BYTES: [u8; 8] = 1_u64.to_ne_bytes();

/// Single-consumer Linux runtime wake descriptor owner.
///
/// The descriptor begins at counter zero, is close-on-exec and nonblocking, and
/// is deliberately not created in semaphore mode. Only this type exposes drain
/// authority; cloned producers use [`LocalLinuxRuntimeWakeNotifier`].
#[derive(Debug)]
pub struct LocalLinuxRuntimeWake {
    fd: Arc<OwnedFd>,
}

/// Cloneable write-only producer for one [`LocalLinuxRuntimeWake`].
#[derive(Debug, Clone)]
pub struct LocalLinuxRuntimeWakeNotifier {
    fd: Arc<OwnedFd>,
}

/// Successful result of one runtime wake notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeWakeNotify {
    /// The fixed wake value was written to the kernel counter.
    Queued,
    /// `EAGAIN` proved that a readable wake was already pending.
    AlreadyPending,
}

/// Failure while creating the Phase 089 wake descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeWakeCreateError {
    /// Linux rejected `eventfd(0, CLOEXEC | NONBLOCK)`.
    CreateFailed,
}

/// Failure while posting one fixed runtime wake notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeWakeNotifyError {
    /// A successful syscall reported a byte count other than exactly eight.
    ShortWrite,
    /// The write failed with an errno other than `EINTR` or `EAGAIN`.
    WriteFailed,
}

/// Failure while draining one already-reported runtime wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxRuntimeWakeDrainError {
    /// The descriptor was not readable when the drain was attempted.
    WouldBlock,
    /// A successful syscall reported a byte count other than exactly eight.
    ShortRead,
    /// The eight-byte result decoded to zero, which is not a valid wake.
    ZeroCounter,
    /// The all-ones overflow sentinel was observed.
    OverflowCounter,
    /// The read failed with an errno other than `EINTR` or `EAGAIN`.
    ReadFailed,
}

impl LocalLinuxRuntimeWake {
    /// Creates one Phase 089 runtime wake descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxRuntimeWakeCreateError::CreateFailed`] when Linux
    /// rejects the exact `eventfd` creation request.
    pub fn create() -> Result<Self, LocalLinuxRuntimeWakeCreateError> {
        let flags = EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK;
        let fd = eventfd(0, flags).map_err(|_| LocalLinuxRuntimeWakeCreateError::CreateFailed)?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Creates a cloneable producer with write-only API authority.
    #[must_use]
    pub fn notifier(&self) -> LocalLinuxRuntimeWakeNotifier {
        LocalLinuxRuntimeWakeNotifier {
            fd: Arc::clone(&self.fd),
        }
    }

    /// Drains one accumulated non-semaphore wake counter.
    ///
    /// The numeric counter value is validated only as nonzero and non-overflow;
    /// it is intentionally not returned as semantic event data.
    ///
    /// `EINTR` retries only the same fixed eight-byte read operation.
    ///
    /// # Errors
    ///
    /// Returns a bounded drain error for no pending wake, short I/O, invalid
    /// counter values, or another kernel read failure.
    pub fn drain(&self) -> Result<(), LocalLinuxRuntimeWakeDrainError> {
        drain_with(|buffer| read(self.fd.as_ref(), &mut buffer[..]))
    }
}

impl AsFd for LocalLinuxRuntimeWake {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_ref().as_fd()
    }
}

impl LocalLinuxRuntimeWakeNotifier {
    /// Posts one coalescible runtime wake.
    ///
    /// The notifier writes exactly native-endian `1_u64`. `EINTR` retries only
    /// that same fixed write. `EAGAIN` is classified as an already-pending wake
    /// because the nonblocking `eventfd` counter is already readable/nonzero.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for unexpected short I/O or another kernel write
    /// failure. The method itself does not panic.
    pub fn notify(&self) -> Result<LocalLinuxRuntimeWakeNotify, LocalLinuxRuntimeWakeNotifyError> {
        notify_with(|| write(self.fd.as_ref(), &WAKE_VALUE_BYTES))
    }
}

fn notify_with<F>(
    mut attempt: F,
) -> Result<LocalLinuxRuntimeWakeNotify, LocalLinuxRuntimeWakeNotifyError>
where
    F: FnMut() -> Result<usize, Errno>,
{
    loop {
        match attempt() {
            Ok(8) => return Ok(LocalLinuxRuntimeWakeNotify::Queued),
            Ok(_) => return Err(LocalLinuxRuntimeWakeNotifyError::ShortWrite),
            Err(error) if error == Errno::INTR => {}
            Err(error) if error == Errno::AGAIN => {
                return Ok(LocalLinuxRuntimeWakeNotify::AlreadyPending);
            }
            Err(_) => return Err(LocalLinuxRuntimeWakeNotifyError::WriteFailed),
        }
    }
}

fn drain_with<F>(mut attempt: F) -> Result<(), LocalLinuxRuntimeWakeDrainError>
where
    F: FnMut(&mut [u8; 8]) -> Result<usize, Errno>,
{
    let mut buffer = [0_u8; 8];

    loop {
        match attempt(&mut buffer) {
            Ok(8) => {
                let value = u64::from_ne_bytes(buffer);
                if value == 0 {
                    return Err(LocalLinuxRuntimeWakeDrainError::ZeroCounter);
                }
                if value == u64::MAX {
                    return Err(LocalLinuxRuntimeWakeDrainError::OverflowCounter);
                }
                return Ok(());
            }
            Ok(_) => return Err(LocalLinuxRuntimeWakeDrainError::ShortRead),
            Err(error) if error == Errno::INTR => {}
            Err(error) if error == Errno::AGAIN => {
                return Err(LocalLinuxRuntimeWakeDrainError::WouldBlock);
            }
            Err(_) => return Err(LocalLinuxRuntimeWakeDrainError::ReadFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use rustix::fs::{OFlags, fcntl_getfl};
    use rustix::io::{Errno, FdFlags, fcntl_getfd};

    use super::{
        LocalLinuxRuntimeWake, LocalLinuxRuntimeWakeDrainError, LocalLinuxRuntimeWakeNotify,
        LocalLinuxRuntimeWakeNotifyError, drain_with, notify_with,
    };

    #[test]
    fn created_descriptor_is_cloexec_nonblocking_and_starts_without_pending_wake() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 eventfd creates");

        let descriptor_flags = fcntl_getfd(wake.as_fd()).expect("descriptor flags read");
        let status_flags = fcntl_getfl(wake.as_fd()).expect("status flags read");

        assert!(descriptor_flags.contains(FdFlags::CLOEXEC));
        assert!(status_flags.contains(OFlags::NONBLOCK));
        assert_eq!(
            wake.drain(),
            Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
        );
    }

    #[test]
    fn one_notify_is_drained_once_and_numeric_count_is_not_exposed() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 eventfd creates");
        let notifier = wake.notifier();

        assert_eq!(notifier.notify(), Ok(LocalLinuxRuntimeWakeNotify::Queued));
        assert_eq!(wake.drain(), Ok(()));
        assert_eq!(
            wake.drain(),
            Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
        );
    }

    #[test]
    fn multiple_notifications_coalesce_into_one_drainable_wake() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 eventfd creates");
        let notifier = wake.notifier();

        assert_eq!(notifier.notify(), Ok(LocalLinuxRuntimeWakeNotify::Queued));
        assert_eq!(notifier.notify(), Ok(LocalLinuxRuntimeWakeNotify::Queued));

        assert_eq!(wake.drain(), Ok(()));
        assert_eq!(
            wake.drain(),
            Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
        );
    }

    #[test]
    fn cloned_notifiers_share_one_wake_transport() {
        let wake = LocalLinuxRuntimeWake::create().expect("Phase 089 eventfd creates");
        let first = wake.notifier();
        let second = first.clone();

        assert_eq!(first.notify(), Ok(LocalLinuxRuntimeWakeNotify::Queued));
        assert_eq!(second.notify(), Ok(LocalLinuxRuntimeWakeNotify::Queued));
        assert_eq!(wake.drain(), Ok(()));
    }

    #[test]
    fn notify_retries_only_interrupted_fixed_write() {
        let mut calls = 0_usize;
        let outcome = notify_with(|| {
            calls += 1;
            if calls == 1 { Err(Errno::INTR) } else { Ok(8) }
        });

        assert_eq!(outcome, Ok(LocalLinuxRuntimeWakeNotify::Queued));
        assert_eq!(calls, 2);
    }

    #[test]
    fn notify_eagain_is_already_pending_without_retry() {
        let mut calls = 0_usize;
        let outcome = notify_with(|| {
            calls += 1;
            Err(Errno::AGAIN)
        });

        assert_eq!(outcome, Ok(LocalLinuxRuntimeWakeNotify::AlreadyPending));
        assert_eq!(calls, 1);
    }

    #[test]
    fn notify_rejects_short_write_and_non_interrupt_failure() {
        assert_eq!(
            notify_with(|| Ok(7)),
            Err(LocalLinuxRuntimeWakeNotifyError::ShortWrite)
        );

        let mut calls = 0_usize;
        let outcome = notify_with(|| {
            calls += 1;
            Err(Errno::IO)
        });
        assert_eq!(outcome, Err(LocalLinuxRuntimeWakeNotifyError::WriteFailed));
        assert_eq!(calls, 1);
    }

    #[test]
    fn drain_retries_only_interrupted_fixed_read() {
        let mut calls = 0_usize;
        let outcome = drain_with(|buffer| {
            calls += 1;
            if calls == 1 {
                Err(Errno::INTR)
            } else {
                *buffer = 3_u64.to_ne_bytes();
                Ok(8)
            }
        });

        assert_eq!(outcome, Ok(()));
        assert_eq!(calls, 2);
    }

    #[test]
    fn drain_rejects_would_block_short_zero_overflow_and_other_failure() {
        assert_eq!(
            drain_with(|_| Err(Errno::AGAIN)),
            Err(LocalLinuxRuntimeWakeDrainError::WouldBlock)
        );
        assert_eq!(
            drain_with(|_| Ok(7)),
            Err(LocalLinuxRuntimeWakeDrainError::ShortRead)
        );
        assert_eq!(
            drain_with(|buffer| {
                *buffer = 0_u64.to_ne_bytes();
                Ok(8)
            }),
            Err(LocalLinuxRuntimeWakeDrainError::ZeroCounter)
        );
        assert_eq!(
            drain_with(|buffer| {
                *buffer = u64::MAX.to_ne_bytes();
                Ok(8)
            }),
            Err(LocalLinuxRuntimeWakeDrainError::OverflowCounter)
        );

        let mut calls = 0_usize;
        let outcome = drain_with(|_| {
            calls += 1;
            Err(Errno::IO)
        });
        assert_eq!(outcome, Err(LocalLinuxRuntimeWakeDrainError::ReadFailed));
        assert_eq!(calls, 1);
    }

    #[test]
    fn wake_and_notifier_have_expected_thread_safety() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalLinuxRuntimeWake>();
        assert_send_sync::<super::LocalLinuxRuntimeWakeNotifier>();
    }
}
