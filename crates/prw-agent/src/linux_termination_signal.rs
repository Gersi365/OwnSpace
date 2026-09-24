//! Thread-affine safe Linux termination-signal source.
//!
//! Phase 098 uses nix's safe `SigSet`/`SignalFd` wrappers to synchronously route
//! SIGTERM and SIGINT through one nonblocking pollable descriptor. The owner is
//! deliberately `!Send`/`!Sync`: the saved calling-thread signal mask must be
//! restored on the same thread that installed it.

use std::marker::PhantomData;
use std::os::fd::{AsFd, BorrowedFd};
use std::rc::Rc;

use nix::errno::Errno;
use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};

/// Termination signals accepted by the initial production-local runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxTerminationSignal {
    /// Service-manager / conventional process termination request.
    SigTerm,
    /// Interactive interrupt request.
    SigInt,
}

/// Signal-mask restoration evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxTerminationSignalMaskRestore {
    /// The exact prior calling-thread signal mask was restored.
    Restored,
    /// Restoring the exact prior calling-thread signal mask failed.
    Failed,
}

/// Bounded failure while creating the safe termination-signal source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxTerminationSignalSourceCreateError {
    /// The calling thread could not atomically preserve and block the termination mask.
    MaskBlockFailed,
    /// Creating the nonblocking close-on-exec `SignalFd` failed after the mask changed.
    DescriptorCreateFailed {
        /// Best-effort rollback result for the previously installed signal mask.
        mask_restore: LocalLinuxTerminationSignalMaskRestore,
    },
}

/// Successful result from one nonblocking `SignalFd` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxTerminationSignalRead {
    /// One supported termination signal was consumed from `SignalFd`.
    Signal(LocalLinuxTerminationSignal),
    /// `SignalFd` was nonblocking and had no signal available at read time.
    WouldBlock,
    /// The fixed `SignalFd` read was interrupted; caller must re-observe readiness.
    Interrupted,
}

/// Bounded non-retryable `SignalFd` read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxTerminationSignalReadError {
    /// `SignalFd` returned a signal outside the exact SIGTERM/SIGINT contract.
    UnexpectedSignal,
    /// `SignalFd` read failed for an errno other than EINTR.
    ReadFailed,
}

/// Thread-affine owner for the blocked termination mask and pollable `SignalFd`.
#[derive(Debug)]
pub struct LocalLinuxTerminationSignalSource {
    descriptor: Option<SignalFd>,
    previous_mask: Option<SigSet>,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl LocalLinuxTerminationSignalSource {
    /// Blocks SIGTERM/SIGINT on the calling thread and creates one `SignalFd`.
    ///
    /// The exact prior thread mask is retained for explicit restoration. If
    /// `SignalFd` creation fails after the mask change, mask rollback is attempted
    /// before the error is returned.
    ///
    /// # Errors
    ///
    /// Returns a bounded creation error if the thread mask cannot be changed or
    /// the nonblocking close-on-exec `SignalFd` cannot be created.
    pub fn create() -> Result<Self, LocalLinuxTerminationSignalSourceCreateError> {
        let mask = termination_mask();
        let previous_mask = mask
            .thread_swap_mask(SigmaskHow::SIG_BLOCK)
            .map_err(|_| LocalLinuxTerminationSignalSourceCreateError::MaskBlockFailed)?;

        let flags = SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC;
        let Ok(descriptor) = SignalFd::with_flags(&mask, flags) else {
            let mask_restore = restore_mask(&previous_mask);
            return Err(
                LocalLinuxTerminationSignalSourceCreateError::DescriptorCreateFailed {
                    mask_restore,
                },
            );
        };

        Ok(Self {
            descriptor: Some(descriptor),
            previous_mask: Some(previous_mask),
            _thread_affinity: PhantomData,
        })
    }

    /// Reads at most one pending termination signal without blocking.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an unexpected signal number or a non-EINTR
    /// `SignalFd` read failure.
    pub fn read_signal(
        &self,
    ) -> Result<LocalLinuxTerminationSignalRead, LocalLinuxTerminationSignalReadError> {
        let descriptor = self
            .descriptor
            .as_ref()
            .expect("Phase 098 signal source is readable only before restoration");

        match descriptor.read_signal() {
            Ok(Some(info)) => {
                classify_signal_number(info.ssi_signo).map(LocalLinuxTerminationSignalRead::Signal)
            }
            Ok(None) => Ok(LocalLinuxTerminationSignalRead::WouldBlock),
            Err(Errno::EINTR) => Ok(LocalLinuxTerminationSignalRead::Interrupted),
            Err(_) => Err(LocalLinuxTerminationSignalReadError::ReadFailed),
        }
    }

    /// Closes `SignalFd` and restores the exact prior calling-thread signal mask.
    #[must_use]
    pub fn restore(mut self) -> LocalLinuxTerminationSignalMaskRestore {
        drop(self.descriptor.take());
        let previous_mask = self
            .previous_mask
            .take()
            .expect("Phase 098 signal mask restores exactly once");
        restore_mask(&previous_mask)
    }
}

impl AsFd for LocalLinuxTerminationSignalSource {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor
            .as_ref()
            .expect("Phase 098 signal source descriptor is live before restoration")
            .as_fd()
    }
}

impl Drop for LocalLinuxTerminationSignalSource {
    fn drop(&mut self) {
        drop(self.descriptor.take());
        if let Some(previous_mask) = self.previous_mask.take() {
            let _ = previous_mask.thread_set_mask();
        }
    }
}

fn termination_mask() -> SigSet {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask
}

fn restore_mask(previous_mask: &SigSet) -> LocalLinuxTerminationSignalMaskRestore {
    match previous_mask.thread_set_mask() {
        Ok(()) => LocalLinuxTerminationSignalMaskRestore::Restored,
        Err(_) => LocalLinuxTerminationSignalMaskRestore::Failed,
    }
}

fn classify_signal_number(
    raw_signal: u32,
) -> Result<LocalLinuxTerminationSignal, LocalLinuxTerminationSignalReadError> {
    let raw_signal = i32::try_from(raw_signal)
        .map_err(|_| LocalLinuxTerminationSignalReadError::UnexpectedSignal)?;
    match Signal::try_from(raw_signal) {
        Ok(Signal::SIGTERM) => Ok(LocalLinuxTerminationSignal::SigTerm),
        Ok(Signal::SIGINT) => Ok(LocalLinuxTerminationSignal::SigInt),
        Ok(_) | Err(_) => Err(LocalLinuxTerminationSignalReadError::UnexpectedSignal),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::thread;

    use nix::sys::signal::{SigSet, Signal, raise};
    use rustix::event::{PollFd, PollFlags, poll};

    use super::{
        LocalLinuxTerminationSignal, LocalLinuxTerminationSignalMaskRestore,
        LocalLinuxTerminationSignalRead, LocalLinuxTerminationSignalReadError,
        LocalLinuxTerminationSignalSource, classify_signal_number, termination_mask,
    };

    const SUBPROCESS_ENV: &str = "PRW_PHASE_098_SIGNAL_SOURCE_SUBPROCESS";

    #[test]
    fn termination_mask_contains_exact_initial_signal_contract() {
        let mask = termination_mask();
        assert!(mask.contains(Signal::SIGTERM));
        assert!(mask.contains(Signal::SIGINT));
        assert_eq!(mask.iter().count(), 2);
    }

    #[test]
    fn signal_number_classifier_accepts_only_sigterm_and_sigint() {
        assert_eq!(
            classify_signal_number(Signal::SIGTERM as u32),
            Ok(LocalLinuxTerminationSignal::SigTerm)
        );
        assert_eq!(
            classify_signal_number(Signal::SIGINT as u32),
            Ok(LocalLinuxTerminationSignal::SigInt)
        );
        assert_eq!(
            classify_signal_number(Signal::SIGHUP as u32),
            Err(LocalLinuxTerminationSignalReadError::UnexpectedSignal)
        );
        assert_eq!(
            classify_signal_number(u32::MAX),
            Err(LocalLinuxTerminationSignalReadError::UnexpectedSignal)
        );
    }

    #[test]
    fn real_mask_inheritance_signalfd_delivery_and_restore_are_subprocess_isolated() {
        if std::env::var_os(SUBPROCESS_ENV).is_some() {
            run_signal_source_subprocess();
            return;
        }

        let executable = std::env::current_exe().expect("current test executable resolves");
        let output = Command::new(executable)
            .arg("--exact")
            .arg(
                "linux_identity::termination_signal::tests::real_mask_inheritance_signalfd_delivery_and_restore_are_subprocess_isolated",
            )
            .arg("--nocapture")
            .env(SUBPROCESS_ENV, "1")
            .output()
            .expect("isolated Phase 098 subprocess starts");

        assert!(
            output.status.success(),
            "isolated Phase 098 signal-source subprocess failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_signal_source_subprocess() {
        let original_mask = SigSet::thread_get_mask().expect("original thread mask reads");
        let source = LocalLinuxTerminationSignalSource::create()
            .expect("safe Phase 098 signal source creates");

        let blocked_mask = SigSet::thread_get_mask().expect("blocked thread mask reads");
        assert!(blocked_mask.contains(Signal::SIGTERM));
        assert!(blocked_mask.contains(Signal::SIGINT));

        let inherited_mask =
            thread::spawn(|| SigSet::thread_get_mask().expect("child thread inherited mask reads"))
                .join()
                .expect("mask-observer child thread joins");
        assert!(inherited_mask.contains(Signal::SIGTERM));
        assert!(inherited_mask.contains(Signal::SIGINT));

        raise(Signal::SIGTERM).expect("SIGTERM posts to the current isolated test thread");
        wait_until_signal_ready(&source);
        assert_eq!(
            source.read_signal(),
            Ok(LocalLinuxTerminationSignalRead::Signal(
                LocalLinuxTerminationSignal::SigTerm
            ))
        );

        raise(Signal::SIGINT).expect("SIGINT posts to the current isolated test thread");
        wait_until_signal_ready(&source);
        assert_eq!(
            source.read_signal(),
            Ok(LocalLinuxTerminationSignalRead::Signal(
                LocalLinuxTerminationSignal::SigInt
            ))
        );

        assert_eq!(
            source.restore(),
            LocalLinuxTerminationSignalMaskRestore::Restored
        );
        let restored_mask = SigSet::thread_get_mask().expect("restored thread mask reads");
        assert_eq!(restored_mask, original_mask);

        {
            let source = LocalLinuxTerminationSignalSource::create()
                .expect("second source creates for Drop restoration proof");
            assert!(
                SigSet::thread_get_mask()
                    .expect("second blocked mask reads")
                    .contains(Signal::SIGTERM)
            );
            drop(source);
        }
        assert_eq!(
            SigSet::thread_get_mask().expect("Drop-restored thread mask reads"),
            original_mask
        );
    }

    fn wait_until_signal_ready(source: &LocalLinuxTerminationSignalSource) {
        let mut descriptors = [PollFd::new(source, PollFlags::IN)];
        let ready = poll(&mut descriptors, None).expect("SignalFd poll succeeds");
        assert_eq!(ready, 1);
        assert_eq!(descriptors[0].revents(), PollFlags::IN);
    }
}
