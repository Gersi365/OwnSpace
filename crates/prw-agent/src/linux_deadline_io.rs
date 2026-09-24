//! Absolute-deadline blocking Unix stream I/O adapter.
//!
//! Phase 073 preserves the Phase 070 blocking accepted-stream model while
//! ensuring partial I/O cannot reset the caller-supplied wall-clock budget.
//! Phase 074 adds a deferred writer whose absolute deadline begins only on the
//! first non-empty response write.

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Strictly positive wall-clock budget for one local Linux I/O phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLinuxIoBudget(Duration);

impl LocalLinuxIoBudget {
    /// Creates a strictly positive I/O budget.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxIoBudgetError::ZeroDuration`] when `duration` is zero.
    pub const fn try_new(duration: Duration) -> Result<Self, LocalLinuxIoBudgetError> {
        if duration.is_zero() {
            return Err(LocalLinuxIoBudgetError::ZeroDuration);
        }
        Ok(Self(duration))
    }

    /// Returns the configured relative budget.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Invalid caller-supplied local Linux I/O budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxIoBudgetError {
    /// Zero duration would not provide a usable blocking-I/O budget.
    ZeroDuration,
}

/// Failure to construct an absolute deadline from a validated relative budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxDeadlineStartError {
    /// The monotonic clock cannot represent `now + budget`.
    DeadlineOverflow,
}

/// Blocking reader whose complete lifetime shares one immutable absolute deadline.
#[derive(Debug)]
pub struct LocalLinuxDeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> LocalLinuxDeadlineReader<'a> {
    /// Starts one absolute read deadline from the current monotonic instant.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxDeadlineStartError::DeadlineOverflow`] when the
    /// monotonic clock cannot represent the requested deadline.
    pub fn start(
        stream: &'a UnixStream,
        budget: LocalLinuxIoBudget,
    ) -> Result<Self, LocalLinuxDeadlineStartError> {
        let deadline = Instant::now()
            .checked_add(budget.duration())
            .ok_or(LocalLinuxDeadlineStartError::DeadlineOverflow)?;
        Ok(Self { stream, deadline })
    }

    #[cfg(test)]
    const fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Read for LocalLinuxDeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let remaining = remaining_until(self.deadline)?;
        self.stream.set_read_timeout(Some(remaining))?;

        let mut stream = self.stream;
        stream.read(buffer).map_err(normalize_timeout_error)
    }
}

/// Blocking writer whose complete lifetime shares one immutable absolute deadline.
#[derive(Debug)]
pub struct LocalLinuxDeadlineWriter<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> LocalLinuxDeadlineWriter<'a> {
    /// Starts one absolute write deadline from the current monotonic instant.
    ///
    /// # Errors
    ///
    /// Returns [`LocalLinuxDeadlineStartError::DeadlineOverflow`] when the
    /// monotonic clock cannot represent the requested deadline.
    pub fn start(
        stream: &'a UnixStream,
        budget: LocalLinuxIoBudget,
    ) -> Result<Self, LocalLinuxDeadlineStartError> {
        let deadline = Instant::now()
            .checked_add(budget.duration())
            .ok_or(LocalLinuxDeadlineStartError::DeadlineOverflow)?;
        Ok(Self { stream, deadline })
    }

    #[cfg(test)]
    const fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Write for LocalLinuxDeadlineWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let remaining = remaining_until(self.deadline)?;
        self.stream.set_write_timeout(Some(remaining))?;

        let mut stream = self.stream;
        stream.write(buffer).map_err(normalize_timeout_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

/// Blocking writer whose deadline starts only when response bytes are first written.
#[derive(Debug)]
pub struct LocalLinuxDeferredDeadlineWriter<'a> {
    stream: &'a UnixStream,
    budget: LocalLinuxIoBudget,
    deadline: Option<Instant>,
}

impl<'a> LocalLinuxDeferredDeadlineWriter<'a> {
    /// Creates a deferred writer without starting its absolute deadline.
    #[must_use]
    pub const fn new(stream: &'a UnixStream, budget: LocalLinuxIoBudget) -> Self {
        Self {
            stream,
            budget,
            deadline: None,
        }
    }

    fn deadline_or_start(&mut self) -> io::Result<Instant> {
        if let Some(deadline) = self.deadline {
            return Ok(deadline);
        }

        let deadline = Instant::now()
            .checked_add(self.budget.duration())
            .ok_or_else(deadline_overflow_io_error)?;
        self.deadline = Some(deadline);
        Ok(deadline)
    }

    #[cfg(test)]
    const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

impl Write for LocalLinuxDeferredDeadlineWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let deadline = self.deadline_or_start()?;
        let remaining = remaining_until(deadline)?;
        self.stream.set_write_timeout(Some(remaining))?;

        let mut stream = self.stream;
        stream.write(buffer).map_err(normalize_timeout_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

fn remaining_until(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(deadline_timeout_error())
    } else {
        Ok(remaining)
    }
}

fn normalize_timeout_error(error: io::Error) -> io::Error {
    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        deadline_timeout_error()
    } else {
        error
    }
}

fn deadline_timeout_error() -> io::Error {
    io::Error::new(
        ErrorKind::TimedOut,
        "PRW local IPC absolute I/O deadline expired",
    )
}

fn deadline_overflow_io_error() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidInput,
        "PRW local IPC absolute I/O deadline is not representable",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::{
        LocalLinuxDeadlineReader, LocalLinuxDeadlineStartError, LocalLinuxDeadlineWriter,
        LocalLinuxDeferredDeadlineWriter, LocalLinuxIoBudget, LocalLinuxIoBudgetError,
    };

    fn budget(milliseconds: u64) -> LocalLinuxIoBudget {
        LocalLinuxIoBudget::try_new(Duration::from_millis(milliseconds))
            .expect("test deadline budget is nonzero")
    }

    #[test]
    fn zero_budget_is_rejected() {
        assert_eq!(
            LocalLinuxIoBudget::try_new(Duration::ZERO),
            Err(LocalLinuxIoBudgetError::ZeroDuration)
        );
    }

    #[test]
    fn unrepresentable_deadline_is_rejected() {
        let (stream, _peer) = UnixStream::pair().expect("anonymous Unix pair creates");
        let huge = LocalLinuxIoBudget::try_new(Duration::MAX).expect("huge budget is nonzero");

        assert_eq!(
            LocalLinuxDeadlineReader::start(&stream, huge).unwrap_err(),
            LocalLinuxDeadlineStartError::DeadlineOverflow
        );
        assert_eq!(
            LocalLinuxDeadlineWriter::start(&stream, huge).unwrap_err(),
            LocalLinuxDeadlineStartError::DeadlineOverflow
        );
    }

    #[test]
    fn read_and_write_round_trip_with_independent_absolute_deadlines() {
        let (left, right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let mut writer =
            LocalLinuxDeadlineWriter::start(&left, budget(500)).expect("write deadline starts");
        let mut reader =
            LocalLinuxDeadlineReader::start(&right, budget(500)).expect("read deadline starts");
        let expected = *b"phase-073";
        let mut received = [0_u8; 9];

        writer
            .write_all(&expected)
            .expect("deadline write succeeds");
        reader
            .read_exact(&mut received)
            .expect("deadline read succeeds");

        assert_eq!(received, expected);
    }

    #[test]
    fn partial_progress_does_not_replace_reader_deadline() {
        let (left, mut right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let mut reader =
            LocalLinuxDeadlineReader::start(&left, budget(500)).expect("read deadline starts");
        let original_deadline = reader.deadline();
        right.write_all(&[7]).expect("peer byte writes");
        let mut byte = [0_u8; 1];

        reader.read_exact(&mut byte).expect("first byte reads");

        assert_eq!(byte, [7]);
        assert_eq!(reader.deadline(), original_deadline);
    }

    #[test]
    fn partial_progress_does_not_replace_writer_deadline() {
        let (left, _right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let mut writer =
            LocalLinuxDeadlineWriter::start(&left, budget(500)).expect("write deadline starts");
        let original_deadline = writer.deadline();

        writer.write_all(&[9]).expect("single byte writes");

        assert_eq!(writer.deadline(), original_deadline);
    }

    #[test]
    fn empty_peer_read_expires_as_timed_out() {
        let (left, _right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let mut reader =
            LocalLinuxDeadlineReader::start(&left, budget(25)).expect("read deadline starts");
        let mut byte = [0_u8; 1];

        let error = reader
            .read_exact(&mut byte)
            .expect_err("idle peer must hit absolute read deadline");

        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn deferred_writer_starts_deadline_only_on_first_nonempty_write() {
        let (left, _right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let mut writer = LocalLinuxDeferredDeadlineWriter::new(&left, budget(500));

        assert_eq!(writer.deadline(), None);
        assert_eq!(writer.write(&[]).expect("empty write succeeds"), 0);
        assert_eq!(writer.deadline(), None);

        writer.write_all(&[1]).expect("first byte writes");
        let started = writer.deadline().expect("first write starts deadline");

        writer.write_all(&[2]).expect("second byte writes");
        assert_eq!(writer.deadline(), Some(started));
    }

    #[test]
    fn deferred_writer_reports_deadline_overflow_only_when_write_begins() {
        let (left, _right) = UnixStream::pair().expect("anonymous Unix pair creates");
        let huge = LocalLinuxIoBudget::try_new(Duration::MAX).expect("huge budget is nonzero");
        let mut writer = LocalLinuxDeferredDeadlineWriter::new(&left, huge);

        assert_eq!(writer.deadline(), None);
        let error = writer
            .write(&[1])
            .expect_err("first write cannot represent huge deadline");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(writer.deadline(), None);
    }
}
