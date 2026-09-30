//! Linux production PTY backend for the bounded local terminal broker.
//!
//! This provider deliberately supports only the existing `PosixShell` launch profile.
//! It allocates one local pseudoterminal, starts the fixed `/bin/sh -i` process as the
//! Agent's existing effective UID, and exposes only the already-bounded terminal backend
//! operations. Request bytes cannot select an executable, arguments, environment, user,
//! filesystem root, network target, or privilege boundary.

#![cfg(target_os = "linux")]

use std::cmp;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use prw_terminal::{TerminalBackend, TerminalError, TerminalGeometry, TerminalProfile};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::{dup, ioctl_fionread, read, write};
use rustix::process::{Pid, Signal, kill_process_group};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

const POSIX_SHELL_PATH: &str = "/bin/sh";

/// Production Linux PTY backend selected by the local Agent runtime.
#[derive(Debug, Default)]
pub(super) struct LocalPosixPtyTerminalBackend;

/// One provider-owned PTY and shell process group.
#[derive(Debug)]
pub(super) struct LocalPosixPtyTerminalHandle {
    controller: std::os::fd::OwnedFd,
    child: Child,
}

impl LocalPosixPtyTerminalBackend {
    #[must_use]
    pub(super) const fn new() -> Self {
        Self
    }
}

impl TerminalBackend for LocalPosixPtyTerminalBackend {
    type Handle = LocalPosixPtyTerminalHandle;

    fn open(
        &mut self,
        profile: TerminalProfile,
        geometry: TerminalGeometry,
    ) -> Result<Self::Handle, TerminalError> {
        if profile != TerminalProfile::PosixShell {
            return Err(TerminalError::Backend);
        }

        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
            .map_err(|_| TerminalError::Backend)?;
        grantpt(&controller).map_err(|_| TerminalError::Backend)?;
        unlockpt(&controller).map_err(|_| TerminalError::Backend)?;
        let slave_name = ptsname(&controller, Vec::new()).map_err(|_| TerminalError::Backend)?;
        let slave = open(
            slave_name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| TerminalError::Backend)?;
        tcsetwinsize(&slave, winsize(geometry)).map_err(|_| TerminalError::Backend)?;

        let stdin = dup(&slave).map_err(|_| TerminalError::Backend)?;
        let stdout = dup(&slave).map_err(|_| TerminalError::Backend)?;
        let stderr = slave;

        let mut command = Command::new(POSIX_SHELL_PATH);
        command
            .arg("-i")
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        command.process_group(0);
        let child = command.spawn().map_err(|_| TerminalError::Backend)?;

        Ok(LocalPosixPtyTerminalHandle { controller, child })
    }

    fn write_input(
        &mut self,
        handle: &mut Self::Handle,
        mut bytes: &[u8],
    ) -> Result<(), TerminalError> {
        while !bytes.is_empty() {
            let written = write(&handle.controller, bytes).map_err(|_| TerminalError::Backend)?;
            if written == 0 {
                return Err(TerminalError::Backend);
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    fn resize(
        &mut self,
        handle: &mut Self::Handle,
        geometry: TerminalGeometry,
    ) -> Result<(), TerminalError> {
        tcsetwinsize(&handle.controller, winsize(geometry)).map_err(|_| TerminalError::Backend)
    }

    fn read_output(
        &mut self,
        handle: &mut Self::Handle,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, TerminalError> {
        let available = ioctl_fionread(&handle.controller).map_err(|_| TerminalError::Backend)?;
        if available == 0 {
            return Ok(Vec::new());
        }
        let available = usize::try_from(available).unwrap_or(usize::MAX);
        let mut output = vec![0_u8; cmp::min(maximum_bytes, available)];
        let read_len = read(&handle.controller, &mut output).map_err(|_| TerminalError::Backend)?;
        output.truncate(read_len);
        Ok(output)
    }

    fn close(&mut self, handle: &mut Self::Handle) -> Result<(), TerminalError> {
        let raw_pid = i32::try_from(handle.child.id()).map_err(|_| TerminalError::Backend)?;
        let pid = Pid::from_raw(raw_pid).ok_or(TerminalError::Backend)?;
        match kill_process_group(pid, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(_) => return Err(TerminalError::Backend),
        }
        handle.child.wait().map_err(|_| TerminalError::Backend)?;
        Ok(())
    }
}

const fn winsize(geometry: TerminalGeometry) -> Winsize {
    Winsize {
        ws_row: geometry.rows(),
        ws_col: geometry.columns(),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use prw_terminal::{TerminalBackend, TerminalGeometry, TerminalProfile};
    use rustix::termios::tcgetwinsize;

    use super::LocalPosixPtyTerminalBackend;

    fn geometry(columns: u16, rows: u16) -> TerminalGeometry {
        TerminalGeometry::new(columns, rows).expect("test geometry is bounded")
    }

    #[test]
    fn production_backend_rejects_non_posix_profile() {
        let mut backend = LocalPosixPtyTerminalBackend::new();
        assert!(
            backend
                .open(TerminalProfile::BashShell, geometry(80, 24))
                .is_err()
        );
    }

    #[test]
    fn production_backend_opens_io_resizes_and_closes_one_posix_shell() {
        let mut backend = LocalPosixPtyTerminalBackend::new();
        let mut handle = backend
            .open(TerminalProfile::PosixShell, geometry(80, 24))
            .expect("fixed POSIX shell opens");

        backend
            .resize(&mut handle, geometry(100, 35))
            .expect("PTY resize succeeds");
        let observed = tcgetwinsize(&handle.controller).expect("PTY geometry reads");
        assert_eq!(observed.ws_col, 100);
        assert_eq!(observed.ws_row, 35);

        backend
            .write_input(&mut handle, b"printf 'OWNSPACE_PTY_OK\\n'\n")
            .expect("bounded shell input writes");
        let mut output = Vec::new();
        for _ in 0..100 {
            output.extend(
                backend
                    .read_output(&mut handle, 4096)
                    .expect("bounded PTY output reads"),
            );
            if output
                .windows(b"OWNSPACE_PTY_OK".len())
                .any(|window| window == b"OWNSPACE_PTY_OK")
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            output
                .windows(b"OWNSPACE_PTY_OK".len())
                .any(|window| window == b"OWNSPACE_PTY_OK")
        );

        backend
            .close(&mut handle)
            .expect("PTY process group closes");
    }
}
