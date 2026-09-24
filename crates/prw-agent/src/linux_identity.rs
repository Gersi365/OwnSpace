//! Non-activating Linux local platform boundary.
//!
//! Phase 057 reads only the Agent effective UID and Linux kernel `SO_PEERCRED`
//! from an already-existing socket file descriptor. Phase 058 adds same-UID
//! authorization, Phase 059 adds typed authenticated stream ownership, Phase 060
//! composes authenticated application-session processing, Phase 062 adds
//! read-only XDG runtime-root validation, Phase 067 adds a bound validated Agent
//! socket, Phase 068 adds an explicit listening-state transition, Phase 070 adds
//! a nonblocking accept-ready state plus one-shot authenticated accept, Phase 071
//! adds pure composition into Phase 060 authenticated session state, Phase 073
//! adds absolute-deadline blocking stream I/O primitives, Phase 075 adds bounded
//! thread-safe worker-capacity accounting, Phase 076 adds a finite session worker
//! body, Phase 078 adds one fallible scoped OS-thread spawn adapter, Phase 079
//! adds explicit joined-worker completion classification, Phase 080 retains/reaps
//! scoped worker handles, Phase 082 pairs them with authenticated-stream
//! cancellation authority, Phase 084 composes one capacity-gated scheduling
//! transaction, Phase 086 adds a finite shutdown-gated scheduling cycle, Phase
//! 089 adds an isolated coalescing Linux runtime wake transport, Phase 090 adds
//! a runtime-specific worker completion wake wrapper, Phase 091 adds one
//! capacity-aware blocking readiness wait step, Phase 092 adds finite
//! readiness-plus-completion-wake scheduling orchestration, and Phase 095 adds
//! immutable production-runtime configuration plus bounded evidence/disposition
//! types, Phase 096 adds scoped lifecycle resource assembly with explicit
//! listener rollback/cleanup, and Phase 097 adds the callable programmatic-
//! shutdown long-running runtime loop. Phase 098 adds a safe thread-affine
//! SIGTERM/SIGINT `SignalFd` source plus one-step signal-aware readiness with
//! termination > runtime-wake > listener precedence while preserving
//! `unsafe_code = forbid`. Phase 098 also composes these primitives into a
//! callable signal-aware long-running runtime with mask restoration after
//! listener cleanup. The Agent bootstrap remains inactive; `main.rs` and systemd
//! still do not start this runtime.

#[allow(
    dead_code,
    reason = "pre-runtime Linux accept-ready adapter is intentionally crate-internal"
)]
#[path = "linux_agent_accept_ready.rs"]
pub mod accept_ready;
#[allow(
    dead_code,
    reason = "pre-runtime authenticated Linux connection wrapper is intentionally crate-internal"
)]
#[path = "linux_authenticated_connection.rs"]
pub mod authenticated_connection;
#[allow(
    dead_code,
    reason = "pre-runtime authenticated Linux application session is intentionally crate-internal"
)]
#[path = "linux_authenticated_session.rs"]
pub mod authenticated_session;
#[allow(
    dead_code,
    reason = "pre-runtime Linux authenticated accept-to-session bridge is intentionally crate-internal"
)]
#[path = "linux_agent_session_bridge.rs"]
pub mod authenticated_session_bridge;
#[allow(
    dead_code,
    reason = "pre-listen bound Linux Agent socket is intentionally crate-internal"
)]
#[path = "linux_agent_bound_socket.rs"]
pub mod bound_socket;
#[allow(
    dead_code,
    reason = "pre-runtime bounded Linux scheduling cycle is intentionally crate-internal"
)]
#[path = "linux_bounded_scheduler_cycle.rs"]
pub mod bounded_scheduler_cycle;
#[allow(
    dead_code,
    reason = "pre-runtime Linux absolute-deadline I/O adapter is intentionally crate-internal"
)]
#[path = "linux_deadline_io.rs"]
pub mod deadline_io;
#[allow(
    dead_code,
    reason = "pre-runtime listening Linux Agent socket is intentionally crate-internal"
)]
#[path = "linux_agent_listening_socket.rs"]
pub mod listening_socket;
#[allow(
    dead_code,
    reason = "pre-runtime one-shot Linux worker scheduler is intentionally crate-internal"
)]
#[path = "linux_one_shot_scheduler.rs"]
pub mod one_shot_scheduler;
#[allow(
    dead_code,
    reason = "pre-runtime Linux same-UID authorization is intentionally crate-internal"
)]
#[path = "linux_peer_auth.rs"]
pub mod peer_auth;
#[allow(
    dead_code,
    reason = "pre-bootstrap Linux production lifecycle assembly is intentionally crate-internal"
)]
#[path = "linux_production_lifecycle.rs"]
pub mod production_lifecycle;
#[allow(
    dead_code,
    reason = "pre-bootstrap Linux production runtime loop is intentionally crate-internal"
)]
#[path = "linux_production_runtime_loop.rs"]
pub mod production_runtime_loop;
#[allow(
    dead_code,
    reason = "pre-bootstrap Linux production runtime types are intentionally crate-internal"
)]
#[path = "linux_production_runtime_types.rs"]
pub mod production_runtime_types;
#[allow(
    dead_code,
    reason = "pre-runtime finite Linux readiness/scheduling orchestration is intentionally crate-internal"
)]
#[path = "linux_runtime_orchestration.rs"]
pub mod runtime_orchestration;
#[allow(
    dead_code,
    reason = "pre-runtime one-step Linux readiness wait is intentionally crate-internal"
)]
#[path = "linux_runtime_readiness.rs"]
pub mod runtime_readiness;
#[allow(
    dead_code,
    reason = "pre-runtime Linux runtime wake transport is intentionally crate-internal"
)]
#[path = "linux_runtime_wake.rs"]
pub mod runtime_wake;
#[allow(
    dead_code,
    reason = "pre-runtime finite Linux session worker body is intentionally crate-internal"
)]
#[path = "linux_session_worker.rs"]
pub mod session_worker;
#[allow(
    dead_code,
    reason = "pre-runtime scoped Linux worker spawn adapter is intentionally crate-internal"
)]
#[path = "linux_session_worker_thread.rs"]
pub mod session_worker_thread;
#[allow(
    dead_code,
    reason = "pre-bootstrap signal-aware Linux readiness is intentionally crate-internal"
)]
#[path = "linux_signal_aware_readiness.rs"]
pub mod signal_aware_readiness;
#[allow(
    dead_code,
    reason = "pre-bootstrap signal-aware Linux runtime is intentionally crate-internal"
)]
#[path = "linux_signal_aware_runtime.rs"]
pub mod signal_aware_runtime;
#[allow(
    dead_code,
    reason = "pre-bootstrap safe Linux termination signal source is intentionally crate-internal"
)]
#[path = "linux_termination_signal.rs"]
pub mod termination_signal;
#[allow(
    dead_code,
    reason = "pre-runtime authenticated worker cancellation is intentionally crate-internal"
)]
#[path = "linux_worker_cancellation.rs"]
pub mod worker_cancellation;
#[allow(
    dead_code,
    reason = "pre-runtime bounded Linux worker capacity is intentionally crate-internal"
)]
#[path = "linux_worker_capacity.rs"]
pub mod worker_capacity;
#[allow(
    dead_code,
    reason = "pre-runtime scoped worker completion classifier is intentionally crate-internal"
)]
#[path = "linux_worker_completion.rs"]
pub mod worker_completion;
#[allow(
    dead_code,
    reason = "pre-runtime scoped worker registry is intentionally crate-internal"
)]
#[path = "linux_worker_registry.rs"]
pub mod worker_registry;
#[allow(
    dead_code,
    reason = "pre-runtime Linux XDG runtime-root validation is intentionally crate-internal"
)]
#[path = "linux_xdg_runtime_root.rs"]
pub mod xdg_runtime_root;

use rustix::fd::AsFd;
use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;

/// PRW-local copy of Linux kernel credentials for one connected local peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLinuxPeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

impl LocalLinuxPeerCredentials {
    /// Returns the kernel-reported peer process identifier.
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }

    /// Returns the kernel-reported peer user identifier.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the kernel-reported peer group identifier.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// Returns the effective UID under which the Agent is executing.
#[must_use]
pub fn effective_agent_uid() -> u32 {
    geteuid().as_raw()
}

/// Reads Linux kernel `SO_PEERCRED` from an already-existing socket descriptor.
///
/// This function does not read application data from the descriptor and does not
/// make an authorization decision.
///
/// # Errors
///
/// Returns [`LocalLinuxIdentityError::PeerCredentialLookup`] when Linux rejects
/// the `SO_PEERCRED` lookup for the supplied descriptor.
pub fn peer_credentials<Fd: AsFd>(
    fd: Fd,
) -> Result<LocalLinuxPeerCredentials, LocalLinuxIdentityError> {
    let credentials =
        socket_peercred(fd).map_err(|_| LocalLinuxIdentityError::PeerCredentialLookup)?;

    Ok(LocalLinuxPeerCredentials {
        pid: credentials.pid.as_raw_pid(),
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    })
}

/// Bounded Linux identity-adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxIdentityError {
    /// Kernel peer-credential lookup failed for the supplied descriptor.
    PeerCredentialLookup,
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use rustix::process::getegid;

    use super::{effective_agent_uid, peer_credentials};

    #[test]
    fn anonymous_unix_pair_reports_current_process_identity() {
        let (left, right) = UnixStream::pair().expect("anonymous Unix pair creates");

        let left_peer = peer_credentials(&left).expect("left peer credentials read");
        let right_peer = peer_credentials(&right).expect("right peer credentials read");
        let process_pid = i32::try_from(std::process::id()).expect("Linux process id fits i32");
        let effective_uid = effective_agent_uid();

        for credentials in [left_peer, right_peer] {
            assert_eq!(credentials.pid(), process_pid);
            assert_eq!(credentials.uid(), effective_uid);
            assert_eq!(credentials.gid(), getegid().as_raw());
        }
    }
}
