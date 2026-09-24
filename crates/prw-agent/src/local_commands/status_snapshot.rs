//! Typed read-only Agent status snapshot.
//!
//! Phase 017 defines the minimal body model for a successful
//! `GetAgentStatus` response. Phase 018 adds its fixed-width byte codec, Phase
//! 019 composes the command payload, and Phase 023 composes a complete
//! validated in-memory response frame. Runtime command dispatch and socket I/O
//! remain out of scope.

pub mod codec;
pub mod response_frame;
pub mod response_payload;

use crate::LocalIpcProtocolVersion;

/// Coarse runtime lifecycle state exposed by the local status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalAgentRuntimeState {
    /// Agent process is initializing and is not yet ready for normal requests.
    Starting,
    /// Agent is ready for its normal currently enabled local request surface.
    Ready,
    /// Agent is running but one or more non-fatal capabilities are degraded.
    Degraded,
    /// Agent is performing orderly shutdown and should not accept new work.
    Stopping,
}

impl LocalAgentRuntimeState {
    /// Returns the stable Phase 017 runtime-state identifier.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Starting => 1,
            Self::Ready => 2,
            Self::Degraded => 3,
            Self::Stopping => 4,
        }
    }

    /// Returns the runtime state represented by a stable identifier.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Starting),
            2 => Some(Self::Ready),
            3 => Some(Self::Degraded),
            4 => Some(Self::Stopping),
            _ => None,
        }
    }

    /// Returns whether the Agent reports normal request readiness.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Minimal typed snapshot returned by a future successful `GetAgentStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAgentStatusSnapshot {
    runtime_state: LocalAgentRuntimeState,
    protocol_version: LocalIpcProtocolVersion,
}

impl LocalAgentStatusSnapshot {
    /// Creates a status snapshot using the current local IPC protocol version.
    #[must_use]
    pub const fn current(runtime_state: LocalAgentRuntimeState) -> Self {
        Self {
            runtime_state,
            protocol_version: LocalIpcProtocolVersion::current(),
        }
    }

    /// Returns the reported Agent runtime state.
    #[must_use]
    pub const fn runtime_state(self) -> LocalAgentRuntimeState {
        self.runtime_state
    }

    /// Returns the local IPC protocol version spoken by the Agent snapshot.
    #[must_use]
    pub const fn protocol_version(self) -> LocalIpcProtocolVersion {
        self.protocol_version
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalAgentRuntimeState, LocalAgentStatusSnapshot};
    use crate::LocalIpcProtocolVersion;

    #[test]
    fn runtime_state_codes_are_stable_and_invertible() {
        for (state, code) in [
            (LocalAgentRuntimeState::Starting, 1),
            (LocalAgentRuntimeState::Ready, 2),
            (LocalAgentRuntimeState::Degraded, 3),
            (LocalAgentRuntimeState::Stopping, 4),
        ] {
            assert_eq!(state.code(), code);
            assert_eq!(LocalAgentRuntimeState::from_code(code), Some(state));
        }
        assert_eq!(LocalAgentRuntimeState::from_code(0), None);
        assert_eq!(LocalAgentRuntimeState::from_code(5), None);
    }

    #[test]
    fn only_ready_state_reports_normal_readiness() {
        assert!(!LocalAgentRuntimeState::Starting.is_ready());
        assert!(LocalAgentRuntimeState::Ready.is_ready());
        assert!(!LocalAgentRuntimeState::Degraded.is_ready());
        assert!(!LocalAgentRuntimeState::Stopping.is_ready());
    }

    #[test]
    fn snapshot_uses_current_protocol_version() {
        let snapshot = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);

        assert_eq!(snapshot.runtime_state(), LocalAgentRuntimeState::Ready);
        assert_eq!(
            snapshot.protocol_version(),
            LocalIpcProtocolVersion::current()
        );
    }
}
