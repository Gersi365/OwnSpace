//! Bounded provider-neutral local Agent command contracts.
//!
//! Phase 008 introduces only read-only command identifiers and correlated
//! response metadata. Later phases add pure request/response byte codecs and
//! typed response bodies without activating runtime dispatch.

#[allow(
    dead_code,
    reason = "pre-runtime admission pipeline is intentionally crate-internal"
)]
pub(crate) mod admission;
#[allow(
    dead_code,
    reason = "pre-runtime boundary inbound guard is intentionally crate-internal"
)]
pub(crate) mod boundary_inbound_state;
#[allow(
    dead_code,
    reason = "pre-runtime boundary policy processor is intentionally crate-internal"
)]
pub(crate) mod boundary_policy_processor;
#[allow(
    dead_code,
    reason = "pre-runtime boundary request-response transaction is intentionally crate-internal"
)]
pub(crate) mod boundary_request_response_transaction;
pub mod codec;
#[allow(
    dead_code,
    reason = "pre-runtime inbound request state is intentionally crate-internal"
)]
pub(crate) mod inbound_state;
#[allow(
    dead_code,
    reason = "C03e-VU fixed AgentStatus boundary remains dormant before production wiring"
)]
pub(crate) mod management_agent_status_boundary;
#[allow(
    dead_code,
    reason = "C03e-VU fixed AgentStatus runtime remains dormant before production wiring"
)]
pub(crate) mod management_agent_status_runtime;
#[allow(
    dead_code,
    reason = "C02c Agent-owned authority foundation is intentionally not runtime-wired"
)]
pub(crate) mod management_authority;
#[allow(
    dead_code,
    reason = "C03 management-capable boundary transaction is staged before runtime wiring"
)]
pub(crate) mod management_boundary_transaction;
#[allow(
    dead_code,
    reason = "C02a provider-neutral dispatch proof is intentionally not runtime-wired"
)]
pub(crate) mod management_dispatch;
#[allow(
    dead_code,
    reason = "C02c complete typed management execution seam is intentionally not runtime-wired"
)]
pub(crate) mod management_execution;
#[allow(
    dead_code,
    reason = "C02d pure provider backend policy seam is intentionally not runtime-wired"
)]
pub(crate) mod management_provider_backend_policy;
#[allow(
    dead_code,
    reason = "C02c provider lifecycle ownership seam is intentionally not runtime-wired"
)]
pub(crate) mod management_provider_lifecycle;
pub mod management_request;
#[allow(
    dead_code,
    reason = "C02c deterministic management response semantics are intentionally not runtime-wired"
)]
pub(crate) mod management_response;
#[allow(
    dead_code,
    reason = "C02c typed provider dispatch seam is intentionally not response-encoded or runtime-wired"
)]
pub(crate) mod management_typed_provider_dispatch;
#[allow(
    dead_code,
    reason = "pre-runtime policy response pipeline is intentionally crate-internal"
)]
pub(crate) mod policy_response;
pub mod private_dns_codec;
pub mod private_dns_response;
pub mod private_dns_snapshot;
pub mod request_frame;
#[allow(
    dead_code,
    reason = "pre-runtime request processor is intentionally crate-internal"
)]
pub(crate) mod request_processor;
#[allow(
    dead_code,
    reason = "pre-runtime request-response transaction is intentionally crate-internal"
)]
pub(crate) mod request_response_transaction;
pub mod request_tracker;
#[allow(
    dead_code,
    reason = "pre-runtime successful responder is intentionally crate-internal"
)]
pub(crate) mod responder;
pub mod response_codec;
#[allow(
    dead_code,
    reason = "pre-runtime terminal response writer is intentionally crate-internal"
)]
pub(crate) mod response_writer;
#[allow(
    dead_code,
    reason = "pre-runtime bounded server connection loop is intentionally crate-internal"
)]
pub(crate) mod server_connection_loop;
#[allow(
    dead_code,
    reason = "pre-runtime server connection state is intentionally crate-internal"
)]
pub(crate) mod server_connection_state;
pub mod status_snapshot;
pub mod terminal_completion;
pub mod terminal_response;

use crate::LocalIpcRequestId;

/// Read-only command identifiers admitted by the Phase 008 local baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalAgentCommand {
    /// Read the Agent's local runtime status snapshot.
    GetAgentStatus,
    /// Read the effective private-DNS configuration snapshot.
    GetPrivateDnsConfig,
}

impl LocalAgentCommand {
    /// Returns the stable Phase 008 command identifier.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::GetAgentStatus => 1,
            Self::GetPrivateDnsConfig => 2,
        }
    }

    /// Returns the command represented by a stable identifier.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::GetAgentStatus),
            2 => Some(Self::GetPrivateDnsConfig),
            _ => None,
        }
    }
}

/// Terminal status associated with one local Agent response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalAgentResponseStatus {
    /// Request completed successfully.
    Ok,
    /// Request metadata or future payload is malformed or invalid.
    InvalidRequest,
    /// Authenticated local peer is not authorized for the requested operation.
    Unauthorized,
    /// Command identifier is not supported by the active Agent protocol.
    UnsupportedCommand,
    /// Request conflicts with the Agent's current state.
    Conflict,
    /// Agent failed internally without exposing implementation-sensitive detail.
    InternalError,
}

impl LocalAgentResponseStatus {
    /// Returns the stable Phase 008 response-status identifier.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 0,
            Self::InvalidRequest => 1,
            Self::Unauthorized => 2,
            Self::UnsupportedCommand => 3,
            Self::Conflict => 4,
            Self::InternalError => 5,
        }
    }

    /// Returns the status represented by a stable identifier.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::Unauthorized),
            3 => Some(Self::UnsupportedCommand),
            4 => Some(Self::Conflict),
            5 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Returns whether the status represents success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Typed metadata for one local Agent request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAgentRequestEnvelope {
    request_id: LocalIpcRequestId,
    command: LocalAgentCommand,
}

impl LocalAgentRequestEnvelope {
    /// Creates a typed request envelope.
    #[must_use]
    pub const fn new(request_id: LocalIpcRequestId, command: LocalAgentCommand) -> Self {
        Self {
            request_id,
            command,
        }
    }

    /// Returns the frame correlation identifier.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the requested local Agent command.
    #[must_use]
    pub const fn command(self) -> LocalAgentCommand {
        self.command
    }
}

/// Typed metadata for one terminal local Agent response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAgentResponseEnvelope {
    request_id: LocalIpcRequestId,
    status: LocalAgentResponseStatus,
}

impl LocalAgentResponseEnvelope {
    /// Creates a response envelope correlated to a request identifier.
    #[must_use]
    pub const fn new(request_id: LocalIpcRequestId, status: LocalAgentResponseStatus) -> Self {
        Self { request_id, status }
    }

    /// Returns the correlated request identifier.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request_id
    }

    /// Returns the terminal response status.
    #[must_use]
    pub const fn status(self) -> LocalAgentResponseStatus {
        self.status
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalAgentCommand, LocalAgentRequestEnvelope, LocalAgentResponseEnvelope,
        LocalAgentResponseStatus,
    };
    use crate::LocalIpcRequestId;

    #[test]
    fn read_only_command_codes_are_stable() {
        assert_eq!(LocalAgentCommand::GetAgentStatus.code(), 1);
        assert_eq!(LocalAgentCommand::GetPrivateDnsConfig.code(), 2);
        assert_eq!(
            LocalAgentCommand::from_code(1),
            Some(LocalAgentCommand::GetAgentStatus)
        );
        assert_eq!(
            LocalAgentCommand::from_code(2),
            Some(LocalAgentCommand::GetPrivateDnsConfig)
        );
        assert_eq!(LocalAgentCommand::from_code(3), None);
    }

    #[test]
    fn response_status_codes_are_stable() {
        assert_eq!(LocalAgentResponseStatus::Ok.code(), 0);
        assert_eq!(LocalAgentResponseStatus::InvalidRequest.code(), 1);
        assert_eq!(LocalAgentResponseStatus::Unauthorized.code(), 2);
        assert_eq!(LocalAgentResponseStatus::UnsupportedCommand.code(), 3);
        assert_eq!(LocalAgentResponseStatus::Conflict.code(), 4);
        assert_eq!(LocalAgentResponseStatus::InternalError.code(), 5);
        assert_eq!(
            LocalAgentResponseStatus::from_code(0),
            Some(LocalAgentResponseStatus::Ok)
        );
        assert_eq!(
            LocalAgentResponseStatus::from_code(5),
            Some(LocalAgentResponseStatus::InternalError)
        );
        assert_eq!(LocalAgentResponseStatus::from_code(6), None);
        assert!(LocalAgentResponseStatus::Ok.is_success());
        assert!(!LocalAgentResponseStatus::InvalidRequest.is_success());
    }

    #[test]
    fn response_preserves_request_correlation() {
        let request_id = LocalIpcRequestId::new(42).expect("non-zero request id");
        let request = LocalAgentRequestEnvelope::new(request_id, LocalAgentCommand::GetAgentStatus);
        let status = LocalAgentResponseStatus::Ok;
        let response = LocalAgentResponseEnvelope::new(request.request_id(), status);

        assert_eq!(request.command(), LocalAgentCommand::GetAgentStatus);
        assert_eq!(response.request_id(), request.request_id());
        assert_eq!(response.status(), LocalAgentResponseStatus::Ok);
    }
}
