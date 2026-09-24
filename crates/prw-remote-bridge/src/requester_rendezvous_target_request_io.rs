//! Bridge-owned one-frame requester/rendezvous target-request I/O adapter over PRWM.
//!
//! C03e-EQ materializes only the C03e-EP-selected requester-specific receive boundary on one
//! already-accepted bounded control stream. Lower stream I/O remains bridge-owned and strict PRWZ
//! semantics remain delegated to the existing pure target-request codec. This adapter performs no
//! logical-session authentication, requester/target authorization, registry or policy evaluation,
//! provider mutation, response write, retry, loop, peer close, networking activation, or deployment.

use std::fmt;

use prw_remote_transport::runtime::{MeshControlStream, MeshQuicRuntimeError};

use crate::requester_rendezvous_target_request_wire::{
    RequesterRendezvousTargetWireError, RequesterRendezvousTargetWireRequest,
    decode_requester_rendezvous_target_request_frame,
};

/// Failure while receiving exactly one requester/rendezvous target request from one existing stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousTargetRequestIoError {
    /// Existing bounded PRWM stream/frame receive failed.
    Runtime(MeshQuicRuntimeError),
    /// The received PRWM frame failed the existing strict requester/rendezvous PRWZ codec.
    Wire(RequesterRendezvousTargetWireError),
}

impl fmt::Display for RequesterRendezvousTargetRequestIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime(_) => "requester rendezvous target-request stream receive failed",
            Self::Wire(_) => "requester rendezvous target-request wire decode failed",
        })
    }
}

impl std::error::Error for RequesterRendezvousTargetRequestIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Wire(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for RequesterRendezvousTargetRequestIoError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RequesterRendezvousTargetWireError> for RequesterRendezvousTargetRequestIoError {
    fn from(error: RequesterRendezvousTargetWireError) -> Self {
        Self::Wire(error)
    }
}

/// Receives and strictly decodes exactly one requester/rendezvous target request.
///
/// The supplied stream must already have been accepted by the existing authenticated peer owner.
/// This function performs one bounded PRWM frame receive, then delegates exactly once to the pure
/// requester/rendezvous target-request codec. The returned value preserves outer `request_id` only
/// as correlation and carries only the typed logical target `DeviceId`; requester/session identity
/// is not read from the wire.
///
/// # Errors
///
/// Preserves bounded stream receive failure as [`RequesterRendezvousTargetRequestIoError::Runtime`]
/// and strict PRWZ/PRWM semantic decode failure as
/// [`RequesterRendezvousTargetRequestIoError::Wire`]. No retry, fallback decode, response write, or
/// peer close is performed.
pub async fn receive_requester_rendezvous_target_request(
    stream: &mut MeshControlStream,
) -> Result<RequesterRendezvousTargetWireRequest, RequesterRendezvousTargetRequestIoError> {
    let frame = stream.receive_frame().await?;
    decode_requester_rendezvous_target_request_frame(&frame).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::runtime::MeshQuicRuntimeError;

    use super::{
        RequesterRendezvousTargetRequestIoError, receive_requester_rendezvous_target_request,
    };
    use crate::requester_rendezvous_target_request_wire::RequesterRendezvousTargetWireError;

    #[test]
    fn adapter_surface_exposes_only_one_request_receive_operation() {
        let _ = receive_requester_rendezvous_target_request;
    }

    #[test]
    fn runtime_failure_classification_is_preserved() {
        let error = MeshQuicRuntimeError::ReadFrame;
        assert_eq!(
            RequesterRendezvousTargetRequestIoError::from(error),
            RequesterRendezvousTargetRequestIoError::Runtime(error)
        );
    }

    #[test]
    fn wire_failure_classification_is_preserved() {
        let error = RequesterRendezvousTargetWireError::InvalidPayload;
        assert_eq!(
            RequesterRendezvousTargetRequestIoError::from(error),
            RequesterRendezvousTargetRequestIoError::Wire(error)
        );
    }
}
