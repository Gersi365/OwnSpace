//! Bridge-owned one-frame capability request/response wire adapter over PRWM.
//!
//! C03e-M selected this narrow post-authentication I/O boundary so Agent code does not need a
//! direct dependency on lower `prw-remote-transport` stream/frame/runtime types. This module only
//! receives or sends one already-bounded PRWM frame on one existing control stream. It does not
//! authenticate a logical session, authorize a capability, evaluate registry/policy state, dispatch
//! a command, retry I/O, accept another stream, close a peer, or publish readiness.

use std::fmt;

use prw_remote_transport::{
    ControlFrame,
    runtime::{MeshControlStream, MeshQuicRuntimeError},
};

/// Failure at the C03e-N bridge-owned capability frame I/O boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityRequestWireError {
    /// Existing bounded QUIC stream I/O failed.
    Runtime(MeshQuicRuntimeError),
}

impl fmt::Display for CapabilityRequestWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(_) => formatter.write_str("remote capability QUIC stream I/O failed"),
        }
    }
}

impl std::error::Error for CapabilityRequestWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for CapabilityRequestWireError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// Receives exactly one complete bounded PRWM frame from one existing capability control stream.
///
/// This adapter intentionally does not validate the frame's application message kind. The existing
/// `CapabilityBridge` remains authoritative for request-kind validation, bounded PRWC decoding,
/// current registry/transport binding, lease validity, policy and dispatcher admission.
///
/// # Errors
///
/// Propagates the existing bounded stream read/PRWM validation failure through
/// [`CapabilityRequestWireError::Runtime`].
pub async fn receive_capability_request_frame(
    stream: &mut MeshControlStream,
) -> Result<ControlFrame, CapabilityRequestWireError> {
    stream.receive_frame().await.map_err(Into::into)
}

/// Sends exactly one already-constructed bounded PRWM response frame on the existing stream.
///
/// The caller must supply the frame returned by the existing capability bridge. This adapter does
/// not construct a second response envelope, alter request correlation, or invent an error-response
/// protocol.
///
/// # Errors
///
/// Propagates the existing bounded stream write/finish failure through
/// [`CapabilityRequestWireError::Runtime`].
pub async fn send_capability_response_frame(
    stream: &mut MeshControlStream,
    frame: &ControlFrame,
) -> Result<(), CapabilityRequestWireError> {
    stream.send_frame(frame).await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::runtime::MeshQuicRuntimeError;

    use super::{
        CapabilityRequestWireError, receive_capability_request_frame,
        send_capability_response_frame,
    };

    #[test]
    fn adapter_surface_exposes_only_one_frame_receive_and_send_operations() {
        let _ = receive_capability_request_frame;
        let _ = send_capability_response_frame;
    }

    #[test]
    fn runtime_error_is_preserved_without_translation() {
        let error = MeshQuicRuntimeError::ReadFrame;
        assert_eq!(
            CapabilityRequestWireError::from(error),
            CapabilityRequestWireError::Runtime(error)
        );
    }
}
