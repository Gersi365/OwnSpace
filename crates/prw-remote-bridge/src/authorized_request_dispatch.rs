//! Bridge-owned dispatch and response framing for one already-authorized capability request.
//!
//! C03e-W selects this split so future shared-current authorization can release its authority guard
//! before dispatcher side effects and response I/O. This module owns no authorization rule, task,
//! retry, network listener or Agent runtime activation.

use prw_remote_transport::{ControlFrame, ControlMessageKind, MAX_CONTROL_PAYLOAD_BYTES};

use crate::{AuthorizedCapabilityRequest, CapabilityDispatcher, RemoteBridgeError};

/// Dispatches exactly one already-authorized request and constructs its bounded response frame.
///
/// # Errors
///
/// Preserves the existing bridge failure classes for dispatcher failure, oversized dispatcher
/// output and response-frame construction failure. No authorization, retry or negative response is
/// performed here.
pub fn dispatch_authorized_request<D: CapabilityDispatcher>(
    authorized: &AuthorizedCapabilityRequest,
    dispatcher: &mut D,
) -> Result<ControlFrame, RemoteBridgeError> {
    let response = dispatcher
        .dispatch(authorized)
        .map_err(|_| RemoteBridgeError::DispatchFailed)?;
    if response.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(RemoteBridgeError::DispatchResponseTooLarge);
    }
    ControlFrame::new(
        ControlMessageKind::Response,
        authorized.request_id(),
        response,
    )
    .map_err(|_| RemoteBridgeError::ResponseFrameRejected)
}
