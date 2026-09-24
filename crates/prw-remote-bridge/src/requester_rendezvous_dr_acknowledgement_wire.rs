//! Pure requester/rendezvous DR acknowledgement projection and framing over PRWM.
//!
//! C03e-FD materializes only the C03e-FC-selected requester-specific terminal DR acknowledgement
//! semantics. The exact completed DR `Result<(), E>` is projected without inspecting `E`; accepted
//! means only DR-stage validation, requester-aware authorization and requester registration
//! succeeded. Framing reuses the requester/rendezvous `PRWZ` v1.0 family with distinct terminal
//! operation tags and exact outer PRWM correlation. This module performs no stream read/write,
//! transaction consumption, retry, loop resume, candidate selection, dialing, runtime activation,
//! deployment or merge.

use std::fmt;

use prw_remote_transport::{ControlFrame, ControlMessageKind, RemoteTransportError};

use crate::{
    post_auth_control_stream_ingress::PostAuthRequesterRendezvousTransaction,
    requester_rendezvous_target_request_wire::{
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC,
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR,
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR,
    },
};

/// PRWZ v1.0 terminal DR acknowledgement operation for accepted-for-continuation.
pub const OP_REQUESTER_RENDEZVOUS_DR_ACCEPTED: u16 = 2;
/// PRWZ v1.0 terminal DR acknowledgement operation for generic rejection.
pub const OP_REQUESTER_RENDEZVOUS_DR_REJECTED: u16 = 3;
/// Exact PRWZ terminal DR acknowledgement payload size; acknowledgements carry no result body.
pub const REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES: usize = 12;

/// Coarse requester-visible terminal result of the already-completed DR stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequesterRendezvousDrAcknowledgement {
    /// Validation, requester-aware authorization and requester registration completed successfully.
    Accepted,
    /// The completed DR stage failed; the internal failure class is intentionally not exposed.
    Rejected,
}

impl RequesterRendezvousDrAcknowledgement {
    const fn operation(self) -> u16 {
        match self {
            Self::Accepted => OP_REQUESTER_RENDEZVOUS_DR_ACCEPTED,
            Self::Rejected => OP_REQUESTER_RENDEZVOUS_DR_REJECTED,
        }
    }

    const fn outer_kind(self) -> ControlMessageKind {
        match self {
            Self::Accepted => ControlMessageKind::Response,
            Self::Rejected => ControlMessageKind::Error,
        }
    }
}

/// Failure at the pure requester/rendezvous DR acknowledgement wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousDrAcknowledgementWireError {
    /// Outer PRWM kind did not match the encoded PRWZ acknowledgement operation.
    InvalidOuterKind,
    /// PRWZ acknowledgement metadata, operation, flags, size or trailing data were invalid.
    InvalidPayload,
    /// Existing PRWM frame construction rejected the supplied request correlation or payload.
    Frame(RemoteTransportError),
}

impl fmt::Display for RequesterRendezvousDrAcknowledgementWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOuterKind => {
                "invalid outer PRWM kind for requester rendezvous DR acknowledgement"
            }
            Self::InvalidPayload => "invalid requester rendezvous PRWZ DR acknowledgement payload",
            Self::Frame(_) => "failed to construct requester rendezvous DR acknowledgement frame",
        })
    }
}

impl std::error::Error for RequesterRendezvousDrAcknowledgementWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::InvalidOuterKind | Self::InvalidPayload => None,
        }
    }
}

impl From<RemoteTransportError> for RequesterRendezvousDrAcknowledgementWireError {
    fn from(error: RemoteTransportError) -> Self {
        Self::Frame(error)
    }
}

/// Projects one already-completed DR result into the FC-selected coarse requester acknowledgement.
///
/// The error value is never inspected, formatted or otherwise translated. Any `Err(_)` becomes the
/// same generic rejection, preserving internal DR failure taxonomy behind the requester boundary.
#[must_use]
pub const fn project_requester_rendezvous_dr_result<E>(
    result: &Result<(), E>,
) -> RequesterRendezvousDrAcknowledgement {
    match result {
        Ok(()) => RequesterRendezvousDrAcknowledgement::Accepted,
        Err(_) => RequesterRendezvousDrAcknowledgement::Rejected,
    }
}

/// Encodes one coarse requester/rendezvous DR acknowledgement into a bounded PRWM frame.
///
/// The supplied request ID is echo correlation only. Accepted carries no candidate, reachability,
/// endpoint, relay, transport or session-success data; rejected carries no internal DR detail.
///
/// # Errors
///
/// Returns the existing PRWM frame-construction error if the supplied correlation or bounded payload
/// is rejected by the transport frame constructor.
pub fn encode_requester_rendezvous_dr_acknowledgement_frame(
    request_id: u64,
    acknowledgement: RequesterRendezvousDrAcknowledgement,
) -> Result<ControlFrame, RequesterRendezvousDrAcknowledgementWireError> {
    let mut payload = Vec::with_capacity(REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES);
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC);
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR.to_be_bytes());
    payload.extend_from_slice(&REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR.to_be_bytes());
    payload.extend_from_slice(&acknowledgement.operation().to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    ControlFrame::new(acknowledgement.outer_kind(), request_id, payload)
        .map_err(RequesterRendezvousDrAcknowledgementWireError::Frame)
}

/// Purely projects and frames the exact completed DR result for one retained requester transaction.
///
/// The transaction is borrowed only to echo its exact strict request's original PRWM `request_id`.
/// Neither the transaction nor its retained stream is consumed, read, written, closed or cloned.
/// The DR error type remains generic and is never inspected.
///
/// # Errors
///
/// Returns only a local PRWM frame-construction failure. A semantic DR failure is projected to a
/// valid generic rejected acknowledgement and is not converted into a local codec failure.
pub fn encode_requester_rendezvous_dr_result_for_transaction<E>(
    transaction: &PostAuthRequesterRendezvousTransaction,
    dr_result: &Result<(), E>,
) -> Result<ControlFrame, RequesterRendezvousDrAcknowledgementWireError> {
    encode_requester_rendezvous_dr_acknowledgement_frame(
        transaction.request().request_id(),
        project_requester_rendezvous_dr_result(dr_result),
    )
}

/// Decodes one already-parsed PRWM frame as a strict PRWZ terminal DR acknowledgement.
///
/// Successful decode proves only bounded acknowledgement structure and exact outer-kind pairing. It
/// does not prove DR provenance, requester identity, target reachability or rendezvous completion.
///
/// # Errors
///
/// Rejects any non-exact payload size, wrong PRWZ family/version, non-zero flags, unknown operation,
/// or mismatch between the terminal operation and outer PRWM kind.
pub fn decode_requester_rendezvous_dr_acknowledgement_frame(
    frame: &ControlFrame,
) -> Result<RequesterRendezvousDrAcknowledgement, RequesterRendezvousDrAcknowledgementWireError> {
    let payload = frame.payload();
    if payload.len() != REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES
        || payload[..4] != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC
        || u16::from_be_bytes([payload[4], payload[5]])
            != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAJOR
        || u16::from_be_bytes([payload[6], payload[7]])
            != REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MINOR
        || u16::from_be_bytes([payload[10], payload[11]]) != 0
    {
        return Err(RequesterRendezvousDrAcknowledgementWireError::InvalidPayload);
    }

    let acknowledgement = match u16::from_be_bytes([payload[8], payload[9]]) {
        OP_REQUESTER_RENDEZVOUS_DR_ACCEPTED => RequesterRendezvousDrAcknowledgement::Accepted,
        OP_REQUESTER_RENDEZVOUS_DR_REJECTED => RequesterRendezvousDrAcknowledgement::Rejected,
        _ => return Err(RequesterRendezvousDrAcknowledgementWireError::InvalidPayload),
    };

    if frame.kind() != acknowledgement.outer_kind() {
        return Err(RequesterRendezvousDrAcknowledgementWireError::InvalidOuterKind);
    }

    Ok(acknowledgement)
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::{ControlFrame, ControlMessageKind};

    use super::{
        OP_REQUESTER_RENDEZVOUS_DR_ACCEPTED, OP_REQUESTER_RENDEZVOUS_DR_REJECTED,
        REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES, RequesterRendezvousDrAcknowledgement,
        RequesterRendezvousDrAcknowledgementWireError,
        decode_requester_rendezvous_dr_acknowledgement_frame,
        encode_requester_rendezvous_dr_acknowledgement_frame,
        project_requester_rendezvous_dr_result,
    };

    #[test]
    fn accepted_round_trip_preserves_exact_correlation_and_no_body() {
        let frame = encode_requester_rendezvous_dr_acknowledgement_frame(
            91,
            RequesterRendezvousDrAcknowledgement::Accepted,
        )
        .expect("bounded accepted acknowledgement must frame");

        assert_eq!(frame.kind(), ControlMessageKind::Response);
        assert_eq!(frame.request_id(), 91);
        assert_eq!(
            frame.payload().len(),
            REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES
        );
        assert_eq!(
            u16::from_be_bytes([frame.payload()[8], frame.payload()[9]]),
            OP_REQUESTER_RENDEZVOUS_DR_ACCEPTED
        );
        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&frame),
            Ok(RequesterRendezvousDrAcknowledgement::Accepted)
        );
    }

    #[test]
    fn rejected_round_trip_uses_error_kind_and_no_internal_detail() {
        let frame = encode_requester_rendezvous_dr_acknowledgement_frame(
            17,
            RequesterRendezvousDrAcknowledgement::Rejected,
        )
        .expect("bounded rejected acknowledgement must frame");

        assert_eq!(frame.kind(), ControlMessageKind::Error);
        assert_eq!(frame.request_id(), 17);
        assert_eq!(
            frame.payload().len(),
            REQUESTER_RENDEZVOUS_DR_ACKNOWLEDGEMENT_WIRE_BYTES
        );
        assert_eq!(
            u16::from_be_bytes([frame.payload()[8], frame.payload()[9]]),
            OP_REQUESTER_RENDEZVOUS_DR_REJECTED
        );
        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&frame),
            Ok(RequesterRendezvousDrAcknowledgement::Rejected)
        );
    }

    #[test]
    fn projector_maps_every_error_type_to_one_generic_rejection() {
        let accepted: Result<(), &'static str> = Ok(());
        let rejected_a: Result<(), &'static str> = Err("registry detail must stay internal");
        let rejected_b: Result<(), u64> = Err(42);

        assert_eq!(
            project_requester_rendezvous_dr_result(&accepted),
            RequesterRendezvousDrAcknowledgement::Accepted
        );
        assert_eq!(
            project_requester_rendezvous_dr_result(&rejected_a),
            RequesterRendezvousDrAcknowledgement::Rejected
        );
        assert_eq!(
            project_requester_rendezvous_dr_result(&rejected_b),
            RequesterRendezvousDrAcknowledgement::Rejected
        );
    }

    #[test]
    fn decoder_rejects_outer_kind_mismatch() {
        let accepted = encode_requester_rendezvous_dr_acknowledgement_frame(
            9,
            RequesterRendezvousDrAcknowledgement::Accepted,
        )
        .expect("accepted acknowledgement must frame");
        let wrong_kind = ControlFrame::new(
            ControlMessageKind::Error,
            accepted.request_id(),
            accepted.payload().to_vec(),
        )
        .expect("bounded test frame must construct");

        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&wrong_kind),
            Err(RequesterRendezvousDrAcknowledgementWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn decoder_rejects_non_zero_flags_unknown_operation_and_trailing_data() {
        let accepted = encode_requester_rendezvous_dr_acknowledgement_frame(
            5,
            RequesterRendezvousDrAcknowledgement::Accepted,
        )
        .expect("accepted acknowledgement must frame");

        let mut flags = accepted.payload().to_vec();
        flags[11] = 1;
        let flags_frame = ControlFrame::new(ControlMessageKind::Response, 5, flags)
            .expect("bounded malformed test frame must construct");
        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&flags_frame),
            Err(RequesterRendezvousDrAcknowledgementWireError::InvalidPayload)
        );

        let mut unknown_operation = accepted.payload().to_vec();
        unknown_operation[8..10].copy_from_slice(&99_u16.to_be_bytes());
        let unknown_operation_frame =
            ControlFrame::new(ControlMessageKind::Response, 5, unknown_operation)
                .expect("bounded malformed test frame must construct");
        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&unknown_operation_frame),
            Err(RequesterRendezvousDrAcknowledgementWireError::InvalidPayload)
        );

        let mut trailing = accepted.payload().to_vec();
        trailing.push(0);
        let trailing_frame = ControlFrame::new(ControlMessageKind::Response, 5, trailing)
            .expect("bounded malformed test frame must construct");
        assert_eq!(
            decode_requester_rendezvous_dr_acknowledgement_frame(&trailing_frame),
            Err(RequesterRendezvousDrAcknowledgementWireError::InvalidPayload)
        );
    }
}
