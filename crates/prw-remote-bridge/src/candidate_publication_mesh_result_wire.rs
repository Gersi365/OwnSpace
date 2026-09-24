//! Pure current-Mesh PRWP candidate-publication terminal result composition.
//!
//! C03e-GM materializes only the C03e-GL-selected pure projection/frame-composition seam for the
//! current `prw_remote_transport::ControlFrame` ownership domain. It deliberately performs no
//! stream I/O, semantic execution, requester mutation, retry, task creation, runtime activation,
//! traversal, listener/readiness work, dialing, deployment, process recovery, or merge behavior.

use std::fmt;

use prw_remote_transport::{
    ControlFrame as MeshControlFrame, ControlMessageKind as MeshControlMessageKind,
    RemoteTransportError,
};

use crate::{
    candidate_publication_result_wire::{
        CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES, CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES,
        CandidatePublicationResultMessage, OP_PUBLISHER_CANDIDATE_SET_ACCEPTED,
        OP_PUBLISHER_CANDIDATE_SET_REJECTED,
    },
    candidate_publication_wire::{
        CANDIDATE_PUBLICATION_WIRE_MAGIC, CANDIDATE_PUBLICATION_WIRE_MAJOR,
        CANDIDATE_PUBLICATION_WIRE_MINOR,
    },
    reachability_owner::ReachabilityCommitOutcome,
};

/// Local current-Mesh candidate terminal frame-construction failure.
///
/// This layer is deliberately separate from candidate semantic execution, exact production-owner
/// lookup and post-commit requester cleanup. A local frame-construction failure authorizes no
/// fallback frame, semantic replay, cleanup replay, second durable commit, stream replacement or
/// response retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationMeshResultFrameError {
    /// Existing current-Mesh frame validation rejected the selected kind/request correlation/payload.
    Frame(RemoteTransportError),
}

impl fmt::Display for CandidatePublicationMeshResultFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(_) => formatter.write_str(
                "failed to construct current-Mesh candidate publication result control frame",
            ),
        }
    }
}

impl std::error::Error for CandidatePublicationMeshResultFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
        }
    }
}

/// One locally composed current-Mesh frame result paired with opaque higher-owner disposition.
///
/// The bridge never inspects or serializes `disposition`. This carrier performs no frame I/O and
/// exists only so a higher owner can retain exact post-commit cleanup state beside frame composition.
pub struct CandidatePublicationMeshResultFrameComposition<D> {
    frame_result: Result<MeshControlFrame, CandidatePublicationMeshResultFrameError>,
    disposition: D,
}

impl<D> CandidatePublicationMeshResultFrameComposition<D> {
    /// Pairs one already-computed current-Mesh frame result with one opaque disposition.
    #[must_use]
    pub const fn new(
        frame_result: Result<MeshControlFrame, CandidatePublicationMeshResultFrameError>,
        disposition: D,
    ) -> Self {
        Self {
            frame_result,
            disposition,
        }
    }

    /// Transfers both channels without inspecting, flattening or serializing the disposition.
    pub fn into_parts(
        self,
    ) -> (
        Result<MeshControlFrame, CandidatePublicationMeshResultFrameError>,
        D,
    ) {
        (self.frame_result, self.disposition)
    }
}

fn encode_candidate_publication_terminal_payload(
    message: CandidatePublicationResultMessage,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(match message {
        CandidatePublicationResultMessage::Accepted { .. } => {
            CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES
        }
        CandidatePublicationResultMessage::Rejected => CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES,
    });
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAGIC);
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAJOR.to_be_bytes());
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MINOR.to_be_bytes());

    let operation = match message {
        CandidatePublicationResultMessage::Accepted { .. } => OP_PUBLISHER_CANDIDATE_SET_ACCEPTED,
        CandidatePublicationResultMessage::Rejected => OP_PUBLISHER_CANDIDATE_SET_REJECTED,
    };
    payload.extend_from_slice(&operation.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    if let CandidatePublicationResultMessage::Accepted {
        replacement_freshness,
    } = message
    {
        payload.extend_from_slice(replacement_freshness.as_bytes());
    }

    payload
}

/// Encodes one typed candidate terminal result into the current PRWM control-frame ownership type.
///
/// `request_id` is caller-supplied peer correlation only. No request identifier is allocated or
/// registered here. Existing PRWP terminal payload bytes remain byte-equivalent to the historical
/// codec while the outer frame is the current `prw_remote_transport::ControlFrame` type.
///
/// # Errors
///
/// Returns a distinct local frame-construction error if existing current-Mesh frame validation
/// rejects the request correlation or bounded payload. No fallback frame is constructed.
pub fn encode_candidate_publication_mesh_result_frame(
    request_id: u64,
    message: CandidatePublicationResultMessage,
) -> Result<MeshControlFrame, CandidatePublicationMeshResultFrameError> {
    let kind = match message {
        CandidatePublicationResultMessage::Accepted { .. } => MeshControlMessageKind::Response,
        CandidatePublicationResultMessage::Rejected => MeshControlMessageKind::Error,
    };

    MeshControlFrame::new(
        kind,
        request_id,
        encode_candidate_publication_terminal_payload(message),
    )
    .map_err(CandidatePublicationMeshResultFrameError::Frame)
}

/// Projects one already-completed semantic result into current-Mesh terminal framing while
/// preserving an opaque success-only higher-owner disposition.
///
/// Definite durable success is the only Accepted path and carries exactly the verifier-issued
/// replacement freshness from [`ReachabilityCommitOutcome`]. Every pre/at-commit error projects to
/// generic Rejected and carries no post-commit disposition. The error value remains distinguishable
/// to the caller before it is consumed by this pure projection, but no error detail is serialized.
///
/// This helper performs no semantic execution, owner lookup, cleanup, stream I/O or retry.
#[must_use]
pub fn compose_candidate_publication_current_mesh_terminal_result<D, E>(
    request_id: u64,
    result: Result<(ReachabilityCommitOutcome, D), E>,
) -> CandidatePublicationMeshResultFrameComposition<Option<D>> {
    let (message, disposition) = match result {
        Ok((committed, disposition)) => (
            CandidatePublicationResultMessage::Accepted {
                replacement_freshness: committed.replacement_freshness(),
            },
            Some(disposition),
        ),
        Err(_) => (CandidatePublicationResultMessage::Rejected, None),
    };

    CandidatePublicationMeshResultFrameComposition::new(
        encode_candidate_publication_mesh_result_frame(request_id, message),
        disposition,
    )
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::{
        ControlMessageKind as MeshControlMessageKind, RemoteTransportError,
    };

    use crate::{
        candidate_publication_freshness::CandidatePublicationFreshnessToken,
        candidate_publication_result_wire::{
            CandidatePublicationResultMessage, encode_candidate_publication_result_frame,
        },
    };

    use super::{
        CandidatePublicationMeshResultFrameError,
        compose_candidate_publication_current_mesh_terminal_result,
        encode_candidate_publication_mesh_result_frame,
    };

    fn freshness(byte: u8) -> CandidatePublicationFreshnessToken {
        CandidatePublicationFreshnessToken::new([byte; 32])
            .expect("non-zero GM replacement freshness")
    }

    #[test]
    fn current_mesh_accepted_echoes_request_id_and_preserves_historical_prwp_payload_bytes() {
        let message = CandidatePublicationResultMessage::Accepted {
            replacement_freshness: freshness(0x71),
        };
        let historical =
            encode_candidate_publication_result_frame(73, message).expect("historical accepted");
        let current =
            encode_candidate_publication_mesh_result_frame(73, message).expect("current accepted");

        assert_eq!(current.kind(), MeshControlMessageKind::Response);
        assert_eq!(current.request_id(), 73);
        assert_eq!(current.payload(), historical.payload());
    }

    #[test]
    fn current_mesh_rejected_echoes_request_id_and_preserves_historical_prwp_payload_bytes() {
        let message = CandidatePublicationResultMessage::Rejected;
        let historical =
            encode_candidate_publication_result_frame(79, message).expect("historical rejected");
        let current =
            encode_candidate_publication_mesh_result_frame(79, message).expect("current rejected");

        assert_eq!(current.kind(), MeshControlMessageKind::Error);
        assert_eq!(current.request_id(), 79);
        assert_eq!(current.payload(), historical.payload());
    }

    #[test]
    fn local_frame_construction_failure_has_no_fallback_frame() {
        let error = encode_candidate_publication_mesh_result_frame(
            0,
            CandidatePublicationResultMessage::Rejected,
        )
        .expect_err("zero current-Mesh request correlation must fail");

        assert_eq!(
            error,
            CandidatePublicationMeshResultFrameError::Frame(
                RemoteTransportError::InvalidControlFrame
            )
        );
    }

    #[test]
    fn pre_commit_error_projects_to_generic_rejected_with_no_disposition() {
        let composition = compose_candidate_publication_current_mesh_terminal_result::<(), _>(
            83,
            Err("semantic failure"),
        );
        let (frame_result, disposition) = composition.into_parts();
        let frame = frame_result.expect("generic rejected frame");

        assert_eq!(frame.kind(), MeshControlMessageKind::Error);
        assert_eq!(frame.request_id(), 83);
        assert!(disposition.is_none());
    }
}
