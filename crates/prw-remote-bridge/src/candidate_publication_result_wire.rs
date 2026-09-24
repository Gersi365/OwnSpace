//! Pure PRWP v1.0 candidate-publication terminal result codec.
//!
//! C03e-CV materializes only the C03e-CU-selected pure projection between an already-completed
//! candidate-publication semantic execution result and bounded Phase 129 `Response`/`Error`
//! frames. It performs no frame I/O, request-ID allocation, retry, loop, task creation,
//! runtime/process ownership, listener activation, networking, deployment, or merge behavior.

use std::fmt;

use prw_control_transport::{ControlFrame, ControlFrameError, ControlMessageKind};

use crate::{
    candidate_publication_control_frame::CandidatePublicationControlFrame,
    candidate_publication_execution::CandidatePublicationExecutionError,
    candidate_publication_freshness::{
        CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, CandidatePublicationFreshnessToken,
    },
    candidate_publication_wire::{
        CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES, CANDIDATE_PUBLICATION_WIRE_MAGIC,
        CANDIDATE_PUBLICATION_WIRE_MAJOR, CANDIDATE_PUBLICATION_WIRE_MINOR,
    },
    reachability_owner::ReachabilityCommitOutcome,
};

/// PRWP v1.0 terminal accepted-result operation tag.
pub const OP_PUBLISHER_CANDIDATE_SET_ACCEPTED: u16 = 2;
/// PRWP v1.0 terminal rejected-result operation tag.
pub const OP_PUBLISHER_CANDIDATE_SET_REJECTED: u16 = 3;
/// Exact accepted-result PRWP payload size.
pub const CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES: usize =
    CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES + CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES;
/// Exact generic rejected-result PRWP payload size.
pub const CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES: usize =
    CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES;

/// One structurally valid terminal candidate-publication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePublicationResultMessage {
    /// Durable semantic execution committed and installed this verifier freshness token.
    Accepted {
        replacement_freshness: CandidatePublicationFreshnessToken,
    },
    /// Generic fail-closed terminal rejection with no detailed external reason.
    Rejected,
}

impl CandidatePublicationResultMessage {
    const fn operation(self) -> u16 {
        match self {
            Self::Accepted { .. } => OP_PUBLISHER_CANDIDATE_SET_ACCEPTED,
            Self::Rejected => OP_PUBLISHER_CANDIDATE_SET_REJECTED,
        }
    }

    const fn outer_kind(self) -> ControlMessageKind {
        match self {
            Self::Accepted { .. } => ControlMessageKind::Response,
            Self::Rejected => ControlMessageKind::Error,
        }
    }
}

/// Stable pure result-codec failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationResultWireError {
    /// Outer Phase 129 message kind did not match the PRWP terminal result operation.
    InvalidOuterKind,
    /// PRWP terminal result structure, metadata, freshness, bounds, or trailing bytes were invalid.
    InvalidPayload,
    /// Existing Phase 129 frame construction rejected the supplied request ID or payload.
    Frame(ControlFrameError),
}

impl fmt::Display for CandidatePublicationResultWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOuterKind => "invalid outer PRWC kind for candidate publication result",
            Self::InvalidPayload => "invalid candidate publication result PRWP payload",
            Self::Frame(_) => "failed to construct candidate publication result control frame",
        })
    }
}

impl std::error::Error for CandidatePublicationResultWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::InvalidOuterKind | Self::InvalidPayload => None,
        }
    }
}

/// One locally constructed candidate-publication terminal frame result paired with an opaque
/// higher-owner disposition that is never inspected or serialized by this bridge codec.
///
/// C03e-GC introduces this narrow generic custody carrier so an Agent caller can preserve its
/// post-commit requester cleanup disposition beside the exact existing frame-construction result
/// without adding a direct control-transport dependency merely to name [`ControlFrame`]. The
/// existing Accepted/Rejected encoding functions remain authoritative and unchanged.
pub struct CandidatePublicationResultFrameComposition<D> {
    frame_result: Result<ControlFrame, CandidatePublicationResultWireError>,
    disposition: D,
}

impl<D> CandidatePublicationResultFrameComposition<D> {
    /// Pairs one already-computed existing frame result with one opaque disposition.
    ///
    /// Construction performs no encoding, frame I/O, retry, semantic execution, or disposition
    /// inspection. `disposition` cannot alter `frame_result`.
    #[must_use]
    pub const fn new(
        frame_result: Result<ControlFrame, CandidatePublicationResultWireError>,
        disposition: D,
    ) -> Self {
        Self {
            frame_result,
            disposition,
        }
    }

    /// Transfers the exact frame-construction result and opaque disposition by value.
    pub fn into_parts(self) -> (Result<ControlFrame, CandidatePublicationResultWireError>, D) {
        (self.frame_result, self.disposition)
    }
}

/// Encodes one typed terminal candidate-publication result into a bounded Phase 129 frame.
///
/// `request_id` is caller-supplied echo correlation only. This codec allocates and registers no
/// request ID and performs no frame I/O.
///
/// # Errors
///
/// Returns [`CandidatePublicationResultWireError::Frame`] if existing Phase 129 frame validation
/// rejects the supplied request ID or bounded payload.
pub fn encode_candidate_publication_result_frame(
    request_id: u64,
    message: CandidatePublicationResultMessage,
) -> Result<ControlFrame, CandidatePublicationResultWireError> {
    let mut payload = Vec::with_capacity(match message {
        CandidatePublicationResultMessage::Accepted { .. } => {
            CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES
        }
        CandidatePublicationResultMessage::Rejected => CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES,
    });
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAGIC);
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAJOR.to_be_bytes());
    payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MINOR.to_be_bytes());
    payload.extend_from_slice(&message.operation().to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    if let CandidatePublicationResultMessage::Accepted {
        replacement_freshness,
    } = message
    {
        payload.extend_from_slice(replacement_freshness.as_bytes());
    }

    ControlFrame::new(message.outer_kind(), request_id, payload)
        .map_err(CandidatePublicationResultWireError::Frame)
}

/// Decodes one already-parsed Phase 129 frame as a terminal candidate-publication result.
///
/// Successful return proves only strict PRWP result structure and exact outer-kind pairing. It
/// does not establish semantic authorization or durable commit provenance.
///
/// # Errors
///
/// Rejects malformed metadata, unknown operations, wrong outer-kind pairing, zero accepted
/// freshness, truncation, or trailing bytes.
pub fn decode_candidate_publication_result_frame(
    frame: &ControlFrame,
) -> Result<CandidatePublicationResultMessage, CandidatePublicationResultWireError> {
    let payload = frame.payload();
    if payload.len() < CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES
        || payload[..4] != CANDIDATE_PUBLICATION_WIRE_MAGIC
        || u16::from_be_bytes([payload[4], payload[5]]) != CANDIDATE_PUBLICATION_WIRE_MAJOR
        || u16::from_be_bytes([payload[6], payload[7]]) != CANDIDATE_PUBLICATION_WIRE_MINOR
        || u16::from_be_bytes([payload[10], payload[11]]) != 0
    {
        return Err(CandidatePublicationResultWireError::InvalidPayload);
    }

    let operation = u16::from_be_bytes([payload[8], payload[9]]);
    let (expected_outer_kind, message) = match operation {
        OP_PUBLISHER_CANDIDATE_SET_ACCEPTED => {
            if payload.len() != CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES {
                return Err(CandidatePublicationResultWireError::InvalidPayload);
            }
            let mut freshness_bytes = [0_u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES];
            freshness_bytes.copy_from_slice(&payload[CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES..]);
            let replacement_freshness = CandidatePublicationFreshnessToken::new(freshness_bytes)
                .map_err(|_| CandidatePublicationResultWireError::InvalidPayload)?;
            (
                ControlMessageKind::Response,
                CandidatePublicationResultMessage::Accepted {
                    replacement_freshness,
                },
            )
        }
        OP_PUBLISHER_CANDIDATE_SET_REJECTED => {
            if payload.len() != CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES {
                return Err(CandidatePublicationResultWireError::InvalidPayload);
            }
            (
                ControlMessageKind::Error,
                CandidatePublicationResultMessage::Rejected,
            )
        }
        _ => return Err(CandidatePublicationResultWireError::InvalidPayload),
    };

    if frame.kind() != expected_outer_kind {
        return Err(CandidatePublicationResultWireError::InvalidOuterKind);
    }

    Ok(message)
}

/// Projects one already-completed semantic execution result into the CU-selected terminal message.
///
/// Every internal execution failure maps to the same generic external rejection. Successful
/// projection exposes only the verifier-issued replacement freshness; traversal invalidation
/// remains internal.
///
/// This function performs no candidate-publication execution and no frame I/O.
#[must_use]
pub const fn project_candidate_publication_execution_result(
    result: Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
) -> CandidatePublicationResultMessage {
    match result {
        Ok(outcome) => CandidatePublicationResultMessage::Accepted {
            replacement_freshness: outcome.replacement_freshness(),
        },
        Err(_) => CandidatePublicationResultMessage::Rejected,
    }
}

/// Projects one completed semantic execution result and frames it with the decoded Command's exact
/// peer-originated request correlation.
///
/// This helper reads only `command.request_id()`. It allocates/registers no local request ID and
/// performs no frame write.
///
/// # Errors
///
/// Returns the local pure-codec frame-construction failure if existing Phase 129 validation rejects
/// the echoed request ID or result payload.
pub fn encode_candidate_publication_execution_result_frame(
    command: &CandidatePublicationControlFrame,
    result: Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
) -> Result<ControlFrame, CandidatePublicationResultWireError> {
    encode_candidate_publication_result_frame(
        command.request_id(),
        project_candidate_publication_execution_result(result),
    )
}

#[cfg(test)]
mod tests {
    use prw_connectivity::TransportIdentity;
    use prw_control_transport::{ControlFrame, ControlFrameError, ControlMessageKind};

    use crate::{
        candidate_publication_control_frame::{
            decode_candidate_publication_control_frame, encode_candidate_publication_control_frame,
        },
        candidate_publication_execution::CandidatePublicationExecutionError,
        candidate_publication_freshness::CandidatePublicationFreshnessToken,
        candidate_publication_wire::CandidatePublicationWireSubmission,
        candidate_reachability::CandidateReachabilityError,
        reachability_owner::{ReachabilityCommitOutcome, ReachabilityOwnerError},
        requester_rendezvous_authority::RequesterRendezvousAuthorityError,
    };

    use super::{
        CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES, CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES,
        CandidatePublicationResultFrameComposition, CandidatePublicationResultMessage,
        CandidatePublicationResultWireError, OP_PUBLISHER_CANDIDATE_SET_ACCEPTED,
        OP_PUBLISHER_CANDIDATE_SET_REJECTED, decode_candidate_publication_result_frame,
        encode_candidate_publication_execution_result_frame,
        encode_candidate_publication_result_frame, project_candidate_publication_execution_result,
    };

    fn freshness(byte: u8) -> CandidatePublicationFreshnessToken {
        CandidatePublicationFreshnessToken::new([byte; 32]).expect("non-zero CV freshness")
    }

    fn submission() -> CandidatePublicationWireSubmission {
        CandidatePublicationWireSubmission::new(
            TransportIdentity::new([0x31; 32]).expect("non-zero CV transport identity"),
            freshness(0x41),
            Vec::new(),
        )
        .expect("empty candidate set is bounded")
    }

    #[test]
    fn accepted_result_uses_response_exact_request_id_and_replacement_freshness() {
        let replacement_freshness = freshness(0x51);
        let message = CandidatePublicationResultMessage::Accepted {
            replacement_freshness,
        };

        let frame =
            encode_candidate_publication_result_frame(17, message).expect("encode accepted result");

        assert_eq!(frame.kind(), ControlMessageKind::Response);
        assert_eq!(frame.request_id(), 17);
        assert_eq!(
            frame.payload().len(),
            CANDIDATE_PUBLICATION_ACCEPTED_RESULT_BYTES
        );
        assert_eq!(
            u16::from_be_bytes([frame.payload()[8], frame.payload()[9]]),
            OP_PUBLISHER_CANDIDATE_SET_ACCEPTED
        );
        assert_eq!(&frame.payload()[12..], replacement_freshness.as_bytes());
        assert_eq!(
            decode_candidate_publication_result_frame(&frame),
            Ok(message)
        );
    }

    #[test]
    fn rejected_result_uses_error_exact_request_id_and_header_only_payload() {
        let frame = encode_candidate_publication_result_frame(
            23,
            CandidatePublicationResultMessage::Rejected,
        )
        .expect("encode rejected result");

        assert_eq!(frame.kind(), ControlMessageKind::Error);
        assert_eq!(frame.request_id(), 23);
        assert_eq!(
            frame.payload().len(),
            CANDIDATE_PUBLICATION_REJECTED_RESULT_BYTES
        );
        assert_eq!(
            u16::from_be_bytes([frame.payload()[8], frame.payload()[9]]),
            OP_PUBLISHER_CANDIDATE_SET_REJECTED
        );
        assert_eq!(
            decode_candidate_publication_result_frame(&frame),
            Ok(CandidatePublicationResultMessage::Rejected)
        );
    }

    #[test]
    fn accepted_decoder_rejects_wrong_outer_kind() {
        let accepted = encode_candidate_publication_result_frame(
            29,
            CandidatePublicationResultMessage::Accepted {
                replacement_freshness: freshness(0x61),
            },
        )
        .expect("encode accepted result");
        let wrong_kind = ControlFrame::new(
            ControlMessageKind::Error,
            accepted.request_id(),
            accepted.payload().to_vec(),
        )
        .expect("generic frame accepts bounded payload");

        assert_eq!(
            decode_candidate_publication_result_frame(&wrong_kind),
            Err(CandidatePublicationResultWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn rejected_decoder_rejects_wrong_outer_kind() {
        let rejected = encode_candidate_publication_result_frame(
            31,
            CandidatePublicationResultMessage::Rejected,
        )
        .expect("encode rejected result");
        let wrong_kind = ControlFrame::new(
            ControlMessageKind::Response,
            rejected.request_id(),
            rejected.payload().to_vec(),
        )
        .expect("generic frame accepts bounded payload");

        assert_eq!(
            decode_candidate_publication_result_frame(&wrong_kind),
            Err(CandidatePublicationResultWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn malformed_common_metadata_and_lengths_fail_closed() {
        let rejected = encode_candidate_publication_result_frame(
            37,
            CandidatePublicationResultMessage::Rejected,
        )
        .expect("encode rejected result");
        let valid = rejected.payload().to_vec();

        let mut wrong_magic = valid.clone();
        wrong_magic[0] ^= 0xff;
        let mut wrong_major = valid.clone();
        wrong_major[5] = 2;
        let mut wrong_minor = valid.clone();
        wrong_minor[7] = 1;
        let mut unknown_operation = valid.clone();
        unknown_operation[9] = 9;
        let mut non_zero_reserved = valid.clone();
        non_zero_reserved[11] = 1;
        let truncated = valid[..11].to_vec();
        let mut trailing = valid;
        trailing.push(0);

        for payload in [
            wrong_magic,
            wrong_major,
            wrong_minor,
            unknown_operation,
            non_zero_reserved,
            truncated,
            trailing,
        ] {
            let frame = ControlFrame::new(ControlMessageKind::Error, 37, payload)
                .expect("generic frame accepts bounded malformed payload");
            assert_eq!(
                decode_candidate_publication_result_frame(&frame),
                Err(CandidatePublicationResultWireError::InvalidPayload)
            );
        }
    }

    #[test]
    fn accepted_truncation_trailing_bytes_and_zero_freshness_fail_closed() {
        let accepted = encode_candidate_publication_result_frame(
            41,
            CandidatePublicationResultMessage::Accepted {
                replacement_freshness: freshness(0x71),
            },
        )
        .expect("encode accepted result");
        let valid = accepted.payload().to_vec();

        let mut truncated = valid.clone();
        truncated.pop();
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut zero_freshness = valid;
        zero_freshness[12..].fill(0);

        for payload in [truncated, trailing, zero_freshness] {
            let frame = ControlFrame::new(ControlMessageKind::Response, 41, payload)
                .expect("generic frame accepts bounded malformed payload");
            assert_eq!(
                decode_candidate_publication_result_frame(&frame),
                Err(CandidatePublicationResultWireError::InvalidPayload)
            );
        }
    }

    #[test]
    fn direct_zero_request_id_fails_through_existing_control_frame_validation() {
        assert_eq!(
            encode_candidate_publication_result_frame(
                0,
                CandidatePublicationResultMessage::Rejected,
            ),
            Err(CandidatePublicationResultWireError::Frame(
                ControlFrameError::ZeroRequestId
            ))
        );
    }

    #[test]
    fn frame_composition_preserves_existing_frame_result_and_opaque_disposition() {
        let frame = encode_candidate_publication_result_frame(
            61,
            CandidatePublicationResultMessage::Rejected,
        )
        .expect("encode bounded rejected frame");
        let composition = CandidatePublicationResultFrameComposition::new(Ok(frame), 17_u8);

        let (frame_result, disposition) = composition.into_parts();
        let frame = frame_result.expect("preserved frame result");

        assert_eq!(frame.request_id(), 61);
        assert_eq!(
            decode_candidate_publication_result_frame(&frame),
            Ok(CandidatePublicationResultMessage::Rejected)
        );
        assert_eq!(disposition, 17);
    }

    #[test]
    fn frame_composition_preserves_frame_failure_and_opaque_disposition() {
        let composition = CandidatePublicationResultFrameComposition::new(
            Err(CandidatePublicationResultWireError::Frame(
                ControlFrameError::ZeroRequestId,
            )),
            23_u8,
        );

        let (frame_result, disposition) = composition.into_parts();

        assert_eq!(
            frame_result,
            Err(CandidatePublicationResultWireError::Frame(
                ControlFrameError::ZeroRequestId
            ))
        );
        assert_eq!(disposition, 23);
    }

    #[test]
    fn representative_internal_execution_errors_all_project_to_generic_rejected() {
        let errors = [
            CandidatePublicationExecutionError::Candidate(
                CandidateReachabilityError::WorkspaceMismatch,
            ),
            CandidatePublicationExecutionError::RequesterAuthority(
                RequesterRendezvousAuthorityError::Missing,
            ),
            CandidatePublicationExecutionError::ExpectedPublisherMismatch,
            CandidatePublicationExecutionError::Reachability(
                ReachabilityOwnerError::RecoveryRequired,
            ),
        ];

        for error in errors {
            assert_eq!(
                project_candidate_publication_execution_result(Err(error)),
                CandidatePublicationResultMessage::Rejected
            );
        }
    }

    #[test]
    fn execution_result_framing_echoes_decoded_command_request_id_without_local_allocation() {
        let command_frame = encode_candidate_publication_control_frame(&submission(), 73)
            .expect("encode candidate publication command");
        let command = decode_candidate_publication_control_frame(&command_frame)
            .expect("decode candidate publication command");

        let result_frame = encode_candidate_publication_execution_result_frame(
            &command,
            Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch),
        )
        .expect("encode generic execution rejection");

        assert_eq!(result_frame.request_id(), 73);
        assert_eq!(result_frame.kind(), ControlMessageKind::Error);
        assert_eq!(
            decode_candidate_publication_result_frame(&result_frame),
            Ok(CandidatePublicationResultMessage::Rejected)
        );
    }

    #[test]
    fn execution_projection_signature_consumes_only_existing_semantic_result() {
        fn assert_signature(
            function: fn(
                Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
            ) -> CandidatePublicationResultMessage,
        ) {
            let _ = function;
        }

        assert_signature(project_candidate_publication_execution_result);
    }
}
