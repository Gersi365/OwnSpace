//! Pure in-memory composition between candidate-publication PRWP payloads and Phase 129 PRWC frames.
//!
//! Phase 152 C03e-BT materializes only the BS-selected bridge-owned adapter. It performs no
//! request-ID allocation, stream I/O, TLS connection work, authentication, routing, publication
//! admission, freshness rotation, reachability mutation, networking activation, or deployment.

use std::fmt;

use prw_control_transport::{ControlFrame, ControlFrameError, ControlMessageKind};

use crate::candidate_publication_wire::{
    CandidatePublicationWireError, CandidatePublicationWireSubmission,
};

/// One decoded candidate-publication command plus its outer correlation value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePublicationControlFrame {
    request_id: u64,
    submission: CandidatePublicationWireSubmission,
}

impl CandidatePublicationControlFrame {
    /// Returns the outer Phase 129 request correlation value.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the decoded typed candidate-publication submission.
    #[must_use]
    pub const fn submission(&self) -> &CandidatePublicationWireSubmission {
        &self.submission
    }
}

/// Stable pure-composition failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationControlFrameError {
    /// The supplied or decoded outer frame is not the BR-selected Command kind.
    WrongMessageKind,
    /// The BQ PRWP payload failed strict inner decoding.
    InvalidPublicationPayload,
    /// The existing Phase 129 frame constructor rejected the supplied correlation or payload.
    InvalidControlFrame,
}

impl fmt::Display for CandidatePublicationControlFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::WrongMessageKind => "candidate publication requires control Command kind",
            Self::InvalidPublicationPayload => "invalid candidate publication PRWP payload",
            Self::InvalidControlFrame => "invalid candidate publication control frame",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CandidatePublicationControlFrameError {}

impl From<CandidatePublicationWireError> for CandidatePublicationControlFrameError {
    fn from(_: CandidatePublicationWireError) -> Self {
        Self::InvalidPublicationPayload
    }
}

impl From<ControlFrameError> for CandidatePublicationControlFrameError {
    fn from(_: ControlFrameError) -> Self {
        Self::InvalidControlFrame
    }
}

/// Wraps one already-typed BQ submission in the BR-selected Phase 129 Command envelope.
///
/// `request_id` is caller-supplied outer correlation only. This function does not allocate,
/// authorize, persist, route, or assign lifecycle semantics to it.
///
/// # Errors
///
/// Returns [`CandidatePublicationControlFrameError::InvalidControlFrame`] when the existing
/// Phase 129 constructor rejects the supplied request ID or payload.
pub fn encode_candidate_publication_control_frame(
    submission: &CandidatePublicationWireSubmission,
    request_id: u64,
) -> Result<ControlFrame, CandidatePublicationControlFrameError> {
    ControlFrame::new(ControlMessageKind::Command, request_id, submission.encode())
        .map_err(Into::into)
}

/// Decodes one already-parsed Phase 129 frame as a candidate-publication Command.
///
/// Successful return proves only outer-kind correctness plus BQ structural/type decoding. It does
/// not authenticate a publisher, authorize routing, validate publication freshness, or commit
/// reachability state.
///
/// # Errors
///
/// Rejects non-Command frames and malformed PRWP payloads.
pub fn decode_candidate_publication_control_frame(
    frame: &ControlFrame,
) -> Result<CandidatePublicationControlFrame, CandidatePublicationControlFrameError> {
    if frame.kind() != ControlMessageKind::Command {
        return Err(CandidatePublicationControlFrameError::WrongMessageKind);
    }

    let submission = CandidatePublicationWireSubmission::decode(frame.payload())?;
    Ok(CandidatePublicationControlFrame {
        request_id: frame.request_id(),
        submission,
    })
}

#[cfg(test)]
mod tests {
    use prw_connectivity::TransportIdentity;
    use prw_control_transport::{ControlFrame, ControlMessageKind};

    use crate::{
        candidate_publication_freshness::CandidatePublicationFreshnessToken,
        candidate_publication_wire::CandidatePublicationWireSubmission,
    };

    use super::{
        CandidatePublicationControlFrameError, decode_candidate_publication_control_frame,
        encode_candidate_publication_control_frame,
    };

    fn submission() -> CandidatePublicationWireSubmission {
        CandidatePublicationWireSubmission::new(
            TransportIdentity::new([0x11; 32]).expect("non-zero transport identity"),
            CandidatePublicationFreshnessToken::new([0x22; 32]).expect("non-zero freshness"),
            Vec::new(),
        )
        .expect("empty candidate set is bounded")
    }

    #[test]
    fn encode_uses_command_and_preserves_outer_request_id_and_prwp_payload() {
        let submission = submission();
        let expected_payload = submission.encode();
        let frame = encode_candidate_publication_control_frame(&submission, 17)
            .expect("valid correlation must compose");

        assert_eq!(frame.kind(), ControlMessageKind::Command);
        assert_eq!(frame.request_id(), 17);
        assert_eq!(frame.payload(), expected_payload);
    }

    #[test]
    fn decode_preserves_outer_request_id_and_typed_submission() {
        let submission = submission();
        let frame = ControlFrame::new(ControlMessageKind::Command, 23, submission.encode())
            .expect("valid command frame");
        let decoded =
            decode_candidate_publication_control_frame(&frame).expect("valid PRWP command");

        assert_eq!(decoded.request_id(), 23);
        assert_eq!(decoded.submission(), &submission);
    }

    #[test]
    fn decode_rejects_wrong_outer_kind() {
        let frame = ControlFrame::new(ControlMessageKind::Event, 31, submission().encode())
            .expect("valid generic event frame");

        assert_eq!(
            decode_candidate_publication_control_frame(&frame),
            Err(CandidatePublicationControlFrameError::WrongMessageKind)
        );
    }

    #[test]
    fn decode_classifies_malformed_prwp_payload() {
        let frame = ControlFrame::new(ControlMessageKind::Command, 41, vec![0_u8; 80])
            .expect("generic frame accepts bounded bytes");

        assert_eq!(
            decode_candidate_publication_control_frame(&frame),
            Err(CandidatePublicationControlFrameError::InvalidPublicationPayload)
        );
    }

    #[test]
    fn encode_rejects_zero_outer_request_id_through_existing_control_frame_contract() {
        assert_eq!(
            encode_candidate_publication_control_frame(&submission(), 0),
            Err(CandidatePublicationControlFrameError::InvalidControlFrame)
        );
    }
}
