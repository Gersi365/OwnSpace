//! Candidate-publication current-Mesh same-stream terminal-response custody.
//!
//! C03e-GO materializes only the C03e-GN-selected consuming response-custody primitive on the
//! existing bridge-owned [`PostAuthCandidatePublicationTransaction`]. The higher owner must supply one
//! already-composed current-Mesh [`ControlFrame`]. This module verifies exact retained request
//! correlation before any stream I/O, then delegates one bounded write + send-direction finish to the
//! existing `MeshControlStream::send_frame(...)` seam. It does not construct candidate semantics,
//! reparse terminal payloads, retry, reconnect, reopen a stream, close a peer, resume ingress, activate
//! candidate execution, populate reachability owners, dial, listen, publish readiness, or deploy.

use std::fmt;

use prw_remote_transport::{ControlFrame, runtime::MeshQuicRuntimeError};

use crate::post_auth_control_stream_ingress::PostAuthCandidatePublicationTransaction;

/// Failure while consuming one candidate transaction to send one already-composed terminal frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationTerminalResponseIoError {
    /// The supplied response frame does not echo the exact retained current-Mesh request correlation.
    CorrelationMismatch,
    /// Existing bounded current-Mesh stream write or send-direction finish failed.
    Runtime(MeshQuicRuntimeError),
}

impl fmt::Display for CandidatePublicationTerminalResponseIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CorrelationMismatch => {
                "candidate-publication terminal response correlation mismatch"
            }
            Self::Runtime(_) => "candidate-publication terminal response I/O failed",
        })
    }
}

impl std::error::Error for CandidatePublicationTerminalResponseIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CorrelationMismatch => None,
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for CandidatePublicationTerminalResponseIoError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl PostAuthCandidatePublicationTransaction {
    /// Consumes this exact candidate transaction and sends one already-composed terminal frame on the
    /// exact same retained current-Mesh control stream.
    ///
    /// The supplied frame must carry exactly the request ID retained by this transaction. Request ID
    /// equality is transaction-lineage correlation only and grants no identity, requester, owner,
    /// freshness, candidate-admission or durable-commit authority. The frame payload/kind is not
    /// reparsed or rebuilt here. On exact correlation, the existing lower stream primitive performs
    /// exactly one bounded write and finishes the QUIC send direction.
    ///
    /// This consuming seam returns no stream custody and performs no retry, fallback frame,
    /// reconstruction, semantic replay, reconnect, alternate stream open/accept, peer close or loop
    /// continuation on either correlation mismatch or runtime failure.
    ///
    /// # Errors
    ///
    /// Returns [`CandidatePublicationTerminalResponseIoError::CorrelationMismatch`] before any stream
    /// I/O when the supplied frame does not echo the exact retained request ID. Existing bounded
    /// stream write/finish/timeout failure is preserved under
    /// [`CandidatePublicationTerminalResponseIoError::Runtime`].
    pub async fn send_terminal_response_frame(
        self,
        response_frame: &ControlFrame,
    ) -> Result<(), CandidatePublicationTerminalResponseIoError> {
        let (request, mut stream) = self.into_parts();
        validate_terminal_response_correlation(request.request_id(), response_frame)?;
        stream.send_frame(response_frame).await.map_err(Into::into)
    }
}

const fn validate_terminal_response_correlation(
    expected_request_id: u64,
    response_frame: &ControlFrame,
) -> Result<(), CandidatePublicationTerminalResponseIoError> {
    if response_frame.request_id() != expected_request_id {
        return Err(CandidatePublicationTerminalResponseIoError::CorrelationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::{ControlFrame, ControlMessageKind, runtime::MeshQuicRuntimeError};

    use super::{
        CandidatePublicationTerminalResponseIoError, validate_terminal_response_correlation,
    };
    use crate::post_auth_control_stream_ingress::PostAuthCandidatePublicationTransaction;

    fn response_frame(request_id: u64) -> ControlFrame {
        ControlFrame::new(ControlMessageKind::Response, request_id, vec![0x01])
            .expect("bounded test response frame must be valid")
    }

    #[test]
    fn exact_retained_request_correlation_is_accepted() {
        let frame = response_frame(17);
        assert_eq!(validate_terminal_response_correlation(17, &frame), Ok(()));
    }

    #[test]
    fn mismatched_request_correlation_fails_closed_before_send_seam() {
        let frame = response_frame(18);
        assert_eq!(
            validate_terminal_response_correlation(17, &frame),
            Err(CandidatePublicationTerminalResponseIoError::CorrelationMismatch)
        );
    }

    #[test]
    fn runtime_failure_preserves_candidate_specific_response_io_class() {
        let error = MeshQuicRuntimeError::WriteFrame;
        assert_eq!(
            CandidatePublicationTerminalResponseIoError::from(error),
            CandidatePublicationTerminalResponseIoError::Runtime(error)
        );
    }

    #[test]
    fn candidate_terminal_response_send_surface_is_consuming() {
        let _ = PostAuthCandidatePublicationTransaction::send_terminal_response_frame;
    }
}
