//! Bridge-owned post-authenticated single-read control-stream family ingress.
//!
//! C03e-ET materializes only the C03e-ES-selected one-read family-custody boundary on one already
//! accepted authenticated control stream. The bridge reads exactly one bounded PRWM frame, routes an
//! exact `PRWZ` payload prefix through the existing strict requester/rendezvous decoder, and preserves
//! every other frame plus the same stream as capability transaction custody. C03e-EZ extends only the
//! requester/rendezvous typed outcome so the strict decoded request retains the exact same stream for
//! separately gated requester continuation. C03e-FF adds only the C03e-FE-selected consuming
//! same-stream send surface for one already-constructed requester/rendezvous DR acknowledgement.
//! C03e-GE extends only the C03e-GD-selected family/custody boundary: exact `PRWP` payload prefix now
//! routes through a current-Mesh `Request` adapter backed by the existing pure PRWP payload decoder
//! and retains the decoded candidate request plus that exact same stream in bridge-owned custody.
//! This module does not accept another stream, authenticate a session, authorize a capability,
//! execute requester or candidate policy/provider logic, construct requester/candidate response
//! semantics, retry I/O, close a peer, select candidates, mutate reachability, dial traffic, resume a
//! loop/listener, or deploy anything.

use std::fmt;

use prw_remote_transport::{
    ControlFrame, ControlMessageKind,
    runtime::{MeshControlStream, MeshQuicRuntimeError},
};

use crate::{
    candidate_publication_wire::{
        CANDIDATE_PUBLICATION_WIRE_MAGIC, CandidatePublicationWireError,
        CandidatePublicationWireSubmission,
    },
    capability_request_wire::{CapabilityRequestWireError, send_capability_response_frame},
    requester_rendezvous_target_request_wire::{
        REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC, RequesterRendezvousTargetWireError,
        RequesterRendezvousTargetWireRequest, decode_requester_rendezvous_target_request_frame,
    },
};

/// One strict requester/rendezvous transaction retaining exact same-stream response custody.
pub struct PostAuthRequesterRendezvousTransaction {
    request: RequesterRendezvousTargetWireRequest,
    stream: MeshControlStream,
}

/// Failure while sending one already-constructed requester/rendezvous DR acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousDrAcknowledgementResponseIoError {
    /// Existing bounded PRWM stream write or send-direction finish failed.
    Runtime(MeshQuicRuntimeError),
}

impl fmt::Display for RequesterRendezvousDrAcknowledgementResponseIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(_) => {
                formatter.write_str("requester rendezvous DR acknowledgement response I/O failed")
            }
        }
    }
}

impl std::error::Error for RequesterRendezvousDrAcknowledgementResponseIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for RequesterRendezvousDrAcknowledgementResponseIoError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl PostAuthRequesterRendezvousTransaction {
    /// Borrows the exact strict requester/rendezvous request decoded from this retained stream.
    #[must_use]
    pub const fn request(&self) -> &RequesterRendezvousTargetWireRequest {
        &self.request
    }

    /// Transfers the exact strict decoded request and exact same already-accepted stream by value.
    ///
    /// This is custody transfer only. It performs no response construction/write, second read,
    /// retry, close, requester/provider authority, target resolution, candidate selection or dialing.
    #[must_use]
    pub fn into_parts(self) -> (RequesterRendezvousTargetWireRequest, MeshControlStream) {
        (self.request, self.stream)
    }

    /// Consumes this requester/rendezvous custody envelope and sends exactly one already-constructed
    /// DR acknowledgement frame on the exact same retained control stream.
    ///
    /// The caller must supply the frame already materialized by the requester/rendezvous DR
    /// acknowledgement framing boundary. This method does not inspect or reconstruct DR semantics,
    /// alter correlation, validate a second request, retry, return stream custody, close the peer, or
    /// resume repeated ingress. The lower stream write finishes the QUIC send direction.
    ///
    /// # Errors
    ///
    /// Preserves the existing bounded stream write/finish/timeout failure under the requester-specific
    /// response-I/O classification. A failure consumes this local transaction custody and is not a
    /// semantic requester rejection.
    pub async fn send_dr_acknowledgement_frame(
        self,
        acknowledgement_frame: &ControlFrame,
    ) -> Result<(), RequesterRendezvousDrAcknowledgementResponseIoError> {
        let Self { mut stream, .. } = self;
        stream
            .send_frame(acknowledgement_frame)
            .await
            .map_err(Into::into)
    }
}

/// Structurally valid current-Mesh candidate-publication request plus exact outer correlation.
///
/// This value proves only current-Mesh outer-kind validity plus pure bounded PRWP decoding. It is
/// not publisher identity, requester authority, freshness currentness, reachability authority, or
/// durable commit authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePublicationMeshRequest {
    request_id: u64,
    submission: CandidatePublicationWireSubmission,
}

impl CandidatePublicationMeshRequest {
    /// Returns the exact non-zero outer PRWM request correlation value.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Borrows the exact pure PRWP submission decoded from this current-Mesh request.
    #[must_use]
    pub const fn submission(&self) -> &CandidatePublicationWireSubmission {
        &self.submission
    }

    /// Transfers ownership of the exact decoded PRWP submission without reinterpretation.
    #[must_use]
    pub fn into_submission(self) -> CandidatePublicationWireSubmission {
        self.submission
    }
}

/// Strict current-Mesh candidate-publication request decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationMeshRequestError {
    /// The outer PRWM frame was not the current-Mesh peer-operation `Request` kind.
    InvalidOuterKind,
    /// The existing pure bounded PRWP payload decoder rejected the payload.
    Wire(CandidatePublicationWireError),
}

impl fmt::Display for CandidatePublicationMeshRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOuterKind => {
                "invalid outer PRWM kind for current-Mesh candidate publication"
            }
            Self::Wire(_) => "invalid current-Mesh candidate-publication PRWP payload",
        })
    }
}

impl std::error::Error for CandidatePublicationMeshRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidOuterKind => None,
            Self::Wire(error) => Some(error),
        }
    }
}

impl From<CandidatePublicationWireError> for CandidatePublicationMeshRequestError {
    fn from(error: CandidatePublicationWireError) -> Self {
        Self::Wire(error)
    }
}

/// One strict current-Mesh candidate-publication request retaining exact same-stream custody.
pub struct PostAuthCandidatePublicationTransaction {
    request: CandidatePublicationMeshRequest,
    stream: MeshControlStream,
}

impl PostAuthCandidatePublicationTransaction {
    /// Borrows the exact strict current-Mesh candidate-publication request decoded from this stream.
    #[must_use]
    pub const fn request(&self) -> &CandidatePublicationMeshRequest {
        &self.request
    }

    /// Transfers the exact strict decoded request and exact same already-accepted stream by value.
    ///
    /// This is custody transfer only. It performs no semantic execution, response composition/write,
    /// second read, retry, close, requester authority, reachability-owner recovery, commit, or dialing.
    #[must_use]
    pub fn into_parts(self) -> (CandidatePublicationMeshRequest, MeshControlStream) {
        (self.request, self.stream)
    }
}

/// One already-read capability transaction that retains same-stream response custody.
pub struct PostAuthCapabilityTransaction {
    request_frame: ControlFrame,
    stream: MeshControlStream,
}

impl PostAuthCapabilityTransaction {
    /// Borrows the exact already-received bounded PRWM frame for the existing capability bridge.
    #[must_use]
    pub const fn request_frame(&self) -> &ControlFrame {
        &self.request_frame
    }

    /// Consumes this custody envelope and sends exactly one already-constructed capability response
    /// through the existing bridge-owned response adapter on the same control stream.
    ///
    /// # Errors
    ///
    /// Preserves the existing bounded capability response I/O failure classification.
    pub async fn send_response_frame(
        self,
        response_frame: &ControlFrame,
    ) -> Result<(), CapabilityRequestWireError> {
        let Self { mut stream, .. } = self;
        send_capability_response_frame(&mut stream, response_frame).await
    }
}

/// Typed result of one bridge-owned post-authenticated control-stream read and family selection.
pub enum PostAuthControlStreamIngress {
    /// Exact `PRWZ` prefix was observed, strict decode passed, and same-stream custody is retained.
    RequesterRendezvous(PostAuthRequesterRendezvousTransaction),
    /// Exact `PRWP` prefix was observed, strict Mesh decode passed, and same-stream custody remains.
    CandidatePublication(PostAuthCandidatePublicationTransaction),
    /// Any non-`PRWZ`, non-`PRWP` frame remains on capability with same-stream custody retained.
    Capability(PostAuthCapabilityTransaction),
}

/// Failure while materializing one post-authenticated single-read family ingress result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PostAuthControlStreamIngressError {
    /// Existing bounded PRWM stream/frame receive failed.
    Runtime(MeshQuicRuntimeError),
    /// Exact `PRWZ` prefix selected requester/rendezvous, but strict PRWZ semantics failed.
    RequesterRendezvousWire(RequesterRendezvousTargetWireError),
    /// Exact `PRWP` prefix selected candidate publication, but strict Mesh/PRWP semantics failed.
    CandidatePublicationWire(CandidatePublicationMeshRequestError),
}

impl fmt::Display for PostAuthControlStreamIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime(_) => "post-authenticated control-stream receive failed",
            Self::RequesterRendezvousWire(_) => {
                "post-authenticated requester/rendezvous wire decode failed"
            }
            Self::CandidatePublicationWire(_) => {
                "post-authenticated candidate-publication request decode failed"
            }
        })
    }
}

impl std::error::Error for PostAuthControlStreamIngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::RequesterRendezvousWire(error) => Some(error),
            Self::CandidatePublicationWire(error) => Some(error),
        }
    }
}

impl From<MeshQuicRuntimeError> for PostAuthControlStreamIngressError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RequesterRendezvousTargetWireError> for PostAuthControlStreamIngressError {
    fn from(error: RequesterRendezvousTargetWireError) -> Self {
        Self::RequesterRendezvousWire(error)
    }
}

impl From<CandidatePublicationMeshRequestError> for PostAuthControlStreamIngressError {
    fn from(error: CandidatePublicationMeshRequestError) -> Self {
        Self::CandidatePublicationWire(error)
    }
}

/// Reads exactly one bounded PRWM frame from one already-accepted authenticated control stream and
/// returns one typed family-custody result.
///
/// Routing is deliberately ordered and legacy-preserving: exact first-four-byte `PRWZ` selects the
/// existing strict requester/rendezvous codec; otherwise exact first-four-byte `PRWP` selects the
/// current-Mesh candidate-publication request adapter; every other bounded PRWM frame, including
/// short, unknown, malformed or `PRWC` payloads, remains on the existing capability path. Prefix
/// recognition is only family selection and grants no authentication, authorization, target
/// eligibility, publisher identity, requester authority, freshness, reachability-owner, commit,
/// candidate or rendezvous-success authority.
///
/// The stream is consumed by value so lower transport custody cannot remain simultaneously with the
/// caller. Capability, requester/rendezvous, and candidate-publication successful outcomes each retain
/// the exact same already-accepted stream in exactly one bridge-owned typed custody envelope.
///
/// # Errors
///
/// Preserves one bounded stream receive failure as [`PostAuthControlStreamIngressError::Runtime`].
/// Exact `PRWZ` strict-decoder failure is preserved as
/// [`PostAuthControlStreamIngressError::RequesterRendezvousWire`]. Exact `PRWP` current-Mesh strict
/// decode failure is preserved as [`PostAuthControlStreamIngressError::CandidatePublicationWire`].
/// Once either exact prefix selects a family, no fallback decode, retry, second read, response write
/// or peer close is performed by this receive operation.
pub async fn receive_post_auth_control_stream_ingress(
    mut stream: MeshControlStream,
) -> Result<PostAuthControlStreamIngress, PostAuthControlStreamIngressError> {
    let frame = stream.receive_frame().await?;
    if is_requester_rendezvous_family(&frame) {
        let request = decode_requester_rendezvous_target_request_frame(&frame)?;
        return Ok(PostAuthControlStreamIngress::RequesterRendezvous(
            PostAuthRequesterRendezvousTransaction { request, stream },
        ));
    }
    if is_candidate_publication_family(&frame) {
        let request = decode_candidate_publication_mesh_request_frame(&frame)?;
        return Ok(PostAuthControlStreamIngress::CandidatePublication(
            PostAuthCandidatePublicationTransaction { request, stream },
        ));
    }

    Ok(PostAuthControlStreamIngress::Capability(
        PostAuthCapabilityTransaction {
            request_frame: frame,
            stream,
        },
    ))
}

fn decode_candidate_publication_mesh_request_frame(
    frame: &ControlFrame,
) -> Result<CandidatePublicationMeshRequest, CandidatePublicationMeshRequestError> {
    if frame.kind() != ControlMessageKind::Request {
        return Err(CandidatePublicationMeshRequestError::InvalidOuterKind);
    }
    let submission = CandidatePublicationWireSubmission::decode(frame.payload())?;
    Ok(CandidatePublicationMeshRequest {
        request_id: frame.request_id(),
        submission,
    })
}

fn is_requester_rendezvous_family(frame: &ControlFrame) -> bool {
    frame
        .payload()
        .starts_with(REQUESTER_RENDEZVOUS_TARGET_REQUEST_WIRE_MAGIC.as_slice())
}

fn is_candidate_publication_family(frame: &ControlFrame) -> bool {
    frame
        .payload()
        .starts_with(CANDIDATE_PUBLICATION_WIRE_MAGIC.as_slice())
}

#[cfg(test)]
mod tests {
    use prw_remote_transport::{
        ControlFrame, ControlMessageKind,
        runtime::{MeshControlStream, MeshQuicRuntimeError},
    };

    use super::{
        CandidatePublicationMeshRequest, CandidatePublicationMeshRequestError,
        PostAuthCandidatePublicationTransaction, PostAuthRequesterRendezvousTransaction,
        RequesterRendezvousDrAcknowledgementResponseIoError,
        decode_candidate_publication_mesh_request_frame, is_candidate_publication_family,
        is_requester_rendezvous_family, receive_post_auth_control_stream_ingress,
    };
    use crate::{
        candidate_publication_wire::{
            CANDIDATE_PUBLICATION_WIRE_MAGIC, CandidatePublicationWireError,
        },
        requester_rendezvous_target_request_wire::{
            RequesterRendezvousTargetWireError, RequesterRendezvousTargetWireRequest,
            decode_requester_rendezvous_target_request_frame,
        },
    };

    fn frame(kind: ControlMessageKind, payload: &[u8]) -> ControlFrame {
        ControlFrame::new(kind, 17, payload.to_vec()).expect("bounded test frame must be valid")
    }

    fn valid_candidate_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAGIC);
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&[0x41; 32]);
        payload.extend_from_slice(&[0x51; 32]);
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload
    }

    fn assert_requester_custody_transfer_signature(
        transfer: fn(
            PostAuthRequesterRendezvousTransaction,
        ) -> (RequesterRendezvousTargetWireRequest, MeshControlStream),
    ) {
        let _ = transfer;
    }

    fn assert_candidate_custody_transfer_signature(
        transfer: fn(
            PostAuthCandidatePublicationTransaction,
        ) -> (CandidatePublicationMeshRequest, MeshControlStream),
    ) {
        let _ = transfer;
    }

    #[test]
    fn ingress_surface_exposes_only_one_stream_consuming_receive_operation() {
        let _ = receive_post_auth_control_stream_ingress;
        assert_requester_custody_transfer_signature(
            PostAuthRequesterRendezvousTransaction::into_parts,
        );
        assert_candidate_custody_transfer_signature(
            PostAuthCandidatePublicationTransaction::into_parts,
        );
    }

    #[test]
    fn requester_dr_acknowledgement_send_surface_is_consuming_and_requester_specific() {
        let _ = PostAuthRequesterRendezvousTransaction::send_dr_acknowledgement_frame;
        let error = MeshQuicRuntimeError::WriteFrame;
        assert_eq!(
            RequesterRendezvousDrAcknowledgementResponseIoError::from(error),
            RequesterRendezvousDrAcknowledgementResponseIoError::Runtime(error)
        );
    }

    #[test]
    fn classifier_preserves_prwz_then_prwp_then_capability_partition() {
        let requester = frame(ControlMessageKind::Request, b"PRWZ");
        assert!(is_requester_rendezvous_family(&requester));
        assert!(!is_candidate_publication_family(&requester));

        let candidate = frame(ControlMessageKind::Request, b"PRWP");
        assert!(!is_requester_rendezvous_family(&candidate));
        assert!(is_candidate_publication_family(&candidate));

        for payload in [b"PRWC".as_slice(), b"PRW".as_slice(), b"ABCD".as_slice()] {
            let fallback = frame(ControlMessageKind::Request, payload);
            assert!(!is_requester_rendezvous_family(&fallback));
            assert!(!is_candidate_publication_family(&fallback));
        }
    }

    #[test]
    fn requester_family_recognition_does_not_replace_strict_prwz_validation() {
        let candidate = frame(ControlMessageKind::Event, b"PRWZ");
        assert!(is_requester_rendezvous_family(&candidate));
        assert_eq!(
            decode_requester_rendezvous_target_request_frame(&candidate),
            Err(RequesterRendezvousTargetWireError::InvalidOuterKind)
        );
    }

    #[test]
    fn candidate_family_recognition_requires_current_mesh_request_kind() {
        let candidate = frame(ControlMessageKind::Event, b"PRWP");
        assert!(is_candidate_publication_family(&candidate));
        assert_eq!(
            decode_candidate_publication_mesh_request_frame(&candidate),
            Err(CandidatePublicationMeshRequestError::InvalidOuterKind)
        );
    }

    #[test]
    fn candidate_family_recognition_still_requires_strict_prwp_payload_decode() {
        let candidate = frame(ControlMessageKind::Request, b"PRWP");
        assert!(is_candidate_publication_family(&candidate));
        assert_eq!(
            decode_candidate_publication_mesh_request_frame(&candidate),
            Err(CandidatePublicationMeshRequestError::Wire(
                CandidatePublicationWireError::InvalidPayload
            ))
        );
    }

    #[test]
    fn current_mesh_candidate_decode_preserves_request_id_and_submission() {
        let candidate = frame(ControlMessageKind::Request, &valid_candidate_payload());
        let decoded = decode_candidate_publication_mesh_request_frame(&candidate)
            .expect("valid current-Mesh candidate request must decode");
        assert_eq!(decoded.request_id(), 17);
        assert!(decoded.submission().candidates().is_empty());
    }
}
