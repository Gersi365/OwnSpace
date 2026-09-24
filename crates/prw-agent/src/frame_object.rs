//! Bounded in-memory local IPC frame objects.
//!
//! Phase 010 couples an already validated Phase 007 header with an owned,
//! bounded payload. It performs no socket I/O and no payload deserialization.

#[allow(
    dead_code,
    reason = "pre-runtime frame-boundary reader is intentionally crate-internal"
)]
pub(crate) mod boundary_reader;
pub mod reader;
pub mod writer;

use std::fmt;

use crate::{LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcFrameHeader};

/// Opaque local IPC payload whose length is within the global control bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIpcPayload {
    bytes: Vec<u8>,
    length: u32,
}

impl LocalIpcPayload {
    /// Creates a bounded opaque payload.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcPayloadError::PayloadTooLarge`] when the byte length
    /// cannot fit the protocol length field or exceeds the Phase 007 1 MiB
    /// global payload limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, LocalIpcPayloadError> {
        let length =
            u32::try_from(bytes.len()).map_err(|_| LocalIpcPayloadError::PayloadTooLarge)?;
        if length > LOCAL_IPC_MAX_PAYLOAD_LENGTH {
            return Err(LocalIpcPayloadError::PayloadTooLarge);
        }

        Ok(Self { bytes, length })
    }

    /// Returns the validated payload length.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.length
    }

    /// Returns whether the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the opaque payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns ownership of the opaque payload bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Invalid in-memory local IPC payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcPayloadError {
    /// Payload length exceeds the global local control-channel limit.
    PayloadTooLarge,
}

impl fmt::Display for LocalIpcPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => {
                formatter.write_str("local IPC payload exceeds maximum length")
            }
        }
    }
}

impl std::error::Error for LocalIpcPayloadError {}

/// One complete validated local IPC frame held in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIpcFrame {
    header: LocalIpcFrameHeader,
    payload: LocalIpcPayload,
}

impl LocalIpcFrame {
    /// Couples validated header metadata with the exact declared payload.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcFrameError::PayloadLengthMismatch`] when the header's
    /// declared payload length differs from the bounded payload's actual length.
    pub fn new(
        header: LocalIpcFrameHeader,
        payload: LocalIpcPayload,
    ) -> Result<Self, LocalIpcFrameError> {
        if header.payload_length() != payload.len() {
            return Err(LocalIpcFrameError::PayloadLengthMismatch {
                declared: header.payload_length(),
                actual: payload.len(),
            });
        }

        Ok(Self { header, payload })
    }

    /// Returns the validated frame header.
    #[must_use]
    pub const fn header(&self) -> LocalIpcFrameHeader {
        self.header
    }

    /// Returns the bounded opaque payload.
    #[must_use]
    pub const fn payload(&self) -> &LocalIpcPayload {
        &self.payload
    }

    /// Splits the frame into its validated header and owned payload.
    #[must_use]
    pub fn into_parts(self) -> (LocalIpcFrameHeader, LocalIpcPayload) {
        (self.header, self.payload)
    }
}

/// Invalid relationship between validated frame metadata and payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIpcFrameError {
    /// Header and actual payload lengths differ.
    PayloadLengthMismatch {
        /// Length declared by the validated frame header.
        declared: u32,
        /// Length of the bounded in-memory payload.
        actual: u32,
    },
}

impl fmt::Display for LocalIpcFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadLengthMismatch { declared, actual } => write!(
                formatter,
                "local IPC payload length mismatch: declared {declared}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for LocalIpcFrameError {}

#[cfg(test)]
mod tests {
    use super::{LocalIpcFrame, LocalIpcFrameError, LocalIpcPayload, LocalIpcPayloadError};
    use crate::{
        LOCAL_IPC_MAX_PAYLOAD_LENGTH, LocalIpcFrameHeader, LocalIpcMessageKind,
        LocalIpcProtocolVersion, LocalIpcRequestId,
    };

    fn header(payload_length: u32) -> LocalIpcFrameHeader {
        LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            LocalIpcRequestId::new(11).expect("non-zero request id"),
            payload_length,
        )
        .expect("valid header")
    }

    #[test]
    fn payload_accepts_global_maximum() {
        let payload = LocalIpcPayload::new(vec![0; 1_048_576]).expect("maximum payload is valid");

        assert_eq!(payload.len(), LOCAL_IPC_MAX_PAYLOAD_LENGTH);
        assert!(!payload.is_empty());
    }

    #[test]
    fn payload_rejects_above_global_maximum() {
        assert_eq!(
            LocalIpcPayload::new(vec![0; 1_048_577]),
            Err(LocalIpcPayloadError::PayloadTooLarge)
        );
    }

    #[test]
    fn complete_frame_requires_exact_payload_length() {
        let payload = LocalIpcPayload::new(vec![1, 2, 3]).expect("bounded payload");
        let frame = LocalIpcFrame::new(header(3), payload).expect("matching frame");

        assert_eq!(frame.header().payload_length(), 3);
        assert_eq!(frame.payload().as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn complete_frame_rejects_payload_length_mismatch() {
        let payload = LocalIpcPayload::new(vec![1, 2, 3]).expect("bounded payload");

        assert_eq!(
            LocalIpcFrame::new(header(2), payload),
            Err(LocalIpcFrameError::PayloadLengthMismatch {
                declared: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn empty_payload_is_valid_when_header_declares_zero() {
        let payload = LocalIpcPayload::new(Vec::new()).expect("empty payload is bounded");
        let frame = LocalIpcFrame::new(header(0), payload).expect("matching empty frame");

        assert!(frame.payload().is_empty());
        let (frame_header, frame_payload) = frame.into_parts();
        assert_eq!(frame_header.payload_length(), 0);
        assert!(frame_payload.into_bytes().is_empty());
    }
}
