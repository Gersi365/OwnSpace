//! Bounded logical-session challenge/proof wire adapter over PRWM.
//!
//! This module serializes the existing Phase 128 session-authentication values into the
//! already-reserved PRWM `SessionAuthentication` message kind. It does not authenticate a
//! transport peer, create a remote-session lease, evaluate policy, or grant capabilities.

use std::fmt;

use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentitySignature, DeviceIdentitySignatureEncoding,
    session_auth::{
        MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS, MAX_SESSION_AUTH_IDENTIFIER_BYTES,
        SESSION_AUTH_NONCE_LEN, SessionAuthChallenge, SessionAuthNonce, SessionAuthProof,
    },
};
use prw_remote_transport::{
    ControlFrame, ControlMessageKind, RemoteTransportError,
    runtime::{MeshControlStream, MeshQuicRuntimeError},
};

/// C03d logical-session wire magic inside a PRWM `SessionAuthentication` payload.
pub const SESSION_AUTH_WIRE_MAGIC: [u8; 4] = *b"PRWS";
/// Initial logical-session wire major version.
pub const SESSION_AUTH_WIRE_MAJOR: u16 = 1;
/// Initial logical-session wire minor version.
pub const SESSION_AUTH_WIRE_MINOR: u16 = 0;
/// Fixed PRWS header bytes before the message body.
pub const SESSION_AUTH_WIRE_HEADER_BYTES: usize = 12;
/// Conservative bound for one locked P-256 ASN.1 DER signature value.
pub const MAX_SESSION_AUTH_WIRE_SIGNATURE_BYTES: usize = 256;

const CHALLENGE_KIND: u16 = 1;
const PROOF_KIND: u16 = 2;

/// Failure at the C03d session-authentication wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionAuthenticationWireError {
    /// The outer PRWM frame was not the reserved `SessionAuthentication` kind.
    InvalidOuterKind,
    /// PRWS structure, bounds, UTF-8, lifetime, identifier, or trailing data were invalid.
    InvalidPayload,
    /// A proof used a device-signature profile other than the locked Phase 128 profile.
    UnsupportedSignatureProfile,
    /// PRWM frame construction failed.
    Frame(RemoteTransportError),
    /// Real QUIC stream I/O failed.
    Runtime(MeshQuicRuntimeError),
}

impl fmt::Display for SessionAuthenticationWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOuterKind => "invalid outer PRWM kind for session authentication",
            Self::InvalidPayload => "invalid logical-session authentication wire payload",
            Self::UnsupportedSignatureProfile => "unsupported logical-session signature profile",
            Self::Frame(_) => "failed to construct logical-session PRWM frame",
            Self::Runtime(_) => "logical-session QUIC stream I/O failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionAuthenticationWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RemoteTransportError> for SessionAuthenticationWireError {
    fn from(error: RemoteTransportError) -> Self {
        Self::Frame(error)
    }
}

impl From<MeshQuicRuntimeError> for SessionAuthenticationWireError {
    fn from(error: MeshQuicRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// Transport representation of one server-issued Phase 128 challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticationWireChallenge {
    session_id: String,
    nonce: SessionAuthNonce,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl SessionAuthenticationWireChallenge {
    /// Copies the public challenge fields from one typed server challenge.
    #[must_use]
    pub fn from_typed(challenge: &SessionAuthChallenge) -> Self {
        Self {
            session_id: challenge.session_id().as_str().to_owned(),
            nonce: challenge.nonce(),
            issued_at_unix_seconds: challenge.issued_at_unix_seconds(),
            expires_at_unix_seconds: challenge.expires_at_unix_seconds(),
        }
    }

    /// Returns the bounded UTF-8 session identifier carried on the wire.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the exact challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> SessionAuthNonce {
        self.nonce
    }

    /// Returns the verifier-owned issue time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the verifier-owned expiry time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Transport representation of one Phase 128 device proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticationWireProof {
    session_id: String,
    nonce: SessionAuthNonce,
    signature: DeviceIdentitySignature,
}

impl SessionAuthenticationWireProof {
    /// Copies the public proof fields from one typed Phase 128 proof.
    #[must_use]
    pub fn from_typed(proof: &SessionAuthProof) -> Self {
        Self {
            session_id: proof.session_id().as_str().to_owned(),
            nonce: proof.nonce(),
            signature: proof.signature().clone(),
        }
    }

    /// Returns the bounded UTF-8 session identifier carried on the wire.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the submitted challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> SessionAuthNonce {
        self.nonce
    }

    /// Returns the locked-profile device signature.
    #[must_use]
    pub const fn signature(&self) -> &DeviceIdentitySignature {
        &self.signature
    }
}

/// One decoded PRWS v1 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAuthenticationWireMessage {
    /// Server-issued challenge fields.
    Challenge(SessionAuthenticationWireChallenge),
    /// Client device-identity proof fields.
    Proof(SessionAuthenticationWireProof),
}

/// Encodes one PRWS message inside the reserved PRWM `SessionAuthentication` envelope.
///
/// # Errors
///
/// Rejects invalid identifier/signature bounds, an unsupported proof signature profile, or
/// invalid PRWM request identifiers.
pub fn encode_session_authentication_frame(
    request_id: u64,
    message: &SessionAuthenticationWireMessage,
) -> Result<ControlFrame, SessionAuthenticationWireError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&SESSION_AUTH_WIRE_MAGIC);
    payload.extend_from_slice(&SESSION_AUTH_WIRE_MAJOR.to_be_bytes());
    payload.extend_from_slice(&SESSION_AUTH_WIRE_MINOR.to_be_bytes());

    match message {
        SessionAuthenticationWireMessage::Challenge(challenge) => {
            payload.extend_from_slice(&CHALLENGE_KIND.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            push_session_id(&mut payload, challenge.session_id())?;
            payload.extend_from_slice(challenge.nonce().as_bytes());
            payload.extend_from_slice(&challenge.issued_at_unix_seconds().to_be_bytes());
            payload.extend_from_slice(&challenge.expires_at_unix_seconds().to_be_bytes());
            validate_lifetime(
                challenge.issued_at_unix_seconds(),
                challenge.expires_at_unix_seconds(),
            )?;
        }
        SessionAuthenticationWireMessage::Proof(proof) => {
            if proof.signature().algorithm() != DeviceIdentityAlgorithm::EcdsaP256Sha256
                || proof.signature().encoding() != DeviceIdentitySignatureEncoding::EcdsaSigValueDer
            {
                return Err(SessionAuthenticationWireError::UnsupportedSignatureProfile);
            }
            let signature = proof.signature().as_bytes();
            if signature.is_empty() || signature.len() > MAX_SESSION_AUTH_WIRE_SIGNATURE_BYTES {
                return Err(SessionAuthenticationWireError::InvalidPayload);
            }
            payload.extend_from_slice(&PROOF_KIND.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            push_session_id(&mut payload, proof.session_id())?;
            payload.extend_from_slice(proof.nonce().as_bytes());
            push_u16_len(&mut payload, signature)?;
        }
    }

    ControlFrame::new(
        ControlMessageKind::SessionAuthentication,
        request_id,
        payload,
    )
    .map_err(SessionAuthenticationWireError::Frame)
}

/// Decodes one bounded PRWS message from the reserved PRWM `SessionAuthentication` envelope.
///
/// # Errors
///
/// Rejects a wrong outer kind, malformed header, unsupported version/message kind, non-zero flags,
/// invalid bounds/UTF-8/profile, truncation, lifetime violations, and trailing data.
pub fn decode_session_authentication_frame(
    frame: &ControlFrame,
) -> Result<SessionAuthenticationWireMessage, SessionAuthenticationWireError> {
    if frame.kind() != ControlMessageKind::SessionAuthentication {
        return Err(SessionAuthenticationWireError::InvalidOuterKind);
    }
    let mut decoder = Decoder::new(frame.payload());
    if decoder.take(4)? != SESSION_AUTH_WIRE_MAGIC.as_slice()
        || decoder.u16()? != SESSION_AUTH_WIRE_MAJOR
        || decoder.u16()? != SESSION_AUTH_WIRE_MINOR
    {
        return Err(SessionAuthenticationWireError::InvalidPayload);
    }
    let kind = decoder.u16()?;
    if decoder.u16()? != 0 {
        return Err(SessionAuthenticationWireError::InvalidPayload);
    }

    let message = match kind {
        CHALLENGE_KIND => {
            let session_id = decoder.session_id()?;
            let nonce = SessionAuthNonce::try_from_slice(decoder.take(SESSION_AUTH_NONCE_LEN)?)
                .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
            let issued_at_unix_seconds = decoder.u64()?;
            let expires_at_unix_seconds = decoder.u64()?;
            validate_lifetime(issued_at_unix_seconds, expires_at_unix_seconds)?;
            SessionAuthenticationWireMessage::Challenge(SessionAuthenticationWireChallenge {
                session_id,
                nonce,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            })
        }
        PROOF_KIND => {
            let session_id = decoder.session_id()?;
            let nonce = SessionAuthNonce::try_from_slice(decoder.take(SESSION_AUTH_NONCE_LEN)?)
                .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
            let signature_len = usize::from(decoder.u16()?);
            if signature_len == 0 || signature_len > MAX_SESSION_AUTH_WIRE_SIGNATURE_BYTES {
                return Err(SessionAuthenticationWireError::InvalidPayload);
            }
            let signature = DeviceIdentitySignature::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
                decoder.take(signature_len)?.to_vec(),
            )
            .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
            SessionAuthenticationWireMessage::Proof(SessionAuthenticationWireProof {
                session_id,
                nonce,
                signature,
            })
        }
        _ => return Err(SessionAuthenticationWireError::InvalidPayload),
    };
    decoder.finish()?;
    Ok(message)
}

/// Sends one complete PRWS message over one C03c QUIC stream direction.
///
/// # Errors
///
/// Propagates PRWS encoding and bounded QUIC stream write failures.
pub async fn send_session_authentication_message(
    stream: &mut MeshControlStream,
    request_id: u64,
    message: &SessionAuthenticationWireMessage,
) -> Result<(), SessionAuthenticationWireError> {
    let frame = encode_session_authentication_frame(request_id, message)?;
    stream.send_frame(&frame).await?;
    Ok(())
}

/// Receives one complete PRWS message from one C03c QUIC stream direction.
///
/// # Errors
///
/// Propagates bounded QUIC stream read failures and PRWS decode failures.
pub async fn receive_session_authentication_message(
    stream: &mut MeshControlStream,
) -> Result<(u64, SessionAuthenticationWireMessage), SessionAuthenticationWireError> {
    let frame = stream.receive_frame().await?;
    let request_id = frame.request_id();
    let message = decode_session_authentication_frame(&frame)?;
    Ok((request_id, message))
}

fn push_session_id(
    output: &mut Vec<u8>,
    session_id: &str,
) -> Result<(), SessionAuthenticationWireError> {
    validate_session_id(session_id)?;
    push_u16_len(output, session_id.as_bytes())
}

fn push_u16_len(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SessionAuthenticationWireError> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_session_id(value: &str) -> Result<(), SessionAuthenticationWireError> {
    let len = value.len();
    if len == 0 || len > MAX_SESSION_AUTH_IDENTIFIER_BYTES || value.trim().is_empty() {
        return Err(SessionAuthenticationWireError::InvalidPayload);
    }
    Ok(())
}

fn validate_lifetime(
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<(), SessionAuthenticationWireError> {
    let lifetime = expires_at_unix_seconds
        .checked_sub(issued_at_unix_seconds)
        .ok_or(SessionAuthenticationWireError::InvalidPayload)?;
    if lifetime == 0 || lifetime > MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS {
        return Err(SessionAuthenticationWireError::InvalidPayload);
    }
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SessionAuthenticationWireError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(SessionAuthenticationWireError::InvalidPayload)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(SessionAuthenticationWireError::InvalidPayload)?;
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, SessionAuthenticationWireError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SessionAuthenticationWireError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn session_id(&mut self) -> Result<String, SessionAuthenticationWireError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_SESSION_AUTH_IDENTIFIER_BYTES {
            return Err(SessionAuthenticationWireError::InvalidPayload);
        }
        let value = std::str::from_utf8(self.take(len)?)
            .map_err(|_| SessionAuthenticationWireError::InvalidPayload)?;
        validate_session_id(value)?;
        Ok(value.to_owned())
    }

    const fn finish(self) -> Result<(), SessionAuthenticationWireError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(SessionAuthenticationWireError::InvalidPayload)
        }
    }
}
