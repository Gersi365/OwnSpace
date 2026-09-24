//! Narrow Phase 145 Android/JNI adapter.
//!
//! The unavoidable Rust 2024 unsafe symbol-export attributes are isolated here.
//! This crate contains no unsafe block, private-key import/export, socket ownership,
//! arbitrary command execution, filesystem authority, or production endpoint.

use std::fmt;

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JByteArray, JClass},
    sys::{jboolean, jint},
};
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
    DeviceIdentitySignature, DeviceIdentitySignatureEncoding, EnrollmentRequest,
    PublicIdentityMaterial,
    enrollment_pop::{EnrollmentProofNonce, encode_enrollment_proof_message},
    session_auth::{SessionAuthNonce, encode_session_auth_message},
};
use prw_core::{DeviceId, DeviceLifecycle, EnrollmentId, SessionId, UserId, WorkspaceId};
use prw_device_identity::verify_device_identity_signature;
use prw_remote_transport::ControlFrame;

mod files;
mod network;
mod terminal;

pub const ANDROID_ADAPTER_PROTOCOL_VERSION: i32 = 1;
const BOOTSTRAP_MAGIC: [u8; 4] = *b"P145";
const BOOTSTRAP_VERSION: u16 = 1;
const ENROLLMENT_MAGIC: [u8; 4] = *b"P146";
const ENROLLMENT_VERSION: u16 = 1;
const MAX_BOOTSTRAP_BYTES: usize = 4_096;
const MAX_ENROLLMENT_REQUEST_BYTES: usize = 4_400;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_PUBLIC_SPKI_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidAdapterError {
    InvalidBootstrap,
    InvalidEnrollment,
    InvalidIdentifier,
    InvalidPublicIdentity,
    InvalidControlFrame,
}

impl fmt::Display for AndroidAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBootstrap => "invalid Android bootstrap request",
            Self::InvalidEnrollment => "invalid Android enrollment proof request",
            Self::InvalidIdentifier => "invalid Android bootstrap identifier",
            Self::InvalidPublicIdentity => "invalid Android bootstrap public identity",
            Self::InvalidControlFrame => "invalid PRWM control frame",
        })
    }
}

impl std::error::Error for AndroidAdapterError {}

struct BootstrapIdentity {
    binding: DeviceIdentityBinding,
    session_id: SessionId,
    nonce: SessionAuthNonce,
}

struct EnrollmentIdentity {
    request: EnrollmentRequest,
    nonce: EnrollmentProofNonce,
}

/// Decodes and re-encodes one bounded PRWM control frame using the existing transport codec.
///
/// # Errors
///
/// Returns [`AndroidAdapterError::InvalidControlFrame`] when `input` is not a valid
/// bounded PRWM control frame.
pub fn round_trip_control_frame(input: &[u8]) -> Result<Vec<u8>, AndroidAdapterError> {
    ControlFrame::decode(input)
        .map(|frame| frame.encode())
        .map_err(|_| AndroidAdapterError::InvalidControlFrame)
}

/// Builds the canonical typed PRW session-authentication message for one bootstrap request.
///
/// # Errors
///
/// Returns a bounded [`AndroidAdapterError`] when the bootstrap request, identifiers,
/// public identity, or existing session-authentication encoding is invalid.
pub fn canonical_session_message(input: &[u8]) -> Result<Vec<u8>, AndroidAdapterError> {
    let parsed = parse_bootstrap(input)?;
    encode_session_auth_message(&parsed.binding, &parsed.session_id, parsed.nonce)
        .map_err(|_| AndroidAdapterError::InvalidBootstrap)
}

#[must_use]
pub fn verify_session_signature(input: &[u8], signature: &[u8]) -> bool {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return false;
    }
    let Ok(parsed) = parse_bootstrap(input) else {
        return false;
    };
    let Ok(message) =
        encode_session_auth_message(&parsed.binding, &parsed.session_id, parsed.nonce)
    else {
        return false;
    };
    let Ok(signature) = DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        signature.to_vec(),
    ) else {
        return false;
    };
    verify_device_identity_signature(&parsed.binding.public_identity, &message, &signature).is_ok()
}

/// Builds the canonical typed PRW enrollment proof-of-possession message.
///
/// # Errors
///
/// Returns a bounded [`AndroidAdapterError`] when the local JNI enrollment envelope,
/// identifiers, public identity, nonce, or canonical proof message is invalid.
pub fn canonical_enrollment_message(input: &[u8]) -> Result<Vec<u8>, AndroidAdapterError> {
    let parsed = parse_enrollment(input)?;
    encode_enrollment_proof_message(&parsed.request, parsed.nonce)
        .map_err(|_| AndroidAdapterError::InvalidEnrollment)
}

/// Verifies a bounded DER P-256 signature over the canonical enrollment message.
#[must_use]
pub fn verify_enrollment_signature(input: &[u8], signature: &[u8]) -> bool {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return false;
    }
    let Ok(parsed) = parse_enrollment(input) else {
        return false;
    };
    let Ok(message) = encode_enrollment_proof_message(&parsed.request, parsed.nonce) else {
        return false;
    };
    let Ok(signature) = DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        signature.to_vec(),
    ) else {
        return false;
    };
    verify_device_identity_signature(&parsed.request.public_identity, &message, &signature).is_ok()
}

fn parse_bootstrap(input: &[u8]) -> Result<BootstrapIdentity, AndroidAdapterError> {
    if input.len() > MAX_BOOTSTRAP_BYTES || input.len() < 6 + 32 {
        return Err(AndroidAdapterError::InvalidBootstrap);
    }
    if input[..4] != BOOTSTRAP_MAGIC
        || u16::from_be_bytes([input[4], input[5]]) != BOOTSTRAP_VERSION
    {
        return Err(AndroidAdapterError::InvalidBootstrap);
    }
    let mut reader = Reader::new(&input[6..]);
    let workspace = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let user = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let device = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let session = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let public_spki = reader.bytes(MAX_PUBLIC_SPKI_BYTES)?;
    let nonce = reader.array::<32>()?;
    reader.finish()?;

    let public_identity = PublicIdentityMaterial::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
        public_spki,
    )
    .map_err(|_| AndroidAdapterError::InvalidPublicIdentity)?;
    Ok(BootstrapIdentity {
        binding: DeviceIdentityBinding {
            workspace_id: WorkspaceId::new(workspace)
                .map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            user_id: UserId::new(user).map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            device_id: DeviceId::new(device).map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            public_identity,
            lifecycle: DeviceLifecycle::Enrolled,
        },
        session_id: SessionId::new(session).map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
        nonce: SessionAuthNonce::new(nonce),
    })
}

fn parse_enrollment(input: &[u8]) -> Result<EnrollmentIdentity, AndroidAdapterError> {
    if input.len() > MAX_ENROLLMENT_REQUEST_BYTES || input.len() < 6 + 32 {
        return Err(AndroidAdapterError::InvalidEnrollment);
    }
    if input[..4] != ENROLLMENT_MAGIC
        || u16::from_be_bytes([input[4], input[5]]) != ENROLLMENT_VERSION
    {
        return Err(AndroidAdapterError::InvalidEnrollment);
    }
    let mut reader = Reader::new(&input[6..]);
    let enrollment = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let workspace = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let user = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let device = reader.utf8(MAX_IDENTIFIER_BYTES)?;
    let public_spki = reader.bytes(MAX_PUBLIC_SPKI_BYTES)?;
    let nonce = reader.array::<32>()?;
    reader.finish()?;

    let public_identity = PublicIdentityMaterial::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
        public_spki,
    )
    .map_err(|_| AndroidAdapterError::InvalidPublicIdentity)?;
    Ok(EnrollmentIdentity {
        request: EnrollmentRequest {
            enrollment_id: EnrollmentId::new(enrollment)
                .map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            workspace_id: WorkspaceId::new(workspace)
                .map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            user_id: UserId::new(user).map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            device_id: DeviceId::new(device).map_err(|_| AndroidAdapterError::InvalidIdentifier)?,
            public_identity,
        },
        nonce: EnrollmentProofNonce::new(nonce),
    })
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn u16(&mut self) -> Result<u16, AndroidAdapterError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, AndroidAdapterError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(AndroidAdapterError::InvalidBootstrap);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AndroidAdapterError::InvalidBootstrap)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(AndroidAdapterError::InvalidBootstrap)?;
        self.offset = end;
        Ok(bytes.to_vec())
    }

    fn utf8(&mut self, maximum: usize) -> Result<String, AndroidAdapterError> {
        let bytes = self.bytes(maximum)?;
        String::from_utf8(bytes).map_err(|_| AndroidAdapterError::InvalidBootstrap)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AndroidAdapterError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(AndroidAdapterError::InvalidBootstrap)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(AndroidAdapterError::InvalidBootstrap)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(bytes);
        self.offset = end;
        Ok(output)
    }

    const fn finish(self) -> Result<(), AndroidAdapterError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(AndroidAdapterError::InvalidBootstrap)
        }
    }
}

fn jni_bytes<'caller>(
    unowned_env: &mut EnvUnowned<'caller>,
    input: &JByteArray<'caller>,
    operation: impl FnOnce(&[u8]) -> Vec<u8>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let input = env.convert_byte_array(input)?;
            env.byte_array_from_slice(&operation(&input))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub const extern "system" fn Java_com_privateworkspace_prw_NativeBridge_protocolVersion<'caller>(
    _env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> jint {
    ANDROID_ADAPTER_PROTOCOL_VERSION
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_roundTripControlFrame<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    input: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_bytes(&mut env, &input, |bytes| {
        round_trip_control_frame(bytes).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_canonicalSessionMessage<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    input: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_bytes(&mut env, &input, |bytes| {
        canonical_session_message(bytes).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_verifySessionSignature<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    input: JByteArray<'caller>,
    signature: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let input = env.convert_byte_array(&input)?;
            let signature = env.convert_byte_array(&signature)?;
            Ok(verify_session_signature(&input, &signature))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_canonicalEnrollmentMessage<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    input: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_bytes(&mut env, &input, |bytes| {
        canonical_enrollment_message(bytes).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_verifyEnrollmentSignature<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    input: JByteArray<'caller>,
    signature: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let input = env.convert_byte_array(&input)?;
            let signature = env.convert_byte_array(&signature)?;
            Ok(verify_enrollment_signature(&input, &signature))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_device_identity_signer::UbuntuEnrollmentSigner;
    use prw_remote_transport::{ControlFrame, ControlMessageKind};

    use super::*;

    fn field(target: &mut Vec<u8>, bytes: &[u8]) {
        target.extend_from_slice(
            &u16::try_from(bytes.len())
                .expect("field length")
                .to_be_bytes(),
        );
        target.extend_from_slice(bytes);
    }

    fn input(public_spki: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&BOOTSTRAP_MAGIC);
        value.extend_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
        field(&mut value, b"workspace-145");
        field(&mut value, b"user-145");
        field(&mut value, b"device-145");
        field(&mut value, b"session-145");
        field(&mut value, public_spki);
        value.extend_from_slice(&[7; 32]);
        value
    }

    #[test]
    fn prwm_round_trip_uses_existing_transport_codec() {
        let frame = ControlFrame::new(ControlMessageKind::Heartbeat, 17, b"phase145".to_vec())
            .expect("frame")
            .encode();
        assert_eq!(round_trip_control_frame(&frame), Ok(frame));
        assert_eq!(
            round_trip_control_frame(b"bad"),
            Err(AndroidAdapterError::InvalidControlFrame)
        );
    }

    #[test]
    fn typed_session_message_and_signature_validate() {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("key");
        let signer = UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("signer");
        let request = input(signer.public_identity().as_bytes());
        let parsed = parse_bootstrap(&request).expect("parse");
        let message = canonical_session_message(&request).expect("canonical message");
        let challenge = prw_control_plane::session_auth::SessionAuthChallengeState::new(
            parsed.binding.clone(),
            parsed.session_id.clone(),
            parsed.nonce,
            10,
            20,
        )
        .expect("challenge state");
        let signature = signer
            .sign_session_auth_proof(&parsed.binding, challenge.challenge())
            .expect("typed proof");
        assert!(verify_session_signature(
            &request,
            signature.signature().as_bytes()
        ));
        let mut bad = signature.signature().as_bytes().to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify_session_signature(&request, &bad));
        assert!(
            message.starts_with(prw_control_plane::session_auth::SESSION_AUTH_DOMAIN_SEPARATOR)
        );
    }

    fn enrollment_input(public_spki: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&ENROLLMENT_MAGIC);
        value.extend_from_slice(&ENROLLMENT_VERSION.to_be_bytes());
        field(&mut value, b"enrollment-146");
        field(&mut value, b"workspace-146");
        field(&mut value, b"user-146");
        field(&mut value, b"device-146");
        field(&mut value, public_spki);
        value.extend_from_slice(&[11; 32]);
        value
    }

    #[test]
    fn typed_enrollment_message_and_signature_validate() {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("key");
        let signer = UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref()).expect("signer");
        let input = enrollment_input(signer.public_identity().as_bytes());
        let parsed = parse_enrollment(&input).expect("parse enrollment");
        let canonical = canonical_enrollment_message(&input).expect("canonical enrollment");
        let challenge = prw_control_plane::enrollment_pop::EnrollmentProofChallengeState::new(
            parsed.request.clone(),
            parsed.nonce,
            10,
            20,
        )
        .expect("challenge state");
        let proof = signer
            .sign_enrollment_proof(&parsed.request, challenge.challenge())
            .expect("typed enrollment proof");
        assert!(verify_enrollment_signature(
            &input,
            proof.signature().as_bytes()
        ));
        let mut bad = proof.signature().as_bytes().to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify_enrollment_signature(&input, &bad));
        assert!(
            canonical
                .starts_with(prw_control_plane::enrollment_pop::ENROLLMENT_PROOF_DOMAIN_SEPARATOR)
        );
    }

    #[test]
    fn malformed_enrollment_fails_closed() {
        assert_eq!(
            canonical_enrollment_message(b"P146\x00\x01"),
            Err(AndroidAdapterError::InvalidEnrollment)
        );
        assert!(!verify_enrollment_signature(b"bad", &[1, 2, 3]));
    }

    #[test]
    fn malformed_bootstrap_fails_closed() {
        assert_eq!(
            canonical_session_message(b"P145\x00\x01"),
            Err(AndroidAdapterError::InvalidBootstrap)
        );
        assert!(!verify_session_signature(b"bad", &[1, 2, 3]));
    }
}
