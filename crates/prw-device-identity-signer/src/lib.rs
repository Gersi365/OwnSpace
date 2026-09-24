//! Typed Ubuntu device-identity signer for Ownspace.
//!
//! This crate deliberately exposes no generic signing API, private-key export API,
//! systemd credential reader, filesystem access, enrollment approval, capability
//! grant, or networking. Callers provide one bounded canonical PKCS#8 v1 DER
//! credential from the trusted custody boundary and can request only explicitly
//! typed enrollment or enrolled-device session-authentication proofs.

use std::fmt;

use aws_lc_rs::{
    digest::{SHA256, digest},
    encoding::AsDer,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
    DeviceIdentitySignature, DeviceIdentitySignatureEncoding, EnrollmentRequest,
    PublicIdentityMaterial,
    enrollment_pop::{
        EnrollmentProofChallenge, EnrollmentProofMessageError, EnrollmentProofOfPossession,
        encode_enrollment_proof_message,
    },
    session_auth::{
        SessionAuthChallenge, SessionAuthMessageError, SessionAuthProof,
        encode_session_auth_message,
    },
};

/// Maximum accepted plaintext Ubuntu device-identity PKCS#8 credential size.
pub const MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES: usize = 4096;

/// Failure while loading or using the typed Ubuntu device-identity signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UbuntuEnrollmentSignerError {
    /// The supplied credential was empty or exceeded the locked size bound.
    CredentialOutOfBounds,
    /// The supplied bytes were not the exact canonical P-256 PKCS#8 v1 DER payload.
    InvalidPrivateCredential,
    /// The provider could not derive the canonical public identity.
    PublicIdentityDerivationFailed,
    /// Enrollment request and challenge identifiers did not match exactly.
    EnrollmentMismatch,
    /// The typed request/binding declared a different public identity than the loaded signer.
    PublicIdentityMismatch,
    /// Session authentication was attempted from a non-enrolled binding.
    SessionBindingNotEnrolled,
    /// Canonical enrollment proof message construction failed.
    MessageConstruction(EnrollmentProofMessageError),
    /// Canonical session-authentication message construction failed.
    SessionMessageConstruction(SessionAuthMessageError),
    /// The provider failed to create the P-256/SHA-256 signature.
    SigningFailed,
    /// The provider signature could not be represented as the locked typed signature profile.
    SignatureMaterialConstructionFailed,
}

impl fmt::Display for UbuntuEnrollmentSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialOutOfBounds => {
                formatter.write_str("device identity credential out of bounds")
            }
            Self::InvalidPrivateCredential => {
                formatter.write_str("invalid device identity private credential")
            }
            Self::PublicIdentityDerivationFailed => {
                formatter.write_str("device identity public identity derivation failed")
            }
            Self::EnrollmentMismatch => formatter.write_str("enrollment challenge mismatch"),
            Self::PublicIdentityMismatch => {
                formatter.write_str("device identity public identity mismatch")
            }
            Self::SessionBindingNotEnrolled => {
                formatter.write_str("session authentication binding is not enrolled")
            }
            Self::MessageConstruction(error) => {
                write!(
                    formatter,
                    "enrollment proof message construction failed: {error}"
                )
            }
            Self::SessionMessageConstruction(error) => {
                write!(
                    formatter,
                    "session authentication message construction failed: {error}"
                )
            }
            Self::SigningFailed => formatter.write_str("device identity signing failed"),
            Self::SignatureMaterialConstructionFailed => {
                formatter.write_str("device identity signature construction failed")
            }
        }
    }
}

impl std::error::Error for UbuntuEnrollmentSignerError {}

/// Loaded Ubuntu device-identity signer restricted to typed PRW proofs.
pub struct UbuntuEnrollmentSigner {
    key_pair: EcdsaKeyPair,
    public_identity: PublicIdentityMaterial,
}

impl fmt::Debug for UbuntuEnrollmentSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UbuntuEnrollmentSigner")
            .field("algorithm", &DeviceIdentityAlgorithm::EcdsaP256Sha256)
            .field(
                "public_key_encoding",
                &DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            )
            .finish_non_exhaustive()
    }
}

impl UbuntuEnrollmentSigner {
    /// Loads the exact Phase 119 canonical P-256 PKCS#8 v1 DER credential.
    ///
    /// The input is borrowed only during construction. This type retains the provider
    /// key object and canonical public identity, not a second PRW-owned raw PKCS#8 copy.
    /// The custody adapter remains responsible for zeroizing its own plaintext buffer.
    ///
    /// # Errors
    ///
    /// Returns [`UbuntuEnrollmentSignerError`] when the input is outside the locked
    /// bound, provider parsing fails, the accepted input is not byte-for-byte canonical
    /// PKCS#8 v1 DER, or canonical public-identity derivation fails.
    pub fn from_pkcs8_v1_der(credential: &[u8]) -> Result<Self, UbuntuEnrollmentSignerError> {
        if credential.is_empty() || credential.len() > MAX_UBUNTU_DEVICE_IDENTITY_PKCS8_BYTES {
            return Err(UbuntuEnrollmentSignerError::CredentialOutOfBounds);
        }

        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, credential)
            .map_err(|_| UbuntuEnrollmentSignerError::InvalidPrivateCredential)?;

        let canonical_private = key_pair
            .to_pkcs8v1()
            .map_err(|_| UbuntuEnrollmentSignerError::InvalidPrivateCredential)?;
        if canonical_private.as_ref() != credential {
            return Err(UbuntuEnrollmentSignerError::InvalidPrivateCredential);
        }

        let public_der = key_pair
            .public_key()
            .as_der()
            .map_err(|_| UbuntuEnrollmentSignerError::PublicIdentityDerivationFailed)?;
        let public_identity = PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            public_der.as_ref().to_vec(),
        )
        .map_err(|_| UbuntuEnrollmentSignerError::PublicIdentityDerivationFailed)?;

        Ok(Self {
            key_pair,
            public_identity,
        })
    }

    /// Returns the canonical public identity derived from the loaded private credential.
    #[must_use]
    pub const fn public_identity(&self) -> &PublicIdentityMaterial {
        &self.public_identity
    }

    /// Returns SHA-256 over the exact canonical public `SubjectPublicKeyInfo` DER bytes.
    ///
    /// This fingerprint contains no private-key material and is suitable for bounded
    /// activation evidence that compares provisioning-time and runtime identity.
    #[must_use]
    pub fn public_identity_sha256(&self) -> [u8; 32] {
        let value = digest(&SHA256, self.public_identity.as_bytes());
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(value.as_ref());
        fingerprint
    }

    /// Signs exactly one typed PRW enrollment proof-of-possession challenge.
    ///
    /// The request and challenge must name the same enrollment and the request must
    /// declare exactly this signer's canonical public identity. The canonical message
    /// is constructed internally; callers cannot supply arbitrary bytes to sign.
    ///
    /// # Errors
    ///
    /// Returns [`UbuntuEnrollmentSignerError`] when enrollment/public-identity binding
    /// fails, canonical message construction fails, or provider signing/output wrapping
    /// fails.
    pub fn sign_enrollment_proof(
        &self,
        request: &EnrollmentRequest,
        challenge: &EnrollmentProofChallenge,
    ) -> Result<EnrollmentProofOfPossession, UbuntuEnrollmentSignerError> {
        if &request.enrollment_id != challenge.enrollment_id() {
            return Err(UbuntuEnrollmentSignerError::EnrollmentMismatch);
        }
        if &request.public_identity != self.public_identity() {
            return Err(UbuntuEnrollmentSignerError::PublicIdentityMismatch);
        }

        let message = encode_enrollment_proof_message(request, challenge.nonce())
            .map_err(UbuntuEnrollmentSignerError::MessageConstruction)?;
        let signature = self.sign_typed_message(&message)?;

        Ok(EnrollmentProofOfPossession::new(
            request.enrollment_id.clone(),
            challenge.nonce(),
            signature,
        ))
    }

    /// Signs exactly one typed enrolled-device session-authentication challenge.
    ///
    /// The binding must be enrolled and must declare exactly this signer's canonical
    /// public identity. The session identifier and nonce come from the server challenge;
    /// callers cannot supply arbitrary message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`UbuntuEnrollmentSignerError`] when lifecycle/public-identity binding
    /// fails, canonical session-message construction fails, or provider signing/output
    /// wrapping fails.
    pub fn sign_session_auth_proof(
        &self,
        binding: &DeviceIdentityBinding,
        challenge: &SessionAuthChallenge,
    ) -> Result<SessionAuthProof, UbuntuEnrollmentSignerError> {
        if !binding.lifecycle.can_participate() {
            return Err(UbuntuEnrollmentSignerError::SessionBindingNotEnrolled);
        }
        if &binding.public_identity != self.public_identity() {
            return Err(UbuntuEnrollmentSignerError::PublicIdentityMismatch);
        }

        let message =
            encode_session_auth_message(binding, challenge.session_id(), challenge.nonce())
                .map_err(UbuntuEnrollmentSignerError::SessionMessageConstruction)?;
        let signature = self.sign_typed_message(&message)?;

        Ok(SessionAuthProof::new(
            challenge.session_id().clone(),
            challenge.nonce(),
            signature,
        ))
    }

    fn sign_typed_message(
        &self,
        message: &[u8],
    ) -> Result<DeviceIdentitySignature, UbuntuEnrollmentSignerError> {
        let signature = self
            .key_pair
            .sign(&SystemRandom::new(), message)
            .map_err(|_| UbuntuEnrollmentSignerError::SigningFailed)?;
        DeviceIdentitySignature::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
            signature.as_ref().to_vec(),
        )
        .map_err(|_| UbuntuEnrollmentSignerError::SignatureMaterialConstructionFailed)
    }
}
