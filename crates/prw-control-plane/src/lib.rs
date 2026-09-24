//! Transport-agnostic control-plane contracts for Ownspace.
//!
//! Phase 002 defines typed identity, enrollment, and revocation boundaries.
//! Phase 003 locks the initial device-identity signature algorithm identifier.
//! Phase 004 locks the initial public-key and signature byte encodings.
//! Phase 115 adds provider-neutral enrollment proof-of-possession message and
//! challenge/replay state semantics without selecting a wire protocol, signing
//! backend, persistence layer, account-authentication mechanism, or listener.
//! Phase 128 adds provider-neutral enrolled-device session authentication
//! challenge, replay, and canonical-message semantics without granting capabilities.

#[allow(dead_code)]
mod fence_sequence;
#[allow(dead_code, clippy::redundant_pub_crate)]
mod fence_sequence_allocation_etcd;
#[allow(dead_code)]
mod fence_sequence_allocation_orchestrator;
#[allow(dead_code)]
mod fence_sequence_live_owner_bridge;
#[allow(dead_code)]
mod fence_sequence_live_owner_handoff;
#[allow(dead_code)]
mod recovery_epoch;

pub mod durable_registry_etcd;
pub mod durable_registry_etcd_bootstrap;
pub mod enrollment_pop;
pub mod reachability_acquisition_evidence;
pub mod reachability_durable_snapshot_etcd;
pub mod reachability_live_owner_codec;
pub mod reachability_live_owner_etcd;
pub mod reachability_live_owner_txn;
pub mod session_auth;

use std::fmt;

use prw_core::{DeviceId, DeviceLifecycle, EnrollmentId, UserId, WorkspaceId};

/// Initial device-identity signature algorithm.
///
/// Phase 003 selects ECDSA with NIST P-256 and SHA-256 as the first device
/// identity signature primitive. Device identity remains cryptographically
/// separate from future transport identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIdentityAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256.
    EcdsaP256Sha256,
}

/// Public-key byte encoding for device identity.
///
/// Phase 004 selects DER-encoded X.509 `SubjectPublicKeyInfo` for the initial
/// P-256 device public key. The structure uses `id-ecPublicKey` with the
/// `secp256r1` named-curve parameters defined by RFC 5480.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIdentityPublicKeyEncoding {
    /// DER-encoded X.509 `SubjectPublicKeyInfo`.
    SubjectPublicKeyInfoDer,
}

/// Signature byte encoding for device identity.
///
/// Phase 004 selects the ASN.1 DER `ECDSA-Sig-Value` structure from RFC 3279:
/// a sequence containing the ECDSA `r` and `s` integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIdentitySignatureEncoding {
    /// DER-encoded `ECDSA-Sig-Value` sequence.
    EcdsaSigValueDer,
}

/// Public device-identity material.
///
/// The material carries explicit algorithm and encoding identifiers so neither
/// property is inferred from byte length or a byte prefix. Phase 004 does not
/// parse or cryptographically validate the DER bytes; strict parsing and key
/// validation belong to the future cryptographic-provider boundary. Private
/// identity material is never represented by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentityMaterial {
    algorithm: DeviceIdentityAlgorithm,
    encoding: DeviceIdentityPublicKeyEncoding,
    bytes: Vec<u8>,
}

impl PublicIdentityMaterial {
    /// Creates non-empty public identity material with explicit metadata.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityMaterialError::Empty`] when no public bytes are supplied.
    pub fn new(
        algorithm: DeviceIdentityAlgorithm,
        encoding: DeviceIdentityPublicKeyEncoding,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, IdentityMaterialError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentityMaterialError::Empty);
        }
        Ok(Self {
            algorithm,
            encoding,
            bytes: value,
        })
    }

    /// Returns the explicit device-identity algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DeviceIdentityAlgorithm {
        self.algorithm
    }

    /// Returns the explicit public-key byte encoding.
    #[must_use]
    pub const fn encoding(&self) -> DeviceIdentityPublicKeyEncoding {
        self.encoding
    }

    /// Returns the public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Public-identity material validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMaterialError {
    /// Public identity material must not be empty.
    Empty,
}

impl fmt::Display for IdentityMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("public identity material must not be empty"),
        }
    }
}

impl std::error::Error for IdentityMaterialError {}

/// Device-identity signature bytes.
///
/// This is a typed serialized signature value only. Phase 004 does not sign,
/// verify, normalize, or parse signatures and does not select a crypto backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentitySignature {
    algorithm: DeviceIdentityAlgorithm,
    encoding: DeviceIdentitySignatureEncoding,
    bytes: Vec<u8>,
}

impl DeviceIdentitySignature {
    /// Creates non-empty signature bytes with explicit algorithm and encoding.
    ///
    /// # Errors
    ///
    /// Returns [`IdentitySignatureError::Empty`] when no signature bytes are supplied.
    pub fn new(
        algorithm: DeviceIdentityAlgorithm,
        encoding: DeviceIdentitySignatureEncoding,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, IdentitySignatureError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentitySignatureError::Empty);
        }
        Ok(Self {
            algorithm,
            encoding,
            bytes: value,
        })
    }

    /// Returns the explicit device-identity algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DeviceIdentityAlgorithm {
        self.algorithm
    }

    /// Returns the explicit signature byte encoding.
    #[must_use]
    pub const fn encoding(&self) -> DeviceIdentitySignatureEncoding {
        self.encoding
    }

    /// Returns the signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Device-identity signature material validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySignatureError {
    /// Signature material must not be empty.
    Empty,
}

impl fmt::Display for IdentitySignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("device identity signature must not be empty"),
        }
    }
}

impl std::error::Error for IdentitySignatureError {}

/// Control-plane view of a device identity bound to a workspace and user.
///
/// `user_id` identifies the logical owner/reference in the domain model; it
/// does not imply that account authentication has been selected or implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentityBinding {
    /// Workspace containing the device.
    pub workspace_id: WorkspaceId,
    /// Logical user associated with the device.
    pub user_id: UserId,
    /// Stable device identifier.
    pub device_id: DeviceId,
    /// Public identity material only.
    pub public_identity: PublicIdentityMaterial,
    /// Current device lifecycle.
    pub lifecycle: DeviceLifecycle,
}

/// Enrollment request submitted to the future control plane.
///
/// This is a typed domain message, not a wire-format or transport contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    /// Stable enrollment request identifier.
    pub enrollment_id: EnrollmentId,
    /// Target workspace.
    pub workspace_id: WorkspaceId,
    /// Logical user for whom the device is being enrolled.
    pub user_id: UserId,
    /// Device requesting enrollment.
    pub device_id: DeviceId,
    /// Public device-identity material.
    pub public_identity: PublicIdentityMaterial,
}

/// Architecture-neutral enrollment decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentDecision {
    /// Enrollment is approved.
    Approve,
    /// Enrollment is rejected.
    Reject,
}

/// Lifecycle of an enrollment request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    /// No terminal decision has been recorded.
    Pending,
    /// Enrollment was approved.
    Approved,
    /// Enrollment was rejected.
    Rejected,
}

impl EnrollmentState {
    /// Returns whether no further enrollment decision is valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Approved | Self::Rejected)
    }

    /// Applies exactly one terminal decision to a pending enrollment.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentTransitionError::AlreadyDecided`] if the enrollment
    /// is already approved or rejected.
    pub const fn decide(
        self,
        decision: EnrollmentDecision,
    ) -> Result<Self, EnrollmentTransitionError> {
        match self {
            Self::Pending => match decision {
                EnrollmentDecision::Approve => Ok(Self::Approved),
                EnrollmentDecision::Reject => Ok(Self::Rejected),
            },
            Self::Approved | Self::Rejected => Err(EnrollmentTransitionError::AlreadyDecided),
        }
    }
}

/// Invalid enrollment-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentTransitionError {
    /// A terminal enrollment decision already exists.
    AlreadyDecided,
}

impl fmt::Display for EnrollmentTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyDecided => {
                formatter.write_str("enrollment already has a terminal decision")
            }
        }
    }
}

impl std::error::Error for EnrollmentTransitionError {}

/// Request to mark an enrolled device as revoked.
///
/// Phase 004 deliberately leaves revocation propagation, stale-device behavior,
/// and persistence semantics undefined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    /// Workspace containing the device.
    pub workspace_id: WorkspaceId,
    /// Device to revoke.
    pub device_id: DeviceId,
}

/// Typed action boundary for a future control-plane service.
///
/// Authorization of these actions, wire transport, persistence, retries, and
/// idempotency semantics are deliberately deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlPlaneAction {
    /// Submit a new enrollment request.
    SubmitEnrollment(EnrollmentRequest),
    /// Record an enrollment decision.
    DecideEnrollment {
        /// Enrollment request receiving the decision.
        enrollment_id: EnrollmentId,
        /// Decision to record.
        decision: EnrollmentDecision,
    },
    /// Mark a device as revoked.
    RevokeDevice(DeviceRevocation),
}

#[cfg(test)]
mod tests {
    use super::{
        ControlPlaneAction, DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding,
        DeviceIdentitySignature, DeviceIdentitySignatureEncoding, EnrollmentDecision,
        EnrollmentRequest, EnrollmentState, EnrollmentTransitionError, IdentityMaterialError,
        IdentitySignatureError, PublicIdentityMaterial,
    };
    use prw_core::{DeviceId, EnrollmentId, UserId, WorkspaceId};

    #[test]
    fn public_identity_material_rejects_empty_bytes() {
        assert_eq!(
            PublicIdentityMaterial::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
                Vec::<u8>::new(),
            ),
            Err(IdentityMaterialError::Empty)
        );
    }

    #[test]
    fn public_identity_material_preserves_algorithm_and_encoding() {
        let identity = PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![1, 2, 3],
        )
        .expect("non-empty public identity");

        assert_eq!(
            identity.algorithm(),
            DeviceIdentityAlgorithm::EcdsaP256Sha256
        );
        assert_eq!(
            identity.encoding(),
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer
        );
    }

    #[test]
    fn device_identity_signature_rejects_empty_bytes() {
        assert_eq!(
            DeviceIdentitySignature::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
                Vec::<u8>::new(),
            ),
            Err(IdentitySignatureError::Empty)
        );
    }

    #[test]
    fn device_identity_signature_preserves_algorithm_and_encoding() {
        let signature = DeviceIdentitySignature::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
            vec![0x30, 0x01, 0x00],
        )
        .expect("non-empty signature");

        assert_eq!(
            signature.algorithm(),
            DeviceIdentityAlgorithm::EcdsaP256Sha256
        );
        assert_eq!(
            signature.encoding(),
            DeviceIdentitySignatureEncoding::EcdsaSigValueDer
        );
    }

    #[test]
    fn enrollment_decision_is_terminal() {
        let approved = EnrollmentState::Pending
            .decide(EnrollmentDecision::Approve)
            .expect("pending enrollment may be approved");

        assert!(approved.is_terminal());
        assert_eq!(
            approved.decide(EnrollmentDecision::Reject),
            Err(EnrollmentTransitionError::AlreadyDecided)
        );
    }

    #[test]
    fn typed_action_preserves_identity_boundaries() {
        let request = EnrollmentRequest {
            enrollment_id: EnrollmentId::new("enrollment-1").expect("valid enrollment id"),
            workspace_id: WorkspaceId::new("workspace-1").expect("valid workspace id"),
            user_id: UserId::new("user-1").expect("valid user id"),
            device_id: DeviceId::new("device-1").expect("valid device id"),
            public_identity: PublicIdentityMaterial::new(
                DeviceIdentityAlgorithm::EcdsaP256Sha256,
                DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
                vec![1, 2, 3],
            )
            .expect("non-empty public identity"),
        };

        assert!(matches!(
            ControlPlaneAction::SubmitEnrollment(request),
            ControlPlaneAction::SubmitEnrollment(_)
        ));
    }
}
