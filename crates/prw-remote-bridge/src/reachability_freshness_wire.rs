//! Phase 152 C02e freshness-token delivery and authenticated resynchronization wire contract.
//!
//! This module selects a bounded PRW remote-transport payload codec for verifier-owned
//! candidate-publication freshness. It does not open sockets, spawn tasks, select a persistence
//! backend, advance freshness during resynchronization, grant capabilities, or activate Agent
//! bootstrap/runtime behavior.

use std::fmt;

use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_registry::{RegistryError, WorkspaceDeviceRegistry};
use prw_remote_transport::{ControlFrame, ControlMessageKind, RemoteTransportError};
use prw_session::AuthenticatedDeviceSession;

use crate::candidate_publication_freshness::{
    CandidatePublicationFreshnessLifecycle, CandidatePublicationFreshnessRecord,
    CandidatePublicationFreshnessToken,
};
use crate::reachability_owner::{
    ReachabilityCommitOutcome, ReachabilityDurableStore, ReachabilityPersistenceError,
};

/// Exact inner payload magic for the C02e freshness wire contract.
pub const REACHABILITY_FRESHNESS_WIRE_MAGIC: [u8; 4] = *b"PRWF";
/// Initial freshness wire major version.
pub const REACHABILITY_FRESHNESS_WIRE_MAJOR: u16 = 1;
/// Initial freshness wire minor version.
pub const REACHABILITY_FRESHNESS_WIRE_MINOR: u16 = 0;
/// Fixed payload header bytes: magic + major + minor + operation + reserved flags.
pub const REACHABILITY_FRESHNESS_WIRE_HEADER_BYTES: usize = 12;

const OP_CURRENT_TOKEN_RESYNCHRONIZATION_REQUEST: u16 = 1;
const OP_TOKEN_DELIVERY: u16 = 2;
const OP_FAILURE: u16 = 3;

/// Why an exact verifier token is being delivered to the authenticated publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FreshnessTokenDeliveryReason {
    /// Initial delivery of a token from an already-durable `NewLifecycleEligible` record.
    Bootstrap = 1,
    /// Delivery of the replacement token from a definitely committed candidate publication.
    AcceptedPublication = 2,
    /// Non-mutating re-delivery of the exact authoritative current token after authenticated reload.
    Resynchronization = 3,
}

impl TryFrom<u16> for FreshnessTokenDeliveryReason {
    type Error = ReachabilityFreshnessWireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::AcceptedPublication),
            3 => Ok(Self::Resynchronization),
            _ => Err(ReachabilityFreshnessWireError::InvalidPayload),
        }
    }
}

/// Stable bounded semantic failure codes for freshness delivery/publication responses.
///
/// Authentication details are intentionally collapsed into `CurrentnessRejected`; callers do not
/// receive registry-internal failure detail over this wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FreshnessWireFailureCode {
    /// Current authenticated session/device/transport admission failed.
    CurrentnessRejected = 1,
    /// A candidate publication presented a freshness token that is no longer current.
    StalePublicationFreshness = 2,
    /// Authoritative durable state for the established exact peer lifecycle is absent.
    DurableStateMissing = 3,
    /// Exact freshness authority is unavailable/ambiguous and the lifecycle fails closed.
    RecoveryRequired = 4,
    /// Exact peer lifecycle is a durable historical tombstone.
    Retired = 5,
    /// Persistence could not provide an authoritative current result.
    PersistenceUnavailable = 6,
    /// Payload/message semantics were rejected without exposing internal details.
    ProtocolRejected = 7,
}

impl TryFrom<u16> for FreshnessWireFailureCode {
    type Error = ReachabilityFreshnessWireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CurrentnessRejected),
            2 => Ok(Self::StalePublicationFreshness),
            3 => Ok(Self::DurableStateMissing),
            4 => Ok(Self::RecoveryRequired),
            5 => Ok(Self::Retired),
            6 => Ok(Self::PersistenceUnavailable),
            7 => Ok(Self::ProtocolRejected),
            _ => Err(ReachabilityFreshnessWireError::InvalidPayload),
        }
    }
}

/// One typed C02e freshness wire payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityFreshnessWireMessage {
    /// Authenticated publisher asks for the exact current token of its current transport identity.
    CurrentTokenResynchronizationRequest {
        /// Transport identity whose current registry binding must be revalidated before durable load.
        transport_identity: TransportIdentity,
    },
    /// Verifier delivers one exact token bound to the exact current transport identity.
    TokenDelivery {
        /// Semantic reason for delivery; the token bytes themselves carry no reason metadata.
        reason: FreshnessTokenDeliveryReason,
        /// Exact transport identity that scopes the delivered token with authenticated `DeviceId`.
        transport_identity: TransportIdentity,
        /// Exact verifier-owned freshness token.
        token: CandidatePublicationFreshnessToken,
    },
    /// Bounded fail-closed semantic response.
    Failure(FreshnessWireFailureCode),
}

impl ReachabilityFreshnessWireMessage {
    /// Creates an authenticated-current-token resynchronization request payload.
    #[must_use]
    pub const fn current_token_resynchronization_request(
        transport_identity: TransportIdentity,
    ) -> Self {
        Self::CurrentTokenResynchronizationRequest { transport_identity }
    }

    /// Creates one exact token-delivery payload.
    #[must_use]
    pub const fn token_delivery(
        reason: FreshnessTokenDeliveryReason,
        transport_identity: TransportIdentity,
        token: CandidatePublicationFreshnessToken,
    ) -> Self {
        Self::TokenDelivery {
            reason,
            transport_identity,
            token,
        }
    }

    /// Creates one bounded semantic failure payload.
    #[must_use]
    pub const fn failure(code: FreshnessWireFailureCode) -> Self {
        Self::Failure(code)
    }

    /// Returns the required outer PRWM control-frame kind for this payload.
    #[must_use]
    pub const fn control_message_kind(self) -> ControlMessageKind {
        match self {
            Self::CurrentTokenResynchronizationRequest { .. } => ControlMessageKind::Request,
            Self::TokenDelivery { .. } => ControlMessageKind::Response,
            Self::Failure(_) => ControlMessageKind::Error,
        }
    }

    /// Encodes one complete PRWF v1.0 payload.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let (operation, body_len) = match self {
            Self::CurrentTokenResynchronizationRequest { .. } => {
                (OP_CURRENT_TOKEN_RESYNCHRONIZATION_REQUEST, 32)
            }
            Self::TokenDelivery { .. } => (OP_TOKEN_DELIVERY, 68),
            Self::Failure(_) => (OP_FAILURE, 4),
        };
        let mut payload = Vec::with_capacity(REACHABILITY_FRESHNESS_WIRE_HEADER_BYTES + body_len);
        payload.extend_from_slice(&REACHABILITY_FRESHNESS_WIRE_MAGIC);
        payload.extend_from_slice(&REACHABILITY_FRESHNESS_WIRE_MAJOR.to_be_bytes());
        payload.extend_from_slice(&REACHABILITY_FRESHNESS_WIRE_MINOR.to_be_bytes());
        payload.extend_from_slice(&operation.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        match self {
            Self::CurrentTokenResynchronizationRequest { transport_identity } => {
                payload.extend_from_slice(transport_identity.as_bytes());
            }
            Self::TokenDelivery {
                reason,
                transport_identity,
                token,
            } => {
                payload.extend_from_slice(&(reason as u16).to_be_bytes());
                payload.extend_from_slice(&0_u16.to_be_bytes());
                payload.extend_from_slice(transport_identity.as_bytes());
                payload.extend_from_slice(token.as_bytes());
            }
            Self::Failure(code) => {
                payload.extend_from_slice(&(code as u16).to_be_bytes());
                payload.extend_from_slice(&0_u16.to_be_bytes());
            }
        }
        payload
    }

    /// Decodes one complete PRWF v1.0 payload with exact lengths and zero reserved fields.
    ///
    /// # Errors
    ///
    /// Rejects wrong magic/version, unknown operations/codes, invalid zero identities/tokens,
    /// non-zero reserved fields, truncation and trailing bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, ReachabilityFreshnessWireError> {
        if payload.len() < REACHABILITY_FRESHNESS_WIRE_HEADER_BYTES
            || payload[..4] != REACHABILITY_FRESHNESS_WIRE_MAGIC
        {
            return Err(ReachabilityFreshnessWireError::InvalidPayload);
        }
        let major = u16::from_be_bytes([payload[4], payload[5]]);
        let minor = u16::from_be_bytes([payload[6], payload[7]]);
        if major != REACHABILITY_FRESHNESS_WIRE_MAJOR || minor != REACHABILITY_FRESHNESS_WIRE_MINOR
        {
            return Err(ReachabilityFreshnessWireError::InvalidPayload);
        }
        let operation = u16::from_be_bytes([payload[8], payload[9]]);
        if u16::from_be_bytes([payload[10], payload[11]]) != 0 {
            return Err(ReachabilityFreshnessWireError::InvalidPayload);
        }
        let body = &payload[REACHABILITY_FRESHNESS_WIRE_HEADER_BYTES..];
        match operation {
            OP_CURRENT_TOKEN_RESYNCHRONIZATION_REQUEST if body.len() == 32 => {
                let mut transport_bytes = [0_u8; 32];
                transport_bytes.copy_from_slice(body);
                let transport_identity = TransportIdentity::new(transport_bytes)
                    .map_err(|_| ReachabilityFreshnessWireError::InvalidPayload)?;
                Ok(Self::CurrentTokenResynchronizationRequest { transport_identity })
            }
            OP_TOKEN_DELIVERY if body.len() == 68 => {
                let reason =
                    FreshnessTokenDeliveryReason::try_from(u16::from_be_bytes([body[0], body[1]]))?;
                if u16::from_be_bytes([body[2], body[3]]) != 0 {
                    return Err(ReachabilityFreshnessWireError::InvalidPayload);
                }
                let mut transport_bytes = [0_u8; 32];
                transport_bytes.copy_from_slice(&body[4..36]);
                let transport_identity = TransportIdentity::new(transport_bytes)
                    .map_err(|_| ReachabilityFreshnessWireError::InvalidPayload)?;
                let mut token_bytes = [0_u8; 32];
                token_bytes.copy_from_slice(&body[36..68]);
                let token = CandidatePublicationFreshnessToken::new(token_bytes)
                    .map_err(|_| ReachabilityFreshnessWireError::InvalidPayload)?;
                Ok(Self::TokenDelivery {
                    reason,
                    transport_identity,
                    token,
                })
            }
            OP_FAILURE if body.len() == 4 => {
                let code =
                    FreshnessWireFailureCode::try_from(u16::from_be_bytes([body[0], body[1]]))?;
                if u16::from_be_bytes([body[2], body[3]]) != 0 {
                    return Err(ReachabilityFreshnessWireError::InvalidPayload);
                }
                Ok(Self::Failure(code))
            }
            _ => Err(ReachabilityFreshnessWireError::InvalidPayload),
        }
    }

    /// Wraps this payload in the existing bounded PRWM control frame.
    ///
    /// # Errors
    ///
    /// Fails if the existing transport rejects the request identifier or frame bounds.
    pub fn into_control_frame(
        self,
        request_id: u64,
    ) -> Result<ControlFrame, ReachabilityFreshnessWireError> {
        ControlFrame::new(self.control_message_kind(), request_id, self.encode())
            .map_err(ReachabilityFreshnessWireError::Transport)
    }

    /// Decodes and verifies one freshness payload from an existing PRWM control frame.
    ///
    /// # Errors
    ///
    /// The inner operation and outer request/response/error kind must agree exactly.
    pub fn from_control_frame(
        frame: &ControlFrame,
    ) -> Result<Self, ReachabilityFreshnessWireError> {
        let message = Self::decode(frame.payload())?;
        if frame.kind() != message.control_message_kind() {
            return Err(ReachabilityFreshnessWireError::WrongControlMessageKind);
        }
        Ok(message)
    }
}

/// Constructs bootstrap delivery only from an already-authoritative bootstrap-eligible record.
///
/// This function never creates bootstrap authority or generates a token.
///
/// # Errors
///
/// Rejects any lifecycle other than `NewLifecycleEligible`.
pub const fn bootstrap_token_delivery(
    record: &CandidatePublicationFreshnessRecord,
) -> Result<ReachabilityFreshnessWireMessage, ReachabilityFreshnessWireError> {
    let CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(token) = record.lifecycle()
    else {
        return Err(ReachabilityFreshnessWireError::BootstrapRecordRequired);
    };
    Ok(ReachabilityFreshnessWireMessage::token_delivery(
        FreshnessTokenDeliveryReason::Bootstrap,
        record.peer().transport_identity(),
        token,
    ))
}

/// Constructs post-commit token delivery from evidence that can exist only after definite commit.
#[must_use]
pub const fn accepted_publication_token_delivery(
    peer: &PeerConnectivityIdentity,
    outcome: ReachabilityCommitOutcome,
) -> ReachabilityFreshnessWireMessage {
    ReachabilityFreshnessWireMessage::token_delivery(
        FreshnessTokenDeliveryReason::AcceptedPublication,
        peer.transport_identity(),
        outcome.replacement_freshness(),
    )
}

/// Performs non-mutating freshness resynchronization from authenticated current identity plus
/// authoritative durable load.
///
/// The authenticated session supplies `DeviceId`; the request supplies only the independently
/// rotatable `TransportIdentity`. Current registry validation occurs before durable lookup. The
/// exact current durable token is re-delivered without generation, compare-and-commit, rotation,
/// rebaseline or candidate/traversal mutation.
///
/// # Errors
///
/// Fails closed on stale/revoked currentness, missing/ambiguous durable state, peer mismatch,
/// `RecoveryRequired`, or `Retired`.
pub async fn authenticated_current_token_resynchronization<S>(
    registry: &WorkspaceDeviceRegistry,
    publisher_session: &AuthenticatedDeviceSession,
    presented_transport_identity: TransportIdentity,
    store: &mut S,
) -> Result<ReachabilityFreshnessWireMessage, FreshnessResynchronizationError>
where
    S: ReachabilityDurableStore,
{
    let principal = registry
        .validate_authenticated_session(publisher_session)
        .map_err(FreshnessResynchronizationError::Registry)?;
    registry
        .validate_transport_identity(principal.device_id(), presented_transport_identity)
        .map_err(FreshnessResynchronizationError::Registry)?;

    let peer =
        PeerConnectivityIdentity::new(principal.device_id().clone(), presented_transport_identity);
    let snapshot = store
        .load_current(&peer)
        .await
        .map_err(FreshnessResynchronizationError::Persistence)?
        .ok_or(FreshnessResynchronizationError::DurableStateMissing)?;
    if snapshot.plan().peer() != &peer || snapshot.freshness().peer() != &peer {
        return Err(FreshnessResynchronizationError::SnapshotPeerMismatch);
    }

    let token = match snapshot.freshness().lifecycle() {
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(token)
        | CandidatePublicationFreshnessLifecycle::Established(token) => token,
        CandidatePublicationFreshnessLifecycle::RecoveryRequired => {
            return Err(FreshnessResynchronizationError::RecoveryRequired);
        }
        CandidatePublicationFreshnessLifecycle::Retired => {
            return Err(FreshnessResynchronizationError::Retired);
        }
    };

    Ok(ReachabilityFreshnessWireMessage::token_delivery(
        FreshnessTokenDeliveryReason::Resynchronization,
        presented_transport_identity,
        token,
    ))
}

/// Stable wire/codec construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityFreshnessWireError {
    /// PRWF metadata/body is malformed, unknown, invalid, truncated or contains trailing bytes.
    InvalidPayload,
    /// Outer PRWM message kind conflicts with the decoded freshness operation.
    WrongControlMessageKind,
    /// Existing PRWM frame construction rejected the request identifier or payload.
    Transport(RemoteTransportError),
    /// Bootstrap delivery was requested from a non-bootstrap durable lifecycle state.
    BootstrapRecordRequired,
}

impl fmt::Display for ReachabilityFreshnessWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload => {
                formatter.write_str("invalid reachability freshness wire payload")
            }
            Self::WrongControlMessageKind => {
                formatter.write_str("reachability freshness outer control kind mismatch")
            }
            Self::Transport(error) => {
                write!(formatter, "reachability freshness frame rejected: {error}")
            }
            Self::BootstrapRecordRequired => {
                formatter.write_str("bootstrap freshness delivery requires new-lifecycle state")
            }
        }
    }
}

impl std::error::Error for ReachabilityFreshnessWireError {}

/// Fail-closed authenticated current-token resynchronization failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FreshnessResynchronizationError {
    /// Authenticated session or exact transport identity is not current in the registry.
    Registry(RegistryError),
    /// No durable snapshot exists for the exact authenticated current peer lifecycle.
    DurableStateMissing,
    /// Durable store returned a snapshot whose plan/freshness peer does not match the lookup peer.
    SnapshotPeerMismatch,
    /// Durable exact peer lifecycle explicitly requires recovery and cannot disclose a token.
    RecoveryRequired,
    /// Durable exact peer lifecycle is a historical tombstone and cannot disclose a token.
    Retired,
    /// Authoritative durable load was unavailable or ambiguous.
    Persistence(ReachabilityPersistenceError),
}

impl FreshnessResynchronizationError {
    /// Collapses internal failure detail to the stable bounded wire failure taxonomy.
    #[must_use]
    pub const fn wire_failure_code(self) -> FreshnessWireFailureCode {
        match self {
            Self::Registry(_) => FreshnessWireFailureCode::CurrentnessRejected,
            Self::DurableStateMissing => FreshnessWireFailureCode::DurableStateMissing,
            Self::SnapshotPeerMismatch | Self::RecoveryRequired => {
                FreshnessWireFailureCode::RecoveryRequired
            }
            Self::Retired => FreshnessWireFailureCode::Retired,
            Self::Persistence(_) => FreshnessWireFailureCode::PersistenceUnavailable,
        }
    }
}

impl fmt::Display for FreshnessResynchronizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => {
                write!(formatter, "freshness resync currentness rejected: {error}")
            }
            Self::DurableStateMissing => {
                formatter.write_str("freshness resync durable state missing")
            }
            Self::SnapshotPeerMismatch => {
                formatter.write_str("freshness resync durable peer mismatch")
            }
            Self::RecoveryRequired => formatter.write_str("freshness resync recovery required"),
            Self::Retired => formatter.write_str("freshness resync lifecycle retired"),
            Self::Persistence(error) => {
                write!(formatter, "freshness resync persistence failed: {error}")
            }
        }
    }
}

impl std::error::Error for FreshnessResynchronizationError {}
