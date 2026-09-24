//! Phase 152 C02e verifier-owned candidate-publication freshness representation.
//!
//! Tranche 3 selected the production token/lifecycle representation. Tranche 4 consumes this
//! representation from the production reachability owner and durable compare-and-commit seam.
//! This module still selects no database product, persistence serialization, wire message, socket,
//! async runtime, network transport, Agent bootstrap activation, or deployment behavior.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;

/// Exact byte width of one verifier-issued candidate-publication freshness token.
pub const CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES: usize = 32;

/// Opaque verifier-issued candidate-publication freshness token.
///
/// The token is replay-ordering state, not an authentication credential. Production authority
/// must generate each installed token from a cryptographically secure verifier-owned entropy
/// source and must never accept an all-zero value as a current or bootstrap token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidatePublicationFreshnessToken([u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES]);

impl CandidatePublicationFreshnessToken {
    /// Creates one exact non-zero opaque token from verifier-owned bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CandidatePublicationFreshnessRepresentationError::InvalidAllZeroToken`] when
    /// `bytes` is the all-zero value. The all-zero value is reserved as invalid so missing or
    /// default state can never alias a valid freshness token.
    pub fn new(
        bytes: [u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES],
    ) -> Result<Self, CandidatePublicationFreshnessRepresentationError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(CandidatePublicationFreshnessRepresentationError::InvalidAllZeroToken);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact opaque token bytes without assigning any numeric or timestamp meaning.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES] {
        &self.0
    }
}

/// Durable semantic state for one exact peer connectivity lifecycle.
///
/// Absence from storage is deliberately not represented here as `NewLifecycleEligible`.
/// New-lifecycle eligibility must be established authoritatively. `RecoveryRequired` is the
/// fail-closed state when an existing lifecycle's exact freshness cannot be recovered. `Retired`
/// is a durable tombstone preventing a historical `DeviceId + TransportIdentity` from silently
/// becoming a fresh replay namespace if that transport identity value is seen again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePublicationFreshnessLifecycle {
    /// Authoritatively new peer lifecycle with verifier-issued bootstrap freshness.
    NewLifecycleEligible(CandidatePublicationFreshnessToken),
    /// Established peer lifecycle with the verifier-owned current expected token.
    Established(CandidatePublicationFreshnessToken),
    /// Existing/current lifecycle whose exact freshness cannot be authoritatively recovered.
    RecoveryRequired,
    /// Historical lifecycle retained as a non-bootstrap-eligible tombstone.
    Retired,
}

impl CandidatePublicationFreshnessLifecycle {
    /// Returns current verifier token material only for bootstrap-eligible or established state.
    #[must_use]
    pub const fn current_token(self) -> Option<CandidatePublicationFreshnessToken> {
        match self {
            Self::NewLifecycleEligible(token) | Self::Established(token) => Some(token),
            Self::RecoveryRequired | Self::Retired => None,
        }
    }
}

/// Logical durable record keyed to one exact authenticated peer connectivity identity.
///
/// This type is a persistence-neutral schema boundary. It intentionally contains no database
/// key encoding, revision counter, session ID, requester ID, endpoint, clock value, or wire tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePublicationFreshnessRecord {
    peer: PeerConnectivityIdentity,
    lifecycle: CandidatePublicationFreshnessLifecycle,
}

impl CandidatePublicationFreshnessRecord {
    /// Creates an explicitly authorized new-lifecycle bootstrap record.
    #[must_use]
    pub const fn new_lifecycle_eligible(
        peer: PeerConnectivityIdentity,
        verifier_token: CandidatePublicationFreshnessToken,
    ) -> Self {
        Self {
            peer,
            lifecycle: CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(verifier_token),
        }
    }

    /// Creates a restored/established durable record with exact current verifier freshness.
    #[must_use]
    pub const fn established(
        peer: PeerConnectivityIdentity,
        verifier_token: CandidatePublicationFreshnessToken,
    ) -> Self {
        Self {
            peer,
            lifecycle: CandidatePublicationFreshnessLifecycle::Established(verifier_token),
        }
    }

    /// Creates the explicit fail-closed state for an existing lifecycle with unavailable state.
    #[must_use]
    pub const fn recovery_required(peer: PeerConnectivityIdentity) -> Self {
        Self {
            peer,
            lifecycle: CandidatePublicationFreshnessLifecycle::RecoveryRequired,
        }
    }

    /// Creates a durable historical tombstone for a retired peer lifecycle.
    #[must_use]
    pub const fn retired(peer: PeerConnectivityIdentity) -> Self {
        Self {
            peer,
            lifecycle: CandidatePublicationFreshnessLifecycle::Retired,
        }
    }

    /// Returns the exact logical/transport peer identity that scopes this replay authority.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the durable lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> CandidatePublicationFreshnessLifecycle {
        self.lifecycle
    }
}

/// Stable representation-level construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationFreshnessRepresentationError {
    /// The all-zero token is reserved as invalid/default state.
    InvalidAllZeroToken,
}

impl fmt::Display for CandidatePublicationFreshnessRepresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAllZeroToken => {
                "candidate publication freshness token must not be all zero"
            }
        })
    }
}

impl std::error::Error for CandidatePublicationFreshnessRepresentationError {}
