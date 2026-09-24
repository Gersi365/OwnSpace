//! Phase 152 C02e Tranche 6 distributed live-owner fencing semantics.
//!
//! This module defines only the provider-neutral authority seam required to distinguish durable
//! accepted reachability state from transient distributed runtime ownership. It performs no clock,
//! lease-renewal, persistence, socket, task, traversal, Agent bootstrap or deployment operation.

use std::{fmt, num::NonZeroU128};

use prw_connectivity::PeerConnectivityIdentity;

/// Strictly ordered fencing generation for one exact peer lifecycle.
///
/// The value is not a secret credential. A concrete authority must issue generations monotonically
/// for one exact `DeviceId + TransportIdentity` namespace and must durably prevent reuse of an older
/// generation after restart/failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReachabilityLiveOwnerFence(NonZeroU128);

impl ReachabilityLiveOwnerFence {
    /// Creates a non-zero fencing generation.
    ///
    /// This constructor validates representation only. Production callers must obtain a fence from
    /// a concrete [`ReachabilityLiveOwnerAuthority`], not from request-controlled input.
    ///
    /// # Errors
    ///
    /// Returns [`ReachabilityLiveOwnerFenceError::Zero`] for zero.
    pub const fn new(value: u128) -> Result<Self, ReachabilityLiveOwnerFenceError> {
        match NonZeroU128::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ReachabilityLiveOwnerFenceError::Zero),
        }
    }

    /// Returns the raw ordered generation.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

/// Structural fencing-generation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityLiveOwnerFenceError {
    /// Zero is reserved and never denotes a live-owner generation.
    Zero,
}

impl fmt::Display for ReachabilityLiveOwnerFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Zero => "reachability live-owner fence must be non-zero",
        })
    }
}

impl std::error::Error for ReachabilityLiveOwnerFenceError {}

/// Authority-issued grant for one exact peer lifecycle.
///
/// Construction is exposed for future concrete authority adapters, but the grant carries no
/// authority by possession alone. Every use must still establish exact-peer binding and currentness
/// through the concrete authority. Request payloads must never be allowed to choose this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityLiveOwnerGrant {
    peer: PeerConnectivityIdentity,
    fence: ReachabilityLiveOwnerFence,
}

impl ReachabilityLiveOwnerGrant {
    /// Constructs a grant from already-authoritative allocation results.
    ///
    /// This is an adapter boundary, not an authorization check. Production code must call it only
    /// after a concrete authority has atomically established `fence` as current for `peer`.
    #[must_use]
    pub const fn from_authority(
        peer: PeerConnectivityIdentity,
        fence: ReachabilityLiveOwnerFence,
    ) -> Self {
        Self { peer, fence }
    }

    /// Returns the exact peer lifecycle carried by this grant.
    #[must_use]
    pub const fn peer(&self) -> &PeerConnectivityIdentity {
        &self.peer
    }

    /// Returns the authority-issued fencing generation.
    #[must_use]
    pub const fn fence(&self) -> ReachabilityLiveOwnerFence {
        self.fence
    }

    /// Requires this grant to belong to the exact expected peer lifecycle.
    ///
    /// # Errors
    ///
    /// Rejects a grant for any other `DeviceId + TransportIdentity` namespace.
    pub fn require_peer(
        &self,
        expected: &PeerConnectivityIdentity,
    ) -> Result<(), ReachabilityLiveOwnerGrantError> {
        if &self.peer == expected {
            Ok(())
        } else {
            Err(ReachabilityLiveOwnerGrantError::PeerMismatch)
        }
    }
}

/// Structural live-owner grant failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityLiveOwnerGrantError {
    /// Grant belongs to a different exact logical/transport peer lifecycle.
    PeerMismatch,
}

impl fmt::Display for ReachabilityLiveOwnerGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PeerMismatch => "reachability live-owner grant peer mismatch",
        })
    }
}

impl std::error::Error for ReachabilityLiveOwnerGrantError {}

/// Result of attempting to acquire transient live-owner authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerAcquisition {
    /// The authority atomically established this exact grant as current.
    Granted(ReachabilityLiveOwnerGrant),
    /// Current backend policy did not permit replacement/acquisition at this time.
    Contended,
}

/// Definite currentness result for one previously issued grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerCurrentness {
    /// This grant is the exact current generation for its peer lifecycle.
    Current,
    /// A newer grant or retirement/replacement state makes this grant stale.
    Stale,
}

/// Result of an explicit release attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityLiveOwnerRelease {
    /// The exact current grant was released.
    Released,
    /// The supplied grant was already stale/not current.
    NotCurrent,
}

/// Ambiguous/unavailable distributed live-owner authority failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityLiveOwnerAuthorityError {
    /// Currentness/acquisition outcome cannot be proven and therefore must fail closed.
    UnavailableOrAmbiguous,
    /// The concrete ordered-generation space cannot issue a strictly newer safe fence.
    FenceExhausted,
}

impl fmt::Display for ReachabilityLiveOwnerAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnavailableOrAmbiguous => {
                "reachability live-owner authority is unavailable or ambiguous"
            }
            Self::FenceExhausted => "reachability live-owner fencing generation is exhausted",
        })
    }
}

impl std::error::Error for ReachabilityLiveOwnerAuthorityError {}

/// Distributed transient-owner authority for exact reachability peer lifecycles.
///
/// A concrete implementation owns acquisition/replacement policy, lease/TTL/heartbeat mechanics if
/// any, persistence and failover. Those implementation choices are deliberately outside this seam.
///
/// Safety requirements for every implementation:
///
/// - every successful grant for one exact peer uses a generation strictly newer than every prior
///   grant for that same peer lifecycle;
/// - replacement currentness is durable enough that authority restart/failover cannot make an older
///   generation current again;
/// - ambiguous results never become successful ownership;
/// - explicit release is not required for stale-owner safety;
/// - future real runtime side effects must be fenced separately; a one-time currentness pre-check
///   does not by itself prove stale network work is impossible.
pub trait ReachabilityLiveOwnerAuthority {
    /// Attempts to establish one current live-owner grant for `peer`.
    ///
    /// A returned [`ReachabilityLiveOwnerAcquisition::Granted`] value means every older grant for
    /// the same exact peer lifecycle is stale.
    ///
    /// # Errors
    ///
    /// Returns an authority error when acquisition outcome/currentness is unavailable or when a
    /// concrete ordered-generation representation cannot safely advance.
    fn acquire(
        &mut self,
        peer: &PeerConnectivityIdentity,
    ) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError>;

    /// Establishes whether an already-issued grant is still exact-current.
    ///
    /// # Errors
    ///
    /// Ambiguous/unavailable authority state must be returned as an error rather than `Current`.
    fn currentness(
        &mut self,
        grant: &ReachabilityLiveOwnerGrant,
    ) -> Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError>;

    /// Releases the exact current grant when supported by the concrete authority.
    ///
    /// Release is a liveness operation only; safety must still hold when the owner crashes without
    /// calling it.
    ///
    /// # Errors
    ///
    /// Ambiguous release state is reported rather than treated as released/currentness proof.
    fn release(
        &mut self,
        grant: &ReachabilityLiveOwnerGrant,
    ) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError>;
}

#[cfg(test)]
mod tests {
    use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
    use prw_core::DeviceId;

    use super::{
        ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthority,
        ReachabilityLiveOwnerAuthorityError, ReachabilityLiveOwnerCurrentness,
        ReachabilityLiveOwnerFence, ReachabilityLiveOwnerFenceError, ReachabilityLiveOwnerGrant,
        ReachabilityLiveOwnerGrantError, ReachabilityLiveOwnerRelease,
    };

    struct ReferenceAuthority {
        current: Option<ReachabilityLiveOwnerGrant>,
        last_issued: u128,
    }

    impl ReferenceAuthority {
        const fn new() -> Self {
            Self {
                current: None,
                last_issued: 0,
            }
        }
    }

    impl ReachabilityLiveOwnerAuthority for ReferenceAuthority {
        fn acquire(
            &mut self,
            peer: &PeerConnectivityIdentity,
        ) -> Result<ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthorityError> {
            let next = self
                .last_issued
                .checked_add(1)
                .ok_or(ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;
            let fence = ReachabilityLiveOwnerFence::new(next)
                .map_err(|_| ReachabilityLiveOwnerAuthorityError::FenceExhausted)?;
            let grant = ReachabilityLiveOwnerGrant::from_authority(peer.clone(), fence);
            self.last_issued = next;
            self.current = Some(grant.clone());
            Ok(ReachabilityLiveOwnerAcquisition::Granted(grant))
        }

        fn currentness(
            &mut self,
            grant: &ReachabilityLiveOwnerGrant,
        ) -> Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError> {
            Ok(if self.current.as_ref() == Some(grant) {
                ReachabilityLiveOwnerCurrentness::Current
            } else {
                ReachabilityLiveOwnerCurrentness::Stale
            })
        }

        fn release(
            &mut self,
            grant: &ReachabilityLiveOwnerGrant,
        ) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
            if self.current.as_ref() == Some(grant) {
                self.current = None;
                Ok(ReachabilityLiveOwnerRelease::Released)
            } else {
                Ok(ReachabilityLiveOwnerRelease::NotCurrent)
            }
        }
    }

    fn peer(device: &str, transport_byte: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid device id"),
            TransportIdentity::new([transport_byte; 32]).expect("non-zero transport identity"),
        )
    }

    fn granted(
        authority: &mut ReferenceAuthority,
        peer: &PeerConnectivityIdentity,
    ) -> ReachabilityLiveOwnerGrant {
        match authority.acquire(peer).expect("reference acquisition") {
            ReachabilityLiveOwnerAcquisition::Granted(grant) => grant,
            ReachabilityLiveOwnerAcquisition::Contended => panic!("reference authority grants"),
        }
    }

    #[test]
    fn fence_rejects_zero() {
        assert_eq!(
            ReachabilityLiveOwnerFence::new(0),
            Err(ReachabilityLiveOwnerFenceError::Zero)
        );
    }

    #[test]
    fn newer_grant_fences_older_grant() {
        let peer = peer("device-a", 1);
        let mut authority = ReferenceAuthority::new();
        let first = granted(&mut authority, &peer);
        let second = granted(&mut authority, &peer);

        assert!(second.fence() > first.fence());
        assert_eq!(
            authority.currentness(&first),
            Ok(ReachabilityLiveOwnerCurrentness::Stale)
        );
        assert_eq!(
            authority.currentness(&second),
            Ok(ReachabilityLiveOwnerCurrentness::Current)
        );
    }

    #[test]
    fn grant_is_bound_to_exact_peer_lifecycle() {
        let peer_a = peer("device-a", 1);
        let peer_b = peer("device-a", 2);
        let mut authority = ReferenceAuthority::new();
        let grant = granted(&mut authority, &peer_a);

        assert_eq!(grant.require_peer(&peer_a), Ok(()));
        assert_eq!(
            grant.require_peer(&peer_b),
            Err(ReachabilityLiveOwnerGrantError::PeerMismatch)
        );
    }

    #[test]
    fn stale_release_cannot_clear_newer_grant() {
        let peer = peer("device-a", 1);
        let mut authority = ReferenceAuthority::new();
        let first = granted(&mut authority, &peer);
        let second = granted(&mut authority, &peer);

        assert_eq!(
            authority.release(&first),
            Ok(ReachabilityLiveOwnerRelease::NotCurrent)
        );
        assert_eq!(
            authority.currentness(&second),
            Ok(ReachabilityLiveOwnerCurrentness::Current)
        );
    }

    #[test]
    fn current_release_does_not_make_old_grant_current_again() {
        let peer = peer("device-a", 1);
        let mut authority = ReferenceAuthority::new();
        let first = granted(&mut authority, &peer);
        let second = granted(&mut authority, &peer);

        assert_eq!(
            authority.release(&second),
            Ok(ReachabilityLiveOwnerRelease::Released)
        );
        assert_eq!(
            authority.currentness(&first),
            Ok(ReachabilityLiveOwnerCurrentness::Stale)
        );
    }
}
