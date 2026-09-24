use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_core::DeviceId;
use prw_remote_bridge::reachability_live_owner::{
    ReachabilityLiveOwnerAcquisition, ReachabilityLiveOwnerAuthority,
    ReachabilityLiveOwnerAuthorityError, ReachabilityLiveOwnerCurrentness,
    ReachabilityLiveOwnerFence, ReachabilityLiveOwnerGrant, ReachabilityLiveOwnerRelease,
};

/// Test-only authority model keyed by exact `DeviceId + TransportIdentity` lifecycle.
///
/// This deliberately models only namespace/currentness semantics. Registry currentness remains a
/// separate production authority: a transport rotation can make the old transport non-current even
/// though the old and replacement transports are distinct live-owner namespaces here.
struct PeerScopedReferenceAuthority {
    current: Vec<ReachabilityLiveOwnerGrant>,
    last_issued: u128,
}

impl PeerScopedReferenceAuthority {
    const fn new() -> Self {
        Self {
            current: Vec::new(),
            last_issued: 0,
        }
    }
}

impl ReachabilityLiveOwnerAuthority for PeerScopedReferenceAuthority {
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

        let mut replaced = false;
        for current in &mut self.current {
            if current.peer() == peer {
                current.clone_from(&grant);
                replaced = true;
                break;
            }
        }
        if !replaced {
            self.current.push(grant.clone());
        }

        Ok(ReachabilityLiveOwnerAcquisition::Granted(grant))
    }

    fn currentness(
        &mut self,
        grant: &ReachabilityLiveOwnerGrant,
    ) -> Result<ReachabilityLiveOwnerCurrentness, ReachabilityLiveOwnerAuthorityError> {
        Ok(if self.current.contains(grant) {
            ReachabilityLiveOwnerCurrentness::Current
        } else {
            ReachabilityLiveOwnerCurrentness::Stale
        })
    }

    fn release(
        &mut self,
        grant: &ReachabilityLiveOwnerGrant,
    ) -> Result<ReachabilityLiveOwnerRelease, ReachabilityLiveOwnerAuthorityError> {
        let Some(index) = self.current.iter().position(|current| current == grant) else {
            return Ok(ReachabilityLiveOwnerRelease::NotCurrent);
        };
        self.current.remove(index);
        Ok(ReachabilityLiveOwnerRelease::Released)
    }
}

fn peer(device: &str, transport_byte: u8) -> PeerConnectivityIdentity {
    PeerConnectivityIdentity::new(
        DeviceId::new(device).expect("valid device id"),
        TransportIdentity::new([transport_byte; 32]).expect("non-zero transport identity"),
    )
}

fn granted(
    authority: &mut PeerScopedReferenceAuthority,
    peer: &PeerConnectivityIdentity,
) -> ReachabilityLiveOwnerGrant {
    match authority.acquire(peer).expect("reference acquisition") {
        ReachabilityLiveOwnerAcquisition::Granted(grant) => grant,
        ReachabilityLiveOwnerAcquisition::Contended => panic!("reference authority grants"),
    }
}

#[test]
fn acquiring_another_peer_does_not_stale_existing_peer() {
    let peer_a = peer("device-a", 1);
    let peer_b = peer("device-b", 1);
    let mut authority = PeerScopedReferenceAuthority::new();

    let grant_a = granted(&mut authority, &peer_a);
    let grant_b = granted(&mut authority, &peer_b);

    assert_eq!(
        authority.currentness(&grant_a),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
    assert_eq!(
        authority.currentness(&grant_b),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
}

#[test]
fn replacement_fences_only_the_same_exact_peer_namespace() {
    let peer_a = peer("device-a", 1);
    let peer_b = peer("device-b", 1);
    let mut authority = PeerScopedReferenceAuthority::new();

    let first_a = granted(&mut authority, &peer_a);
    let grant_b = granted(&mut authority, &peer_b);
    let second_a = granted(&mut authority, &peer_a);

    assert!(second_a.fence() > first_a.fence());
    assert_eq!(
        authority.currentness(&first_a),
        Ok(ReachabilityLiveOwnerCurrentness::Stale)
    );
    assert_eq!(
        authority.currentness(&second_a),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
    assert_eq!(
        authority.currentness(&grant_b),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
}

#[test]
fn transport_rotation_uses_a_distinct_authority_namespace() {
    let old_transport_peer = peer("device-a", 1);
    let replacement_transport_peer = peer("device-a", 2);
    let mut authority = PeerScopedReferenceAuthority::new();

    let old_grant = granted(&mut authority, &old_transport_peer);
    let replacement_grant = granted(&mut authority, &replacement_transport_peer);

    assert_eq!(old_grant.peer(), &old_transport_peer);
    assert_eq!(replacement_grant.peer(), &replacement_transport_peer);
    assert_eq!(
        authority.currentness(&old_grant),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
    assert_eq!(
        authority.currentness(&replacement_grant),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
}

#[test]
fn stale_release_in_one_namespace_cannot_clear_another_namespace() {
    let peer_a = peer("device-a", 1);
    let peer_b = peer("device-b", 1);
    let mut authority = PeerScopedReferenceAuthority::new();

    let first_a = granted(&mut authority, &peer_a);
    let grant_b = granted(&mut authority, &peer_b);
    let second_a = granted(&mut authority, &peer_a);

    assert_eq!(
        authority.release(&first_a),
        Ok(ReachabilityLiveOwnerRelease::NotCurrent)
    );
    assert_eq!(
        authority.currentness(&second_a),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
    assert_eq!(
        authority.currentness(&grant_b),
        Ok(ReachabilityLiveOwnerCurrentness::Current)
    );
}
