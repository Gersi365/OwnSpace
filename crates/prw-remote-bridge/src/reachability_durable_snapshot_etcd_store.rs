//! Phase 152 C03e-HG bridge-owned semantic durable-snapshot etcd adapter.
//!
//! This module implements the existing [`ReachabilityDurableStore`] boundary using the canonical
//! bridge-owned durable key/value codecs and the control-plane-owned raw etcd executor. It owns PRW
//! semantic validation, exact requested-peer/key/value binding, freshness currentness, and mapping
//! of definitive/ambiguous provider results. It does not own etcd connection bootstrap,
//! TLS/auth/RBAC/credentials, schema, scans, Watch/lease/TTL, retries, background tasks, owner-map
//! population, runtime activation, networking, or deployment.

#![allow(clippy::manual_async_fn)]

use std::future::Future;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::reachability_durable_snapshot_etcd::{
    ReachabilityDurableSnapshotEtcdExecutor, ReachabilityDurableSnapshotEtcdMutation,
    ReachabilityDurableSnapshotEtcdObservation,
};

use crate::{
    candidate_publication_freshness::CandidatePublicationFreshnessToken,
    reachability_durable_snapshot_codec::{
        decode_reachability_durable_snapshot, encode_reachability_durable_snapshot,
    },
    reachability_durable_snapshot_key_codec::{
        decode_reachability_durable_snapshot_key, encode_reachability_durable_snapshot_key,
    },
    reachability_owner::{
        ReachabilityDurableSnapshot, ReachabilityDurableStore, ReachabilityPersistenceCommit,
        ReachabilityPersistenceError,
    },
};

/// Concrete bridge semantic adapter over the control-plane raw etcd executor.
pub struct ReachabilityDurableSnapshotEtcdStore {
    provider: ReachabilityDurableSnapshotEtcdExecutor,
}

impl ReachabilityDurableSnapshotEtcdStore {
    /// Creates the semantic store around an already-created raw etcd executor.
    #[must_use]
    pub const fn new(provider: ReachabilityDurableSnapshotEtcdExecutor) -> Self {
        Self { provider }
    }

    /// Consumes the store and returns the underlying raw etcd executor.
    #[must_use]
    pub fn into_inner(self) -> ReachabilityDurableSnapshotEtcdExecutor {
        self.provider
    }
}

impl ReachabilityDurableStore for ReachabilityDurableSnapshotEtcdStore {
    fn load_current<'a>(
        &'a mut self,
        peer: &'a PeerConnectivityIdentity,
    ) -> impl Future<
        Output = Result<Option<ReachabilityDurableSnapshot>, ReachabilityPersistenceError>,
    > + Send
    + 'a {
        async move {
            let key = encode_reachability_durable_snapshot_key(peer)
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
            let observation = self
                .provider
                .linearizable_get(&key)
                .await
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
            let Some(observation) = observation else {
                return Ok(None);
            };
            decode_bound_snapshot(peer, observation.key(), observation.value()).map(Some)
        }
    }

    fn compare_and_commit<'a>(
        &'a mut self,
        expected_current: CandidatePublicationFreshnessToken,
        replacement: &'a ReachabilityDurableSnapshot,
    ) -> impl Future<Output = Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError>>
    + Send
    + 'a {
        async move {
            let peer = replacement.plan().peer();
            let key = encode_reachability_durable_snapshot_key(peer)
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
            let replacement_value = encode_reachability_durable_snapshot(replacement)
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;

            let observation = self
                .provider
                .linearizable_get(&key)
                .await
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
            let Some(observation) = observation else {
                return Ok(ReachabilityPersistenceCommit::StaleExpected);
            };
            let current = decode_bound_snapshot(peer, observation.key(), observation.value())?;
            if current.freshness().lifecycle().current_token() != Some(expected_current) {
                return Ok(ReachabilityPersistenceCommit::StaleExpected);
            }

            let mutation = self
                .provider
                .compare_and_put(
                    &key,
                    observation.mod_revision(),
                    observation.value(),
                    &replacement_value,
                )
                .await
                .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;

            match mutation {
                ReachabilityDurableSnapshotEtcdMutation::Committed => {
                    Ok(ReachabilityPersistenceCommit::Committed)
                }
                ReachabilityDurableSnapshotEtcdMutation::CompareFailed(None) => {
                    Ok(ReachabilityPersistenceCommit::StaleExpected)
                }
                ReachabilityDurableSnapshotEtcdMutation::CompareFailed(Some(failure)) => {
                    classify_compare_failure(peer, expected_current, &failure)
                }
            }
        }
    }
}

fn decode_bound_snapshot(
    requested_peer: &PeerConnectivityIdentity,
    key: &[u8],
    value: &[u8],
) -> Result<ReachabilityDurableSnapshot, ReachabilityPersistenceError> {
    let decoded_key = decode_reachability_durable_snapshot_key(key)
        .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
    if &decoded_key != requested_peer {
        return Err(ReachabilityPersistenceError::UnavailableOrAmbiguous);
    }

    let snapshot = decode_reachability_durable_snapshot(value)
        .map_err(|_| ReachabilityPersistenceError::UnavailableOrAmbiguous)?;
    if snapshot.plan().peer() != requested_peer || snapshot.freshness().peer() != requested_peer {
        return Err(ReachabilityPersistenceError::UnavailableOrAmbiguous);
    }
    Ok(snapshot)
}

fn classify_compare_failure(
    requested_peer: &PeerConnectivityIdentity,
    expected_current: CandidatePublicationFreshnessToken,
    failure: &ReachabilityDurableSnapshotEtcdObservation,
) -> Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError> {
    classify_compare_failure_record(
        requested_peer,
        expected_current,
        failure.key(),
        failure.value(),
    )
}

fn classify_compare_failure_record(
    requested_peer: &PeerConnectivityIdentity,
    expected_current: CandidatePublicationFreshnessToken,
    key: &[u8],
    value: &[u8],
) -> Result<ReachabilityPersistenceCommit, ReachabilityPersistenceError> {
    let snapshot = decode_bound_snapshot(requested_peer, key, value)?;
    if snapshot.freshness().lifecycle().current_token() == Some(expected_current) {
        return Err(ReachabilityPersistenceError::UnavailableOrAmbiguous);
    }
    Ok(ReachabilityPersistenceCommit::StaleExpected)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use prw_connectivity::{
        CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
        PeerConnectivityPlanDurableState, TransportIdentity,
    };
    use prw_core::DeviceId;

    use super::*;
    use crate::candidate_publication_freshness::CandidatePublicationFreshnessRecord;

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero transport identity"),
        )
    }

    fn token(marker: u8) -> CandidatePublicationFreshnessToken {
        CandidatePublicationFreshnessToken::new([marker; 32]).expect("non-zero freshness token")
    }

    fn snapshot(
        peer: PeerConnectivityIdentity,
        freshness: CandidatePublicationFreshnessToken,
        with_candidate: bool,
    ) -> ReachabilityDurableSnapshot {
        let (candidates, high_water) = if with_candidate {
            let id = CandidateId::new(1).expect("candidate id");
            let endpoint =
                ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 443)
                    .expect("endpoint");
            (
                vec![ConnectivityCandidate::new(
                    id,
                    ConnectivityPathKind::InternetDirect,
                    endpoint,
                )],
                Some(id),
            )
        } else {
            (Vec::new(), None)
        };
        let plan =
            PeerConnectivityPlanDurableState::from_parts(peer.clone(), candidates, high_water);
        let freshness = CandidatePublicationFreshnessRecord::established(peer, freshness);
        ReachabilityDurableSnapshot::new(plan, freshness).expect("peer-consistent snapshot")
    }

    fn raw(snapshot: &ReachabilityDurableSnapshot) -> (Vec<u8>, Vec<u8>) {
        (
            encode_reachability_durable_snapshot_key(snapshot.plan().peer()).expect("encode key"),
            encode_reachability_durable_snapshot(snapshot).expect("encode value"),
        )
    }

    #[test]
    fn exact_peer_key_value_binding_roundtrips() {
        let expected_peer = peer("durable-etcd-binding", 1);
        let snapshot = snapshot(expected_peer.clone(), token(2), false);
        let (key, value) = raw(&snapshot);

        let decoded = decode_bound_snapshot(&expected_peer, &key, &value).expect("bound snapshot");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn requested_peer_mismatch_fails_closed() {
        let persisted_peer = peer("durable-etcd-persisted", 3);
        let requested_peer = peer("durable-etcd-requested", 4);
        let snapshot = snapshot(persisted_peer, token(5), false);
        let (key, value) = raw(&snapshot);

        assert_eq!(
            decode_bound_snapshot(&requested_peer, &key, &value),
            Err(ReachabilityPersistenceError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn same_expected_token_with_different_bytes_is_ambiguous() {
        let expected_peer = peer("durable-etcd-same-token", 6);
        let expected_token = token(7);
        let before = snapshot(expected_peer.clone(), expected_token, false);
        let failure_snapshot = snapshot(expected_peer.clone(), expected_token, true);
        let (_, before_value) = raw(&before);
        let (failure_key, failure_value) = raw(&failure_snapshot);
        assert_ne!(before_value, failure_value);

        assert_eq!(
            classify_compare_failure_record(
                &expected_peer,
                expected_token,
                &failure_key,
                &failure_value,
            ),
            Err(ReachabilityPersistenceError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn same_expected_token_with_identical_bytes_fails_closed() {
        let expected_peer = peer("durable-etcd-same-token-same-bytes", 8);
        let expected_token = token(9);
        let failure_snapshot = snapshot(expected_peer.clone(), expected_token, false);
        let (failure_key, failure_value) = raw(&failure_snapshot);

        assert_eq!(
            classify_compare_failure_record(
                &expected_peer,
                expected_token,
                &failure_key,
                &failure_value,
            ),
            Err(ReachabilityPersistenceError::UnavailableOrAmbiguous)
        );
    }

    #[test]
    fn different_current_token_after_compare_failure_is_stale() {
        let expected_peer = peer("durable-etcd-stale", 8);
        let expected_token = token(9);
        let failure_snapshot = snapshot(expected_peer.clone(), token(10), false);
        let (failure_key, failure_value) = raw(&failure_snapshot);
        assert_eq!(
            classify_compare_failure_record(
                &expected_peer,
                expected_token,
                &failure_key,
                &failure_value,
            ),
            Ok(ReachabilityPersistenceCommit::StaleExpected)
        );
    }
}
