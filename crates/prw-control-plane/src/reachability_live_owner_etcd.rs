//! Phase 152 C02f-AD real `etcd-client` wiring for live-owner authority reads and transactions.
//!
//! This module binds the already-validated C02f-AA codec and C02f-AB deterministic transaction
//! plan to `etcd-client = 0.19.0`. It deliberately accepts an already-created [`KvClient`] instead
//! of selecting endpoints or calling `Client::connect`, uses default linearizable exact-key Gets,
//! and executes only the selected dual-CAS Txn shape. It does not configure TLS/auth/RBAC, Watch,
//! lease/TTL behavior, fence allocation, attempt-ID generation, recovery/bootstrap, runtime/task
//! ownership, or production activation.

mod first_owner;

pub use first_owner::{
    ReachabilityLiveOwnerFirstOwnerExecutionError, ReachabilityLiveOwnerFirstOwnerResolvedOutcome,
    ReachabilityLiveOwnerResolvedFirstOwner,
};

use std::{fmt, num::NonZeroU128};

use etcd_client::{Compare, CompareOp, GetResponse, KvClient, Txn, TxnOp, TxnOpResponse};
use prw_connectivity::PeerConnectivityIdentity;

use crate::{
    reachability_live_owner_codec::{ReachabilityLiveOwnerCodecError, encode_live_owner_key},
    reachability_live_owner_txn::{
        LiveOwnerDefinitiveMutation, LiveOwnerObservation, LiveOwnerProviderCurrentness,
        LiveOwnerTxnCompare, LiveOwnerTxnError, LiveOwnerTxnOperation, LiveOwnerTxnPlan,
        classify_currentness, classify_definitive_mutation,
    },
};

/// Real etcd KV boundary for the selected live-owner exact-key authority protocol.
///
/// Construction itself performs no network I/O. The caller supplies an already-created etcd KV
/// client; endpoint selection and connection/bootstrap ownership remain outside C02f-AD.
pub struct ReachabilityLiveOwnerEtcdStore {
    kv: KvClient,
}

impl ReachabilityLiveOwnerEtcdStore {
    /// Wraps an already-created etcd KV client without contacting an endpoint.
    #[must_use]
    pub const fn new(kv: KvClient) -> Self {
        Self { kv }
    }

    /// Consumes the store and returns the underlying etcd KV client.
    #[must_use]
    pub fn into_inner(self) -> KvClient {
        self.kv
    }

    /// Performs one latest linearizable Get for the exact peer authority key.
    ///
    /// `etcd-client` Gets are linearizable by default. This path intentionally passes no
    /// `GetOptions::with_serializable()` option.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for key-encoding failure, etcd read unavailability, impossible
    /// Get cardinality/key mismatch, or malformed/non-canonical persisted authority state.
    pub async fn linearizable_observation(
        &mut self,
        peer: &PeerConnectivityIdentity,
    ) -> Result<Option<LiveOwnerObservation>, ReachabilityLiveOwnerEtcdError> {
        let key = encode_live_owner_key(peer)?;
        let response = self
            .kv
            .get(key.clone(), None)
            .await
            .map_err(ReachabilityLiveOwnerEtcdError::ReadUnavailable)?;
        decode_exact_get(&key, &response)
    }

    /// Proves currentness from one real linearizable exact-key Get plus C02f-AB classification.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when authority cannot be read or validated, including missing
    /// established state. No provider failure can map to `Current`.
    pub async fn currentness(
        &mut self,
        peer: &PeerConnectivityIdentity,
        fence: NonZeroU128,
    ) -> Result<LiveOwnerProviderCurrentness, ReachabilityLiveOwnerEtcdError> {
        let observation = self.linearizable_observation(peer).await?;
        classify_currentness(peer, fence, observation.as_ref())
            .map_err(ReachabilityLiveOwnerEtcdError::from)
    }

    /// Executes one canonical C02f-AB dual-CAS mutation through a real etcd Txn.
    ///
    /// The Txn contains exactly the selected `mod_revision == observed` and exact-value compares,
    /// exactly one Put on success, and exactly one default-linearizable exact-key Get on compare
    /// failure. An RPC error is classified as indeterminate; callers must re-observe authority
    /// before any retry and must never blindly retransmit the mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ReachabilityLiveOwnerEtcdError::MutationIndeterminate`] when etcd does not return a
    /// definitive Txn response. Structural response mismatches and malformed failure observations
    /// also fail closed.
    pub async fn execute(
        &mut self,
        plan: &LiveOwnerTxnPlan,
    ) -> Result<LiveOwnerDefinitiveMutation, ReachabilityLiveOwnerEtcdError> {
        let transaction = build_etcd_transaction(plan);
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(ReachabilityLiveOwnerEtcdError::MutationIndeterminate)?;
        classify_etcd_transaction_response(plan, &response)
    }
}

/// Fail-closed real-etcd wiring error for C02f-AD.
#[derive(Debug)]
pub enum ReachabilityLiveOwnerEtcdError {
    /// Exact peer key construction failed before provider I/O.
    Codec(ReachabilityLiveOwnerCodecError),
    /// Deterministic C02f-AB validation/classification failed.
    Transaction(LiveOwnerTxnError),
    /// A linearizable authority read could not return an authoritative response.
    ReadUnavailable(etcd_client::Error),
    /// A mutation RPC returned no definitive Txn response; re-observation is mandatory.
    MutationIndeterminate(etcd_client::Error),
    /// An exact-key Get returned more than one key-value pair.
    UnexpectedGetCardinality {
        /// Number of key-value pairs returned by etcd.
        actual: usize,
    },
    /// An exact-key Get returned a key different from the requested canonical key.
    UnexpectedGetKey,
    /// A definitive Txn response did not contain exactly the selected branch operation response.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for ReachabilityLiveOwnerEtcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "{error}"),
            Self::Transaction(error) => write!(formatter, "{error}"),
            Self::ReadUnavailable(error) => {
                write!(
                    formatter,
                    "live-owner etcd linearizable read unavailable: {error}"
                )
            }
            Self::MutationIndeterminate(error) => {
                write!(
                    formatter,
                    "live-owner etcd mutation outcome is indeterminate: {error}"
                )
            }
            Self::UnexpectedGetCardinality { actual } => write!(
                formatter,
                "live-owner exact-key Get returned unexpected cardinality {actual}"
            ),
            Self::UnexpectedGetKey => {
                formatter.write_str("live-owner exact-key Get returned another key")
            }
            Self::UnexpectedTxnResponseShape => formatter
                .write_str("live-owner etcd Txn returned an unexpected branch response shape"),
        }
    }
}

impl std::error::Error for ReachabilityLiveOwnerEtcdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::ReadUnavailable(error) | Self::MutationIndeterminate(error) => Some(error),
            Self::UnexpectedGetCardinality { .. }
            | Self::UnexpectedGetKey
            | Self::UnexpectedTxnResponseShape => None,
        }
    }
}

impl From<ReachabilityLiveOwnerCodecError> for ReachabilityLiveOwnerEtcdError {
    fn from(value: ReachabilityLiveOwnerCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<LiveOwnerTxnError> for ReachabilityLiveOwnerEtcdError {
    fn from(value: LiveOwnerTxnError) -> Self {
        Self::Transaction(value)
    }
}

fn build_etcd_transaction(plan: &LiveOwnerTxnPlan) -> Txn {
    let compares = plan.compares().iter().map(etcd_compare).collect::<Vec<_>>();

    let LiveOwnerTxnOperation::Put { key, value } = plan.success() else {
        unreachable!("canonical live-owner success branch is always Put")
    };
    let success = TxnOp::put(key.clone(), value.clone(), None);

    let LiveOwnerTxnOperation::LinearizableGet { key } = plan.failure() else {
        unreachable!("canonical live-owner failure branch is always linearizable Get")
    };
    let failure = TxnOp::get(key.clone(), None);

    Txn::new()
        .when(compares)
        .and_then(vec![success])
        .or_else(vec![failure])
}

fn etcd_compare(compare: &LiveOwnerTxnCompare) -> Compare {
    match compare {
        LiveOwnerTxnCompare::ModRevisionEquals { key, expected } => {
            Compare::mod_revision(key.clone(), CompareOp::Equal, *expected)
        }
        LiveOwnerTxnCompare::ExactValueEquals { key, expected } => {
            Compare::value(key.clone(), CompareOp::Equal, expected.clone())
        }
    }
}

fn classify_etcd_transaction_response(
    plan: &LiveOwnerTxnPlan,
    response: &etcd_client::TxnResponse,
) -> Result<LiveOwnerDefinitiveMutation, ReachabilityLiveOwnerEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(ReachabilityLiveOwnerEtcdError::UnexpectedTxnResponseShape);
        }
        return classify_definitive_mutation(plan, true, None)
            .map_err(ReachabilityLiveOwnerEtcdError::from);
    }

    let [TxnOpResponse::Get(get_response)] = responses.as_slice() else {
        return Err(ReachabilityLiveOwnerEtcdError::UnexpectedTxnResponseShape);
    };
    let LiveOwnerTxnOperation::LinearizableGet { key } = plan.failure() else {
        unreachable!("canonical live-owner failure branch is always linearizable Get")
    };
    let observation =
        decode_exact_get(key, get_response)?.ok_or(LiveOwnerTxnError::MissingEstablishedState)?;
    classify_definitive_mutation(plan, false, Some(observation))
        .map_err(ReachabilityLiveOwnerEtcdError::from)
}

fn decode_exact_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<LiveOwnerObservation>, ReachabilityLiveOwnerEtcdError> {
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(ReachabilityLiveOwnerEtcdError::UnexpectedGetKey);
            }
            Ok(Some(LiveOwnerObservation::decode(
                kv.key().to_vec(),
                kv.value().to_vec(),
                kv.mod_revision(),
            )?))
        }
        kvs => Err(ReachabilityLiveOwnerEtcdError::UnexpectedGetCardinality { actual: kvs.len() }),
    }
}

#[cfg(test)]
mod tests {
    use prw_connectivity::TransportIdentity;
    use prw_core::DeviceId;

    use super::*;
    use crate::{
        reachability_live_owner_codec::{
            AuthorityAttemptId, LiveOwnerLifecycle, ReachabilityLiveOwnerAuthorityRecord,
            encode_live_owner_record,
        },
        reachability_live_owner_txn::plan_acquisition,
    };

    fn peer(device: &str, marker: u8) -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new(device).expect("valid DeviceId"),
            TransportIdentity::new([marker; 32]).expect("non-zero TransportIdentity"),
        )
    }

    fn fence(value: u128) -> NonZeroU128 {
        NonZeroU128::new(value).expect("non-zero fence")
    }

    fn attempt(marker: u8) -> AuthorityAttemptId {
        AuthorityAttemptId::new([marker; 32]).expect("non-zero attempt id")
    }

    fn observation(
        peer: PeerConnectivityIdentity,
        lifecycle: LiveOwnerLifecycle,
        fence_value: u128,
        attempt_marker: u8,
        revision: i64,
    ) -> LiveOwnerObservation {
        let current = ReachabilityLiveOwnerAuthorityRecord::current(
            peer,
            fence(fence_value),
            attempt(attempt_marker),
        );
        let record = if lifecycle == LiveOwnerLifecycle::Current {
            current
        } else {
            current.released_successor()
        };
        let key = encode_live_owner_key(record.peer()).expect("encode key");
        let value = encode_live_owner_record(&record).expect("encode record");
        LiveOwnerObservation::decode(key, value, revision).expect("decode observation")
    }

    #[test]
    fn canonical_plan_materializes_real_etcd_transaction_without_endpoint() {
        let peer = peer("etcd-txn-shape", 1);
        let before = observation(peer.clone(), LiveOwnerLifecycle::Released, 10, 2, 20);
        let successor = ReachabilityLiveOwnerAuthorityRecord::current(peer, fence(11), attempt(3));
        let plan = plan_acquisition(&before, successor).expect("plan acquisition");

        let _transaction = build_etcd_transaction(&plan);
    }
}

/// Bounded C02f-AE indeterminate-mutation reconciliation orchestration.
pub mod reconciliation;
