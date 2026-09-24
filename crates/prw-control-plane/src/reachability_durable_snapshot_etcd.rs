//! Phase 152 C03e-HG raw exact-key etcd executor for durable reachability snapshots.
//!
//! This control-plane module owns only provider-specific etcd KV execution over opaque key/value
//! bytes. It accepts an already-created [`KvClient`], performs default-linearizable exact-key Gets,
//! and executes the C03e-HF-selected dual CAS on exact `mod_revision` plus exact observed value.
//! It does not decode PRW durable snapshot semantics, construct bridge-owned types, configure
//! endpoints/TLS/auth/RBAC, create records, scan prefixes, use Watch/lease/TTL, retry mutations,
//! spawn tasks, activate recovery, or perform production deployment.

use std::fmt;

use etcd_client::{Compare, CompareOp, GetResponse, KvClient, Txn, TxnOp, TxnOpResponse};

/// One exact raw etcd observation for a durable reachability snapshot key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityDurableSnapshotEtcdObservation {
    key: Vec<u8>,
    value: Vec<u8>,
    mod_revision: i64,
}

impl ReachabilityDurableSnapshotEtcdObservation {
    /// Returns the exact observed key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the exact observed raw value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the positive etcd modification revision observed with this value.
    #[must_use]
    pub const fn mod_revision(&self) -> i64 {
        self.mod_revision
    }
}

/// Definitive provider result of one selected exact-key dual-CAS mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityDurableSnapshotEtcdMutation {
    /// The selected Put branch committed.
    Committed,
    /// The compare branch failed definitively; the optional value is the linearizable failure read.
    CompareFailed(Option<ReachabilityDurableSnapshotEtcdObservation>),
}

/// Fail-closed provider execution error for the durable snapshot etcd seam.
#[derive(Debug)]
pub enum ReachabilityDurableSnapshotEtcdError {
    /// A default-linearizable exact-key read could not return an authoritative response.
    ReadUnavailable(etcd_client::Error),
    /// A mutation RPC returned no definitive transaction response.
    MutationIndeterminate(etcd_client::Error),
    /// An exact-key Get returned more than one key-value pair.
    UnexpectedGetCardinality {
        /// Actual number of returned key-value pairs.
        actual: usize,
    },
    /// An exact-key Get returned a key different from the requested key.
    UnexpectedGetKey,
    /// A returned or supplied etcd modification revision was not positive.
    InvalidModRevision {
        /// Invalid revision value.
        actual: i64,
    },
    /// A definitive transaction response did not contain exactly the selected branch operation.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for ReachabilityDurableSnapshotEtcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadUnavailable(error) => {
                write!(
                    formatter,
                    "durable snapshot etcd linearizable read unavailable: {error}"
                )
            }
            Self::MutationIndeterminate(error) => {
                write!(
                    formatter,
                    "durable snapshot etcd mutation outcome is indeterminate: {error}"
                )
            }
            Self::UnexpectedGetCardinality { actual } => write!(
                formatter,
                "durable snapshot exact-key Get returned unexpected cardinality {actual}"
            ),
            Self::UnexpectedGetKey => {
                formatter.write_str("durable snapshot exact-key Get returned another key")
            }
            Self::InvalidModRevision { actual } => write!(
                formatter,
                "durable snapshot etcd modification revision must be positive, got {actual}"
            ),
            Self::UnexpectedTxnResponseShape => formatter.write_str(
                "durable snapshot etcd Txn returned an unexpected branch response shape",
            ),
        }
    }
}

impl std::error::Error for ReachabilityDurableSnapshotEtcdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadUnavailable(error) | Self::MutationIndeterminate(error) => Some(error),
            Self::UnexpectedGetCardinality { .. }
            | Self::UnexpectedGetKey
            | Self::InvalidModRevision { .. }
            | Self::UnexpectedTxnResponseShape => None,
        }
    }
}

/// Raw etcd executor for one exact durable-snapshot key at a time.
pub struct ReachabilityDurableSnapshotEtcdExecutor {
    kv: KvClient,
}

impl ReachabilityDurableSnapshotEtcdExecutor {
    /// Wraps an already-created etcd KV client without contacting an endpoint.
    #[must_use]
    pub const fn new(kv: KvClient) -> Self {
        Self { kv }
    }

    /// Consumes the executor and returns the underlying etcd KV client.
    #[must_use]
    pub fn into_inner(self) -> KvClient {
        self.kv
    }

    /// Performs one default-linearizable Get for exactly `key`.
    ///
    /// # Errors
    ///
    /// Fails closed on provider unavailability, impossible cardinality, key mismatch, or invalid
    /// provider revision evidence.
    pub async fn linearizable_get(
        &mut self,
        key: &[u8],
    ) -> Result<
        Option<ReachabilityDurableSnapshotEtcdObservation>,
        ReachabilityDurableSnapshotEtcdError,
    > {
        let response = self
            .kv
            .get(key.to_vec(), None)
            .await
            .map_err(ReachabilityDurableSnapshotEtcdError::ReadUnavailable)?;
        decode_exact_get(key, &response)
    }

    /// Executes the selected exact-key `mod_revision + value` dual CAS and replacement Put.
    ///
    /// The success branch contains exactly one Put. The compare-failure branch contains exactly one
    /// default-linearizable exact-key Get so the semantic owner can classify the definitive
    /// non-commit from authoritative bytes. Provider RPC failure is indeterminate and is never
    /// converted into a successful or stale semantic result here.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-positive observed revision, indeterminate provider RPC result, or an
    /// unexpected definitive transaction response shape.
    pub async fn compare_and_put(
        &mut self,
        key: &[u8],
        observed_mod_revision: i64,
        observed_value: &[u8],
        replacement_value: &[u8],
    ) -> Result<ReachabilityDurableSnapshotEtcdMutation, ReachabilityDurableSnapshotEtcdError> {
        let transaction = build_transaction(
            key,
            observed_mod_revision,
            observed_value,
            replacement_value,
        )?;
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(ReachabilityDurableSnapshotEtcdError::MutationIndeterminate)?;
        classify_transaction_response(key, &response)
    }
}

fn build_transaction(
    key: &[u8],
    observed_mod_revision: i64,
    observed_value: &[u8],
    replacement_value: &[u8],
) -> Result<Txn, ReachabilityDurableSnapshotEtcdError> {
    validate_mod_revision(observed_mod_revision)?;
    let key = key.to_vec();
    let compares = vec![
        Compare::mod_revision(key.clone(), CompareOp::Equal, observed_mod_revision),
        Compare::value(key.clone(), CompareOp::Equal, observed_value.to_vec()),
    ];
    let success = TxnOp::put(key.clone(), replacement_value.to_vec(), None);
    let failure = TxnOp::get(key, None);
    Ok(Txn::new()
        .when(compares)
        .and_then(vec![success])
        .or_else(vec![failure]))
}

fn classify_transaction_response(
    key: &[u8],
    response: &etcd_client::TxnResponse,
) -> Result<ReachabilityDurableSnapshotEtcdMutation, ReachabilityDurableSnapshotEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(ReachabilityDurableSnapshotEtcdError::UnexpectedTxnResponseShape);
        }
        return Ok(ReachabilityDurableSnapshotEtcdMutation::Committed);
    }

    let [TxnOpResponse::Get(get_response)] = responses.as_slice() else {
        return Err(ReachabilityDurableSnapshotEtcdError::UnexpectedTxnResponseShape);
    };
    Ok(ReachabilityDurableSnapshotEtcdMutation::CompareFailed(
        decode_exact_get(key, get_response)?,
    ))
}

fn decode_exact_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<ReachabilityDurableSnapshotEtcdObservation>, ReachabilityDurableSnapshotEtcdError>
{
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(ReachabilityDurableSnapshotEtcdError::UnexpectedGetKey);
            }
            validate_mod_revision(kv.mod_revision())?;
            Ok(Some(ReachabilityDurableSnapshotEtcdObservation {
                key: kv.key().to_vec(),
                value: kv.value().to_vec(),
                mod_revision: kv.mod_revision(),
            }))
        }
        kvs => Err(
            ReachabilityDurableSnapshotEtcdError::UnexpectedGetCardinality { actual: kvs.len() },
        ),
    }
}

const fn validate_mod_revision(revision: i64) -> Result<(), ReachabilityDurableSnapshotEtcdError> {
    if revision <= 0 {
        return Err(ReachabilityDurableSnapshotEtcdError::InvalidModRevision { actual: revision });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_dual_cas_materializes_without_endpoint() {
        let _transaction = build_transaction(
            b"/prw/reachability/durable-snapshot/test",
            7,
            b"before",
            b"after",
        )
        .expect("positive observed revision");
    }

    #[test]
    fn non_positive_revision_is_rejected_before_provider_io() {
        assert!(matches!(
            build_transaction(b"key", 0, b"before", b"after"),
            Err(ReachabilityDurableSnapshotEtcdError::InvalidModRevision { actual: 0 })
        ));
        assert!(matches!(
            build_transaction(b"key", -1, b"before", b"after"),
            Err(ReachabilityDurableSnapshotEtcdError::InvalidModRevision { actual: -1 })
        ));
    }
}
