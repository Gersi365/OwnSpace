//! C03e-IT raw etcd executor for durable registry provider mechanics.
//!
//! This module owns only provider-specific etcd execution over opaque registry key/value bytes.
//! It accepts an already-created [`KvClient`], performs default-linearizable exact-key reads, and
//! executes only the C03e-IQ/C03e-IS selected bounded transaction shapes. It does not decode PRWM
//! or PRWD records, import registry semantic types, classify registry lifecycle state, configure
//! endpoints/TLS/auth/RBAC, scan prefixes, use Watch/lease/TTL, retry mutations, populate registry
//! records, spawn tasks, construct peer identity, or activate production runtime behavior.

use std::fmt;

use etcd_client::{Compare, CompareOp, GetResponse, KvClient, Txn, TxnOp, TxnOpResponse};

/// One exact raw etcd observation for a durable registry key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRegistryEtcdObservation {
    key: Vec<u8>,
    value: Vec<u8>,
    mod_revision: i64,
}

impl DurableRegistryEtcdObservation {
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

/// One transactionally consistent pair of exact raw registry observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRegistryEtcdObservationPair {
    first: Option<DurableRegistryEtcdObservation>,
    second: Option<DurableRegistryEtcdObservation>,
}

impl DurableRegistryEtcdObservationPair {
    /// Returns the first exact-key observation, or authoritative absence.
    #[must_use]
    pub const fn first(&self) -> Option<&DurableRegistryEtcdObservation> {
        self.first.as_ref()
    }

    /// Returns the second exact-key observation, or authoritative absence.
    #[must_use]
    pub const fn second(&self) -> Option<&DurableRegistryEtcdObservation> {
        self.second.as_ref()
    }

    /// Consumes the pair into its two exact raw observations.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Option<DurableRegistryEtcdObservation>,
        Option<DurableRegistryEtcdObservation>,
    ) {
        (self.first, self.second)
    }
}

/// Definitive provider result of one selected single-record registry mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableRegistryEtcdMutation {
    /// The selected Put success branch committed.
    Committed,
    /// The compare branch failed definitively; the value is its authoritative exact-key read.
    CompareFailed(Option<DurableRegistryEtcdObservation>),
}

/// Definitive provider result of the selected membership-guarded device registration mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableRegistryEtcdRegistrationMutation {
    /// The selected device Put success branch committed.
    Committed,
    /// The compare branch failed definitively with authoritative membership/device observations.
    CompareFailed(DurableRegistryEtcdObservationPair),
}

/// Fail-closed provider execution error for the durable registry etcd seam.
#[derive(Debug)]
pub enum DurableRegistryEtcdError {
    /// A default-linearizable read could not return an authoritative response.
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
    /// A definitive transaction response did not contain exactly the selected branch operations.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for DurableRegistryEtcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadUnavailable(error) => {
                write!(
                    formatter,
                    "durable registry etcd linearizable read unavailable: {error}"
                )
            }
            Self::MutationIndeterminate(error) => {
                write!(
                    formatter,
                    "durable registry etcd mutation outcome is indeterminate: {error}"
                )
            }
            Self::UnexpectedGetCardinality { actual } => write!(
                formatter,
                "durable registry exact-key Get returned unexpected cardinality {actual}"
            ),
            Self::UnexpectedGetKey => {
                formatter.write_str("durable registry exact-key Get returned another key")
            }
            Self::InvalidModRevision { actual } => write!(
                formatter,
                "durable registry etcd modification revision must be positive, got {actual}"
            ),
            Self::UnexpectedTxnResponseShape => formatter.write_str(
                "durable registry etcd Txn returned an unexpected branch response shape",
            ),
        }
    }
}

impl std::error::Error for DurableRegistryEtcdError {
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

/// Raw etcd executor for the bounded durable registry provider protocol.
pub struct DurableRegistryEtcdExecutor {
    kv: KvClient,
}

impl DurableRegistryEtcdExecutor {
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
    ) -> Result<Option<DurableRegistryEtcdObservation>, DurableRegistryEtcdError> {
        let response = self
            .kv
            .get(key.to_vec(), None)
            .await
            .map_err(DurableRegistryEtcdError::ReadUnavailable)?;
        decode_exact_get(key, &response)
    }

    /// Performs two exact-key Gets in one etcd transactionally consistent transaction response.
    ///
    /// No serializable, range, or prefix option is supplied. The response must contain exactly two
    /// Get operations in the same requested order; each Get is then validated as an exact-key read.
    ///
    /// # Errors
    ///
    /// Fails closed on provider unavailability, unexpected transaction shape, impossible exact-key
    /// cardinality, key mismatch, or invalid provider revision evidence.
    pub async fn linearizable_pair_get(
        &mut self,
        first_key: &[u8],
        second_key: &[u8],
    ) -> Result<DurableRegistryEtcdObservationPair, DurableRegistryEtcdError> {
        let transaction = build_pair_read_transaction(first_key, second_key);
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(DurableRegistryEtcdError::ReadUnavailable)?;
        classify_pair_read_response(first_key, second_key, &response)
    }

    /// Executes one exact create-if-absent transaction using `version == 0`.
    ///
    /// Success contains one complete raw Put. Compare failure contains one default-linearizable
    /// exact-key Get for later semantic classification. Provider RPC uncertainty is indeterminate
    /// and is never retried or converted into semantic success here.
    ///
    /// # Errors
    ///
    /// Fails closed on provider indeterminacy or unexpected definitive provider response shape.
    pub async fn create_if_absent(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<DurableRegistryEtcdMutation, DurableRegistryEtcdError> {
        let transaction = build_create_transaction(key, value);
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(DurableRegistryEtcdError::MutationIndeterminate)?;
        classify_single_mutation_response(key, &response)
    }

    /// Executes the selected exact-key `mod_revision + raw value` dual CAS and replacement Put.
    ///
    /// Success contains one complete replacement Put. Compare failure contains one authoritative
    /// exact-key Get. A changed revision with identical bytes remains a compare failure; this layer
    /// performs no idempotence inference and no retry.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-positive observed revision, indeterminate provider result, or an
    /// unexpected definitive provider response shape.
    pub async fn compare_and_put(
        &mut self,
        key: &[u8],
        observed_mod_revision: i64,
        observed_value: &[u8],
        replacement_value: &[u8],
    ) -> Result<DurableRegistryEtcdMutation, DurableRegistryEtcdError> {
        let transaction = build_compare_and_put_transaction(
            key,
            observed_mod_revision,
            observed_value,
            replacement_value,
        )?;
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(DurableRegistryEtcdError::MutationIndeterminate)?;
        classify_single_mutation_response(key, &response)
    }

    /// Executes the selected active-membership guarded device-registration transaction.
    ///
    /// The compare set is exactly membership `mod_revision`, membership exact raw value, and device
    /// `version == 0`. Success performs only the exact device Put. Compare failure returns exactly
    /// membership and device exact-key Gets in that order for semantic classification above this
    /// provider boundary.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-positive membership revision, indeterminate provider result, or an
    /// unexpected definitive provider response shape.
    pub async fn register_device_if_membership_unchanged(
        &mut self,
        membership_key: &[u8],
        membership_mod_revision: i64,
        membership_value: &[u8],
        device_key: &[u8],
        device_value: &[u8],
    ) -> Result<DurableRegistryEtcdRegistrationMutation, DurableRegistryEtcdError> {
        let transaction = build_device_registration_transaction(
            membership_key,
            membership_mod_revision,
            membership_value,
            device_key,
            device_value,
        )?;
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(DurableRegistryEtcdError::MutationIndeterminate)?;
        classify_registration_response(membership_key, device_key, &response)
    }
}

fn build_pair_read_transaction(first_key: &[u8], second_key: &[u8]) -> Txn {
    Txn::new().and_then(vec![
        TxnOp::get(first_key.to_vec(), None),
        TxnOp::get(second_key.to_vec(), None),
    ])
}

fn build_create_transaction(key: &[u8], value: &[u8]) -> Txn {
    let key = key.to_vec();
    Txn::new()
        .when(vec![Compare::version(key.clone(), CompareOp::Equal, 0)])
        .and_then(vec![TxnOp::put(key.clone(), value.to_vec(), None)])
        .or_else(vec![TxnOp::get(key, None)])
}

fn build_compare_and_put_transaction(
    key: &[u8],
    observed_mod_revision: i64,
    observed_value: &[u8],
    replacement_value: &[u8],
) -> Result<Txn, DurableRegistryEtcdError> {
    validate_mod_revision(observed_mod_revision)?;
    let key = key.to_vec();
    Ok(Txn::new()
        .when(vec![
            Compare::mod_revision(key.clone(), CompareOp::Equal, observed_mod_revision),
            Compare::value(key.clone(), CompareOp::Equal, observed_value.to_vec()),
        ])
        .and_then(vec![TxnOp::put(
            key.clone(),
            replacement_value.to_vec(),
            None,
        )])
        .or_else(vec![TxnOp::get(key, None)]))
}

fn build_device_registration_transaction(
    membership_key: &[u8],
    membership_mod_revision: i64,
    membership_value: &[u8],
    device_key: &[u8],
    device_value: &[u8],
) -> Result<Txn, DurableRegistryEtcdError> {
    validate_mod_revision(membership_mod_revision)?;
    let membership_key = membership_key.to_vec();
    let device_key = device_key.to_vec();
    Ok(Txn::new()
        .when(vec![
            Compare::mod_revision(
                membership_key.clone(),
                CompareOp::Equal,
                membership_mod_revision,
            ),
            Compare::value(
                membership_key.clone(),
                CompareOp::Equal,
                membership_value.to_vec(),
            ),
            Compare::version(device_key.clone(), CompareOp::Equal, 0),
        ])
        .and_then(vec![TxnOp::put(
            device_key.clone(),
            device_value.to_vec(),
            None,
        )])
        .or_else(vec![
            TxnOp::get(membership_key, None),
            TxnOp::get(device_key, None),
        ]))
}

fn classify_pair_read_response(
    first_key: &[u8],
    second_key: &[u8],
    response: &etcd_client::TxnResponse,
) -> Result<DurableRegistryEtcdObservationPair, DurableRegistryEtcdError> {
    if !response.succeeded() {
        return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
    }
    let responses = response.op_responses();
    let [TxnOpResponse::Get(first), TxnOpResponse::Get(second)] = responses.as_slice() else {
        return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
    };
    Ok(DurableRegistryEtcdObservationPair {
        first: decode_exact_get(first_key, first)?,
        second: decode_exact_get(second_key, second)?,
    })
}

fn classify_single_mutation_response(
    key: &[u8],
    response: &etcd_client::TxnResponse,
) -> Result<DurableRegistryEtcdMutation, DurableRegistryEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
        }
        return Ok(DurableRegistryEtcdMutation::Committed);
    }

    let [TxnOpResponse::Get(get_response)] = responses.as_slice() else {
        return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
    };
    Ok(DurableRegistryEtcdMutation::CompareFailed(
        decode_exact_get(key, get_response)?,
    ))
}

fn classify_registration_response(
    membership_key: &[u8],
    device_key: &[u8],
    response: &etcd_client::TxnResponse,
) -> Result<DurableRegistryEtcdRegistrationMutation, DurableRegistryEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
        }
        return Ok(DurableRegistryEtcdRegistrationMutation::Committed);
    }

    let [TxnOpResponse::Get(membership), TxnOpResponse::Get(device)] = responses.as_slice() else {
        return Err(DurableRegistryEtcdError::UnexpectedTxnResponseShape);
    };
    Ok(DurableRegistryEtcdRegistrationMutation::CompareFailed(
        DurableRegistryEtcdObservationPair {
            first: decode_exact_get(membership_key, membership)?,
            second: decode_exact_get(device_key, device)?,
        },
    ))
}

fn decode_exact_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<DurableRegistryEtcdObservation>, DurableRegistryEtcdError> {
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(DurableRegistryEtcdError::UnexpectedGetKey);
            }
            validate_mod_revision(kv.mod_revision())?;
            Ok(Some(DurableRegistryEtcdObservation {
                key: kv.key().to_vec(),
                value: kv.value().to_vec(),
                mod_revision: kv.mod_revision(),
            }))
        }
        kvs => Err(DurableRegistryEtcdError::UnexpectedGetCardinality { actual: kvs.len() }),
    }
}

const fn validate_mod_revision(revision: i64) -> Result<(), DurableRegistryEtcdError> {
    if revision <= 0 {
        return Err(DurableRegistryEtcdError::InvalidModRevision { actual: revision });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_pair_read_materializes_without_endpoint() {
        let _transaction = build_pair_read_transaction(b"membership", b"device");
    }

    #[test]
    fn selected_create_if_absent_materializes_without_endpoint() {
        let _transaction = build_create_transaction(b"key", b"value");
    }

    #[test]
    fn selected_dual_cas_materializes_without_endpoint() {
        let _transaction = build_compare_and_put_transaction(b"key", 7, b"before", b"after")
            .expect("positive observed revision");
    }

    #[test]
    fn selected_device_registration_materializes_without_endpoint() {
        let _transaction = build_device_registration_transaction(
            b"membership",
            11,
            b"active-membership",
            b"device",
            b"enrolled-unbound-device",
        )
        .expect("positive membership revision");
    }

    #[test]
    fn non_positive_revisions_are_rejected_before_provider_io() {
        assert!(matches!(
            build_compare_and_put_transaction(b"key", 0, b"before", b"after"),
            Err(DurableRegistryEtcdError::InvalidModRevision { actual: 0 })
        ));
        assert!(matches!(
            build_compare_and_put_transaction(b"key", -1, b"before", b"after"),
            Err(DurableRegistryEtcdError::InvalidModRevision { actual: -1 })
        ));
        assert!(matches!(
            build_device_registration_transaction(b"membership", 0, b"active", b"device", b"new"),
            Err(DurableRegistryEtcdError::InvalidModRevision { actual: 0 })
        ));
    }
}
