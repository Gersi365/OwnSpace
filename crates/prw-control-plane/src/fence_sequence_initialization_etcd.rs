//! C02f-AN real `etcd-client` wiring for fence-sequence epoch-head initialization.
//!
//! This module translates the already-selected C02f-AM deterministic initialization plan to
//! `etcd-client = 0.19.0`. It accepts an already-created [`KvClient`], performs only exact-key
//! default-linearizable Gets and one retained-plan Txn submission per call, and never selects
//! endpoints, connects a client, configures TLS/auth/RBAC, retries a mutation, allocates a fence
//! sequence, issues a recovery epoch, or activates runtime authority.

use std::fmt;

use etcd_client::{Compare, CompareOp, GetResponse, KvClient, Txn, TxnOp, TxnOpResponse};

use crate::{
    fence_sequence::{FENCE_SEQUENCE_HEAD_KEY, FenceSequenceError, FenceSequenceHeadObservation},
    fence_sequence_initialization::{
        FenceSequenceInitializationCompare, FenceSequenceInitializationError,
        FenceSequenceInitializationOperation, FenceSequenceInitializationReobservation,
        FenceSequenceInitializationTxnPlan, classify_initialization_reobservation,
    },
};

/// Definitive result of one real etcd initialization transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceInitializationDefinitiveMutation {
    /// The retained C02f-AM compare set succeeded and the exact target head Put was committed.
    Applied,
    /// The compare set failed and the Txn failure-branch Get was classified against the retained plan.
    CompareFailed(FenceSequenceInitializationReobservation),
}

/// Real etcd KV boundary for the selected C02f-AM fence-sequence initialization protocol.
///
/// Construction itself performs no network I/O. The caller supplies an already-created etcd KV
/// client; endpoint selection and connection/bootstrap ownership remain outside C02f-AN.
pub struct FenceSequenceInitializationEtcdStore {
    kv: KvClient,
}

impl FenceSequenceInitializationEtcdStore {
    /// Wraps an already-created etcd KV client without contacting an endpoint.
    #[must_use]
    pub const fn new(kv: KvClient) -> Self {
        Self { kv }
    }

    /// Consumes the adapter and returns the underlying etcd KV client.
    #[must_use]
    pub fn into_inner(self) -> KvClient {
        self.kv
    }

    /// Performs one latest default-linearizable Get for the canonical PRWF head key.
    ///
    /// `etcd-client` Gets are linearizable by default. This path deliberately supplies no
    /// serializable option.
    ///
    /// # Errors
    ///
    /// Fails closed for provider read failure, impossible exact-key cardinality/key mismatch, or
    /// malformed/non-canonical PRWF state.
    pub async fn linearizable_head(
        &mut self,
    ) -> Result<Option<FenceSequenceHeadObservation>, FenceSequenceInitializationEtcdError> {
        let key = FENCE_SEQUENCE_HEAD_KEY.to_vec();
        let response = self
            .kv
            .get(key.clone(), None)
            .await
            .map_err(FenceSequenceInitializationEtcdError::ReadUnavailable)?;
        decode_exact_head_get(&key, &response)
    }

    /// Executes exactly one retained C02f-AM initialization mutation through a real etcd Txn.
    ///
    /// No retry or reissue occurs here. A transport/provider error after submission is classified as
    /// indeterminate and requires a later fresh re-observation by the caller before any retry policy
    /// could be considered.
    ///
    /// # Errors
    ///
    /// Returns [`FenceSequenceInitializationEtcdError::MutationIndeterminate`] when etcd does not
    /// return a definitive Txn response. Structural response mismatches and contradictory failure
    /// observations also fail closed.
    pub async fn execute(
        &mut self,
        plan: &FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationDefinitiveMutation, FenceSequenceInitializationEtcdError>
    {
        let transaction = build_etcd_transaction(plan)?;
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(FenceSequenceInitializationEtcdError::MutationIndeterminate)?;
        classify_etcd_transaction_response(plan, &response)
    }

    /// Performs one fresh default-linearizable exact-key Get and classifies it against the retained
    /// initialization plan after an indeterminate submission.
    ///
    /// This method performs no retry and consumes no reissue budget.
    ///
    /// # Errors
    ///
    /// Fails closed when the provider read is unavailable, PRWF state is malformed, or the fresh
    /// observation contradicts the exact retained C02f-AM plan.
    pub async fn reobserve(
        &mut self,
        plan: &FenceSequenceInitializationTxnPlan,
    ) -> Result<FenceSequenceInitializationReobservation, FenceSequenceInitializationEtcdError>
    {
        let observed = self.linearizable_head().await?;
        classify_initialization_reobservation(plan, observed.as_ref())
            .map_err(FenceSequenceInitializationEtcdError::from)
    }
}

/// Fail-closed real-etcd wiring error for C02f-AN.
#[derive(Debug)]
pub enum FenceSequenceInitializationEtcdError {
    /// Existing AJ PRWF decoding/observation validation rejected provider state.
    FenceSequence(FenceSequenceError),
    /// Existing AM re-observation classification found contradictory provider state.
    Initialization(FenceSequenceInitializationError),
    /// A default-linearizable head read could not return an authoritative response.
    ReadUnavailable(etcd_client::Error),
    /// A mutation RPC returned no definitive Txn response; fresh re-observation is mandatory.
    MutationIndeterminate(etcd_client::Error),
    /// An exact-key Get returned more than one key-value pair.
    UnexpectedGetCardinality {
        /// Number of key-value pairs returned by etcd.
        actual: usize,
    },
    /// An exact-key Get returned a key different from the requested canonical key.
    UnexpectedGetKey,
    /// The retained public AM plan does not contain the canonical one-Put/one-Get branch shape.
    UnexpectedPlanShape,
    /// A definitive Txn response did not contain exactly the selected branch operation response.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for FenceSequenceInitializationEtcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FenceSequence(error) => write!(formatter, "{error}"),
            Self::Initialization(error) => write!(formatter, "{error}"),
            Self::ReadUnavailable(error) => {
                write!(
                    formatter,
                    "fence-sequence initialization etcd linearizable read unavailable: {error}"
                )
            }
            Self::MutationIndeterminate(error) => write!(
                formatter,
                "fence-sequence initialization etcd mutation outcome is indeterminate: {error}"
            ),
            Self::UnexpectedGetCardinality { actual } => write!(
                formatter,
                "fence-sequence initialization exact-key Get returned unexpected cardinality {actual}"
            ),
            Self::UnexpectedGetKey => formatter
                .write_str("fence-sequence initialization exact-key Get returned another key"),
            Self::UnexpectedPlanShape => formatter
                .write_str("fence-sequence initialization plan has unexpected branch shape"),
            Self::UnexpectedTxnResponseShape => formatter.write_str(
                "fence-sequence initialization etcd Txn returned an unexpected branch response shape",
            ),
        }
    }
}

impl std::error::Error for FenceSequenceInitializationEtcdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FenceSequence(error) => Some(error),
            Self::Initialization(error) => Some(error),
            Self::ReadUnavailable(error) | Self::MutationIndeterminate(error) => Some(error),
            Self::UnexpectedGetCardinality { .. }
            | Self::UnexpectedGetKey
            | Self::UnexpectedPlanShape
            | Self::UnexpectedTxnResponseShape => None,
        }
    }
}

impl From<FenceSequenceError> for FenceSequenceInitializationEtcdError {
    fn from(value: FenceSequenceError) -> Self {
        Self::FenceSequence(value)
    }
}

impl From<FenceSequenceInitializationError> for FenceSequenceInitializationEtcdError {
    fn from(value: FenceSequenceInitializationError) -> Self {
        Self::Initialization(value)
    }
}

pub(crate) fn build_etcd_transaction(
    plan: &FenceSequenceInitializationTxnPlan,
) -> Result<Txn, FenceSequenceInitializationEtcdError> {
    let compares = plan.compares.iter().map(etcd_compare).collect::<Vec<_>>();

    let FenceSequenceInitializationOperation::Put { key, value } = &plan.success[0] else {
        return Err(FenceSequenceInitializationEtcdError::UnexpectedPlanShape);
    };
    let success = TxnOp::put(key.clone(), value.clone(), None);

    let FenceSequenceInitializationOperation::LinearizableGet { key } = &plan.failure[0] else {
        return Err(FenceSequenceInitializationEtcdError::UnexpectedPlanShape);
    };
    let failure = TxnOp::get(key.clone(), None);

    Ok(Txn::new()
        .when(compares)
        .and_then(vec![success])
        .or_else(vec![failure]))
}

fn etcd_compare(compare: &FenceSequenceInitializationCompare) -> Compare {
    match compare {
        FenceSequenceInitializationCompare::HeadVersionZero { key } => {
            Compare::version(key.clone(), CompareOp::Equal, 0)
        }
        FenceSequenceInitializationCompare::HeadModRevisionEquals { key, expected } => {
            Compare::mod_revision(key.clone(), CompareOp::Equal, *expected)
        }
        FenceSequenceInitializationCompare::HeadExactValueEquals { key, expected } => {
            Compare::value(key.clone(), CompareOp::Equal, expected.clone())
        }
    }
}

fn classify_etcd_transaction_response(
    plan: &FenceSequenceInitializationTxnPlan,
    response: &etcd_client::TxnResponse,
) -> Result<FenceSequenceInitializationDefinitiveMutation, FenceSequenceInitializationEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(responses.as_slice(), [TxnOpResponse::Put(_)]) {
            return Err(FenceSequenceInitializationEtcdError::UnexpectedTxnResponseShape);
        }
        return Ok(FenceSequenceInitializationDefinitiveMutation::Applied);
    }

    let [TxnOpResponse::Get(get_response)] = responses.as_slice() else {
        return Err(FenceSequenceInitializationEtcdError::UnexpectedTxnResponseShape);
    };
    let FenceSequenceInitializationOperation::LinearizableGet { key } = &plan.failure[0] else {
        return Err(FenceSequenceInitializationEtcdError::UnexpectedPlanShape);
    };
    let observed = decode_exact_head_get(key, get_response)?;
    let classification = classify_initialization_reobservation(plan, observed.as_ref())?;
    Ok(FenceSequenceInitializationDefinitiveMutation::CompareFailed(classification))
}

fn decode_exact_head_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<FenceSequenceHeadObservation>, FenceSequenceInitializationEtcdError> {
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(FenceSequenceInitializationEtcdError::UnexpectedGetKey);
            }
            Ok(Some(FenceSequenceHeadObservation::new(
                kv.value().to_vec(),
                kv.mod_revision(),
            )?))
        }
        kvs => Err(
            FenceSequenceInitializationEtcdError::UnexpectedGetCardinality { actual: kvs.len() },
        ),
    }
}
