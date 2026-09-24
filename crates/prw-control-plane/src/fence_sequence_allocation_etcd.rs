//! C02f-AP real `etcd-client` wiring for within-epoch fence-sequence allocation.
//!
//! This module translates the already-selected C02f-AJ deterministic PRWF/PRWR allocation plan to
//! `etcd-client = 0.19.0`. It accepts an already-created [`KvClient`], performs only canonical
//! default-linearizable exact-key reads and one retained-plan Txn submission per call, and never
//! selects endpoints, connects a client, configures TLS/auth/RBAC, retries a mutation, generates an
//! allocation attempt ID, initializes PRWF state, issues a recovery epoch, or activates runtime
//! authority.

use std::fmt;

use etcd_client::{Compare, CompareOp, GetResponse, KvClient, Txn, TxnOp, TxnOpResponse};

use crate::fence_sequence::{
    FENCE_SEQUENCE_HEAD_KEY, FenceSequenceAllocationPlan, FenceSequenceError, FenceSequenceHead,
    FenceSequenceHeadObservation, FenceSequenceReobservation, FenceSequenceReservation,
    FenceSequenceTxnCompare, FenceSequenceTxnOperation, classify_reobservation, decode_reservation,
    encode_head, encode_reservation, reservation_key,
};

/// Definitive result of one real etcd fence-sequence allocation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceAllocationDefinitiveMutation {
    /// The retained C02f-AJ compare set succeeded and both exact Put operations were committed.
    Applied,
    /// The compare set failed and the two Get responses were classified against the retained plan.
    CompareFailed(FenceSequenceReobservation),
}

/// Real etcd KV boundary for the selected C02f-AJ fence-sequence allocation protocol.
///
/// Construction itself performs no network I/O. The caller supplies an already-created etcd KV
/// client; endpoint selection and connection/bootstrap ownership remain outside C02f-AP.
pub struct FenceSequenceAllocationEtcdStore {
    kv: KvClient,
}

impl FenceSequenceAllocationEtcdStore {
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
    /// serializable option. Absence remains absence and is never promoted to initialization
    /// authority by this adapter.
    ///
    /// # Errors
    ///
    /// Fails closed for provider read failure, impossible exact-key cardinality/key mismatch, or
    /// malformed/non-canonical PRWF state.
    pub async fn linearizable_head(
        &mut self,
    ) -> Result<Option<FenceSequenceHeadObservation>, FenceSequenceAllocationEtcdError> {
        let key = FENCE_SEQUENCE_HEAD_KEY.to_vec();
        let response = self
            .kv
            .get(key.clone(), None)
            .await
            .map_err(FenceSequenceAllocationEtcdError::ReadUnavailable)?;
        decode_exact_head_get(&key, &response)
    }

    /// Executes exactly one retained C02f-AJ allocation mutation through a real etcd Txn.
    ///
    /// No retry or reissue occurs here. A transport/provider error after submission is classified as
    /// indeterminate and requires later fresh re-observation by the caller before any retry policy
    /// could be considered.
    ///
    /// # Errors
    ///
    /// Returns [`FenceSequenceAllocationEtcdError::MutationIndeterminate`] when etcd does not return
    /// a definitive Txn response. Structural plan/response mismatches and contradictory failure
    /// observations fail closed.
    pub async fn execute(
        &mut self,
        plan: &FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceAllocationDefinitiveMutation, FenceSequenceAllocationEtcdError> {
        let transaction = build_etcd_transaction(plan)?;
        let response = self
            .kv
            .txn(transaction)
            .await
            .map_err(FenceSequenceAllocationEtcdError::MutationIndeterminate)?;
        classify_etcd_transaction_response(plan, &response)
    }

    /// Performs fresh default-linearizable head plus exact-reservation re-observation and delegates
    /// the result to the retained C02f-AJ classifier.
    ///
    /// This method performs no mutation, retry, reissue, or attempt-ID generation. Concurrent state
    /// movement that cannot be reconciled with the exact retained plan fails closed rather than
    /// manufacturing safe-to-reissue authority.
    ///
    /// # Errors
    ///
    /// Fails closed when provider reads are unavailable, the initialized PRWF head is missing,
    /// provider state is malformed, or AJ classification finds contradictory state.
    pub async fn reobserve(
        &mut self,
        plan: &FenceSequenceAllocationPlan,
    ) -> Result<FenceSequenceReobservation, FenceSequenceAllocationEtcdError> {
        validate_plan_shape(plan)?;
        let head = self
            .linearizable_head()
            .await?
            .ok_or(FenceSequenceAllocationEtcdError::MissingHead)?;
        let reservation = self.linearizable_reservation(plan).await?;
        classify_reobservation(plan, &head, reservation)
            .map_err(FenceSequenceAllocationEtcdError::from)
    }

    async fn linearizable_reservation(
        &mut self,
        plan: &FenceSequenceAllocationPlan,
    ) -> Result<Option<FenceSequenceReservation>, FenceSequenceAllocationEtcdError> {
        let key = plan.reservation_key.clone();
        let response = self
            .kv
            .get(key.clone(), None)
            .await
            .map_err(FenceSequenceAllocationEtcdError::ReadUnavailable)?;
        decode_exact_reservation_get(&key, &response)
    }
}

/// Fail-closed real-etcd wiring error for C02f-AP.
#[derive(Debug)]
pub enum FenceSequenceAllocationEtcdError {
    /// Existing AJ PRWF/PRWR decoding or re-observation validation rejected provider state.
    FenceSequence(FenceSequenceError),
    /// A default-linearizable head/reservation read could not return an authoritative response.
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
    /// Normal allocation re-observation found no initialized canonical PRWF head.
    MissingHead,
    /// The retained public AJ plan does not contain the canonical compare/two-Put/two-Get shape.
    UnexpectedPlanShape,
    /// A definitive Txn response did not contain exactly the selected branch operation responses.
    UnexpectedTxnResponseShape,
}

impl fmt::Display for FenceSequenceAllocationEtcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FenceSequence(error) => write!(formatter, "{error}"),
            Self::ReadUnavailable(error) => write!(
                formatter,
                "fence-sequence allocation etcd linearizable read unavailable: {error}"
            ),
            Self::MutationIndeterminate(error) => write!(
                formatter,
                "fence-sequence allocation etcd mutation outcome is indeterminate: {error}"
            ),
            Self::UnexpectedGetCardinality { actual } => write!(
                formatter,
                "fence-sequence allocation exact-key Get returned unexpected cardinality {actual}"
            ),
            Self::UnexpectedGetKey => {
                formatter.write_str("fence-sequence allocation exact-key Get returned another key")
            }
            Self::MissingHead => formatter
                .write_str("fence-sequence allocation requires an initialized canonical PRWF head"),
            Self::UnexpectedPlanShape => {
                formatter.write_str("fence-sequence allocation plan has unexpected canonical shape")
            }
            Self::UnexpectedTxnResponseShape => formatter.write_str(
                "fence-sequence allocation etcd Txn returned an unexpected branch response shape",
            ),
        }
    }
}

impl std::error::Error for FenceSequenceAllocationEtcdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FenceSequence(error) => Some(error),
            Self::ReadUnavailable(error) | Self::MutationIndeterminate(error) => Some(error),
            Self::UnexpectedGetCardinality { .. }
            | Self::UnexpectedGetKey
            | Self::MissingHead
            | Self::UnexpectedPlanShape
            | Self::UnexpectedTxnResponseShape => None,
        }
    }
}

impl From<FenceSequenceError> for FenceSequenceAllocationEtcdError {
    fn from(value: FenceSequenceError) -> Self {
        Self::FenceSequence(value)
    }
}

pub(crate) fn build_etcd_transaction(
    plan: &FenceSequenceAllocationPlan,
) -> Result<Txn, FenceSequenceAllocationEtcdError> {
    validate_plan_shape(plan)?;

    let compares = plan.compares.iter().map(etcd_compare).collect::<Vec<_>>();

    let [
        FenceSequenceTxnOperation::Put(head_key, head_value),
        FenceSequenceTxnOperation::Put(reservation_key, reservation_value),
    ] = &plan.success
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };
    let success = vec![
        TxnOp::put(head_key.clone(), head_value.clone(), None),
        TxnOp::put(reservation_key.clone(), reservation_value.clone(), None),
    ];

    let [
        FenceSequenceTxnOperation::Get(head_key),
        FenceSequenceTxnOperation::Get(reservation_key),
    ] = &plan.failure
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };
    let failure = vec![
        TxnOp::get(head_key.clone(), None),
        TxnOp::get(reservation_key.clone(), None),
    ];

    Ok(Txn::new().when(compares).and_then(success).or_else(failure))
}

fn validate_plan_shape(
    plan: &FenceSequenceAllocationPlan,
) -> Result<(), FenceSequenceAllocationEtcdError> {
    let [
        FenceSequenceTxnCompare::HeadModRevision(expected_revision),
        FenceSequenceTxnCompare::HeadExactValue(expected_value),
        FenceSequenceTxnCompare::ReservationVersionZero(compare_reservation_key),
    ] = &plan.compares
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };

    let [
        FenceSequenceTxnOperation::Put(success_head_key, success_head_value),
        FenceSequenceTxnOperation::Put(success_reservation_key, success_reservation_value),
    ] = &plan.success
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };

    let [
        FenceSequenceTxnOperation::Get(failure_head_key),
        FenceSequenceTxnOperation::Get(failure_reservation_key),
    ] = &plan.failure
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };

    let Some(expected_sequence) = plan.predecessor.head.high_water.checked_add(1) else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    };
    if plan.sequence.get() != expected_sequence {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    }

    let expected_reservation_key = reservation_key(plan.predecessor.head.epoch, plan.sequence);
    let expected_head_value = encode_head(FenceSequenceHead {
        epoch: plan.predecessor.head.epoch,
        high_water: plan.sequence.get(),
    });
    let expected_reservation_value = encode_reservation(FenceSequenceReservation {
        epoch: plan.predecessor.head.epoch,
        sequence: plan.sequence,
        attempt_id: plan.attempt_id,
    });

    if *expected_revision != plan.predecessor.mod_revision
        || expected_value != &plan.predecessor.value
        || compare_reservation_key != &plan.reservation_key
        || plan.reservation_key != expected_reservation_key
        || success_head_key.as_slice() != FENCE_SEQUENCE_HEAD_KEY
        || success_head_value.as_slice() != expected_head_value
        || success_reservation_key != &plan.reservation_key
        || success_reservation_value.as_slice() != expected_reservation_value
        || failure_head_key.as_slice() != FENCE_SEQUENCE_HEAD_KEY
        || failure_reservation_key != &plan.reservation_key
    {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedPlanShape);
    }

    Ok(())
}

fn etcd_compare(compare: &FenceSequenceTxnCompare) -> Compare {
    match compare {
        FenceSequenceTxnCompare::HeadModRevision(expected) => Compare::mod_revision(
            FENCE_SEQUENCE_HEAD_KEY.to_vec(),
            CompareOp::Equal,
            *expected,
        ),
        FenceSequenceTxnCompare::HeadExactValue(expected) => Compare::value(
            FENCE_SEQUENCE_HEAD_KEY.to_vec(),
            CompareOp::Equal,
            expected.clone(),
        ),
        FenceSequenceTxnCompare::ReservationVersionZero(key) => {
            Compare::version(key.clone(), CompareOp::Equal, 0)
        }
    }
}

fn classify_etcd_transaction_response(
    plan: &FenceSequenceAllocationPlan,
    response: &etcd_client::TxnResponse,
) -> Result<FenceSequenceAllocationDefinitiveMutation, FenceSequenceAllocationEtcdError> {
    let responses = response.op_responses();
    if response.succeeded() {
        if !matches!(
            responses.as_slice(),
            [TxnOpResponse::Put(_), TxnOpResponse::Put(_)]
        ) {
            return Err(FenceSequenceAllocationEtcdError::UnexpectedTxnResponseShape);
        }
        return Ok(FenceSequenceAllocationDefinitiveMutation::Applied);
    }

    let [
        TxnOpResponse::Get(head_response),
        TxnOpResponse::Get(reservation_response),
    ] = responses.as_slice()
    else {
        return Err(FenceSequenceAllocationEtcdError::UnexpectedTxnResponseShape);
    };

    let head = decode_exact_head_get(FENCE_SEQUENCE_HEAD_KEY, head_response)?
        .ok_or(FenceSequenceAllocationEtcdError::MissingHead)?;
    let reservation = decode_exact_reservation_get(&plan.reservation_key, reservation_response)?;
    let classification = classify_reobservation(plan, &head, reservation)?;
    Ok(FenceSequenceAllocationDefinitiveMutation::CompareFailed(
        classification,
    ))
}

fn decode_exact_head_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<FenceSequenceHeadObservation>, FenceSequenceAllocationEtcdError> {
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(FenceSequenceAllocationEtcdError::UnexpectedGetKey);
            }
            Ok(Some(FenceSequenceHeadObservation::new(
                kv.value().to_vec(),
                kv.mod_revision(),
            )?))
        }
        kvs => {
            Err(FenceSequenceAllocationEtcdError::UnexpectedGetCardinality { actual: kvs.len() })
        }
    }
}

fn decode_exact_reservation_get(
    expected_key: &[u8],
    response: &GetResponse,
) -> Result<Option<FenceSequenceReservation>, FenceSequenceAllocationEtcdError> {
    match response.kvs() {
        [] => Ok(None),
        [kv] => {
            if kv.key() != expected_key {
                return Err(FenceSequenceAllocationEtcdError::UnexpectedGetKey);
            }
            if kv.mod_revision() <= 0 {
                return Err(FenceSequenceError::InvalidRevision.into());
            }
            Ok(Some(decode_reservation(kv.value())?))
        }
        kvs => {
            Err(FenceSequenceAllocationEtcdError::UnexpectedGetCardinality { actual: kvs.len() })
        }
    }
}
