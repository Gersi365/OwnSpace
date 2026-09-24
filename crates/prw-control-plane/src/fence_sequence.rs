//! C02f-AJ provider-neutral within-epoch sequence codecs and deterministic etcd transaction plan.
//!
//! No etcd RPC, endpoint, TLS, credential, task, or production authority activation occurs here.

use crate::recovery_epoch::RecoveryEpoch;
use std::{fmt, num::NonZeroU64};

pub const FENCE_SEQUENCE_HEAD_KEY: &[u8] = b"/prw/reachability/fence-sequence/v1/head";
pub const FENCE_SEQUENCE_RESERVATION_PREFIX: &[u8] =
    b"/prw/reachability/fence-sequence/v1/reservation/";
pub const FENCE_SEQUENCE_VERSION: u16 = 1;
pub const FENCE_SEQUENCE_HEAD_MAGIC: [u8; 4] = *b"PRWF";
pub const FENCE_SEQUENCE_RESERVATION_MAGIC: [u8; 4] = *b"PRWR";
pub const FENCE_SEQUENCE_HEAD_RECORD_BYTES: usize = 22;
pub const FENCE_SEQUENCE_RESERVATION_RECORD_BYTES: usize = 54;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SequenceAllocationAttemptId([u8; 32]);

impl SequenceAllocationAttemptId {
    /// Constructs a non-zero sequence-allocation attempt identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FenceSequenceError::ZeroAttemptId`] when `bytes` is all zero.
    pub fn new(bytes: [u8; 32]) -> Result<Self, FenceSequenceError> {
        if bytes == [0; 32] {
            return Err(FenceSequenceError::ZeroAttemptId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceSequenceHead {
    pub epoch: RecoveryEpoch,
    pub high_water: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceSequenceReservation {
    pub epoch: RecoveryEpoch,
    pub sequence: NonZeroU64,
    pub attempt_id: SequenceAllocationAttemptId,
}

#[must_use]
pub fn encode_head(head: FenceSequenceHead) -> [u8; FENCE_SEQUENCE_HEAD_RECORD_BYTES] {
    let mut out = [0; FENCE_SEQUENCE_HEAD_RECORD_BYTES];
    out[0..4].copy_from_slice(&FENCE_SEQUENCE_HEAD_MAGIC);
    out[4..6].copy_from_slice(&FENCE_SEQUENCE_VERSION.to_be_bytes());
    out[6..14].copy_from_slice(&head.epoch.get().to_be_bytes());
    out[14..22].copy_from_slice(&head.high_water.to_be_bytes());
    out
}

/// Decodes one canonical `PRWF` head record.
///
/// # Errors
///
/// Returns an error for a non-canonical record length, magic, version, or zero epoch.
pub fn decode_head(encoded: &[u8]) -> Result<FenceSequenceHead, FenceSequenceError> {
    if encoded.len() != FENCE_SEQUENCE_HEAD_RECORD_BYTES {
        return Err(FenceSequenceError::InvalidHeadLength);
    }
    if encoded[0..4] != FENCE_SEQUENCE_HEAD_MAGIC {
        return Err(FenceSequenceError::InvalidMagic);
    }
    let mut version_bytes = [0_u8; 2];
    version_bytes.copy_from_slice(&encoded[4..6]);
    if u16::from_be_bytes(version_bytes) != FENCE_SEQUENCE_VERSION {
        return Err(FenceSequenceError::UnsupportedVersion);
    }
    let mut epoch_bytes = [0_u8; 8];
    epoch_bytes.copy_from_slice(&encoded[6..14]);
    let mut high_water_bytes = [0_u8; 8];
    high_water_bytes.copy_from_slice(&encoded[14..22]);
    Ok(FenceSequenceHead {
        epoch: RecoveryEpoch::new(u64::from_be_bytes(epoch_bytes))
            .map_err(|_| FenceSequenceError::ZeroEpoch)?,
        high_water: u64::from_be_bytes(high_water_bytes),
    })
}

#[must_use]
pub fn encode_reservation(
    record: FenceSequenceReservation,
) -> [u8; FENCE_SEQUENCE_RESERVATION_RECORD_BYTES] {
    let mut out = [0; FENCE_SEQUENCE_RESERVATION_RECORD_BYTES];
    out[0..4].copy_from_slice(&FENCE_SEQUENCE_RESERVATION_MAGIC);
    out[4..6].copy_from_slice(&FENCE_SEQUENCE_VERSION.to_be_bytes());
    out[6..14].copy_from_slice(&record.epoch.get().to_be_bytes());
    out[14..22].copy_from_slice(&record.sequence.get().to_be_bytes());
    out[22..54].copy_from_slice(record.attempt_id.as_bytes());
    out
}

/// Decodes one canonical `PRWR` reservation record.
///
/// # Errors
///
/// Returns an error for a non-canonical record length, magic, version, epoch, sequence, or attempt ID.
pub fn decode_reservation(encoded: &[u8]) -> Result<FenceSequenceReservation, FenceSequenceError> {
    if encoded.len() != FENCE_SEQUENCE_RESERVATION_RECORD_BYTES {
        return Err(FenceSequenceError::InvalidReservationLength);
    }
    if encoded[0..4] != FENCE_SEQUENCE_RESERVATION_MAGIC {
        return Err(FenceSequenceError::InvalidMagic);
    }
    let mut version_bytes = [0_u8; 2];
    version_bytes.copy_from_slice(&encoded[4..6]);
    if u16::from_be_bytes(version_bytes) != FENCE_SEQUENCE_VERSION {
        return Err(FenceSequenceError::UnsupportedVersion);
    }
    let mut epoch_bytes = [0_u8; 8];
    epoch_bytes.copy_from_slice(&encoded[6..14]);
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&encoded[14..22]);
    let mut attempt_bytes = [0_u8; 32];
    attempt_bytes.copy_from_slice(&encoded[22..54]);
    Ok(FenceSequenceReservation {
        epoch: RecoveryEpoch::new(u64::from_be_bytes(epoch_bytes))
            .map_err(|_| FenceSequenceError::ZeroEpoch)?,
        sequence: NonZeroU64::new(u64::from_be_bytes(sequence_bytes))
            .ok_or(FenceSequenceError::ZeroSequence)?,
        attempt_id: SequenceAllocationAttemptId::new(attempt_bytes)?,
    })
}

#[must_use]
pub fn reservation_key(epoch: RecoveryEpoch, sequence: NonZeroU64) -> Vec<u8> {
    let mut key = Vec::with_capacity(FENCE_SEQUENCE_RESERVATION_PREFIX.len() + 16);
    key.extend_from_slice(FENCE_SEQUENCE_RESERVATION_PREFIX);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(&sequence.get().to_be_bytes());
    key
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceHeadObservation {
    pub value: Vec<u8>,
    pub mod_revision: i64,
    pub head: FenceSequenceHead,
}

impl FenceSequenceHeadObservation {
    /// Builds a validated observation of the authoritative head key.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is non-positive or `value` is not a canonical head record.
    pub fn new(value: Vec<u8>, mod_revision: i64) -> Result<Self, FenceSequenceError> {
        if mod_revision <= 0 {
            return Err(FenceSequenceError::InvalidRevision);
        }
        let head = decode_head(&value)?;
        Ok(Self {
            value,
            mod_revision,
            head,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceSequenceTxnCompare {
    HeadModRevision(i64),
    HeadExactValue(Vec<u8>),
    ReservationVersionZero(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceSequenceTxnOperation {
    Put(Vec<u8>, Vec<u8>),
    Get(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSequenceAllocationPlan {
    pub predecessor: FenceSequenceHeadObservation,
    pub sequence: NonZeroU64,
    pub attempt_id: SequenceAllocationAttemptId,
    pub reservation_key: Vec<u8>,
    pub compares: [FenceSequenceTxnCompare; 3],
    pub success: [FenceSequenceTxnOperation; 2],
    pub failure: [FenceSequenceTxnOperation; 2],
}

/// Builds the deterministic compare-and-swap plan for one sequence allocation.
///
/// # Errors
///
/// Returns an error when the predecessor high-water mark cannot advance to a non-zero `u64`.
pub fn plan_allocation(
    predecessor: FenceSequenceHeadObservation,
    attempt_id: SequenceAllocationAttemptId,
) -> Result<FenceSequenceAllocationPlan, FenceSequenceError> {
    let next = predecessor
        .head
        .high_water
        .checked_add(1)
        .ok_or(FenceSequenceError::SequenceOverflow)?;
    let sequence = NonZeroU64::new(next).ok_or(FenceSequenceError::ZeroSequence)?;
    let key = reservation_key(predecessor.head.epoch, sequence);
    let successor = encode_head(FenceSequenceHead {
        epoch: predecessor.head.epoch,
        high_water: next,
    })
    .to_vec();
    let reservation = encode_reservation(FenceSequenceReservation {
        epoch: predecessor.head.epoch,
        sequence,
        attempt_id,
    })
    .to_vec();

    Ok(FenceSequenceAllocationPlan {
        compares: [
            FenceSequenceTxnCompare::HeadModRevision(predecessor.mod_revision),
            FenceSequenceTxnCompare::HeadExactValue(predecessor.value.clone()),
            FenceSequenceTxnCompare::ReservationVersionZero(key.clone()),
        ],
        success: [
            FenceSequenceTxnOperation::Put(FENCE_SEQUENCE_HEAD_KEY.to_vec(), successor),
            FenceSequenceTxnOperation::Put(key.clone(), reservation),
        ],
        failure: [
            FenceSequenceTxnOperation::Get(FENCE_SEQUENCE_HEAD_KEY.to_vec()),
            FenceSequenceTxnOperation::Get(key.clone()),
        ],
        predecessor,
        sequence,
        attempt_id,
        reservation_key: key,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceReobservation {
    Committed,
    Superseded,
    ProvenNotCommitted,
}

/// Classifies a strong head-plus-reservation re-observation after an indeterminate mutation.
///
/// # Errors
///
/// Returns [`FenceSequenceError::ContradictoryState`] when the observations cannot be reconciled
/// with the retained exact allocation plan.
pub fn classify_reobservation(
    plan: &FenceSequenceAllocationPlan,
    head: &FenceSequenceHeadObservation,
    reservation: Option<FenceSequenceReservation>,
) -> Result<FenceSequenceReobservation, FenceSequenceError> {
    if let Some(record) = reservation {
        if record.epoch != plan.predecessor.head.epoch || record.sequence != plan.sequence {
            return Err(FenceSequenceError::ContradictoryState);
        }
        if record.attempt_id != plan.attempt_id {
            return Ok(FenceSequenceReobservation::Superseded);
        }
        if head.head.epoch == record.epoch && head.head.high_water >= record.sequence.get() {
            return Ok(FenceSequenceReobservation::Committed);
        }
        return Err(FenceSequenceError::ContradictoryState);
    }

    if head.mod_revision == plan.predecessor.mod_revision && head.value == plan.predecessor.value {
        return Ok(FenceSequenceReobservation::ProvenNotCommitted);
    }

    Err(FenceSequenceError::ContradictoryState)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FenceSequenceReissueBudget(bool);

impl FenceSequenceReissueBudget {
    /// Consumes the single deliberate reissue allowance after proof of non-commit.
    ///
    /// # Errors
    ///
    /// Returns an error unless non-commit was proven or when the one-reissue budget was already consumed.
    pub fn consume(
        &mut self,
        observed: FenceSequenceReobservation,
    ) -> Result<(), FenceSequenceError> {
        if observed != FenceSequenceReobservation::ProvenNotCommitted {
            return Err(FenceSequenceError::ReissueNotProvenSafe);
        }
        if self.0 {
            return Err(FenceSequenceError::ReissueLimitReached);
        }
        self.0 = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceSequenceError {
    InvalidHeadLength,
    InvalidReservationLength,
    InvalidMagic,
    UnsupportedVersion,
    ZeroEpoch,
    ZeroSequence,
    ZeroAttemptId,
    InvalidRevision,
    SequenceOverflow,
    ContradictoryState,
    ReissueNotProvenSafe,
    ReissueLimitReached,
}

impl fmt::Display for FenceSequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FenceSequenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> RecoveryEpoch {
        RecoveryEpoch::new(9).expect("epoch")
    }

    fn attempt(byte: u8) -> SequenceAllocationAttemptId {
        SequenceAllocationAttemptId::new([byte; 32]).expect("attempt")
    }

    #[test]
    fn exact_record_sizes_and_round_trip() {
        let head = FenceSequenceHead {
            epoch: epoch(),
            high_water: 41,
        };
        assert_eq!(decode_head(&encode_head(head)), Ok(head));

        let reservation = FenceSequenceReservation {
            epoch: epoch(),
            sequence: NonZeroU64::new(42).expect("sequence"),
            attempt_id: attempt(7),
        };
        assert_eq!(
            decode_reservation(&encode_reservation(reservation)),
            Ok(reservation)
        );
    }

    #[test]
    fn plan_is_three_compare_two_put_two_get() {
        let value = encode_head(FenceSequenceHead {
            epoch: epoch(),
            high_water: 41,
        })
        .to_vec();
        let plan = plan_allocation(
            FenceSequenceHeadObservation::new(value, 17).expect("observation"),
            attempt(4),
        )
        .expect("plan");
        assert_eq!(plan.compares.len(), 3);
        assert_eq!(plan.success.len(), 2);
        assert_eq!(plan.failure.len(), 2);
        assert_eq!(plan.sequence.get(), 42);
    }

    #[test]
    fn aba_without_reservation_fails_closed() {
        let value = encode_head(FenceSequenceHead {
            epoch: epoch(),
            high_water: 41,
        })
        .to_vec();
        let plan = plan_allocation(
            FenceSequenceHeadObservation::new(value.clone(), 17).expect("observation"),
            attempt(4),
        )
        .expect("plan");
        let same_bytes_new_revision =
            FenceSequenceHeadObservation::new(value, 18).expect("observation");
        assert_eq!(
            classify_reobservation(&plan, &same_bytes_new_revision, None),
            Err(FenceSequenceError::ContradictoryState)
        );
    }
}
