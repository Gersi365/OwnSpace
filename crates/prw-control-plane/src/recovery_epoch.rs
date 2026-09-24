//! C02f-AJ provider-neutral recovery-epoch types and deterministic reconciliation.
//!
//! No Google SDK types, network I/O, credentials, schema creation, randomness, recovery execution,
//! or runtime activation live here.

use std::{fmt, future::Future, num::NonZeroU64};

pub const RECOVERY_EPOCH_BYTES: usize = 8;
pub const RECOVERY_EPOCH_ATTEMPT_ID_BYTES: usize = 32;
pub const RECOVERY_EPOCH_BOOTSTRAP_LAST_ATTEMPT_MARKER: [u8; 32] = [0; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryEpoch(NonZeroU64);

impl RecoveryEpoch {
    /// Constructs a non-zero issued recovery epoch.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryEpochError::ZeroIssuedEpoch`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, RecoveryEpochError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RecoveryEpochError::ZeroIssuedEpoch)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryEpochValue {
    Bootstrap,
    Issued(RecoveryEpoch),
}

impl RecoveryEpochValue {
    #[must_use]
    pub const fn get(self) -> u64 {
        match self {
            Self::Bootstrap => 0,
            Self::Issued(epoch) => epoch.get(),
        }
    }

    /// Returns the next strictly greater recovery epoch.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryEpochError::EpochOverflow`] when the current epoch is `u64::MAX`.
    pub fn checked_successor(self) -> Result<RecoveryEpoch, RecoveryEpochError> {
        RecoveryEpoch::new(
            self.get()
                .checked_add(1)
                .ok_or(RecoveryEpochError::EpochOverflow)?,
        )
    }
}

impl From<RecoveryEpoch> for RecoveryEpochValue {
    fn from(value: RecoveryEpoch) -> Self {
        Self::Issued(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryEpochAttemptId([u8; RECOVERY_EPOCH_ATTEMPT_ID_BYTES]);

impl RecoveryEpochAttemptId {
    /// Constructs a non-zero recovery-epoch issuance attempt identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryEpochError::ZeroAttemptId`] when `bytes` is the all-zero bootstrap marker.
    pub fn new(bytes: [u8; RECOVERY_EPOCH_ATTEMPT_ID_BYTES]) -> Result<Self, RecoveryEpochError> {
        if bytes == [0; RECOVERY_EPOCH_ATTEMPT_ID_BYTES] {
            return Err(RecoveryEpochError::ZeroAttemptId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_EPOCH_ATTEMPT_ID_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEpochHeadRecord {
    Bootstrap,
    Issued {
        epoch: RecoveryEpoch,
        last_attempt_id: RecoveryEpochAttemptId,
    },
}

impl RecoveryEpochHeadRecord {
    #[must_use]
    pub const fn epoch(self) -> RecoveryEpochValue {
        match self {
            Self::Bootstrap => RecoveryEpochValue::Bootstrap,
            Self::Issued { epoch, .. } => RecoveryEpochValue::Issued(epoch),
        }
    }

    #[must_use]
    pub const fn encode_columns(
        self,
    ) -> (
        [u8; RECOVERY_EPOCH_BYTES],
        [u8; RECOVERY_EPOCH_ATTEMPT_ID_BYTES],
    ) {
        match self {
            Self::Bootstrap => (
                [0; RECOVERY_EPOCH_BYTES],
                RECOVERY_EPOCH_BOOTSTRAP_LAST_ATTEMPT_MARKER,
            ),
            Self::Issued {
                epoch,
                last_attempt_id,
            } => (epoch.get().to_be_bytes(), *last_attempt_id.as_bytes()),
        }
    }

    /// Decodes the canonical Spanner head-row epoch and attempt-ID columns.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid byte lengths, a non-canonical bootstrap marker, or a zero issued attempt ID.
    pub fn decode_columns(epoch_be: &[u8], attempt: &[u8]) -> Result<Self, RecoveryEpochError> {
        let epoch = decode_recovery_epoch(epoch_be)?;
        let attempt: [u8; RECOVERY_EPOCH_ATTEMPT_ID_BYTES] = attempt
            .try_into()
            .map_err(|_| RecoveryEpochError::InvalidAttemptIdLength)?;

        match epoch {
            RecoveryEpochValue::Bootstrap if attempt == [0; RECOVERY_EPOCH_ATTEMPT_ID_BYTES] => {
                Ok(Self::Bootstrap)
            }
            RecoveryEpochValue::Bootstrap => {
                Err(RecoveryEpochError::NonCanonicalBootstrapAttemptMarker)
            }
            RecoveryEpochValue::Issued(epoch) => Ok(Self::Issued {
                epoch,
                last_attempt_id: RecoveryEpochAttemptId::new(attempt)?,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEpochIssuancePlan {
    previous_epoch: RecoveryEpochValue,
    proposed_epoch: RecoveryEpoch,
    attempt_id: RecoveryEpochAttemptId,
}

impl RecoveryEpochIssuancePlan {
    /// Builds the exact retained `(H, N, A)` issuance plan.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryEpochError::EpochOverflow`] when `previous_epoch` has no successor.
    pub fn new(
        previous_epoch: RecoveryEpochValue,
        attempt_id: RecoveryEpochAttemptId,
    ) -> Result<Self, RecoveryEpochError> {
        Ok(Self {
            previous_epoch,
            proposed_epoch: previous_epoch.checked_successor()?,
            attempt_id,
        })
    }

    #[must_use]
    pub const fn previous_epoch(self) -> RecoveryEpochValue {
        self.previous_epoch
    }

    #[must_use]
    pub const fn proposed_epoch(self) -> RecoveryEpoch {
        self.proposed_epoch
    }

    #[must_use]
    pub const fn attempt_id(self) -> RecoveryEpochAttemptId {
        self.attempt_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEpochIssuanceRecord {
    pub epoch: RecoveryEpoch,
    pub previous_epoch: RecoveryEpochValue,
    pub attempt_id: RecoveryEpochAttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEpochSubmissionOutcome {
    CommittedCurrent,
    Aborted,
    MutationIndeterminate,
}

pub trait RecoveryEpochLedgerAuthority {
    type Error;

    fn strong_head(
        &mut self,
    ) -> impl Future<Output = Result<RecoveryEpochHeadRecord, Self::Error>> + Send;

    fn submit_issuance(
        &mut self,
        plan: RecoveryEpochIssuancePlan,
    ) -> impl Future<Output = Result<RecoveryEpochSubmissionOutcome, Self::Error>> + Send;

    fn strong_reobserve(
        &mut self,
        proposed: RecoveryEpoch,
    ) -> impl Future<
        Output = Result<
            (RecoveryEpochHeadRecord, Option<RecoveryEpochIssuanceRecord>),
            Self::Error,
        >,
    > + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEpochReobservation {
    CommittedCurrent,
    CommittedButSuperseded,
    Superseded,
    ProvenNotCommitted,
}

/// Classifies one strong head-plus-history re-observation against an exact issuance plan.
///
/// # Errors
///
/// Returns [`RecoveryEpochError::ContradictoryState`] when the observed durable state cannot be
/// reconciled with the retained `(H, N, A)` plan.
pub fn classify_reobservation(
    plan: RecoveryEpochIssuancePlan,
    head: RecoveryEpochHeadRecord,
    history: Option<RecoveryEpochIssuanceRecord>,
) -> Result<RecoveryEpochReobservation, RecoveryEpochError> {
    let h = plan.previous_epoch().get();
    let n = plan.proposed_epoch().get();
    let current = head.epoch().get();

    if current < h {
        return Err(RecoveryEpochError::ContradictoryState);
    }

    if current == h {
        return if history.is_none() {
            Ok(RecoveryEpochReobservation::ProvenNotCommitted)
        } else {
            Err(RecoveryEpochError::ContradictoryState)
        };
    }

    let history = history.ok_or(RecoveryEpochError::ContradictoryState)?;
    if history.epoch != plan.proposed_epoch() {
        return Err(RecoveryEpochError::ContradictoryState);
    }

    let exact =
        history.previous_epoch == plan.previous_epoch() && history.attempt_id == plan.attempt_id();
    if !exact {
        return Ok(RecoveryEpochReobservation::Superseded);
    }

    if current == n {
        return match head {
            RecoveryEpochHeadRecord::Issued {
                epoch,
                last_attempt_id,
            } if epoch == plan.proposed_epoch() && last_attempt_id == plan.attempt_id() => {
                Ok(RecoveryEpochReobservation::CommittedCurrent)
            }
            _ => Err(RecoveryEpochError::ContradictoryState),
        };
    }

    if current > n {
        return Ok(RecoveryEpochReobservation::CommittedButSuperseded);
    }

    Err(RecoveryEpochError::ContradictoryState)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEpochReissueBudget(bool);

impl RecoveryEpochReissueBudget {
    /// Consumes the single deliberate epoch-issuance reissue allowance.
    ///
    /// # Errors
    ///
    /// Returns an error unless non-commit was proven or when the one-reissue budget was already consumed.
    pub fn consume(
        &mut self,
        observed: RecoveryEpochReobservation,
    ) -> Result<(), RecoveryEpochError> {
        if observed != RecoveryEpochReobservation::ProvenNotCommitted {
            return Err(RecoveryEpochError::ReissueNotProvenSafe);
        }
        if self.0 {
            return Err(RecoveryEpochError::ReissueLimitReached);
        }
        self.0 = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEpochError {
    ZeroIssuedEpoch,
    InvalidEpochLength,
    InvalidAttemptIdLength,
    ZeroAttemptId,
    NonCanonicalBootstrapAttemptMarker,
    EpochOverflow,
    ContradictoryState,
    ReissueNotProvenSafe,
    ReissueLimitReached,
}

impl fmt::Display for RecoveryEpochError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RecoveryEpochError {}

#[must_use]
pub const fn encode_recovery_epoch(value: RecoveryEpochValue) -> [u8; RECOVERY_EPOCH_BYTES] {
    value.get().to_be_bytes()
}

/// Decodes the canonical unsigned big-endian recovery-epoch bytes.
///
/// # Errors
///
/// Returns [`RecoveryEpochError::InvalidEpochLength`] unless `encoded` is exactly eight bytes.
pub fn decode_recovery_epoch(encoded: &[u8]) -> Result<RecoveryEpochValue, RecoveryEpochError> {
    let bytes: [u8; RECOVERY_EPOCH_BYTES] = encoded
        .try_into()
        .map_err(|_| RecoveryEpochError::InvalidEpochLength)?;
    let value = u64::from_be_bytes(bytes);
    Ok(
        NonZeroU64::new(value).map_or(RecoveryEpochValue::Bootstrap, |value| {
            RecoveryEpochValue::Issued(RecoveryEpoch(value))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(byte: u8) -> RecoveryEpochAttemptId {
        RecoveryEpochAttemptId::new([byte; RECOVERY_EPOCH_ATTEMPT_ID_BYTES]).expect("non-zero")
    }

    #[test]
    fn canonical_epoch_and_bootstrap_marker() {
        assert_eq!(
            decode_recovery_epoch(&[0; RECOVERY_EPOCH_BYTES]),
            Ok(RecoveryEpochValue::Bootstrap)
        );
        assert_eq!(
            RecoveryEpochHeadRecord::decode_columns(
                &[0; RECOVERY_EPOCH_BYTES],
                &[0; RECOVERY_EPOCH_ATTEMPT_ID_BYTES],
            ),
            Ok(RecoveryEpochHeadRecord::Bootstrap)
        );
        assert_eq!(
            RecoveryEpochHeadRecord::decode_columns(
                &[0; RECOVERY_EPOCH_BYTES],
                &[1; RECOVERY_EPOCH_ATTEMPT_ID_BYTES],
            ),
            Err(RecoveryEpochError::NonCanonicalBootstrapAttemptMarker)
        );
    }

    #[test]
    fn exact_commit_and_non_commit_classify() {
        let plan = RecoveryEpochIssuancePlan::new(RecoveryEpochValue::Bootstrap, attempt(7))
            .expect("plan");
        let row = RecoveryEpochIssuanceRecord {
            epoch: plan.proposed_epoch(),
            previous_epoch: plan.previous_epoch(),
            attempt_id: plan.attempt_id(),
        };
        let head = RecoveryEpochHeadRecord::Issued {
            epoch: plan.proposed_epoch(),
            last_attempt_id: plan.attempt_id(),
        };
        assert_eq!(
            classify_reobservation(plan, head, Some(row)),
            Ok(RecoveryEpochReobservation::CommittedCurrent)
        );
        assert_eq!(
            classify_reobservation(plan, RecoveryEpochHeadRecord::Bootstrap, None),
            Ok(RecoveryEpochReobservation::ProvenNotCommitted)
        );
    }

    #[test]
    fn one_reissue_only() {
        let mut budget = RecoveryEpochReissueBudget::default();
        assert_eq!(
            budget.consume(RecoveryEpochReobservation::ProvenNotCommitted),
            Ok(())
        );
        assert_eq!(
            budget.consume(RecoveryEpochReobservation::ProvenNotCommitted),
            Err(RecoveryEpochError::ReissueLimitReached)
        );
    }
}
