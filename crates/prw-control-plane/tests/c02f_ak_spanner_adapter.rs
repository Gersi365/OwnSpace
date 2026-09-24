//! Phase 152 C02f-AK staging compile harness for the Spanner recovery-epoch adapter.
//!
//! The production source modules are included directly so the concrete SDK adapter can be
//! compiled, linted, and unit-tested without exposing it through the control-plane public module
//! surface or constructing credentials/endpoints. This harness performs no provider network I/O.

#[path = "../src/recovery_epoch.rs"]
pub mod recovery_epoch;
#[path = "../src/recovery_epoch_spanner.rs"]
pub mod recovery_epoch_spanner;

#[test]
fn c02f_ak_spanner_adapter_is_linked_into_validation() {
    assert_eq!(
        recovery_epoch_spanner::PRW_RECOVERY_EPOCH_LEDGER_ID,
        "prw-recovery-epoch-v1"
    );
    assert_eq!(
        recovery_epoch_spanner::PRW_RECOVERY_EPOCH_HEAD_TABLE,
        "PrwRecoveryEpochHeadV1"
    );
    assert_eq!(
        recovery_epoch_spanner::PRW_RECOVERY_EPOCH_ISSUANCE_TABLE,
        "PrwRecoveryEpochIssuanceV1"
    );
}
