//! Phase 152 C02f-AU public evidence facade for reconciled live-owner acquisition mapping.
//!
//! This module exposes the retained provider-neutral evidence types needed by higher-level semantic
//! mapping. C02f-BS additionally exposes one lifetime-bounded acquisition-execution capability over
//! the exact live-owner store already owned by the C02f-BM preparation facade. C02f-BU adds a
//! separate lifetime-bounded lifecycle-execution capability over that same preparation-owned store
//! for only the provider primitives required by the selected BF currentness and BD release bridge
//! compositions. C02f-BX adds the bounded control-plane-owned TLS/mTLS provider bootstrap that
//! creates two role-scoped KV clients from one validated immutable authority-cluster configuration
//! and returns only the preparation facade. No raw provider client is exposed across this boundary.

#[allow(dead_code)]
pub(crate) mod attempt_id_generation;
pub mod bootstrap;
#[allow(dead_code)]
mod first_owner;
mod preparation;

pub use crate::fence_sequence::{
    FenceSequenceAllocationPlan, FenceSequenceHead, FenceSequenceHeadObservation,
    FenceSequenceTxnCompare, FenceSequenceTxnOperation, SequenceAllocationAttemptId,
};
pub use crate::fence_sequence_allocation_orchestrator::{
    FenceSequenceAllocationResolved, FenceSequenceAllocationResolvedOutcome,
};
pub use crate::fence_sequence_live_owner_bridge::FenceSequenceLiveOwnerAcquisitionPlan;
pub use crate::fence_sequence_live_owner_handoff::FenceSequenceLiveOwnerAcquisitionHandoff;
pub use crate::recovery_epoch::RecoveryEpoch;
pub use first_owner::{
    ReachabilityLiveOwnerFirstOwnerHandoff, ReachabilityLiveOwnerFirstOwnerTxnCompare,
    ReachabilityLiveOwnerFirstOwnerTxnOperation, ReachabilityLiveOwnerFirstOwnerTxnPlan,
};
pub use preparation::{
    ReachabilityLiveOwnerAcquisitionExecution, ReachabilityLiveOwnerAcquisitionPreparation,
    ReachabilityLiveOwnerLifecycleExecution, ReachabilityLiveOwnerPreparationError,
    ReachabilityLiveOwnerPreparedAcquisition,
};
