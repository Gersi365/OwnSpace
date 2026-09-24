use prw_control_plane::reachability_acquisition_evidence::{
    FenceSequenceAllocationPlan, FenceSequenceAllocationResolved,
    FenceSequenceAllocationResolvedOutcome, FenceSequenceHead, FenceSequenceHeadObservation,
    FenceSequenceLiveOwnerAcquisitionHandoff, FenceSequenceLiveOwnerAcquisitionPlan,
    FenceSequenceTxnCompare, FenceSequenceTxnOperation, RecoveryEpoch, SequenceAllocationAttemptId,
};

#[test]
fn acquisition_evidence_chain_is_externally_nameable_without_provider_activation() {
    fn assert_surface(handoff: &FenceSequenceLiveOwnerAcquisitionHandoff) {
        let acquisition: &FenceSequenceLiveOwnerAcquisitionPlan = handoff.acquisition();
        let allocation: &FenceSequenceAllocationResolved = acquisition.allocation();
        let outcome: FenceSequenceAllocationResolvedOutcome = allocation.outcome();
        let plan: &FenceSequenceAllocationPlan = allocation.plan();
        let predecessor: &FenceSequenceHeadObservation = &plan.predecessor;
        let head: &FenceSequenceHead = &predecessor.head;
        let epoch: RecoveryEpoch = head.epoch;
        let attempt_id: SequenceAllocationAttemptId = plan.attempt_id;
        let compares: &[FenceSequenceTxnCompare; 3] = &plan.compares;
        let success: &[FenceSequenceTxnOperation; 2] = &plan.success;
        let failure: &[FenceSequenceTxnOperation; 2] = &plan.failure;

        let _ = (
            outcome,
            epoch,
            attempt_id,
            compares,
            success,
            failure,
            acquisition.transaction(),
            handoff.observation(),
        );
    }

    let surface: fn(&FenceSequenceLiveOwnerAcquisitionHandoff) = assert_surface;
    let _ = surface;
}
