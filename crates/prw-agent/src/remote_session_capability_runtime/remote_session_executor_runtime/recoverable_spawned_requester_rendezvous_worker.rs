//! Recoverable spawned requester-aware FL worker custody.
//!
//! C03e-FQ materializes only the C03e-FO-selected bounded spawned ownership seam. One exact
//! authenticated-session owner remains inside a supervisor-retained `Arc<TokioMutex<Option<_>>>`
//! cell while one spawned task borrows that owner mutably for exact FL execution. After normal or
//! abnormal join, the supervisor recovers the exact owner by value. C03e-FS adds the recoverable
//! persistent entry/completion custody, and C03e-FU adds only the separately selected repeated
//! real-admission requester-aware integration. This module does not close or reuse a peer, clean
//! requester records, select reachability, dial targets, publish readiness, deploy, restart/recover
//! the process, or merge.

use std::{future::Future, sync::Arc};

use prw_core::DeviceId;
use prw_policy::PolicyEvaluator;
use prw_remote_bridge::CapabilityDispatcher;
use tokio::{sync::Mutex, task::JoinHandle};

use super::{
    RemoteSessionExecutorRuntime, RemoteSessionSpawnedWorkerJoinError, map_worker_join_result,
};
use crate::{
    candidate_publication_requester_rendezvous_start_intent::policy_source::RequesterRendezvousStartPolicySource,
    production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority,
    remote_session_capability_runtime::{
        AuthenticatedRemoteSessionRuntimeOwner, SharedCurrentCapabilityAuthority,
        SharedRequesterRendezvousAuthority,
        requester_rendezvous_retained_custody_dr_continuation::{
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker,
            run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability,
        },
    },
};

type RecoverableAuthenticatedSessionOwnerCell =
    Arc<Mutex<Option<AuthenticatedRemoteSessionRuntimeOwner>>>;

/// Terminal custody returned by one bounded recoverable spawned requester-aware FL worker.
///
/// The exact authenticated-session owner is recovered by value after the spawned task reaches a
/// terminal join result. The result preserves the exact FL stop on normal completion or the existing
/// bounded spawned-worker join error on abnormal completion. Possession of this value does not
/// authorize peer reuse, peer close, worker restart, requester-record cleanup, reachability work, or
/// another ingress cycle.
#[allow(
    dead_code,
    reason = "C03e-FQ materializes completion custody for a separately gated persistent integration consumer"
)]
pub(super) struct RecoverableSpawnedRequesterRendezvousWorkerCompletion {
    session_owner: AuthenticatedRemoteSessionRuntimeOwner,
    result: Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
}

#[allow(
    dead_code,
    reason = "C03e-FQ materializes completion accessors for a separately gated persistent integration consumer"
)]
impl RecoverableSpawnedRequesterRendezvousWorkerCompletion {
    /// Borrows the exact recovered authenticated-session owner retained after worker join.
    #[must_use]
    pub(super) const fn session_owner(&self) -> &AuthenticatedRemoteSessionRuntimeOwner {
        &self.session_owner
    }

    /// Returns the exact FL stop or existing bounded abnormal-join classification.
    pub(super) const fn result(
        &self,
    ) -> Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    > {
        self.result
    }

    /// Transfers the recovered session owner and exact worker/join terminal result by value.
    pub(super) fn into_parts(
        self,
    ) -> (
        AuthenticatedRemoteSessionRuntimeOwner,
        Result<
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) {
        (self.session_owner, self.result)
    }
}

/// Ownership-bearing completion published by the FU repeated real-admission requester-aware path.
///
/// The authenticated logical `DeviceId`, exact recovered session owner, and exact FL/join terminal
/// result remain one custody value. This envelope performs no peer disposition, requester cleanup,
/// candidate/reachability continuation, dialing, retry, replacement worker, or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-FU materializes the FT-selected owner-bearing repeated-admission completion before separately gated higher-owner consumption"
)]
pub(super) struct RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion {
    device_id: DeviceId,
    session_owner: AuthenticatedRemoteSessionRuntimeOwner,
    result: Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
}

#[allow(
    dead_code,
    reason = "C03e-FU retains exact requester-aware completion custody for separately gated higher-owner handling"
)]
impl RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion {
    pub(super) const fn new(
        device_id: DeviceId,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        result: Result<
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) -> Self {
        Self {
            device_id,
            session_owner,
            result,
        }
    }

    /// Returns the authenticated logical `DeviceId` that keyed the detached active entry.
    #[must_use]
    pub(super) const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Borrows the exact recovered authenticated-session owner.
    #[must_use]
    pub(super) const fn session_owner(&self) -> &AuthenticatedRemoteSessionRuntimeOwner {
        &self.session_owner
    }

    /// Returns the exact requester-aware FL stop or existing bounded abnormal-join result.
    pub(super) const fn result(
        &self,
    ) -> Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    > {
        self.result
    }

    /// Transfers the complete authenticated identity, owner and exact terminal result by value.
    pub(super) fn into_parts(
        self,
    ) -> (
        DeviceId,
        AuthenticatedRemoteSessionRuntimeOwner,
        Result<
            RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) {
        (self.device_id, self.session_owner, self.result)
    }
}

/// Ownership-bearing completion for one production-durable scheduling-aware requester worker.
///
/// The authenticated logical `DeviceId`, exact recovered authenticated-session owner, and exact
/// scheduling-aware worker/join terminal result remain one by-value custody envelope. The scheduling
/// grant is never cloned, copied, reconstructed, reminted, or diverted to a side channel.
#[allow(
    dead_code,
    reason = "C03e-NY materializes scheduling-aware repeated-admission completion custody before boundary-safe owner disposition"
)]
pub(super) struct RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion {
    device_id: DeviceId,
    session_owner: AuthenticatedRemoteSessionRuntimeOwner,
    result: Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
}

#[allow(
    dead_code,
    reason = "C03e-NY retains exact scheduling-aware completion custody for the selected higher-owner disposer"
)]
impl RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion {
    pub(super) const fn new(
        device_id: DeviceId,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        result: Result<
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) -> Self {
        Self {
            device_id,
            session_owner,
            result,
        }
    }

    #[must_use]
    pub(super) const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    #[must_use]
    pub(super) const fn session_owner(&self) -> &AuthenticatedRemoteSessionRuntimeOwner {
        &self.session_owner
    }

    pub(super) const fn result(
        &self,
    ) -> &Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    > {
        &self.result
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        DeviceId,
        AuthenticatedRemoteSessionRuntimeOwner,
        Result<
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) {
        (self.device_id, self.session_owner, self.result)
    }
}

/// Ownership-bearing completion for one fallible-verifier-time production-durable scheduling-aware
/// requester worker.
///
/// Authenticated logical identity, exact recovered authenticated-session owner and exact fallible
/// scheduling worker/join terminal result remain one by-value custody envelope. This type performs no
/// peer disposition, terminal reinterpretation, collection migration or runtime activation.
#[allow(
    dead_code,
    reason = "C03e-RB materializes the RA-selected fallible scheduling repeated-admission completion custody before separately gated owner disposition and collection migration"
)]
pub(super) struct RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion
{
    device_id: DeviceId,
    session_owner: AuthenticatedRemoteSessionRuntimeOwner,
    result: Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
}

#[allow(
    dead_code,
    reason = "C03e-RB retains exact fallible scheduling completion custody for separately gated higher-owner handling"
)]
impl RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion {
    pub(super) const fn new(
        device_id: DeviceId,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        result: Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) -> Self {
        Self {
            device_id,
            session_owner,
            result,
        }
    }

    #[must_use]
    pub(super) const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    #[must_use]
    pub(super) const fn session_owner(&self) -> &AuthenticatedRemoteSessionRuntimeOwner {
        &self.session_owner
    }

    pub(super) const fn result(
        &self,
    ) -> &Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    > {
        &self.result
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        DeviceId,
        AuthenticatedRemoteSessionRuntimeOwner,
        Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        >,
    ) {
        (self.device_id, self.session_owner, self.result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "C03e-FW materializes the FV-selected two-branch peer-disposition classifier before a separately gated runtime consumer invokes it"
)]
enum RecoverableRequesterAwarePeerDisposition {
    OrderlyShutdown,
    TerminalFailure,
}

#[allow(
    dead_code,
    reason = "C03e-FW materializes the FV-selected exact terminal-class partition for the higher-owner completion consumer"
)]
const fn select_recoverable_requester_aware_peer_disposition(
    result: Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RecoverableRequesterAwarePeerDisposition {
    match result {
        Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled) => {
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        }
        Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(_))
        | Err(_) => RecoverableRequesterAwarePeerDisposition::TerminalFailure,
    }
}

/// Consumes one exact FU completion through the C03e-FV-selected terminal peer disposition.
///
/// Cancellation reuses the existing consuming orderly-shutdown code-4 close seam. Typed FL failure
/// and abnormal join consume the recovered owner through the dedicated requester-aware code-6
/// terminal-failure close seam. The authenticated `DeviceId` and exact unchanged FL/join result are
/// returned only after owner disposition. No peer/owner, requester cleanup authority, restart token,
/// candidate/reachability state, dial target, retry, reconnect, deployment, or merge capability is
/// returned or created.
#[allow(
    dead_code,
    reason = "C03e-FW materializes the FV-selected higher-owner completion consumer before separately gated runtime integration"
)]
pub(super) fn dispose_recoverable_repeated_real_admission_requester_aware_worker_completion(
    completion: RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion,
) -> (
    DeviceId,
    Result<
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) {
    let (device_id, session_owner, result) = completion.into_parts();

    match select_recoverable_requester_aware_peer_disposition(result) {
        RecoverableRequesterAwarePeerDisposition::OrderlyShutdown => {
            session_owner.close_for_orderly_shutdown();
        }
        RecoverableRequesterAwarePeerDisposition::TerminalFailure => {
            session_owner.close_for_requester_aware_terminal_failure();
        }
    }

    (device_id, result)
}

#[allow(
    dead_code,
    reason = "C03e-NY materializes the NX-selected acknowledgement-only scheduling terminal peer-disposition partition"
)]
const fn select_scheduling_terminal_acknowledgement_peer_disposition(
    acknowledgement_succeeded: bool,
) -> RecoverableRequesterAwarePeerDisposition {
    if acknowledgement_succeeded {
        RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
    } else {
        RecoverableRequesterAwarePeerDisposition::TerminalFailure
    }
}

#[allow(
    dead_code,
    reason = "C03e-NY materializes exact scheduling-aware terminal classification before consuming recovered owner custody"
)]
const fn select_recoverable_requester_aware_scheduling_peer_disposition(
    result: &Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RecoverableRequesterAwarePeerDisposition {
    match result {
        Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled) => {
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        }
        Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::Failed(_)) | Err(_) => {
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        }
        Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            outcome,
        )) => select_scheduling_terminal_acknowledgement_peer_disposition(
            outcome.acknowledgement_result().is_ok(),
        ),
    }
}

#[allow(
    dead_code,
    reason = "C03e-RD materializes the RC-selected exact fallible scheduling terminal classification before consuming recovered owner custody"
)]
const fn select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition(
    result: &Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) -> RecoverableRequesterAwarePeerDisposition {
    match result {
        Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Cancelled) => {
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        }
        Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(_))
        | Err(_) => RecoverableRequesterAwarePeerDisposition::TerminalFailure,
        Ok(RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::SchedulingTerminal(
            outcome,
        )) => select_scheduling_terminal_acknowledgement_peer_disposition(
            outcome.acknowledgement_result().is_ok(),
        ),
    }
}

/// Consumes one exact scheduling-aware repeated-admission completion through the NX-selected owner
/// disposition law and returns only authenticated identity plus unchanged terminal result custody.
///
/// Scheduling derivation success or failure never controls owner disposition. `SchedulingTerminal`
/// uses only requester acknowledgement disposition: ACK success selects the existing orderly-shutdown
/// close seam, while ACK failure selects the existing requester-aware terminal-failure close seam.
/// Cancellation, pre-scheduling failure, and abnormal join retain the historical classification.
/// No owner, peer-reuse capability, requester cleanup authority, retry token, scheduling channel, or
/// request-construction authority crosses this boundary.
#[allow(
    dead_code,
    reason = "C03e-NY materializes the NX-selected scheduling-aware higher-owner completion disposer"
)]
pub(super) fn dispose_recoverable_repeated_real_admission_requester_aware_scheduling_worker_completion(
    completion: RecoverableRepeatedRealAdmissionRequesterAwareSchedulingWorkerCompletion,
) -> (
    DeviceId,
    Result<
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) {
    let (device_id, session_owner, result) = completion.into_parts();

    match select_recoverable_requester_aware_scheduling_peer_disposition(&result) {
        RecoverableRequesterAwarePeerDisposition::OrderlyShutdown => {
            session_owner.close_for_orderly_shutdown();
        }
        RecoverableRequesterAwarePeerDisposition::TerminalFailure => {
            session_owner.close_for_requester_aware_terminal_failure();
        }
    }

    (device_id, result)
}

/// Consumes one exact fallible-verifier-time scheduling-aware repeated-admission completion through
/// the RC-selected owner disposition law and returns only authenticated identity plus unchanged
/// terminal result custody.
///
/// Cancellation reuses the existing orderly-shutdown close seam. Exact fallible lifecycle failure
/// and abnormal join reuse the existing requester-aware terminal-failure close seam. A scheduling
/// terminal uses only requester acknowledgement disposition through the existing ACK-only helper;
/// scheduling derivation success or failure never controls peer disposition. No owner, peer-reuse
/// capability, requester cleanup authority, retry token, scheduling channel or request-construction
/// authority crosses this boundary.
#[allow(
    dead_code,
    reason = "C03e-RD materializes the RC-selected fallible scheduling higher-owner completion disposer before separately gated collection migration"
)]
pub(super) fn dispose_recoverable_repeated_real_admission_requester_aware_fallible_verifier_time_scheduling_worker_completion(
    completion: RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
) -> (
    DeviceId,
    Result<
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RemoteSessionSpawnedWorkerJoinError,
    >,
) {
    let (device_id, session_owner, result) = completion.into_parts();

    match select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition(
        &result,
    ) {
        RecoverableRequesterAwarePeerDisposition::OrderlyShutdown => {
            session_owner.close_for_orderly_shutdown();
        }
        RecoverableRequesterAwarePeerDisposition::TerminalFailure => {
            session_owner.close_for_requester_aware_terminal_failure();
        }
    }

    (device_id, result)
}

async fn join_and_recover_owned_value<T, W>(
    owner_cell: Arc<Mutex<Option<T>>>,
    worker_handle: JoinHandle<W>,
) -> (T, Result<W, RemoteSessionSpawnedWorkerJoinError>) {
    let result = map_worker_join_result(worker_handle.await);
    let mut owner_guard = owner_cell.lock().await;
    let owner = owner_guard
        .take()
        .expect("recoverable spawned worker must leave exact owner in retained cell");
    drop(owner_guard);
    (owner, result)
}

impl RemoteSessionExecutorRuntime {
    /// Spawns and joins exactly one requester-aware FL worker while preserving recoverable peer
    /// custody outside the task's by-value ownership.
    ///
    /// The exact authenticated-session owner is placed into one `Arc<TokioMutex<Option<_>>>` cell.
    /// The supervisor retains one clone while the spawned task receives another. The task never
    /// `take()`s the owner; it acquires the cell guard and borrows the contained owner mutably for
    /// exact FL execution. Consequently normal return, task panic, or any abnormal join result drops
    /// the guard while leaving owner custody in the retained cell.
    ///
    /// Shared-current authority, shared requester/rendezvous authority, and requester-aware policy
    /// source are shared only through their already-selected cloneable handles. Dispatcher,
    /// verifier-time provider, and caller cancellation future move by value into the one task.
    ///
    /// After the join handle is terminal, this seam reacquires the owner cell, recovers the exact
    /// authenticated-session owner by value, and returns it together with either the exact FL stop or
    /// [`RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion`]. The recovered peer remains
    /// retained-stopped. No path closes, reuses, restarts, retries, aborts, detaches, replaces, or
    /// inserts the worker into the persistent collection.
    #[allow(
        dead_code,
        reason = "C03e-FQ materializes the FO-selected bounded recoverable spawned FL seam for a separately gated persistent integration consumer"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        clippy::too_many_arguments,
        reason = "C03e-FQ preserves executor custody and the exact FL dependency surface without introducing an aggregate runtime context"
    )]
    pub(super) fn drive_recoverable_spawned_requester_rendezvous_worker<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        C: Future<Output = ()> + Send + 'static,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: Arc<S>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        cancellation: C,
    ) -> RecoverableSpawnedRequesterRendezvousWorkerCompletion {
        let authority = (*authority).clone();
        let requester_rendezvous_authority = requester_rendezvous_authority.clone();
        let session_owner_cell: RecoverableAuthenticatedSessionOwnerCell =
            Arc::new(Mutex::new(Some(session_owner)));
        let worker_session_owner_cell = Arc::clone(&session_owner_cell);

        let (session_owner, result) = self.runtime.block_on(async move {
            let worker_handle = tokio::spawn(async move {
                let mut session_owner_guard = worker_session_owner_cell.lock().await;
                let session_owner = session_owner_guard
                    .as_mut()
                    .expect("spawned FL worker must borrow retained authenticated-session owner");
                let mut dispatcher = dispatcher;

                let result =
                    run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker(
                        session_owner,
                        &authority,
                        policy_source.as_ref(),
                        &requester_rendezvous_authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation,
                    )
                    .await;
                drop(session_owner_guard);
                result
            });

            join_and_recover_owned_value(session_owner_cell, worker_handle).await
        });

        RecoverableSpawnedRequesterRendezvousWorkerCompletion {
            session_owner,
            result,
        }
    }

    /// Spawns and joins exactly one requester-aware KS durable-capability worker while preserving
    /// recoverable peer custody and keeping durable-capability authority distinct from requester DR.
    ///
    /// One caller-owned outer `Arc<ProductionDurableCapabilityAuthority>` moves by value into the
    /// bounded `'static` task. Inside that task only an ordinary borrow of the same authority reaches
    /// the existing KS FI worker. The authority type itself is not cloned or widened, and the
    /// existing shared-current authority remains reserved for requester DR continuation.
    ///
    /// Authenticated-session owner-cell recovery, requester/rendezvous authority sharing, dispatcher
    /// ownership, verifier-time provider ownership, cancellation transfer and join classification
    /// remain identical to the existing recoverable FQ seam. This method is dormant until a separately
    /// gated higher-owner/FU integration is selected.
    #[allow(
        dead_code,
        reason = "C03e-KU materializes the KT-selected dormant production-durable recoverable spawned requester-aware worker seam before separately gated FU propagation"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        clippy::too_many_arguments,
        reason = "C03e-KU preserves distinct durable-capability and requester-DR authority lanes without introducing an aggregate runtime context"
    )]
    pub(super) fn drive_recoverable_spawned_requester_rendezvous_worker_with_production_durable_capability<
        P: PolicyEvaluator + Send + Sync + 'static,
        D: CapabilityDispatcher + Send + 'static,
        T: FnMut() -> u64 + Send + 'static,
        S: RequesterRendezvousStartPolicySource + Send + Sync + ?Sized + 'static,
        C: Future<Output = ()> + Send + 'static,
    >(
        &mut self,
        session_owner: AuthenticatedRemoteSessionRuntimeOwner,
        capability_authority: Arc<ProductionDurableCapabilityAuthority>,
        requester_dr_authority: &SharedCurrentCapabilityAuthority<P>,
        policy_source: Arc<S>,
        requester_rendezvous_authority: &SharedRequesterRendezvousAuthority,
        verifier_time_unix_seconds: T,
        dispatcher: D,
        cancellation: C,
    ) -> RecoverableSpawnedRequesterRendezvousWorkerCompletion {
        let requester_dr_authority = (*requester_dr_authority).clone();
        let requester_rendezvous_authority = requester_rendezvous_authority.clone();
        let session_owner_cell: RecoverableAuthenticatedSessionOwnerCell =
            Arc::new(Mutex::new(Some(session_owner)));
        let worker_session_owner_cell = Arc::clone(&session_owner_cell);

        let (session_owner, result) = self.runtime.block_on(async move {
            let worker_handle = tokio::spawn(async move {
                let mut session_owner_guard = worker_session_owner_cell.lock().await;
                let session_owner = session_owner_guard
                    .as_mut()
                    .expect("spawned KS worker must borrow retained authenticated-session owner");
                let mut dispatcher = dispatcher;

                let result =
                    run_requester_rendezvous_post_terminal_response_serial_lifecycle_worker_with_production_durable_capability(
                        session_owner,
                        capability_authority.as_ref(),
                        &requester_dr_authority,
                        policy_source.as_ref(),
                        &requester_rendezvous_authority,
                        verifier_time_unix_seconds,
                        &mut dispatcher,
                        cancellation,
                    )
                    .await;
                drop(session_owner_guard);
                result
            });

            join_and_recover_owned_value(session_owner_cell, worker_handle).await
        });

        RecoverableSpawnedRequesterRendezvousWorkerCompletion {
            session_owner,
            result,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prw_core::DeviceId;
    use prw_remote_bridge::RemoteBridgeError;
    use tokio::{runtime::Builder, sync::Mutex};

    use super::{
        RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
        RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion,
        RecoverableRequesterAwarePeerDisposition, RemoteSessionSpawnedWorkerJoinError,
        RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
        RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
        RequesterRendezvousProductionDurableSchedulingWorkerStop,
        dispose_recoverable_repeated_real_admission_requester_aware_fallible_verifier_time_scheduling_worker_completion,
        dispose_recoverable_repeated_real_admission_requester_aware_worker_completion,
        join_and_recover_owned_value,
        select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition,
        select_recoverable_requester_aware_peer_disposition,
        select_recoverable_requester_aware_scheduling_peer_disposition,
        select_scheduling_terminal_acknowledgement_peer_disposition,
    };
    use crate::remote_session_capability_runtime::{
        AuthenticatedRemoteSessionPostAuthIngressTransactionError,
        authenticated_remote_session_runtime::AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError,
        requester_rendezvous_retained_custody_dr_continuation::{
            RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError,
            RequesterRendezvousPostTerminalResponseSerialLifecycleError,
        },
    };

    fn assert_completion_disposer_signature(
        disposer: fn(
            RecoverableRepeatedRealAdmissionRequesterAwareWorkerCompletion,
        ) -> (
            DeviceId,
            Result<
                RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ),
    ) {
        let _ = disposer;
    }

    fn assert_fallible_scheduling_completion_disposer_signature(
        disposer: fn(
            RecoverableRepeatedRealAdmissionRequesterAwareFallibleVerifierTimeSchedulingWorkerCompletion,
        ) -> (
            DeviceId,
            Result<
                RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
                RemoteSessionSpawnedWorkerJoinError,
            >,
        ),
    ) {
        let _ = disposer;
    }

    #[test]
    fn completion_disposer_consumes_exact_fu_completion_shape() {
        assert_completion_disposer_signature(
            dispose_recoverable_repeated_real_admission_requester_aware_worker_completion,
        );
    }

    #[test]
    fn fallible_scheduling_completion_disposer_consumes_exact_rb_completion_shape() {
        assert_fallible_scheduling_completion_disposer_signature(
            dispose_recoverable_repeated_real_admission_requester_aware_fallible_verifier_time_scheduling_worker_completion,
        );
    }

    #[test]
    fn cancellation_selects_orderly_shutdown_peer_disposition() {
        let result =
            Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Cancelled);

        assert_eq!(
            select_recoverable_requester_aware_peer_disposition(result),
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        );
    }

    #[test]
    fn typed_fl_failure_selects_terminal_failure_peer_disposition() {
        let failure = RequesterRendezvousPostTerminalResponseSerialLifecycleError::Ingress(
            AuthenticatedRemoteSessionPostAuthIngressTransactionError::Bridge(
                RemoteBridgeError::SessionExpired,
            ),
        );
        let result =
            Ok(RequesterRendezvousPostTerminalResponseSerialLifecycleWorkerStop::Failed(failure));

        assert_eq!(
            select_recoverable_requester_aware_peer_disposition(result),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn abnormal_join_selects_terminal_failure_peer_disposition() {
        let result = Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion);

        assert_eq!(
            select_recoverable_requester_aware_peer_disposition(result),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn scheduling_cancellation_selects_orderly_shutdown_peer_disposition() {
        let result = Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::Cancelled);

        assert_eq!(
            select_recoverable_requester_aware_scheduling_peer_disposition(&result),
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        );
    }

    #[test]
    fn scheduling_preterminal_failure_selects_terminal_failure_peer_disposition() {
        let failure = RequesterRendezvousPostTerminalResponseSerialLifecycleError::Ingress(
            AuthenticatedRemoteSessionPostAuthIngressTransactionError::Bridge(
                RemoteBridgeError::SessionExpired,
            ),
        );
        let result = Ok(RequesterRendezvousProductionDurableSchedulingWorkerStop::Failed(failure));

        assert_eq!(
            select_recoverable_requester_aware_scheduling_peer_disposition(&result),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn scheduling_abnormal_join_selects_terminal_failure_peer_disposition() {
        let result: Result<
            RequesterRendezvousProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        > = Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion);

        assert_eq!(
            select_recoverable_requester_aware_scheduling_peer_disposition(&result),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn fallible_scheduling_cancellation_selects_orderly_shutdown_peer_disposition() {
        let result = Ok(
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Cancelled,
        );

        assert_eq!(
            select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition(
                &result,
            ),
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        );
    }

    #[test]
    fn fallible_scheduling_preterminal_failure_selects_terminal_failure_peer_disposition() {
        let failure = RequesterRendezvousFallibleVerifierTimePostTerminalResponseSerialLifecycleError::Ingress(
            AuthenticatedRemoteSessionFallibleVerifierTimeProductionDurablePostAuthIngressError::Ingress(
                AuthenticatedRemoteSessionPostAuthIngressTransactionError::Bridge(
                    RemoteBridgeError::SessionExpired,
                ),
            ),
        );
        let result = Ok(
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop::Failed(
                failure,
            ),
        );

        assert_eq!(
            select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition(
                &result,
            ),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn fallible_scheduling_abnormal_join_selects_terminal_failure_peer_disposition() {
        let result: Result<
            RequesterRendezvousFallibleVerifierTimeProductionDurableSchedulingWorkerStop,
            RemoteSessionSpawnedWorkerJoinError,
        > = Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion);

        assert_eq!(
            select_recoverable_requester_aware_fallible_verifier_time_scheduling_peer_disposition(
                &result,
            ),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn scheduling_terminal_ack_success_selects_orderly_shutdown_independent_of_derivation() {
        assert_eq!(
            select_scheduling_terminal_acknowledgement_peer_disposition(true),
            RecoverableRequesterAwarePeerDisposition::OrderlyShutdown
        );
    }

    #[test]
    fn scheduling_terminal_ack_failure_selects_terminal_failure_independent_of_derivation() {
        assert_eq!(
            select_scheduling_terminal_acknowledgement_peer_disposition(false),
            RecoverableRequesterAwarePeerDisposition::TerminalFailure
        );
    }

    #[test]
    fn retained_cell_recovers_exact_owner_after_normal_join() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime constructs");

        let (owner, result) = runtime.block_on(async {
            let owner_cell = Arc::new(Mutex::new(Some(41_u8)));
            let worker_owner_cell = Arc::clone(&owner_cell);
            let worker_handle = tokio::spawn(async move {
                let owner_guard = worker_owner_cell.lock().await;
                assert_eq!(owner_guard.as_ref(), Some(&41_u8));
                drop(owner_guard);
                7_u8
            });

            join_and_recover_owned_value(owner_cell, worker_handle).await
        });

        assert_eq!(owner, 41_u8);
        assert_eq!(result, Ok(7_u8));
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "C03e-FQ intentionally proves panic unwinding releases a held owner-cell guard without removing owner custody"
    )]
    fn retained_cell_recovers_exact_owner_after_abnormal_join() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime constructs");

        let (owner, result) = runtime.block_on(async {
            let owner_cell = Arc::new(Mutex::new(Some(53_u8)));
            let worker_owner_cell = Arc::clone(&owner_cell);
            let worker_handle = tokio::spawn(async move {
                let owner_guard = worker_owner_cell.lock().await;
                assert_eq!(owner_guard.as_ref(), Some(&53_u8));
                panic!("intentional recoverable spawned-worker test panic");
            });

            join_and_recover_owned_value(owner_cell, worker_handle).await
        });

        assert_eq!(owner, 53_u8);
        assert_eq!(
            result,
            Err(RemoteSessionSpawnedWorkerJoinError::AbnormalTaskCompletion)
        );
    }
}

mod recoverable_persistent_requester_rendezvous_worker;
#[allow(
    dead_code,
    reason = "C03e-FU materializes FT-selected repeated real-admission requester-aware persistent FL integration before separately gated higher-owner consumption"
)]
mod repeated_real_admission_requester_aware_persistent_fl_integration;
