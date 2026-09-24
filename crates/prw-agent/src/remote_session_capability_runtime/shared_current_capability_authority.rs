//! Agent-owned shared-current registry/policy authority for staged remote-session workers.
//!
//! C03e-W selects one combined Tokio `RwLock` state so future spawned workers can revalidate each
//! protected operation against current registry and policy state without per-task authority
//! snapshots. C03e-X materializes only this owner and its bounded internal read operation. C03e-GR
//! adds only a bounded async read operation so the same current-authority read custody can remain
//! lexical across one explicitly awaitable durable candidate commit. It does not spawn tasks,
//! expose lock guards, wire the Agent binary, publish readiness or activate remote transport.

use std::sync::Arc;

use prw_policy::PolicyEvaluator;
use prw_registry::WorkspaceDeviceRegistry;
use tokio::sync::RwLock;

struct CurrentCapabilityAuthorityState<P> {
    registry: WorkspaceDeviceRegistry,
    policy: P,
}

/// Shared owner of the current registry and policy authority used by remote capability requests.
///
/// Clones share only the outer [`Arc`]. Registry state, policy state and authorization outcomes are
/// never cloned into per-worker snapshots.
pub struct SharedCurrentCapabilityAuthority<P> {
    state: Arc<RwLock<CurrentCapabilityAuthorityState<P>>>,
}

impl<P> Clone for SharedCurrentCapabilityAuthority<P> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<P> SharedCurrentCapabilityAuthority<P> {
    /// Creates one shared current-authority state from the exact registry and policy values.
    ///
    /// Construction performs no authorization, registry mutation, network I/O, task spawn or
    /// readiness publication.
    #[must_use]
    pub fn new(registry: WorkspaceDeviceRegistry, policy: P) -> Self {
        Self {
            state: Arc::new(RwLock::new(CurrentCapabilityAuthorityState {
                registry,
                policy,
            })),
        }
    }
}

impl<P> SharedCurrentCapabilityAuthority<P>
where
    P: PolicyEvaluator + Send + Sync,
{
    /// Runs one synchronous operation against one coherent current registry/policy read snapshot.
    ///
    /// The read guard is acquired asynchronously, but `operation` itself is synchronous and its
    /// return type cannot borrow the registry or policy arguments. Consequently the guard is
    /// released before the caller can perform dispatcher execution, network I/O, cancellation waits
    /// or task lifecycle work.
    #[allow(
        dead_code,
        reason = "C03e-X materializes shared-current authority before the separately gated worker-integration seam"
    )]
    pub(super) async fn with_current_authority<R, F>(&self, operation: F) -> R
    where
        R: Send,
        F: for<'a> FnOnce(&'a WorkspaceDeviceRegistry, &'a P) -> R + Send,
    {
        let state = self.state.read().await;
        operation(&state.registry, &state.policy)
    }

    /// Runs one explicitly awaitable operation while retaining one coherent current-authority read.
    ///
    /// The existing `RwLock` read guard remains lexical to this method for the complete awaited
    /// operation. Neither the guard nor registry/policy references can escape. This exists only so
    /// an already-selected durable operation can be awaited without dropping current registry
    /// authority between commit-time validation and durable completion; it creates no runtime,
    /// task, channel, retry path, snapshot authority or new synchronization primitive.
    pub(super) async fn with_current_authority_async<R, F>(&self, operation: F) -> R
    where
        R: Send,
        F: for<'a> AsyncFnOnce(&'a WorkspaceDeviceRegistry, &'a P) -> R + Send,
    {
        let state = self.state.read().await;
        operation(&state.registry, &state.policy).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prw_policy::BoundedLocalManagementPolicy;
    use prw_registry::WorkspaceDeviceRegistry;

    use super::SharedCurrentCapabilityAuthority;

    #[test]
    fn clone_shares_one_current_authority_allocation() {
        let authority = SharedCurrentCapabilityAuthority::new(
            WorkspaceDeviceRegistry::new(),
            BoundedLocalManagementPolicy::deny_all(),
        );
        let clone = authority.clone();

        assert!(Arc::ptr_eq(&authority.state, &clone.state));
    }

    #[test]
    fn owner_does_not_require_registry_or_policy_clone() {
        struct NonClonePolicy;

        impl prw_policy::PolicyEvaluator for NonClonePolicy {
            fn evaluate(&self, _capability: prw_policy::Capability) -> prw_policy::Decision {
                prw_policy::Decision::Deny
            }
        }

        fn assert_clone<T: Clone>(_value: &T) {}

        let authority =
            SharedCurrentCapabilityAuthority::new(WorkspaceDeviceRegistry::new(), NonClonePolicy);
        assert_clone(&authority);
    }
}
