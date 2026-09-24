//! Authorization capability model for Ownspace.

/// Explicit remote capabilities.
///
/// This enum is intentionally narrow. It does not imply that the capability
/// is implemented merely because it is represented in the domain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Read the Agent's bounded local runtime status snapshot.
    AgentStatusRead,
    /// Read the effective bounded private-DNS configuration snapshot.
    PrivateDnsConfigRead,
    /// Open a terminal session.
    TerminalOpen,
    /// Execute a command through an authorized terminal/session mechanism.
    TerminalExec,
    /// Read filesystem content.
    FilesRead,
    /// Create or modify filesystem content.
    FilesWrite,
    /// Delete filesystem content.
    FilesDelete,
    /// Create an authorized port forward.
    ForwardingCreate,
    /// Begin requester-side rendezvous toward one registry-validated logical target.
    RequesterRendezvousStart,
    /// Manage a device.
    DeviceManage,
    /// Manage authorization policy.
    PolicyManage,
}

/// Minimal authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Operation is explicitly allowed.
    Allow,
    /// Operation is not allowed.
    Deny,
}

/// A policy evaluator can decide whether a capability is granted.
///
/// The evaluator is intentionally principal-agnostic at this interface layer.
/// Runtime code must bind/select an evaluator only after authenticating the
/// relevant principal; representing a capability does not authenticate anyone.
pub trait PolicyEvaluator {
    /// Evaluates a requested capability.
    fn evaluate(&self, capability: Capability) -> Decision;
}

/// Production-safe remote capability baseline that grants no capability.
///
/// This type has no external policy source or mutable grant state. It exists so
/// production durable capability-authority composition can remain explicitly
/// fail-closed until an allow-bearing production policy source is separately
/// selected and reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionRemoteCapabilityDenyAllPolicy;

impl PolicyEvaluator for ProductionRemoteCapabilityDenyAllPolicy {
    fn evaluate(&self, _capability: Capability) -> Decision {
        Decision::Deny
    }
}

/// Fixed, bounded local policy for the initial read-only Agent command surface.
///
/// Evaluation is entirely in-memory and covers exactly the two currently
/// implemented local read capabilities. Every other represented capability is
/// denied fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLocalReadPolicy {
    agent_status: Decision,
    private_dns: Decision,
}

impl BoundedLocalReadPolicy {
    /// Creates an explicit local read policy from independent decisions.
    #[must_use]
    pub const fn new(agent_status: Decision, private_dns: Decision) -> Self {
        Self {
            agent_status,
            private_dns,
        }
    }

    /// Creates the fail-closed local read policy.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self::new(Decision::Deny, Decision::Deny)
    }

    /// Creates a policy allowing both implemented local read capabilities.
    #[must_use]
    pub const fn allow_local_reads() -> Self {
        Self::new(Decision::Allow, Decision::Allow)
    }
}

impl PolicyEvaluator for BoundedLocalReadPolicy {
    fn evaluate(&self, capability: Capability) -> Decision {
        match capability {
            Capability::AgentStatusRead => self.agent_status,
            Capability::PrivateDnsConfigRead => self.private_dns,
            Capability::TerminalOpen
            | Capability::TerminalExec
            | Capability::FilesRead
            | Capability::FilesWrite
            | Capability::FilesDelete
            | Capability::ForwardingCreate
            | Capability::RequesterRendezvousStart
            | Capability::DeviceManage
            | Capability::PolicyManage => Decision::Deny,
        }
    }
}

/// Explicit decision bundle for the reviewed local-management capability surface.
///
/// Using a named bundle keeps every capability decision visible while avoiding an
/// order-sensitive multi-argument policy constructor. Capabilities absent from this
/// bundle are not implicitly granted by the resulting policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLocalManagementDecisions {
    /// Agent status-read decision.
    pub agent_status: Decision,
    /// Existing private-DNS read decision retained for the local command surface.
    pub private_dns: Decision,
    /// Terminal-open decision.
    pub terminal_open: Decision,
    /// Terminal execution/I/O decision.
    pub terminal_exec: Decision,
    /// File/read-download decision.
    pub files_read: Decision,
    /// File/create-upload decision.
    pub files_write: Decision,
    /// Forwarding-create/close decision.
    pub forwarding_create: Decision,
}

impl BoundedLocalManagementDecisions {
    /// Creates the explicit fail-closed decision bundle.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            agent_status: Decision::Deny,
            private_dns: Decision::Deny,
            terminal_open: Decision::Deny,
            terminal_exec: Decision::Deny,
            files_read: Decision::Deny,
            files_write: Decision::Deny,
            forwarding_create: Decision::Deny,
        }
    }
}

/// Explicit bounded policy for the currently represented local management bridge.
///
/// This type is a configuration primitive only. Constructing it does not authenticate
/// a caller, create provider authority, wire a runtime, or activate management in the
/// production Agent. Each capability used by the existing typed `BridgeCommand` surface
/// has an independent decision. Capabilities with no admitted management command in that
/// surface (`FilesDelete`, `RequesterRendezvousStart`, `DeviceManage`, `PolicyManage`) are always
/// denied.
///
/// There is intentionally no `allow_all` constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLocalManagementPolicy {
    decisions: BoundedLocalManagementDecisions,
}

impl BoundedLocalManagementPolicy {
    /// Creates one fully explicit management policy from named capability decisions.
    #[must_use]
    pub const fn new(decisions: BoundedLocalManagementDecisions) -> Self {
        Self { decisions }
    }

    /// Creates the fail-closed management policy.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self::new(BoundedLocalManagementDecisions::deny_all())
    }
}

impl PolicyEvaluator for BoundedLocalManagementPolicy {
    fn evaluate(&self, capability: Capability) -> Decision {
        match capability {
            Capability::AgentStatusRead => self.decisions.agent_status,
            Capability::PrivateDnsConfigRead => self.decisions.private_dns,
            Capability::TerminalOpen => self.decisions.terminal_open,
            Capability::TerminalExec => self.decisions.terminal_exec,
            Capability::FilesRead => self.decisions.files_read,
            Capability::FilesWrite => self.decisions.files_write,
            Capability::ForwardingCreate => self.decisions.forwarding_create,
            Capability::FilesDelete
            | Capability::RequesterRendezvousStart
            | Capability::DeviceManage
            | Capability::PolicyManage => Decision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, BoundedLocalReadPolicy,
        Capability, Decision, PolicyEvaluator, ProductionRemoteCapabilityDenyAllPolicy,
    };

    struct DenyAll;

    impl PolicyEvaluator for DenyAll {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Deny
        }
    }

    #[test]
    fn evaluator_can_deny_capability() {
        let evaluator = DenyAll;
        assert_eq!(evaluator.evaluate(Capability::FilesDelete), Decision::Deny);
    }

    #[test]
    fn production_remote_policy_denies_every_represented_capability() {
        let policy = ProductionRemoteCapabilityDenyAllPolicy;

        for capability in [
            Capability::AgentStatusRead,
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::FilesDelete,
            Capability::ForwardingCreate,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn production_remote_policy_is_copy_send_sync_and_zero_source() {
        fn assert_copy_send_sync<T: Copy + Send + Sync>() {}
        assert_copy_send_sync::<ProductionRemoteCapabilityDenyAllPolicy>();

        let first = ProductionRemoteCapabilityDenyAllPolicy;
        let second = ProductionRemoteCapabilityDenyAllPolicy;
        assert_eq!(first, second);
    }

    #[test]
    fn local_read_capabilities_are_distinct() {
        assert_ne!(
            Capability::AgentStatusRead,
            Capability::PrivateDnsConfigRead
        );
        assert_ne!(Capability::AgentStatusRead, Capability::FilesRead);
        assert_ne!(Capability::PrivateDnsConfigRead, Capability::FilesRead);
        assert_ne!(
            Capability::RequesterRendezvousStart,
            Capability::ForwardingCreate
        );
        assert_ne!(
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage
        );
    }

    #[test]
    fn bounded_local_policy_configures_local_reads_independently() {
        let status_only = BoundedLocalReadPolicy::new(Decision::Allow, Decision::Deny);
        let dns_only = BoundedLocalReadPolicy::new(Decision::Deny, Decision::Allow);

        assert_eq!(
            status_only.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        assert_eq!(
            status_only.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Deny
        );
        assert_eq!(
            dns_only.evaluate(Capability::AgentStatusRead),
            Decision::Deny
        );
        assert_eq!(
            dns_only.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Allow
        );
    }

    #[test]
    fn bounded_local_policy_denies_every_nonlocal_capability() {
        let policy = BoundedLocalReadPolicy::allow_local_reads();

        for capability in [
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::FilesDelete,
            Capability::ForwardingCreate,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn bounded_local_policy_constructors_are_deterministic() {
        let deny_all = BoundedLocalReadPolicy::deny_all();
        assert_eq!(
            deny_all.evaluate(Capability::AgentStatusRead),
            Decision::Deny
        );
        assert_eq!(
            deny_all.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Deny
        );

        let allow = BoundedLocalReadPolicy::allow_local_reads();
        assert_eq!(allow.evaluate(Capability::AgentStatusRead), Decision::Allow);
        assert_eq!(
            allow.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Allow
        );
    }

    #[test]
    fn bounded_local_policy_is_copy_send_sync() {
        fn assert_copy_send_sync<T: Copy + Send + Sync>() {}
        assert_copy_send_sync::<BoundedLocalReadPolicy>();
    }

    #[test]
    fn management_policy_configures_only_existing_bridge_capabilities() {
        let policy = BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
            agent_status: Decision::Allow,
            private_dns: Decision::Deny,
            terminal_open: Decision::Allow,
            terminal_exec: Decision::Deny,
            files_read: Decision::Allow,
            files_write: Decision::Deny,
            forwarding_create: Decision::Allow,
        });

        assert_eq!(
            policy.evaluate(Capability::AgentStatusRead),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(Capability::PrivateDnsConfigRead),
            Decision::Deny
        );
        assert_eq!(policy.evaluate(Capability::TerminalOpen), Decision::Allow);
        assert_eq!(policy.evaluate(Capability::TerminalExec), Decision::Deny);
        assert_eq!(policy.evaluate(Capability::FilesRead), Decision::Allow);
        assert_eq!(policy.evaluate(Capability::FilesWrite), Decision::Deny);
        assert_eq!(
            policy.evaluate(Capability::ForwardingCreate),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(Capability::RequesterRendezvousStart),
            Decision::Deny
        );
    }

    #[test]
    fn management_policy_always_denies_unrepresented_high_risk_capabilities() {
        let policy = BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
            agent_status: Decision::Allow,
            private_dns: Decision::Allow,
            terminal_open: Decision::Allow,
            terminal_exec: Decision::Allow,
            files_read: Decision::Allow,
            files_write: Decision::Allow,
            forwarding_create: Decision::Allow,
        });

        for capability in [
            Capability::FilesDelete,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn management_policy_deny_all_is_fail_closed() {
        let policy = BoundedLocalManagementPolicy::deny_all();
        for capability in [
            Capability::AgentStatusRead,
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::FilesDelete,
            Capability::ForwardingCreate,
            Capability::RequesterRendezvousStart,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }
    }

    #[test]
    fn bounded_management_policy_is_copy_send_sync() {
        fn assert_copy_send_sync<T: Copy + Send + Sync>() {}
        assert_copy_send_sync::<BoundedLocalManagementDecisions>();
        assert_copy_send_sync::<BoundedLocalManagementPolicy>();
    }
}
