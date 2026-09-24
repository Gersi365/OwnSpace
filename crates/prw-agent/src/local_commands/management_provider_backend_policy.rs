//! Pure provider-backend policy seams for Phase 152 C02d.
//!
//! This module deliberately performs no PTY, process, socket, thread, or runtime
//! operation. It separates provider-owned terminal template selection and
//! forwarding egress/lifecycle policy from request decoding before any concrete
//! Linux adapter is introduced.

use std::time::Duration;

use prw_forwarding::{ForwardTarget, TcpForwardSpec};
use prw_terminal::TerminalProfile;

/// Maximum simultaneous accepted connections owned by one forwarding session.
///
/// This reuses the existing Phase 140 remote-transport concurrency precedent of
/// 32 remotely initiated bidirectional streams rather than introducing a wider
/// forwarding-specific concurrency surface.
pub(super) const MAX_FORWARD_CONNECTIONS_PER_SESSION: usize = 32;
/// Maximum simultaneous forwarding connections owned by one Agent provider lifecycle.
pub(super) const MAX_FORWARD_CONNECTIONS_AGGREGATE: usize = 32;
/// Maximum exact target endpoints selectable by one Agent-owned egress policy.
pub(super) const MAX_FORWARD_EGRESS_TARGETS: usize = 32;
/// Bounded target-connect budget inherited from the existing Phase 140 operation timeout.
pub(super) const FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded forwarding inactivity budget inherited from the Phase 140 idle timeout.
pub(super) const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-direction forwarding copy buffer bound matching the existing 64 KiB transport bound.
pub(super) const FORWARD_COPY_BUFFER_BYTES: usize = 65_536;

/// Provider-owned terminal launch-template identifier.
///
/// The identifier is derived only from the already-typed terminal profile. It
/// intentionally carries no executable path, argument vector, environment,
/// working directory, or request-controlled string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinuxTerminalLaunchTemplateId {
    /// Provider-owned template corresponding to the POSIX-shell profile.
    PosixInteractiveShell,
    /// Provider-owned template corresponding to the Bash-shell profile.
    BashInteractiveShell,
}

impl LinuxTerminalLaunchTemplateId {
    /// Maps one admitted named terminal profile to its provider-owned template ID.
    #[must_use]
    pub(super) const fn for_profile(profile: TerminalProfile) -> Self {
        match profile {
            TerminalProfile::PosixShell => Self::PosixInteractiveShell,
            TerminalProfile::BashShell => Self::BashInteractiveShell,
        }
    }
}

/// Agent-owned forwarding-target policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForwardingEgressDecision {
    /// Exact validated forwarding target is permitted by provider policy.
    Allow,
    /// Exact validated forwarding target is denied by provider policy.
    Deny,
}

/// Pure policy boundary evaluated before a concrete forwarding backend connects.
///
/// The input is already a validated [`TcpForwardSpec`]. Implementations cannot
/// widen the loopback bind domain, introduce DNS, or receive raw request bytes.
/// Production assembly must provide an explicitly reviewed implementation before
/// any real socket adapter is wired.
pub(super) trait ForwardingEgressPolicy {
    /// Evaluates the exact validated forwarding specification.
    fn evaluate(&self, spec: TcpForwardSpec) -> ForwardingEgressDecision;
}

/// Fail-closed forwarding egress policy used before production policy selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DenyAllForwardingEgressPolicy;

impl ForwardingEgressPolicy for DenyAllForwardingEgressPolicy {
    fn evaluate(&self, _spec: TcpForwardSpec) -> ForwardingEgressDecision {
        ForwardingEgressDecision::Deny
    }
}

/// Failure while assembling a bounded exact-target forwarding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExactForwardingEgressPolicyError {
    /// More exact target entries were supplied than the locked policy bound.
    TooManyTargets,
}

/// Agent-owned bounded allowlist of exact validated forwarding targets.
///
/// The allowlist stores only typed IP-address + port targets. It cannot represent
/// hostnames, CIDRs, port ranges, wildcard targets, bind-address changes, or raw
/// request text. Assembly is crate-internal and therefore remains outside request
/// decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExactForwardingEgressPolicy {
    allowed_targets: Box<[ForwardTarget]>,
}

impl ExactForwardingEgressPolicy {
    /// Builds one bounded target allowlist, removing duplicate exact targets.
    ///
    /// # Errors
    ///
    /// Returns [`ExactForwardingEgressPolicyError::TooManyTargets`] when the
    /// caller supplies more than [`MAX_FORWARD_EGRESS_TARGETS`] entries.
    pub(super) fn try_from_targets(
        targets: &[ForwardTarget],
    ) -> Result<Self, ExactForwardingEgressPolicyError> {
        if targets.len() > MAX_FORWARD_EGRESS_TARGETS {
            return Err(ExactForwardingEgressPolicyError::TooManyTargets);
        }

        let mut allowed_targets = Vec::with_capacity(targets.len());
        for target in targets {
            if !allowed_targets.contains(target) {
                allowed_targets.push(*target);
            }
        }

        Ok(Self {
            allowed_targets: allowed_targets.into_boxed_slice(),
        })
    }

    /// Returns the number of unique exact targets in the policy.
    #[must_use]
    pub(super) fn target_count(&self) -> usize {
        self.allowed_targets.len()
    }
}

impl ForwardingEgressPolicy for ExactForwardingEgressPolicy {
    fn evaluate(&self, spec: TcpForwardSpec) -> ForwardingEgressDecision {
        if self.allowed_targets.contains(&spec.target()) {
            ForwardingEgressDecision::Allow
        } else {
            ForwardingEgressDecision::Deny
        }
    }
}

/// Locked TCP half-close behavior for a future forwarding pump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForwardingHalfClosePolicy {
    /// Propagate EOF to the peer write half, then continue draining the opposite
    /// direction until its EOF, explicit cancellation, or idle-timeout expiry.
    PropagateEofAndDrainPeer,
}

/// One ordered provider-close stage for a future forwarding handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForwardingCloseStage {
    /// Stop accepting new loopback connections first.
    StopAccepting,
    /// Cancel or close every currently owned forwarding connection next.
    CancelActiveConnections,
    /// Join every owned connection/pump worker before close can succeed.
    JoinWorkers,
}

/// Locked forwarding close ordering used by later concrete provider review.
pub(super) const FORWARDING_CLOSE_ORDER: [ForwardingCloseStage; 3] = [
    ForwardingCloseStage::StopAccepting,
    ForwardingCloseStage::CancelActiveConnections,
    ForwardingCloseStage::JoinWorkers,
];

/// Returns the locked forwarding half-close behavior.
#[must_use]
pub(super) const fn forwarding_half_close_policy() -> ForwardingHalfClosePolicy {
    ForwardingHalfClosePolicy::PropagateEofAndDrainPeer
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use prw_forwarding::{ForwardTarget, LoopbackBind, LoopbackFamily, TcpForwardSpec};
    use prw_terminal::TerminalProfile;

    use super::{
        DenyAllForwardingEgressPolicy, ExactForwardingEgressPolicy,
        ExactForwardingEgressPolicyError, FORWARD_CONNECT_TIMEOUT, FORWARD_COPY_BUFFER_BYTES,
        FORWARD_IDLE_TIMEOUT, FORWARDING_CLOSE_ORDER, ForwardingCloseStage,
        ForwardingEgressDecision, ForwardingEgressPolicy, ForwardingHalfClosePolicy,
        LinuxTerminalLaunchTemplateId, MAX_FORWARD_CONNECTIONS_AGGREGATE,
        MAX_FORWARD_CONNECTIONS_PER_SESSION, MAX_FORWARD_EGRESS_TARGETS,
        forwarding_half_close_policy,
    };

    fn target(address: Ipv4Addr, port: u16) -> ForwardTarget {
        ForwardTarget::new(IpAddr::V4(address), port).expect("valid explicit target")
    }

    fn spec(bind_port: u16, target: ForwardTarget) -> TcpForwardSpec {
        TcpForwardSpec::new(
            LoopbackBind::new(LoopbackFamily::Ipv4, bind_port).expect("valid loopback bind"),
            target,
        )
    }

    #[test]
    fn terminal_profile_maps_only_to_provider_owned_template_id() {
        assert_eq!(
            LinuxTerminalLaunchTemplateId::for_profile(TerminalProfile::PosixShell),
            LinuxTerminalLaunchTemplateId::PosixInteractiveShell
        );
        assert_eq!(
            LinuxTerminalLaunchTemplateId::for_profile(TerminalProfile::BashShell),
            LinuxTerminalLaunchTemplateId::BashInteractiveShell
        );
    }

    #[test]
    fn default_forwarding_egress_policy_is_deny_all() {
        let policy = DenyAllForwardingEgressPolicy;
        let ssh = target(Ipv4Addr::LOCALHOST, 22);
        let https = target(Ipv4Addr::LOCALHOST, 443);
        assert_eq!(
            policy.evaluate(spec(2200, ssh)),
            ForwardingEgressDecision::Deny
        );
        assert_eq!(
            policy.evaluate(spec(8443, https)),
            ForwardingEgressDecision::Deny
        );
    }

    #[test]
    fn exact_target_policy_allows_only_configured_ip_port_targets() {
        let ssh = target(Ipv4Addr::new(10, 0, 0, 10), 22);
        let policy = ExactForwardingEgressPolicy::try_from_targets(&[ssh])
            .expect("one exact target is within policy bound");

        assert_eq!(policy.target_count(), 1);
        assert_eq!(
            policy.evaluate(spec(2200, ssh)),
            ForwardingEgressDecision::Allow
        );
        assert_eq!(
            policy.evaluate(spec(2201, ssh)),
            ForwardingEgressDecision::Allow
        );
        assert_eq!(
            policy.evaluate(spec(2200, target(Ipv4Addr::new(10, 0, 0, 10), 23))),
            ForwardingEgressDecision::Deny
        );
        assert_eq!(
            policy.evaluate(spec(2200, target(Ipv4Addr::new(10, 0, 0, 11), 22))),
            ForwardingEgressDecision::Deny
        );
    }

    #[test]
    fn exact_target_policy_is_bounded_and_deduplicated() {
        let ssh = target(Ipv4Addr::new(10, 0, 0, 10), 22);
        let deduplicated = ExactForwardingEgressPolicy::try_from_targets(&[ssh, ssh])
            .expect("duplicates remain inside input bound");
        assert_eq!(deduplicated.target_count(), 1);

        let too_many = (0..=MAX_FORWARD_EGRESS_TARGETS)
            .map(|index| {
                target(
                    Ipv4Addr::new(10, 0, 0, u8::try_from(index + 1).expect("test octet fits")),
                    22,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ExactForwardingEgressPolicy::try_from_targets(&too_many),
            Err(ExactForwardingEgressPolicyError::TooManyTargets)
        );
    }

    #[test]
    fn forwarding_worker_bounds_match_locked_transport_precedent() {
        assert_eq!(MAX_FORWARD_CONNECTIONS_PER_SESSION, 32);
        assert_eq!(MAX_FORWARD_CONNECTIONS_AGGREGATE, 32);
        assert_eq!(MAX_FORWARD_EGRESS_TARGETS, 32);
        const {
            assert!(MAX_FORWARD_CONNECTIONS_PER_SESSION <= MAX_FORWARD_CONNECTIONS_AGGREGATE);
        }
        assert_eq!(FORWARD_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(FORWARD_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(FORWARD_COPY_BUFFER_BYTES, 65_536);
    }

    #[test]
    fn forwarding_half_close_and_teardown_order_are_explicit() {
        assert_eq!(
            forwarding_half_close_policy(),
            ForwardingHalfClosePolicy::PropagateEofAndDrainPeer
        );
        assert_eq!(
            FORWARDING_CLOSE_ORDER,
            [
                ForwardingCloseStage::StopAccepting,
                ForwardingCloseStage::CancelActiveConnections,
                ForwardingCloseStage::JoinWorkers,
            ]
        );
    }
}
