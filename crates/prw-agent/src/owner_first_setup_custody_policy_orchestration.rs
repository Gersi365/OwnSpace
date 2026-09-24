//! Dormant first-time-setup custody-policy orchestration for the owner PC.
//!
//! C03e-YT composes an already-authoritative owner logical-identity record with
//! one explicit transport-identity provisioning selection. It is pure in-memory
//! orchestration: no environment reads, capability probes, key generation,
//! credential persistence, `SQLite` access, or bootstrap transaction occur here.
//! Validated first-run startup authority now consumes this plan.

use prw_core::{DeviceId, UserId, WorkspaceId};
use prw_transport_identity_provisioning::TransportIdentityProvisioningPolicy;

use crate::owner_first_setup_bootstrap_inputs::OwnerLogicalIdentityRecord;

/// Explicit first-time-setup transport custody selection.
///
/// The preferred policy is the normal/default selection. The host-key-only
/// variant is deliberately named as an explicit fallback so callers cannot
/// mistake it for an automatic downgrade result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFirstSetupTransportCustodySelection {
    /// Preferred TPM2-plus-host-secret policy.
    PreferredDefault,
    /// Explicit lower-tier host-key-only fallback.
    ExplicitHostKeyOnlyFallback,
}

impl OwnerFirstSetupTransportCustodySelection {
    /// Maps setup intent to the single authoritative provisioning policy type.
    #[must_use]
    pub const fn provisioning_policy(self) -> TransportIdentityProvisioningPolicy {
        match self {
            Self::PreferredDefault => TransportIdentityProvisioningPolicy::Preferred,
            Self::ExplicitHostKeyOnlyFallback => TransportIdentityProvisioningPolicy::HostKeyOnly,
        }
    }
}

/// Pure non-secret first-time-setup plan produced before any provisioning.
///
/// This carrier preserves the exact logical owner identity tuple and one caller-
/// selected transport custody policy. It contains no private key material and does
/// not itself authorize provisioning or local-authority mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerFirstSetupCustodyPolicyPlan {
    workspace_id: WorkspaceId,
    user_id: UserId,
    device_id: DeviceId,
    transport_selection: OwnerFirstSetupTransportCustodySelection,
}

impl OwnerFirstSetupCustodyPolicyPlan {
    /// Returns the exact owner workspace identifier copied from the bootstrap record.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    /// Returns the exact owner user identifier copied from the bootstrap record.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the exact owner-PC device identifier copied from the bootstrap record.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the explicit first-time-setup custody selection.
    #[must_use]
    pub const fn transport_selection(&self) -> OwnerFirstSetupTransportCustodySelection {
        self.transport_selection
    }

    /// Returns the authoritative transport provisioning policy represented by this plan.
    #[must_use]
    pub const fn transport_provisioning_policy(&self) -> TransportIdentityProvisioningPolicy {
        self.transport_selection.provisioning_policy()
    }
}

/// Composes one pure first-time-setup custody-policy plan.
///
/// The caller must already possess an authoritative owner logical-identity record
/// and must explicitly select the transport custody policy. This function does not
/// create or load the record and does not invoke either transport provisioner.
#[must_use]
pub fn compose_owner_first_setup_custody_policy_plan(
    record: &OwnerLogicalIdentityRecord,
    transport_selection: OwnerFirstSetupTransportCustodySelection,
) -> OwnerFirstSetupCustodyPolicyPlan {
    OwnerFirstSetupCustodyPolicyPlan {
        workspace_id: record.workspace_id().clone(),
        user_id: record.user_id().clone(),
        device_id: record.device_id().clone(),
        transport_selection,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
    };
    use crate::owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record;
    use prw_transport_identity_provisioning::{
        TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER, TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
        TransportIdentityProvisioningPolicy,
    };

    #[test]
    fn plan_preserves_exact_owner_identity_for_each_explicit_selection() {
        let record = generate_owner_logical_identity_record().expect("generate disposable record");

        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            let plan = compose_owner_first_setup_custody_policy_plan(&record, selection);
            assert_eq!(plan.workspace_id(), record.workspace_id());
            assert_eq!(plan.user_id(), record.user_id());
            assert_eq!(plan.device_id(), record.device_id());
            assert_eq!(plan.transport_selection(), selection);
        }
    }

    #[test]
    fn setup_selection_maps_to_authoritative_provisioning_policy() {
        let preferred = OwnerFirstSetupTransportCustodySelection::PreferredDefault;
        assert_eq!(
            preferred.provisioning_policy(),
            TransportIdentityProvisioningPolicy::Preferred
        );
        assert_eq!(
            preferred.provisioning_policy().custody_tier(),
            TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER
        );

        let fallback = OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback;
        assert_eq!(
            fallback.provisioning_policy(),
            TransportIdentityProvisioningPolicy::HostKeyOnly
        );
        assert_eq!(
            fallback.provisioning_policy().custody_tier(),
            TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER
        );
    }
}
