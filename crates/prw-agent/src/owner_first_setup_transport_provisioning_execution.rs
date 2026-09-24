//! Dormant first-time-setup transport provisioning execution seam.
//!
//! C03e-YU is source-only execution wiring. It consumes the explicit policy already
//! carried by the YT first-time-setup plan and dispatches to exactly one existing
//! transport provisioning entrypoint. Validated first-run startup authority may reach it,
//! but validation itself must never invoke the production provisioning function.

use prw_transport_identity_provisioning::{
    ProvisionedTransportIdentity, TransportIdentityProvisioningError,
    TransportIdentityProvisioningPolicy, provision_first_ubuntu_transport_identity_host_key_only,
    provision_first_ubuntu_transport_identity_preferred,
};

use crate::owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan;

/// Executes exactly one transport-identity provisioner selected by the YT setup plan.
///
/// There is no automatic fallback. A preferred provisioning failure is returned
/// directly and is never retried as host-key-only. Likewise, an explicit
/// host-key-only selection never attempts the preferred entrypoint first.
///
/// This function is reachable only through validated first-run authority when transport
/// custody is absent. Validation and unrelated runtime/CI paths must not invoke it.
///
/// # Errors
///
/// Returns the selected provisioning entrypoint's bounded
/// [`TransportIdentityProvisioningError`] unchanged.
pub fn execute_owner_first_setup_transport_identity_provisioning(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
) -> Result<ProvisionedTransportIdentity, TransportIdentityProvisioningError> {
    match plan.transport_provisioning_policy() {
        TransportIdentityProvisioningPolicy::Preferred => {
            provision_first_ubuntu_transport_identity_preferred()
        }
        TransportIdentityProvisioningPolicy::HostKeyOnly => {
            provision_first_ubuntu_transport_identity_host_key_only()
        }
    }
}
