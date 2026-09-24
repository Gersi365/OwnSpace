//! Dormant first-time-setup execution composition seam.
//!
//! C03e-YW composes the already-validated YU transport-provisioning dispatcher
//! with the YV bootstrap-input composer. The production entrypoint remains
//! crate-internal and is reachable only through validated first-run startup authority.
//!
//! If a future explicitly authorized caller invokes this seam, exactly one
//! transport provisioner selected by the YT plan runs first. Only a successful
//! provisioned `TransportIdentity` is then passed into YV composition. This
//! module does not invoke the YL `SQLite` bootstrap transaction.

use prw_connectivity::TransportIdentity;
use prw_control_plane::PublicIdentityMaterial;
use prw_transport_identity_provisioning::TransportIdentityProvisioningError;

use crate::{
    owner_first_setup_bootstrap_input_composition::compose_owner_first_setup_bootstrap_inputs_from_plan,
    owner_first_setup_bootstrap_inputs::OwnerFirstSetupBootstrapInputs,
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan,
    owner_first_setup_transport_provisioning_execution::execute_owner_first_setup_transport_identity_provisioning,
};

/// Executes the YT-selected YU provisioner once and composes the resulting YV input.
///
/// The caller must already hold the authoritative YT plan and public device
/// identity. This function does not create or load those values.
///
/// A provisioning error is returned unchanged and composition does not run.
/// There is no automatic fallback, retry, alternate custody selection, or
/// existing-credential adoption in this seam.
///
/// # Errors
///
/// Returns the exact bounded `TransportIdentityProvisioningError` emitted by
/// the single YU provisioning attempt.
pub fn execute_owner_first_setup_transport_provisioning_and_compose_bootstrap_inputs(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerFirstSetupBootstrapInputs, TransportIdentityProvisioningError> {
    execute_and_compose_with_transport_identity(plan, public_device_identity, |selected_plan| {
        execute_owner_first_setup_transport_identity_provisioning(selected_plan)
            .map(|provisioned| *provisioned.transport_identity())
    })
}

fn execute_and_compose_with_transport_identity<F>(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
    provision_transport_identity: F,
) -> Result<OwnerFirstSetupBootstrapInputs, TransportIdentityProvisioningError>
where
    F: FnOnce(
        &OwnerFirstSetupCustodyPolicyPlan,
    ) -> Result<TransportIdentity, TransportIdentityProvisioningError>,
{
    let transport_identity = provision_transport_identity(plan)?;
    Ok(compose_owner_first_setup_bootstrap_inputs_from_plan(
        plan,
        public_device_identity,
        transport_identity,
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };

    use super::execute_and_compose_with_transport_identity;
    use crate::{
        owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record,
        owner_first_setup_custody_policy_orchestration::{
            OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
        },
    };

    #[test]
    fn validation_composes_one_disposable_transport_result_without_production_provisioning() {
        let record = generate_owner_logical_identity_record().expect("generate disposable record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![1, 2, 3],
        )
        .expect("public identity");
        let disposable_transport =
            TransportIdentity::new([0x5a; 32]).expect("disposable transport identity");
        let calls = Cell::new(0_u8);

        let inputs =
            execute_and_compose_with_transport_identity(&plan, &public_identity, |selected_plan| {
                calls.set(calls.get() + 1);
                assert_eq!(
                    selected_plan.transport_selection(),
                    OwnerFirstSetupTransportCustodySelection::PreferredDefault
                );
                Ok(disposable_transport)
            })
            .expect("compose disposable validation input");

        assert_eq!(calls.get(), 1);
        assert_eq!(&inputs.binding().workspace_id, plan.workspace_id());
        assert_eq!(&inputs.binding().user_id, plan.user_id());
        assert_eq!(&inputs.binding().device_id, plan.device_id());
        assert_eq!(&inputs.binding().public_identity, &public_identity);
        assert_eq!(inputs.transport_identity(), disposable_transport);
    }
}
