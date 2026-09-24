//! Dormant first-time-setup bootstrap-input composition seam.
//!
//! C03e-YV composes the already-authoritative logical owner identity carried by the
//! YT plan, one explicitly supplied public device identity, and one supplied
//! `TransportIdentity` into the existing YL `OwnerFirstSetupBootstrapInputs` carrier.
//! This module performs no custody load, transport provisioning, `SQLite` access,
//! bootstrap transaction invocation, startup wiring, or runtime activation.

use prw_connectivity::TransportIdentity;
use prw_control_plane::PublicIdentityMaterial;

use crate::{
    owner_first_setup_bootstrap_inputs::{
        OwnerFirstSetupBootstrapInputs,
        compose_owner_first_setup_bootstrap_inputs_from_identity_parts,
    },
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan,
};

/// Purely composes the final fresh-owner YL bootstrap input from already-authoritative values.
///
/// The caller must supply the public device identity from an already-authorized
/// custody boundary and the `TransportIdentity` associated with the already-selected
/// transport key. This function does not load either value itself.
///
/// # Safety boundary
///
/// This function does not invoke transport provisioning or the YL `SQLite` bootstrap
/// transaction and does not persist or mutate any authority state.
#[must_use]
pub fn compose_owner_first_setup_bootstrap_inputs_from_plan(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
    transport_identity: TransportIdentity,
) -> OwnerFirstSetupBootstrapInputs {
    compose_owner_first_setup_bootstrap_inputs_from_identity_parts(
        plan.workspace_id(),
        plan.user_id(),
        plan.device_id(),
        public_device_identity,
        transport_identity,
    )
}

#[cfg(test)]
mod tests {
    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };

    use super::compose_owner_first_setup_bootstrap_inputs_from_plan;
    use crate::{
        owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record,
        owner_first_setup_custody_policy_orchestration::{
            OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
        },
    };

    #[test]
    fn composition_preserves_plan_identity_public_identity_and_transport_identity() {
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
        let transport_identity = TransportIdentity::new([0x59; 32]).expect("transport identity");

        let inputs = compose_owner_first_setup_bootstrap_inputs_from_plan(
            &plan,
            &public_identity,
            transport_identity,
        );

        assert_eq!(&inputs.binding().workspace_id, plan.workspace_id());
        assert_eq!(&inputs.binding().user_id, plan.user_id());
        assert_eq!(&inputs.binding().device_id, plan.device_id());
        assert_eq!(&inputs.binding().public_identity, &public_identity);
        assert!(inputs.binding().lifecycle.can_participate());
        assert_eq!(inputs.transport_identity(), transport_identity);
    }
}
