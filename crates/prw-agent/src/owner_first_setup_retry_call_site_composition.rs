//! Dormant first-time-setup retry call-site composition.
//!
//! C03e-YZ composes the already-validated creation and recovery branches without
//! invoking the YL fresh-owner `SQLite` bootstrap transaction. It first proves
//! that the YT plan still matches the persisted owner logical identity, classifies
//! the fixed transport-custody artifact pair, and dispatches exactly one branch.
//!
//! This module is crate-internal. Agent startup reaches it only through validated
//! first-run authority; installer, service and unrelated runtime code do not call it.

use std::fmt;

use prw_connectivity::TransportIdentity;
use prw_control_plane::PublicIdentityMaterial;
use prw_transport_identity_provisioning::{
    TransportIdentityPersistentState, TransportIdentityProvisioningError,
    TransportIdentityRecoveryError, inspect_ubuntu_transport_identity_persistent_state,
};

use crate::{
    owner_first_setup_bootstrap_input_composition::compose_owner_first_setup_bootstrap_inputs_from_plan,
    owner_first_setup_bootstrap_inputs::{
        OwnerFirstSetupBootstrapInputError, OwnerFirstSetupBootstrapInputs,
        OwnerLogicalIdentityRecord, load_owner_logical_identity_record_from_env,
    },
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan,
    owner_first_setup_execution_composition::execute_owner_first_setup_transport_provisioning_and_compose_bootstrap_inputs,
    owner_first_setup_transport_identity_recovery::{
        OwnerFirstSetupTransportIdentityRecoveryError, recover_owner_first_setup_transport_identity,
    },
};

/// Fail-closed error for first-time-setup retry dispatch.
#[derive(Debug)]
pub enum OwnerFirstSetupRetryCallSiteError {
    /// The authoritative persisted owner logical-identity record could not be loaded.
    OwnerIdentity(OwnerFirstSetupBootstrapInputError),
    /// The supplied YT plan does not carry the exact persisted owner identity tuple.
    OwnerIdentityMismatch,
    /// The fixed transport-custody artifact pair could not be safely classified.
    StateInspection(TransportIdentityRecoveryError),
    /// The selected absent-state creation branch failed.
    Provisioning(TransportIdentityProvisioningError),
    /// The selected established-state recovery branch failed.
    Recovery(OwnerFirstSetupTransportIdentityRecoveryError),
}

impl fmt::Display for OwnerFirstSetupRetryCallSiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerIdentity(error) => {
                write!(
                    formatter,
                    "owner logical identity retry validation failed: {error}"
                )
            }
            Self::OwnerIdentityMismatch => {
                formatter.write_str("first-time-setup retry plan does not match owner identity")
            }
            Self::StateInspection(error) => {
                write!(
                    formatter,
                    "transport custody retry-state inspection failed: {error}"
                )
            }
            Self::Provisioning(error) => {
                write!(
                    formatter,
                    "first-time transport provisioning failed: {error}"
                )
            }
            Self::Recovery(error) => {
                write!(formatter, "established transport recovery failed: {error}")
            }
        }
    }
}

impl std::error::Error for OwnerFirstSetupRetryCallSiteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OwnerIdentity(error) => Some(error),
            Self::StateInspection(error) => Some(error),
            Self::Provisioning(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::OwnerIdentityMismatch => None,
        }
    }
}

/// Selects exactly one validated first-time-setup transport branch and composes YV inputs.
///
/// This production-capable seam is reached only through validated first-run startup
/// authority. It has no installer or unrelated runtime caller and does not itself invoke YL.
///
/// Ordering is fail-closed:
/// 1. reload and match the authoritative owner logical identity;
/// 2. classify the fixed transport-custody artifact pair under the exact YT policy;
/// 3. if absent, call the existing YW creation/composition path exactly once;
/// 4. if established, call the YY recovery path and compose through YV.
///
/// Partial or policy-conflicting custody state fails before either branch.
///
/// # Errors
///
/// Returns a bounded error when owner identity, state inspection, the selected
/// creation path, or the selected recovery path fails.
pub fn execute_owner_first_setup_retry_and_compose_bootstrap_inputs(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerFirstSetupBootstrapInputs, OwnerFirstSetupRetryCallSiteError> {
    let record = load_owner_logical_identity_record_from_env()
        .map_err(OwnerFirstSetupRetryCallSiteError::OwnerIdentity)?;
    validate_plan_owner_identity(plan, &record)?;

    let state =
        inspect_ubuntu_transport_identity_persistent_state(plan.transport_provisioning_policy())
            .map_err(OwnerFirstSetupRetryCallSiteError::StateInspection)?;

    execute_retry_branch_with(
        state,
        plan,
        public_device_identity,
        execute_owner_first_setup_transport_provisioning_and_compose_bootstrap_inputs,
        recover_owner_first_setup_transport_identity,
    )
}

fn validate_plan_owner_identity(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    record: &OwnerLogicalIdentityRecord,
) -> Result<(), OwnerFirstSetupRetryCallSiteError> {
    if plan.workspace_id() != record.workspace_id()
        || plan.user_id() != record.user_id()
        || plan.device_id() != record.device_id()
    {
        return Err(OwnerFirstSetupRetryCallSiteError::OwnerIdentityMismatch);
    }
    Ok(())
}

fn execute_retry_branch_with<C, R>(
    state: TransportIdentityPersistentState,
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
    create: C,
    recover: R,
) -> Result<OwnerFirstSetupBootstrapInputs, OwnerFirstSetupRetryCallSiteError>
where
    C: FnOnce(
        &OwnerFirstSetupCustodyPolicyPlan,
        &PublicIdentityMaterial,
    ) -> Result<OwnerFirstSetupBootstrapInputs, TransportIdentityProvisioningError>,
    R: FnOnce(
        &OwnerFirstSetupCustodyPolicyPlan,
    ) -> Result<TransportIdentity, OwnerFirstSetupTransportIdentityRecoveryError>,
{
    match state {
        TransportIdentityPersistentState::Absent => create(plan, public_device_identity)
            .map_err(OwnerFirstSetupRetryCallSiteError::Provisioning),
        TransportIdentityPersistentState::Established => {
            let transport_identity =
                recover(plan).map_err(OwnerFirstSetupRetryCallSiteError::Recovery)?;
            Ok(compose_owner_first_setup_bootstrap_inputs_from_plan(
                plan,
                public_device_identity,
                transport_identity,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };
    use prw_transport_identity_provisioning::{
        TransportIdentityPersistentState, TransportIdentityProvisioningError,
    };

    use super::{execute_retry_branch_with, validate_plan_owner_identity};
    use crate::{
        owner_first_setup_bootstrap_input_composition::compose_owner_first_setup_bootstrap_inputs_from_plan,
        owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record,
        owner_first_setup_custody_policy_orchestration::{
            OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
        },
        owner_first_setup_transport_identity_recovery::OwnerFirstSetupTransportIdentityRecoveryError,
    };

    fn disposable_public_identity() -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![1, 2, 3],
        )
        .expect("public identity")
    }

    #[test]
    fn retry_dispatches_absent_state_only_to_creation() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = disposable_public_identity();
        let transport = TransportIdentity::new([0x61; 32]).expect("transport identity");
        let creation_calls = Cell::new(0_u8);
        let recovery_calls = Cell::new(0_u8);

        let inputs = execute_retry_branch_with(
            TransportIdentityPersistentState::Absent,
            &plan,
            &public_identity,
            |selected_plan, selected_public_identity| {
                creation_calls.set(creation_calls.get() + 1);
                Ok(compose_owner_first_setup_bootstrap_inputs_from_plan(
                    selected_plan,
                    selected_public_identity,
                    transport,
                ))
            },
            |_selected_plan| {
                recovery_calls.set(recovery_calls.get() + 1);
                Err(OwnerFirstSetupTransportIdentityRecoveryError::OwnerIdentityMismatch)
            },
        )
        .expect("absent state uses creation branch");

        assert_eq!(creation_calls.get(), 1);
        assert_eq!(recovery_calls.get(), 0);
        assert_eq!(inputs.transport_identity(), transport);
    }

    #[test]
    fn retry_dispatches_established_state_only_to_recovery() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = disposable_public_identity();
        let transport = TransportIdentity::new([0x62; 32]).expect("transport identity");
        let creation_calls = Cell::new(0_u8);
        let recovery_calls = Cell::new(0_u8);

        let inputs = execute_retry_branch_with(
            TransportIdentityPersistentState::Established,
            &plan,
            &public_identity,
            |_selected_plan, _selected_public_identity| {
                creation_calls.set(creation_calls.get() + 1);
                Err(TransportIdentityProvisioningError::AlreadyProvisioned)
            },
            |_selected_plan| {
                recovery_calls.set(recovery_calls.get() + 1);
                Ok(transport)
            },
        )
        .expect("established state uses recovery branch");

        assert_eq!(creation_calls.get(), 0);
        assert_eq!(recovery_calls.get(), 1);
        assert_eq!(inputs.transport_identity(), transport);
    }

    #[test]
    fn retry_plan_must_match_persisted_owner_identity() {
        let first = generate_owner_logical_identity_record().expect("first owner record");
        let second = generate_owner_logical_identity_record().expect("second owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &first,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );

        assert!(validate_plan_owner_identity(&plan, &first).is_ok());
        assert!(validate_plan_owner_identity(&plan, &second).is_err());
    }
}
