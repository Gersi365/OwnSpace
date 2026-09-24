//! Authorized local-authority bootstrap execution seam for first-time setup.
//!
//! C03e-ZA crosses the previously gated YL/live-SQLite boundary with explicit
//! owner authorization. It composes the already-validated YZ retry path with the
//! fixed YK owner-PC `SQLite` custody adapter and the existing YL atomic fresh-owner
//! bootstrap transaction.
//!
//! This module remains crate-internal. Agent startup reaches it only through validated
//! first-run authority; it remains isolated from installer, certificate, service-lifecycle,
//! and network-activation code.

use std::fmt;

use prw_control_plane::PublicIdentityMaterial;
use prw_registry::{
    durable_registry_authority::DurableRegistryAuthorityError,
    durable_registry_sqlite_custody::{
        DurableRegistrySqliteCustodyError, open_owner_pc_sqlite_authority_from_env,
    },
    durable_registry_sqlite_store::OwnerPcLocalAuthorityBootstrapOutcome,
};

use crate::{
    owner_first_setup_bootstrap_inputs::OwnerFirstSetupBootstrapInputs,
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan,
    owner_first_setup_retry_call_site_composition::{
        OwnerFirstSetupRetryCallSiteError,
        execute_owner_first_setup_retry_and_compose_bootstrap_inputs,
    },
};

/// Fail-closed error for the authorized local-authority bootstrap execution seam.
#[derive(Debug)]
pub enum OwnerFirstSetupLocalAuthorityBootstrapError {
    /// The YZ retry path could not produce exact authoritative bootstrap inputs.
    BootstrapInputs(OwnerFirstSetupRetryCallSiteError),
    /// The fixed owner-PC `SQLite` path/custody boundary could not be opened safely.
    DatabaseCustody(DurableRegistrySqliteCustodyError),
    /// The YL atomic owner-authority bootstrap transaction failed.
    AuthorityBootstrap(DurableRegistryAuthorityError),
}

impl fmt::Display for OwnerFirstSetupLocalAuthorityBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootstrapInputs(error) => {
                write!(formatter, "owner bootstrap input execution failed: {error}")
            }
            Self::DatabaseCustody(error) => {
                write!(formatter, "owner SQLite authority custody failed: {error}")
            }
            Self::AuthorityBootstrap(error) => {
                write!(
                    formatter,
                    "owner SQLite authority bootstrap failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for OwnerFirstSetupLocalAuthorityBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BootstrapInputs(error) => Some(error),
            Self::DatabaseCustody(error) => Some(error),
            Self::AuthorityBootstrap(error) => Some(error),
        }
    }
}

/// Executes the authorized first-time-setup path through the YL local `SQLite` transaction.
///
/// Ordering is fixed and fail-closed:
/// 1. YZ validates/replays owner and transport state and produces exact bootstrap inputs;
/// 2. YK opens or creates the fixed private owner-PC `SQLite` authority path;
/// 3. YL atomically initializes the owner membership and enrolled/bound owner device.
///
/// Exact replay is allowed only through YL's existing `AlreadyCurrent` outcome.
/// Partial or conflicting authority is not repaired or overwritten.
///
/// This production-capable function is invoked only through the validated first-run
/// authority chain. It is not a general startup/runtime, installer, networking, certificate,
/// or service-lifecycle entrypoint.
///
/// # Errors
///
/// Returns the exact bounded failure from YZ input execution, YK `SQLite` custody,
/// or YL authority bootstrap. No fallback provider or alternate authority path is used.
pub fn execute_owner_first_setup_retry_and_bootstrap_local_authority(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstSetupLocalAuthorityBootstrapError> {
    execute_local_authority_bootstrap_with(
        plan,
        public_device_identity,
        execute_owner_first_setup_retry_and_compose_bootstrap_inputs,
        open_owner_pc_sqlite_authority_from_env,
        |store, inputs| {
            let (binding, transport_identity) = inputs.into_parts();
            store.bootstrap_fresh_owner_authority(binding, transport_identity)
        },
    )
}

fn execute_local_authority_bootstrap_with<C, O, B, S>(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    public_device_identity: &PublicIdentityMaterial,
    compose_inputs: C,
    open_authority: O,
    bootstrap_authority: B,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstSetupLocalAuthorityBootstrapError>
where
    C: FnOnce(
        &OwnerFirstSetupCustodyPolicyPlan,
        &PublicIdentityMaterial,
    ) -> Result<OwnerFirstSetupBootstrapInputs, OwnerFirstSetupRetryCallSiteError>,
    O: FnOnce() -> Result<S, DurableRegistrySqliteCustodyError>,
    B: FnOnce(
        &mut S,
        OwnerFirstSetupBootstrapInputs,
    ) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, DurableRegistryAuthorityError>,
{
    let inputs = compose_inputs(plan, public_device_identity)
        .map_err(OwnerFirstSetupLocalAuthorityBootstrapError::BootstrapInputs)?;
    let mut authority =
        open_authority().map_err(OwnerFirstSetupLocalAuthorityBootstrapError::DatabaseCustody)?;
    bootstrap_authority(&mut authority, inputs)
        .map_err(OwnerFirstSetupLocalAuthorityBootstrapError::AuthorityBootstrap)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };
    use prw_registry::{
        durable_registry_authority::DurableRegistryAuthorityError,
        durable_registry_sqlite_store::OwnerPcLocalAuthorityBootstrapOutcome,
    };

    use super::execute_local_authority_bootstrap_with;
    use crate::{
        owner_first_setup_bootstrap_input_composition::compose_owner_first_setup_bootstrap_inputs_from_plan,
        owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record,
        owner_first_setup_custody_policy_orchestration::{
            OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
        },
        owner_first_setup_retry_call_site_composition::OwnerFirstSetupRetryCallSiteError,
    };

    fn public_identity() -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![1, 2, 3],
        )
        .expect("public identity")
    }

    #[test]
    fn successful_inputs_open_authority_once_and_forward_exact_bootstrap_tuple() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = public_identity();
        let transport = TransportIdentity::new([0x71; 32]).expect("transport");
        let open_calls = Cell::new(0_u8);
        let bootstrap_calls = Cell::new(0_u8);

        let outcome = execute_local_authority_bootstrap_with(
            &plan,
            &public_identity,
            |selected_plan, selected_public_identity| {
                Ok(compose_owner_first_setup_bootstrap_inputs_from_plan(
                    selected_plan,
                    selected_public_identity,
                    transport,
                ))
            },
            || {
                open_calls.set(open_calls.get() + 1);
                Ok(())
            },
            |_authority, inputs| {
                bootstrap_calls.set(bootstrap_calls.get() + 1);
                let (binding, selected_transport) = inputs.into_parts();
                assert_eq!(&binding.workspace_id, plan.workspace_id());
                assert_eq!(&binding.user_id, plan.user_id());
                assert_eq!(&binding.device_id, plan.device_id());
                assert_eq!(&binding.public_identity, &public_identity);
                assert_eq!(selected_transport, transport);
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized)
            },
        )
        .expect("bootstrap execution");

        assert_eq!(outcome, OwnerPcLocalAuthorityBootstrapOutcome::Initialized);
        assert_eq!(open_calls.get(), 1);
        assert_eq!(bootstrap_calls.get(), 1);
    }

    #[test]
    fn input_failure_prevents_database_open_and_bootstrap() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = public_identity();
        let open_calls = Cell::new(0_u8);
        let bootstrap_calls = Cell::new(0_u8);

        let result = execute_local_authority_bootstrap_with(
            &plan,
            &public_identity,
            |_selected_plan, _selected_public_identity| {
                Err(OwnerFirstSetupRetryCallSiteError::OwnerIdentityMismatch)
            },
            || {
                open_calls.set(open_calls.get() + 1);
                Ok(())
            },
            |_authority, _inputs| {
                bootstrap_calls.set(bootstrap_calls.get() + 1);
                Err(DurableRegistryAuthorityError::InvalidAuthority)
            },
        );

        assert!(result.is_err());
        assert_eq!(open_calls.get(), 0);
        assert_eq!(bootstrap_calls.get(), 0);
    }

    #[test]
    fn authority_failure_is_returned_without_retry_or_alternate_provider() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &record,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );
        let public_identity = public_identity();
        let transport = TransportIdentity::new([0x72; 32]).expect("transport");
        let bootstrap_calls = Cell::new(0_u8);

        let result = execute_local_authority_bootstrap_with(
            &plan,
            &public_identity,
            |selected_plan, selected_public_identity| {
                Ok(compose_owner_first_setup_bootstrap_inputs_from_plan(
                    selected_plan,
                    selected_public_identity,
                    transport,
                ))
            },
            || Ok(()),
            |_authority, _inputs| {
                bootstrap_calls.set(bootstrap_calls.get() + 1);
                Err(DurableRegistryAuthorityError::CurrentnessConflict)
            },
        );

        assert!(result.is_err());
        assert_eq!(bootstrap_calls.get(), 1);
    }
}
