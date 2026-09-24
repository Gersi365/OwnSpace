//! Dormant first-time-setup recovery for an already-established transport identity.
//!
//! C03e-YY implements only the recovery/load branch required by the YX retry
//! contract. It reloads the authoritative owner logical-identity record, proves
//! that the supplied YT plan carries the same IDs, and delegates established
//! transport credential validation/decryption to the provisioning crate's
//! dedicated recovery boundary.
//!
//! Agent startup reaches this module only through validated first-run retry of established
//! custody. It never provisions, replaces, rekeys, downgrades, or deletes transport identity state
//! and does not open `SQLite` or invoke the YL bootstrap transaction.

use std::fmt;

use prw_connectivity::TransportIdentity;
use prw_transport_identity_provisioning::{
    TransportIdentityRecoveryError, recover_existing_ubuntu_transport_identity,
};

use crate::{
    owner_first_setup_bootstrap_inputs::{
        OwnerFirstSetupBootstrapInputError, OwnerLogicalIdentityRecord,
        load_owner_logical_identity_record_from_env,
    },
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupCustodyPolicyPlan,
};

/// Fail-closed error for owner first-time-setup transport recovery.
#[derive(Debug)]
pub enum OwnerFirstSetupTransportIdentityRecoveryError {
    /// The authoritative persisted owner logical-identity record could not be loaded.
    OwnerIdentity(OwnerFirstSetupBootstrapInputError),
    /// The supplied YT plan does not carry the exact persisted owner identity tuple.
    OwnerIdentityMismatch,
    /// Established encrypted transport custody could not be validated and recovered.
    TransportIdentity(TransportIdentityRecoveryError),
}

impl fmt::Display for OwnerFirstSetupTransportIdentityRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerIdentity(error) => {
                write!(formatter, "owner logical identity recovery failed: {error}")
            }
            Self::OwnerIdentityMismatch => {
                formatter.write_str("first-time-setup plan does not match owner logical identity")
            }
            Self::TransportIdentity(error) => {
                write!(formatter, "transport identity recovery failed: {error}")
            }
        }
    }
}

impl std::error::Error for OwnerFirstSetupTransportIdentityRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OwnerIdentity(error) => Some(error),
            Self::TransportIdentity(error) => Some(error),
            Self::OwnerIdentityMismatch => None,
        }
    }
}

/// Recovers the established transport identity for the exact authoritative YT plan.
///
/// The owner logical-identity record is reloaded read-only and must exactly match
/// the plan's `WorkspaceId`, `UserId`, and `DeviceId`. The selected custody
/// policy carried by the same plan is then required to match the persisted
/// transport service binding before authenticated credential decryption occurs.
///
/// This function is reachable only through validated first-run retry of established custody.
///
/// # Errors
///
/// Fails closed if the owner record cannot be loaded, the plan identity tuple is
/// stale/conflicting, or established transport custody cannot be validated and
/// recovered under the plan's exact policy.
pub fn recover_owner_first_setup_transport_identity(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
) -> Result<TransportIdentity, OwnerFirstSetupTransportIdentityRecoveryError> {
    let record = load_owner_logical_identity_record_from_env()
        .map_err(OwnerFirstSetupTransportIdentityRecoveryError::OwnerIdentity)?;
    validate_plan_owner_identity(plan, &record)?;

    recover_existing_ubuntu_transport_identity(plan.transport_provisioning_policy())
        .map_err(OwnerFirstSetupTransportIdentityRecoveryError::TransportIdentity)
}

fn validate_plan_owner_identity(
    plan: &OwnerFirstSetupCustodyPolicyPlan,
    record: &OwnerLogicalIdentityRecord,
) -> Result<(), OwnerFirstSetupTransportIdentityRecoveryError> {
    if plan.workspace_id() != record.workspace_id()
        || plan.user_id() != record.user_id()
        || plan.device_id() != record.device_id()
    {
        return Err(OwnerFirstSetupTransportIdentityRecoveryError::OwnerIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_plan_owner_identity;
    use crate::{
        owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record,
        owner_first_setup_custody_policy_orchestration::{
            OwnerFirstSetupTransportCustodySelection, compose_owner_first_setup_custody_policy_plan,
        },
    };

    #[test]
    fn exact_owner_record_matches_each_explicit_custody_plan() {
        let record = generate_owner_logical_identity_record().expect("generate disposable record");

        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            let plan = compose_owner_first_setup_custody_policy_plan(&record, selection);
            validate_plan_owner_identity(&plan, &record).expect("exact owner identity must match");
        }
    }

    #[test]
    fn different_owner_record_is_rejected() {
        let first = generate_owner_logical_identity_record().expect("generate first record");
        let second = generate_owner_logical_identity_record().expect("generate second record");
        let plan = compose_owner_first_setup_custody_policy_plan(
            &first,
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
        );

        assert!(validate_plan_owner_identity(&plan, &second).is_err());
    }
}
