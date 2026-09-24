//! First-run authority orchestration for the owner PC.
//!
//! C03e-ZC materialized the ZB-authorized orchestration from an already-typed
//! transport-custody selection. C03e-ZL added reader composition and C03e-ZM added
//! post-success retirement. The current startup-state dispatcher activates that
//! validated chain only for a valid present setup-intent record.
//!
//! The module remains crate-internal and has no caller in `main.rs`,
//! `linux_bootstrap`, systemd, installer, certificate, or network activation code.

use std::fmt;

use prw_control_plane::PublicIdentityMaterial;
use prw_registry::durable_registry_sqlite_store::OwnerPcLocalAuthorityBootstrapOutcome;

use crate::{
    owner_first_run_setup_intent::{
        OwnerFirstRunSetupIntentError, OwnerFirstRunSetupIntentRetirementOutcome,
        load_owner_first_run_transport_custody_selection_from_env,
        retire_owner_first_run_transport_custody_intent_after_local_authority_success_from_env,
    },
    owner_first_setup_bootstrap_inputs::{
        OwnerFirstSetupBootstrapInputError, OwnerLogicalIdentityRecordOutcome,
        ensure_owner_logical_identity_record_from_env,
    },
    owner_first_setup_custody_policy_orchestration::{
        OwnerFirstSetupCustodyPolicyPlan, OwnerFirstSetupTransportCustodySelection,
        compose_owner_first_setup_custody_policy_plan,
    },
    owner_first_setup_local_authority_bootstrap_execution::{
        OwnerFirstSetupLocalAuthorityBootstrapError,
        execute_owner_first_setup_retry_and_bootstrap_local_authority,
    },
};

/// Fail-closed error for the first-run orchestration seam.
#[derive(Debug)]
pub enum OwnerFirstRunOrchestrationError {
    /// The fixed first-run setup-intent record could not be loaded fail-closed.
    SetupIntent(OwnerFirstRunSetupIntentError),
    /// The post-success fixed setup-intent retirement transaction failed.
    SetupIntentRetirement(OwnerFirstRunSetupIntentError),
    /// The authoritative owner logical-identity record could not be ensured or replayed.
    OwnerIdentity(OwnerFirstSetupBootstrapInputError),
    /// The validated ZA local-authority bootstrap seam failed.
    LocalAuthority(OwnerFirstSetupLocalAuthorityBootstrapError),
}

impl fmt::Display for OwnerFirstRunOrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupIntent(error) => {
                write!(
                    formatter,
                    "owner first-run setup-intent load failed: {error}"
                )
            }
            Self::SetupIntentRetirement(error) => {
                write!(
                    formatter,
                    "owner first-run setup-intent retirement failed: {error}"
                )
            }
            Self::OwnerIdentity(error) => {
                write!(
                    formatter,
                    "owner logical identity orchestration failed: {error}"
                )
            }
            Self::LocalAuthority(error) => {
                write!(
                    formatter,
                    "owner local authority orchestration failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for OwnerFirstRunOrchestrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SetupIntent(error) | Self::SetupIntentRetirement(error) => Some(error),
            Self::OwnerIdentity(error) => Some(error),
            Self::LocalAuthority(error) => Some(error),
        }
    }
}

/// Result of first-run authority success followed by the bounded setup-intent retirement transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFirstRunOrchestrationAndRetirementOutcome {
    local_authority_outcome: OwnerPcLocalAuthorityBootstrapOutcome,
    setup_intent_retirement_outcome: OwnerFirstRunSetupIntentRetirementOutcome,
}

impl OwnerFirstRunOrchestrationAndRetirementOutcome {
    /// Returns the exact successful local-authority bootstrap outcome produced by ZC.
    #[must_use]
    pub const fn local_authority_outcome(self) -> OwnerPcLocalAuthorityBootstrapOutcome {
        self.local_authority_outcome
    }

    /// Returns the exact post-success setup-intent retirement outcome.
    #[must_use]
    pub const fn setup_intent_retirement_outcome(
        self,
    ) -> OwnerFirstRunSetupIntentRetirementOutcome {
        self.setup_intent_retirement_outcome
    }
}

/// Executes first-run authority composition from the fixed setup-intent reader.
///
/// This C03e-ZL wrapper performs exactly one fail-closed setup-intent read and
/// forwards the resulting typed selection unchanged into the existing C03e-ZC
/// orchestration seam.
///
/// It does not retire the setup-intent record and remains unreferenced by Agent
/// startup, installer, Desktop, systemd, services, certificate, or networking code.
///
/// # Errors
///
/// Returns a setup-intent read failure before ZC invocation, or the exact existing
/// ZC orchestration error after a successful typed read.
pub fn execute_dormant_owner_first_run_orchestration_from_setup_intent(
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError> {
    execute_first_run_orchestration_from_setup_intent_with(
        public_device_identity,
        load_owner_first_run_transport_custody_selection_from_env,
        execute_dormant_owner_first_run_orchestration,
    )
}

/// Executes reader-to-first-run orchestration and retires setup intent only after authority success.
///
/// The exact typed selection read from the fixed setup-intent record is preserved
/// through both ZC and the retirement seam. Retirement is invoked only after ZC
/// returns one of the two successful local-authority outcomes.
///
/// The startup-state dispatcher invokes this function only for validated present setup intent.
///
/// # Errors
///
/// Returns a fail-closed setup-intent read error before ZC, an existing ZC error,
/// or a distinct post-success setup-intent retirement error.
pub fn execute_dormant_owner_first_run_orchestration_and_retire_setup_intent_after_success(
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerFirstRunOrchestrationAndRetirementOutcome, OwnerFirstRunOrchestrationError> {
    execute_first_run_orchestration_and_retire_setup_intent_with(
        public_device_identity,
        load_owner_first_run_transport_custody_selection_from_env,
        execute_dormant_owner_first_run_orchestration,
        retire_owner_first_run_transport_custody_intent_after_local_authority_success_from_env,
    )
}

/// Executes the first-run composition selected by the validated custody choice.
///
/// The caller must provide one explicit typed custody selection plus the public
/// identity already derived from the previously loaded device-identity signer.
///
/// Ordering is fixed:
/// 1. ensure/reuse the owner logical-identity record through the existing atomic seam;
/// 2. compose the YT plan from that exact record plus the exact caller selection;
/// 3. invoke ZA with that plan plus the already-derived public device identity.
///
/// The function performs no selection inference or fallback. In particular,
/// `ExplicitHostKeyOnlyFallback` is reachable only when the caller supplies it
/// explicitly.
///
/// The startup-state dispatcher reaches this production seam only through the validated
/// first-run path. It remains isolated from `linux_bootstrap`, installer, certificate,
/// service-lifecycle, and network-activation code.
///
/// # Errors
///
/// Returns the exact owner-identity or ZA failure. No retry, replacement,
/// alternate provider, or custody-policy conversion is attempted here.
pub fn execute_dormant_owner_first_run_orchestration(
    transport_selection: OwnerFirstSetupTransportCustodySelection,
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError> {
    execute_first_run_orchestration_with(
        transport_selection,
        public_device_identity,
        ensure_owner_logical_identity_record_from_env,
        execute_owner_first_setup_retry_and_bootstrap_local_authority,
    )
}

fn execute_first_run_orchestration_and_retire_setup_intent_with<R, O, T>(
    public_device_identity: &PublicIdentityMaterial,
    read_setup_intent: R,
    execute_orchestration: O,
    retire_setup_intent: T,
) -> Result<OwnerFirstRunOrchestrationAndRetirementOutcome, OwnerFirstRunOrchestrationError>
where
    R: FnOnce() -> Result<OwnerFirstSetupTransportCustodySelection, OwnerFirstRunSetupIntentError>,
    O: FnOnce(
        OwnerFirstSetupTransportCustodySelection,
        &PublicIdentityMaterial,
    )
        -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError>,
    T: FnOnce(
        OwnerFirstSetupTransportCustodySelection,
        OwnerPcLocalAuthorityBootstrapOutcome,
    )
        -> Result<OwnerFirstRunSetupIntentRetirementOutcome, OwnerFirstRunSetupIntentError>,
{
    let selection = read_setup_intent().map_err(OwnerFirstRunOrchestrationError::SetupIntent)?;
    let local_authority_outcome = execute_orchestration(selection, public_device_identity)?;
    let setup_intent_retirement_outcome =
        retire_setup_intent(selection, local_authority_outcome)
            .map_err(OwnerFirstRunOrchestrationError::SetupIntentRetirement)?;

    Ok(OwnerFirstRunOrchestrationAndRetirementOutcome {
        local_authority_outcome,
        setup_intent_retirement_outcome,
    })
}

fn execute_first_run_orchestration_from_setup_intent_with<R, O>(
    public_device_identity: &PublicIdentityMaterial,
    read_setup_intent: R,
    execute_orchestration: O,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError>
where
    R: FnOnce() -> Result<OwnerFirstSetupTransportCustodySelection, OwnerFirstRunSetupIntentError>,
    O: FnOnce(
        OwnerFirstSetupTransportCustodySelection,
        &PublicIdentityMaterial,
    )
        -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError>,
{
    let selection = read_setup_intent().map_err(OwnerFirstRunOrchestrationError::SetupIntent)?;
    execute_orchestration(selection, public_device_identity)
}

fn execute_first_run_orchestration_with<E, A>(
    transport_selection: OwnerFirstSetupTransportCustodySelection,
    public_device_identity: &PublicIdentityMaterial,
    ensure_owner_identity: E,
    execute_local_authority: A,
) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, OwnerFirstRunOrchestrationError>
where
    E: FnOnce() -> Result<OwnerLogicalIdentityRecordOutcome, OwnerFirstSetupBootstrapInputError>,
    A: FnOnce(
        &OwnerFirstSetupCustodyPolicyPlan,
        &PublicIdentityMaterial,
    ) -> Result<
        OwnerPcLocalAuthorityBootstrapOutcome,
        OwnerFirstSetupLocalAuthorityBootstrapError,
    >,
{
    let owner_identity =
        ensure_owner_identity().map_err(OwnerFirstRunOrchestrationError::OwnerIdentity)?;
    let plan =
        compose_owner_first_setup_custody_policy_plan(owner_identity.record(), transport_selection);
    execute_local_authority(&plan, public_device_identity)
        .map_err(OwnerFirstRunOrchestrationError::LocalAuthority)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };
    use prw_registry::{
        durable_registry_authority::DurableRegistryAuthorityError,
        durable_registry_sqlite_store::OwnerPcLocalAuthorityBootstrapOutcome,
    };

    use super::{
        OwnerFirstRunOrchestrationAndRetirementOutcome, OwnerFirstRunOrchestrationError,
        execute_first_run_orchestration_and_retire_setup_intent_with,
        execute_first_run_orchestration_from_setup_intent_with,
        execute_first_run_orchestration_with,
    };
    use crate::{
        owner_first_run_setup_intent::{
            OwnerFirstRunSetupIntentError, OwnerFirstRunSetupIntentRetirementOutcome,
        },
        owner_first_setup_bootstrap_inputs::{
            OwnerFirstSetupBootstrapInputError, OwnerLogicalIdentityRecordOutcome,
            generate_owner_logical_identity_record,
        },
        owner_first_setup_custody_policy_orchestration::OwnerFirstSetupTransportCustodySelection,
        owner_first_setup_local_authority_bootstrap_execution::OwnerFirstSetupLocalAuthorityBootstrapError,
    };

    fn public_identity() -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![7, 8, 9],
        )
        .expect("public identity")
    }

    #[test]
    fn post_success_retirement_receives_exact_selection_and_exact_zc_outcome() {
        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            for local_authority_outcome in [
                OwnerPcLocalAuthorityBootstrapOutcome::Initialized,
                OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent,
            ] {
                let public_identity = public_identity();
                let read_calls = Cell::new(0_u8);
                let orchestration_calls = Cell::new(0_u8);
                let retirement_calls = Cell::new(0_u8);

                let outcome = execute_first_run_orchestration_and_retire_setup_intent_with(
                    &public_identity,
                    || {
                        read_calls.set(read_calls.get() + 1);
                        Ok(selection)
                    },
                    |selected, selected_public_identity| {
                        orchestration_calls.set(orchestration_calls.get() + 1);
                        assert_eq!(selected, selection);
                        assert_eq!(selected_public_identity, &public_identity);
                        Ok(local_authority_outcome)
                    },
                    |selected, completed_outcome| {
                        retirement_calls.set(retirement_calls.get() + 1);
                        assert_eq!(selected, selection);
                        assert_eq!(completed_outcome, local_authority_outcome);
                        Ok(OwnerFirstRunSetupIntentRetirementOutcome::Retired(selected))
                    },
                )
                .expect("post-success retirement composition");

                assert_eq!(
                    outcome,
                    OwnerFirstRunOrchestrationAndRetirementOutcome {
                        local_authority_outcome,
                        setup_intent_retirement_outcome:
                            OwnerFirstRunSetupIntentRetirementOutcome::Retired(selection),
                    }
                );
                assert_eq!(read_calls.get(), 1);
                assert_eq!(orchestration_calls.get(), 1);
                assert_eq!(retirement_calls.get(), 1);
            }
        }
    }

    #[test]
    fn reader_failure_prevents_zc_and_retirement() {
        let public_identity = public_identity();
        let orchestration_calls = Cell::new(0_u8);
        let retirement_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_and_retire_setup_intent_with(
            &public_identity,
            || Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord),
            |_selection, _public_identity| {
                orchestration_calls.set(orchestration_calls.get() + 1);
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized)
            },
            |_selection, _outcome| {
                retirement_calls.set(retirement_calls.get() + 1);
                Ok(OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired)
            },
        );

        assert!(matches!(
            result,
            Err(OwnerFirstRunOrchestrationError::SetupIntent(
                OwnerFirstRunSetupIntentError::MalformedIntentRecord
            ))
        ));
        assert_eq!(orchestration_calls.get(), 0);
        assert_eq!(retirement_calls.get(), 0);
    }

    #[test]
    fn zc_failure_prevents_retirement() {
        let public_identity = public_identity();
        let retirement_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_and_retire_setup_intent_with(
            &public_identity,
            || Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault),
            |_selection, _public_identity| {
                Err(OwnerFirstRunOrchestrationError::OwnerIdentity(
                    OwnerFirstSetupBootstrapInputError::InsecureStateRoot,
                ))
            },
            |_selection, _outcome| {
                retirement_calls.set(retirement_calls.get() + 1);
                Ok(OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired)
            },
        );

        assert!(matches!(
            result,
            Err(OwnerFirstRunOrchestrationError::OwnerIdentity(
                OwnerFirstSetupBootstrapInputError::InsecureStateRoot
            ))
        ));
        assert_eq!(retirement_calls.get(), 0);
    }

    #[test]
    fn retirement_failure_is_distinct_and_occurs_only_after_zc_success() {
        let public_identity = public_identity();
        let selection = OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback;
        let local_authority_outcome = OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent;
        let retirement_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_and_retire_setup_intent_with(
            &public_identity,
            || Ok(selection),
            |selected, _public_identity| {
                assert_eq!(selected, selection);
                Ok(local_authority_outcome)
            },
            |selected, completed_outcome| {
                retirement_calls.set(retirement_calls.get() + 1);
                assert_eq!(selected, selection);
                assert_eq!(completed_outcome, local_authority_outcome);
                Err(OwnerFirstRunSetupIntentError::DirectorySyncFailed)
            },
        );

        assert!(matches!(
            result,
            Err(OwnerFirstRunOrchestrationError::SetupIntentRetirement(
                OwnerFirstRunSetupIntentError::DirectorySyncFailed
            ))
        ));
        assert_eq!(retirement_calls.get(), 1);
    }

    #[test]
    fn already_retired_is_preserved_after_successful_zc() {
        let public_identity = public_identity();

        let outcome = execute_first_run_orchestration_and_retire_setup_intent_with(
            &public_identity,
            || Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault),
            |_selection, _public_identity| Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized),
            |_selection, _outcome| Ok(OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired),
        )
        .expect("already-retired completion");

        assert_eq!(
            outcome.setup_intent_retirement_outcome(),
            OwnerFirstRunSetupIntentRetirementOutcome::AlreadyRetired
        );
        assert_eq!(
            outcome.local_authority_outcome(),
            OwnerPcLocalAuthorityBootstrapOutcome::Initialized
        );
    }

    #[test]
    fn setup_intent_reader_forwards_exact_typed_selection_once() {
        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            let public_identity = public_identity();
            let read_calls = Cell::new(0_u8);
            let orchestration_calls = Cell::new(0_u8);

            let outcome = execute_first_run_orchestration_from_setup_intent_with(
                &public_identity,
                || {
                    read_calls.set(read_calls.get() + 1);
                    Ok(selection)
                },
                |selected, selected_public_identity| {
                    orchestration_calls.set(orchestration_calls.get() + 1);
                    assert_eq!(selected, selection);
                    assert_eq!(selected_public_identity, &public_identity);
                    Ok(OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent)
                },
            )
            .expect("reader-to-ZC composition");

            assert_eq!(
                outcome,
                OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent
            );
            assert_eq!(read_calls.get(), 1);
            assert_eq!(orchestration_calls.get(), 1);
        }
    }

    #[test]
    fn setup_intent_reader_failure_prevents_zc_invocation() {
        let public_identity = public_identity();
        let orchestration_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_from_setup_intent_with(
            &public_identity,
            || Err(OwnerFirstRunSetupIntentError::MalformedIntentRecord),
            |_selection, _public_identity| {
                orchestration_calls.set(orchestration_calls.get() + 1);
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized)
            },
        );

        assert!(matches!(
            result,
            Err(OwnerFirstRunOrchestrationError::SetupIntent(
                OwnerFirstRunSetupIntentError::MalformedIntentRecord
            ))
        ));
        assert_eq!(orchestration_calls.get(), 0);
    }

    #[test]
    fn zc_error_is_returned_after_successful_setup_intent_read() {
        let public_identity = public_identity();
        let orchestration_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_from_setup_intent_with(
            &public_identity,
            || Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault),
            |_selection, _public_identity| {
                orchestration_calls.set(orchestration_calls.get() + 1);
                Err(OwnerFirstRunOrchestrationError::OwnerIdentity(
                    OwnerFirstSetupBootstrapInputError::InsecureStateRoot,
                ))
            },
        );

        assert!(matches!(
            result,
            Err(OwnerFirstRunOrchestrationError::OwnerIdentity(
                OwnerFirstSetupBootstrapInputError::InsecureStateRoot
            ))
        ));
        assert_eq!(orchestration_calls.get(), 1);
    }

    #[test]
    fn exact_owner_record_and_explicit_selection_are_forwarded_once() {
        for selection in [
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
        ] {
            let record = generate_owner_logical_identity_record().expect("owner record");
            let expected_workspace = record.workspace_id().clone();
            let expected_user = record.user_id().clone();
            let expected_device = record.device_id().clone();
            let public_identity = public_identity();
            let ensure_calls = Cell::new(0_u8);
            let authority_calls = Cell::new(0_u8);

            let outcome = execute_first_run_orchestration_with(
                selection,
                &public_identity,
                || {
                    ensure_calls.set(ensure_calls.get() + 1);
                    Ok(OwnerLogicalIdentityRecordOutcome::Existing(record))
                },
                |plan, selected_public_identity| {
                    authority_calls.set(authority_calls.get() + 1);
                    assert_eq!(plan.workspace_id(), &expected_workspace);
                    assert_eq!(plan.user_id(), &expected_user);
                    assert_eq!(plan.device_id(), &expected_device);
                    assert_eq!(plan.transport_selection(), selection);
                    assert_eq!(selected_public_identity, &public_identity);
                    Ok(OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent)
                },
            )
            .expect("first-run orchestration");

            assert_eq!(
                outcome,
                OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent
            );
            assert_eq!(ensure_calls.get(), 1);
            assert_eq!(authority_calls.get(), 1);
        }
    }

    #[test]
    fn owner_identity_failure_prevents_za_invocation() {
        let public_identity = public_identity();
        let authority_calls = Cell::new(0_u8);

        let result = execute_first_run_orchestration_with(
            OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            &public_identity,
            || Err(OwnerFirstSetupBootstrapInputError::InsecureStateRoot),
            |_plan, _selected_public_identity| {
                authority_calls.set(authority_calls.get() + 1);
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized)
            },
        );

        assert!(result.is_err());
        assert_eq!(authority_calls.get(), 0);
    }

    #[test]
    fn za_failure_is_returned_without_retry_or_selection_change() {
        let record = generate_owner_logical_identity_record().expect("owner record");
        let public_identity = public_identity();
        let authority_calls = Cell::new(0_u8);
        let selection = OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback;

        let result = execute_first_run_orchestration_with(
            selection,
            &public_identity,
            || Ok(OwnerLogicalIdentityRecordOutcome::Created(record)),
            |plan, _selected_public_identity| {
                authority_calls.set(authority_calls.get() + 1);
                assert_eq!(plan.transport_selection(), selection);
                Err(
                    OwnerFirstSetupLocalAuthorityBootstrapError::AuthorityBootstrap(
                        DurableRegistryAuthorityError::CurrentnessConflict,
                    ),
                )
            },
        );

        assert!(result.is_err());
        assert_eq!(authority_calls.get(), 1);
    }
}
