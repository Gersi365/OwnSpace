//! Startup-state authority dispatch between pending first-run completion and established restart.
//!
//! The dispatcher composes only already-validated seams. It classifies the fixed
//! setup-intent record fail-closed, routes valid present intent to the first-run
//! authority path, and routes exact validated absence to established-state proof.
//! It completes before either Agent runtime lane is allowed to begin. Legacy helper
//! identifiers containing `dormant` are retained to minimize compatibility-sensitive source churn.

use std::fmt;

use prw_control_plane::PublicIdentityMaterial;

use crate::{
    owner_established_startup_authority::{
        OwnerEstablishedStartupAuthorityError, OwnerEstablishedStartupAuthorityProof,
        verify_established_owner_startup_authority,
    },
    owner_first_run_orchestration::{
        OwnerFirstRunOrchestrationAndRetirementOutcome, OwnerFirstRunOrchestrationError,
        execute_dormant_owner_first_run_orchestration_and_retire_setup_intent_after_success,
    },
    owner_first_run_setup_intent::{
        OwnerFirstRunSetupIntentError, OwnerFirstRunSetupIntentPresence,
        inspect_owner_first_run_setup_intent_presence_from_env,
    },
};

/// Exact authority path selected by the startup-state dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerStartupStateDispatchOutcome {
    /// A valid pending first-run transaction completed through ZM.
    FirstRunCompleted(OwnerFirstRunOrchestrationAndRetirementOutcome),
    /// Exact setup-intent absence was followed by successful established-state proof through ZO.
    EstablishedRestartVerified(OwnerEstablishedStartupAuthorityProof),
}

/// Fail-closed error stage for startup-state dispatch.
#[derive(Debug)]
pub enum OwnerStartupStateDispatchError {
    /// Setup-intent presence could not be classified safely.
    SetupIntentClassification(OwnerFirstRunSetupIntentError),
    /// A valid pending first-run transaction failed in the existing ZM seam.
    FirstRun(OwnerFirstRunOrchestrationError),
    /// Exact setup-intent absence was observed, but established restart proof failed.
    EstablishedRestart(OwnerEstablishedStartupAuthorityError),
}

impl fmt::Display for OwnerStartupStateDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupIntentClassification(error) => {
                write!(
                    formatter,
                    "startup setup-intent classification failed: {error}"
                )
            }
            Self::FirstRun(error) => {
                write!(formatter, "startup first-run completion failed: {error}")
            }
            Self::EstablishedRestart(error) => {
                write!(
                    formatter,
                    "startup established-restart proof failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for OwnerStartupStateDispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SetupIntentClassification(error) => Some(error),
            Self::FirstRun(error) => Some(error),
            Self::EstablishedRestart(error) => Some(error),
        }
    }
}

/// Classifies startup state and invokes exactly one already-validated authority seam.
///
/// A valid present setup-intent record routes only to ZM. Exact validated absence
/// routes only to ZO. No ZM error falls back to ZO, and no ZO error retries ZM.
///
/// Executable Agent startup invokes this seam after device-identity signer custody
/// succeeds and before execution enters either runtime lane.
///
/// # Errors
///
/// Returns the exact fail-closed classification, ZM, or ZO failure stage.
pub fn dispatch_owner_startup_authority(
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerStartupStateDispatchOutcome, OwnerStartupStateDispatchError> {
    match dispatch_startup_state_with(
        public_device_identity,
        inspect_owner_first_run_setup_intent_presence_from_env,
        execute_dormant_owner_first_run_orchestration_and_retire_setup_intent_after_success,
        verify_established_owner_startup_authority,
    ) {
        Ok(DispatchOutcome::FirstRun(outcome)) => {
            Ok(OwnerStartupStateDispatchOutcome::FirstRunCompleted(outcome))
        }
        Ok(DispatchOutcome::EstablishedRestart(proof)) => {
            Ok(OwnerStartupStateDispatchOutcome::EstablishedRestartVerified(proof))
        }
        Err(DispatchError::Inspect(error)) => Err(
            OwnerStartupStateDispatchError::SetupIntentClassification(error),
        ),
        Err(DispatchError::FirstRun(error)) => Err(OwnerStartupStateDispatchError::FirstRun(error)),
        Err(DispatchError::EstablishedRestart(error)) => {
            Err(OwnerStartupStateDispatchError::EstablishedRestart(error))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchOutcome<F, E> {
    FirstRun(F),
    EstablishedRestart(E),
}

#[derive(Debug, PartialEq, Eq)]
enum DispatchError<I, F, E> {
    Inspect(I),
    FirstRun(F),
    EstablishedRestart(E),
}

fn dispatch_startup_state_with<I, F, E, FOut, EOut, IErr, FErr, EErr>(
    public_device_identity: &PublicIdentityMaterial,
    inspect_setup_intent: I,
    execute_first_run: F,
    verify_established_restart: E,
) -> Result<DispatchOutcome<FOut, EOut>, DispatchError<IErr, FErr, EErr>>
where
    I: FnOnce() -> Result<OwnerFirstRunSetupIntentPresence, IErr>,
    F: FnOnce(&PublicIdentityMaterial) -> Result<FOut, FErr>,
    E: FnOnce(&PublicIdentityMaterial) -> Result<EOut, EErr>,
{
    match inspect_setup_intent().map_err(DispatchError::Inspect)? {
        OwnerFirstRunSetupIntentPresence::Present => execute_first_run(public_device_identity)
            .map(DispatchOutcome::FirstRun)
            .map_err(DispatchError::FirstRun),
        OwnerFirstRunSetupIntentPresence::Absent => {
            verify_established_restart(public_device_identity)
                .map(DispatchOutcome::EstablishedRestart)
                .map_err(DispatchError::EstablishedRestart)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };

    use super::{DispatchError, DispatchOutcome, dispatch_startup_state_with};
    use crate::owner_first_run_setup_intent::OwnerFirstRunSetupIntentPresence;

    fn public_identity() -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![0x31; 32],
        )
        .expect("valid public identity")
    }

    #[test]
    fn present_routes_only_to_first_run() {
        let identity = public_identity();
        let first_run_calls = Cell::new(0_u8);
        let established_calls = Cell::new(0_u8);

        let result = dispatch_startup_state_with(
            &identity,
            || Ok::<_, &'static str>(OwnerFirstRunSetupIntentPresence::Present),
            |selected_identity| {
                first_run_calls.set(first_run_calls.get() + 1);
                assert_eq!(selected_identity, &identity);
                Ok::<_, &'static str>(11_u8)
            },
            |_selected_identity| {
                established_calls.set(established_calls.get() + 1);
                Ok::<_, &'static str>(22_u8)
            },
        );

        assert_eq!(result, Ok(DispatchOutcome::FirstRun(11)));
        assert_eq!(first_run_calls.get(), 1);
        assert_eq!(established_calls.get(), 0);
    }

    #[test]
    fn exact_absence_routes_only_to_established_restart() {
        let identity = public_identity();
        let first_run_calls = Cell::new(0_u8);
        let established_calls = Cell::new(0_u8);

        let result = dispatch_startup_state_with(
            &identity,
            || Ok::<_, &'static str>(OwnerFirstRunSetupIntentPresence::Absent),
            |_selected_identity| {
                first_run_calls.set(first_run_calls.get() + 1);
                Ok::<_, &'static str>(11_u8)
            },
            |selected_identity| {
                established_calls.set(established_calls.get() + 1);
                assert_eq!(selected_identity, &identity);
                Ok::<_, &'static str>(22_u8)
            },
        );

        assert_eq!(result, Ok(DispatchOutcome::EstablishedRestart(22)));
        assert_eq!(first_run_calls.get(), 0);
        assert_eq!(established_calls.get(), 1);
    }

    #[test]
    fn classification_failure_invokes_neither_authority_path() {
        let identity = public_identity();
        let first_run_calls = Cell::new(0_u8);
        let established_calls = Cell::new(0_u8);

        let result = dispatch_startup_state_with(
            &identity,
            || Err::<OwnerFirstRunSetupIntentPresence, _>("invalid-intent"),
            |_selected_identity| {
                first_run_calls.set(first_run_calls.get() + 1);
                Ok::<_, &'static str>(11_u8)
            },
            |_selected_identity| {
                established_calls.set(established_calls.get() + 1);
                Ok::<_, &'static str>(22_u8)
            },
        );

        assert_eq!(result, Err(DispatchError::Inspect("invalid-intent")));
        assert_eq!(first_run_calls.get(), 0);
        assert_eq!(established_calls.get(), 0);
    }

    #[test]
    fn first_run_failure_never_falls_back_to_established_restart() {
        let identity = public_identity();
        let established_calls = Cell::new(0_u8);

        let result = dispatch_startup_state_with(
            &identity,
            || Ok::<_, &'static str>(OwnerFirstRunSetupIntentPresence::Present),
            |_selected_identity| Err::<u8, _>("first-run-failed"),
            |_selected_identity| {
                established_calls.set(established_calls.get() + 1);
                Ok::<_, &'static str>(22_u8)
            },
        );

        assert_eq!(result, Err(DispatchError::FirstRun("first-run-failed")));
        assert_eq!(established_calls.get(), 0);
    }

    #[test]
    fn established_restart_failure_never_retries_first_run() {
        let identity = public_identity();
        let first_run_calls = Cell::new(0_u8);

        let result = dispatch_startup_state_with(
            &identity,
            || Ok::<_, &'static str>(OwnerFirstRunSetupIntentPresence::Absent),
            |_selected_identity| {
                first_run_calls.set(first_run_calls.get() + 1);
                Ok::<_, &'static str>(11_u8)
            },
            |_selected_identity| Err::<u8, _>("established-failed"),
        );

        assert_eq!(
            result,
            Err(DispatchError::EstablishedRestart("established-failed"))
        );
        assert_eq!(first_run_calls.get(), 0);
    }
}
