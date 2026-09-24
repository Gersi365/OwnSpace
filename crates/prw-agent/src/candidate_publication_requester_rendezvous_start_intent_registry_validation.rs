//! Agent-internal current-registry validation for requester/rendezvous start intent.
//!
//! C03e-DI materializes only the C03e-DG/DH-selected post-registry-validation provenance carrier
//! and ownership transfer after the existing C03e-DF fail-closed registry composition succeeds. It
//! does not select or evaluate policy, derive provider authority, mutate requester/rendezvous state,
//! handle wire commands, inspect target transport readiness, perform I/O, activate runtime behavior,
//! or deploy anything.

use std::fmt;

use prw_core::{DeviceId, DeviceLifecycle, WorkspaceId};
use prw_registry::{MembershipLifecycle, RegistryError, WorkspaceDeviceRegistry};
use prw_session::AuthenticatedDeviceSession;

use crate::candidate_publication_requester_rendezvous_start_intent::RequesterRendezvousStartIntent;

/// Stable crate-internal failure for current-registry start-intent validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousStartRegistryValidationError {
    /// An existing registry-currentness check failed.
    Registry(RegistryError),
    /// The current requester and target belong to different workspaces.
    WorkspaceMismatch,
    /// The resolved registry target no longer preserves the nominated logical device identity.
    TargetIdentityMismatch,
}

impl fmt::Display for RequesterRendezvousStartRegistryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => {
                write!(
                    formatter,
                    "requester rendezvous registry validation failed: {error}"
                )
            }
            Self::WorkspaceMismatch => {
                formatter.write_str("requester rendezvous target workspace mismatch")
            }
            Self::TargetIdentityMismatch => {
                formatter.write_str("requester rendezvous target identity mismatch")
            }
        }
    }
}

impl std::error::Error for RequesterRendezvousStartRegistryValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::WorkspaceMismatch | Self::TargetIdentityMismatch => None,
        }
    }
}

/// One exact requester/target pair that passed the full current-registry validation chain.
///
/// This owned value proves only point-in-time registry eligibility. It is deliberately neither
/// `Copy` nor `Clone`, has no constructor from arbitrary identity values, and is not policy
/// authorization, requester/rendezvous provider registration authority, transport readiness,
/// live-owner authority, candidate-publication authority, or a lease/currentness guarantee.
pub struct RegistryValidatedRequesterRendezvousStart {
    requester_session: AuthenticatedDeviceSession,
    target_device_id: DeviceId,
}

impl RegistryValidatedRequesterRendezvousStart {
    /// Returns the exact server-held requester session that passed current-registry validation.
    #[must_use]
    pub const fn requester_session(&self) -> &AuthenticatedDeviceSession {
        &self.requester_session
    }

    /// Returns the exact logical target device that passed current-registry validation.
    #[must_use]
    pub const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }
}

/// Revalidates one unvalidated requester/rendezvous start intent against current registry state.
///
/// Validation order is fixed: requester session currentness, exact target lookup, target device
/// lifecycle, target membership lifecycle, same-workspace equality, then exact target preservation.
/// The input intent is consumed, but its owned identity values are moved into the returned validated
/// provenance carrier only after every current-registry check succeeds. Successful return proves
/// only current registry eligibility. It is not policy authorization and does not mutate
/// requester/rendezvous provider state.
///
/// # Errors
///
/// Fails closed on stale requester state, unknown/ineligible target state, cross-workspace intent,
/// or any structural target-identity mismatch. Failure produces no validated carrier.
pub fn validate_current_requester_rendezvous_start_intent(
    registry: &WorkspaceDeviceRegistry,
    intent: RequesterRendezvousStartIntent,
) -> Result<
    RegistryValidatedRequesterRendezvousStart,
    RequesterRendezvousStartRegistryValidationError,
> {
    let requester = registry
        .validate_authenticated_session(intent.requester_session())
        .map_err(RequesterRendezvousStartRegistryValidationError::Registry)?;

    validate_current_target(
        registry,
        requester.workspace_id(),
        intent.target_device_id(),
    )?;

    let RequesterRendezvousStartIntent {
        requester_session,
        target_device_id,
    } = intent;

    Ok(RegistryValidatedRequesterRendezvousStart {
        requester_session,
        target_device_id,
    })
}

fn validate_current_target(
    registry: &WorkspaceDeviceRegistry,
    requester_workspace_id: &WorkspaceId,
    target_device_id: &DeviceId,
) -> Result<(), RequesterRendezvousStartRegistryValidationError> {
    let target = registry.device(target_device_id).ok_or(
        RequesterRendezvousStartRegistryValidationError::Registry(RegistryError::DeviceUnknown),
    )?;
    let binding = target.binding();

    match binding.lifecycle {
        DeviceLifecycle::Enrolled => {}
        DeviceLifecycle::PendingEnrollment => {
            return Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::DeviceNotEnrolled,
            ));
        }
        DeviceLifecycle::Revoked => {
            return Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::DeviceRevoked,
            ));
        }
    }

    let target_membership = registry
        .membership(&binding.workspace_id, &binding.user_id)
        .ok_or(RequesterRendezvousStartRegistryValidationError::Registry(
            RegistryError::MembershipUnknown,
        ))?;

    match target_membership.lifecycle() {
        MembershipLifecycle::Active => {}
        MembershipLifecycle::Suspended => {
            return Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::MembershipNotActive,
            ));
        }
        MembershipLifecycle::Removed => {
            return Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::MembershipRemoved,
            ));
        }
    }

    if requester_workspace_id != &binding.workspace_id {
        return Err(RequesterRendezvousStartRegistryValidationError::WorkspaceMismatch);
    }
    if &binding.device_id != target_device_id {
        return Err(RequesterRendezvousStartRegistryValidationError::TargetIdentityMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
        PublicIdentityMaterial,
    };
    use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};
    use prw_registry::{RegistryError, WorkspaceDeviceRegistry, WorkspaceRole};

    use crate::candidate_publication_requester_rendezvous_start_intent::RequesterRendezvousStartIntent;

    use super::{
        RegistryValidatedRequesterRendezvousStart, RequesterRendezvousStartRegistryValidationError,
        validate_current_requester_rendezvous_start_intent, validate_current_target,
    };

    fn public_identity(seed: u8) -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![seed],
        )
        .expect("non-empty disposable target identity")
    }

    fn add_current_target(
        registry: &mut WorkspaceDeviceRegistry,
        workspace_name: &str,
        user_name: &str,
        device_name: &str,
    ) -> (WorkspaceId, UserId, DeviceId) {
        let workspace_id = WorkspaceId::new(workspace_name).expect("workspace id");
        let user_id = UserId::new(user_name).expect("user id");
        let device_id = DeviceId::new(device_name).expect("device id");

        registry
            .add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Member)
            .expect("add target membership");
        registry
            .register_device(DeviceIdentityBinding {
                workspace_id: workspace_id.clone(),
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                public_identity: public_identity(0x41),
                lifecycle: DeviceLifecycle::Enrolled,
            })
            .expect("register current target");

        (workspace_id, user_id, device_id)
    }

    fn assert_validation_signature(
        validation: fn(
            &WorkspaceDeviceRegistry,
            RequesterRendezvousStartIntent,
        ) -> Result<
            RegistryValidatedRequesterRendezvousStart,
            RequesterRendezvousStartRegistryValidationError,
        >,
    ) {
        let _ = validation;
    }

    #[test]
    fn validation_surface_has_selected_consuming_carrier_shape() {
        assert_validation_signature(validate_current_requester_rendezvous_start_intent);
    }

    #[test]
    fn current_enrolled_active_same_workspace_target_passes() {
        let mut registry = WorkspaceDeviceRegistry::new();
        let (workspace_id, _user_id, target_device_id) = add_current_target(
            &mut registry,
            "workspace-df",
            "target-user-df",
            "target-device-df",
        );

        assert_eq!(
            validate_current_target(&registry, &workspace_id, &target_device_id),
            Ok(())
        );
    }

    #[test]
    fn unknown_target_fails_closed() {
        let registry = WorkspaceDeviceRegistry::new();
        let workspace_id = WorkspaceId::new("workspace-df").expect("workspace id");
        let target_device_id = DeviceId::new("missing-target-df").expect("device id");

        assert_eq!(
            validate_current_target(&registry, &workspace_id, &target_device_id),
            Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::DeviceUnknown
            ))
        );
    }

    #[test]
    fn revoked_target_fails_closed() {
        let mut registry = WorkspaceDeviceRegistry::new();
        let (workspace_id, _user_id, target_device_id) = add_current_target(
            &mut registry,
            "workspace-df",
            "target-user-df",
            "target-device-df",
        );
        registry
            .revoke_device(&target_device_id)
            .expect("revoke target");

        assert_eq!(
            validate_current_target(&registry, &workspace_id, &target_device_id),
            Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::DeviceRevoked
            ))
        );
    }

    #[test]
    fn suspended_target_membership_fails_before_workspace_comparison() {
        let mut registry = WorkspaceDeviceRegistry::new();
        let (target_workspace_id, target_user_id, target_device_id) = add_current_target(
            &mut registry,
            "target-workspace-df",
            "target-user-df",
            "target-device-df",
        );
        registry
            .suspend_membership(&target_workspace_id, &target_user_id)
            .expect("suspend target membership");
        let requester_workspace_id =
            WorkspaceId::new("requester-workspace-df").expect("workspace id");

        assert_eq!(
            validate_current_target(&registry, &requester_workspace_id, &target_device_id),
            Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::MembershipNotActive
            ))
        );
    }

    #[test]
    fn removed_target_membership_fails_closed() {
        let mut registry = WorkspaceDeviceRegistry::new();
        let (workspace_id, target_user_id, target_device_id) = add_current_target(
            &mut registry,
            "workspace-df",
            "target-user-df",
            "target-device-df",
        );
        registry
            .remove_membership(&workspace_id, &target_user_id)
            .expect("remove target membership");

        assert_eq!(
            validate_current_target(&registry, &workspace_id, &target_device_id),
            Err(RequesterRendezvousStartRegistryValidationError::Registry(
                RegistryError::MembershipRemoved
            ))
        );
    }

    #[test]
    fn active_cross_workspace_target_fails_closed() {
        let mut registry = WorkspaceDeviceRegistry::new();
        let (_target_workspace_id, _target_user_id, target_device_id) = add_current_target(
            &mut registry,
            "target-workspace-df",
            "target-user-df",
            "target-device-df",
        );
        let requester_workspace_id =
            WorkspaceId::new("requester-workspace-df").expect("workspace id");

        assert_eq!(
            validate_current_target(&registry, &requester_workspace_id, &target_device_id),
            Err(RequesterRendezvousStartRegistryValidationError::WorkspaceMismatch)
        );
    }
}
