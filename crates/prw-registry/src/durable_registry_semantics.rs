//! Provider-neutral durable-registry read/revalidation semantics.
//!
//! These helpers keep identity, membership, device-lifecycle and transport validation rules outside
//! any concrete persistence provider. Provider adapters load authoritative records; this module
//! applies the shared PRW semantics.

use prw_connectivity::TransportIdentity;
use prw_control_plane::PublicIdentityMaterial;
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};

use crate::{
    MembershipLifecycle, RegisteredDevice, RegistryError, RegistryValidatedPrincipal,
    WorkspaceMembership,
    durable_registry_authority::{
        DurableRegistryAuthorityError, DurableRegistryAuthorityError::Semantic,
    },
};

pub const fn ensure_enrolled_device(
    device: &RegisteredDevice,
) -> Result<(), DurableRegistryAuthorityError> {
    match device.binding().lifecycle {
        DeviceLifecycle::Enrolled => Ok(()),
        DeviceLifecycle::Revoked => Err(Semantic(RegistryError::DeviceRevoked)),
        DeviceLifecycle::PendingEnrollment => Err(DurableRegistryAuthorityError::InvalidAuthority),
    }
}

pub fn current_transport_from_device(
    device: &RegisteredDevice,
) -> Result<TransportIdentity, DurableRegistryAuthorityError> {
    ensure_enrolled_device(device)?;
    device
        .transport_identity()
        .ok_or(Semantic(RegistryError::TransportIdentityMissing))
}

pub fn validate_presented_transport_from_device(
    device: &RegisteredDevice,
    presented: TransportIdentity,
) -> Result<(), DurableRegistryAuthorityError> {
    let current = current_transport_from_device(device)?;
    if current != presented {
        return Err(Semantic(RegistryError::TransportIdentityMismatch));
    }
    Ok(())
}

pub fn validate_session_records(
    workspace_id: &WorkspaceId,
    user_id: &UserId,
    device_id: &DeviceId,
    public_identity: &PublicIdentityMaterial,
    membership: &WorkspaceMembership,
    device: &RegisteredDevice,
) -> Result<RegistryValidatedPrincipal, DurableRegistryAuthorityError> {
    if membership.lifecycle() != MembershipLifecycle::Active {
        return Err(Semantic(RegistryError::MembershipNotActive));
    }

    ensure_enrolled_device(device)?;
    let binding = device.binding();
    if &binding.workspace_id != workspace_id
        || &binding.user_id != user_id
        || &binding.device_id != device_id
        || &binding.public_identity != public_identity
    {
        return Err(Semantic(RegistryError::SessionBindingMismatch));
    }

    Ok(RegistryValidatedPrincipal {
        workspace_id: workspace_id.clone(),
        user_id: user_id.clone(),
        device_id: device_id.clone(),
        public_identity: public_identity.clone(),
        role: membership.role(),
    })
}
