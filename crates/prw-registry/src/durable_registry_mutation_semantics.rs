//! Provider-neutral durable-registry lifecycle mutation semantics.
//!
//! Persistence providers own atomicity/currentness mechanics. These helpers own only the existing
//! PRW membership/device successor rules so provider adapters cannot drift semantically.

use prw_connectivity::TransportIdentity;
use prw_core::DeviceLifecycle;

use crate::{
    MembershipLifecycle, RegisteredDevice, RegistryError, WorkspaceMembership,
    durable_registry_authority::{
        DurableRegistryAuthorityError, DurableRegistryAuthorityError::Semantic,
    },
    durable_registry_semantics::ensure_enrolled_device,
};

pub fn suspend_membership_successor(
    current: &WorkspaceMembership,
) -> Result<WorkspaceMembership, DurableRegistryAuthorityError> {
    match current.lifecycle() {
        MembershipLifecycle::Active => {
            let mut successor = current.clone();
            successor.lifecycle = MembershipLifecycle::Suspended;
            Ok(successor)
        }
        MembershipLifecycle::Suspended => Err(Semantic(RegistryError::InvalidMembershipTransition)),
        MembershipLifecycle::Removed => Err(Semantic(RegistryError::MembershipRemoved)),
    }
}

pub fn remove_membership_successor(
    current: &WorkspaceMembership,
) -> Result<WorkspaceMembership, DurableRegistryAuthorityError> {
    match current.lifecycle() {
        MembershipLifecycle::Active | MembershipLifecycle::Suspended => {
            let mut successor = current.clone();
            successor.lifecycle = MembershipLifecycle::Removed;
            Ok(successor)
        }
        MembershipLifecycle::Removed => Err(Semantic(RegistryError::MembershipRemoved)),
    }
}

pub fn bind_transport_successor(
    current: &RegisteredDevice,
    identity: TransportIdentity,
) -> Result<RegisteredDevice, DurableRegistryAuthorityError> {
    ensure_enrolled_device(current)?;
    if current.transport_identity().is_some() {
        return Err(Semantic(RegistryError::TransportIdentityAlreadyBound));
    }
    let mut successor = current.clone();
    successor.transport_identity = Some(identity);
    Ok(successor)
}

pub fn rotate_transport_successor(
    current: &RegisteredDevice,
    expected_current: TransportIdentity,
    replacement: TransportIdentity,
) -> Result<RegisteredDevice, DurableRegistryAuthorityError> {
    if expected_current == replacement {
        return Err(Semantic(RegistryError::TransportIdentityUnchanged));
    }
    ensure_enrolled_device(current)?;
    let existing = current
        .transport_identity()
        .ok_or(Semantic(RegistryError::TransportIdentityMissing))?;
    if existing != expected_current {
        return Err(Semantic(RegistryError::TransportIdentityMismatch));
    }
    let mut successor = current.clone();
    successor.transport_identity = Some(replacement);
    Ok(successor)
}

pub fn revoke_device_successor(
    current: &RegisteredDevice,
) -> Result<RegisteredDevice, DurableRegistryAuthorityError> {
    match current.binding().lifecycle {
        DeviceLifecycle::Enrolled => {
            let mut successor = current.clone();
            successor.binding.lifecycle = DeviceLifecycle::Revoked;
            Ok(successor)
        }
        DeviceLifecycle::Revoked => Err(Semantic(RegistryError::DeviceRevoked)),
        DeviceLifecycle::PendingEnrollment => Err(DurableRegistryAuthorityError::InvalidAuthority),
    }
}

pub fn same_device_immutable_tuple(left: &RegisteredDevice, right: &RegisteredDevice) -> bool {
    let left = left.binding();
    let right = right.binding();
    left.workspace_id == right.workspace_id
        && left.user_id == right.user_id
        && left.device_id == right.device_id
        && left.public_identity == right.public_identity
}
