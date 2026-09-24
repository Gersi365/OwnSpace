//! C03e-IV semantic durable-registry adapter over the bounded raw etcd executor.
//!
//! This module owns PRW registry semantics above `prw-control-plane` provider mechanics.
//! It constructs and validates canonical PRWM/PRWD records, preserves Phase 130 transition
//! semantics, and classifies authoritative compare-failure observations. It does not own a raw
//! `KvClient`, provider bootstrap, endpoints, credentials/TLS/auth/RBAC, retry/reconciliation,
//! Watch/lease/TTL, scans, production registry population, Agent composition, runtime activation,
//! networking, or deployment.

use prw_connectivity::TransportIdentity;
use prw_control_plane::{
    DeviceIdentityBinding,
    durable_registry_etcd::{
        DurableRegistryEtcdError, DurableRegistryEtcdExecutor, DurableRegistryEtcdMutation,
        DurableRegistryEtcdObservation, DurableRegistryEtcdObservationPair,
        DurableRegistryEtcdRegistrationMutation,
    },
};
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};
use prw_session::AuthenticatedDeviceSession;

use crate::{
    MembershipLifecycle, RegisteredDevice, RegistryError, RegistryValidatedPrincipal,
    WorkspaceMembership, WorkspaceRole,
    durable_registry_authority::{
        DurableRegistryAuthority, DurableRegistryAuthorityError, DurableRegistryAuthorityFuture,
    },
    durable_registry_codec::{
        decode_bound_device_record, decode_bound_membership_record, encode_device_key,
        encode_device_value, encode_membership_key, encode_membership_value,
    },
    durable_registry_mutation_semantics::{
        bind_transport_successor, remove_membership_successor, revoke_device_successor,
        rotate_transport_successor, same_device_immutable_tuple, suspend_membership_successor,
    },
    durable_registry_semantics::{
        current_transport_from_device, validate_presented_transport_from_device,
        validate_session_records,
    },
};

/// Compatibility alias retained while provider-specific callers are migrated to the neutral port.
pub type DurableRegistryEtcdStoreError = DurableRegistryAuthorityError;

/// Concrete registry-semantic adapter over the control-plane raw etcd executor.
pub struct DurableRegistryEtcdStore {
    provider: DurableRegistryEtcdExecutor,
}

impl DurableRegistryEtcdStore {
    /// Creates the semantic adapter around an already-created raw executor without network I/O.
    #[must_use]
    pub const fn new(provider: DurableRegistryEtcdExecutor) -> Self {
        Self { provider }
    }

    /// Consumes the adapter and returns the bounded raw executor.
    #[must_use]
    pub fn into_inner(self) -> DurableRegistryEtcdExecutor {
        self.provider
    }

    /// Loads one exact current membership.
    ///
    /// # Errors
    ///
    /// Returns provider/currentness authority failures distinctly from semantic absence.
    pub async fn membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Option<WorkspaceMembership>, DurableRegistryEtcdStoreError> {
        Ok(self
            .load_membership_observation(workspace_id, user_id)
            .await?
            .map(|observation| observation.record))
    }

    /// Loads one exact current registered device.
    ///
    /// # Errors
    ///
    /// Returns provider/currentness authority failures distinctly from semantic absence.
    pub async fn device(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<Option<RegisteredDevice>, DurableRegistryEtcdStoreError> {
        Ok(self
            .load_device_observation(device_id)
            .await?
            .map(|observation| observation.record))
    }

    /// Creates one active membership only when the exact key is absent.
    ///
    /// # Errors
    ///
    /// Preserves duplicate membership semantics and provider failure distinctions.
    pub async fn add_membership(
        &mut self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> Result<WorkspaceMembership, DurableRegistryEtcdStoreError> {
        let membership = WorkspaceMembership {
            workspace_id,
            user_id,
            role,
            lifecycle: MembershipLifecycle::Active,
        };
        let key = encode_membership_key(membership.workspace_id(), membership.user_id())
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let value = encode_membership_value(&membership)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .create_if_absent(&key, &value)
            .await
            .map_err(map_provider_error)?;
        match mutation {
            DurableRegistryEtcdMutation::Committed => Ok(membership),
            DurableRegistryEtcdMutation::CompareFailed(Some(observation)) => {
                decode_membership_observation(
                    &observation,
                    membership.workspace_id(),
                    membership.user_id(),
                )?;
                Err(semantic(RegistryError::MembershipAlreadyExists))
            }
            DurableRegistryEtcdMutation::CompareFailed(None) => {
                Err(DurableRegistryEtcdStoreError::InvalidAuthority)
            }
        }
    }

    /// Suspends one exact active membership using authoritative pre-read plus dual CAS.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 transition errors and fails closed on moved currentness.
    pub async fn suspend_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        let key = encode_membership_key(workspace_id, user_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let before = self
            .load_membership_observation_with_key(&key, workspace_id, user_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::MembershipUnknown))?;
        let successor = suspend_membership_successor(&before.record)?;
        let value = encode_membership_value(&successor)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .compare_and_put(&key, before.mod_revision, &before.raw_value, &value)
            .await
            .map_err(map_provider_error)?;
        classify_membership_update_result(
            mutation,
            workspace_id,
            user_id,
            &before,
            MembershipUpdateKind::Suspend,
        )
    }

    /// Terminally removes one exact active or suspended membership using dual CAS.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 transition errors and fails closed on moved currentness.
    pub async fn remove_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        let key = encode_membership_key(workspace_id, user_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let before = self
            .load_membership_observation_with_key(&key, workspace_id, user_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::MembershipUnknown))?;
        let successor = remove_membership_successor(&before.record)?;
        let value = encode_membership_value(&successor)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .compare_and_put(&key, before.mod_revision, &before.raw_value, &value)
            .await
            .map_err(map_provider_error)?;
        classify_membership_update_result(
            mutation,
            workspace_id,
            user_id,
            &before,
            MembershipUpdateKind::Remove,
        )
    }

    /// Registers one enrolled/unbound device under one exact active membership.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 precondition order and the selected cross-record transaction semantics.
    pub async fn register_device(
        &mut self,
        binding: DeviceIdentityBinding,
    ) -> Result<RegisteredDevice, DurableRegistryEtcdStoreError> {
        if binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(semantic(RegistryError::DeviceNotEnrolled));
        }
        let workspace_id = binding.workspace_id.clone();
        let user_id = binding.user_id.clone();
        let device_id = binding.device_id.clone();
        let membership_key = encode_membership_key(&workspace_id, &user_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let membership = self
            .load_membership_observation_with_key(&membership_key, &workspace_id, &user_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::MembershipUnknown))?;
        if membership.record.lifecycle() != MembershipLifecycle::Active {
            return Err(semantic(RegistryError::MembershipNotActive));
        }

        let device = RegisteredDevice {
            binding,
            transport_identity: None,
        };
        let device_key = encode_device_key(&device_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let device_value = encode_device_value(&device)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .register_device_if_membership_unchanged(
                &membership_key,
                membership.mod_revision,
                &membership.raw_value,
                &device_key,
                &device_value,
            )
            .await
            .map_err(map_provider_error)?;

        match mutation {
            DurableRegistryEtcdRegistrationMutation::Committed => Ok(device),
            DurableRegistryEtcdRegistrationMutation::CompareFailed(pair) => {
                Err(classify_registration_failure(
                    &pair,
                    &workspace_id,
                    &user_id,
                    &device_id,
                    &membership,
                )?)
            }
        }
    }

    /// Binds the first current transport identity to one exact enrolled/unbound device.
    ///
    /// # Errors
    ///
    /// Rejects unknown/revoked/already-bound devices and moved currentness.
    pub async fn bind_transport_identity(
        &mut self,
        device_id: &DeviceId,
        identity: TransportIdentity,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        let key = encode_device_key(device_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let before = self
            .load_device_observation_with_key(&key, device_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::DeviceUnknown))?;
        let successor = bind_transport_successor(&before.record, identity)?;
        let replacement = encode_device_value(&successor)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .compare_and_put(&key, before.mod_revision, &before.raw_value, &replacement)
            .await
            .map_err(map_provider_error)?;
        classify_device_update_result(mutation, device_id, &before, DeviceUpdateKind::Bind)
    }

    /// Compare-and-rotates one current transport identity under exact dual CAS.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 missing/mismatch/unchanged semantics and moved-currentness conflict.
    pub async fn rotate_transport_identity(
        &mut self,
        device_id: &DeviceId,
        expected_current: TransportIdentity,
        replacement: TransportIdentity,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        if expected_current == replacement {
            return Err(semantic(RegistryError::TransportIdentityUnchanged));
        }
        let key = encode_device_key(device_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let before = self
            .load_device_observation_with_key(&key, device_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::DeviceUnknown))?;
        let successor = rotate_transport_successor(&before.record, expected_current, replacement)?;
        let replacement_value = encode_device_value(&successor)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .compare_and_put(
                &key,
                before.mod_revision,
                &before.raw_value,
                &replacement_value,
            )
            .await
            .map_err(map_provider_error)?;
        classify_device_update_result(
            mutation,
            device_id,
            &before,
            DeviceUpdateKind::Rotate {
                expected: expected_current,
            },
        )
    }

    /// Terminally revokes one enrolled device while preserving immutable tuple and transport.
    ///
    /// # Errors
    ///
    /// Rejects unknown/already-revoked state and moved currentness.
    pub async fn revoke_device(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        let key = encode_device_key(device_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let before = self
            .load_device_observation_with_key(&key, device_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::DeviceUnknown))?;
        let successor = revoke_device_successor(&before.record)?;
        let replacement = encode_device_value(&successor)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let mutation = self
            .provider
            .compare_and_put(&key, before.mod_revision, &before.raw_value, &replacement)
            .await
            .map_err(map_provider_error)?;
        classify_device_update_result(mutation, device_id, &before, DeviceUpdateKind::Revoke)
    }

    /// Returns the exact current enrolled/bound transport identity for one logical device.
    ///
    /// # Errors
    ///
    /// Preserves unknown/revoked/unbound semantics and fails closed on invalid durable authority.
    pub async fn current_transport_identity(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<TransportIdentity, DurableRegistryEtcdStoreError> {
        let device = self
            .device(device_id)
            .await?
            .ok_or_else(|| semantic(RegistryError::DeviceUnknown))?;
        current_transport_from_device(&device)
    }

    /// Validates one presented transport identity against one authoritative current device read.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 unknown/revoked/unbound/mismatch semantics.
    pub async fn validate_transport_identity(
        &mut self,
        device_id: &DeviceId,
        presented: TransportIdentity,
    ) -> Result<(), DurableRegistryEtcdStoreError> {
        let current = self.current_transport_identity(device_id).await?;
        if current != presented {
            return Err(semantic(RegistryError::TransportIdentityMismatch));
        }
        Ok(())
    }

    /// Revalidates one authenticated session against one transactional membership/device snapshot.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 validation precedence while separating invalid provider authority.
    pub async fn validate_authenticated_session(
        &mut self,
        session: &AuthenticatedDeviceSession,
    ) -> Result<RegistryValidatedPrincipal, DurableRegistryEtcdStoreError> {
        self.validate_authenticated_session_snapshot(session)
            .await
            .map(|(principal, _device)| principal)
    }

    /// Revalidates one authenticated session and its presented transport identity against the same
    /// transactional membership/device snapshot.
    ///
    /// # Errors
    ///
    /// Preserves Phase 130 session-validation precedence, then rejects an absent, stale, mismatched
    /// or revoked transport identity from the already-decoded current device record. Provider and
    /// canonical-authority failures remain distinct from semantic rejection.
    pub async fn validate_authenticated_session_and_transport_identity(
        &mut self,
        session: &AuthenticatedDeviceSession,
        presented: TransportIdentity,
    ) -> Result<RegistryValidatedPrincipal, DurableRegistryEtcdStoreError> {
        let (principal, device) = self
            .validate_authenticated_session_snapshot(session)
            .await?;
        validate_presented_transport_from_device(&device, presented)?;
        Ok(principal)
    }

    async fn validate_authenticated_session_snapshot(
        &mut self,
        session: &AuthenticatedDeviceSession,
    ) -> Result<(RegistryValidatedPrincipal, RegisteredDevice), DurableRegistryEtcdStoreError> {
        let membership_key = encode_membership_key(session.workspace_id(), session.user_id())
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let device_key = encode_device_key(session.device_id())
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        let pair = self
            .provider
            .linearizable_pair_get(&membership_key, &device_key)
            .await
            .map_err(map_provider_error)?;

        let membership = match pair.first() {
            Some(observation) => {
                decode_membership_observation(
                    observation,
                    session.workspace_id(),
                    session.user_id(),
                )?
                .record
            }
            None => return Err(semantic(RegistryError::MembershipUnknown)),
        };
        if membership.lifecycle() != MembershipLifecycle::Active {
            return Err(semantic(RegistryError::MembershipNotActive));
        }

        let device = match pair.second() {
            Some(observation) => {
                decode_device_observation(observation, session.device_id())?.record
            }
            None => return Err(semantic(RegistryError::DeviceUnknown)),
        };
        let principal = validate_session_records(
            session.workspace_id(),
            session.user_id(),
            session.device_id(),
            session.public_identity(),
            &membership,
            &device,
        )?;
        Ok((principal, device))
    }

    async fn load_membership_observation(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Option<BoundMembershipObservation>, DurableRegistryEtcdStoreError> {
        let key = encode_membership_key(workspace_id, user_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        self.load_membership_observation_with_key(&key, workspace_id, user_id)
            .await
    }

    async fn load_membership_observation_with_key(
        &mut self,
        key: &[u8],
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Option<BoundMembershipObservation>, DurableRegistryEtcdStoreError> {
        let observation = self
            .provider
            .linearizable_get(key)
            .await
            .map_err(map_provider_error)?;
        observation
            .as_ref()
            .map(|current| decode_membership_observation(current, workspace_id, user_id))
            .transpose()
    }

    async fn load_device_observation(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<Option<BoundDeviceObservation>, DurableRegistryEtcdStoreError> {
        let key = encode_device_key(device_id)
            .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
        self.load_device_observation_with_key(&key, device_id).await
    }

    async fn load_device_observation_with_key(
        &mut self,
        key: &[u8],
        device_id: &DeviceId,
    ) -> Result<Option<BoundDeviceObservation>, DurableRegistryEtcdStoreError> {
        let observation = self
            .provider
            .linearizable_get(key)
            .await
            .map_err(map_provider_error)?;
        observation
            .as_ref()
            .map(|current| decode_device_observation(current, device_id))
            .transpose()
    }
}

impl DurableRegistryAuthority for DurableRegistryEtcdStore {
    fn current_transport_identity<'a>(
        &'a mut self,
        device_id: &'a DeviceId,
    ) -> DurableRegistryAuthorityFuture<'a, TransportIdentity> {
        Box::pin(async move { Self::current_transport_identity(self, device_id).await })
    }

    fn validate_authenticated_session_and_transport_identity<'a>(
        &'a mut self,
        session: &'a AuthenticatedDeviceSession,
        presented: TransportIdentity,
    ) -> DurableRegistryAuthorityFuture<'a, RegistryValidatedPrincipal> {
        Box::pin(async move {
            Self::validate_authenticated_session_and_transport_identity(self, session, presented)
                .await
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundMembershipObservation {
    record: WorkspaceMembership,
    raw_value: Vec<u8>,
    mod_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundDeviceObservation {
    record: RegisteredDevice,
    raw_value: Vec<u8>,
    mod_revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MembershipUpdateKind {
    Suspend,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceUpdateKind {
    Bind,
    Rotate { expected: TransportIdentity },
    Revoke,
}

const fn semantic(error: RegistryError) -> DurableRegistryEtcdStoreError {
    DurableRegistryEtcdStoreError::Semantic(error)
}

fn map_provider_error(error: DurableRegistryEtcdError) -> DurableRegistryEtcdStoreError {
    match error {
        DurableRegistryEtcdError::ReadUnavailable(_error) => {
            DurableRegistryEtcdStoreError::ReadUnavailable
        }
        DurableRegistryEtcdError::MutationIndeterminate(_error) => {
            DurableRegistryEtcdStoreError::MutationIndeterminate
        }
        DurableRegistryEtcdError::UnexpectedGetCardinality { .. }
        | DurableRegistryEtcdError::UnexpectedGetKey
        | DurableRegistryEtcdError::InvalidModRevision { .. }
        | DurableRegistryEtcdError::UnexpectedTxnResponseShape => {
            DurableRegistryEtcdStoreError::InvalidAuthority
        }
    }
}

fn decode_membership_observation(
    observation: &DurableRegistryEtcdObservation,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
) -> Result<BoundMembershipObservation, DurableRegistryEtcdStoreError> {
    decode_membership_parts(
        observation.key(),
        observation.value(),
        observation.mod_revision(),
        workspace_id,
        user_id,
    )
}

fn decode_membership_parts(
    key: &[u8],
    value: &[u8],
    mod_revision: i64,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
) -> Result<BoundMembershipObservation, DurableRegistryEtcdStoreError> {
    if mod_revision <= 0 {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    let record = decode_bound_membership_record(key, value, workspace_id, user_id)
        .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
    Ok(BoundMembershipObservation {
        record,
        raw_value: value.to_vec(),
        mod_revision,
    })
}

fn decode_device_observation(
    observation: &DurableRegistryEtcdObservation,
    device_id: &DeviceId,
) -> Result<BoundDeviceObservation, DurableRegistryEtcdStoreError> {
    decode_device_parts(
        observation.key(),
        observation.value(),
        observation.mod_revision(),
        device_id,
    )
}

fn decode_device_parts(
    key: &[u8],
    value: &[u8],
    mod_revision: i64,
    device_id: &DeviceId,
) -> Result<BoundDeviceObservation, DurableRegistryEtcdStoreError> {
    if mod_revision <= 0 {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    let record = decode_bound_device_record(key, value, device_id)
        .map_err(|_| DurableRegistryEtcdStoreError::InvalidAuthority)?;
    Ok(BoundDeviceObservation {
        record,
        raw_value: value.to_vec(),
        mod_revision,
    })
}

fn classify_membership_update_result(
    mutation: DurableRegistryEtcdMutation,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
    before: &BoundMembershipObservation,
    kind: MembershipUpdateKind,
) -> Result<(), DurableRegistryEtcdStoreError> {
    match mutation {
        DurableRegistryEtcdMutation::Committed => Ok(()),
        DurableRegistryEtcdMutation::CompareFailed(None) => {
            Err(semantic(RegistryError::MembershipUnknown))
        }
        DurableRegistryEtcdMutation::CompareFailed(Some(observation)) => {
            let current = decode_membership_observation(&observation, workspace_id, user_id)?;
            classify_membership_compare_failure(before, &current, kind)
        }
    }
}

fn classify_membership_compare_failure(
    before: &BoundMembershipObservation,
    current: &BoundMembershipObservation,
    kind: MembershipUpdateKind,
) -> Result<(), DurableRegistryEtcdStoreError> {
    if before.record.role() != current.record.role() {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    if same_membership_observation(before, current) {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    let error = match (kind, current.record.lifecycle()) {
        (MembershipUpdateKind::Suspend, MembershipLifecycle::Suspended) => {
            Some(RegistryError::InvalidMembershipTransition)
        }
        (_, MembershipLifecycle::Removed) => Some(RegistryError::MembershipRemoved),
        (MembershipUpdateKind::Suspend, MembershipLifecycle::Active)
        | (
            MembershipUpdateKind::Remove,
            MembershipLifecycle::Active | MembershipLifecycle::Suspended,
        ) => None,
    };
    error.map_or(
        Err(DurableRegistryEtcdStoreError::CurrentnessConflict),
        |error| Err(semantic(error)),
    )
}

fn same_membership_observation(
    left: &BoundMembershipObservation,
    right: &BoundMembershipObservation,
) -> bool {
    left.mod_revision == right.mod_revision && left.raw_value == right.raw_value
}

fn classify_registration_failure(
    pair: &DurableRegistryEtcdObservationPair,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
    device_id: &DeviceId,
    before_membership: &BoundMembershipObservation,
) -> Result<DurableRegistryEtcdStoreError, DurableRegistryEtcdStoreError> {
    let current_membership = match pair.first() {
        Some(observation) => decode_membership_observation(observation, workspace_id, user_id)?,
        None => return Ok(semantic(RegistryError::MembershipUnknown)),
    };
    if current_membership.record.lifecycle() != MembershipLifecycle::Active {
        return Ok(semantic(RegistryError::MembershipNotActive));
    }
    if !same_membership_observation(before_membership, &current_membership) {
        return Ok(DurableRegistryEtcdStoreError::CurrentnessConflict);
    }
    match pair.second() {
        Some(observation) => {
            decode_device_observation(observation, device_id)?;
            Ok(semantic(RegistryError::DeviceAlreadyExists))
        }
        None => Ok(DurableRegistryEtcdStoreError::InvalidAuthority),
    }
}

fn classify_device_update_result(
    mutation: DurableRegistryEtcdMutation,
    device_id: &DeviceId,
    before: &BoundDeviceObservation,
    kind: DeviceUpdateKind,
) -> Result<(), DurableRegistryEtcdStoreError> {
    match mutation {
        DurableRegistryEtcdMutation::Committed => Ok(()),
        DurableRegistryEtcdMutation::CompareFailed(None) => {
            Err(semantic(RegistryError::DeviceUnknown))
        }
        DurableRegistryEtcdMutation::CompareFailed(Some(observation)) => {
            let current = decode_device_observation(&observation, device_id)?;
            classify_device_compare_failure(before, &current, kind)
        }
    }
}

fn classify_device_compare_failure(
    before: &BoundDeviceObservation,
    current: &BoundDeviceObservation,
    kind: DeviceUpdateKind,
) -> Result<(), DurableRegistryEtcdStoreError> {
    if !same_device_immutable_tuple(&before.record, &current.record) {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    if same_device_observation(before, current) {
        return Err(DurableRegistryEtcdStoreError::InvalidAuthority);
    }
    match current.record.binding().lifecycle {
        DeviceLifecycle::PendingEnrollment => Err(DurableRegistryEtcdStoreError::InvalidAuthority),
        DeviceLifecycle::Revoked => Err(semantic(RegistryError::DeviceRevoked)),
        DeviceLifecycle::Enrolled => classify_enrolled_device_conflict(&current.record, kind),
    }
}

fn classify_enrolled_device_conflict(
    current: &RegisteredDevice,
    kind: DeviceUpdateKind,
) -> Result<(), DurableRegistryEtcdStoreError> {
    match kind {
        DeviceUpdateKind::Bind => {
            if current.transport_identity().is_some() {
                Err(semantic(RegistryError::TransportIdentityAlreadyBound))
            } else {
                Err(DurableRegistryEtcdStoreError::CurrentnessConflict)
            }
        }
        DeviceUpdateKind::Rotate { expected } => match current.transport_identity() {
            None => Err(semantic(RegistryError::TransportIdentityMissing)),
            Some(identity) if identity != expected => {
                Err(semantic(RegistryError::TransportIdentityMismatch))
            }
            Some(_) => Err(DurableRegistryEtcdStoreError::CurrentnessConflict),
        },
        DeviceUpdateKind::Revoke => Err(DurableRegistryEtcdStoreError::CurrentnessConflict),
    }
}

fn same_device_observation(left: &BoundDeviceObservation, right: &BoundDeviceObservation) -> bool {
    left.mod_revision == right.mod_revision && left.raw_value == right.raw_value
}

#[cfg(test)]
mod tests {
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, PublicIdentityMaterial,
    };

    use super::*;

    fn workspace(value: &str) -> WorkspaceId {
        WorkspaceId::new(value).expect("valid workspace")
    }

    fn user(value: &str) -> UserId {
        UserId::new(value).expect("valid user")
    }

    fn device_id(value: &str) -> DeviceId {
        DeviceId::new(value).expect("valid device")
    }

    fn public_identity(marker: u8) -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![0x30, marker],
        )
        .expect("public identity")
    }

    fn membership(lifecycle: MembershipLifecycle) -> WorkspaceMembership {
        WorkspaceMembership {
            workspace_id: workspace("workspace"),
            user_id: user("user"),
            role: WorkspaceRole::Admin,
            lifecycle,
        }
    }

    fn registered(
        lifecycle: DeviceLifecycle,
        transport: Option<TransportIdentity>,
        identity_marker: u8,
    ) -> RegisteredDevice {
        RegisteredDevice {
            binding: DeviceIdentityBinding {
                workspace_id: workspace("workspace"),
                user_id: user("user"),
                device_id: device_id("device"),
                public_identity: public_identity(identity_marker),
                lifecycle,
            },
            transport_identity: transport,
        }
    }

    fn membership_observation(
        record: WorkspaceMembership,
        revision: i64,
    ) -> BoundMembershipObservation {
        BoundMembershipObservation {
            raw_value: encode_membership_value(&record).expect("membership value"),
            record,
            mod_revision: revision,
        }
    }

    fn device_observation(record: RegisteredDevice, revision: i64) -> BoundDeviceObservation {
        BoundDeviceObservation {
            raw_value: encode_device_value(&record).expect("device value"),
            record,
            mod_revision: revision,
        }
    }

    #[test]
    fn exact_membership_binding_rejects_requested_mismatch() {
        let record = membership(MembershipLifecycle::Active);
        let key = encode_membership_key(record.workspace_id(), record.user_id()).expect("key");
        let value = encode_membership_value(&record).expect("value");
        assert_eq!(
            decode_membership_parts(&key, &value, 1, &workspace("other"), record.user_id()),
            Err(DurableRegistryEtcdStoreError::InvalidAuthority)
        );
    }

    #[test]
    fn exact_device_binding_rejects_requested_mismatch() {
        let record = registered(DeviceLifecycle::Enrolled, None, 1);
        let key = encode_device_key(&record.binding().device_id).expect("key");
        let value = encode_device_value(&record).expect("value");
        assert_eq!(
            decode_device_parts(&key, &value, 1, &device_id("other")),
            Err(DurableRegistryEtcdStoreError::InvalidAuthority)
        );
    }

    #[test]
    fn non_positive_revision_is_invalid_authority() {
        let record = membership(MembershipLifecycle::Active);
        let key = encode_membership_key(record.workspace_id(), record.user_id()).expect("key");
        let value = encode_membership_value(&record).expect("value");
        assert_eq!(
            decode_membership_parts(&key, &value, 0, record.workspace_id(), record.user_id()),
            Err(DurableRegistryEtcdStoreError::InvalidAuthority)
        );
    }

    #[test]
    fn suspension_preserves_role_and_tuple() {
        let current = membership(MembershipLifecycle::Active);
        let successor = suspend_membership_successor(&current).expect("suspend");
        assert_eq!(successor.workspace_id(), current.workspace_id());
        assert_eq!(successor.user_id(), current.user_id());
        assert_eq!(successor.role(), current.role());
        assert_eq!(successor.lifecycle(), MembershipLifecycle::Suspended);
    }

    #[test]
    fn removed_membership_cannot_be_suspended_or_removed_again() {
        let current = membership(MembershipLifecycle::Removed);
        assert_eq!(
            suspend_membership_successor(&current),
            Err(semantic(RegistryError::MembershipRemoved))
        );
        assert_eq!(
            remove_membership_successor(&current),
            Err(semantic(RegistryError::MembershipRemoved))
        );
    }

    #[test]
    fn removal_accepts_suspended_and_preserves_role() {
        let current = membership(MembershipLifecycle::Suspended);
        let successor = remove_membership_successor(&current).expect("remove");
        assert_eq!(successor.role(), current.role());
        assert_eq!(successor.lifecycle(), MembershipLifecycle::Removed);
    }

    #[test]
    fn moved_same_membership_bytes_are_currentness_conflict() {
        let before = membership_observation(membership(MembershipLifecycle::Active), 4);
        let current = membership_observation(before.record.clone(), 5);
        assert_eq!(
            classify_membership_compare_failure(&before, &current, MembershipUpdateKind::Suspend),
            Err(DurableRegistryEtcdStoreError::CurrentnessConflict)
        );
    }

    #[test]
    fn unchanged_membership_failure_shape_is_invalid_authority() {
        let before = membership_observation(membership(MembershipLifecycle::Active), 4);
        assert_eq!(
            classify_membership_compare_failure(&before, &before, MembershipUpdateKind::Suspend),
            Err(DurableRegistryEtcdStoreError::InvalidAuthority)
        );
    }

    #[test]
    fn first_bind_requires_enrolled_unbound_device() {
        let current = registered(DeviceLifecycle::Enrolled, None, 1);
        let identity = TransportIdentity::new([1; 32]).expect("transport");
        let successor = bind_transport_successor(&current, identity).expect("bind");
        assert_eq!(successor.transport_identity(), Some(identity));
        assert!(same_device_immutable_tuple(&current, &successor));
    }

    #[test]
    fn second_initial_bind_is_rejected() {
        let identity = TransportIdentity::new([2; 32]).expect("transport");
        let current = registered(DeviceLifecycle::Enrolled, Some(identity), 1);
        assert_eq!(
            bind_transport_successor(&current, identity),
            Err(semantic(RegistryError::TransportIdentityAlreadyBound))
        );
    }

    #[test]
    fn rotation_requires_exact_expected_and_distinct_replacement() {
        let current_identity = TransportIdentity::new([3; 32]).expect("current");
        let replacement = TransportIdentity::new([4; 32]).expect("replacement");
        let current = registered(DeviceLifecycle::Enrolled, Some(current_identity), 1);
        assert_eq!(
            rotate_transport_successor(&current, replacement, current_identity),
            Err(semantic(RegistryError::TransportIdentityMismatch))
        );
        assert_eq!(
            rotate_transport_successor(&current, current_identity, current_identity),
            Err(semantic(RegistryError::TransportIdentityUnchanged))
        );
        let successor =
            rotate_transport_successor(&current, current_identity, replacement).expect("rotate");
        assert_eq!(successor.transport_identity(), Some(replacement));
        assert!(same_device_immutable_tuple(&current, &successor));
    }

    #[test]
    fn revocation_preserves_transport_and_immutable_tuple() {
        let identity = TransportIdentity::new([5; 32]).expect("transport");
        let current = registered(DeviceLifecycle::Enrolled, Some(identity), 1);
        let successor = revoke_device_successor(&current).expect("revoke");
        assert_eq!(successor.binding().lifecycle, DeviceLifecycle::Revoked);
        assert_eq!(successor.transport_identity(), Some(identity));
        assert!(same_device_immutable_tuple(&current, &successor));
    }

    #[test]
    fn repeated_revocation_is_rejected() {
        let current = registered(DeviceLifecycle::Revoked, None, 1);
        assert_eq!(
            revoke_device_successor(&current),
            Err(semantic(RegistryError::DeviceRevoked))
        );
    }

    #[test]
    fn moved_same_device_bytes_are_currentness_conflict() {
        let before = device_observation(registered(DeviceLifecycle::Enrolled, None, 1), 7);
        let current = device_observation(before.record.clone(), 8);
        assert_eq!(
            classify_device_compare_failure(&before, &current, DeviceUpdateKind::Bind),
            Err(DurableRegistryEtcdStoreError::CurrentnessConflict)
        );
    }

    #[test]
    fn immutable_tuple_movement_is_invalid_authority() {
        let before = device_observation(registered(DeviceLifecycle::Enrolled, None, 1), 7);
        let current = device_observation(registered(DeviceLifecycle::Enrolled, None, 2), 8);
        assert_eq!(
            classify_device_compare_failure(&before, &current, DeviceUpdateKind::Bind),
            Err(DurableRegistryEtcdStoreError::InvalidAuthority)
        );
    }

    #[test]
    fn rotation_compare_failure_maps_stale_transport_semantics() {
        let expected = TransportIdentity::new([6; 32]).expect("expected");
        let stale = TransportIdentity::new([7; 32]).expect("stale");
        let before =
            device_observation(registered(DeviceLifecycle::Enrolled, Some(expected), 1), 9);
        let current = device_observation(registered(DeviceLifecycle::Enrolled, Some(stale), 1), 10);
        assert_eq!(
            classify_device_compare_failure(
                &before,
                &current,
                DeviceUpdateKind::Rotate { expected }
            ),
            Err(semantic(RegistryError::TransportIdentityMismatch))
        );
    }

    #[test]
    fn current_transport_requires_enrolled_and_bound() {
        let bound = TransportIdentity::new([8; 32]).expect("transport");
        assert_eq!(
            current_transport_from_device(&registered(DeviceLifecycle::Enrolled, Some(bound), 1)),
            Ok(bound)
        );
        assert_eq!(
            current_transport_from_device(&registered(DeviceLifecycle::Enrolled, None, 1)),
            Err(semantic(RegistryError::TransportIdentityMissing))
        );
        assert_eq!(
            current_transport_from_device(&registered(DeviceLifecycle::Revoked, Some(bound), 1)),
            Err(semantic(RegistryError::DeviceRevoked))
        );
    }

    #[test]
    fn presented_transport_validation_uses_exact_current_device_record() {
        let current = TransportIdentity::new([9; 32]).expect("current");
        let stale = TransportIdentity::new([10; 32]).expect("stale");
        let device = registered(DeviceLifecycle::Enrolled, Some(current), 1);
        assert_eq!(
            validate_presented_transport_from_device(&device, current),
            Ok(())
        );
        assert_eq!(
            validate_presented_transport_from_device(&device, stale),
            Err(semantic(RegistryError::TransportIdentityMismatch))
        );
        assert_eq!(
            validate_presented_transport_from_device(
                &registered(DeviceLifecycle::Enrolled, None, 1),
                current,
            ),
            Err(semantic(RegistryError::TransportIdentityMissing))
        );
    }

    #[test]
    fn session_snapshot_preserves_membership_precedence_and_identity_binding() {
        let membership = membership(MembershipLifecycle::Active);
        let device = registered(DeviceLifecycle::Enrolled, None, 1);
        let principal = validate_session_records(
            membership.workspace_id(),
            membership.user_id(),
            &device.binding().device_id,
            &device.binding().public_identity,
            &membership,
            &device,
        )
        .expect("valid session snapshot");
        assert_eq!(principal.role(), WorkspaceRole::Admin);

        let suspended = membership_observation(
            WorkspaceMembership {
                lifecycle: MembershipLifecycle::Suspended,
                ..membership.clone()
            },
            1,
        )
        .record;
        assert_eq!(
            validate_session_records(
                membership.workspace_id(),
                membership.user_id(),
                &device.binding().device_id,
                &public_identity(9),
                &suspended,
                &device,
            ),
            Err(semantic(RegistryError::MembershipNotActive))
        );
    }

    #[test]
    fn session_snapshot_rejects_public_identity_mismatch() {
        let membership = membership(MembershipLifecycle::Active);
        let device = registered(DeviceLifecycle::Enrolled, None, 1);
        assert_eq!(
            validate_session_records(
                membership.workspace_id(),
                membership.user_id(),
                &device.binding().device_id,
                &public_identity(2),
                &membership,
                &device,
            ),
            Err(semantic(RegistryError::SessionBindingMismatch))
        );
    }
}
