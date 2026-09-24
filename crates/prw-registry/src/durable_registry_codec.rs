//! Provider-neutral durable registry key/value codecs selected by Phase 152 C03e-IQ.
//!
//! This module materializes only canonical membership/device key and value representations plus
//! exact key/value/request binding validation. It performs no provider I/O, transaction planning,
//! retry, credential handling, runtime work, registry population, migration, or production activation.

use std::{fmt, str};

use prw_connectivity::TransportIdentity;
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
    PublicIdentityMaterial,
};
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};

use crate::{MembershipLifecycle, RegisteredDevice, WorkspaceMembership, WorkspaceRole};

/// Exact durable-registry membership key prefix selected by C03e-IQ.
pub const DURABLE_REGISTRY_MEMBERSHIP_KEY_PREFIX: &[u8] = b"/prw/registry/membership/";
/// Exact durable-registry device key prefix selected by C03e-IQ.
pub const DURABLE_REGISTRY_DEVICE_KEY_PREFIX: &[u8] = b"/prw/registry/device/";
/// Initial durable-registry key major version.
pub const DURABLE_REGISTRY_KEY_MAJOR: u16 = 1;
/// Initial durable-registry key minor version.
pub const DURABLE_REGISTRY_KEY_MINOR: u16 = 0;
/// Canonical durable-registry membership value magic.
pub const DURABLE_REGISTRY_MEMBERSHIP_MAGIC: [u8; 4] = *b"PRWM";
/// Canonical durable-registry device value magic.
pub const DURABLE_REGISTRY_DEVICE_MAGIC: [u8; 4] = *b"PRWD";
/// Initial durable-registry value major version.
pub const DURABLE_REGISTRY_VALUE_MAJOR: u16 = 1;
/// Initial durable-registry value minor version.
pub const DURABLE_REGISTRY_VALUE_MINOR: u16 = 0;
/// Maximum UTF-8 byte length of each durable-registry identifier.
pub const MAX_DURABLE_REGISTRY_IDENTIFIER_BYTES: usize = 1024;
/// Maximum byte length of the locked initial durable-registry public identity.
pub const MAX_DURABLE_REGISTRY_PUBLIC_IDENTITY_BYTES: usize = 256;
/// Exact fixed membership-value width before variable identifier bytes.
pub const DURABLE_REGISTRY_MEMBERSHIP_FIXED_BYTES: usize = 40;
/// Exact fixed device-value width before variable identity bytes.
pub const DURABLE_REGISTRY_DEVICE_FIXED_BYTES: usize = 92;
/// Exact transport-identity slot width in a durable device value.
pub const DURABLE_REGISTRY_TRANSPORT_BYTES: usize = 32;

const VERSION_BYTES: usize = 4;
const LENGTH_BYTES: usize = 8;
const MEMBERSHIP_ROLE_OWNER: u16 = 1;
const MEMBERSHIP_ROLE_ADMIN: u16 = 2;
const MEMBERSHIP_ROLE_MEMBER: u16 = 3;
const MEMBERSHIP_LIFECYCLE_ACTIVE: u16 = 1;
const MEMBERSHIP_LIFECYCLE_SUSPENDED: u16 = 2;
const MEMBERSHIP_LIFECYCLE_REMOVED: u16 = 3;
const DEVICE_IDENTITY_ALGORITHM_ECDSA_P256_SHA256: u16 = 1;
const DEVICE_IDENTITY_ENCODING_SPKI_DER: u16 = 1;
const DEVICE_LIFECYCLE_ENROLLED: u16 = 1;
const DEVICE_LIFECYCLE_REVOKED: u16 = 2;
const TRANSPORT_ABSENT: u16 = 0;
const TRANSPORT_PRESENT: u16 = 1;

/// Canonical durable-registry codec or exact-binding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableRegistryCodecError {
    /// A key does not begin with the exact selected authority-domain prefix.
    InvalidKeyPrefix,
    /// A key uses a major/minor version other than the selected v1.0 pair.
    UnsupportedKeyVersion,
    /// A key length field, total length, or checked size computation is invalid.
    InvalidKeyLength,
    /// An identifier is empty, over the selected byte bound, or invalid under its typed constructor.
    InvalidIdentifier,
    /// Identifier bytes are not valid UTF-8.
    InvalidIdentifierUtf8,
    /// A value does not begin with the expected exact record magic.
    InvalidValueMagic,
    /// A value uses a major/minor version other than the selected v1.0 pair.
    UnsupportedValueVersion,
    /// A value length field, total length, or checked size computation is invalid.
    InvalidRecordLength,
    /// A reserved field is not canonically zero.
    InvalidReservedField,
    /// A membership role code is not selected by Phase 130/C03e-IQ.
    InvalidWorkspaceRole,
    /// A membership lifecycle code is not selected by Phase 130/C03e-IQ.
    InvalidMembershipLifecycle,
    /// A durable device lifecycle is invalid or not registrable.
    InvalidDeviceLifecycle,
    /// A public-identity profile code is unsupported.
    UnsupportedPublicIdentityProfile,
    /// Public identity bytes are empty, oversized, or rejected by the typed constructor.
    InvalidPublicIdentity,
    /// A transport presence code or absent-slot representation is invalid.
    InvalidTransportPresence,
    /// Present transport bytes do not construct a valid non-zero transport identity.
    InvalidTransportIdentity,
    /// Canonical key, canonical value, and exact requested identity do not agree.
    BindingMismatch,
}

impl fmt::Display for DurableRegistryCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyPrefix => "invalid durable registry key prefix",
            Self::UnsupportedKeyVersion => "unsupported durable registry key version",
            Self::InvalidKeyLength => "invalid durable registry key length",
            Self::InvalidIdentifier => "invalid durable registry identifier",
            Self::InvalidIdentifierUtf8 => "invalid durable registry identifier UTF-8",
            Self::InvalidValueMagic => "invalid durable registry value magic",
            Self::UnsupportedValueVersion => "unsupported durable registry value version",
            Self::InvalidRecordLength => "invalid durable registry record length",
            Self::InvalidReservedField => "invalid durable registry reserved field",
            Self::InvalidWorkspaceRole => "invalid durable registry workspace role",
            Self::InvalidMembershipLifecycle => "invalid durable registry membership lifecycle",
            Self::InvalidDeviceLifecycle => "invalid durable registry device lifecycle",
            Self::UnsupportedPublicIdentityProfile => {
                "unsupported durable registry public identity profile"
            }
            Self::InvalidPublicIdentity => "invalid durable registry public identity",
            Self::InvalidTransportPresence => "invalid durable registry transport presence",
            Self::InvalidTransportIdentity => "invalid durable registry transport identity",
            Self::BindingMismatch => "durable registry key/value/request binding mismatch",
        })
    }
}

impl std::error::Error for DurableRegistryCodecError {}

/// Encodes one exact `(WorkspaceId, UserId)` into the selected durable membership key.
///
/// # Errors
///
/// Fails when either identifier violates the selected production persistence bounds or checked
/// encoded-size computation fails.
pub fn encode_membership_key(
    workspace_id: &WorkspaceId,
    user_id: &UserId,
) -> Result<Vec<u8>, DurableRegistryCodecError> {
    let workspace_bytes = bounded_identifier(workspace_id.as_str().as_bytes())?;
    let user_bytes = bounded_identifier(user_id.as_str().as_bytes())?;
    let workspace_len = u64::try_from(workspace_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidKeyLength)?;
    let user_len =
        u64::try_from(user_bytes.len()).map_err(|_| DurableRegistryCodecError::InvalidKeyLength)?;
    let capacity = DURABLE_REGISTRY_MEMBERSHIP_KEY_PREFIX
        .len()
        .checked_add(VERSION_BYTES + LENGTH_BYTES)
        .and_then(|value| value.checked_add(workspace_bytes.len()))
        .and_then(|value| value.checked_add(LENGTH_BYTES))
        .and_then(|value| value.checked_add(user_bytes.len()))
        .ok_or(DurableRegistryCodecError::InvalidKeyLength)?;

    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(DURABLE_REGISTRY_MEMBERSHIP_KEY_PREFIX);
    encoded.extend_from_slice(&DURABLE_REGISTRY_KEY_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&DURABLE_REGISTRY_KEY_MINOR.to_be_bytes());
    encoded.extend_from_slice(&workspace_len.to_be_bytes());
    encoded.extend_from_slice(workspace_bytes);
    encoded.extend_from_slice(&user_len.to_be_bytes());
    encoded.extend_from_slice(user_bytes);
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

/// Decodes one canonical durable membership key.
///
/// # Errors
///
/// Rejects a wrong prefix/version, malformed lengths, trailing bytes, invalid UTF-8, values outside
/// selected identifier bounds, or values rejected by the existing typed constructors.
pub fn decode_membership_key(
    encoded: &[u8],
) -> Result<(WorkspaceId, UserId), DurableRegistryCodecError> {
    if !encoded.starts_with(DURABLE_REGISTRY_MEMBERSHIP_KEY_PREFIX) {
        return Err(DurableRegistryCodecError::InvalidKeyPrefix);
    }
    let mut cursor = DURABLE_REGISTRY_MEMBERSHIP_KEY_PREFIX.len();
    decode_key_version(encoded, &mut cursor)?;
    let workspace_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    let workspace_bytes = read_slice(
        encoded,
        &mut cursor,
        workspace_len,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    let user_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    let user_bytes = read_slice(
        encoded,
        &mut cursor,
        user_len,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    if cursor != encoded.len() {
        return Err(DurableRegistryCodecError::InvalidKeyLength);
    }
    Ok((
        decode_workspace_id(workspace_bytes)?,
        decode_user_id(user_bytes)?,
    ))
}

/// Encodes one exact logical device identifier into the selected durable device key.
///
/// # Errors
///
/// Fails when the identifier violates the selected production persistence bounds or checked
/// encoded-size computation fails.
pub fn encode_device_key(device_id: &DeviceId) -> Result<Vec<u8>, DurableRegistryCodecError> {
    let device_bytes = bounded_identifier(device_id.as_str().as_bytes())?;
    let device_len = u64::try_from(device_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidKeyLength)?;
    let capacity = DURABLE_REGISTRY_DEVICE_KEY_PREFIX
        .len()
        .checked_add(VERSION_BYTES + LENGTH_BYTES)
        .and_then(|value| value.checked_add(device_bytes.len()))
        .ok_or(DurableRegistryCodecError::InvalidKeyLength)?;

    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(DURABLE_REGISTRY_DEVICE_KEY_PREFIX);
    encoded.extend_from_slice(&DURABLE_REGISTRY_KEY_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&DURABLE_REGISTRY_KEY_MINOR.to_be_bytes());
    encoded.extend_from_slice(&device_len.to_be_bytes());
    encoded.extend_from_slice(device_bytes);
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

/// Decodes one canonical durable device key.
///
/// # Errors
///
/// Rejects a wrong prefix/version, malformed length, trailing bytes, invalid UTF-8, values outside
/// selected identifier bounds, or values rejected by the existing typed constructor.
pub fn decode_device_key(encoded: &[u8]) -> Result<DeviceId, DurableRegistryCodecError> {
    if !encoded.starts_with(DURABLE_REGISTRY_DEVICE_KEY_PREFIX) {
        return Err(DurableRegistryCodecError::InvalidKeyPrefix);
    }
    let mut cursor = DURABLE_REGISTRY_DEVICE_KEY_PREFIX.len();
    decode_key_version(encoded, &mut cursor)?;
    let device_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    let device_bytes = read_slice(
        encoded,
        &mut cursor,
        device_len,
        DurableRegistryCodecError::InvalidKeyLength,
    )?;
    if cursor != encoded.len() {
        return Err(DurableRegistryCodecError::InvalidKeyLength);
    }
    decode_device_id(device_bytes)
}

/// Encodes one canonical `PRWM` v1.0 membership value.
///
/// # Errors
///
/// Rejects identifiers outside selected bounds or checked record-size conversion/overflow.
pub fn encode_membership_value(
    membership: &WorkspaceMembership,
) -> Result<Vec<u8>, DurableRegistryCodecError> {
    let workspace_bytes = bounded_identifier(membership.workspace_id().as_str().as_bytes())?;
    let user_bytes = bounded_identifier(membership.user_id().as_str().as_bytes())?;
    let total_len = DURABLE_REGISTRY_MEMBERSHIP_FIXED_BYTES
        .checked_add(workspace_bytes.len())
        .and_then(|value| value.checked_add(user_bytes.len()))
        .ok_or(DurableRegistryCodecError::InvalidRecordLength)?;
    let total_len_u64 =
        u64::try_from(total_len).map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let workspace_len = u64::try_from(workspace_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let user_len = u64::try_from(user_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;

    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(&DURABLE_REGISTRY_MEMBERSHIP_MAGIC);
    encoded.extend_from_slice(&DURABLE_REGISTRY_VALUE_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&DURABLE_REGISTRY_VALUE_MINOR.to_be_bytes());
    encoded.extend_from_slice(&total_len_u64.to_be_bytes());
    encoded.extend_from_slice(&workspace_len.to_be_bytes());
    encoded.extend_from_slice(&user_len.to_be_bytes());
    encoded.extend_from_slice(&encode_workspace_role(membership.role()).to_be_bytes());
    encoded.extend_from_slice(&encode_membership_lifecycle(membership.lifecycle()).to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(workspace_bytes);
    encoded.extend_from_slice(user_bytes);
    debug_assert_eq!(encoded.len(), total_len);
    Ok(encoded)
}

/// Decodes one canonical `PRWM` v1.0 membership value.
///
/// # Errors
///
/// Rejects wrong magic/version, malformed lengths, non-zero reserved data, unsupported role or
/// lifecycle codes, invalid identifiers, or trailing bytes.
pub fn decode_membership_value(
    encoded: &[u8],
) -> Result<WorkspaceMembership, DurableRegistryCodecError> {
    let mut cursor = 0;
    if read_array::<4>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )? != DURABLE_REGISTRY_MEMBERSHIP_MAGIC
    {
        return Err(DurableRegistryCodecError::InvalidValueMagic);
    }
    decode_value_version(encoded, &mut cursor)?;
    let total_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let workspace_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let user_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let role_code = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    let lifecycle_code = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    if u32::from_be_bytes(read_array::<4>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?) != 0
    {
        return Err(DurableRegistryCodecError::InvalidReservedField);
    }
    let expected_len = DURABLE_REGISTRY_MEMBERSHIP_FIXED_BYTES
        .checked_add(workspace_len)
        .and_then(|value| value.checked_add(user_len))
        .ok_or(DurableRegistryCodecError::InvalidRecordLength)?;
    if total_len != expected_len || encoded.len() != expected_len {
        return Err(DurableRegistryCodecError::InvalidRecordLength);
    }
    let workspace_bytes = read_slice(
        encoded,
        &mut cursor,
        workspace_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let user_bytes = read_slice(
        encoded,
        &mut cursor,
        user_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    debug_assert_eq!(cursor, encoded.len());
    Ok(WorkspaceMembership {
        workspace_id: decode_workspace_id(workspace_bytes)?,
        user_id: decode_user_id(user_bytes)?,
        role: decode_workspace_role(role_code)?,
        lifecycle: decode_membership_lifecycle(lifecycle_code)?,
    })
}

/// Encodes one canonical `PRWD` v1.0 registered-device value.
///
/// # Errors
///
/// Rejects unsupported/non-registrable lifecycle state, unsupported public-identity profile,
/// identifier/public-identity bounds violations, or checked record-size conversion/overflow.
pub fn encode_device_value(
    device: &RegisteredDevice,
) -> Result<Vec<u8>, DurableRegistryCodecError> {
    let binding = device.binding();
    let workspace_bytes = bounded_identifier(binding.workspace_id.as_str().as_bytes())?;
    let user_bytes = bounded_identifier(binding.user_id.as_str().as_bytes())?;
    let device_bytes = bounded_identifier(binding.device_id.as_str().as_bytes())?;
    let public_identity = binding.public_identity.as_bytes();
    if public_identity.is_empty()
        || public_identity.len() > MAX_DURABLE_REGISTRY_PUBLIC_IDENTITY_BYTES
    {
        return Err(DurableRegistryCodecError::InvalidPublicIdentity);
    }

    let algorithm_code = match binding.public_identity.algorithm() {
        DeviceIdentityAlgorithm::EcdsaP256Sha256 => DEVICE_IDENTITY_ALGORITHM_ECDSA_P256_SHA256,
        _ => return Err(DurableRegistryCodecError::UnsupportedPublicIdentityProfile),
    };
    let encoding_code = match binding.public_identity.encoding() {
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer => {
            DEVICE_IDENTITY_ENCODING_SPKI_DER
        }
        _ => return Err(DurableRegistryCodecError::UnsupportedPublicIdentityProfile),
    };
    let lifecycle_code = encode_device_lifecycle(binding.lifecycle)?;

    let (transport_presence, transport_bytes) = device.transport_identity().map_or(
        (TRANSPORT_ABSENT, [0; DURABLE_REGISTRY_TRANSPORT_BYTES]),
        |identity| (TRANSPORT_PRESENT, *identity.as_bytes()),
    );

    let total_len = DURABLE_REGISTRY_DEVICE_FIXED_BYTES
        .checked_add(workspace_bytes.len())
        .and_then(|value| value.checked_add(user_bytes.len()))
        .and_then(|value| value.checked_add(device_bytes.len()))
        .and_then(|value| value.checked_add(public_identity.len()))
        .ok_or(DurableRegistryCodecError::InvalidRecordLength)?;
    let total_len_u64 =
        u64::try_from(total_len).map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let workspace_len = u64::try_from(workspace_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let user_len = u64::try_from(user_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let device_len = u64::try_from(device_bytes.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;
    let public_identity_len = u64::try_from(public_identity.len())
        .map_err(|_| DurableRegistryCodecError::InvalidRecordLength)?;

    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(&DURABLE_REGISTRY_DEVICE_MAGIC);
    encoded.extend_from_slice(&DURABLE_REGISTRY_VALUE_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&DURABLE_REGISTRY_VALUE_MINOR.to_be_bytes());
    encoded.extend_from_slice(&total_len_u64.to_be_bytes());
    encoded.extend_from_slice(&workspace_len.to_be_bytes());
    encoded.extend_from_slice(&user_len.to_be_bytes());
    encoded.extend_from_slice(&device_len.to_be_bytes());
    encoded.extend_from_slice(&public_identity_len.to_be_bytes());
    encoded.extend_from_slice(&algorithm_code.to_be_bytes());
    encoded.extend_from_slice(&encoding_code.to_be_bytes());
    encoded.extend_from_slice(&lifecycle_code.to_be_bytes());
    encoded.extend_from_slice(&transport_presence.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&transport_bytes);
    encoded.extend_from_slice(workspace_bytes);
    encoded.extend_from_slice(user_bytes);
    encoded.extend_from_slice(device_bytes);
    encoded.extend_from_slice(public_identity);
    debug_assert_eq!(encoded.len(), total_len);
    Ok(encoded)
}

struct DeviceValueHeader {
    workspace_len: usize,
    user_len: usize,
    device_len: usize,
    public_identity_len: usize,
    algorithm_code: u16,
    encoding_code: u16,
    lifecycle_code: u16,
    transport_presence: u16,
    transport_slot: [u8; DURABLE_REGISTRY_TRANSPORT_BYTES],
    payload_offset: usize,
}

fn decode_device_value_header(
    encoded: &[u8],
) -> Result<DeviceValueHeader, DurableRegistryCodecError> {
    let mut cursor = 0;
    if read_array::<4>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )? != DURABLE_REGISTRY_DEVICE_MAGIC
    {
        return Err(DurableRegistryCodecError::InvalidValueMagic);
    }
    decode_value_version(encoded, &mut cursor)?;
    let total_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let workspace_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let user_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let device_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let public_identity_len = read_length(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let algorithm_code = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    let encoding_code = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    let lifecycle_code = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    let transport_presence = u16::from_be_bytes(read_array::<2>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    if u32::from_be_bytes(read_array::<4>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?) != 0
    {
        return Err(DurableRegistryCodecError::InvalidReservedField);
    }
    let transport_slot = read_array::<DURABLE_REGISTRY_TRANSPORT_BYTES>(
        encoded,
        &mut cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let expected_len = DURABLE_REGISTRY_DEVICE_FIXED_BYTES
        .checked_add(workspace_len)
        .and_then(|value| value.checked_add(user_len))
        .and_then(|value| value.checked_add(device_len))
        .and_then(|value| value.checked_add(public_identity_len))
        .ok_or(DurableRegistryCodecError::InvalidRecordLength)?;
    if total_len != expected_len || encoded.len() != expected_len {
        return Err(DurableRegistryCodecError::InvalidRecordLength);
    }
    Ok(DeviceValueHeader {
        workspace_len,
        user_len,
        device_len,
        public_identity_len,
        algorithm_code,
        encoding_code,
        lifecycle_code,
        transport_presence,
        transport_slot,
        payload_offset: cursor,
    })
}

/// Decodes one canonical `PRWD` v1.0 registered-device value.
///
/// # Errors
///
/// Rejects wrong magic/version, malformed lengths, non-zero reserved data, unsupported identity
/// profile/lifecycle/transport representation, invalid identifiers/public identity, or trailing bytes.
pub fn decode_device_value(encoded: &[u8]) -> Result<RegisteredDevice, DurableRegistryCodecError> {
    let header = decode_device_value_header(encoded)?;
    let mut cursor = header.payload_offset;
    let workspace_bytes = read_slice(
        encoded,
        &mut cursor,
        header.workspace_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let user_bytes = read_slice(
        encoded,
        &mut cursor,
        header.user_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let device_bytes = read_slice(
        encoded,
        &mut cursor,
        header.device_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    let public_identity_bytes = read_slice(
        encoded,
        &mut cursor,
        header.public_identity_len,
        DurableRegistryCodecError::InvalidRecordLength,
    )?;
    debug_assert_eq!(cursor, encoded.len());

    if header.algorithm_code != DEVICE_IDENTITY_ALGORITHM_ECDSA_P256_SHA256
        || header.encoding_code != DEVICE_IDENTITY_ENCODING_SPKI_DER
    {
        return Err(DurableRegistryCodecError::UnsupportedPublicIdentityProfile);
    }
    if public_identity_bytes.is_empty()
        || public_identity_bytes.len() > MAX_DURABLE_REGISTRY_PUBLIC_IDENTITY_BYTES
    {
        return Err(DurableRegistryCodecError::InvalidPublicIdentity);
    }
    let public_identity = PublicIdentityMaterial::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
        public_identity_bytes.to_vec(),
    )
    .map_err(|_| DurableRegistryCodecError::InvalidPublicIdentity)?;
    let transport_identity =
        decode_transport_identity(header.transport_presence, header.transport_slot)?;

    Ok(RegisteredDevice {
        binding: DeviceIdentityBinding {
            workspace_id: decode_workspace_id(workspace_bytes)?,
            user_id: decode_user_id(user_bytes)?,
            device_id: decode_device_id(device_bytes)?,
            public_identity,
            lifecycle: decode_device_lifecycle(header.lifecycle_code)?,
        },
        transport_identity,
    })
}

/// Decodes and verifies one exact membership key/value/request binding.
///
/// # Errors
///
/// Returns the underlying codec failure or [`DurableRegistryCodecError::BindingMismatch`] when the
/// decoded key, decoded value, and requested exact identifiers differ.
pub fn decode_bound_membership_record(
    key: &[u8],
    value: &[u8],
    requested_workspace_id: &WorkspaceId,
    requested_user_id: &UserId,
) -> Result<WorkspaceMembership, DurableRegistryCodecError> {
    let (key_workspace_id, key_user_id) = decode_membership_key(key)?;
    let membership = decode_membership_value(value)?;
    if &key_workspace_id != requested_workspace_id
        || &key_user_id != requested_user_id
        || membership.workspace_id() != requested_workspace_id
        || membership.user_id() != requested_user_id
        || membership.workspace_id() != &key_workspace_id
        || membership.user_id() != &key_user_id
    {
        return Err(DurableRegistryCodecError::BindingMismatch);
    }
    Ok(membership)
}

/// Decodes and verifies one exact device key/value/request binding.
///
/// # Errors
///
/// Returns the underlying codec failure or [`DurableRegistryCodecError::BindingMismatch`] when the
/// decoded key, decoded value, and requested exact `DeviceId` differ.
pub fn decode_bound_device_record(
    key: &[u8],
    value: &[u8],
    requested_device_id: &DeviceId,
) -> Result<RegisteredDevice, DurableRegistryCodecError> {
    let key_device_id = decode_device_key(key)?;
    let device = decode_device_value(value)?;
    if &key_device_id != requested_device_id
        || &device.binding().device_id != requested_device_id
        || device.binding().device_id != key_device_id
    {
        return Err(DurableRegistryCodecError::BindingMismatch);
    }
    Ok(device)
}

fn decode_key_version(encoded: &[u8], cursor: &mut usize) -> Result<(), DurableRegistryCodecError> {
    let major = u16::from_be_bytes(read_array::<2>(
        encoded,
        cursor,
        DurableRegistryCodecError::InvalidKeyLength,
    )?);
    let minor = u16::from_be_bytes(read_array::<2>(
        encoded,
        cursor,
        DurableRegistryCodecError::InvalidKeyLength,
    )?);
    if (major, minor) != (DURABLE_REGISTRY_KEY_MAJOR, DURABLE_REGISTRY_KEY_MINOR) {
        return Err(DurableRegistryCodecError::UnsupportedKeyVersion);
    }
    Ok(())
}

fn decode_value_version(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<(), DurableRegistryCodecError> {
    let major = u16::from_be_bytes(read_array::<2>(
        encoded,
        cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    let minor = u16::from_be_bytes(read_array::<2>(
        encoded,
        cursor,
        DurableRegistryCodecError::InvalidRecordLength,
    )?);
    if (major, minor) != (DURABLE_REGISTRY_VALUE_MAJOR, DURABLE_REGISTRY_VALUE_MINOR) {
        return Err(DurableRegistryCodecError::UnsupportedValueVersion);
    }
    Ok(())
}

const fn bounded_identifier(bytes: &[u8]) -> Result<&[u8], DurableRegistryCodecError> {
    if bytes.is_empty() || bytes.len() > MAX_DURABLE_REGISTRY_IDENTIFIER_BYTES {
        return Err(DurableRegistryCodecError::InvalidIdentifier);
    }
    Ok(bytes)
}

fn decode_workspace_id(bytes: &[u8]) -> Result<WorkspaceId, DurableRegistryCodecError> {
    let text = decode_identifier_text(bytes)?;
    WorkspaceId::new(text.to_owned()).map_err(|_| DurableRegistryCodecError::InvalidIdentifier)
}

fn decode_user_id(bytes: &[u8]) -> Result<UserId, DurableRegistryCodecError> {
    let text = decode_identifier_text(bytes)?;
    UserId::new(text.to_owned()).map_err(|_| DurableRegistryCodecError::InvalidIdentifier)
}

fn decode_device_id(bytes: &[u8]) -> Result<DeviceId, DurableRegistryCodecError> {
    let text = decode_identifier_text(bytes)?;
    DeviceId::new(text.to_owned()).map_err(|_| DurableRegistryCodecError::InvalidIdentifier)
}

fn decode_identifier_text(bytes: &[u8]) -> Result<&str, DurableRegistryCodecError> {
    bounded_identifier(bytes)?;
    str::from_utf8(bytes).map_err(|_| DurableRegistryCodecError::InvalidIdentifierUtf8)
}

const fn encode_workspace_role(role: WorkspaceRole) -> u16 {
    match role {
        WorkspaceRole::Owner => MEMBERSHIP_ROLE_OWNER,
        WorkspaceRole::Admin => MEMBERSHIP_ROLE_ADMIN,
        WorkspaceRole::Member => MEMBERSHIP_ROLE_MEMBER,
    }
}

const fn decode_workspace_role(code: u16) -> Result<WorkspaceRole, DurableRegistryCodecError> {
    match code {
        MEMBERSHIP_ROLE_OWNER => Ok(WorkspaceRole::Owner),
        MEMBERSHIP_ROLE_ADMIN => Ok(WorkspaceRole::Admin),
        MEMBERSHIP_ROLE_MEMBER => Ok(WorkspaceRole::Member),
        _ => Err(DurableRegistryCodecError::InvalidWorkspaceRole),
    }
}

const fn encode_membership_lifecycle(lifecycle: MembershipLifecycle) -> u16 {
    match lifecycle {
        MembershipLifecycle::Active => MEMBERSHIP_LIFECYCLE_ACTIVE,
        MembershipLifecycle::Suspended => MEMBERSHIP_LIFECYCLE_SUSPENDED,
        MembershipLifecycle::Removed => MEMBERSHIP_LIFECYCLE_REMOVED,
    }
}

const fn decode_membership_lifecycle(
    code: u16,
) -> Result<MembershipLifecycle, DurableRegistryCodecError> {
    match code {
        MEMBERSHIP_LIFECYCLE_ACTIVE => Ok(MembershipLifecycle::Active),
        MEMBERSHIP_LIFECYCLE_SUSPENDED => Ok(MembershipLifecycle::Suspended),
        MEMBERSHIP_LIFECYCLE_REMOVED => Ok(MembershipLifecycle::Removed),
        _ => Err(DurableRegistryCodecError::InvalidMembershipLifecycle),
    }
}

const fn encode_device_lifecycle(
    lifecycle: DeviceLifecycle,
) -> Result<u16, DurableRegistryCodecError> {
    match lifecycle {
        DeviceLifecycle::Enrolled => Ok(DEVICE_LIFECYCLE_ENROLLED),
        DeviceLifecycle::Revoked => Ok(DEVICE_LIFECYCLE_REVOKED),
        DeviceLifecycle::PendingEnrollment => {
            Err(DurableRegistryCodecError::InvalidDeviceLifecycle)
        }
    }
}

const fn decode_device_lifecycle(code: u16) -> Result<DeviceLifecycle, DurableRegistryCodecError> {
    match code {
        DEVICE_LIFECYCLE_ENROLLED => Ok(DeviceLifecycle::Enrolled),
        DEVICE_LIFECYCLE_REVOKED => Ok(DeviceLifecycle::Revoked),
        _ => Err(DurableRegistryCodecError::InvalidDeviceLifecycle),
    }
}

fn decode_transport_identity(
    presence: u16,
    slot: [u8; DURABLE_REGISTRY_TRANSPORT_BYTES],
) -> Result<Option<TransportIdentity>, DurableRegistryCodecError> {
    match presence {
        TRANSPORT_ABSENT if slot.iter().all(|byte| *byte == 0) => Ok(None),
        TRANSPORT_PRESENT => TransportIdentity::new(slot)
            .map(Some)
            .map_err(|_| DurableRegistryCodecError::InvalidTransportIdentity),
        _ => Err(DurableRegistryCodecError::InvalidTransportPresence),
    }
}

fn read_length(
    encoded: &[u8],
    cursor: &mut usize,
    error: DurableRegistryCodecError,
) -> Result<usize, DurableRegistryCodecError> {
    usize::try_from(u64::from_be_bytes(read_array::<LENGTH_BYTES>(
        encoded, cursor, error,
    )?))
    .map_err(|_| error)
}

fn read_slice<'a>(
    encoded: &'a [u8],
    cursor: &mut usize,
    length: usize,
    error: DurableRegistryCodecError,
) -> Result<&'a [u8], DurableRegistryCodecError> {
    let end = (*cursor).checked_add(length).ok_or(error)?;
    let bytes = encoded.get(*cursor..end).ok_or(error)?;
    *cursor = end;
    Ok(bytes)
}

fn read_array<const N: usize>(
    encoded: &[u8],
    cursor: &mut usize,
    error: DurableRegistryCodecError,
) -> Result<[u8; N], DurableRegistryCodecError> {
    let bytes = read_slice(encoded, cursor, N, error)?;
    bytes.try_into().map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(value: &str) -> WorkspaceId {
        WorkspaceId::new(value.to_owned()).expect("workspace id")
    }

    fn user(value: &str) -> UserId {
        UserId::new(value.to_owned()).expect("user id")
    }

    fn device_id(value: &str) -> DeviceId {
        DeviceId::new(value.to_owned()).expect("device id")
    }

    fn public_identity(bytes: Vec<u8>) -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            bytes,
        )
        .expect("public identity")
    }

    fn membership(
        workspace_value: &str,
        user_value: &str,
        role: WorkspaceRole,
        lifecycle: MembershipLifecycle,
    ) -> WorkspaceMembership {
        WorkspaceMembership {
            workspace_id: workspace(workspace_value),
            user_id: user(user_value),
            role,
            lifecycle,
        }
    }

    fn device(
        workspace_value: &str,
        user_value: &str,
        device_value: &str,
        lifecycle: DeviceLifecycle,
        transport: Option<TransportIdentity>,
    ) -> RegisteredDevice {
        RegisteredDevice {
            binding: DeviceIdentityBinding {
                workspace_id: workspace(workspace_value),
                user_id: user(user_value),
                device_id: device_id(device_value),
                public_identity: public_identity(vec![0x30, 0x01, 0x00]),
                lifecycle,
            },
            transport_identity: transport,
        }
    }

    #[test]
    fn exact_membership_and_device_key_bytes_roundtrip() {
        let workspace_id = workspace("workspace-a");
        let user_id = user("user-a");
        let device_id = device_id("device-a");

        let membership_key =
            encode_membership_key(&workspace_id, &user_id).expect("membership key encode");
        let mut expected_membership = b"/prw/registry/membership/".to_vec();
        expected_membership.extend_from_slice(&1_u16.to_be_bytes());
        expected_membership.extend_from_slice(&0_u16.to_be_bytes());
        expected_membership.extend_from_slice(&11_u64.to_be_bytes());
        expected_membership.extend_from_slice(b"workspace-a");
        expected_membership.extend_from_slice(&6_u64.to_be_bytes());
        expected_membership.extend_from_slice(b"user-a");
        assert_eq!(membership_key, expected_membership);
        assert_eq!(
            decode_membership_key(&membership_key).expect("membership key decode"),
            (workspace_id, user_id)
        );

        let device_key = encode_device_key(&device_id).expect("device key encode");
        let mut expected_device = b"/prw/registry/device/".to_vec();
        expected_device.extend_from_slice(&1_u16.to_be_bytes());
        expected_device.extend_from_slice(&0_u16.to_be_bytes());
        expected_device.extend_from_slice(&8_u64.to_be_bytes());
        expected_device.extend_from_slice(b"device-a");
        assert_eq!(device_key, expected_device);
        assert_eq!(
            decode_device_key(&device_key).expect("device key decode"),
            device_id
        );
    }

    #[test]
    fn delimiter_unicode_and_nul_identifiers_roundtrip_without_normalization() {
        let workspace_id = workspace("workspace/α:\0tail");
        let user_id = user("user/β:\0tail");
        let device_id = device_id("device/γ:\0tail");

        let membership_key =
            encode_membership_key(&workspace_id, &user_id).expect("membership key");
        assert_eq!(
            decode_membership_key(&membership_key).expect("decode membership key"),
            (workspace_id, user_id)
        );
        let device_key = encode_device_key(&device_id).expect("device key");
        assert_eq!(
            decode_device_key(&device_key).expect("decode device key"),
            device_id
        );
    }

    #[test]
    fn membership_roles_lifecycles_and_removed_state_roundtrip() {
        for (role, lifecycle) in [
            (WorkspaceRole::Owner, MembershipLifecycle::Active),
            (WorkspaceRole::Admin, MembershipLifecycle::Suspended),
            (WorkspaceRole::Member, MembershipLifecycle::Removed),
        ] {
            let source = membership("workspace", "user", role, lifecycle);
            let encoded = encode_membership_value(&source).expect("membership value encode");
            assert_eq!(encoded.len(), DURABLE_REGISTRY_MEMBERSHIP_FIXED_BYTES + 13);
            assert_eq!(
                decode_membership_value(&encoded).expect("membership value decode"),
                source
            );
        }
    }

    #[test]
    fn device_enrolled_unbound_bound_and_revoked_states_roundtrip() {
        let transport = TransportIdentity::new([0x5a; 32]).expect("transport identity");
        for source in [
            device(
                "workspace",
                "user",
                "device",
                DeviceLifecycle::Enrolled,
                None,
            ),
            device(
                "workspace",
                "user",
                "device",
                DeviceLifecycle::Enrolled,
                Some(transport),
            ),
            device(
                "workspace",
                "user",
                "device",
                DeviceLifecycle::Revoked,
                Some(transport),
            ),
        ] {
            let encoded = encode_device_value(&source).expect("device value encode");
            assert_eq!(
                decode_device_value(&encoded).expect("device value decode"),
                source
            );
        }
    }

    #[test]
    fn pending_device_and_out_of_bounds_identity_fail_before_encoding() {
        let pending = device(
            "workspace",
            "user",
            "device",
            DeviceLifecycle::PendingEnrollment,
            None,
        );
        assert_eq!(
            encode_device_value(&pending),
            Err(DurableRegistryCodecError::InvalidDeviceLifecycle)
        );

        let oversized = "x".repeat(MAX_DURABLE_REGISTRY_IDENTIFIER_BYTES + 1);
        assert_eq!(
            encode_device_key(&device_id(&oversized)),
            Err(DurableRegistryCodecError::InvalidIdentifier)
        );

        let oversized_public = RegisteredDevice {
            binding: DeviceIdentityBinding {
                workspace_id: workspace("workspace"),
                user_id: user("user"),
                device_id: device_id("device"),
                public_identity: public_identity(vec![
                    0x31;
                    MAX_DURABLE_REGISTRY_PUBLIC_IDENTITY_BYTES
                        + 1
                ]),
                lifecycle: DeviceLifecycle::Enrolled,
            },
            transport_identity: None,
        };
        assert_eq!(
            encode_device_value(&oversized_public),
            Err(DurableRegistryCodecError::InvalidPublicIdentity)
        );
    }

    #[test]
    fn malformed_keys_versions_lengths_utf8_and_trailing_bytes_fail_closed() {
        let source = encode_device_key(&device_id("device")).expect("device key");
        let version_offset = DURABLE_REGISTRY_DEVICE_KEY_PREFIX.len();
        let length_offset = version_offset + VERSION_BYTES;
        let device_offset = length_offset + LENGTH_BYTES;

        let mut wrong_prefix = source.clone();
        wrong_prefix[0] ^= 1;
        assert_eq!(
            decode_device_key(&wrong_prefix),
            Err(DurableRegistryCodecError::InvalidKeyPrefix)
        );

        let mut wrong_version = source.clone();
        wrong_version[version_offset..version_offset + 2].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_device_key(&wrong_version),
            Err(DurableRegistryCodecError::UnsupportedKeyVersion)
        );

        let mut wrong_length = source.clone();
        wrong_length[length_offset..length_offset + LENGTH_BYTES]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            decode_device_key(&wrong_length),
            Err(DurableRegistryCodecError::InvalidKeyLength)
        );

        let mut invalid_utf8 = source.clone();
        invalid_utf8[device_offset] = 0xff;
        assert_eq!(
            decode_device_key(&invalid_utf8),
            Err(DurableRegistryCodecError::InvalidIdentifierUtf8)
        );

        let mut trailing = source;
        trailing.push(0);
        assert_eq!(
            decode_device_key(&trailing),
            Err(DurableRegistryCodecError::InvalidKeyLength)
        );
    }

    #[test]
    fn malformed_membership_value_fields_fail_closed() {
        let source = encode_membership_value(&membership(
            "workspace",
            "user",
            WorkspaceRole::Owner,
            MembershipLifecycle::Active,
        ))
        .expect("membership value");

        let mut wrong_magic = source.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            decode_membership_value(&wrong_magic),
            Err(DurableRegistryCodecError::InvalidValueMagic)
        );

        let mut wrong_version = source.clone();
        wrong_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_membership_value(&wrong_version),
            Err(DurableRegistryCodecError::UnsupportedValueVersion)
        );

        let mut wrong_role = source.clone();
        wrong_role[32..34].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            decode_membership_value(&wrong_role),
            Err(DurableRegistryCodecError::InvalidWorkspaceRole)
        );

        let mut reserved = source;
        reserved[36..40].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            decode_membership_value(&reserved),
            Err(DurableRegistryCodecError::InvalidReservedField)
        );
    }

    #[test]
    fn malformed_device_transport_profile_and_lifecycle_fail_closed() {
        let transport = TransportIdentity::new([0x7b; 32]).expect("transport identity");
        let source = encode_device_value(&device(
            "workspace",
            "user",
            "device",
            DeviceLifecycle::Enrolled,
            Some(transport),
        ))
        .expect("device value");

        let mut unsupported_profile = source.clone();
        unsupported_profile[48..50].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_device_value(&unsupported_profile),
            Err(DurableRegistryCodecError::UnsupportedPublicIdentityProfile)
        );

        let mut pending_lifecycle = source.clone();
        pending_lifecycle[52..54].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            decode_device_value(&pending_lifecycle),
            Err(DurableRegistryCodecError::InvalidDeviceLifecycle)
        );

        let mut invalid_presence = source.clone();
        invalid_presence[54..56].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_device_value(&invalid_presence),
            Err(DurableRegistryCodecError::InvalidTransportPresence)
        );

        let mut absent_nonzero = source;
        absent_nonzero[54..56].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            decode_device_value(&absent_nonzero),
            Err(DurableRegistryCodecError::InvalidTransportPresence)
        );

        let mut present_zero = encode_device_value(&device(
            "workspace",
            "user",
            "device",
            DeviceLifecycle::Enrolled,
            None,
        ))
        .expect("unbound value");
        present_zero[54..56].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_device_value(&present_zero),
            Err(DurableRegistryCodecError::InvalidTransportIdentity)
        );
    }

    #[test]
    fn exact_key_value_request_binding_is_mandatory() {
        let membership = membership(
            "workspace-a",
            "user-a",
            WorkspaceRole::Admin,
            MembershipLifecycle::Active,
        );
        let membership_key =
            encode_membership_key(membership.workspace_id(), membership.user_id()).expect("key");
        let membership_value = encode_membership_value(&membership).expect("value");
        assert_eq!(
            decode_bound_membership_record(
                &membership_key,
                &membership_value,
                membership.workspace_id(),
                membership.user_id(),
            )
            .expect("bound membership"),
            membership
        );
        assert_eq!(
            decode_bound_membership_record(
                &membership_key,
                &membership_value,
                &workspace("workspace-b"),
                membership.user_id(),
            ),
            Err(DurableRegistryCodecError::BindingMismatch)
        );

        let device = device(
            "workspace-a",
            "user-a",
            "device-a",
            DeviceLifecycle::Enrolled,
            Some(TransportIdentity::new([0x11; 32]).expect("transport")),
        );
        let device_key = encode_device_key(&device.binding().device_id).expect("key");
        let device_value = encode_device_value(&device).expect("value");
        assert_eq!(
            decode_bound_device_record(&device_key, &device_value, &device.binding().device_id)
                .expect("bound device"),
            device
        );
        assert_eq!(
            decode_bound_device_record(&device_key, &device_value, &device_id("device-b")),
            Err(DurableRegistryCodecError::BindingMismatch)
        );
    }
}
