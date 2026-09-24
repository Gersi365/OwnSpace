//! Phase 152 C03e-HE canonical provider-neutral durable reachability snapshot database-key codec.
//!
//! This module materializes only the exact durable-snapshot key/keyspace representation selected by
//! C03e-HD. It performs no durable value encoding, provider call, transaction/CAS operation, retry,
//! I/O, credential handling, task/runtime work, owner recovery/install, or production activation.

use std::{fmt, str};

use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_core::DeviceId;

/// Exact durable-snapshot database-key domain prefix selected by C03e-HD.
pub const REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX: &[u8] = b"/prw/reachability/durable-snapshot/";
/// Initial durable-snapshot database-key major version.
pub const REACHABILITY_DURABLE_SNAPSHOT_KEY_MAJOR: u16 = 1;
/// Initial durable-snapshot database-key minor version.
pub const REACHABILITY_DURABLE_SNAPSHOT_KEY_MINOR: u16 = 0;
/// Exact encoded transport-identity width in the durable-snapshot database key.
pub const REACHABILITY_DURABLE_SNAPSHOT_KEY_TRANSPORT_BYTES: usize = 32;

const DEVICE_ID_LENGTH_BYTES: usize = 8;
const KEY_VERSION_BYTES: usize = 4;

/// Fail-closed canonical durable-snapshot database-key validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityDurableSnapshotKeyCodecError {
    /// Key does not start with the exact durable-snapshot authority-domain prefix.
    InvalidKeyPrefix,
    /// Key major/minor version is not the selected v1.0 pair.
    UnsupportedKeyVersion,
    /// Key length field or total encoded length is invalid/non-canonical.
    InvalidKeyLength,
    /// `DeviceId` bytes are invalid UTF-8 or violate the existing typed constructor.
    InvalidDeviceId,
    /// `TransportIdentity` bytes violate the existing typed constructor.
    InvalidTransportIdentity,
    /// Host-size/capacity conversion overflow prevented canonical encoding.
    LengthOverflow,
}

impl fmt::Display for ReachabilityDurableSnapshotKeyCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyPrefix => "invalid reachability durable snapshot key prefix",
            Self::UnsupportedKeyVersion => "unsupported reachability durable snapshot key version",
            Self::InvalidKeyLength => "invalid reachability durable snapshot key length",
            Self::InvalidDeviceId => "invalid reachability durable snapshot key DeviceId bytes",
            Self::InvalidTransportIdentity => {
                "invalid reachability durable snapshot key TransportIdentity bytes"
            }
            Self::LengthOverflow => "reachability durable snapshot key length overflow",
        })
    }
}

impl std::error::Error for ReachabilityDurableSnapshotKeyCodecError {}

/// Encodes one exact peer into the selected canonical durable-snapshot database key.
///
/// # Errors
///
/// Returns [`ReachabilityDurableSnapshotKeyCodecError::LengthOverflow`] when the source `DeviceId`
/// length or encoded key capacity cannot be represented canonically.
pub fn encode_reachability_durable_snapshot_key(
    peer: &PeerConnectivityIdentity,
) -> Result<Vec<u8>, ReachabilityDurableSnapshotKeyCodecError> {
    let device_bytes = peer.device_id().as_str().as_bytes();
    let device_len = u64::try_from(device_bytes.len())
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::LengthOverflow)?;
    let capacity = REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX
        .len()
        .checked_add(KEY_VERSION_BYTES + DEVICE_ID_LENGTH_BYTES)
        .and_then(|value| value.checked_add(device_bytes.len()))
        .and_then(|value| value.checked_add(REACHABILITY_DURABLE_SNAPSHOT_KEY_TRANSPORT_BYTES))
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::LengthOverflow)?;

    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX);
    encoded.extend_from_slice(&REACHABILITY_DURABLE_SNAPSHOT_KEY_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&REACHABILITY_DURABLE_SNAPSHOT_KEY_MINOR.to_be_bytes());
    encoded.extend_from_slice(&device_len.to_be_bytes());
    encoded.extend_from_slice(device_bytes);
    encoded.extend_from_slice(peer.transport_identity().as_bytes());
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

/// Decodes and canonically validates one selected durable-snapshot database key.
///
/// # Errors
///
/// Rejects malformed, unsupported, non-canonical, or invalid typed key bytes. Decoding performs no
/// provider access, durable-value repair, peer substitution, or owner installation.
pub fn decode_reachability_durable_snapshot_key(
    encoded: &[u8],
) -> Result<PeerConnectivityIdentity, ReachabilityDurableSnapshotKeyCodecError> {
    if !encoded.starts_with(REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX) {
        return Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyPrefix);
    }

    let mut cursor = REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX.len();
    let major = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    let minor = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    if (major, minor)
        != (
            REACHABILITY_DURABLE_SNAPSHOT_KEY_MAJOR,
            REACHABILITY_DURABLE_SNAPSHOT_KEY_MINOR,
        )
    {
        return Err(ReachabilityDurableSnapshotKeyCodecError::UnsupportedKeyVersion);
    }

    let device_len = usize::try_from(u64::from_be_bytes(read_array::<8>(encoded, &mut cursor)?))
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    let expected_len = cursor
        .checked_add(device_len)
        .and_then(|value| value.checked_add(REACHABILITY_DURABLE_SNAPSHOT_KEY_TRANSPORT_BYTES))
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    if encoded.len() != expected_len {
        return Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength);
    }

    let device_end = cursor
        .checked_add(device_len)
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    let device_bytes = encoded
        .get(cursor..device_end)
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    cursor = device_end;
    let device_text = str::from_utf8(device_bytes)
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::InvalidDeviceId)?;
    let device_id = DeviceId::new(device_text.to_owned())
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::InvalidDeviceId)?;

    let transport_bytes =
        read_array::<REACHABILITY_DURABLE_SNAPSHOT_KEY_TRANSPORT_BYTES>(encoded, &mut cursor)?;
    let transport_identity = TransportIdentity::new(transport_bytes)
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::InvalidTransportIdentity)?;
    debug_assert_eq!(cursor, encoded.len());

    Ok(PeerConnectivityIdentity::new(device_id, transport_identity))
}

fn read_array<const N: usize>(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReachabilityDurableSnapshotKeyCodecError> {
    let end = (*cursor)
        .checked_add(N)
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    let array = bytes
        .try_into()
        .map_err(|_| ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)?;
    *cursor = end;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(device_id: &str, transport_fill: u8) -> PeerConnectivityIdentity {
        let device_id = DeviceId::new(device_id.to_owned()).expect("valid DeviceId");
        let transport_identity =
            TransportIdentity::new([transport_fill; 32]).expect("non-zero transport identity");
        PeerConnectivityIdentity::new(device_id, transport_identity)
    }

    #[test]
    fn exact_v1_key_bytes_and_roundtrip_match_selected_layout() {
        let source = peer("device-a", 0xa5);
        let encoded = encode_reachability_durable_snapshot_key(&source).expect("encode key");

        let mut expected = b"/prw/reachability/durable-snapshot/".to_vec();
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&8_u64.to_be_bytes());
        expected.extend_from_slice(b"device-a");
        expected.extend_from_slice(&[0xa5; 32]);

        assert_eq!(encoded, expected);
        assert_eq!(
            decode_reachability_durable_snapshot_key(&encoded).expect("decode key"),
            source
        );
    }

    #[test]
    fn delimiter_like_unicode_and_nul_device_bytes_roundtrip_without_normalization() {
        let source = peer("device/α:β\0tail", 0x31);
        let encoded = encode_reachability_durable_snapshot_key(&source).expect("encode key");
        let decoded = decode_reachability_durable_snapshot_key(&encoded).expect("decode key");

        assert_eq!(decoded, source);
        assert!(encoded.starts_with(REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX));
    }

    #[test]
    fn distinct_exact_peers_encode_to_distinct_keys() {
        let one = encode_reachability_durable_snapshot_key(&peer("device/a", 0x11))
            .expect("encode first key");
        let different_device = encode_reachability_durable_snapshot_key(&peer("device:a", 0x11))
            .expect("encode second key");
        let different_transport = encode_reachability_durable_snapshot_key(&peer("device/a", 0x12))
            .expect("encode third key");

        assert_ne!(one, different_device);
        assert_ne!(one, different_transport);
        assert_ne!(different_device, different_transport);
    }

    #[test]
    fn decoder_rejects_wrong_prefix_versions_lengths_utf8_transport_and_trailing_bytes() {
        let canonical =
            encode_reachability_durable_snapshot_key(&peer("valid", 0x44)).expect("encode key");
        let version_offset = REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX.len();
        let device_length_offset = version_offset + KEY_VERSION_BYTES;
        let device_offset = device_length_offset + DEVICE_ID_LENGTH_BYTES;

        let mut wrong_prefix = canonical.clone();
        wrong_prefix[0] ^= 1;
        assert_eq!(
            decode_reachability_durable_snapshot_key(&wrong_prefix),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyPrefix)
        );

        let mut wrong_major = canonical.clone();
        wrong_major[version_offset..version_offset + 2].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_reachability_durable_snapshot_key(&wrong_major),
            Err(ReachabilityDurableSnapshotKeyCodecError::UnsupportedKeyVersion)
        );

        let mut wrong_minor = canonical.clone();
        wrong_minor[version_offset + 2..version_offset + 4].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_reachability_durable_snapshot_key(&wrong_minor),
            Err(ReachabilityDurableSnapshotKeyCodecError::UnsupportedKeyVersion)
        );

        let mut oversized_device = canonical.clone();
        oversized_device[device_length_offset..device_length_offset + DEVICE_ID_LENGTH_BYTES]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            decode_reachability_durable_snapshot_key(&oversized_device),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)
        );

        let mut invalid_utf8 = canonical.clone();
        invalid_utf8[device_offset] = 0xff;
        assert_eq!(
            decode_reachability_durable_snapshot_key(&invalid_utf8),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidDeviceId)
        );

        let mut zero_transport = canonical.clone();
        let transport_offset =
            zero_transport.len() - REACHABILITY_DURABLE_SNAPSHOT_KEY_TRANSPORT_BYTES;
        zero_transport[transport_offset..].fill(0);
        assert_eq!(
            decode_reachability_durable_snapshot_key(&zero_transport),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidTransportIdentity)
        );

        let truncated = &canonical[..canonical.len() - 1];
        assert_eq!(
            decode_reachability_durable_snapshot_key(truncated),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)
        );

        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode_reachability_durable_snapshot_key(&trailing),
            Err(ReachabilityDurableSnapshotKeyCodecError::InvalidKeyLength)
        );
    }

    #[test]
    fn every_fixed_field_boundary_truncation_fails_closed() {
        let canonical =
            encode_reachability_durable_snapshot_key(&peer("boundary", 0x55)).expect("encode key");
        let prefix = REACHABILITY_DURABLE_SNAPSHOT_KEY_PREFIX.len();
        let boundaries = [
            0,
            prefix.saturating_sub(1),
            prefix,
            prefix + 1,
            prefix + KEY_VERSION_BYTES - 1,
            prefix + KEY_VERSION_BYTES,
            prefix + KEY_VERSION_BYTES + DEVICE_ID_LENGTH_BYTES - 1,
        ];

        for boundary in boundaries {
            assert!(
                decode_reachability_durable_snapshot_key(&canonical[..boundary]).is_err(),
                "truncation at byte {boundary} must fail closed"
            );
        }
    }
}
