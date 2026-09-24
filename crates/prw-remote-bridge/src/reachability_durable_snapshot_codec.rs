//! Phase 152 C03e-HC canonical provider-neutral durable reachability snapshot value codec.
//!
//! This module materializes only the `PRWS` v1.0 value representation selected by C03e-HB. It
//! performs no database/key construction, provider call, transaction, retry, I/O, task/runtime
//! work, randomness generation, owner recovery/install, or production activation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    MAX_CONNECTIVITY_CANDIDATES, PeerConnectivityIdentity, PeerConnectivityPlanDurableState,
    TransportIdentity,
};
use prw_core::DeviceId;

use crate::{
    candidate_publication_freshness::{
        CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, CandidatePublicationFreshnessLifecycle,
        CandidatePublicationFreshnessRecord, CandidatePublicationFreshnessToken,
    },
    reachability_owner::{ReachabilityDurableSnapshot, ReachabilitySnapshotError},
};

pub const REACHABILITY_DURABLE_SNAPSHOT_MAGIC: [u8; 4] = *b"PRWS";
pub const REACHABILITY_DURABLE_SNAPSHOT_MAJOR: u16 = 1;
pub const REACHABILITY_DURABLE_SNAPSHOT_MINOR: u16 = 0;
pub const REACHABILITY_DURABLE_SNAPSHOT_HEADER_BYTES: usize = 72;
pub const REACHABILITY_DURABLE_SNAPSHOT_TRANSPORT_BYTES: usize = 32;
pub const REACHABILITY_DURABLE_SNAPSHOT_CANDIDATE_BYTES: usize = 32;
pub const REACHABILITY_DURABLE_SNAPSHOT_FIXED_BYTES: usize =
    REACHABILITY_DURABLE_SNAPSHOT_HEADER_BYTES + REACHABILITY_DURABLE_SNAPSHOT_TRANSPORT_BYTES;

const HIGH_WATER_PRESENT_FLAG: u16 = 1;
const KNOWN_STATE_FLAGS: u16 = HIGH_WATER_PRESENT_FLAG;
const CANDIDATE_ADDRESS_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReachabilityDurableSnapshotCodecError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidRecordLength,
    InvalidReservedField,
    InvalidFreshness,
    InvalidDeviceId,
    InvalidTransportIdentity,
    InvalidCandidateCount,
    InvalidCandidateId,
    InvalidPathKind,
    InvalidAddressFamily,
    InvalidEndpoint,
    InvalidHighWater,
    Snapshot(ReachabilitySnapshotError),
}

impl fmt::Display for ReachabilityDurableSnapshotCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMagic => "invalid reachability durable snapshot magic",
            Self::UnsupportedVersion => "unsupported reachability durable snapshot version",
            Self::InvalidRecordLength => "invalid reachability durable snapshot record length",
            Self::InvalidReservedField => "invalid reachability durable snapshot reserved field",
            Self::InvalidFreshness => "invalid reachability durable snapshot freshness encoding",
            Self::InvalidDeviceId => "invalid reachability durable snapshot DeviceId",
            Self::InvalidTransportIdentity => {
                "invalid reachability durable snapshot TransportIdentity"
            }
            Self::InvalidCandidateCount => "invalid reachability durable snapshot candidate count",
            Self::InvalidCandidateId => "invalid reachability durable snapshot candidate ID",
            Self::InvalidPathKind => "invalid reachability durable snapshot path kind",
            Self::InvalidAddressFamily => "invalid reachability durable snapshot address encoding",
            Self::InvalidEndpoint => "invalid reachability durable snapshot endpoint",
            Self::InvalidHighWater => "invalid reachability durable snapshot high-water encoding",
            Self::Snapshot(_) => "invalid reachability durable snapshot peer binding",
        })
    }
}

impl std::error::Error for ReachabilityDurableSnapshotCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Snapshot(error) => Some(error),
            _ => None,
        }
    }
}

/// Encodes one canonical PRWS v1.0 durable snapshot value.
///
/// # Errors
///
/// Fails closed when the typed carrier cannot fit the selected bounded canonical format.
pub fn encode_reachability_durable_snapshot(
    snapshot: &ReachabilityDurableSnapshot,
) -> Result<Vec<u8>, ReachabilityDurableSnapshotCodecError> {
    let plan = snapshot.plan();
    let freshness = snapshot.freshness();
    debug_assert_eq!(plan.peer(), freshness.peer());

    let candidates = plan.candidates();
    if candidates.len() > MAX_CONNECTIVITY_CANDIDATES {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidCandidateCount);
    }
    let candidate_count = u16::try_from(candidates.len())
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidCandidateCount)?;
    let device_bytes = plan.peer().device_id().as_str().as_bytes();
    let device_len = u64::try_from(device_bytes.len())
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let candidate_bytes = REACHABILITY_DURABLE_SNAPSHOT_CANDIDATE_BYTES
        .checked_mul(candidates.len())
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let total_len = REACHABILITY_DURABLE_SNAPSHOT_FIXED_BYTES
        .checked_add(device_bytes.len())
        .and_then(|value| value.checked_add(candidate_bytes))
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let total_len_u64 = u64::try_from(total_len)
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let (freshness_tag, freshness_bytes) = encode_freshness(freshness.lifecycle());
    let (state_flags, high_water) = plan
        .candidate_id_high_watermark()
        .map_or((0, 0), |high_water| {
            (HIGH_WATER_PRESENT_FLAG, high_water.get())
        });

    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(&REACHABILITY_DURABLE_SNAPSHOT_MAGIC);
    encoded.extend_from_slice(&REACHABILITY_DURABLE_SNAPSHOT_MAJOR.to_be_bytes());
    encoded.extend_from_slice(&REACHABILITY_DURABLE_SNAPSHOT_MINOR.to_be_bytes());
    encoded.extend_from_slice(&freshness_tag.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&total_len_u64.to_be_bytes());
    encoded.extend_from_slice(&device_len.to_be_bytes());
    encoded.extend_from_slice(&candidate_count.to_be_bytes());
    encoded.extend_from_slice(&state_flags.to_be_bytes());
    encoded.extend_from_slice(&high_water.to_be_bytes());
    encoded.extend_from_slice(&freshness_bytes);
    encoded.extend_from_slice(device_bytes);
    encoded.extend_from_slice(plan.peer().transport_identity().as_bytes());
    for candidate in candidates {
        encode_candidate(&mut encoded, *candidate);
    }
    debug_assert_eq!(encoded.len(), total_len);
    Ok(encoded)
}

/// Decodes and canonically validates one PRWS v1.0 durable snapshot value.
///
/// # Errors
///
/// Rejects malformed, unsupported, non-canonical, or invalid typed bytes without live-plan
/// restoration, persistence access, repair, or runtime behavior.
pub fn decode_reachability_durable_snapshot(
    encoded: &[u8],
) -> Result<ReachabilityDurableSnapshot, ReachabilityDurableSnapshotCodecError> {
    let mut cursor = 0;
    if read_array::<4>(encoded, &mut cursor)? != REACHABILITY_DURABLE_SNAPSHOT_MAGIC {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidMagic);
    }
    let major = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    let minor = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    if (major, minor)
        != (
            REACHABILITY_DURABLE_SNAPSHOT_MAJOR,
            REACHABILITY_DURABLE_SNAPSHOT_MINOR,
        )
    {
        return Err(ReachabilityDurableSnapshotCodecError::UnsupportedVersion);
    }
    let freshness_tag = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    if u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?) != 0 {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidReservedField);
    }
    let total_len = usize::try_from(u64::from_be_bytes(read_array::<8>(encoded, &mut cursor)?))
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let device_len = usize::try_from(u64::from_be_bytes(read_array::<8>(encoded, &mut cursor)?))
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let candidate_count = usize::from(u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?));
    if candidate_count > MAX_CONNECTIVITY_CANDIDATES {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidCandidateCount);
    }
    let state_flags = u16::from_be_bytes(read_array::<2>(encoded, &mut cursor)?);
    if state_flags & !KNOWN_STATE_FLAGS != 0 {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidReservedField);
    }
    let raw_high_water = u64::from_be_bytes(read_array::<8>(encoded, &mut cursor)?);
    let freshness_bytes =
        read_array::<CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES>(encoded, &mut cursor)?;

    let candidate_bytes = REACHABILITY_DURABLE_SNAPSHOT_CANDIDATE_BYTES
        .checked_mul(candidate_count)
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let expected_len = REACHABILITY_DURABLE_SNAPSHOT_FIXED_BYTES
        .checked_add(device_len)
        .and_then(|value| value.checked_add(candidate_bytes))
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    if total_len != expected_len || encoded.len() != expected_len {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidRecordLength);
    }

    let device_end = cursor
        .checked_add(device_len)
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let device_bytes = encoded
        .get(cursor..device_end)
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    cursor = device_end;
    let device_text = str::from_utf8(device_bytes)
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidDeviceId)?;
    let device_id = DeviceId::new(device_text)
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidDeviceId)?;
    let transport_identity = TransportIdentity::new(read_array::<32>(encoded, &mut cursor)?)
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidTransportIdentity)?;
    let peer = PeerConnectivityIdentity::new(device_id, transport_identity);

    let mut candidates = Vec::with_capacity(candidate_count);
    for _ in 0..candidate_count {
        candidates.push(decode_candidate(encoded, &mut cursor)?);
    }
    if cursor != encoded.len() {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidRecordLength);
    }

    let high_water = decode_high_water(state_flags, raw_high_water)?;
    let plan = PeerConnectivityPlanDurableState::from_parts(peer.clone(), candidates, high_water);
    let freshness = decode_freshness(peer, freshness_tag, freshness_bytes)?;
    ReachabilityDurableSnapshot::new(plan, freshness)
        .map_err(ReachabilityDurableSnapshotCodecError::Snapshot)
}

const fn encode_freshness(
    lifecycle: CandidatePublicationFreshnessLifecycle,
) -> (u16, [u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES]) {
    match lifecycle {
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(token) => {
            (1, *token.as_bytes())
        }
        CandidatePublicationFreshnessLifecycle::Established(token) => (2, *token.as_bytes()),
        CandidatePublicationFreshnessLifecycle::RecoveryRequired => (3, [0; 32]),
        CandidatePublicationFreshnessLifecycle::Retired => (4, [0; 32]),
    }
}

fn decode_freshness(
    peer: PeerConnectivityIdentity,
    tag: u16,
    bytes: [u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES],
) -> Result<CandidatePublicationFreshnessRecord, ReachabilityDurableSnapshotCodecError> {
    match tag {
        1 | 2 => {
            let token = CandidatePublicationFreshnessToken::new(bytes)
                .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidFreshness)?;
            Ok(if tag == 1 {
                CandidatePublicationFreshnessRecord::new_lifecycle_eligible(peer, token)
            } else {
                CandidatePublicationFreshnessRecord::established(peer, token)
            })
        }
        3 | 4 if bytes.iter().all(|byte| *byte == 0) => Ok(if tag == 3 {
            CandidatePublicationFreshnessRecord::recovery_required(peer)
        } else {
            CandidatePublicationFreshnessRecord::retired(peer)
        }),
        _ => Err(ReachabilityDurableSnapshotCodecError::InvalidFreshness),
    }
}

fn encode_candidate(encoded: &mut Vec<u8>, candidate: ConnectivityCandidate) {
    encoded.extend_from_slice(&candidate.id().get().to_be_bytes());
    encoded.extend_from_slice(&encode_path_kind(candidate.kind()).to_be_bytes());
    let endpoint = candidate.endpoint();
    let (family, address_bytes) = encode_address(endpoint.address());
    encoded.extend_from_slice(&family.to_be_bytes());
    encoded.extend_from_slice(&endpoint.port().to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&address_bytes);
}

fn decode_candidate(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<ConnectivityCandidate, ReachabilityDurableSnapshotCodecError> {
    let id = CandidateId::new(u64::from_be_bytes(read_array::<8>(encoded, cursor)?))
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidCandidateId)?;
    let kind = decode_path_kind(u16::from_be_bytes(read_array::<2>(encoded, cursor)?))?;
    let family = u16::from_be_bytes(read_array::<2>(encoded, cursor)?);
    let port = u16::from_be_bytes(read_array::<2>(encoded, cursor)?);
    if u16::from_be_bytes(read_array::<2>(encoded, cursor)?) != 0 {
        return Err(ReachabilityDurableSnapshotCodecError::InvalidReservedField);
    }
    let address = decode_address(family, read_array::<16>(encoded, cursor)?)?;
    let endpoint = ConnectivityEndpoint::new(address, port)
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidEndpoint)?;
    Ok(ConnectivityCandidate::new(id, kind, endpoint))
}

const fn encode_path_kind(kind: ConnectivityPathKind) -> u16 {
    match kind {
        ConnectivityPathKind::LocalDirect => 1,
        ConnectivityPathKind::InternetDirect => 2,
        ConnectivityPathKind::Relay => 3,
    }
}

const fn decode_path_kind(
    tag: u16,
) -> Result<ConnectivityPathKind, ReachabilityDurableSnapshotCodecError> {
    match tag {
        1 => Ok(ConnectivityPathKind::LocalDirect),
        2 => Ok(ConnectivityPathKind::InternetDirect),
        3 => Ok(ConnectivityPathKind::Relay),
        _ => Err(ReachabilityDurableSnapshotCodecError::InvalidPathKind),
    }
}

fn encode_address(address: IpAddr) -> (u16, [u8; CANDIDATE_ADDRESS_BYTES]) {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0; CANDIDATE_ADDRESS_BYTES];
            bytes[..4].copy_from_slice(&address.octets());
            (1, bytes)
        }
        IpAddr::V6(address) => (2, address.octets()),
    }
}

fn decode_address(
    family: u16,
    bytes: [u8; CANDIDATE_ADDRESS_BYTES],
) -> Result<IpAddr, ReachabilityDurableSnapshotCodecError> {
    match family {
        1 if bytes[4..].iter().all(|byte| *byte == 0) => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        2 => Ok(IpAddr::V6(Ipv6Addr::from(bytes))),
        _ => Err(ReachabilityDurableSnapshotCodecError::InvalidAddressFamily),
    }
}

fn decode_high_water(
    state_flags: u16,
    raw_high_water: u64,
) -> Result<Option<CandidateId>, ReachabilityDurableSnapshotCodecError> {
    match (state_flags & HIGH_WATER_PRESENT_FLAG != 0, raw_high_water) {
        (false, 0) => Ok(None),
        (false, _) | (true, 0) => Err(ReachabilityDurableSnapshotCodecError::InvalidHighWater),
        (true, value) => CandidateId::new(value)
            .map(Some)
            .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidHighWater),
    }
}

fn read_array<const N: usize>(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReachabilityDurableSnapshotCodecError> {
    let end = cursor
        .checked_add(N)
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| ReachabilityDurableSnapshotCodecError::InvalidRecordLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerConnectivityIdentity {
        PeerConnectivityIdentity::new(
            DeviceId::new("device-1").expect("device"),
            TransportIdentity::new([0x33; 32]).expect("transport"),
        )
    }

    fn token(byte: u8) -> CandidatePublicationFreshnessToken {
        CandidatePublicationFreshnessToken::new([byte; 32]).expect("token")
    }

    fn candidate(
        id: u64,
        kind: ConnectivityPathKind,
        address: IpAddr,
        port: u16,
    ) -> ConnectivityCandidate {
        ConnectivityCandidate::new(
            CandidateId::new(id).expect("candidate ID"),
            kind,
            ConnectivityEndpoint::new(address, port).expect("endpoint"),
        )
    }

    fn snapshot(
        freshness: CandidatePublicationFreshnessRecord,
        candidates: Vec<ConnectivityCandidate>,
        high_water: Option<CandidateId>,
    ) -> ReachabilityDurableSnapshot {
        ReachabilityDurableSnapshot::new(
            PeerConnectivityPlanDurableState::from_parts(peer(), candidates, high_water),
            freshness,
        )
        .expect("matching peer")
    }

    fn malformed_fixture() -> (Vec<u8>, usize, usize) {
        let snapshot = snapshot(
            CandidatePublicationFreshnessRecord::established(peer(), token(4)),
            vec![candidate(
                1,
                ConnectivityPathKind::InternetDirect,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                8000,
            )],
            Some(CandidateId::new(1).expect("high-water")),
        );
        let encoded = encode_reachability_durable_snapshot(&snapshot).expect("encode");
        let transport = REACHABILITY_DURABLE_SNAPSHOT_HEADER_BYTES + b"device-1".len();
        let candidate = transport + REACHABILITY_DURABLE_SNAPSHOT_TRANSPORT_BYTES;
        (encoded, transport, candidate)
    }

    #[test]
    fn exact_v1_bytes_and_round_trip_are_stable() {
        let snapshot = snapshot(
            CandidatePublicationFreshnessRecord::established(peer(), token(0x55)),
            vec![candidate(
                7,
                ConnectivityPathKind::InternetDirect,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                4242,
            )],
            Some(CandidateId::new(9).expect("high-water")),
        );
        let encoded = encode_reachability_durable_snapshot(&snapshot).expect("encode");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"PRWS");
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&2_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&144_u64.to_be_bytes());
        expected.extend_from_slice(&8_u64.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&9_u64.to_be_bytes());
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(b"device-1");
        expected.extend_from_slice(&[0x33; 32]);
        expected.extend_from_slice(&7_u64.to_be_bytes());
        expected.extend_from_slice(&2_u16.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&4242_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.extend_from_slice(&[203, 0, 113, 7]);
        expected.extend_from_slice(&[0; 12]);
        assert_eq!(encoded, expected);
        assert_eq!(decode_reachability_durable_snapshot(&encoded), Ok(snapshot));
    }

    #[test]
    fn lifecycle_ipv6_order_and_high_water_round_trip() {
        for freshness in [
            CandidatePublicationFreshnessRecord::new_lifecycle_eligible(peer(), token(1)),
            CandidatePublicationFreshnessRecord::established(peer(), token(2)),
            CandidatePublicationFreshnessRecord::recovery_required(peer()),
            CandidatePublicationFreshnessRecord::retired(peer()),
        ] {
            let snapshot = snapshot(
                freshness,
                vec![
                    candidate(
                        12,
                        ConnectivityPathKind::Relay,
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 12)),
                        5000,
                    ),
                    candidate(
                        4,
                        ConnectivityPathKind::LocalDirect,
                        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
                        6000,
                    ),
                ],
                Some(CandidateId::new(20).expect("high-water")),
            );
            let encoded = encode_reachability_durable_snapshot(&snapshot).expect("encode");
            assert_eq!(decode_reachability_durable_snapshot(&encoded), Ok(snapshot));
        }
    }

    #[test]
    fn empty_current_historical_high_water_and_semantic_nonrepair_are_preserved() {
        let historical = snapshot(
            CandidatePublicationFreshnessRecord::retired(peer()),
            Vec::new(),
            Some(CandidateId::new(44).expect("high-water")),
        );
        let bytes = encode_reachability_durable_snapshot(&historical).expect("encode");
        assert_eq!(decode_reachability_durable_snapshot(&bytes), Ok(historical));

        let semantically_low = snapshot(
            CandidatePublicationFreshnessRecord::established(peer(), token(3)),
            vec![candidate(
                8,
                ConnectivityPathKind::InternetDirect,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
                7000,
            )],
            Some(CandidateId::new(3).expect("high-water")),
        );
        let bytes = encode_reachability_durable_snapshot(&semantically_low).expect("encode");
        assert_eq!(
            decode_reachability_durable_snapshot(&bytes),
            Ok(semantically_low)
        );
    }

    #[test]
    fn malformed_header_and_peer_bytes_fail_closed() {
        let (encoded, transport, _) = malformed_fixture();
        let cases = [
            (0, b'X', ReachabilityDurableSnapshotCodecError::InvalidMagic),
            (
                5,
                2,
                ReachabilityDurableSnapshotCodecError::UnsupportedVersion,
            ),
            (
                11,
                1,
                ReachabilityDurableSnapshotCodecError::InvalidReservedField,
            ),
            (
                19,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidRecordLength,
            ),
            (
                9,
                9,
                ReachabilityDurableSnapshotCodecError::InvalidFreshness,
            ),
            (
                40,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidFreshness,
            ),
            (
                30,
                0x80,
                ReachabilityDurableSnapshotCodecError::InvalidReservedField,
            ),
            (
                39,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidHighWater,
            ),
            (
                REACHABILITY_DURABLE_SNAPSHOT_HEADER_BYTES,
                0xff,
                ReachabilityDurableSnapshotCodecError::InvalidDeviceId,
            ),
            (
                transport,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidTransportIdentity,
            ),
        ];
        for (offset, value, expected) in cases {
            let mut damaged = encoded.clone();
            if offset == 40 {
                damaged[40..72].fill(0);
            } else if offset == transport {
                damaged[transport..transport + 32].fill(0);
            } else if offset == 39 {
                damaged[30..32].fill(0);
                damaged[39] = 1;
            } else {
                damaged[offset] = value;
            }
            assert_eq!(
                decode_reachability_durable_snapshot(&damaged),
                Err(expected)
            );
        }
    }

    #[test]
    fn malformed_candidate_and_record_length_bytes_fail_closed() {
        let (encoded, _, candidate) = malformed_fixture();
        let cases = [
            (
                candidate + 7,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidCandidateId,
            ),
            (
                candidate + 9,
                9,
                ReachabilityDurableSnapshotCodecError::InvalidPathKind,
            ),
            (
                candidate + 14,
                1,
                ReachabilityDurableSnapshotCodecError::InvalidReservedField,
            ),
            (
                candidate + 20,
                1,
                ReachabilityDurableSnapshotCodecError::InvalidAddressFamily,
            ),
            (
                candidate + 12,
                0,
                ReachabilityDurableSnapshotCodecError::InvalidEndpoint,
            ),
        ];
        for (offset, value, expected) in cases {
            let mut damaged = encoded.clone();
            if offset == candidate + 7 {
                damaged[candidate..candidate + 8].fill(0);
            } else if offset == candidate + 12 {
                damaged[candidate + 12..candidate + 14].fill(0);
            } else {
                damaged[offset] = value;
            }
            assert_eq!(
                decode_reachability_durable_snapshot(&damaged),
                Err(expected)
            );
        }

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            decode_reachability_durable_snapshot(&truncated),
            Err(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_reachability_durable_snapshot(&trailing),
            Err(ReachabilityDurableSnapshotCodecError::InvalidRecordLength)
        );
    }

    #[test]
    fn candidate_capacity_fails_closed_on_encode_and_decode() {
        let empty_snapshot = snapshot(
            CandidatePublicationFreshnessRecord::established(peer(), token(5)),
            Vec::new(),
            None,
        );
        let canonical = encode_reachability_durable_snapshot(&empty_snapshot).expect("encode");
        assert_eq!(
            decode_reachability_durable_snapshot(&canonical),
            Ok(empty_snapshot)
        );
        let mut encoded = canonical;
        encoded[28..30].copy_from_slice(&17_u16.to_be_bytes());
        assert_eq!(
            decode_reachability_durable_snapshot(&encoded),
            Err(ReachabilityDurableSnapshotCodecError::InvalidCandidateCount)
        );

        let candidates = (1_u16..=17)
            .map(|id| {
                candidate(
                    u64::from(id),
                    ConnectivityPathKind::LocalDirect,
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                    10_000 + id,
                )
            })
            .collect();
        let overflow_snapshot = snapshot(
            CandidatePublicationFreshnessRecord::established(peer(), token(6)),
            candidates,
            Some(CandidateId::new(17).expect("high-water")),
        );
        assert_eq!(
            encode_reachability_durable_snapshot(&overflow_snapshot),
            Err(ReachabilityDurableSnapshotCodecError::InvalidCandidateCount)
        );
    }
}
