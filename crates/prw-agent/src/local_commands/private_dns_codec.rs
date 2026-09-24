//! Bounded binary codec for the Phase 026 private-DNS IPC snapshot.

use std::str;

use prw_network::PrivateDnsConfig;

use super::private_dns_snapshot::{
    LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES, LOCAL_PRIVATE_DNS_MAX_RESOLVERS,
    LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES, LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS,
    LocalPrivateDnsSnapshot, LocalPrivateDnsSnapshotError,
};

/// Fixed Phase 027 header length: flags + resolver count + split-domain count.
pub const LOCAL_PRIVATE_DNS_CODEC_HEADER_LENGTH: usize = 3;
/// Maximum encoded Phase 027 snapshot length in bytes.
pub const LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH: usize = 18_403;

const FLAG_ENABLED: u8 = 0b0000_0001;
const FLAG_DEVICE_NAMING: u8 = 0b0000_0010;
const ALLOWED_FLAGS: u8 = FLAG_ENABLED | FLAG_DEVICE_NAMING;

/// Returns the exact encoded byte length for a validated snapshot.
#[must_use]
pub fn encoded_private_dns_snapshot_len(snapshot: &LocalPrivateDnsSnapshot) -> usize {
    LOCAL_PRIVATE_DNS_CODEC_HEADER_LENGTH
        + snapshot
            .resolvers()
            .iter()
            .map(|value| 2 + value.len())
            .sum::<usize>()
        + snapshot
            .split_domains()
            .iter()
            .map(|value| 2 + value.len())
            .sum::<usize>()
}

/// Encodes one validated private-DNS snapshot into the Phase 027 byte format.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsEncodeError`] if an internal snapshot invariant can
/// no longer be represented by the locked one-byte list counts or two-byte
/// entry lengths. Public snapshot construction prevents these states, but the
/// encoder remains defensive and non-panicking.
pub fn encode_private_dns_snapshot(
    snapshot: &LocalPrivateDnsSnapshot,
) -> Result<Vec<u8>, LocalPrivateDnsEncodeError> {
    let mut flags = 0_u8;
    if snapshot.enabled() {
        flags |= FLAG_ENABLED;
    }
    if snapshot.device_naming() {
        flags |= FLAG_DEVICE_NAMING;
    }

    let resolver_count = u8::try_from(snapshot.resolvers().len())
        .map_err(|_| LocalPrivateDnsEncodeError::ResolverCountInvariant)?;
    let split_domain_count = u8::try_from(snapshot.split_domains().len())
        .map_err(|_| LocalPrivateDnsEncodeError::SplitDomainCountInvariant)?;

    let mut output = Vec::with_capacity(encoded_private_dns_snapshot_len(snapshot));
    output.push(flags);
    output.push(resolver_count);
    output.push(split_domain_count);
    for resolver in snapshot.resolvers() {
        append_string(&mut output, resolver)?;
    }
    for domain in snapshot.split_domains() {
        append_string(&mut output, domain)?;
    }
    Ok(output)
}

/// Decodes one exact Phase 027 private-DNS snapshot body.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsDecodeError`] for truncated/invalid header fields,
/// disallowed flag bits, count or entry bounds violations, invalid UTF-8,
/// truncated entries, trailing bytes, or a final snapshot-invariant failure.
pub fn decode_private_dns_snapshot(
    payload: &[u8],
) -> Result<LocalPrivateDnsSnapshot, LocalPrivateDnsDecodeError> {
    if payload.len() < LOCAL_PRIVATE_DNS_CODEC_HEADER_LENGTH {
        return Err(LocalPrivateDnsDecodeError::HeaderTruncated);
    }

    let flags = payload[0];
    if flags & !ALLOWED_FLAGS != 0 {
        return Err(LocalPrivateDnsDecodeError::ReservedFlagsSet);
    }
    let resolver_count = usize::from(payload[1]);
    let split_domain_count = usize::from(payload[2]);
    if resolver_count > LOCAL_PRIVATE_DNS_MAX_RESOLVERS {
        return Err(LocalPrivateDnsDecodeError::TooManyResolvers);
    }
    if split_domain_count > LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS {
        return Err(LocalPrivateDnsDecodeError::TooManySplitDomains);
    }

    let mut cursor = LOCAL_PRIVATE_DNS_CODEC_HEADER_LENGTH;
    let mut resolvers = Vec::with_capacity(resolver_count);
    for _ in 0..resolver_count {
        resolvers.push(read_string(
            payload,
            &mut cursor,
            LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES,
        )?);
    }

    let mut split_domains = Vec::with_capacity(split_domain_count);
    for _ in 0..split_domain_count {
        split_domains.push(read_string(
            payload,
            &mut cursor,
            LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES,
        )?);
    }

    if cursor != payload.len() {
        return Err(LocalPrivateDnsDecodeError::TrailingBytes);
    }

    let config = PrivateDnsConfig {
        enabled: flags & FLAG_ENABLED != 0,
        device_naming: flags & FLAG_DEVICE_NAMING != 0,
        resolvers,
        split_domains,
    };
    LocalPrivateDnsSnapshot::try_from_config(&config)
        .map_err(LocalPrivateDnsDecodeError::SnapshotInvariant)
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), LocalPrivateDnsEncodeError> {
    let length =
        u16::try_from(value.len()).map_err(|_| LocalPrivateDnsEncodeError::EntryLengthInvariant)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_string(
    payload: &[u8],
    cursor: &mut usize,
    maximum_length: usize,
) -> Result<String, LocalPrivateDnsDecodeError> {
    if payload.len().saturating_sub(*cursor) < 2 {
        return Err(LocalPrivateDnsDecodeError::EntryLengthTruncated);
    }
    let length = usize::from(u16::from_be_bytes([payload[*cursor], payload[*cursor + 1]]));
    *cursor += 2;

    if length == 0 {
        return Err(LocalPrivateDnsDecodeError::EmptyEntry);
    }
    if length > maximum_length {
        return Err(LocalPrivateDnsDecodeError::EntryTooLong);
    }
    if payload.len().saturating_sub(*cursor) < length {
        return Err(LocalPrivateDnsDecodeError::EntryTruncated);
    }

    let end = *cursor + length;
    let value = str::from_utf8(&payload[*cursor..end])
        .map_err(|_| LocalPrivateDnsDecodeError::InvalidUtf8)?
        .to_owned();
    *cursor = end;
    Ok(value)
}

/// Defensive Phase 027 private-DNS snapshot encoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsEncodeError {
    /// Resolver count cannot be represented by the locked one-byte count field.
    ResolverCountInvariant,
    /// Split-domain count cannot be represented by the locked one-byte count field.
    SplitDomainCountInvariant,
    /// An entry length cannot be represented by the locked two-byte length field.
    EntryLengthInvariant,
}

/// Fail-closed Phase 027 private-DNS snapshot decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsDecodeError {
    /// Fewer than three fixed header bytes are present.
    HeaderTruncated,
    /// One or more reserved flag bits are non-zero.
    ReservedFlagsSet,
    /// Resolver count exceeds the Phase 026 bound.
    TooManyResolvers,
    /// Split-domain count exceeds the Phase 026 bound.
    TooManySplitDomains,
    /// A required two-byte string-length field is incomplete.
    EntryLengthTruncated,
    /// An entry uses zero length.
    EmptyEntry,
    /// An entry exceeds its list-specific Phase 026 byte-length bound.
    EntryTooLong,
    /// The declared entry bytes are truncated.
    EntryTruncated,
    /// Entry bytes are not valid UTF-8.
    InvalidUtf8,
    /// Bytes remain after all declared entries are decoded.
    TrailingBytes,
    /// Defensive final projection validation failed.
    SnapshotInvariant(LocalPrivateDnsSnapshotError),
}

#[cfg(test)]
mod tests {
    use super::{
        LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH, LocalPrivateDnsDecodeError,
        decode_private_dns_snapshot, encode_private_dns_snapshot, encoded_private_dns_snapshot_len,
    };
    use crate::local_commands::private_dns_snapshot::{
        LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES, LOCAL_PRIVATE_DNS_MAX_RESOLVERS,
        LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES, LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS,
        LocalPrivateDnsSnapshot,
    };
    use prw_network::PrivateDnsConfig;

    fn snapshot(config: &PrivateDnsConfig) -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(config).expect("bounded test config")
    }

    fn encode(snapshot: &LocalPrivateDnsSnapshot) -> Vec<u8> {
        encode_private_dns_snapshot(snapshot).expect("validated snapshot encodes")
    }

    #[test]
    fn default_snapshot_has_stable_three_byte_encoding() {
        let snapshot = snapshot(&PrivateDnsConfig::default());
        assert_eq!(encode(&snapshot), [0, 0, 0]);
        assert_eq!(decode_private_dns_snapshot(&[0, 0, 0]), Ok(snapshot));
    }

    #[test]
    fn flags_lists_and_utf8_round_trip_exactly() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into(), "fd00::53".into()],
            split_domains: vec!["corp.example".into(), "láb.example".into()],
        };
        let snapshot = snapshot(&config);
        let encoded = encode(&snapshot);

        assert_eq!(encoded[0], 0b11);
        assert_eq!(encoded[1], 2);
        assert_eq!(encoded[2], 2);
        assert_eq!(encoded.len(), encoded_private_dns_snapshot_len(&snapshot));
        assert_eq!(decode_private_dns_snapshot(&encoded), Ok(snapshot));
    }

    #[test]
    fn maximum_snapshot_matches_locked_encoded_bound() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec![
                "r".repeat(LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES);
                LOCAL_PRIVATE_DNS_MAX_RESOLVERS
            ],
            split_domains: vec![
                "d".repeat(LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES);
                LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS
            ],
        };
        let snapshot = snapshot(&config);
        let encoded = encode(&snapshot);

        assert_eq!(encoded.len(), LOCAL_PRIVATE_DNS_MAX_ENCODED_LENGTH);
        assert_eq!(decode_private_dns_snapshot(&encoded), Ok(snapshot));
    }

    #[test]
    fn header_flags_and_counts_fail_closed() {
        assert_eq!(
            decode_private_dns_snapshot(&[0, 0]),
            Err(LocalPrivateDnsDecodeError::HeaderTruncated)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0b100, 0, 0]),
            Err(LocalPrivateDnsDecodeError::ReservedFlagsSet)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 17, 0]),
            Err(LocalPrivateDnsDecodeError::TooManyResolvers)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 0, 65]),
            Err(LocalPrivateDnsDecodeError::TooManySplitDomains)
        );
    }

    #[test]
    fn entry_boundaries_and_utf8_fail_closed() {
        assert_eq!(
            decode_private_dns_snapshot(&[0, 1, 0, 0]),
            Err(LocalPrivateDnsDecodeError::EntryLengthTruncated)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 1, 0, 0, 0]),
            Err(LocalPrivateDnsDecodeError::EmptyEntry)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 1, 0, 0, 129]),
            Err(LocalPrivateDnsDecodeError::EntryTooLong)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 1, 0, 0, 2, b'a']),
            Err(LocalPrivateDnsDecodeError::EntryTruncated)
        );
        assert_eq!(
            decode_private_dns_snapshot(&[0, 1, 0, 0, 1, 0xff]),
            Err(LocalPrivateDnsDecodeError::InvalidUtf8)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            decode_private_dns_snapshot(&[0, 0, 0, 9]),
            Err(LocalPrivateDnsDecodeError::TrailingBytes)
        );
    }
}
