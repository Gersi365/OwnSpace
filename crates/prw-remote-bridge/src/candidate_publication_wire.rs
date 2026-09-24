//! Pure bounded candidate-publication inner wire codec.
//!
//! Phase 152 C03e-BQ materializes only the BP-selected `PRWP` v1.0 publisher candidate-set
//! submission representation. This module performs no PRWC wrapping, request correlation,
//! authentication, routing, publication admission, freshness rotation, socket I/O, candidate
//! discovery/classification, reachability mutation, networking activation, or deployment.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    MAX_CONNECTIVITY_CANDIDATES, TransportIdentity,
};

use crate::candidate_publication_freshness::CandidatePublicationFreshnessToken;

/// Exact inner payload magic for candidate publication.
pub const CANDIDATE_PUBLICATION_WIRE_MAGIC: [u8; 4] = *b"PRWP";
/// Initial candidate-publication inner wire major version.
pub const CANDIDATE_PUBLICATION_WIRE_MAJOR: u16 = 1;
/// Initial candidate-publication inner wire minor version.
pub const CANDIDATE_PUBLICATION_WIRE_MINOR: u16 = 0;
/// Publisher candidate-set submission operation tag.
pub const OP_PUBLISHER_CANDIDATE_SET_SUBMISSION: u16 = 1;
/// Fixed PRWP header bytes before the operation body.
pub const CANDIDATE_PUBLICATION_WIRE_HEADER_BYTES: usize = 12;
/// Exact PRWP v1.0 length for an empty candidate vector.
pub const CANDIDATE_PUBLICATION_WIRE_EMPTY_BYTES: usize = 80;
/// Exact maximum PRWP v1.0 payload length for sixteen IPv6 candidates.
pub const CANDIDATE_PUBLICATION_WIRE_MAX_BYTES: usize = 592;

const PATH_KIND_LOCAL_DIRECT: u16 = 1;
const PATH_KIND_INTERNET_DIRECT: u16 = 2;
const PATH_KIND_RELAY: u16 = 3;
const IP_FAMILY_IPV4: u16 = 1;
const IP_FAMILY_IPV6: u16 = 2;
const IPV4_CANDIDATE_RECORD_BYTES: usize = 20;
const IPV6_CANDIDATE_RECORD_BYTES: usize = 32;

/// One BP-selected publisher candidate-set submission represented only by typed semantic fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePublicationWireSubmission {
    presented_transport_identity: TransportIdentity,
    presented_freshness: CandidatePublicationFreshnessToken,
    candidates: Vec<ConnectivityCandidate>,
}

impl CandidatePublicationWireSubmission {
    /// Creates one bounded inner submission from already-typed fields.
    ///
    /// Duplicate/reuse/high-water candidate semantics intentionally remain above this codec.
    ///
    /// # Errors
    ///
    /// Rejects candidate vectors above the existing product maximum of sixteen.
    pub fn new(
        presented_transport_identity: TransportIdentity,
        presented_freshness: CandidatePublicationFreshnessToken,
        candidates: Vec<ConnectivityCandidate>,
    ) -> Result<Self, CandidatePublicationWireError> {
        if candidates.len() > MAX_CONNECTIVITY_CANDIDATES {
            return Err(CandidatePublicationWireError::InvalidPayload);
        }
        Ok(Self {
            presented_transport_identity,
            presented_freshness,
            candidates,
        })
    }

    /// Returns the exact presented lower-transport identity.
    #[must_use]
    pub const fn presented_transport_identity(&self) -> TransportIdentity {
        self.presented_transport_identity
    }

    /// Returns the exact opaque verifier freshness token presented by the publisher.
    #[must_use]
    pub const fn presented_freshness(&self) -> CandidatePublicationFreshnessToken {
        self.presented_freshness
    }

    /// Returns the candidate vector in exact publisher submission order.
    #[must_use]
    pub const fn candidates(&self) -> &[ConnectivityCandidate] {
        self.candidates.as_slice()
    }

    /// Encodes one complete canonical PRWP v1.0 payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let candidate_bytes = self
            .candidates
            .iter()
            .map(|candidate| match candidate.endpoint().address() {
                IpAddr::V4(_) => IPV4_CANDIDATE_RECORD_BYTES,
                IpAddr::V6(_) => IPV6_CANDIDATE_RECORD_BYTES,
            })
            .sum::<usize>();
        let mut payload =
            Vec::with_capacity(CANDIDATE_PUBLICATION_WIRE_EMPTY_BYTES + candidate_bytes);
        payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAGIC);
        payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MAJOR.to_be_bytes());
        payload.extend_from_slice(&CANDIDATE_PUBLICATION_WIRE_MINOR.to_be_bytes());
        payload.extend_from_slice(&OP_PUBLISHER_CANDIDATE_SET_SUBMISSION.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(self.presented_transport_identity.as_bytes());
        payload.extend_from_slice(self.presented_freshness.as_bytes());
        let candidate_count = u16::try_from(self.candidates.len()).unwrap_or_default();
        payload.extend_from_slice(&candidate_count.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());

        for candidate in &self.candidates {
            payload.extend_from_slice(&candidate.id().get().to_be_bytes());
            payload.extend_from_slice(&path_kind_tag(candidate.kind()).to_be_bytes());
            match candidate.endpoint().address() {
                IpAddr::V4(address) => {
                    payload.extend_from_slice(&IP_FAMILY_IPV4.to_be_bytes());
                    payload.extend_from_slice(&candidate.endpoint().port().to_be_bytes());
                    payload.extend_from_slice(&0_u16.to_be_bytes());
                    payload.extend_from_slice(&address.octets());
                }
                IpAddr::V6(address) => {
                    payload.extend_from_slice(&IP_FAMILY_IPV6.to_be_bytes());
                    payload.extend_from_slice(&candidate.endpoint().port().to_be_bytes());
                    payload.extend_from_slice(&0_u16.to_be_bytes());
                    payload.extend_from_slice(&address.octets());
                }
            }
        }

        payload
    }

    /// Decodes one complete PRWP v1.0 payload through existing typed constructors.
    ///
    /// Successful decode proves only bounded structural/type validity. Authenticated publisher
    /// currentness, freshness currentness, duplicate/high-water semantics and publication admission
    /// remain above this codec.
    ///
    /// # Errors
    ///
    /// Rejects wrong magic/version/operation, non-zero reserved fields, invalid tags or typed
    /// values, more than sixteen candidates, payloads outside 80..=592 bytes, truncation and
    /// trailing data.
    pub fn decode(payload: &[u8]) -> Result<Self, CandidatePublicationWireError> {
        if !(CANDIDATE_PUBLICATION_WIRE_EMPTY_BYTES..=CANDIDATE_PUBLICATION_WIRE_MAX_BYTES)
            .contains(&payload.len())
        {
            return Err(CandidatePublicationWireError::InvalidPayload);
        }

        let mut decoder = Decoder::new(payload);
        if decoder.array::<4>()? != CANDIDATE_PUBLICATION_WIRE_MAGIC
            || decoder.u16()? != CANDIDATE_PUBLICATION_WIRE_MAJOR
            || decoder.u16()? != CANDIDATE_PUBLICATION_WIRE_MINOR
            || decoder.u16()? != OP_PUBLISHER_CANDIDATE_SET_SUBMISSION
            || decoder.u16()? != 0
        {
            return Err(CandidatePublicationWireError::InvalidPayload);
        }

        let presented_transport_identity = TransportIdentity::new(decoder.array::<32>()?)
            .map_err(|_| CandidatePublicationWireError::InvalidPayload)?;
        let presented_freshness = CandidatePublicationFreshnessToken::new(decoder.array::<32>()?)
            .map_err(|_| CandidatePublicationWireError::InvalidPayload)?;
        let candidate_count = usize::from(decoder.u16()?);
        if candidate_count > MAX_CONNECTIVITY_CANDIDATES || decoder.u16()? != 0 {
            return Err(CandidatePublicationWireError::InvalidPayload);
        }

        let mut candidates = Vec::with_capacity(candidate_count);
        for _ in 0..candidate_count {
            let id = CandidateId::new(decoder.u64()?)
                .map_err(|_| CandidatePublicationWireError::InvalidPayload)?;
            let kind = path_kind_from_tag(decoder.u16()?)?;
            let family = decoder.u16()?;
            let port = decoder.u16()?;
            if decoder.u16()? != 0 {
                return Err(CandidatePublicationWireError::InvalidPayload);
            }
            let address = match family {
                IP_FAMILY_IPV4 => IpAddr::V4(Ipv4Addr::from(decoder.array::<4>()?)),
                IP_FAMILY_IPV6 => IpAddr::V6(Ipv6Addr::from(decoder.array::<16>()?)),
                _ => return Err(CandidatePublicationWireError::InvalidPayload),
            };
            let endpoint = ConnectivityEndpoint::new(address, port)
                .map_err(|_| CandidatePublicationWireError::InvalidPayload)?;
            candidates.push(ConnectivityCandidate::new(id, kind, endpoint));
        }
        decoder.finish()?;

        Self::new(
            presented_transport_identity,
            presented_freshness,
            candidates,
        )
    }
}

/// Stable pure-codec failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationWireError {
    /// PRWP metadata/body is malformed, unknown, invalid, out of bounds, truncated or trailing.
    InvalidPayload,
}

impl fmt::Display for CandidatePublicationWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid candidate publication wire payload")
    }
}

impl std::error::Error for CandidatePublicationWireError {}

const fn path_kind_tag(kind: ConnectivityPathKind) -> u16 {
    match kind {
        ConnectivityPathKind::LocalDirect => PATH_KIND_LOCAL_DIRECT,
        ConnectivityPathKind::InternetDirect => PATH_KIND_INTERNET_DIRECT,
        ConnectivityPathKind::Relay => PATH_KIND_RELAY,
    }
}

const fn path_kind_from_tag(
    tag: u16,
) -> Result<ConnectivityPathKind, CandidatePublicationWireError> {
    match tag {
        PATH_KIND_LOCAL_DIRECT => Ok(ConnectivityPathKind::LocalDirect),
        PATH_KIND_INTERNET_DIRECT => Ok(ConnectivityPathKind::InternetDirect),
        PATH_KIND_RELAY => Ok(ConnectivityPathKind::Relay),
        _ => Err(CandidatePublicationWireError::InvalidPayload),
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CandidatePublicationWireError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CandidatePublicationWireError::InvalidPayload)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(CandidatePublicationWireError::InvalidPayload)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(bytes);
        self.offset = end;
        Ok(output)
    }

    fn u16(&mut self) -> Result<u16, CandidatePublicationWireError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, CandidatePublicationWireError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    const fn finish(self) -> Result<(), CandidatePublicationWireError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(CandidatePublicationWireError::InvalidPayload)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use prw_connectivity::{
        CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
        MAX_CONNECTIVITY_CANDIDATES, TransportIdentity,
    };

    use crate::candidate_publication_freshness::CandidatePublicationFreshnessToken;

    use super::{
        CANDIDATE_PUBLICATION_WIRE_EMPTY_BYTES, CANDIDATE_PUBLICATION_WIRE_MAGIC,
        CANDIDATE_PUBLICATION_WIRE_MAJOR, CANDIDATE_PUBLICATION_WIRE_MAX_BYTES,
        CANDIDATE_PUBLICATION_WIRE_MINOR, CandidatePublicationWireError,
        CandidatePublicationWireSubmission, OP_PUBLISHER_CANDIDATE_SET_SUBMISSION,
    };

    fn transport_identity(marker: u8) -> TransportIdentity {
        let mut bytes = [0_u8; 32];
        bytes[31] = marker;
        TransportIdentity::new(bytes).expect("non-zero transport identity")
    }

    fn freshness_token(marker: u8) -> CandidatePublicationFreshnessToken {
        let mut bytes = [0_u8; 32];
        bytes[31] = marker;
        CandidatePublicationFreshnessToken::new(bytes).expect("non-zero freshness token")
    }

    fn candidate(
        id: u64,
        kind: ConnectivityPathKind,
        address: IpAddr,
        port: u16,
    ) -> ConnectivityCandidate {
        ConnectivityCandidate::new(
            CandidateId::new(id).expect("non-zero candidate id"),
            kind,
            ConnectivityEndpoint::new(address, port).expect("valid explicit endpoint"),
        )
    }

    fn submission(candidates: Vec<ConnectivityCandidate>) -> CandidatePublicationWireSubmission {
        CandidatePublicationWireSubmission::new(
            transport_identity(1),
            freshness_token(2),
            candidates,
        )
        .expect("bounded typed submission")
    }

    fn assert_invalid(payload: &[u8]) {
        assert_eq!(
            CandidatePublicationWireSubmission::decode(payload),
            Err(CandidatePublicationWireError::InvalidPayload)
        );
    }

    #[test]
    fn empty_submission_has_exact_selected_header_and_length() {
        let encoded = submission(Vec::new()).encode();

        assert_eq!(encoded.len(), CANDIDATE_PUBLICATION_WIRE_EMPTY_BYTES);
        assert_eq!(&encoded[0..4], CANDIDATE_PUBLICATION_WIRE_MAGIC.as_slice());
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            CANDIDATE_PUBLICATION_WIRE_MAJOR
        );
        assert_eq!(
            u16::from_be_bytes([encoded[6], encoded[7]]),
            CANDIDATE_PUBLICATION_WIRE_MINOR
        );
        assert_eq!(
            u16::from_be_bytes([encoded[8], encoded[9]]),
            OP_PUBLISHER_CANDIDATE_SET_SUBMISSION
        );
        assert_eq!(u16::from_be_bytes([encoded[10], encoded[11]]), 0);
        assert_eq!(u16::from_be_bytes([encoded[76], encoded[77]]), 0);
        assert_eq!(u16::from_be_bytes([encoded[78], encoded[79]]), 0);
        assert_eq!(
            CandidatePublicationWireSubmission::decode(&encoded),
            Ok(submission(Vec::new()))
        );
    }

    #[test]
    fn mixed_ipv4_ipv6_round_trip_preserves_vector_order_and_tags() {
        let first = candidate(
            7,
            ConnectivityPathKind::InternetDirect,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            4_432,
        );
        let second = candidate(
            9,
            ConnectivityPathKind::Relay,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
            5_543,
        );
        let typed = submission(vec![first, second]);
        let encoded = typed.encode();

        assert_eq!(encoded.len(), 132);
        assert_eq!(
            u64::from_be_bytes(encoded[80..88].try_into().expect("id")),
            7
        );
        assert_eq!(u16::from_be_bytes([encoded[88], encoded[89]]), 2);
        assert_eq!(u16::from_be_bytes([encoded[90], encoded[91]]), 1);
        assert_eq!(u16::from_be_bytes([encoded[94], encoded[95]]), 0);
        assert_eq!(
            u64::from_be_bytes(encoded[100..108].try_into().expect("id")),
            9
        );
        assert_eq!(u16::from_be_bytes([encoded[108], encoded[109]]), 3);
        assert_eq!(u16::from_be_bytes([encoded[110], encoded[111]]), 2);
        assert_eq!(
            CandidatePublicationWireSubmission::decode(&encoded),
            Ok(typed)
        );
    }

    #[test]
    fn sixteen_ipv6_candidates_reach_exact_selected_maximum() {
        let mut candidates = Vec::with_capacity(MAX_CONNECTIVITY_CANDIDATES);
        for id in 1_u64..=16 {
            let segment = u16::try_from(id).expect("bounded test id");
            candidates.push(candidate(
                id,
                ConnectivityPathKind::Relay,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, segment)),
                6_000_u16 + segment,
            ));
        }
        let typed = submission(candidates);
        let encoded = typed.encode();

        assert_eq!(encoded.len(), CANDIDATE_PUBLICATION_WIRE_MAX_BYTES);
        assert_eq!(
            CandidatePublicationWireSubmission::decode(&encoded),
            Ok(typed)
        );
    }

    #[test]
    fn constructor_rejects_more_than_sixteen_candidates_without_cross_candidate_semantics() {
        let repeated = candidate(
            1,
            ConnectivityPathKind::LocalDirect,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            4_000,
        );

        assert_eq!(
            CandidatePublicationWireSubmission::new(
                transport_identity(1),
                freshness_token(2),
                vec![repeated; MAX_CONNECTIVITY_CANDIDATES + 1]
            ),
            Err(CandidatePublicationWireError::InvalidPayload)
        );
    }

    #[test]
    fn decoder_rejects_wrong_header_fields_and_reserved_bits() {
        let encoded = submission(Vec::new()).encode();
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        let mut bad_major = encoded.clone();
        bad_major[5] = 2;
        let mut bad_minor = encoded.clone();
        bad_minor[7] = 1;
        let mut bad_operation = encoded.clone();
        bad_operation[9] = 2;
        let mut bad_header_reserved = encoded.clone();
        bad_header_reserved[11] = 1;
        let mut bad_vector_reserved = encoded;
        bad_vector_reserved[79] = 1;

        for payload in [
            bad_magic,
            bad_major,
            bad_minor,
            bad_operation,
            bad_header_reserved,
            bad_vector_reserved,
        ] {
            assert_invalid(&payload);
        }
    }

    #[test]
    fn decoder_rejects_invalid_typed_prefix_and_candidate_fields() {
        let one = submission(vec![candidate(
            1,
            ConnectivityPathKind::LocalDirect,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            4_000,
        )])
        .encode();

        let mut zero_transport = one.clone();
        zero_transport[12..44].fill(0);
        let mut zero_freshness = one.clone();
        zero_freshness[44..76].fill(0);
        let mut zero_candidate_id = one.clone();
        zero_candidate_id[80..88].fill(0);
        let mut unknown_path_kind = one.clone();
        unknown_path_kind[88..90].copy_from_slice(&9_u16.to_be_bytes());
        let mut unknown_family = one.clone();
        unknown_family[90..92].copy_from_slice(&9_u16.to_be_bytes());
        let mut zero_port = one.clone();
        zero_port[92..94].fill(0);
        let mut candidate_reserved = one.clone();
        candidate_reserved[94..96].copy_from_slice(&1_u16.to_be_bytes());
        let mut unspecified_address = one;
        unspecified_address[96..100].fill(0);

        for payload in [
            zero_transport,
            zero_freshness,
            zero_candidate_id,
            unknown_path_kind,
            unknown_family,
            zero_port,
            candidate_reserved,
            unspecified_address,
        ] {
            assert_invalid(&payload);
        }
    }

    #[test]
    fn decoder_rejects_count_over_bound_truncation_and_trailing_data() {
        let empty = submission(Vec::new()).encode();
        let mut too_many = empty.clone();
        too_many[76..78].copy_from_slice(&17_u16.to_be_bytes());
        let mut trailing = empty.clone();
        trailing.push(0);
        let truncated = empty[..empty.len() - 1].to_vec();
        let mut oversized = vec![0_u8; CANDIDATE_PUBLICATION_WIRE_MAX_BYTES + 1];
        oversized[..empty.len()].copy_from_slice(&empty);

        for payload in [too_many, trailing, truncated, oversized] {
            assert_invalid(&payload);
        }
    }

    #[test]
    fn decoder_rejects_truncated_family_specific_candidate_address() {
        let mut encoded = submission(vec![candidate(
            3,
            ConnectivityPathKind::InternetDirect,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
            4_433,
        )])
        .encode();
        encoded.pop();

        assert_invalid(&encoded);
    }
}
