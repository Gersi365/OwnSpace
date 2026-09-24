//! Generic stream composition for successful `GetPrivateDnsConfig` responses.
//!
//! Phase 029 uses only `std::io::Read` and `std::io::Write`; it does not create
//! or configure a socket.

pub mod completion;

use std::io::{Read, Write};

use super::{
    LocalPrivateDnsFrame, LocalPrivateDnsFrameBuildError, LocalPrivateDnsFrameDecodeError,
    build_success_private_dns_frame, decode_success_private_dns_frame,
};
use crate::LocalIpcRequestId;
use crate::frame_object::reader::{LocalIpcFrameReadError, read_frame};
use crate::frame_object::writer::{LocalIpcFrameWriteError, write_frame};
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;

/// Builds and writes one successful `GetPrivateDnsConfig` frame to a generic stream.
///
/// The function deliberately does not flush the writer.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsStreamWriteError::Build`] when complete frame
/// construction fails or [`LocalPrivateDnsStreamWriteError::Write`] when the
/// validated frame cannot be fully written.
pub fn write_success_private_dns_response<W: Write>(
    writer: &mut W,
    request_id: LocalIpcRequestId,
    snapshot: &LocalPrivateDnsSnapshot,
) -> Result<(), LocalPrivateDnsStreamWriteError> {
    let frame = build_success_private_dns_frame(request_id, snapshot)
        .map_err(LocalPrivateDnsStreamWriteError::Build)?;
    write_frame(writer, &frame).map_err(LocalPrivateDnsStreamWriteError::Write)
}

/// Reads and decodes one successful `GetPrivateDnsConfig` frame from a generic stream.
///
/// # Errors
///
/// Returns [`LocalPrivateDnsStreamReadError::Read`] when a complete validated
/// frame cannot be acquired, or [`LocalPrivateDnsStreamReadError::Decode`] when
/// that frame is not a valid successful private-DNS response.
pub fn read_success_private_dns_response<R: Read>(
    reader: &mut R,
) -> Result<LocalPrivateDnsFrame, LocalPrivateDnsStreamReadError> {
    let frame = read_frame(reader).map_err(LocalPrivateDnsStreamReadError::Read)?;
    decode_success_private_dns_frame(&frame).map_err(LocalPrivateDnsStreamReadError::Decode)
}

/// Phase 029 private-DNS stream write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsStreamWriteError {
    /// Complete private-DNS response-frame construction failed.
    Build(LocalPrivateDnsFrameBuildError),
    /// Generic frame writing failed.
    Write(LocalIpcFrameWriteError),
}

/// Phase 029 private-DNS stream read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPrivateDnsStreamReadError {
    /// Generic frame acquisition failed.
    Read(LocalIpcFrameReadError),
    /// Acquired frame failed successful private-DNS decoding.
    Decode(LocalPrivateDnsFrameDecodeError),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{
        LocalPrivateDnsStreamReadError, read_success_private_dns_response,
        write_success_private_dns_response,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::local_commands::private_dns_response::LOCAL_PRIVATE_DNS_MAX_SUCCESS_WIRE_LENGTH;
    use crate::local_commands::private_dns_snapshot::{
        LOCAL_PRIVATE_DNS_MAX_RESOLVER_BYTES, LOCAL_PRIVATE_DNS_MAX_RESOLVERS,
        LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAIN_BYTES, LOCAL_PRIVATE_DNS_MAX_SPLIT_DOMAINS,
        LocalPrivateDnsSnapshot,
    };
    use prw_network::PrivateDnsConfig;

    fn id() -> LocalIpcRequestId {
        LocalIpcRequestId::new(110).expect("non-zero request id")
    }

    fn snapshot(config: &PrivateDnsConfig) -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(config).expect("bounded test config")
    }

    #[test]
    fn default_response_wire_length_is_exactly_twenty_nine_bytes() {
        let snapshot = snapshot(&PrivateDnsConfig::default());
        let mut bytes = Vec::new();

        write_success_private_dns_response(&mut bytes, id(), &snapshot)
            .expect("memory write succeeds");

        assert_eq!(bytes.len(), 29);
    }

    #[test]
    fn bounded_utf8_snapshot_round_trips_through_generic_stream_io() {
        let config = PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into(), "fd00::53".into()],
            split_domains: vec!["corp.example".into(), "láb.example".into()],
        };
        let snapshot = snapshot(&config);
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(), &snapshot)
            .expect("memory write succeeds");
        let mut cursor = Cursor::new(bytes);
        let decoded =
            read_success_private_dns_response(&mut cursor).expect("memory read/decode succeeds");

        assert_eq!(decoded.request_id(), id());
        assert_eq!(decoded.snapshot(), &snapshot);
    }

    #[test]
    fn maximum_snapshot_matches_locked_wire_bound() {
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
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(), &snapshot)
            .expect("maximum memory write succeeds");

        assert_eq!(bytes.len(), LOCAL_PRIVATE_DNS_MAX_SUCCESS_WIRE_LENGTH);
        let mut cursor = Cursor::new(bytes);
        assert_eq!(
            read_success_private_dns_response(&mut cursor)
                .expect("maximum response decodes")
                .snapshot(),
            &snapshot
        );
    }

    #[test]
    fn reader_consumes_exactly_one_frame_and_leaves_trailing_bytes() {
        let snapshot = snapshot(&PrivateDnsConfig::default());
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(), &snapshot)
            .expect("memory write succeeds");
        bytes.extend_from_slice(&[9, 8, 7]);
        let mut cursor = Cursor::new(bytes);

        read_success_private_dns_response(&mut cursor).expect("first frame succeeds");
        assert_eq!(cursor.position(), 29);

        let mut trailing = Vec::new();
        cursor.read_to_end(&mut trailing).expect("trailing read");
        assert_eq!(trailing, [9, 8, 7]);
    }

    #[test]
    fn truncated_payload_preserves_generic_read_error() {
        let snapshot = snapshot(&PrivateDnsConfig::default());
        let mut bytes = Vec::new();
        write_success_private_dns_response(&mut bytes, id(), &snapshot)
            .expect("memory write succeeds");
        bytes.pop();
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            read_success_private_dns_response(&mut cursor),
            Err(LocalPrivateDnsStreamReadError::Read(
                LocalIpcFrameReadError::TruncatedPayload
            ))
        );
    }
}
