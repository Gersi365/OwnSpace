#![allow(
    dead_code,
    reason = "Phase 152 Slice B local management IPC integration is exercised by deterministic tests before live Agent dispatch"
)]

use prw_agent::{
    LocalIpcRequestId,
    frame_object::LocalIpcFrame,
    local_commands::management_request::{
        LocalManagementRequestBuildError, build_local_management_request_frame,
    },
};
use prw_file_service::{MAX_DIRECTORY_ENTRIES, RemotePath};
use prw_remote_bridge::{BridgeCommand, RemoteBridgeError};

/// Pure client-side failure while composing one typed local management request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalManagementClientError {
    /// Canonical PRWC encoding rejected the typed operation.
    Bridge(RemoteBridgeError),
    /// Agent-owned local command-3 framing rejected the encoded body.
    Local(LocalManagementRequestBuildError),
    /// The requested file-list path is not a canonical relative remote path.
    InvalidFilePath,
}

/// Encodes one existing typed bridge command and wraps it in the Agent-owned
/// local command-3 request envelope.
///
/// This function performs no socket I/O and does not treat construction as
/// authorization, dispatch, acknowledgement, or completion.
///
/// # Errors
///
/// Preserves canonical PRWC encoding failures and bounded local framing
/// failures without introducing an alternate command representation.
pub fn build_bridge_management_request(
    request_id: LocalIpcRequestId,
    command: &BridgeCommand,
) -> Result<LocalIpcFrame, LocalManagementClientError> {
    let bridge_payload = command
        .encode()
        .map_err(LocalManagementClientError::Bridge)?;
    build_local_management_request_frame(request_id, &bridge_payload)
        .map_err(LocalManagementClientError::Local)
}

/// One decoded read-only file-list entry returned by the Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileListEntry {
    name: String,
    kind: LocalFileListEntryKind,
}

impl LocalFileListEntry {
    #[must_use]
    pub(crate) fn display_text(&self) -> String {
        match self.kind {
            LocalFileListEntryKind::RegularFile => self.name.clone(),
            LocalFileListEntryKind::Directory => format!("{}/", self.name),
            LocalFileListEntryKind::SymbolicLink => format!("{} [symlink]", self.name),
            LocalFileListEntryKind::Other => format!("{} [other]", self.name),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalFileListEntryKind {
    RegularFile,
    Directory,
    SymbolicLink,
    Other,
}

/// Fail-closed decoder error for one successful directory-list response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalFileListDecodeError {
    MissingResult,
    UnexpectedResult,
    EntryCount,
    EntryType,
    EntryLength,
    EntryUtf8,
    TrailingBytes,
}

/// Builds the only live management request enabled by the desktop Files surface.
pub fn build_file_list_management_request(
    request_id: LocalIpcRequestId,
    path: &str,
) -> Result<LocalIpcFrame, LocalManagementClientError> {
    let path = RemotePath::parse(path).map_err(|_| LocalManagementClientError::InvalidFilePath)?;
    build_bridge_management_request(request_id, &BridgeCommand::FileList(path))
}

/// Decodes the command-specific body after the common two-byte success status prefix.
pub fn decode_file_list_success_body(
    payload: &[u8],
) -> Result<Vec<LocalFileListEntry>, LocalFileListDecodeError> {
    const STATUS_PREFIX_LENGTH: usize = 2;
    const DIRECTORY_ENTRIES_RESULT: u8 = 2;

    let body = payload
        .get(STATUS_PREFIX_LENGTH..)
        .ok_or(LocalFileListDecodeError::MissingResult)?;
    if body.first().copied() != Some(DIRECTORY_ENTRIES_RESULT) {
        return Err(LocalFileListDecodeError::UnexpectedResult);
    }
    let count_bytes = body.get(1..3).ok_or(LocalFileListDecodeError::EntryCount)?;
    let count = usize::from(u16::from_be_bytes([count_bytes[0], count_bytes[1]]));
    if count > MAX_DIRECTORY_ENTRIES {
        return Err(LocalFileListDecodeError::EntryCount);
    }

    let mut cursor = 3_usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = match body.get(cursor).copied() {
            Some(1) => LocalFileListEntryKind::RegularFile,
            Some(2) => LocalFileListEntryKind::Directory,
            Some(3) => LocalFileListEntryKind::SymbolicLink,
            Some(4) => LocalFileListEntryKind::Other,
            _ => return Err(LocalFileListDecodeError::EntryType),
        };
        cursor += 1;
        let len_bytes = body
            .get(cursor..cursor + 2)
            .ok_or(LocalFileListDecodeError::EntryLength)?;
        let name_len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
        cursor += 2;
        let name_bytes = body
            .get(cursor..cursor + name_len)
            .ok_or(LocalFileListDecodeError::EntryLength)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| LocalFileListDecodeError::EntryUtf8)?
            .to_owned();
        if name.is_empty() {
            return Err(LocalFileListDecodeError::EntryLength);
        }
        cursor += name_len;
        entries.push(LocalFileListEntry { name, kind });
    }
    if cursor != body.len() {
        return Err(LocalFileListDecodeError::TrailingBytes);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use prw_agent::{
        LocalIpcRequestId,
        local_commands::{
            codec::{LocalAgentRequestDecodeError, decode_request_command},
            management_request::{
                LOCAL_MANAGEMENT_REQUEST_PREFIX_LENGTH, decode_local_management_request_frame,
            },
        },
    };
    use prw_file_service::RemotePath;
    use prw_forwarding::{
        ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec,
    };
    use prw_remote_bridge::BridgeCommand;
    use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

    use super::{
        LocalManagementClientError, build_bridge_management_request,
        build_file_list_management_request, decode_file_list_success_body,
    };

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn representative_commands() -> [(u64, BridgeCommand); 3] {
        let terminal = BridgeCommand::TerminalOpen {
            session_id: TerminalSessionId::new(152).expect("valid terminal session id"),
            profile: TerminalProfile::BashShell,
            geometry: TerminalGeometry::new(120, 40).expect("valid terminal geometry"),
        };
        let files =
            BridgeCommand::FileList(RemotePath::parse("docs").expect("valid relative path"));
        let forward = BridgeCommand::ForwardOpen {
            forward_id: PortForwardId::new(152).expect("valid forward id"),
            spec: TcpForwardSpec::new(
                LoopbackBind::new(LoopbackFamily::Ipv4, 41_152).expect("valid loopback bind"),
                ForwardTarget::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22)
                    .expect("valid explicit target"),
            ),
        };

        [(152, terminal), (153, files), (154, forward)]
    }

    #[test]
    fn legacy_two_byte_namespace_remains_byte_compatible_and_rejects_code_three() {
        assert_eq!(
            decode_request_command(&[0, 1]).expect("legacy status command"),
            prw_agent::local_commands::LocalAgentCommand::GetAgentStatus
        );
        assert_eq!(
            decode_request_command(&[0, 2]).expect("legacy private DNS command"),
            prw_agent::local_commands::LocalAgentCommand::GetPrivateDnsConfig
        );
        assert_eq!(
            decode_request_command(&[0, 3]),
            Err(LocalAgentRequestDecodeError::UnknownCommand)
        );
    }

    #[test]
    fn typed_terminal_file_and_forwarding_intents_round_trip_through_local_command_three() {
        for (request_id, command) in representative_commands() {
            let expected_bridge_payload = command.encode().expect("canonical PRWC encoding");
            let expected_capability = command.required_capability();
            let frame = build_bridge_management_request(id(request_id), &command)
                .expect("typed local management request builds");

            assert_eq!(frame.header().request_id(), id(request_id));
            assert_eq!(&frame.payload().as_bytes()[..2], &[0, 3]);
            assert_eq!(
                &frame.payload().as_bytes()[LOCAL_MANAGEMENT_REQUEST_PREFIX_LENGTH..],
                expected_bridge_payload.as_slice()
            );

            let local = decode_local_management_request_frame(&frame)
                .expect("Agent-owned management envelope decodes");
            assert_eq!(local.request_id(), id(request_id));
            let decoded = BridgeCommand::decode(local.bridge_payload())
                .expect("canonical PRWC bridge payload decodes");
            assert_eq!(decoded, command);
            assert_eq!(decoded.required_capability(), expected_capability);
        }
    }

    #[test]
    fn local_schema_contains_only_command_length_and_canonical_bridge_bytes() {
        let command = BridgeCommand::FileList(RemotePath::parse("workspace").expect("valid path"));
        let bridge_payload = command.encode().expect("canonical PRWC encoding");
        let frame = build_bridge_management_request(id(155), &command)
            .expect("typed local management request builds");
        let local_payload = frame.payload().as_bytes();

        assert_eq!(&local_payload[..2], &[0, 3]);
        let declared = u32::from_be_bytes([
            local_payload[2],
            local_payload[3],
            local_payload[4],
            local_payload[5],
        ]);
        assert_eq!(
            usize::try_from(declared).expect("declared local body length fits usize"),
            bridge_payload.len()
        );
        assert_eq!(
            &local_payload[LOCAL_MANAGEMENT_REQUEST_PREFIX_LENGTH..],
            bridge_payload.as_slice()
        );
        assert_eq!(
            local_payload.len(),
            LOCAL_MANAGEMENT_REQUEST_PREFIX_LENGTH + bridge_payload.len()
        );
    }

    #[test]
    fn live_file_list_builder_accepts_root_and_rejects_noncanonical_paths() {
        let root = build_file_list_management_request(id(156), "").expect("root listing builds");
        let local = decode_local_management_request_frame(&root).expect("local envelope decodes");
        assert_eq!(
            BridgeCommand::decode(local.bridge_payload()).expect("bridge decodes"),
            BridgeCommand::FileList(RemotePath::parse("").expect("root path"))
        );
        assert!(matches!(
            build_file_list_management_request(id(157), "../escape"),
            Err(LocalManagementClientError::InvalidFilePath)
        ));
    }

    #[test]
    fn directory_entry_success_body_decodes_types_and_rejects_trailing_bytes() {
        let payload = [
            0, 0, 2, 0, 2, 2, 0, 4, b'd', b'o', b'c', b's', 1, 0, 5, b'n', b'o', b't', b'e', b's',
        ];
        let entries = decode_file_list_success_body(&payload).expect("directory body decodes");
        assert_eq!(entries[0].display_text(), "docs/");
        assert_eq!(entries[1].display_text(), "notes");

        let mut trailing = payload.to_vec();
        trailing.push(9);
        assert!(decode_file_list_success_body(&trailing).is_err());
    }
}
