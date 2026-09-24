//! C02c deterministic response encoding for typed local-management provider results.
//!
//! The common local two-byte response-status prefix and outer Response/Error kind remain
//! owned by the existing terminal-response builder. This module defines only the bounded
//! command body used after typed provider dispatch. Provider errors are collapsed into the
//! existing coarse local statuses and never serialize provider strings or host detail.

use prw_file_service::{FileServiceError, RemoteDirectoryEntry, RemoteFileType};
use prw_file_transfer::FileTransferError;
use prw_forwarding::ForwardingError;
use prw_terminal::TerminalError;

use super::LocalAgentResponseStatus;
use super::management_typed_provider_dispatch::{
    LocalManagementTypedProviderDispatchError, LocalManagementTypedProviderResult,
};
use super::status_snapshot::codec::encode_status_snapshot;
use super::terminal_response::builder::{
    LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH, LocalTerminalResponseBuildError,
    build_terminal_response_frame,
};
use crate::LocalIpcRequestId;
use crate::frame_object::LocalIpcFrame;

const RESULT_AGENT_STATUS: u8 = 1;
const RESULT_DIRECTORY_ENTRIES: u8 = 2;
const RESULT_METADATA: u8 = 3;
const RESULT_EMPTY: u8 = 4;
const RESULT_OFFSET: u8 = 5;
const RESULT_BYTES: u8 = 6;

const FILE_TYPE_REGULAR: u8 = 1;
const FILE_TYPE_DIRECTORY: u8 = 2;
const FILE_TYPE_SYMLINK: u8 = 3;
const FILE_TYPE_OTHER: u8 = 4;

/// Defensive failure while encoding one successful typed provider result body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalManagementSuccessBodyEncodeError {
    /// Directory entry count did not fit the locked two-byte count field.
    DirectoryEntryCount,
    /// One provider entry name did not fit the locked two-byte name-length field.
    DirectoryEntryNameLength,
    /// Encoded result exceeded the existing local terminal-response body bound.
    BodyTooLarge,
}

/// Builds one correlated terminal response from a typed provider result or failure.
///
/// Successful provider results receive the existing `Ok` status only after their body
/// encodes within the local IPC bound. A success-body encoding failure is converted to
/// a correlated `InternalError` with an empty body, so encoding failure can never forge
/// a success acknowledgement. Typed provider failures are mapped to existing coarse
/// statuses with empty bodies.
///
/// # Errors
///
/// Returns only failures from the pre-existing terminal-response frame builder.
pub(super) fn build_management_provider_response(
    request_id: LocalIpcRequestId,
    result: Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError> {
    match result {
        Ok(result) => encode_success_body(&result).map_or_else(
            |_| {
                build_terminal_response_frame(
                    request_id,
                    LocalAgentResponseStatus::InternalError,
                    &[],
                )
            },
            |body| build_terminal_response_frame(request_id, LocalAgentResponseStatus::Ok, &body),
        ),
        Err(error) => build_terminal_response_frame(request_id, error_status(error), &[]),
    }
}

/// Encodes one typed success body without the common two-byte status prefix.
///
/// Body tags are stable within the C02c local-management surface:
///
/// - `1`: Agent status, followed by the existing five-byte status snapshot codec;
/// - `2`: directory entries, `u16 count`, then repeated `u8 type + u16 name_len + name`;
/// - `3`: metadata, `u8 type + u64 size`;
/// - `4`: empty acknowledgement;
/// - `5`: exact big-endian `u64` offset;
/// - `6`: bounded raw bytes.
///
/// # Errors
///
/// Rejects defensive count/name conversion failure or an encoded body above the
/// existing local IPC response-body limit.
pub(super) fn encode_success_body(
    result: &LocalManagementTypedProviderResult,
) -> Result<Vec<u8>, LocalManagementSuccessBodyEncodeError> {
    let mut body = Vec::new();
    match result {
        LocalManagementTypedProviderResult::AgentStatus(snapshot) => {
            body.push(RESULT_AGENT_STATUS);
            body.extend_from_slice(&encode_status_snapshot(*snapshot));
        }
        LocalManagementTypedProviderResult::DirectoryEntries(entries) => {
            encode_directory_entries(&mut body, entries)?;
        }
        LocalManagementTypedProviderResult::Metadata(metadata) => {
            body.push(RESULT_METADATA);
            body.push(remote_file_type_code(metadata.file_type()));
            body.extend_from_slice(&metadata.size().to_be_bytes());
        }
        LocalManagementTypedProviderResult::Empty => {
            body.push(RESULT_EMPTY);
        }
        LocalManagementTypedProviderResult::Offset(offset) => {
            body.push(RESULT_OFFSET);
            body.extend_from_slice(&offset.to_be_bytes());
        }
        LocalManagementTypedProviderResult::Bytes(bytes) => {
            body.push(RESULT_BYTES);
            body.extend_from_slice(bytes);
        }
    }

    if body.len() > LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH {
        return Err(LocalManagementSuccessBodyEncodeError::BodyTooLarge);
    }
    Ok(body)
}

fn encode_directory_entries(
    body: &mut Vec<u8>,
    entries: &[RemoteDirectoryEntry],
) -> Result<(), LocalManagementSuccessBodyEncodeError> {
    let count = u16::try_from(entries.len())
        .map_err(|_| LocalManagementSuccessBodyEncodeError::DirectoryEntryCount)?;
    body.push(RESULT_DIRECTORY_ENTRIES);
    body.extend_from_slice(&count.to_be_bytes());

    for entry in entries {
        let name = entry.name().as_bytes();
        let name_len = u16::try_from(name.len())
            .map_err(|_| LocalManagementSuccessBodyEncodeError::DirectoryEntryNameLength)?;
        body.push(remote_file_type_code(entry.file_type()));
        body.extend_from_slice(&name_len.to_be_bytes());
        body.extend_from_slice(name);
        if body.len() > LOCAL_IPC_MAX_TERMINAL_BODY_LENGTH {
            return Err(LocalManagementSuccessBodyEncodeError::BodyTooLarge);
        }
    }
    Ok(())
}

const fn remote_file_type_code(file_type: RemoteFileType) -> u8 {
    match file_type {
        RemoteFileType::RegularFile => FILE_TYPE_REGULAR,
        RemoteFileType::Directory => FILE_TYPE_DIRECTORY,
        RemoteFileType::SymbolicLink => FILE_TYPE_SYMLINK,
        RemoteFileType::Other => FILE_TYPE_OTHER,
    }
}

const fn error_status(
    error: LocalManagementTypedProviderDispatchError,
) -> LocalAgentResponseStatus {
    match error {
        LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch
        | LocalManagementTypedProviderDispatchError::FilesystemAuthorityMismatch
        | LocalManagementTypedProviderDispatchError::PrincipalMismatch => {
            LocalAgentResponseStatus::Conflict
        }
        LocalManagementTypedProviderDispatchError::File(error) => file_error_status(error),
        LocalManagementTypedProviderDispatchError::Transfer(error) => transfer_error_status(error),
        LocalManagementTypedProviderDispatchError::Terminal(error) => terminal_error_status(error),
        LocalManagementTypedProviderDispatchError::Forwarding(error) => {
            forwarding_error_status(error)
        }
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "file-service errors are non-exhaustive; unknown future variants fail internal"
)]
const fn file_error_status(error: FileServiceError) -> LocalAgentResponseStatus {
    match error {
        FileServiceError::RootNotAllowed | FileServiceError::PayloadTooLarge => {
            LocalAgentResponseStatus::InvalidRequest
        }
        FileServiceError::AlreadyExists
        | FileServiceError::NotRegularFile
        | FileServiceError::NotDirectory => LocalAgentResponseStatus::Conflict,
        _ => LocalAgentResponseStatus::InternalError,
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "file-transfer errors are non-exhaustive; unknown future variants fail internal"
)]
const fn transfer_error_status(error: FileTransferError) -> LocalAgentResponseStatus {
    match error {
        FileTransferError::RootDestination
        | FileTransferError::TransferTooLarge
        | FileTransferError::InvalidChunkLength
        | FileTransferError::ExceedsPlannedTotal => LocalAgentResponseStatus::InvalidRequest,
        FileTransferError::ActiveTransferCapacity
        | FileTransferError::TransferAlreadyActive
        | FileTransferError::TransferUnknown
        | FileTransferError::OffsetMismatch
        | FileTransferError::Incomplete
        | FileTransferError::DigestMismatch => LocalAgentResponseStatus::Conflict,
        _ => LocalAgentResponseStatus::InternalError,
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "terminal errors are non-exhaustive; unknown future variants fail internal"
)]
const fn terminal_error_status(error: TerminalError) -> LocalAgentResponseStatus {
    match error {
        TerminalError::InvalidIdentifier
        | TerminalError::InvalidGeometry
        | TerminalError::EmptyIo
        | TerminalError::IoTooLarge
        | TerminalError::InvalidOutputRequest => LocalAgentResponseStatus::InvalidRequest,
        TerminalError::UnknownSession
        | TerminalError::DuplicateSession
        | TerminalError::SessionCapacity
        | TerminalError::InvalidState => LocalAgentResponseStatus::Conflict,
        _ => LocalAgentResponseStatus::InternalError,
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "forwarding errors are non-exhaustive; unknown future variants fail internal"
)]
const fn forwarding_error_status(error: ForwardingError) -> LocalAgentResponseStatus {
    match error {
        ForwardingError::InvalidIdentifier
        | ForwardingError::InvalidBindPort
        | ForwardingError::InvalidTargetPort
        | ForwardingError::InvalidTargetAddress => LocalAgentResponseStatus::InvalidRequest,
        ForwardingError::DuplicateSession
        | ForwardingError::SessionCapacity
        | ForwardingError::UnknownSession
        | ForwardingError::InvalidState => LocalAgentResponseStatus::Conflict,
        _ => LocalAgentResponseStatus::InternalError,
    }
}
