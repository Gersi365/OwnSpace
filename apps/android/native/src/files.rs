use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JByteArray, JClass},
    sys::{jboolean, jint, jlong},
};
use prw_file_service::RemotePath;
use prw_file_transfer::{MAX_TRANSFER_BYTES, TransferId, UploadPlan};
use prw_remote_bridge::{BridgeCommand, MAX_BRIDGE_INLINE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileAdapterError {
    Path,
    TransferId,
    Digest,
    Total,
    Offset,
    Chunk,
    Read,
    Utf8,
    Bridge,
}

fn utf8(input: &[u8]) -> Result<&str, FileAdapterError> {
    std::str::from_utf8(input).map_err(|_| FileAdapterError::Utf8)
}

fn path(input: &[u8]) -> Result<RemotePath, FileAdapterError> {
    RemotePath::parse(utf8(input)?).map_err(|_| FileAdapterError::Path)
}

fn transfer_id(input: &[u8]) -> Result<TransferId, FileAdapterError> {
    TransferId::from_hex(utf8(input)?).map_err(|_| FileAdapterError::TransferId)
}

fn digest(input: &[u8]) -> Result<[u8; 32], FileAdapterError> {
    input.try_into().map_err(|_| FileAdapterError::Digest)
}

fn nonnegative_u64(value: i64, error: FileAdapterError) -> Result<u64, FileAdapterError> {
    u64::try_from(value).map_err(|_| error)
}

fn bridge_payload(command: &BridgeCommand) -> Result<Vec<u8>, FileAdapterError> {
    command.encode().map_err(|_| FileAdapterError::Bridge)
}

fn upload_plan(
    transfer: &[u8],
    destination: &[u8],
    total_bytes: i64,
    sha256: &[u8],
) -> Result<UploadPlan, FileAdapterError> {
    let total_bytes = nonnegative_u64(total_bytes, FileAdapterError::Total)?;
    if total_bytes > MAX_TRANSFER_BYTES {
        return Err(FileAdapterError::Total);
    }
    UploadPlan::new(
        transfer_id(transfer)?,
        path(destination)?,
        total_bytes,
        digest(sha256)?,
    )
    .map_err(|_| FileAdapterError::Total)
}

fn encode_file_list(remote_path: &[u8]) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::FileList(path(remote_path)?))
}

fn encode_file_stat(remote_path: &[u8]) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::FileStat(path(remote_path)?))
}

fn encode_upload_begin(
    transfer: &[u8],
    destination: &[u8],
    total_bytes: i64,
    sha256: &[u8],
) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::UploadBegin(upload_plan(
        transfer,
        destination,
        total_bytes,
        sha256,
    )?))
}

fn encode_upload_resume(
    transfer: &[u8],
    destination: &[u8],
    total_bytes: i64,
    sha256: &[u8],
) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::UploadResume(upload_plan(
        transfer,
        destination,
        total_bytes,
        sha256,
    )?))
}

fn encode_upload_chunk(
    transfer: &[u8],
    offset: i64,
    chunk: &[u8],
) -> Result<Vec<u8>, FileAdapterError> {
    if chunk.is_empty() || chunk.len() > MAX_BRIDGE_INLINE_BYTES {
        return Err(FileAdapterError::Chunk);
    }
    bridge_payload(&BridgeCommand::UploadChunk {
        transfer_id: transfer_id(transfer)?,
        offset: nonnegative_u64(offset, FileAdapterError::Offset)?,
        chunk: chunk.to_vec(),
    })
}

fn encode_upload_finalize(transfer: &[u8]) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::UploadFinalize(transfer_id(transfer)?))
}

fn encode_upload_abort(transfer: &[u8]) -> Result<Vec<u8>, FileAdapterError> {
    bridge_payload(&BridgeCommand::UploadAbort(transfer_id(transfer)?))
}

fn encode_download_chunk(
    remote_path: &[u8],
    offset: i64,
    requested_len: i32,
) -> Result<Vec<u8>, FileAdapterError> {
    let requested_len = usize::try_from(requested_len).map_err(|_| FileAdapterError::Read)?;
    if requested_len == 0 || requested_len > MAX_BRIDGE_INLINE_BYTES {
        return Err(FileAdapterError::Read);
    }
    bridge_payload(&BridgeCommand::DownloadChunk {
        path: path(remote_path)?,
        offset: nonnegative_u64(offset, FileAdapterError::Offset)?,
        requested_len,
    })
}

fn is_file_transfer_payload(payload: &[u8]) -> bool {
    matches!(
        BridgeCommand::decode(payload),
        Ok(BridgeCommand::FileList(_)
            | BridgeCommand::FileStat(_)
            | BridgeCommand::UploadBegin(_)
            | BridgeCommand::UploadResume(_)
            | BridgeCommand::UploadChunk { .. }
            | BridgeCommand::UploadFinalize(_)
            | BridgeCommand::UploadAbort(_)
            | BridgeCommand::DownloadChunk { .. })
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_fileListPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    remote_path: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let remote_path = env.convert_byte_array(&remote_path)?;
            let payload = encode_file_list(&remote_path).unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_fileStatPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    remote_path: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let remote_path = env.convert_byte_array(&remote_path)?;
            let payload = encode_file_stat(&remote_path).unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

fn jni_upload_plan<'caller>(
    unowned_env: &mut EnvUnowned<'caller>,
    transfer: &JByteArray<'caller>,
    destination: &JByteArray<'caller>,
    total_bytes: jlong,
    sha256: &JByteArray<'caller>,
    resume: bool,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let transfer = env.convert_byte_array(transfer)?;
            let destination = env.convert_byte_array(destination)?;
            let sha256 = env.convert_byte_array(sha256)?;
            let payload = if resume {
                encode_upload_resume(&transfer, &destination, total_bytes, &sha256)
            } else {
                encode_upload_begin(&transfer, &destination, total_bytes, &sha256)
            }
            .unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_uploadBeginPayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transfer: JByteArray<'caller>,
    destination: JByteArray<'caller>,
    total_bytes: jlong,
    sha256: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_upload_plan(
        &mut env,
        &transfer,
        &destination,
        total_bytes,
        &sha256,
        false,
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_uploadResumePayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transfer: JByteArray<'caller>,
    destination: JByteArray<'caller>,
    total_bytes: jlong,
    sha256: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_upload_plan(
        &mut env,
        &transfer,
        &destination,
        total_bytes,
        &sha256,
        true,
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_uploadChunkPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transfer: JByteArray<'caller>,
    offset: jlong,
    chunk: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let transfer = env.convert_byte_array(&transfer)?;
            let chunk = env.convert_byte_array(&chunk)?;
            let payload = encode_upload_chunk(&transfer, offset, &chunk).unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

fn jni_transfer_only<'caller>(
    unowned_env: &mut EnvUnowned<'caller>,
    transfer: &JByteArray<'caller>,
    finalize: bool,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let transfer = env.convert_byte_array(transfer)?;
            let payload = if finalize {
                encode_upload_finalize(&transfer)
            } else {
                encode_upload_abort(&transfer)
            }
            .unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_uploadFinalizePayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transfer: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_transfer_only(&mut env, &transfer, true)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_uploadAbortPayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transfer: JByteArray<'caller>,
) -> JByteArray<'caller> {
    jni_transfer_only(&mut env, &transfer, false)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_downloadChunkPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    remote_path: JByteArray<'caller>,
    offset: jlong,
    requested_len: jint,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let remote_path = env.convert_byte_array(&remote_path)?;
            let payload =
                encode_download_chunk(&remote_path, offset, requested_len).unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_isFileTransferPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    payload: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let payload = env.convert_byte_array(&payload)?;
            Ok(is_file_transfer_payload(&payload))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use prw_file_service::RemotePath;
    use prw_file_transfer::{MAX_TRANSFER_BYTES, TransferId, UploadPlan};
    use prw_remote_bridge::{BridgeCommand, MAX_BRIDGE_INLINE_BYTES};

    use super::*;

    const ID: &[u8] = b"abababababababababababababababab";

    fn expected_id() -> TransferId {
        TransferId::from_hex("abababababababababababababababab").expect("transfer id")
    }

    #[test]
    fn all_phase148_payloads_round_trip_through_existing_bridge_codec() {
        let root = encode_file_list(b"").expect("list root");
        assert_eq!(
            BridgeCommand::decode(&root).expect("decode list"),
            BridgeCommand::FileList(RemotePath::parse("").expect("root path"))
        );

        let stat = encode_file_stat(b"docs/readme.txt").expect("stat");
        assert_eq!(
            BridgeCommand::decode(&stat).expect("decode stat"),
            BridgeCommand::FileStat(RemotePath::parse("docs/readme.txt").expect("path"))
        );

        let sha = [7_u8; 32];
        let plan = UploadPlan::new(
            expected_id(),
            RemotePath::parse("uploads/demo.bin").expect("destination"),
            120_000,
            sha,
        )
        .expect("plan");
        let begin = encode_upload_begin(ID, b"uploads/demo.bin", 120_000, &sha).expect("begin");
        assert_eq!(
            BridgeCommand::decode(&begin).expect("decode begin"),
            BridgeCommand::UploadBegin(plan.clone())
        );
        let resume = encode_upload_resume(ID, b"uploads/demo.bin", 120_000, &sha).expect("resume");
        assert_eq!(
            BridgeCommand::decode(&resume).expect("decode resume"),
            BridgeCommand::UploadResume(plan)
        );

        let chunk = encode_upload_chunk(ID, 60_000, b"abc").expect("chunk");
        assert_eq!(
            BridgeCommand::decode(&chunk).expect("decode chunk"),
            BridgeCommand::UploadChunk {
                transfer_id: expected_id(),
                offset: 60_000,
                chunk: b"abc".to_vec()
            }
        );

        let finalize = encode_upload_finalize(ID).expect("finalize");
        assert_eq!(
            BridgeCommand::decode(&finalize).expect("decode finalize"),
            BridgeCommand::UploadFinalize(expected_id())
        );
        let abort = encode_upload_abort(ID).expect("abort");
        assert_eq!(
            BridgeCommand::decode(&abort).expect("decode abort"),
            BridgeCommand::UploadAbort(expected_id())
        );

        let download =
            encode_download_chunk(b"downloads/demo.bin", 60_000, 4096).expect("download");
        assert_eq!(
            BridgeCommand::decode(&download).expect("decode download"),
            BridgeCommand::DownloadChunk {
                path: RemotePath::parse("downloads/demo.bin").expect("download path"),
                offset: 60_000,
                requested_len: 4096
            }
        );

        for payload in [
            &root, &stat, &begin, &resume, &chunk, &finalize, &abort, &download,
        ] {
            assert!(is_file_transfer_payload(payload));
        }
    }

    #[test]
    fn path_and_transfer_bounds_fail_closed() {
        assert_eq!(encode_file_list(b"/absolute"), Err(FileAdapterError::Path));
        assert_eq!(encode_file_list(b"../escape"), Err(FileAdapterError::Path));
        assert_eq!(
            encode_upload_finalize(b"ABABABABABABABABABABABABABABABAB"),
            Err(FileAdapterError::TransferId)
        );
        assert_eq!(
            encode_upload_begin(ID, b"file", 1, &[0; 31]),
            Err(FileAdapterError::Digest)
        );
        assert_eq!(
            encode_upload_begin(ID, b"file", -1, &[0; 32]),
            Err(FileAdapterError::Total)
        );
        assert_eq!(
            encode_upload_begin(
                ID,
                b"file",
                i64::try_from(MAX_TRANSFER_BYTES + 1).expect("bound"),
                &[0; 32]
            ),
            Err(FileAdapterError::Total)
        );
        assert_eq!(
            encode_upload_chunk(ID, 0, b""),
            Err(FileAdapterError::Chunk)
        );
        assert_eq!(
            encode_upload_chunk(ID, 0, &vec![0; MAX_BRIDGE_INLINE_BYTES + 1]),
            Err(FileAdapterError::Chunk)
        );
        assert_eq!(
            encode_upload_chunk(ID, -1, b"a"),
            Err(FileAdapterError::Offset)
        );
        assert_eq!(
            encode_download_chunk(b"file", 0, 0),
            Err(FileAdapterError::Read)
        );
        assert_eq!(
            encode_download_chunk(
                b"file",
                0,
                i32::try_from(MAX_BRIDGE_INLINE_BYTES + 1).expect("bound")
            ),
            Err(FileAdapterError::Read)
        );
    }

    #[test]
    fn recognizer_rejects_non_file_bridge_payload() {
        let status = BridgeCommand::AgentStatus.encode().expect("status");
        assert!(!is_file_transfer_payload(&status));
        assert!(!is_file_transfer_payload(b"not-prwc"));
    }
}
