//! Finite worker for legacy commands plus the fixed bounded command-3 local slice.
//!
//! Normal `AgentStatus`/`FileList` requests preserve the existing configured request budget.
//! A successful fresh `UploadBegin` may extend only that authenticated connection while one
//! upload remains active, under a hard bound derived from the global transfer/chunk limits.
//! Teardown explicitly aborts any unfinished staging transaction before provider state drops.

use std::os::unix::net::UnixStream;

use prw_file_service::MAX_TRANSFER_CHUNK_BYTES;
use prw_file_transfer::MAX_TRANSFER_BYTES;
use prw_policy::PolicyEvaluator;

use super::{LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop};
use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
use crate::linux_identity::worker_capacity::LocalLinuxWorkerPermit;
use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use crate::local_commands::management_agent_status_runtime::{
    LocalBoundedUploadRuntime, home_filesystem_authority,
};
use crate::local_commands::management_authority::LocalManagementFilesystemAuthority;
use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use crate::local_commands::status_snapshot::LocalAgentStatusSnapshot;

#[allow(
    clippy::cast_possible_truncation,
    reason = "the fixed transfer limits produce 1024 chunks, which fits every supported usize"
)]
const MAX_UPLOAD_CHUNKS: usize =
    MAX_TRANSFER_BYTES.div_ceil(MAX_TRANSFER_CHUNK_BYTES as u64) as usize;
/// After `UploadBegin` has consumed one normal request slot, at most every full transfer
/// chunk plus one `UploadFinalize` or `UploadAbort` request may extend the connection.
const MAX_UPLOAD_CONTINUATION_REQUESTS: usize = MAX_UPLOAD_CHUNKS + 1;

/// Coarse crate-internal failure for one bounded-management finite worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalLinuxAgentStatusManagementSessionWorkerError {
    /// One request failed after the stated number of prior responses.
    Processing {
        /// Number of terminal responses completed before the failing request.
        responses_written: usize,
    },
    /// Explicit unfinished-upload cleanup failed before provider state could be dropped cleanly.
    Cleanup {
        /// Number of terminal responses completed before cleanup failed.
        responses_written: usize,
    },
}

/// Runs one authenticated local session through the bounded production command-3 slice.
///
/// The existing `$HOME` descriptor authority is opened before mutable upload state is created.
/// If that authority cannot be opened, the exact compatibility worker remains available so
/// `AgentStatus` keeps working and `FileList` retains its existing per-request failure behavior.
/// No caller can supply management policy, host root, terminal backend, or forwarding backend.
///
/// # Errors
///
/// Returns on the first request-processing or explicit upload-cleanup failure and preserves
/// the number of prior completed terminal responses.
pub(super) fn run_authenticated_session_worker_with_agent_status_management<
    RE: PolicyEvaluator + ?Sized,
>(
    session: AuthenticatedLocalLinuxSession<UnixStream>,
    permit: LocalLinuxWorkerPermit,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxAgentStatusManagementSessionWorkerError> {
    let _permit = permit;
    match home_filesystem_authority() {
        Ok(filesystem) => run_authenticated_session_worker_with_bounded_upload(
            session,
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
            config,
            &filesystem,
        ),
        Err(_) => run_authenticated_session_worker_compatibility(
            session,
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
            config,
        ),
    }
}

fn run_authenticated_session_worker_compatibility<RE: PolicyEvaluator + ?Sized>(
    mut session: AuthenticatedLocalLinuxSession<UnixStream>,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxAgentStatusManagementSessionWorkerError> {
    for responses_written in 0..config.request_budget().get() {
        match session.process_one_agent_status_management_with_deadlines(
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
            config.read_budget(),
            config.write_budget(),
        ) {
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten) => {}
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof) => {
                return Ok(LocalLinuxSessionWorkerStop::CleanEof { responses_written });
            }
            Err(_) => {
                return Err(
                    LocalLinuxAgentStatusManagementSessionWorkerError::Processing {
                        responses_written,
                    },
                );
            }
        }
    }

    Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
        responses_written: config.request_budget().get(),
    })
}

fn run_authenticated_session_worker_with_bounded_upload<RE: PolicyEvaluator + ?Sized>(
    mut session: AuthenticatedLocalLinuxSession<UnixStream>,
    read_evaluator: &RE,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
    config: LocalLinuxSessionWorkerConfig,
    filesystem: &LocalManagementFilesystemAuthority,
) -> Result<LocalLinuxSessionWorkerStop, LocalLinuxAgentStatusManagementSessionWorkerError> {
    let mut runtime = LocalBoundedUploadRuntime::new(filesystem);
    let base_request_budget = config.request_budget().get();
    let hard_request_limit = base_request_budget.saturating_add(MAX_UPLOAD_CONTINUATION_REQUESTS);
    let mut responses_written = 0_usize;

    let result = loop {
        if responses_written >= base_request_budget && !runtime.is_upload_active() {
            break Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted { responses_written });
        }
        if responses_written >= hard_request_limit {
            break Ok(LocalLinuxSessionWorkerStop::RequestBudgetExhausted { responses_written });
        }

        match session.process_one_agent_status_file_list_upload_management_with_deadlines(
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
            &mut runtime,
            config.read_budget(),
            config.write_budget(),
        ) {
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten) => {
                responses_written += 1;
            }
            Ok(LocalBoundaryRequestResponseOutcome::CleanEof) => {
                break Ok(LocalLinuxSessionWorkerStop::CleanEof { responses_written });
            }
            Err(_) => {
                break Err(
                    LocalLinuxAgentStatusManagementSessionWorkerError::Processing {
                        responses_written,
                    },
                );
            }
        }
    };

    if runtime.finish().is_err() {
        return Err(LocalLinuxAgentStatusManagementSessionWorkerError::Cleanup {
            responses_written,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::net::Shutdown;
    use std::num::NonZeroUsize;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use aws_lc_rs::digest::{SHA256, digest};
    use prw_file_service::{RemotePath, transfer_staging_name};
    use prw_file_transfer::{TransferId, UploadPlan};
    use prw_network::PrivateDnsConfig;
    use prw_policy::BoundedLocalReadPolicy;
    use prw_remote_bridge::BridgeCommand;

    use super::{
        LocalLinuxSessionWorkerConfig, LocalLinuxSessionWorkerStop,
        run_authenticated_session_worker_with_agent_status_management,
        run_authenticated_session_worker_with_bounded_upload,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::write_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::linux_identity::authenticated_session::AuthenticatedLocalLinuxSession;
    use crate::linux_identity::deadline_io::LocalLinuxIoBudget;
    use crate::linux_identity::worker_capacity::LocalLinuxWorkerCapacity;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::management_authority::LocalManagementFilesystemAuthority;
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::build_local_command_request_frame;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("request id is non-zero")
    }

    fn session(stream: UnixStream) -> AuthenticatedLocalLinuxSession<UnixStream> {
        let connection = AuthenticatedLocalLinuxConnection::try_new(stream)
            .expect("same-UID test stream authenticates");
        AuthenticatedLocalLinuxSession::new(connection)
    }

    fn status() -> LocalAgentStatusSnapshot {
        LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready)
    }

    fn dns() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    fn config() -> LocalLinuxSessionWorkerConfig {
        LocalLinuxSessionWorkerConfig::new(
            NonZeroUsize::new(1).expect("request budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("read budget is non-zero"),
            LocalLinuxIoBudget::try_new(Duration::from_secs(2)).expect("write budget is non-zero"),
        )
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ownspace-bounded-upload-worker-{}-{sequence}-{nonce}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test root creates");
        path
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        let value = digest(&SHA256, bytes);
        let mut output = [0_u8; 32];
        output.copy_from_slice(value.as_ref());
        output
    }

    fn management_frame(
        request_id: u64,
        command: &BridgeCommand,
    ) -> crate::frame_object::LocalIpcFrame {
        let bridge = command.encode().expect("management command encodes");
        build_local_management_request_frame(id(request_id), &bridge)
            .expect("management frame builds")
    }

    #[test]
    fn command_three_agent_status_runs_through_narrow_worker() {
        let (server, mut client) = UnixStream::pair().expect("local pair creates");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity is non-zero"));
        let permit = capacity.try_acquire().expect("worker permit acquires");
        let bridge = BridgeCommand::AgentStatus
            .encode()
            .expect("AgentStatus command encodes");
        let frame = build_local_management_request_frame(id(951), &bridge)
            .expect("management frame builds");
        write_frame(&mut client, &frame).expect("management request writes");

        let stop = run_authenticated_session_worker_with_agent_status_management(
            session(server),
            permit,
            &BoundedLocalReadPolicy::deny_all(),
            status(),
            &dns(),
            config(),
        )
        .expect("narrow management worker succeeds");

        assert_eq!(
            stop,
            LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                responses_written: 1
            }
        );
        assert_eq!(capacity.active_workers(), 0);

        let response = read_frame(&mut client).expect("management response reads");
        let terminal =
            validate_terminal_response_frame(&response).expect("management response validates");
        assert_eq!(terminal.request_id(), id(951));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
    }

    #[test]
    fn legacy_command_one_keeps_existing_response_path() {
        let (server, mut client) = UnixStream::pair().expect("local pair creates");
        let capacity =
            LocalLinuxWorkerCapacity::new(NonZeroUsize::new(1).expect("capacity is non-zero"));
        let permit = capacity.try_acquire().expect("worker permit acquires");
        let frame = build_local_command_request_frame(id(952), LocalAgentCommand::GetAgentStatus)
            .expect("legacy frame builds");
        write_frame(&mut client, &frame).expect("legacy request writes");

        run_authenticated_session_worker_with_agent_status_management(
            session(server),
            permit,
            &BoundedLocalReadPolicy::allow_local_reads(),
            status(),
            &dns(),
            config(),
        )
        .expect("legacy request succeeds");

        assert_eq!(capacity.active_workers(), 0);
        let response = read_frame(&mut client).expect("response reads");
        let decoded =
            decode_success_status_frame(&response).expect("legacy status response decodes");
        assert_eq!(decoded.request_id(), id(952));

        let mut trailing = [0_u8; 1];
        assert_eq!(
            client
                .read(&mut trailing)
                .expect("worker stream reaches EOF"),
            0
        );
    }

    #[test]
    fn active_upload_extends_only_its_connection_beyond_base_request_budget() {
        let root = test_root("complete");
        let filesystem = LocalManagementFilesystemAuthority::open_trusted_root(&root)
            .expect("test filesystem authority opens");
        let payload = b"bounded live upload";
        let transfer_id = TransferId::new([0x41; 16]);
        let plan = UploadPlan::new(
            transfer_id,
            RemotePath::parse("uploaded.bin").expect("destination path"),
            payload.len() as u64,
            sha(payload),
        )
        .expect("upload plan");
        let (server, mut client) = UnixStream::pair().expect("local pair creates");

        for frame in [
            management_frame(960, &BridgeCommand::UploadBegin(plan)),
            management_frame(
                961,
                &BridgeCommand::UploadChunk {
                    transfer_id,
                    offset: 0,
                    chunk: payload.to_vec(),
                },
            ),
            management_frame(962, &BridgeCommand::UploadFinalize(transfer_id)),
        ] {
            write_frame(&mut client, &frame).expect("upload request writes");
        }

        let stop = run_authenticated_session_worker_with_bounded_upload(
            session(server),
            &BoundedLocalReadPolicy::allow_local_reads(),
            status(),
            &dns(),
            config(),
            &filesystem,
        )
        .expect("bounded upload worker succeeds");

        assert_eq!(
            stop,
            LocalLinuxSessionWorkerStop::RequestBudgetExhausted {
                responses_written: 3
            }
        );
        for request_id in [960, 961, 962] {
            let frame = read_frame(&mut client).expect("upload response reads");
            let terminal = validate_terminal_response_frame(&frame).expect("response validates");
            assert_eq!(terminal.request_id(), id(request_id));
            assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        }
        assert_eq!(
            fs::read(root.join("uploaded.bin")).expect("final file"),
            payload
        );
        fs::remove_dir_all(root).expect("test root removes");
    }

    #[test]
    fn clean_eof_aborts_unfinished_upload_before_worker_returns() {
        let root = test_root("abort-on-eof");
        let filesystem = LocalManagementFilesystemAuthority::open_trusted_root(&root)
            .expect("test filesystem authority opens");
        let transfer_id = TransferId::new([0x42; 16]);
        let plan = UploadPlan::new(
            transfer_id,
            RemotePath::parse("never-published.bin").expect("destination path"),
            4,
            sha(b"data"),
        )
        .expect("upload plan");
        let (server, mut client) = UnixStream::pair().expect("local pair creates");
        let begin = management_frame(970, &BridgeCommand::UploadBegin(plan));
        write_frame(&mut client, &begin).expect("begin writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client write direction closes");

        let stop = run_authenticated_session_worker_with_bounded_upload(
            session(server),
            &BoundedLocalReadPolicy::allow_local_reads(),
            status(),
            &dns(),
            config(),
            &filesystem,
        )
        .expect("clean EOF performs bounded cleanup");

        assert_eq!(
            stop,
            LocalLinuxSessionWorkerStop::CleanEof {
                responses_written: 1
            }
        );
        let response = read_frame(&mut client).expect("begin response reads");
        let terminal = validate_terminal_response_frame(&response).expect("response validates");
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Ok);
        assert!(!root.join("never-published.bin").exists());
        assert!(
            !root
                .join(transfer_staging_name(*transfer_id.as_bytes()))
                .exists()
        );
        fs::remove_dir_all(root).expect("test root removes");
    }
}
