//! Headless Ownspace Agent binary bootstrap.
//!
//! The executable boundary performs fail-closed device-identity custody first,
//! then proves or completes owner startup authority with that exact public identity
//! before selecting or entering either Linux runtime lane. Invalid identity or
//! startup-authority state therefore fails before the Agent runtime directory,
//! instance lock, or local socket can be created.

use std::process::ExitCode;

fn sha256_hex(fingerprint: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in fingerprint {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let Ok(device_identity_signer) =
        prw_device_identity_custody::load_ubuntu_enrollment_signer_from_systemd_credential()
    else {
        eprintln!(
            "prw-agent event=startup_failure kind=device_identity exit=failure signal_mask_restore=not_applicable"
        );
        return ExitCode::FAILURE;
    };

    println!(
        "prw-agent event=device_identity_loaded public_spki_sha256={}",
        sha256_hex(device_identity_signer.public_identity_sha256())
    );

    if let Err(stage) =
        prw_agent::gate_owner_startup_authority(device_identity_signer.public_identity())
    {
        eprintln!(
            "prw-agent event=startup_failure kind=startup_authority stage={} exit=failure signal_mask_restore=not_applicable",
            stage.token(),
        );
        return ExitCode::FAILURE;
    }

    let Ok(execution_mode) = prw_agent::linux_bootstrap::load_linux_agent_execution_mode_from_env()
    else {
        eprintln!(
            "prw-agent event=startup_failure kind=execution_mode exit=failure signal_mask_restore=not_applicable"
        );
        return ExitCode::FAILURE;
    };

    match execution_mode {
        prw_agent::linux_bootstrap::LinuxAgentExecutionMode::LocalOnly => {
            match prw_agent::linux_bootstrap::run() {
                Ok(report) => {
                    let counters = report.counters();
                    let success = report.is_success();
                    eprintln!(
                        "prw-agent event=terminal terminal={} exit={} readiness_steps={} listener_armed_steps={} runtime_wakes={} wait_interruptions={} scheduling_attempts={} workers_registered={} worker_completions={} peer_rejections={} cleanup={} signal_mask_restore={}",
                        report.terminal().token(),
                        if success { "success" } else { "failure" },
                        counters.readiness_steps(),
                        counters.listener_armed_steps(),
                        counters.runtime_wakes(),
                        counters.wait_interruptions(),
                        counters.scheduling_attempts(),
                        counters.workers_registered(),
                        counters.worker_completions(),
                        counters.peer_rejections(),
                        report.cleanup().token(),
                        report.signal_mask_restore().token(),
                    );
                    if success {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(failure) => {
                    eprintln!(
                        "prw-agent event=startup_failure kind={} exit=failure signal_mask_restore={}",
                        failure.kind().token(),
                        failure.signal_mask_restore().token(),
                    );
                    ExitCode::FAILURE
                }
            }
        }
        prw_agent::linux_bootstrap::LinuxAgentExecutionMode::ConfiguredRemote => {
            match prw_agent::linux_bootstrap::run_with_configured_production_remote_companion() {
                Ok(report) => {
                    let local = report.local();
                    let remote = report.remote();
                    let counters = local.counters();
                    let success = local.is_success() && remote.is_success();
                    eprintln!(
                        "prw-agent event=terminal terminal={} exit={} readiness_steps={} listener_armed_steps={} runtime_wakes={} wait_interruptions={} scheduling_attempts={} workers_registered={} worker_completions={} peer_rejections={} cleanup={} signal_mask_restore={} remote_companion={}",
                        local.terminal().token(),
                        if success { "success" } else { "failure" },
                        counters.readiness_steps(),
                        counters.listener_armed_steps(),
                        counters.runtime_wakes(),
                        counters.wait_interruptions(),
                        counters.scheduling_attempts(),
                        counters.workers_registered(),
                        counters.worker_completions(),
                        counters.peer_rejections(),
                        local.cleanup().token(),
                        local.signal_mask_restore().token(),
                        remote.token(),
                    );
                    if success {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(failure) => {
                    eprintln!(
                        "prw-agent event=startup_failure kind={} exit=failure signal_mask_restore={}",
                        failure.kind().token(),
                        failure.signal_mask_restore().token(),
                    );
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!(
        "prw-agent event=startup_failure kind=unsupported_platform exit=failure signal_mask_restore=not_applicable"
    );
    ExitCode::FAILURE
}
