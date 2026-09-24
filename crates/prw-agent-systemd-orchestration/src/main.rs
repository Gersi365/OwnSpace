use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use prw_agent_systemd_orchestration::{parse_action_args, run_process_action};

    let action = match parse_action_args(std::env::args_os().skip(1)) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("prw-agent-configure event=failed kind={error} exit=failure");
            return ExitCode::FAILURE;
        }
    };
    match run_process_action(action) {
        Ok(outcome) => {
            println!("prw-agent-configure event=complete action={outcome}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("prw-agent-configure event=failed kind={error} exit=failure");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("prw-agent-configure event=failed kind=unsupported_platform exit=failure");
    ExitCode::FAILURE
}
