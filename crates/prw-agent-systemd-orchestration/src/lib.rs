//! Same-user Linux systemd configuration orchestration selected by C03e-TX.
//!
//! The production entry point is deliberately one-shot and fixed-surface. It accepts only `write`
//! or `reconfigure-active`, acquires the existing seven process configuration values, and never
//! changes enablement or linger state. The active lane is guarded by existing local Agent IPC
//! readiness and uses only fixed absolute systemd executables.

use std::{ffi::OsString, fmt};

/// Fixed administrative action accepted by `prw-agent-configure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministrativeAction {
    /// Commit and verify only managed configuration files.
    Write,
    /// Reconfigure an already healthy active Agent with bounded rollback.
    ReconfigureActive,
}

impl fmt::Display for AdministrativeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Write => "write",
            Self::ReconfigureActive => "reconfigure-active",
        })
    }
}

/// Invalid fixed action grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidArguments;

impl fmt::Display for InvalidArguments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid_arguments")
    }
}

impl std::error::Error for InvalidArguments {}

/// Parses exactly one fixed action token and rejects every additional argument.
///
/// # Errors
/// Returns [`InvalidArguments`] for missing, unknown, non-Unicode, or extra arguments.
pub fn parse_action_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<AdministrativeAction, InvalidArguments> {
    let mut args = args.into_iter();
    let action = args.next().ok_or(InvalidArguments)?;
    if args.next().is_some() {
        return Err(InvalidArguments);
    }
    match action.to_str() {
        Some("write") => Ok(AdministrativeAction::Write),
        Some("reconfigure-active") => Ok(AdministrativeAction::ReconfigureActive),
        _ => Err(InvalidArguments),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        ffi::OsString,
        fs,
        os::unix::{
            ffi::OsStringExt,
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use prw_agent::{
        LocalIpcContract, LocalIpcProtocolVersion, LocalIpcRequestId,
        frame_object::reader::read_frame,
        local_commands::{
            LocalAgentCommand, request_frame::stream::write_local_command_request,
            status_snapshot::response_frame::decode_success_status_frame,
        },
    };
    use prw_agent_configuration::linux_systemd::{
        CONFIGURED_REMOTE_INPUTS_DROPIN_NAME, EXECUTION_MODE_DROPIN_NAME,
        ExternalSystemdFragmentCustody, IntendedUserSystemdContext, ManagedAgentConfiguration,
        ManagedSystemdWriteResult, RecoverableManagedSystemdTransaction,
        apply_managed_systemd_configuration, apply_managed_systemd_configuration_recoverable,
        capture_external_systemd_fragment_custody, reprove_external_systemd_fragment_custody,
        restore_recoverable_managed_systemd_configuration,
    };
    use prw_agent_configuration::{
        AgentExecutionMode, ConfiguredRemoteBundle, PRW_AGENT_EXECUTION_MODE,
        PRW_REMOTE_APPLICATION_LEASE_SECONDS, PRW_REMOTE_BIND_ADDR,
        PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
        PRW_REMOTE_MAX_ACTIVE_WORKERS, PRW_REMOTE_PEER_DEVICE_ID,
        PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS, validate_agent_execution_mode,
    };
    use rustix::{
        fs::{Mode, OFlags, open},
        net::sockopt::socket_peercred,
        process::{geteuid, getuid},
    };

    use super::AdministrativeAction;

    const SYSTEMD_ANALYZE_PATH: &str = "/usr/bin/systemd-analyze";
    const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
    const AGENT_UNIT: &str = "prw-agent.service";
    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
    const PRIVATE_SOCKET_MODE: u32 = 0o600;
    const READINESS_DEADLINE: Duration = Duration::from_secs(5);
    const IPC_TIMEOUT: Duration = Duration::from_secs(2);
    const READINESS_POLL: Duration = Duration::from_millis(100);
    const READINESS_REQUEST_ID: u64 = 0x5459;

    /// Stable bounded orchestration failure classification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OrchestrationError {
        Environment,
        SameUserContext,
        Configuration,
        BaselineSystemd,
        BaselineReadiness,
        ManagedWrite,
        ExternalConfigurationDrift,
        TargetVerify,
        DaemonReload,
        PostReloadState,
        TryRestart,
        PostRestartReadiness,
        Rollback,
    }

    impl std::fmt::Display for OrchestrationError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(match self {
                Self::Environment => "environment",
                Self::SameUserContext => "same_user_context",
                Self::Configuration => "configuration",
                Self::BaselineSystemd => "baseline_systemd",
                Self::BaselineReadiness => "baseline_readiness",
                Self::ManagedWrite => "managed_write",
                Self::ExternalConfigurationDrift => "external_configuration_drift",
                Self::TargetVerify => "target_verify",
                Self::DaemonReload => "daemon_reload",
                Self::PostReloadState => "post_reload_state",
                Self::TryRestart => "try_restart",
                Self::PostRestartReadiness => "post_restart_readiness",
                Self::Rollback => "rollback",
            })
        }
    }

    impl std::error::Error for OrchestrationError {}

    /// Successful fixed administrative action.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OrchestrationOutcome {
        Write,
        ReconfigureActive,
    }

    impl std::fmt::Display for OrchestrationOutcome {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(match self {
                Self::Write => "write",
                Self::ReconfigureActive => "reconfigure-active",
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EnvironmentReadError {
        Missing,
        InvalidUnicode,
    }

    trait EnvironmentSource {
        fn read(&mut self, name: &'static str) -> Result<String, EnvironmentReadError>;
    }

    struct ProcessEnvironment;

    impl EnvironmentSource for ProcessEnvironment {
        fn read(&mut self, name: &'static str) -> Result<String, EnvironmentReadError> {
            match std::env::var(name) {
                Ok(value) => Ok(value),
                Err(std::env::VarError::NotPresent) => Err(EnvironmentReadError::Missing),
                Err(std::env::VarError::NotUnicode(_)) => Err(EnvironmentReadError::InvalidUnicode),
            }
        }
    }

    #[derive(Debug)]
    struct UserContext {
        systemd: IntendedUserSystemdContext,
        runtime: Option<PathBuf>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct UnitStatus {
        load_state: String,
        active_state: String,
        sub_state: String,
        main_pid: u32,
        invocation_id: String,
        unit_file_state: String,
        drop_in_paths: Vec<PathBuf>,
    }

    impl UnitStatus {
        fn is_active_running(&self) -> bool {
            self.load_state == "loaded"
                && self.active_state == "active"
                && self.sub_state == "running"
                && self.main_pid != 0
                && !self.invocation_id.is_empty()
                && !self.unit_file_state.is_empty()
        }
    }

    fn acquire_user_context(
        env: &mut impl EnvironmentSource,
        require_runtime: bool,
        uid: u32,
        euid: u32,
    ) -> Result<UserContext, OrchestrationError> {
        if uid != euid {
            return Err(OrchestrationError::SameUserContext);
        }
        let home = PathBuf::from(
            env.read("HOME")
                .map_err(|_| OrchestrationError::Environment)?,
        );
        if !home.is_absolute() {
            return Err(OrchestrationError::SameUserContext);
        }
        let config = env.read("XDG_CONFIG_HOME").map_or_else(
            |error| match error {
                EnvironmentReadError::Missing => Ok(home.join(".config")),
                EnvironmentReadError::InvalidUnicode => Err(OrchestrationError::Environment),
            },
            |value| Ok(PathBuf::from(value)),
        )?;
        if !config.is_absolute() {
            return Err(OrchestrationError::SameUserContext);
        }
        let systemd = IntendedUserSystemdContext::new(uid, home, config)
            .map_err(|_| OrchestrationError::SameUserContext)?;
        let runtime = if require_runtime {
            let path = PathBuf::from(
                env.read("XDG_RUNTIME_DIR")
                    .map_err(|_| OrchestrationError::Environment)?,
            );
            validate_private_directory(&path, uid)?;
            Some(path)
        } else {
            None
        };
        Ok(UserContext { systemd, runtime })
    }

    fn validate_private_directory(path: &Path, uid: u32) -> Result<(), OrchestrationError> {
        if !path.is_absolute() {
            return Err(OrchestrationError::SameUserContext);
        }
        let before = fs::symlink_metadata(path).map_err(|_| OrchestrationError::SameUserContext)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != uid
            || before.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(OrchestrationError::SameUserContext);
        }
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| OrchestrationError::SameUserContext)?;
        let opened = std::fs::File::from(fd)
            .metadata()
            .map_err(|_| OrchestrationError::SameUserContext)?;
        if !opened.is_dir()
            || opened.uid() != uid
            || opened.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            || before.dev() != opened.dev()
            || before.ino() != opened.ino()
        {
            return Err(OrchestrationError::SameUserContext);
        }
        Ok(())
    }

    fn acquire_desired_configuration(
        env: &mut impl EnvironmentSource,
    ) -> Result<ManagedAgentConfiguration, OrchestrationError> {
        let mode_text = env
            .read(PRW_AGENT_EXECUTION_MODE)
            .map_err(|_| OrchestrationError::Environment)?;
        let mode = validate_agent_execution_mode(&mode_text)
            .map_err(|_| OrchestrationError::Configuration)?;
        match mode {
            AgentExecutionMode::LocalOnly => Ok(ManagedAgentConfiguration::LocalOnly),
            AgentExecutionMode::ConfiguredRemote => {
                let bind = env
                    .read(PRW_REMOTE_BIND_ADDR)
                    .map_err(|_| OrchestrationError::Environment)?;
                let peer = env
                    .read(PRW_REMOTE_PEER_DEVICE_ID)
                    .map_err(|_| OrchestrationError::Environment)?;
                let workers = env
                    .read(PRW_REMOTE_MAX_ACTIVE_WORKERS)
                    .map_err(|_| OrchestrationError::Environment)?;
                let lease = env
                    .read(PRW_REMOTE_APPLICATION_LEASE_SECONDS)
                    .map_err(|_| OrchestrationError::Environment)?;
                let rendezvous = env
                    .read(PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS)
                    .map_err(|_| OrchestrationError::Environment)?;
                let scheduling = env
                    .read(PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS)
                    .map_err(|_| OrchestrationError::Environment)?;
                let bundle = ConfiguredRemoteBundle::try_new(
                    &bind,
                    &peer,
                    &workers,
                    &lease,
                    &rendezvous,
                    &scheduling,
                )
                .map_err(|_| OrchestrationError::Configuration)?;
                Ok(ManagedAgentConfiguration::ConfiguredRemote(Box::new(
                    bundle,
                )))
            }
        }
    }

    trait ActivationBackend {
        type Recovery;
        type ExternalCustody;

        fn write_only(
            &mut self,
            context: &UserContext,
            desired: &ManagedAgentConfiguration,
        ) -> Result<(), OrchestrationError>;
        fn status(&mut self, context: &UserContext) -> Result<UnitStatus, OrchestrationError>;
        fn ready_once(&mut self, context: &UserContext) -> Result<(), OrchestrationError>;
        fn capture_external_custody(
            &mut self,
            context: &UserContext,
        ) -> Result<Self::ExternalCustody, OrchestrationError>;
        fn reprove_external_custody(
            &mut self,
            context: &UserContext,
            custody: &Self::ExternalCustody,
        ) -> Result<(), OrchestrationError>;
        fn write_recoverable(
            &mut self,
            context: &UserContext,
            desired: &ManagedAgentConfiguration,
        ) -> Result<Self::Recovery, OrchestrationError>;
        fn restore(
            &mut self,
            context: &UserContext,
            recovery: Self::Recovery,
        ) -> Result<(), OrchestrationError>;
        fn verify_target(&mut self, context: &UserContext) -> Result<(), OrchestrationError>;
        fn daemon_reload(&mut self, context: &UserContext) -> Result<(), OrchestrationError>;
        fn try_restart(&mut self, context: &UserContext) -> Result<(), OrchestrationError>;
        fn restart(&mut self, context: &UserContext) -> Result<(), OrchestrationError>;
        fn wait_ready(
            &mut self,
            context: &UserContext,
            unit_file_state: &str,
            prior_invocation_id: Option<&str>,
        ) -> Result<UnitStatus, OrchestrationError>;
    }

    struct ProductionBackend;

    impl ActivationBackend for ProductionBackend {
        type Recovery = RecoverableManagedSystemdTransaction;
        type ExternalCustody = ExternalSystemdFragmentCustody;

        fn write_only(
            &mut self,
            context: &UserContext,
            desired: &ManagedAgentConfiguration,
        ) -> Result<(), OrchestrationError> {
            apply_managed_systemd_configuration(&context.systemd, desired)
                .map(|_: ManagedSystemdWriteResult| ())
                .map_err(|_| OrchestrationError::ManagedWrite)
        }

        fn status(&mut self, context: &UserContext) -> Result<UnitStatus, OrchestrationError> {
            query_unit_status(context)
        }

        fn ready_once(&mut self, context: &UserContext) -> Result<(), OrchestrationError> {
            probe_agent_ready(context)
        }

        fn capture_external_custody(
            &mut self,
            context: &UserContext,
        ) -> Result<Self::ExternalCustody, OrchestrationError> {
            capture_external_systemd_fragment_custody(&context.systemd)
                .map_err(|_| OrchestrationError::BaselineSystemd)
        }

        fn reprove_external_custody(
            &mut self,
            context: &UserContext,
            custody: &Self::ExternalCustody,
        ) -> Result<(), OrchestrationError> {
            reprove_external_systemd_fragment_custody(&context.systemd, custody)
                .map_err(|_| OrchestrationError::ExternalConfigurationDrift)
        }

        fn write_recoverable(
            &mut self,
            context: &UserContext,
            desired: &ManagedAgentConfiguration,
        ) -> Result<Self::Recovery, OrchestrationError> {
            apply_managed_systemd_configuration_recoverable(&context.systemd, desired)
                .map(|write| write.into_parts().1)
                .map_err(|_| OrchestrationError::ManagedWrite)
        }

        fn restore(
            &mut self,
            context: &UserContext,
            recovery: Self::Recovery,
        ) -> Result<(), OrchestrationError> {
            restore_recoverable_managed_systemd_configuration(&context.systemd, recovery)
                .map_err(|_| OrchestrationError::Rollback)
        }

        fn verify_target(&mut self, context: &UserContext) -> Result<(), OrchestrationError> {
            run_target_verify(context)
        }

        fn daemon_reload(&mut self, context: &UserContext) -> Result<(), OrchestrationError> {
            run_systemctl(context, &["daemon-reload"]).map_err(|_| OrchestrationError::DaemonReload)
        }

        fn try_restart(&mut self, context: &UserContext) -> Result<(), OrchestrationError> {
            run_systemctl(context, &["try-restart", AGENT_UNIT])
                .map_err(|_| OrchestrationError::TryRestart)
        }

        fn restart(&mut self, context: &UserContext) -> Result<(), OrchestrationError> {
            run_systemctl(context, &["restart", AGENT_UNIT])
                .map_err(|_| OrchestrationError::Rollback)
        }

        fn wait_ready(
            &mut self,
            context: &UserContext,
            unit_file_state: &str,
            prior_invocation_id: Option<&str>,
        ) -> Result<UnitStatus, OrchestrationError> {
            wait_for_ready(context, unit_file_state, prior_invocation_id)
        }
    }

    fn execute_with_backend(
        action: AdministrativeAction,
        env: &mut impl EnvironmentSource,
        uid: u32,
        euid: u32,
        backend: &mut impl ActivationBackend,
    ) -> Result<OrchestrationOutcome, OrchestrationError> {
        let context = acquire_user_context(
            env,
            matches!(action, AdministrativeAction::ReconfigureActive),
            uid,
            euid,
        )?;
        let desired = acquire_desired_configuration(env)?;
        match action {
            AdministrativeAction::Write => {
                backend.write_only(&context, &desired)?;
                Ok(OrchestrationOutcome::Write)
            }
            AdministrativeAction::ReconfigureActive => {
                reconfigure_active(&context, &desired, backend)?;
                Ok(OrchestrationOutcome::ReconfigureActive)
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RollbackDisposition {
        Restored,
        ExternalDrift,
    }

    fn fail_after_manager_mutation<B: ActivationBackend>(
        context: &UserContext,
        backend: &mut B,
        recovery: B::Recovery,
        baseline: &UnitStatus,
        external_custody: &B::ExternalCustody,
        restart_attempted: bool,
        original: OrchestrationError,
    ) -> Result<(), OrchestrationError> {
        match rollback_after_manager_mutation(
            context,
            backend,
            recovery,
            baseline,
            external_custody,
            restart_attempted,
        )? {
            RollbackDisposition::Restored => Err(original),
            RollbackDisposition::ExternalDrift => {
                Err(OrchestrationError::ExternalConfigurationDrift)
            }
        }
    }

    fn reprove_or_restore_managed_files<B: ActivationBackend>(
        context: &UserContext,
        backend: &mut B,
        recovery: B::Recovery,
        external_custody: &B::ExternalCustody,
    ) -> Result<B::Recovery, OrchestrationError> {
        if backend
            .reprove_external_custody(context, external_custody)
            .is_err()
        {
            backend.restore(context, recovery)?;
            Err(OrchestrationError::ExternalConfigurationDrift)
        } else {
            Ok(recovery)
        }
    }

    fn require_external_reproof<B: ActivationBackend>(
        context: &UserContext,
        backend: &mut B,
        external_custody: &B::ExternalCustody,
    ) -> Result<(), OrchestrationError> {
        backend
            .reprove_external_custody(context, external_custody)
            .map_err(|_| OrchestrationError::ExternalConfigurationDrift)
    }

    fn reconfigure_active<B: ActivationBackend>(
        context: &UserContext,
        desired: &ManagedAgentConfiguration,
        backend: &mut B,
    ) -> Result<(), OrchestrationError> {
        let baseline = backend.status(context)?;
        if !baseline.is_active_running() || !drop_in_paths_are_valid(&baseline.drop_in_paths) {
            return Err(OrchestrationError::BaselineSystemd);
        }
        backend
            .ready_once(context)
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        let external_custody = backend.capture_external_custody(context)?;
        let recovery = backend.write_recoverable(context, desired)?;

        let recovery =
            reprove_or_restore_managed_files(context, backend, recovery, &external_custody)?;
        if backend.verify_target(context).is_err() {
            backend.restore(context, recovery)?;
            return Err(OrchestrationError::TargetVerify);
        }
        let recovery =
            reprove_or_restore_managed_files(context, backend, recovery, &external_custody)?;
        if backend.daemon_reload(context).is_err() {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                false,
                OrchestrationError::DaemonReload,
            );
        }
        let Ok(post_reload) = backend.status(context) else {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                false,
                OrchestrationError::PostReloadState,
            );
        };
        if !loaded_topology_matches(context, desired, &baseline, &post_reload) {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                false,
                OrchestrationError::PostReloadState,
            );
        }
        if backend
            .reprove_external_custody(context, &external_custody)
            .is_err()
        {
            backend.restore(context, recovery)?;
            backend
                .daemon_reload(context)
                .map_err(|_| OrchestrationError::Rollback)?;
            return Err(OrchestrationError::ExternalConfigurationDrift);
        }
        if backend.try_restart(context).is_err() {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                true,
                OrchestrationError::TryRestart,
            );
        }
        let Ok(post_restart) = backend.wait_ready(
            context,
            &baseline.unit_file_state,
            Some(&baseline.invocation_id),
        ) else {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                true,
                OrchestrationError::PostRestartReadiness,
            );
        };
        if !loaded_topology_matches(context, desired, &baseline, &post_restart) {
            return fail_after_manager_mutation(
                context,
                backend,
                recovery,
                &baseline,
                &external_custody,
                true,
                OrchestrationError::PostRestartReadiness,
            );
        }
        require_external_reproof(context, backend, &external_custody)?;
        Ok(())
    }

    fn rollback_after_manager_mutation<B: ActivationBackend>(
        context: &UserContext,
        backend: &mut B,
        recovery: B::Recovery,
        baseline: &UnitStatus,
        external_custody: &B::ExternalCustody,
        restart_attempted: bool,
    ) -> Result<RollbackDisposition, OrchestrationError> {
        if backend
            .reprove_external_custody(context, external_custody)
            .is_err()
        {
            if restart_attempted {
                return Ok(RollbackDisposition::ExternalDrift);
            }
            backend.restore(context, recovery)?;
            backend
                .daemon_reload(context)
                .map_err(|_| OrchestrationError::Rollback)?;
            return Ok(RollbackDisposition::ExternalDrift);
        }
        backend.restore(context, recovery)?;
        backend
            .daemon_reload(context)
            .map_err(|_| OrchestrationError::Rollback)?;
        backend
            .restart(context)
            .map_err(|_| OrchestrationError::Rollback)?;
        let restored = backend
            .wait_ready(context, &baseline.unit_file_state, None)
            .map_err(|_| OrchestrationError::Rollback)?;
        if !drop_in_paths_are_valid(&restored.drop_in_paths)
            || restored.drop_in_paths != baseline.drop_in_paths
        {
            return Err(OrchestrationError::Rollback);
        }
        Ok(RollbackDisposition::Restored)
    }

    fn managed_drop_in_paths(context: &UserContext) -> (PathBuf, PathBuf) {
        let managed = context
            .systemd
            .xdg_config_root()
            .join("systemd/user/prw-agent.service.d");
        (
            managed.join(EXECUTION_MODE_DROPIN_NAME),
            managed.join(CONFIGURED_REMOTE_INPUTS_DROPIN_NAME),
        )
    }

    fn drop_in_paths_are_valid(paths: &[PathBuf]) -> bool {
        let mut seen = BTreeSet::new();
        paths
            .iter()
            .all(|path| path.is_absolute() && seen.insert(path.clone()))
    }

    fn foreign_drop_in_sequence<'a>(
        paths: &'a [PathBuf],
        mode: &Path,
        remote: &Path,
    ) -> Vec<&'a Path> {
        paths
            .iter()
            .map(PathBuf::as_path)
            .filter(|path| *path != mode && *path != remote)
            .collect()
    }

    fn loaded_topology_matches(
        context: &UserContext,
        desired: &ManagedAgentConfiguration,
        baseline: &UnitStatus,
        current: &UnitStatus,
    ) -> bool {
        if current.load_state != "loaded"
            || current.unit_file_state != baseline.unit_file_state
            || !drop_in_paths_are_valid(&baseline.drop_in_paths)
            || !drop_in_paths_are_valid(&current.drop_in_paths)
        {
            return false;
        }
        let (mode, remote) = managed_drop_in_paths(context);
        if !current.drop_in_paths.contains(&mode) {
            return false;
        }
        let managed_membership_matches = match desired {
            ManagedAgentConfiguration::LocalOnly => !current.drop_in_paths.contains(&remote),
            ManagedAgentConfiguration::ConfiguredRemote(_) => {
                current.drop_in_paths.contains(&remote)
            }
        };
        managed_membership_matches
            && foreign_drop_in_sequence(&current.drop_in_paths, &mode, &remote)
                == foreign_drop_in_sequence(&baseline.drop_in_paths, &mode, &remote)
    }

    fn sanitized_command(path: &str, context: &UserContext) -> Result<Command, OrchestrationError> {
        let runtime = context
            .runtime
            .as_ref()
            .ok_or(OrchestrationError::SameUserContext)?;
        let mut command = Command::new(path);
        command
            .env_clear()
            .env("HOME", context.systemd.home_dir())
            .env("XDG_CONFIG_HOME", context.systemd.xdg_config_root())
            .env("XDG_RUNTIME_DIR", runtime)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    fn run_target_verify(context: &UserContext) -> Result<(), OrchestrationError> {
        let status = sanitized_command(SYSTEMD_ANALYZE_PATH, context)?
            .args(target_verify_arguments())
            .stdout(Stdio::null())
            .status()
            .map_err(|_| OrchestrationError::TargetVerify)?;
        if status.success() {
            Ok(())
        } else {
            Err(OrchestrationError::TargetVerify)
        }
    }

    const fn target_verify_arguments() -> [&'static str; 6] {
        [
            "--user",
            "--recursive-errors=no",
            "--man=no",
            "--generators=no",
            "verify",
            AGENT_UNIT,
        ]
    }

    fn run_systemctl(context: &UserContext, args: &[&str]) -> Result<(), OrchestrationError> {
        let status = sanitized_command(SYSTEMCTL_PATH, context)?
            .arg("--user")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .map_err(|_| OrchestrationError::DaemonReload)?;
        if status.success() {
            Ok(())
        } else {
            Err(OrchestrationError::DaemonReload)
        }
    }

    fn query_unit_status(context: &UserContext) -> Result<UnitStatus, OrchestrationError> {
        let output = sanitized_command(SYSTEMCTL_PATH, context)?
            .args([
                "--user",
                "show",
                AGENT_UNIT,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--property=InvocationID",
                "--property=UnitFileState",
                "--property=DropInPaths",
                "--no-pager",
            ])
            .stdout(Stdio::piped())
            .output()
            .map_err(|_| OrchestrationError::BaselineSystemd)?;
        if !output.status.success() {
            return Err(OrchestrationError::BaselineSystemd);
        }
        parse_unit_status(&output.stdout).ok_or(OrchestrationError::BaselineSystemd)
    }

    fn parse_unit_status(bytes: &[u8]) -> Option<UnitStatus> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=')?;
            if !matches!(
                key,
                "LoadState"
                    | "ActiveState"
                    | "SubState"
                    | "MainPID"
                    | "InvocationID"
                    | "UnitFileState"
                    | "DropInPaths"
            ) || values.insert(key, value).is_some()
            {
                return None;
            }
        }
        if values.len() != 7 {
            return None;
        }
        Some(UnitStatus {
            load_state: values.remove("LoadState")?.to_owned(),
            active_state: values.remove("ActiveState")?.to_owned(),
            sub_state: values.remove("SubState")?.to_owned(),
            main_pid: values.remove("MainPID")?.parse().ok()?,
            invocation_id: values.remove("InvocationID")?.to_owned(),
            unit_file_state: values.remove("UnitFileState")?.to_owned(),
            drop_in_paths: parse_drop_in_paths(values.remove("DropInPaths")?)?,
        })
    }

    fn parse_drop_in_paths(value: &str) -> Option<Vec<PathBuf>> {
        if value.is_empty() {
            return Some(Vec::new());
        }
        let paths = value
            .split_ascii_whitespace()
            .map(decode_systemd_path)
            .collect::<Option<Vec<_>>>()?;
        drop_in_paths_are_valid(&paths).then_some(paths)
    }

    fn decode_systemd_path(value: &str) -> Option<PathBuf> {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'\\' {
                out.push(bytes[index]);
                index += 1;
                continue;
            }
            index += 1;
            let escaped = *bytes.get(index)?;
            match escaped {
                b'\\' => {
                    out.push(b'\\');
                    index += 1;
                }
                b's' => {
                    out.push(b' ');
                    index += 1;
                }
                b'x' => {
                    let hi = hex(*bytes.get(index + 1)?)?;
                    let lo = hex(*bytes.get(index + 2)?)?;
                    out.push((hi << 4) | lo);
                    index += 3;
                }
                _ => return None,
            }
        }
        Some(PathBuf::from(OsString::from_vec(out)))
    }

    const fn hex(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }

    fn probe_agent_ready(context: &UserContext) -> Result<(), OrchestrationError> {
        let runtime = context
            .runtime
            .as_ref()
            .ok_or(OrchestrationError::BaselineReadiness)?;
        let app_dir = runtime.join(prw_agent::AGENT_RUNTIME_SUBDIRECTORY);
        validate_runtime_object(
            &app_dir,
            context.systemd.uid(),
            true,
            PRIVATE_DIRECTORY_MODE,
        )?;
        let socket_path = LocalIpcContract::socket_path(runtime);
        validate_runtime_object(
            &socket_path,
            context.systemd.uid(),
            false,
            PRIVATE_SOCKET_MODE,
        )?;
        let mut stream =
            UnixStream::connect(&socket_path).map_err(|_| OrchestrationError::BaselineReadiness)?;
        stream
            .set_read_timeout(Some(IPC_TIMEOUT))
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        stream
            .set_write_timeout(Some(IPC_TIMEOUT))
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        let peer = socket_peercred(&stream).map_err(|_| OrchestrationError::BaselineReadiness)?;
        if peer.uid.as_raw() != context.systemd.uid() {
            return Err(OrchestrationError::BaselineReadiness);
        }
        let request_id = LocalIpcRequestId::new(READINESS_REQUEST_ID)
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        write_local_command_request(&mut stream, request_id, LocalAgentCommand::GetAgentStatus)
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        let frame = read_frame(&mut stream).map_err(|_| OrchestrationError::BaselineReadiness)?;
        let status = decode_success_status_frame(&frame)
            .map_err(|_| OrchestrationError::BaselineReadiness)?;
        let snapshot = status.snapshot();
        if status.request_id() != request_id
            || !snapshot.runtime_state().is_ready()
            || snapshot.protocol_version() != LocalIpcProtocolVersion::current()
        {
            return Err(OrchestrationError::BaselineReadiness);
        }
        Ok(())
    }

    fn validate_runtime_object(
        path: &Path,
        uid: u32,
        directory: bool,
        mode: u32,
    ) -> Result<(), OrchestrationError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| OrchestrationError::BaselineReadiness)?;
        let expected_type = if directory {
            metadata.is_dir()
        } else {
            metadata.file_type().is_socket()
        };
        if metadata.file_type().is_symlink()
            || !expected_type
            || metadata.uid() != uid
            || metadata.mode() & 0o777 != mode
        {
            return Err(OrchestrationError::BaselineReadiness);
        }
        Ok(())
    }

    fn wait_for_ready(
        context: &UserContext,
        unit_file_state: &str,
        prior_invocation_id: Option<&str>,
    ) -> Result<UnitStatus, OrchestrationError> {
        let deadline = Instant::now() + READINESS_DEADLINE;
        loop {
            if let Ok(status) = query_unit_status(context) {
                let invocation_ok =
                    prior_invocation_id.is_none_or(|prior| status.invocation_id != prior);
                if status.is_active_running()
                    && status.unit_file_state == unit_file_state
                    && invocation_ok
                    && probe_agent_ready(context).is_ok()
                {
                    return Ok(status);
                }
            }
            if Instant::now() >= deadline {
                return Err(OrchestrationError::PostRestartReadiness);
            }
            thread::sleep(READINESS_POLL);
        }
    }

    /// Executes one selected action from the current process environment.
    ///
    /// # Errors
    /// Returns only stable bounded stage classifications and never raw configured values.
    pub fn run_process_action(
        action: AdministrativeAction,
    ) -> Result<OrchestrationOutcome, OrchestrationError> {
        let mut env = ProcessEnvironment;
        let mut backend = ProductionBackend;
        execute_with_backend(
            action,
            &mut env,
            getuid().as_raw(),
            geteuid().as_raw(),
            &mut backend,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            cell::RefCell,
            collections::HashMap,
            fs::Permissions,
            os::unix::fs::PermissionsExt,
            rc::Rc,
            sync::atomic::{AtomicU64, Ordering},
        };

        struct FakeEnv {
            values: HashMap<&'static str, String>,
            reads: Rc<RefCell<Vec<&'static str>>>,
        }
        impl FakeEnv {
            fn local_only(home: &Path, config: &Path) -> Self {
                Self {
                    values: HashMap::from([
                        ("HOME", home.display().to_string()),
                        ("XDG_CONFIG_HOME", config.display().to_string()),
                        (PRW_AGENT_EXECUTION_MODE, "local_only".to_owned()),
                    ]),
                    reads: Rc::new(RefCell::new(Vec::new())),
                }
            }
        }
        impl EnvironmentSource for FakeEnv {
            fn read(&mut self, name: &'static str) -> Result<String, EnvironmentReadError> {
                self.reads.borrow_mut().push(name);
                self.values
                    .get(name)
                    .cloned()
                    .ok_or(EnvironmentReadError::Missing)
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum Event {
            Write,
            Status,
            Ready,
            ExternalCapture,
            ExternalReprove,
            Recoverable,
            Restore,
            Verify,
            Reload,
            TryRestart,
            Restart,
            Wait,
        }
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum FakeFailure {
            Ready,
            ExternalCapture,
            Verify,
            Reload,
            TryRestart,
            Wait,
        }
        struct FakeBackend {
            events: Vec<Event>,
            statuses: Vec<UnitStatus>,
            failure: Option<FakeFailure>,
            external_reproofs: Vec<bool>,
        }
        impl FakeBackend {
            fn new(statuses: Vec<UnitStatus>) -> Self {
                Self {
                    events: Vec::new(),
                    statuses,
                    failure: None,
                    external_reproofs: Vec::new(),
                }
            }

            fn with_external_reproofs(mut self, results: Vec<bool>) -> Self {
                self.external_reproofs = results;
                self
            }

            fn fail_once(&mut self, stage: FakeFailure) -> bool {
                if self.failure == Some(stage) {
                    self.failure = None;
                    true
                } else {
                    false
                }
            }
        }
        impl ActivationBackend for FakeBackend {
            type Recovery = ();
            type ExternalCustody = ();

            fn write_only(
                &mut self,
                _: &UserContext,
                _: &ManagedAgentConfiguration,
            ) -> Result<(), OrchestrationError> {
                self.events.push(Event::Write);
                Ok(())
            }
            fn status(&mut self, _: &UserContext) -> Result<UnitStatus, OrchestrationError> {
                self.events.push(Event::Status);
                if self.statuses.is_empty() {
                    Err(OrchestrationError::BaselineSystemd)
                } else {
                    Ok(self.statuses.remove(0))
                }
            }
            fn ready_once(&mut self, _: &UserContext) -> Result<(), OrchestrationError> {
                self.events.push(Event::Ready);
                (!self.fail_once(FakeFailure::Ready))
                    .then_some(())
                    .ok_or(OrchestrationError::BaselineReadiness)
            }
            fn capture_external_custody(
                &mut self,
                _: &UserContext,
            ) -> Result<Self::ExternalCustody, OrchestrationError> {
                self.events.push(Event::ExternalCapture);
                (!self.fail_once(FakeFailure::ExternalCapture))
                    .then_some(())
                    .ok_or(OrchestrationError::BaselineSystemd)
            }
            fn reprove_external_custody(
                &mut self,
                _: &UserContext,
                (): &Self::ExternalCustody,
            ) -> Result<(), OrchestrationError> {
                self.events.push(Event::ExternalReprove);
                let unchanged = if self.external_reproofs.is_empty() {
                    true
                } else {
                    self.external_reproofs.remove(0)
                };
                unchanged
                    .then_some(())
                    .ok_or(OrchestrationError::ExternalConfigurationDrift)
            }
            fn write_recoverable(
                &mut self,
                _: &UserContext,
                _: &ManagedAgentConfiguration,
            ) -> Result<Self::Recovery, OrchestrationError> {
                self.events.push(Event::Recoverable);
                Ok(())
            }
            fn restore(
                &mut self,
                _: &UserContext,
                (): Self::Recovery,
            ) -> Result<(), OrchestrationError> {
                self.events.push(Event::Restore);
                Ok(())
            }
            fn verify_target(&mut self, _: &UserContext) -> Result<(), OrchestrationError> {
                self.events.push(Event::Verify);
                (!self.fail_once(FakeFailure::Verify))
                    .then_some(())
                    .ok_or(OrchestrationError::TargetVerify)
            }
            fn daemon_reload(&mut self, _: &UserContext) -> Result<(), OrchestrationError> {
                self.events.push(Event::Reload);
                (!self.fail_once(FakeFailure::Reload))
                    .then_some(())
                    .ok_or(OrchestrationError::DaemonReload)
            }
            fn try_restart(&mut self, _: &UserContext) -> Result<(), OrchestrationError> {
                self.events.push(Event::TryRestart);
                (!self.fail_once(FakeFailure::TryRestart))
                    .then_some(())
                    .ok_or(OrchestrationError::TryRestart)
            }
            fn restart(&mut self, _: &UserContext) -> Result<(), OrchestrationError> {
                self.events.push(Event::Restart);
                Ok(())
            }
            fn wait_ready(
                &mut self,
                _: &UserContext,
                _: &str,
                _: Option<&str>,
            ) -> Result<UnitStatus, OrchestrationError> {
                self.events.push(Event::Wait);
                if self.fail_once(FakeFailure::Wait) {
                    return Err(OrchestrationError::PostRestartReadiness);
                }
                if self.statuses.is_empty() {
                    Ok(active_status("after", Vec::new()))
                } else {
                    Ok(self.statuses.remove(0))
                }
            }
        }

        fn active_status(invocation: &str, drop_in_paths: Vec<PathBuf>) -> UnitStatus {
            UnitStatus {
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: 42,
                invocation_id: invocation.into(),
                unit_file_state: "enabled".into(),
                drop_in_paths,
            }
        }

        fn configured_remote_desired() -> ManagedAgentConfiguration {
            ManagedAgentConfiguration::ConfiguredRemote(Box::new(
                ConfiguredRemoteBundle::try_new("127.0.0.1:0", "peer-exact", "1", "60", "0", "0")
                    .expect("valid configured-remote test bundle"),
            ))
        }

        fn active_context(root: &Path, config: &Path, runtime: &Path) -> UserContext {
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(root, config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            acquire_user_context(&mut env, true, uid, uid).expect("valid active test context")
        }

        static SANDBOX_SEQUENCE: AtomicU64 = AtomicU64::new(0);

        fn sandbox() -> (PathBuf, PathBuf, PathBuf) {
            let sequence = SANDBOX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("prw-ty-orch-{}-{sequence}", std::process::id()));
            let config = root.join("config");
            let runtime = root.join("runtime");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&config).unwrap();
            fs::create_dir_all(&runtime).unwrap();
            fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
            (root, config, runtime)
        }

        #[test]
        fn action_parser_accepts_only_exact_single_tokens() {
            assert_eq!(
                super::super::parse_action_args([OsString::from("write")]),
                Ok(AdministrativeAction::Write)
            );
            assert_eq!(
                super::super::parse_action_args([OsString::from("reconfigure-active")]),
                Ok(AdministrativeAction::ReconfigureActive)
            );
            assert!(super::super::parse_action_args(Vec::<OsString>::new()).is_err());
            assert!(super::super::parse_action_args([OsString::from("restart")]).is_err());
            assert!(
                super::super::parse_action_args([OsString::from("write"), OsString::from("extra")])
                    .is_err()
            );
        }

        #[test]
        fn local_only_never_acquires_remote_inputs_and_write_has_no_manager_calls() {
            let (root, config, _) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            let reads = Rc::clone(&env.reads);
            let mut backend = FakeBackend::new(Vec::new());
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::Write,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Ok(OrchestrationOutcome::Write)
            );
            assert_eq!(backend.events, [Event::Write]);
            let reads = reads.borrow();
            for remote in [
                PRW_REMOTE_BIND_ADDR,
                PRW_REMOTE_PEER_DEVICE_ID,
                PRW_REMOTE_MAX_ACTIVE_WORKERS,
                PRW_REMOTE_APPLICATION_LEASE_SECONDS,
                PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
                PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
            ] {
                assert!(!reads.contains(&remote));
            }
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn configured_remote_requires_all_six_exact_inputs() {
            let (root, config, _) = sandbox();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert(PRW_AGENT_EXECUTION_MODE, "configured_remote".into());
            env.values
                .insert(PRW_REMOTE_BIND_ADDR, "127.0.0.1:0".into());
            assert_eq!(
                acquire_desired_configuration(&mut env),
                Err(OrchestrationError::Environment)
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn failed_service_blocks_before_writer_mutation() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let failed = UnitStatus {
                load_state: "loaded".into(),
                active_state: "failed".into(),
                sub_state: "failed".into(),
                main_pid: 0,
                invocation_id: "old".into(),
                unit_file_state: "enabled".into(),
                drop_in_paths: Vec::new(),
            };
            let mut backend = FakeBackend::new(vec![failed]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Err(OrchestrationError::BaselineSystemd)
            );
            assert_eq!(backend.events, [Event::Status]);
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn baseline_readiness_failure_blocks_before_writer_mutation() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![active_status("before", Vec::new())]);
            backend.failure = Some(FakeFailure::Ready);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Err(OrchestrationError::BaselineReadiness)
            );
            assert_eq!(backend.events, [Event::Status, Event::Ready]);
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn baseline_external_custody_capture_blocks_before_writer_mutation() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![active_status("before", Vec::new())]);
            backend.failure = Some(FakeFailure::ExternalCapture);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::BaselineSystemd)
            );
            assert_eq!(
                backend.events,
                [Event::Status, Event::Ready, Event::ExternalCapture]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn configured_remote_with_all_six_inputs_reaches_write_without_manager_calls() {
            let (root, config, _) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert(PRW_AGENT_EXECUTION_MODE, "configured_remote".into());
            env.values
                .insert(PRW_REMOTE_BIND_ADDR, "127.0.0.1:0".into());
            env.values
                .insert(PRW_REMOTE_PEER_DEVICE_ID, "peer-exact".into());
            env.values
                .insert(PRW_REMOTE_MAX_ACTIVE_WORKERS, "0002".into());
            env.values
                .insert(PRW_REMOTE_APPLICATION_LEASE_SECONDS, "003600".into());
            env.values
                .insert(PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS, "0007".into());
            env.values.insert(
                PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
                "0009".into(),
            );
            let reads = Rc::clone(&env.reads);
            let mut backend = FakeBackend::new(Vec::new());
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::Write,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Ok(OrchestrationOutcome::Write)
            );
            assert_eq!(backend.events, [Event::Write]);
            let reads = reads.borrow();
            for required in [
                PRW_REMOTE_BIND_ADDR,
                PRW_REMOTE_PEER_DEVICE_ID,
                PRW_REMOTE_MAX_ACTIVE_WORKERS,
                PRW_REMOTE_APPLICATION_LEASE_SECONDS,
                PRW_REMOTE_REQUESTER_RENDEZVOUS_MAX_RECORDS,
                PRW_REMOTE_EXPECTED_DEVICE_SCHEDULING_CONSUMPTION_MAX_RECORDS,
            ] {
                assert!(reads.contains(&required));
            }
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn successful_active_lane_orders_external_custody_with_existing_gates() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let foreign_a = PathBuf::from("/vendor/10-a.conf");
            let foreign_b = PathBuf::from("/vendor/20-b.conf");
            let baseline = active_status("before", vec![foreign_a.clone(), foreign_b.clone()]);
            let post = active_status(
                "before",
                vec![foreign_a.clone(), mode.clone(), foreign_b.clone()],
            );
            let post_restart = active_status("after", vec![foreign_a, mode, foreign_b]);
            let mut backend = FakeBackend::new(vec![baseline, post, post_restart]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Ok(OrchestrationOutcome::ReconfigureActive)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Verify,
                    Event::ExternalReprove,
                    Event::Reload,
                    Event::Status,
                    Event::ExternalReprove,
                    Event::TryRestart,
                    Event::Wait,
                    Event::ExternalReprove,
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn postwrite_external_drift_restores_without_verify_or_reload() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![active_status("before", Vec::new())])
                .with_external_reproofs(vec![false]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Restore,
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn postverify_prereload_external_drift_restores_without_reload() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![active_status("before", Vec::new())])
                .with_external_reproofs(vec![true, false]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Verify,
                    Event::ExternalReprove,
                    Event::Restore,
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn target_verify_failure_restores_before_any_reload_or_restart() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![active_status("before", Vec::new())]);
            backend.failure = Some(FakeFailure::Verify);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Err(OrchestrationError::TargetVerify)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Verify,
                    Event::Restore
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn postreload_state_failure_with_unchanged_custody_uses_ordinary_rollback() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![
                active_status("before", Vec::new()),
                active_status("before", Vec::new()),
                active_status("rollback", Vec::new()),
            ]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend
                ),
                Err(OrchestrationError::PostReloadState)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Verify,
                    Event::ExternalReprove,
                    Event::Reload,
                    Event::Status,
                    Event::ExternalReprove,
                    Event::Restore,
                    Event::Reload,
                    Event::Restart,
                    Event::Wait,
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn postreload_state_failure_with_external_drift_suppresses_restart() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mut backend = FakeBackend::new(vec![
                active_status("before", Vec::new()),
                active_status("before", Vec::new()),
            ])
            .with_external_reproofs(vec![true, true, false]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(
                backend.events,
                [
                    Event::Status,
                    Event::Ready,
                    Event::ExternalCapture,
                    Event::Recoverable,
                    Event::ExternalReprove,
                    Event::Verify,
                    Event::ExternalReprove,
                    Event::Reload,
                    Event::Status,
                    Event::ExternalReprove,
                    Event::Restore,
                    Event::Reload,
                ]
            );
            assert!(!backend.events.contains(&Event::Restart));
            assert!(!backend.events.contains(&Event::TryRestart));
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn postreload_external_drift_before_try_restart_restores_and_reloads_once() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let baseline = active_status("before", Vec::new());
            let post_reload = active_status("before", vec![mode]);
            let mut backend = FakeBackend::new(vec![baseline, post_reload])
                .with_external_reproofs(vec![true, true, false]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Reload)
                    .count(),
                2
            );
            assert!(!backend.events.contains(&Event::TryRestart));
            assert!(!backend.events.contains(&Event::Restart));
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn drift_after_restart_attempt_suppresses_automatic_rollback_mutation() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let baseline = active_status("before", Vec::new());
            let post_reload = active_status("before", vec![mode]);
            let mut backend = FakeBackend::new(vec![baseline, post_reload])
                .with_external_reproofs(vec![true, true, true, false]);
            backend.failure = Some(FakeFailure::TryRestart);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(backend.events.last(), Some(&Event::ExternalReprove));
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Restore)
                    .count(),
                0
            );
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Restart)
                    .count(),
                0
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn final_postrestart_external_reproof_is_required_before_success() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let baseline = active_status("before", Vec::new());
            let post_reload = active_status("before", vec![mode.clone()]);
            let post_restart = active_status("after", vec![mode]);
            let mut backend = FakeBackend::new(vec![baseline, post_reload, post_restart])
                .with_external_reproofs(vec![true, true, true, false]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::ExternalConfigurationDrift)
            );
            assert_eq!(backend.events.last(), Some(&Event::ExternalReprove));
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Restart)
                    .count(),
                0
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn systemd_show_parser_and_dropin_decoder_are_fail_closed() {
            let bytes = b"LoadState=loaded\nActiveState=active\nSubState=running\nDropInPaths=/tmp/a\\x20b.conf /tmp/c.conf\nUnitFileState=enabled\nInvocationID=abc\nMainPID=7\n";
            let parsed = parse_unit_status(bytes).unwrap();
            assert_eq!(
                parsed.drop_in_paths,
                [PathBuf::from("/tmp/a b.conf"), PathBuf::from("/tmp/c.conf")]
            );
            assert!(parse_unit_status(b"LoadState=loaded\nLoadState=loaded\n").is_none());
            assert!(decode_systemd_path("/tmp/bad\\q").is_none());
            assert!(parse_drop_in_paths("relative.conf").is_none());
            assert!(parse_drop_in_paths("/tmp/a.conf /tmp/a.conf").is_none());
        }

        #[test]
        fn selected_loaded_topology_accepts_both_modes_and_rejects_wrong_membership() {
            let (root, config, runtime) = sandbox();
            let context = active_context(&root, &config, &runtime);
            let (mode, remote) = managed_drop_in_paths(&context);
            let foreign_a = PathBuf::from("/vendor/10-a.conf");
            let foreign_b = PathBuf::from("/vendor/20-b.conf");
            let baseline = active_status("before", vec![foreign_a.clone(), foreign_b.clone()]);
            let local = active_status(
                "before",
                vec![foreign_a.clone(), mode.clone(), foreign_b.clone()],
            );
            assert!(loaded_topology_matches(
                &context,
                &ManagedAgentConfiguration::LocalOnly,
                &baseline,
                &local,
            ));
            let configured = active_status("before", vec![mode, foreign_a, remote, foreign_b]);
            let desired_remote = configured_remote_desired();
            assert!(loaded_topology_matches(
                &context,
                &desired_remote,
                &baseline,
                &configured,
            ));
            assert!(!loaded_topology_matches(
                &context,
                &ManagedAgentConfiguration::LocalOnly,
                &baseline,
                &configured,
            ));
            assert!(!loaded_topology_matches(
                &context,
                &desired_remote,
                &baseline,
                &local,
            ));
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn post_reload_foreign_topology_drift_fails_before_forward_restart() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let foreign_a = PathBuf::from("/vendor/10-a.conf");
            let foreign_b = PathBuf::from("/vendor/20-b.conf");
            let foreign_c = PathBuf::from("/vendor/30-c.conf");
            let cases = [
                vec![
                    foreign_a.clone(),
                    foreign_c.clone(),
                    foreign_b.clone(),
                    mode.clone(),
                ],
                vec![foreign_a.clone(), mode.clone()],
                vec![foreign_a.clone(), foreign_c, mode.clone()],
                vec![foreign_b.clone(), foreign_a.clone(), mode],
            ];
            for post_paths in cases {
                let mut env = FakeEnv::local_only(&root, &config);
                env.values
                    .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
                let baseline_paths = vec![foreign_a.clone(), foreign_b.clone()];
                let baseline = active_status("before", baseline_paths.clone());
                let post = active_status("before", post_paths);
                let restored = active_status("after", baseline_paths);
                let mut backend = FakeBackend::new(vec![baseline, post, restored]);
                assert_eq!(
                    execute_with_backend(
                        AdministrativeAction::ReconfigureActive,
                        &mut env,
                        uid,
                        uid,
                        &mut backend,
                    ),
                    Err(OrchestrationError::PostReloadState)
                );
                assert!(!backend.events.contains(&Event::TryRestart));
                assert_eq!(
                    backend
                        .events
                        .iter()
                        .filter(|event| **event == Event::Restart)
                        .count(),
                    1
                );
            }
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn post_restart_foreign_topology_drift_invokes_rollback_when_external_custody_is_unchanged()
        {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let mode = config
                .join("systemd/user/prw-agent.service.d")
                .join(EXECUTION_MODE_DROPIN_NAME);
            let foreign_a = PathBuf::from("/vendor/10-a.conf");
            let foreign_b = PathBuf::from("/vendor/20-b.conf");
            let baseline_paths = vec![foreign_a.clone(), foreign_b.clone()];
            let baseline = active_status("before", baseline_paths.clone());
            let post_reload = active_status(
                "before",
                vec![foreign_a.clone(), mode.clone(), foreign_b.clone()],
            );
            let post_restart = active_status("after", vec![foreign_b, mode, foreign_a]);
            let restored = active_status("rollback", baseline_paths);
            let mut backend = FakeBackend::new(vec![baseline, post_reload, post_restart, restored]);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::PostRestartReadiness)
            );
            assert!(backend.events.contains(&Event::ExternalReprove));
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Restart)
                    .count(),
                1
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn invalid_baseline_dropin_topology_blocks_before_writer_mutation() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            for paths in [
                vec![PathBuf::from("relative.conf")],
                vec![
                    PathBuf::from("/vendor/a.conf"),
                    PathBuf::from("/vendor/a.conf"),
                ],
            ] {
                let mut env = FakeEnv::local_only(&root, &config);
                env.values
                    .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
                let mut backend = FakeBackend::new(vec![active_status("before", paths)]);
                assert_eq!(
                    execute_with_backend(
                        AdministrativeAction::ReconfigureActive,
                        &mut env,
                        uid,
                        uid,
                        &mut backend,
                    ),
                    Err(OrchestrationError::BaselineSystemd)
                );
                assert_eq!(backend.events, [Event::Status]);
            }
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn rollback_requires_exact_full_ordered_baseline_dropins() {
            let (root, config, runtime) = sandbox();
            let context = active_context(&root, &config, &runtime);
            let foreign_a = PathBuf::from("/vendor/10-a.conf");
            let foreign_b = PathBuf::from("/vendor/20-b.conf");
            let baseline = active_status("before", vec![foreign_a.clone(), foreign_b.clone()]);
            let restored = active_status("rollback", vec![foreign_b, foreign_a]);
            let mut backend = FakeBackend::new(vec![restored]);
            assert_eq!(
                rollback_after_manager_mutation(&context, &mut backend, (), &baseline, &(), false),
                Err(OrchestrationError::Rollback)
            );
            assert_eq!(
                backend.events,
                [
                    Event::ExternalReprove,
                    Event::Restore,
                    Event::Reload,
                    Event::Restart,
                    Event::Wait,
                ]
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn target_verify_arguments_force_target_warning_failure_mode() {
            assert_eq!(
                target_verify_arguments(),
                [
                    "--user",
                    "--recursive-errors=no",
                    "--man=no",
                    "--generators=no",
                    "verify",
                    AGENT_UNIT
                ]
            );
            assert_eq!(READINESS_DEADLINE, Duration::from_secs(5));
            assert_eq!(IPC_TIMEOUT, Duration::from_secs(2));
            assert!(READINESS_POLL > Duration::ZERO);
        }

        #[test]
        fn sanitized_systemd_child_environment_contains_only_selected_same_user_context() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let context = acquire_user_context(&mut env, true, uid, uid).expect("valid context");
            let output = sanitized_command("/usr/bin/env", &context)
                .expect("sanitized command")
                .stdout(Stdio::piped())
                .output()
                .expect("env child runs");
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).expect("utf8 env");
            let mut actual = text.lines().collect::<Vec<_>>();
            actual.sort_unstable();
            let mut expected = vec![
                format!("HOME={}", root.display()),
                format!("XDG_CONFIG_HOME={}", config.display()),
                format!("XDG_RUNTIME_DIR={}", runtime.display()),
                "LANG=C".to_owned(),
                "LC_ALL=C".to_owned(),
            ];
            expected.sort_unstable();
            assert_eq!(actual, expected);
            assert!(!text.contains("DBUS_SESSION_BUS_ADDRESS="));
            assert!(!text.contains("SYSTEMD_UNIT_PATH="));
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn daemon_reload_failure_rolls_back_only_after_external_reproof() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            let baseline_dropin = PathBuf::from("/vendor/20-device-identity-credential.conf");
            let baseline_paths = vec![baseline_dropin];
            let mut backend = FakeBackend::new(vec![
                active_status("before", baseline_paths.clone()),
                active_status("rollback", baseline_paths),
            ]);
            backend.failure = Some(FakeFailure::Reload);
            assert_eq!(
                execute_with_backend(
                    AdministrativeAction::ReconfigureActive,
                    &mut env,
                    uid,
                    uid,
                    &mut backend,
                ),
                Err(OrchestrationError::DaemonReload)
            );
            assert!(backend.events.contains(&Event::ExternalReprove));
            assert_eq!(
                backend
                    .events
                    .iter()
                    .filter(|event| **event == Event::Restart)
                    .count(),
                1
            );
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn external_drift_error_text_is_fixed_and_content_free() {
            assert_eq!(
                OrchestrationError::ExternalConfigurationDrift.to_string(),
                "external_configuration_drift"
            );
            assert!(
                !OrchestrationError::ExternalConfigurationDrift
                    .to_string()
                    .contains('/')
            );
        }

        #[test]
        fn runtime_root_must_be_owned_private_directory() {
            let (root, config, runtime) = sandbox();
            let uid = getuid().as_raw();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            assert!(acquire_user_context(&mut env, true, uid, uid).is_ok());
            fs::set_permissions(&runtime, Permissions::from_mode(0o755)).unwrap();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime.display().to_string());
            assert_eq!(
                acquire_user_context(&mut env, true, uid, uid).unwrap_err(),
                OrchestrationError::SameUserContext
            );
            fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
            let runtime_link = root.join("runtime-link");
            std::os::unix::fs::symlink(&runtime, &runtime_link).unwrap();
            let mut env = FakeEnv::local_only(&root, &config);
            env.values
                .insert("XDG_RUNTIME_DIR", runtime_link.display().to_string());
            assert_eq!(
                acquire_user_context(&mut env, true, uid, uid).unwrap_err(),
                OrchestrationError::SameUserContext
            );
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{OrchestrationError, OrchestrationOutcome, run_process_action};

#[cfg(test)]
mod common_tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn public_action_parser_rejects_extra_arguments() {
        assert_eq!(
            parse_action_args([OsString::from("write")]),
            Ok(AdministrativeAction::Write)
        );
        assert!(parse_action_args([OsString::from("write"), OsString::from("x")]).is_err());
    }
}
