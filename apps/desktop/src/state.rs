use prw_agent::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
use prw_agent::local_commands::status_snapshot::{
    LocalAgentRuntimeState, LocalAgentStatusSnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NavigationDestination {
    #[default]
    Overview,
    Machines,
    Sessions,
    Files,
    Transfers,
    Activity,
    Settings,
}

impl NavigationDestination {
    pub(crate) const ALL: [Self; 7] = [
        Self::Overview,
        Self::Machines,
        Self::Sessions,
        Self::Files,
        Self::Transfers,
        Self::Activity,
        Self::Settings,
    ];

    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Machines => "Machines",
            Self::Sessions => "Sessions",
            Self::Files => "Files",
            Self::Transfers => "Transfers",
            Self::Activity => "Activity",
            Self::Settings => "Settings",
        }
    }

    pub(crate) const fn stack_name(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Machines => "machines",
            Self::Sessions => "sessions",
            Self::Files => "files",
            Self::Transfers => "transfers",
            Self::Activity => "activity",
            Self::Settings => "settings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentAvailability {
    #[default]
    Unknown,
    Offline,
    Connecting,
    Online,
    Error,
}

impl AgentAvailability {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Offline => "Offline",
            Self::Connecting => "Connecting",
            Self::Online => "Online",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRuntimePresentation {
    Starting,
    Ready,
    Degraded,
    Stopping,
    Unknown,
}

impl AgentRuntimePresentation {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Ready => "Ready",
            Self::Degraded => "Degraded",
            Self::Stopping => "Stopping",
            Self::Unknown => "Unknown",
        }
    }
}

impl From<LocalAgentRuntimeState> for AgentRuntimePresentation {
    fn from(value: LocalAgentRuntimeState) -> Self {
        match value {
            LocalAgentRuntimeState::Starting => Self::Starting,
            LocalAgentRuntimeState::Ready => Self::Ready,
            LocalAgentRuntimeState::Degraded => Self::Degraded,
            LocalAgentRuntimeState::Stopping => Self::Stopping,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateDnsPresentation {
    pub(crate) enabled: bool,
    pub(crate) device_naming: bool,
    pub(crate) resolver_count: usize,
    pub(crate) split_domain_count: usize,
}

impl From<&LocalPrivateDnsSnapshot> for PrivateDnsPresentation {
    fn from(value: &LocalPrivateDnsSnapshot) -> Self {
        Self {
            enabled: value.enabled(),
            device_naming: value.device_naming(),
            resolver_count: value.resolvers().len(),
            split_domain_count: value.split_domains().len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopPresentationState {
    pub(crate) availability: AgentAvailability,
    pub(crate) runtime: Option<AgentRuntimePresentation>,
    pub(crate) private_dns: Option<PrivateDnsPresentation>,
    pub(crate) selected: NavigationDestination,
    pub(crate) detail: String,
}

impl Default for DesktopPresentationState {
    fn default() -> Self {
        Self {
            availability: AgentAvailability::Unknown,
            runtime: None,
            private_dns: None,
            selected: NavigationDestination::Overview,
            detail: String::new(),
        }
    }
}

impl DesktopPresentationState {
    pub(crate) fn connecting() -> Self {
        Self {
            availability: AgentAvailability::Connecting,
            detail: "Reading local Agent state…".to_owned(),
            ..Self::default()
        }
    }

    pub(crate) fn with_status(mut self, snapshot: LocalAgentStatusSnapshot) -> Self {
        self.availability = AgentAvailability::Online;
        self.runtime = Some(snapshot.runtime_state().into());
        self.detail = format!(
            "Local IPC protocol {}.{}",
            snapshot.protocol_version().major(),
            snapshot.protocol_version().minor()
        );
        self
    }

    pub(crate) fn with_private_dns(mut self, snapshot: &LocalPrivateDnsSnapshot) -> Self {
        self.private_dns = Some(snapshot.into());
        self
    }

    pub(crate) fn with_error(
        mut self,
        availability: AgentAvailability,
        detail: impl Into<String>,
    ) -> Self {
        self.availability = availability;
        self.detail = detail.into();
        self
    }

    #[must_use]
    pub(crate) fn agent_status_text(&self) -> String {
        let runtime = self
            .runtime
            .map_or("Not reported", AgentRuntimePresentation::label);
        format!(
            "Agent status\nAvailability: {}\nRuntime: {runtime}",
            self.availability.label()
        )
    }

    #[must_use]
    pub(crate) fn private_dns_status_text(&self) -> String {
        self.private_dns.as_ref().map_or_else(
            || "Private DNS\nNo validated snapshot available".to_owned(),
            |dns| {
                format!(
                    "Private DNS\nEnabled: {}\nDevice naming: {}\nResolvers: {}\nSplit domains: {}",
                    yes_no(dns.enabled),
                    yes_no(dns.device_naming),
                    dns.resolver_count,
                    dns.split_domain_count
                )
            },
        )
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentAvailability, AgentRuntimePresentation, DesktopPresentationState,
        NavigationDestination, PrivateDnsPresentation,
    };
    use prw_agent::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };

    #[test]
    fn overview_is_the_deterministic_default_destination() {
        let state = DesktopPresentationState::default();
        assert_eq!(state.selected, NavigationDestination::Overview);
        assert_eq!(NavigationDestination::ALL.len(), 7);
        assert_eq!(NavigationDestination::Overview.stack_name(), "overview");
    }

    #[test]
    fn runtime_states_project_without_granting_capabilities() {
        for (runtime, expected) in [
            (
                LocalAgentRuntimeState::Starting,
                AgentRuntimePresentation::Starting,
            ),
            (
                LocalAgentRuntimeState::Ready,
                AgentRuntimePresentation::Ready,
            ),
            (
                LocalAgentRuntimeState::Degraded,
                AgentRuntimePresentation::Degraded,
            ),
            (
                LocalAgentRuntimeState::Stopping,
                AgentRuntimePresentation::Stopping,
            ),
        ] {
            let state = DesktopPresentationState::connecting()
                .with_status(LocalAgentStatusSnapshot::current(runtime));
            assert_eq!(state.availability, AgentAvailability::Online);
            assert_eq!(state.runtime, Some(expected));
        }
    }

    #[test]
    fn status_text_projection_is_deterministic_and_read_only() {
        let connecting = DesktopPresentationState::connecting();
        assert_eq!(
            connecting.agent_status_text(),
            "Agent status\nAvailability: Connecting\nRuntime: Not reported"
        );
        assert_eq!(
            connecting.private_dns_status_text(),
            "Private DNS\nNo validated snapshot available"
        );

        let mut online = DesktopPresentationState::connecting().with_status(
            LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready),
        );
        online.private_dns = Some(PrivateDnsPresentation {
            enabled: true,
            device_naming: false,
            resolver_count: 2,
            split_domain_count: 1,
        });

        assert_eq!(
            online.agent_status_text(),
            "Agent status\nAvailability: Online\nRuntime: Ready"
        );
        assert_eq!(
            online.private_dns_status_text(),
            "Private DNS\nEnabled: Yes\nDevice naming: No\nResolvers: 2\nSplit domains: 1"
        );
    }

    #[test]
    fn error_projection_preserves_read_only_desktop_state() {
        let state = DesktopPresentationState::default().with_error(
            AgentAvailability::Error,
            "Local Agent probe worker ended without a result",
        );

        assert_eq!(state.availability, AgentAvailability::Error);
        assert_eq!(state.runtime, None);
        assert_eq!(state.private_dns, None);
        assert_eq!(state.selected, NavigationDestination::Overview);
        assert_eq!(
            state.detail,
            "Local Agent probe worker ended without a result"
        );
    }

    #[test]
    fn navigation_destinations_have_stable_presentation_contract() {
        for (actual, expected) in NavigationDestination::ALL.into_iter().zip([
            (NavigationDestination::Overview, "Overview", "overview"),
            (NavigationDestination::Machines, "Machines", "machines"),
            (NavigationDestination::Sessions, "Sessions", "sessions"),
            (NavigationDestination::Files, "Files", "files"),
            (NavigationDestination::Transfers, "Transfers", "transfers"),
            (NavigationDestination::Activity, "Activity", "activity"),
            (NavigationDestination::Settings, "Settings", "settings"),
        ]) {
            let (destination, title, stack_name) = expected;
            assert_eq!(actual, destination);
            assert_eq!(actual.title(), title);
            assert_eq!(actual.stack_name(), stack_name);
        }
    }

    #[test]
    fn agent_presentation_labels_are_stable() {
        for (availability, label) in [
            (AgentAvailability::Unknown, "Unknown"),
            (AgentAvailability::Offline, "Offline"),
            (AgentAvailability::Connecting, "Connecting"),
            (AgentAvailability::Online, "Online"),
            (AgentAvailability::Error, "Error"),
        ] {
            assert_eq!(availability.label(), label);
        }

        for (runtime, label) in [
            (AgentRuntimePresentation::Starting, "Starting"),
            (AgentRuntimePresentation::Ready, "Ready"),
            (AgentRuntimePresentation::Degraded, "Degraded"),
            (AgentRuntimePresentation::Stopping, "Stopping"),
            (AgentRuntimePresentation::Unknown, "Unknown"),
        ] {
            assert_eq!(runtime.label(), label);
        }
    }
}
