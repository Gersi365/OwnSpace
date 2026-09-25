use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;
use prw_agent::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME};

use crate::ipc;
use crate::state::{AgentAvailability, DesktopPresentationState, NavigationDestination};

const REFRESH_BUTTON_IDLE_LABEL: &str = "Refresh status";
const REFRESH_BUTTON_BUSY_LABEL: &str = "Refreshing…";
const COPY_SNAPSHOT_IDLE_LABEL: &str = "Copy current snapshot";
const COPY_SNAPSHOT_DONE_LABEL: &str = "Copied";

#[derive(Clone)]
struct StatusProbeTargets {
    overview_agent_label: gtk::Label,
    overview_dns_label: gtk::Label,
    overview_detail_label: gtk::Label,
    activity_agent_label: gtk::Label,
    activity_dns_label: gtk::Label,
    activity_detail_label: gtk::Label,
    activity_copy_button: gtk::Button,
    overview_refresh_button: gtk::Button,
    activity_refresh_button: gtk::Button,
}

pub fn build(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Ownspace")
        .default_width(1_100)
        .default_height(720)
        .build();

    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root.append(&adw::HeaderBar::new());

    let body = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    body.set_hexpand(true);
    body.set_vexpand(true);

    let stack = gtk::Stack::new();
    stack.set_hexpand(true);
    stack.set_vexpand(true);
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);

    let (overview, agent_label, dns_label, detail_label, refresh_button) = overview_page();
    stack.add_titled(
        &overview,
        Some(NavigationDestination::Overview.stack_name()),
        NavigationDestination::Overview.title(),
    );

    let (
        activity,
        activity_agent_label,
        activity_dns_label,
        activity_detail_label,
        activity_refresh_button,
        activity_copy_button,
    ) = activity_page();

    for destination in NavigationDestination::ALL.into_iter().skip(1) {
        let page = match destination {
            NavigationDestination::Activity => activity.clone(),
            NavigationDestination::Settings => settings_page(),
            _ => placeholder_page(destination),
        };
        stack.add_titled(&page, Some(destination.stack_name()), destination.title());
    }

    let sidebar = gtk::StackSidebar::new();
    sidebar.set_stack(&stack);
    sidebar.set_size_request(220, -1);

    body.append(&sidebar);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));
    body.append(&stack);
    root.append(&body);

    window.set_content(Some(&root));
    window.present();

    let probe_targets = StatusProbeTargets {
        overview_agent_label: agent_label,
        overview_dns_label: dns_label,
        overview_detail_label: detail_label,
        activity_agent_label,
        activity_dns_label,
        activity_detail_label,
        activity_copy_button,
        overview_refresh_button: refresh_button,
        activity_refresh_button,
    };
    let connecting = DesktopPresentationState::connecting();
    render_probe_state(&connecting, &probe_targets);
    connect_refresh_controls(&probe_targets);
    start_startup_probe(probe_targets);
}

fn overview_page() -> (gtk::Box, gtk::Label, gtk::Label, gtk::Label, gtk::Button) {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some("Overview"));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let subtitle = gtk::Label::new(Some(
        "Read-only local Agent status. Refresh performs only bounded local IPC reads.",
    ));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class("dim-label");
    page.append(&subtitle);

    let refresh_button = gtk::Button::with_label(REFRESH_BUTTON_IDLE_LABEL);
    refresh_button.set_halign(gtk::Align::Start);
    page.append(&refresh_button);

    let agent_label = section_label("Agent status");
    page.append(&agent_label);

    let dns_label = section_label("Private DNS");
    page.append(&dns_label);

    let detail_label = gtk::Label::new(None);
    detail_label.set_xalign(0.0);
    detail_label.set_wrap(true);
    detail_label.add_css_class("dim-label");
    page.append(&detail_label);

    (page, agent_label, dns_label, detail_label, refresh_button)
}

fn activity_page() -> (
    gtk::Box,
    gtk::Label,
    gtk::Label,
    gtk::Label,
    gtk::Button,
    gtk::Button,
) {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some("Activity"));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let subtitle = gtk::Label::new(Some(
        "Latest local diagnostics snapshot. Refresh uses the same bounded local status probe as Overview; copy becomes available after the first probe result and writes only the currently rendered snapshot to the local desktop clipboard.",
    ));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class("dim-label");
    page.append(&subtitle);

    let refresh_button = gtk::Button::with_label(REFRESH_BUTTON_IDLE_LABEL);
    refresh_button.set_halign(gtk::Align::Start);
    page.append(&refresh_button);

    let agent_label = section_label("Agent status");
    page.append(&agent_label);

    let dns_label = section_label("Private DNS");
    page.append(&dns_label);

    let detail_label = gtk::Label::new(None);
    detail_label.set_xalign(0.0);
    detail_label.set_wrap(true);
    detail_label.add_css_class("dim-label");
    page.append(&detail_label);

    let copy_button = gtk::Button::with_label(COPY_SNAPSHOT_IDLE_LABEL);
    copy_button.set_halign(gtk::Align::Start);
    let copy_agent_label = agent_label.clone();
    let copy_dns_label = dns_label.clone();
    let copy_detail_label = detail_label.clone();
    copy_button.connect_clicked(move |button| {
        let agent = copy_agent_label.text().to_string();
        let dns = copy_dns_label.text().to_string();
        let detail = copy_detail_label.text().to_string();
        let copy_text = activity_snapshot_clipboard_text(&agent, &dns, &detail);
        button.display().clipboard().set_text(&copy_text);
        button.set_label(COPY_SNAPSHOT_DONE_LABEL);
    });
    page.append(&copy_button);

    (
        page,
        agent_label,
        dns_label,
        detail_label,
        refresh_button,
        copy_button,
    )
}

fn activity_snapshot_clipboard_text(agent: &str, dns: &str, detail: &str) -> String {
    format!("{agent}\n\n{dns}\n\nDetail\n{detail}")
}

const fn activity_snapshot_copy_available(availability: AgentAvailability) -> bool {
    matches!(
        availability,
        AgentAvailability::Offline | AgentAvailability::Online | AgentAvailability::Error
    )
}

fn section_label(title: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("title-3");
    label
}

fn local_endpoint_contract_text() -> String {
    format!("$XDG_RUNTIME_DIR/{AGENT_RUNTIME_SUBDIRECTORY}/{AGENT_SOCKET_FILENAME}")
}

fn settings_page() -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some("Settings"));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let status = gtk::Label::new(Some("Read-only local diagnostics"));
    status.set_xalign(0.0);
    status.add_css_class("title-3");
    page.append(&status);

    let detail = gtk::Label::new(Some(
        "This surface exposes local Ownspace diagnostics only. It does not change Agent configuration or activate capabilities.",
    ));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class("dim-label");
    page.append(&detail);

    let endpoint_title = gtk::Label::new(Some("Local control endpoint"));
    endpoint_title.set_xalign(0.0);
    endpoint_title.add_css_class("heading");
    page.append(&endpoint_title);

    let endpoint = gtk::Label::new(Some(&local_endpoint_contract_text()));
    endpoint.set_xalign(0.0);
    endpoint.set_selectable(true);
    endpoint.set_wrap(true);
    endpoint.add_css_class("monospace");
    page.append(&endpoint);

    let resolved_title = gtk::Label::new(Some("Resolved endpoint for this session"));
    resolved_title.set_xalign(0.0);
    resolved_title.add_css_class("heading");
    page.append(&resolved_title);

    let resolved_endpoint = ipc::endpoint_candidate_from_environment();
    let resolved_text = match &resolved_endpoint {
        Ok(path) => path.display().to_string(),
        Err(error) => format!("Unavailable: {error}"),
    };
    let resolved = gtk::Label::new(Some(&resolved_text));
    resolved.set_xalign(0.0);
    resolved.set_selectable(true);
    resolved.set_wrap(true);
    resolved.add_css_class("monospace");
    page.append(&resolved);

    let copy_button = gtk::Button::with_label("Copy resolved endpoint");
    copy_button.set_halign(gtk::Align::Start);
    match resolved_endpoint {
        Ok(path) => {
            let copy_text = path.display().to_string();
            copy_button.connect_clicked(move |button| {
                button.display().clipboard().set_text(&copy_text);
                button.set_label("Copied");
            });
        }
        Err(_) => copy_button.set_sensitive(false),
    }
    page.append(&copy_button);

    let resolved_detail = gtk::Label::new(Some(
        "This is path derivation only; copying uses the local desktop clipboard and does not assert endpoint trust, availability, or connectivity.",
    ));
    resolved_detail.set_xalign(0.0);
    resolved_detail.set_wrap(true);
    resolved_detail.add_css_class("dim-label");
    page.append(&resolved_detail);

    page
}

fn placeholder_page(destination: NavigationDestination) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some(destination.title()));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let status = gtk::Label::new(Some("Placeholder — no capability active"));
    status.set_xalign(0.0);
    status.add_css_class("title-3");
    page.append(&status);

    let detail = gtk::Label::new(Some(placeholder_description(destination)));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class("dim-label");
    page.append(&detail);

    page
}

const fn placeholder_description(destination: NavigationDestination) -> &'static str {
    match destination {
        NavigationDestination::Overview => {
            "Overview is implemented as a read-only local status surface."
        }
        NavigationDestination::Machines => {
            "Reserved for enrolled-device and reachability presentation. Endpoint data is not identity or authorization."
        }
        NavigationDestination::Sessions => {
            "Reserved for authorized terminal, Remote Desktop, and forwarding session presentation when runtime state is available."
        }
        NavigationDestination::Files => {
            "Reserved for remote browsing and file operations through the existing authenticated file authority."
        }
        NavigationDestination::Transfers => {
            "Reserved for verified upload/download progress and completion state."
        }
        NavigationDestination::Activity => {
            "Reserved for locally available Ownspace activity and diagnostics. No external telemetry is implied."
        }
        NavigationDestination::Settings => {
            "Reserved for explicit owner-controlled local settings and diagnostics; no cloud account dependency is implied."
        }
    }
}

fn connect_refresh_controls(targets: &StatusProbeTargets) {
    let overview_targets = targets.clone();
    targets
        .overview_refresh_button
        .connect_clicked(move |_| start_startup_probe(overview_targets.clone()));

    let activity_targets = targets.clone();
    targets
        .activity_refresh_button
        .connect_clicked(move |_| start_startup_probe(activity_targets.clone()));
}

fn start_startup_probe(targets: StatusProbeTargets) {
    set_refresh_controls_busy(
        &targets.overview_refresh_button,
        &targets.activity_refresh_button,
        true,
    );
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn_result = std::thread::Builder::new()
        .name("prw-desktop-readonly-agent-probe".to_owned())
        .spawn(move || {
            let _ = sender.send(ipc::query_startup());
        });

    if spawn_result.is_err() {
        let state = DesktopPresentationState::default().with_error(
            crate::state::AgentAvailability::Error,
            "Unable to start the bounded local Agent probe worker",
        );
        render_probe_state(&state, &targets);
        set_refresh_controls_busy(
            &targets.overview_refresh_button,
            &targets.activity_refresh_button,
            false,
        );
        return;
    }

    let _source_id = glib::timeout_add_local(Duration::from_millis(75), move || {
        match receiver.try_recv() {
            Ok(probe) => {
                let state = probe.into_presentation();
                render_probe_state(&state, &targets);
                set_refresh_controls_busy(
                    &targets.overview_refresh_button,
                    &targets.activity_refresh_button,
                    false,
                );
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                let state = DesktopPresentationState::default().with_error(
                    crate::state::AgentAvailability::Error,
                    "Local Agent probe worker ended without a result",
                );
                render_probe_state(&state, &targets);
                set_refresh_controls_busy(
                    &targets.overview_refresh_button,
                    &targets.activity_refresh_button,
                    false,
                );
                glib::ControlFlow::Break
            }
        }
    });
}

fn render_probe_state(state: &DesktopPresentationState, targets: &StatusProbeTargets) {
    render_state(
        state,
        &targets.overview_agent_label,
        &targets.overview_dns_label,
        &targets.overview_detail_label,
    );
    render_state(
        state,
        &targets.activity_agent_label,
        &targets.activity_dns_label,
        &targets.activity_detail_label,
    );
    targets
        .activity_copy_button
        .set_label(COPY_SNAPSHOT_IDLE_LABEL);
    targets
        .activity_copy_button
        .set_sensitive(activity_snapshot_copy_available(state.availability));
}

fn set_refresh_controls_busy(
    overview_refresh_button: &gtk::Button,
    activity_refresh_button: &gtk::Button,
    busy: bool,
) {
    let label = if busy {
        REFRESH_BUTTON_BUSY_LABEL
    } else {
        REFRESH_BUTTON_IDLE_LABEL
    };
    for button in [overview_refresh_button, activity_refresh_button] {
        button.set_sensitive(!busy);
        button.set_label(label);
    }
}

fn render_state(
    state: &DesktopPresentationState,
    agent_label: &gtk::Label,
    dns_label: &gtk::Label,
    detail_label: &gtk::Label,
) {
    agent_label.set_text(&state.agent_status_text());
    dns_label.set_text(&state.private_dns_status_text());
    detail_label.set_text(&state.detail);
}

#[cfg(test)]
mod tests {
    use super::{
        AgentAvailability, COPY_SNAPSHOT_DONE_LABEL, COPY_SNAPSHOT_IDLE_LABEL,
        NavigationDestination, REFRESH_BUTTON_BUSY_LABEL, REFRESH_BUTTON_IDLE_LABEL,
        activity_snapshot_clipboard_text, activity_snapshot_copy_available,
        local_endpoint_contract_text, placeholder_description,
    };

    #[test]
    fn refresh_button_labels_have_stable_presentation_contract() {
        assert_eq!(REFRESH_BUTTON_IDLE_LABEL, "Refresh status");
        assert_eq!(REFRESH_BUTTON_BUSY_LABEL, "Refreshing…");
    }

    #[test]
    fn activity_snapshot_clipboard_projection_is_local_text_only() {
        assert_eq!(COPY_SNAPSHOT_IDLE_LABEL, "Copy current snapshot");
        assert_eq!(COPY_SNAPSHOT_DONE_LABEL, "Copied");
        assert_eq!(
            activity_snapshot_clipboard_text(
                "Agent status\nAvailability: Online\nRuntime: Ready",
                "Private DNS\nEnabled: Yes",
                "Local IPC protocol 1.0",
            ),
            "Agent status\nAvailability: Online\nRuntime: Ready\n\nPrivate DNS\nEnabled: Yes\n\nDetail\nLocal IPC protocol 1.0"
        );
    }

    #[test]
    fn activity_snapshot_copy_requires_a_settled_probe_result() {
        assert!(!activity_snapshot_copy_available(AgentAvailability::Unknown));
        assert!(!activity_snapshot_copy_available(
            AgentAvailability::Connecting
        ));
        assert!(activity_snapshot_copy_available(AgentAvailability::Offline));
        assert!(activity_snapshot_copy_available(AgentAvailability::Online));
        assert!(activity_snapshot_copy_available(AgentAvailability::Error));
    }

    #[test]
    fn settings_endpoint_uses_authoritative_agent_identifiers() {
        assert_eq!(
            local_endpoint_contract_text(),
            "$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock"
        );
    }

    #[test]
    fn placeholder_descriptions_have_stable_presentation_contract() {
        for (destination, description) in [
            (
                NavigationDestination::Overview,
                "Overview is implemented as a read-only local status surface.",
            ),
            (
                NavigationDestination::Machines,
                "Reserved for enrolled-device and reachability presentation. Endpoint data is not identity or authorization.",
            ),
            (
                NavigationDestination::Sessions,
                "Reserved for authorized terminal, Remote Desktop, and forwarding session presentation when runtime state is available.",
            ),
            (
                NavigationDestination::Files,
                "Reserved for remote browsing and file operations through the existing authenticated file authority.",
            ),
            (
                NavigationDestination::Transfers,
                "Reserved for verified upload/download progress and completion state.",
            ),
            (
                NavigationDestination::Activity,
                "Reserved for locally available Ownspace activity and diagnostics. No external telemetry is implied.",
            ),
            (
                NavigationDestination::Settings,
                "Reserved for explicit owner-controlled local settings and diagnostics; no cloud account dependency is implied.",
            ),
        ] {
            assert_eq!(placeholder_description(destination), description);
        }
    }
}
