use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use crate::ipc;
use crate::state::{DesktopPresentationState, NavigationDestination};

const REFRESH_BUTTON_IDLE_LABEL: &str = "Refresh status";
const REFRESH_BUTTON_BUSY_LABEL: &str = "Refreshing…";

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

    for destination in NavigationDestination::ALL.into_iter().skip(1) {
        let page = placeholder_page(destination);
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

    render_state(
        &DesktopPresentationState::connecting(),
        &agent_label,
        &dns_label,
        &detail_label,
    );
    let refresh_agent_label = agent_label.clone();
    let refresh_dns_label = dns_label.clone();
    let refresh_detail_label = detail_label.clone();
    refresh_button.connect_clicked(move |button| {
        render_state(
            &DesktopPresentationState::connecting(),
            &refresh_agent_label,
            &refresh_dns_label,
            &refresh_detail_label,
        );
        start_startup_probe(
            refresh_agent_label.clone(),
            refresh_dns_label.clone(),
            refresh_detail_label.clone(),
            button.clone(),
        );
    });
    start_startup_probe(agent_label, dns_label, detail_label, refresh_button);
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

fn section_label(title: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("title-3");
    label
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

fn start_startup_probe(
    agent_label: gtk::Label,
    dns_label: gtk::Label,
    detail_label: gtk::Label,
    refresh_button: gtk::Button,
) {
    refresh_button.set_sensitive(false);
    refresh_button.set_label(REFRESH_BUTTON_BUSY_LABEL);
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
        render_state(&state, &agent_label, &dns_label, &detail_label);
        refresh_button.set_label(REFRESH_BUTTON_IDLE_LABEL);
        refresh_button.set_sensitive(true);
        return;
    }

    let _source_id = glib::timeout_add_local(Duration::from_millis(75), move || {
        match receiver.try_recv() {
            Ok(probe) => {
                let state = probe.into_presentation();
                render_state(&state, &agent_label, &dns_label, &detail_label);
                refresh_button.set_label(REFRESH_BUTTON_IDLE_LABEL);
                refresh_button.set_sensitive(true);
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                let state = DesktopPresentationState::default().with_error(
                    crate::state::AgentAvailability::Error,
                    "Local Agent probe worker ended without a result",
                );
                render_state(&state, &agent_label, &dns_label, &detail_label);
                refresh_button.set_label(REFRESH_BUTTON_IDLE_LABEL);
                refresh_button.set_sensitive(true);
                glib::ControlFlow::Break
            }
        }
    });
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
