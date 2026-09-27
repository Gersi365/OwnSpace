use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;
use prw_agent::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME, LocalIpcProtocolVersion};
use prw_file_service::RemotePath;

use crate::ipc;
use crate::local_management_ipc::LocalFileListEntry;
use crate::state::{DesktopPresentationState, NavigationDestination};

const REFRESH_BUTTON_IDLE_LABEL: &str = "Refresh status";
const REFRESH_BUTTON_BUSY_LABEL: &str = "Refreshing…";
const COPY_SNAPSHOT_IDLE_LABEL: &str = "Copy current snapshot";
const COPY_SNAPSHOT_DONE_LABEL: &str = "Copied";
const PLACEHOLDER_STATUS: &str = "No live state source available";
const FILES_LIST_IDLE_LABEL: &str = "List files";
const FILES_LIST_BUSY_LABEL: &str = "Listing…";
const FILES_REFRESH_LABEL: &str = "Refresh";
const FILES_PATH_INVALID_STATUS: &str = "Invalid path: use a canonical relative path under home";
const FILES_PATH_UNLOADED_LABEL: &str = "Current path: not loaded";
const FILES_SUBTITLE: &str = concat!(
    "Read-only directory listing under the local owner home authority. ",
    "Paths are relative; this surface does not read file contents, mutate files, transfer data, open terminals, or create forwarding."
);
const MACHINES_SUBTITLE: &str = concat!(
    "Current local owner-host status from the same bounded Agent snapshot as Overview. ",
    "This surface does not enumerate remote devices, infer identity from endpoint data, or grant capabilities."
);
const ACTIVITY_SUBTITLE: &str = concat!(
    "Latest local diagnostics snapshot. ",
    "Refresh uses the same bounded local status probe as Overview; ",
    "copy writes the rendered snapshot plus the session endpoint candidate to the local desktop clipboard."
);

#[derive(Clone)]
struct StatusProbeTargets {
    overview_agent_label: gtk::Label,
    overview_dns_label: gtk::Label,
    overview_detail_label: gtk::Label,
    machines_agent_label: gtk::Label,
    machines_dns_label: gtk::Label,
    machines_detail_label: gtk::Label,
    activity_agent_label: gtk::Label,
    activity_dns_label: gtk::Label,
    activity_detail_label: gtk::Label,
    settings_agent_protocol_label: gtk::Label,
    activity_copy_button: gtk::Button,
    overview_refresh_button: gtk::Button,
    machines_refresh_button: gtk::Button,
    activity_refresh_button: gtk::Button,
}

#[derive(Clone)]
struct FilesPageTargets {
    path_entry: gtk::Entry,
    list_button: gtk::Button,
    home_button: gtk::Button,
    up_button: gtk::Button,
    refresh_button: gtk::Button,
    current_path_label: gtk::Label,
    status: gtk::Label,
    entries: gtk::Box,
    current_path: Rc<RefCell<String>>,
    has_successful_listing: Rc<Cell<bool>>,
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
        machines,
        machines_agent_label,
        machines_dns_label,
        machines_detail_label,
        machines_refresh_button,
    ) = machines_page();

    let (
        activity,
        activity_agent_label,
        activity_dns_label,
        activity_detail_label,
        activity_refresh_button,
        activity_copy_button,
    ) = activity_page();
    let files = files_page();
    let (settings, settings_agent_protocol_label) = settings_page();

    for destination in NavigationDestination::ALL.into_iter().skip(1) {
        let page = match destination {
            NavigationDestination::Overview => continue,
            NavigationDestination::Machines => machines.clone(),
            NavigationDestination::Sessions | NavigationDestination::Transfers => {
                placeholder_page(destination)
            }
            NavigationDestination::Files => files.clone(),
            NavigationDestination::Activity => activity.clone(),
            NavigationDestination::Settings => settings.clone(),
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
        machines_agent_label,
        machines_dns_label,
        machines_detail_label,
        activity_agent_label,
        activity_dns_label,
        activity_detail_label,
        settings_agent_protocol_label,
        activity_copy_button,
        overview_refresh_button: refresh_button,
        machines_refresh_button,
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

fn machines_page() -> (gtk::Box, gtk::Label, gtk::Label, gtk::Label, gtk::Button) {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some("Machines"));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let subtitle = gtk::Label::new(Some(MACHINES_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class("dim-label");
    page.append(&subtitle);

    let refresh_button = gtk::Button::with_label(REFRESH_BUTTON_IDLE_LABEL);
    refresh_button.set_halign(gtk::Align::Start);
    page.append(&refresh_button);

    let agent_label = section_label("Local host Agent");
    page.append(&agent_label);

    let dns_label = section_label("Local host Private DNS");
    page.append(&dns_label);

    let detail_label = gtk::Label::new(None);
    detail_label.set_xalign(0.0);
    detail_label.set_wrap(true);
    detail_label.add_css_class("dim-label");
    page.append(&detail_label);

    (page, agent_label, dns_label, detail_label, refresh_button)
}

fn file_list_child_path(parent: &str, child_name: &str) -> Option<String> {
    if child_name.is_empty() || child_name.contains('/') {
        return None;
    }

    let candidate = if parent.is_empty() {
        child_name.to_owned()
    } else {
        format!("{parent}/{child_name}")
    };
    RemotePath::parse(&candidate).ok()?;
    Some(candidate)
}

fn file_list_parent_path(path: &str) -> Option<String> {
    RemotePath::parse(path).ok()?;
    if path.is_empty() {
        return None;
    }

    match path.rsplit_once('/') {
        Some((parent, _)) => Some(parent.to_owned()),
        None => Some(String::new()),
    }
}

fn file_list_path_label(path: &str) -> String {
    if path.is_empty() {
        "Current path: home".to_owned()
    } else {
        format!("Current path: {path}")
    }
}

fn file_list_manual_path_is_canonical(path: &str) -> bool {
    RemotePath::parse(path).is_ok()
}

const fn file_list_refresh_enabled(controls_enabled: bool, has_successful_listing: bool) -> bool {
    controls_enabled && has_successful_listing
}

fn clear_file_list_entries(entries: &gtk::Box) {
    while let Some(child) = entries.first_child() {
        entries.remove(&child);
    }
}

fn set_file_list_controls_enabled(targets: &FilesPageTargets, enabled: bool) {
    targets.path_entry.set_sensitive(enabled);
    targets.list_button.set_sensitive(enabled);
    targets.home_button.set_sensitive(enabled);
    targets
        .refresh_button
        .set_sensitive(file_list_refresh_enabled(
            enabled,
            targets.has_successful_listing.get(),
        ));
    targets
        .up_button
        .set_sensitive(enabled && !targets.current_path.borrow().is_empty());
    targets.entries.set_sensitive(enabled);
}

fn restore_file_list_path_entry(targets: &FilesPageTargets) {
    targets
        .path_entry
        .set_text(targets.current_path.borrow().as_str());
}

fn append_file_list_entry(
    targets: &FilesPageTargets,
    parent_path: &str,
    entry: &LocalFileListEntry,
) {
    if entry.is_directory() {
        let button = gtk::Button::with_label(&entry.display_text());
        button.set_halign(gtk::Align::Start);
        if let Some(child_path) = file_list_child_path(parent_path, entry.name()) {
            let navigation_targets = targets.clone();
            button.connect_clicked(move |_| {
                request_file_listing(&navigation_targets, child_path.clone());
            });
        } else {
            button.set_sensitive(false);
            button.set_tooltip_text(Some(
                "Directory entry cannot form a canonical relative path",
            ));
        }
        targets.entries.append(&button);
    } else {
        let label = gtk::Label::new(Some(&entry.display_text()));
        label.set_xalign(0.0);
        label.set_selectable(true);
        targets.entries.append(&label);
    }
}

fn request_manual_file_listing(targets: &FilesPageTargets, path: String) {
    if !file_list_manual_path_is_canonical(&path) {
        targets.status.set_text(FILES_PATH_INVALID_STATUS);
        return;
    }

    request_file_listing(targets, path);
}

fn request_file_listing(targets: &FilesPageTargets, path: String) {
    set_file_list_controls_enabled(targets, false);
    targets.list_button.set_label(FILES_LIST_BUSY_LABEL);
    targets
        .status
        .set_text("Reading authorized directory listing…");

    let worker_path = path.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn_result = std::thread::Builder::new()
        .name("prw-desktop-readonly-file-list".to_owned())
        .spawn(move || {
            let _ = sender.send(ipc::query_file_list(&worker_path));
        });

    if spawn_result.is_err() {
        restore_file_list_path_entry(targets);
        targets
            .status
            .set_text("Unable to start the read-only file-list worker");
        targets.list_button.set_label(FILES_LIST_IDLE_LABEL);
        set_file_list_controls_enabled(targets, true);
        return;
    }

    let poll_targets = targets.clone();
    let _source_id = glib::timeout_add_local(Duration::from_millis(75), move || {
        match receiver.try_recv() {
            Ok(Ok(listing)) => {
                poll_targets.has_successful_listing.set(true);
                poll_targets.current_path.borrow_mut().clone_from(&path);
                poll_targets.path_entry.set_text(&path);
                poll_targets
                    .current_path_label
                    .set_text(&file_list_path_label(&path));
                clear_file_list_entries(&poll_targets.entries);
                if listing.is_empty() {
                    let empty = gtk::Label::new(Some("(empty directory)"));
                    empty.set_xalign(0.0);
                    poll_targets.entries.append(&empty);
                } else {
                    for entry in listing {
                        append_file_list_entry(&poll_targets, &path, &entry);
                    }
                }
                poll_targets.status.set_text("Read-only listing loaded");
                poll_targets.list_button.set_label(FILES_LIST_IDLE_LABEL);
                set_file_list_controls_enabled(&poll_targets, true);
                glib::ControlFlow::Break
            }
            Ok(Err(error)) => {
                restore_file_list_path_entry(&poll_targets);
                poll_targets
                    .status
                    .set_text(&format!("Unavailable: {error}"));
                poll_targets.list_button.set_label(FILES_LIST_IDLE_LABEL);
                set_file_list_controls_enabled(&poll_targets, true);
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                restore_file_list_path_entry(&poll_targets);
                poll_targets
                    .status
                    .set_text("Read-only file-list worker ended without a result");
                poll_targets.list_button.set_label(FILES_LIST_IDLE_LABEL);
                set_file_list_controls_enabled(&poll_targets, true);
                glib::ControlFlow::Break
            }
        }
    });
}

fn files_page() -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(32);
    page.set_margin_bottom(32);
    page.set_margin_start(32);
    page.set_margin_end(32);

    let title = gtk::Label::new(Some("Files"));
    title.set_xalign(0.0);
    title.add_css_class("title-1");
    page.append(&title);

    let subtitle = gtk::Label::new(Some(FILES_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class("dim-label");
    page.append(&subtitle);

    let current_path_label = gtk::Label::new(Some(FILES_PATH_UNLOADED_LABEL));
    current_path_label.set_xalign(0.0);
    current_path_label.add_css_class("title-3");
    page.append(&current_path_label);

    let path_entry = gtk::Entry::new();
    path_entry.set_placeholder_text(Some("Relative path; blank = home"));
    page.append(&path_entry);

    let navigation = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let home_button = gtk::Button::with_label("Home");
    let up_button = gtk::Button::with_label("Up");
    up_button.set_sensitive(false);
    let refresh_button = gtk::Button::with_label(FILES_REFRESH_LABEL);
    refresh_button.set_sensitive(false);
    let list_button = gtk::Button::with_label(FILES_LIST_IDLE_LABEL);
    navigation.append(&home_button);
    navigation.append(&up_button);
    navigation.append(&refresh_button);
    navigation.append(&list_button);
    page.append(&navigation);

    let status = gtk::Label::new(Some("No directory listing requested yet"));
    status.set_xalign(0.0);
    status.add_css_class("title-3");
    page.append(&status);

    let entries = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_hexpand(true);
    scroller.set_vexpand(true);
    scroller.set_child(Some(&entries));
    page.append(&scroller);

    let targets = FilesPageTargets {
        path_entry,
        list_button,
        home_button,
        up_button,
        refresh_button,
        current_path_label,
        status,
        entries,
        current_path: Rc::new(RefCell::new(String::new())),
        has_successful_listing: Rc::new(Cell::new(false)),
    };

    let list_targets = targets.clone();
    targets.list_button.connect_clicked(move |_| {
        let path = list_targets.path_entry.text().to_string();
        request_manual_file_listing(&list_targets, path);
    });

    let entry_targets = targets.clone();
    targets.path_entry.connect_activate(move |entry| {
        request_manual_file_listing(&entry_targets, entry.text().to_string());
    });

    let refresh_targets = targets.clone();
    targets.refresh_button.connect_clicked(move |_| {
        let current_path = refresh_targets.current_path.borrow().clone();
        request_file_listing(&refresh_targets, current_path);
    });

    let home_targets = targets.clone();
    targets.home_button.connect_clicked(move |_| {
        request_file_listing(&home_targets, String::new());
    });

    let up_targets = targets.clone();
    targets.up_button.connect_clicked(move |_| {
        let current_path = up_targets.current_path.borrow().clone();
        if let Some(parent_path) = file_list_parent_path(&current_path) {
            request_file_listing(&up_targets, parent_path);
        }
    });

    page
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

    let subtitle = gtk::Label::new(Some(ACTIVITY_SUBTITLE));
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
    let copy_endpoint = ipc::endpoint_candidate_from_environment().map_or_else(
        |error| format!("Unavailable: {error}"),
        |path| path.display().to_string(),
    );
    copy_button.connect_clicked(move |button| {
        let agent = copy_agent_label.text().to_string();
        let dns = copy_dns_label.text().to_string();
        let detail = copy_detail_label.text().to_string();
        let copy_text = activity_snapshot_clipboard_text(&agent, &dns, &detail, &copy_endpoint);
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

fn activity_snapshot_clipboard_text(
    agent: &str,
    dns: &str,
    detail: &str,
    endpoint_candidate: &str,
) -> String {
    format!(
        "{agent}\n\n{dns}\n\nDetail\n{detail}\n\nSession endpoint candidate\n{endpoint_candidate}"
    )
}

fn section_label(title: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("title-3");
    label
}

fn desktop_version_text() -> String {
    format!("Ownspace Desktop version {}", env!("CARGO_PKG_VERSION"))
}

fn desktop_local_ipc_protocol_text() -> String {
    let version = LocalIpcProtocolVersion::current();
    format!(
        "Supported local IPC protocol {}.{}",
        version.major(),
        version.minor()
    )
}

fn local_endpoint_contract_text() -> String {
    format!("$XDG_RUNTIME_DIR/{AGENT_RUNTIME_SUBDIRECTORY}/{AGENT_SOCKET_FILENAME}")
}

fn settings_page() -> (gtk::Box, gtk::Label) {
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

    let build_title = gtk::Label::new(Some("Build information"));
    build_title.set_xalign(0.0);
    build_title.add_css_class("heading");
    page.append(&build_title);

    let version = gtk::Label::new(Some(&desktop_version_text()));
    version.set_xalign(0.0);
    version.set_selectable(true);
    version.add_css_class("monospace");
    page.append(&version);

    let protocol_title = gtk::Label::new(Some("Local IPC compatibility"));
    protocol_title.set_xalign(0.0);
    protocol_title.add_css_class("heading");
    page.append(&protocol_title);

    let protocol = gtk::Label::new(Some(&desktop_local_ipc_protocol_text()));
    protocol.set_xalign(0.0);
    protocol.set_selectable(true);
    protocol.add_css_class("monospace");
    page.append(&protocol);

    let protocol_detail = gtk::Label::new(Some(
        "This is the protocol version compiled into the desktop client. It does not probe the Agent or assert endpoint trust, availability, or connectivity.",
    ));
    protocol_detail.set_xalign(0.0);
    protocol_detail.set_wrap(true);
    protocol_detail.add_css_class("dim-label");
    page.append(&protocol_detail);

    let agent_protocol = append_agent_reported_protocol_section(&page);

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

    (page, agent_protocol)
}

fn append_agent_reported_protocol_section(page: &gtk::Box) -> gtk::Label {
    let title = gtk::Label::new(Some("Latest Agent-reported protocol"));
    title.set_xalign(0.0);
    title.add_css_class("heading");
    page.append(&title);

    let protocol = gtk::Label::new(Some(
        &DesktopPresentationState::connecting().agent_reported_protocol_text(),
    ));
    protocol.set_xalign(0.0);
    protocol.set_selectable(true);
    protocol.add_css_class("monospace");
    page.append(&protocol);

    let detail = gtk::Label::new(Some(
        "This value and compatibility classification come only from the existing bounded GetAgentStatus snapshot and the authoritative LocalIpcProtocolVersion support rule. They add no Agent probe and do not assert endpoint trust or capability authorization.",
    ));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class("dim-label");
    page.append(&detail);

    protocol
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

    let status = gtk::Label::new(Some(PLACEHOLDER_STATUS));
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

fn placeholder_description(destination: NavigationDestination) -> &'static str {
    match destination {
        NavigationDestination::Sessions => {
            "Reserved for authorized terminal, Remote Desktop, and forwarding session presentation when runtime state is available."
        }
        NavigationDestination::Transfers => {
            "Reserved for verified upload/download progress and completion state."
        }
        NavigationDestination::Overview
        | NavigationDestination::Machines
        | NavigationDestination::Files
        | NavigationDestination::Activity
        | NavigationDestination::Settings => {
            unreachable!("implemented destinations must not use placeholder descriptions")
        }
    }
}

fn connect_refresh_controls(targets: &StatusProbeTargets) {
    let overview_targets = targets.clone();
    targets
        .overview_refresh_button
        .connect_clicked(move |_| start_startup_probe(overview_targets.clone()));

    let machines_targets = targets.clone();
    targets
        .machines_refresh_button
        .connect_clicked(move |_| start_startup_probe(machines_targets.clone()));

    let activity_targets = targets.clone();
    targets
        .activity_refresh_button
        .connect_clicked(move |_| start_startup_probe(activity_targets.clone()));
}

fn start_startup_probe(targets: StatusProbeTargets) {
    set_refresh_controls_busy(
        &targets.overview_refresh_button,
        &targets.machines_refresh_button,
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
            &targets.machines_refresh_button,
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
                    &targets.machines_refresh_button,
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
                    &targets.machines_refresh_button,
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
        &targets.machines_agent_label,
        &targets.machines_dns_label,
        &targets.machines_detail_label,
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
        .settings_agent_protocol_label
        .set_text(&state.agent_reported_protocol_text());
}

fn set_refresh_controls_busy(
    overview_refresh_button: &gtk::Button,
    machines_refresh_button: &gtk::Button,
    activity_refresh_button: &gtk::Button,
    busy: bool,
) {
    let label = if busy {
        REFRESH_BUTTON_BUSY_LABEL
    } else {
        REFRESH_BUTTON_IDLE_LABEL
    };
    for button in [
        overview_refresh_button,
        machines_refresh_button,
        activity_refresh_button,
    ] {
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
        ACTIVITY_SUBTITLE, COPY_SNAPSHOT_DONE_LABEL, COPY_SNAPSHOT_IDLE_LABEL,
        FILES_LIST_BUSY_LABEL, FILES_LIST_IDLE_LABEL, FILES_PATH_INVALID_STATUS,
        FILES_PATH_UNLOADED_LABEL, FILES_REFRESH_LABEL, FILES_SUBTITLE, MACHINES_SUBTITLE,
        NavigationDestination, PLACEHOLDER_STATUS, REFRESH_BUTTON_BUSY_LABEL,
        REFRESH_BUTTON_IDLE_LABEL, activity_snapshot_clipboard_text,
        desktop_local_ipc_protocol_text, desktop_version_text, file_list_child_path,
        file_list_manual_path_is_canonical, file_list_parent_path, file_list_path_label,
        file_list_refresh_enabled, local_endpoint_contract_text, placeholder_description,
    };

    #[test]
    fn refresh_button_labels_have_stable_presentation_contract() {
        assert_eq!(REFRESH_BUTTON_IDLE_LABEL, "Refresh status");
        assert_eq!(REFRESH_BUTTON_BUSY_LABEL, "Refreshing…");
    }

    #[test]
    fn files_surface_labels_lock_read_only_file_list_boundary() {
        assert_eq!(FILES_LIST_IDLE_LABEL, "List files");
        assert_eq!(FILES_LIST_BUSY_LABEL, "Listing…");
        assert_eq!(FILES_REFRESH_LABEL, "Refresh");
        assert_eq!(
            FILES_SUBTITLE,
            concat!(
                "Read-only directory listing under the local owner home authority. ",
                "Paths are relative; this surface does not read file contents, mutate files, transfer data, open terminals, or create forwarding."
            )
        );
    }

    #[test]
    fn files_manual_paths_fail_fast_on_noncanonical_input() {
        assert!(file_list_manual_path_is_canonical(""));
        assert!(file_list_manual_path_is_canonical("docs/reports"));

        for invalid_path in [
            "/etc",
            "../escape",
            "docs/../escape",
            "./docs",
            "docs//reports",
            "docs/./reports",
            "docs/reports/",
            r"docs\reports",
        ] {
            assert!(
                !file_list_manual_path_is_canonical(invalid_path),
                "{invalid_path}"
            );
        }

        assert_eq!(
            FILES_PATH_INVALID_STATUS,
            "Invalid path: use a canonical relative path under home"
        );
    }

    #[test]
    fn files_refresh_requires_idle_controls_and_a_successful_listing() {
        assert!(!file_list_refresh_enabled(false, false));
        assert!(!file_list_refresh_enabled(true, false));
        assert!(!file_list_refresh_enabled(false, true));
        assert!(file_list_refresh_enabled(true, true));
    }

    #[test]
    fn files_current_path_distinguishes_unloaded_from_committed_paths() {
        assert_eq!(FILES_PATH_UNLOADED_LABEL, "Current path: not loaded");
        assert_eq!(file_list_path_label(""), "Current path: home");
        assert_eq!(file_list_path_label("docs"), "Current path: docs");
    }

    #[test]
    fn files_navigation_paths_remain_canonical_and_root_bounded() {
        assert_eq!(file_list_child_path("", "docs"), Some("docs".to_owned()));
        assert_eq!(
            file_list_child_path("docs", "reports"),
            Some("docs/reports".to_owned())
        );
        assert_eq!(
            file_list_parent_path("docs/reports"),
            Some("docs".to_owned())
        );
        assert_eq!(file_list_parent_path("docs"), Some(String::new()));
        assert_eq!(file_list_parent_path(""), None);

        for invalid_child in ["", ".", "..", "nested/name", r"nested\name"] {
            assert_eq!(file_list_child_path("docs", invalid_child), None);
        }
        assert_eq!(file_list_parent_path("../escape"), None);
        assert_eq!(file_list_parent_path("docs//reports"), None);
    }

    #[test]
    fn machines_subtitle_locks_existing_read_only_snapshot_boundary() {
        assert_eq!(
            MACHINES_SUBTITLE,
            concat!(
                "Current local owner-host status from the same bounded Agent snapshot as Overview. ",
                "This surface does not enumerate remote devices, infer identity from endpoint data, or grant capabilities."
            )
        );
    }

    #[test]
    fn activity_subtitle_matches_copy_projection_contract() {
        assert_eq!(
            ACTIVITY_SUBTITLE,
            concat!(
                "Latest local diagnostics snapshot. ",
                "Refresh uses the same bounded local status probe as Overview; ",
                "copy writes the rendered snapshot plus the session endpoint candidate to the local desktop clipboard."
            )
        );
    }

    #[test]
    fn activity_snapshot_clipboard_projection_is_local_text_only() {
        assert_eq!(COPY_SNAPSHOT_IDLE_LABEL, "Copy current snapshot");
        assert_eq!(COPY_SNAPSHOT_DONE_LABEL, "Copied");
        assert_eq!(
            activity_snapshot_clipboard_text(
                "Agent status\nAvailability: Online\nRuntime: Ready",
                "Private DNS\nEnabled: Yes",
                "Local IPC protocol 1.0\nCompatibility: Supported by this desktop client",
                "/run/user/1000/private-remote-workspace/agent.sock",
            ),
            "Agent status\nAvailability: Online\nRuntime: Ready\n\nPrivate DNS\nEnabled: Yes\n\nDetail\nLocal IPC protocol 1.0\nCompatibility: Supported by this desktop client\n\nSession endpoint candidate\n/run/user/1000/private-remote-workspace/agent.sock"
        );
    }

    #[test]
    fn settings_build_information_uses_workspace_package_version() {
        assert_eq!(desktop_version_text(), "Ownspace Desktop version 0.1.0");
    }

    #[test]
    fn settings_local_ipc_protocol_uses_authoritative_protocol_version() {
        assert_eq!(
            desktop_local_ipc_protocol_text(),
            "Supported local IPC protocol 1.0"
        );
    }

    #[test]
    fn settings_endpoint_uses_authoritative_agent_identifiers() {
        assert_eq!(
            local_endpoint_contract_text(),
            "$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock"
        );
    }

    #[test]
    fn placeholder_status_has_explicit_no_live_source_contract() {
        assert_eq!(PLACEHOLDER_STATUS, "No live state source available");
    }

    #[test]
    fn placeholder_descriptions_cover_only_session_and_transfer_routes() {
        for (destination, description) in [
            (
                NavigationDestination::Sessions,
                "Reserved for authorized terminal, Remote Desktop, and forwarding session presentation when runtime state is available.",
            ),
            (
                NavigationDestination::Transfers,
                "Reserved for verified upload/download progress and completion state.",
            ),
        ] {
            assert_eq!(placeholder_description(destination), description);
        }
    }
}
