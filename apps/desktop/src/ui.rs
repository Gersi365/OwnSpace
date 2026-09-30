use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use adw::prelude::*;
use gtk::glib;
use prw_agent::{AGENT_RUNTIME_SUBDIRECTORY, AGENT_SOCKET_FILENAME, LocalIpcProtocolVersion};
use prw_file_service::RemotePath;
use prw_file_transfer::{MAX_TRANSFER_BYTES, TransferId};
use prw_remote_bridge::MAX_BRIDGE_INLINE_BYTES;
use prw_terminal::TerminalProfile;
use sha2::{Digest, Sha256};

use crate::ipc;
use crate::local_management_ipc::{LocalFileListEntry, LocalRegisteredDeviceEntry};
use crate::management::{TerminalPresentation, TerminalPresentationState, UploadPresentation};
use crate::state::{DesktopPresentationState, NavigationDestination};

const REFRESH_BUTTON_IDLE_LABEL: &str = "Refresh status";
const REFRESH_BUTTON_BUSY_LABEL: &str = "Refreshing…";
const MACHINES_DEVICE_REFRESH_IDLE_LABEL: &str = "Refresh registered devices";
const MACHINES_DEVICE_REFRESH_BUSY_LABEL: &str = "Loading devices…";
const MACHINES_DEVICE_NOT_LOADED_STATUS: &str = "Registered devices: not loaded";
const MACHINES_REACHABILITY_NOT_OBSERVED: &str = "Not observed by this local surface";
const COPY_SNAPSHOT_IDLE_LABEL: &str = "Copy current snapshot";
const COPY_SNAPSHOT_DONE_LABEL: &str = "Copied";
const TERMINAL_OPEN_LABEL: &str = "Open POSIX shell session";
const TERMINAL_SEND_LABEL: &str = "Send line";
const TERMINAL_CLOSE_LABEL: &str = "Close session";
const TERMINAL_COLUMNS: u16 = 80;
const TERMINAL_ROWS: u16 = 24;
static NEXT_TERMINAL_SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
static NEXT_UPLOAD_TRANSFER_COUNTER: AtomicU64 = AtomicU64::new(1);
const UPLOAD_BUTTON_IDLE_LABEL: &str = "Upload file";
const UPLOAD_BUTTON_BUSY_LABEL: &str = "Uploading…";
const UPLOAD_SUBTITLE: &str = concat!(
    "Bounded one-way upload under the existing Agent owner-home transfer authority. ",
    "Choose an absolute local source path and a canonical relative destination. ",
    "Download, resume, and user-triggered abort are not enabled in this checkpoint."
);
const FILES_LIST_IDLE_LABEL: &str = "List files";
const FILES_LIST_BUSY_LABEL: &str = "Listing…";
const FILES_REFRESH_LABEL: &str = "Refresh";
const FILES_PATH_INVALID_STATUS: &str = "Invalid path: use a canonical relative path under home";
const FILES_PATH_UNLOADED_LABEL: &str = "Current path: not loaded";
const WORKER_RESULT_POLL_INTERVAL: Duration = Duration::from_millis(75);
const PAGE_OUTER_MARGIN: i32 = 32;
const DIM_LABEL_CSS_CLASS: &str = "dim-label";
const PAGE_TITLE_CSS_CLASS: &str = "title-1";
const TITLE_3_CSS_CLASS: &str = "title-3";
const HEADING_CSS_CLASS: &str = "heading";
const MONOSPACE_CSS_CLASS: &str = "monospace";
const FILES_SUBTITLE: &str = concat!(
    "Read-only directory listing under the local owner home authority. ",
    "Paths are relative; this surface does not read file contents, mutate files, transfer data, open terminals, or create forwarding."
);
const MACHINES_SUBTITLE: &str = concat!(
    "Read-only registered-device inventory from the owner-PC authority through the local Agent. ",
    "Reachability is shown only from authoritative live observation; this checkpoint does not infer Online/Offline from endpoint data and does not mutate device authority."
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
struct MachinesPageTargets {
    refresh_button: gtk::Button,
    status: gtk::Label,
    entries: gtk::Box,
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

#[derive(Clone)]
struct SessionsPageTargets {
    status: gtk::Label,
    input: gtk::Entry,
    open_button: gtk::Button,
    send_button: gtk::Button,
    close_button: gtk::Button,
    terminal: Rc<RefCell<TerminalPresentation>>,
    terminal_connection: Arc<Mutex<Option<ipc::TerminalManagementSession>>>,
    operation_pending: Rc<Cell<bool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalOperation {
    Open,
    Input,
    Close,
}

#[derive(Clone)]
struct TransfersPageTargets {
    source_entry: gtk::Entry,
    destination_entry: gtk::Entry,
    upload_button: gtk::Button,
    progress: gtk::ProgressBar,
    status: gtk::Label,
    operation_pending: Rc<Cell<bool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadCleanupStatus {
    NotRequired,
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadWorkerEvent {
    Progress {
        committed: u64,
        total: u64,
    },
    Completed,
    Failed {
        reason: &'static str,
        cleanup: UploadCleanupStatus,
    },
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

    let (
        machines,
        machines_agent_label,
        machines_dns_label,
        machines_detail_label,
        machines_refresh_button,
        machines_page_targets,
    ) = machines_page();

    let (
        activity,
        activity_agent_label,
        activity_dns_label,
        activity_detail_label,
        activity_refresh_button,
        activity_copy_button,
    ) = activity_page();
    let sessions = sessions_page();
    let transfers = transfers_page();
    let files = files_page();
    let (settings, settings_agent_protocol_label) = settings_page();

    for destination in NavigationDestination::ALL {
        let page = match destination {
            NavigationDestination::Overview => overview.clone(),
            NavigationDestination::Machines => machines.clone(),
            NavigationDestination::Sessions => sessions.clone(),
            NavigationDestination::Transfers => transfers.clone(),
            NavigationDestination::Files => files.clone(),
            NavigationDestination::Activity => activity.clone(),
            NavigationDestination::Settings => settings.clone(),
        };
        stack.add_titled(&page, Some(destination.stack_name()), destination.title());
    }
    stack.set_visible_child_name(NavigationDestination::Overview.stack_name());

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
    start_status_probe(probe_targets);
    start_registered_device_probe(&machines_page_targets);
}

fn overview_page() -> (gtk::Box, gtk::Label, gtk::Label, gtk::Label, gtk::Button) {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Overview.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(
        "Read-only local Agent status. Refresh performs only bounded local IPC reads.",
    ));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
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
    detail_label.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&detail_label);

    (page, agent_label, dns_label, detail_label, refresh_button)
}

fn machines_page() -> (
    gtk::Box,
    gtk::Label,
    gtk::Label,
    gtk::Label,
    gtk::Button,
    MachinesPageTargets,
) {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Machines.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(MACHINES_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&subtitle);

    let device_refresh_button = gtk::Button::with_label(MACHINES_DEVICE_REFRESH_IDLE_LABEL);
    device_refresh_button.set_halign(gtk::Align::Start);
    page.append(&device_refresh_button);

    let devices_title = gtk::Label::new(Some("Registered devices"));
    devices_title.set_xalign(0.0);
    devices_title.add_css_class(HEADING_CSS_CLASS);
    page.append(&devices_title);

    let device_status = gtk::Label::new(Some(MACHINES_DEVICE_NOT_LOADED_STATUS));
    device_status.set_xalign(0.0);
    device_status.set_wrap(true);
    device_status.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&device_status);

    let device_entries = gtk::Box::new(gtk::Orientation::Vertical, 8);
    page.append(&device_entries);

    let local_status_title = gtk::Label::new(Some("Local owner-host status"));
    local_status_title.set_xalign(0.0);
    local_status_title.add_css_class(HEADING_CSS_CLASS);
    page.append(&local_status_title);

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
    detail_label.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&detail_label);

    let targets = MachinesPageTargets {
        refresh_button: device_refresh_button,
        status: device_status,
        entries: device_entries,
    };
    let click_targets = targets.clone();
    targets
        .refresh_button
        .connect_clicked(move |_| start_registered_device_probe(&click_targets));

    (
        page,
        agent_label,
        dns_label,
        detail_label,
        refresh_button,
        targets,
    )
}

fn clear_registered_device_entries(entries: &gtk::Box) {
    while let Some(child) = entries.first_child() {
        entries.remove(&child);
    }
}

fn append_registered_device_entry(entries: &gtk::Box, device: &LocalRegisteredDeviceEntry) {
    let label = gtk::Label::new(Some(&format!(
        "Device: {}\nLifecycle: {}\nReachability: {}",
        device.device_id(),
        device.lifecycle_text(),
        MACHINES_REACHABILITY_NOT_OBSERVED
    )));
    label.set_xalign(0.0);
    label.set_selectable(true);
    label.set_wrap(true);
    entries.append(&label);
}

fn start_registered_device_probe(targets: &MachinesPageTargets) {
    targets.refresh_button.set_sensitive(false);
    targets
        .refresh_button
        .set_label(MACHINES_DEVICE_REFRESH_BUSY_LABEL);
    targets.status.set_text("Loading registered devices…");

    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn_result = std::thread::Builder::new()
        .name("prw-desktop-registered-device-read".to_owned())
        .spawn(move || {
            let _ = sender.send(ipc::query_registered_devices());
        });

    if spawn_result.is_err() {
        targets
            .status
            .set_text("Unable to start registered-device read worker");
        targets.refresh_button.set_sensitive(true);
        targets
            .refresh_button
            .set_label(MACHINES_DEVICE_REFRESH_IDLE_LABEL);
        return;
    }

    let targets = targets.clone();
    let _source_id = glib::timeout_add_local(WORKER_RESULT_POLL_INTERVAL, move || {
        match receiver.try_recv() {
            Ok(Ok(devices)) => {
                clear_registered_device_entries(&targets.entries);
                for device in &devices {
                    append_registered_device_entry(&targets.entries, device);
                }
                targets.status.set_text(&format!(
                    "Registered devices: {}. Reachability is not inferred from routing data.",
                    devices.len()
                ));
                targets.refresh_button.set_sensitive(true);
                targets
                    .refresh_button
                    .set_label(MACHINES_DEVICE_REFRESH_IDLE_LABEL);
                glib::ControlFlow::Break
            }
            Ok(Err(error)) => {
                clear_registered_device_entries(&targets.entries);
                targets
                    .status
                    .set_text(&format!("Registered-device read unavailable: {error}"));
                targets.refresh_button.set_sensitive(true);
                targets
                    .refresh_button
                    .set_label(MACHINES_DEVICE_REFRESH_IDLE_LABEL);
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                clear_registered_device_entries(&targets.entries);
                targets
                    .status
                    .set_text("Registered-device read worker ended without a result");
                targets.refresh_button.set_sensitive(true);
                targets
                    .refresh_button
                    .set_label(MACHINES_DEVICE_REFRESH_IDLE_LABEL);
                glib::ControlFlow::Break
            }
        }
    });
}

fn next_terminal_session_id() -> u64 {
    let process = u64::from(std::process::id());
    let counter = NEXT_TERMINAL_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    (process << 32) | counter
}

const fn terminal_controls_for_state(
    state: TerminalPresentationState,
    operation_pending: bool,
) -> (bool, bool, bool, bool) {
    if operation_pending {
        return (false, false, false, false);
    }

    match state {
        TerminalPresentationState::Closed => (true, false, false, false),
        TerminalPresentationState::Open => (false, true, true, true),
        TerminalPresentationState::Opening
        | TerminalPresentationState::Closing
        | TerminalPresentationState::Failed => (false, false, false, false),
    }
}

fn render_terminal_controls(targets: &SessionsPageTargets) {
    let state = targets.terminal.borrow().state();
    let (open, input, send, close) =
        terminal_controls_for_state(state, targets.operation_pending.get());
    targets.open_button.set_sensitive(open);
    targets.input.set_sensitive(input);
    targets.send_button.set_sensitive(send);
    targets.close_button.set_sensitive(close);
}

const fn terminal_operation_status(operation: TerminalOperation) -> &'static str {
    match operation {
        TerminalOperation::Open => "Opening authorized terminal session…",
        TerminalOperation::Input => "Sending bounded terminal input…",
        TerminalOperation::Close => "Closing terminal session…",
    }
}

fn execute_terminal_operation(
    connection: &Arc<Mutex<Option<ipc::TerminalManagementSession>>>,
    operation: TerminalOperation,
    payload: &[u8],
) -> Result<(), ipc::DesktopIpcError> {
    let mut connection = connection
        .lock()
        .map_err(|_| ipc::DesktopIpcError::TerminalSessionUnavailable)?;
    match operation {
        TerminalOperation::Open => {
            if connection.is_some() {
                return Err(ipc::DesktopIpcError::TerminalSessionUnavailable);
            }
            let mut session = ipc::TerminalManagementSession::connect()?;
            session.open(payload)?;
            *connection = Some(session);
            Ok(())
        }
        TerminalOperation::Input => connection
            .as_mut()
            .ok_or(ipc::DesktopIpcError::TerminalSessionUnavailable)?
            .input(payload),
        TerminalOperation::Close => {
            let result = connection
                .as_mut()
                .ok_or(ipc::DesktopIpcError::TerminalSessionUnavailable)?
                .close(payload);
            *connection = None;
            result
        }
    }
}

fn start_terminal_operation(
    targets: &SessionsPageTargets,
    operation: TerminalOperation,
    payload: Vec<u8>,
) {
    targets.operation_pending.set(true);
    targets
        .status
        .set_text(terminal_operation_status(operation));
    render_terminal_controls(targets);

    let connection = Arc::clone(&targets.terminal_connection);
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn_result = std::thread::Builder::new()
        .name("prw-desktop-terminal-management".to_owned())
        .spawn(move || {
            let result = execute_terminal_operation(&connection, operation, &payload);
            if result.is_err()
                && let Ok(mut connection) = connection.lock()
            {
                *connection = None;
            }
            let _ = sender.send(result);
        });

    if spawn_result.is_err() {
        targets.operation_pending.set(false);
        targets.terminal.borrow_mut().apply_failure();
        targets
            .status
            .set_text("Unable to start terminal management worker");
        render_terminal_controls(targets);
        return;
    }

    let poll_targets = targets.clone();
    let _source_id = glib::timeout_add_local(WORKER_RESULT_POLL_INTERVAL, move || {
        match receiver.try_recv() {
            Ok(Ok(())) => {
                let acknowledgement = match operation {
                    TerminalOperation::Open => poll_targets
                        .terminal
                        .borrow_mut()
                        .apply_open_acknowledgement(),
                    TerminalOperation::Input => Ok(()),
                    TerminalOperation::Close => poll_targets
                        .terminal
                        .borrow_mut()
                        .apply_close_acknowledgement(),
                };

                poll_targets.operation_pending.set(false);
                if acknowledgement.is_err() {
                    if let Ok(mut connection) = poll_targets.terminal_connection.lock() {
                        *connection = None;
                    }
                    poll_targets.terminal.borrow_mut().apply_failure();
                    poll_targets
                        .status
                        .set_text("Terminal acknowledgement did not match local session state");
                } else {
                    match operation {
                        TerminalOperation::Open => poll_targets.status.set_text(
                            "Session open. Input is authorized by the Agent; output presentation is not enabled in this checkpoint.",
                        ),
                        TerminalOperation::Input => {
                            poll_targets.input.set_text("");
                            poll_targets.status.set_text("Terminal input acknowledged");
                        }
                        TerminalOperation::Close => {
                            poll_targets.status.set_text("Terminal session closed");
                        }
                    }
                }
                render_terminal_controls(&poll_targets);
                glib::ControlFlow::Break
            }
            Ok(Err(error)) => {
                poll_targets.operation_pending.set(false);
                if let Ok(mut connection) = poll_targets.terminal_connection.lock() {
                    *connection = None;
                }
                poll_targets.terminal.borrow_mut().apply_failure();
                poll_targets
                    .status
                    .set_text(&format!("Unavailable: {error}"));
                render_terminal_controls(&poll_targets);
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                poll_targets.operation_pending.set(false);
                if let Ok(mut connection) = poll_targets.terminal_connection.lock() {
                    *connection = None;
                }
                poll_targets.terminal.borrow_mut().apply_failure();
                poll_targets
                    .status
                    .set_text("Terminal management worker ended without a result");
                render_terminal_controls(&poll_targets);
                glib::ControlFlow::Break
            }
        }
    });
}

fn request_terminal_open(targets: &SessionsPageTargets) {
    let payload = targets.terminal.borrow_mut().request_open(
        TerminalProfile::PosixShell,
        TERMINAL_COLUMNS,
        TERMINAL_ROWS,
    );
    match payload {
        Ok(payload) => start_terminal_operation(targets, TerminalOperation::Open, payload),
        Err(_) => targets
            .status
            .set_text("Terminal session cannot be opened from the current local state"),
    }
}

fn request_terminal_input(targets: &SessionsPageTargets) {
    let mut bytes = targets.input.text().as_bytes().to_vec();
    bytes.push(b'\n');
    let payload = targets.terminal.borrow().request_input(&bytes);
    match payload {
        Ok(payload) => start_terminal_operation(targets, TerminalOperation::Input, payload),
        Err(_) => targets
            .status
            .set_text("Terminal input is unavailable from the current local state"),
    }
}

fn request_terminal_close(targets: &SessionsPageTargets) {
    let payload = targets.terminal.borrow_mut().request_close();
    match payload {
        Ok(payload) => start_terminal_operation(targets, TerminalOperation::Close, payload),
        Err(_) => targets
            .status
            .set_text("Terminal session cannot be closed from the current local state"),
    }
}

fn sessions_page() -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Sessions.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(
        "Authorized local terminal-session control through the existing trusted Agent socket and Agent-owned terminal capability checks. This checkpoint opens a POSIX shell, sends bounded input lines, and closes the session; terminal output presentation is not enabled yet.",
    ));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&subtitle);

    let session_id = next_terminal_session_id();
    let session_label = gtk::Label::new(Some(&format!("Local terminal session: {session_id}")));
    session_label.set_xalign(0.0);
    session_label.add_css_class(TITLE_3_CSS_CLASS);
    page.append(&session_label);

    let status = gtk::Label::new(Some("Session closed"));
    status.set_xalign(0.0);
    status.set_wrap(true);
    page.append(&status);

    let input = gtk::Entry::new();
    input.set_placeholder_text(Some("Terminal input line"));
    page.append(&input);

    let controls = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let open_button = gtk::Button::with_label(TERMINAL_OPEN_LABEL);
    let send_button = gtk::Button::with_label(TERMINAL_SEND_LABEL);
    let close_button = gtk::Button::with_label(TERMINAL_CLOSE_LABEL);
    controls.append(&open_button);
    controls.append(&send_button);
    controls.append(&close_button);
    page.append(&controls);

    let targets = SessionsPageTargets {
        status,
        input,
        open_button,
        send_button,
        close_button,
        terminal: Rc::new(RefCell::new(TerminalPresentation::new(session_id))),
        terminal_connection: Arc::new(Mutex::new(None)),
        operation_pending: Rc::new(Cell::new(false)),
    };
    render_terminal_controls(&targets);

    let open_targets = targets.clone();
    targets
        .open_button
        .connect_clicked(move |_| request_terminal_open(&open_targets));

    let send_targets = targets.clone();
    targets
        .send_button
        .connect_clicked(move |_| request_terminal_input(&send_targets));

    let activate_targets = targets.clone();
    targets
        .input
        .connect_activate(move |_| request_terminal_input(&activate_targets));

    let close_targets = targets.clone();
    targets
        .close_button
        .connect_clicked(move |_| request_terminal_close(&close_targets));

    page
}

fn upload_source_path_is_valid(source: &str) -> bool {
    !source.is_empty() && Path::new(source).is_absolute()
}

fn upload_destination_is_valid(destination: &str) -> bool {
    RemotePath::parse(destination).is_ok_and(|path| !path.is_root())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "bounded byte counters are projected only into a GTK presentation fraction"
)]
fn upload_progress_fraction(committed: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        committed.min(total) as f64 / total as f64
    }
}

fn upload_failure_status(reason: &str, cleanup: UploadCleanupStatus) -> String {
    match cleanup {
        UploadCleanupStatus::NotRequired => reason.to_owned(),
        UploadCleanupStatus::Confirmed => {
            format!("{reason}. Staged upload cleanup confirmed.")
        }
        UploadCleanupStatus::Unconfirmed => {
            format!("{reason}. Staged upload cleanup could not be confirmed.")
        }
    }
}

fn hash_upload_source(path: &Path) -> Result<([u8; 32], u64), &'static str> {
    let mut file = File::open(path).map_err(|_| "Local source file is unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Local source metadata is unavailable")?;
    if !metadata.is_file() {
        return Err("Local source path is not a regular file");
    }
    if metadata.len() > MAX_TRANSFER_BYTES {
        return Err("Local source file exceeds the bounded upload size");
    }

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; MAX_BRIDGE_INLINE_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "Local source file could not be read")?;
        if read == 0 {
            break;
        }
        let read = u64::try_from(read).map_err(|_| "Local source length is invalid")?;
        total = total
            .checked_add(read)
            .ok_or("Local source length is invalid")?;
        if total > MAX_TRANSFER_BYTES {
            return Err("Local source file exceeds the bounded upload size");
        }
        hasher.update(
            &buffer[..usize::try_from(read).map_err(|_| "Local source length is invalid")?],
        );
    }

    let digest = hasher.finalize();
    let mut sha256 = [0_u8; 32];
    sha256.copy_from_slice(&digest);
    Ok((sha256, total))
}

fn next_upload_transfer_id(
    source: &str,
    destination: &str,
    total_bytes: u64,
    sha256: &[u8; 32],
) -> String {
    let counter = NEXT_UPLOAD_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = Sha256::new();
    hasher.update(b"Ownspace Desktop bounded upload transfer id v1");
    hasher.update(counter.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update(sha256);
    hasher.update(source.as_bytes());
    hasher.update(destination.as_bytes());

    let digest = hasher.finalize();
    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(&digest[..16]);
    TransferId::new(identifier).to_hex()
}

#[allow(clippy::manual_let_else)]
fn cleanup_failed_upload(
    upload: &mut UploadPresentation,
    session: &mut ipc::BoundedUploadSession,
) -> UploadCleanupStatus {
    let payload = match upload.request_abort() {
        Ok(payload) => payload,
        Err(_) => return UploadCleanupStatus::Unconfirmed,
    };
    if session.abort(&payload).is_ok() {
        UploadCleanupStatus::Confirmed
    } else {
        UploadCleanupStatus::Unconfirmed
    }
}

fn send_upload_failure(
    sender: &mpsc::Sender<UploadWorkerEvent>,
    reason: &'static str,
    cleanup: UploadCleanupStatus,
) {
    let _ = sender.send(UploadWorkerEvent::Failed { reason, cleanup });
}

#[allow(
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::too_many_lines
)]
fn run_upload_worker(source: String, destination: String, sender: mpsc::Sender<UploadWorkerEvent>) {
    let source_path = PathBuf::from(&source);
    let (sha256, total_bytes) = match hash_upload_source(&source_path) {
        Ok(result) => result,
        Err(reason) => {
            send_upload_failure(&sender, reason, UploadCleanupStatus::NotRequired);
            return;
        }
    };

    let transfer_id = next_upload_transfer_id(&source, &destination, total_bytes, &sha256);
    let mut upload = UploadPresentation::new(transfer_id, destination, total_bytes, sha256);
    let mut session = match ipc::BoundedUploadSession::connect() {
        Ok(session) => session,
        Err(_) => {
            send_upload_failure(
                &sender,
                "Unable to open the trusted local Agent upload session",
                UploadCleanupStatus::NotRequired,
            );
            return;
        }
    };
    let begin_payload = match upload.request_begin() {
        Ok(payload) => payload,
        Err(_) => {
            send_upload_failure(
                &sender,
                "Upload plan failed local validation",
                UploadCleanupStatus::NotRequired,
            );
            return;
        }
    };

    let begin_offset = match session.begin(&begin_payload) {
        Ok(offset) => offset,
        Err(_) => {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(
                &sender,
                "Agent rejected or lost the upload begin acknowledgement",
                cleanup,
            );
            return;
        }
    };
    if upload.apply_begin_acknowledgement(begin_offset).is_err() {
        let cleanup = cleanup_failed_upload(&mut upload, &mut session);
        send_upload_failure(
            &sender,
            "Upload begin acknowledgement was not the exact zero offset",
            cleanup,
        );
        return;
    }
    if sender
        .send(UploadWorkerEvent::Progress {
            committed: 0,
            total: total_bytes,
        })
        .is_err()
    {
        let _ = cleanup_failed_upload(&mut upload, &mut session);
        return;
    }

    let mut file = match File::open(&source_path) {
        Ok(file) => file,
        Err(_) => {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(&sender, "Local source file became unavailable", cleanup);
            return;
        }
    };
    let mut buffer = vec![0_u8; MAX_BRIDGE_INLINE_BYTES];

    while upload.committed_bytes() < total_bytes {
        let remaining = total_bytes - upload.committed_bytes();
        let requested = usize::try_from(remaining)
            .unwrap_or(MAX_BRIDGE_INLINE_BYTES)
            .min(MAX_BRIDGE_INLINE_BYTES);
        let read = match file.read(&mut buffer[..requested]) {
            Ok(0) => {
                let cleanup = cleanup_failed_upload(&mut upload, &mut session);
                send_upload_failure(
                    &sender,
                    "Local source file ended before its hashed length",
                    cleanup,
                );
                return;
            }
            Ok(read) => read,
            Err(_) => {
                let cleanup = cleanup_failed_upload(&mut upload, &mut session);
                send_upload_failure(
                    &sender,
                    "Local source file could not be read during upload",
                    cleanup,
                );
                return;
            }
        };

        let payload = match upload.request_chunk(&buffer[..read]) {
            Ok(payload) => payload,
            Err(_) => {
                let cleanup = cleanup_failed_upload(&mut upload, &mut session);
                send_upload_failure(
                    &sender,
                    "Upload chunk failed local bounds validation",
                    cleanup,
                );
                return;
            }
        };
        let committed = match session.chunk(&payload) {
            Ok(offset) => offset,
            Err(_) => {
                let cleanup = cleanup_failed_upload(&mut upload, &mut session);
                send_upload_failure(
                    &sender,
                    "Agent rejected or lost an upload chunk acknowledgement",
                    cleanup,
                );
                return;
            }
        };
        if upload.apply_chunk_acknowledgement(committed).is_err() {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(
                &sender,
                "Upload chunk acknowledgement offset did not match",
                cleanup,
            );
            return;
        }
        if sender
            .send(UploadWorkerEvent::Progress {
                committed,
                total: total_bytes,
            })
            .is_err()
        {
            let _ = cleanup_failed_upload(&mut upload, &mut session);
            return;
        }
    }

    let mut trailing = [0_u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(
                &sender,
                "Local source file changed length during upload",
                cleanup,
            );
            return;
        }
        Err(_) => {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(
                &sender,
                "Local source file could not be revalidated",
                cleanup,
            );
            return;
        }
    }

    let finalize_payload = match upload.request_finalize() {
        Ok(payload) => payload,
        Err(_) => {
            let cleanup = cleanup_failed_upload(&mut upload, &mut session);
            send_upload_failure(
                &sender,
                "Upload could not enter finalization state",
                cleanup,
            );
            return;
        }
    };
    if session.finalize(&finalize_payload).is_err() {
        let cleanup = cleanup_failed_upload(&mut upload, &mut session);
        send_upload_failure(
            &sender,
            "Agent did not confirm upload finalization",
            cleanup,
        );
        return;
    }
    if upload.apply_finalize_acknowledgement().is_err() {
        send_upload_failure(
            &sender,
            "Upload finalization succeeded but local acknowledgement state was invalid",
            UploadCleanupStatus::NotRequired,
        );
        return;
    }
    let _ = sender.send(UploadWorkerEvent::Completed);
}

fn render_upload_controls(targets: &TransfersPageTargets) {
    let enabled = !targets.operation_pending.get();
    targets.source_entry.set_sensitive(enabled);
    targets.destination_entry.set_sensitive(enabled);
    targets.upload_button.set_sensitive(enabled);
    targets.upload_button.set_label(if enabled {
        UPLOAD_BUTTON_IDLE_LABEL
    } else {
        UPLOAD_BUTTON_BUSY_LABEL
    });
}

fn start_upload(targets: &TransfersPageTargets) {
    if targets.operation_pending.get() {
        return;
    }

    let source = targets.source_entry.text().to_string();
    let destination = targets.destination_entry.text().to_string();
    if !upload_source_path_is_valid(&source) {
        targets
            .status
            .set_text("Invalid source: enter an absolute local file path");
        return;
    }
    if !upload_destination_is_valid(&destination) {
        targets.status.set_text(
            "Invalid destination: use a non-root canonical relative path under owner home",
        );
        return;
    }

    targets.operation_pending.set(true);
    targets.progress.set_fraction(0.0);
    targets.progress.set_text(Some("Preparing upload…"));
    targets
        .status
        .set_text("Hashing local source and preparing bounded upload…");
    render_upload_controls(targets);

    let (sender, receiver) = mpsc::channel();
    let spawn_result = std::thread::Builder::new()
        .name("prw-desktop-bounded-upload".to_owned())
        .spawn(move || run_upload_worker(source, destination, sender));
    if spawn_result.is_err() {
        targets.operation_pending.set(false);
        targets
            .status
            .set_text("Unable to start bounded upload worker");
        targets.progress.set_text(Some("Upload not started"));
        render_upload_controls(targets);
        return;
    }

    let poll_targets = targets.clone();
    let _source_id = glib::timeout_add_local(WORKER_RESULT_POLL_INTERVAL, move || {
        match receiver.try_recv() {
            Ok(UploadWorkerEvent::Progress { committed, total }) => {
                poll_targets
                    .progress
                    .set_fraction(upload_progress_fraction(committed, total));
                poll_targets
                    .progress
                    .set_text(Some(&format!("{committed} / {total} bytes")));
                poll_targets
                    .status
                    .set_text("Upload acknowledged by the Agent and progressing");
                glib::ControlFlow::Continue
            }
            Ok(UploadWorkerEvent::Completed) => {
                poll_targets.operation_pending.set(false);
                poll_targets.progress.set_fraction(1.0);
                poll_targets.progress.set_text(Some("Upload complete"));
                poll_targets
                    .status
                    .set_text("Upload completed and finalized by the Agent");
                render_upload_controls(&poll_targets);
                glib::ControlFlow::Break
            }
            Ok(UploadWorkerEvent::Failed { reason, cleanup }) => {
                poll_targets.operation_pending.set(false);
                poll_targets
                    .status
                    .set_text(&upload_failure_status(reason, cleanup));
                poll_targets.progress.set_text(Some("Upload failed"));
                render_upload_controls(&poll_targets);
                glib::ControlFlow::Break
            }
            Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                poll_targets.operation_pending.set(false);
                poll_targets
                    .status
                    .set_text("Upload worker ended without a terminal result");
                poll_targets.progress.set_text(Some("Upload failed"));
                render_upload_controls(&poll_targets);
                glib::ControlFlow::Break
            }
        }
    });
}

fn transfers_page() -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Transfers.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(UPLOAD_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&subtitle);

    let source_label = gtk::Label::new(Some("Local source file"));
    source_label.set_xalign(0.0);
    source_label.add_css_class(HEADING_CSS_CLASS);
    page.append(&source_label);

    let source_entry = gtk::Entry::new();
    source_entry.set_placeholder_text(Some("/absolute/path/to/file"));
    page.append(&source_entry);

    let destination_label = gtk::Label::new(Some("Owner-home destination"));
    destination_label.set_xalign(0.0);
    destination_label.add_css_class(HEADING_CSS_CLASS);
    page.append(&destination_label);

    let destination_entry = gtk::Entry::new();
    destination_entry.set_placeholder_text(Some("uploads/example.bin"));
    page.append(&destination_entry);

    let progress = gtk::ProgressBar::new();
    progress.set_show_text(true);
    progress.set_text(Some("No upload requested"));
    page.append(&progress);

    let status = gtk::Label::new(Some("No upload requested yet"));
    status.set_xalign(0.0);
    status.set_wrap(true);
    status.add_css_class(TITLE_3_CSS_CLASS);
    page.append(&status);

    let upload_button = gtk::Button::with_label(UPLOAD_BUTTON_IDLE_LABEL);
    page.append(&upload_button);

    let targets = TransfersPageTargets {
        source_entry,
        destination_entry,
        upload_button,
        progress,
        status,
        operation_pending: Rc::new(Cell::new(false)),
    };
    render_upload_controls(&targets);

    let click_targets = targets.clone();
    targets
        .upload_button
        .connect_clicked(move |_| start_upload(&click_targets));

    let activate_targets = targets.clone();
    targets
        .destination_entry
        .connect_activate(move |_| start_upload(&activate_targets));

    page
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
    let _source_id = glib::timeout_add_local(WORKER_RESULT_POLL_INTERVAL, move || {
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
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Files.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(FILES_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&subtitle);

    let current_path_label = gtk::Label::new(Some(FILES_PATH_UNLOADED_LABEL));
    current_path_label.set_xalign(0.0);
    current_path_label.add_css_class(TITLE_3_CSS_CLASS);
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
    status.add_css_class(TITLE_3_CSS_CLASS);
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
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Activity.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let subtitle = gtk::Label::new(Some(ACTIVITY_SUBTITLE));
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    subtitle.add_css_class(DIM_LABEL_CSS_CLASS);
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
    detail_label.add_css_class(DIM_LABEL_CSS_CLASS);
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
    label.add_css_class(TITLE_3_CSS_CLASS);
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
    page.set_margin_top(PAGE_OUTER_MARGIN);
    page.set_margin_bottom(PAGE_OUTER_MARGIN);
    page.set_margin_start(PAGE_OUTER_MARGIN);
    page.set_margin_end(PAGE_OUTER_MARGIN);

    let title = gtk::Label::new(Some(NavigationDestination::Settings.title()));
    title.set_xalign(0.0);
    title.add_css_class(PAGE_TITLE_CSS_CLASS);
    page.append(&title);

    let status = gtk::Label::new(Some("Read-only local diagnostics"));
    status.set_xalign(0.0);
    status.add_css_class(TITLE_3_CSS_CLASS);
    page.append(&status);

    let detail = gtk::Label::new(Some(
        "This surface exposes local Ownspace diagnostics only. It does not change Agent configuration or activate capabilities.",
    ));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&detail);

    let build_title = gtk::Label::new(Some("Build information"));
    build_title.set_xalign(0.0);
    build_title.add_css_class(HEADING_CSS_CLASS);
    page.append(&build_title);

    let version = gtk::Label::new(Some(&desktop_version_text()));
    version.set_xalign(0.0);
    version.set_selectable(true);
    version.add_css_class(MONOSPACE_CSS_CLASS);
    page.append(&version);

    let protocol_title = gtk::Label::new(Some("Local IPC compatibility"));
    protocol_title.set_xalign(0.0);
    protocol_title.add_css_class(HEADING_CSS_CLASS);
    page.append(&protocol_title);

    let protocol = gtk::Label::new(Some(&desktop_local_ipc_protocol_text()));
    protocol.set_xalign(0.0);
    protocol.set_selectable(true);
    protocol.add_css_class(MONOSPACE_CSS_CLASS);
    page.append(&protocol);

    let protocol_detail = gtk::Label::new(Some(
        "This is the protocol version compiled into the desktop client. It does not probe the Agent or assert endpoint trust, availability, or connectivity.",
    ));
    protocol_detail.set_xalign(0.0);
    protocol_detail.set_wrap(true);
    protocol_detail.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&protocol_detail);

    let agent_protocol = append_agent_reported_protocol_section(&page);

    let endpoint_title = gtk::Label::new(Some("Local control endpoint"));
    endpoint_title.set_xalign(0.0);
    endpoint_title.add_css_class(HEADING_CSS_CLASS);
    page.append(&endpoint_title);

    let endpoint = gtk::Label::new(Some(&local_endpoint_contract_text()));
    endpoint.set_xalign(0.0);
    endpoint.set_selectable(true);
    endpoint.set_wrap(true);
    endpoint.add_css_class(MONOSPACE_CSS_CLASS);
    page.append(&endpoint);

    let resolved_title = gtk::Label::new(Some("Resolved endpoint for this session"));
    resolved_title.set_xalign(0.0);
    resolved_title.add_css_class(HEADING_CSS_CLASS);
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
    resolved.add_css_class(MONOSPACE_CSS_CLASS);
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
    resolved_detail.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&resolved_detail);

    (page, agent_protocol)
}

fn append_agent_reported_protocol_section(page: &gtk::Box) -> gtk::Label {
    let title = gtk::Label::new(Some("Latest Agent-reported protocol"));
    title.set_xalign(0.0);
    title.add_css_class(HEADING_CSS_CLASS);
    page.append(&title);

    let protocol = gtk::Label::new(Some(
        &DesktopPresentationState::connecting().agent_reported_protocol_text(),
    ));
    protocol.set_xalign(0.0);
    protocol.set_selectable(true);
    protocol.add_css_class(MONOSPACE_CSS_CLASS);
    page.append(&protocol);

    let detail = gtk::Label::new(Some(
        "This value and compatibility classification come only from the existing bounded GetAgentStatus snapshot and the authoritative LocalIpcProtocolVersion support rule. They add no Agent probe and do not assert endpoint trust or capability authorization.",
    ));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class(DIM_LABEL_CSS_CLASS);
    page.append(&detail);

    protocol
}

fn connect_refresh_controls(targets: &StatusProbeTargets) {
    let overview_targets = targets.clone();
    targets
        .overview_refresh_button
        .connect_clicked(move |_| start_status_probe(overview_targets.clone()));

    let machines_targets = targets.clone();
    targets
        .machines_refresh_button
        .connect_clicked(move |_| start_status_probe(machines_targets.clone()));

    let activity_targets = targets.clone();
    targets
        .activity_refresh_button
        .connect_clicked(move |_| start_status_probe(activity_targets.clone()));
}

fn start_status_probe(targets: StatusProbeTargets) {
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
            let _ = sender.send(ipc::query_status_probe());
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

    let _source_id = glib::timeout_add_local(WORKER_RESULT_POLL_INTERVAL, move || {
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
        REFRESH_BUTTON_BUSY_LABEL, REFRESH_BUTTON_IDLE_LABEL, UPLOAD_BUTTON_BUSY_LABEL,
        UPLOAD_BUTTON_IDLE_LABEL, UPLOAD_SUBTITLE, UploadCleanupStatus,
        activity_snapshot_clipboard_text, desktop_local_ipc_protocol_text, desktop_version_text,
        file_list_child_path, file_list_manual_path_is_canonical, file_list_parent_path,
        file_list_path_label, file_list_refresh_enabled, local_endpoint_contract_text,
        upload_destination_is_valid, upload_failure_status, upload_progress_fraction,
        upload_source_path_is_valid,
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
    fn machines_subtitle_locks_registered_device_read_boundary() {
        assert_eq!(
            MACHINES_SUBTITLE,
            concat!(
                "Read-only registered-device inventory from the owner-PC authority through the local Agent. ",
                "Reachability is shown only from authoritative live observation; this checkpoint does not infer Online/Offline from endpoint data and does not mutate device authority."
            )
        );
        assert_eq!(
            super::MACHINES_REACHABILITY_NOT_OBSERVED,
            "Not observed by this local surface"
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
    fn transfers_surface_locks_bounded_upload_only_contract() {
        assert_eq!(UPLOAD_BUTTON_IDLE_LABEL, "Upload file");
        assert_eq!(UPLOAD_BUTTON_BUSY_LABEL, "Uploading…");
        assert_eq!(
            UPLOAD_SUBTITLE,
            concat!(
                "Bounded one-way upload under the existing Agent owner-home transfer authority. ",
                "Choose an absolute local source path and a canonical relative destination. ",
                "Download, resume, and user-triggered abort are not enabled in this checkpoint."
            )
        );
    }

    #[test]
    fn transfer_paths_fail_closed_before_worker_start() {
        assert!(upload_source_path_is_valid("/home/owner/demo.bin"));
        assert!(!upload_source_path_is_valid(""));
        assert!(!upload_source_path_is_valid("relative/demo.bin"));

        assert!(upload_destination_is_valid("uploads/demo.bin"));
        for invalid in [
            "",
            "/absolute.bin",
            "../escape",
            "uploads/../escape",
            "uploads//demo.bin",
        ] {
            assert!(!upload_destination_is_valid(invalid), "{invalid}");
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn transfer_progress_and_cleanup_status_are_explicit() {
        assert_eq!(upload_progress_fraction(0, 10), 0.0);
        assert_eq!(upload_progress_fraction(5, 10), 0.5);
        assert_eq!(upload_progress_fraction(10, 10), 1.0);
        assert_eq!(upload_progress_fraction(12, 10), 1.0);
        assert_eq!(upload_progress_fraction(0, 0), 0.0);
        assert_eq!(
            upload_failure_status("Upload failed", UploadCleanupStatus::NotRequired),
            "Upload failed"
        );
        assert_eq!(
            upload_failure_status("Upload failed", UploadCleanupStatus::Confirmed),
            "Upload failed. Staged upload cleanup confirmed."
        );
        assert_eq!(
            upload_failure_status("Upload failed", UploadCleanupStatus::Unconfirmed),
            "Upload failed. Staged upload cleanup could not be confirmed."
        );
    }

    #[test]
    fn terminal_controls_fail_closed_outside_open_state() {
        use super::TerminalPresentationState::{Closed, Closing, Failed, Open, Opening};

        assert_eq!(
            super::terminal_controls_for_state(Closed, false),
            (true, false, false, false)
        );
        assert_eq!(
            super::terminal_controls_for_state(Open, false),
            (false, true, true, true)
        );
        for state in [Opening, Closing, Failed] {
            assert_eq!(
                super::terminal_controls_for_state(state, false),
                (false, false, false, false)
            );
        }
        assert_eq!(
            super::terminal_controls_for_state(Open, true),
            (false, false, false, false)
        );
    }

    #[test]
    fn generated_terminal_session_ids_are_nonzero_and_distinct() {
        let first = super::next_terminal_session_id();
        let second = super::next_terminal_session_id();
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
    }
}
