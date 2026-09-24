mod ipc;
mod local_management_ipc;
#[allow(
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    reason = "Phase 152 Slice A keeps explicit crate-scoped management boundaries and ordinary presentation transitions until desktop authority wiring"
)]
pub(crate) mod management;
mod state;
mod ui;

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    let application = adw::Application::builder()
        .application_id("io.patchmirror.prw.desktop")
        .build();

    application.connect_activate(ui::build);
    application.run()
}
