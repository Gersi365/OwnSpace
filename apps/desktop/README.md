# PRW Desktop Application

Status: Phase 151 desktop client foundation candidate

The desktop application is a separate native Rust/GTK 4/libadwaita UI/client process.

It is not required for the Ubuntu host to remain remotely reachable. The headless PRW Agent remains authoritative for host runtime state, policy enforcement, remote capability execution, private-key boundaries, and production lifecycle ownership.

## Phase 151 scope

The initial desktop shell provides:

- native libadwaita application/window;
- Overview, Machines, Sessions, Files, Transfers, Activity, and Settings navigation;
- read-only local Agent availability/runtime presentation;
- read-only private-DNS summary presentation;
- explicit offline/error handling;
- a bounded worker thread so local Unix-socket reads do not block the GTK main thread.

Only the existing local `GetAgentStatus` and `GetPrivateDnsConfig` commands are used in this phase.

The local control endpoint remains:

`$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock`

The desktop client performs no TCP, D-Bus, abstract-socket, `/tmp`, shell-command, or alternate-path fallback.

## Deliberately not implemented in Phase 151

The remaining navigation destinations are structural placeholders only. They do not claim capability availability.

Phase 151 does not implement or activate:

- terminal actions;
- file or transfer actions;
- forwarding actions;
- enrollment/device mutations;
- DNS mutation;
- production remote networking;
- Agent installation/restart/replacement;
- packaging, signing, auto-update, or distribution;
- remote-desktop screen capture, streaming, input injection, clipboard, or multi-monitor support.

Those remain behind their existing later contracts and explicit mutation gates.
