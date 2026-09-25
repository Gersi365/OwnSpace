# Ownspace Desktop Application

Status: current native desktop management surface

The desktop application is a separate native Rust/GTK 4/libadwaita UI/client process.

It is not required for the Ubuntu host to remain remotely reachable. The headless Ownspace Agent remains authoritative for host runtime state, policy enforcement, remote capability execution, private-key boundaries, and production lifecycle ownership.

## Current read-only scope

The desktop shell provides:

- native libadwaita application/window;
- Overview, Machines, Sessions, Files, Transfers, Activity, and Settings navigation;
- read-only local Agent availability/runtime presentation;
- read-only Private DNS summary presentation;
- manual bounded local status refresh with explicit `Refreshing…` progress feedback while the read-only probe is active;
- explicit offline/error handling, including partial Private DNS query failure visibility;
- a bounded worker thread so local Unix-socket reads do not block the GTK main thread.

Only the existing local `GetAgentStatus` and `GetPrivateDnsConfig` commands are used by the implemented status surface.

The local control endpoint remains:

`$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock`

That socket path and existing `prw-*` package, service, protocol, filesystem, and related identifiers are compatibility-sensitive internal identifiers. Public product terminology is **Ownspace**; this documentation update does not rename compatibility surfaces.

The desktop client performs no TCP, D-Bus, abstract-socket, `/tmp`, shell-command, or alternate-path fallback for this local status surface.

## Deliberately not activated by this surface

The remaining navigation destinations are structural placeholders unless backed by separately validated capability work. The current desktop status surface does not implement or activate:

- terminal actions;
- file or transfer actions;
- forwarding actions;
- enrollment/device mutations;
- DNS mutation;
- production remote networking;
- Agent installation/restart/replacement;
- packaging, signing, auto-update, or distribution;
- Remote Desktop screen capture, streaming, input injection, clipboard, or multi-monitor support.

Those remain behind their existing contracts, authorization boundaries, and explicit mutation gates.
