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
- manual bounded local status refresh that preserves the last rendered status while the read-only probe is active and gives explicit `Refreshing…` progress feedback;
- a read-only Settings diagnostics page that shows the local Ownspace Desktop package version, exposes both the compatibility-sensitive endpoint contract and the session-resolved candidate endpoint derived through the existing `LocalIpcContract`, with a local-only copy action for the resolved path and no Agent configuration mutation;
- a read-only Activity page that mirrors the latest local Agent/Private DNS probe snapshot, can trigger the same bounded local refresh as Overview, and can copy the currently rendered snapshot to the local desktop clipboard without persisting history or emitting external telemetry;
- explicit offline/error handling, including partial Private DNS query failure visibility;
- a bounded worker thread so local Unix-socket reads do not block the GTK main thread.

Only the existing local `GetAgentStatus` and `GetPrivateDnsConfig` commands are used by the implemented status surface.

The local control endpoint remains:

`$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock`

Settings also displays the session-resolved candidate path when `XDG_RUNTIME_DIR` is available and absolute. The resolved path can be copied to the local desktop clipboard for diagnostics; this is not Remote Desktop clipboard integration. The display remains derivation-only, and endpoint trust, availability, and connectivity remain governed by the existing validated IPC path.

That socket path and existing `prw-*` package, service, protocol, filesystem, and related identifiers are compatibility-sensitive internal identifiers. Public product terminology is **Ownspace**; this documentation update does not rename compatibility surfaces.

The desktop client performs no TCP, D-Bus, abstract-socket, `/tmp`, shell-command, or alternate-path fallback for this local status surface.

## Deliberately not activated by this surface

Machines, Sessions, Files, and Transfers remain structural placeholders unless backed by separately validated capability work. Activity is limited to the latest in-memory local diagnostics snapshot; its refresh action reuses the same bounded local status probe as Overview, and its copy action exports only the currently rendered text to the local desktop clipboard. It does not provide persisted history, external telemetry, or Remote Desktop clipboard integration. The current desktop status/diagnostics surface does not implement or activate:

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
