# Ownspace Desktop Application

Status: current native desktop management surface

The desktop application is a separate native Rust/GTK 4/libadwaita UI/client process.

It is not required for the Ubuntu host to remain remotely reachable. The headless Ownspace Agent remains authoritative for host runtime state, policy enforcement, remote capability execution, private-key boundaries, and production lifecycle ownership.

## Current management scope

The desktop shell provides:

- native libadwaita application/window;
- Overview, Machines, Sessions, Files, Transfers, Activity, and Settings navigation;
- read-only local Agent availability/runtime presentation;
- read-only Private DNS summary presentation;
- manual bounded local status refresh that preserves the last rendered status while the read-only probe is active and gives explicit `Refreshing…` progress feedback;
- a read-only Machines registered-device inventory loaded through the authenticated local Agent from the existing owner-PC registry authority, exposing only device identifier and lifecycle metadata; this surface does not mutate enrollment/device authority and does not infer Online/Offline from endpoint or transport data when no authoritative live per-device reachability observation is available;
- local-only Machines inventory search by device identifier or enrollment lifecycle, stable device-ID sorting, and enrolled/pending/revoked snapshot totals; filtering reuses the last successfully decoded DeviceList snapshot without sending a new Agent request, changing device authority, or inventing reachability;
- a read-only Settings diagnostics page that shows the local Ownspace Desktop package version, the desktop client’s compiled-in supported local IPC protocol version, and the latest Agent-reported local IPC protocol version from the same bounded `GetAgentStatus` snapshot used by Overview and Activity; it also exposes both the compatibility-sensitive endpoint contract and the session-resolved candidate endpoint derived through the existing `LocalIpcContract`, with a local-only copy action for the resolved path and no Agent configuration mutation;
- a read-only Activity page that mirrors the latest local Agent/Private DNS probe snapshot, can trigger the same bounded local refresh as Overview, and can copy the currently rendered snapshot plus the session-resolved local IPC endpoint candidate to the local desktop clipboard without persisting history or emitting external telemetry;
- an implemented Sessions page for one local terminal session through existing command-3 terminal authority: it keeps terminal open/input/read/resize/close on one authenticated local Agent connection, where the Agent owns a fixed `/bin/sh -i` PTY as the same UID with bounded geometry/I/O and explicit process-group cleanup; Agent-owned terminal principal/capability checks remain authoritative, output reads are explicit and bounded, and resize uses the existing validated terminal geometry contract;
- an implemented Files page for authenticated read-only directory listing through command-3 `FileList` and separately manually requested read-only type/size metadata snapshots through existing command-3 `FileStat`, both under the Agent-owned owner-home authority, with canonical relative-path entry, Home/Up navigation, Refresh after a successful listing, explicit current-path presentation, and no file-content read/open or mutation; metadata is a snapshot, not a guarantee that later file contents are unchanged;
- an implemented Transfers page for one bounded local-file upload at a time through existing command-3 upload begin/chunk/finalize authority, with exact Agent-acknowledged committed offsets, SHA-256 finalization, progress/completion/failure presentation, and internal best-effort abort cleanup after an uncertain or failed active upload; download, resume, and user-triggered abort are not enabled in this checkpoint;
- explicit offline/error handling, including partial Private DNS query failure visibility;
- a bounded worker thread so local Unix-socket reads do not block the GTK main thread.

The implemented status/diagnostics surfaces use only the existing local `GetAgentStatus` and `GetPrivateDnsConfig` commands. Machines separately uses the additive read-only command-3 `DeviceList` path over the same authenticated local Agent socket and reads the existing owner-PC registry in strict read-only mode; it does not read SQLite directly from the Desktop. The Files page uses the already-authorized read-only command-3 `FileList` and existing `FileStat` paths over the same trusted local Agent socket; the FileStat result is strictly decoded as the existing type/size metadata body, without reading file contents or changing Agent authority. The Sessions page uses existing command-3 terminal open/input/read/resize/close operations on one retained authenticated local Agent connection; the Agent-side production terminal provider is limited to the existing POSIX-shell profile and preserves same-UID principal/capability checks, bounded I/O/geometry, and explicit connection teardown cleanup. Desktop presents terminal output only through an explicit bounded read action and exposes explicit validated columns/rows resize controls; it does not introduce background output streaming or an alternate transport. The Transfers page uses the existing upload begin/chunk/finalize transfer family and Agent-owned owner-home filesystem authority; its internal abort request is cleanup-only after a failed or uncertain active upload and does not expose resume or user-triggered abort controls.

The local control endpoint remains:

`$XDG_RUNTIME_DIR/private-remote-workspace/agent.sock`

Settings also displays the desktop client’s compiled-in supported local IPC protocol version without performing an Agent probe. Separately, it mirrors the latest Agent-reported local IPC protocol version only from the existing bounded `GetAgentStatus` snapshot and classifies that reported version with the existing authoritative `LocalIpcProtocolVersion::is_supported()` rule. This adds no command or additional socket read; the classification is limited to exact local IPC version support and does not assert endpoint trust or capability authorization. Overview and Activity reuse that same snapshot and support rule in their rendered protocol detail, so the current snapshot copied from Activity includes the same exact compatibility classification without any additional read. Settings also displays the session-resolved candidate path when `XDG_RUNTIME_DIR` is available and absolute. The resolved path can be copied to the local desktop clipboard for diagnostics; this is not Remote Desktop clipboard integration. The protocol/version and endpoint displays do not alter endpoint trust, availability, connectivity, live protocol acceptance, or capability authorization, which remain governed by the existing validated IPC path.

That socket path and existing `prw-*` package, service, protocol, filesystem, and related identifiers are compatibility-sensitive internal identifiers. Public product terminology is **Ownspace**; this documentation update does not rename compatibility surfaces.

The desktop client performs no TCP, D-Bus, abstract-socket, `/tmp`, shell-command, or alternate-path fallback for this local status surface.

## Deliberately not activated by this surface

Transfers now activates only bounded upload begin/chunk/finalize plus internal failure cleanup over the existing trusted local management path; it does not activate download execution, transfer resume, user-triggered abort, or full bidirectional transfer management. Sessions activates terminal open/input/read/resize/close over one retained authenticated local management connection backed by the fixed same-UID POSIX PTY provider; output presentation is driven only by explicit bounded reads and resize remains within the existing typed geometry contract. Desktop does not activate Remote Desktop or forwarding. Activity is limited to the latest in-memory local diagnostics snapshot; its refresh action reuses the same bounded local status probe as Overview, and its copy action exports only the currently rendered text plus the session-resolved local IPC endpoint candidate to the local desktop clipboard. The endpoint value is path derivation from `XDG_RUNTIME_DIR` through the existing `LocalIpcContract`; it does not perform an Agent read or assert endpoint trust, availability, or connectivity. Activity does not provide persisted history, external telemetry, or Remote Desktop clipboard integration. The current desktop management surface does not implement or activate:

- arbitrary run-command shortcuts, request-selected terminal executable/profile/environment/cwd, background terminal-output streaming, or alternate terminal transports;
- `DownloadChunk`, file-content read/open, general file mutation, download execution, upload resume, or user-triggered upload abort; `FileStat` is activated only for explicit read-only metadata inspection;
- forwarding actions;
- enrollment/device mutations;
- DNS mutation;
- production remote networking;
- Agent installation/restart/replacement;
- packaging, signing, auto-update, or distribution;
- Remote Desktop screen capture, streaming, input injection, clipboard, or multi-monitor support.

Those remain behind their existing contracts, authorization boundaries, and explicit mutation gates.
