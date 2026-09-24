# Ownspace

Ownspace is a private, local-first remote workspace and device-management application.

The product is designed around owner-controlled local authority, device identity, encrypted remote access, terminal/file operations, networking and device management without requiring a third-party runtime service as an architectural prerequisite.

## Current platforms

- Ubuntu owner/host runtime and desktop application
- Android application

## Source layout

- `apps/android` — Android application and native adapter
- `apps/desktop` — Linux desktop application
- `crates` — Rust workspace libraries and agent/runtime components
- `packaging` — Linux packaging and systemd integration assets

## Technical compatibility identifiers

The current source still uses internal identifiers such as `prw-*`, `com.privateworkspace.prw`, `prw-agent` and existing service/protocol names. These are implementation identifiers retained to preserve build/runtime compatibility during the Drive cutover. They are not the public product name.

The public application name is **Ownspace**.

## Authority and workflow

The authoritative working source is the `02_Source_Current` folder inside the Ownspace Drive workspace. Development and validation are performed in temporary workspaces created from that Drive snapshot. Results are written back to the Ownspace Drive workspace.
