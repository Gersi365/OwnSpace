# PRW Android Application

Phase 149 completes the currently planned non-production Android functional-client slices.

Current development responsibilities include:

- non-exportable Android Keystore identity custody and typed authenticated bootstrap;
- enrollment/device-management presentation;
- bounded terminal UX through existing PRWC terminal commands;
- bounded remote-file browser and resumable upload/download presentation;
- loopback-only TCP forwarding intent encoding through existing `prw-forwarding` and Phase 143 `BridgeCommand` authority;
- private-network selected-path presentation through existing `prw-connectivity` authority;
- optional private-DNS draft validation through existing `prw-private-dns` authority.

Phase 149 remains non-production. It opens no forwarding socket, performs no network discovery/probe, mutates no route/firewall/NAT/TUN/TAP or OS resolver state, and does not sign/distribute a production Android application.
