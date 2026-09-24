# Ownspace Linux service packaging

This directory contains the current Linux systemd and installer assets used by the Ownspace agent/runtime.

The files here are source packaging assets only. They do not by themselves install, enable, start, restart or reload a real service.

Current compatibility identifiers such as `prw-agent`, existing unit names and existing filesystem paths are retained so the current source remains build/runtime compatible during the Ownspace Drive cutover.

Build and installation validation must be performed from a temporary workspace created from the authoritative `02_Source_Current` Drive snapshot. Validation results belong in the Ownspace Drive workspace, not in an external repository or machine-specific workspace.
