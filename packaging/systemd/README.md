# Ownspace Linux service packaging

This directory contains the current Linux systemd and installer assets used by the Ownspace agent/runtime.

The files here are source packaging assets only. They do not by themselves install, enable, start, restart or reload a real service.

Current compatibility identifiers such as `prw-agent`, existing unit names and existing filesystem paths are retained so the current source remains build/runtime compatible during the Ownspace Drive cutover.

Permanent Ownspace workflow/process rules are defined only by `OWNSPACE_WORKFLOW_AUTHORITY.md` in the Ownspace Drive workspace.
