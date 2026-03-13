# Phase 8.2 — Honeypot Real Rebuild (Bounded)

## Objective

Deliver a practical real honeypot mode without sacrificing the safe operational posture:
- keep `demo` as default
- run bounded decoys in `listener` mode
- add controlled redirect + forensics

## What was implemented

- `honeypot` skill listener mode now supports **multi-service decoys**:
  - `ssh` decoy (banner emulation)
  - `http` decoy (light decoy response)
- Added **selective redirection** (optional):
  - target-IP scoped `iptables` redirect rules
  - automatic best-effort cleanup at session end
- Added **isolation guardrails**:
  - loopback bind required by default
  - `allow_public_listener=true` required for external bind
  - `strict_target_only=true` by default
  - bounded session via `duration_secs`, `max_connections`, and `max_payload_bytes`
- Added **forensics pipeline** in `data_dir/honeypot/`:
  - `listener-session-*.json` (session metadata and redirect status)
  - `listener-session-*.jsonl` (session lifecycle + per-connection evidence lines)

## Config additions

```toml
[honeypot]
mode = "demo"                 # demo | listener
bind_addr = "127.0.0.1"
port = 2222                   # ssh decoy port
http_port = 8080              # http decoy port
duration_secs = 300
services = ["ssh"]            # ["ssh", "http"] for multi-service
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512

[honeypot.redirect]
enabled = false
backend = "iptables"
```

## Safety notes

- Default behavior remains unchanged (`mode = "demo"`).
- Listener mode is still bounded/fail-open and should be rolled out progressively.
- Redirect rules are optional and explicitly gated by config.

## Next step

Move from bounded listener runtime to harder isolation + deeper forensics in a dedicated hardening phase (Phase 8.3).
