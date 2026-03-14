# Phase 8.3 — Honeypot Hardening (Isolation + Forensics Depth)

## Objective

Harden the real listener mode from Phase 8.2 without changing the default-safe posture.

## What was implemented

- Added listener hardening controls:
  - `isolation_profile = "strict_local" | "standard"`
  - `require_high_ports`
  - active session lock (`listener-active.lock`) with stale lock recovery (`lock_stale_secs`)
- Added forensic depth controls:
  - `forensics_keep_days` retention cleanup for `listener-session-*` artifacts
  - `transcript_preview_bytes` and protocol classification (`protocol_guess`) per connection
- Redirect lifecycle now has stronger cleanup validation:
  - apply/remove remains best effort
  - post-cleanup verification uses `iptables -C`
  - metadata records `cleanup_verified_absent`

## Config additions

```toml
[honeypot]
isolation_profile = "strict_local"
require_high_ports = true
forensics_keep_days = 7
transcript_preview_bytes = 96
lock_stale_secs = 1800
```

## Notes

- `demo` mode remains default.
- `strict_local` profile enforces:
  - `strict_target_only = true`
  - `allow_public_listener = false`
  - `require_high_ports = true`
- Listener remains bounded and fail-open.

## Next step

Delivered in `docs/phase-8-honeypot-sandbox-runtime.md` (Phase 8.4):
- dedicated sandbox worker runtime for decoys
- optional bounded pcap handoff
- stricter forensic retention budget
