# Phase 8.1 — Honeypot Real Rebuild Foundation

## Objective

Start the real honeypot track without breaking the current safe golden path.

## What was implemented

- Added honeypot runtime config in agent TOML:
  - `[honeypot].mode` = `demo` | `listener`
  - `[honeypot].bind_addr`
  - `[honeypot].port`
  - `[honeypot].duration_secs`
- Default remains `demo` for safety and backward compatibility.
- Introduced optional `listener` mode:
  - starts bounded decoy TCP listener
  - writes session metadata to `data_dir/honeypot/`
  - runs fail-open (returns readable error message if bind/start fails)
- Marker event is now mode-aware:
  - demo: `honeypot.demo_decoy_hit`
  - listener: `honeypot.listener_session_started`

## Why this is only a foundation

This phase intentionally does not include:
- traffic redirection
- multi-service decoys
- isolation hardening
- forensic pipeline

Those belong to the full rebuild phase.

## Next step (Phase 8.2)

Implemented in `docs/phase-8-honeypot-real-rebuild.md`:
- selective redirection (optional, target-IP scoped)
- stronger isolation guardrails (loopback default, strict target filters)
- richer evidence collection (`.json` + `.jsonl` artifacts)
