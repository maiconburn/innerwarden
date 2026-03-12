# Inner Warden (draft)

This folder contains early brainstorming for an autonomous server observability/security agent.

Minimal, portable Linux security/observability agent.

Goal
- Read a few high-signal sources (auth.log, journald, docker events, file integrity)
- Emit portable JSONL: events + incidents
- Keep small state file for cursors/offsets
- No auto-remediation in MVP (alert only)

Non-goals (MVP)
- Full SIEM / long-term storage
- Kernel instrumentation (eBPF/auditd) unless explicitly enabled later

Outputs
- `data/events-YYYY-MM-DD.jsonl`
- `data/incidents-YYYY-MM-DD.jsonl`
- `data/state.json`

MVP collectors
- auth.log tailer (works almost everywhere)
- journald reader (optional)
- docker events (optional)
- integrity watcher (config-defined paths)

MVP detectors
- SSH brute force (rate threshold per IP)
- root/admin login attempts
- change in critical files (mtime/hash)
- unexpected container lifecycle events

Configuration
- `config.toml` (see `config.example.toml`)

Run modes
- daemon (systemd)
- cron batch mode (optional future)

Roadmap
- v0.1: collectors + jsonl writer + basic detectors
- v0.2: incident grouping + dedupe + severity scoring
- v0.3: optional OpenClaw integration (read incidents + narrate)

License: TBD
