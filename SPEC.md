# Inner Warden — Specifications (v0.1)

Status: draft

## Purpose
Inner Warden is a lightweight, portable host observability and security agent.

It should provide:
- **continuous awareness** of host activity (not just passive logs)
- **high-signal detections** with low noise
- **portable outputs** (JSONL files) usable by OpenClaw or any other tool
- an architecture that can run on this server today, but also adapt to other Linux hosts.

Non-goals (v0.1)
- No destructive actions
- No traffic blocking
- No service restarts (unless explicitly requested)
- No heavy SIEM stack (ELK/Prometheus required)

## Context (this server)
- Ubuntu 22.04 LTS, arm64
- Docker-heavy: reverse proxy + web apps + databases
- Public SSH receives constant scanning
- Disk pressure was a real constraint; journald is now limited and docker cache cleaned.

## Dataflow

collectors -> events -> detectors -> policy -> incidents

### Collectors
Collectors acquire raw signals from the host and emit normalized **Events**.
Collectors MUST:
- be read-only
- keep cursors/offsets in `state.json`
- never block on slow downstream processing

Initial collectors (v0.1):
1) **auth.log** tailer
   - path default: `/var/log/auth.log`
2) **journald** reader (optional)
   - default units of interest: `ssh`, `docker`, `containerd`
3) **docker events** collector (optional)
   - socket: `/var/run/docker.sock`
4) **integrity watcher** (poll-based)
   - critical paths list (configurable)

### Normalized Event
Events are append-only JSON lines in `events-YYYY-MM-DD.jsonl`.

Required fields:
- `ts` (RFC3339 UTC)
- `host`
- `source` (auth.log | journald | docker | integrity)
- `kind` (e.g. `ssh.login_failed`)
- `severity` (debug/info/low/medium/high/critical)
- `summary`
- `details` (json object)
- `tags` (string[])
- `entities` (EntityRef[])

### Detectors
Detectors consume events and emit **Signals**.
Signals are weaker than incidents: they represent pattern matches, counts, or anomalies.

Examples:
- `ssh.failed_login_burst(ip=..., count=..., window=...)`
- `integrity.changed(path=..., old_hash=..., new_hash=...)`
- `docker.container_started(name=..., image=...)`

### Policy (central brain)
Policy consumes signals and decides to:
- ignore
- elevate severity
- group/aggregate
- emit incident

Policy should support:
- allowlists (e.g. known admin IPs)
- dedupe windows
- per-entity rate limits

### Incidents
Incidents are append-only JSONL in `incidents-YYYY-MM-DD.jsonl`.

Required fields:
- `ts`, `host`
- `incident_id` (stable)
- `severity`
- `title`, `summary`
- `evidence` (json array)
- `recommended_checks` (string[])
- `tags`
- `entities`

## Entity Tracking
Entity tracking is mandatory.

Entities:
- `ip`
- `user`
- `container`
- `path`
- `service`

Implementation notes:
- Event/Signal/Incident always carry relevant entities.
- State keeps counters per entity for simple anomaly scoring.

## State and Output
Output directory (default): `./data`

Files:
- `state.json`
- `events-YYYY-MM-DD.jsonl`
- `incidents-YYYY-MM-DD.jsonl`

State must include:
- auth.log: inode + byte offset + last_ts
- journald: cursor
- docker: last event timestamp/id (best-effort)
- per-entity counters for current windows

Retention (v0.1):
- keep N days (config)
- compress older files optional

## MVP detections (v0.1)
1) SSH brute force / credential stuffing indicators
   - invalid users, root/admin attempts
   - high rate of failed logins per IP
2) Critical file changes
   - sshd config, sudoers, cron, systemd unit dirs
3) Unexpected docker lifecycle changes
   - new container started, image pulled, container restarted repeatedly
4) Disk pressure / log pressure
   - filesystem usage > thresholds

## Integration (optional)
Inner Warden should not depend on OpenClaw.
However, it should be easy to integrate:
- OpenClaw can tail incidents JSONL and narrate it.
- Inner Warden can optionally write a short `daily-summary.md`.

## Security and Safety
- Default mode is read-only.
- No auto-remediation in v0.1.
- Any future action requires explicit approval mode.

## Run modes
- systemd service (recommended)
- CLI "one-shot" mode for debugging

## Implementation plan (next steps)
1) Create real repo structure (outside brainstorm):
   - `crates/innerwarden` (binary)
   - `crates/core`
   - `crates/collectors/*`
   - `crates/detectors/*`
2) Implement JSONL writer + state.json manager
3) Implement auth.log collector + basic ssh detectors
4) Implement policy (dedupe + severity mapping)
5) Add docker events collector
6) Add integrity watcher
7) Add packaging:
   - example systemd unit
   - minimal config

## Acceptance criteria (v0.1)
- Runs continuously on this server with negligible load
- Produces valid JSONL files
- Detects SSH bursts and file changes reliably
- Incidents are clear and actionable
- No destructive changes performed
