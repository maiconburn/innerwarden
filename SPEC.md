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

## Performance Goals (v0.1)
Inner Warden must remain extremely lightweight.

Target constraints:
- Memory usage: < 20 MB typical
- CPU usage: < 1% on idle systems
- No collector should block the main loop
- Disk writes must be append-only and buffered
- Event ingestion must tolerate bursty log input

## Context (this server)
- Ubuntu 22.04 LTS, arm64
- Docker-heavy: reverse proxy + web apps + databases
- Public SSH receives constant scanning
- Disk pressure was a real constraint; journald is now limited and docker cache cleaned.

## Dataflow

collectors -> events -> detectors -> policy -> incidents

### Architectural Separation
Inner Warden should maintain a strict separation between:
- Collectors (data ingestion)
- Core Engine (detectors + policy)
- Sinks (output destinations)

The core engine must remain agnostic to:
- event source (auth.log, journald, docker, etc.)
- output destination (JSONL, webhook, external agents)

The engine should operate purely on normalized Events and produce normalized Incidents.
This allows Inner Warden to remain portable and easily integrable with other systems.

### Collectors
Collectors acquire raw signals from the host and emit normalized **Events**.
Collectors MUST:
- be read-only
- keep cursors/offsets in `state.json`
- never block on slow downstream processing
- fail open: if a collector fails or crashes, the agent must continue running and log the failure without stopping other collectors

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

Event details should remain compact.
Recommended maximum size: 16KB.
This prevents oversized log payloads and keeps event processing lightweight.

### Detectors
Detectors consume events and emit **Signals**.
Signals are weaker than incidents: they represent pattern matches, counts, or anomalies.

Events may arrive slightly out of chronological order depending on the log source.
Detectors should rely on event timestamps rather than ingestion order.

Examples:
- `ssh.failed_login_burst(ip=..., count=..., window=...)`
- `integrity.changed(path=..., old_hash=..., new_hash=...)`
- `docker.container_started(name=..., image=...)`

#### Normalized Signal
Signals represent pattern matches or anomaly indicators derived from events.

Signals are NOT incidents; they are intermediate observations that may later be aggregated by policy.

Signals must include:
- `ts` (RFC3339 UTC)
- `signal_type`
- `source_event_ids` (array of event references)
- `entities`
- `score` (numeric confidence or weight)
- `details` (json object)

Signals are not persisted long-term in v0.1 unless needed for incident evidence.

### Policy (central brain)
Policy is the correlation layer that converts signals into actionable incidents.

Responsibilities include:
- signal aggregation
- deduplication windows
- severity escalation
- allowlist evaluation
- entity rate tracking

Policy should remain deterministic in v0.1 (rule-based).

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

## Configuration
Inner Warden should load configuration from `config.toml`.

Example:

```toml
[authlog]
path = "/var/log/auth.log"

[journald]
enabled = true
units = ["ssh", "docker", "containerd"]

[docker]
enabled = true
socket = "/var/run/docker.sock"

[integrity]
paths = [
  "/etc/ssh/sshd_config",
  "/etc/sudoers",
  "/etc/cron.d"
]

[retention]
days = 7
compress_after_days = 3
```

Configuration should also allow environment variable overrides.

## Entity Tracking
Entity tracking is mandatory.

Entities:
- `ip`
- `user`
- `container`
- `path`
- `service`

EntityRef schema:
- `type` (ip | user | container | path | service)
- `value` (string)

Events, Signals and Incidents must reference entities using this structure.

Implementation notes:
- Event/Signal/Incident always carry relevant entities.
- State keeps counters per entity for simple anomaly scoring.

## State and Output
Output directory (default): `./data`

Files:
- `state.json`
- `events-YYYY-MM-DD.jsonl`
- `incidents-YYYY-MM-DD.jsonl`

Buffered event writes should flush within 1–5 seconds to minimize data loss in case of crash.

State must include:
- auth.log: inode + byte offset + last_ts
- journald: cursor
- docker: last event timestamp/id (best-effort)
- per-entity counters for current windows

Retention (v0.1):
- event files rotate daily
- incident files rotate daily
- optional gzip compression after N days
- deletion after configured retention period
- rotation must never block event ingestion

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

## Design Principles
Inner Warden follows these principles:
- minimal dependencies
- append-only data model
- deterministic detections first
- portability over ecosystem lock-in
- clear separation between event ingestion and detection logic

## Implementation plan (next steps)
1) Create real repo structure (outside brainstorm)

   Suggested repository structure:

   ```
   crates/
     core/
       event.rs
       signal.rs
       incident.rs
       entity.rs
       policy_engine.rs
     collectors/
       authlog.rs
       journald.rs
       docker.rs
       integrity.rs
     detectors/
       ssh.rs
       integrity.rs
       docker.rs
     sinks/
       jsonl.rs
     innerwarden/
       main.rs
   ```

2) Implement JSONL sink + state.json manager
3) Implement auth.log collector + basic ssh detectors
4) Implement policy engine (dedupe + severity mapping)
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
