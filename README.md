# InnerWarden

An open-source host security agent for Linux and macOS. It watches system
activity in real time, detects attacks using deterministic rules, and responds
autonomously when confidence is high enough.

Two Rust binaries. No external dependencies at runtime.

- `innerwarden-sensor` — deterministic telemetry collection and incident detection (no AI, no HTTP)
- `innerwarden-agent` — incremental analysis, AI-assisted triage, response skills, dashboard and Telegram alerts

The default posture is conservative:

- all collectors are append-only JSONL
- responders are disabled by default
- `dry_run = true` is the recommended starting point
- privacy-sensitive collectors are explicit opt-ins

## What It Does

### Sensor — collection

The sensor tails log files and system interfaces, normalizes every event into a
common shape and writes `events-YYYY-MM-DD.jsonl` and `incidents-YYYY-MM-DD.jsonl`.

**Built-in sources:**

- `/var/log/auth.log` — SSH login attempts, failures, invalid users
- `journald` — sshd, sudo, kernel (firewall signals), any configured unit
- Docker events — start, stop, die, OOM
- File integrity — SHA-256 polling of configurable paths
- nginx access log — HTTP-layer events (Combined Log Format)
- `auditd EXECVE` — shell command trail (opt-in, explicit consent required)
- `auditd TTY` — raw keyboard input (opt-in, high privacy impact)
- `log stream` (macOS) — unified log for SSH, sudo, and system events

**Integration collectors:**

| Tool | What it ingests | How |
|------|----------------|-----|
| Falco | Kernel / container anomaly alerts | tails Falco JSON log |
| Suricata | Network IDS alerts (alert, dns, http, tls, anomaly) | tails EVE JSON log |
| osquery | Host queries (ports, cron, sudoers, processes, users) | tails differential results log |

High and Critical Falco alerts and Suricata severity-1/2 alerts skip the detector
layer and go directly to the agent as incidents — the tool already did the detection.

All collectors are fail-open: errors are logged and never crash the sensor.

### Sensor — detectors

Six built-in detectors run on the normalized event stream:

| Detector | What it catches | Source |
|----------|----------------|--------|
| `ssh_bruteforce` | Repeated SSH failures from the same IP | auth.log / journald |
| `credential_stuffing` | Many distinct usernames tried from one IP | auth.log / journald |
| `port_scan` | Rapid unique-port probing by source IP | firewall / kernel logs |
| `sudo_abuse` | Burst of suspicious privileged commands by a user | journald sudo |
| `search_abuse` | High-rate requests to expensive HTTP endpoints | nginx access log |
| `execution_guard` | Suspicious shell command patterns via AST analysis | auditd EXECVE |

`execution_guard` uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash)
to parse commands structurally. It detects `curl | sh` pipelines, execution from `/tmp`,
reverse shell patterns, obfuscated commands, and staged sequences (download → chmod → execute).
Currently runs in `observe` mode only — emits incidents, no automatic blocking.

### Agent — analysis and response

- reads JSONL incrementally via byte-offset cursors (no re-read on restart)
- applies an algorithm gate before any AI call (severity, private IP, already-blocked)
- correlates incidents in a time window and clusters them for richer AI context
- supports OpenAI, Anthropic, and Ollama (local/air-gapped) as AI providers
- executes bounded response skills when explicitly enabled
- sends real-time alerts and approval requests via Telegram

**Response skills:**

| Skill | Tier | What it does |
|-------|------|-------------|
| `block-ip-ufw` | Open | Blocks IP via ufw (Linux) |
| `block-ip-iptables` | Open | Blocks IP via iptables (Linux) |
| `block-ip-nftables` | Open | Blocks IP via nftables (Linux) |
| `block-ip-pf` | Open | Blocks IP via pf firewall (macOS) |
| `suspend-user-sudo` | Open | Temporary sudo denial with auto-expiry TTL |
| `rate-limit-nginx` | Open | HTTP 403 deny at nginx layer with TTL |
| `monitor-ip` | Premium | Bounded traffic capture via tcpdump + metadata sidecar |
| `honeypot` | Premium | SSH/HTTP decoy with containment profiles and forensic handoff |

**Operator communication:**

- Webhook HTTP POST with minimum-severity filter
- Telegram T.1: real-time push alerts for High/Critical incidents
- Telegram T.2: inline approve/deny for pending actions — decisions are audited

**Dashboard (local, authenticated):**

- HTTP Basic auth (Argon2 hash), read-only by default
- Live incident timeline via Server-Sent Events (no polling)
- Attacker journey viewer with AI-generated chapter rail
- Report tab: health summary, day-over-day trends, anomaly hints
- Operator actions: block IPs and suspend users from the browser (requires `responder.enabled = true`)
- Inline entity search, alert toasts, deep-link investigation state

### Modules

Detectors and skills are packaged into modules — vertical solutions for a specific threat class:

| Module | What it covers |
|--------|---------------|
| `ssh-protection` | SSH brute-force + credential stuffing → block-ip |
| `network-defense` | Port scan → block-ip |
| `sudo-protection` | Sudo abuse → suspend-user-sudo |
| `execution-guard` | Shell command AST analysis → suspicious_execution incidents |
| `file-integrity` | SHA-256 file monitoring → webhook alert |
| `container-security` | Docker lifecycle events (observability) |
| `search-protection` | nginx access log → search_abuse → rate-limit-nginx |
| `threat-capture` | monitor-ip + honeypot (Premium) |
| `falco-integration` | Falco JSON log → incident passthrough |
| `suricata-integration` | Suricata EVE JSON → incident passthrough |
| `osquery-integration` | osquery results log → enriched events |

## Architecture

```text
External tools (Falco, Suricata, osquery)
  -> log files
     -> innerwarden-sensor
        -> events-YYYY-MM-DD.jsonl
        -> incidents-YYYY-MM-DD.jsonl
           -> innerwarden-agent
              -> decisions-YYYY-MM-DD.jsonl
              -> telemetry-YYYY-MM-DD.jsonl
              -> summary-YYYY-MM-DD.md
              -> Telegram alerts / approvals
              -> local dashboard
```

## Supported Environments

- **Linux** — Ubuntu 22.04+ (primary reference), any `systemd`-based distro
- **macOS** — Ventura and later (launchd services, pf firewall, `log stream` collector)

Pre-built binaries for `x86_64` and `aarch64`.

## Quickstart

### Build and test

```bash
make test   # 374 tests (145 agent + 116 ctl + 113 sensor)
make build
```

### Run locally with fixture config

```bash
make run-sensor   # writes to ./data/
make run-agent    # reads from ./data/
```

### Start the dashboard

```bash
innerwarden-agent --dashboard-generate-password-hash
export INNERWARDEN_DASHBOARD_USER=admin
export INNERWARDEN_DASHBOARD_PASSWORD_HASH='$argon2id$...'
make run-dashboard
```

Dashboard: `http://127.0.0.1:8787`

Deep-link investigation state:

```text
/?date=2026-03-13&subject_type=ip&subject=203.0.113.10&window_seconds=300
```

## Install on Linux or macOS

```bash
curl -fsSL https://get.innerwarden.dev | bash
```

What it does:

- downloads pre-built binaries for your architecture (~10 s)
- creates `/etc/innerwarden/{config.toml,agent.toml,agent.env}`
- creates and enables `systemd` units (Linux) or `launchd` plists (macOS)
- starts in a conservative profile (`responder.enabled = false`, `dry_run = true`)
- prompts for privacy consent before enabling shell audit
- `--with-integrations` flag: detects and optionally installs Falco, Suricata and osquery with pre-configured collectors

Build from source instead:

```bash
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://get.innerwarden.dev | bash
```

First rollout posture:

- `responder.enabled = false`
- `dry_run = true`
- dashboard auth configured before any remote exposure

## Control Plane

```bash
innerwarden list                        # list all capabilities and modules
innerwarden enable block-ip             # enable IP blocking (ufw backend)
innerwarden enable block-ip --param backend=nftables
innerwarden enable sudo-protection
innerwarden enable shell-audit          # prompts for privacy consent
innerwarden status                      # services + capabilities + modules
innerwarden doctor                      # diagnostics with fix hints (exit 1 on issues)
innerwarden upgrade                     # fetch and install latest release (SHA-256 verified)
innerwarden upgrade --check             # check without installing
innerwarden module install <url>        # install a module (SHA-256 verified)
innerwarden module update-all           # update all modules with update_url
```

## Safe Update Path

```bash
make rollout-precheck HOST=user@server
make deploy HOST=user@server
ssh user@server "sudo systemctl restart innerwarden-agent innerwarden-sensor"
make rollout-postcheck HOST=user@server
```

Fast rollback:

```bash
make rollout-rollback HOST=user@server
```

Or self-update from the binary:

```bash
innerwarden upgrade
```

## Safety Model

- response skills are config-gated (`responder.enabled = false` by default)
- `dry_run = true` is the recommended default during rollout
- shell audit via `auditd` is privacy-sensitive — only enable with explicit authorization
- `execution_guard` runs in `observe` mode only in v0.1 — detects, does not block
- honeypot features are bounded and opt-in
- AI is advisory unless you explicitly allow auto-execution

## FAQ

**Is this an EDR?**
No. It is a focused host-security observability and response project with
append-only artifacts, bounded investigation features, and optional response skills.

**Does it block by default?**
No. The safe starting posture is `responder.enabled = false` and `dry_run = true`.

**Do I need an AI provider?**
No. Collection, detection, JSONL artifacts, reports and dashboarding all work without AI.
The AI layer is only needed for the confidence-scored decision engine, which is optional.

**Can I use it without Falco or Suricata?**
Yes. The integration collectors are opt-in. The built-in sensor detectors cover SSH,
sudo, port scans, API abuse and command execution without any external tools.

**Can I add custom detectors or skills?**
Yes. See [docs/module-authoring.md](docs/module-authoring.md).

## Repository Guide

- [ROADMAP.md](ROADMAP.md) — what is planned and what shipped
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [CONTRIBUTING.md](CONTRIBUTING.md) — contributor workflow
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [docs/index.md](docs/index.md) — documentation map
- [docs/format.md](docs/format.md) — JSONL event and incident schemas
- [docs/module-authoring.md](docs/module-authoring.md) — guide for building custom modules
- [docs/integrated-setup.md](docs/integrated-setup.md) — Falco + Suricata + osquery + Telegram setup on Ubuntu 22.04
- [CLAUDE.md](CLAUDE.md) — maintainer operating document

## License

MIT. See [LICENSE](LICENSE).
