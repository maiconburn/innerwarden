# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.4] — 2026-03-16

### Sensor (`innerwarden-sensor`)

**New collectors**
- `wazuh_alerts` — tails `/var/ossec/logs/alerts/alerts.json`; maps `rule.level` to severity (0–15 → Debug/Low/Medium/High/Critical); passthrough for High/Critical; extracts `data.srcip`, `data.dstuser`, `agent.name`
- `nginx_error` — tails nginx `error.log`; parses `[level]` + client IP + request; emits `http.error` events feeding the `web_scan` detector
- `macos_log` — `log stream` subprocess (macOS only); reuses SSH parser; emits `sudo.command` events
- `syslog_firewall` — tails `/var/log/syslog` or `/var/log/kern.log`; parses iptables, nftables, and UFW DROP entries (`SRC=`, `DPT=`, `PROTO=`); emits `network.connection_blocked` feeding the `port_scan` detector; alternative to journald for servers without systemd

**New detectors**
- `web_scan` — sliding window of `http.error` events per IP; fires `web_scan` incident (High) when threshold exceeded; dedup within window
- `user_agent_scanner` — stateless User-Agent matching against 20 scanner signatures (Nikto, sqlmap, Nuclei, Masscan, Gobuster, ffuf, Burp Suite, Metasploit, and more); emits `http.scanner_ua` (High) on first match; dedup by `(ip, scanner)` in 10-minute window; MITRE T1595 / T1595.002

**Enhanced integrity detection**
- SSH `authorized_keys` tampering: changes to `authorized_keys` files emit `ssh.authorized_keys_changed` (High) instead of generic `file.changed`; extracts username from path; MITRE T1098.004
- Cron tampering: changes to crontab files emit `cron.tampering` (High); MITRE T1053.003

**Docker privilege escalation detection**
- On `container.start`, detects `--privileged` flag, docker.sock mount, and dangerous capabilities; emits `container.privileged`, `container.sock_mount`, `container.dangerous_cap`

### Agent (`innerwarden-agent`)

**New integrations**
- Slack notifications via Incoming Webhook (Block Kit, severity colours, optional dashboard deep-link)
- Fail2ban integration: syncs active bans into InnerWarden blocklist
- GeoIP enrichment via ip-api.com (no API key; 45 req/min free)
- CrowdSec integration: enforces crowd-sourced bans via block skills
- Cloudflare integration: pushes `block_ip` decisions to Cloudflare edge via IP Access Rules API

**Response skills**
- `block-ip-pf` — IP block via macOS Packet Filter (`pfctl`); Open tier

**DDoS and AI overload protection**
- `abuseipdb.auto_block_threshold` — skip AI for known-malicious IPs (AbuseIPDB confidence ≥ threshold)
- `ai.max_ai_calls_per_tick` — cap AI calls per tick (default 5); prevents API bill spikes
- `ai.circuit_breaker_threshold` — suspend AI for the tick if incident burst ≥ threshold

### Control plane (`innerwarden` / `innerwarden-ctl`)

**New commands**
- `innerwarden setup` — onboarding wizard: scans machine, configures AI, Telegram, responder, and enables essential modules
- `innerwarden incidents` — lists recent incidents with severity, IP, and time
- `innerwarden decisions` — shows agent decisions (block, suspend, ignore) with confidence and dry-run status
- `innerwarden entity <ip|user>` — full chronological timeline for one IP or user across events, incidents, and decisions
- `innerwarden block / unblock` — manual firewall control with audit trail
- `innerwarden sensor-status` — reads telemetry snapshot; shows collector and detector event counts
- `innerwarden export` — exports events, incidents, or decisions to JSON or CSV
- `innerwarden tail` — streams new entries in real time (like `tail -f`)
- `innerwarden report` — prints the daily Markdown summary to the terminal
- `innerwarden watchdog` — checks agent health against telemetry mtime; `--status` shows cron schedule
- `innerwarden tune` — analyses noise/signal per detector and suggests threshold adjustments
- `innerwarden test-alert` — sends a test message to all configured notification channels
- `innerwarden completions bash|zsh|fish` — generates shell tab-completion scripts
- `innerwarden configure` — interactive menu for all integrations; sub-commands for AI, Telegram, Slack, webhook, dashboard, AbuseIPDB, GeoIP, fail2ban, watchdog
- `innerwarden scan` — probes the machine and scores all built-in modules by relevance
- `innerwarden ai install` — configures Ollama cloud as AI provider (free tier, no GPU)

### Module system

New built-in modules: `wazuh-integration`, `nginx-error-monitor`, `falco-integration`, `suricata-integration`, `osquery-integration`, `slack-notify`, `fail2ban-integration`, `geoip-enrichment`, `abuseipdb-enrichment`, `crowdsec-integration`, `cloudflare-integration`

### Test coverage

502 tests across three crates (185 sensor + 178 agent + 139 ctl).

---

## [0.1.0] — 2026-03-15

Initial public release.

### Sensor (`innerwarden-sensor`)

- SSH brute-force detector (sliding window per IP, configurable threshold)
- SSH credential-stuffing detector (distinct users per IP in window)
- Port scan detector via firewall log signals (journald kernel unit)
- sudo abuse detector (burst of suspicious privileged commands per user)
- Search abuse detector (nginx access log rate-limit per IP+path)
- Auth log collector (`/var/log/auth.log` tail with full SSH parser)
- journald collector (sshd, sudo, kernel, any systemd unit)
- Docker events collector (start / stop / die / OOM)
- File-integrity collector (SHA-256 polling, configurable paths)
- Shell audit trail via auditd `EXECVE` (opt-in, explicit privacy gate)
- TTY ingestion via auditd `type=TTY` (opt-in, high privacy impact gate)
- nginx access log collector (Combined Log Format → `http.request` events)
- Falco JSON log collector (syscall anomaly events with severity mapping)
- Suricata EVE JSON collector (alert / dns / http / tls / anomaly event types)
- osquery result log collector (listening ports, crontabs, startup items, etc.)
- JSONL append-only output with automatic daily rotation
- Graceful shutdown (SIGINT/SIGTERM) with cursor persistence
- Fail-open design: collector I/O errors logged, never crash the process

### Agent (`innerwarden-agent`)

**AI decision engine**
- Multi-provider AI: OpenAI (gpt-4o-mini default), Anthropic (claude-haiku-4-5-20251001), Ollama (local/air-gapped)
- Algorithm gate: skips Low/Medium incidents, private IPs, already-blocked IPs — zero API cost
- Decision cooldown (1 h) to suppress repeated AI calls for the same scope
- Confidence threshold enforcement: `auto_execute` only when `confidence ≥ threshold`
- AI decision sanitisation: `block_ip` without `target_ip` downgraded to `ignore`
- Prompt injection hardening: free-text truncation + explicit system-prompt guard
- Temporal correlation of incidents by pivot (ip / user / detector) for richer AI context

**Response skills (open-core)**
- `block-ip-ufw` — immediate IP block via ufw (Open)
- `block-ip-iptables` — immediate IP block via iptables (Open)
- `block-ip-nftables` — immediate IP block via nftables (Open)
- `suspend-user-sudo` — temporary sudo denial via `/etc/sudoers.d` drop-in with auto-expiry TTL (Open)
- `rate-limit-nginx` — HTTP 403 deny at nginx layer with TTL + auto-cleanup (Open)
- `monitor-ip` — bounded network capture via tcpdump + metadata sidecar (Premium)
- `honeypot` — multi-service decoy listener with SSH key-exchange capture (russh), HTTP login-form capture, containment profiles (`process` / `namespace` / `jail`), and optional HMAC-attested external handoff (Premium)

**Operator communication**
- Webhook HTTP POST with minimum-severity filter and configurable timeout
- Telegram T.1: real-time push notifications for High/Critical incidents via Bot API
- Telegram T.2: inline keyboard approval workflow — pending actions with configurable TTL, `approve:id` / `reject:id` callback handling, audit trail with `ai_provider: "telegram:<operator>"`

**Dashboard (local, authenticated)**
- HTTP Basic auth (Argon2 hash) — read-only by default
- D2 entity journey viewer: IP/user timeline with verdict card and chapter rail
- D3 operator actions: block-IP and suspend-user directly from the dashboard (requires `responder.enabled = true`)
- D4 visual redesign: navy palette, radial ambient gradients, mobile-responsive layout
- D5 attacker path viewer: entry vector, access status, privilege status, containment assessment
- D6 live push via Server-Sent Events (SSE): `GET /api/events/stream`, 2 s file watcher, 30 s heartbeat
- D7 live timeline: incremental card updates with slide-in animation and KPI flash on change
- D8 incident alert toasts: High/Critical push with coloured badge and entity deep-link
- D9 inline entity search: client-side filter, no reload, re-applied after live refresh

**Observability and operations**
- Append-only audit trail: `decisions-YYYY-MM-DD.jsonl` (immediate flush per decision)
- Operational telemetry: `telemetry-YYYY-MM-DD.jsonl` with ingest/detect/gate/AI/latency metrics
- Daily Markdown narrative: `summary-YYYY-MM-DD.md` with 5 min write throttle
- Trial report (`--report`): day-over-day deltas, anomaly hints, 6 h recent window, JSON + Markdown output
- Incremental JSONL reader with byte-offset cursors; fail-open on corrupt state
- `--once` mode for batch processing
- Auto-load `.env` on startup (dotenvy, fail-silent)

### Control plane (`innerwarden` / `innerwarden-ctl`)

- `innerwarden enable <capability>` / `disable` — atomic TOML config patch + sudoers drop-in + service restart
- `innerwarden status` — global overview: services + capabilities + modules
- `innerwarden doctor` — diagnostic checks with fix hints (exit 1 on issues):
  - Service health, data directory, config readability
  - AI provider-aware API key validation (OpenAI `sk-` prefix, Anthropic `sk-ant-` prefix)
  - Telegram bot config with `@BotFather` / `@userinfobot` step-by-step hints
  - Integration health: Falco (`json_output: true`), Suricata (ET rules, EVE log), osquery (schedule config, results log)
- `innerwarden upgrade` — GitHub API version check + SHA-256-validated binary download + atomic install
- `innerwarden module` — install / uninstall / publish / update-all / validate / list for packaged modules

### Module system

Built-in modules (initial): `ssh-protection`, `network-defense`, `sudo-protection`, `file-integrity`, `container-security`, `threat-capture`, `search-protection`, `execution-guard`

Each module ships: `module.toml` manifest, config examples, documentation, and tests.

### Infrastructure

- Cross-compile for x86_64 and aarch64 via `cargo-zigbuild` + zig
- GitHub Actions release CI: 6 binaries + SHA-256 sidecars + `install.sh` on tag push
- `install.sh`: downloads pre-built binaries by default (~10 s); `--with-integrations` flag detects and offers Falco / Suricata / osquery installation + collector config patches
- `make replay-qa`: end-to-end fixture replay (auth_log + falco_log + suricata_eve + osquery_log → sensor → agent → report assertions)
- `make rollout-precheck` / `postcheck` / `rollback`: production rollout smoke tests

### Test coverage

374 tests across three crates (145 agent + 116 ctl + 113 sensor) at time of release.

---

[Unreleased]: https://github.com/maiconburn/innerwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/maiconburn/innerwarden/releases/tag/v0.1.0
