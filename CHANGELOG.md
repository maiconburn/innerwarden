# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.4] — 2026-03-19

### New commands
- **`innerwarden backup`** — archive configs to tar.gz for safe upgrades
- **`innerwarden metrics`** — events per collector, incidents per detector, AI latency, uptime

### Security hardening
- **Disk exhaustion protection** — events file capped at 200MB/day, auto-pauses writes
- **Constant-time auth** — dashboard username comparison prevents timing attacks
- **Prompt sanitization on all providers** — Anthropic provider now sanitizes attacker-controlled strings (was OpenAI/Ollama only)

### Performance
- **Dashboard 15x faster** — overview loads in 0.2s instead of 3s by counting lines instead of parsing 165MB of events JSON

### New detector
- **osquery anomaly** — promotes High/Critical osquery events (sudoers, SUID, authorized_keys, crontab) to incidents

### Fixes
- **install.sh preserves configs** — detects existing installation and skips config overwrite on upgrade
- **Dashboard protection-first UX** — hero shows "Server Protected" with containment rate, resolved incidents faded

---

## [0.1.3] — 2026-03-19

### Security hardening

- **Dashboard login rate limiting** — after 5 failed login attempts within 15 minutes, the IP is blocked from trying again. Returns HTTP 429. Prevents brute-force on the dashboard itself.
- **Ban escalation for repeat offenders** — when an IP is blocked more than once, the decision reason is annotated with "repeat offender (blocked N times)". Flows through to Telegram, audit trail, and AbuseIPDB reports.
- **Dashboard HTTPS warning** — warns when the dashboard runs with auth on a non-localhost address over HTTP. Credentials would be sent in plaintext.
- **AI prompt injection sanitization** — attacker-controlled strings (usernames, paths, summaries) are sanitized before injection into the AI prompt. Control characters stripped, whitespace normalized.

### CrowdSec integration

- CrowdSec installed and enrolled on production server. Community blocklist flowing — known bad IPs are blocked preventively before they attack.

### Other

- Data retention enabled (7-day auto-cleanup of JSONL files)
- Watchdog cron (10-min health check, auto-restart + Telegram alert)
- OpenClaw skill published on ClawHub (innerwarden-security v1.0.3, "Benign" verdict)

---

## [0.1.2] — 2026-03-19

### NPM log support
- **Nginx Proxy Manager format** — the nginx_access collector now auto-detects and parses NPM log format (`[Client IP]` style). Sites behind Docker NPM are now protected by search_abuse, user_agent_scanner, and web_scan detectors.

### Bot detection
- **Known good bot whitelist** — 25+ legitimate crawlers (Google, Bing, DuckDuckGo, etc.) excluded from abuse detection.
- **rDNS verification** — for major search engine bots, the sensor verifies the IP via reverse DNS. Fake Googlebots (spoofed user-agent) are tagged `bot:spoofed` and treated as attackers.

### OpenClaw integration
- **innerwarden-security skill** — OpenClaw skill that installs Inner Warden, validates commands, monitors health, and fixes issues. Auto-detects AI provider. Prompt injection defense built in.

### Fixes
- **All strings in English** — removed all Portuguese from dashboard, Telegram, and agent messages.
- **max_completion_tokens** — auto-detects newer OpenAI models (gpt-5.x, o1, o3) that require the new parameter.
- **systemd dependency** — agent no longer dies when sensor restarts (Requires → Wants).

---

## [0.1.1] — 2026-03-18

### New detectors

- **Suricata IDS detector** — repeated alerts from same source IP → incident → block-ip
- **Docker anomaly detector** — rapid container restarts / OOM kills → incident → block-container
- **File integrity detector** — any change to monitored files (passwd, shadow, sudoers) → Critical incident

### Telegram follow-up

- **Fail2ban block notifications** — when fail2ban blocks an IP, Telegram now sends a follow-up message confirming the block or reporting failures. Previously only the initial "Live threat" alert was sent.

### Dashboard

- **Incident outcome field** — API now returns `outcome` (blocked/suspended/open) and `action_taken` for each incident by cross-referencing decisions.

### Fixes

- **install.sh: remove NoNewPrivileges from agent service** — the flag prevented sudo from working, breaking all response skills (ufw, iptables, sudoers). Sensor keeps the restriction.
- **Falco and osquery docs** — honest "Current Limitations" sections explaining they provide context but don't trigger automated actions yet.

---

## [0.1.0] — 2026-03-18

First public release.

### Detection (8 detectors)

- SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- `execution_guard` — shell command AST analysis via tree-sitter-bash
- `web_scan` — HTTP error floods per IP
- `user_agent_scanner` — 20+ known scanner signatures (Nikto, sqlmap, Nuclei, etc.)

### Collection (15 collectors)

- auth_log, journald, Docker, file integrity, nginx access/error, exec audit
- macOS unified log, syslog/kern.log firewall
- Falco, Suricata EVE, osquery, Wazuh alerts
- AWS CloudTrail (IAM changes, root usage, audit tampering)

### Response skills (8 skills)

- Block IP (ufw / iptables / nftables / pf)
- Suspend user sudo (TTL-based, auto-cleanup)
- Rate limit nginx (HTTP 403 deny with TTL)
- Monitor IP (bounded tcpdump capture)
- Kill process (pkill by user, TTL metadata)
- Block container (docker pause with auto-unpause)
- Honeypot — SSH/HTTP decoy with LLM-powered shell, always-on mode, IOC extraction

### AI decision engine

- 12 providers: OpenAI, Anthropic, Groq, DeepSeek, Mistral, xAI/Grok, Google Gemini, Ollama, Together, MiniMax, Fireworks, OpenRouter — plus any OpenAI-compatible API
- Dynamic model discovery — wizard fetches available models from the provider API
- `innerwarden configure ai` — interactive wizard or direct CLI
- Algorithm gate, decision cooldown, confidence threshold, blocklist
- DDoS protection: auto-block threshold, max AI calls per tick, circuit breaker

### Collective defense

- AbuseIPDB enrichment + report-back — blocked IPs reported to global database
- Cloudflare WAF — blocks pushed to edge automatically
- GeoIP enrichment
- Fail2ban sync
- CrowdSec community threat intel

### Operator tools

- Telegram bot: alerts + approve/deny + conversational AI (/status, /incidents, /blocked, /ask)
- Slack notifications, webhook, browser push (VAPID/RFC 8291)
- Dashboard: investigation UI, SSE live push, operator actions, entity search, honeypot tab, attacker path viewer
- `innerwarden test` — pipeline test (synthetic incident → decision verification)

### Agent API for AI agents

- `GET /api/agent/security-context` — threat level and recommendation
- `GET /api/agent/check-ip?ip=X` — IP reputation check
- `POST /api/agent/check-command` — command safety analysis (reverse shells, download+execute, obfuscation, persistence, destructive ops)

### Control plane CLI

- enable/disable, setup wizard, doctor diagnostics, self-upgrade (SHA-256)
- scan advisor, incidents, decisions, entity timeline, block/unblock, export, tail, report, tune, watchdog
- Structured allowlists (IP/CIDR + users)
- `innerwarden configure ai` / `innerwarden configure responder`

### Module system

- 20 built-in modules with manifest, validate, install/uninstall, publish
- `openclaw-protection` module for AI agent environments

### Security CI

- cargo-deny: dependency advisories + license compliance
- gitleaks: secrets scanning
- Dependabot: weekly dependency updates

### Platform

- Linux (x86_64 + arm64) + macOS (x86_64 + arm64)
- 577 tests across four crates
