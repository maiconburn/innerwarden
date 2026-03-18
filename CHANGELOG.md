# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
