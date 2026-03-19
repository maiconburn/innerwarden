# Roadmap

This document tracks what is planned, in progress, and under consideration for InnerWarden — a self-defending security agent for Linux and macOS.

This roadmap is high-level only; implementation details live in the code, commits, and issues.

---

## Status legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Shipped |
| 🔄 | In progress |
| 📋 | Planned |
| 💡 | Under consideration |

---

## Phase 1 — Foundation (shipped, v0.1.0–v0.1.25)

**Detection (8 detectors):**
- ✅ SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- ✅ `execution_guard` — shell command AST analysis via tree-sitter-bash (observe + active response)
- ✅ `web_scan` — HTTP error floods per IP
- ✅ `user_agent_scanner` — 20 known scanner signatures (Nikto, sqlmap, Nuclei, etc.)

**Collection (15 collectors):**
- ✅ auth_log, journald, Docker, file integrity, nginx access/error, exec audit
- ✅ macOS unified log, syslog/kern.log firewall
- ✅ Falco, Suricata EVE, osquery, Wazuh alerts
- ✅ AWS CloudTrail (IAM changes, root usage, audit tampering)

**Response skills (8 skills):**
- ✅ Block IP (ufw / iptables / nftables / pf)
- ✅ Suspend user sudo (TTL-based, auto-cleanup)
- ✅ Rate limit nginx (HTTP 403 deny with TTL)
- ✅ Monitor IP (bounded tcpdump capture + metadata)
- ✅ Kill process (pkill by user, TTL metadata)
- ✅ Block container (docker pause with auto-unpause)
- ✅ Honeypot — SSH/HTTP decoy with LLM-powered shell, always-on mode, IOC extraction, post-session auto-block

**AI decision engine:**
- ✅ OpenAI, Anthropic, Ollama providers
- ✅ Algorithm gate, decision cooldown, confidence threshold, blocklist
- ✅ DDoS protection: auto-block threshold, max AI calls per tick, circuit breaker
- ✅ Temporal correlation of incidents by pivot (ip/user/detector)

**Operator tools:**
- ✅ Telegram alerts + inline approve/deny + conversational bot (/status, /incidents, /decisions, /ask)
- ✅ Slack notifications (Block Kit, severity colours)
- ✅ Webhook HTTP POST with severity filter
- ✅ Web Push notifications (VAPID/RFC 8291, service worker)
- ✅ Dashboard: investigation UI, SSE live push, operator actions, entity search, honeypot tab, attacker path viewer, health/integration panels, mobile-responsive
- ✅ Notification cooldown (10 min dedup per detector+entity)

**Integrations:**
- ✅ Fail2ban sync, AbuseIPDB enrichment, GeoIP enrichment
- ✅ CrowdSec community threat intel
- ✅ Cloudflare edge blocking via IP Access Rules API

**CTL (control plane CLI):**
- ✅ enable/disable, setup wizard, doctor diagnostics, self-upgrade (SHA-256)
- ✅ scan advisor (NATIVE/EXTERNAL badges, conflict detection, activation sequence)
- ✅ incidents, decisions, entity timeline, block/unblock, export, tail, report, tune, watchdog
- ✅ `innerwarden test` — pipeline test (synthetic incident → agent decision verification)
- ✅ Structured allowlists (IP/CIDR + users, CLI add/remove/list)

**AI agent protection:**
- ✅ `openclaw-protection` module — pre-configured for OpenClaw, n8n, Langchain, or any autonomous AI agent
- ✅ Agent API: `/api/agent/security-context`, `/api/agent/check-ip`, `/api/agent/check-command`
- ✅ `check-command` static analysis: reverse shells, download+execute, staged attacks, obfuscation, persistence, destructive ops

**Module system:**
- ✅ 20 built-in modules with manifest, validate, install/uninstall, publish, update-all
- ✅ Community module contribution workflow (CI validation, PR template)

**Platform & CI:**
- ✅ Linux (x86_64 + arm64) + macOS (x86_64 + arm64) binaries via GitHub Actions
- ✅ install.sh with `--with-integrations` flag
- ✅ replay-qa CI job for end-to-end validation
- ✅ 609 tests across four crates

---

## Phase 2 — Hardening & polish (next)

**Detection improvements:**
- 📋 **Falco alert detector** — promote high-severity Falco runtime alerts into incidents with automated response (block-ip, kill-process)
- 📋 **osquery anomaly detector** — detect new SUID binaries, unauthorized SSH keys, unexpected listening ports from osquery differential results
- 📋 **Detector auto-tuning** — adaptive thresholds based on baseline traffic (currently manual via `innerwarden tune`)
- 📋 **`execution_guard` block mode** — move from observe/kill to pre-exec block via seccomp-notify or eBPF
- 📋 **DNS anomaly detector** — detect DNS exfiltration and C2 beaconing patterns

**Response improvements:**
- 📋 **Skill undo timeline** — dashboard UI showing active blocks/suspensions with one-click undo and remaining TTL
- 📋 **Honeypot intelligence feed** — aggregate IOCs from honeypot sessions into a local threat intel database for cross-incident correlation
- 📋 **Rate limiter for HAProxy/Caddy** — extend rate-limit skill beyond nginx

**Dashboard & UX:**
- 📋 **Report tab in dashboard** — render daily/weekly Markdown summaries as HTML with charts
- 📋 **MITRE ATT&CK mapping view** — visual heatmap of detected techniques across the ATT&CK matrix
- 📋 **Alert rules editor** — configure notification filters and routing from the dashboard instead of TOML
- 📋 **Dark mode**

**CTL & operations:**
- 📋 **`innerwarden backup / restore`** — export/import config + allowlists + decisions for migration
- 📋 **`innerwarden replay <file>`** — replay arbitrary log files through the sensor for testing/forensics
- 📋 **Structured logging for agent** — machine-readable agent logs (currently human-readable only)

**Quality:**
- 📋 **Integration tests with real firewall** — CI job that runs block/unblock against ufw in a container
- 📋 **Fuzz testing** — fuzz all log parsers (auth_log, nginx, syslog, CloudTrail)
- 📋 **Benchmarks** — continuous perf tracking for sensor throughput and agent decision latency

---

## Phase 3 — Multi-platform & cloud

- 📋 **Windows support** — Sysmon + Windows Event Log collectors, `block-ip-netsh` skill, Windows service (sc.exe)
- 📋 **GCP Cloud Audit Logs collector** — similar to CloudTrail, maps IAM/compute/storage events
- 📋 **Azure Activity Log collector** — Azure-specific event mapping
- 📋 **Kubernetes kube-audit collector** — pod lifecycle, RBAC changes, secret access (Falco integration already covers eBPF)
- 📋 **AWS WAF skill** — push block decisions to AWS WAF rules (complement to Cloudflare integration)

---

## Phase 4 — Scale & fleet

- 💡 **Multi-host agent** — single agent reading from multiple sensor data directories or remote sensors
- 💡 **gRPC streaming** — replace JSONL polling with push-based sensor-to-agent transport
- 💡 **Central dashboard** — aggregate incidents/decisions from multiple hosts into one view
- 💡 **Fleet management** — `innerwarden fleet status`, push config updates to multiple hosts
- 💡 **SIEM export** — forward events to Splunk, Elastic, or Loki in real time

---

## Under consideration

- 💡 **cgroups / eBPF native sensor** — bypass auditd for lower overhead process tracing
- 💡 **YARA rule scanner** — file-based malware detection as a collector
- 💡 **Incident playbooks** — user-defined response chains (detect → enrich → block → notify → honeypot)
- 💡 **REST API for external automation** — authenticated API for SOAR integration
- 💡 **Agent API: check-command with AST** — upgrade `/api/agent/check-command` to use tree-sitter-bash for full structural analysis
- 💡 **Agent API: bidirectional webhook** — Inner Warden notifies OpenClaw/n8n when threat detected, agent pauses risky operations automatically
- 💡 **Package manager distribution** — Homebrew tap, APT/RPM repos, AUR

---

## How to influence the roadmap

Open an issue or start a GitHub Discussion. Items with real-world use cases and contributor interest move up.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
