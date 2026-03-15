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

## v0.1.0 — Foundation (shipped)

**Detection:**
- ✅ SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse detectors
- ✅ `execution_guard` — shell command AST analysis via tree-sitter-bash (observe mode)
- ✅ Collectors: auth.log, journald, Docker, file integrity, nginx, exec audit, macOS unified log

**Response skills:**
- ✅ Block IP (ufw / iptables / nftables / pf)
- ✅ Suspend user sudo (TTL-based, auto-cleanup)
- ✅ Rate limit nginx (HTTP 403 deny with TTL)
- ✅ Monitor IP (bounded tcpdump capture + metadata)
- ✅ Honeypot — SSH/HTTP decoy with containment profiles and forensic handoff

**AI decision engine:**
- ✅ OpenAI, Anthropic, Ollama providers
- ✅ Algorithm gate, decision cooldown, confidence threshold, blocklist

**Operator tools:**
- ✅ Telegram alerts + inline approve/deny workflow
- ✅ Local authenticated dashboard with investigation UI, SSE live push, operator actions
- ✅ CTL: enable/disable capabilities, doctor diagnostics, self-upgrade

**Integrations:**
- ✅ Falco, Suricata, osquery collectors with incident passthrough
- ✅ Module system: manifest, validate, install/uninstall, publish, update-all

**Platform:**
- ✅ Linux (x86_64 + arm64) + macOS (x86_64 + arm64) binaries via CI
- ✅ install.sh: binary download, systemd/launchd, platform detection

---

## v0.2.0 — Operator experience

- 📋 **`innerwarden module search`** — central community registry; `search <term>` lists modules with install URL
- 📋 **Ollama provider** — local/offline AI (currently a stub)
- 📋 **Dashboard D11** — browser push notifications (Web Notifications API)
- 📋 **Structured allowlists** — per-user/per-IP/per-pattern temporary and permanent exceptions

---

## v0.3.0 — Windows + Cloud

- 📋 **Windows support** — Sysmon + Windows Event Log collectors, `block-ip-netsh` skill
- 📋 **Cloud audit log collectors** — AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity Log
- 📋 **Kubernetes** — kube-audit collector (Falco integration already covers eBPF)

---

## Under consideration

- 💡 **cgroups / eBPF native sensor** — bypass auditd for lower overhead process tracing
- 💡 **Multi-host agent** — single agent reading from multiple sensor data directories
- 💡 **gRPC streaming** — replace JSONL polling with push-based sensor-to-agent transport
- 💡 **Container isolation skill** — pause/stop Docker containers in response to anomalies

---

## How to influence the roadmap

Open an issue or start a GitHub Discussion. Items with real-world use cases and contributor interest move up.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
