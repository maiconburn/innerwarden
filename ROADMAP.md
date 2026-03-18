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

## v0.2.0 — Operator experience (shipped)

- ✅ **`innerwarden module search`** — central community registry; `search <term>` lists modules with install URL
- ✅ **Ollama provider** — local/offline AI (cloud and self-hosted modes)
- ✅ **Dashboard D11** — browser push notifications (Web Notifications API)
- ✅ **Structured allowlists** — per-user/per-IP/per-pattern temporary and permanent exceptions

---

## v0.2.1 — Active response expansion (shipped)

- ✅ **`kill-process` skill** — kills all processes owned by a user via `pkill -9 -u <user>`; AI action `KillProcess`; applicable to `suspicious_execution` / `execution_guard`
- ✅ **`block-container` skill** — pauses a Docker container via `docker pause` with TTL and auto-unpause; AI action `BlockContainer`
- ✅ **AWS CloudTrail collector** — polls a directory of pre-extracted CloudTrail JSON files; maps login failures, IAM changes, security group changes, root usage, secrets access, and audit tampering to InnerWarden events
- ✅ **`execution_guard` active response** — `KillProcess` and `BlockContainer` skills are now tagged applicable to `execution_guard` detector incidents

---

## v0.3.0 — Windows + Cloud

- 📋 **Windows support** — Sysmon + Windows Event Log collectors, `block-ip-netsh` skill
- ✅ **AWS CloudTrail collector** — shipped in v0.2.1 (see above)
- 📋 **GCP Cloud Audit Logs, Azure Activity Log** — planned
- 📋 **Kubernetes** — kube-audit collector (Falco integration already covers eBPF)

---

## Under consideration

- 💡 **cgroups / eBPF native sensor** — bypass auditd for lower overhead process tracing
- 💡 **Multi-host agent** — single agent reading from multiple sensor data directories
- 💡 **gRPC streaming** — replace JSONL polling with push-based sensor-to-agent transport

---

## How to influence the roadmap

Open an issue or start a GitHub Discussion. Items with real-world use cases and contributor interest move up.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
