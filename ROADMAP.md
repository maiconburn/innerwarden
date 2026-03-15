# Roadmap

This document tracks what is planned, in progress, and under consideration for InnerWarden.

It is intentionally high-level. Implementation details live in code, commits, and issues.

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

- ✅ Sensor: auth.log, journald, Docker, file integrity, exec audit, nginx access
- ✅ Detectors: SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- ✅ Agent: AI-assisted decisions (OpenAI, Anthropic), algorithm gate, cooldown, blocklist
- ✅ Skills: block-ip (ufw/iptables/nftables/pf), suspend-user-sudo, rate-limit-nginx, monitor-ip, honeypot
- ✅ Honeypot: banner + medium interaction (SSH key exchange + HTTP login decoy), containment, attested handoff
- ✅ Dashboard: investigation UI (D1–D9), SSE live push, attacker path viewer, operator actions, Report tab
- ✅ Integrations: Falco, Suricata, osquery collectors + incident passthrough
- ✅ Telegram: one-way alerts (T.1) + approval workflow (T.2)
- ✅ Module system: manifest, validate, install, uninstall, publish, update-all
- ✅ CTL: enable/disable capabilities, doctor, upgrade
- ✅ Cross-platform: Linux (x86_64 + arm64) + macOS (x86_64 + arm64) binaries via CI
- ✅ install.sh: binary download, systemd/launchd, platform detection

---

## v0.2.0 — Operator experience

- 📋 **`innerwarden module search`** — central community registry; `search <term>` lists modules with install URL
- 📋 **Ollama provider** — local/offline AI via Ollama (currently a stub)
- 📋 **`innerwarden doctor` integration checks** — Falco service active, Suricata eve.json accessible, osquery results log reachable
- 📋 **Dashboard D11** — Web Notifications API push when dashboard is in background
- 📋 **Windows v0.3.0 planning** — Sysmon collector, Windows Event Log collector, block-ip-netsh skill

---

## v0.3.0 — Windows + Cloud

- 📋 **Windows support** — Sysmon + Windows Event Log collectors, `block-ip-netsh` skill
- 📋 **Cloud audit log collectors** — AWS CloudTrail (S3/CloudWatch), GCP Cloud Audit Logs (Pub/Sub), Azure Activity Log (Event Hub)
- 📋 **Kubernetes** — Falco integration already covers eBPF; kube-audit collector planned

---

## Under consideration

- 💡 **cgroups / eBPF native sensor** — bypass auditd for lower overhead process tracing
- 💡 **Structured allowlists** — per-user/per-IP/per-pattern temporary and permanent allowlists managed via CTL
- 💡 **Multi-host agent** — single agent reading from multiple sensor data directories
- 💡 **gRPC streaming** — replace JSONL polling with push-based sensor→agent transport

---

## How to influence the roadmap

Open an issue or start a GitHub Discussion. Items with the most real-world use cases and contributor interest move up.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
