# Inner Warden — Roadmap

## Vision

A self-defending server that collaborates with other servers to form an autonomous defense network. No cloud. No vendor. Every node is both defender and intelligence source.

---

## Phase 1 — Foundation (DONE)

Everything shipped in v0.1.x:

- [x] 14 stateful detectors (SSH brute-force, credential stuffing, port scan, web scan, sudo abuse, execution guard, distributed SSH, suspicious login, integrity, docker anomaly, suricata, osquery, user-agent scanner)
- [x] 8 response skills (block IP, suspend sudo, kill process, block container, rate-limit nginx, monitor IP, honeypot with fake shell, traffic capture)
- [x] 12 AI providers with dynamic model discovery
- [x] Telegram bot with personality and approve/deny buttons
- [x] Honeypot with fake filesystem (/proc, /sys, 25+ commands, LLM fallback)
- [x] check-command API for AI agent validation (OpenClaw integration)
- [x] CrowdSec community intelligence (lookup table)
- [x] AbuseIPDB enrichment + report-back
- [x] Cloudflare WAF push
- [x] Prometheus /metrics endpoint
- [x] PagerDuty + Opsgenie webhook formats
- [x] Dashboard with investigation timeline, attacker path viewer, SSE live push
- [x] jemalloc allocator, under 50 MB RAM
- [x] 669 tests, 6 platforms

---

## Phase 2 — Deep Visibility (eBPF) (DONE)

**Goal:** See everything at the kernel level — before logs are written.

- [x] eBPF sensor using Aya (Rust eBPF framework)
  - `sys_enter_execve` — every process execution in real time
  - `sys_enter_connect` — every outbound network connection
  - `sys_enter_openat` — sensitive file access patterns
- [x] Process tree tracking — ppid chain, suspicious parent-child detection (web server → shell, database → shell, Java RCE)
- [x] File access monitoring — real-time via openat tracepoint, sensitive path filtering in kernel space
- [x] Network connection tracking — C2 callback detection (beaconing, C2 ports, data exfiltration)
- [x] Container-aware context — cgroup_id from kernel, container ID resolution, container escape detection
- [x] 3 new detectors: c2_callback, process_tree, container_escape

---

## Phase 3 — Collaborative Defense Network

**Goal:** Servers protect each other. Attack one, alert all.

- [ ] Mesh protocol — peer-to-peer encrypted communication between nodes
- [ ] Threat signal sharing — not just IPs, but TTPs, confidence scores, honeypot evidence
- [ ] Collective blocklist — distributed, reputation-scored, TTL-based
- [ ] Coordinated honeypot — multiple nodes deploy traps for the same attacker
- [ ] Threat escalation — auto-escalate when multiple nodes see the same attacker

---

## Phase 4 — Malware Analysis

- [ ] YARA rule engine — scan files against community rules
- [ ] Binary behavior analysis — sandbox suspicious binaries
- [ ] Payload capture from honeypot — capture and analyze what attackers download
- [ ] Hash reputation — VirusTotal / MalwareBazaar integration
- [ ] Auto-quarantine with audit trail

---

## Phase 5 — Enterprise

- [ ] Multi-server dashboard — single view for all mesh nodes
- [ ] Role-based access control
- [ ] Compliance reports (PCI-DSS, SOC 2, ISO 27001)
- [ ] SIEM export (Elasticsearch, Splunk, Loki)
- [ ] Managed offering — hosted dashboard + mesh relay

---

## Timeline

| Phase | Status | Target |
|-------|--------|--------|
| Phase 1 — Foundation | Done | v0.1.x |
| Phase 2 — eBPF | Done | v0.2.x |
| Phase 3 — Mesh Network | Planned | v0.3.x |
| Phase 4 — Malware Analysis | Planned | v0.4.x |
| Phase 5 — Enterprise | Future | v1.0 |

---

## Contributing

We welcome contributions at any phase. See [CONTRIBUTING.md](CONTRIBUTING.md).
