# Inner Warden — Developer Handbook

Self-defending security agent for Linux and macOS. Two Rust daemons (**sensor** + **agent**) plus a CLI (`innerwarden`).

For user-facing overview, install instructions, and feature summary: see `README.md`.

---

## Workspace

```
crates/
  core/     — shared types: Event, Incident, EntityRef, Severity, EntityType
  sensor/   — innerwarden-sensor binary (deterministic collection, zero AI/HTTP)
  agent/    — innerwarden-agent binary (AI triage, skill execution, dashboard, notifications)
  ctl/      — innerwarden / innerwarden-ctl binary (control plane CLI)
modules/    — vertical security modules (manifest + config + docs + tests)
integrations/ — declarative integration recipes for external tools
docs/
  internal/ — detailed capability and operations references (this file's companions)
  *.md      — public documentation
examples/   — systemd service files
scripts/    — replay QA, rollout smoke checks
testdata/   — fixture files for tests
```

### Sensor source layout (`crates/sensor/src/`)

```
collectors/
  auth_log.rs          nginx_access.rs      falco_log.rs
  journald.rs          nginx_error.rs       suricata_eve.rs
  exec_audit.rs        syslog_firewall.rs   wazuh_alerts.rs
  docker.rs            macos_log.rs         osquery_log.rs
  integrity.rs         cloudtrail.rs
detectors/
  ssh_bruteforce.rs    search_abuse.rs      execution_guard.rs
  credential_stuffing.rs  web_scan.rs       user_agent_scanner.rs
  port_scan.rs         sudo_abuse.rs
sinks/
  jsonl.rs             state.rs
```

### Agent source layout (`crates/agent/src/`)

```
ai/
  mod.rs (AiProvider trait, gate, factory)
  openai.rs   anthropic.rs   ollama.rs
skills/builtin/
  block_ip_ufw.rs   block_ip_iptables.rs   block_ip_nftables.rs   block_ip_pf.rs
  suspend_user_sudo.rs   monitor_ip.rs   kill_process.rs   block_container.rs
  honeypot/ (mod.rs, ssh_interact.rs, http_interact.rs)
dashboard.rs   report.rs        data_retention.rs
correlation.rs telemetry.rs     narrative.rs
webhook.rs     decisions.rs     reader.rs
telegram.rs    slack.rs         cloudflare.rs
abuseipdb.rs   geoip.rs         fail2ban.rs
```

### CTL source layout (`crates/ctl/src/`)

```
main.rs              capability.rs        config_editor.rs
preflight.rs         sudoers.rs           systemd.rs
scan.rs              module_manifest.rs   module_validator.rs
capabilities/
  ai.rs   block_ip.rs   sudo_protection.rs   shell_audit.rs   search_protection.rs
```

---

## Essential Commands

```bash
make test             # run all tests (must pass before committing)
make build            # debug build — sensor + agent + ctl
make run-sensor       # sensor with config.test.toml, writes to ./data/
make run-agent        # agent reading ./data/
make replay-qa        # end-to-end multi-source replay validation
```

See [docs/internal/operations.md](docs/internal/operations.md) for full command reference, deployment, and permissions.

---

## Architecture Summary

**Sensor** — collects host activity (auth_log, journald, docker, integrity, exec_audit, nginx, firewall logs) via `mpsc::channel(1024)`, passes through stateful detectors (ssh_bruteforce, credential_stuffing, port_scan, sudo_abuse, etc.), writes `events-*.jsonl` + `incidents-*.jsonl`.

**Agent** — reads incrementally via byte-offset cursors. Fast loop (2s): webhook + Telegram → algorithm gate → enrichment (AbuseIPDB, GeoIP) → AI provider → skill executor → audit trail → notifications. Slow loop (30s): narrative, telemetry, data retention.

**CTL** — control plane CLI: capability enable/disable, module management, diagnostics, upgrade, notifications setup, IP management, reporting, tuning.

---

## Conventions

- **Commits in English** — no other language in messages.
- **CLAUDE.md always updated** — required part of the development process.
- **Sensor**: deterministic, no HTTP/LLM/AI. Collectors are fail-open.
- **Agent**: interpretive layer. May call external APIs.
- Each collector: `run(tx, shared_state)` — async, never crashes the process.
- I/O errors in sinks: log with `warn!`, do not propagate with `?`.
- New event types: `source` describes origin, `kind` describes the event.
- `Event.details`: keep small (< 16KB). No arbitrary payloads.
- `spawn_blocking` for any synchronous file I/O inside Tokio tasks.
- AI provider in `AgentState` uses `Arc<dyn AiProvider>` (not `Box`) — avoids borrow conflicts in async loops.

---

## Development Process

For each feature or fix, in this order:

```
1. implement
2. make test         ← all tests must pass before committing
3. update CLAUDE.md  ← required: capabilities, workspace, config, next steps
4. git commit (English)
5. git push
```

---

## Detailed References

| Document | Content |
|----------|---------|
| [docs/internal/sensor-capabilities.md](docs/internal/sensor-capabilities.md) | All sensor collectors, detectors, output format |
| [docs/internal/agent-capabilities.md](docs/internal/agent-capabilities.md) | Agent pipeline, AI providers, skills, dashboard, notifications |
| [docs/internal/configuration.md](docs/internal/configuration.md) | Full TOML config reference + environment variables |
| [docs/internal/operations.md](docs/internal/operations.md) | CLI reference, build, deploy, permissions, service management |
| [docs/module-authoring.md](docs/module-authoring.md) | Guide for creating new modules |
| [docs/integration-recipes.md](docs/integration-recipes.md) | Declarative integration recipe format |
| [docs/integrated-setup.md](docs/integrated-setup.md) | Ubuntu 22.04 setup: Falco + Suricata + osquery + Telegram |
| [ROADMAP.md](ROADMAP.md) | Active roadmap and planned phases |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
