# Inner Warden

[![CI](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml)
[![Security](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/InnerWarden/innerwarden?label=release&color=blue)](https://github.com/InnerWarden/innerwarden/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/InnerWarden/innerwarden)](https://github.com/InnerWarden/innerwarden/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/InnerWarden/innerwarden)](https://github.com/InnerWarden/innerwarden/commits/main)

![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Memory](https://img.shields.io/badge/memory-under%2050MB-green)
![AI Optional](https://img.shields.io/badge/AI-optional-lightgrey)

**Your server should defend itself.**

Inner Warden is an autonomous security agent for Linux and macOS. It detects attacks, alerts you, and — when you allow it — responds automatically. No cloud. No dependencies. Just two Rust daemons and a CLI.

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

Installs in 10 seconds. Starts in observe-only mode. You decide when to go live.

<p align="center">
  <img src="docs/images/dashboard-threats.png" alt="Dashboard — real-time threat overview" width="820">
</p>
<p align="center">
  <img src="docs/images/dashboard-investigate.png" alt="Dashboard — IP investigation view" width="820">
</p>

---

## What it does

1. **Watches** — collects signals from your host: SSH, Docker, nginx, sudo, shell audit, firewall logs, **eBPF kernel tracing** (every process, connection, and file access)
2. **Detects** — nineteen stateful detectors identify brute-force, credential stuffing, port scans, C2 callbacks, privilege escalation, container escapes, suspicious process trees, and more
3. **Alerts you** — Telegram, Slack, browser push, webhook — real time, on your phone
4. **Decides** — optionally asks AI for a confidence-scored recommendation (not required)
5. **Acts** — blocks the IP, suspends sudo, deploys a honeypot, captures traffic. Or does nothing — your call.

Everything is local, audited, and reversible.

---

## What happens when your server is attacked

```
00:00  SSH brute-force begins from 203.0.113.10
00:45  Detector fires — 8 failed logins, 5 usernames, one IP

       AI evaluates: "coordinated brute-force"
       Confidence: 0.94
       Recommended action: block_ip

00:46  Firewall rule added: ufw deny from 203.0.113.10
00:46  Telegram alert lands on your phone
00:46  Decision logged to audit trail

       Threat contained.
```

No human needed when auto-execution is enabled. Otherwise, you approve via Telegram or the dashboard. Full audit trail. Every action reversible.

---

## Response skills

When a threat is confirmed, Inner Warden picks the right tool.

| Skill | What it does |
|-------|-------------|
| **Block IP (XDP)** | Wire-speed drop at the network driver — 10M+ packets/sec, zero CPU overhead |
| **Block IP (firewall)** | Deny via ufw, iptables, nftables, or pf (macOS). Persists across reboots. |
| **Suspend sudo** | Revokes sudo for a user via sudoers drop-in. Auto-expires after TTL. |
| **Kill process** | Terminates all processes for a compromised user. TTL-bounded. |
| **Block container** | Pauses a Docker container. Auto-unpauses after TTL. |
| **Deploy honeypot** | SSH/HTTP decoy with LLM-powered shell — captures credentials and behavior |
| **Rate limit nginx** | Blocks abusive HTTP traffic at the nginx layer with TTL |
| **Monitor IP** | Bounded tcpdump capture for forensic analysis |

Blocking is **layered** — a single block decision triggers XDP (instant kernel drop) + firewall (persists reboot) + Cloudflare edge (stops traffic upstream) + AbuseIPDB report (community intelligence). All skills are bounded, audited, and reversible.

---

## What it detects

| Detector | Threat | MITRE |
|----------|--------|-------|
| `ssh_bruteforce` | Repeated SSH failures from one IP | T1110.001 |
| `credential_stuffing` | Many usernames tried from one IP | T1110.004 |
| `port_scan` | Rapid unique-port probing | T1595 |
| `sudo_abuse` | Burst of privileged commands by a user | T1548 |
| `search_abuse` | High-rate requests to expensive endpoints | — |
| `execution_guard` | Suspicious shell commands via AST analysis | T1059 |
| `web_scan` | HTTP error floods — path traversal, LFI probing | T1190 |
| `user_agent_scanner` | Known scanner signatures (Nikto, sqlmap, Nuclei, 20+) with rDNS bot verification | T1595.002 |
| `suricata_alert` | Repeated IDS alerts from same source IP (Suricata integration) | — |
| `docker_anomaly` | Rapid container restarts, OOM kills | T1610 |
| `integrity_alert` | Changes to /etc/passwd, /etc/shadow, sudoers, SSH keys | T1098 |
| `osquery_anomaly` | New SUID binaries, unauthorized SSH keys, crontab changes | T1053 |
| `distributed_ssh` | Coordinated botnet scan — many IPs, few attempts each | T1110 |
| `suspicious_login` | Brute-force followed by successful login = compromise | T1110 |
| `c2_callback` | Beaconing, C2 port connections, data exfiltration patterns | T1071 |
| `process_tree` | Suspicious parent-child: web server → shell, Java RCE | T1059 |
| `container_escape` | nsenter, Docker socket access, host file reads from container | T1611 |
| `privesc` | Real-time privilege escalation via eBPF kprobe on `commit_creds` | T1068 |

`execution_guard` parses commands structurally using tree-sitter-bash. It catches `curl | sh` pipelines, `/tmp` execution, reverse shell patterns, and staged download-chmod-execute sequences.

`c2_callback` uses coefficient-of-variation analysis to detect beaconing — regular-interval connections to the same IP that indicate a compromised process phoning home.

`privesc` hooks the kernel's `commit_creds` function via kprobe. When a non-root process gains root through an unexpected path (not sudo/su/login), a Critical incident fires instantly — before any log is written.

---

## How it works

```
[Sensor]  →  [Detectors]  →  [AI triage]  →  [Skill execution]
 watch        identify        assess &         block / suspend /
 activity     patterns        recommend        honeypot / capture
```

**Sensor** — deterministic signal collection. No AI, no HTTP. Sources: auth.log, journald, Docker events, file integrity, nginx, shell audit, macOS unified log, syslog firewall, **eBPF syscall tracing** (execve, connect, openat). Optional: Falco, Suricata, osquery, Wazuh, AWS CloudTrail.

**eBPF** — six programs running inside the Linux kernel (5.8+):
- 3 **tracepoints** (execve, connect, openat) — sees every process, connection, and file access
- 1 **kprobe** (`commit_creds`) — detects privilege escalation in real time
- 1 **LSM hook** (`bprm_check_security`) — blocks execution from /tmp and /dev/shm at the kernel level
- 1 **XDP program** — wire-speed IP blocking at the network driver (10M+ pps drop rate)

All in 10KB of bytecode. Container-aware via cgroup ID. Zero performance overhead.

**Agent** — reads incidents, applies algorithm gate (skip low severity, private IPs, already-blocked), optionally sends to AI for confidence-scored triage, executes the chosen skill. Policy-gated: nothing runs unless you've explicitly enabled it.

Two Rust daemons. No external dependencies. Under 50 MB RAM total. Dashboard sleeps after 15 min of inactivity.

---

## AI is optional — and controlled

Inner Warden detects and logs threats without any AI provider. Add AI when you want:

- **Confidence-scored recommendations** — not binary yes/no, but 0.0–1.0 scored decisions
- **Policy-gated execution** — AI recommends, your policy decides if it runs
- **Full transparency** — every AI decision recorded in append-only JSONL with reasoning
- **Twelve providers** — OpenAI, Anthropic, Ollama (local), OpenRouter, Groq, Together, Mistral, DeepSeek, Fireworks, Cerebras, Google Gemini, xAI Grok

AI is advisory unless you explicitly enable auto-execution. You set the confidence threshold.

---

## Operator in the loop

Not everything should be automatic.

- **Telegram** — every High/Critical incident pushed to your phone. Approve or deny with inline buttons.
- **Slack** — incident notifications via incoming webhook
- **Browser push** — native Web Push (VAPID), no relay service
- **Webhook** — HTTP POST to any endpoint with severity filter
- **Dashboard** — local authenticated UI: investigation, entity search, operator actions, live SSE, attacker path viewer

---

## Safety model

Inner Warden starts in the safest possible posture.

| Default | Meaning |
|---------|---------|
| `responder.enabled = false` | No actions taken. Observe only. |
| `dry_run = true` | Logs what it *would* do, without doing it. |
| `execution_guard` in observe mode | Detects suspicious commands, does not block. |
| Shell audit opt-in | Requires explicit privacy consent. |
| AI optional | Detection and logging work without any provider. |
| Append-only audit trail | Every decision in `decisions-YYYY-MM-DD.jsonl`. |

Go live when you trust what you see:

```toml
[responder]
dry_run = false
```

---

## Modules

Enable what you need.

| Module | Threat | Response |
|--------|--------|----------|
| `ssh-protection` | SSH brute-force + credential stuffing | Block IP |
| `network-defense` | Port scanning | Block IP |
| `sudo-protection` | Sudo privilege abuse | Suspend user sudo |
| `execution-guard` | Malicious shell commands (AST) | Kill process / observe |
| `search-protection` | HTTP endpoint abuse | Rate limit nginx |
| `file-integrity` | Unauthorized file changes | Alert |
| `container-security` | Docker lifecycle anomalies | Block container / observe |
| `threat-capture` | Active threat investigation | Honeypot + traffic capture |
| `nginx-error-monitor` | HTTP error floods, path traversal | Block IP |
| `slack-notify` | Incident notifications | Slack webhook |
| `cloudflare-integration` | L7 DDoS / botnet IPs | Block at Cloudflare edge |
| `abuseipdb-enrichment` | IP reputation context | Enriched AI prompt |
| `geoip-enrichment` | Country/ISP geolocation | Enriched AI prompt |
| `fail2ban-integration` | Sync active fail2ban bans | Block enforcement |
| `crowdsec-integration` | CrowdSec community intel | Block enforcement (experimental) |
| `falco-integration` | Kernel/container anomalies | Incident passthrough |
| `suricata-integration` | Network IDS alerts | Incident passthrough |
| `osquery-integration` | Host state queries | Enriched events |
| `wazuh-integration` | Wazuh HIDS alerts | Incident passthrough |

```bash
innerwarden enable block-ip
innerwarden enable ssh-protection
innerwarden enable shell-audit       # prompts for privacy consent
```

Community modules:
```bash
innerwarden module install <url>     # SHA-256 verified
innerwarden module search <term>     # search the registry
```

---

## Protecting AI agents

If you run OpenClaw, n8n, Langchain, or any autonomous AI agent on your server, Inner Warden can watch what it does and stop it if something goes wrong.

```bash
innerwarden enable openclaw-protection
```

This enables real-time monitoring of every command your agent executes — using structural analysis (tree-sitter AST), not just regex. Download-and-execute pipelines, reverse shells, staged attacks, and obfuscated commands are caught before they can do damage.

### Let your agent ask before acting

Inner Warden exposes an API that AI agents can query:

```bash
# "Is my server safe right now?"
curl -s http://localhost:8787/api/agent/security-context
# → {"threat_level": "low", "recommendation": "safe to proceed"}

# "Is this command safe to run?"
curl -s -X POST http://localhost:8787/api/agent/check-command \
  -H "Content-Type: application/json" \
  -d '{"command": "curl https://example.com/setup.sh | bash"}'
# → {"risk_score": 40, "recommendation": "review", "signals": ["download_and_execute"]}

# "Is this IP safe to connect to?"
curl -s "http://localhost:8787/api/agent/check-ip?ip=203.0.113.10"
# → {"known_threat": true, "blocked": true, "recommendation": "avoid"}
```

Your agent calls `check-command` before executing. If the recommendation is `deny`, it stops. No changes to the agent runtime needed — just an HTTP call.

See [AI Agent Protection docs](modules/openclaw-protection/docs/README.md) for full integration guide.

---

## Scan advisor

Let your server tell you what it needs.

```
$ innerwarden scan

  sshd       running  → ssh-protection       ESSENTIAL    [NATIVE]
  docker     running  → container-security    RECOMMENDED  [NATIVE]
  nginx      running  → search-protection     RECOMMENDED  [NATIVE]
  falco      not found → falco-integration    OPTIONAL     [EXTERNAL] requires: falco install
  fail2ban   running  → fail2ban-integration  RECOMMENDED  [NATIVE]

  Conflicts detected:
    fail2ban-integration + abuseipdb-enrichment — both auto-block IPs; enable one

  Activation sequence:
    1. innerwarden enable block-ip
    2. innerwarden enable ssh-protection
    3. innerwarden enable fail2ban-integration
```

**NATIVE** = reads existing logs, zero external deps. **EXTERNAL** = requires separate tool install.

---

## Install

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

No API key required. What it does:
- Creates a dedicated `innerwarden` service user
- Downloads SHA-256 verified binaries for your architecture (x86_64 / aarch64)
- Writes config to `/etc/innerwarden/`, creates data directory
- Starts sensor + agent via systemd (Linux) or launchd (macOS)
- Safe posture: detection active, no response skills enabled, `dry_run = true`

With external integrations:
```bash
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --with-integrations
```

Build from source:
```bash
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://innerwarden.com/install | sudo bash
```

### Configure AI

AI triage is optional. Add it when you want confidence-scored decisions.

**OpenAI:**
```bash
# /etc/innerwarden/agent.env
OPENAI_API_KEY=sk-...
```

**Anthropic:**
```bash
# /etc/innerwarden/agent.env
ANTHROPIC_API_KEY=sk-ant-...
```
```toml
# /etc/innerwarden/agent.toml
[ai]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
```

**Ollama (local, no key):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh && ollama pull llama3.2
```
```toml
# /etc/innerwarden/agent.toml
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
```

After changing config:
```bash
sudo systemctl restart innerwarden-agent          # Linux
sudo launchctl kickstart -k system/com.innerwarden.agent  # macOS
```

Run `innerwarden doctor` to validate your provider.

### After install

```bash
innerwarden status     # verify services are running
innerwarden doctor     # diagnose issues with fix hints
innerwarden test       # inject a synthetic incident and verify the full pipeline responds
innerwarden list       # see capabilities and modules
```

Enable response skills when ready:
```bash
innerwarden enable block-ip          # IP blocking (ufw default, or iptables/nftables)
innerwarden enable sudo-protection   # detect + respond to sudo abuse
innerwarden enable shell-audit       # shell command trail via auditd
```

### Configure notifications

```bash
innerwarden notify telegram          # interactive wizard
innerwarden notify slack --webhook-url https://hooks.slack.com/...
innerwarden notify web-push --subject mailto:you@example.com
innerwarden notify webhook --url https://hooks.example.com/notify
innerwarden notify test              # verify all channels
```

### Go live

After enabling skills, the responder is active but still in `dry_run = true`. When you trust the decisions:

```bash
innerwarden configure responder --enable --dry-run false
```

### Updates

```bash
innerwarden upgrade          # fetch + install latest (SHA-256 verified)
innerwarden upgrade --check  # check without installing
```

### Control plane

```bash
innerwarden list                                    # capabilities + modules
innerwarden status                                  # services + active capabilities
innerwarden doctor                                  # diagnostics with fix hints
innerwarden enable block-ip                         # activate
innerwarden enable block-ip --param backend=iptables
innerwarden disable block-ip                        # deactivate and clean up
innerwarden --dry-run enable block-ip               # preview
innerwarden scan                                    # detect + recommend
innerwarden allowlist add --ip 10.0.0.0/8           # skip AI for trusted ranges
innerwarden allowlist add --user deploy             # skip AI for trusted users
innerwarden configure ai                            # interactive AI provider setup (12 providers)
innerwarden configure responder --enable --dry-run false
innerwarden backup                                  # archive configs to tar.gz
innerwarden metrics                                 # events, decisions, AI latency, uptime
innerwarden test                                    # verify full pipeline end-to-end
```

---

## Supported environments

- **Linux** — Ubuntu 22.04+, any systemd-based distro
- **macOS** — Ventura and later (launchd, pf firewall, unified log)

Pre-built binaries: `x86_64` and `aarch64` for both platforms.

---

## Build and test

```bash
make test       # 692 tests
make build      # debug build (sensor + agent + ctl)
make replay-qa  # end-to-end integration test
```

Run locally:
```bash
make run-sensor   # writes to ./data/
make run-agent    # reads from ./data/
```

---

## FAQ

**Is this an EDR?**
No. It is a self-contained defense agent with bounded response skills and full audit trails. No cloud, no phone-home, runs entirely on your host.

**Does it block by default?**
No. Starts in observe-only mode. You enable response skills and disable dry-run when ready.

**Do I need an AI provider?**
No. Detection, logging, dashboard, and reports all work without AI. AI adds confidence-scored triage for autonomous response — it is optional.

**How is this different from Fail2ban?**
Fail2ban blocks IPs based on regex patterns. Inner Warden has nineteen detectors, six eBPF kernel programs (tracepoints + kprobe + LSM + XDP), eleven response skills (including sudo suspension, process kill, container pause, honeypots, and traffic capture), twelve AI providers, Telegram bot, AbuseIPDB intelligence sharing, and a full investigation dashboard.

**Can I add custom detectors or skills?**
Yes. See [module authoring guide](docs/module-authoring.md).

---

## Links

- [Website](https://www.innerwarden.com)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Documentation](docs/index.md)
- [Module authoring](docs/module-authoring.md)
- [Integrated setup guide](docs/integrated-setup.md) (Falco + Suricata + osquery + Telegram on Ubuntu 22.04)

## License

MIT. See [LICENSE](LICENSE).
