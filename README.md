# InnerWarden

A self-defending security agent for Linux and macOS servers.

Three binaries (two daemons + a CLI). Installs in 10 seconds. Detects attacks and can respond automatically when response skills are enabled (non-dry-run mode).

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

---

## What happens when someone attacks your server

```
Without Inner Warden:

00:00  Attacker starts SSH brute force
03:00  Maybe someone reads auth.log
04:00  Maybe someone blocks the IP manually
???    Maybe the attacker is already inside

With Inner Warden (auto-execution enabled):

00:00  Attacker starts SSH brute force from 203.0.113.10
00:45  Detector fires: 8 failed logins in 5 minutes
00:46  AI evaluates: confidence 0.94 → action: block_ip
00:46  Skill executes: ufw deny from 203.0.113.10
00:47  Telegram alert sent to operator
00:47  Decision logged to audit trail. Server defended itself.
```

No human needed when auto-execution is enabled; otherwise approvals/alerts apply. Full audit trail. Reversible.

---

## The arsenal

Inner Warden carries defensive skills. When a threat is detected, the agent picks the right tool and acts.

| Skill | What it does |
|-------|-------------|
| **Block IP** | Firewall block via ufw, iptables, nftables, or pf (macOS) |
| **Suspend sudo** | Revokes sudo for a compromised user. Auto-expires after TTL. |
| **Deploy honeypot** | SSH/HTTP decoy captures attacker credentials and behavior |
| **Rate limit nginx** | Blocks abusive HTTP traffic at nginx layer with TTL |
| **Monitor IP** | Captures traffic from a suspicious IP for forensic analysis |

All skills are bounded, audited, and reversible.
Premium skills (honeypot, monitor-ip) are opt-in.

---

## What it detects

| Detector | Threat |
|----------|--------|
| `ssh_bruteforce` | Repeated SSH failures from the same IP |
| `credential_stuffing` | Many usernames tried from one IP (spray attack) |
| `port_scan` | Rapid unique-port probing from one source |
| `sudo_abuse` | Burst of suspicious privileged commands by a user |
| `search_abuse` | High-rate requests hammering expensive HTTP endpoints |
| `execution_guard` | Suspicious shell commands via AST analysis (tree-sitter-bash) |
| `web_scan` | HTTP error floods from one IP — automated path traversal and LFI probing |
| `user_agent_scanner` | Requests carrying known scanner User-Agents (Nikto, sqlmap, Nuclei, 17 more) |

`execution_guard` parses commands structurally. It catches `curl | sh` pipelines, `/tmp` execution, reverse shell patterns, and staged download-chmod-execute sequences.

---

## How it works

```
[Sensors] → [Detectors] → [AI Decision] → [Skills Execute]
 watch       identify       assess threat    block / suspend /
 activity    patterns       pick response    honeypot / capture
```

**Sensor** — collects signals from the host. No AI, no HTTP, fully deterministic.
Sources: auth.log, journald, Docker events, file integrity (with cron and SSH key tampering detection), nginx access/error logs, shell audit (opt-in), macOS unified log, syslog/kern.log (firewall drops). Optional: Falco, Suricata, osquery, Wazuh integration.

**Agent** — reads incidents, applies an algorithm gate (skip low severity, private IPs, already-blocked), optionally calls AI for triage, and executes the chosen skill.

Two Rust daemons (sensor and agent) plus a Rust CLI (`innerwarden`, with `innerwarden-ctl` as an alternate symlink). No external dependencies at runtime. ~50 MB RAM.

---

## Operator in the loop

Not everything should be automatic. Inner Warden supports human approval when you want it.

- **Telegram alerts** — every High/Critical incident pushed to your phone in real time
- **Approve or deny** — inline keyboard in Telegram, decision logged to audit trail
- **Webhook** — HTTP POST to any endpoint with severity filter
- **Dashboard** — local authenticated UI for investigation, entity search, and operator actions

AI is advisory unless you explicitly enable auto-execution. You control the threshold.

---

## Safety model

Inner Warden starts in the safest possible posture:

- `responder.enabled = false` — no actions taken, observe only
- `dry_run = true` — logs what it *would* do without doing it
- Shell audit is opt-in with explicit privacy consent
- `execution_guard` runs in observe mode — detects, does not block
- AI is optional — detection and logging work without any provider
- Every decision is recorded in append-only `decisions-YYYY-MM-DD.jsonl`

Go live when you trust what you see: flip `dry_run = false`.

---

## Modules

Detectors and skills are packaged into modules — enable what you need:

| Module | Threat | Response |
|--------|--------|----------|
| `ssh-protection` | SSH brute-force + credential stuffing | Block IP |
| `network-defense` | Port scanning | Block IP |
| `sudo-protection` | Sudo privilege abuse | Suspend user sudo |
| `execution-guard` | Malicious shell commands (AST) | Detect (observe mode) |
| `search-protection` | HTTP endpoint abuse | Rate limit at nginx |
| `file-integrity` | Unauthorized file changes | Alert via webhook |
| `container-security` | Docker lifecycle anomalies | Observe |
| `threat-capture` | Active threat investigation | Honeypot + traffic capture |
| `falco-integration` | Kernel/container anomalies (Falco) | Incident passthrough |
| `suricata-integration` | Network IDS alerts (Suricata) | Incident passthrough |
| `osquery-integration` | Host state queries (osquery) | Enriched events |
| `wazuh-integration` | Wazuh HIDS alerts | Incident passthrough |
| `nginx-error-monitor` | HTTP error floods and path traversal probes | Block IP |
| `slack-notify` | Incident notifications to Slack | — (notification only) |
| `cloudflare-integration` | L7 DDoS / botnet IPs reaching the host | Block at Cloudflare edge |
| `abuseipdb-enrichment` | IP reputation context before AI analysis | Enriched AI prompt |
| `geoip-enrichment` | Country/ISP geolocation context | Enriched AI prompt |
| `fail2ban-integration` | Sync active fail2ban bans into InnerWarden | Block enforcement |
| `crowdsec-integration` | CrowdSec community threat intel | Block enforcement |

```bash
innerwarden enable block-ip
innerwarden enable search-protection
innerwarden enable shell-audit    # prompts for privacy consent
```

```bash
innerwarden module install <url>       # community modules (SHA-256 verified)
innerwarden module enable /path/to/module
```

---

## Install

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

No API key required. What it does:
- Creates a dedicated `innerwarden` service user
- Downloads pre-built binaries for your architecture (x86_64 or aarch64), SHA-256 verified
- Writes config to `/etc/innerwarden/` and creates the data directory
- Starts `innerwarden-sensor` + `innerwarden-agent` via systemd (Linux) or launchd (macOS)
- Safe posture by default: detection and logging active, no response skills enabled, `dry_run = true`

With integrations (Falco, Suricata, osquery):
```bash
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --with-integrations
```

Build from source:
```bash
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://innerwarden.com/install | sudo bash
```

### Configure AI

AI triage is optional. Inner Warden detects and logs threats without it. Add AI to get confidence-scored decisions and autonomous response.

**OpenAI** (fastest to set up):
```bash
# Add to /etc/innerwarden/agent.env
OPENAI_API_KEY=sk-...
```

**Anthropic:**
```bash
# Add to /etc/innerwarden/agent.env
ANTHROPIC_API_KEY=sk-ant-...
```
```toml
# Set in /etc/innerwarden/agent.toml
[ai]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
```

**Ollama (local, no key needed):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
```
```toml
# Set in /etc/innerwarden/agent.toml
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
# base_url = "http://localhost:11434"  # default, override if needed
```

After changing either file, restart the agent:
```bash
sudo systemctl restart innerwarden-agent          # Linux
sudo launchctl kickstart -k system/com.innerwarden.agent  # macOS
```

Run `innerwarden doctor` to validate your provider configuration.

### After install

```bash
innerwarden status     # verify services are running
innerwarden doctor     # diagnose any issues with fix hints
innerwarden list       # see available capabilities and modules
```

Enable response skills when ready. Each `enable` command patches the config, writes sudoers rules, and restarts the relevant service — no manual editing needed:

```bash
innerwarden enable block-ip          # IP blocking via ufw (default), iptables, or nftables
innerwarden enable sudo-protection   # detect sudo abuse and suspend user sudo rights
innerwarden enable shell-audit       # shell command trail via auditd (prompts for privacy consent)
```

After enabling, the responder is active but still in `dry_run = true` mode — it logs what it would do without executing. When you trust the decisions, flip one flag in `/etc/innerwarden/agent.toml`:

```toml
[responder]
dry_run = false
```

Then restart: `sudo systemctl restart innerwarden-agent` (Linux) or `sudo launchctl kickstart -k system/com.innerwarden.agent` (macOS).

### Updates

```bash
innerwarden upgrade          # fetch and install the latest release (SHA-256 verified)
innerwarden upgrade --check  # check if an update is available without installing
```

### Control plane reference

```bash
innerwarden list                              # capabilities and modules with status
innerwarden status                            # services + active capabilities
innerwarden status block-ip                   # status of a specific capability
innerwarden doctor                            # diagnostics with fix hints
innerwarden enable block-ip                   # activate (ufw by default)
innerwarden enable block-ip --param backend=iptables  # activate with a specific backend
innerwarden disable block-ip                  # deactivate and clean up
innerwarden --dry-run enable block-ip         # preview what enable would do
innerwarden scan                              # detect installed tools and recommend modules
```

---

## Supported environments

- **Linux** — Ubuntu 22.04+, any systemd-based distro
- **macOS** — Ventura and later (launchd, pf firewall, unified log)

Pre-built binaries: `x86_64` and `aarch64` for both platforms.

---

## Build and test

```bash
make test    # 511 tests
make build   # debug build (sensor + agent + ctl)
```

Run locally with fixture data:
```bash
make run-sensor   # writes to ./data/
make run-agent    # reads from ./data/
make replay-qa    # end-to-end replay validation
```

---

## FAQ

**Is this an EDR?**
No. It is a self-contained defense agent with bounded response skills and full audit trails. It does not phone home, has no cloud dependency, and runs entirely on your host.

**Does it block by default?**
No. It starts in observe-only mode. You enable response skills and disable dry-run when you are ready.

**Do I need an AI provider?**
No. Detection, logging, dashboards, and reports all work without AI. The AI layer adds confidence-scored triage for automated decisions — it is optional.

**How is this different from Fail2ban?**
Fail2ban blocks IPs based on regex patterns. Inner Warden has eight detectors, eight response skills (including sudo suspension, honeypots, and traffic capture), AI-assisted triage, Telegram approval workflows, and a full investigation dashboard.

**Can I add custom detectors or skills?**
Yes. See [module authoring guide](docs/module-authoring.md).

---

## Links

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Documentation](docs/index.md)
- [Module authoring](docs/module-authoring.md)
- [Integrated setup guide](docs/integrated-setup.md) (Falco + Suricata + osquery + Telegram on Ubuntu 22.04)

## License

MIT. See [LICENSE](LICENSE).
