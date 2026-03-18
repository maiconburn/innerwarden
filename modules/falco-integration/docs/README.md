# falco-integration

Integrates [Falco](https://falco.org) runtime security alerts with InnerWarden.

Falco uses eBPF to monitor Linux kernel syscalls in real time. It detects
threats that log-based detection cannot see — process spawns, file access,
network connections, privilege escalation — at the kernel level.

InnerWarden ingests Falco's alert output and provides:
- AI-assisted triage for High/Critical alerts
- Response actions (block-ip, suspend-user-sudo) when responder is enabled
- Attacker journey investigation via the dashboard
- Correlation with SSH, auditd, and other collector events

## What It Detects

Everything Falco detects. Out-of-the-box Falco rules cover:

| Category | Example rules |
|---|---|
| Container / Kubernetes | Terminal shell in container, Privileged container started |
| Process | Outbound connection by non-standard process, Shell spawned by web server |
| Filesystem | Write below /etc, Read sensitive file |
| Network | Outbound connection to suspicious IP, Unexpected listening port |
| Privilege escalation | SUID/SGID binary execution, Change thread namespace |

## Incident Passthrough

Falco has already performed detection — its alerts are not raw events but
conclusions. InnerWarden promotes Falco alerts at severity `high` or `critical`
directly to `incidents-YYYY-MM-DD.jsonl` without running them through an
additional InnerWarden detector. The AI triage layer sees them immediately.

Lower-severity Falco alerts (`medium`, `low`) are written to
`events-YYYY-MM-DD.jsonl` as observability context.

## Setup

### 1. Install Falco

```bash
# Ubuntu/Debian
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y falco
```

### 2. Configure Falco JSON output

Add to `/etc/falco/falco.yaml`:

```yaml
json_output: true
json_include_output_property: true

file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/falco.log
```

```bash
sudo systemctl restart falco
```

### 3. Enable in InnerWarden

```bash
innerwarden enable falco-integration
```

Or manually in `config.toml`:

```toml
[collectors.falco_log]
enabled = true
path    = "/var/log/falco/falco.log"
```

## Severity Mapping

| Falco priority | InnerWarden severity |
|---|---|
| Emergency, Alert, Critical | `critical` → incident |
| Error, Warning | `high` → incident |
| Notice | `medium` → event |
| Informational | `low` → event |
| Debug | `debug` → event |

## Entities Extracted

From `output_fields` in each Falco alert:

| Field | Entity type |
|---|---|
| `fd.sip`, `fd.rip`, `fd.cip` | IP |
| `user.name` | User |
| `container.id` (first 12 chars) | Container |
| `k8s.pod.name` | Service |

## No Kernel Module Required

Falco supports eBPF probes (recommended) and kernel modules. The modern
`falco-driver-loader` handles installation automatically. InnerWarden only
reads Falco's log output — it does not interact with the kernel driver.
