# ssh-protection

Detects and responds to SSH brute-force attacks and credential stuffing attempts in real time.

## Overview

This module monitors SSH authentication failures from `/var/log/auth.log` and systemd journal (sshd unit). It uses two independent detectors:

- **ssh-bruteforce**: sliding window per source IP — triggers when a single IP exceeds the failure threshold
- **credential-stuffing**: sliding window per source IP tracking distinct usernames — triggers when one IP tries many different users (password spray)

When a detector triggers, the agent evaluates the incident with AI and can automatically block the source IP via ufw, iptables, or nftables.

## When to use

Enable this module on any Linux server that exposes SSH (port 22 or custom) to the internet.

## Configuration

Copy the snippets from `config/sensor.example.toml` and `config/agent.example.toml` into your config files, or use the quick-start below:

```toml
# sensor config (config.toml)
[collectors.auth_log]
enabled = true
path    = "/var/log/auth.log"

[collectors.journald]
enabled = true
units   = ["sshd"]

[detectors.ssh_bruteforce]
enabled        = true
threshold      = 8
window_seconds = 300

[detectors.credential_stuffing]
enabled        = true
threshold      = 6
window_seconds = 300

# agent config (agent.toml)
[responder]
enabled        = true
dry_run        = true
block_backend  = "ufw"
allowed_skills = ["block-ip-ufw"]
```

Key tuning parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `ssh_bruteforce.threshold` | 8 | Failed attempts per IP before triggering |
| `ssh_bruteforce.window_seconds` | 300 | Sliding window duration |
| `credential_stuffing.threshold` | 6 | Distinct usernames per IP before triggering |
| `responder.block_backend` | `ufw` | Firewall backend: `ufw`, `iptables`, `nftables` |
| `ai.confidence_threshold` | `0.8` | Minimum AI confidence before auto-executing block |

## Security

- Always start with `dry_run = true` and review `decisions-*.jsonl` before enabling live blocking
- Ensure your own IP or jump host is not in the monitored range before enabling auto-execution
- Skills only run commands listed in `[security].allowed_commands` in `module.toml`

## Source code

- Collectors: `crates/sensor/src/collectors/auth_log.rs`, `crates/sensor/src/collectors/journald.rs`
- Detectors: `crates/sensor/src/detectors/ssh_bruteforce.rs`, `crates/sensor/src/detectors/credential_stuffing.rs`
- Skills: `crates/agent/src/skills/builtin/block_ip_ufw.rs`, `block_ip_iptables.rs`, `block_ip_nftables.rs`
