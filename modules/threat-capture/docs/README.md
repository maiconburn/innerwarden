# threat-capture (Premium)

Active and passive threat intelligence collection: packet capture and attacker engagement.

## Overview

This module provides two premium skills that the AI can invoke when it judges a threat warrants deeper investigation:

- **monitor-ip**: captures limited network traffic from a source IP using tcpdump, stores a bounded `.pcap` file alongside metadata for forensic review
- **honeypot**: deploys a temporary decoy service (SSH and/or HTTP) that engages the attacker, captures credentials and interaction data, and produces structured forensic evidence

## Configuration

```toml
# agent.toml
[responder]
enabled        = true
dry_run        = true
allowed_skills = ["monitor-ip", "honeypot"]

[honeypot]
mode          = "listener"
bind_addr     = "127.0.0.1"
port          = 2222
duration_secs = 300
interaction   = "medium"

[ai]
confidence_threshold = 0.9
```

See `config/agent.example.toml` for the full configuration reference.

## Skills

### monitor-ip

- Requires `tcpdump` and appropriate sudo permissions
- Captures up to `max_packets` packets in a `.pcap` file in `data_dir/honeypot/`
- Hard time limit via `timeout` — bounded by design
- In `dry_run = true`: logs intent, does not run tcpdump

### honeypot

- `interaction = "banner"`: simple banner response, logs connection attempt
- `interaction = "medium"`: real SSH key exchange (captures client fingerprint and credentials) + HTTP fake login page (captures form submissions)
- Containment profiles: `strict_local` (default), `standard`
- Session evidence stored as JSONL; optional `.pcap` via `[honeypot.pcap_handoff]`
- External handoff with HMAC attestation via `[honeypot.external_handoff]`

## Security

- Both skills have a high confidence threshold (0.9 recommended) — they are invasive
- Start with `dry_run = true` always
- `honeypot` binds to `127.0.0.1` by default — never expose to `0.0.0.0` without explicit `allow_public_listener = true`
- Review all forensic artifacts before sharing externally

## Required sudo permissions

```bash
# tcpdump for monitor-ip:
innerwarden ALL=(ALL) NOPASSWD: /usr/bin/timeout *, /usr/sbin/tcpdump *
```

## Source code

- Skills: `crates/agent/src/skills/builtin/monitor_ip.rs`
- Honeypot: `crates/agent/src/skills/builtin/honeypot/mod.rs`
- SSH interaction: `crates/agent/src/skills/builtin/honeypot/ssh_interact.rs`
- HTTP interaction: `crates/agent/src/skills/builtin/honeypot/http_interact.rs`
