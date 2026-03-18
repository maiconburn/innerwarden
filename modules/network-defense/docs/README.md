# network-defense

Detects port scanning by analyzing firewall drop/reject events from the kernel via journald.

## Overview

This module requires that your firewall logs blocked connections to the system journal (e.g., via iptables LOG target or nftables log statement). The `port-scan` detector uses a sliding window per source IP tracking distinct destination ports. When a single IP probes many ports quickly, an incident is raised and the AI can block that IP.

## Prerequisites

Your firewall must log blocked connections to the journal. Example iptables rule:

```bash
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTABLES-BLOCK: "
```

Or via ufw:

```bash
ufw logging on
```

## Configuration

Copy snippets from `config/` into your config files.

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `port_scan.threshold` | 12 | Distinct ports per IP before triggering |
| `port_scan.window_seconds` | 60 | Sliding window duration |

## Security

- High false-positive rate possible in environments with legitimate port diversity — tune threshold per baseline
- Always validate in `dry_run = true` before enabling auto-block

## Source code

- Collector: `crates/sensor/src/collectors/journald.rs`
- Detector: `crates/sensor/src/detectors/port_scan.rs`
- Skills: `crates/agent/src/skills/builtin/block_ip_*.rs`
