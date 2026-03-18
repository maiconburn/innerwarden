# search-protection

Detects and blocks automated abuse of high-cost HTTP routes by analyzing nginx access logs in real time.

## Overview

This module tails the nginx access log and tracks request rates per source IP against a configurable path prefix. When a single IP exceeds the threshold within the sliding window, an incident is raised and the agent can block that IP.

Two components:

- **nginx-access-log collector** (`nginx_access`): tails the nginx access log in Combined Log Format, emitting `http.request` events per request
- **search-abuse detector** (`search_abuse`): sliding window per (IP, path prefix), triggers at threshold

The collector uses a byte-offset cursor for resume-on-restart — it picks up from where it left off after a sensor restart.

## Configuration

```toml
# sensor config (config.toml)
[collectors.nginx_access]
enabled = true
path    = "/var/log/nginx/access.log"

[detectors.search_abuse]
enabled        = true
threshold      = 30
window_seconds = 60
path_prefix    = "/api/search"

# agent config (agent.toml)
[responder]
enabled        = true
dry_run        = true
block_backend  = "ufw"
allowed_skills = ["block-ip-ufw"]
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `nginx_access.path` | `/var/log/nginx/access.log` | Path to nginx access log |
| `search_abuse.threshold` | 30 | Requests per IP in window before triggering |
| `search_abuse.window_seconds` | 60 | Sliding window duration |
| `search_abuse.path_prefix` | `/api/search` | Path prefix to monitor; `""` monitors all paths |

## Tuning

- Start with `dry_run = true` and observe `decisions-*.jsonl` for 24h before enabling live blocking
- Lower `threshold` (e.g. 10) if your search route is expensive and even moderate automation causes problems
- Set `path_prefix = ""` to monitor all routes — useful as a general rate-abuse detector
- Adjust `window_seconds = 300` (5min) if you want to catch slower but sustained crawling

## Security

- The collector is read-only (tails a file)
- Skills only block IPs — no server-side nginx config is modified
- Blocking is done via ufw/iptables/nftables, which requires the sudoers permission for the `innerwarden` user
- Always validate in `dry_run = true` to avoid blocking legitimate users (e.g. paginated scrapers you've authorized)

## Source code

- Collector: `crates/sensor/src/collectors/nginx_access.rs`
- Detector: `crates/sensor/src/detectors/search_abuse.rs`
- Skills: `crates/agent/src/skills/builtin/block_ip_ufw.rs`, `block_ip_iptables.rs`, `block_ip_nftables.rs`
