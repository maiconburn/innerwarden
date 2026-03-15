# nginx-error-monitor

Detects automated web scans, path traversal probes, and LFI attempts by
tailing the nginx error log.

## What it does

The `nginx_error` collector tails `/var/log/nginx/error.log` and emits
`http.error` events for every line that contains a client IP address. The
`web_scan` detector applies a sliding window per source IP: when a single IP
generates more than `threshold` errors within `window_seconds`, an incident
is raised for AI triage.

```
nginx error.log  →  nginx_error collector  →  http.error events
                    web_scan detector  →  web_scan incident (High)
                    AI triage  →  block_ip / ignore
```

## When to use it

- You expose web services behind nginx
- You want to detect path traversal, LFI, or directory enumeration probes
- You want automated scanners (Nuclei, Nikto, etc.) blocked before they hit
  your application layer

## Setup

### 1. Enable in sensor config

```toml
[collectors.nginx_error]
enabled = true
path    = "/var/log/nginx/error.log"

[detectors.web_scan]
enabled        = true
threshold      = 15
window_seconds = 60
```

### 2. Ensure sensor user can read the log

```bash
sudo usermod -aG adm innerwarden
# Or set log permissions explicitly:
sudo chmod 640 /var/log/nginx/error.log
sudo chown root:adm /var/log/nginx/error.log
```

### 3. Validate

```bash
innerwarden doctor
```

## Event schema

`http.error` events include:

| Field     | Description                          |
|-----------|--------------------------------------|
| `level`   | nginx log level (warn/error/crit)    |
| `ip`      | client IP address                    |
| `server`  | virtual host name                    |
| `request` | HTTP request line (method + path)    |
| `message` | nginx error message (truncated)      |

## What it does NOT do

- Does not tail the access log (use `nginx_access` + `search_abuse` for that)
- Does not block IPs itself — that requires the `block-ip` capability
- Debug and notice-level lines are silently skipped
