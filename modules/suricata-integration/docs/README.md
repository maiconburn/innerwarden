# suricata-integration

Integrates [Suricata](https://suricata.io) network IDS alerts with InnerWarden.

Suricata inspects live network traffic at line rate using a rule-based engine
(ET Open, ET Pro, custom rules). It detects network-layer threats that
host-based log analysis cannot see — exploit attempts, C2 beaconing, port
scans, protocol anomalies, lateral movement.

InnerWarden ingests Suricata's EVE JSON output and provides:
- AI-assisted triage for High/Critical network alerts
- Response actions (block-ip) when responder is enabled
- DNS, HTTP, and TLS observability events for attacker journey investigation
- Correlation with Falco, SSH, and auditd events in the dashboard

## What It Detects

Everything the Suricata ruleset covers. With ET Open rules (free):

| Category | Examples |
|---|---|
| Exploit attempts | Buffer overflows, shellcode patterns, CVE-specific signatures |
| Malware / C2 | Known malware domains, beaconing patterns, RAT protocols |
| Reconnaissance | Port scans, service fingerprinting, banner grabbing |
| Web attacks | SQL injection, XSS, path traversal, web shells |
| Protocol abuse | DNS tunneling, unusual TLS certificates, protocol anomalies |
| Policy violations | Tor exit node traffic, file transfer over unusual ports |

## Incident Passthrough

Suricata alerts at severity 1 (critical) and 2 (high) are promoted directly
to `incidents-YYYY-MM-DD.jsonl` without an additional InnerWarden detector.

Lower-severity alerts (severity 3) and observability events (dns, http, tls)
are written as events for correlation context.

## Severity Mapping

Suricata uses inverse severity (1 = most severe):

| Suricata severity | InnerWarden severity |
|---|---|
| 1 | `critical` → incident |
| 2 | `high` → incident |
| 3 | `medium` → event |
| other | `low` → event |

## Event Types Ingested

| Type | Default | Description |
|---|---|---|
| `alert` | ✅ | Rule-triggered IDS alerts — the main threat signal |
| `dns` | ✅ | DNS queries/responses — detect C2 domain lookups |
| `http` | ✅ | HTTP metadata — detect web attacks |
| `tls` | ✅ | TLS handshake metadata — detect unusual certificates |
| `anomaly` | ✅ | Protocol anomalies |
| `flow` | ❌ | Network flow stats (high volume, disable if noisy) |
| `stats` | ❌ | Internal Suricata stats (skip) |

## Setup

### 1. Install Suricata

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata

# Update rules
sudo suricata-update
```

### 2. Configure EVE JSON output

In `/etc/suricata/suricata.yaml`, ensure:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: no
            packet: no
        - dns
        - http
        - tls
```

```bash
sudo systemctl restart suricata
```

### 3. Enable in InnerWarden

```bash
innerwarden enable suricata-integration
```

Or manually in `config.toml`:

```toml
[collectors.suricata_eve]
enabled = true
path    = "/var/log/suricata/eve.json"
```

## Recommended Ruleset

[ET Open](https://rules.emergingthreats.net/) is free and covers most
threat categories. Update daily via `suricata-update`:

```bash
# /etc/cron.daily/suricata-update
suricata-update && systemctl kill -s USR2 suricata
```
