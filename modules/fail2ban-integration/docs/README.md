# Fail2ban Integration

Polls fail2ban for currently banned IPs and enforces those bans via InnerWarden's block skills, unifying all ban decisions into a single audit trail in `decisions-YYYY-MM-DD.jsonl`.

## What it does

```
fail2ban daemon
    │  (manages its own jails and bans)
    │
    ▼
fail2ban-client status <jail>   ← polled every poll_secs seconds
    │
    ▼
InnerWarden agent (fail2ban module)
    │  filters: private IPs, already-known IPs, already-blocked IPs
    │
    ▼
block-ip skill  (block-ip-ufw / block-ip-iptables / block-ip-nftables / block-ip-pf)
    │
    ▼
decisions-YYYY-MM-DD.jsonl      ← ai_provider: "fail2ban:<jail>"
```

## When to use it

- You already run fail2ban on the host and want InnerWarden to be aware of its bans.
- You want a consolidated audit trail of all blocking decisions (fail2ban + InnerWarden AI) in one place.
- You want InnerWarden's blocklist to stay in sync with fail2ban so the AI layer does not waste API calls re-evaluating IPs that fail2ban has already banned.

## What it does NOT do

- It does **not** sync InnerWarden's block decisions back to fail2ban. InnerWarden and fail2ban block IPs independently.
- It does **not** replace fail2ban's detectors or rules. Fail2ban continues to detect and ban IPs using its own filters.
- It does **not** modify fail2ban's configuration or jail rules.

## Setup

### 1. Install fail2ban

```bash
sudo apt-get install fail2ban        # Debian/Ubuntu
sudo yum install fail2ban            # RHEL/CentOS
```

Verify it is running:

```bash
sudo systemctl status fail2ban
fail2ban-client ping   # should print "Server replied: pong"
```

### 2. Configure agent.toml

Add the following section:

```toml
[fail2ban]
enabled   = true
poll_secs = 60
# jails = ["sshd", "nginx-req-limit"]  # restrict to specific jails; empty = all active jails
jails     = []
```

The `block_backend` configured under `[responder]` determines which firewall tool is used to enforce the ban:

```toml
[responder]
enabled       = true
dry_run       = false
block_backend = "ufw"   # or "iptables", "nftables", "pf"
```

### 3. Verify with innerwarden doctor

```bash
innerwarden doctor
```

The doctor will check:
- Whether `fail2ban-client` is present on the system.
- Whether the fail2ban daemon is responding (`fail2ban-client ping`).

### 4. Watch the audit trail

When a new IP is picked up from fail2ban, a line is appended to `decisions-YYYY-MM-DD.jsonl`:

```json
{
  "ts": "2026-03-15T10:23:45Z",
  "incident_id": "fail2ban:sshd:203.0.113.42",
  "host": "my-server",
  "ai_provider": "fail2ban:sshd",
  "action_type": "block_ip",
  "target_ip": "203.0.113.42",
  "skill_id": "block-ip-ufw",
  "confidence": 1.0,
  "auto_executed": true,
  "dry_run": false,
  "reason": "fail2ban ban in jail 'sshd'",
  "estimated_threat": "high",
  "execution_result": "blocked 203.0.113.42 via ufw"
}
```

The `ai_provider` field is set to `fail2ban:<jail>` so you can distinguish fail2ban-sourced decisions from AI decisions or other integrations in the audit trail.
