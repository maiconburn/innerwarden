# crowdsec-integration

Connects InnerWarden to CrowdSec's crowd-sourced threat intelligence.

## What it does

CrowdSec is a collaborative security engine: millions of servers share attack
signals, and CrowdSec distills them into a continuously updated list of
malicious IPs. This module polls the **CrowdSec Local API (LAPI)** running on
your host and automatically enforces its ban decisions through InnerWarden's
block skills — without waiting for local detection.

```
CrowdSec LAPI  →  innerwarden-agent (poll every 60s)
                   → new ban decision?
                   → execute block-ip-<backend>
                   → write to decisions-YYYY-MM-DD.jsonl (ai_provider: "crowdsec:<origin>")
```

## When to use it

- You already run CrowdSec on the host
- You want to enforce community-sourced blocklists automatically
- You want a single audit trail for all blocking decisions (InnerWarden decisions +
  CrowdSec decisions in the same `decisions-*.jsonl`)

## Setup

### 1. Install CrowdSec

```bash
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install crowdsec
```

### 2. Create a bouncer API key for InnerWarden

```bash
sudo cscli bouncers add innerwarden
# Output: API key: <your-key>
```

### 3. Configure InnerWarden

Add to your `agent.toml`:

```toml
[crowdsec]
enabled   = true
url       = "http://localhost:8080"
api_key   = "<your-key>"   # or set CROWDSEC_API_KEY env var
poll_secs = 60
```

Or set via environment:

```bash
CROWDSEC_API_KEY=<your-key> innerwarden-agent
```

### 4. Validate

```bash
innerwarden doctor
```

The doctor will check that CrowdSec is running and the API key is valid.

## Decision audit trail

Every CrowdSec-sourced block is recorded with:

```json
{
  "ai_provider": "crowdsec:crowdsec",
  "action_type": "block_ip",
  "target_ip": "1.2.3.4",
  "confidence": 1.0,
  "reason": "CrowdSec ban from origin 'crowdsec', duration 86399s"
}
```

The `origin` field reflects CrowdSec's decision source: `crowdsec` (community
consensus), `cscli` (manual ban), `CAPI` (central API), etc.

## What it does NOT do

- It does **not** report InnerWarden's own blocks back to CrowdSec (one-way sync).
  Bidirectional reporting requires implementing a CrowdSec bouncer — out of scope.
- It does **not** replace your existing InnerWarden detectors. Both work in parallel.
- Private/loopback IPs from CrowdSec are silently skipped.
- Simulated decisions are skipped.
