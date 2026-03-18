# abuseipdb-enrichment

Enriches InnerWarden's AI triage decisions with crowd-sourced IP reputation
data from [AbuseIPDB](https://www.abuseipdb.com/).

## What it does

Before sending an incident to the AI provider, InnerWarden queries the
AbuseIPDB API for the primary IP in the incident. The response includes:

- **Abuse confidence score** (0–100) — percentage of reporters who flagged
  this IP as abusive
- **Total reports** — lifetime report count from the community
- **Distinct reporters** — number of independent users who reported this IP
- **Country** and **ISP** — geolocation metadata
- **Tor exit node** flag

This data is injected into the AI prompt as additional context, helping the
AI provider make more confident decisions:

```
IP REPUTATION (AbuseIPDB):
AbuseIPDB: score=87/100, reports=342, distinct_reporters=89, country=CN, isp=SomeHosting Inc.
```

A score of 87/100 with 342 reports is strong evidence of malicious intent and
typically pushes the AI confidence above the auto-execute threshold.

```
Incident (ssh_bruteforce, High)
  + AbuseIPDB enrichment (score=87)
  → AI: block_ip, confidence=0.97, auto_execute=true
```

## When to use it

- You want the AI to be more decisive about known-bad IPs
- You want to reduce false-positive blocks by flagging IPs with score=0
- Free tier (1,000 checks/day) covers most self-hosted servers

## Setup

### 1. Get an API key

Register at [abuseipdb.com](https://www.abuseipdb.com/register). The free
tier provides 1,000 lookups per day with 30-day history.

### 2. Configure InnerWarden

Add to your `agent.toml`:

```toml
[abuseipdb]
enabled      = true
api_key      = ""          # or set ABUSEIPDB_API_KEY env var
max_age_days = 30
```

Or set via environment:

```bash
ABUSEIPDB_API_KEY=<your-key> innerwarden-agent
```

### 3. Validate

```bash
innerwarden doctor
```

## Privacy note

Only the IP addresses that trigger High/Critical incidents are queried. No
other data is sent to AbuseIPDB. The API key is stored locally in `agent.toml`
or as an environment variable.

## What it does NOT do

- Does not report InnerWarden's own blocks back to AbuseIPDB
- Does not affect detection — only enriches the AI context
- Private / loopback IPs are never queried (the algorithm gate filters them
  before this module runs)
