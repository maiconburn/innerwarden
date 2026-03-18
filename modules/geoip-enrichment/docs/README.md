# GeoIP Enrichment

Enriches the AI triage context with geolocation data for the primary IP of every High/Critical incident. Powered by [ip-api.com](http://ip-api.com) — no API key required.

## What it adds to the AI prompt

```
IP GEOLOCATION:
Geolocation: country=China (CN), city=Shenzhen, isp=China Telecom, asn=AS4134 China Telecom
```

The AI uses this to distinguish geographically plausible from implausible attack sources, correlate ISP/ASN patterns, and calibrate confidence without needing external reputation databases.

## Rate limits

ip-api.com free tier: **45 requests per minute**. This is sufficient for most self-hosted servers — InnerWarden only looks up IPs that cross the High/Critical incident threshold, not every event.

Private IPs (RFC1918, loopback) return `status: fail` from ip-api.com and are handled gracefully — the lookup returns `None` and the AI prompt is unchanged.

## Setup

Add to `agent.toml`:

```toml
[geoip]
enabled = true
```

No API key, no sign-up, no external account needed.

## What it does NOT do

- Does not block or rate-limit any IP based on geolocation alone.
- Does not store geolocation data persistently (enrichment is ephemeral, per-incident).
- Does not bypass the algorithm gate — only incidents already passing the High/Critical threshold are enriched.
- Does not make HTTP requests over TLS (ip-api.com free tier is HTTP only).
