# Phase 7.2 — Temporal Correlation (MVP)

Goal: improve signal quality by grouping related incidents in a short time window, without introducing a complex rule engine.

## Model (short)

Correlation pivot candidates:
- `ip:<value>`
- `user:<value>`
- `detector:<incident_kind>`

Where `incident_kind` is derived from `incident_id` prefix (example: `ssh_bruteforce:...` -> `ssh_bruteforce`).

Two incidents are considered correlated when:
1. They occur inside the configured window (`correlation.window_seconds`), and
2. They share at least one pivot (`ip`, `user`, or `detector kind`).

This supports scenarios such as:
- `port_scan` followed by `ssh_bruteforce` on the same IP
- `credential_stuffing` plus `ssh_bruteforce` against the same entity
- Bursts of same detector kind in a short interval

## Implementation

- `crates/agent/src/correlation.rs`
  - `TemporalCorrelator`: in-memory recent history for fast incident-tick correlation
  - `build_clusters`: lightweight daily clustering for narrative rendering
- Agent fast loop (`process_incidents`)
  - gathers related incidents per incoming incident
  - injects related incidents into AI decision context
- OpenAI prompt
  - now includes a `TEMPORALLY CORRELATED INCIDENTS` section
- Narrative output
  - adds `Clusters correlacionados` section when cluster size >= 2

## Config (agent.toml)

```toml
[correlation]
enabled = true
window_seconds = 300
max_related_incidents = 8
```

## Out of scope (intentional)

- No persistent graph database
- No multi-host correlation
- No heavyweight CEP/rule engine
- No behavioral ML model
