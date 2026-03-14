# Phase 7.4 — Honeypot Demo Only (Simulation)

## Objective

Provide a controlled product demo signal for "attacker fell into honeypot" without deploying real honeypot infrastructure.

## What is implemented

- Premium skill `honeypot` now runs in explicit demo mode.
- On execution, agent emits a synthetic event marker into daily events:
  - `source`: `agent.honeypot_demo`
  - `kind`: `honeypot.demo_decoy_hit`
  - labels: `DEMO`, `SIMULATION`, `DECOY`
- Marker includes incident + target IP context and appears in normal narrative/report flows via `events-YYYY-MM-DD.jsonl`.

## Safety and scope boundaries

- No real decoy service is exposed.
- No traffic redirection is performed.
- No honeypot infrastructure is provisioned.
- This is intentionally a simulation marker only.

## TODO (future real rebuild)

- Replace demo marker with real honeypot track in a dedicated future phase:
  - hardened decoy services
  - controlled redirection layer
  - forensic artifact capture pipeline
  - strict isolation and rollback controls
