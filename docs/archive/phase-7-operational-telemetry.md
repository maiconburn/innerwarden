# Phase 7.3 — Operational Telemetry (lightweight)

## Objective

Measure whether InnerWarden is healthy in real host conditions without adding heavy infra.

## Implementation

- Agent keeps in-memory telemetry counters (`TelemetryState`) and emits append-only daily snapshots:
  - `telemetry-YYYY-MM-DD.jsonl`
- Emission points:
  - Fast loop (incident tick)
  - Slow loop (narrative tick)
- Rotation:
  - Daily file rotation, same pattern as other dated artifacts.

## Metrics captured

- `events_by_collector`
- `incidents_by_detector`
- `gate_pass_count`
- `ai_sent_count`
- `ai_decision_count`
- `avg_decision_latency_ms`
- `errors_by_component`
- `decisions_by_action`
- `dry_run_execution_count`
- `real_execution_count`

## Report integration

- `innerwarden-agent --report` now reads the latest telemetry snapshot for the analyzed date and includes:
  - Operational telemetry block in JSON report
  - Operational telemetry section in Markdown report

## Validation

- Unit tests:
  - counter tracking and average latency
  - writer/reader roundtrip
  - report consumption of telemetry snapshot
- Replay QA:
  - verifies telemetry artifact exists and key telemetry counters are present in report output

## Out of scope (intentional)

- Prometheus/Grafana
- external metrics backend
- distributed/centralized multi-host telemetry aggregation
