# Phase 8.4 — Honeypot Sandbox Runtime + Forensic Handoff

## Objective

Introduce a dedicated runtime track for honeypot listener sessions with stronger process isolation controls, optional bounded packet handoff, and stricter forensic retention.

## What was implemented

- Added sandbox worker mode for honeypot listeners:
  - internal CLI mode (`--honeypot-sandbox-runner`)
  - per-session spec/result files for controlled execution handoff
  - configurable worker runner path (`[honeypot.sandbox].runner_path`)
  - optional environment scrubbing (`[honeypot.sandbox].clear_env`)
- Added optional pcap handoff:
  - bounded capture window (`timeout_secs`)
  - bounded packet count (`max_packets`)
  - metadata/evidence now include pcap handoff status and generated file path
- Strengthened retention policy:
  - existing age cleanup (`forensics_keep_days`) preserved
  - new total-size cap (`forensics_max_total_mb`) enforces aggregate forensic budget

## Config additions

```toml
[honeypot]
forensics_max_total_mb = 128

[honeypot.sandbox]
enabled = false
runner_path = ""
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120
```

## Artifacts

- `honeypot/listener-session-*.json`: final session metadata now includes `sandbox` and `pcap_handoff` blocks
- `honeypot/listener-session-*.jsonl`: lifecycle + connection evidence
- `honeypot/listener-session-*.pcap`: generated only when pcap handoff is enabled and successful

## Notes

- Default behavior remains unchanged and safe (`mode = "demo"`).
- Sandbox and pcap handoff are opt-in; listener path remains bounded and fail-open.
- Next phase should focus on stronger OS-level containment and external forensic handoff controls.
