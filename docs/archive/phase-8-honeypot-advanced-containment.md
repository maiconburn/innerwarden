# Phase 8.5 — Honeypot Advanced Containment and External Handoff

## Objective

Strengthen the honeypot runtime path with explicit containment mode controls and a controlled external forensic handoff pipeline, while keeping the default behavior safe and fail-open.

## Delivered

- Added containment controls (`[honeypot.containment]`):
  - `mode` (`process` | `namespace`)
  - `require_success`
  - `namespace_runner`
  - `namespace_args`
- Sandbox runtime now records containment status in session metadata:
  - requested vs effective mode
  - fallback reason when namespace runner is unavailable
- Added external handoff controls (`[honeypot.external_handoff]`):
  - `enabled`, `command`, `args`, `timeout_secs`, `require_success`, `clear_env`
  - placeholder expansion in args:
    - `{session_id}`, `{target_ip}`, `{metadata_path}`, `{evidence_path}`, `{pcap_path}`
- Added handoff result artifact:
  - `honeypot/listener-session-*.external-handoff.json`
- Added lifecycle checks in metadata/evidence for generated artifacts (`metadata`, `evidence`, optional `pcap`)

## Config

```toml
[honeypot.containment]
mode = "process"              # process | namespace
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
```

## Safety

- Default mode remains `process` with no external handoff.
- If `mode = "namespace"` and `require_success = false`, missing namespace runner falls back to `process`.
- If `external_handoff.require_success = true`, handoff failures are surfaced in session outcome.
- Fail-open behavior is preserved by default to avoid destabilizing the main agent loop.

## Validation

- `make test`
- `make replay-qa`
