# Phase 8.6 — Honeypot Runtime Jail and Trusted External Handoff

## Objective

Strengthen listener runtime isolation with an explicit `jail` containment track and harden forensic handoff trust with command allowlist + signed handoff artifacts.

## Delivered

- Added `jail` containment mode in `[honeypot.containment]`.
- Added jail controls:
  - `jail_runner`
  - `jail_args`
  - `allow_namespace_fallback`
- Preserved bounded/fail-open defaults:
  - default remains `mode = "process"`
  - jail mode may fall back to namespace/process when configured
- Added trusted external handoff controls in `[honeypot.external_handoff]`:
  - `allowed_commands`
  - `enforce_allowlist`
  - `signature_enabled`
  - `signature_key_env`
- Added signed handoff sidecar:
  - `honeypot/listener-session-*.external-handoff.sig`
- Handoff result metadata now reports trust state:
  - `trusted`
  - allowlist match details
  - signature metadata (hash/signature file path)

## Config

```toml
[honeypot.containment]
mode = "process"              # process | namespace | jail
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
allow_namespace_fallback = true

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
allowed_commands = ["/usr/local/bin/iw-handoff"]
enforce_allowlist = false
signature_enabled = false
signature_key_env = "INNERWARDEN_HANDOFF_SIGNING_KEY"
```

## Validation

- `make test`
- `make replay-qa`
