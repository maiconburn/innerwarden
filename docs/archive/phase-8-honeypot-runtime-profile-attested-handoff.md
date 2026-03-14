# Phase 8.7 — Runtime Profile Hardening and Attested Receiver Handoff

## Objective

Add stricter jail policy presets for listener containment and add an attested receiver contract for external forensic handoff.

## Delivered

- Added jail profile preset in `[honeypot.containment]`:
  - `jail_profile = "standard" | "strict"`
- `strict` profile now appends hardened bwrap-compatible arguments while preserving custom `jail_args`.
- Containment status now records jail profile intent/effective values:
  - `jail_profile_requested`
  - `jail_profile_effective`
- Added receiver attestation controls in `[honeypot.external_handoff]`:
  - `attestation_enabled`
  - `attestation_key_env`
  - `attestation_prefix`
  - `attestation_expected_receiver`
- Attestation contract:
  - agent exports challenge in `INNERWARDEN_HANDOFF_ATTEST_CHALLENGE`
  - receiver prints `<prefix>:<receiver_id>:<challenge>:<hmac_hex>`
  - agent validates HMAC for payload `receiver_id:challenge:session_id:target_ip`
- External handoff trust now requires all enabled checks (allowlist, signature, attestation).

## Config

```toml
[honeypot.containment]
mode = "process"              # process | namespace | jail
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"     # standard | strict
allow_namespace_fallback = true

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--target", "{target_ip}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
allowed_commands = ["/usr/local/bin/iw-handoff"]
enforce_allowlist = false
signature_enabled = false
signature_key_env = "INNERWARDEN_HANDOFF_SIGNING_KEY"
attestation_enabled = false
attestation_key_env = "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = ""
```

## Validation

- `make test`
- `make replay-qa`
