# JSONL format

## Event line (events-*.jsonl)
```json
{
  "ts": "2026-03-12T05:00:00Z",
  "host": "instance-maiconburn",
  "source": "auth.log",
  "kind": "ssh.login_failed",
  "severity": "info",
  "summary": "Invalid user root from 1.2.3.4",
  "details": {"ip":"1.2.3.4","user":"root"},
  "tags": ["auth","ssh"]
}
```

## Incident line (incidents-*.jsonl)
```json
{
  "ts": "2026-03-12T05:05:00Z",
  "host": "instance-maiconburn",
  "incident_id": "ssh_bruteforce:1.2.3.4:2026-03-12T05:05Z",
  "severity": "high",
  "title": "Possible SSH brute force",
  "summary": "12 failed SSH attempts from 1.2.3.4 in 5 minutes",
  "evidence": [{"kind":"ssh.login_failed","count":12}],
  "recommended_checks": ["Check auth.log for successful logins", "Consider fail2ban"],
  "tags": ["auth","ssh","bruteforce"]
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
