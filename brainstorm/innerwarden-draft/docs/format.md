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
