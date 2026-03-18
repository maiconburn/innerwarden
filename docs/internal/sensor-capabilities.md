# Sensor Capabilities

`innerwarden-sensor` — deterministic event collection and detection. Zero AI, zero HTTP. Fail-open.

## Collectors

### NATIVE (built-in, no external tools required)

**auth_log** — tail `/var/log/auth.log`; full SSH parser (failures, logins, invalid users)

**journald** — subprocess `journalctl --follow --output=json`; units: sshd, sudo, kernel

**exec_audit** — tail `/var/log/audit/audit.log`; `type=EXECVE` + optional `type=TTY` (high privacy impact, gated by config)

**docker** — subprocess `docker events`; privilege escalation detection via `docker inspect` on `container.start`:
- Detects `--privileged`, docker.sock mount (`HostConfig.Binds` + `Mounts`), dangerous `CapAdd` (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`)
- Emits `container.privileged` (High), `container.sock_mount` (High), `container.dangerous_cap` (Medium)
- 10 tests

**integrity** — SHA-256 polling of configured paths, configurable interval:
- SSH key tampering: when modified file is `authorized_keys`, emits `ssh.authorized_keys_changed` (High) instead of `file.changed`; extracts username from path; MITRE T1098.004; 8 tests
- Cron tampering: when `/etc/crontab`, `/etc/cron.d/*`, cron.{hourly,daily,weekly,monthly}`, or `/var/spool/cron/crontabs/<user>` changes, emits `cron.tampering` (High); MITRE T1053.003; 7 tests

**nginx_access** — tail nginx access log (Combined Log Format); emits `http.request`

**nginx_error** — tail nginx error.log; emits `http.error` (warn/error/crit with client IP); skips debug/notice; 8 tests

**syslog_firewall** — tail `/var/log/syslog` (or `/var/log/kern.log`); parses iptables/nftables/UFW DROP (`SRC=`, `DPT=`, `PROTO=`, `IN=`); emits `network.connection_blocked` (Low) feeding port_scan detector; supports UFW `[UFW BLOCK]`, iptables LOG, nftables; ignores ICMP; byte-offset cursor with resume; 10 tests

**macos_log** — subprocess `log stream` (macOS only); reuses SSH parser; emits `sudo.command`; restart loop; 3 tests

### EXTERNAL (requires separate tool installation)

**falco_log** — tail `/var/log/falco/falco.log` (JSONL); maps priority → Severity; extracts entities from `output_fields` (IP, user, container, pod); incident passthrough for High/Critical; 12 tests

**suricata_eve** — tail `/var/log/suricata/eve.json` (JSONL); configurable event_types (alert, dns, http, tls, anomaly by default); inverse Suricata severity mapping (1→Critical, 2→High, 3→Medium); incident passthrough for alert severity 1+2; builders per type; 10 tests

**wazuh_alerts** — tail `/var/ossec/logs/alerts/alerts.json` (JSONL); severity by `rule.level` (0-2→Debug, 3-6→Low, 7-9→Medium, 10-11→High, 12-15→Critical); kind from `rule.groups[0]` with `wazuh.` prefix; extracts `data.srcip`, `data.dstuser`, `agent.name`; incident passthrough for High/Critical; 12 tests

**osquery_log** — tail `/var/log/osquery/osqueryd.results.log` (JSONL); differential results (added/snapshot, skips removed); severity by query name prefix (sudoers→High, listening_ports/crontab→Medium, processes/users→Low); filters private IPs; extracts remote IP, path, user (prefers decorations); contextual summaries by query slug; 9 tests

## Detectors

**ssh_bruteforce** — sliding window by IP, configurable threshold and window

**credential_stuffing** — distinct usernames per IP within window (spray attack detection)

**port_scan** — unique destination ports per IP from firewall logs

**sudo_abuse** — burst of suspicious privileged commands per user within window

**search_abuse** — sliding window by IP+path from nginx `http.request` events

**web_scan** — sliding window by IP from nginx `http.error` events; detects scanners/probes; 6 tests

**execution_guard** — structural AST analysis via `tree-sitter-bash` + argv scoring + sequence correlation per user (download→chmod→execute in sliding window); emits `suspicious_execution` with score, signals, evidence; observe mode (detects, does not block);

**user_agent_scanner** — immediate detection of known security scanners by User-Agent in `http.request` events; 20 signatures (Nikto, sqlmap, Nuclei, Masscan, Zgrab, wfuzz, DirBuster, Gobuster, ffuf, Acunetix, w3af, AppScan, OpenVAS, Nessus, Burp Suite, Metasploit, Nmap, python-requests, go-http-client, plus variants); dedup by `(ip, scanner)` in 10-minute window; MITRE T1595, T1595.002; 11 tests

## Output

- JSONL append-only with automatic daily rotation
- Fail-open: I/O errors in collectors are logged, never crash the daemon
- Dual flush: by count (50 events) + by time (5s interval)
- Graceful shutdown (SIGINT/SIGTERM) with cursor persistence

## Architecture

```
[auth_log] [journald] [docker] [integrity] [nginx] [falco] [suricata] ...
     ↓           ↓          ↓         ↓          ↓       ↓         ↓
                        mpsc::channel(1024)
                               ↓
              [ssh_bruteforce] [port_scan] [sudo_abuse] ...  ← Detectors (stateful)
                               ↓
                    events-YYYY-MM-DD.jsonl
                    incidents-YYYY-MM-DD.jsonl
```
