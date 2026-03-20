# Configuration Reference

## Sensor (`config.toml`)

```toml
[agent]
host_id = "my-server"

[output]
data_dir = "/var/lib/innerwarden"
write_events = true

# ── Collectors ──────────────────────────────────────────────────────────────

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.macos_log]
enabled = false   # macOS only; uses `log stream`; replaces auth_log + journald on Darwin

[collectors.journald]
enabled = true
units = ["sshd", "sudo", "kernel"]   # "sshd" not "ssh"; "kernel" enables firewall/port scan signals

[collectors.exec_audit]
enabled = false
path = "/var/log/audit/audit.log"
include_tty = false   # high privacy impact; enable only with explicit authorization

[collectors.docker]
enabled = true

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[collectors.syslog_firewall]
enabled = false        # alternative to journald.kernel for servers without journald
path = "/var/log/syslog"  # or /var/log/kern.log; feeds port_scan detector

# ── External collectors (require separate tool installation) ─────────────────

[collectors.falco_log]
enabled = false
path = "/var/log/falco/falco.log"

[collectors.suricata_eve]
enabled = false
path = "/var/log/suricata/eve.json"
event_types = ["alert", "dns", "http", "tls", "anomaly"]

[collectors.wazuh_alerts]
enabled = false
path = "/var/ossec/logs/alerts/alerts.json"

[collectors.osquery_log]
enabled = false
path = "/var/log/osquery/osqueryd.results.log"

# ── Detectors ────────────────────────────────────────────────────────────────

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300

[detectors.credential_stuffing]
enabled = false       # enable after establishing baseline noise on the host
threshold = 6         # distinct usernames per IP in window
window_seconds = 300

[detectors.port_scan]
enabled = false       # enable after validating firewall log volume
threshold = 12        # unique destination ports per IP in window
window_seconds = 60

[detectors.sudo_abuse]
enabled = false       # enable with clear response policy and governance
threshold = 3         # suspicious sudo commands per user in window
window_seconds = 300

[detectors.user_agent_scanner]
enabled = false       # enable when nginx_access.enabled = true
# No threshold params — any known scanner UA is an immediate incident

[detectors.search_abuse]
enabled = false
threshold = 100       # requests per IP+path in window
window_seconds = 60

[detectors.web_scan]
enabled = false
threshold = 20        # HTTP errors per IP in window
window_seconds = 60
```

Test config: `config.test.toml` (points to `./testdata/`)

---

## Agent (`agent.toml`)

All fields have sane defaults; the file is optional. Use `--config` to specify location.

```toml
[narrative]
enabled = true       # generates summary-YYYY-MM-DD.md
keep_days = 7

[webhook]
enabled = false
url = "https://hooks.example.com/notify"
min_severity = "medium"   # debug | info | low | medium | high | critical
timeout_secs = 10

[ai]
enabled = true
provider = "openai"        # openai | anthropic | ollama | groq | deepseek | mistral | xai | gemini | openrouter | together | fireworks | cerebras
# api_key = ""             # or env OPENAI_API_KEY / ANTHROPIC_API_KEY
model = "gpt-4o-mini"
# base_url = ""            # override API endpoint (used by ollama and OpenAI-compatible providers)
                           # or env OLLAMA_BASE_URL
context_events = 20        # recent events sent as context to AI
confidence_threshold = 0.8 # below this → no auto-execution
incident_poll_secs = 2
max_ai_calls_per_tick = 5  # 0 = unlimited
circuit_breaker_threshold = 0   # 0 = disabled; recommended: 20 for DDoS defense
circuit_breaker_cooldown_secs = 60

[correlation]
enabled = true
window_seconds = 300
max_related_incidents = 8

[telemetry]
enabled = true

[honeypot]
mode = "demo"              # demo | listener
bind_addr = "127.0.0.1"
port = 2222
http_port = 8080
duration_secs = 300
services = ["ssh"]         # ["ssh", "http"] for multi-service
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512
isolation_profile = "strict_local"  # strict_local | standard
require_high_ports = true
forensics_keep_days = 7
forensics_max_total_mb = 128
transcript_preview_bytes = 96
lock_stale_secs = 1800
interaction = "banner"     # banner | medium (SSH key exchange + HTTP login page)
ssh_max_auth_attempts = 6
http_max_requests = 10

[honeypot.sandbox]
enabled = false
runner_path = ""
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120

[honeypot.containment]
mode = "process"             # process | namespace | jail
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"    # standard | strict
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

[honeypot.redirect]
enabled = false
backend = "iptables"

[responder]
enabled = true
dry_run = true             # SAFETY: always starts in dry_run
block_backend = "ufw"      # ufw | iptables | nftables
allowed_skills = ["block-ip-ufw", "monitor-ip"]

[telegram]
enabled = false
# bot_token = ""           # or env TELEGRAM_BOT_TOKEN
# chat_id = ""             # or env TELEGRAM_CHAT_ID
# daily_summary_hour = 8   # optional: send daily summary at this local hour (0-23)

[slack]
enabled = false
# webhook_url = ""         # or env SLACK_WEBHOOK_URL
min_severity = "high"
# dashboard_url = ""       # optional deep-link in Slack messages

[abuseipdb]
enabled = false
# api_key = ""             # or env ABUSEIPDB_API_KEY
auto_block_threshold = 0   # 0 = disabled; 80+ recommended for known botnet blocking

[geoip]
enabled = false            # ip-api.com, no API key required

[fail2ban]
enabled = false            # polls fail2ban-client CLI; Linux only

[cloudflare]
enabled = false
# zone_id = ""
# api_token = ""           # or env CLOUDFLARE_API_TOKEN
auto_push_blocks = true
block_notes_prefix = "InnerWarden:"

[crowdsec]
enabled = false
# lapi_url = "http://localhost:8080"
# api_key = ""             # or env CROWDSEC_API_KEY; find in /etc/crowdsec/local_api_credentials.yaml
poll_secs = 60             # how often to poll LAPI for new ban decisions
max_per_sync = 50          # max new IPs to block per tick (prevents OOM from large community lists)

[data]
events_keep_days = 7
incidents_keep_days = 30
decisions_keep_days = 90
telemetry_keep_days = 14
reports_keep_days = 30
```

---

## Environment Variables

```bash
# AI providers
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
OLLAMA_BASE_URL=http://localhost:11434   # optional override

# Notifications
TELEGRAM_BOT_TOKEN=<id>:<secret>
TELEGRAM_CHAT_ID=<numeric>
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Enrichment
ABUSEIPDB_API_KEY=...
CLOUDFLARE_API_TOKEN=...

# Dashboard auth
INNERWARDEN_DASHBOARD_USER=admin
INNERWARDEN_DASHBOARD_PASSWORD_HASH=$argon2id$...   # generated by: innerwarden-agent --dashboard-generate-password-hash

# Honeypot signing (optional)
INNERWARDEN_HANDOFF_SIGNING_KEY=...
INNERWARDEN_HANDOFF_ATTESTATION_KEY=...

# Debug
RUST_LOG=innerwarden_agent=debug
```

Create `/etc/innerwarden/agent.env` (or `.env` locally) — loaded automatically at startup, fail-silent if absent.
