# Integrated Setup Guide — Falco + Suricata + osquery + InnerWarden

> Ubuntu 22.04 LTS. Takes ~20 minutes. Requires sudo access.

## Overview

Each tool contributes a distinct detection layer:

- **InnerWarden**: reads all detection layers, runs AI triage, and executes bounded response skills (block-ip, suspend-user-sudo, honeypot)
- **Falco**: monitors Linux kernel syscalls and container activity with eBPF — detects shell spawns, file access violations, privilege escalation attempts, and container escapes in real time
- **Suricata**: analyses network traffic inline — detects port scans, exploit attempts, C2 beacons, and known attack signatures using the Emerging Threats ruleset
- **osquery**: runs scheduled SQL queries against the host — surfaces file changes, new listening ports, cron modifications, sudoers changes, and suspicious running processes

All four write logs that InnerWarden reads incrementally. You can enable any subset — none are required.

---

## 1. Install InnerWarden

If InnerWarden is not yet installed, run the guided installer:

```bash
curl -fsSL https://raw.githubusercontent.com/InnerWarden/innerwarden/main/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/InnerWarden/innerwarden
cd innerwarden
make build
```

Verify the services are running:

```bash
sudo systemctl status innerwarden-sensor innerwarden-agent
```

---

## 2. Install Falco

Falco publishes an official apt repository for Ubuntu.

```bash
# Add Falco apt repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update
sudo apt-get install -y falco
```

During install, Falco will ask which driver to use. For most Ubuntu 22.04 hosts, select **eBPF** (modern-bpf) or **kernel module**.

Enable JSON output so InnerWarden can parse Falco events:

```bash
sudo tee -a /etc/falco/falco.yaml <<'EOF'
json_output: true
json_include_output_property: true
EOF
```

Start Falco and verify the log file exists:

```bash
sudo systemctl enable --now falco
sudo ls -lh /var/log/falco/falco.log
```

If the file does not appear within 30 seconds:

```bash
sudo systemctl restart falco
sudo journalctl -u falco -n 50
```

---

## 3. Install Suricata

```bash
sudo apt-get install -y suricata
```

Update the Emerging Threats Open ruleset (runs suricata-update, which downloads and installs rules automatically):

```bash
sudo suricata-update
```

Restart Suricata so it picks up the rules and creates `eve.json`:

```bash
sudo systemctl enable --now suricata
sudo systemctl restart suricata
```

Verify `eve.json` exists and is being written to:

```bash
sudo ls -lh /var/log/suricata/eve.json
sudo tail -f /var/log/suricata/eve.json
```

If `eve.json` is not created, check the output interface in `/etc/suricata/suricata.yaml`. Set `af-packet` to your primary interface (for example `eth0` or `ens3`):

```bash
sudo grep -n "interface:" /etc/suricata/suricata.yaml
```

---

## 4. Install osquery

osquery publishes an official apt repository.

```bash
# Add osquery apt repository
curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/osquery-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-archive-keyring.gpg] \
  https://pkg.osquery.io/deb deb main" \
  | sudo tee /etc/apt/sources.list.d/osquery.list

sudo apt-get update
sudo apt-get install -y osquery
```

Create the osquery config with recommended scheduled queries. The following config enables result event logging and runs queries covering listening ports, cron jobs, sudoers, startup items, and new processes:

```bash
sudo tee /etc/osquery/osquery.conf <<'EOF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "log_result_events": "true",
    "schedule_splay_percent": "10"
  },
  "schedule": {
    "listening_ports": {
      "query": "SELECT pid, port, protocol, family, address FROM listening_ports;",
      "interval": 60
    },
    "crontab": {
      "query": "SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab;",
      "interval": 300
    },
    "sudoers": {
      "query": "SELECT header, rule_details FROM sudoers;",
      "interval": 300
    },
    "startup_items": {
      "query": "SELECT name, path, status, type FROM startup_items;",
      "interval": 300
    },
    "process_open_sockets": {
      "query": "SELECT pid, fd, family, protocol, local_address, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE remote_port != 0;",
      "interval": 60
    },
    "users": {
      "query": "SELECT username, uid, gid, shell, directory FROM users;",
      "interval": 300
    }
  }
}
EOF
```

Start osqueryd and verify the results log appears after the first query interval (~60 seconds):

```bash
sudo systemctl enable --now osqueryd
sudo systemctl restart osqueryd

# Wait ~60 seconds, then:
sudo ls -lh /var/log/osquery/osqueryd.results.log
```

---

## 5. Enable integrations in InnerWarden

Add the collector blocks to `/etc/innerwarden/config.toml`:

```toml
[collectors.falco_log]
enabled = true
path = "/var/log/falco/falco.log"

[collectors.suricata_eve]
enabled = true
path = "/var/log/suricata/eve.json"

[collectors.osquery_log]
enabled = true
path = "/var/log/osquery/osqueryd.results.log"
```

Apply the change by restarting the sensor:

```bash
sudo systemctl restart innerwarden-sensor
```

Verify the sensor picks up the new collectors:

```bash
sudo journalctl -u innerwarden-sensor -n 30 --no-pager
```

You should see log lines like `starting falco_log collector`, `starting suricata_eve collector`, and `starting osquery_log collector`.

---

## 6. (Optional) Configure Telegram notifications

To receive push notifications for High and Critical incidents, add a `[telegram]` block to `/etc/innerwarden/agent.toml`:

```toml
[telegram]
enabled = true
min_severity = "high"
```

Then add your credentials to `/etc/innerwarden/agent.env` (never put secrets directly in the TOML file):

```bash
TELEGRAM_BOT_TOKEN=1234567890:AABBccDDeeffGGHHiijjKK...
TELEGRAM_CHAT_ID=123456789
```

To get a bot token, message [@BotFather](https://t.me/BotFather) on Telegram and use `/newbot`. To find your chat ID, message [@userinfobot](https://t.me/userinfobot).

Restart the agent to apply:

```bash
sudo systemctl restart innerwarden-agent
```

---

## 7. Validate with `innerwarden doctor`

```bash
innerwarden doctor
```

Healthy output with all integrations enabled looks like this:

```
InnerWarden Doctor
════════════════════════════════════════════════

System
  [ok]   systemctl found
  [ok]   innerwarden system user exists
  [ok]   /etc/sudoers.d/ directory exists

Services
  [ok]   innerwarden-sensor is running
  [ok]   innerwarden-agent is running

Configuration
  [ok]   Sensor config found (/etc/innerwarden/config.toml)
  [ok]   Sensor config is valid TOML
  [ok]   Agent config found (/etc/innerwarden/agent.toml)
  [ok]   Agent config is valid TOML
  [ok]   OPENAI_API_KEY is set and format looks correct

Integrations
  Falco
  [ok]   Falco binary found
  [ok]   Falco service is running
  [ok]   Falco log file exists (/var/log/falco/falco.log)
  [ok]   Falco json_output is enabled
  Suricata
  [ok]   Suricata binary found
  [ok]   Suricata service is running
  [ok]   Suricata eve.json exists (/var/log/suricata/eve.json)
  [ok]   Suricata ET rules present
  osquery
  [ok]   osqueryd binary found
  [ok]   osqueryd service is running
  [ok]   osquery results log exists (/var/log/osquery/osqueryd.results.log)
  [ok]   osquery config contains scheduled queries

────────────────────────────────────────────────
All checks passed — system looks healthy.
```

If any check shows `[warn]` or `[fail]`, follow the hint printed below it. Every check has an exact command to fix the issue.

---

## 8. Smoke test

Confirm each tool is producing data and InnerWarden is seeing it.

**Falco** — watch for live syscall events:

```bash
sudo tail -f /var/log/falco/falco.log
```

Trigger a test event by running something suspicious in another terminal (for example `sudo cat /etc/shadow`). You should see a JSON event appear within seconds.

**Suricata** — watch the eve log:

```bash
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

**osquery** — watch the results log:

```bash
sudo tail -f /var/log/osquery/osqueryd.results.log
```

Results appear after each scheduled query fires (every 60–300 seconds depending on the query).

**InnerWarden events** — confirm the sensor is ingesting from all sources:

```bash
TODAY=$(date +%Y-%m-%d)
sudo tail -f /var/lib/innerwarden/events-${TODAY}.jsonl | jq '.source'
```

You should see values like `"falco_log"`, `"suricata_eve"`, and `"osquery_log"` mixed with the built-in sources (`"auth_log"`, `"journald"`, etc.).

---

## Troubleshooting

**Falco log not appearing**
Follow the hint: `sudo mkdir -p /var/log/falco && sudo systemctl restart falco`
Then check: `sudo journalctl -u falco -n 50`

**Falco events not JSON**
Follow the hint: `echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo systemctl restart falco`

**Suricata eve.json missing**
Follow the hint: `sudo systemctl restart suricata`
If it still does not appear, check the interface setting in `/etc/suricata/suricata.yaml`.

**Suricata no rules**
Follow the hint: `sudo suricata-update && sudo systemctl restart suricata`

**osquery results log missing**
This is expected for the first ~60 seconds after start. Wait one full query interval, then check again. If still missing, follow the hint: ensure `log_result_events=true` is set in `/etc/osquery/osquery.conf`.

**osquery no scheduled queries**
Copy the `[schedule]` block from Section 4 above into `/etc/osquery/osquery.conf`.

**Sensor not picking up new collectors**
Make sure `enabled = true` is set under each `[collectors.*]` block and run:
`sudo systemctl restart innerwarden-sensor`

**`innerwarden doctor` reports an issue**
Every `[warn]` and `[fail]` line is followed by `→ <exact command>`. Run that command, then re-run `innerwarden doctor` to confirm the fix.
