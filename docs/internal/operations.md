# Operations Reference

## Build and Test

```bash
make test             # run all tests (sensor + agent + ctl)
make build            # debug build (sensor + agent + ctl)
make build-sensor
make build-agent
make build-ctl
```

`cargo` lives at `~/.cargo/bin/cargo` — the Makefile resolves it via the `CARGO` variable.

## Run Locally

```bash
make run-sensor       # sensor with config.test.toml, writes to ./data/
make run-agent        # agent reading ./data/
make run-dashboard    # read-only dashboard at http://127.0.0.1:8787

innerwarden-agent --dashboard-generate-password-hash   # generate Argon2 hash for dashboard auth
innerwarden-agent --report --data-dir ./data           # generate trial-report-YYYY-MM-DD.{md,json}
innerwarden-agent --data-dir ./data --once             # run once and exit

make replay-qa        # end-to-end multi-source replay (auth_log + falco_log + suricata_eve + osquery_log)
make ops-check DATA_DIR=./data  # quick ops-check of 6h recent window from trial-report-*.json
```

## Control Plane (`innerwarden` CLI)

```bash
# Status and diagnostics
innerwarden list                              # capabilities and modules with status
innerwarden status                            # services + active capabilities + today's counts
innerwarden status block-ip                   # status of a specific capability
innerwarden doctor                            # diagnostics with fix hints; exit 1 if issues

# Enable / disable capabilities
innerwarden enable block-ip                   # activate (ufw by default)
innerwarden enable block-ip --param backend=iptables
innerwarden enable sudo-protection
innerwarden enable shell-audit
innerwarden enable shell-audit --yes          # skip interactive confirmation
innerwarden disable block-ip
innerwarden --dry-run enable block-ip         # preview what enable would do

# Scan and advisor
innerwarden scan                              # probe installed tools, score modules, recommend;
                                              # interactive Q&A: type number or name to view README

# Module management
innerwarden module validate ./modules/ssh-protection
innerwarden module install https://example.com/mod.tar.gz
innerwarden module install ./local-mod.tar.gz --enable
innerwarden module uninstall <id>
innerwarden module publish ./modules/my-module
innerwarden module update-all
innerwarden module update-all --check
innerwarden module list
innerwarden module status <id>

# Notifications (interactive wizards)
innerwarden notify telegram
innerwarden notify telegram --token T --chat-id C
innerwarden notify slack
innerwarden notify slack --webhook-url URL --min-severity medium
innerwarden notify webhook --url https://... --min-severity high
innerwarden notify dashboard
innerwarden notify dashboard --user admin --password mypassword
innerwarden notify test                    # send test alert to all configured channels
innerwarden notify test --channel telegram

# Enrichment integrations
innerwarden integrate abuseipdb
innerwarden integrate abuseipdb --api-key <key>
innerwarden integrate geoip
innerwarden integrate fail2ban
innerwarden integrate watchdog

# Manual IP management
innerwarden block <ip> --reason "manual block"
innerwarden unblock <ip> --reason "false positive"

# Reporting and investigation
innerwarden incidents                        # recent incidents in terminal
innerwarden incidents --days 7 --severity high
innerwarden decisions                        # agent decisions log
innerwarden decisions --days 7 --action block_ip
innerwarden entity <ip|user>                 # full timeline for an entity
innerwarden report                           # show daily Markdown report
innerwarden report --date yesterday

# Tuning
innerwarden tune                             # analyze noise/signal ratio, suggest threshold adjustments
innerwarden tune --yes                       # apply without prompt

# Health monitoring
innerwarden watchdog                         # check if agent wrote telemetry recently
innerwarden watchdog --status               # show cron schedule + last telemetry age
innerwarden watchdog --notify               # send Telegram alert if unhealthy

# Updates
innerwarden upgrade                          # fetch and install latest release (SHA-256 verified)
innerwarden upgrade --check

# Shell completions
innerwarden completions bash
innerwarden completions zsh
innerwarden completions fish
```

## Installation on Linux (systemd)

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
# With integrations (Falco, Suricata, osquery):
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --with-integrations
# Build from source:
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://innerwarden.com/install | sudo bash
```

What the installer does:
- Creates dedicated `innerwarden` service user
- Downloads pre-built binaries for your architecture (x86_64 or aarch64), SHA-256 verified
- Writes config to `/etc/innerwarden/`, creates data directory
- Starts `innerwarden-sensor` + `innerwarden-agent` via systemd (Linux) or launchd (macOS)
- Safe posture: detection + logging active, no response skills, `dry_run = true`

## Cross-compile for Linux arm64

```bash
# Requires cargo-zigbuild + zig
make build-linux   # → target/aarch64-unknown-linux-gnu/release/innerwarden-{sensor,agent}
```

## Deploy to Remote Server

```bash
# Adjust HOST=user@server
make deploy HOST=ubuntu@1.2.3.4
make deploy-config HOST=ubuntu@1.2.3.4
make deploy-service HOST=ubuntu@1.2.3.4

# Remote log and status
make logs HOST=ubuntu@1.2.3.4
make status HOST=ubuntu@1.2.3.4
```

## Rollout Hardening

```bash
make rollout-precheck HOST=ubuntu@1.2.3.4
make rollout-postcheck HOST=ubuntu@1.2.3.4
make rollout-rollback HOST=ubuntu@1.2.3.4
make rollout-stop-agent HOST=ubuntu@1.2.3.4
```

## Production Permissions (Ubuntu 22.04)

```bash
# Create dedicated user
sudo useradd -r -s /sbin/nologin innerwarden

# Journal access (no root needed)
sudo usermod -aG systemd-journal innerwarden

# Docker socket access
sudo usermod -aG docker innerwarden

# Data directory
sudo mkdir -p /var/lib/innerwarden
sudo chown innerwarden:innerwarden /var/lib/innerwarden

# Block skills (choose backend)
# ufw:
echo "innerwarden ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from *" \
  | sudo tee /etc/sudoers.d/innerwarden

# iptables:
echo "innerwarden ALL=(ALL) NOPASSWD: /sbin/iptables -A INPUT *" \
  | sudo tee /etc/sudoers.d/innerwarden

# nftables:
echo "innerwarden ALL=(ALL) NOPASSWD: /usr/sbin/nft add element *" \
  | sudo tee /etc/sudoers.d/innerwarden

# monitor-ip (premium, optional):
# innerwarden ALL=(ALL) NOPASSWD: /usr/bin/timeout *, /usr/sbin/tcpdump *

# suspend-user-sudo (open, optional):
# innerwarden ALL=(ALL) NOPASSWD: /usr/bin/install *, /usr/sbin/visudo -cf *, /bin/rm -f /etc/sudoers.d/zz-innerwarden-deny-*
```

`data_dir` in `config.toml` **must** match `ReadWritePaths` in the systemd service file.

## Service Management

```bash
# Linux (systemd)
sudo systemctl restart innerwarden-sensor
sudo systemctl restart innerwarden-agent
sudo journalctl -u innerwarden-agent -f

# macOS (launchd)
sudo launchctl kickstart -k system/com.innerwarden.sensor
sudo launchctl kickstart -k system/com.innerwarden.agent
```

## Test Fixtures

`testdata/`:
- `sample-auth.log` — 20 SSH lines (9 failures from 203.0.113.10, 8 from 198.51.100.5)
- `sample-audit.log` — `auditd` examples (`EXECVE` + `TTY`)
- `sample-falco.jsonl` — Falco log fixture
- `sample-suricata-eve.jsonl` — Suricata EVE fixture
- `sample-osquery.jsonl` — osquery results fixture
- `watched/sshd_config`, `watched/sudoers` — integrity watcher fixtures
