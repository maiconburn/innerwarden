#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (production trial profile)
#
# What this script does:
# - Installs rustup/cargo if missing (user install)
# - Builds release binaries (sensor + agent)
# - Installs binaries to /usr/local/bin
# - Creates /etc/innerwarden/{config.toml,agent.toml,agent.env}
# - Creates systemd units for sensor + agent
# - Configures a SAFE trial mode:
#   * OpenAI analysis enabled
#   * responder.enabled = false (no skill execution)
#   * dry_run = true
#   * only block-ip-ufw in allowed_skills

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IW_USER="innerwarden"

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/innerwarden"
DATA_DIR="/var/lib/innerwarden"

SENSOR_BIN="${BIN_DIR}/innerwarden-sensor"
AGENT_BIN="${BIN_DIR}/innerwarden-agent"

SENSOR_CONFIG="${CONFIG_DIR}/config.toml"
AGENT_CONFIG="${CONFIG_DIR}/agent.toml"
AGENT_ENV="${CONFIG_DIR}/agent.env"

SENSOR_UNIT="/etc/systemd/system/innerwarden-sensor.service"
AGENT_UNIT="/etc/systemd/system/innerwarden-agent.service"

log() {
  printf '[innerwarden-install] %s\n' "$*"
}

fail() {
  printf '[innerwarden-install] ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "this installer currently supports Linux hosts only"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  fail "systemctl not found; this installer requires systemd"
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  fail "sudo not found and current user is not root"
fi

run_root() {
  if [[ -n "${SUDO}" ]]; then
    "${SUDO}" "$@"
  else
    "$@"
  fi
}

backup_if_exists() {
  local path="$1"
  if run_root test -f "$path"; then
    local backup
    backup="${path}.bak.$(date +%Y%m%d%H%M%S)"
    run_root cp "$path" "$backup"
    log "backup created: ${backup}"
  fi
}

install_from_stdin() {
  local target="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"

  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}"

  backup_if_exists "${target}"
  run_root install -o "${owner}" -g "${group}" -m "${mode}" "${tmp}" "${target}"
  rm -f "${tmp}"
}

OPENAI_API_KEY="${OPENAI_API_KEY:-}"
if [[ -z "${OPENAI_API_KEY}" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p "Enter OPENAI_API_KEY (sk-...): " OPENAI_API_KEY
    echo
  else
    fail "OPENAI_API_KEY not set. Export it before running in non-interactive mode."
  fi
fi

if [[ -z "${OPENAI_API_KEY}" ]]; then
  fail "OPENAI_API_KEY cannot be empty"
fi

if ! command -v cargo >/dev/null 2>&1; then
  log "cargo not found. Installing rustup (user install)..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y
fi

# shellcheck disable=SC1090
source "${HOME}/.cargo/env"

log "ensuring stable Rust toolchain..."
rustup toolchain install stable >/dev/null
rustup default stable >/dev/null

cd "${ROOT_DIR}"

log "building innerwarden-sensor + innerwarden-agent (release)..."
cargo build --release -p innerwarden-sensor -p innerwarden-agent

NOLOGIN_BIN="$(command -v nologin || echo /usr/sbin/nologin)"
if ! id "${IW_USER}" >/dev/null 2>&1; then
  log "creating service user: ${IW_USER}"
  run_root useradd -r -s "${NOLOGIN_BIN}" "${IW_USER}"
fi

for grp in adm systemd-journal docker; do
  if getent group "${grp}" >/dev/null 2>&1; then
    run_root usermod -aG "${grp}" "${IW_USER}"
  fi
done

run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
run_root chown root:root "${CONFIG_DIR}"
run_root chmod 750 "${CONFIG_DIR}"
run_root chown "${IW_USER}:${IW_USER}" "${DATA_DIR}"
run_root chmod 750 "${DATA_DIR}"

log "installing binaries to ${BIN_DIR}"
run_root install -o root -g root -m 755 "${ROOT_DIR}/target/release/innerwarden-sensor" "${SENSOR_BIN}"
run_root install -o root -g root -m 755 "${ROOT_DIR}/target/release/innerwarden-agent" "${AGENT_BIN}"

HOST_ID="$(hostname -f 2>/dev/null || hostname)"

log "writing sensor config: ${SENSOR_CONFIG}"
install_from_stdin "${SENSOR_CONFIG}" 640 root "${IW_USER}" <<EOF
[agent]
host_id = "${HOST_ID}"

[output]
data_dir = "${DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.journald]
enabled = true
units = ["sshd", "sudo"]

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300
EOF

log "writing agent config: ${AGENT_CONFIG}"
install_from_stdin "${AGENT_CONFIG}" 640 root "${IW_USER}" <<EOF
[narrative]
enabled = true
keep_days = 7

[webhook]
enabled = false

[ai]
enabled = true
provider = "openai"
model = "gpt-4o-mini"
context_events = 20
confidence_threshold = 1.01
incident_poll_secs = 2

[honeypot]
mode = "demo"
bind_addr = "127.0.0.1"
port = 2222
http_port = 8080
duration_secs = 300
services = ["ssh"]
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512

[honeypot.redirect]
enabled = false
backend = "iptables"

[responder]
enabled = false
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw"]
EOF

log "writing environment file: ${AGENT_ENV}"
tmp_env="$(mktemp)"
printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}" > "${tmp_env}"
backup_if_exists "${AGENT_ENV}"
run_root install -o root -g "${IW_USER}" -m 640 "${tmp_env}" "${AGENT_ENV}"
rm -f "${tmp_env}"

log "writing systemd unit: ${SENSOR_UNIT}"
install_from_stdin "${SENSOR_UNIT}" 644 root root <<'EOF'
[Unit]
Description=Inner Warden - Sensor (host observability)
After=network.target syslog.target
Documentation=https://github.com/maiconesteves/innerwarden

[Service]
Type=simple
User=innerwarden
Group=innerwarden
SupplementaryGroups=adm systemd-journal
ExecStart=/usr/local/bin/innerwarden-sensor --config /etc/innerwarden/config.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-sensor
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/innerwarden
ReadOnlyPaths=/var/log /etc/innerwarden
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

log "writing systemd unit: ${AGENT_UNIT}"
install_from_stdin "${AGENT_UNIT}" 644 root root <<'EOF'
[Unit]
Description=Inner Warden - Agent (AI analysis and audit)
After=network-online.target innerwarden-sensor.service
Wants=network-online.target
Requires=innerwarden-sensor.service
Documentation=https://github.com/maiconesteves/innerwarden

[Service]
Type=simple
User=innerwarden
Group=innerwarden
EnvironmentFile=/etc/innerwarden/agent.env
ExecStart=/usr/local/bin/innerwarden-agent --data-dir /var/lib/innerwarden --config /etc/innerwarden/agent.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-agent
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/innerwarden
ReadOnlyPaths=/etc/innerwarden
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

log "reloading systemd and starting services..."
run_root systemctl daemon-reload
run_root systemctl enable innerwarden-sensor innerwarden-agent >/dev/null
run_root systemctl restart innerwarden-sensor
run_root systemctl restart innerwarden-agent

if ! run_root systemctl is-active --quiet innerwarden-sensor; then
  fail "innerwarden-sensor failed to start. Check: sudo journalctl -u innerwarden-sensor -n 200"
fi

if ! run_root systemctl is-active --quiet innerwarden-agent; then
  fail "innerwarden-agent failed to start. Check: sudo journalctl -u innerwarden-agent -n 200"
fi

log "installation complete."
log "services are running in SAFE trial mode (analysis-only):"
log "  responder.enabled = false"
log "  responder.dry_run = true"
echo
echo "Useful commands:"
echo "  sudo systemctl status innerwarden-sensor --no-pager"
echo "  sudo systemctl status innerwarden-agent --no-pager"
echo "  sudo journalctl -u innerwarden-sensor -f --no-pager"
echo "  sudo journalctl -u innerwarden-agent -f --no-pager"
echo "  ls -lah ${DATA_DIR}"
echo
echo "To move to dry-run execution validation later:"
echo "  1) Edit ${AGENT_CONFIG}"
echo "  2) Set [responder] enabled = true (keep dry_run = true)"
echo "  3) sudo systemctl restart innerwarden-agent"
