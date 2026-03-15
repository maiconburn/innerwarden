#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (production trial profile)
#
# Default mode: downloads pre-built binaries from GitHub Releases (~10 s).
# Source mode:  INNERWARDEN_BUILD_FROM_SOURCE=1 — builds from source with cargo.
#
# One-liner:
#   curl -fsSL https://github.com/maiconburn/innerwarden/releases/latest/download/install.sh | sudo bash
#
# What this script does:
# - Downloads (or builds) sensor + agent + ctl binaries
# - Validates SHA-256 of downloaded binaries
# - Installs binaries to /usr/local/bin
# - Creates /etc/innerwarden/{config.toml,agent.toml,agent.env}
# - Creates systemd units for sensor + agent
# - Configures a SAFE trial mode:
#   * OpenAI analysis enabled
#   * responder.enabled = false (no skill execution)
#   * dry_run = true
#   * only block-ip-ufw in allowed_skills

GITHUB_REPO="maiconburn/innerwarden"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IW_USER="innerwarden"

# Parse flags
WITH_INTEGRATIONS=0
for arg in "$@"; do
  case "$arg" in
    --with-integrations) WITH_INTEGRATIONS=1 ;;
  esac
done

# Detect OS
OS_TYPE="$(uname -s)"   # Linux | Darwin

BIN_DIR="/usr/local/bin"

if [[ "$OS_TYPE" == "Darwin" ]]; then
  CONFIG_DIR="/usr/local/etc/innerwarden"
  DATA_DIR="/usr/local/var/lib/innerwarden"
  PLIST_DIR="/Library/LaunchDaemons"
  SENSOR_PLIST="$PLIST_DIR/com.innerwarden.sensor.plist"
  AGENT_PLIST="$PLIST_DIR/com.innerwarden.agent.plist"
  LOG_DIR="/usr/local/var/log/innerwarden"
else
  CONFIG_DIR="/etc/innerwarden"
  DATA_DIR="/var/lib/innerwarden"
fi

SENSOR_BIN="${BIN_DIR}/innerwarden-sensor"
AGENT_BIN="${BIN_DIR}/innerwarden-agent"

SENSOR_CONFIG="${CONFIG_DIR}/config.toml"
AGENT_CONFIG="${CONFIG_DIR}/agent.toml"
AGENT_ENV="${CONFIG_DIR}/agent.env"

SENSOR_UNIT="/etc/systemd/system/innerwarden-sensor.service"
AGENT_UNIT="/etc/systemd/system/innerwarden-agent.service"
AUDIT_RULE_FILE="/etc/audit/rules.d/innerwarden-shell-audit.rules"

log() {
  printf '[innerwarden-install] %s\n' "$*"
}

fail() {
  printf '[innerwarden-install] ERROR: %s\n' "$*" >&2
  exit 1
}

normalize_bool() {
  case "${1,,}" in
    1|true|yes|y|on)
      echo "true"
      ;;
    *)
      echo "false"
      ;;
  esac
}

prompt_yes_no() {
  local question="$1"
  local default_answer="$2" # yes|no
  local suffix answer normalized

  if [[ "${default_answer}" == "yes" ]]; then
    suffix="[Y/n]"
  else
    suffix="[y/N]"
  fi

  read -r -p "${question} ${suffix} " answer
  answer="${answer:-${default_answer}}"
  normalized="$(normalize_bool "${answer}")"
  [[ "${normalized}" == "true" ]]
}

if [[ "$OS_TYPE" != "Linux" && "$OS_TYPE" != "Darwin" ]]; then
  fail "this installer supports Linux and macOS (Darwin) hosts only"
fi

if [[ "$OS_TYPE" != "Darwin" ]]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemctl not found; this installer requires systemd on Linux"
  fi
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

ENABLE_EXEC_AUDIT="${INNERWARDEN_ENABLE_EXEC_AUDIT:-}"
ENABLE_EXEC_AUDIT_TTY="${INNERWARDEN_ENABLE_EXEC_AUDIT_TTY:-}"

if [[ -t 0 && -z "${ENABLE_EXEC_AUDIT}" ]]; then
  echo
  echo "Privacy notice:"
  echo "  Shell auditing can capture executed commands and, if enabled, terminal input."
  echo "  This may include sensitive or personal data."
  echo "  Enable only with explicit legal authorization from the host owner."
  if prompt_yes_no "Enable shell command audit trail (auditd EXECVE)?" "no"; then
    ENABLE_EXEC_AUDIT="true"
  else
    ENABLE_EXEC_AUDIT="false"
  fi
fi

ENABLE_EXEC_AUDIT="$(normalize_bool "${ENABLE_EXEC_AUDIT:-false}")"

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  if [[ -t 0 && -z "${ENABLE_EXEC_AUDIT_TTY}" ]]; then
    if prompt_yes_no "Also ingest auditd TTY input records when available? (higher privacy impact)" "no"; then
      ENABLE_EXEC_AUDIT_TTY="true"
    else
      ENABLE_EXEC_AUDIT_TTY="false"
    fi
  fi
  ENABLE_EXEC_AUDIT_TTY="$(normalize_bool "${ENABLE_EXEC_AUDIT_TTY:-false}")"
else
  ENABLE_EXEC_AUDIT_TTY="false"
fi

BUILD_FROM_SOURCE="${INNERWARDEN_BUILD_FROM_SOURCE:-0}"

# ── Detect architecture ──────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64)        echo "x86_64"  ;;
    aarch64|arm64) echo "aarch64" ;;
    *)
      ISSUE_URL="https://github.com/maiconburn/innerwarden/issues/new?template=platform_support.yml&title=Platform+support+request:+$(uname -m)+on+$(uname -s)&labels=platform-support"
      echo ""
      echo "  Your platform ($(uname -m) on $(uname -s)) is not yet supported by pre-built binaries."
      echo "  Please request support here (takes 30 seconds):"
      echo "  $ISSUE_URL"
      echo ""
      echo "  To build from source instead: INNERWARDEN_BUILD_FROM_SOURCE=1 bash install.sh"
      fail "unsupported architecture: $(uname -m)"
      ;;
  esac
}

# ── Detect OS platform prefix for asset names ─────────────────────────────────
detect_platform() {
  case "$OS_TYPE" in
    Darwin) echo "macos" ;;
    *)      echo "linux" ;;
  esac
}

# ── Download a binary from GitHub Releases and validate its SHA-256 ──────────
download_asset() {
  local binary="$1"    # e.g. innerwarden-sensor
  local dest="$2"      # destination file path
  local version="$3"   # e.g. v0.2.0
  local arch="$4"      # x86_64 | aarch64
  local platform="$5"  # linux | macos

  local asset="${binary}-${platform}-${arch}"
  local base_url="https://github.com/${GITHUB_REPO}/releases/download/${version}"

  log "downloading ${asset}..."
  curl -fsSL --output "${dest}" "${base_url}/${asset}"

  if curl -fsSL "${base_url}/${asset}.sha256" | awk '{print $1}' > /tmp/iw-expected-sha256 2>/dev/null; then
    local expected actual
    expected="$(cat /tmp/iw-expected-sha256)"
    # Use shasum on macOS, sha256sum on Linux
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "${dest}" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "${dest}" | awk '{print $1}')"
    fi
    rm -f /tmp/iw-expected-sha256
    if [[ "${expected}" != "${actual}" ]]; then
      fail "SHA-256 mismatch for ${asset}:\n  expected: ${expected}\n  got:      ${actual}"
    fi
    log "SHA-256 ok"
  else
    log "warning: no SHA-256 sidecar for ${asset} — skipping integrity check"
  fi
}

if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then
  # ── Build from source (development / unsupported arch) ──────────────────
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
  log "building innerwarden-sensor + innerwarden-agent + innerwarden-ctl (release)..."
  cargo build --release -p innerwarden-sensor -p innerwarden-agent -p innerwarden-ctl
  IW_SENSOR_BIN="${ROOT_DIR}/target/release/innerwarden-sensor"
  IW_AGENT_BIN="${ROOT_DIR}/target/release/innerwarden-agent"
  IW_CTL_BIN="${ROOT_DIR}/target/release/innerwarden-ctl"
else
  # ── Download pre-built binaries from GitHub Releases (~10 s) ────────────
  if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required to download binaries (apt install curl / brew install curl)"
  fi
  # Require sha256sum (Linux) or shasum (macOS)
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "sha256sum or shasum is required for integrity checks"
  fi

  ARCH="$(detect_arch)"
  PLATFORM="$(detect_platform)"

  # Resolve version: env override or latest from GitHub API
  if [[ -n "${INNERWARDEN_VERSION:-}" ]]; then
    IW_VERSION="${INNERWARDEN_VERSION}"
  else
    log "fetching latest release version..."
    IW_VERSION="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      "${GITHUB_API}/releases/latest" \
      | grep '"tag_name"' | head -1 \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "${IW_VERSION}" ]] || fail "could not determine latest release version from GitHub API"
  fi

  log "installing InnerWarden ${IW_VERSION} for ${PLATFORM}/${ARCH}"

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  download_asset "innerwarden-sensor" "${TMP_DIR}/innerwarden-sensor" "${IW_VERSION}" "${ARCH}" "${PLATFORM}"
  download_asset "innerwarden-agent"  "${TMP_DIR}/innerwarden-agent"  "${IW_VERSION}" "${ARCH}" "${PLATFORM}"
  download_asset "innerwarden-ctl"    "${TMP_DIR}/innerwarden-ctl"    "${IW_VERSION}" "${ARCH}" "${PLATFORM}"

  IW_SENSOR_BIN="${TMP_DIR}/innerwarden-sensor"
  IW_AGENT_BIN="${TMP_DIR}/innerwarden-agent"
  IW_CTL_BIN="${TMP_DIR}/innerwarden-ctl"
fi

if [[ "$OS_TYPE" == "Darwin" ]]; then
  # macOS: create user via dscl if it doesn't exist
  if ! id "${IW_USER}" >/dev/null 2>&1; then
    log "creating service user: ${IW_USER}"
    # Find an unused UID in the system range
    NEXT_UID=300
    while dscl . -list /Users UniqueID | awk '{print $2}' | grep -q "^${NEXT_UID}$"; do
      NEXT_UID=$((NEXT_UID + 1))
    done
    run_root dscl . -create /Users/"${IW_USER}"
    run_root dscl . -create /Users/"${IW_USER}" UserShell /usr/bin/false
    run_root dscl . -create /Users/"${IW_USER}" RealName "Inner Warden"
    run_root dscl . -create /Users/"${IW_USER}" UniqueID "${NEXT_UID}"
    run_root dscl . -create /Users/"${IW_USER}" PrimaryGroupID 20
    run_root dscl . -create /Users/"${IW_USER}" NFSHomeDirectory /var/empty
  fi
  run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  run_root chown root:"staff" "${CONFIG_DIR}"
  run_root chmod 750 "${CONFIG_DIR}"
  run_root chown "${IW_USER}:staff" "${DATA_DIR}"
  run_root chmod 750 "${DATA_DIR}"
  run_root chown "${IW_USER}:staff" "${LOG_DIR}"
  run_root chmod 750 "${LOG_DIR}"
else
  NOLOGIN_BIN="$(command -v nologin || echo /usr/sbin/nologin)"
  if ! id "${IW_USER}" >/dev/null 2>&1; then
    log "creating service user: ${IW_USER}"
    run_root useradd -r -s "${NOLOGIN_BIN}" "${IW_USER}"
  fi

  for grp in adm systemd-journal docker audit; do
    if getent group "${grp}" >/dev/null 2>&1; then
      run_root usermod -aG "${grp}" "${IW_USER}"
    fi
  done

  run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
  # Allow the service user to traverse/read config files without making them world-readable.
  run_root chown root:"${IW_USER}" "${CONFIG_DIR}"
  run_root chmod 750 "${CONFIG_DIR}"
  run_root chown "${IW_USER}:${IW_USER}" "${DATA_DIR}"
  run_root chmod 750 "${DATA_DIR}"
fi

log "installing binaries to ${BIN_DIR}"
run_root install -o root -g root -m 755 "${IW_SENSOR_BIN}" "${SENSOR_BIN}"
run_root install -o root -g root -m 755 "${IW_AGENT_BIN}"  "${AGENT_BIN}"
run_root install -o root -g root -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden-ctl"
run_root install -o root -g root -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden"

HOST_ID="$(hostname -f 2>/dev/null || hostname)"

log "writing sensor config: ${SENSOR_CONFIG}"
if [[ "$OS_TYPE" == "Darwin" ]]; then
  install_from_stdin "${SENSOR_CONFIG}" 640 root "${IW_USER}" <<EOF
[agent]
host_id = "${HOST_ID}"

[output]
data_dir = "${DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = false

[collectors.macos_log]
enabled = true

[collectors.journald]
enabled = false

[collectors.exec_audit]
enabled = false
path = "/var/log/audit/audit.log"
include_tty = false

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

[detectors.sudo_abuse]
enabled = false
threshold = 3
window_seconds = 300
EOF
else
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

[collectors.exec_audit]
enabled = ${ENABLE_EXEC_AUDIT}
path = "/var/log/audit/audit.log"
include_tty = ${ENABLE_EXEC_AUDIT_TTY}

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

[detectors.sudo_abuse]
enabled = false
threshold = 3
window_seconds = 300
EOF
fi

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  log "shell command audit enabled (include_tty=${ENABLE_EXEC_AUDIT_TTY})"
  if run_root test -d /etc/audit/rules.d; then
    log "writing auditd rules: ${AUDIT_RULE_FILE}"
    install_from_stdin "${AUDIT_RULE_FILE}" 640 root root <<'EOF'
# Inner Warden shell command trail (installed with explicit consent)
-a always,exit -F arch=b64 -S execve -k innerwarden-shell-exec
-a always,exit -F arch=b32 -S execve -k innerwarden-shell-exec
EOF
    if command -v augenrules >/dev/null 2>&1; then
      if run_root augenrules --load >/dev/null 2>&1; then
        log "auditd rules loaded via augenrules"
      else
        log "WARNING: failed to load auditd rules via augenrules"
      fi
    elif command -v auditctl >/dev/null 2>&1; then
      if run_root auditctl -R "${AUDIT_RULE_FILE}" >/dev/null 2>&1; then
        log "auditd rules loaded via auditctl"
      else
        log "WARNING: failed to load auditd rules via auditctl"
      fi
    else
      log "WARNING: augenrules/auditctl not found; exec trail may remain disabled until auditd is configured"
    fi
  else
    log "WARNING: /etc/audit/rules.d not found; cannot install exec audit rules automatically"
  fi

  if [[ "${ENABLE_EXEC_AUDIT_TTY}" == "true" ]]; then
    log "TTY ingestion enabled in sensor config; host must emit auditd type=TTY records (e.g. via pam_tty_audit policy)"
  fi
fi

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
isolation_profile = "strict_local"
require_high_ports = true
forensics_keep_days = 7
forensics_max_total_mb = 128
transcript_preview_bytes = 96
lock_stale_secs = 1800

[honeypot.sandbox]
enabled = false
runner_path = ""
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120

[honeypot.containment]
mode = "process"
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"
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

if [[ "$OS_TYPE" == "Darwin" ]]; then
  log "writing launchd plist: ${SENSOR_PLIST}"
  run_root mkdir -p "${PLIST_DIR}"
  install_from_stdin "${SENSOR_PLIST}" 644 root root <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.innerwarden.sensor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/innerwarden-sensor</string>
    <string>--config</string>
    <string>${CONFIG_DIR}/config.toml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOG_DIR}/sensor.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/sensor.log</string>
</dict>
</plist>
EOF

  log "writing launchd plist: ${AGENT_PLIST}"
  install_from_stdin "${AGENT_PLIST}" 644 root root <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.innerwarden.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/innerwarden-agent</string>
    <string>--data-dir</string>
    <string>${DATA_DIR}</string>
    <string>--config</string>
    <string>${CONFIG_DIR}/agent.toml</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>OPENAI_API_KEY</key><string>${OPENAI_API_KEY}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOG_DIR}/agent.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/agent.log</string>
</dict>
</plist>
EOF
else
  log "writing systemd unit: ${SENSOR_UNIT}"
  install_from_stdin "${SENSOR_UNIT}" 644 root root <<'EOF'
[Unit]
Description=Inner Warden - Sensor (host observability)
After=network.target syslog.target
Documentation=https://github.com/maiconburn/innerwarden

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
Documentation=https://github.com/maiconburn/innerwarden

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
fi

# ── Integration installer ─────────────────────────────────────────────────────
#
# Called when --with-integrations is passed.
# Detects Falco / Suricata / osquery, offers to install missing ones,
# then patches /etc/innerwarden/config.toml with their collector sections.

FALCO_LOG_PATH="/var/log/falco/events.json"
SURICATA_EVE_PATH="/var/log/suricata/eve.json"
OSQUERY_LOG_PATH="/var/log/osquery/osqueryd.results.log"

_integration_installed() {
  local binary="$1"
  command -v "$binary" >/dev/null 2>&1
}

_offer_install_falco() {
  if _integration_installed falco; then
    log "Falco already installed: $(falco --version 2>/dev/null | head -1 || echo 'version unknown')"
    return 0
  fi
  if [[ -t 0 ]]; then
    echo
    echo "Falco is not installed."
    echo "  It detects anomalous syscall behaviour (container escapes, suspicious shells, etc.)."
    if ! prompt_yes_no "Install Falco now?" "yes"; then
      log "skipping Falco installation"
      return 1
    fi
  else
    log "Falco not found; skipping (non-interactive mode)"
    return 1
  fi

  log "installing Falco..."
  run_root bash -c '
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
      | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
https://download.falco.org/packages/deb stable main" \
      | tee /etc/apt/sources.list.d/falcosecurity.list > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y falco
  '

  # Enable JSON output if falco is freshly installed
  local falco_cfg="/etc/falco/falco.yaml"
  if run_root test -f "$falco_cfg"; then
    if ! run_root grep -q "json_output: true" "$falco_cfg"; then
      run_root sed -i 's/json_output: false/json_output: true/' "$falco_cfg" 2>/dev/null || true
      run_root bash -c "echo 'json_output: true' >> $falco_cfg" 2>/dev/null || true
      log "Falco: enabled json_output in $falco_cfg"
    fi
    local log_dir
    log_dir="$(dirname "$FALCO_LOG_PATH")"
    run_root mkdir -p "$log_dir"
    if ! run_root grep -q "json_include_output_property" "$falco_cfg" 2>/dev/null; then
      run_root bash -c "cat >> $falco_cfg <<'FALCOCFG'

# Added by innerwarden installer
file_output:
  enabled: true
  keep_alive: false
  filename: $FALCO_LOG_PATH
FALCOCFG
"
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    run_root systemctl enable --now falco 2>/dev/null || true
  fi
  log "Falco installed and started"
  return 0
}

_offer_install_suricata() {
  if _integration_installed suricata; then
    log "Suricata already installed: $(suricata --build-info 2>/dev/null | grep 'Suricata version' | head -1 || echo 'version unknown')"
    return 0
  fi
  if [[ -t 0 ]]; then
    echo
    echo "Suricata is not installed."
    echo "  It detects network-level threats (port scans, C2 callbacks, exploit attempts) via IDS/IPS rules."
    if ! prompt_yes_no "Install Suricata now?" "yes"; then
      log "skipping Suricata installation"
      return 1
    fi
  else
    log "Suricata not found; skipping (non-interactive mode)"
    return 1
  fi

  log "installing Suricata + Emerging Threats rules..."
  run_root bash -c '
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata suricata-update
    suricata-update 2>&1 | tail -5
    systemctl enable --now suricata 2>/dev/null || true
  '
  log "Suricata installed and started (eve.json → $SURICATA_EVE_PATH)"
  return 0
}

_offer_install_osquery() {
  if _integration_installed osqueryd; then
    log "osquery already installed: $(osqueryd --version 2>/dev/null | head -1 || echo 'version unknown')"
    return 0
  fi
  if [[ -t 0 ]]; then
    echo
    echo "osquery is not installed."
    echo "  It exposes host state (listening ports, crontabs, startup items, users) via SQL queries."
    if ! prompt_yes_no "Install osquery now?" "yes"; then
      log "skipping osquery installation"
      return 1
    fi
  else
    log "osquery not found; skipping (non-interactive mode)"
    return 1
  fi

  log "installing osquery..."
  run_root bash -c '
    export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "$OSQUERY_KEY" 2>/dev/null || \
      curl -fsSL "https://pkg.osquery.io/deb/pubkey.gpg" | apt-key add -
    add-apt-repository "deb [arch=amd64] https://pkg.osquery.io/deb deb main" -y 2>/dev/null || \
      echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" \
        > /etc/apt/sources.list.d/osquery.list
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y osquery
    systemctl enable --now osqueryd 2>/dev/null || true
  '
  log "osquery installed and started (results log → $OSQUERY_LOG_PATH)"
  return 0
}

_append_integration_collector() {
  local section="$1"   # TOML section text to append
  local marker="$2"    # unique string to check before appending (idempotent)
  if run_root grep -q "$marker" "${SENSOR_CONFIG}" 2>/dev/null; then
    log "sensor config already contains $marker — skipping"
    return
  fi
  local tmp
  tmp="$(mktemp)"
  run_root cat "${SENSOR_CONFIG}" > "$tmp"
  printf '\n%s\n' "$section" >> "$tmp"
  run_root install -o root -g "${IW_USER}" -m 640 "$tmp" "${SENSOR_CONFIG}"
  rm -f "$tmp"
}

install_integrations() {
  echo
  log "=== Integration setup (--with-integrations) ==="
  echo "  InnerWarden can ingest alerts from Falco, Suricata, and osquery."
  echo "  Each tool covers a different detection layer."
  echo

  local need_restart=0

  if _offer_install_falco; then
    _append_integration_collector \
      "[collectors.falco_log]
enabled = true
path = \"${FALCO_LOG_PATH}\"" \
      "collectors.falco_log"
    need_restart=1
    log "Falco collector added to sensor config"
  fi

  if _offer_install_suricata; then
    _append_integration_collector \
      "[collectors.suricata_eve]
enabled = true
path = \"${SURICATA_EVE_PATH}\"
event_types = [\"alert\", \"anomaly\"]" \
      "collectors.suricata_eve"
    need_restart=1
    log "Suricata EVE collector added to sensor config"
  fi

  if _offer_install_osquery; then
    _append_integration_collector \
      "[collectors.osquery_log]
enabled = true
path = \"${OSQUERY_LOG_PATH}\"" \
      "collectors.osquery_log"
    need_restart=1
    log "osquery collector added to sensor config"
  fi

  if [[ "$need_restart" -eq 1 ]]; then
    log "restarting innerwarden-sensor to apply integration config..."
    run_root systemctl restart innerwarden-sensor
    if run_root systemctl is-active --quiet innerwarden-sensor; then
      log "innerwarden-sensor restarted successfully"
    else
      log "WARNING: innerwarden-sensor failed to restart — check: sudo journalctl -u innerwarden-sensor -n 50"
    fi
  else
    log "no integration collectors were added"
  fi

  echo
  log "Integration setup complete. Run 'innerwarden doctor' to validate."
}

if [[ "$OS_TYPE" == "Darwin" ]]; then
  log "loading launchd services..."
  # Unload first if already loaded (idempotent install)
  run_root launchctl unload "${SENSOR_PLIST}" 2>/dev/null || true
  run_root launchctl unload "${AGENT_PLIST}" 2>/dev/null || true
  run_root launchctl load "${SENSOR_PLIST}"
  run_root launchctl load "${AGENT_PLIST}"

  # Give services a moment to start
  sleep 2

  if ! run_root launchctl list com.innerwarden.sensor 2>/dev/null | grep -q '"PID"'; then
    fail "innerwarden-sensor failed to start. Check: sudo tail -50 ${LOG_DIR}/sensor.log"
  fi

  if ! run_root launchctl list com.innerwarden.agent 2>/dev/null | grep -q '"PID"'; then
    fail "innerwarden-agent failed to start. Check: sudo tail -50 ${LOG_DIR}/agent.log"
  fi
else
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

  if [[ "${WITH_INTEGRATIONS}" -eq 1 ]]; then
    install_integrations
  fi
fi

log "installation complete."
log "services are running in SAFE trial mode (analysis-only):"
log "  responder.enabled = false"
log "  responder.dry_run = true"
echo
echo "Useful commands:"
echo "  innerwarden status                              — system overview"
echo "  innerwarden doctor                              — diagnose any issues"
echo "  innerwarden list                                — show available capabilities"
if [[ "$OS_TYPE" == "Darwin" ]]; then
echo "  sudo launchctl list com.innerwarden.sensor"
echo "  sudo launchctl list com.innerwarden.agent"
echo "  sudo tail -f ${LOG_DIR}/sensor.log"
echo "  sudo tail -f ${LOG_DIR}/agent.log"
else
echo "  sudo systemctl status innerwarden-sensor --no-pager"
echo "  sudo systemctl status innerwarden-agent --no-pager"
echo "  sudo journalctl -u innerwarden-sensor -f --no-pager"
echo "  sudo journalctl -u innerwarden-agent -f --no-pager"
fi
echo "  ls -lah ${DATA_DIR}"
echo
if [[ "$OS_TYPE" != "Darwin" ]]; then
echo "To add Falco + Suricata + osquery integration:"
echo "  curl -fsSL .../install.sh | sudo bash -s -- --with-integrations"
echo "  # or on an existing install:"
echo "  sudo bash install.sh --with-integrations"
echo
fi
echo "To move to dry-run execution validation later:"
echo "  1) Edit ${AGENT_CONFIG}"
echo "  2) Set [responder] enabled = true (keep dry_run = true)"
if [[ "$OS_TYPE" == "Darwin" ]]; then
echo "  3) sudo launchctl kickstart -k system/com.innerwarden.agent"
else
echo "  3) sudo systemctl restart innerwarden-agent"
fi
