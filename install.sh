#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (source build)
# - Installs rustup if cargo is missing
# - Builds release binaries (sensor + agent)
# - Installs to ~/.local/bin
# - Creates default config and data dirs

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_BIN_DIR="${HOME}/.local/bin"
INSTALL_CONFIG_DIR="${HOME}/.config/innerwarden"
INSTALL_DATA_DIR="${HOME}/.local/share/innerwarden"

mkdir -p "$INSTALL_BIN_DIR" "$INSTALL_CONFIG_DIR" "$INSTALL_DATA_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Installing rustup (user install)..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
fi

# Ensure stable toolchain
rustup toolchain install stable >/dev/null
rustup default stable >/dev/null

cd "$ROOT_DIR"

echo "Building innerwarden-sensor + innerwarden-agent (release)..."
cargo build --release -p innerwarden-sensor -p innerwarden-agent

install -m 0755 "$ROOT_DIR/target/release/innerwarden-sensor" "$INSTALL_BIN_DIR/innerwarden-sensor"
install -m 0755 "$ROOT_DIR/target/release/innerwarden-agent"  "$INSTALL_BIN_DIR/innerwarden-agent"

echo "Installed:"
echo "  $INSTALL_BIN_DIR/innerwarden-sensor"
echo "  $INSTALL_BIN_DIR/innerwarden-agent"

# Default config (sensor)
if [ ! -f "$INSTALL_CONFIG_DIR/config.toml" ]; then
  cat > "$INSTALL_CONFIG_DIR/config.toml" <<EOF
[agent]
host_id = "$(hostname)"

[output]
data_dir = "${INSTALL_DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.journald]
enabled = false
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
  echo "Created default config: $INSTALL_CONFIG_DIR/config.toml"
else
  echo "Config exists: $INSTALL_CONFIG_DIR/config.toml (kept)"
fi

echo
echo "Next steps:"
echo "  # Run sensor (may need sudo for auth.log):"
echo "  innerwarden-sensor --config $INSTALL_CONFIG_DIR/config.toml"
echo
echo "  # Run agent (reads sensor JSONL output):"
echo "  innerwarden-agent --data-dir $INSTALL_DATA_DIR --once"
echo
