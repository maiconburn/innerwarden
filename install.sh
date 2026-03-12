#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (source build)
# - Installs rustup if cargo is missing
# - Builds release binary
# - Installs to ~/.local/bin
# - Creates default config and data dirs

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_NAME="innerwarden"
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

echo "Building ${BIN_NAME} (release)..."
cargo build --release -p innerwarden

SRC_BIN="$ROOT_DIR/target/release/${BIN_NAME}"
DST_BIN="$INSTALL_BIN_DIR/${BIN_NAME}"

install -m 0755 "$SRC_BIN" "$DST_BIN"

echo "Installed binary: $DST_BIN"

# Default config
if [ ! -f "$INSTALL_CONFIG_DIR/config.toml" ]; then
  if [ -f "$ROOT_DIR/config.example.toml" ]; then
    cp "$ROOT_DIR/config.example.toml" "$INSTALL_CONFIG_DIR/config.toml"
  else
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
units = ["ssh", "docker", "containerd"]

[collectors.docker]
enabled = false
socket = "/var/run/docker.sock"

[collectors.integrity]
enabled = true
paths = ["/etc/ssh/sshd_config","/etc/sudoers","/etc/cron.d"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300
EOF
  fi
  echo "Created default config: $INSTALL_CONFIG_DIR/config.toml"
else
  echo "Config exists: $INSTALL_CONFIG_DIR/config.toml (kept)"
fi

echo
echo "Next: run a quick test (may need sudo to read auth.log):"
echo "  $DST_BIN --config $INSTALL_CONFIG_DIR/config.toml"
echo
