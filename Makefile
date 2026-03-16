TARGET_LINUX := aarch64-unknown-linux-gnu
SENSOR_DIR   := crates/sensor
AGENT_DIR    := crates/agent
RELEASE_DIR  := target/$(TARGET_LINUX)/release
CARGO        := $(HOME)/.cargo/bin/cargo

# ─── Local dev ───────────────────────────────────────────────────────────────

.PHONY: build
build:
	$(CARGO) build -p innerwarden-sensor -p innerwarden-agent -p innerwarden-ctl

.PHONY: build-sensor
build-sensor:
	$(CARGO) build -p innerwarden-sensor

.PHONY: build-agent
build-agent:
	$(CARGO) build -p innerwarden-agent

.PHONY: build-ctl
build-ctl:
	$(CARGO) build -p innerwarden-ctl

.PHONY: test
test:
	$(CARGO) test --workspace

.PHONY: run-sensor
run-sensor:
	$(CARGO) run -p innerwarden-sensor -- --config config.test.toml

.PHONY: run-agent
run-agent:
	$(CARGO) run -p innerwarden-agent -- --data-dir ./data

.PHONY: run-dashboard
run-dashboard:
	$(CARGO) run -p innerwarden-agent -- --data-dir ./data --dashboard

# Test the enable flow without applying changes (safe to run locally)
.PHONY: test-enable-dry-run
test-enable-dry-run: build-ctl
	$(CARGO) run -p innerwarden-ctl -- \
		--sensor-config config.test.toml \
		--agent-config agent-test.toml \
		--dry-run \
		enable block-ip

.PHONY: replay-qa
replay-qa:
	./scripts/replay_qa.sh

.PHONY: ops-check
ops-check:
	./scripts/ops-check.sh $(DATA_DIR)

# ─── Cross-compile for Linux arm64 ───────────────────────────────────────────

.PHONY: build-linux
build-linux:
	@$(dir $(CARGO))cargo-zigbuild --version >/dev/null 2>&1 || \
		{ echo "cargo-zigbuild not found — install with: cargo install cargo-zigbuild"; exit 1; }
	@rustup target add $(TARGET_LINUX) 2>/dev/null || true
	$(CARGO) zigbuild -p innerwarden-sensor -p innerwarden-agent -p innerwarden-ctl \
		--target $(TARGET_LINUX) --release
	@echo "Sensor: $(RELEASE_DIR)/innerwarden-sensor"
	@echo "Agent:  $(RELEASE_DIR)/innerwarden-agent"
	@echo "Ctl:    $(RELEASE_DIR)/innerwarden-ctl"

# ─── Deploy ──────────────────────────────────────────────────────────────────

# Override on the command line: make update HOST=user@myserver
HOST ?= user@your-server

# ── Full update pipeline: test → build → deploy → restart → verify ────────────
# Usage: make update HOST=ubuntu@1.2.3.4
#
# Steps:
#   1. make test      — all 157 tests must pass (fails fast if any break)
#   2. make build-linux — cross-compile release binaries for arm64 Linux
#   3. Stop agent + sensor gracefully (sensor last so no events are lost)
#   4. SCP both binaries to /tmp, install to /usr/local/bin atomically
#   5. Restart sensor → agent (sensor first so agent finds fresh data)
#   6. Wait 3s, show status of both services + tail last 20 log lines
.PHONY: update
update: test build-linux
	@echo "══════════════════════════════════════════════════"
	@echo "  Deploying to $(HOST)"
	@echo "══════════════════════════════════════════════════"
	@echo "→ Stopping services..."
	ssh $(HOST) "sudo systemctl stop innerwarden-agent  2>/dev/null || true"
	ssh $(HOST) "sudo systemctl stop innerwarden-sensor 2>/dev/null || true"
	@echo "→ Uploading binaries..."
	scp $(RELEASE_DIR)/innerwarden-sensor $(HOST):/tmp/innerwarden-sensor
	scp $(RELEASE_DIR)/innerwarden-agent  $(HOST):/tmp/innerwarden-agent
	@echo "→ Installing binaries..."
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-sensor /usr/local/bin/innerwarden-sensor"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-agent  /usr/local/bin/innerwarden-agent"
	@echo "→ Restarting services..."
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start innerwarden-sensor"
	ssh $(HOST) "sudo systemctl start innerwarden-agent 2>/dev/null || true"
	@echo "→ Waiting for services to settle..."
	@sleep 3
	@echo "══════════════════════════════════════════════════"
	@echo "  Status"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager -l"
	@echo "══════════════════════════════════════════════════"
	@echo "  Recent logs (sensor)"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -n 20 --no-pager"
	@echo "══════════════════════════════════════════════════"
	@echo "  Recent logs (agent)"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo journalctl -u innerwarden-agent  -n 20 --no-pager"
	@echo ""
	@echo "✓ Update complete."

# ── deploy: binaries only, no test run (faster, use when tests already passed) ─
.PHONY: deploy
deploy: build-linux
	@echo "Deploying to $(HOST) (no test run — use 'make update' for full pipeline)..."
	ssh $(HOST) "sudo systemctl stop innerwarden-agent  2>/dev/null || true"
	ssh $(HOST) "sudo systemctl stop innerwarden-sensor 2>/dev/null || true"
	scp $(RELEASE_DIR)/innerwarden-sensor $(HOST):/tmp/innerwarden-sensor
	scp $(RELEASE_DIR)/innerwarden-agent  $(HOST):/tmp/innerwarden-agent
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-sensor /usr/local/bin/innerwarden-sensor"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-agent  /usr/local/bin/innerwarden-agent"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start innerwarden-sensor"
	ssh $(HOST) "sudo systemctl start innerwarden-agent 2>/dev/null || true"
	@echo "Deploy complete — checking status:"
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager"

.PHONY: deploy-config
deploy-config:
	@[ -f config.prod.toml ] || { echo "config.prod.toml not found"; exit 1; }
	ssh $(HOST) "sudo mkdir -p /etc/innerwarden"
	scp config.prod.toml $(HOST):/tmp/innerwarden-config.toml
	ssh $(HOST) "sudo install -o root -g root -m 640 /tmp/innerwarden-config.toml /etc/innerwarden/config.toml"

.PHONY: deploy-service
deploy-service:
	scp examples/systemd/innerwarden-sensor.service $(HOST):/tmp/innerwarden-sensor.service
	scp examples/systemd/innerwarden-agent.service  $(HOST):/tmp/innerwarden-agent.service
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden-sensor.service /etc/systemd/system/innerwarden-sensor.service"
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden-agent.service  /etc/systemd/system/innerwarden-agent.service"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl enable innerwarden-sensor innerwarden-agent"

.PHONY: rollout-precheck
rollout-precheck:
	ssh $(HOST) 'bash -s -- pre' < scripts/rollout_smoke.sh

.PHONY: rollout-postcheck
rollout-postcheck:
	ssh $(HOST) 'bash -s -- post' < scripts/rollout_smoke.sh

.PHONY: rollout-rollback
rollout-rollback:
	ssh $(HOST) 'bash -s -- rollback' < scripts/rollout_smoke.sh

.PHONY: rollout-stop-agent
rollout-stop-agent:
	ssh $(HOST) "sudo systemctl stop innerwarden-agent && sudo systemctl status innerwarden-agent --no-pager || true"

# ─── Remote ops ──────────────────────────────────────────────────────────────

.PHONY: logs
logs:
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -u innerwarden-agent -f --no-pager"

.PHONY: logs-sensor
logs-sensor:
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -f --no-pager"

.PHONY: logs-agent
logs-agent:
	ssh $(HOST) "sudo journalctl -u innerwarden-agent -f --no-pager"

.PHONY: status
status:
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager"

# ─── Consistency ──────────────────────────────────────────────────────────────

.PHONY: consistency-check
consistency-check:
	./scripts/consistency_check.sh

# ─── Helpers ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(CARGO) clean

.PHONY: check
check:
	$(CARGO) clippy --workspace -- -D warnings
	$(CARGO) fmt --all --check
