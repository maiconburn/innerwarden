TARGET_LINUX := aarch64-unknown-linux-gnu
SENSOR_DIR   := crates/sensor
AGENT_DIR    := crates/agent
RELEASE_DIR  := target/$(TARGET_LINUX)/release
CARGO        := $(HOME)/.cargo/bin/cargo

# ─── Local dev ───────────────────────────────────────────────────────────────

.PHONY: build
build:
	$(CARGO) build -p innerwarden-sensor -p innerwarden-agent

.PHONY: build-sensor
build-sensor:
	$(CARGO) build -p innerwarden-sensor

.PHONY: build-agent
build-agent:
	$(CARGO) build -p innerwarden-agent

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

.PHONY: replay-qa
replay-qa:
	./scripts/replay_qa.sh

# ─── Cross-compile for Linux arm64 ───────────────────────────────────────────

.PHONY: build-linux
build-linux:
	@$(dir $(CARGO))cargo-zigbuild --version >/dev/null 2>&1 || \
		{ echo "cargo-zigbuild not found — install with: cargo install cargo-zigbuild"; exit 1; }
	@rustup target add $(TARGET_LINUX) 2>/dev/null || true
	$(CARGO) zigbuild -p innerwarden-sensor -p innerwarden-agent \
		--target $(TARGET_LINUX) --release
	@echo "Sensor: $(RELEASE_DIR)/innerwarden-sensor"
	@echo "Agent:  $(RELEASE_DIR)/innerwarden-agent"

# ─── Deploy ──────────────────────────────────────────────────────────────────

# Override on the command line: make deploy HOST=user@myserver
HOST ?= user@your-server

.PHONY: deploy
deploy: build-linux
	@echo "Deploying to $(HOST) ..."
	ssh $(HOST) "sudo systemctl stop innerwarden-sensor 2>/dev/null || true"
	scp $(RELEASE_DIR)/innerwarden-sensor $(HOST):/tmp/innerwarden-sensor
	scp $(RELEASE_DIR)/innerwarden-agent  $(HOST):/tmp/innerwarden-agent
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-sensor /usr/local/bin/innerwarden-sensor"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-agent  /usr/local/bin/innerwarden-agent"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start innerwarden-sensor"
	@echo "Deploy complete — checking status:"
	ssh $(HOST) "sudo systemctl status innerwarden-sensor --no-pager"

.PHONY: deploy-config
deploy-config:
	@[ -f config.prod.toml ] || { echo "config.prod.toml not found"; exit 1; }
	ssh $(HOST) "sudo mkdir -p /etc/innerwarden"
	scp config.prod.toml $(HOST):/tmp/innerwarden-config.toml
	ssh $(HOST) "sudo install -o root -g root -m 640 /tmp/innerwarden-config.toml /etc/innerwarden/config.toml"

.PHONY: deploy-service
deploy-service:
	scp examples/systemd/innerwarden-sensor.service $(HOST):/tmp/innerwarden-sensor.service
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden-sensor.service /etc/systemd/system/innerwarden-sensor.service"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl enable innerwarden-sensor"

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
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -f --no-pager"

.PHONY: status
status:
	ssh $(HOST) "sudo systemctl status innerwarden-sensor --no-pager"

# ─── Helpers ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(CARGO) clean

.PHONY: check
check:
	$(CARGO) clippy --workspace -- -D warnings
	$(CARGO) fmt --all --check
