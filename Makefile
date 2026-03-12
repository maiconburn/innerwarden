TARGET_LINUX := aarch64-unknown-linux-gnu
BINARY       := innerwarden
AGENT_DIR    := crates/agent
RELEASE_DIR  := target/$(TARGET_LINUX)/release
CARGO        := $(HOME)/.cargo/bin/cargo

# ─── Local dev ───────────────────────────────────────────────────────────────

.PHONY: build
build:
	$(CARGO) build --manifest-path $(AGENT_DIR)/Cargo.toml

.PHONY: test
test:
	$(CARGO) test --manifest-path $(AGENT_DIR)/Cargo.toml

.PHONY: run
run:
	$(CARGO) run --manifest-path $(AGENT_DIR)/Cargo.toml -- --config config.test.toml

# ─── Cross-compile for Linux arm64 ───────────────────────────────────────────

.PHONY: build-linux
build-linux:
	@$(dir $(CARGO))cargo-zigbuild --version >/dev/null 2>&1 || \
		{ echo "cargo-zigbuild not found — install with: cargo install cargo-zigbuild"; exit 1; }
	@rustup target add $(TARGET_LINUX) 2>/dev/null || true
	$(CARGO) zigbuild --manifest-path $(AGENT_DIR)/Cargo.toml \
		--target $(TARGET_LINUX) --release
	@echo "Binary: $(RELEASE_DIR)/$(BINARY)"

# ─── Deploy ──────────────────────────────────────────────────────────────────

# Override on the command line: make deploy HOST=user@myserver
HOST ?= user@your-server

.PHONY: deploy
deploy: build-linux
	@echo "Deploying to $(HOST) ..."
	ssh $(HOST) "sudo systemctl stop $(BINARY) 2>/dev/null || true"
	scp $(RELEASE_DIR)/$(BINARY) $(HOST):/tmp/$(BINARY)
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/$(BINARY) /usr/local/bin/$(BINARY)"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start $(BINARY)"
	@echo "Deploy complete — checking status:"
	ssh $(HOST) "sudo systemctl status $(BINARY) --no-pager"

.PHONY: deploy-config
deploy-config:
	@[ -f config.prod.toml ] || { echo "config.prod.toml not found"; exit 1; }
	ssh $(HOST) "sudo mkdir -p /etc/innerwarden"
	scp config.prod.toml $(HOST):/tmp/innerwarden-config.toml
	ssh $(HOST) "sudo install -o root -g root -m 640 /tmp/innerwarden-config.toml /etc/innerwarden/config.toml"

.PHONY: deploy-service
deploy-service:
	scp examples/systemd/innerwarden.service $(HOST):/tmp/innerwarden.service
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden.service /etc/systemd/system/innerwarden.service"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl enable innerwarden"

# ─── Remote ops ──────────────────────────────────────────────────────────────

.PHONY: logs
logs:
	ssh $(HOST) "sudo journalctl -u $(BINARY) -f --no-pager"

.PHONY: status
status:
	ssh $(HOST) "sudo systemctl status $(BINARY) --no-pager"

# ─── Helpers ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(CARGO) clean

.PHONY: check
check:
	$(CARGO) clippy --manifest-path $(AGENT_DIR)/Cargo.toml -- -D warnings
	$(CARGO) fmt --manifest-path $(AGENT_DIR)/Cargo.toml --check
