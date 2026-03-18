#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"

if [[ ! -x "$CARGO_BIN" ]]; then
  echo "error: cargo not found at $CARGO_BIN"
  exit 1
fi

TMP_DIR="${1:-$(mktemp -d "${TMPDIR:-/tmp}/innerwarden-replay.XXXXXX")}"
KEEP_TMP="${KEEP_TMP:-0}"

cleanup() {
  local status=$?
  if [[ "$KEEP_TMP" == "1" ]]; then
    echo "Replay workspace kept at: $TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

DATA_DIR="$TMP_DIR/data"
mkdir -p "$DATA_DIR"

SENSOR_CFG="$TMP_DIR/sensor-replay.toml"
AGENT_CFG="$TMP_DIR/agent-replay.toml"
AUTH_FIXTURE="$TMP_DIR/replay-auth.log"
FALCO_FIXTURE="$TMP_DIR/replay-falco.jsonl"
SURICATA_FIXTURE="$TMP_DIR/replay-suricata-eve.jsonl"
OSQUERY_FIXTURE="$TMP_DIR/replay-osquery.jsonl"

SENSOR_LOG="$TMP_DIR/sensor.log"
AGENT_LOG="$TMP_DIR/agent.log"
REPORT_LOG="$TMP_DIR/report.log"

DATE="$(date +%F)"
EVENTS_FILE="$DATA_DIR/events-$DATE.jsonl"
INCIDENTS_FILE="$DATA_DIR/incidents-$DATE.jsonl"
DECISIONS_FILE="$DATA_DIR/decisions-$DATE.jsonl"
TELEMETRY_FILE="$DATA_DIR/telemetry-$DATE.jsonl"
SUMMARY_FILE="$DATA_DIR/summary-$DATE.md"
REPORT_MD="$DATA_DIR/trial-report-$DATE.md"
REPORT_JSON="$DATA_DIR/trial-report-$DATE.json"
STATE_FILE="$DATA_DIR/state.json"
AGENT_STATE_FILE="$DATA_DIR/agent-state.json"
SENSOR_BIN="$ROOT_DIR/target/debug/innerwarden-sensor"
AGENT_BIN="$ROOT_DIR/target/debug/innerwarden-agent"

assert_file_nonempty() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "assertion failed: missing file $path"
    exit 1
  fi
  if [[ ! -s "$path" ]]; then
    echo "assertion failed: empty file $path"
    exit 1
  fi
}

assert_json_metric_positive() {
  local path="$1"
  local metric="$2"
  if ! grep -Eq "\"${metric}\"[[:space:]]*:[[:space:]]*[1-9][0-9]*" "$path"; then
    echo "assertion failed: ${metric} should be > 0 in $path"
    exit 1
  fi
}

assert_events_contain_source() {
  local source="$1"
  if ! grep -q "\"source\":\"$source\"" "$EVENTS_FILE"; then
    echo "assertion failed: events file should contain source=$source events"
    exit 1
  fi
}

echo "[replay] preparing fixture logs"

# sample-auth.log uses TEST-NET ranges that are filtered by the AI gate.
# Replace with routable IPs so decision/audit paths are exercised deterministically.
sed \
  -e 's/203\.0\.113\.10/1.2.3.4/g' \
  -e 's/198\.51\.100\.5/5.6.7.8/g' \
  "$ROOT_DIR/testdata/sample-auth.log" > "$AUTH_FIXTURE"

# Falco fixture: use routable IPs for Outbound C2 event
sed \
  -e 's/1\.2\.3\.4/1.2.3.4/g' \
  "$ROOT_DIR/testdata/sample-falco.jsonl" > "$FALCO_FIXTURE"

# Suricata EVE fixture: already uses routable IPs in sample
cp "$ROOT_DIR/testdata/sample-suricata-eve.jsonl" "$SURICATA_FIXTURE"

# osquery fixture: already uses routable IPs in crontab event
cp "$ROOT_DIR/testdata/sample-osquery.jsonl" "$OSQUERY_FIXTURE"

cat > "$SENSOR_CFG" <<EOF
[agent]
host_id = "replay-host"

[output]
data_dir = "$DATA_DIR"
write_events = true

[collectors.auth_log]
enabled = true
path = "$AUTH_FIXTURE"

[collectors.journald]
enabled = false
units = ["sshd", "sudo", "kernel"]

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = false
poll_seconds = 60
paths = []

[collectors.falco_log]
enabled = true
path = "$FALCO_FIXTURE"

[collectors.suricata_eve]
enabled = true
path = "$SURICATA_FIXTURE"
event_types = ["alert", "http"]

[collectors.osquery_log]
enabled = true
path = "$OSQUERY_FIXTURE"

[detectors.ssh_bruteforce]
enabled = true
threshold = 5
window_seconds = 300

[detectors.credential_stuffing]
enabled = true
threshold = 3
window_seconds = 300

[detectors.port_scan]
enabled = false
threshold = 12
window_seconds = 60
EOF

cat > "$AGENT_CFG" <<EOF
[narrative]
enabled = true
keep_days = 7

[webhook]
enabled = false
url = ""
min_severity = "medium"
timeout_secs = 5

[ai]
enabled = true
provider = "anthropic"
model = "claude-stub"
context_events = 20
confidence_threshold = 0.8
incident_poll_secs = 2

[telemetry]
enabled = true

[responder]
enabled = false
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw"]
EOF

echo "[replay] building binaries"
"$CARGO_BIN" build -p innerwarden-sensor -p innerwarden-agent > /dev/null
if [[ ! -x "$SENSOR_BIN" || ! -x "$AGENT_BIN" ]]; then
  echo "assertion failed: expected debug binaries were not built"
  exit 1
fi

echo "[replay] running sensor from multi-source fixtures (graceful stop)"
"$SENSOR_BIN" --config "$SENSOR_CFG" > "$SENSOR_LOG" 2>&1 &
SENSOR_PID=$!
sleep 4
kill -INT "$SENSOR_PID" 2>/dev/null || true
for _ in $(seq 1 20); do
  if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$SENSOR_PID" 2>/dev/null; then
  kill -TERM "$SENSOR_PID" 2>/dev/null || true
fi
wait "$SENSOR_PID" || true

echo "[replay] running agent once (AI stub + audit)"
"$AGENT_BIN" --data-dir "$DATA_DIR" --config "$AGENT_CFG" --once > "$AGENT_LOG" 2>&1

echo "[replay] generating operational report"
"$AGENT_BIN" --report --data-dir "$DATA_DIR" > "$REPORT_LOG" 2>&1

echo "[replay] validating artifacts"
assert_file_nonempty "$EVENTS_FILE"
assert_file_nonempty "$INCIDENTS_FILE"
assert_file_nonempty "$DECISIONS_FILE"
assert_file_nonempty "$TELEMETRY_FILE"
assert_file_nonempty "$SUMMARY_FILE"
assert_file_nonempty "$STATE_FILE"
assert_file_nonempty "$AGENT_STATE_FILE"
assert_file_nonempty "$REPORT_MD"
assert_file_nonempty "$REPORT_JSON"

if ! grep -Eq '"expected_files_present"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: expected_files_present should be true"
  exit 1
fi
if ! grep -Eq '"state_json_readable"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: state_json_readable should be true"
  exit 1
fi
if ! grep -Eq '"agent_state_json_readable"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: agent_state_json_readable should be true"
  exit 1
fi
if ! grep -Eq '"available"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: operational telemetry should be available"
  exit 1
fi

assert_json_metric_positive "$REPORT_JSON" "total_events"
assert_json_metric_positive "$REPORT_JSON" "total_incidents"
assert_json_metric_positive "$REPORT_JSON" "total_decisions"
assert_json_metric_positive "$REPORT_JSON" "ai_decision_count"

# Multi-source assertions: each integration must emit at least one event
# Source names match what collectors actually emit in the Event.source field
assert_events_contain_source "auth.log"
assert_events_contain_source "falco"
assert_events_contain_source "suricata"
assert_events_contain_source "osquery"

if ! grep -q '"ai_provider":"anthropic"' "$DECISIONS_FILE"; then
  echo "assertion failed: decisions must include anthropic provider entries"
  exit 1
fi

FALCO_COUNT=$(grep -c '"source":"falco"' "$EVENTS_FILE" || true)
SURICATA_COUNT=$(grep -c '"source":"suricata"' "$EVENTS_FILE" || true)
OSQUERY_COUNT=$(grep -c '"source":"osquery"' "$EVENTS_FILE" || true)
AUTH_COUNT=$(grep -c '"source":"auth.log"' "$EVENTS_FILE" || true)

echo "[replay] success"
echo "  data_dir:   $DATA_DIR"
echo "  events:     $(wc -l < "$EVENTS_FILE" | tr -d ' ') total"
echo "    auth_log:    $AUTH_COUNT"
echo "    falco_log:   $FALCO_COUNT"
echo "    suricata_eve:$SURICATA_COUNT"
echo "    osquery_log: $OSQUERY_COUNT"
echo "  incidents:  $(wc -l < "$INCIDENTS_FILE" | tr -d ' ')"
echo "  decisions:  $(wc -l < "$DECISIONS_FILE" | tr -d ' ')"
echo "  telemetry:  $(wc -l < "$TELEMETRY_FILE" | tr -d ' ')"
echo "  report:     $REPORT_MD"
