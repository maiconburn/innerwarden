#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"

IW_USER="${IW_USER:-innerwarden}"
IW_DATA_DIR="${IW_DATA_DIR:-/var/lib/innerwarden}"
IW_SENSOR_SERVICE="${IW_SENSOR_SERVICE:-innerwarden-sensor}"
IW_AGENT_SERVICE="${IW_AGENT_SERVICE:-innerwarden-agent}"
IW_SENSOR_BIN="${IW_SENSOR_BIN:-/usr/local/bin/innerwarden-sensor}"
IW_AGENT_BIN="${IW_AGENT_BIN:-/usr/local/bin/innerwarden-agent}"
IW_SENSOR_CONFIG="${IW_SENSOR_CONFIG:-/etc/innerwarden/config.toml}"
IW_AGENT_CONFIG="${IW_AGENT_CONFIG:-/etc/innerwarden/agent.toml}"

failures=0

usage() {
  cat <<'EOF'
Usage:
  rollout_smoke.sh pre
  rollout_smoke.sh post
  rollout_smoke.sh rollback

Modes:
  pre      Run pre-deploy hardening checks (services/files/permissions/data_dir)
  post     Run post-deploy smoke checks (service status + artifacts + report generation)
  rollback Print quick rollback commands (safe fallback to observability-only)
EOF
}

check_cmd() {
  local label="$1"
  local cmd="$2"
  if bash -lc "$cmd" >/dev/null 2>&1; then
    echo "PASS: $label"
  else
    echo "FAIL: $label"
    failures=$((failures + 1))
  fi
}

info_cmd() {
  local label="$1"
  local cmd="$2"
  if bash -lc "$cmd" >/dev/null 2>&1; then
    echo "INFO: $label"
  else
    echo "INFO: $label (not present)"
  fi
}

run_prechecks() {
  echo "== InnerWarden rollout prechecks =="
  check_cmd "systemctl available" "command -v systemctl"
  check_cmd "innerwarden user exists" "id '$IW_USER'"
  check_cmd "sensor binary present" "test -x '$IW_SENSOR_BIN'"
  check_cmd "agent binary present" "test -x '$IW_AGENT_BIN'"
  check_cmd "sensor config present" "test -r '$IW_SENSOR_CONFIG'"
  check_cmd "agent config present" "test -r '$IW_AGENT_CONFIG'"
  check_cmd "data_dir exists" "test -d '$IW_DATA_DIR'"
  check_cmd "data_dir writable by $IW_USER" "sudo -u '$IW_USER' test -w '$IW_DATA_DIR'"
  check_cmd "sensor unit installed" "systemctl list-unit-files '${IW_SENSOR_SERVICE}.service' | grep -q '${IW_SENSOR_SERVICE}.service'"
  check_cmd "agent unit installed" "systemctl list-unit-files '${IW_AGENT_SERVICE}.service' | grep -q '${IW_AGENT_SERVICE}.service'"
  check_cmd "$IW_USER in systemd-journal group" "id -nG '$IW_USER' | tr ' ' '\n' | grep -qx 'systemd-journal'"
  info_cmd "$IW_USER in docker group (optional)" "id -nG '$IW_USER' | tr ' ' '\n' | grep -qx 'docker'"

  if ((failures > 0)); then
    echo "Precheck finished with $failures failure(s)."
    exit 1
  fi
  echo "Precheck finished successfully."
}

run_postchecks() {
  local today_utc report_date
  today_utc="$(date -u +%F)"
  report_date="$(date +%F)"

  echo "== InnerWarden rollout postchecks =="
  check_cmd "sensor service active" "systemctl is-active --quiet '$IW_SENSOR_SERVICE'"
  check_cmd "agent service active" "systemctl is-active --quiet '$IW_AGENT_SERVICE'"
  check_cmd "events file for UTC day exists and is non-empty" "test -s '$IW_DATA_DIR/events-${today_utc}.jsonl'"
  check_cmd "state.json exists" "test -s '$IW_DATA_DIR/state.json'"
  check_cmd "agent-state.json exists" "test -s '$IW_DATA_DIR/agent-state.json'"

  info_cmd "incidents file exists for UTC day" "test -s '$IW_DATA_DIR/incidents-${today_utc}.jsonl'"
  info_cmd "decisions file exists for UTC day" "test -s '$IW_DATA_DIR/decisions-${today_utc}.jsonl'"

  check_cmd "report generation command works" \
    "sudo -u '$IW_USER' '$IW_AGENT_BIN' --report --data-dir '$IW_DATA_DIR' >/tmp/innerwarden-report-smoke.log 2>&1"
  check_cmd "trial report JSON created" "test -s '$IW_DATA_DIR/trial-report-${report_date}.json'"
  check_cmd "trial report markdown created" "test -s '$IW_DATA_DIR/trial-report-${report_date}.md'"

  if ((failures > 0)); then
    echo "Postcheck finished with $failures failure(s)."
    echo "Hint: inspect /tmp/innerwarden-report-smoke.log and service journals."
    exit 1
  fi
  echo "Postcheck finished successfully."
}

print_rollback() {
  cat <<EOF
== Quick rollback (safe) ==
1) Immediate containment: stop agent (keeps sensor observability alive)
   sudo systemctl stop ${IW_AGENT_SERVICE}

2) Confirm sensor keeps running
   sudo systemctl is-active ${IW_SENSOR_SERVICE}

3) Optional: keep agent disabled until investigation ends
   sudo systemctl disable ${IW_AGENT_SERVICE}

4) Verify artifact flow is still healthy
   ls -la ${IW_DATA_DIR}
   tail -n 20 ${IW_DATA_DIR}/events-\$(date -u +%F).jsonl

5) Re-enable agent later (controlled)
   sudo systemctl enable ${IW_AGENT_SERVICE}
   sudo systemctl start ${IW_AGENT_SERVICE}
EOF
}

case "$MODE" in
  pre)
    run_prechecks
    ;;
  post)
    run_postchecks
    ;;
  rollback)
    print_rollback
    ;;
  *)
    usage
    exit 2
    ;;
esac
