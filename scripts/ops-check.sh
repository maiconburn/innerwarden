#!/usr/bin/env bash
# ops-check.sh — quick operational health check from the latest trial report JSON.
# Reads the most recent trial-report-*.json in IW_DATA_DIR (default: /var/lib/innerwarden).
#
# Usage:
#   ./scripts/ops-check.sh [data_dir]
#   IW_DATA_DIR=/var/lib/innerwarden ./scripts/ops-check.sh
set -euo pipefail

IW_DATA_DIR="${1:-${IW_DATA_DIR:-/var/lib/innerwarden}}"

# Find latest report
REPORT=$(ls -1t "$IW_DATA_DIR"/trial-report-*.json 2>/dev/null | head -1 || true)
if [[ -z "$REPORT" ]]; then
  echo "ERROR: no trial-report-*.json found in $IW_DATA_DIR"
  echo "Run: innerwarden-agent --report --data-dir $IW_DATA_DIR"
  exit 1
fi

echo "== InnerWarden Ops Check =="
echo "Report: $REPORT"
echo ""

# ── Recent 6h window ───────────────────────────────────────────────────────────
echo "=== Recent 6h window ==="
jq -r '
  .recent_window |
  "Events:            \(.events)",
  "Incidents:         \(.incidents)",
  "High/critical:     \(.high_critical_incidents)",
  "Decisions:         \(.decisions)",
  "Latest event ts:   \(.latest_event_ts)",
  "Latest incident ts:\(.latest_incident_ts)",
  "Latest decision ts:\(.latest_decision_ts)",
  "Latest telemetry:  \(.latest_telemetry_ts)"
' "$REPORT"

echo ""
echo "Decisions by action (last 6h):"
jq -r '.recent_window.decisions_by_action | to_entries[] | "  \(.key): \(.value)"' "$REPORT" 2>/dev/null || echo "  none"

# ── Day totals ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Day totals ==="
jq -r '
  "Events:    \(.detection_summary.total_events)",
  "Incidents: \(.detection_summary.total_incidents)",
  "Decisions: \(.agent_ai_summary.total_decisions)",
  "block_ip:  \(.agent_ai_summary.block_ip_count)",
  "ignore:    \(.agent_ai_summary.ignore_count)",
  "dry_run:   \(.agent_ai_summary.dry_run_count)"
' "$REPORT"

echo ""
echo "Actions breakdown:"
jq -r '.agent_ai_summary.decisions_by_action | to_entries[] | "  \(.key): \(.value)"' "$REPORT" 2>/dev/null || echo "  none"

# ── Anomaly hints ──────────────────────────────────────────────────────────────
echo ""
echo "=== Anomaly hints ==="
HINT_COUNT=$(jq '.anomaly_hints | length' "$REPORT")
if [[ "$HINT_COUNT" -eq 0 ]]; then
  echo "  none"
else
  jq -r '.anomaly_hints[] | "  [\(.severity)] \(.code): \(.message)"' "$REPORT"
fi

# ── Suggested improvements ─────────────────────────────────────────────────────
echo ""
echo "=== Suggested improvements ==="
jq -r '.suggested_improvements[] | "  - \(.)"' "$REPORT" 2>/dev/null || echo "  none"

echo ""
echo "=== Done ==="
