use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

// ---------------------------------------------------------------------------
// Payload formats
// ---------------------------------------------------------------------------

/// The JSON body posted to the webhook endpoint (default format).
#[derive(Debug, Serialize)]
struct DefaultPayload<'a> {
    ts: &'a str,
    host: &'a str,
    incident_id: &'a str,
    severity: &'a str,
    title: &'a str,
    summary: &'a str,
    tags: &'a [String],
}

/// Build a PagerDuty Events API v2 payload.
fn pagerduty_payload(incident: &Incident, routing_key: &str) -> serde_json::Value {
    let severity = match format!("{:?}", incident.severity).to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "error",
        "medium" => "warning",
        _ => "info",
    };
    serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": incident.incident_id,
        "payload": {
            "summary": format!("[{}] {} — {}", incident.host, incident.title, incident.summary),
            "source": incident.host,
            "severity": severity,
            "component": "innerwarden",
            "group": incident.tags.first().unwrap_or(&"security".to_string()),
            "custom_details": {
                "incident_id": incident.incident_id,
                "tags": incident.tags,
            }
        }
    })
}

/// Build an Opsgenie Alert API payload.
fn opsgenie_payload(incident: &Incident) -> serde_json::Value {
    let priority = match format!("{:?}", incident.severity).to_lowercase().as_str() {
        "critical" => "P1",
        "high" => "P2",
        "medium" => "P3",
        _ => "P4",
    };
    serde_json::json!({
        "message": format!("[{}] {}", incident.host, incident.title),
        "alias": incident.incident_id,
        "description": incident.summary,
        "priority": priority,
        "source": "innerwarden",
        "tags": incident.tags,
        "entity": incident.host,
        "details": {
            "incident_id": incident.incident_id,
            "severity": format!("{:?}", incident.severity).to_lowercase(),
        }
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// POST an incident notification to `url`.
///
/// `format` controls the payload shape:
/// - `"default"` — InnerWarden native format
/// - `"pagerduty"` — PagerDuty Events API v2
/// - `"opsgenie"` — Opsgenie Alert API
///
/// For PagerDuty, `url` should be "https://events.pagerduty.com/v2/enqueue"
/// and the routing key goes in the webhook URL or is extracted from it.
///
/// Failures are logged as warnings and swallowed — fail-open policy.
pub async fn send_incident(
    url: &str,
    timeout_secs: u64,
    incident: &Incident,
    format: &str,
) -> Result<()> {
    let severity_str = format!("{:?}", incident.severity).to_lowercase();
    let ts_str = incident.ts.to_rfc3339();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let resp = match format {
        "pagerduty" => {
            // Extract routing key from URL query param or use a default
            let routing_key = url
                .split("routing_key=")
                .nth(1)
                .unwrap_or("")
                .split('&')
                .next()
                .unwrap_or("");
            let base_url = if url.contains('?') {
                url.split('?').next().unwrap_or(url)
            } else {
                url
            };
            let payload = pagerduty_payload(incident, routing_key);
            client.post(base_url).json(&payload).send().await
        }
        "opsgenie" => {
            let payload = opsgenie_payload(incident);
            client.post(url).json(&payload).send().await
        }
        _ => {
            // Default InnerWarden format
            let payload = DefaultPayload {
                ts: &ts_str,
                host: &incident.host,
                incident_id: &incident.incident_id,
                severity: &severity_str,
                title: &incident.title,
                summary: &incident.summary,
                tags: &incident.tags,
            };
            client.post(url).json(&payload).send().await
        }
    }
    .with_context(|| format!("webhook POST to {url} failed"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(
            url,
            status = status.as_u16(),
            body = body.chars().take(200).collect::<String>(),
            "webhook returned non-2xx"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Severity comparison helper (used in main.rs to filter by min_severity)
// ---------------------------------------------------------------------------

/// Returns a numeric rank for a Severity so we can compare thresholds.
pub fn severity_rank(s: &innerwarden_core::event::Severity) -> u8 {
    use innerwarden_core::event::Severity::*;
    match s {
        Debug => 0,
        Info => 1,
        Low => 2,
        Medium => 3,
        High => 4,
        Critical => 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{entities::EntityRef, event::Severity};

    fn test_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026".to_string(),
            severity: Severity::High,
            title: "SSH brute force from 1.2.3.4".to_string(),
            summary: "8 failed attempts".to_string(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec!["ssh".to_string(), "bruteforce".to_string()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        }
    }

    #[test]
    fn pagerduty_format_has_required_fields() {
        let inc = test_incident();
        let payload = pagerduty_payload(&inc, "test-routing-key");
        assert_eq!(payload["routing_key"], "test-routing-key");
        assert_eq!(payload["event_action"], "trigger");
        assert_eq!(payload["dedup_key"], inc.incident_id);
        assert_eq!(payload["payload"]["severity"], "error"); // High → error
        assert!(payload["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("SSH brute force"));
    }

    #[test]
    fn opsgenie_format_has_required_fields() {
        let inc = test_incident();
        let payload = opsgenie_payload(&inc);
        assert_eq!(payload["priority"], "P2"); // High → P2
        assert_eq!(payload["source"], "innerwarden");
        assert!(payload["message"]
            .as_str()
            .unwrap()
            .contains("SSH brute force"));
        assert_eq!(payload["alias"], inc.incident_id);
    }

    #[test]
    fn pagerduty_severity_mapping() {
        let mut inc = test_incident();
        inc.severity = Severity::Critical;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "critical");

        inc.severity = Severity::Medium;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "warning");

        inc.severity = Severity::Low;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "info");
    }

    #[test]
    fn opsgenie_priority_mapping() {
        let mut inc = test_incident();
        inc.severity = Severity::Critical;
        assert_eq!(opsgenie_payload(&inc)["priority"], "P1");

        inc.severity = Severity::Medium;
        assert_eq!(opsgenie_payload(&inc)["priority"], "P3");
    }
}
