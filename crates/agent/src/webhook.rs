use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// The JSON body posted to the webhook endpoint.
/// Intentionally small — only the fields needed for a notification.
#[derive(Debug, Serialize)]
struct Payload<'a> {
    ts: &'a str,
    host: &'a str,
    incident_id: &'a str,
    severity: &'a str,
    title: &'a str,
    summary: &'a str,
    tags: &'a [String],
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// POST an incident notification to `url`.
///
/// Failures are logged as warnings and swallowed — a dead webhook must never
/// stop the agent from processing events (fail-open policy).
pub async fn send_incident(url: &str, timeout_secs: u64, incident: &Incident) -> Result<()> {
    let severity_str = format!("{:?}", incident.severity).to_lowercase();
    let ts_str = incident.ts.to_rfc3339();

    let payload = Payload {
        ts: &ts_str,
        host: &incident.host,
        incident_id: &incident.incident_id,
        severity: &severity_str,
        title: &incident.title,
        summary: &incident.summary,
        tags: &incident.tags,
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
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
