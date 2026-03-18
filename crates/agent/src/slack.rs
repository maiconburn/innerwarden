use anyhow::{Context, Result};
use innerwarden_core::{entities::EntityType, incident::Incident};
use serde_json::json;
use tracing::warn;

// ---------------------------------------------------------------------------
// Slack Incoming Webhook client
// ---------------------------------------------------------------------------

/// Sends incident alerts to a Slack channel via an Incoming Webhook URL.
///
/// Uses Block Kit for a structured, readable message.
/// Failure is logged as a warning and swallowed — a dead Slack webhook must
/// never stop the agent from processing events (fail-open policy).
pub struct SlackClient {
    /// Slack Incoming Webhook URL.
    webhook_url: String,
    /// Reused HTTP client (connection pool).
    client: reqwest::Client,
}

impl SlackClient {
    pub fn new(webhook_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build Slack HTTP client")?;
        Ok(Self {
            webhook_url: webhook_url.into(),
            client,
        })
    }

    /// Send an incident alert to Slack.
    ///
    /// The message uses Block Kit: a severity-coloured header section, a brief
    /// summary, entity details, and an optional deep-link to the dashboard.
    pub async fn send_incident_alert(
        &self,
        incident: &Incident,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let severity_str = format!("{:?}", incident.severity);
        let emoji = severity_emoji(&severity_str);
        let color = severity_color(&severity_str);

        // Extract primary IP or user entity for display
        let entity_line = {
            let ip = incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::Ip)
                .map(|e| format!("IP: `{}`", e.value));
            let user = incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::User)
                .map(|e| format!("User: `{}`", e.value));
            [ip, user]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("  |  ")
        };

        // Dashboard deep-link button (optional)
        let actions_block = if let Some(url) = dashboard_url {
            // Build a URL that deep-links to the first IP entity if available
            let link_url = incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::Ip)
                .map(|e| format!("{}/?entity={}", url, e.value))
                .unwrap_or_else(|| url.to_string());

            Some(json!({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": { "type": "plain_text", "text": "Investigate →", "emoji": true },
                    "url": link_url,
                    "style": "danger"
                }]
            }))
        } else {
            None
        };

        let mut blocks = vec![
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("{emoji} *{severity_str} — {title}*\n{summary}",
                        emoji = emoji,
                        severity_str = severity_str.to_uppercase(),
                        title = &incident.title,
                        summary = &incident.summary,
                    )
                }
            }),
            json!({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": format!("🖥 `{host}`  {entity_part}  🕐 {time}",
                        host = &incident.host,
                        entity_part = if entity_line.is_empty() { String::new() } else { format!(" |  {entity_line}") },
                        time = incident.ts.format("%H:%M UTC"),
                    )
                }]
            }),
        ];

        if let Some(ab) = actions_block {
            blocks.push(ab);
        }

        // Slack's `attachments` API supports a sidebar colour line.
        let payload = json!({
            "attachments": [{
                "color": color,
                "blocks": blocks,
                "fallback": format!("[InnerWarden] {}: {}", severity_str, incident.title),
            }]
        });

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Slack webhook POST to {} failed", self.webhook_url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                body = body.chars().take(200).collect::<String>(),
                "Slack webhook returned non-2xx"
            );
        }

        Ok(())
    }
}

fn severity_emoji(severity: &str) -> &'static str {
    match severity {
        "Critical" => "🚨",
        "High" => "🔴",
        "Medium" => "🟠",
        "Low" => "🟡",
        _ => "ℹ️",
    }
}

fn severity_color(severity: &str) -> &'static str {
    match severity {
        "Critical" => "#9b1c1c", // dark red
        "High" => "#f43f5e",     // red
        "Medium" => "#f97316",   // orange
        "Low" => "#eab308",      // yellow
        _ => "#6b7280",          // gray
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_emoji_maps_correctly() {
        assert_eq!(severity_emoji("Critical"), "🚨");
        assert_eq!(severity_emoji("High"), "🔴");
        assert_eq!(severity_emoji("Medium"), "🟠");
        assert_eq!(severity_emoji("Low"), "🟡");
        assert_eq!(severity_emoji("Info"), "ℹ️");
    }

    #[test]
    fn severity_color_maps_correctly() {
        assert_eq!(severity_color("Critical"), "#9b1c1c");
        assert_eq!(severity_color("High"), "#f43f5e");
        assert_eq!(severity_color("Medium"), "#f97316");
        assert_eq!(severity_color("Low"), "#eab308");
        assert_eq!(severity_color("Debug"), "#6b7280");
    }

    #[test]
    fn slack_client_new_succeeds_with_valid_url() {
        let result = SlackClient::new("https://hooks.slack.com/services/T/B/xyz");
        assert!(result.is_ok());
    }

    #[test]
    fn severity_emoji_unknown_returns_info() {
        assert_eq!(severity_emoji("Unknown"), "ℹ️");
    }

    #[test]
    fn severity_color_unknown_returns_gray() {
        assert_eq!(severity_color("Unknown"), "#6b7280");
    }
}
