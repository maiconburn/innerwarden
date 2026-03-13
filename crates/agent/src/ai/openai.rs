use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

// ---------------------------------------------------------------------------
// OpenAI provider (real implementation)
// ---------------------------------------------------------------------------

pub struct OpenAiProvider {
    api_key: String,
    model: String,
    /// Shared HTTP client — holds the connection pool across calls.
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(api_key: String, model: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("failed to build reqwest client");
        Self { api_key, model, client }
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        if self.api_key.is_empty() {
            bail!(
                "OpenAI API key not configured. Set OPENAI_API_KEY env var or [ai].api_key in config."
            );
        }

        let prompt = build_prompt(ctx);
        debug!(model = %self.model, "calling OpenAI API");

        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user",   "content": prompt }
            ],
            "response_format": { "type": "json_object" },
            "temperature": 0.2,
            "max_tokens": 512,
        });

        let resp = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("OpenAI API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("OpenAI API returned {status}: {}", text.chars().take(300).collect::<String>());
        }

        let completion: ChatCompletion = resp
            .json()
            .await
            .context("failed to parse OpenAI response")?;

        let content = completion
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .context("OpenAI returned empty response")?;

        parse_decision(&content)
    }
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT: &str = r#"
You are a real-time security decision engine for a Linux server running Inner Warden.

Your job is to analyze security incidents and select the most appropriate response skill.
Be conservative — a false block harms legitimate users. A missed attack harms the server.

Rules:
- Prefer block_ip for clear, external brute-force attacks with high confidence.
- Prefer monitor for ambiguous cases where more data is needed.
- Prefer ignore for private IPs, already-handled incidents, or low-confidence signals.
- Never recommend blocking internal/private IPs (10.x, 192.168.x, 172.16-31.x, 127.x).
- Set auto_execute=true only when confidence > 0.85 and the attack is unambiguous.

Respond ONLY with valid JSON using exactly this schema (no extra fields, no markdown):
{
  "action": "block_ip" | "monitor" | "honeypot" | "request_confirmation" | "ignore",
  "target_ip": "<IP or null>",
  "skill_id": "<skill id from available_skills, or null>",
  "confidence": <0.0 to 1.0>,
  "auto_execute": <true or false>,
  "reason": "<one-sentence explanation>",
  "alternatives": ["<alt1>", "<alt2>"],
  "estimated_threat": "low" | "medium" | "high" | "critical"
}
"#;

fn build_prompt(ctx: &DecisionContext<'_>) -> String {
    let incident_json = serde_json::to_string_pretty(ctx.incident)
        .unwrap_or_else(|_| "{}".to_string());

    let events_json = {
        let events: Vec<_> = ctx.recent_events.iter().map(|e| {
            json!({
                "ts": e.ts,
                "kind": e.kind,
                "summary": e.summary,
                "severity": format!("{:?}", e.severity),
                "source": e.source,
            })
        }).collect();
        serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".to_string())
    };

    let related_incidents_json = {
        let related: Vec<_> = ctx.related_incidents.iter().map(|inc| {
            json!({
                "ts": inc.ts,
                "incident_id": inc.incident_id,
                "detector_kind": inc.incident_id.split(':').next().unwrap_or("unknown"),
                "severity": format!("{:?}", inc.severity),
                "title": inc.title,
                "summary": inc.summary,
                "entities": inc.entities,
            })
        }).collect();
        serde_json::to_string_pretty(&related).unwrap_or_else(|_| "[]".to_string())
    };

    let skills_json = serde_json::to_string_pretty(&ctx.available_skills)
        .unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"Analyze this security incident and decide on a response.

INCIDENT:
{incident_json}

RECENT EVENTS FROM THE SAME ENTITY (last {count}):
{events_json}

TEMPORALLY CORRELATED INCIDENTS (last {related_count}, grouped by pivot ip/user/detector):
{related_incidents_json}

ALREADY BLOCKED IPs (do not block these again):
{blocked:?}

AVAILABLE RESPONSE SKILLS (select skill_id from this list):
{skills_json}

Select the best skill and return a JSON decision."#,
        incident_json = incident_json,
        events_json = events_json,
        count = ctx.recent_events.len(),
        related_incidents_json = related_incidents_json,
        related_count = ctx.related_incidents.len(),
        blocked = ctx.already_blocked,
        skills_json = skills_json,
    )
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Deserialize)]
struct Message {
    content: Option<String>,
}

/// Raw JSON structure expected from the AI response.
#[derive(Deserialize)]
struct RawDecision {
    action: String,
    target_ip: Option<String>,
    skill_id: Option<String>,
    confidence: f32,
    auto_execute: bool,
    reason: String,
    #[serde(default)]
    alternatives: Vec<String>,
    #[serde(default = "default_threat")]
    estimated_threat: String,
}

fn default_threat() -> String {
    "medium".to_string()
}

fn parse_decision(content: &str) -> Result<AiDecision> {
    let raw: RawDecision = serde_json::from_str(content)
        .with_context(|| format!("failed to parse AI decision JSON: {content}"))?;

    let action = match raw.action.as_str() {
        "block_ip" => {
            // target_ip is mandatory for block_ip — a missing IP would produce
            // a bogus `sudo ufw deny from unknown` command. Downgrade to Ignore
            // so the audit trail captures the event without executing a bad command.
            let Some(ip) = raw.target_ip.clone() else {
                warn!("AI returned block_ip with no target_ip — downgrading to ignore");
                return Ok(AiDecision {
                    action: AiAction::Ignore {
                        reason: "block_ip action had no target IP".to_string(),
                    },
                    confidence: raw.confidence.clamp(0.0, 1.0),
                    auto_execute: false,
                    reason: raw.reason,
                    alternatives: raw.alternatives,
                    estimated_threat: raw.estimated_threat,
                });
            };
            let skill_id = raw
                .skill_id
                .clone()
                .unwrap_or_else(|| "block-ip-ufw".to_string());
            AiAction::BlockIp { ip, skill_id }
        }
        "monitor" => AiAction::Monitor {
            ip: raw.target_ip.clone().unwrap_or_else(|| "unknown".to_string()),
        },
        "honeypot" => AiAction::Honeypot {
            ip: raw.target_ip.clone().unwrap_or_else(|| "unknown".to_string()),
        },
        "request_confirmation" => AiAction::RequestConfirmation {
            summary: raw.reason.clone(),
        },
        "ignore" | _ => {
            if raw.action != "ignore" {
                warn!(action = %raw.action, "unknown AI action — defaulting to ignore");
            }
            AiAction::Ignore { reason: raw.reason.clone() }
        }
    };

    Ok(AiDecision {
        action,
        confidence: raw.confidence.clamp(0.0, 1.0),
        auto_execute: raw.auto_execute,
        reason: raw.reason,
        alternatives: raw.alternatives,
        estimated_threat: raw.estimated_threat,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_ip_decision() {
        let json = r#"{
            "action": "block_ip",
            "target_ip": "203.0.113.10",
            "skill_id": "block-ip-ufw",
            "confidence": 0.97,
            "auto_execute": true,
            "reason": "9 SSH failures in 5 min from external IP",
            "alternatives": ["monitor"],
            "estimated_threat": "high"
        }"#;

        let d = parse_decision(json).unwrap();
        assert!(matches!(d.action, AiAction::BlockIp { ref ip, .. } if ip == "203.0.113.10"));
        assert!((d.confidence - 0.97).abs() < 0.01);
        assert!(d.auto_execute);
        assert_eq!(d.estimated_threat, "high");
    }

    #[test]
    fn parses_ignore_decision() {
        let json = r#"{
            "action": "ignore",
            "target_ip": null,
            "skill_id": null,
            "confidence": 0.9,
            "auto_execute": false,
            "reason": "Low confidence, insufficient data",
            "alternatives": [],
            "estimated_threat": "low"
        }"#;

        let d = parse_decision(json).unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
    }

    #[test]
    fn block_ip_without_target_ip_downgrades_to_ignore() {
        let json = r#"{
            "action": "block_ip",
            "target_ip": null,
            "skill_id": "block-ip-ufw",
            "confidence": 0.92,
            "auto_execute": true,
            "reason": "Should block but IP is missing",
            "alternatives": ["ignore"],
            "estimated_threat": "high"
        }"#;

        let d = parse_decision(json).unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert!(!d.auto_execute, "downgraded decision must never auto-execute");
    }

    #[test]
    fn unknown_action_defaults_to_ignore() {
        let json = r#"{
            "action": "unknown_future_action",
            "target_ip": null,
            "skill_id": null,
            "confidence": 0.5,
            "auto_execute": false,
            "reason": "test",
            "alternatives": [],
            "estimated_threat": "low"
        }"#;

        let d = parse_decision(json).unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
    }
}
