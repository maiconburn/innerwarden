mod anthropic;
mod ollama;
mod openai;

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::AiConfig;

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The action the AI recommends (and may auto-execute).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiAction {
    /// Block the attacking IP immediately via the configured firewall backend.
    /// `skill_id` is the skill the AI selected (e.g. "block-ip-ufw").
    BlockIp { ip: String, skill_id: String },

    /// Shadow-monitor the IP — log all its activity without blocking.
    /// Premium feature stub; community can implement full tracking.
    Monitor { ip: String },

    /// Trigger honeypot response.
    /// Behavior depends on runtime mode:
    /// - `demo`: synthetic marker
    /// - `listener`: bounded multi-service decoy listeners with optional redirect
    Honeypot { ip: String },

    /// Temporarily suspend sudo privileges for a user.
    /// Implemented by the `suspend-user-sudo` skill using a sudoers drop-in.
    SuspendUserSudo { user: String, duration_secs: u64 },

    /// Kill all processes owned by a user (pkill -9 -u <user>).
    /// Used for suspicious execution incidents.
    KillProcess { user: String, duration_secs: u64 },

    /// Pause or stop a Docker container in response to an anomaly.
    /// `action` is "pause" (default, reversible) or "stop".
    BlockContainer {
        container_id: String,
        action: String,
    },

    /// Send a confirmation request to the operator webhook before acting.
    RequestConfirmation { summary: String },

    /// No action required — false positive or already handled.
    Ignore { reason: String },
}

/// The structured decision returned by an AI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDecision {
    pub action: AiAction,

    /// Confidence score 0.0–1.0. Below the configured threshold, the decision
    /// is logged but NOT auto-executed even if `auto_execute` is true.
    pub confidence: f32,

    /// Whether the AI considers this safe to execute automatically.
    pub auto_execute: bool,

    /// Human-readable explanation of the reasoning.
    pub reason: String,

    /// Alternative actions the AI considered.
    pub alternatives: Vec<String>,

    /// Estimated threat level: "low" | "medium" | "high" | "critical"
    pub estimated_threat: String,
}

impl AiAction {
    /// Short name used as the action key in trust rules (e.g. "block_ip").
    pub fn name(&self) -> &'static str {
        match self {
            AiAction::BlockIp { .. } => "block_ip",
            AiAction::Monitor { .. } => "monitor",
            AiAction::Honeypot { .. } => "honeypot",
            AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
            AiAction::KillProcess { .. } => "kill_process",
            AiAction::BlockContainer { .. } => "block_container",
            AiAction::RequestConfirmation { .. } => "request_confirmation",
            AiAction::Ignore { .. } => "ignore",
        }
    }
}

impl AiDecision {
    /// Convenience constructor for a no-op decision.
    #[allow(dead_code)]
    pub fn ignore(reason: impl Into<String>) -> Self {
        Self {
            action: AiAction::Ignore {
                reason: reason.into(),
            },
            confidence: 1.0,
            auto_execute: false,
            reason: String::new(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Context passed to the AI provider
// ---------------------------------------------------------------------------

pub struct DecisionContext<'a> {
    pub incident: &'a Incident,
    /// Recent events from the same entity (IP/user) for contextual analysis
    pub recent_events: Vec<&'a Event>,
    /// Temporally correlated incidents sharing pivot(s) (ip/user/detector kind)
    pub related_incidents: Vec<&'a Incident>,
    /// IPs already in the blocklist (to avoid duplicate blocks)
    pub already_blocked: Vec<String>,
    /// Available skill IDs (sent to the AI so it can select the right one)
    pub available_skills: Vec<SkillInfo>,
    /// Optional AbuseIPDB reputation data for the primary IP (enrichment).
    pub ip_reputation: Option<crate::abuseipdb::IpReputation>,
    /// Optional geolocation data for the primary IP (enrichment via ip-api.com).
    pub ip_geo: Option<crate::geoip::GeoInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub id: String,
    /// Incident kinds this skill applies to (empty = all).
    /// Serialized to AI so it can match skills to incident types.
    pub applicable_to: Vec<String>,
}

// ---------------------------------------------------------------------------
// AiProvider trait — implement this to add a new provider
// ---------------------------------------------------------------------------

/// Implement this trait to add a new AI provider to Inner Warden.
///
/// Open-source contributions welcome: https://github.com/InnerWarden/innerwarden
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Short identifier shown in logs, e.g. "openai", "anthropic".
    fn name(&self) -> &'static str;

    /// Analyse an incident and return a decision.
    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision>;

    /// Send a free-form chat message with a system prompt and get a plain-text response.
    /// Used by the Telegram conversational bot.
    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Algorithm gate — runs BEFORE calling the AI (no I/O, no cost)
// ---------------------------------------------------------------------------

/// Returns true if the incident is worth sending to the AI provider.
///
/// Avoids wasting API calls on noise or already-handled incidents.
pub fn should_invoke_ai(incident: &Incident, already_blocked: &HashSet<String>) -> bool {
    use innerwarden_core::event::Severity;

    // Only High and Critical incidents warrant real-time AI analysis
    if !matches!(incident.severity, Severity::High | Severity::Critical) {
        return false;
    }

    // Extract the primary IP entity from the incident
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str());

    if let Some(ip_str) = ip {
        // Skip if already blocked
        if already_blocked.contains(ip_str) {
            return false;
        }

        // Skip RFC1918 / loopback / link-local — these are internal and
        // should not be auto-blocked without deeper investigation
        if let Ok(addr) = ip_str.parse::<IpAddr>() {
            if is_private_or_loopback(addr) {
                info!(ip = ip_str, "skipping AI analysis for private/loopback IP");
                return false;
            }
        }
    }

    true
}

fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Factory — creates the right provider based on config
// ---------------------------------------------------------------------------

/// Known OpenAI-compatible providers and their default base URLs + models.
/// Any provider that speaks the `/v1/chat/completions` format works here.
const OPENAI_COMPATIBLE: &[(&str, &str, &str)] = &[
    // (provider name, default base_url, default model)
    ("openai", "https://api.openai.com", "gpt-4o-mini"),
    (
        "groq",
        "https://api.groq.com/openai",
        "llama-3.3-70b-versatile",
    ),
    ("deepseek", "https://api.deepseek.com", "deepseek-chat"),
    (
        "together",
        "https://api.together.xyz",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    ),
    ("minimax", "https://api.minimaxi.chat", "MiniMax-Text-01"),
    ("mistral", "https://api.mistral.ai", "mistral-small-latest"),
    ("xai", "https://api.x.ai", "grok-3-mini-fast"),
    (
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-2.0-flash",
    ),
    (
        "fireworks",
        "https://api.fireworks.ai/inference",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
    ),
    (
        "openrouter",
        "https://openrouter.ai/api",
        "meta-llama/llama-3.3-70b-instruct",
    ),
];

pub fn build_provider(cfg: &AiConfig) -> Box<dyn AiProvider> {
    // Check if provider is OpenAI-compatible (including "openai" itself)
    if let Some(&(_, default_url, default_model)) = OPENAI_COMPATIBLE
        .iter()
        .find(|&&(name, _, _)| name == cfg.provider)
    {
        let base_url = if cfg.base_url.is_empty() {
            default_url.to_string()
        } else {
            cfg.base_url.clone()
        };
        let model = if cfg.model.is_empty() {
            default_model.to_string()
        } else {
            cfg.model.clone()
        };
        return Box::new(openai::OpenAiProvider::with_base_url(
            cfg.resolved_api_key(),
            model,
            base_url,
        ));
    }

    match cfg.provider.as_str() {
        "anthropic" => Box::new(anthropic::AnthropicProvider::new(
            cfg.resolved_api_key(),
            cfg.model.clone(),
        )),
        "ollama" => {
            let api_key = cfg.resolved_api_key();
            let api_key = if api_key.is_empty() {
                None
            } else {
                Some(api_key)
            };

            let base_url = if !cfg.base_url.is_empty() {
                cfg.base_url.clone()
            } else if api_key.is_some() {
                // Cloud mode: default to Ollama's hosted API
                "https://api.ollama.com".to_string()
            } else {
                std::env::var("OLLAMA_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string())
            };

            // Default model: cloud → qwen3-coder:480b, local → llama3.2
            let model = if cfg.model.is_empty() || cfg.model == "gpt-4o-mini" {
                if api_key.is_some() {
                    "qwen3-coder:480b".to_string()
                } else {
                    "llama3.2".to_string()
                }
            } else {
                cfg.model.clone()
            };
            Box::new(ollama::OllamaProvider::new(base_url, model, api_key))
        }
        other => {
            // Unknown provider name — if base_url is set, treat as OpenAI-compatible.
            // This lets users connect any compatible API without code changes.
            if !cfg.base_url.is_empty() {
                tracing::info!(
                    provider = other,
                    base_url = %cfg.base_url,
                    "treating unknown provider as OpenAI-compatible via base_url"
                );
                Box::new(openai::OpenAiProvider::with_base_url(
                    cfg.resolved_api_key(),
                    cfg.model.clone(),
                    cfg.base_url.clone(),
                ))
            } else {
                tracing::warn!(
                    provider = other,
                    "unknown AI provider and no base_url — falling back to openai"
                );
                Box::new(openai::OpenAiProvider::new(
                    cfg.resolved_api_key(),
                    cfg.model.clone(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn make_incident(severity: Severity, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "host".into(),
            incident_id: "test-id".into(),
            severity,
            title: "Test".into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn gate_passes_high_severity_external_ip() {
        // 1.2.3.4 is a routable public IP (not private/loopback/documentation)
        let inc = make_incident(Severity::High, "1.2.3.4");
        assert!(should_invoke_ai(&inc, &HashSet::new()));
    }

    #[test]
    fn gate_blocks_already_blocked_ip() {
        let inc = make_incident(Severity::High, "1.2.3.4");
        let mut blocked = HashSet::new();
        blocked.insert("1.2.3.4".to_string());
        assert!(!should_invoke_ai(&inc, &blocked));
    }

    #[test]
    fn gate_blocks_low_severity() {
        let inc = make_incident(Severity::Low, "1.2.3.4");
        assert!(!should_invoke_ai(&inc, &HashSet::new()));
    }

    #[test]
    fn gate_blocks_private_ip() {
        let inc = make_incident(Severity::High, "192.168.1.100");
        assert!(!should_invoke_ai(&inc, &HashSet::new()));
    }

    #[test]
    fn gate_blocks_loopback() {
        let inc = make_incident(Severity::Critical, "127.0.0.1");
        assert!(!should_invoke_ai(&inc, &HashSet::new()));
    }

    #[test]
    fn ignore_decision_helper() {
        let d = AiDecision::ignore("test reason");
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert!(!d.auto_execute);
    }
}
