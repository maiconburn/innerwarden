// ---------------------------------------------------------------------------
// CrowdSec integration — polls the local LAPI and syncs ban decisions
// ---------------------------------------------------------------------------
//
// CrowdSec runs a Local API (LAPI) on each host. This module polls it for
// active ban decisions and forwards new IPs to InnerWarden's block skill,
// bypassing the AI layer (CrowdSec's own engine already made the decision).
//
// Flow:
//   1. Every `poll_secs` seconds, GET /v1/decisions?type=ban&scope=ip
//   2. Compare against the last-seen decision set (persisted in memory)
//   3. For each new IP: execute block_ip via the configured skill
//   4. Write a DecisionEntry to decisions-*.jsonl (ai_provider = "crowdsec")
//
// Required: CrowdSec LAPI must be running and the API key must be set.
//   - Default URL: http://localhost:8080
//   - API key: find in /etc/crowdsec/local_api_credentials.yaml under `password`
//   - Or set via CROWDSEC_API_KEY env var

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config::{AgentConfig, CrowdSecConfig};
use crate::decisions::{DecisionEntry, DecisionWriter};
use crate::skills::{self, Blocklist, SkillContext, SkillRegistry};

// ---------------------------------------------------------------------------
// LAPI response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CrowdSecDecision {
    pub id: i64,
    pub origin: String,
    #[allow(dead_code)]
    pub r#type: String,
    #[allow(dead_code)]
    pub scope: String,
    pub value: String,    // the IP address
    pub duration: String, // e.g. "87599.956744792s"
    #[serde(rename = "simulated")]
    pub simulated: Option<bool>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct CrowdSecClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl CrowdSecClient {
    pub fn new(cfg: &CrowdSecConfig) -> Self {
        let api_key = if !cfg.api_key.is_empty() {
            cfg.api_key.clone()
        } else {
            std::env::var("CROWDSEC_API_KEY").unwrap_or_default()
        };

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build CrowdSec HTTP client");

        Self {
            base_url: cfg.url.trim_end_matches('/').to_string(),
            api_key,
            http,
        }
    }

    /// Fetch all active IP ban decisions from the LAPI.
    pub async fn fetch_bans(&self) -> Result<Vec<CrowdSecDecision>> {
        let url = format!("{}/v1/decisions?type=ban&scope=ip", self.base_url);

        debug!(url = %url, "polling CrowdSec LAPI");

        let resp = self
            .http
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "CrowdSec LAPI unreachable at {url} — is CrowdSec running?\n\
                     Start it with: sudo systemctl start crowdsec"
                )
            })?;

        if resp.status().as_u16() == 204 {
            // 204 No Content = no active decisions
            return Ok(vec![]);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 403 || body.contains("Forbidden") {
                anyhow::bail!(
                    "CrowdSec LAPI returned 403: invalid API key.\n\
                     Check crowdsec.api_key in agent.toml or CROWDSEC_API_KEY env var.\n\
                     Find your key in: /etc/crowdsec/local_api_credentials.yaml"
                );
            }
            anyhow::bail!(
                "CrowdSec LAPI returned {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }

        // 200 with body = list of decisions (may be null if empty)
        let text = resp.text().await?;
        if text.trim() == "null" || text.trim().is_empty() {
            return Ok(vec![]);
        }

        serde_json::from_str::<Vec<CrowdSecDecision>>(&text)
            .context("failed to parse CrowdSec decision list")
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Sync tick — called from the agent's fast loop
// ---------------------------------------------------------------------------

/// State persisted between ticks so we only act on *new* decisions.
pub struct CrowdSecState {
    /// IPs we have already processed (blocked via InnerWarden or already in blocklist).
    pub known_ips: std::collections::HashSet<String>,
    pub client: CrowdSecClient,
}

impl CrowdSecState {
    pub fn new(cfg: &CrowdSecConfig) -> Self {
        Self {
            known_ips: std::collections::HashSet::new(),
            client: CrowdSecClient::new(cfg),
        }
    }
}

/// Process CrowdSec decisions for one tick.
/// Returns the number of new IPs blocked.
pub async fn sync_tick(
    cs: &mut CrowdSecState,
    blocklist: &mut Blocklist,
    skill_registry: &SkillRegistry,
    cfg: &AgentConfig,
    decision_writer: &mut Option<DecisionWriter>,
    host: &str,
) -> usize {
    if !cs.client.is_configured() {
        return 0;
    }

    let decisions = match cs.client.fetch_bans().await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "CrowdSec sync failed");
            return 0;
        }
    };

    let mut new_blocks = 0;

    for decision in decisions {
        let ip = &decision.value;

        // Skip non-IP scopes, simulated decisions, and already-known IPs
        if decision.simulated == Some(true) {
            continue;
        }
        if cs.known_ips.contains(ip) || blocklist.contains(ip) {
            cs.known_ips.insert(ip.clone());
            continue;
        }

        // Skip private / loopback IPs (same gate as AI layer)
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            if is_private_or_loopback(addr) {
                cs.known_ips.insert(ip.clone());
                continue;
            }
        }

        info!(
            ip = %ip,
            origin = %decision.origin,
            duration = %decision.duration,
            "CrowdSec ban — blocking IP"
        );

        // Execute block skill directly (bypass AI)
        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let skill = skill_registry
            .get(&skill_id)
            .or_else(|| skill_registry.block_skill_for_backend(&cfg.responder.block_backend));

        let execution_result = match skill {
            Some(skill) => {
                use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
                let synthetic_incident = Incident {
                    ts: chrono::Utc::now(),
                    host: host.to_string(),
                    incident_id: format!("crowdsec:{}", decision.id),
                    severity: Severity::High,
                    title: format!("CrowdSec ban: {ip}"),
                    summary: format!(
                        "CrowdSec banned {} (origin: {}, duration: {})",
                        ip, decision.origin, decision.duration
                    ),
                    evidence: serde_json::json!({
                        "source": "crowdsec",
                        "origin": decision.origin,
                        "duration": decision.duration,
                    }),
                    recommended_checks: vec![],
                    tags: vec!["crowdsec".to_string()],
                    entities: vec![EntityRef::ip(ip)],
                };
                let ctx = SkillContext {
                    incident: synthetic_incident,
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    duration_secs: None,
                    host: host.to_string(),
                    data_dir: std::path::PathBuf::new(),
                    honeypot: skills::HoneypotRuntimeConfig::default(),
                };
                let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                if result.success {
                    blocklist.insert(ip.clone());
                    new_blocks += 1;
                }
                result.message
            }
            None => {
                warn!(skill_id = %skill_id, "CrowdSec: no block skill available");
                format!("skipped: skill '{skill_id}' not found or not in allowed_skills")
            }
        };

        cs.known_ips.insert(ip.clone());

        // Write audit trail
        if let Some(writer) = decision_writer {
            let entry = DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: format!("crowdsec:{}", decision.id),
                host: host.to_string(),
                ai_provider: format!("crowdsec:{}", decision.origin),
                action_type: "block_ip".to_string(),
                target_ip: Some(ip.clone()),
                target_user: None,
                skill_id: Some(skill_id),
                confidence: 1.0,
                auto_executed: true,
                dry_run: cfg.responder.dry_run,
                reason: format!(
                    "CrowdSec ban from origin '{}', duration {}",
                    decision.origin, decision.duration
                ),
                estimated_threat: "high".to_string(),
                execution_result,
            };
            if let Err(e) = writer.write(&entry) {
                warn!(error = %e, "failed to write CrowdSec decision to audit trail");
            }
        }
    }

    if new_blocks > 0 {
        info!(
            count = new_blocks,
            "CrowdSec: blocked {} new IP(s)", new_blocks
        );
    }

    new_blocks
}

fn is_private_or_loopback(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decisions_from_json() {
        let raw = r#"[
            {"id":1,"origin":"crowdsec","type":"ban","scope":"ip","value":"1.2.3.4","duration":"86399s"},
            {"id":2,"origin":"cscli","type":"ban","scope":"ip","value":"5.6.7.8","duration":"3600s","simulated":false}
        ]"#;
        let decisions: Vec<CrowdSecDecision> = serde_json::from_str(raw).unwrap();
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].value, "1.2.3.4");
        assert_eq!(decisions[1].origin, "cscli");
    }

    #[test]
    fn parse_null_response() {
        // CrowdSec returns literal "null" when no decisions exist
        let text = "null";
        assert!(text.trim() == "null");
    }

    #[test]
    fn parse_empty_array() {
        let raw = "[]";
        let decisions: Vec<CrowdSecDecision> = serde_json::from_str(raw).unwrap();
        assert!(decisions.is_empty());
    }

    #[test]
    fn skips_simulated_decisions() {
        let raw = r#"[{"id":1,"origin":"crowdsec","type":"ban","scope":"ip","value":"1.2.3.4","duration":"3600s","simulated":true}]"#;
        let decisions: Vec<CrowdSecDecision> = serde_json::from_str(raw).unwrap();
        assert!(decisions[0].simulated == Some(true));
    }

    #[test]
    fn private_ip_is_filtered() {
        assert!(is_private_or_loopback("192.168.1.1".parse().unwrap()));
        assert!(is_private_or_loopback("127.0.0.1".parse().unwrap()));
        assert!(!is_private_or_loopback("1.2.3.4".parse().unwrap()));
    }
}
