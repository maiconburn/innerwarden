use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpPf;

impl ResponseSkill for BlockIpPf {
    fn id(&self) -> &'static str {
        "block-ip-pf"
    }
    fn name(&self) -> &'static str {
        "Block IP via pf (macOS Packet Filter)"
    }
    fn description(&self) -> &'static str {
        "Permanently blocks the attacking IP using macOS Packet Filter (pf). \
         Adds the IP to the 'innerwarden-blocked' table via \
         `pfctl -t innerwarden-blocked -T add <IP>`. \
         Setup requires adding a persistent anchor to /etc/pf.conf with: \
         `table <innerwarden-blocked> persist` and \
         `block in quick from <innerwarden-blocked> to any`. \
         Requires: sudo pfctl (configured in /etc/sudoers.d/innerwarden)."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &["ssh_bruteforce", "port_scan", "credential_stuffing"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => {
                    return SkillResult {
                        success: false,
                        message: "block-ip-pf: no target IP in context".to_string(),
                    }
                }
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo pfctl -t innerwarden-blocked -T add {ip}"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via pf"),
                };
            }

            let output = tokio::process::Command::new("sudo")
                .args(["pfctl", "-t", "innerwarden-blocked", "-T", "add", &ip])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via pf");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via pf"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "pf block command failed");
                    SkillResult {
                        success: false,
                        message: format!("pf block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn pfctl command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run pfctl: {e}"),
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{HoneypotRuntimeConfig, SkillContext};

    fn make_ctx(ip: Option<&str>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: "id".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_logs_without_executing() {
        let ctx = make_ctx(Some("1.2.3.4"));
        let result = BlockIpPf.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn no_target_ip_returns_error() {
        let ctx = make_ctx(None);
        let result = BlockIpPf.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata() {
        assert_eq!(BlockIpPf.id(), "block-ip-pf");
        assert!(BlockIpPf.name().contains("pf"));
        assert!(BlockIpPf.description().contains("pfctl"));
        assert_eq!(BlockIpPf.tier(), SkillTier::Open);
        assert!(BlockIpPf.applicable_to().contains(&"ssh_bruteforce"));
        assert!(BlockIpPf.applicable_to().contains(&"port_scan"));
        assert!(BlockIpPf.applicable_to().contains(&"credential_stuffing"));
    }
}
