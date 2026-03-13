use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpUfw;

impl ResponseSkill for BlockIpUfw {
    fn id(&self) -> &'static str {
        "block-ip-ufw"
    }
    fn name(&self) -> &'static str {
        "Block IP via ufw"
    }
    fn description(&self) -> &'static str {
        "Permanently blocks the attacking IP using ufw (Uncomplicated Firewall). \
         Adds a DENY rule with the 'innerwarden' comment for traceability. \
         Requires: sudo ufw deny from <IP> (configured in /etc/sudoers.d/innerwarden)."
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
                        message: "block-ip-ufw: no target IP in context".to_string(),
                    }
                }
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo ufw deny from {ip} comment 'innerwarden'"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via ufw"),
                };
            }

            let output = tokio::process::Command::new("sudo")
                .args(["ufw", "deny", "from", &ip, "comment", "innerwarden"])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via ufw");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via ufw"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "ufw block command failed");
                    SkillResult {
                        success: false,
                        message: format!("ufw block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn ufw command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run ufw: {e}"),
                    }
                }
            }
        })
    }
}
