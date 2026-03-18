use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpNftables;

impl ResponseSkill for BlockIpNftables {
    fn id(&self) -> &'static str {
        "block-ip-nftables"
    }
    fn name(&self) -> &'static str {
        "Block IP via nftables"
    }
    fn description(&self) -> &'static str {
        "Adds the attacking IP to a named blacklist set in nftables. \
         Requires an 'inet filter blacklist' set pre-configured in nftables.conf. \
         Requires: sudo nft add element ... (configured in /etc/sudoers.d/innerwarden)."
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
                        message: "block-ip-nftables: no target IP in context".to_string(),
                    }
                }
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo nft add element inet filter blacklist {{ {ip} }}"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via nftables"),
                };
            }

            let element = format!("{{ {ip} }}");
            let output = tokio::process::Command::new("sudo")
                .args([
                    "nft",
                    "add",
                    "element",
                    "inet",
                    "filter",
                    "blacklist",
                    &element,
                ])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "added to nftables blacklist");
                    SkillResult {
                        success: true,
                        message: format!("Added {ip} to nftables blacklist"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "nftables block command failed");
                    SkillResult {
                        success: false,
                        message: format!("nftables block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn nft command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run nft: {e}"),
                    }
                }
            }
        })
    }
}
