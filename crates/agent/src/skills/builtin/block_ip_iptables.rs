use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpIptables;

impl ResponseSkill for BlockIpIptables {
    fn id(&self) -> &'static str {
        "block-ip-iptables"
    }
    fn name(&self) -> &'static str {
        "Block IP via iptables"
    }
    fn description(&self) -> &'static str {
        "Blocks the attacking IP by appending a DROP rule to the INPUT chain using iptables. \
         Requires: sudo iptables -A INPUT ... (configured in /etc/sudoers.d/innerwarden). \
         Note: rules are lost on reboot unless persisted with iptables-save."
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
                        message: "block-ip-iptables: no target IP in context".to_string(),
                    }
                }
            };

            if dry_run {
                info!(ip, "DRY RUN: would execute: sudo iptables -A INPUT -s {ip} -j DROP -m comment --comment innerwarden");
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via iptables"),
                };
            }

            let output = tokio::process::Command::new("sudo")
                .args([
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    &ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "innerwarden",
                ])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via iptables");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via iptables"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "iptables block command failed");
                    SkillResult {
                        success: false,
                        message: format!("iptables block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn iptables command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run iptables: {e}"),
                    }
                }
            }
        })
    }
}
