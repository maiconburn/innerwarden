use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_TTL_SECS: u64 = 300;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;

pub struct KillProcess;

#[derive(Debug, Serialize, Deserialize)]
struct ProcessKillMetadata {
    user: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
}

impl ResponseSkill for KillProcess {
    fn id(&self) -> &'static str {
        "kill-process"
    }

    fn name(&self) -> &'static str {
        "Kill User Processes"
    }

    fn description(&self) -> &'static str {
        "Kills all running processes owned by a user (SIGKILL) in response to suspicious execution activity. TTL is informational — no automatic process restart prevention."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["suspicious_execution", "sudo_abuse", "execution_guard"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let Some(user) = ctx.target_user.clone() else {
                return SkillResult {
                    success: false,
                    message: "kill-process: no target user in context".to_string(),
                };
            };

            if !is_valid_username(&user) {
                return SkillResult {
                    success: false,
                    message: format!("kill-process: invalid username '{user}'"),
                };
            }

            let ttl_secs = ctx
                .duration_secs
                .unwrap_or(DEFAULT_TTL_SECS)
                .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(ttl_secs as i64);

            if dry_run {
                info!(user, ttl_secs, "DRY RUN: would kill all processes for user");
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would kill all processes for user {user} (pkill -9 -u {user}); TTL note: {ttl_secs}s"
                    ),
                };
            }

            // Kill all processes owned by the user
            let kill_output = Command::new("sudo")
                .args(["pkill", "-9", "-u", &user])
                .output()
                .await;

            match kill_output {
                Ok(out) => {
                    // pkill exits with 1 if no processes matched — that is acceptable
                    if out.status.success() || out.status.code() == Some(1) {
                        let meta = ProcessKillMetadata {
                            user: user.clone(),
                            created_at,
                            expires_at,
                            reason: ctx.incident.summary.clone(),
                        };

                        if let Err(e) = write_metadata(&ctx.data_dir, &meta) {
                            warn!(user, error = %e, "failed to write process-kill metadata");
                        }

                        info!(
                            user,
                            ttl_secs,
                            expires_at = %expires_at,
                            "killed all processes for user"
                        );

                        SkillResult {
                            success: true,
                            message: format!(
                                "Killed all processes for user {user} (TTL note: {ttl_secs}s until {expires_at})"
                            ),
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        warn!(user, stderr = %stderr, "pkill returned unexpected exit code");
                        SkillResult {
                            success: false,
                            message: format!("pkill failed for user {user}: {stderr}"),
                        }
                    }
                }
                Err(e) => {
                    warn!(user, error = %e, "failed to spawn pkill command");
                    SkillResult {
                        success: false,
                        message: format!("failed to spawn pkill for user {user}: {e}"),
                    }
                }
            }
        })
    }
}

fn write_metadata(data_dir: &Path, meta: &ProcessKillMetadata) -> Result<()> {
    let dir = metadata_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata dir {}", dir.display()))?;

    let path = dir.join(format!("{}.json", meta.user));
    let content = serde_json::to_string_pretty(meta)?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write process-kill metadata {}", path.display()))?;
    Ok(())
}

fn metadata_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("process-kills")
}

fn is_valid_username(user: &str) -> bool {
    if user.is_empty() || user.len() > 64 {
        return false;
    }

    let mut chars = user.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphanumeric() || first == '_' || first == '-') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '$')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_succeeds() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "suspicious_execution:deploy:test".to_string(),
                severity: innerwarden_core::event::Severity::Critical,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: None,
            target_user: Some("deploy".to_string()),
            target_container: None,
            duration_secs: Some(300),
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = KillProcess.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
        assert!(res.message.contains("deploy"));
    }

    #[test]
    fn username_validation_is_strict() {
        assert!(is_valid_username("deploy"));
        assert!(is_valid_username("svc_user-1"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("../etc/passwd"));
        assert!(!is_valid_username("bad user"));
        assert!(!is_valid_username("user;rm -rf /"));
    }

    #[tokio::test]
    async fn no_target_user_fails_gracefully() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "test:id".to_string(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: None,
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = KillProcess.execute(&ctx, true).await;
        assert!(!res.success);
        assert!(res.message.contains("no target user"));
    }
}
