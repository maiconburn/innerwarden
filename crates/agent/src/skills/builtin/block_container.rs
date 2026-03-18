use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_TTL_SECS: u64 = 1800;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;

pub struct BlockContainer;

#[derive(Debug, Serialize, Deserialize)]
struct ContainerBlockMetadata {
    container_id: String,
    action: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
}

impl ResponseSkill for BlockContainer {
    fn id(&self) -> &'static str {
        "block-container"
    }

    fn name(&self) -> &'static str {
        "Block Container"
    }

    fn description(&self) -> &'static str {
        "Pauses a Docker container in response to anomalous activity. Uses 'docker pause' (reversible). TTL metadata is written; use cleanup_expired_container_blocks to unpause after TTL."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["suspicious_execution", "execution_guard"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let Some(container_id) = ctx.target_container.clone() else {
                return SkillResult {
                    success: false,
                    message: "block-container: no target container in context".to_string(),
                };
            };

            if !is_valid_container_id(&container_id) {
                return SkillResult {
                    success: false,
                    message: format!(
                        "block-container: invalid container ID or name '{container_id}'"
                    ),
                };
            }

            let ttl_secs = ctx
                .duration_secs
                .unwrap_or(DEFAULT_TTL_SECS)
                .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(ttl_secs as i64);
            // Always pause (safer; stop is irreversible and not done automatically)
            let action = "pause";

            if dry_run {
                info!(
                    container_id,
                    action, ttl_secs, "DRY RUN: would pause Docker container"
                );
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would docker {action} {container_id} for {ttl_secs}s"
                    ),
                };
            }

            let pause_output = Command::new("docker")
                .args([action, &container_id])
                .output()
                .await;

            match pause_output {
                Ok(out) if out.status.success() => {
                    let meta = ContainerBlockMetadata {
                        container_id: container_id.clone(),
                        action: action.to_string(),
                        created_at,
                        expires_at,
                        reason: ctx.incident.summary.clone(),
                    };

                    if let Err(e) = write_metadata(&ctx.data_dir, &meta) {
                        warn!(container_id, error = %e, "failed to write container-block metadata");
                    }

                    info!(
                        container_id,
                        action,
                        ttl_secs,
                        expires_at = %expires_at,
                        "container paused"
                    );

                    SkillResult {
                        success: true,
                        message: format!(
                            "Container {container_id} paused for {ttl_secs}s (until {expires_at})"
                        ),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(container_id, stderr = %stderr, "docker pause failed");
                    SkillResult {
                        success: false,
                        message: format!("docker {action} {container_id} failed: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(container_id, error = %e, "failed to spawn docker command");
                    SkillResult {
                        success: false,
                        message: format!("failed to spawn docker command: {e}"),
                    }
                }
            }
        })
    }
}

pub async fn cleanup_expired_container_blocks(
    data_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<usize> {
    let dir = metadata_dir(data_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    let now = Utc::now();

    for entry in std::fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to read container-block metadata entry");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }

        let meta = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<ContainerBlockMetadata>(&s).ok())
        {
            Some(v) => v,
            None => {
                warn!(path = %path.display(), "invalid container-block metadata; removing file");
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        if meta.expires_at > now {
            continue;
        }

        if meta.action != "pause" {
            // Non-pause actions (e.g. stop) are not automatically reversed
            let _ = std::fs::remove_file(&path);
            continue;
        }

        if dry_run {
            info!(
                container_id = %meta.container_id,
                "DRY RUN: would unpause expired container block"
            );
            let _ = std::fs::remove_file(&path);
            removed += 1;
            continue;
        }

        let output = Command::new("docker")
            .args(["unpause", &meta.container_id])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let _ = std::fs::remove_file(&path);
                removed += 1;
                info!(container_id = %meta.container_id, "expired container pause lifted");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(
                    container_id = %meta.container_id,
                    stderr = %stderr,
                    "failed to unpause expired container"
                );
            }
            Err(e) => {
                warn!(
                    container_id = %meta.container_id,
                    error = %e,
                    "failed to spawn docker unpause for expired container"
                );
            }
        }
    }

    Ok(removed)
}

fn write_metadata(data_dir: &Path, meta: &ContainerBlockMetadata) -> Result<()> {
    let dir = metadata_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata dir {}", dir.display()))?;

    // Use a sanitized filename: replace chars that aren't safe for filenames
    let safe_name: String = meta
        .container_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let path = dir.join(format!("{safe_name}.json"));
    let content = serde_json::to_string_pretty(meta)?;
    std::fs::write(&path, content).with_context(|| {
        format!(
            "failed to write container-block metadata {}",
            path.display()
        )
    })?;
    Ok(())
}

fn metadata_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("container-blocks")
}

/// Validate container ID or name: alphanumeric + `-`, `_`, `.`, max 128 chars.
fn is_valid_container_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(container: Option<&str>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "suspicious_execution:container:test".to_string(),
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
            target_container: container.map(|s| s.to_string()),
            duration_secs: Some(600),
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_pause_succeeds() {
        let ctx = make_ctx(Some("my-container-123"));
        let res = BlockContainer.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
        assert!(res.message.contains("my-container-123"));
    }

    #[tokio::test]
    async fn invalid_container_id_fails() {
        let ctx = make_ctx(Some("bad container; rm -rf /"));
        let res = BlockContainer.execute(&ctx, true).await;
        assert!(!res.success);
        assert!(res.message.contains("invalid container"));
    }

    #[tokio::test]
    async fn no_target_container_fails_gracefully() {
        let ctx = make_ctx(None);
        let res = BlockContainer.execute(&ctx, true).await;
        assert!(!res.success);
        assert!(res.message.contains("no target container"));
    }

    #[test]
    fn container_id_validation() {
        assert!(is_valid_container_id("abc123"));
        assert!(is_valid_container_id("my-container_v1.2"));
        assert!(!is_valid_container_id(""));
        assert!(!is_valid_container_id("bad container"));
        assert!(!is_valid_container_id("bad;rm -rf /"));
        assert!(!is_valid_container_id(&"a".repeat(129)));
    }
}
