/// Rate-limit an IP at the nginx layer.
///
/// Adds a `deny IP;` rule to a managed blocklist file, installs it to
/// `/etc/nginx/innerwarden-blocklist.conf`, validates with `nginx -t`, then
/// reloads nginx. Auto-removes the rule after the TTL expires.
///
/// # Operator prerequisite
///
/// The operator must add the following include to their nginx server or location block:
///
/// ```nginx
/// server {
///     include /etc/nginx/innerwarden-blocklist.conf;
///     ...
/// }
/// ```
///
/// And grant the innerwarden user the necessary sudo permissions:
///
/// ```sudoers
/// innerwarden ALL=(ALL) NOPASSWD: \
///   /usr/bin/install * /etc/nginx/innerwarden-blocklist.conf, \
///   /usr/sbin/nginx -t, \
///   /usr/sbin/nginx -s reload
/// ```
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_TTL_SECS: u64 = 3_600; // 1 hour
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400; // 24 hours
const NGINX_BLOCKLIST_DEST: &str = "/etc/nginx/innerwarden-blocklist.conf";
const NGINX_BLOCKS_SUBDIR: &str = "nginx-blocks";

// ---------------------------------------------------------------------------
// Skill
// ---------------------------------------------------------------------------

pub struct RateLimitNginx;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NginxBlockMetadata {
    ip: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
}

impl ResponseSkill for RateLimitNginx {
    fn id(&self) -> &'static str {
        "rate-limit-nginx"
    }

    fn name(&self) -> &'static str {
        "Rate-Limit IP via Nginx"
    }

    fn description(&self) -> &'static str {
        "Denies an IP at the nginx application layer (HTTP 403) by adding a 'deny' rule to \
         /etc/nginx/innerwarden-blocklist.conf and reloading nginx. Auto-expires after TTL. \
         Requires 'include /etc/nginx/innerwarden-blocklist.conf;' in the nginx server block."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["search_abuse"]
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
                        message: "rate-limit-nginx: no target_ip in context".to_string(),
                    }
                }
            };

            if let Err(e) = validate_ip(&ip) {
                return SkillResult {
                    success: false,
                    message: format!("rate-limit-nginx: invalid IP '{ip}': {e}"),
                };
            }

            let ttl_secs = ctx
                .duration_secs
                .unwrap_or(DEFAULT_TTL_SECS)
                .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(ttl_secs as i64);

            if dry_run {
                info!(ip, ttl_secs, "DRY RUN: would add nginx deny rule");
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would add nginx deny rule for {ip} to {NGINX_BLOCKLIST_DEST} \
                         (TTL: {ttl_secs}s, expires: {})",
                        expires_at.to_rfc3339()
                    ),
                };
            }

            let blocks_dir = blocks_dir(&ctx.data_dir);
            if let Err(e) = std::fs::create_dir_all(&blocks_dir) {
                return SkillResult {
                    success: false,
                    message: format!("failed to create nginx-blocks dir: {e}"),
                };
            }

            // 1. Update the shadow blocklist
            let meta = NginxBlockMetadata {
                ip: ip.clone(),
                created_at,
                expires_at,
                reason: ctx.incident.summary.clone(),
            };

            if let Err(e) = add_to_blocklist(&blocks_dir, &ip, expires_at) {
                return SkillResult {
                    success: false,
                    message: format!("failed to update blocklist: {e}"),
                };
            }

            // 2. Install shadow → /etc/nginx/innerwarden-blocklist.conf
            let shadow_path = shadow_blocklist_path(&blocks_dir);
            if let Err(e) = install_blocklist(&shadow_path).await {
                // Rollback: remove the IP we just added
                let _ = remove_from_blocklist(&blocks_dir, &ip);
                return SkillResult {
                    success: false,
                    message: format!("failed to install nginx blocklist: {e}"),
                };
            }

            // 3. Validate nginx config
            if let Err(e) = nginx_test().await {
                // Rollback everything
                let _ = remove_from_blocklist(&blocks_dir, &ip);
                let _ = install_blocklist(&shadow_blocklist_path(&blocks_dir)).await;
                return SkillResult {
                    success: false,
                    message: format!("nginx -t failed after adding rule for {ip}: {e}"),
                };
            }

            // 4. Reload nginx
            if let Err(e) = nginx_reload().await {
                warn!(ip, error = %e, "nginx reload failed; rule is written but not active");
                return SkillResult {
                    success: false,
                    message: format!("rule written but nginx reload failed: {e}"),
                };
            }

            // 5. Persist metadata for TTL cleanup
            if let Err(e) = write_metadata(&blocks_dir, &meta) {
                warn!(ip, error = %e, "failed to write nginx block metadata");
            }

            info!(ip, ttl_secs, expires_at = %expires_at, "nginx deny rule applied");

            SkillResult {
                success: true,
                message: format!(
                    "Nginx deny rule added for {ip} (TTL: {ttl_secs}s, expires: {expires_at})"
                ),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// TTL cleanup — called from the agent slow loop (30s)
// ---------------------------------------------------------------------------

pub async fn cleanup_expired_nginx_blocks(data_dir: &Path, dry_run: bool) -> Result<usize> {
    let dir = blocks_dir(data_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    let now = Utc::now();

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    for entry in entries {
        let path = entry.path();
        let meta = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<NginxBlockMetadata>(&s).ok())
        {
            Some(v) => v,
            None => {
                warn!(path = %path.display(), "invalid nginx block metadata; removing");
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        if meta.expires_at > now {
            continue;
        }

        if dry_run {
            info!(ip = %meta.ip, "DRY RUN: would remove expired nginx block");
            let _ = std::fs::remove_file(&path);
            removed += 1;
            continue;
        }

        // Remove IP from shadow blocklist, reinstall, reload
        if let Err(e) = remove_from_blocklist(&dir, &meta.ip) {
            warn!(ip = %meta.ip, error = %e, "failed to remove ip from shadow blocklist");
            continue;
        }

        let shadow_path = shadow_blocklist_path(&dir);
        if let Err(e) = install_blocklist(&shadow_path).await {
            warn!(ip = %meta.ip, error = %e, "failed to reinstall blocklist after expiry");
            continue;
        }

        if let Err(e) = nginx_reload().await {
            warn!(ip = %meta.ip, error = %e, "nginx reload failed after block expiry");
        } else {
            let _ = std::fs::remove_file(&path);
            removed += 1;
            info!(ip = %meta.ip, "expired nginx deny rule removed");
        }
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Blocklist file management
// ---------------------------------------------------------------------------

/// Add an IP deny line to the shadow blocklist file.
/// The file is written atomically via a temp-then-rename sequence.
fn add_to_blocklist(blocks_dir: &Path, ip: &str, expires_at: DateTime<Utc>) -> Result<()> {
    let path = shadow_blocklist_path(blocks_dir);

    // Read existing denies, excluding this IP if already present (idempotent)
    let current = read_deny_lines(&path);
    let mut lines: Vec<String> = current
        .into_iter()
        .filter(|line| !line.contains(&format!("deny {ip};")))
        .collect();

    lines.push(format!(
        "deny {ip}; # expires:{} managed-by:innerwarden",
        expires_at.to_rfc3339()
    ));

    write_blocklist_atomic(&path, &lines)
}

/// Remove an IP deny line from the shadow blocklist file.
fn remove_from_blocklist(blocks_dir: &Path, ip: &str) -> Result<()> {
    let path = shadow_blocklist_path(blocks_dir);
    let current = read_deny_lines(&path);
    let lines: Vec<String> = current
        .into_iter()
        .filter(|line| !line.contains(&format!("deny {ip};")))
        .collect();
    write_blocklist_atomic(&path, &lines)
}

fn read_deny_lines(path: &Path) -> Vec<String> {
    if !path.exists() {
        return vec![];
    }
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn write_blocklist_atomic(path: &Path, deny_lines: &[String]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(
        ".innerwarden-blocklist.tmp.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut content =
        "# InnerWarden nginx blocklist — managed automatically, do not edit\n".to_string();
    for line in deny_lines {
        content.push_str(line);
        content.push('\n');
    }

    std::fs::write(&tmp, &content)
        .with_context(|| format!("write temp blocklist {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename temp blocklist to {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Nginx operations
// ---------------------------------------------------------------------------

/// Install the shadow blocklist to /etc/nginx/innerwarden-blocklist.conf via sudo.
async fn install_blocklist(shadow_path: &Path) -> Result<()> {
    let shadow_str = shadow_path.to_string_lossy().to_string();
    let out = Command::new("sudo")
        .args([
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "644",
            &shadow_str,
            NGINX_BLOCKLIST_DEST,
        ])
        .output()
        .await
        .context("failed to spawn sudo install for nginx blocklist")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("sudo install failed: {stderr}");
    }
    Ok(())
}

async fn nginx_test() -> Result<()> {
    let out = Command::new("sudo")
        .args(["/usr/sbin/nginx", "-t"])
        .output()
        .await
        .context("failed to spawn nginx -t")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nginx -t: {stderr}");
    }
    Ok(())
}

async fn nginx_reload() -> Result<()> {
    let out = Command::new("sudo")
        .args(["/usr/sbin/nginx", "-s", "reload"])
        .output()
        .await
        .context("failed to spawn nginx -s reload")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nginx -s reload: {stderr}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_ip(ip: &str) -> Result<()> {
    IpAddr::from_str(ip).with_context(|| format!("'{ip}' is not a valid IP address"))?;
    Ok(())
}

fn blocks_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(NGINX_BLOCKS_SUBDIR)
}

fn shadow_blocklist_path(blocks_dir: &Path) -> PathBuf {
    blocks_dir.join("blocklist.conf")
}

fn write_metadata(blocks_dir: &Path, meta: &NginxBlockMetadata) -> Result<()> {
    // Use a filename-safe IP representation
    let safe_ip = meta.ip.replace([':', '.'], "_");
    let path = blocks_dir.join(format!("{safe_ip}.json"));
    let content = serde_json::to_string_pretty(meta)?;
    std::fs::write(&path, content)
        .with_context(|| format!("write nginx block metadata {}", path.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ctx(ip: &str, data_dir: &Path) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".into(),
                incident_id: format!("search_abuse:{ip}:test"),
                severity: innerwarden_core::event::Severity::High,
                title: "Test incident".into(),
                summary: "30 requests to /api/search in 60s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: Some(300),
            host: "host".into(),
            data_dir: data_dir.to_path_buf(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_returns_success() {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx("1.2.3.4", tmp.path());
        let result = RateLimitNginx.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
        assert!(result.message.contains("300s"));
    }

    #[tokio::test]
    async fn dry_run_does_not_write_files() {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx("1.2.3.4", tmp.path());
        let _ = RateLimitNginx.execute(&ctx, true).await;
        // No nginx-blocks directory should be created in dry_run
        assert!(!tmp.path().join(NGINX_BLOCKS_SUBDIR).exists());
    }

    #[tokio::test]
    async fn no_target_ip_fails() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = make_ctx("1.2.3.4", tmp.path());
        ctx.target_ip = None;
        let result = RateLimitNginx.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target_ip"));
    }

    #[tokio::test]
    async fn invalid_ip_fails_in_dry_run() {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx("not-an-ip", tmp.path());
        let result = RateLimitNginx.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("invalid IP"));
    }

    #[test]
    fn validate_ip_accepts_ipv4() {
        assert!(validate_ip("1.2.3.4").is_ok());
        assert!(validate_ip("192.168.1.100").is_ok());
        assert!(validate_ip("0.0.0.0").is_ok());
    }

    #[test]
    fn validate_ip_accepts_ipv6() {
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
    }

    #[test]
    fn validate_ip_rejects_garbage() {
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("1.2.3.4; deny all").is_err());
        assert!(validate_ip("").is_err());
        assert!(validate_ip("$(rm -rf /)").is_err());
        assert!(validate_ip("1.2.3").is_err());
    }

    #[test]
    fn add_and_remove_from_blocklist() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let expires = Utc::now() + Duration::hours(1);

        // Add two IPs
        add_to_blocklist(dir, "1.1.1.1", expires).unwrap();
        add_to_blocklist(dir, "2.2.2.2", expires).unwrap();

        let path = shadow_blocklist_path(dir);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("deny 1.1.1.1;"));
        assert!(content.contains("deny 2.2.2.2;"));

        // Remove one
        remove_from_blocklist(dir, "1.1.1.1").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("deny 1.1.1.1;"));
        assert!(content.contains("deny 2.2.2.2;"));
    }

    #[test]
    fn add_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let expires = Utc::now() + Duration::hours(1);

        add_to_blocklist(dir, "1.1.1.1", expires).unwrap();
        add_to_blocklist(dir, "1.1.1.1", expires).unwrap(); // duplicate

        let path = shadow_blocklist_path(dir);
        let content = std::fs::read_to_string(&path).unwrap();
        // Should appear exactly once
        assert_eq!(content.matches("deny 1.1.1.1;").count(), 1);
    }

    #[test]
    fn blocklist_header_comment_is_present() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let expires = Utc::now() + Duration::hours(1);

        add_to_blocklist(dir, "3.3.3.3", expires).unwrap();

        let content = std::fs::read_to_string(shadow_blocklist_path(dir)).unwrap();
        assert!(content.contains("InnerWarden nginx blocklist"));
    }

    #[test]
    fn applicable_to_search_abuse() {
        let skill = RateLimitNginx;
        assert!(skill.applicable_to().contains(&"search_abuse"));
    }
}
