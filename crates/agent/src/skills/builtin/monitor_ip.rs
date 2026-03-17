use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use chrono::Utc;
use tokio::process::Command;
use tracing::info;

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_CAPTURE_DIR: &str = "/var/lib/innerwarden/monitoring";
const CAPTURE_TIMEOUT_SECS: u64 = 30;
const CAPTURE_MAX_PACKETS: u64 = 200;

/// Premium skill: capture bounded network traffic for a target IP without blocking.
///
/// This implementation performs a short-lived tcpdump capture and stores:
/// - `.pcap` with captured packets
/// - `.txt` sidecar with incident metadata
pub struct MonitorIp;

impl ResponseSkill for MonitorIp {
    fn id(&self) -> &'static str {
        "monitor-ip"
    }
    fn name(&self) -> &'static str {
        "Shadow-monitor IP (Premium)"
    }
    fn description(&self) -> &'static str {
        "Captures bounded traffic for the target IP without blocking it, writing a .pcap \
         and metadata sidecar for later analysis. Useful to gather evidence before blocking. \
         [PREMIUM] Requires tcpdump privileges."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Premium
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match ctx.target_ip.as_deref() {
                Some(raw) => match raw.parse::<IpAddr>() {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        return SkillResult {
                            success: false,
                            message: format!("monitor-ip: invalid target IP '{}'", raw),
                        }
                    }
                },
                None => {
                    return SkillResult {
                        success: false,
                        message: "monitor-ip: no target IP in context".to_string(),
                    }
                }
            };

            let capture_dir = capture_dir();
            let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let ip_tag = ip_filename_tag(ip);
            let pcap_path = capture_dir.join(format!("monitor-{ip_tag}-{ts}.pcap"));
            let meta_path = capture_dir.join(format!("monitor-{ip_tag}-{ts}.txt"));
            let timeout = format!("{}s", CAPTURE_TIMEOUT_SECS);
            let pcap_path_s = pcap_path.to_string_lossy().to_string();
            let command_preview = format!(
                "sudo timeout {} tcpdump -nn -i any host {} -c {} -w {}",
                timeout,
                ip,
                CAPTURE_MAX_PACKETS,
                pcap_path.display()
            );

            if dry_run {
                info!(ip = %ip, command = %command_preview, "DRY RUN: monitor-ip");
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would capture traffic for {ip} into {}",
                        pcap_path.display()
                    ),
                };
            }

            if let Err(e) = std::fs::create_dir_all(&capture_dir) {
                return SkillResult {
                    success: false,
                    message: format!(
                        "monitor-ip: failed to create capture dir {}: {e}",
                        capture_dir.display()
                    ),
                };
            }

            let output = Command::new("sudo")
                .args([
                    "timeout",
                    &timeout,
                    "tcpdump",
                    "-nn",
                    "-i",
                    "any",
                    "host",
                    &ip.to_string(),
                    "-c",
                    &CAPTURE_MAX_PACKETS.to_string(),
                    "-w",
                    &pcap_path_s,
                ])
                .output()
                .await;

            match output {
                Ok(out) => {
                    let status = out.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();

                    // timeout returns 124 when duration is reached; in this use-case
                    // this is still a valid bounded capture.
                    if out.status.success() || status == 124 {
                        if let Err(e) =
                            write_metadata(&meta_path, ip, ctx, &pcap_path, status, &stderr)
                        {
                            return SkillResult {
                                success: false,
                                message: format!(
                                    "monitor-ip: capture succeeded but failed to write metadata: {e}"
                                ),
                            };
                        }

                        return SkillResult {
                            success: true,
                            message: format!(
                                "Captured traffic for {ip} (status {status}). pcap: {} metadata: {}",
                                pcap_path.display(),
                                meta_path.display()
                            ),
                        };
                    }

                    SkillResult {
                        success: false,
                        message: format!(
                            "monitor-ip capture failed for {ip} (status {status}): {stderr}"
                        ),
                    }
                }
                Err(e) => SkillResult {
                    success: false,
                    message: format!("monitor-ip: failed to execute tcpdump for {ip}: {e}"),
                },
            }
        })
    }
}

fn capture_dir() -> PathBuf {
    std::env::var("INNERWARDEN_MONITOR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CAPTURE_DIR))
}

fn ip_filename_tag(ip: IpAddr) -> String {
    ip.to_string().replace(':', "_")
}

fn write_metadata(
    path: &Path,
    ip: IpAddr,
    ctx: &SkillContext,
    pcap_path: &Path,
    status: i32,
    stderr: &str,
) -> std::io::Result<()> {
    let mut body = String::new();
    body.push_str(&format!("ts={}\n", Utc::now().to_rfc3339()));
    body.push_str(&format!("host={}\n", ctx.host));
    body.push_str(&format!("incident_id={}\n", ctx.incident.incident_id));
    body.push_str(&format!("target_ip={ip}\n"));
    body.push_str(&format!("pcap_path={}\n", pcap_path.display()));
    body.push_str(&format!("status_code={status}\n"));
    if !stderr.is_empty() {
        body.push_str(&format!("stderr={stderr}\n"));
    }
    std::fs::write(path, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{event::Severity, incident::Incident};

    fn ctx_with_ip(ip: Option<&str>) -> SkillContext {
        SkillContext {
            incident: Incident {
                ts: Utc::now(),
                host: "host-a".to_string(),
                incident_id: "incident-1".to_string(),
                severity: Severity::High,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: ip.map(|v| v.to_string()),
            target_user: None,
            duration_secs: None,
            host: "host-a".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_succeeds() {
        let ctx = ctx_with_ip(Some("1.2.3.4"));
        let result = MonitorIp.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[tokio::test]
    async fn missing_ip_fails() {
        let ctx = ctx_with_ip(None);
        let result = MonitorIp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[tokio::test]
    async fn invalid_ip_fails() {
        let ctx = ctx_with_ip(Some("not-an-ip"));
        let result = MonitorIp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("invalid target IP"));
    }

    #[test]
    fn writes_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.txt");
        let pcap_path = dir.path().join("sample.pcap");
        let ctx = ctx_with_ip(Some("1.2.3.4"));
        write_metadata(
            &meta_path,
            "1.2.3.4".parse().unwrap(),
            &ctx,
            &pcap_path,
            0,
            "ok",
        )
        .unwrap();
        let content = std::fs::read_to_string(meta_path).unwrap();
        assert!(content.contains("incident_id=incident-1"));
        assert!(content.contains("target_ip=1.2.3.4"));
        assert!(content.contains("pcap_path="));
    }
}
