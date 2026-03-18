// ---------------------------------------------------------------------------
// Fail2ban integration — polls fail2ban-client for active bans and syncs them
// ---------------------------------------------------------------------------
//
// Fail2ban manages ban decisions locally on the host. This module polls it via
// the `fail2ban-client` CLI, discovers banned IPs across configured jails, and
// forwards new IPs to InnerWarden's block skill, bypassing the AI layer
// (fail2ban's own engine already made the detection decision).
//
// Flow:
//   1. Every `poll_secs` seconds, run `fail2ban-client status` to list jails
//      (or use the configured jail list directly)
//   2. For each jail: run `fail2ban-client status <jail>` to get banned IPs
//   3. Compare against the last-seen set (persisted in memory)
//   4. For each new IP: execute block_ip via the configured skill
//   5. Write a DecisionEntry to decisions-*.jsonl (ai_provider = "fail2ban:<jail>")
//
// Required: fail2ban must be installed and running.
//   - Binary: /usr/bin/fail2ban-client (or /usr/local/bin/fail2ban-client)
//   - The agent process must be able to invoke fail2ban-client without sudo
//     (or have the necessary permissions via sudoers)

use tracing::{debug, info, warn};

use crate::config::{AgentConfig, Fail2BanConfig};
use crate::decisions::{DecisionEntry, DecisionWriter};
use crate::skills::{self, Blocklist, SkillContext, SkillRegistry};

// ---------------------------------------------------------------------------
// Parsed types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BannedIp {
    pub ip: String,
    #[allow(dead_code)]
    pub jail: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct Fail2BanClient {
    use_sudo: bool,
}

impl Fail2BanClient {
    pub fn new(use_sudo: bool) -> Self {
        Self { use_sudo }
    }

    /// List all active jails by running `fail2ban-client status`.
    /// Parses the "Jail list:" line from the output.
    pub async fn list_jails(&self) -> Vec<String> {
        let use_sudo = self.use_sudo;
        let output = tokio::task::spawn_blocking(move || {
            if use_sudo {
                std::process::Command::new("sudo")
                    .args(["fail2ban-client", "status"])
                    .output()
            } else {
                std::process::Command::new("fail2ban-client")
                    .arg("status")
                    .output()
            }
        })
        .await;

        let output = match output {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                warn!(error = %e, "fail2ban-client status: failed to spawn process");
                return vec![];
            }
            Err(e) => {
                warn!(error = %e, "fail2ban-client status: spawn_blocking error");
                return vec![];
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(stderr = %stderr, "fail2ban-client status: non-zero exit");
            return vec![];
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_jail_list(&stdout)
    }

    /// Get banned IPs for a specific jail by running `fail2ban-client status <jail>`.
    /// Parses the "Banned IP list:" line from the output.
    pub async fn banned_ips(&self, jail: &str) -> Vec<BannedIp> {
        let jail_owned = jail.to_string();
        let use_sudo = self.use_sudo;
        let output = tokio::task::spawn_blocking(move || {
            if use_sudo {
                std::process::Command::new("sudo")
                    .args(["fail2ban-client", "status", &jail_owned])
                    .output()
            } else {
                std::process::Command::new("fail2ban-client")
                    .args(["status", &jail_owned])
                    .output()
            }
        })
        .await;

        let output = match output {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                warn!(error = %e, jail, "fail2ban-client status <jail>: failed to spawn process");
                return vec![];
            }
            Err(e) => {
                warn!(error = %e, jail, "fail2ban-client status <jail>: spawn_blocking error");
                return vec![];
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(jail, stderr = %stderr, "fail2ban-client status <jail>: non-zero exit");
            return vec![];
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_banned_ips(&stdout, jail)
    }
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse `fail2ban-client status` output and extract the list of jail names.
///
/// Expected output:
/// ```text
/// Status
/// |- Number of jail:    2
/// `- Jail list:    sshd, nginx-req-limit
/// ```
pub fn parse_jail_list(output: &str) -> Vec<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Jail list:") {
            let list = rest.trim_start_matches(['\t', ' ']);
            return list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        // Also handle the backtick variant: "`- Jail list:\t..."
        if let Some(rest) = trimmed.strip_prefix("`- Jail list:") {
            let list = rest.trim_start_matches(['\t', ' ']);
            return list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(rest) = trimmed.strip_prefix("|- Jail list:") {
            let list = rest.trim_start_matches(['\t', ' ']);
            return list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![]
}

/// Parse `fail2ban-client status <jail>` output and extract banned IPs.
///
/// Expected output:
/// ```text
/// Status for the jail: sshd
/// |- Filter
/// |  |- Currently failed:    1
/// |  |- Total failed:    42
/// |  `- File list:    /var/log/auth.log
/// `- Actions
///    |- Currently banned:    3
///    |- Total banned:    15
///    `- Banned IP list:    1.2.3.4 5.6.7.8 9.10.11.12
/// ```
///
/// If "Currently banned:" is 0, returns an empty vec immediately.
pub fn parse_banned_ips(output: &str, jail: &str) -> Vec<BannedIp> {
    let mut currently_banned: Option<u32> = None;
    let mut banned_ip_line: Option<&str> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Parse "Currently banned:\tN" (with or without |-/`- prefix)
        let banned_count_part = trimmed
            .strip_prefix("|- Currently banned:")
            .or_else(|| trimmed.strip_prefix("Currently banned:"));
        if let Some(rest) = banned_count_part {
            let count_str = rest.trim_start_matches(['\t', ' ']);
            if let Ok(n) = count_str.parse::<u32>() {
                currently_banned = Some(n);
            }
        }

        // Parse "Banned IP list:\t..." (with or without `- prefix)
        let ip_list_part = trimmed
            .strip_prefix("`- Banned IP list:")
            .or_else(|| trimmed.strip_prefix("Banned IP list:"));
        if let Some(rest) = ip_list_part {
            banned_ip_line = Some(rest);
        }
    }

    // If currently_banned is explicitly 0, skip parsing the IP list
    if currently_banned == Some(0) {
        return vec![];
    }

    let Some(ip_list_raw) = banned_ip_line else {
        return vec![];
    };

    let ip_list = ip_list_raw.trim_start_matches(['\t', ' ']);
    if ip_list.is_empty() {
        return vec![];
    }

    ip_list
        .split_whitespace()
        .map(|ip| BannedIp {
            ip: ip.to_string(),
            jail: jail.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// State persisted between ticks so we only act on *new* bans.
pub struct Fail2BanState {
    /// IPs we have already processed (blocked via InnerWarden or already in blocklist).
    pub known_ips: std::collections::HashSet<String>,
    /// Jails to poll (empty = all active jails from `fail2ban-client status`).
    pub jails: Vec<String>,
    pub client: Fail2BanClient,
}

impl Fail2BanState {
    pub fn new(cfg: &Fail2BanConfig) -> Self {
        Self {
            known_ips: std::collections::HashSet::new(),
            jails: cfg.jails.clone(),
            client: Fail2BanClient::new(cfg.use_sudo),
        }
    }
}

// ---------------------------------------------------------------------------
// Sync tick — called from the agent's continuous loop
// ---------------------------------------------------------------------------

/// Process fail2ban bans for one tick.
/// Returns the number of new IPs blocked.
#[allow(clippy::too_many_arguments)]
pub async fn sync_tick(
    fb: &mut Fail2BanState,
    blocklist: &mut Blocklist,
    skill_registry: &SkillRegistry,
    cfg: &AgentConfig,
    decision_writer: &mut Option<DecisionWriter>,
    decision_cooldowns: &mut std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    host: &str,
    telegram_client: Option<&std::sync::Arc<crate::telegram::TelegramClient>>,
) -> usize {
    // Determine which jails to poll
    let jails: Vec<String> = if fb.jails.is_empty() {
        let found = fb.client.list_jails().await;
        if found.is_empty() {
            debug!("fail2ban: no active jails found (fail2ban-client status returned empty list)");
            return 0;
        }
        found
    } else {
        fb.jails.clone()
    };

    let mut new_blocks = 0;

    for jail in &jails {
        let banned = fb.client.banned_ips(jail).await;

        for entry in banned {
            let ip = &entry.ip;

            // Skip already-known or already-blocked IPs
            if fb.known_ips.contains(ip) || blocklist.contains(ip) {
                fb.known_ips.insert(ip.clone());
                continue;
            }

            // Skip private / loopback IPs (same gate as AI layer)
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                if is_private_or_loopback(addr) {
                    fb.known_ips.insert(ip.clone());
                    continue;
                }
            }

            // Decision cooldown — skip if we already blocked this IP recently.
            // Survives agent restarts (cooldowns loaded from decisions file on startup).
            let cooldown_key = format!("block_ip:fail2ban:ip:{ip}");
            let cooldown_cutoff = chrono::Utc::now() - chrono::Duration::seconds(3600);
            if decision_cooldowns
                .get(&cooldown_key)
                .is_some_and(|ts| *ts > cooldown_cutoff)
            {
                fb.known_ips.insert(ip.clone());
                continue;
            }

            info!(
                ip = %ip,
                jail = %jail,
                "fail2ban ban — blocking IP"
            );

            // Execute block skill directly (bypass AI)
            let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
            let skill = skill_registry
                .get(&skill_id)
                .or_else(|| skill_registry.block_skill_for_backend(&cfg.responder.block_backend));

            let execution_result = match skill {
                Some(skill) => {
                    use innerwarden_core::{
                        entities::EntityRef, event::Severity, incident::Incident,
                    };
                    let synthetic_incident = Incident {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        incident_id: format!("fail2ban:{}:{}", jail, ip),
                        severity: Severity::High,
                        title: format!("fail2ban ban [{}]: {}", jail, ip),
                        summary: format!("fail2ban banned {} in jail '{}'", ip, jail),
                        evidence: serde_json::json!({
                            "source": "fail2ban",
                            "jail": jail,
                        }),
                        recommended_checks: vec![],
                        tags: vec!["fail2ban".to_string(), jail.clone()],
                        entities: vec![EntityRef::ip(ip)],
                    };
                    let ctx = SkillContext {
                        incident: synthetic_incident,
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.to_string(),
                        data_dir: std::path::PathBuf::new(),
                        honeypot: skills::HoneypotRuntimeConfig::default(),
                        ai_provider: None,
                    };
                    let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    if result.success {
                        blocklist.insert(ip.clone());
                        new_blocks += 1;
                    }
                    result.message
                }
                None => {
                    warn!(skill_id = %skill_id, "fail2ban: no block skill available");
                    format!("skipped: skill '{skill_id}' not found or not in allowed_skills")
                }
            };

            fb.known_ips.insert(ip.clone());
            decision_cooldowns.insert(cooldown_key, chrono::Utc::now());

            // Write audit trail
            if let Some(writer) = decision_writer {
                let decision_entry = DecisionEntry {
                    ts: chrono::Utc::now(),
                    incident_id: format!("fail2ban:{}:{}", jail, ip),
                    host: host.to_string(),
                    ai_provider: format!("fail2ban:{}", jail),
                    action_type: "block_ip".to_string(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    skill_id: Some(skill_id),
                    confidence: 1.0,
                    auto_executed: true,
                    dry_run: cfg.responder.dry_run,
                    reason: format!("fail2ban ban in jail '{}'", jail),
                    estimated_threat: "high".to_string(),
                    execution_result,
                };
                // Send Telegram follow-up so the operator knows the outcome
                if cfg.telegram.bot.enabled {
                    if let Some(tg) = telegram_client {
                        let msg = if decision_entry.execution_result.starts_with("Blocked") {
                            format!(
                                "🛡️ <b>Blocked</b> <code>{ip}</code> via fail2ban (jail: {jail})\n\
                                 Firewall rule added. Attacker can no longer connect.",
                            )
                        } else {
                            format!(
                                "⚠️ fail2ban detected <code>{ip}</code> (jail: {jail}) — firewall block failed.\nCheck <code>innerwarden doctor</code> for fix hints.",
                            )
                        };
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let _ = tg.send_text_message(&msg).await;
                        });
                    }
                }

                if let Err(e) = writer.write(&decision_entry) {
                    warn!(error = %e, "failed to write fail2ban decision to audit trail");
                }
            }
        }
    }

    if new_blocks > 0 {
        info!(
            count = new_blocks,
            "fail2ban: blocked {} new IP(s)", new_blocks
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
    fn parse_jail_list_two_jails() {
        let output = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-req-limit\n";
        let jails = parse_jail_list(output);
        assert_eq!(jails, vec!["sshd", "nginx-req-limit"]);
    }

    #[test]
    fn parse_banned_ips_three_ips() {
        let output = "Status for the jail: sshd\n\
            |- Filter\n\
            |  |- Currently failed:\t1\n\
            |  |- Total failed:\t42\n\
            |  `- File list:\t/var/log/auth.log\n\
            `- Actions\n\
               |- Currently banned:\t3\n\
               |- Total banned:\t15\n\
               `- Banned IP list:\t1.2.3.4 5.6.7.8 9.10.11.12\n";
        let banned = parse_banned_ips(output, "sshd");
        assert_eq!(banned.len(), 3);
        assert_eq!(banned[0].ip, "1.2.3.4");
        assert_eq!(banned[1].ip, "5.6.7.8");
        assert_eq!(banned[2].ip, "9.10.11.12");
        for b in &banned {
            assert_eq!(b.jail, "sshd");
        }
    }

    #[test]
    fn parse_empty_banned_list_no_bans() {
        let output = "Status for the jail: sshd\n\
            |- Filter\n\
            |  |- Currently failed:\t0\n\
            |  `- File list:\t/var/log/auth.log\n\
            `- Actions\n\
               |- Currently banned:\t0\n\
               |- Total banned:\t0\n\
               `- Banned IP list:\t\n";
        let banned = parse_banned_ips(output, "sshd");
        assert!(banned.is_empty());
    }

    #[test]
    fn parse_jail_with_no_bans_currently_zero() {
        // "Currently banned: 0" should short-circuit even if IP list line exists
        let output = "Status for the jail: nginx-req-limit\n\
            `- Actions\n\
               |- Currently banned:\t0\n\
               |- Total banned:\t5\n\
               `- Banned IP list:\t203.0.113.10\n";
        let banned = parse_banned_ips(output, "nginx-req-limit");
        // Currently banned = 0 means we skip processing
        assert!(banned.is_empty());
    }

    #[test]
    fn private_ip_filtered() {
        assert!(is_private_or_loopback("192.168.1.1".parse().unwrap()));
        assert!(is_private_or_loopback("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_loopback("10.0.0.1".parse().unwrap()));
        assert!(is_private_or_loopback("172.16.0.1".parse().unwrap()));
        assert!(!is_private_or_loopback("203.0.113.10".parse().unwrap()));
        assert!(!is_private_or_loopback("1.2.3.4".parse().unwrap()));
    }
}
