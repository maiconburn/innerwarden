use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct CredentialStuffingDetector {
    threshold: usize,
    window: Duration,
    /// Per-IP ring of (timestamp, username) entries within the current window.
    windows: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    /// Last incident emission time per IP — suppresses re-alerts in the same window.
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl CredentialStuffingDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Detect potential credential stuffing:
    /// one source IP failing SSH auth against many distinct usernames.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "ssh.login_failed" {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        let user = event.details["user"].as_str()?.trim();
        if user.is_empty() {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|(ts, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, user.to_string()));

        let unique_users: HashSet<&str> = entries.iter().map(|(_, u)| u.as_str()).collect();
        let unique_count = unique_users.len();
        if unique_count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(ip.clone(), now);

        let mut usernames: Vec<&str> = unique_users.into_iter().collect();
        usernames.sort_unstable();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "credential_stuffing:{}:{}",
                ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!("Possible SSH credential stuffing from {ip}"),
            summary: format!(
                "{} failed SSH attempts from {ip} across {unique_count} distinct usernames in the last {} seconds",
                entries.len(),
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "ssh.login_failed",
                "ip": ip,
                "attempts": entries.len(),
                "unique_users": unique_count,
                "users": usernames,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Review auth.log for username spray patterns from {ip}"),
                "Correlate with successful SSH logins around the same timeframe".to_string(),
                "Consider temporary blocking if attempts continue".to_string(),
            ],
            tags: vec!["auth".to_string(), "ssh".to_string(), "credential-stuffing".to_string()],
            entities: vec![EntityRef::ip(ip)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn failed_event(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Sev::Info,
            summary: format!("Failed login for {user} from {ip}"),
            details: serde_json::json!({ "ip": ip, "user": user }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn success_event(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: Sev::Info,
            summary: format!("Login accepted for {user} from {ip}"),
            details: serde_json::json!({ "ip": ip, "user": user }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = CredentialStuffingDetector::new("host", 4, 300);
        let base = Utc::now();
        assert!(det
            .process(&failed_event("1.2.3.4", "alice", base))
            .is_none());
        assert!(det
            .process(&failed_event("1.2.3.4", "bob", base + Duration::seconds(1)))
            .is_none());
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "carol",
                base + Duration::seconds(2)
            ))
            .is_none());
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = CredentialStuffingDetector::new("host", 3, 300);
        let base = Utc::now();
        det.process(&failed_event("1.2.3.4", "alice", base));
        det.process(&failed_event("1.2.3.4", "bob", base + Duration::seconds(1)));
        let inc = det
            .process(&failed_event(
                "1.2.3.4",
                "carol",
                base + Duration::seconds(2),
            ))
            .expect("incident expected at threshold");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("credential_stuffing:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["unique_users"], 3);
    }

    #[test]
    fn repeated_same_user_does_not_raise_unique_count() {
        let mut det = CredentialStuffingDetector::new("host", 3, 300);
        let base = Utc::now();
        assert!(det
            .process(&failed_event("1.2.3.4", "root", base))
            .is_none());
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "root",
                base + Duration::seconds(1)
            ))
            .is_none());
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "root",
                base + Duration::seconds(2)
            ))
            .is_none());
    }

    #[test]
    fn dedup_suppresses_second_alert_within_window() {
        let mut det = CredentialStuffingDetector::new("host", 3, 300);
        let base = Utc::now();
        det.process(&failed_event("1.2.3.4", "alice", base));
        det.process(&failed_event("1.2.3.4", "bob", base + Duration::seconds(1)));
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "carol",
                base + Duration::seconds(2)
            ))
            .is_some());
        // Still above threshold but must suppress in the same window.
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "dave",
                base + Duration::seconds(3)
            ))
            .is_none());
    }

    #[test]
    fn old_entries_expire_from_window() {
        let mut det = CredentialStuffingDetector::new("host", 3, 10);
        let base = Utc::now();
        det.process(&failed_event(
            "1.2.3.4",
            "alice",
            base - Duration::seconds(20),
        ));
        det.process(&failed_event(
            "1.2.3.4",
            "bob",
            base - Duration::seconds(15),
        ));
        assert!(det
            .process(&failed_event("1.2.3.4", "carol", base))
            .is_none());
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "dave",
                base + Duration::seconds(1)
            ))
            .is_none());
        assert!(det
            .process(&failed_event(
                "1.2.3.4",
                "erin",
                base + Duration::seconds(2)
            ))
            .is_some());
    }

    #[test]
    fn success_events_are_ignored() {
        let mut det = CredentialStuffingDetector::new("host", 3, 300);
        let base = Utc::now();
        assert!(det
            .process(&success_event("1.2.3.4", "alice", base))
            .is_none());
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "bob",
                base + Duration::seconds(1)
            ))
            .is_none());
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "carol",
                base + Duration::seconds(2)
            ))
            .is_none());
    }
}
