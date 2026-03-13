use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct SshBruteforceDetector {
    threshold: usize,
    window: Duration,
    /// Per-IP ring of event timestamps within the current window.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Last incident emission time per IP — used to suppress re-alerts
    /// until the full window has elapsed.
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl SshBruteforceDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` if the brute-force threshold is crossed.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "ssh.login_failed" {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        let now = event.ts;
        let cutoff = now - self.window;

        // Advance the sliding window: drop entries older than cutoff
        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().map_or(false, |&t| t < cutoff) {
            entries.pop_front();
        }
        entries.push_back(now);

        let count = entries.len();
        if count < self.threshold {
            return None;
        }

        // Suppress re-alerts within the same window period
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(ip.clone(), now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("ssh_bruteforce:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Possible SSH brute force from {ip}"),
            summary: format!(
                "{count} failed SSH login attempts from {ip} in the last {} seconds",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "ssh.login_failed",
                "ip": ip,
                "count": count,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Check auth.log for successful logins from {ip}"),
                "Consider blocking the IP with ufw or fail2ban".to_string(),
                "Review /var/log/auth.log for the full session".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                "bruteforce".to_string(),
            ],
            entities: vec![EntityRef::ip(&ip)],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn failed_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Sev::Info,
            summary: format!("Failed login from {ip}"),
            details: serde_json::json!({ "ip": ip, "user": "root" }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn success_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: Sev::Info,
            summary: format!("Login from {ip}"),
            details: serde_json::json!({ "ip": ip, "user": "ubuntu" }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = SshBruteforceDetector::new("host", 5, 300);
        let base = Utc::now();
        for i in 0..4 {
            let ev = failed_event("1.2.3.4", base + Duration::seconds(i));
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = SshBruteforceDetector::new("host", 5, 300);
        let base = Utc::now();
        let mut incident = None;
        for i in 0..5 {
            let ev = failed_event("1.2.3.4", base + Duration::seconds(i));
            incident = det.process(&ev);
        }
        let inc = incident.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("ssh_bruteforce:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["count"], 5);
    }

    #[test]
    fn dedup_suppresses_second_alert_within_window() {
        let mut det = SshBruteforceDetector::new("host", 3, 300);
        let base = Utc::now();
        // First 3 trigger an incident
        for i in 0..3 {
            det.process(&failed_event("1.2.3.4", base + Duration::seconds(i)));
        }
        // 4th and 5th should not emit another incident
        assert!(det
            .process(&failed_event("1.2.3.4", base + Duration::seconds(3)))
            .is_none());
        assert!(det
            .process(&failed_event("1.2.3.4", base + Duration::seconds(4)))
            .is_none());
    }

    #[test]
    fn different_ips_are_independent() {
        let mut det = SshBruteforceDetector::new("host", 3, 300);
        let base = Utc::now();
        // 3 from ip-A → incident
        for i in 0..3 {
            det.process(&failed_event("1.1.1.1", base + Duration::seconds(i)));
        }
        // ip-B only has 2 → no incident
        for i in 0..2 {
            let result = det.process(&failed_event("2.2.2.2", base + Duration::seconds(i)));
            assert!(result.is_none());
        }
    }

    #[test]
    fn success_events_are_ignored() {
        let mut det = SshBruteforceDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..5 {
            assert!(det
                .process(&success_event("1.2.3.4", base + Duration::seconds(i)))
                .is_none());
        }
    }

    #[test]
    fn old_events_expire_from_window() {
        let mut det = SshBruteforceDetector::new("host", 3, 10); // 10s window
        let base = Utc::now();
        // 2 old events, outside window
        det.process(&failed_event("1.2.3.4", base - Duration::seconds(20)));
        det.process(&failed_event("1.2.3.4", base - Duration::seconds(15)));
        // 2 new events inside window — total in window = 2, below threshold
        assert!(det.process(&failed_event("1.2.3.4", base)).is_none());
        assert!(det
            .process(&failed_event("1.2.3.4", base + Duration::seconds(1)))
            .is_none());
        // 3rd new event → hits threshold
        let inc = det.process(&failed_event("1.2.3.4", base + Duration::seconds(2)));
        assert!(inc.is_some());
    }
}
