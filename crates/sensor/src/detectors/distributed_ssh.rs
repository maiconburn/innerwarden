use std::collections::{HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects distributed SSH attacks — many distinct IPs failing in a short window.
/// Unlike ssh_bruteforce (which tracks one IP), this tracks the *aggregate*
/// pattern: if 10+ different IPs fail SSH in 5 minutes, it's a coordinated scan.
///
/// When triggered, the agent should activate the honeypot for ALL SSH traffic
/// for a short duration, catching the rotating botnet.
pub struct DistributedSshDetector {
    /// Minimum distinct IPs in window to trigger (default: 8)
    threshold: usize,
    window: Duration,
    /// Ring of (timestamp, IP) pairs within the window
    recent_failures: VecDeque<(DateTime<Utc>, String)>,
    /// Last alert time — suppress re-alerts within window
    last_alerted: Option<DateTime<Utc>>,
    host: String,
}

impl DistributedSshDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            recent_failures: VecDeque::new(),
            last_alerted: None,
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "ssh.login_failed" {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        if super::is_internal_ip(&ip) {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        // Prune old entries
        while self
            .recent_failures
            .front()
            .is_some_and(|(t, _)| *t < cutoff)
        {
            self.recent_failures.pop_front();
        }
        self.recent_failures.push_back((now, ip));

        // Count distinct IPs in window
        let distinct_ips: HashSet<&str> = self
            .recent_failures
            .iter()
            .map(|(_, ip)| ip.as_str())
            .collect();

        if distinct_ips.len() < self.threshold {
            return None;
        }

        // Suppress re-alerts within window
        if let Some(last) = self.last_alerted {
            if now - last < self.window {
                return None;
            }
        }

        self.last_alerted = Some(now);
        let count = distinct_ips.len();
        let sample_ips: Vec<&str> = distinct_ips.iter().take(5).copied().collect();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "distributed_ssh:{}:{}",
                count,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!(
                "Distributed SSH attack — {count} IPs in {} seconds",
                self.window.num_seconds()
            ),
            summary: format!(
                "{count} distinct IPs failed SSH login in the last {} seconds. \
                 This is a coordinated botnet scan. Sample IPs: {}",
                self.window.num_seconds(),
                sample_ips.join(", ")
            ),
            evidence: serde_json::json!([{
                "kind": "distributed_ssh",
                "distinct_ips": count,
                "sample_ips": sample_ips,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                "Activate honeypot to capture attacker TTPs".to_string(),
                "Check if any login succeeded during this window".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                "distributed".to_string(),
                "botnet".to_string(),
            ],
            entities: sample_ips.iter().map(|ip| EntityRef::ip(*ip)).collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: format!("Failed SSH from {ip}"),
            details: serde_json::json!({"ip": ip}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn fires_when_distinct_ips_exceed_threshold() {
        let mut det = DistributedSshDetector::new("test", 3, 300);
        let now = Utc::now();

        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
        assert!(det.process(&make_event("2.2.2.2", now)).is_none());
        let incident = det.process(&make_event("3.3.3.3", now));
        assert!(incident.is_some());
        assert!(incident.unwrap().title.contains("3 IPs"));
    }

    #[test]
    fn same_ip_does_not_increase_count() {
        let mut det = DistributedSshDetector::new("test", 3, 300);
        let now = Utc::now();

        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
        // Still only 1 distinct IP — should not fire
        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
    }

    #[test]
    fn suppresses_realert_within_window() {
        let mut det = DistributedSshDetector::new("test", 2, 300);
        let now = Utc::now();

        det.process(&make_event("1.1.1.1", now));
        assert!(det.process(&make_event("2.2.2.2", now)).is_some()); // fires
                                                                     // Re-alert suppressed
        assert!(det.process(&make_event("3.3.3.3", now)).is_none());
    }

    #[test]
    fn old_entries_expire() {
        let mut det = DistributedSshDetector::new("test", 3, 60);
        let old = Utc::now() - Duration::seconds(120);
        let now = Utc::now();

        det.process(&make_event("1.1.1.1", old));
        det.process(&make_event("2.2.2.2", old));
        // These are expired, so only the new one counts
        assert!(det.process(&make_event("3.3.3.3", now)).is_none());
    }

    #[test]
    fn ignores_internal_ips() {
        let mut det = DistributedSshDetector::new("test", 2, 300);
        let now = Utc::now();

        det.process(&make_event("192.168.1.1", now));
        det.process(&make_event("10.0.0.1", now));
        assert!(det.process(&make_event("1.1.1.1", now)).is_none());
    }
}
