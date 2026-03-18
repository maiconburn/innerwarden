/// Suricata IDS alert detector.
///
/// Watches events whose `kind` starts with `"suricata.alert."`. When a single
/// source IP triggers multiple Suricata alerts within a sliding window, the
/// detector promotes the cluster to an incident.
use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct SuricataAlertDetector {
    host: String,
    threshold: usize,
    window: Duration,
    /// Per-IP sliding window of alert timestamps.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Last incident time per IP — suppresses re-alerts within the same window.
    alerted: HashMap<String, DateTime<Utc>>,
    /// Track whether any alert from a given IP in the current burst had
    /// suricata severity 1 (highest).
    saw_severity_one: HashMap<String, bool>,
}

impl SuricataAlertDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            saw_severity_one: HashMap::new(),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when a single IP exceeds the alert threshold.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if !event.kind.starts_with("suricata.alert.") {
            return None;
        }

        let ip = event.details.get("src_ip")?.as_str()?.to_string();
        let now = event.ts;
        let cutoff = now - self.window;

        // Track whether we have seen severity 1 from this IP
        if let Some(sev) = event.details.get("severity").and_then(|v| v.as_u64()) {
            if sev == 1 {
                self.saw_severity_one.insert(ip.clone(), true);
            }
        }

        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|&t| t < cutoff) {
            entries.pop_front();
        }
        entries.push_back(now);

        let count = entries.len();
        if count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(ip.clone(), now);

        let signature = event
            .details
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let category = event
            .details
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let severity = if self.saw_severity_one.get(&ip).copied().unwrap_or(false) {
            Severity::Critical
        } else {
            Severity::High
        };

        // Reset severity-one tracker for this IP after firing
        self.saw_severity_one.remove(&ip);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("suricata_alert:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Suricata IDS: repeated alerts from {ip}"),
            summary: format!(
                "{count} Suricata alerts from {ip} in the last {} seconds — last signature: {signature} ({category})",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": &event.kind,
                "src_ip": ip,
                "signature": signature,
                "category": category,
                "count": count,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Review Suricata eve.json logs for {ip} — check alert signatures and categories"),
                "Correlate with network flow data for lateral movement".to_string(),
                "Consider blocking IP if attack pattern confirmed".to_string(),
            ],
            tags: vec![
                "suricata".to_string(),
                "ids".to_string(),
                "network".to_string(),
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

    fn suricata_event(ip: &str, ts: DateTime<Utc>, suri_severity: u64) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "suricata".into(),
            kind: "suricata.alert.potentially_bad_traffic".into(),
            severity: Sev::Medium,
            summary: format!("suricata alert from {ip}"),
            details: serde_json::json!({
                "src_ip": ip,
                "signature": "ET SCAN Potential SSH Scan",
                "category": "potentially_bad_traffic",
                "severity": suri_severity,
            }),
            tags: vec!["suricata".to_string()],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..2 {
            assert!(det
                .process(&suricata_event("1.2.3.4", base + Duration::seconds(i), 2))
                .is_none());
        }
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        let mut last = None;
        for i in 0..3 {
            last = det.process(&suricata_event("1.2.3.4", base + Duration::seconds(i), 2));
        }
        let inc = last.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("suricata_alert:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["count"], 3);
    }

    #[test]
    fn critical_when_severity_one() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        det.process(&suricata_event("1.2.3.4", base, 2));
        det.process(&suricata_event("1.2.3.4", base + Duration::seconds(1), 1)); // severity 1
        let inc = det
            .process(&suricata_event("1.2.3.4", base + Duration::seconds(2), 3))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn dedup_suppresses_realert_within_window() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&suricata_event("1.2.3.4", base + Duration::seconds(i), 2));
        }
        // Fourth event in same window — suppressed
        assert!(det
            .process(&suricata_event("1.2.3.4", base + Duration::seconds(3), 2))
            .is_none());
    }

    #[test]
    fn ignores_non_suricata_alert_events() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Sev::Medium,
            summary: "failed login".into(),
            details: serde_json::json!({ "src_ip": "1.2.3.4" }),
            tags: vec![],
            entities: vec![],
        };
        for _ in 0..10 {
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn different_ips_are_independent() {
        let mut det = SuricataAlertDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&suricata_event("1.1.1.1", base + Duration::seconds(i), 2));
        }
        // Different IP — only 2 events, below threshold
        for i in 0..2 {
            assert!(det
                .process(&suricata_event("2.2.2.2", base + Duration::seconds(i), 2))
                .is_none());
        }
    }

    #[test]
    fn old_entries_expire_from_window() {
        let mut det = SuricataAlertDetector::new("host", 3, 10); // 10s window
        let base = Utc::now();
        det.process(&suricata_event("1.2.3.4", base - Duration::seconds(20), 2));
        det.process(&suricata_event("1.2.3.4", base - Duration::seconds(15), 2));
        // Both old — only 1 new event → below threshold
        assert!(det.process(&suricata_event("1.2.3.4", base, 2)).is_none());
        assert!(det
            .process(&suricata_event("1.2.3.4", base + Duration::seconds(1), 2))
            .is_none());
        // Third new event hits threshold
        let inc = det.process(&suricata_event("1.2.3.4", base + Duration::seconds(2), 2));
        assert!(inc.is_some());
    }
}
