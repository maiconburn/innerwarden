/// Web scan detector.
///
/// Detects HTTP error flooding from a single IP — the hallmark of automated
/// vulnerability scanners and path traversal / LFI probes.
///
/// Listens for `http.error` events (emitted by the nginx_error collector) and
/// fires an incident when a single IP exceeds the configured error-per-window
/// threshold.
use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct WebScanDetector {
    host: String,
    threshold: usize,
    window: Duration,
    /// Per-IP sliding window of http.error timestamps.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Last incident time per IP — suppresses re-alerts within the same window.
    alerted: HashMap<String, DateTime<Utc>>,
}

impl WebScanDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when a single IP exceeds the error threshold.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "http.error" {
            return None;
        }

        if event.tags.iter().any(|t| t == "bot:known") {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        if super::is_internal_ip(&ip) {
            return None;
        }
        let now = event.ts;
        let cutoff = now - self.window;

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

        let level = event.details["level"]
            .as_str()
            .unwrap_or("error")
            .to_string();
        let last_request = event
            .details
            .get("request")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect::<String>();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("web_scan:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Possible web scan / probe from {ip}"),
            summary: format!(
                "{count} HTTP errors from {ip} in the last {} seconds — likely automated scan or probe",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "http.error",
                "ip": ip,
                "error_level": level,
                "count": count,
                "window_seconds": self.window.num_seconds(),
                "last_request": last_request,
            }]),
            recommended_checks: vec![
                format!("Review nginx error log for {ip} — look for path traversal or LFI patterns"),
                "Check if requests target admin, config, or sensitive endpoints".to_string(),
                "Consider blocking IP or enabling rate-limit-nginx skill".to_string(),
            ],
            tags: vec![
                "http".to_string(),
                "scan".to_string(),
                "web".to_string(),
                "probe".to_string(),
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

    fn error_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "nginx_error".into(),
            kind: "http.error".into(),
            severity: Sev::Medium,
            summary: format!("[error] {ip} some error"),
            details: serde_json::json!({
                "ip": ip,
                "level": "error",
                "request": "GET /etc/passwd HTTP/1.1",
                "message": "open() failed",
            }),
            tags: vec!["http".to_string()],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = WebScanDetector::new("host", 5, 60);
        let base = Utc::now();
        for i in 0..4 {
            assert!(det
                .process(&error_event("1.2.3.4", base + Duration::seconds(i)))
                .is_none());
        }
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = WebScanDetector::new("host", 5, 60);
        let base = Utc::now();
        let mut last = None;
        for i in 0..5 {
            last = det.process(&error_event("1.2.3.4", base + Duration::seconds(i)));
        }
        let inc = last.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("web_scan:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["count"], 5);
    }

    #[test]
    fn dedup_suppresses_realert_within_window() {
        let mut det = WebScanDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&error_event("1.2.3.4", base + Duration::seconds(i)));
        }
        assert!(det
            .process(&error_event("1.2.3.4", base + Duration::seconds(3)))
            .is_none());
    }

    #[test]
    fn ignores_non_http_error_events() {
        let mut det = WebScanDetector::new("host", 3, 60);
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Sev::Medium,
            summary: "failed login".into(),
            details: serde_json::json!({ "ip": "1.2.3.4" }),
            tags: vec![],
            entities: vec![],
        };
        for _ in 0..10 {
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn different_ips_are_independent() {
        let mut det = WebScanDetector::new("host", 3, 60);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&error_event("1.1.1.1", base + Duration::seconds(i)));
        }
        for i in 0..2 {
            assert!(det
                .process(&error_event("2.2.2.2", base + Duration::seconds(i)))
                .is_none());
        }
    }

    #[test]
    fn old_entries_expire_from_window() {
        let mut det = WebScanDetector::new("host", 3, 10); // 10s window
        let base = Utc::now();
        det.process(&error_event("1.2.3.4", base - Duration::seconds(20)));
        det.process(&error_event("1.2.3.4", base - Duration::seconds(15)));
        // Both old — only 1 new event → below threshold
        assert!(det.process(&error_event("1.2.3.4", base)).is_none());
        assert!(det
            .process(&error_event("1.2.3.4", base + Duration::seconds(1)))
            .is_none());
        // Third new event hits threshold
        let inc = det.process(&error_event("1.2.3.4", base + Duration::seconds(2)));
        assert!(inc.is_some());
    }
}
