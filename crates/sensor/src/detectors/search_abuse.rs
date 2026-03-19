/// Search abuse detector.
///
/// Detects automated/abusive high-rate access to expensive HTTP routes
/// (e.g. search APIs). Uses a sliding window per source IP, scoped to a
/// configurable path prefix. Triggers when a single IP exceeds the threshold
/// within the window.
use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct SearchAbuseDetector {
    host: String,
    threshold: usize,
    window: Duration,
    /// Path prefix to watch (e.g. "/api/search"). Empty = any path.
    path_prefix: String,
    /// Per-IP sliding window of request timestamps.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Last incident time per IP — suppresses re-alerts within the same window.
    alerted: HashMap<String, DateTime<Utc>>,
}

impl SearchAbuseDetector {
    pub fn new(
        host: impl Into<String>,
        threshold: usize,
        window_seconds: u64,
        path_prefix: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            path_prefix: path_prefix.into(),
            windows: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when a single IP exceeds the request threshold.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "http.request" {
            return None;
        }

        // Skip known good bots (Googlebot, Bingbot, etc.)
        if event.tags.iter().any(|t| t == "bot:known") {
            return None;
        }

        // Only track requests matching the configured path prefix
        let path = event.details["path"].as_str().unwrap_or("");
        let path_without_qs = path.split('?').next().unwrap_or(path);
        if !self.path_prefix.is_empty() && !path_without_qs.starts_with(&self.path_prefix) {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        if super::is_internal_ip(&ip) {
            return None;
        }
        let now = event.ts;
        let cutoff = now - self.window;

        // Advance sliding window: drop entries older than cutoff
        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|&t| t < cutoff) {
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

        let method = event.details["method"].as_str().unwrap_or("?").to_string();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("search_abuse:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Possible search route abuse from {ip}"),
            summary: format!(
                "{count} requests to {}{} from {ip} in the last {} seconds",
                if self.path_prefix.is_empty() {
                    "(any path)"
                } else {
                    &self.path_prefix
                },
                if self.path_prefix.is_empty() {
                    ""
                } else {
                    "* "
                },
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "http.request",
                "ip": ip,
                "method": method,
                "path_prefix": self.path_prefix,
                "count": count,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Review access logs for {ip} — check for automation patterns"),
                "Consider rate-limiting or blocking the source IP".to_string(),
                "Check if traffic correlates with an SSH or credential-stuffing incident"
                    .to_string(),
            ],
            tags: vec![
                "http".to_string(),
                "abuse".to_string(),
                "search".to_string(),
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

    fn request_event(ip: &str, path: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "nginx_access".into(),
            kind: "http.request".into(),
            severity: Sev::Info,
            summary: format!("GET {path} 200"),
            details: serde_json::json!({
                "ip": ip,
                "method": "GET",
                "path": path,
                "status": 200,
                "bytes": 512,
                "user_agent": "bot/1.0"
            }),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = SearchAbuseDetector::new("host", 5, 60, "/api/search");
        let base = Utc::now();
        for i in 0..4 {
            let ev = request_event("1.2.3.4", "/api/search?q=test", base + Duration::seconds(i));
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = SearchAbuseDetector::new("host", 5, 60, "/api/search");
        let base = Utc::now();
        let mut last = None;
        for i in 0..5 {
            let ev = request_event("1.2.3.4", "/api/search?q=foo", base + Duration::seconds(i));
            last = det.process(&ev);
        }
        let inc = last.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("search_abuse:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["count"], 5);
    }

    #[test]
    fn dedup_suppresses_realert_within_window() {
        let mut det = SearchAbuseDetector::new("host", 3, 300, "/api/search");
        let base = Utc::now();
        for i in 0..3 {
            det.process(&request_event(
                "1.2.3.4",
                "/api/search",
                base + Duration::seconds(i),
            ));
        }
        // Further requests within same window should not re-alert
        assert!(det
            .process(&request_event(
                "1.2.3.4",
                "/api/search",
                base + Duration::seconds(3)
            ))
            .is_none());
    }

    #[test]
    fn ignores_non_matching_paths() {
        let mut det = SearchAbuseDetector::new("host", 3, 60, "/api/search");
        let base = Utc::now();
        for i in 0..10 {
            let ev = request_event("1.2.3.4", "/api/users", base + Duration::seconds(i));
            assert!(
                det.process(&ev).is_none(),
                "should not trigger for /api/users"
            );
        }
    }

    #[test]
    fn empty_prefix_matches_any_path() {
        let mut det = SearchAbuseDetector::new("host", 3, 60, "");
        let base = Utc::now();
        let mut last = None;
        for i in 0..3 {
            let ev = request_event("1.2.3.4", "/anything/at/all", base + Duration::seconds(i));
            last = det.process(&ev);
        }
        assert!(last.is_some());
    }

    #[test]
    fn different_ips_are_independent() {
        let mut det = SearchAbuseDetector::new("host", 3, 60, "/api/search");
        let base = Utc::now();
        // ip-A hits threshold
        for i in 0..3 {
            det.process(&request_event(
                "1.1.1.1",
                "/api/search",
                base + Duration::seconds(i),
            ));
        }
        // ip-B only 2 requests — no incident
        for i in 0..2 {
            let r = det.process(&request_event(
                "2.2.2.2",
                "/api/search",
                base + Duration::seconds(i),
            ));
            assert!(r.is_none());
        }
    }

    #[test]
    fn path_with_query_string_matches_prefix() {
        let mut det = SearchAbuseDetector::new("host", 3, 60, "/api/search");
        let base = Utc::now();
        let mut last = None;
        for i in 0..3 {
            let ev = request_event(
                "1.2.3.4",
                "/api/search?q=automated+query",
                base + Duration::seconds(i),
            );
            last = det.process(&ev);
        }
        assert!(last.is_some());
    }

    #[test]
    fn old_entries_expire_from_window() {
        let mut det = SearchAbuseDetector::new("host", 3, 10, "/api/search"); // 10s window
        let base = Utc::now();
        // 2 old events outside the window
        det.process(&request_event(
            "1.2.3.4",
            "/api/search",
            base - Duration::seconds(20),
        ));
        det.process(&request_event(
            "1.2.3.4",
            "/api/search",
            base - Duration::seconds(15),
        ));
        // 2 new events inside window — total in window = 2, below threshold of 3
        assert!(det
            .process(&request_event("1.2.3.4", "/api/search", base))
            .is_none());
        assert!(det
            .process(&request_event(
                "1.2.3.4",
                "/api/search",
                base + Duration::seconds(1)
            ))
            .is_none());
        // 3rd new event hits threshold
        let inc = det.process(&request_event(
            "1.2.3.4",
            "/api/search",
            base + Duration::seconds(2),
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn ignores_non_http_events() {
        let mut det = SearchAbuseDetector::new("host", 3, 60, "/api/search");
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Sev::Info,
            summary: "failed login".into(),
            details: serde_json::json!({ "ip": "1.2.3.4" }),
            tags: vec![],
            entities: vec![],
        };
        for _ in 0..10 {
            assert!(det.process(&ev).is_none());
        }
    }
}
