/// User-agent scanner detector.
///
/// Detects HTTP requests from known security scanning tools by matching the
/// User-Agent header against a curated list of scanner signatures.
///
/// Unlike sliding-window detectors, a single request with a scanner UA is
/// already an actionable signal — no threshold needed.
///
/// Tagged as MITRE ATT&CK T1595 (Active Scanning) / T1595.002 (Vulnerability Scanning).
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};

const SCANNER_SIGNATURES: &[(&str, &str)] = &[
    ("nikto", "Nikto"),
    ("sqlmap", "sqlmap"),
    ("nuclei", "Nuclei"),
    ("masscan", "Masscan"),
    ("zgrab", "Zgrab"),
    ("wfuzz", "wfuzz"),
    ("dirbuster", "DirBuster"),
    ("gobuster", "Gobuster"),
    ("ffuf", "ffuf"),
    ("acunetix", "Acunetix"),
    ("w3af", "w3af"),
    ("appscan", "IBM AppScan"),
    ("openvas", "OpenVAS"),
    ("nessus", "Nessus"),
    ("burpsuite", "Burp Suite"),
    ("burp suite", "Burp Suite"),
    ("metasploit", "Metasploit"),
    ("nmap scripting", "Nmap"),
    ("python-requests/", "Python-Requests scanner"),
    ("go-http-client/", "Go-http-client scanner"),
];

pub struct UserAgentScannerDetector {
    host: String,
    /// (ip, scanner_name) → last alert time
    alerted: HashMap<(String, String), DateTime<Utc>>,
    /// Dedup window (default 10 minutes)
    dedup_window: Duration,
}

impl UserAgentScannerDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            alerted: HashMap::new(),
            dedup_window: Duration::minutes(10),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when the User-Agent matches a known scanner signature.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process http.request events from nginx_access
        if event.kind != "http.request" {
            return None;
        }

        let ua = event.details["user_agent"]
            .as_str()
            .unwrap_or("")
            .to_lowercase();
        if ua.is_empty() {
            return None;
        }

        let ip = event.details["ip"].as_str()?.to_string();
        let now = event.ts;

        // Find matching scanner signature
        let (_, scanner_name) = SCANNER_SIGNATURES
            .iter()
            .find(|(sig, _)| ua.contains(sig))?;
        let scanner_name = scanner_name.to_string();

        // Dedup: skip if same IP + scanner alerted recently
        let key = (ip.clone(), scanner_name.clone());
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.dedup_window {
                return None;
            }
        }
        self.alerted.insert(key, now);

        // Get path and method for context
        let path = event.details["path"].as_str().unwrap_or("").to_string();
        let method = event.details["method"].as_str().unwrap_or("").to_string();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "scanner_ua:{}:{}:{}",
                scanner_name.to_lowercase().replace(' ', "_"),
                ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!("{scanner_name} scanner detected from {ip}"),
            summary: format!(
                "{scanner_name} security scanner identified from {ip} — User-Agent matched known scanner signature"
            ),
            evidence: serde_json::json!([{
                "kind": "http.request",
                "ip": ip,
                "scanner": scanner_name,
                "user_agent": event.details["user_agent"].as_str().unwrap_or(""),
                "method": method,
                "path": path,
            }]),
            recommended_checks: vec![
                format!("Review all requests from {ip} in nginx access log"),
                format!(
                    "{scanner_name} may be probing for vulnerabilities — check scan results if authorized"
                ),
                "Consider blocking IP if scan is unauthorized".to_string(),
            ],
            tags: vec![
                "http".to_string(),
                "scan".to_string(),
                "reconnaissance".to_string(),
                "T1595".to_string(),
                "T1595.002".to_string(),
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

    fn http_request_event(ip: &str, ua: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "nginx_access".into(),
            kind: "http.request".into(),
            severity: Sev::Info,
            summary: format!("GET / from {ip}"),
            details: serde_json::json!({
                "ip": ip,
                "method": "GET",
                "path": "/",
                "user_agent": ua,
                "status": 200,
            }),
            tags: vec!["http".to_string()],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn known_scanner_nikto_emits_incident() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event("1.2.3.4", "Nikto/2.1.6", Utc::now());
        let inc = det.process(&ev).unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("Nikto"));
        assert!(inc.incident_id.starts_with("scanner_ua:nikto:1.2.3.4:"));
    }

    #[test]
    fn known_scanner_sqlmap_emits_incident() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event(
            "1.2.3.4",
            "sqlmap/1.7.2#stable (https://sqlmap.org)",
            Utc::now(),
        );
        let inc = det.process(&ev).unwrap();
        assert!(inc.title.contains("sqlmap"));
        assert!(inc.incident_id.starts_with("scanner_ua:sqlmap:"));
    }

    #[test]
    fn known_scanner_nuclei_emits_incident() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event(
            "5.6.7.8",
            "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
            Utc::now(),
        );
        let inc = det.process(&ev).unwrap();
        assert!(inc.title.contains("Nuclei"));
        assert_eq!(inc.entities[0].value, "5.6.7.8");
    }

    #[test]
    fn unknown_ua_no_incident() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event(
            "1.2.3.4",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            Utc::now(),
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn empty_ua_no_incident() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event("1.2.3.4", "", Utc::now());
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn non_http_request_event_ignored() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = Event {
            ts: Utc::now(),
            host: "host".into(),
            source: "auth_log".into(),
            kind: "ssh.login_failed".into(),
            severity: Sev::Medium,
            summary: "failed SSH login".into(),
            details: serde_json::json!({
                "ip": "1.2.3.4",
                "user_agent": "nikto",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedup_suppresses_same_ip_and_scanner() {
        let mut det = UserAgentScannerDetector::new("host");
        let base = Utc::now();
        let ev1 = http_request_event("1.2.3.4", "Nikto/2.1.6", base);
        let ev2 = http_request_event("1.2.3.4", "Nikto/2.1.6", base + Duration::minutes(5));
        // First should fire
        assert!(det.process(&ev1).is_some());
        // Second within 10 min from same IP + same scanner should be suppressed
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn dedup_allows_different_scanner() {
        let mut det = UserAgentScannerDetector::new("host");
        let base = Utc::now();
        let ev_nikto = http_request_event("1.2.3.4", "Nikto/2.1.6", base);
        let ev_sqlmap = http_request_event("1.2.3.4", "sqlmap/1.7", base + Duration::minutes(1));
        // Nikto fires
        assert!(det.process(&ev_nikto).is_some());
        // sqlmap is a different scanner → should also fire
        assert!(det.process(&ev_sqlmap).is_some());
    }

    #[test]
    fn case_insensitive_match() {
        let mut det = UserAgentScannerDetector::new("host");
        // UA in uppercase — detector lowercases before matching
        let ev = http_request_event("1.2.3.4", "NIKTO/2.1.6", Utc::now());
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn incident_has_t1595_tags() {
        let mut det = UserAgentScannerDetector::new("host");
        let ev = http_request_event("1.2.3.4", "nuclei - Open-source", Utc::now());
        let inc = det.process(&ev).unwrap();
        assert!(inc.tags.contains(&"T1595".to_string()));
        assert!(inc.tags.contains(&"T1595.002".to_string()));
    }

    #[test]
    fn dedup_expires_after_window() {
        let mut det = UserAgentScannerDetector::new("host");
        let base = Utc::now();
        let ev1 = http_request_event("1.2.3.4", "Nikto/2.1.6", base);
        // Second event after dedup window expires (11 minutes later)
        let ev2 = http_request_event("1.2.3.4", "Nikto/2.1.6", base + Duration::minutes(11));
        assert!(det.process(&ev1).is_some());
        // After window expires, should fire again
        assert!(det.process(&ev2).is_some());
    }
}
