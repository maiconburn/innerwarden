use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct PortScanDetector {
    threshold: usize,
    window: Duration,
    /// Per-source-IP ring of (timestamp, destination_port) entries in the current window.
    windows: HashMap<String, VecDeque<(DateTime<Utc>, u16)>>,
    /// Last incident emission time per source IP — suppresses re-alerts in the same window.
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl PortScanDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Detect potential port scan from firewall-blocked connections.
    ///
    /// Expected event contract:
    /// - kind: `network.connection_blocked`
    /// - details.src_ip: string
    /// - details.dst_port: integer
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "network.connection_blocked" {
            return None;
        }

        let src_ip = event.details["src_ip"].as_str()?.to_string();
        let dst_port = u16::try_from(event.details["dst_port"].as_u64()?).ok()?;
        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(src_ip.clone()).or_default();
        while entries.front().is_some_and(|(ts, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, dst_port));

        let unique_ports: HashSet<u16> = entries.iter().map(|(_, port)| *port).collect();
        let unique_count = unique_ports.len();
        if unique_count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&src_ip) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(src_ip.clone(), now);

        let mut ports: Vec<u16> = unique_ports.into_iter().collect();
        ports.sort_unstable();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("port_scan:{}:{}", src_ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Possible port scan from {src_ip}"),
            summary: format!(
                "Host {src_ip} hit {unique_count} distinct destination ports in the last {} seconds",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "network.connection_blocked",
                "src_ip": src_ip,
                "unique_dst_ports": unique_count,
                "dst_ports": ports,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                "Review firewall logs (UFW/iptables/nftables) for matching connection bursts".to_string(),
                "Correlate source IP with SSH and app authentication failures".to_string(),
                "Consider temporary IP blocking if traffic persists".to_string(),
            ],
            tags: vec!["network".to_string(), "portscan".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn blocked_event(ip: &str, port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".to_string(),
            source: "journald".to_string(),
            kind: "network.connection_blocked".to_string(),
            severity: Sev::Low,
            summary: format!("Blocked connection from {ip} to port {port}"),
            details: serde_json::json!({
                "src_ip": ip,
                "dst_port": port,
                "dst_ip": "10.0.0.10",
                "proto": "TCP",
            }),
            tags: vec!["network".to_string(), "firewall".to_string()],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn no_incident_below_unique_port_threshold() {
        let mut det = PortScanDetector::new("host", 4, 60);
        let base = Utc::now();
        assert!(det.process(&blocked_event("1.2.3.4", 22, base)).is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 80, base + Duration::seconds(1)))
            .is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 443, base + Duration::seconds(2)))
            .is_none());
    }

    #[test]
    fn incident_at_threshold() {
        let mut det = PortScanDetector::new("host", 3, 60);
        let base = Utc::now();
        det.process(&blocked_event("1.2.3.4", 22, base));
        det.process(&blocked_event("1.2.3.4", 80, base + Duration::seconds(1)));
        let inc = det
            .process(&blocked_event("1.2.3.4", 443, base + Duration::seconds(2)))
            .expect("incident expected at threshold");

        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("port_scan:1.2.3.4:"));
        assert_eq!(inc.evidence[0]["unique_dst_ports"], 3);
    }

    #[test]
    fn repeated_same_port_does_not_raise_unique_count() {
        let mut det = PortScanDetector::new("host", 3, 60);
        let base = Utc::now();
        assert!(det.process(&blocked_event("1.2.3.4", 22, base)).is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 22, base + Duration::seconds(1)))
            .is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 22, base + Duration::seconds(2)))
            .is_none());
    }

    #[test]
    fn dedup_suppresses_second_alert_within_window() {
        let mut det = PortScanDetector::new("host", 3, 60);
        let base = Utc::now();
        det.process(&blocked_event("1.2.3.4", 22, base));
        det.process(&blocked_event("1.2.3.4", 80, base + Duration::seconds(1)));
        assert!(det
            .process(&blocked_event("1.2.3.4", 443, base + Duration::seconds(2)))
            .is_some());
        // Above threshold still, but should be suppressed in same window.
        assert!(det
            .process(&blocked_event("1.2.3.4", 8080, base + Duration::seconds(3)))
            .is_none());
    }

    #[test]
    fn old_entries_expire_and_can_trigger_later() {
        let mut det = PortScanDetector::new("host", 3, 10);
        let base = Utc::now();
        det.process(&blocked_event("1.2.3.4", 22, base - Duration::seconds(20)));
        det.process(&blocked_event("1.2.3.4", 80, base - Duration::seconds(15)));
        assert!(det.process(&blocked_event("1.2.3.4", 443, base)).is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 8080, base + Duration::seconds(1)))
            .is_none());
        assert!(det
            .process(&blocked_event("1.2.3.4", 3306, base + Duration::seconds(2)))
            .is_some());
    }
}
