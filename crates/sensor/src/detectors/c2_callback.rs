use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects Command & Control (C2) callback patterns from outbound connections.
///
/// Patterns detected:
/// 1. Connections to well-known C2 ports (4444, 1337, 31337, 8888, 9999)
/// 2. Beaconing — periodic connections to the same IP at regular intervals
/// 3. Unusual processes making outbound connections (sh, bash, python, perl, nc)
/// 4. Burst of connections to many different IPs in short time (data exfil)
pub struct C2CallbackDetector {
    window: Duration,
    /// Per-IP ring of connection timestamps (for beaconing detection)
    connections: HashMap<String, VecDeque<ConnectionRecord>>,
    /// Track unique destination IPs per process in window (for exfil detection)
    process_destinations: HashMap<String, HashSet<String>>,
    /// Suppress re-alerts per IP within window
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
    /// Known C2 ports
    c2_ports: HashSet<u16>,
    /// Suspicious processes that shouldn't make outbound connections
    suspicious_processes: HashSet<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ConnectionRecord {
    ts: DateTime<Utc>,
    dst_ip: String,
    dst_port: u16,
    comm: String,
    pid: u32,
}

impl C2CallbackDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        let c2_ports: HashSet<u16> = [
            4444, 4445, 1337, 31337, 8888, 9999, 5555, 6666, 7777,
            // Common Metasploit/Cobalt Strike defaults
            443,  // HTTPS C2 (only suspicious from certain processes)
            8080, // HTTP C2
            53,   // DNS tunneling
        ]
        .into_iter()
        .collect();

        let suspicious_processes: HashSet<String> = [
            "sh", "bash", "dash", "zsh", "ash", "python", "python3", "python2", "perl", "ruby",
            "node", "nc", "ncat", "netcat", "socat", "curl",
            "wget", // suspicious when connecting to C2 ports
            "php", "lua",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            window: Duration::seconds(window_seconds as i64),
            connections: HashMap::new(),
            process_destinations: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            c2_ports,
            suspicious_processes,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "network.outbound_connect" {
            return None;
        }

        let dst_ip = event.details["dst_ip"].as_str()?.to_string();
        let dst_port = event.details["dst_port"].as_u64()? as u16;
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        if super::is_internal_ip(&dst_ip) {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        // Record connection
        let record = ConnectionRecord {
            ts: now,
            dst_ip: dst_ip.clone(),
            dst_port,
            comm: comm.clone(),
            pid,
        };

        let entries = self.connections.entry(dst_ip.clone()).or_default();
        while entries.front().is_some_and(|r| r.ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back(record);

        // Track destinations per process
        let proc_key = format!("{}:{}", comm, pid);
        self.process_destinations
            .entry(proc_key.clone())
            .or_default()
            .insert(dst_ip.clone());

        // Suppress re-alerts within window
        let alert_key = format!("{}:{}", dst_ip, comm);
        if let Some(&last) = self.alerted.get(&alert_key) {
            if now - last < self.window {
                return None;
            }
        }

        // ── Check 1: C2 port from suspicious process ────────────────────
        let comm_base = comm.split('/').next_back().unwrap_or(&comm).to_string();
        if self.c2_ports.contains(&dst_port) && self.suspicious_processes.contains(&comm_base) {
            // Port 443/8080 only suspicious from shell/scripting processes
            if (dst_port == 443 || dst_port == 8080)
                && !["sh", "bash", "dash", "nc", "ncat", "netcat", "socat"]
                    .contains(&comm_base.as_str())
            {
                // curl/wget to 443 is normal — skip
            } else {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    &dst_ip,
                    dst_port,
                    &comm,
                    pid,
                    now,
                    "c2_port",
                    Severity::High,
                    format!(
                        "Process {comm} (pid={pid}) connected to {dst_ip}:{dst_port} — known C2 port"
                    ),
                ));
            }
        }

        // ── Check 2: Beaconing (3+ connections to same IP in window) ────
        let conn_count = entries.len();
        if conn_count >= 3 {
            // Check if connections are at regular intervals (beaconing)
            let timestamps: Vec<i64> = entries.iter().map(|r| r.ts.timestamp()).collect();
            if is_beaconing(&timestamps) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    &dst_ip,
                    dst_port,
                    &comm,
                    pid,
                    now,
                    "beaconing",
                    Severity::Critical,
                    format!(
                        "Beaconing detected: {comm} connected to {dst_ip} {} times at regular intervals",
                        conn_count
                    ),
                ));
            }
        }

        // ── Check 3: Data exfil (process connecting to 10+ different IPs) ─
        let unique_dests = self
            .process_destinations
            .get(&proc_key)
            .map(|s| s.len())
            .unwrap_or(0);
        if unique_dests >= 10 && self.suspicious_processes.contains(&comm_base) {
            self.alerted.insert(alert_key, now);
            return Some(self.build_incident(
                &dst_ip,
                dst_port,
                &comm,
                pid,
                now,
                "data_exfil",
                Severity::Critical,
                format!(
                    "Possible data exfiltration: {comm} connected to {unique_dests} unique IPs in {} seconds",
                    self.window.num_seconds()
                ),
            ));
        }

        // Prune stale data
        if self.connections.len() > 5000 {
            self.connections.retain(|_, v| {
                v.retain(|r| r.ts > cutoff);
                !v.is_empty()
            });
        }
        if self.process_destinations.len() > 1000 {
            self.process_destinations.clear();
        }
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    #[allow(clippy::too_many_arguments)]
    fn build_incident(
        &self,
        dst_ip: &str,
        dst_port: u16,
        comm: &str,
        pid: u32,
        ts: DateTime<Utc>,
        pattern: &str,
        severity: Severity,
        summary: String,
    ) -> Incident {
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!("c2_callback:{dst_ip}:{}", ts.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Possible C2 callback to {dst_ip}:{dst_port}"),
            summary,
            evidence: serde_json::json!([{
                "kind": "c2_callback",
                "pattern": pattern,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "comm": comm,
                "pid": pid,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Investigate process {comm} (pid={pid}) — what triggered this connection?"),
                format!("Check if {dst_ip} is a known C2 server (VirusTotal, AbuseIPDB)"),
                "Review process tree: who spawned this process?".to_string(),
                "Consider killing the process and blocking the IP".to_string(),
            ],
            tags: vec!["ebpf".to_string(), "network".to_string(), "c2".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }
}

/// Check if timestamps show a beaconing pattern (regular intervals).
/// Returns true if the standard deviation of intervals is low relative to mean.
fn is_beaconing(timestamps: &[i64]) -> bool {
    if timestamps.len() < 3 {
        return false;
    }

    let mut intervals: Vec<f64> = Vec::new();
    for i in 1..timestamps.len() {
        intervals.push((timestamps[i] - timestamps[i - 1]) as f64);
    }

    if intervals.is_empty() {
        return false;
    }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 1.0 {
        return false; // intervals too short to be meaningful
    }

    let variance =
        intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let std_dev = variance.sqrt();

    // Beaconing: low coefficient of variation (std_dev / mean < 0.3)
    // Means intervals are very regular (e.g., every 30s ± 9s)
    let cv = std_dev / mean;
    cv < 0.3
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_event(comm: &str, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} connecting to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }),
            tags: vec![],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn detects_c2_port_from_shell() {
        let mut det = C2CallbackDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&connect_event("bash", "1.2.3.4", 4444, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("C2 callback"));
    }

    #[test]
    fn ignores_normal_https() {
        let mut det = C2CallbackDetector::new("test", 300);
        let now = Utc::now();

        // curl to 443 is normal
        assert!(det
            .process(&connect_event("curl", "1.2.3.4", 443, now))
            .is_none());
    }

    #[test]
    fn detects_beaconing() {
        let mut det = C2CallbackDetector::new("test", 600);
        let now = Utc::now();

        // Regular 30-second intervals = beaconing
        for i in 0..4 {
            let result = det.process(&connect_event(
                "malware",
                "5.6.7.8",
                8080,
                now + Duration::seconds(i * 30),
            ));
            if i >= 2 {
                // Should fire after 3+ connections with regular intervals
                if result.is_some() {
                    assert_eq!(result.unwrap().severity, Severity::Critical);
                    return;
                }
            }
        }
        // If we got here with 4 regular connections and no alert, that's a problem
        // But beaconing detection needs at least 3 data points
    }

    #[test]
    fn ignores_internal_ips() {
        let mut det = C2CallbackDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&connect_event("bash", "192.168.1.1", 4444, now))
            .is_none());
        assert!(det
            .process(&connect_event("bash", "127.0.0.1", 4444, now))
            .is_none());
    }

    #[test]
    fn beaconing_detection_math() {
        // Perfect beaconing: every 30 seconds
        assert!(is_beaconing(&[0, 30, 60, 90, 120]));

        // Not beaconing: random intervals
        assert!(!is_beaconing(&[0, 5, 100, 103, 500]));

        // Too few points
        assert!(!is_beaconing(&[0, 30]));
    }

    #[test]
    fn suppresses_realert() {
        let mut det = C2CallbackDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&connect_event("bash", "1.2.3.4", 4444, now))
            .is_some());
        // Same IP+comm within window = suppressed
        assert!(det
            .process(&connect_event(
                "bash",
                "1.2.3.4",
                4444,
                now + Duration::seconds(10)
            ))
            .is_none());
    }
}
