/// Docker anomaly detector.
///
/// Watches `container.oom` and `container.die` events. When a container has
/// rapid restarts or OOM kills within a sliding window, the detector fires
/// an incident.
use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct DockerAnomalyDetector {
    host: String,
    threshold: usize,
    window: Duration,
    /// Per-container sliding window of die/oom timestamps.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Last incident time per container — suppresses re-alerts within the same window.
    alerted: HashMap<String, DateTime<Utc>>,
    /// Track whether any event in the current burst was an OOM.
    saw_oom: HashMap<String, bool>,
}

impl DockerAnomalyDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            saw_oom: HashMap::new(),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when a container exceeds the die/oom threshold.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "container.oom" && event.kind != "container.die" {
            return None;
        }

        let container_id = event.details.get("container_id")?.as_str()?.to_string();
        let container_name = event
            .details
            .get("container_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let image = event
            .details
            .get("image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let now = event.ts;
        let cutoff = now - self.window;

        if event.kind == "container.oom" {
            self.saw_oom.insert(container_id.clone(), true);
        }

        let entries = self.windows.entry(container_id.clone()).or_default();
        while entries.front().is_some_and(|&t| t < cutoff) {
            entries.pop_front();
        }
        entries.push_back(now);

        let count = entries.len();
        if count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&container_id) {
            if now - last < self.window {
                return None;
            }
        }

        self.alerted.insert(container_id.clone(), now);

        let is_oom = self.saw_oom.get(&container_id).copied().unwrap_or(false);
        let severity = if is_oom {
            Severity::High
        } else {
            Severity::Medium
        };
        let anomaly_type = if is_oom {
            "OOM kills"
        } else {
            "rapid restarts"
        };

        // Reset OOM tracker for this container after firing
        self.saw_oom.remove(&container_id);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "docker_anomaly:{}:{}",
                container_id,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Docker anomaly: {anomaly_type} for {container_name}"),
            summary: format!(
                "{count} die/oom events for container {container_name} ({container_id}) in the last {} seconds — {anomaly_type}",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": &event.kind,
                "container_id": container_id,
                "container_name": container_name,
                "image": image,
                "count": count,
                "window_seconds": self.window.num_seconds(),
                "has_oom": is_oom,
            }]),
            recommended_checks: vec![
                format!("Check docker logs for container {container_name} ({container_id})"),
                "Review container resource limits (memory, CPU)".to_string(),
                "Consider pausing or restarting the container with adjusted limits".to_string(),
            ],
            tags: vec![
                "docker".to_string(),
                "container".to_string(),
                "anomaly".to_string(),
            ],
            entities: vec![EntityRef::container(&container_id)],
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

    fn docker_die_event(container_id: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "docker".into(),
            kind: "container.die".into(),
            severity: Sev::Medium,
            summary: format!("container {container_id} died"),
            details: serde_json::json!({
                "container_id": container_id,
                "container_name": "my-app",
                "image": "my-app:latest",
            }),
            tags: vec!["docker".to_string()],
            entities: vec![EntityRef::container(container_id)],
        }
    }

    fn docker_oom_event(container_id: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "docker".into(),
            kind: "container.oom".into(),
            severity: Sev::High,
            summary: format!("container {container_id} OOM killed"),
            details: serde_json::json!({
                "container_id": container_id,
                "container_name": "my-app",
                "image": "my-app:latest",
            }),
            tags: vec!["docker".to_string()],
            entities: vec![EntityRef::container(container_id)],
        }
    }

    #[test]
    fn no_incident_below_threshold() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..2 {
            assert!(det
                .process(&docker_die_event("abc123", base + Duration::seconds(i)))
                .is_none());
        }
    }

    #[test]
    fn incident_at_threshold_die_events() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        let mut last = None;
        for i in 0..3 {
            last = det.process(&docker_die_event("abc123", base + Duration::seconds(i)));
        }
        let inc = last.unwrap();
        assert_eq!(inc.severity, Severity::Medium); // no OOM → Medium
        assert!(inc.incident_id.starts_with("docker_anomaly:abc123:"));
        assert_eq!(inc.evidence[0]["count"], 3);
        assert!(!inc.evidence[0]["has_oom"].as_bool().unwrap());
    }

    #[test]
    fn high_severity_when_oom_present() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        det.process(&docker_die_event("abc123", base));
        det.process(&docker_oom_event("abc123", base + Duration::seconds(1)));
        let inc = det
            .process(&docker_die_event("abc123", base + Duration::seconds(2)))
            .unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.evidence[0]["has_oom"].as_bool().unwrap());
    }

    #[test]
    fn dedup_suppresses_realert_within_window() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&docker_die_event("abc123", base + Duration::seconds(i)));
        }
        // Fourth event in same window — suppressed
        assert!(det
            .process(&docker_die_event("abc123", base + Duration::seconds(3)))
            .is_none());
    }

    #[test]
    fn ignores_non_docker_anomaly_events() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "docker".into(),
            kind: "container.start".into(),
            severity: Sev::Info,
            summary: "container started".into(),
            details: serde_json::json!({ "container_id": "abc123" }),
            tags: vec![],
            entities: vec![],
        };
        for _ in 0..10 {
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn different_containers_are_independent() {
        let mut det = DockerAnomalyDetector::new("host", 3, 300);
        let base = Utc::now();
        for i in 0..3 {
            det.process(&docker_die_event("aaa111", base + Duration::seconds(i)));
        }
        // Different container — only 2 events, below threshold
        for i in 0..2 {
            assert!(det
                .process(&docker_die_event("bbb222", base + Duration::seconds(i)))
                .is_none());
        }
    }

    #[test]
    fn old_entries_expire_from_window() {
        let mut det = DockerAnomalyDetector::new("host", 3, 10); // 10s window
        let base = Utc::now();
        det.process(&docker_die_event("abc123", base - Duration::seconds(20)));
        det.process(&docker_die_event("abc123", base - Duration::seconds(15)));
        // Both old — only 1 new event → below threshold
        assert!(det.process(&docker_die_event("abc123", base)).is_none());
        assert!(det
            .process(&docker_die_event("abc123", base + Duration::seconds(1)))
            .is_none());
        // Third new event hits threshold
        let inc = det.process(&docker_die_event("abc123", base + Duration::seconds(2)));
        assert!(inc.is_some());
    }
}
