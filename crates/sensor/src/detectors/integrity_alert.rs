/// File integrity alert detector.
///
/// Watches `file.changed` events emitted by the integrity collector. Every
/// change to a monitored path is inherently suspicious (these are critical
/// system files), so the detector fires an incident for each change — subject
/// to a per-path cooldown to avoid duplicate alerts.
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Paths that warrant Critical severity when changed.
const CRITICAL_PATHS: &[&str] = &["/etc/shadow", "/etc/passwd", "/etc/sudoers"];

pub struct IntegrityAlertDetector {
    host: String,
    /// Last alert time per path — suppresses re-alerts within the cooldown.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl IntegrityAlertDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` for every `file.changed` event, subject to
    /// per-path cooldown.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "file.changed" {
            return None;
        }

        let path = event.details.get("path")?.as_str()?.to_string();
        let now = event.ts;

        // Cooldown check
        if let Some(&last) = self.alerted.get(&path) {
            if now - last < self.cooldown {
                return None;
            }
        }

        self.alerted.insert(path.clone(), now);

        let old_hash = event
            .details
            .get("old_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let new_hash = event
            .details
            .get("new_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let severity = if CRITICAL_PATHS.contains(&path.as_str()) {
            Severity::Critical
        } else {
            Severity::High
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("integrity_alert:{}:{}", path, now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("File integrity change: {path}"),
            summary: format!(
                "Monitored file {path} was modified — hash changed from {old_hash} to {new_hash}"
            ),
            evidence: serde_json::json!([{
                "kind": "file.changed",
                "path": path,
                "old_hash": old_hash,
                "new_hash": new_hash,
            }]),
            recommended_checks: vec![
                format!("Investigate who changed {path} — review audit log and recent logins"),
                "Check if the change was part of a legitimate update or package install"
                    .to_string(),
                "Compare file contents with a known-good backup".to_string(),
            ],
            tags: vec![
                "integrity".to_string(),
                "file_change".to_string(),
                "audit".to_string(),
            ],
            entities: vec![EntityRef::path(&path)],
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

    fn file_changed_event(path: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "integrity".into(),
            kind: "file.changed".into(),
            severity: Sev::High,
            summary: format!("file changed: {path}"),
            details: serde_json::json!({
                "path": path,
                "old_hash": "aaa111",
                "new_hash": "bbb222",
            }),
            tags: vec!["integrity".to_string()],
            entities: vec![EntityRef::path(path)],
        }
    }

    #[test]
    fn fires_on_file_changed() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&file_changed_event("/etc/hosts", base))
            .unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("integrity_alert:/etc/hosts:"));
        assert_eq!(inc.evidence[0]["path"], "/etc/hosts");
    }

    #[test]
    fn critical_for_sensitive_paths() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();

        let inc = det
            .process(&file_changed_event("/etc/shadow", base))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);

        let inc = det
            .process(&file_changed_event("/etc/passwd", base))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);

        let inc = det
            .process(&file_changed_event("/etc/sudoers", base))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();
        // First change fires
        assert!(det
            .process(&file_changed_event("/etc/hosts", base))
            .is_some());
        // Second change within cooldown — suppressed
        assert!(det
            .process(&file_changed_event(
                "/etc/hosts",
                base + Duration::seconds(60)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_changed_event("/etc/hosts", base))
            .is_some());
        // After cooldown — fires again
        assert!(det
            .process(&file_changed_event(
                "/etc/hosts",
                base + Duration::seconds(3601)
            ))
            .is_some());
    }

    #[test]
    fn different_paths_are_independent() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_changed_event("/etc/hosts", base))
            .is_some());
        // Different path — fires even though first path is in cooldown
        assert!(det
            .process(&file_changed_event("/etc/resolv.conf", base))
            .is_some());
    }

    #[test]
    fn ignores_non_file_changed_events() {
        let mut det = IntegrityAlertDetector::new("host", 3600);
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "integrity".into(),
            kind: "file.scanned".into(),
            severity: Sev::Info,
            summary: "file scanned".into(),
            details: serde_json::json!({ "path": "/etc/hosts" }),
            tags: vec![],
            entities: vec![],
        };
        for _ in 0..10 {
            assert!(det.process(&ev).is_none());
        }
    }
}
