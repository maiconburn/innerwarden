/// Osquery anomaly detector.
///
/// Watches events whose `source` is `"osquery"`. When an osquery event has
/// High or Critical severity (sudoers changes, SUID binaries, authorized_keys
/// changes, crontab modifications), the detector promotes it to an incident —
/// subject to a per-query-kind cooldown to avoid duplicate alerts.
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Query kinds that map to specific tags for incident classification.
fn query_tag(kind: &str) -> &'static str {
    match kind {
        k if k.contains("sudoers") => "sudoers_change",
        k if k.contains("suid") => "suid_binary",
        k if k.contains("authorized_keys") => "authorized_keys_change",
        k if k.contains("crontab") || k.contains("cron") => "crontab_change",
        k if k.contains("listening_ports") || k.contains("port") => "listening_ports",
        _ => "host_anomaly",
    }
}

pub struct OsqueryAnomalyDetector {
    host: String,
    /// Last alert time per query kind — suppresses re-alerts within the cooldown.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl OsqueryAnomalyDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when an osquery event with High or Critical
    /// severity is detected, subject to per-kind cooldown.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.source != "osquery" {
            return None;
        }

        // Only promote High or Critical events to incidents
        if !matches!(event.severity, Severity::High | Severity::Critical) {
            return None;
        }

        let kind = &event.kind;
        let now = event.ts;

        // Cooldown check — per query kind
        if let Some(&last) = self.alerted.get(kind.as_str()) {
            if now - last < self.cooldown {
                return None;
            }
        }

        self.alerted.insert(kind.clone(), now);

        let query_name = event
            .details
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(kind.as_str())
            .to_string();

        let tag = query_tag(kind);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "osquery_anomaly:{}:{}",
                kind,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: event.severity.clone(),
            title: format!("Osquery anomaly: {query_name}"),
            summary: format!(
                "Osquery detected a host state change — query: {query_name}, kind: {kind}"
            ),
            evidence: serde_json::json!([{
                "kind": kind,
                "query_name": query_name,
                "details": &event.details,
            }]),
            recommended_checks: vec![
                format!("Investigate osquery result for {query_name} — review columns for unexpected values"),
                "Correlate with recent user activity and login events".to_string(),
                "Check if the change was part of a legitimate administrative action".to_string(),
            ],
            tags: vec![
                "osquery".to_string(),
                "host_state".to_string(),
                tag.to_string(),
            ],
            entities: event.entities.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity as Sev;

    fn osquery_event(kind: &str, severity: Sev, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "host".into(),
            source: "osquery".into(),
            kind: kind.into(),
            severity,
            summary: format!("osquery: {kind}"),
            details: serde_json::json!({
                "name": kind.strip_prefix("osquery.").unwrap_or(kind),
                "columns": { "path": "/etc/sudoers", "action": "modified" },
            }),
            tags: vec!["osquery".to_string()],
            entities: vec![EntityRef::path("/etc/sudoers")],
        }
    }

    #[test]
    fn fires_on_high_severity_osquery_event() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&osquery_event("osquery.sudoers", Sev::High, base))
            .unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc
            .incident_id
            .starts_with("osquery_anomaly:osquery.sudoers:"));
        assert!(inc.tags.contains(&"sudoers_change".to_string()));
        assert!(inc.tags.contains(&"osquery".to_string()));
        assert!(inc.tags.contains(&"host_state".to_string()));
    }

    #[test]
    fn fires_on_critical_severity_osquery_event() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&osquery_event(
                "osquery.authorized_keys",
                Sev::Critical,
                base,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"authorized_keys_change".to_string()));
    }

    #[test]
    fn ignores_medium_severity_events() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&osquery_event("osquery.listening_ports", Sev::Medium, base))
            .is_none());
    }

    #[test]
    fn ignores_non_osquery_events() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        let ev = Event {
            ts: base,
            host: "host".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Sev::High,
            summary: "failed login".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        // First event fires
        assert!(det
            .process(&osquery_event("osquery.sudoers", Sev::High, base))
            .is_some());
        // Same kind within cooldown — suppressed
        assert!(det
            .process(&osquery_event(
                "osquery.sudoers",
                Sev::High,
                base + Duration::seconds(60)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&osquery_event("osquery.sudoers", Sev::High, base))
            .is_some());
        // After cooldown — fires again
        assert!(det
            .process(&osquery_event(
                "osquery.sudoers",
                Sev::High,
                base + Duration::seconds(3601)
            ))
            .is_some());
    }

    #[test]
    fn different_kinds_are_independent() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&osquery_event("osquery.sudoers", Sev::High, base))
            .is_some());
        // Different kind — fires even though first kind is in cooldown
        assert!(det
            .process(&osquery_event("osquery.suid_bin", Sev::High, base))
            .is_some());
    }

    #[test]
    fn query_specific_tags() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();

        let inc = det
            .process(&osquery_event("osquery.suid_bin", Sev::High, base))
            .unwrap();
        assert!(inc.tags.contains(&"suid_binary".to_string()));

        let inc = det
            .process(&osquery_event("osquery.crontab", Sev::High, base))
            .unwrap();
        assert!(inc.tags.contains(&"crontab_change".to_string()));
    }

    #[test]
    fn entities_propagated_from_event() {
        let mut det = OsqueryAnomalyDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&osquery_event("osquery.sudoers", Sev::High, base))
            .unwrap();
        assert_eq!(inc.entities, vec![EntityRef::path("/etc/sudoers")]);
    }
}
