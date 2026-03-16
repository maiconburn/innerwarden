use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct WazuhAlertsCollector {
    path: PathBuf,
    host: String,
    offset: u64,
}

impl WazuhAlertsCollector {
    pub fn new(path: impl Into<PathBuf>, host: impl Into<String>, offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
        }
    }

    /// Tail the Wazuh alerts JSON log, polling every second.
    /// Uses spawn_blocking for file I/O so the tokio executor stays free.
    /// `shared_offset` is updated after each poll for persistence on shutdown.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<Event>,
        shared_offset: Arc<AtomicU64>,
    ) -> Result<()> {
        info!(
            path = %self.path.display(),
            offset = self.offset,
            "wazuh_alerts collector starting"
        );

        loop {
            let path = self.path.clone();
            let host = self.host.clone();
            let offset = self.offset;
            let result = tokio::task::spawn_blocking(move || poll(&path, &host, offset)).await?;

            match result {
                Ok((events, new_offset)) => {
                    self.offset = new_offset;
                    shared_offset.store(new_offset, Ordering::Relaxed);
                    for event in events {
                        debug!(kind = %event.kind, summary = %event.summary, "wazuh event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("wazuh_alerts poll error: {e:#}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            if tx.is_closed() {
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// File poller
// ---------------------------------------------------------------------------

fn poll(path: &Path, host: &str, offset: u64) -> Result<(Vec<Event>, u64)> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((vec![], offset));
        }
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(offset))?;

    let mut events = Vec::new();
    let mut pos = offset;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        pos += n as u64;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match parse_wazuh_alert(trimmed, host) {
            Some(ev) => events.push(ev),
            None => debug!(
                "wazuh_alerts: skipped unparseable line: {}",
                &trimmed[..trimmed.len().min(80)]
            ),
        }
    }

    Ok((events, pos))
}

// ---------------------------------------------------------------------------
// JSON structs for deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WazuhAlert {
    timestamp: String,
    rule: WazuhRule,
    agent: Option<WazuhAgent>,
    data: Option<WazuhData>,
}

#[derive(Deserialize)]
struct WazuhRule {
    level: u64,
    description: String,
    #[serde(default)]
    groups: Vec<String>,
    id: Option<String>,
}

#[derive(Deserialize)]
struct WazuhAgent {
    name: Option<String>,
    #[allow(dead_code)]
    ip: Option<String>,
}

#[derive(Deserialize)]
struct WazuhData {
    srcip: Option<String>,
    dstuser: Option<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one line from Wazuh's JSON alerts log.
///
/// Wazuh JSON format (with `alerts_log_format: json` in ossec.conf):
/// ```json
/// {
///   "timestamp": "2026-03-15T15:00:00.000+0000",
///   "rule": {
///     "level": 10,
///     "description": "Multiple authentication failures.",
///     "id": "5763",
///     "groups": ["authentication_failures", "sshd", "mitre_credential_access"]
///   },
///   "agent": { "id": "001", "name": "web-server-01", "ip": "10.0.0.5" },
///   "data": { "srcip": "203.0.113.10", "dstuser": "root" }
/// }
/// ```
pub fn parse_wazuh_alert(line: &str, host: &str) -> Option<Event> {
    let alert: WazuhAlert = serde_json::from_str(line).ok()?;

    let ts = chrono::DateTime::parse_from_rfc3339(&alert.timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let severity = map_level(alert.rule.level);

    // kind: first group prefixed with "wazuh.", or fallback to rule id
    let kind_slug = alert.rule.groups.first().cloned().unwrap_or_else(|| {
        alert
            .rule
            .id
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    });
    let kind = format!("wazuh.{kind_slug}");

    let summary = alert.rule.description.clone();

    // Tags: static ["wazuh", "hids"] + all rule.groups elements
    let mut tags = vec!["wazuh".to_string(), "hids".to_string()];
    for group in &alert.rule.groups {
        tags.push(group.clone());
    }
    tags.dedup();

    // Entity extraction
    let mut entities = Vec::new();

    // data.srcip — skip private/loopback
    if let Some(ref data) = alert.data {
        if let Some(ref srcip) = data.srcip {
            if is_public_ip(srcip) {
                entities.push(EntityRef::ip(srcip.clone()));
            }
        }

        // data.dstuser
        if let Some(ref dstuser) = data.dstuser {
            if !dstuser.is_empty() {
                entities.push(EntityRef::user(dstuser.clone()));
            }
        }
    }

    // agent.name → service entity (identifies the monitored host)
    if let Some(ref agent) = alert.agent {
        if let Some(ref name) = agent.name {
            if !name.is_empty() {
                entities.push(EntityRef::service(name.clone()));
            }
        }
    }

    // Deduplicate entities by (type, value)
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.r#type.clone(), e.value.clone())));

    let details = serde_json::json!({
        "rule_level": alert.rule.level,
        "rule_description": alert.rule.description,
        "rule_id": alert.rule.id,
        "rule_groups": alert.rule.groups,
        "agent": alert.agent.as_ref().map(|a| serde_json::json!({
            "name": a.name,
            "ip": a.ip,
        })),
        "data": alert.data.as_ref().map(|d| serde_json::json!({
            "srcip": d.srcip,
            "dstuser": d.dstuser,
        })),
    });

    Some(Event {
        ts,
        host: host.to_string(),
        source: "wazuh".to_string(),
        kind,
        severity,
        summary,
        details,
        tags,
        entities,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map Wazuh rule level (0–15) to InnerWarden Severity.
///
/// Levels:
/// - 0–2:   Debug
/// - 3–6:   Low
/// - 7–9:   Medium
/// - 10–11: High
/// - 12–15: Critical
pub fn map_level(level: u64) -> Severity {
    match level {
        0..=2 => Severity::Debug,
        3..=6 => Severity::Low,
        7..=9 => Severity::Medium,
        10..=11 => Severity::High,
        12..=15 => Severity::Critical,
        _ => Severity::Info,
    }
}

/// Return true if the IP address is a public, routable address.
/// Filters out private RFC1918, loopback, link-local, and other non-routable ranges.
fn is_public_ip(ip: &str) -> bool {
    if matches!(ip, "" | "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "<NA>") {
        return false;
    }
    if ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("fe80:")
        || ip.starts_with("169.254.")
    {
        return false;
    }
    // 172.16.0.0/12
    if let Some(second) = ip.strip_prefix("172.") {
        if let Some(octet) = second.split('.').next().and_then(|o| o.parse::<u8>().ok()) {
            if (16..=31).contains(&octet) {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityType;
    use innerwarden_core::event::Severity;

    fn alert_level(level: u64) -> String {
        format!(
            r#"{{"timestamp":"2026-03-15T15:00:00.000+0000","rule":{{"level":{level},"description":"Test alert level {level}.","id":"1000","groups":["authentication_failures","sshd"]}},"agent":{{"id":"001","name":"web-server-01","ip":"10.0.0.5"}},"data":{{"srcip":"203.0.113.10","dstuser":"root"}}}}"#
        )
    }

    fn minimal_alert() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:00:00.000+0000","rule":{"level":5,"description":"Minimal alert.","id":"999","groups":[]}}"#
    }

    fn private_srcip_alert() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:00:00.000+0000","rule":{"level":10,"description":"Private IP alert.","id":"5000","groups":["authentication_failures"]},"agent":{"id":"001","name":"web-01","ip":"10.0.0.5"},"data":{"srcip":"192.168.1.50","dstuser":"admin"}}"#
    }

    #[test]
    fn parse_valid_alert_level_10_high_severity() {
        let line = alert_level(10);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        assert_eq!(ev.source, "wazuh");
        assert_eq!(ev.severity, Severity::High);
        assert_eq!(ev.kind, "wazuh.authentication_failures");
    }

    #[test]
    fn parse_valid_alert_level_12_critical_severity() {
        let line = alert_level(12);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        assert_eq!(ev.severity, Severity::Critical);
    }

    #[test]
    fn parse_valid_alert_level_7_medium_severity() {
        let line = alert_level(7);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        assert_eq!(ev.severity, Severity::Medium);
    }

    #[test]
    fn parse_level_low_severity() {
        let line = alert_level(5);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        assert_eq!(ev.severity, Severity::Low);
    }

    #[test]
    fn parse_level_debug_severity() {
        let line = alert_level(1);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        assert_eq!(ev.severity, Severity::Debug);
    }

    #[test]
    fn kind_from_groups_first_element() {
        let line = r#"{"timestamp":"2026-03-15T15:00:00.000+0000","rule":{"level":10,"description":"Auth failure.","id":"5763","groups":["authentication_failures","sshd","mitre_credential_access"]},"data":{"srcip":"203.0.113.10","dstuser":"root"}}"#;
        let ev = parse_wazuh_alert(line, "host1").unwrap();
        assert_eq!(ev.kind, "wazuh.authentication_failures");
    }

    #[test]
    fn tags_include_all_groups() {
        let line = r#"{"timestamp":"2026-03-15T15:00:00.000+0000","rule":{"level":8,"description":"Alert.","id":"100","groups":["authentication_failures","sshd","mitre_credential_access"]}}"#;
        let ev = parse_wazuh_alert(line, "host1").unwrap();
        assert!(ev.tags.contains(&"wazuh".to_string()));
        assert!(ev.tags.contains(&"hids".to_string()));
        assert!(ev.tags.contains(&"authentication_failures".to_string()));
        assert!(ev.tags.contains(&"sshd".to_string()));
        assert!(ev.tags.contains(&"mitre_credential_access".to_string()));
    }

    #[test]
    fn srcip_extracted_as_entity() {
        let line = alert_level(10);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Ip))
            .collect();
        assert!(
            ips.iter().any(|e| e.value == "203.0.113.10"),
            "expected 203.0.113.10 in entities"
        );
    }

    #[test]
    fn dstuser_extracted_as_entity() {
        let line = alert_level(10);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        let users: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::User))
            .collect();
        assert!(!users.is_empty(), "expected user entity");
        assert_eq!(users[0].value, "root");
    }

    #[test]
    fn agent_name_extracted_as_entity() {
        let line = alert_level(10);
        let ev = parse_wazuh_alert(&line, "host1").unwrap();
        let services: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Service))
            .collect();
        assert!(
            !services.is_empty(),
            "expected service entity from agent.name"
        );
        assert_eq!(services[0].value, "web-server-01");
    }

    #[test]
    fn missing_optional_fields_ok() {
        // No data, no agent fields — should parse successfully
        let ev = parse_wazuh_alert(minimal_alert(), "host1").unwrap();
        assert_eq!(ev.source, "wazuh");
        assert_eq!(ev.severity, Severity::Low);
        // No entities from missing data/agent
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Ip))
            .collect();
        assert!(ips.is_empty());
    }

    #[test]
    fn private_srcip_not_extracted() {
        // 192.168.x.x should be filtered out — it's a private address
        let ev = parse_wazuh_alert(private_srcip_alert(), "host1").unwrap();
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Ip))
            .collect();
        assert!(
            !ips.iter().any(|e| e.value == "192.168.1.50"),
            "private srcip should not be extracted as entity"
        );
    }
}
