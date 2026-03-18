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
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct FalcoLogCollector {
    path: PathBuf,
    host: String,
    offset: u64,
}

impl FalcoLogCollector {
    pub fn new(path: impl Into<PathBuf>, host: impl Into<String>, offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
        }
    }

    /// Tail the Falco JSON log, polling every second.
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
            "falco_log collector starting"
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
                        debug!(kind = %event.kind, summary = %event.summary, "falco event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("falco_log poll error: {e:#}"),
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

        match parse_falco_event(trimmed, host) {
            Some(ev) => events.push(ev),
            None => debug!(
                "falco_log: skipped unparseable line: {}",
                &trimmed[..trimmed.len().min(80)]
            ),
        }
    }

    Ok((events, pos))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one line from Falco's JSON output log.
///
/// Falco JSON format (with `json_output: true`):
/// ```json
/// {
///   "output": "15:00:00.123456789: Warning A shell was spawned ...",
///   "priority": "Warning",
///   "rule": "Terminal shell in container",
///   "source": "syscall",
///   "tags": ["container", "shell", "mitre_execution"],
///   "time": "2026-03-15T15:00:00.123456789Z",
///   "output_fields": {
///     "container.id": "abc123def456",
///     "proc.name": "bash",
///     "user.name": "root",
///     "fd.sip": "1.2.3.4"
///   }
/// }
/// ```
pub fn parse_falco_event(line: &str, host: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let rule = v["rule"].as_str()?;
    let priority = v["priority"].as_str().unwrap_or("Informational");
    let output = v["output"].as_str().unwrap_or(rule);
    let source = v["source"].as_str().unwrap_or("syscall");

    let ts = v["time"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let severity = map_priority(priority);
    let kind = format!("falco.{}", rule_slug(rule));
    let summary = clean_falco_output(output).to_string();

    // Tags: static + dynamic from event
    let mut tags = vec!["falco".to_string(), source.to_string()];
    if let Some(arr) = v["tags"].as_array() {
        for tag in arr {
            if let Some(s) = tag.as_str() {
                tags.push(s.to_string());
            }
        }
    }
    tags.dedup();

    // Entity extraction from output_fields
    let fields = &v["output_fields"];
    let mut entities = Vec::new();

    for key in &["fd.sip", "fd.rip", "fd.cip"] {
        if let Some(ip) = fields[key].as_str() {
            if is_valid_ip(ip) {
                entities.push(EntityRef::ip(ip.to_string()));
            }
        }
    }

    if let Some(user) = fields["user.name"].as_str() {
        if !matches!(user, "<NA>" | "") {
            entities.push(EntityRef::user(user.to_string()));
        }
    }

    if let Some(cid) = fields["container.id"].as_str() {
        if cid != "host" && !cid.is_empty() && cid != "<NA>" {
            let short = &cid[..cid.len().min(12)];
            entities.push(EntityRef::container(short.to_string()));
        }
    }

    if let Some(pod) = fields["k8s.pod.name"].as_str() {
        if !pod.is_empty() && pod != "<NA>" {
            entities.push(EntityRef::service(pod.to_string()));
        }
    }

    // Deduplicate entities by (type, value)
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.r#type.clone(), e.value.clone())));

    let details = serde_json::json!({
        "rule": rule,
        "priority": priority,
        "source": source,
        "output_fields": fields,
        "falco_tags": v["tags"],
    });

    Some(Event {
        ts,
        host: host.to_string(),
        source: "falco".to_string(),
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

fn map_priority(priority: &str) -> Severity {
    match priority {
        "Emergency" | "Alert" | "Critical" => Severity::Critical,
        "Error" | "Warning" => Severity::High,
        "Notice" => Severity::Medium,
        "Informational" => Severity::Low,
        "Debug" => Severity::Debug,
        _ => Severity::Info,
    }
}

/// Convert a Falco rule name to a slug usable in `Event.kind`.
/// "Terminal shell in container" → "terminal_shell_in_container"
pub fn rule_slug(rule: &str) -> String {
    let mut slug = String::with_capacity(rule.len());
    let mut prev_was_sep = true;
    for ch in rule.chars() {
        if ch.is_alphanumeric() {
            slug.push(ch.to_lowercase().next().unwrap());
            prev_was_sep = false;
        } else if !prev_was_sep {
            slug.push('_');
            prev_was_sep = true;
        }
    }
    if slug.ends_with('_') {
        slug.pop();
    }
    slug
}

/// Strip the leading timestamp + priority prefix from Falco's `output` field.
///
/// Input:  "15:00:00.123456789: Warning A shell was spawned in a container (...)"
/// Output: "A shell was spawned in a container (...)"
pub fn clean_falco_output(output: &str) -> &str {
    // Each priority label that appears in the output field after the timestamp
    const PRIORITY_MARKERS: &[&str] = &[
        ": Emergency ",
        ": Alert ",
        ": Critical ",
        ": Error ",
        ": Warning ",
        ": Notice ",
        ": Informational ",
        ": Debug ",
    ];
    for marker in PRIORITY_MARKERS {
        if let Some(pos) = output.find(marker) {
            return &output[pos + marker.len()..];
        }
    }
    output
}

fn is_valid_ip(ip: &str) -> bool {
    !matches!(ip, "" | "0.0.0.0" | "::" | "<NA>")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn warning_shell_json() -> &'static str {
        r#"{"output":"15:00:00.000000000: Warning A shell was spawned in a container (user=root container=abc123def456 shell=bash)","priority":"Warning","rule":"Terminal shell in container","source":"syscall","tags":["container","shell","mitre_execution"],"time":"2026-03-15T15:00:00.000000000Z","output_fields":{"container.id":"abc123def456","proc.name":"bash","user.name":"root"}}"#
    }

    fn network_json() -> &'static str {
        r#"{"output":"15:01:00.000000000: Notice Outbound connection to suspicious IP","priority":"Notice","rule":"Outbound Connection to Suspicious IP","source":"syscall","tags":["network"],"time":"2026-03-15T15:01:00.000000000Z","output_fields":{"fd.sip":"203.0.113.10","fd.cip":"10.0.0.5","proc.name":"curl","user.name":"www-data"}}"#
    }

    fn critical_json() -> &'static str {
        r#"{"output":"15:02:00.000000000: Critical Write below root","priority":"Critical","rule":"Write below root","source":"syscall","tags":["filesystem"],"time":"2026-03-15T15:02:00.000000000Z","output_fields":{"user.name":"attacker","fd.name":"/etc/passwd"}}"#
    }

    #[test]
    fn parses_warning_event() {
        let ev = parse_falco_event(warning_shell_json(), "host1").unwrap();
        assert_eq!(ev.source, "falco");
        assert_eq!(ev.kind, "falco.terminal_shell_in_container");
        assert_eq!(ev.severity, Severity::High);
        assert!(ev.summary.starts_with("A shell was spawned"));
    }

    #[test]
    fn parses_notice_event() {
        let ev = parse_falco_event(network_json(), "host1").unwrap();
        assert_eq!(ev.kind, "falco.outbound_connection_to_suspicious_ip");
        assert_eq!(ev.severity, Severity::Medium);
    }

    #[test]
    fn parses_critical_event() {
        let ev = parse_falco_event(critical_json(), "host1").unwrap();
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.kind, "falco.write_below_root");
    }

    #[test]
    fn extracts_ip_entity() {
        let ev = parse_falco_event(network_json(), "host1").unwrap();
        let ip_entities: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
            .collect();
        assert!(
            ip_entities.iter().any(|e| e.value == "203.0.113.10"),
            "expected 203.0.113.10 in entities"
        );
    }

    #[test]
    fn extracts_user_entity() {
        let ev = parse_falco_event(warning_shell_json(), "host1").unwrap();
        let users: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::User))
            .collect();
        assert!(!users.is_empty(), "expected user entity");
        assert_eq!(users[0].value, "root");
    }

    #[test]
    fn extracts_container_entity() {
        let ev = parse_falco_event(warning_shell_json(), "host1").unwrap();
        let containers: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Container))
            .collect();
        assert!(!containers.is_empty());
        assert_eq!(containers[0].value, "abc123def456"); // ≤ 12 chars
    }

    #[test]
    fn includes_falco_tags() {
        let ev = parse_falco_event(warning_shell_json(), "host1").unwrap();
        assert!(ev.tags.contains(&"falco".to_string()));
        assert!(ev.tags.contains(&"container".to_string()));
        assert!(ev.tags.contains(&"mitre_execution".to_string()));
    }

    #[test]
    fn rule_slug_converts_correctly() {
        assert_eq!(
            rule_slug("Terminal shell in container"),
            "terminal_shell_in_container"
        );
        assert_eq!(
            rule_slug("Outbound Connection to Suspicious IP"),
            "outbound_connection_to_suspicious_ip"
        );
        assert_eq!(rule_slug("Write below root"), "write_below_root");
    }

    #[test]
    fn clean_output_strips_timestamp_prefix() {
        let raw = "15:00:00.123456789: Warning A shell was spawned in a container";
        assert_eq!(
            clean_falco_output(raw),
            "A shell was spawned in a container"
        );

        let already_clean = "No prefix here";
        assert_eq!(clean_falco_output(already_clean), already_clean);
    }

    #[test]
    fn na_ip_not_extracted() {
        let line = r#"{"output":"evt","priority":"Warning","rule":"Test rule","source":"syscall","tags":[],"time":"2026-03-15T10:00:00Z","output_fields":{"fd.sip":"<NA>","user.name":"<NA>"}}"#;
        let ev = parse_falco_event(line, "host1").unwrap();
        assert!(ev.entities.is_empty(), "should not extract <NA> entities");
    }

    #[test]
    fn unparseable_line_returns_none() {
        assert!(parse_falco_event("not json at all", "host1").is_none());
        assert!(parse_falco_event("{}", "host1").is_none()); // missing "rule"
    }

    #[test]
    fn map_priority_covers_all_labels() {
        assert_eq!(map_priority("Emergency"), Severity::Critical);
        assert_eq!(map_priority("Alert"), Severity::Critical);
        assert_eq!(map_priority("Critical"), Severity::Critical);
        assert_eq!(map_priority("Error"), Severity::High);
        assert_eq!(map_priority("Warning"), Severity::High);
        assert_eq!(map_priority("Notice"), Severity::Medium);
        assert_eq!(map_priority("Informational"), Severity::Low);
        assert_eq!(map_priority("Debug"), Severity::Debug);
        assert_eq!(map_priority("Unknown"), Severity::Info);
    }
}
