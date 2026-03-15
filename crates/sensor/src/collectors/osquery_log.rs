use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use chrono::{TimeZone, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct OsqueryLogCollector {
    path: PathBuf,
    host: String,
    offset: u64,
}

impl OsqueryLogCollector {
    pub fn new(path: impl Into<PathBuf>, host: impl Into<String>, offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
        }
    }

    pub async fn run(
        mut self,
        tx: mpsc::Sender<Event>,
        shared_offset: Arc<AtomicU64>,
    ) -> Result<()> {
        info!(
            path = %self.path.display(),
            offset = self.offset,
            "osquery_log collector starting"
        );

        loop {
            let path = self.path.clone();
            let host = self.host.clone();
            let offset = self.offset;
            let result =
                tokio::task::spawn_blocking(move || poll(&path, &host, offset)).await?;

            match result {
                Ok((events, new_offset)) => {
                    self.offset = new_offset;
                    shared_offset.store(new_offset, Ordering::Relaxed);
                    for event in events {
                        debug!(kind = %event.kind, summary = %event.summary, "osquery event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("osquery_log poll error: {e:#}"),
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

        match parse_osquery_event(trimmed, host) {
            Some(ev) => events.push(ev),
            None => debug!(
                "osquery_log: skipped line: {}",
                &trimmed[..trimmed.len().min(80)]
            ),
        }
    }

    Ok((events, pos))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one line from osquery's differential results log.
///
/// osquery JSON format (filesystem logger, log_result_events: true):
/// ```json
/// {
///   "name":            "pack/incident-response/listening_ports",
///   "action":          "added",
///   "hostIdentifier":  "web-server-01",
///   "calendarTime":    "Sun Mar 15 15:00:00 2026 UTC",
///   "unixTime":        1741788000,
///   "epoch":           0,
///   "counter":         1,
///   "decorations":     { "username": "root", "host_uuid": "abc-123" },
///   "columns": {
///     "pid":      "1234",
///     "port":     "4444",
///     "protocol": "6",
///     "address":  "0.0.0.0",
///     "path":     "/usr/bin/nc"
///   }
/// }
/// ```
pub fn parse_osquery_event(line: &str, host: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let name = v["name"].as_str()?;
    let action = v["action"].as_str().unwrap_or("snapshot");
    let unix_ts = v["unixTime"].as_i64().unwrap_or(0);

    // Skip "removed" actions — we only care about new rows appearing
    if action == "removed" {
        return None;
    }

    let ts = Utc
        .timestamp_opt(unix_ts, 0)
        .single()
        .unwrap_or_else(Utc::now);

    let query_slug = query_name_slug(name);
    let kind = format!("osquery.{query_slug}");
    let severity = severity_for_query(name);

    let columns = &v["columns"];
    let decorations = &v["decorations"];

    let summary = build_summary(name, action, columns);

    // Entity extraction
    let mut entities = Vec::new();

    // Network columns — addresses
    for key in &["address", "remote_address", "local_address"] {
        if let Some(addr) = columns[key].as_str() {
            if is_valid_ip(addr) {
                entities.push(EntityRef::ip(addr.to_string()));
            }
        }
    }

    // Process path
    if let Some(path) = columns["path"].as_str() {
        if !path.is_empty() {
            entities.push(EntityRef::path(path.to_string()));
        }
    }

    // Username from decorations (more reliable than columns)
    for key in &["username", "user"] {
        if let Some(user) = decorations[key].as_str() {
            if !matches!(user, "" | "root" | "<NA>") {
                entities.push(EntityRef::user(user.to_string()));
                break;
            }
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.r#type.clone(), e.value.clone())));

    let details = serde_json::json!({
        "query_name": name,
        "action": action,
        "columns": columns,
        "decorations": decorations,
        "host_identifier": v["hostIdentifier"],
    });

    let tags = vec![
        "osquery".to_string(),
        "host-observability".to_string(),
        query_slug.clone(),
    ];

    Some(Event {
        ts,
        host: host.to_string(),
        source: "osquery".to_string(),
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

/// Extract the last path component of an osquery query name and slugify it.
///
/// "pack/incident-response/listening_ports" → "listening_ports"
/// "custom/my-query"                         → "my_query"
/// "top_level_query"                         → "top_level_query"
pub fn query_name_slug(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

/// Assign severity based on known security-relevant query name substrings.
/// Checked in order — first match wins. Defaults to Info.
pub fn severity_for_query(name: &str) -> Severity {
    // High-signal security queries
    const HIGH: &[&str] = &["sudoers", "suid_bin", "authorized_keys", "crontab_modified"];
    const MEDIUM: &[&str] = &[
        "listening_ports",
        "startup_items",
        "crontab",
        "shell_history",
        "logged_in_users",
        "user_ssh_keys",
        "process_open_sockets",
        "socket_events",
        "open_sockets",
    ];
    const LOW: &[&str] = &[
        "process_open_files",
        "processes",
        "users",
        "groups",
        "mounts",
        "dns_resolvers",
    ];

    let lower = name.to_lowercase();

    for pattern in HIGH {
        if lower.contains(pattern) {
            return Severity::High;
        }
    }
    for pattern in MEDIUM {
        if lower.contains(pattern) {
            return Severity::Medium;
        }
    }
    for pattern in LOW {
        if lower.contains(pattern) {
            return Severity::Low;
        }
    }
    Severity::Info
}

fn build_summary(name: &str, action: &str, columns: &serde_json::Value) -> String {
    let slug = query_name_slug(name);

    // Try to build a contextual summary from common column patterns
    match slug.as_str() {
        "listening_ports" => {
            let port = columns["port"].as_str().unwrap_or("?");
            let addr = columns["address"].as_str().unwrap_or("?");
            let path = columns["path"].as_str().unwrap_or("?");
            format!("New listening port: {addr}:{port} ({path})")
        }
        "process_open_sockets" | "open_sockets" | "socket_events" => {
            let pid = columns["pid"].as_str().unwrap_or("?");
            let remote = columns["remote_address"].as_str().unwrap_or("?");
            let rport = columns["remote_port"].as_str().unwrap_or("?");
            format!("Process {pid} opened socket to {remote}:{rport}")
        }
        "startup_items" => {
            let item_name = columns["name"].as_str().unwrap_or("?");
            let path = columns["path"].as_str().unwrap_or("?");
            format!("Startup item {action}: {item_name} ({path})")
        }
        "crontab" | "crontab_modified" => {
            let command = columns["command"].as_str().unwrap_or("?");
            format!("Crontab entry {action}: {command}")
        }
        "sudoers" => {
            let source = columns["source"].as_str().unwrap_or("?");
            let rule = columns["rule_details"].as_str().unwrap_or("?");
            format!("Sudoers change {action} in {source}: {rule}")
        }
        "authorized_keys" => {
            let user = columns["uid"].as_str().unwrap_or("?");
            let key = columns["key"].as_str().unwrap_or("?");
            format!("Authorized key {action} for uid {user}: {key}")
        }
        "logged_in_users" => {
            let user = columns["user"].as_str().unwrap_or("?");
            let host_col = columns["host"].as_str().unwrap_or("?");
            format!("User {user} login {action} from {host_col}")
        }
        _ => format!("osquery {}: {action}", query_name_slug(name)),
    }
}

fn is_valid_ip(addr: &str) -> bool {
    if matches!(addr, "" | "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "<NA>") {
        return false;
    }
    // Skip private/RFC1918 ranges — these are usually the monitored host's own
    // addresses and add noise to entity extraction
    if addr.starts_with("10.")
        || addr.starts_with("192.168.")
        || addr.starts_with("fe80:")  // link-local IPv6
    {
        return false;
    }
    // 172.16.0.0/12
    if let Some(second) = addr.strip_prefix("172.") {
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
    use innerwarden_core::event::Severity;

    fn listening_port_line() -> &'static str {
        r#"{"name":"pack/incident-response/listening_ports","action":"added","hostIdentifier":"web-01","calendarTime":"Sun Mar 15 15:00:00 2026 UTC","unixTime":1741788000,"epoch":0,"counter":1,"decorations":{"username":"root","host_uuid":"abc-123"},"columns":{"pid":"1234","port":"4444","protocol":"6","address":"0.0.0.0","family":"2","socket":"5678","path":"/usr/bin/nc"}}"#
    }

    fn crontab_line() -> &'static str {
        r#"{"name":"pack/incident-response/crontab","action":"added","hostIdentifier":"web-01","unixTime":1741788060,"decorations":{"username":"deploy"},"columns":{"command":"/tmp/backdoor.sh","minute":"*/5","hour":"*","day_of_month":"*","month":"*","day_of_week":"*","path":"/etc/cron.d/deploy"}}"#
    }

    fn sudoers_line() -> &'static str {
        r#"{"name":"pack/incident-response/sudoers","action":"added","hostIdentifier":"web-01","unixTime":1741788120,"decorations":{},"columns":{"source":"/etc/sudoers.d/evil","rule_details":"ALL=(ALL) NOPASSWD: ALL","header_tag":""}}"#
    }

    fn removed_action_line() -> &'static str {
        r#"{"name":"pack/incident-response/processes","action":"removed","hostIdentifier":"web-01","unixTime":1741788000,"decorations":{},"columns":{"pid":"999","name":"bash"}}"#
    }

    fn socket_line() -> &'static str {
        r#"{"name":"custom/process_open_sockets","action":"added","hostIdentifier":"web-01","unixTime":1741788000,"decorations":{},"columns":{"pid":"2222","remote_address":"203.0.113.50","remote_port":"443","local_address":"10.0.0.5","local_port":"55000"}}"#
    }

    #[test]
    fn parses_listening_port_event() {
        let ev = parse_osquery_event(listening_port_line(), "host1").unwrap();
        assert_eq!(ev.source, "osquery");
        assert_eq!(ev.kind, "osquery.listening_ports");
        assert_eq!(ev.severity, Severity::Medium);
        assert!(ev.summary.contains("4444"));
        assert!(ev.tags.contains(&"osquery".to_string()));
        assert!(ev.tags.contains(&"host-observability".to_string()));
    }

    #[test]
    fn parses_crontab_event() {
        let ev = parse_osquery_event(crontab_line(), "host1").unwrap();
        assert_eq!(ev.kind, "osquery.crontab");
        assert_eq!(ev.severity, Severity::Medium);
        assert!(ev.summary.contains("backdoor"));
    }

    #[test]
    fn parses_sudoers_event() {
        let ev = parse_osquery_event(sudoers_line(), "host1").unwrap();
        assert_eq!(ev.kind, "osquery.sudoers");
        assert_eq!(ev.severity, Severity::High);
        assert!(ev.summary.contains("NOPASSWD"));
    }

    #[test]
    fn removed_action_returns_none() {
        // "removed" rows are skipped — we only care about new state
        assert!(parse_osquery_event(removed_action_line(), "host1").is_none());
    }

    #[test]
    fn extracts_ip_from_socket_event() {
        let ev = parse_osquery_event(socket_line(), "host1").unwrap();
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
            .collect();
        assert!(
            ips.iter().any(|e| e.value == "203.0.113.50"),
            "remote_address should be extracted"
        );
        // 127.0.0.1/10.x are filtered out as local
        assert!(!ips.iter().any(|e| e.value == "10.0.0.5"));
    }

    #[test]
    fn extracts_path_entity() {
        let ev = parse_osquery_event(listening_port_line(), "host1").unwrap();
        let paths: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Path))
            .collect();
        assert!(paths.iter().any(|e| e.value == "/usr/bin/nc"));
    }

    #[test]
    fn query_name_slug_extracts_last_component() {
        assert_eq!(
            query_name_slug("pack/incident-response/listening_ports"),
            "listening_ports"
        );
        assert_eq!(query_name_slug("custom/my-query"), "my_query");
        assert_eq!(query_name_slug("top_level"), "top_level");
    }

    #[test]
    fn severity_for_query_matches_patterns() {
        assert_eq!(
            severity_for_query("pack/incident-response/sudoers"),
            Severity::High
        );
        assert_eq!(
            severity_for_query("pack/incident-response/crontab"),
            Severity::Medium
        );
        assert_eq!(
            severity_for_query("pack/incident-response/processes"),
            Severity::Low
        );
        assert_eq!(
            severity_for_query("pack/general/unknown_query"),
            Severity::Info
        );
    }

    #[test]
    fn unparseable_line_returns_none() {
        assert!(parse_osquery_event("not json", "host1").is_none());
        assert!(parse_osquery_event("{}", "host1").is_none()); // missing "name"
    }
}
