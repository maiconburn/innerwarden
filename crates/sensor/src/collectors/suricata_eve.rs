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

pub struct SuricataEveCollector {
    path: PathBuf,
    host: String,
    offset: u64,
    /// Event types to ingest. Defaults: ["alert", "dns", "http", "tls", "anomaly"].
    /// "stats" and "flow" are excluded by default (too high volume).
    event_types: Vec<String>,
}

impl SuricataEveCollector {
    pub fn new(
        path: impl Into<PathBuf>,
        host: impl Into<String>,
        offset: u64,
        event_types: Vec<String>,
    ) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
            event_types,
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
            event_types = ?self.event_types,
            "suricata_eve collector starting"
        );

        loop {
            let path = self.path.clone();
            let host = self.host.clone();
            let offset = self.offset;
            let event_types = self.event_types.clone();
            let result =
                tokio::task::spawn_blocking(move || poll(&path, &host, offset, &event_types))
                    .await?;

            match result {
                Ok((events, new_offset)) => {
                    self.offset = new_offset;
                    shared_offset.store(new_offset, Ordering::Relaxed);
                    for event in events {
                        debug!(kind = %event.kind, summary = %event.summary, "suricata event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("suricata_eve poll error: {e:#}"),
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

fn poll(path: &Path, host: &str, offset: u64, event_types: &[String]) -> Result<(Vec<Event>, u64)> {
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

        match parse_eve_event(trimmed, host, event_types) {
            ParseResult::Event(ev) => events.push(ev),
            ParseResult::Skipped => {}
            ParseResult::Error => debug!(
                "suricata_eve: skipped unparseable line: {}",
                &trimmed[..trimmed.len().min(80)]
            ),
        }
    }

    Ok((events, pos))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub(crate) enum ParseResult {
    Event(Event),
    Skipped, // valid JSON but filtered event_type
    Error,   // unparseable
}

/// Parse one line from Suricata's EVE JSON log.
///
/// EVE JSON format (suricata.yaml: outputs: - eve-log: enabled: yes):
/// ```json
/// {
///   "timestamp": "2026-03-15T15:00:00.000000+0000",
///   "flow_id": 1234567890,
///   "in_iface": "eth0",
///   "event_type": "alert",
///   "src_ip": "203.0.113.10",
///   "src_port": 55123,
///   "dest_ip": "10.0.0.5",
///   "dest_port": 443,
///   "proto": "TCP",
///   "alert": {
///     "action": "allowed",
///     "gid": 1,
///     "signature_id": 2100498,
///     "rev": 7,
///     "signature": "GPL ATTACK_RESPONSE id check returned root",
///     "category": "Potentially Bad Traffic",
///     "severity": 2
///   }
/// }
/// ```
pub fn parse_eve_event(line: &str, host: &str, event_types: &[String]) -> ParseResult {
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return ParseResult::Error,
    };

    let event_type = match v["event_type"].as_str() {
        Some(t) => t,
        None => return ParseResult::Error,
    };

    if !event_types.iter().any(|t| t == event_type) {
        return ParseResult::Skipped;
    }

    let ts = v["timestamp"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let src_ip = v["src_ip"].as_str().unwrap_or("").to_string();
    let dest_ip = v["dest_ip"].as_str().unwrap_or("").to_string();
    let proto = v["proto"].as_str().unwrap_or("").to_lowercase();

    let (kind, severity, summary, details, extra_tags) = match event_type {
        "alert" => build_alert(&v, &src_ip, &dest_ip, &proto),
        "dns" => build_dns(&v, &src_ip),
        "http" => build_http(&v, &src_ip),
        "tls" => build_tls(&v, &src_ip),
        "anomaly" => build_anomaly(&v, &src_ip),
        other => {
            let kind = format!("suricata.{}", slug(other));
            let summary = format!("Suricata {other} event");
            let details = v.clone();
            (kind, Severity::Info, summary, details, vec![])
        }
    };

    let mut entities = Vec::new();

    if is_valid_ip(&src_ip) {
        entities.push(EntityRef::ip(src_ip.clone()));
    }
    // dest_ip is often the monitored host itself; still include it for correlation
    if is_valid_ip(&dest_ip) && dest_ip != src_ip {
        entities.push(EntityRef::ip(dest_ip.clone()));
    }

    // HTTP hostname as service entity
    if let Some(hostname) = v["http"]["hostname"].as_str() {
        if !hostname.is_empty() {
            entities.push(EntityRef::service(hostname.to_string()));
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.r#type.clone(), e.value.clone())));

    let mut tags = vec!["suricata".to_string(), event_type.to_string()];
    if !proto.is_empty() {
        tags.push(proto.clone());
    }
    tags.extend(extra_tags);
    tags.dedup();

    ParseResult::Event(Event {
        ts,
        host: host.to_string(),
        source: "suricata".to_string(),
        kind,
        severity,
        summary,
        details,
        tags,
        entities,
    })
}

// ---------------------------------------------------------------------------
// Per-event-type builders
// ---------------------------------------------------------------------------

fn build_alert(
    v: &serde_json::Value,
    src_ip: &str,
    dest_ip: &str,
    proto: &str,
) -> (String, Severity, String, serde_json::Value, Vec<String>) {
    let alert = &v["alert"];
    let signature = alert["signature"].as_str().unwrap_or("Unknown signature");
    let category = alert["category"].as_str().unwrap_or("Unknown");
    let suricata_sev = alert["severity"].as_u64().unwrap_or(3);
    let action = alert["action"].as_str().unwrap_or("allowed");
    let sid = alert["signature_id"].as_u64().unwrap_or(0);

    let severity = map_alert_severity(suricata_sev);
    let kind = format!("suricata.alert.{}", slug(category));
    let summary = format!("{signature} [{src_ip} → {dest_ip}/{proto}]");
    let details = serde_json::json!({
        "signature": signature,
        "signature_id": sid,
        "category": category,
        "severity": suricata_sev,
        "action": action,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": proto,
        "src_port": v["src_port"],
        "dest_port": v["dest_port"],
        "app_proto": v["app_proto"],
    });

    let mut extra_tags = vec!["ids".to_string()];
    if action == "blocked" || action == "drop" {
        extra_tags.push("blocked".to_string());
    }

    (kind, severity, summary, details, extra_tags)
}

fn build_dns(
    v: &serde_json::Value,
    src_ip: &str,
) -> (String, Severity, String, serde_json::Value, Vec<String>) {
    let dns = &v["dns"];
    let qtype = dns["type"].as_str().unwrap_or("query");
    let rrname = dns["rrname"].as_str().unwrap_or("");
    let rrtype = dns["rrtype"].as_str().unwrap_or("A");

    let kind = format!("suricata.dns.{}", slug(qtype));
    let summary = format!("DNS {qtype}: {rrname} ({rrtype}) from {src_ip}");
    let details = serde_json::json!({
        "dns_type": qtype,
        "rrname": rrname,
        "rrtype": rrtype,
        "src_ip": src_ip,
        "tx_id": v["tx_id"],
    });

    (
        kind,
        Severity::Info,
        summary,
        details,
        vec!["dns".to_string()],
    )
}

fn build_http(
    v: &serde_json::Value,
    src_ip: &str,
) -> (String, Severity, String, serde_json::Value, Vec<String>) {
    let http = &v["http"];
    let method = http["http_method"].as_str().unwrap_or("GET");
    let hostname = http["hostname"].as_str().unwrap_or("");
    let url = http["url"].as_str().unwrap_or("/");
    let status = http["status"].as_u64().unwrap_or(0);

    let severity = if status >= 400 {
        Severity::Low
    } else {
        Severity::Info
    };
    let summary = format!("{method} {hostname}{url} from {src_ip} (HTTP {status})");
    let details = serde_json::json!({
        "method": method,
        "hostname": hostname,
        "url": url,
        "status": status,
        "user_agent": http["http_user_agent"],
        "src_ip": src_ip,
    });

    (
        "suricata.http".to_string(),
        severity,
        summary,
        details,
        vec!["http".to_string()],
    )
}

fn build_tls(
    v: &serde_json::Value,
    src_ip: &str,
) -> (String, Severity, String, serde_json::Value, Vec<String>) {
    let tls = &v["tls"];
    let sni = tls["sni"].as_str().unwrap_or("");
    let version = tls["version"].as_str().unwrap_or("");
    let subject = tls["subject"].as_str().unwrap_or("");

    let summary = if !sni.is_empty() {
        format!("TLS connection to {sni} ({version}) from {src_ip}")
    } else {
        format!("TLS connection ({version}) from {src_ip}")
    };
    let details = serde_json::json!({
        "sni": sni,
        "version": version,
        "subject": subject,
        "issuerdn": tls["issuerdn"],
        "fingerprint": tls["fingerprint"],
        "src_ip": src_ip,
    });

    (
        "suricata.tls".to_string(),
        Severity::Info,
        summary,
        details,
        vec!["tls".to_string()],
    )
}

fn build_anomaly(
    v: &serde_json::Value,
    src_ip: &str,
) -> (String, Severity, String, serde_json::Value, Vec<String>) {
    let anomaly = &v["anomaly"];
    let atype = anomaly["type"].as_str().unwrap_or("unknown");
    let event_field = anomaly["event"].as_str().unwrap_or("");
    let layer = anomaly["layer"].as_str().unwrap_or("");

    let summary = format!("Protocol anomaly: {event_field} ({layer}) from {src_ip}");
    let details = serde_json::json!({
        "anomaly_type": atype,
        "event": event_field,
        "layer": layer,
        "src_ip": src_ip,
    });

    (
        format!("suricata.anomaly.{}", slug(atype)),
        Severity::Low,
        summary,
        details,
        vec!["anomaly".to_string()],
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Suricata alert severity: 1 = highest (critical), 2 = high, 3 = medium/low
fn map_alert_severity(sev: u64) -> Severity {
    match sev {
        1 => Severity::Critical,
        2 => Severity::High,
        3 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Convert a string to a lowercase underscore slug.
/// "Potentially Bad Traffic" → "potentially_bad_traffic"
pub fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_sep = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            out.push(ch.to_lowercase().next().unwrap());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    if out.ends_with('_') {
        out.pop();
    }
    out
}

fn is_valid_ip(ip: &str) -> bool {
    !matches!(ip, "" | "0.0.0.0" | "::")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn default_types() -> Vec<String> {
        ["alert", "dns", "http", "tls", "anomaly"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn alert_line() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:00:00.000000+0000","flow_id":1234567890,"in_iface":"eth0","event_type":"alert","src_ip":"203.0.113.10","src_port":55123,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"Potentially Bad Traffic","severity":2},"app_proto":"tls"}"#
    }

    fn critical_alert_line() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:01:00.000000+0000","event_type":"alert","src_ip":"1.2.3.4","src_port":12345,"dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","alert":{"action":"blocked","signature_id":9999,"signature":"ET EXPLOIT SSH exploit attempt","category":"Exploit","severity":1}}"#
    }

    fn dns_line() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:02:00.000000+0000","event_type":"dns","src_ip":"10.0.0.5","src_port":53244,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":12345,"rrname":"evil.example.com","rrtype":"A","tx_id":0}}"#
    }

    fn http_line() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:03:00.000000+0000","event_type":"http","src_ip":"203.0.113.20","dest_ip":"10.0.0.5","proto":"TCP","http":{"hostname":"victim.example.com","url":"/admin","http_method":"POST","status":404,"http_user_agent":"curl/7.68.0"}}"#
    }

    fn stats_line() -> &'static str {
        r#"{"timestamp":"2026-03-15T15:04:00.000000+0000","event_type":"stats","stats":{"uptime":3600}}"#
    }

    #[test]
    fn parses_alert_event() {
        let types = default_types();
        match parse_eve_event(alert_line(), "host1", &types) {
            ParseResult::Event(ev) => {
                assert_eq!(ev.source, "suricata");
                assert_eq!(ev.kind, "suricata.alert.potentially_bad_traffic");
                assert_eq!(ev.severity, Severity::High);
                assert!(ev.summary.contains("GPL ATTACK_RESPONSE"));
                assert!(ev.tags.contains(&"suricata".to_string()));
                assert!(ev.tags.contains(&"ids".to_string()));
            }
            other => panic!(
                "expected Event, got {:?}",
                matches!(other, ParseResult::Skipped)
            ),
        }
    }

    #[test]
    fn critical_alert_maps_to_critical() {
        let types = default_types();
        match parse_eve_event(critical_alert_line(), "host1", &types) {
            ParseResult::Event(ev) => {
                assert_eq!(ev.severity, Severity::Critical);
                assert!(ev.tags.contains(&"blocked".to_string()));
            }
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn alert_extracts_ip_entities() {
        let types = default_types();
        match parse_eve_event(alert_line(), "host1", &types) {
            ParseResult::Event(ev) => {
                let ips: Vec<_> = ev
                    .entities
                    .iter()
                    .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
                    .collect();
                assert!(
                    ips.iter().any(|e| e.value == "203.0.113.10"),
                    "src_ip should be extracted"
                );
            }
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn parses_dns_event() {
        let types = default_types();
        match parse_eve_event(dns_line(), "host1", &types) {
            ParseResult::Event(ev) => {
                assert_eq!(ev.kind, "suricata.dns.query");
                assert_eq!(ev.severity, Severity::Info);
                assert!(ev.summary.contains("evil.example.com"));
            }
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn parses_http_event() {
        let types = default_types();
        match parse_eve_event(http_line(), "host1", &types) {
            ParseResult::Event(ev) => {
                assert_eq!(ev.kind, "suricata.http");
                assert!(ev.summary.contains("/admin"));
                // HTTP 404 → Low severity
                assert_eq!(ev.severity, Severity::Low);
                let services: Vec<_> = ev
                    .entities
                    .iter()
                    .filter(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Service))
                    .collect();
                assert!(
                    services.iter().any(|e| e.value == "victim.example.com"),
                    "hostname should be service entity"
                );
            }
            _ => panic!("expected Event"),
        }
    }

    #[test]
    fn stats_event_is_filtered() {
        let types = default_types(); // "stats" not in default list
        assert!(matches!(
            parse_eve_event(stats_line(), "host1", &types),
            ParseResult::Skipped
        ));
    }

    #[test]
    fn stats_included_when_configured() {
        let types = vec!["stats".to_string()];
        assert!(matches!(
            parse_eve_event(stats_line(), "host1", &types),
            ParseResult::Event(_)
        ));
    }

    #[test]
    fn unparseable_line_returns_error() {
        let types = default_types();
        assert!(matches!(
            parse_eve_event("not json", "host1", &types),
            ParseResult::Error
        ));
        assert!(matches!(
            parse_eve_event("{}", "host1", &types),
            ParseResult::Error // missing event_type
        ));
    }

    #[test]
    fn slug_converts_correctly() {
        assert_eq!(slug("Potentially Bad Traffic"), "potentially_bad_traffic");
        assert_eq!(slug("ET EXPLOIT SSH exploit"), "et_exploit_ssh_exploit");
        assert_eq!(
            slug("A Attempted Information Leak"),
            "a_attempted_information_leak"
        );
    }

    #[test]
    fn map_alert_severity_covers_all() {
        assert_eq!(map_alert_severity(1), Severity::Critical);
        assert_eq!(map_alert_severity(2), Severity::High);
        assert_eq!(map_alert_severity(3), Severity::Medium);
        assert_eq!(map_alert_severity(4), Severity::Low);
    }
}
