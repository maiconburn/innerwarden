/// Nginx error log collector.
///
/// Tails the nginx error log and emits `http.error` events for lines that
/// contain a client IP. Uses a byte-offset cursor for resume-on-restart.
///
/// Nginx error log format (most common variant):
/// ```text
/// 2024/01/15 12:34:56 [error] 1234#1234: *567 open() "/etc/passwd" failed ...,
///   client: 1.2.3.4, server: example.com, request: "GET /etc/passwd HTTP/1.1", host: "example.com"
/// ```
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::warn;

pub struct NginxErrorCollector {
    path: String,
    host: String,
    start_offset: u64,
}

impl NginxErrorCollector {
    pub fn new(path: impl Into<String>, host: impl Into<String>, start_offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            start_offset,
        }
    }

    pub async fn run(self, tx: mpsc::Sender<Event>, shared_offset: Arc<AtomicU64>) -> Result<()> {
        let path = self.path.clone();
        let host = self.host.clone();
        let mut offset = self.start_offset;

        loop {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    warn!("nginx_error: cannot open {path}: {e:#}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut reader = BufReader::new(file);
            if let Err(e) = reader.seek(SeekFrom::Start(offset)) {
                warn!("nginx_error: seek failed: {e:#}");
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) => {
                        offset += n as u64;
                        shared_offset.store(offset, Ordering::Relaxed);

                        let line = line.trim_end();
                        if line.is_empty() {
                            continue;
                        }

                        if let Some(entry) = parse_line(line) {
                            let event = Event {
                                ts: chrono::Utc::now(),
                                host: host.clone(),
                                source: "nginx_error".to_string(),
                                kind: "http.error".to_string(),
                                severity: error_severity(&entry.level),
                                summary: format!(
                                    "[{}] {} {}",
                                    entry.level,
                                    entry.client_ip.as_deref().unwrap_or("?"),
                                    entry.message
                                ),
                                details: serde_json::json!({
                                    "level": entry.level,
                                    "ip": entry.client_ip,
                                    "server": entry.server,
                                    "request": entry.request,
                                    "message": entry.message,
                                }),
                                tags: vec!["http".to_string(), "nginx".to_string()],
                                entities: entry
                                    .client_ip
                                    .iter()
                                    .map(|ip| EntityRef::ip(ip))
                                    .collect(),
                            };
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("nginx_error: read error: {e:#}");
                        break;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Log parser
// ---------------------------------------------------------------------------

struct NginxErrorEntry {
    level: String,
    client_ip: Option<String>,
    server: Option<String>,
    request: Option<String>,
    message: String,
}

/// Parse one line of nginx error log format:
/// `2024/01/15 12:34:56 [error] 1234#1234: *567 message, client: IP, server: HOST, request: "...", host: "..."`
fn parse_line(line: &str) -> Option<NginxErrorEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Extract level: text between first '[' and ']'
    let level_start = line.find('[')?;
    let level_end = line[level_start + 1..].find(']')?;
    let level = line[level_start + 1..level_start + 1 + level_end].to_string();

    // Only keep warning and above (skip debug/info)
    if matches!(level.as_str(), "debug" | "info" | "notice") {
        return None;
    }

    // Pattern: "YYYY/MM/DD HH:MM:SS [level] pid#tid: message"
    // Find the "] " that closes the level bracket, then find the ": " ending the pid field.
    let level_close = line.find("] ")?;
    let after_level = &line[level_close + 2..]; // "pid#tid: message..."
    let body_colon = after_level.find(": ")?;
    let body = &after_level[body_colon + 2..];

    // Strip optional request context prefix "*NNN " from the body
    let body = if body.starts_with('*') {
        body.splitn(2, ' ').nth(1).unwrap_or(body)
    } else {
        body
    };

    // Extract client IP from "client: X.X.X.X"
    let client_ip = extract_field(body, "client: ");
    let server = extract_field(body, "server: ");
    let request = extract_field(body, "request: ");

    // The message is the part before the first ", client:" (if any)
    let message = if let Some(pos) = body.find(", client:") {
        body[..pos].to_string()
    } else {
        body.chars().take(200).collect()
    };

    // Only emit events with a client IP (server-side errors without client context are noise)
    if client_ip.is_none() && !matches!(level.as_str(), "crit" | "alert" | "emerg") {
        return None;
    }

    Some(NginxErrorEntry {
        level,
        client_ip,
        server,
        request,
        message,
    })
}

/// Extract a named field value from nginx error log metadata.
/// Fields look like: `..., fieldname: value, nextfield: ...`
fn extract_field(body: &str, prefix: &str) -> Option<String> {
    let pos = body.find(prefix)?;
    let after = &body[pos + prefix.len()..];

    // Value may be quoted (e.g. request: "GET / HTTP/1.1") or bare
    let value = if after.starts_with('"') {
        let end = after[1..].find('"')?;
        after[1..end + 1].to_string()
    } else {
        // Bare value — ends at comma or end-of-string
        after.split(',').next().unwrap_or("").trim().to_string()
    };

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn error_severity(level: &str) -> Severity {
    match level {
        "warn" | "warning" => Severity::Low,
        "error" => Severity::Medium,
        "crit" | "alert" | "emerg" => Severity::High,
        _ => Severity::Low,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_error_with_client() {
        let line = r#"2024/01/15 12:34:56 [error] 1234#1234: *567 open() "/etc/passwd" failed (2: No such file or directory), client: 1.2.3.4, server: example.com, request: "GET /etc/passwd HTTP/1.1", host: "example.com""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, "error");
        assert_eq!(entry.client_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(entry.server.as_deref(), Some("example.com"));
        assert!(entry.request.as_deref().unwrap().contains("/etc/passwd"));
        assert!(entry.message.contains("open()"));
    }

    #[test]
    fn parses_warn_level() {
        let line = r#"2024/01/15 12:00:00 [warn] 100#100: *1 conflicting server name "foo", client: 5.5.5.5, server: foo, request: "GET / HTTP/1.1""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, "warn");
        assert_eq!(entry.client_ip.as_deref(), Some("5.5.5.5"));
    }

    #[test]
    fn skips_debug_and_notice() {
        let debug_line = r#"2024/01/15 12:00:00 [debug] 100#100: *1 some debug message, client: 1.2.3.4"#;
        assert!(parse_line(debug_line).is_none());

        let notice_line = r#"2024/01/15 12:00:00 [notice] 100#100: start worker processes"#;
        assert!(parse_line(notice_line).is_none());
    }

    #[test]
    fn skips_server_errors_without_client() {
        let line = r#"2024/01/15 12:00:00 [error] 100#100: bind() to 0.0.0.0:80 failed (98: Address already in use)"#;
        // No client IP → skipped (not crit/alert/emerg)
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn emits_crit_without_client() {
        let line =
            r#"2024/01/15 12:00:00 [crit] 100#100: *1 SSL_do_handshake() failed while SSL handshaking"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, "crit");
        assert!(entry.client_ip.is_none());
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(error_severity("warn"), Severity::Low);
        assert_eq!(error_severity("error"), Severity::Medium);
        assert_eq!(error_severity("crit"), Severity::High);
        assert_eq!(error_severity("emerg"), Severity::High);
    }

    #[test]
    fn ignores_empty_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
    }

    #[test]
    fn extract_field_handles_quoted_values() {
        let body = r#"some message, client: 1.2.3.4, server: example.com, request: "GET /path HTTP/1.1""#;
        assert_eq!(extract_field(body, "client: ").as_deref(), Some("1.2.3.4"));
        assert_eq!(
            extract_field(body, "request: ").as_deref(),
            Some("GET /path HTTP/1.1")
        );
    }
}
