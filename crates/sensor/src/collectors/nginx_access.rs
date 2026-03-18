/// Nginx access log collector.
///
/// Tails a Combined Log Format (or Common Log Format) access log and emits
/// `http.request` events per line. Uses a byte-offset cursor for resume-on-restart.
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

pub struct NginxAccessCollector {
    path: String,
    host: String,
    start_offset: u64,
}

impl NginxAccessCollector {
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
            // Open file and seek to last known offset
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    warn!("nginx_access: cannot open {path}: {e:#}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut reader = BufReader::new(file);
            if let Err(e) = reader.seek(SeekFrom::Start(offset)) {
                warn!("nginx_access: seek failed: {e:#}");
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        // End of file — wait and re-open to detect rotation
                        break;
                    }
                    Ok(n) => {
                        offset += n as u64;
                        shared_offset.store(offset, Ordering::Relaxed);

                        let line = line.trim_end();
                        if line.is_empty() {
                            continue;
                        }

                        if let Some(entry) = parse_line(line) {
                            let severity = http_severity(entry.status);
                            let event = Event {
                                ts: chrono::Utc::now(),
                                host: host.clone(),
                                source: "nginx_access".to_string(),
                                kind: "http.request".to_string(),
                                severity,
                                summary: format!(
                                    "{} {} {} {}",
                                    entry.ip, entry.method, entry.path, entry.status
                                ),
                                details: serde_json::json!({
                                    "ip": entry.ip,
                                    "method": entry.method,
                                    "path": entry.path,
                                    "status": entry.status,
                                    "bytes": entry.bytes,
                                    "user_agent": entry.user_agent,
                                }),
                                tags: vec!["http".to_string()],
                                entities: vec![EntityRef::ip(&entry.ip)],
                            };
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("nginx_access: read error: {e:#}");
                        break;
                    }
                }
            }

            // Pause between tail iterations; also detects log rotation
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Log parser
// ---------------------------------------------------------------------------

struct NginxLogEntry {
    ip: String,
    method: String,
    path: String,
    status: u16,
    bytes: u64,
    user_agent: String,
}

/// Parse one line of Nginx Combined or Common Log Format.
///
/// ```text
/// 1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 1234 "referer" "ua"
/// ```
fn parse_line(line: &str) -> Option<NginxLogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // IP is the first whitespace-delimited token
    let (ip, rest) = line.split_once(' ')?;
    let ip = ip.to_string();

    // Skip "- user [timestamp] " — find the first '"' which starts the request field
    let quote_start = rest.find('"')?;
    let after_quote = &rest[quote_start + 1..];

    // Read until closing '"'
    let quote_end = after_quote.find('"')?;
    let request = &after_quote[..quote_end];
    let after_request = after_quote[quote_end + 1..].trim_start();

    // Parse request: "METHOD /path HTTP/version"
    let mut req_parts = request.splitn(3, ' ');
    let method = req_parts.next().unwrap_or("").to_string();
    let path_with_qs = req_parts.next().unwrap_or("/").to_string();
    // Keep path including query string — detectors handle prefix matching
    let path = path_with_qs;

    // status (next token)
    let (status_str, after_status) = after_request.split_once(' ')?;
    let status: u16 = status_str.parse().ok()?;

    // bytes (next token, '-' means 0)
    let after_status = after_status.trim_start();
    let (bytes_str, rest_str) = after_status.split_once(' ').unwrap_or((after_status, ""));
    let bytes: u64 = bytes_str.parse().unwrap_or(0);

    // User-agent is in the last quoted field (Combined format only)
    let user_agent = extract_last_quoted(rest_str.trim()).unwrap_or_default();

    Some(NginxLogEntry {
        ip,
        method,
        path,
        status,
        bytes,
        user_agent,
    })
}

/// Extract the content of the last `"..."` pair in a string.
fn extract_last_quoted(s: &str) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    let last_quote = s.rfind('"')?;
    let prev_quote = s[..last_quote].rfind('"')?;
    Some(s[prev_quote + 1..last_quote].to_string())
}

fn http_severity(status: u16) -> Severity {
    match status {
        200..=299 => Severity::Info,
        300..=399 => Severity::Debug,
        400..=499 => Severity::Low,
        500..=599 => Severity::Medium,
        _ => Severity::Debug,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_log_format() {
        let line = r#"1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /api/search?q=foo HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "1.2.3.4");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/api/search?q=foo");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 1234);
        assert_eq!(entry.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn parses_common_log_format() {
        let line =
            r#"10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "POST /api/search HTTP/1.0" 200 512"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/api/search");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 512);
        assert!(entry.user_agent.is_empty());
    }

    #[test]
    fn parses_dash_bytes() {
        let line = r#"5.5.5.5 - - [01/Jan/2025:00:00:00 +0000] "GET /health HTTP/1.1" 200 -"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.bytes, 0);
    }

    #[test]
    fn ignores_empty_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
    }

    #[test]
    fn ignores_malformed_lines() {
        assert!(parse_line("not a log line").is_none());
    }

    #[test]
    fn http_severity_mapping() {
        assert_eq!(http_severity(200), Severity::Info);
        assert_eq!(http_severity(301), Severity::Debug);
        assert_eq!(http_severity(404), Severity::Low);
        assert_eq!(http_severity(500), Severity::Medium);
    }

    #[test]
    fn extract_last_quoted_works() {
        assert_eq!(
            extract_last_quoted(r#""https://ref" "Mozilla/5.0""#),
            Some("Mozilla/5.0".to_string())
        );
        assert_eq!(extract_last_quoted(""), None);
    }
}
