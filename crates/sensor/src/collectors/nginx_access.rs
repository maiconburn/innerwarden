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

    // Detect Nginx Proxy Manager format:
    //   [date] - status status - METHOD proto host "/path" [Client IP] [Length N] ... "UA" "ref"
    if line.starts_with('[') && line.contains("[Client ") {
        return parse_npm_line(line);
    }

    // Standard Combined/Common Log Format:
    //   IP - - [date] "METHOD /path HTTP/ver" status bytes "ref" "UA"
    let (ip, rest) = line.split_once(' ')?;
    let ip = ip.to_string();

    let quote_start = rest.find('"')?;
    let after_quote = &rest[quote_start + 1..];
    let quote_end = after_quote.find('"')?;
    let request = &after_quote[..quote_end];
    let after_request = after_quote[quote_end + 1..].trim_start();

    let mut req_parts = request.splitn(3, ' ');
    let method = req_parts.next().unwrap_or("").to_string();
    let path = req_parts.next().unwrap_or("/").to_string();

    let (status_str, after_status) = after_request.split_once(' ')?;
    let status: u16 = status_str.parse().ok()?;

    let after_status = after_status.trim_start();
    let (bytes_str, rest_str) = after_status.split_once(' ').unwrap_or((after_status, ""));
    let bytes: u64 = bytes_str.parse().unwrap_or(0);

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

/// Parse Nginx Proxy Manager log format:
/// [19/Mar/2026:04:49:01 +0000] - - 301 - GET http host.com "/path" [Client 1.2.3.4] [Length 166] [Gzip -] [Sent-to backend] "UA" "ref"
fn parse_npm_line(line: &str) -> Option<NginxLogEntry> {
    // Extract client IP from [Client X.X.X.X]
    let client_start = line.find("[Client ")? + 8;
    let client_end = line[client_start..].find(']')? + client_start;
    let ip = line[client_start..client_end].to_string();

    // Extract path from "..." (first quoted string after the hostname)
    let first_quote = line.find('"')?;
    let after_quote = &line[first_quote + 1..];
    let end_quote = after_quote.find('"')?;
    let path = after_quote[..end_quote].to_string();

    // Extract method — token before "http" or "https" before the hostname
    // Format: ... METHOD proto host "/path" ...
    let before_client = &line[..line.find("[Client")?];
    let tokens: Vec<&str> = before_client.split_whitespace().collect();

    // Find method (GET/POST/etc.) — it's the token before "http" or "https"
    let mut method = String::new();
    let mut status: u16 = 0;
    for (i, t) in tokens.iter().enumerate() {
        if (*t == "http" || *t == "https") && i > 0 {
            method = tokens[i - 1].to_string();
            break;
        }
    }

    // Extract status — first numeric 3-digit token after the date bracket
    for t in &tokens {
        if t.len() == 3 {
            if let Ok(s) = t.parse::<u16>() {
                if (100..600).contains(&s) {
                    status = s;
                    break;
                }
            }
        }
    }

    // Extract length from [Length N]
    let bytes = if let Some(len_start) = line.find("[Length ") {
        let after = &line[len_start + 8..];
        after
            .split(']')
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    } else {
        0
    };

    // User-agent from last quoted string
    let user_agent = extract_last_quoted(line).unwrap_or_default();

    if method.is_empty() || status == 0 {
        return None;
    }

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

    #[test]
    fn parses_npm_format() {
        let line = r#"[19/Mar/2026:04:49:01 +0000] - - 301 - GET http n8n.example.com "/favicon.ico" [Client 104.22.17.224] [Length 166] [Gzip -] [Sent-to n8n] "Mozilla/5.0 Firefox/124.0" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "104.22.17.224");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/favicon.ico");
        assert_eq!(entry.status, 301);
        assert_eq!(entry.bytes, 166);
    }

    #[test]
    fn parses_npm_format_200() {
        let line = r#"[18/Mar/2026:15:57:53 +0000] - 200 200 - POST https mygrowth.tools "/wp-login.php" [Client 172.68.193.204] [Length 2841] [Gzip -] [Sent-to wp_site] "Mozilla/5.0" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "172.68.193.204");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/wp-login.php");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 2841);
    }

    #[test]
    fn npm_format_extracts_user_agent() {
        let line = r#"[19/Mar/2026:00:00:00 +0000] - - 404 - GET https site.com "/api/search?q=test" [Client 203.0.113.42] [Length 100] [Gzip -] [Sent-to back] "sqlmap/1.7" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "203.0.113.42");
        assert_eq!(entry.path, "/api/search?q=test");
        assert_eq!(entry.status, 404);
    }
}
