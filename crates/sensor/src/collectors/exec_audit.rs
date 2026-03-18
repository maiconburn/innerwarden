use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct ExecAuditCollector {
    path: PathBuf,
    host: String,
    offset: u64,
    include_tty: bool,
}

impl ExecAuditCollector {
    pub fn new(
        path: impl Into<PathBuf>,
        host: impl Into<String>,
        offset: u64,
        include_tty: bool,
    ) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
            include_tty,
        }
    }

    /// Tail Linux audit.log for EXECVE records (and optional TTY input records).
    ///
    /// This collector is disabled by default because audit trails can contain
    /// sensitive data; it should only be enabled with explicit authorization.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<Event>,
        shared_offset: Arc<AtomicU64>,
    ) -> Result<()> {
        info!(
            path = %self.path.display(),
            offset = self.offset,
            include_tty = self.include_tty,
            "exec_audit collector starting"
        );

        loop {
            let path = self.path.clone();
            let host = self.host.clone();
            let offset = self.offset;
            let include_tty = self.include_tty;
            let result =
                tokio::task::spawn_blocking(move || poll(&path, &host, offset, include_tty))
                    .await?;

            match result {
                Ok((events, new_offset)) => {
                    self.offset = new_offset;
                    shared_offset.store(new_offset, Ordering::Relaxed);
                    for event in events {
                        debug!(kind = %event.kind, "parsed exec_audit event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("exec_audit poll error: {e:#}"),
            }

            tokio::time::sleep(Duration::from_secs(1)).await;

            if tx.is_closed() {
                break;
            }
        }

        Ok(())
    }
}

fn poll(path: &PathBuf, host: &str, offset: u64, include_tty: bool) -> Result<(Vec<Event>, u64)> {
    let mut file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();

    let offset = if file_len < offset {
        warn!(path = %path.display(), "log rotation detected, resetting exec_audit offset");
        0
    } else {
        offset
    };

    file.seek(SeekFrom::Start(offset))?;

    let mut reader = BufReader::new(&file);
    let mut events = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if let Some(event) = parse_audit_line(line.trim_end(), host, include_tty) {
            events.push(event);
        }
    }

    Ok((events, reader.stream_position()?))
}

fn parse_audit_line(line: &str, host: &str, include_tty: bool) -> Option<Event> {
    if line.starts_with("type=EXECVE") {
        return parse_execve_line(line, host);
    }

    if include_tty && line.starts_with("type=TTY") {
        return parse_tty_line(line, host);
    }

    None
}

fn parse_execve_line(line: &str, host: &str) -> Option<Event> {
    let body = line.split_once("): ")?.1;
    let fields = parse_kv_fields(body);

    let mut args: BTreeMap<usize, String> = BTreeMap::new();
    for (key, value) in &fields {
        if let Some(idx) = key.strip_prefix('a').and_then(|s| s.parse::<usize>().ok()) {
            args.insert(idx, value.clone());
        }
    }

    if args.is_empty() {
        return None;
    }

    let argv: Vec<String> = args.into_values().collect();
    let command = argv.join(" ");
    let (audit_ts, audit_id) = parse_audit_metadata(line)?;
    let argc = fields.get("argc").and_then(|v| v.parse::<usize>().ok());
    let summary = format!("Shell command executed: {}", truncate(&command, 160));

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "auditd".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary,
        details: serde_json::json!({
            "audit_ts": audit_ts,
            "audit_id": audit_id,
            "argc": argc,
            "argv": argv,
            "command": command,
        }),
        tags: vec!["audit".to_string(), "shell".to_string(), "exec".to_string()],
        entities: vec![],
    })
}

fn parse_tty_line(line: &str, host: &str) -> Option<Event> {
    let body = line.split_once("): ")?.1;
    let fields = parse_kv_fields(body);
    let tty = fields.get("tty")?.to_string();
    let raw = fields.get("msg")?.trim_matches('\'').to_string();
    if raw.is_empty() {
        return None;
    }

    let decoded_preview = decode_hex_preview(&raw, 96);
    let (audit_ts, audit_id) = parse_audit_metadata(line)?;

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "auditd".to_string(),
        kind: "shell.tty_input".to_string(),
        severity: Severity::Low,
        summary: format!(
            "TTY input observed on {}: {}",
            tty,
            truncate(&decoded_preview, 120)
        ),
        details: serde_json::json!({
            "audit_ts": audit_ts,
            "audit_id": audit_id,
            "tty": tty,
            "uid": fields.get("uid"),
            "auid": fields.get("auid"),
            "raw_hex": raw,
            "decoded_preview": decoded_preview,
        }),
        tags: vec!["audit".to_string(), "shell".to_string(), "tty".to_string()],
        entities: vec![],
    })
}

fn parse_audit_metadata(line: &str) -> Option<(String, String)> {
    let start = line.find("msg=audit(")? + "msg=audit(".len();
    let end_rel = line[start..].find("):")?;
    let raw = &line[start..start + end_rel];
    let (ts, id) = raw.split_once(':')?;
    Some((ts.to_string(), id.to_string()))
}

fn parse_kv_fields(input: &str) -> BTreeMap<String, String> {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = BTreeMap::new();

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let key = String::from_utf8_lossy(&bytes[key_start..i]).to_string();
        i += 1; // skip '='

        let value = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let quote = bytes[i];
            i += 1;
            let mut value = String::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    value.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                value.push(bytes[i] as char);
                i += 1;
            }
            value
        } else {
            let value_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            String::from_utf8_lossy(&bytes[value_start..i]).to_string()
        };

        if !key.is_empty() {
            out.insert(key, value);
        }
    }

    out
}

fn decode_hex_preview(raw: &str, max_len: usize) -> String {
    let mut out = String::new();

    for chunk in raw.as_bytes().chunks(2) {
        if chunk.len() < 2 {
            break;
        }

        let pair = std::str::from_utf8(chunk).unwrap_or_default();
        let byte = match u8::from_str_radix(pair, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let piece = match byte {
            b'\n' => "\\n".to_string(),
            b'\r' => "\\r".to_string(),
            b'\t' => "\\t".to_string(),
            0x20..=0x7e => (byte as char).to_string(),
            _ => continue,
        };

        if out.len() + piece.len() > max_len {
            break;
        }

        out.push_str(&piece);
    }

    if out.is_empty() {
        "<non-printable>".to_string()
    } else {
        out
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        return s.to_string();
    }

    let trimmed: String = s.chars().take(max_len).collect();
    format!("{}...", trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_execve_command() {
        let line =
            r#"type=EXECVE msg=audit(1711800000.123:4242): argc=3 a0="sudo" a1="ufw" a2="status""#;
        let ev = parse_audit_line(line, "host-a", false).expect("expected event");
        assert_eq!(ev.kind, "shell.command_exec");
        assert_eq!(ev.source, "auditd");
        assert_eq!(ev.details["audit_id"], "4242");
        assert_eq!(ev.details["command"], "sudo ufw status");
        assert_eq!(ev.details["argv"][1], "ufw");
    }

    #[test]
    fn parses_execve_quoted_args_with_spaces() {
        let line = r#"type=EXECVE msg=audit(1711800000.123:4243): argc=3 a0="bash" a1="-lc" a2="ls -lah /tmp""#;
        let ev = parse_audit_line(line, "host-a", false).expect("expected event");
        assert_eq!(ev.details["command"], "bash -lc ls -lah /tmp");
    }

    #[test]
    fn tty_line_requires_include_flag() {
        let line =
            "type=TTY msg=audit(1711800100.456:5000): tty=pts0 uid=1000 auid=1000 msg='6c730d'";
        assert!(parse_audit_line(line, "host-a", false).is_none());
    }

    #[test]
    fn parses_tty_line_when_enabled() {
        let line = "type=TTY msg=audit(1711800100.456:5001): tty=pts0 uid=1000 auid=1000 msg='6c73202d6c610d'";
        let ev = parse_audit_line(line, "host-a", true).expect("expected event");
        assert_eq!(ev.kind, "shell.tty_input");
        assert_eq!(ev.details["tty"], "pts0");
        assert_eq!(ev.details["decoded_preview"], "ls -la\\r");
    }
}
