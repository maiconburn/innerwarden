use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct AuthLogCollector {
    pub path: PathBuf,
    pub host: String,
    pub offset: u64,
}

impl AuthLogCollector {
    pub fn new(path: impl Into<PathBuf>, host: impl Into<String>, offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            offset,
        }
    }

    /// Tail the log file, polling every second.
    /// Uses spawn_blocking for file I/O so the tokio executor stays free.
    /// `shared_offset` is updated after every successful poll so callers
    /// can read the latest position at any time (e.g. on shutdown).
    pub async fn run(
        mut self,
        tx: mpsc::Sender<Event>,
        shared_offset: Arc<AtomicU64>,
    ) -> Result<()> {
        info!(path = %self.path.display(), offset = self.offset, "auth_log collector starting");

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
                        debug!(kind = %event.kind, "parsed event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("auth_log poll error: {e:#}"),
            }

            tokio::time::sleep(Duration::from_secs(1)).await;

            if tx.is_closed() {
                break;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Blocking poll — reads new lines since `offset`, returns (events, new_offset)
// ---------------------------------------------------------------------------

fn poll(path: &Path, host: &str, offset: u64) -> Result<(Vec<Event>, u64)> {
    let mut file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();

    let offset = if file_len < offset {
        warn!(path = %path.display(), "log rotation detected, resetting offset");
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
        if let Some(event) = parse_sshd_line(line.trim_end(), host) {
            events.push(event);
        }
    }

    Ok((events, reader.stream_position()?))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a single auth.log line into an Event, if it's an SSH event we care about.
///
/// Typical formats (syslog):
///   Mar 12 06:00:01 hostname sshd[pid]: <message>
pub fn parse_sshd_line(line: &str, host: &str) -> Option<Event> {
    // Must be an sshd line
    if !line.contains("sshd[") {
        return None;
    }
    // Extract the message part after "sshd[pid]: "
    let msg = line.splitn(2, "]: ").nth(1)?.trim();
    parse_sshd_message(msg, host, "auth.log")
}

/// Parse the raw sshd message string (without syslog prefix) into an Event.
/// `source` is the event source label (e.g. "auth.log" or "journald").
pub fn parse_sshd_message(msg: &str, host: &str, source: &str) -> Option<Event> {
    if msg.starts_with("Failed password for invalid user") {
        // Failed password for invalid user <user> from <ip> port <port> ssh2
        let user = word_after(msg, "for invalid user")?;
        let ip = word_after(msg, "from")?;
        Some(make_event(
            host,
            source,
            "ssh.login_failed",
            Severity::Info,
            format!("Failed login — invalid user {user} from {ip}"),
            serde_json::json!({ "ip": ip, "user": user, "reason": "invalid_user" }),
            vec!["auth", "ssh"],
            vec![EntityRef::ip(ip), EntityRef::user(user)],
        ))
    } else if msg.starts_with("Failed password for") {
        let user = word_after(msg, "for")?;
        let ip = word_after(msg, "from")?;
        Some(make_event(
            host,
            source,
            "ssh.login_failed",
            Severity::Info,
            format!("Failed login for {user} from {ip}"),
            serde_json::json!({ "ip": ip, "user": user, "reason": "wrong_password" }),
            vec!["auth", "ssh"],
            vec![EntityRef::ip(ip), EntityRef::user(user)],
        ))
    } else if msg.starts_with("Invalid user") {
        let user = word_after(msg, "Invalid user")?;
        let ip = word_after(msg, "from")?;
        Some(make_event(
            host,
            source,
            "ssh.login_failed",
            Severity::Info,
            format!("Invalid user {user} from {ip}"),
            serde_json::json!({ "ip": ip, "user": user, "reason": "invalid_user" }),
            vec!["auth", "ssh"],
            vec![EntityRef::ip(ip), EntityRef::user(user)],
        ))
    } else if msg.starts_with("Accepted password for") || msg.starts_with("Accepted publickey for")
    {
        let method = if msg.starts_with("Accepted password") {
            "password"
        } else {
            "publickey"
        };
        let user = word_after(msg, "for")?;
        let ip = word_after(msg, "from")?;
        Some(make_event(
            host,
            source,
            "ssh.login_success",
            Severity::Info,
            format!("Login accepted for {user} from {ip} via {method}"),
            serde_json::json!({ "ip": ip, "user": user, "method": method }),
            vec!["auth", "ssh"],
            vec![EntityRef::ip(ip), EntityRef::user(user)],
        ))
    } else {
        None
    }
}

fn make_event(
    host: &str,
    source: &str,
    kind: &str,
    severity: Severity,
    summary: String,
    details: serde_json::Value,
    tags: Vec<&str>,
    entities: Vec<EntityRef>,
) -> Event {
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: source.to_string(),
        kind: kind.to_string(),
        severity,
        summary,
        details,
        tags: tags.into_iter().map(str::to_string).collect(),
        entities,
    }
}

/// Return the first whitespace-delimited word that appears after `needle` in `s`.
fn word_after<'a>(s: &'a str, needle: &str) -> Option<&'a str> {
    let pos = s.find(needle)?;
    s[pos + needle.len()..].split_whitespace().next()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_failed_invalid_user() {
        let line = "Mar 12 06:00:01 host sshd[123]: Failed password for invalid user oracle from 1.2.3.4 port 54321 ssh2";
        let ev = parse_sshd_line(line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.details["user"], "oracle");
        assert_eq!(ev.details["ip"], "1.2.3.4");
        assert_eq!(ev.details["reason"], "invalid_user");
    }

    #[test]
    fn parse_failed_password() {
        let line =
            "Mar 12 06:00:01 host sshd[123]: Failed password for root from 2.3.4.5 port 22 ssh2";
        let ev = parse_sshd_line(line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.details["user"], "root");
        assert_eq!(ev.details["ip"], "2.3.4.5");
        assert_eq!(ev.details["reason"], "wrong_password");
    }

    #[test]
    fn parse_invalid_user_banner() {
        let line = "Mar 12 06:00:01 host sshd[123]: Invalid user admin from 5.6.7.8 port 1234";
        let ev = parse_sshd_line(line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.details["user"], "admin");
        assert_eq!(ev.details["ip"], "5.6.7.8");
    }

    #[test]
    fn parse_accepted_publickey() {
        let line = "Mar 12 06:00:01 host sshd[123]: Accepted publickey for ubuntu from 10.0.0.1 port 54321 ssh2: RSA SHA256:abc";
        let ev = parse_sshd_line(line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_success");
        assert_eq!(ev.details["user"], "ubuntu");
        assert_eq!(ev.details["method"], "publickey");
    }

    #[test]
    fn parse_accepted_password() {
        let line = "Mar 12 06:00:01 host sshd[123]: Accepted password for deploy from 10.0.0.2 port 22 ssh2";
        let ev = parse_sshd_line(line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_success");
        assert_eq!(ev.details["method"], "password");
    }

    #[test]
    fn skip_non_sshd_lines() {
        let line = "Mar 12 06:00:01 host sudo[999]: user : TTY=pts/0";
        assert!(parse_sshd_line(line, "host").is_none());
    }
}
