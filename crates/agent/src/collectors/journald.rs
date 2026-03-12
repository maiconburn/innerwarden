use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{entities::EntityRef, event::{Event, Severity}};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::auth_log::parse_sshd_message;

pub struct JournaldCollector {
    host: String,
    units: Vec<String>,
    cursor: Option<String>,
}

impl JournaldCollector {
    pub fn new(
        host: impl Into<String>,
        units: Vec<String>,
        cursor: Option<String>,
    ) -> Self {
        Self { host: host.into(), units, cursor }
    }

    /// Stream journald entries via `journalctl --follow --output=json`.
    /// `shared_cursor` is updated after each entry so callers can persist it on shutdown.
    pub async fn run(
        self,
        tx: mpsc::Sender<Event>,
        shared_cursor: Arc<Mutex<Option<String>>>,
    ) -> Result<()> {
        // Verify journalctl is available
        if Command::new("journalctl").arg("--version").output().await.is_err() {
            warn!("journalctl not found — journald collector disabled");
            return Ok(());
        }

        info!(
            units = ?self.units,
            cursor = ?self.cursor,
            "journald collector starting"
        );

        // Restart loop — if journalctl exits unexpectedly, restart it.
        let mut current_cursor = self.cursor.clone();
        loop {
            let mut cmd = Command::new("journalctl");
            cmd.arg("--follow")
                .arg("--output=json")
                .stdout(std::process::Stdio::piped());

            // Resume from cursor or tail-only (no history on first run)
            if let Some(ref c) = current_cursor {
                cmd.arg(format!("--after-cursor={c}"));
            } else {
                cmd.arg("-n").arg("0");
            }

            // Filter to specific systemd units
            for unit in &self.units {
                cmd.arg("-t").arg(unit);
            }

            let mut child = cmd.spawn()?;
            let stdout = child.stdout.take().expect("stdout piped");
            let mut lines = BufReader::new(stdout).lines();

            loop {
                tokio::select! {
                    result = lines.next_line() => {
                        match result {
                            Ok(Some(line)) => {
                                if let Some((cursor, event)) = parse_journal_line(&line, &self.host) {
                                    current_cursor = Some(cursor.clone());
                                    *shared_cursor.lock().unwrap() = Some(cursor);
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return Ok(());
                                    }
                                } else if let Some(cursor) = extract_cursor(&line) {
                                    // Entry parsed but not interesting — still advance cursor
                                    current_cursor = Some(cursor.clone());
                                    *shared_cursor.lock().unwrap() = Some(cursor);
                                }
                            }
                            Ok(None) => break, // journalctl exited
                            Err(e) => {
                                warn!("journald read error: {e}");
                                break;
                            }
                        }
                    }
                    // Poll for shutdown every second even when no entries arrive
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                        if tx.is_closed() {
                            let _ = child.kill().await;
                            return Ok(());
                        }
                    }
                }
            }

            if tx.is_closed() {
                return Ok(());
            }

            warn!("journalctl exited unexpectedly — restarting in 5s");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one JSON line from `journalctl --output=json`.
/// Returns `(cursor, Event)` if the entry is one we care about.
fn parse_journal_line(line: &str, host: &str) -> Option<(String, Event)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let cursor = v["__CURSOR"].as_str()?.to_string();
    let identifier = v["SYSLOG_IDENTIFIER"].as_str().unwrap_or("");
    let message = v["MESSAGE"].as_str().unwrap_or("").trim();

    let event = match identifier {
        "sshd" => parse_sshd_message(message, host, "journald")?,
        "sudo" => parse_sudo_message(message, host)?,
        _ => return None,
    };

    Some((cursor, event))
}

fn extract_cursor(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(v["__CURSOR"].as_str()?.to_string())
}

/// Parse a sudo log message like:
///   <user> : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt
fn parse_sudo_message(msg: &str, host: &str) -> Option<Event> {
    // Must contain USER= to be a command execution entry
    if !msg.contains("USER=") || !msg.contains("COMMAND=") {
        return None;
    }

    let sudo_user = msg.split(':').next()?.trim();
    let run_as = field_after(msg, "USER=")?;
    let command = field_after(msg, "COMMAND=")?;

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "journald".to_string(),
        kind: "sudo.command".to_string(),
        severity: Severity::Info,
        summary: format!("{sudo_user} ran sudo as {run_as}: {command}"),
        details: serde_json::json!({
            "user": sudo_user,
            "run_as": run_as,
            "command": command,
        }),
        tags: vec!["auth".to_string(), "sudo".to_string()],
        entities: vec![EntityRef::user(sudo_user)],
    })
}

/// Extract the value of a `KEY=value` field (stops at ';' or end of string).
fn field_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pos = s.find(key)?;
    let rest = &s[pos + key.len()..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_line(identifier: &str, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": "test-cursor-abc",
            "SYSLOG_IDENTIFIER": identifier,
            "MESSAGE": message,
        })
        .to_string()
    }

    #[test]
    fn parses_sshd_failed_from_journald() {
        let line = journal_line("sshd", "Failed password for invalid user oracle from 1.2.3.4 port 22 ssh2");
        let (cursor, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(cursor, "test-cursor-abc");
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.source, "journald");
        assert_eq!(ev.details["user"], "oracle");
        assert_eq!(ev.details["ip"], "1.2.3.4");
    }

    #[test]
    fn parses_sshd_accepted_from_journald() {
        let line = journal_line("sshd", "Accepted publickey for ubuntu from 10.0.0.1 port 54321 ssh2: RSA SHA256:abc");
        let (_, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(ev.kind, "ssh.login_success");
        assert_eq!(ev.details["method"], "publickey");
    }

    #[test]
    fn parses_sudo_command() {
        let line = journal_line(
            "sudo",
            "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
        );
        let (_, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(ev.kind, "sudo.command");
        assert_eq!(ev.details["user"], "deploy");
        assert_eq!(ev.details["run_as"], "root");
        assert!(ev.details["command"].as_str().unwrap().contains("systemctl"));
    }

    #[test]
    fn skips_unknown_identifier() {
        let line = journal_line("nginx", "GET /health 200");
        assert!(parse_journal_line(&line, "host").is_none());
    }

    #[test]
    fn skips_sudo_non_command_line() {
        let line = journal_line("sudo", "session opened for user root by deploy(uid=1000)");
        assert!(parse_journal_line(&line, "host").is_none());
    }
}
