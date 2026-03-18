use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
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
    pub fn new(host: impl Into<String>, units: Vec<String>, cursor: Option<String>) -> Self {
        Self {
            host: host.into(),
            units,
            cursor,
        }
    }

    /// Stream journald entries via `journalctl --follow --output=json`.
    /// `shared_cursor` is updated after each entry so callers can persist it on shutdown.
    pub async fn run(
        self,
        tx: mpsc::Sender<Event>,
        shared_cursor: Arc<Mutex<Option<String>>>,
    ) -> Result<()> {
        // Verify journalctl is available AND the current user can read the journal.
        // Using `-n 0` actually queries the journal (unlike --version which is always ok).
        let check = Command::new("journalctl")
            .args(["-n", "0", "--output=json"])
            .output()
            .await;
        match check {
            Err(_) => {
                warn!("journalctl not found — journald collector disabled");
                return Ok(());
            }
            Ok(out) if !out.status.success() => {
                warn!("journalctl returned non-zero (permission denied?) — journald collector disabled");
                return Ok(());
            }
            _ => {}
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
                                // parse_journal_line now always returns the cursor when JSON is
                                // valid, so we never need to re-parse just to advance the cursor.
                                match parse_journal_line(&line, &self.host) {
                                    Some((cursor, Some(event))) => {
                                        current_cursor = Some(cursor.clone());
                                        *shared_cursor.lock().unwrap() = Some(cursor);
                                        if tx.send(event).await.is_err() {
                                            let _ = child.kill().await;
                                            return Ok(());
                                        }
                                    }
                                    Some((cursor, None)) => {
                                        // Valid JSON but not an event we care about — still advance cursor
                                        current_cursor = Some(cursor.clone());
                                        *shared_cursor.lock().unwrap() = Some(cursor);
                                    }
                                    None => {} // Malformed JSON — skip
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
///
/// Returns:
/// - `None` — malformed JSON (cursor unknown, skip)
/// - `Some((cursor, None))` — valid entry but not interesting (advance cursor only)
/// - `Some((cursor, Some(event)))` — valid entry that should be emitted
///
/// The cursor is always extracted in a single parse pass, eliminating the
/// previous pattern of calling a separate `extract_cursor()` for non-matching lines.
fn parse_journal_line(line: &str, host: &str) -> Option<(String, Option<Event>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let cursor = v["__CURSOR"].as_str()?.to_string();
    let identifier = v["SYSLOG_IDENTIFIER"].as_str().unwrap_or("");
    let message = v["MESSAGE"].as_str().unwrap_or("").trim();

    let event = match identifier {
        "sshd" => parse_sshd_message(message, host, "journald"),
        "sudo" => parse_sudo_message(message, host),
        "kernel" => parse_kernel_firewall_message(message, host),
        _ => None,
    };

    Some((cursor, event))
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

/// Parse kernel firewall message variants (UFW/iptables/nftables style).
///
/// Typical examples:
///   [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.10 DST=10.0.0.10 ... PROTO=TCP SPT=49466 DPT=3306
///   IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.10 ... PROTO=TCP SPT=45000 DPT=8080
fn parse_kernel_firewall_message(msg: &str, host: &str) -> Option<Event> {
    // Keep this strict enough to avoid turning random kernel logs into network events.
    let has_firewall_hint = msg.contains("UFW BLOCK")
        || (msg.contains("SRC=") && msg.contains("DST=") && msg.contains("DPT="));
    if !has_firewall_hint {
        return None;
    }

    let src_ip = kv_after(msg, "SRC=")?;
    let dst_ip = kv_after(msg, "DST=").unwrap_or("unknown");
    let dst_port = kv_after(msg, "DPT=")?.parse::<u16>().ok()?;
    let proto = kv_after(msg, "PROTO=").unwrap_or("UNKNOWN");

    let mut entities = vec![EntityRef::ip(src_ip)];
    if dst_ip != "unknown" && dst_ip != src_ip {
        entities.push(EntityRef::ip(dst_ip));
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "journald".to_string(),
        kind: "network.connection_blocked".to_string(),
        severity: Severity::Low,
        summary: format!("Firewall blocked {proto} traffic from {src_ip} to {dst_ip}:{dst_port}"),
        details: serde_json::json!({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
        }),
        tags: vec!["network".to_string(), "firewall".to_string()],
        entities,
    })
}

/// Extract the value of a `KEY=value` field (stops at ';' or end of string).
fn field_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pos = s.find(key)?;
    let rest = &s[pos + key.len()..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// Extract a KEY=VALUE token from syslog-style key/value strings.
fn kv_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pos = s.find(key)?;
    let rest = &s[pos + key.len()..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
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
        let line = journal_line(
            "sshd",
            "Failed password for invalid user oracle from 1.2.3.4 port 22 ssh2",
        );
        let (cursor, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(cursor, "test-cursor-abc");
        let ev = ev.expect("should have event");
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.source, "journald");
        assert_eq!(ev.details["user"], "oracle");
        assert_eq!(ev.details["ip"], "1.2.3.4");
    }

    #[test]
    fn parses_sshd_accepted_from_journald() {
        let line = journal_line(
            "sshd",
            "Accepted publickey for ubuntu from 10.0.0.1 port 54321 ssh2: RSA SHA256:abc",
        );
        let (_, ev) = parse_journal_line(&line, "host").unwrap();
        let ev = ev.expect("should have event");
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
        let ev = ev.expect("should have event");
        assert_eq!(ev.kind, "sudo.command");
        assert_eq!(ev.details["user"], "deploy");
        assert_eq!(ev.details["run_as"], "root");
        assert!(ev.details["command"]
            .as_str()
            .unwrap()
            .contains("systemctl"));
    }

    #[test]
    fn skips_unknown_identifier() {
        // Returns Some((cursor, None)) — cursor is advanced but no event is emitted
        let line = journal_line("nginx", "GET /health 200");
        let (cursor, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(cursor, "test-cursor-abc");
        assert!(
            ev.is_none(),
            "unknown identifier should not produce an event"
        );
    }

    #[test]
    fn skips_sudo_non_command_line() {
        // Session lines don't have USER= and COMMAND=, so no event is emitted
        let line = journal_line("sudo", "session opened for user root by deploy(uid=1000)");
        let (cursor, ev) = parse_journal_line(&line, "host").unwrap();
        assert_eq!(cursor, "test-cursor-abc");
        assert!(
            ev.is_none(),
            "non-command sudo line should not produce an event"
        );
    }

    #[test]
    fn returns_none_for_invalid_json() {
        assert!(parse_journal_line("not-json-at-all", "host").is_none());
    }

    #[test]
    fn parses_kernel_ufw_block_message() {
        let line = journal_line(
            "kernel",
            "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.10 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=48888 DPT=5432",
        );
        let (_, ev) = parse_journal_line(&line, "host").unwrap();
        let ev = ev.expect("should parse firewall event");
        assert_eq!(ev.kind, "network.connection_blocked");
        assert_eq!(ev.details["src_ip"], "203.0.113.10");
        assert_eq!(ev.details["dst_ip"], "10.0.0.10");
        assert_eq!(ev.details["dst_port"], 5432);
        assert_eq!(ev.details["proto"], "TCP");
    }

    #[test]
    fn skips_kernel_message_without_firewall_fields() {
        let line = journal_line(
            "kernel",
            "EXT4-fs (vda1): mounted filesystem with ordered data mode",
        );
        let (_, ev) = parse_journal_line(&line, "host").unwrap();
        assert!(ev.is_none());
    }
}
