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

pub struct MacosLogCollector {
    host: String,
}

impl MacosLogCollector {
    pub fn new(host: impl Into<String>) -> Self {
        Self { host: host.into() }
    }

    /// Stream macOS system log events via `log stream`.
    /// Parses SSH and sudo events from the output.
    pub async fn run(self, tx: mpsc::Sender<Event>) -> Result<()> {
        // Check if `log` binary is available
        let check = Command::new("log")
            .arg("version")
            .output()
            .await;
        match check {
            Err(_) => {
                warn!("log binary not found — macos_log collector disabled");
                return Ok(());
            }
            Ok(out) if !out.status.success() => {
                warn!("log version check failed — macos_log collector disabled");
                return Ok(());
            }
            _ => {}
        }

        info!(host = %self.host, "macos_log collector starting");

        // Restart loop — if `log stream` exits unexpectedly, restart it.
        loop {
            let mut cmd = Command::new("log");
            cmd.args([
                "stream",
                "--predicate",
                "process == \"sshd\" OR process == \"sudo\"",
                "--style",
                "syslog",
                "--info",
            ])
            .stdout(std::process::Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    warn!("failed to spawn log stream: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let stdout = child.stdout.take().expect("stdout piped");
            let mut lines = BufReader::new(stdout).lines();

            loop {
                tokio::select! {
                    result = lines.next_line() => {
                        match result {
                            Ok(Some(line)) => {
                                if let Some(event) = parse_macos_log_line(&line, &self.host) {
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return Ok(());
                                    }
                                }
                            }
                            Ok(None) => break, // log stream exited
                            Err(e) => {
                                warn!("macos_log read error: {e}");
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

            warn!("log stream exited unexpectedly — restarting in 5s");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one line from `log stream --style syslog` output.
///
/// The syslog format looks like:
///   Jan 15 15:00:01.123 hostname sshd[1234]: <message>
///   Jan 15 15:00:01.123 hostname sudo[5678]: <message>
///
/// Returns `None` if the line is not an SSH or sudo event we care about.
fn parse_macos_log_line(line: &str, host: &str) -> Option<Event> {
    // Must contain a process marker we care about
    if line.contains("sshd[") {
        // Extract message after "sshd[pid]: "
        let msg = line.split_once("]: ")?.1.trim();
        return parse_sshd_message(msg, host, "macos_log");
    }

    if line.contains("sudo[") {
        return parse_macos_sudo_line(line, host);
    }

    None
}

/// Parse a sudo log line from macOS log stream output.
/// Example:
///   Jan 15 15:00:01.123 hostname sudo[1234]: deploy : TTY=ttys001 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id
fn parse_macos_sudo_line(line: &str, host: &str) -> Option<Event> {
    // Must contain USER= and COMMAND= to be a command execution entry
    if !line.contains("USER=") || !line.contains("COMMAND=") {
        return None;
    }

    // Extract message after "sudo[pid]: "
    let msg = line.split_once("]: ")?.1.trim();

    let sudo_user = msg.split(':').next()?.trim();
    let run_as = field_after(msg, "USER=")?;
    let command = field_after(msg, "COMMAND=")?;

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "macos_log".to_string(),
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

    #[test]
    fn line_with_sshd_is_recognized() {
        let line = "Jan 15 15:00:01.123 mymac sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 55123 ssh2";
        let ev = parse_macos_log_line(line, "mymac").expect("should parse SSH event");
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.source, "macos_log");
        assert_eq!(ev.details["ip"], "1.2.3.4");
        assert_eq!(ev.details["user"], "admin");
    }

    #[test]
    fn line_without_sshd_returns_none() {
        let line = "Jan 15 15:00:01.123 mymac kernel[0]: Some random kernel message";
        assert!(parse_macos_log_line(line, "mymac").is_none());
    }

    #[test]
    fn sudo_line_is_recognized() {
        let line = "Jan 15 15:00:01.123 mymac sudo[5678]: deploy : TTY=ttys001 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id";
        let ev = parse_macos_log_line(line, "mymac").expect("should parse sudo event");
        assert_eq!(ev.kind, "sudo.command");
        assert_eq!(ev.source, "macos_log");
        assert_eq!(ev.details["user"], "deploy");
        assert_eq!(ev.details["run_as"], "root");
        assert!(ev.details["command"].as_str().unwrap().contains("/usr/bin/id"));
    }
}
