use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{entities::EntityRef, event::{Event, Severity}};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct DockerCollector {
    host: String,
    /// Unix timestamp string for `--since` on restart. None = tail from now.
    since: Option<String>,
}

impl DockerCollector {
    pub fn new(host: impl Into<String>, since: Option<String>) -> Self {
        Self { host: host.into(), since }
    }

    /// Stream Docker events via `docker events --format '{{json .}}'`.
    /// `shared_since` is updated after each event so callers can persist it on shutdown.
    pub async fn run(
        self,
        tx: mpsc::Sender<Event>,
        shared_since: Arc<Mutex<Option<String>>>,
    ) -> Result<()> {
        // Verify docker binary is available. `docker version` is lightweight
        // (doesn't require daemon contact for the client section) and is much
        // faster than `docker info` which queries the daemon's full status.
        let check = Command::new("docker").arg("version").output().await;
        match check {
            Err(_) => {
                warn!("docker binary not found — docker collector disabled");
                return Ok(());
            }
            Ok(out) if !out.status.success() => {
                warn!("docker version check failed — docker collector disabled");
                return Ok(());
            }
            _ => {}
        }

        info!(since = ?self.since, "docker collector starting");

        let mut current_since = self.since.clone();
        loop {
            let mut cmd = Command::new("docker");
            cmd.arg("events")
                .arg("--format")
                .arg("{{json .}}")
                .stdout(std::process::Stdio::piped());

            if let Some(ref ts) = current_since {
                cmd.arg("--since").arg(ts);
            }

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    warn!("failed to spawn docker events: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
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
                                if let Some((since, event)) = parse_docker_event(&line, &self.host) {
                                    current_since = Some(since.clone());
                                    *shared_since.lock().unwrap() = Some(since);
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return Ok(());
                                    }
                                }
                            }
                            Ok(None) => break, // docker exited
                            Err(e) => {
                                warn!("docker events read error: {e}");
                                break;
                            }
                        }
                    }
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

            warn!("docker events exited unexpectedly — restarting in 5s");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Docker event JSON from `docker events --format '{{json .}}'`:
/// {
///   "Type": "container",
///   "Action": "start" | "stop" | "die" | "kill" | "oom" | "create" | "destroy",
///   "Actor": { "ID": "abc123...", "Attributes": { "name": "...", "image": "..." } },
///   "time": 1234567890,
///   "timeNano": 1234567890123456789
/// }
fn parse_docker_event(line: &str, host: &str) -> Option<(String, Event)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let event_type = v["Type"].as_str()?;
    let action = v["Action"].as_str()?;
    let unix_ts = v["time"].as_i64()?;

    // Only handle container events we care about
    if event_type != "container" {
        return None;
    }

    let relevant_actions = ["start", "stop", "die", "kill", "oom", "destroy", "create"];
    if !relevant_actions.contains(&action) {
        return None;
    }

    let container_id = v["Actor"]["ID"].as_str().unwrap_or("unknown");
    let short_id = &container_id[..container_id.len().min(12)];
    let name = v["Actor"]["Attributes"]["name"].as_str().unwrap_or(short_id);
    let image = v["Actor"]["Attributes"]["image"].as_str().unwrap_or("unknown");

    let severity = match action {
        "oom" | "kill" => Severity::High,
        "die" => Severity::Medium,
        _ => Severity::Info,
    };

    let kind = format!("container.{action}");
    let summary = format!("Container {action}: {name} ({image})");

    // Use the event unix timestamp + 1 as `--since` for next run (avoids re-emitting last event)
    let next_since = (unix_ts + 1).to_string();

    let event = Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "docker".to_string(),
        kind,
        severity,
        summary,
        details: serde_json::json!({
            "container_id": short_id,
            "name": name,
            "image": image,
            "action": action,
        }),
        tags: vec!["container".to_string(), "docker".to_string()],
        entities: vec![
            EntityRef::container(name.to_string()),
        ],
    };

    Some((next_since, event))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn event_json(event_type: &str, action: &str, name: &str, image: &str) -> String {
        serde_json::json!({
            "Type": event_type,
            "Action": action,
            "Actor": {
                "ID": "abc123def456xyz",
                "Attributes": { "name": name, "image": image }
            },
            "time": 1741788000i64,
            "timeNano": 1741788000000000000i64,
        })
        .to_string()
    }

    #[test]
    fn container_start_emits_event() {
        let line = event_json("container", "start", "nginx", "nginx:latest");
        let (since, ev) = parse_docker_event(&line, "host").unwrap();
        assert_eq!(ev.kind, "container.start");
        assert_eq!(ev.severity, Severity::Info);
        assert_eq!(ev.details["name"], "nginx");
        assert_eq!(ev.details["image"], "nginx:latest");
        assert_eq!(since, "1741788001");
    }

    #[test]
    fn container_die_is_medium_severity() {
        let line = event_json("container", "die", "app", "myapp:v1");
        let (_, ev) = parse_docker_event(&line, "host").unwrap();
        assert_eq!(ev.kind, "container.die");
        assert_eq!(ev.severity, Severity::Medium);
    }

    #[test]
    fn container_oom_is_high_severity() {
        let line = event_json("container", "oom", "worker", "myapp:v1");
        let (_, ev) = parse_docker_event(&line, "host").unwrap();
        assert_eq!(ev.kind, "container.oom");
        assert_eq!(ev.severity, Severity::High);
    }

    #[test]
    fn non_container_events_are_skipped() {
        let line = event_json("network", "connect", "bridge", "");
        assert!(parse_docker_event(&line, "host").is_none());
    }

    #[test]
    fn uninteresting_actions_are_skipped() {
        let line = event_json("container", "exec_start", "app", "myapp:v1");
        assert!(parse_docker_event(&line, "host").is_none());
    }
}
