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

pub struct DockerCollector {
    host: String,
    /// Unix timestamp string for `--since` on restart. None = tail from now.
    since: Option<String>,
}

impl DockerCollector {
    pub fn new(host: impl Into<String>, since: Option<String>) -> Self {
        Self {
            host: host.into(),
            since,
        }
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
                                    let is_start = event.kind == "container.start";
                                    let container_id = event.details["container_id"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    let name = event.details["name"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    let image = event.details["image"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    let host = self.host.clone();

                                    current_since = Some(since.clone());
                                    *shared_since.lock().unwrap() = Some(since);
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return Ok(());
                                    }

                                    // On container start, inspect for privilege escalation risks.
                                    // Fire-and-forget — a failed inspect never disrupts the event loop.
                                    if is_start && !container_id.is_empty() {
                                        let tx2 = tx.clone();
                                        tokio::spawn(async move {
                                            let risk_events =
                                                inspect_for_risks(&container_id, &name, &image, &host)
                                                    .await;
                                            for ev in risk_events {
                                                if tx2.send(ev).await.is_err() {
                                                    break;
                                                }
                                            }
                                        });
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
    let name = v["Actor"]["Attributes"]["name"]
        .as_str()
        .unwrap_or(short_id);
    let image = v["Actor"]["Attributes"]["image"]
        .as_str()
        .unwrap_or("unknown");

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
        entities: vec![EntityRef::container(name.to_string())],
    };

    Some((next_since, event))
}

// ---------------------------------------------------------------------------
// Privilege escalation inspection
// ---------------------------------------------------------------------------

/// Run `docker inspect <container_id>` and return security risk events.
/// Returns an empty Vec if the container is safe or inspect fails (fail-open).
async fn inspect_for_risks(
    container_id: &str,
    name: &str,
    image: &str,
    host: &str,
) -> Vec<Event> {
    let output = match Command::new("docker")
        .args(["inspect", container_id])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            warn!(
                container_id,
                "docker inspect returned non-zero: {}",
                String::from_utf8_lossy(&o.stderr).chars().take(200).collect::<String>()
            );
            return vec![];
        }
        Err(e) => {
            warn!(container_id, "docker inspect failed: {e}");
            return vec![];
        }
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&output) {
        Ok(v) => v,
        Err(e) => {
            warn!(container_id, "docker inspect parse error: {e}");
            return vec![];
        }
    };

    // `docker inspect` returns an array; take the first element.
    let info = &parsed[0];
    parse_inspect_risks(info, container_id, name, image, host)
}

/// Parse `docker inspect` JSON for privilege escalation risks.
/// Returns one event per risk type detected.
///
/// Risks checked:
/// - `HostConfig.Privileged == true` — full host kernel access
/// - `HostConfig.Binds` contains `/var/run/docker.sock` — daemon socket mount
/// - `HostConfig.CapAdd` contains `SYS_ADMIN` or `NET_ADMIN` — dangerous capabilities
pub(crate) fn parse_inspect_risks(
    info: &serde_json::Value,
    container_id: &str,
    name: &str,
    image: &str,
    host: &str,
) -> Vec<Event> {
    let mut events = Vec::new();

    let host_config = &info["HostConfig"];

    // Check --privileged flag
    if host_config["Privileged"].as_bool().unwrap_or(false) {
        events.push(make_risk_event(
            "container.privileged",
            Severity::High,
            format!("Privileged container started: {name} ({image})"),
            format!("Container '{name}' started with --privileged flag, granting full host kernel access. This bypasses all container security boundaries."),
            container_id,
            name,
            image,
            host,
            serde_json::json!({ "risk": "privileged", "privileged": true }),
        ));
    }

    // Check docker.sock bind mounts
    let sock_path = "/var/run/docker.sock";
    let has_sock_mount = host_config["Binds"]
        .as_array()
        .map(|binds| {
            binds.iter().any(|b| {
                b.as_str()
                    .map(|s| s.starts_with(sock_path))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
        || info["Mounts"]
            .as_array()
            .map(|mounts| {
                mounts.iter().any(|m| {
                    m["Source"].as_str().unwrap_or("") == sock_path
                        || m["Destination"].as_str().unwrap_or("") == sock_path
                })
            })
            .unwrap_or(false);

    if has_sock_mount {
        events.push(make_risk_event(
            "container.sock_mount",
            Severity::High,
            format!("Docker socket mounted in container: {name} ({image})"),
            format!("Container '{name}' has /var/run/docker.sock mounted, enabling full Docker daemon control from inside the container (container escape vector)."),
            container_id,
            name,
            image,
            host,
            serde_json::json!({ "risk": "sock_mount", "path": sock_path }),
        ));
    }

    // Check dangerous capabilities
    let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"];
    let cap_add: Vec<String> = host_config["CapAdd"]
        .as_array()
        .map(|caps| {
            caps.iter()
                .filter_map(|c| c.as_str().map(|s| s.to_uppercase()))
                .collect()
        })
        .unwrap_or_default();

    let matched_caps: Vec<&str> = dangerous_caps
        .iter()
        .filter(|cap| cap_add.iter().any(|c| c == **cap))
        .copied()
        .collect();

    if !matched_caps.is_empty() {
        let caps_str = matched_caps.join(", ");
        events.push(make_risk_event(
            "container.dangerous_cap",
            Severity::Medium,
            format!("Dangerous capabilities in container: {name} ({image})"),
            format!("Container '{name}' was granted dangerous Linux capabilities: {caps_str}. These can be used for privilege escalation or container escape."),
            container_id,
            name,
            image,
            host,
            serde_json::json!({ "risk": "dangerous_cap", "capabilities": matched_caps }),
        ));
    }

    events
}

#[allow(clippy::too_many_arguments)]
fn make_risk_event(
    kind: &str,
    severity: Severity,
    summary: String,
    description: String,
    container_id: &str,
    name: &str,
    image: &str,
    host: &str,
    risk_details: serde_json::Value,
) -> Event {
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "docker".to_string(),
        kind: kind.to_string(),
        severity,
        summary,
        details: serde_json::json!({
            "container_id": container_id,
            "name": name,
            "image": image,
            "description": description,
            "risk": risk_details,
        }),
        tags: vec![
            "container".to_string(),
            "docker".to_string(),
            "security".to_string(),
            "privilege-escalation".to_string(),
        ],
        entities: vec![EntityRef::container(name.to_string())],
    }
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

    // ---------------------------------------------------------------------------
    // Privilege escalation inspection tests
    // ---------------------------------------------------------------------------

    fn make_inspect_json(privileged: bool, binds: &[&str], cap_add: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "HostConfig": {
                "Privileged": privileged,
                "Binds": binds,
                "CapAdd": cap_add,
            },
            "Mounts": []
        })
    }

    #[test]
    fn privileged_flag_emits_high_event() {
        let info = make_inspect_json(true, &[], &[]);
        let events = parse_inspect_risks(&info, "abc123", "myapp", "myapp:v1", "host");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "container.privileged");
        assert_eq!(events[0].severity, Severity::High);
        assert!(events[0].summary.contains("myapp"));
    }

    #[test]
    fn sock_mount_via_binds_emits_high_event() {
        let info = make_inspect_json(false, &["/var/run/docker.sock:/var/run/docker.sock"], &[]);
        let events = parse_inspect_risks(&info, "abc123", "agent", "portainer:latest", "host");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "container.sock_mount");
        assert_eq!(events[0].severity, Severity::High);
    }

    #[test]
    fn sock_mount_via_mounts_array() {
        let info = serde_json::json!({
            "HostConfig": { "Privileged": false, "Binds": [], "CapAdd": [] },
            "Mounts": [{ "Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock" }]
        });
        let events = parse_inspect_risks(&info, "abc123", "agent", "img:1", "host");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "container.sock_mount");
    }

    #[test]
    fn dangerous_cap_sys_admin_emits_medium_event() {
        let info = make_inspect_json(false, &[], &["SYS_ADMIN"]);
        let events = parse_inspect_risks(&info, "abc123", "myapp", "myapp:v1", "host");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "container.dangerous_cap");
        assert_eq!(events[0].severity, Severity::Medium);
        assert!(events[0].summary.contains("myapp"));
    }

    #[test]
    fn multiple_risks_emit_multiple_events() {
        let info = make_inspect_json(true, &["/var/run/docker.sock:/var/run/docker.sock"], &["SYS_ADMIN"]);
        let events = parse_inspect_risks(&info, "abc123", "rogue", "rogue:v1", "host");
        assert_eq!(events.len(), 3);
        let kinds: Vec<_> = events.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"container.privileged"));
        assert!(kinds.contains(&"container.sock_mount"));
        assert!(kinds.contains(&"container.dangerous_cap"));
    }

    #[test]
    fn safe_container_emits_no_risk_events() {
        let info = make_inspect_json(false, &[], &[]);
        let events = parse_inspect_risks(&info, "abc123", "nginx", "nginx:latest", "host");
        assert!(events.is_empty());
    }

    #[test]
    fn non_docker_sock_bind_is_safe() {
        let info = make_inspect_json(false, &["/data:/data:ro"], &[]);
        let events = parse_inspect_risks(&info, "abc123", "db", "postgres:14", "host");
        assert!(events.is_empty());
    }

    #[test]
    fn cap_add_net_admin_detected() {
        let info = make_inspect_json(false, &[], &["NET_ADMIN"]);
        let events = parse_inspect_risks(&info, "abc123", "vpn", "openvpn:latest", "host");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "container.dangerous_cap");
    }

    #[test]
    fn benign_cap_add_not_flagged() {
        let info = make_inspect_json(false, &[], &["NET_BIND_SERVICE"]);
        let events = parse_inspect_risks(&info, "abc123", "web", "nginx:latest", "host");
        assert!(events.is_empty());
    }

    #[test]
    fn events_have_privilege_escalation_tag() {
        let info = make_inspect_json(true, &[], &[]);
        let events = parse_inspect_risks(&info, "abc123", "app", "img:1", "host");
        assert!(events[0].tags.contains(&"privilege-escalation".to_string()));
    }
}
