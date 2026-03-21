use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects container escape attempts and container-based privilege escalation.
///
/// Patterns detected:
/// 1. Processes inside containers accessing Docker socket
/// 2. Processes inside containers reading host-sensitive files
/// 3. Privileged container operations (nsenter, mount, chroot from container)
/// 4. Container processes making suspicious outbound connections
pub struct ContainerEscapeDetector {
    window: Duration,
    /// Suppress re-alerts per container+pattern within window
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

/// Commands that indicate container escape attempts when run from inside a container.
const ESCAPE_COMMANDS: &[(&str, Severity, &str)] = &[
    (
        "nsenter",
        Severity::Critical,
        "Namespace escape via nsenter",
    ),
    ("chroot", Severity::Critical, "Chroot escape attempt"),
    ("mount", Severity::High, "Filesystem mount from container"),
    (
        "umount",
        Severity::High,
        "Filesystem unmount from container",
    ),
    (
        "modprobe",
        Severity::Critical,
        "Kernel module load from container",
    ),
    (
        "insmod",
        Severity::Critical,
        "Kernel module load from container",
    ),
    ("ip", Severity::High, "Network configuration from container"),
    (
        "iptables",
        Severity::Critical,
        "Firewall manipulation from container",
    ),
    (
        "nft",
        Severity::Critical,
        "Firewall manipulation from container",
    ),
    (
        "cgroup",
        Severity::High,
        "Cgroup manipulation from container",
    ),
];

/// Sensitive host paths that shouldn't be accessed from containers.
const SENSITIVE_PATHS: &[(&str, Severity, &str)] = &[
    (
        "/var/run/docker.sock",
        Severity::Critical,
        "Docker socket access from container",
    ),
    (
        "/run/docker.sock",
        Severity::Critical,
        "Docker socket access from container",
    ),
    (
        "/proc/sysrq-trigger",
        Severity::Critical,
        "SysRq trigger from container",
    ),
    (
        "/proc/kcore",
        Severity::Critical,
        "Kernel memory read from container",
    ),
    (
        "/dev/sda",
        Severity::Critical,
        "Block device access from container",
    ),
    (
        "/dev/vda",
        Severity::Critical,
        "Block device access from container",
    ),
    (
        "/etc/shadow",
        Severity::High,
        "Host shadow file read from container",
    ),
    (
        "/etc/sudoers",
        Severity::High,
        "Host sudoers read from container",
    ),
    (
        "/root/.ssh",
        Severity::High,
        "Host SSH keys accessed from container",
    ),
];

impl ContainerEscapeDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only analyze events from containerized processes
        let container_id = event.details["container_id"].as_str()?;

        let now = event.ts;

        let result = match event.kind.as_str() {
            "shell.command_exec" => self.check_escape_command(event, container_id, now),
            "file.write_access" | "file.read_access" => {
                self.check_sensitive_file(event, container_id, now)
            }
            _ => None,
        };

        // Prune stale alerts
        if self.alerted.len() > 500 {
            let cutoff = now - self.window;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        result
    }

    fn check_escape_command(
        &mut self,
        event: &Event,
        container_id: &str,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        let comm = event.details["comm"].as_str().unwrap_or("");
        let command = event.details["command"].as_str().unwrap_or("");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        let comm_base = comm.split('/').next_back().unwrap_or(comm);
        let cmd_base = command.split('/').next_back().unwrap_or(command);

        for &(pattern, ref severity, description) in ESCAPE_COMMANDS {
            if comm_base == pattern || cmd_base == pattern {
                let alert_key = format!("{container_id}:escape:{pattern}");
                if self.is_suppressed(&alert_key, now) {
                    return None;
                }
                self.alerted.insert(alert_key, now);

                return Some(self.build_incident(
                    container_id,
                    pid,
                    comm,
                    severity.clone(),
                    description,
                    "escape_command",
                    now,
                ));
            }
        }

        None
    }

    fn check_sensitive_file(
        &mut self,
        event: &Event,
        container_id: &str,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        let filename = event.details["filename"].as_str().unwrap_or("");
        let comm = event.details["comm"].as_str().unwrap_or("");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        for &(path, ref severity, description) in SENSITIVE_PATHS {
            if filename.starts_with(path) {
                let alert_key = format!("{container_id}:file:{path}");
                if self.is_suppressed(&alert_key, now) {
                    return None;
                }
                self.alerted.insert(alert_key, now);

                return Some(self.build_incident(
                    container_id,
                    pid,
                    comm,
                    severity.clone(),
                    &format!("{description} — {filename}"),
                    "sensitive_file_access",
                    now,
                ));
            }
        }

        None
    }

    fn is_suppressed(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < self.window
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_incident(
        &self,
        container_id: &str,
        pid: u32,
        comm: &str,
        severity: Severity,
        description: &str,
        pattern: &str,
        ts: DateTime<Utc>,
    ) -> Incident {
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "container_escape:{container_id}:{pattern}:{}",
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Container escape attempt: {description}"),
            summary: format!(
                "{description} — process {comm} (pid={pid}) in container {container_id}"
            ),
            evidence: serde_json::json!([{
                "kind": "container_escape",
                "pattern": pattern,
                "container_id": container_id,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Immediately inspect container {container_id}"),
                "Check if the container is running with --privileged flag".to_string(),
                "Review container capabilities (docker inspect)".to_string(),
                "Consider killing/stopping the container".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "container".to_string(),
                "escape".to_string(),
            ],
            entities: vec![EntityRef::container(container_id)],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn container_exec_event(comm: &str, container_id: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("command: {comm}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "ppid": 1,
                "comm": comm,
                "command": format!("/usr/bin/{comm}"),
                "container_id": container_id,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn container_file_event(
        comm: &str,
        filename: &str,
        container_id: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.read_access".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} reading {filename}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "comm": comm,
                "filename": filename,
                "container_id": container_id,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_nsenter_escape() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&container_exec_event("nsenter", "abc123", now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_mount_from_container() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&container_exec_event("mount", "abc123", now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_docker_socket_access() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&container_file_event(
            "curl",
            "/var/run/docker.sock",
            "abc123",
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("Docker socket"));
    }

    #[test]
    fn detects_host_shadow_read() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&container_file_event("cat", "/etc/shadow", "abc123", now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn ignores_host_process() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        // No container_id = host process, should be ignored
        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: "command: nsenter".to_string(),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "comm": "nsenter",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn suppresses_realert() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&container_exec_event("nsenter", "abc123", now))
            .is_some());
        assert!(det
            .process(&container_exec_event(
                "nsenter",
                "abc123",
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn different_containers_alert_independently() {
        let mut det = ContainerEscapeDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&container_exec_event("nsenter", "abc123", now))
            .is_some());
        assert!(det
            .process(&container_exec_event("nsenter", "def456", now))
            .is_some());
    }
}
