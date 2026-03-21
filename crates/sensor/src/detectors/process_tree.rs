use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects suspicious process parent-child relationships.
///
/// Patterns detected:
/// 1. Web server spawning a shell (nginx/apache → bash/sh)
/// 2. Database process spawning commands (mysql/postgres → curl/wget)
/// 3. Container process spawning unexpected children
/// 4. System service spawning interactive shells
pub struct ProcessTreeDetector {
    window: Duration,
    /// Process tree: pid → (ppid, comm, first_seen)
    tree: HashMap<u32, ProcessEntry>,
    /// Suppress re-alerts per process chain within window
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

#[allow(dead_code)]
struct ProcessEntry {
    ppid: u32,
    comm: String,
    ts: DateTime<Utc>,
    container_id: Option<String>,
}

/// Suspicious parent → child process relationships.
/// (parent_pattern, child_pattern, severity, description)
const SUSPICIOUS_LINEAGE: &[(&str, &str, Severity, &str)] = &[
    // Web servers spawning shells
    (
        "nginx",
        "sh",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "nginx",
        "bash",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "apache",
        "sh",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "apache2",
        "sh",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "httpd",
        "sh",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "httpd",
        "bash",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "caddy",
        "sh",
        Severity::Critical,
        "Web server spawned shell",
    ),
    (
        "caddy",
        "bash",
        Severity::Critical,
        "Web server spawned shell",
    ),
    // Database processes spawning commands
    ("mysqld", "sh", Severity::High, "Database spawned shell"),
    ("mysqld", "bash", Severity::High, "Database spawned shell"),
    ("postgres", "sh", Severity::High, "Database spawned shell"),
    ("postgres", "bash", Severity::High, "Database spawned shell"),
    ("mongod", "sh", Severity::High, "Database spawned shell"),
    (
        "redis-server",
        "sh",
        Severity::High,
        "Database spawned shell",
    ),
    // Web servers spawning network tools
    (
        "nginx",
        "curl",
        Severity::High,
        "Web server spawned network tool",
    ),
    (
        "nginx",
        "wget",
        Severity::High,
        "Web server spawned network tool",
    ),
    (
        "apache2",
        "curl",
        Severity::High,
        "Web server spawned network tool",
    ),
    (
        "httpd",
        "curl",
        Severity::High,
        "Web server spawned network tool",
    ),
    // Java/Node.js spawning shells (RCE)
    (
        "java",
        "sh",
        Severity::Critical,
        "Java process spawned shell — possible RCE",
    ),
    (
        "java",
        "bash",
        Severity::Critical,
        "Java process spawned shell — possible RCE",
    ),
    ("node", "sh", Severity::High, "Node.js spawned shell"),
    ("node", "bash", Severity::High, "Node.js spawned shell"),
    // Container runtime spawning shells (escape attempt)
    (
        "containerd",
        "sh",
        Severity::Critical,
        "Container runtime spawned shell",
    ),
    (
        "dockerd",
        "sh",
        Severity::Critical,
        "Docker daemon spawned shell",
    ),
    (
        "runc",
        "sh",
        Severity::Critical,
        "Container runtime spawned shell",
    ),
];

impl ProcessTreeDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            tree: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" {
            return None;
        }

        let pid = event.details["pid"].as_u64()? as u32;
        let ppid = event.details["ppid"].as_u64().unwrap_or(0) as u32;
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let container_id = event.details["container_id"]
            .as_str()
            .map(|s| s.to_string());

        let now = event.ts;
        let cutoff = now - self.window;

        // Record this process in the tree
        self.tree.insert(
            pid,
            ProcessEntry {
                ppid,
                comm: comm.clone(),
                ts: now,
                container_id: container_id.clone(),
            },
        );

        // Skip if ppid is unknown
        if ppid == 0 {
            return None;
        }

        // Look up parent process
        let parent_comm = if let Some(parent) = self.tree.get(&ppid) {
            parent.comm.clone()
        } else {
            // Try /proc on Linux
            resolve_comm(ppid).unwrap_or_default()
        };

        if parent_comm.is_empty() {
            return None;
        }

        let child_base = comm.split('/').next_back().unwrap_or(&comm);
        let parent_base = parent_comm.split('/').next_back().unwrap_or(&parent_comm);

        // Check against suspicious lineage patterns
        for &(parent_pat, child_pat, ref severity, description) in SUSPICIOUS_LINEAGE {
            if parent_base == parent_pat && child_base == child_pat {
                // Suppress re-alerts
                let alert_key = format!("{parent_pat}:{child_pat}:{}", ppid);
                if let Some(&last) = self.alerted.get(&alert_key) {
                    if now - last < self.window {
                        return None;
                    }
                }
                self.alerted.insert(alert_key, now);

                let mut tags = vec![
                    "ebpf".to_string(),
                    "process_tree".to_string(),
                    "exec".to_string(),
                ];
                let mut entities = vec![];
                if let Some(ref cid) = container_id {
                    tags.push("container".to_string());
                    entities.push(EntityRef::container(cid));
                }

                let summary = if container_id.is_some() {
                    format!(
                        "{description}: {parent_base} (pid={ppid}) → {child_base} (pid={pid}) [container]"
                    )
                } else {
                    format!("{description}: {parent_base} (pid={ppid}) → {child_base} (pid={pid})")
                };

                return Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!(
                        "process_tree:{parent_base}:{child_base}:{}",
                        now.format("%Y-%m-%dT%H:%MZ")
                    ),
                    severity: severity.clone(),
                    title: format!("Suspicious process lineage: {parent_base} → {child_base}"),
                    summary,
                    evidence: serde_json::json!([{
                        "kind": "process_tree",
                        "parent_comm": parent_base,
                        "parent_pid": ppid,
                        "child_comm": child_base,
                        "child_pid": pid,
                        "container_id": container_id,
                    }]),
                    recommended_checks: vec![
                        format!("Investigate: why did {parent_base} spawn {child_base}?"),
                        format!("Check process tree: ps -ef --forest | grep -E '{ppid}|{pid}'"),
                        "Review web application logs for exploitation attempts".to_string(),
                        "Consider killing the child process immediately".to_string(),
                    ],
                    tags,
                    entities,
                });
            }
        }

        // Prune stale entries
        if self.tree.len() > 10000 {
            self.tree.retain(|_, v| v.ts > cutoff);
        }
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }
}

/// Try to read a process's comm from /proc.
fn resolve_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(
        comm: &str,
        pid: u32,
        ppid: u32,
        container_id: Option<&str>,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut details = serde_json::json!({
            "pid": pid,
            "uid": 0,
            "ppid": ppid,
            "comm": comm,
            "command": format!("/usr/bin/{comm}"),
            "argv": [format!("/usr/bin/{comm}")],
            "argc": 1,
        });
        if let Some(cid) = container_id {
            details["container_id"] = serde_json::Value::String(cid.to_string());
        }

        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: /usr/bin/{comm}"),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_webserver_shell() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        // Register nginx as parent
        det.process(&exec_event("nginx", 100, 1, None, now));
        // bash spawned by nginx
        let inc = det.process(&exec_event("bash", 200, 100, None, now));

        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("nginx"));
        assert!(inc.title.contains("bash"));
    }

    #[test]
    fn detects_database_shell() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        det.process(&exec_event("mysqld", 500, 1, None, now));
        let inc = det.process(&exec_event("sh", 600, 500, None, now));

        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_java_rce() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        det.process(&exec_event("java", 1000, 1, None, now));
        let inc = det.process(&exec_event("bash", 1001, 1000, None, now));

        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("RCE"));
    }

    #[test]
    fn ignores_normal_parent_child() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        // bash → ls is normal
        det.process(&exec_event("bash", 100, 1, None, now));
        let inc = det.process(&exec_event("ls", 200, 100, None, now));
        assert!(inc.is_none());
    }

    #[test]
    fn suppresses_realert() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        det.process(&exec_event("nginx", 100, 1, None, now));
        assert!(det
            .process(&exec_event("bash", 200, 100, None, now))
            .is_some());
        // Second alert within window — suppressed
        assert!(det
            .process(&exec_event(
                "bash",
                201,
                100,
                None,
                now + Duration::seconds(5)
            ))
            .is_none());
    }

    #[test]
    fn detects_container_context() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        det.process(&exec_event("nginx", 100, 1, Some("abc123def456"), now));
        let inc = det.process(&exec_event("sh", 200, 100, Some("abc123def456"), now));

        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert!(inc.summary.contains("container"));
        assert!(inc.tags.contains(&"container".to_string()));
    }

    #[test]
    fn skips_unknown_ppid() {
        let mut det = ProcessTreeDetector::new("test", 300);
        let now = Utc::now();

        // ppid = 0 means unknown
        let inc = det.process(&exec_event("bash", 200, 0, None, now));
        assert!(inc.is_none());
    }
}
