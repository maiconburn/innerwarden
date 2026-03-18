use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Collector struct
// ---------------------------------------------------------------------------

pub struct CloudTrailCollector {
    dir: PathBuf,
    host: String,
    processed: HashSet<String>,
}

impl CloudTrailCollector {
    pub fn new(dir: impl Into<PathBuf>, host: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            host: host.into(),
            processed: HashSet::new(),
        }
    }

    /// Poll the configured directory every 5 seconds for new CloudTrail JSON files.
    /// Each file is expected to contain a JSON object with a "Records" array.
    pub async fn run(mut self, tx: mpsc::Sender<Event>) -> Result<()> {
        info!(
            dir = %self.dir.display(),
            "cloudtrail collector starting"
        );

        loop {
            let dir = self.dir.clone();
            let host = self.host.clone();
            let processed_snapshot = self.processed.clone();

            let result =
                tokio::task::spawn_blocking(move || poll_dir(&dir, &host, &processed_snapshot))
                    .await?;

            match result {
                Ok((events, new_files)) => {
                    for file in new_files {
                        self.processed.insert(file);
                    }
                    for event in events {
                        debug!(kind = %event.kind, summary = %event.summary, "cloudtrail event");
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("cloudtrail poll error: {e:#}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            if tx.is_closed() {
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Directory poller
// ---------------------------------------------------------------------------

fn poll_dir(
    dir: &std::path::Path,
    host: &str,
    processed: &HashSet<String>,
) -> Result<(Vec<Event>, Vec<String>)> {
    if !dir.exists() {
        return Ok((vec![], vec![]));
    }

    let mut events = Vec::new();
    let mut newly_processed = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), "cloudtrail: failed to read directory: {e}");
            return Ok((vec![], vec![]));
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("cloudtrail: failed to read dir entry: {e}");
                continue;
            }
        };

        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        if filename.is_empty() || processed.contains(&filename) {
            continue;
        }

        match process_file(&path, host) {
            Ok(file_events) => {
                events.extend(file_events);
                newly_processed.push(filename);
            }
            Err(e) => {
                warn!(path = %path.display(), "cloudtrail: failed to process file: {e}");
                // Mark as processed anyway to avoid retrying a broken file on every poll
                newly_processed.push(filename);
            }
        }
    }

    Ok((events, newly_processed))
}

fn process_file(path: &std::path::Path, host: &str) -> Result<Vec<Event>> {
    let content = std::fs::read_to_string(path)?;
    let log: CloudTrailLog = serde_json::from_str(&content)?;

    let events = log
        .records
        .into_iter()
        .filter_map(|record| parse_record(record, host))
        .collect();

    Ok(events)
}

// ---------------------------------------------------------------------------
// JSON structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CloudTrailLog {
    #[serde(rename = "Records")]
    records: Vec<CloudTrailRecord>,
}

#[derive(Deserialize)]
struct CloudTrailRecord {
    #[serde(rename = "eventTime")]
    event_time: Option<String>,
    #[serde(rename = "eventSource")]
    event_source: Option<String>,
    #[serde(rename = "eventName")]
    event_name: String,
    #[serde(rename = "awsRegion")]
    aws_region: Option<String>,
    #[serde(rename = "sourceIPAddress")]
    source_ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    error_message: Option<String>,
    #[serde(rename = "userIdentity")]
    user_identity: Option<UserIdentity>,
    #[serde(rename = "eventID")]
    event_id: Option<String>,
}

#[derive(Deserialize)]
struct UserIdentity {
    #[serde(rename = "type")]
    identity_type: Option<String>,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    arn: Option<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn parse_record(record: CloudTrailRecord, host: &str) -> Option<Event> {
    let ts = record
        .event_time
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let event_name = &record.event_name;
    let identity_type = record
        .user_identity
        .as_ref()
        .and_then(|u| u.identity_type.as_deref())
        .unwrap_or("Unknown");
    let user_name = record
        .user_identity
        .as_ref()
        .and_then(|u| u.user_name.as_deref())
        .unwrap_or("");
    let arn = record
        .user_identity
        .as_ref()
        .and_then(|u| u.arn.as_deref())
        .unwrap_or("");

    // Root account usage — always critical regardless of event name
    let is_root = identity_type == "Root";

    let (kind, severity) = classify_event(event_name, &record.error_code, is_root);

    let summary = build_summary(
        event_name,
        user_name,
        &record.error_code,
        &record.error_message,
        is_root,
    );

    // Tags
    let mut tags = vec!["cloudtrail".to_string(), "aws".to_string()];
    if is_root {
        tags.push("root_usage".to_string());
    }
    if let Some(ref region) = record.aws_region {
        tags.push(format!("aws_region:{region}"));
    }

    // Entities
    let mut entities = Vec::new();

    // Source IP (may be an AWS service name like "sts.amazonaws.com" — skip those)
    if let Some(ref ip) = record.source_ip_address {
        if is_routable_ip(ip) {
            entities.push(EntityRef::ip(ip.clone()));
        }
    }

    // User
    if !user_name.is_empty() {
        entities.push(EntityRef::user(user_name.to_string()));
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.r#type.clone(), e.value.clone())));

    let details = serde_json::json!({
        "event_name": event_name,
        "event_source": record.event_source,
        "event_id": record.event_id,
        "aws_region": record.aws_region,
        "source_ip": record.source_ip_address,
        "user_agent": record.user_agent,
        "error_code": record.error_code,
        "error_message": record.error_message,
        "user_identity": {
            "type": identity_type,
            "user_name": user_name,
            "arn": arn,
        },
    });

    Some(Event {
        ts,
        host: host.to_string(),
        source: "cloudtrail".to_string(),
        kind,
        severity,
        summary,
        details,
        tags,
        entities,
    })
}

fn classify_event(
    event_name: &str,
    error_code: &Option<String>,
    is_root: bool,
) -> (String, Severity) {
    if is_root {
        return ("cloud.root_usage".to_string(), Severity::Critical);
    }

    match event_name {
        "ConsoleLogin" => {
            let failed = error_code
                .as_deref()
                .map(|e| e.contains("Failed") || e.contains("Failure"))
                .unwrap_or(false);
            if failed {
                ("cloud.login_failure".to_string(), Severity::Medium)
            } else {
                ("cloud.login_success".to_string(), Severity::Info)
            }
        }
        "CreateUser" | "UpdateUser" | "DeleteUser" | "CreateRole" | "DeleteRole"
        | "AttachUserPolicy" | "DetachUserPolicy" | "CreateAccessKey" | "DeleteAccessKey" => {
            ("cloud.iam_change".to_string(), Severity::High)
        }
        "AuthorizeSecurityGroupIngress"
        | "AuthorizeSecurityGroupEgress"
        | "RevokeSecurityGroupIngress"
        | "RevokeSecurityGroupEgress"
        | "CreateSecurityGroup"
        | "DeleteSecurityGroup" => ("cloud.security_group_change".to_string(), Severity::High),
        "GetSecretValue" | "DescribeSecret" | "ListSecrets" => {
            ("cloud.secrets_access".to_string(), Severity::Medium)
        }
        "StopLogging" | "DeleteTrail" | "UpdateTrail" | "DeleteFlowLogs" => {
            ("cloud.audit_tampering".to_string(), Severity::Critical)
        }
        _ => ("cloud.api_call".to_string(), Severity::Info),
    }
}

fn build_summary(
    event_name: &str,
    user_name: &str,
    error_code: &Option<String>,
    error_message: &Option<String>,
    is_root: bool,
) -> String {
    if is_root {
        return format!("Root account used: {event_name}");
    }
    let user_part = if user_name.is_empty() {
        String::new()
    } else {
        format!(" by {user_name}")
    };
    if let Some(ref ec) = error_code {
        let msg_part = error_message
            .as_deref()
            .map(|m| format!(": {}", &m[..m.len().min(100)]))
            .unwrap_or_default();
        format!("{event_name} failed{user_part} ({ec}{msg_part})")
    } else {
        format!("{event_name}{user_part}")
    }
}

/// Returns true for strings that look like routable IP addresses (not AWS service names).
fn is_routable_ip(s: &str) -> bool {
    // AWS service calls often have "sts.amazonaws.com", "ec2.amazonaws.com" etc. as sourceIPAddress
    if s.contains('.') && s.contains("amazonaws") {
        return false;
    }
    if s == "AWS Internal" {
        return false;
    }
    // Try parsing as IP
    s.parse::<std::net::IpAddr>().is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityType;

    fn make_record(
        event_name: &str,
        error_code: Option<&str>,
        identity_type: &str,
        user_name: &str,
        source_ip: &str,
    ) -> CloudTrailRecord {
        CloudTrailRecord {
            event_time: Some("2024-01-15T03:14:15Z".to_string()),
            event_source: Some("signin.amazonaws.com".to_string()),
            event_name: event_name.to_string(),
            aws_region: Some("us-east-1".to_string()),
            source_ip_address: if source_ip.is_empty() {
                None
            } else {
                Some(source_ip.to_string())
            },
            user_agent: Some("Mozilla/5.0".to_string()),
            error_code: error_code.map(|s| s.to_string()),
            error_message: error_code.map(|s| format!("{s} description")),
            user_identity: Some(UserIdentity {
                identity_type: Some(identity_type.to_string()),
                user_name: if user_name.is_empty() {
                    None
                } else {
                    Some(user_name.to_string())
                },
                arn: Some("arn:aws:iam::123456789:user/alice".to_string()),
            }),
            event_id: Some("abc123".to_string()),
        }
    }

    #[test]
    fn parse_console_login_failure() {
        let record = make_record(
            "ConsoleLogin",
            Some("Failed authentication"),
            "IAMUser",
            "alice",
            "203.0.113.47",
        );
        let ev = parse_record(record, "host1").unwrap();
        assert_eq!(ev.source, "cloudtrail");
        assert_eq!(ev.kind, "cloud.login_failure");
        assert_eq!(ev.severity, Severity::Medium);
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Ip))
            .collect();
        assert!(ips.iter().any(|e| e.value == "203.0.113.47"));
        let users: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::User))
            .collect();
        assert!(users.iter().any(|e| e.value == "alice"));
    }

    #[test]
    fn parse_iam_change() {
        let record = make_record("CreateUser", None, "IAMUser", "admin", "198.51.100.10");
        let ev = parse_record(record, "host1").unwrap();
        assert_eq!(ev.kind, "cloud.iam_change");
        assert_eq!(ev.severity, Severity::High);
    }

    #[test]
    fn parse_root_usage() {
        let record = make_record("ListBuckets", None, "Root", "", "198.51.100.20");
        let ev = parse_record(record, "host1").unwrap();
        assert_eq!(ev.kind, "cloud.root_usage");
        assert_eq!(ev.severity, Severity::Critical);
        assert!(ev.tags.contains(&"root_usage".to_string()));
    }

    #[test]
    fn parse_audit_tampering() {
        let record = make_record("StopLogging", None, "IAMUser", "attacker", "198.51.100.30");
        let ev = parse_record(record, "host1").unwrap();
        assert_eq!(ev.kind, "cloud.audit_tampering");
        assert_eq!(ev.severity, Severity::Critical);
    }

    #[test]
    fn unknown_event_returns_info_level() {
        let record = make_record("DescribeInstances", None, "IAMUser", "svc", "198.51.100.40");
        let ev = parse_record(record, "host1").unwrap();
        assert_eq!(ev.kind, "cloud.api_call");
        assert_eq!(ev.severity, Severity::Info);
    }

    #[test]
    fn aws_service_ip_not_extracted() {
        let record = make_record("AssumeRole", None, "AssumedRole", "", "sts.amazonaws.com");
        let ev = parse_record(record, "host1").unwrap();
        let ips: Vec<_> = ev
            .entities
            .iter()
            .filter(|e| matches!(e.r#type, EntityType::Ip))
            .collect();
        assert!(
            ips.is_empty(),
            "AWS service hostname should not be extracted as IP entity"
        );
    }
}
