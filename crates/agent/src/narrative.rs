use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_core::{
    entities::EntityType,
    event::{Event, Severity},
    incident::Incident,
};

use crate::correlation;

// ---------------------------------------------------------------------------
// Responder context for smart recommendations
// ---------------------------------------------------------------------------

/// Responder state passed into narrative generation so "What to check"
/// recommendations can be context-aware.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponderHint {
    pub enabled: bool,
    pub dry_run: bool,
    /// Whether `block-ip-*` is among the allowed skills.
    pub has_block_ip: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a Markdown daily summary from all events and incidents for a date.
/// Convenience wrapper that uses default (disabled) responder hints.
#[allow(dead_code)]
pub fn generate(
    date: &str,
    host: &str,
    events: &[Event],
    incidents: &[Incident],
    correlation_window_secs: u64,
) -> String {
    generate_with_responder(
        date,
        host,
        events,
        incidents,
        correlation_window_secs,
        ResponderHint::default(),
    )
}

/// Same as [`generate`] but with responder context for smart recommendations.
pub fn generate_with_responder(
    date: &str,
    host: &str,
    events: &[Event],
    incidents: &[Incident],
    correlation_window_secs: u64,
    responder: ResponderHint,
) -> String {
    let mut out = String::with_capacity(2048);

    // Header
    out.push_str(&format!("# Inner Warden — {date}\n\n"));

    // TL;DR summary at the top
    let high_plus = incidents
        .iter()
        .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
        .count();
    let tldr = if incidents.is_empty() {
        format!(
            "✅ Quiet day on **{host}** — no threats detected out of {} logged events.",
            events.len()
        )
    } else if high_plus == 0 {
        format!(
            "🟡 **{host}** had {} low-severity alert{} today across {} logged events. Nothing critical.",
            incidents.len(),
            if incidents.len() == 1 { "" } else { "s" },
            events.len()
        )
    } else {
        format!(
            "🔴 **{host}** had {} high-priority alert{} today ({} total, {} logged events). Review below.",
            high_plus,
            if high_plus == 1 { "" } else { "s" },
            incidents.len(),
            events.len()
        )
    };
    out.push_str(&format!("{tldr}\n\n"));
    out.push_str("---\n\n");

    // Incidents section — group repeated incidents by (first IP, title)
    if incidents.is_empty() {
        out.push_str("## Threats\n\nNo threats detected today.\n\n");
    } else {
        out.push_str("## Threats\n\n");

        // Build groups keyed by (first_ip_or_empty, normalised_title)
        let groups = group_incidents(incidents);

        // Sort groups by highest severity (descending)
        let mut sorted_groups: Vec<&IncidentGroup> = groups.values().collect();
        sorted_groups
            .sort_by(|a, b| severity_rank(&b.max_severity).cmp(&severity_rank(&a.max_severity)));

        for group in &sorted_groups {
            let icon = severity_icon(&group.max_severity);
            let sev_label = severity_plain(&group.max_severity);
            let representative = group.first;

            if group.count == 1 {
                // Single incident — original format
                let time = representative.ts.format("%H:%M UTC").to_string();
                out.push_str(&format!("### {icon} {}\n\n", representative.title));
                out.push_str(&format!("- **Severity:** {sev_label}\n"));
                out.push_str(&format!("- **When:** {time}\n"));
                out.push_str(&format!(
                    "- **What happened:** {}\n",
                    representative.summary
                ));
            } else {
                // Grouped incidents
                let first_time = group.first_ts.format("%H:%M");
                let last_time = group.last_ts.format("%H:%M");
                let title = if group.ip.is_empty() {
                    representative.title.clone()
                } else {
                    format!("{} ({})", representative.title, group.ip)
                };
                out.push_str(&format!("### {icon} {title}\n\n"));
                out.push_str(&format!("- **Severity:** {sev_label}\n"));
                out.push_str(&format!(
                    "- **When:** {} incidents between {first_time}–{last_time} UTC\n",
                    group.count
                ));
                out.push_str(&format!(
                    "- **What happened:** {}\n",
                    representative.summary
                ));
            }

            // Smart "What to check" (Fix 2)
            let checks = smart_checks(&representative.recommended_checks, responder);
            if !checks.is_empty() {
                out.push_str("- **What to check:**\n");
                for check in &checks {
                    out.push_str(&format!("  - {check}\n"));
                }
            }
            out.push('\n');
        }
    }

    // Related activity (clusters)
    if incidents.len() > 1 {
        let clusters: Vec<correlation::IncidentCluster> =
            correlation::build_clusters(incidents, correlation_window_secs)
                .into_iter()
                .filter(|cluster| cluster.size() >= 2)
                .collect();

        if !clusters.is_empty() {
            out.push_str("## Related activity\n\n");
            for cluster in clusters {
                let kinds: Vec<String> = cluster
                    .detector_kinds
                    .iter()
                    .map(|k| human_detector_name(k))
                    .collect();
                let window = format!(
                    "{} – {} UTC",
                    cluster.start_ts.format("%H:%M"),
                    cluster.end_ts.format("%H:%M")
                );
                out.push_str(&format!(
                    "- **{}** triggered {} alerts ({}) between {}\n",
                    format_pivot(&cluster.pivot),
                    cluster.size(),
                    kinds.join(", "),
                    window
                ));
            }
            out.push('\n');
        }
    }

    // Activity breakdown
    if !events.is_empty() {
        out.push_str("## Activity breakdown\n\n");
        out.push_str("| Activity | Count |\n");
        out.push_str("|----------|-------|\n");

        let mut by_kind: HashMap<&str, usize> = HashMap::new();
        for ev in events {
            *by_kind.entry(ev.kind.as_str()).or_insert(0) += 1;
        }
        let mut kinds: Vec<(&&str, &usize)> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &kinds {
            out.push_str(&format!("| {} | {count} |\n", human_event_kind(kind)));
        }
        out.push('\n');
    }

    // Notable entities
    let (ips, users) = collect_entities(events);

    if !ips.is_empty() || !users.is_empty() {
        out.push_str("## Most active\n\n");
        if !ips.is_empty() {
            let ip_list = top_n(&ips, 5)
                .iter()
                .map(|(v, c)| format!("{v} ({c} events)"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("**IPs:** {ip_list}\n\n"));
        }
        if !users.is_empty() {
            let user_list = top_n(&users, 5)
                .iter()
                .map(|(v, c)| format!("{v} ({c} events)"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("**Users:** {user_list}\n\n"));
        }
    }

    out
}

/// Convert a technical detector/event kind into plain English.
///
/// Returns a `Cow` so known kinds use a static string while unknown kinds
/// fall back to displaying the raw `kind` value instead of "Unknown event".
fn human_event_kind(kind: &str) -> std::borrow::Cow<'static, str> {
    use std::borrow::Cow;
    match kind {
        "ssh.login_failed" => Cow::Borrowed("Failed SSH login"),
        "ssh.login_success" => Cow::Borrowed("Successful SSH login"),
        "ssh.invalid_user" => Cow::Borrowed("SSH login with unknown username"),
        "ssh.disconnected" => Cow::Borrowed("SSH disconnection"),
        "sudo.command" => Cow::Borrowed("Sudo command executed"),
        "shell.command_exec" => Cow::Borrowed("Shell command executed"),
        "network.connection_blocked" => Cow::Borrowed("Blocked connection attempt"),
        "http.request" => Cow::Borrowed("HTTP request"),
        "http.error" => Cow::Borrowed("HTTP error"),
        "http.scanner_ua" => Cow::Borrowed("Scanner detected (by User-Agent)"),
        "file.changed" => Cow::Borrowed("File modification"),
        "ssh.authorized_keys_changed" => Cow::Borrowed("SSH authorized_keys modified"),
        "cron.tampering" => Cow::Borrowed("Cron job modification"),
        "container.start" => Cow::Borrowed("Container started"),
        "container.stop" => Cow::Borrowed("Container stopped"),
        "container.die" => Cow::Borrowed("Container crashed"),
        "container.privileged" => Cow::Borrowed("Privileged container started"),
        "container.sock_mount" => Cow::Borrowed("Container with Docker socket access"),
        "container.dangerous_cap" => Cow::Borrowed("Container with dangerous capabilities"),
        "wazuh.syslog" | "wazuh.web" | "wazuh.ids" => Cow::Borrowed("Wazuh alert"),
        "falco.syscall" | "falco.k8s_audit" => Cow::Borrowed("Falco runtime alert"),
        // Suricata protocol events
        "suricata.tls" => Cow::Borrowed("TLS connection observed"),
        "suricata.dns" => Cow::Borrowed("DNS query observed"),
        "suricata.http" => Cow::Borrowed("HTTP transaction observed"),
        "suricata.alert" => Cow::Borrowed("Suricata IDS alert"),
        "suricata.anomaly" => Cow::Borrowed("Network anomaly"),
        // Wildcard-style fallbacks for known prefixes
        _ if kind.starts_with("suricata.") => Cow::Owned(format!("Suricata event ({kind})")),
        _ if kind.starts_with("docker.") => Cow::Borrowed("Docker event"),
        _ if kind.starts_with("container.") => Cow::Borrowed("Docker event"),
        _ if kind.starts_with("osquery.") => Cow::Borrowed("osquery result"),
        _ if kind.starts_with("falco.") => Cow::Borrowed("Falco alert"),
        // Truly unknown — show the raw kind instead of a generic label
        _ => Cow::Owned(format!("event: {kind}")),
    }
}

/// Convert a detector kind into plain English for narratives.
fn human_detector_name(detector: &str) -> String {
    match detector {
        "ssh_bruteforce" => "SSH brute force".to_string(),
        "credential_stuffing" => "credential stuffing".to_string(),
        "port_scan" => "port scan".to_string(),
        "sudo_abuse" => "sudo abuse".to_string(),
        "web_scan" => "web scan".to_string(),
        "search_abuse" => "search/API abuse".to_string(),
        "user_agent_scanner" => "scanner detection".to_string(),
        "execution_guard" => "suspicious command execution".to_string(),
        _ => detector.replace('_', " "),
    }
}

fn severity_plain(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical — immediate attention needed",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        _ => "Informational",
    }
}

/// Write the summary to `data_dir/summary-YYYY-MM-DD.md` (overwrites if exists).
pub fn write(data_dir: &Path, date: &str, markdown: &str) -> Result<()> {
    let path = data_dir.join(format!("summary-{date}.md"));
    std::fs::write(&path, markdown)
        .with_context(|| format!("failed to write summary to {}", path.display()))
}

/// Remove summary files older than `keep_days` days from `data_dir`.
pub fn cleanup_old(data_dir: &Path, keep_days: usize) -> Result<()> {
    let cutoff = chrono::Local::now().date_naive() - chrono::Duration::days(keep_days as i64);

    for entry in std::fs::read_dir(data_dir)
        .with_context(|| format!("failed to read {}", data_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        // Match "summary-YYYY-MM-DD.md"
        if let Some(date_str) = name
            .strip_prefix("summary-")
            .and_then(|s| s.strip_suffix(".md"))
        {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                if date < cutoff {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Incident grouping (Fix 1)
// ---------------------------------------------------------------------------

/// A group of incidents sharing the same (IP, normalised title).
struct IncidentGroup<'a> {
    first: &'a Incident,
    count: usize,
    ip: String,
    first_ts: chrono::DateTime<chrono::Utc>,
    last_ts: chrono::DateTime<chrono::Utc>,
    max_severity: Severity,
}

/// Extract the first IP entity from an incident (empty string if none).
fn first_ip(inc: &Incident) -> String {
    inc.entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.clone())
        .unwrap_or_default()
}

/// Normalise a title for grouping: lowercase + trim whitespace.
fn normalise_title(title: &str) -> String {
    title.trim().to_lowercase()
}

/// Group incidents by (first_ip, normalised title).  Order-preserving via
/// `Vec` index tracking; returns a map keyed by (ip, title).
fn group_incidents(incidents: &[Incident]) -> HashMap<(String, String), IncidentGroup<'_>> {
    let mut groups: HashMap<(String, String), IncidentGroup<'_>> = HashMap::new();

    for inc in incidents {
        let ip = first_ip(inc);
        let key = (ip.clone(), normalise_title(&inc.title));

        groups
            .entry(key)
            .and_modify(|g| {
                g.count += 1;
                if inc.ts < g.first_ts {
                    g.first_ts = inc.ts;
                    g.first = inc;
                }
                if inc.ts > g.last_ts {
                    g.last_ts = inc.ts;
                }
                if severity_rank(&inc.severity) > severity_rank(&g.max_severity) {
                    g.max_severity = inc.severity.clone();
                }
            })
            .or_insert(IncidentGroup {
                first: inc,
                count: 1,
                ip,
                first_ts: inc.ts,
                last_ts: inc.ts,
                max_severity: inc.severity.clone(),
            });
    }
    groups
}

// ---------------------------------------------------------------------------
// Smart recommendations (Fix 2)
// ---------------------------------------------------------------------------

/// Rewrite "What to check" recommendations based on responder configuration.
fn smart_checks(original: &[String], responder: ResponderHint) -> Vec<String> {
    if !responder.enabled || !responder.has_block_ip {
        // Responder disabled or block-ip not allowed — keep originals as-is
        return original.to_vec();
    }

    let block_keywords = [
        "blocking the ip",
        "block the ip",
        "ufw",
        "fail2ban",
        "iptables",
        "nftables",
    ];

    original
        .iter()
        .map(|check| {
            let lower = check.to_lowercase();
            let is_block_rec = block_keywords.iter().any(|kw| lower.contains(kw));
            if !is_block_rec {
                return check.clone();
            }
            if responder.dry_run {
                "InnerWarden would block this IP (dry-run mode). Enable live mode to act automatically.".to_string()
            } else {
                "IP was blocked automatically by InnerWarden. Review the decision in the audit trail.".to_string()
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Debug => 0,
    }
}

fn severity_icon(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "🚨",
        Severity::High => "🔴",
        Severity::Medium => "🟠",
        Severity::Low => "🟡",
        Severity::Info | Severity::Debug => "🔵",
    }
}

fn collect_entities(events: &[Event]) -> (HashMap<String, usize>, HashMap<String, usize>) {
    let mut ips: HashMap<String, usize> = HashMap::new();
    let mut users: HashMap<String, usize> = HashMap::new();

    for ev in events {
        for entity in &ev.entities {
            match entity.r#type {
                EntityType::Ip => *ips.entry(entity.value.clone()).or_insert(0) += 1,
                EntityType::User => *users.entry(entity.value.clone()).or_insert(0) += 1,
                _ => {}
            }
        }
    }
    (ips, users)
}

fn top_n(counts: &HashMap<String, usize>, n: usize) -> Vec<(&String, usize)> {
    let mut items: Vec<(&String, usize)> = counts.iter().map(|(k, &v)| (k, v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    items.truncate(n);
    items
}

fn format_pivot(pivot: &str) -> String {
    if let Some(value) = pivot.strip_prefix("ip:") {
        return format!("IP {}", value);
    }
    if let Some(value) = pivot.strip_prefix("user:") {
        return format!("User {}", value);
    }
    if let Some(value) = pivot.strip_prefix("detector:") {
        return format!("Detector {}", value);
    }
    pivot.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
    use tempfile::TempDir;

    fn make_event(kind: &str, severity: Severity, ip: Option<&str>) -> Event {
        Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "test".into(),
            kind: kind.into(),
            severity,
            summary: format!("test {kind}"),
            details: serde_json::json!({}),
            tags: vec![],
            entities: ip.map(|v| vec![EntityRef::ip(v)]).unwrap_or_default(),
        }
    }

    fn make_incident(title: &str, severity: Severity) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: "id-1".into(),
            severity,
            title: title.into(),
            summary: "test incident".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec!["check logs".into()],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn generates_markdown_with_incidents() {
        let events = vec![
            make_event("ssh.login_failed", Severity::Low, Some("1.2.3.4")),
            make_event("ssh.login_failed", Severity::Low, Some("1.2.3.4")),
            make_event("ssh.login_success", Severity::Info, None),
        ];
        let incidents = vec![make_incident("SSH Brute Force", Severity::High)];
        let md = generate("2026-03-12", "my-server", &events, &incidents, 300);

        assert!(md.contains("# Inner Warden — 2026-03-12"));
        assert!(md.contains("my-server"));
        assert!(md.contains("SSH Brute Force"));
        assert!(md.contains("High"));
        assert!(md.contains("Failed SSH login"));
        assert!(md.contains("1.2.3.4"));
    }

    #[test]
    fn generates_markdown_no_incidents() {
        let events = vec![make_event("sudo.command", Severity::Info, None)];
        let md = generate("2026-03-12", "host", &events, &[], 300);
        assert!(md.contains("No threats detected today"));
        assert!(md.contains("Sudo command executed"));
    }

    #[test]
    fn write_and_cleanup() {
        let dir = TempDir::new().unwrap();
        // Use today's date so it always survives cleanup
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let md = generate(&date, "host", &[], &[], 300);
        write(dir.path(), &date, &md).unwrap();
        assert!(dir.path().join(format!("summary-{date}.md")).exists());

        // Write an old summary (30 days ago — always older than keep_days=7)
        let old_date = (chrono::Local::now() - chrono::Duration::days(30))
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        write(dir.path(), &old_date, "old").unwrap();
        assert!(dir.path().join(format!("summary-{old_date}.md")).exists());

        // Cleanup keeping 7 days — the old file should be removed
        cleanup_old(dir.path(), 7).unwrap();
        assert!(!dir.path().join(format!("summary-{old_date}.md")).exists());
        // Today's file survives
        assert!(dir.path().join(format!("summary-{date}.md")).exists());
    }

    #[test]
    fn includes_correlation_cluster_section() {
        let now = Utc::now();
        let incidents = vec![
            Incident {
                ts: now,
                host: "h".into(),
                incident_id: "port_scan:1.2.3.4:a".into(),
                severity: Severity::High,
                title: "Port scan".into(),
                summary: "scan".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            },
            Incident {
                ts: now + chrono::Duration::seconds(30),
                host: "h".into(),
                incident_id: "ssh_bruteforce:1.2.3.4:b".into(),
                severity: Severity::High,
                title: "Brute force".into(),
                summary: "bf".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
            },
        ];

        let md = generate("2026-03-12", "host", &[], &incidents, 120);
        assert!(md.contains("Related activity"));
        assert!(md.contains("IP 1.2.3.4"));
        assert!(md.contains("port scan"));
        assert!(md.contains("SSH brute force"));
    }
}
