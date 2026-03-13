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
// Public API
// ---------------------------------------------------------------------------

/// Generate a Markdown daily summary from all events and incidents for a date.
pub fn generate(
    date: &str,
    host: &str,
    events: &[Event],
    incidents: &[Incident],
    correlation_window_secs: u64,
) -> String {
    let mut out = String::with_capacity(2048);

    // Header
    out.push_str(&format!("# Inner Warden — {date}\n\n"));
    out.push_str(&format!(
        "**Host:** {host} | **Eventos:** {} | **Incidentes:** {}\n\n",
        events.len(),
        incidents.len()
    ));

    // Incidents section
    if incidents.is_empty() {
        out.push_str("✅ Nenhum incidente detectado.\n\n");
    } else {
        out.push_str("## Incidentes\n\n");
        // Sort by severity (highest first)
        let mut sorted_incidents: Vec<&Incident> = incidents.iter().collect();
        sorted_incidents
            .sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));

        for inc in &sorted_incidents {
            let icon = severity_icon(&inc.severity);
            let sev = format!("{:?}", inc.severity).to_uppercase();
            let time = inc.ts.format("%H:%M UTC").to_string();

            out.push_str(&format!("### {icon} {} ({})\n\n", inc.title, sev));
            out.push_str(&format!("- **Quando:** {time}\n"));
            out.push_str(&format!("- **Resumo:** {}\n", inc.summary));

            if !inc.recommended_checks.is_empty() {
                out.push_str("- **Verificar:**\n");
                for check in &inc.recommended_checks {
                    out.push_str(&format!("  - {check}\n"));
                }
            }
            out.push('\n');
        }
    }

    // Correlated clusters (narrative-ready grouping)
    if incidents.len() > 1 {
        let clusters: Vec<correlation::IncidentCluster> =
            correlation::build_clusters(incidents, correlation_window_secs)
                .into_iter()
                .filter(|cluster| cluster.size() >= 2)
                .collect();

        if !clusters.is_empty() {
            out.push_str("## Clusters correlacionados\n\n");
            for cluster in clusters {
                let kinds = cluster.detector_kinds.join(", ");
                let window = format!(
                    "{} -> {} UTC",
                    cluster.start_ts.format("%H:%M"),
                    cluster.end_ts.format("%H:%M")
                );
                out.push_str(&format!(
                    "- **{}** | {} incidentes | detectores: {} | janela: {}\n",
                    format_pivot(&cluster.pivot),
                    cluster.size(),
                    kinds,
                    window
                ));
            }
            out.push('\n');
        }
    }

    // Events by kind
    if !events.is_empty() {
        out.push_str("## Eventos por tipo\n\n");
        out.push_str("| Tipo | Total |\n");
        out.push_str("|------|-------|\n");

        let mut by_kind: HashMap<&str, usize> = HashMap::new();
        for ev in events {
            *by_kind.entry(ev.kind.as_str()).or_insert(0) += 1;
        }
        let mut kinds: Vec<(&&str, &usize)> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &kinds {
            out.push_str(&format!("| {kind} | {count} |\n"));
        }
        out.push('\n');
    }

    // Notable entities
    let (ips, users) = collect_entities(events);

    if !ips.is_empty() || !users.is_empty() {
        out.push_str("## Entidades notáveis\n\n");
        if !ips.is_empty() {
            let ip_list = top_n(&ips, 5)
                .iter()
                .map(|(v, c)| format!("{v} ({c} eventos)"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("**IPs:** {ip_list}\n\n"));
        }
        if !users.is_empty() {
            let user_list = top_n(&users, 5)
                .iter()
                .map(|(v, c)| format!("{v} ({c} eventos)"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("**Usuários:** {user_list}\n\n"));
        }
    }

    out
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
        assert!(md.contains("**Host:** my-server"));
        assert!(md.contains("**Eventos:** 3"));
        assert!(md.contains("**Incidentes:** 1"));
        assert!(md.contains("SSH Brute Force"));
        assert!(md.contains("HIGH"));
        assert!(md.contains("ssh.login_failed"));
        assert!(md.contains("1.2.3.4"));
    }

    #[test]
    fn generates_markdown_no_incidents() {
        let events = vec![make_event("sudo.command", Severity::Info, None)];
        let md = generate("2026-03-12", "host", &events, &[], 300);
        assert!(md.contains("Nenhum incidente"));
        assert!(md.contains("sudo.command"));
    }

    #[test]
    fn write_and_cleanup() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-12";
        let md = generate(date, "host", &[], &[], 300);
        write(dir.path(), date, &md).unwrap();
        assert!(dir.path().join(format!("summary-{date}.md")).exists());

        // Write an old summary
        let old_date = "2026-03-01";
        write(dir.path(), old_date, "old").unwrap();
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
        assert!(md.contains("Clusters correlacionados"));
        assert!(md.contains("IP 1.2.3.4"));
        assert!(md.contains("port_scan"));
        assert!(md.contains("ssh_bruteforce"));
    }
}
