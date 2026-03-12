mod collectors;
mod config;
mod detectors;
mod sinks;

use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};
use sinks::{jsonl::JsonlWriter, state::State};
use tracing::info;

#[derive(Parser)]
#[command(name = "innerwarden", version, about = "Lightweight host observability agent")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = data_dir.join("state.json");

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let mut writer = JsonlWriter::new(data_dir, cfg.output.write_events)?;

    // --- test: emit a fake event and a fake incident ---
    let host = cfg.agent.host_id.clone();

    let event = Event {
        ts: Utc::now(),
        host: host.clone(),
        source: "auth.log".to_string(),
        kind: "ssh.login_failed".to_string(),
        severity: Severity::Info,
        summary: "Invalid user root from 1.2.3.4".to_string(),
        details: serde_json::json!({ "ip": "1.2.3.4", "user": "root" }),
        tags: vec!["auth".to_string(), "ssh".to_string()],
        entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
    };
    writer.write_event(&event)?;
    info!(kind = %event.kind, "event written");

    let incident = Incident {
        ts: Utc::now(),
        host: host.clone(),
        incident_id: format!("ssh_bruteforce:1.2.3.4:{}", Utc::now().format("%Y-%m-%dT%H:%MZ")),
        severity: Severity::High,
        title: "Possible SSH brute force".to_string(),
        summary: "12 failed SSH attempts from 1.2.3.4 in 5 minutes".to_string(),
        evidence: serde_json::json!([{ "kind": "ssh.login_failed", "count": 12 }]),
        recommended_checks: vec![
            "Check auth.log for successful logins".to_string(),
            "Consider fail2ban".to_string(),
        ],
        tags: vec!["auth".to_string(), "ssh".to_string(), "bruteforce".to_string()],
        entities: vec![EntityRef::ip("1.2.3.4")],
    };
    writer.write_incident(&incident)?;
    info!(title = %incident.title, "incident written");

    writer.flush()?;

    state.set_cursor("auth_log", serde_json::json!(0));
    state.save(&state_path)?;
    info!("state saved");

    info!("check data/ for output files");

    Ok(())
}
