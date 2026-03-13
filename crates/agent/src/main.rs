mod ai;
mod config;
mod narrative;
mod reader;
mod webhook;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "innerwarden-agent", version, about = "Interpretive layer — reads sensor JSONL and produces narratives")]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative + webhook settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Poll interval in seconds for continuous mode
    #[arg(long, default_value = "30")]
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Load config (optional — all fields have sensible defaults)
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    let state_path = cli.data_dir.join("agent-state.json");
    let mut cursor = reader::AgentCursor::load(&state_path)?;

    if cli.once {
        let stats = process_tick(&cli.data_dir, &mut cursor, &cfg).await?;
        cursor.save(&state_path)?;
        info!(
            new_events = stats.new_events,
            new_incidents = stats.new_incidents,
            "run complete"
        );
    } else {
        info!(interval_secs = cli.interval, "entering continuous mode");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                _ = interval.tick() => {
                    let stats = process_tick(&cli.data_dir, &mut cursor, &cfg).await?;
                    cursor.save(&state_path)?;
                    if stats.new_events > 0 || stats.new_incidents > 0 {
                        info!(new_events = stats.new_events, new_incidents = stats.new_incidents, "tick");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received — shutting down");
                    true
                }
            };

            #[cfg(not(unix))]
            let shutdown = tokio::select! {
                _ = interval.tick() => {
                    let stats = process_tick(&cli.data_dir, &mut cursor, &cfg).await?;
                    cursor.save(&state_path)?;
                    if stats.new_events > 0 || stats.new_incidents > 0 {
                        info!(new_events = stats.new_events, new_incidents = stats.new_incidents, "tick");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
            };

            if shutdown {
                cursor.save(&state_path)?;
                break;
            }
        }
    }

    Ok(())
}

struct TickStats {
    new_events: usize,
    new_incidents: usize,
}

/// Process new JSONL entries since the last cursor position.
/// Regenerates the daily Markdown summary and fires webhook notifications
/// when new entries arrive.
async fn process_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
) -> Result<TickStats> {
    let today = chrono::Local::now().date_naive().format("%Y-%m-%d").to_string();

    let events_path = data_dir.join(format!("events-{today}.jsonl"));
    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

    let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
        &events_path,
        cursor.events_offset(&today),
    )?;

    let new_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        cursor.incidents_offset(&today),
    )?;

    let events_count = new_events.entries.len();
    let incidents_count = new_incidents.entries.len();

    // Update cursors to new byte offsets
    cursor.set_events_offset(&today, new_events.new_offset);
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    // Log new incidents
    for incident in &new_incidents.entries {
        info!(
            severity = ?incident.severity,
            title = %incident.title,
            "new incident"
        );
    }

    // Webhook: notify for each new incident that meets the severity threshold
    if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        let min_rank = webhook::severity_rank(&cfg.webhook.parsed_min_severity());
        for incident in &new_incidents.entries {
            if webhook::severity_rank(&incident.severity) >= min_rank {
                if let Err(e) = webhook::send_incident(
                    &cfg.webhook.url,
                    cfg.webhook.timeout_secs,
                    incident,
                )
                .await
                {
                    warn!(
                        incident_id = %incident.incident_id,
                        "webhook notification failed: {e:#}"
                    );
                } else {
                    info!(incident_id = %incident.incident_id, "webhook notified");
                }
            }
        }
    }

    // Narrative: regenerate daily Markdown summary when new entries arrived
    if cfg.narrative.enabled && (events_count > 0 || incidents_count > 0) {
        // Read ALL events/incidents for the day (from offset 0) to build a complete summary
        let all_events =
            reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)?;
        let all_incidents =
            reader::read_new_entries::<innerwarden_core::incident::Incident>(&incidents_path, 0)?;

        // Determine host from events or incidents, fall back to "unknown"
        let host = all_events
            .entries
            .first()
            .map(|e| e.host.as_str())
            .or_else(|| all_incidents.entries.first().map(|i| i.host.as_str()))
            .unwrap_or("unknown");

        let md =
            narrative::generate(&today, host, &all_events.entries, &all_incidents.entries);
        if let Err(e) = narrative::write(data_dir, &today, &md) {
            warn!("failed to write daily summary: {e:#}");
        } else {
            info!(date = today, "daily summary updated");
        }
    }

    Ok(TickStats {
        new_events: events_count,
        new_incidents: incidents_count,
    })
}
