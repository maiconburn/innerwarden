mod collectors;
mod config;
mod detectors;
mod sinks;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use collectors::{auth_log::AuthLogCollector, integrity::IntegrityCollector};
use detectors::ssh_bruteforce::SshBruteforceDetector;
use sinks::{jsonl::JsonlWriter, state::State};
use tokio::sync::mpsc;
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
    let (tx, mut rx) = mpsc::channel(1024);

    // Shared state — updated by collectors, read on shutdown for persistence.
    let shared_auth_offset = Arc::new(AtomicU64::new(0));
    let shared_integrity_hashes: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // SSH brute force detector (stateful, lives in main loop)
    let mut ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(threshold = d.threshold, window_seconds = d.window_seconds, "ssh_bruteforce detector enabled");
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector = AuthLogCollector::new(
            &cfg.collectors.auth_log.path,
            &cfg.agent.host_id,
            offset,
        );
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        let shared = Arc::clone(&shared_auth_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2, shared).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if cfg.collectors.integrity.enabled && !cfg.collectors.integrity.paths.is_empty() {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Seed shared hashes with whatever we loaded from state
        *shared_integrity_hashes.lock().unwrap() = known_hashes.clone();

        let paths = ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        let collector =
            IntegrityCollector::new(paths, &cfg.agent.host_id, ic.poll_seconds, known_hashes);
        info!(paths = ic.paths.len(), poll_secs = ic.poll_seconds, "starting integrity collector");
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Drop the original tx — each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);

    // SIGTERM listener (Unix only)
    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // Main loop: drain events, run detectors, write output
    let mut events_written = 0u64;
    let mut incidents_written = 0u64;

    'main: loop {
        #[cfg(unix)]
        let shutdown = tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        process_event(ev, &mut writer, &mut ssh_detector, &mut events_written, &mut incidents_written)?;
                        false
                    }
                    None => {
                        info!("all collectors stopped");
                        break 'main;
                    }
                }
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
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        process_event(ev, &mut writer, &mut ssh_detector, &mut events_written, &mut incidents_written)?;
                        false
                    }
                    None => {
                        info!("all collectors stopped");
                        break 'main;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received — shutting down");
                true
            }
        };

        if shutdown {
            break 'main;
        }

        // Periodic flush every 50 events
        if events_written % 50 == 0 && events_written > 0 {
            writer.flush()?;
        }
    }

    writer.flush()?;
    info!(events_written, incidents_written, "flushed output");

    // Persist collector state using the latest values from the shared Arcs
    let auth_offset = shared_auth_offset.load(Ordering::Relaxed);
    state.set_cursor("auth_log", serde_json::json!(auth_offset));

    let integrity_hashes = shared_integrity_hashes.lock().unwrap().clone();
    if !integrity_hashes.is_empty() {
        state.set_cursor("integrity", serde_json::to_value(&integrity_hashes)?);
    }

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

fn process_event(
    ev: innerwarden_core::event::Event,
    writer: &mut JsonlWriter,
    ssh_detector: &mut Option<SshBruteforceDetector>,
    events_written: &mut u64,
    incidents_written: &mut u64,
) -> Result<()> {
    info!(kind = %ev.kind, summary = %ev.summary, "event");
    writer.write_event(&ev)?;
    *events_written += 1;

    if let Some(ref mut det) = ssh_detector {
        if let Some(incident) = det.process(&ev) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                title = %incident.title,
                "INCIDENT"
            );
            writer.write_incident(&incident)?;
            *incidents_written += 1;
        }
    }

    Ok(())
}
