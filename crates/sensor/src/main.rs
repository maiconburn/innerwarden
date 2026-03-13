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
use collectors::{
    auth_log::AuthLogCollector, docker::DockerCollector, exec_audit::ExecAuditCollector,
    integrity::IntegrityCollector, journald::JournaldCollector,
};
use detectors::credential_stuffing::CredentialStuffingDetector;
use detectors::port_scan::PortScanDetector;
use detectors::ssh_bruteforce::SshBruteforceDetector;
use detectors::sudo_abuse::SudoAbuseDetector;
use sinks::{jsonl::JsonlWriter, state::State};
use tokio::sync::mpsc;
use tokio::time;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "innerwarden-sensor",
    version,
    about = "Lightweight host observability sensor"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_sensor=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
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
    let shared_journald_cursor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_docker_since: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_exec_audit_offset = Arc::new(AtomicU64::new(0));

    // SSH brute force detector (stateful, lives in main loop)
    let mut ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "ssh_bruteforce detector enabled"
        );
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let mut credential_stuffing_detector = cfg.detectors.credential_stuffing.enabled.then(|| {
        let d = &cfg.detectors.credential_stuffing;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "credential_stuffing detector enabled"
        );
        CredentialStuffingDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let mut port_scan_detector = cfg.detectors.port_scan.enabled.then(|| {
        let d = &cfg.detectors.port_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "port_scan detector enabled"
        );
        PortScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let mut sudo_abuse_detector = cfg.detectors.sudo_abuse.enabled.then(|| {
        let d = &cfg.detectors.sudo_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "sudo_abuse detector enabled"
        );
        SudoAbuseDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector =
            AuthLogCollector::new(&cfg.collectors.auth_log.path, &cfg.agent.host_id, offset);
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
        info!(
            paths = ic.paths.len(),
            poll_secs = ic.poll_seconds,
            "starting integrity collector"
        );
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Spawn journald collector
    if cfg.collectors.journald.enabled {
        let jc = &cfg.collectors.journald;
        let cursor: Option<String> = state
            .get_cursor("journald")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        *shared_journald_cursor.lock().unwrap() = cursor.clone();
        let collector = JournaldCollector::new(&cfg.agent.host_id, jc.units.clone(), cursor);
        info!(units = ?jc.units, "starting journald collector");
        let tx4 = tx.clone();
        let shared = Arc::clone(&shared_journald_cursor);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx4, shared).await {
                tracing::error!("journald collector error: {e:#}");
            }
        });
    }

    // Spawn docker collector
    if cfg.collectors.docker.enabled {
        let since: Option<String> = state
            .get_cursor("docker")
            .and_then(|v| v.as_str().map(str::to_string));
        *shared_docker_since.lock().unwrap() = since.clone();
        let collector = DockerCollector::new(&cfg.agent.host_id, since);
        info!("starting docker collector");
        let tx5 = tx.clone();
        let shared = Arc::clone(&shared_docker_since);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx5, shared).await {
                tracing::error!("docker collector error: {e:#}");
            }
        });
    }

    // Spawn exec_audit collector
    if cfg.collectors.exec_audit.enabled {
        let ec = &cfg.collectors.exec_audit;
        let offset = state
            .get_cursor("exec_audit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_exec_audit_offset.store(offset, Ordering::Relaxed);
        let collector =
            ExecAuditCollector::new(&ec.path, &cfg.agent.host_id, offset, ec.include_tty);
        info!(
            path = %ec.path,
            include_tty = ec.include_tty,
            offset,
            "starting exec_audit collector"
        );
        let tx6 = tx.clone();
        let shared = Arc::clone(&shared_exec_audit_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx6, shared).await {
                tracing::error!("exec_audit collector error: {e:#}");
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

    // Flush every 5 seconds regardless of event count
    let mut flush_ticker = time::interval(time::Duration::from_secs(5));
    flush_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    'main: loop {
        #[cfg(unix)]
        let shutdown = tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        process_event(
                            ev,
                            &mut writer,
                            &mut ssh_detector,
                            &mut credential_stuffing_detector,
                            &mut port_scan_detector,
                            &mut sudo_abuse_detector,
                            &mut events_written,
                            &mut incidents_written,
                        );
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
            _ = flush_ticker.tick() => {
                if let Err(e) = writer.flush() {
                    warn!("periodic flush failed: {e:#}");
                }
                false
            }
        };

        #[cfg(not(unix))]
        let shutdown = tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        process_event(
                            ev,
                            &mut writer,
                            &mut ssh_detector,
                            &mut credential_stuffing_detector,
                            &mut port_scan_detector,
                            &mut sudo_abuse_detector,
                            &mut events_written,
                            &mut incidents_written,
                        );
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
            _ = flush_ticker.tick() => {
                if let Err(e) = writer.flush() {
                    warn!("periodic flush failed: {e:#}");
                }
                false
            }
        };

        if shutdown {
            break 'main;
        }

        // Also flush every 50 events as a safety net
        if events_written % 50 == 0 && events_written > 0 {
            if let Err(e) = writer.flush() {
                warn!("count-based flush failed: {e:#}");
            }
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

    if let Some(cursor) = shared_journald_cursor.lock().unwrap().clone() {
        state.set_cursor("journald", serde_json::json!(cursor));
    }

    if let Some(since) = shared_docker_since.lock().unwrap().clone() {
        state.set_cursor("docker", serde_json::json!(since));
    }

    let exec_audit_offset = shared_exec_audit_offset.load(Ordering::Relaxed);
    state.set_cursor("exec_audit", serde_json::json!(exec_audit_offset));

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

fn process_event(
    ev: innerwarden_core::event::Event,
    writer: &mut JsonlWriter,
    ssh_detector: &mut Option<SshBruteforceDetector>,
    credential_stuffing_detector: &mut Option<CredentialStuffingDetector>,
    port_scan_detector: &mut Option<PortScanDetector>,
    sudo_abuse_detector: &mut Option<SudoAbuseDetector>,
    events_written: &mut u64,
    incidents_written: &mut u64,
) {
    info!(kind = %ev.kind, summary = %ev.summary, "event");
    if let Err(e) = writer.write_event(&ev) {
        warn!(kind = %ev.kind, "failed to write event: {e:#}");
    } else {
        *events_written += 1;
    }

    if let Some(ref mut det) = ssh_detector {
        if let Some(incident) = det.process(&ev) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                title = %incident.title,
                "INCIDENT"
            );
            if let Err(e) = writer.write_incident(&incident) {
                warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
            } else {
                *incidents_written += 1;
            }
        }
    }

    if let Some(ref mut det) = credential_stuffing_detector {
        if let Some(incident) = det.process(&ev) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                title = %incident.title,
                "INCIDENT"
            );
            if let Err(e) = writer.write_incident(&incident) {
                warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
            } else {
                *incidents_written += 1;
            }
        }
    }

    if let Some(ref mut det) = port_scan_detector {
        if let Some(incident) = det.process(&ev) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                title = %incident.title,
                "INCIDENT"
            );
            if let Err(e) = writer.write_incident(&incident) {
                warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
            } else {
                *incidents_written += 1;
            }
        }
    }

    if let Some(ref mut det) = sudo_abuse_detector {
        if let Some(incident) = det.process(&ev) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                title = %incident.title,
                "INCIDENT"
            );
            if let Err(e) = writer.write_incident(&incident) {
                warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
            } else {
                *incidents_written += 1;
            }
        }
    }
}
