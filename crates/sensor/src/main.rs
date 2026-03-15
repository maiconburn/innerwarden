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
    falco_log::FalcoLogCollector, integrity::IntegrityCollector, journald::JournaldCollector,
    nginx_access::NginxAccessCollector, suricata_eve::SuricataEveCollector,
};
use detectors::credential_stuffing::CredentialStuffingDetector;
use detectors::execution_guard::{ExecutionGuardDetector, ExecutionMode};
use detectors::port_scan::PortScanDetector;
use detectors::search_abuse::SearchAbuseDetector;
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

struct DetectorSet {
    ssh: Option<SshBruteforceDetector>,
    credential_stuffing: Option<CredentialStuffingDetector>,
    port_scan: Option<PortScanDetector>,
    sudo_abuse: Option<SudoAbuseDetector>,
    search_abuse: Option<SearchAbuseDetector>,
    execution_guard: Option<ExecutionGuardDetector>,
}

#[derive(Default)]
struct WriteStats {
    events_written: u64,
    incidents_written: u64,
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
    let shared_nginx_offset = Arc::new(AtomicU64::new(0));
    let shared_falco_offset = Arc::new(AtomicU64::new(0));
    let shared_suricata_offset = Arc::new(AtomicU64::new(0));

    // SSH brute force detector (stateful, lives in main loop)
    let ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "ssh_bruteforce detector enabled"
        );
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let credential_stuffing_detector = cfg.detectors.credential_stuffing.enabled.then(|| {
        let d = &cfg.detectors.credential_stuffing;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "credential_stuffing detector enabled"
        );
        CredentialStuffingDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let port_scan_detector = cfg.detectors.port_scan.enabled.then(|| {
        let d = &cfg.detectors.port_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "port_scan detector enabled"
        );
        PortScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let sudo_abuse_detector = cfg.detectors.sudo_abuse.enabled.then(|| {
        let d = &cfg.detectors.sudo_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "sudo_abuse detector enabled"
        );
        SudoAbuseDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let search_abuse_detector = cfg.detectors.search_abuse.enabled.then(|| {
        let d = &cfg.detectors.search_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            path_prefix = %d.path_prefix,
            "search_abuse detector enabled"
        );
        SearchAbuseDetector::new(
            &cfg.agent.host_id,
            d.threshold,
            d.window_seconds,
            &d.path_prefix,
        )
    });
    let execution_guard_detector = cfg.detectors.execution_guard.enabled.then(|| {
        let d = &cfg.detectors.execution_guard;
        info!(
            mode = %d.mode,
            window_seconds = d.window_seconds,
            "execution_guard detector enabled"
        );
        ExecutionGuardDetector::new(
            &cfg.agent.host_id,
            d.window_seconds,
            ExecutionMode::from_str(&d.mode),
        )
    });
    let mut detectors = DetectorSet {
        ssh: ssh_detector,
        credential_stuffing: credential_stuffing_detector,
        port_scan: port_scan_detector,
        sudo_abuse: sudo_abuse_detector,
        search_abuse: search_abuse_detector,
        execution_guard: execution_guard_detector,
    };

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

    // Spawn nginx_access collector
    if cfg.collectors.nginx_access.enabled {
        let nc = &cfg.collectors.nginx_access;
        let offset = state
            .get_cursor("nginx_access")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_offset.store(offset, Ordering::Relaxed);
        let collector = NginxAccessCollector::new(&nc.path, &cfg.agent.host_id, offset);
        info!(path = %nc.path, offset, "starting nginx_access collector");
        let tx7 = tx.clone();
        let shared = Arc::clone(&shared_nginx_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx7, shared).await {
                tracing::error!("nginx_access collector error: {e:#}");
            }
        });
    }

    // Spawn falco_log collector
    if cfg.collectors.falco_log.enabled {
        let fc = &cfg.collectors.falco_log;
        let offset = state
            .get_cursor("falco_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_falco_offset.store(offset, Ordering::Relaxed);
        let collector = FalcoLogCollector::new(&fc.path, &cfg.agent.host_id, offset);
        info!(path = %fc.path, offset, "starting falco_log collector");
        let tx_falco = tx.clone();
        let shared = Arc::clone(&shared_falco_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_falco, shared).await {
                tracing::error!("falco_log collector error: {e:#}");
            }
        });
    }

    // Spawn suricata_eve collector
    if cfg.collectors.suricata_eve.enabled {
        let sc = &cfg.collectors.suricata_eve;
        let offset = state
            .get_cursor("suricata_eve")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_suricata_offset.store(offset, Ordering::Relaxed);
        let collector = SuricataEveCollector::new(
            &sc.path,
            &cfg.agent.host_id,
            offset,
            sc.event_types.clone(),
        );
        info!(
            path = %sc.path,
            event_types = ?sc.event_types,
            offset,
            "starting suricata_eve collector"
        );
        let tx_suricata = tx.clone();
        let shared = Arc::clone(&shared_suricata_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_suricata, shared).await {
                tracing::error!("suricata_eve collector error: {e:#}");
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
    let mut stats = WriteStats::default();

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
                            &mut detectors,
                            &mut stats,
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
                            &mut detectors,
                            &mut stats,
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
        if stats.events_written > 0 && stats.events_written.is_multiple_of(50) {
            if let Err(e) = writer.flush() {
                warn!("count-based flush failed: {e:#}");
            }
        }
    }

    writer.flush()?;
    info!(
        events_written = stats.events_written,
        incidents_written = stats.incidents_written,
        "flushed output"
    );

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

    let nginx_offset = shared_nginx_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_access", serde_json::json!(nginx_offset));

    let falco_offset = shared_falco_offset.load(Ordering::Relaxed);
    state.set_cursor("falco_log", serde_json::json!(falco_offset));

    let suricata_offset = shared_suricata_offset.load(Ordering::Relaxed);
    state.set_cursor("suricata_eve", serde_json::json!(suricata_offset));

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

/// Sources that already performed their own detection.
/// High/Critical events from these sources are promoted directly to incidents
/// without going through an InnerWarden detector.
fn is_passthrough_source(source: &str) -> bool {
    matches!(source, "falco" | "suricata")
}

fn process_event(
    ev: innerwarden_core::event::Event,
    writer: &mut JsonlWriter,
    detectors: &mut DetectorSet,
    stats: &mut WriteStats,
) {
    use innerwarden_core::event::Severity;

    info!(kind = %ev.kind, summary = %ev.summary, "event");
    if let Err(e) = writer.write_event(&ev) {
        warn!(kind = %ev.kind, "failed to write event: {e:#}");
    } else {
        stats.events_written += 1;
    }

    // Incident passthrough: tools that already ran their own detection
    // (Falco, Suricata) emit High/Critical events that are incidents by definition.
    if is_passthrough_source(&ev.source) {
        let is_actionable = matches!(
            ev.severity,
            Severity::High | Severity::Critical
        );
        if is_actionable {
            if let Some(incident) = passthrough_incident(&ev) {
                write_incident(writer, stats, incident);
            }
        }
        // Passthrough sources don't need InnerWarden detectors — return early.
        return;
    }

    if let Some(ref mut det) = detectors.ssh {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.credential_stuffing {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.port_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.sudo_abuse {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.search_abuse {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.execution_guard {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }
}

/// Build an Incident directly from an event emitted by a passthrough source
/// (Falco, Suricata). The external tool already detected the threat; this
/// promotes it into InnerWarden's incident pipeline for AI triage and response.
fn passthrough_incident(
    ev: &innerwarden_core::event::Event,
) -> Option<innerwarden_core::incident::Incident> {
    use innerwarden_core::incident::Incident;

    let incident_id = format!(
        "{}:{}:{}",
        ev.source,
        ev.kind,
        ev.ts.format("%Y-%m-%dT%H:%MZ")
    );

    let recommended_checks = match ev.source.as_str() {
        "falco" => vec![
            "Review Falco alert details".to_string(),
            "Investigate related container/process activity".to_string(),
            "Check for lateral movement indicators".to_string(),
        ],
        "suricata" => vec![
            "Review Suricata IDS signature".to_string(),
            "Check network flow context in eve.json".to_string(),
            "Consider blocking source IP if attack pattern confirmed".to_string(),
        ],
        _ => vec!["Review source alert details".to_string()],
    };

    Some(Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id,
        severity: ev.severity.clone(),
        title: ev.summary.clone(),
        summary: format!("[{}] {}", ev.source.to_uppercase(), ev.summary),
        evidence: serde_json::json!([ev.details]),
        recommended_checks,
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    })
}

fn write_incident(
    writer: &mut JsonlWriter,
    stats: &mut WriteStats,
    incident: innerwarden_core::incident::Incident,
) {
    info!(
        incident_id = %incident.incident_id,
        severity = ?incident.severity,
        title = %incident.title,
        "INCIDENT"
    );
    if let Err(e) = writer.write_incident(&incident) {
        warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
    } else {
        stats.incidents_written += 1;
    }
}
