mod ai;
mod config;
mod correlation;
mod dashboard;
mod data_retention;
mod decisions;
mod narrative;
mod reader;
mod report;
mod skills;
mod telegram;
mod telemetry;
mod webhook;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(
    name = "innerwarden-agent",
    version,
    about = "Interpretive layer — reads sensor JSONL, generates narratives, and auto-responds to incidents"
)]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Generate a trial operational report from existing artifacts and exit
    #[arg(long)]
    report: bool,

    /// Output directory for generated reports (default: same as --data-dir)
    #[arg(long)]
    report_dir: Option<PathBuf>,

    /// Run read-only local dashboard server and exit this process only on SIGTERM/SIGINT
    #[arg(long)]
    dashboard: bool,

    /// Bind address for dashboard mode (default: localhost only)
    #[arg(long, default_value = "127.0.0.1:8787")]
    dashboard_bind: String,

    /// Utility: generate Argon2 password hash for dashboard auth and exit.
    #[arg(long)]
    dashboard_generate_password_hash: bool,

    /// Poll interval in seconds for the narrative slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,

    /// Internal: run honeypot sandbox worker mode.
    #[arg(long, hide = true)]
    honeypot_sandbox_runner: bool,

    /// Internal: path to honeypot sandbox runner spec JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_spec: Option<PathBuf>,

    /// Internal: path to honeypot sandbox runner result JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_result: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    /// Recent action decisions keyed by `action:detector:entity_kind:entity_value`.
    /// Used to suppress repeated AI decisions for the same scope within a short window.
    decision_cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>>,
    correlator: correlation::TemporalCorrelator,
    telemetry: telemetry::TelemetryState,
    telemetry_writer: Option<telemetry::TelemetryWriter>,
    /// Wrapped in Arc so we can clone a handle for use within a loop iteration
    /// without holding a borrow of `state` across async calls that need `&mut state`.
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    decision_writer: Option<decisions::DecisionWriter>,
    /// Tracks when the daily narrative was last written so we can enforce a
    /// minimum interval and avoid rewriting on every 30-second tick.
    last_narrative_at: Option<std::time::Instant>,
    /// Telegram client for T.1 notifications and T.2 approvals (None when disabled).
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    /// Pending T.2 operator confirmations keyed by incident_id.
    /// Stores the original decision and incident so the action can be executed when approved.
    pending_confirmations: HashMap<
        String,
        (
            telegram::PendingConfirmation,
            ai::AiDecision,
            innerwarden_core::incident::Incident,
        ),
    >,
    /// Receives approval results from the Telegram polling task.
    /// Drained at the start of every incident tick via try_recv.
    approval_rx: Option<tokio::sync::mpsc::Receiver<telegram::ApprovalResult>>,
    /// In-memory trust rules: set of "detector:action" strings.
    /// Loaded from data_dir/trust-rules.json at startup; updated live when operator clicks "Always".
    trust_rules: std::collections::HashSet<String>,
}

const DECISION_COOLDOWN_SECS: i64 = 3600;

fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

fn decision_cooldown_key(action: &str, detector: &str, entity_kind: &str, entity: &str) -> String {
    format!("{action}:{detector}:{entity_kind}:{entity}")
}

fn decision_cooldown_candidates(incident: &innerwarden_core::incident::Incident) -> Vec<String> {
    let detector = incident_detector(&incident.incident_id);
    let mut keys = Vec::new();

    for entity in &incident.entities {
        match entity.r#type {
            innerwarden_core::entities::EntityType::Ip => {
                keys.push(decision_cooldown_key(
                    "block_ip",
                    detector,
                    "ip",
                    &entity.value,
                ));
                keys.push(decision_cooldown_key(
                    "monitor",
                    detector,
                    "ip",
                    &entity.value,
                ));
                keys.push(decision_cooldown_key(
                    "honeypot",
                    detector,
                    "ip",
                    &entity.value,
                ));
            }
            innerwarden_core::entities::EntityType::User => {
                keys.push(decision_cooldown_key(
                    "suspend_user_sudo",
                    detector,
                    "user",
                    &entity.value,
                ));
            }
            _ => {}
        }
    }

    keys
}

fn decision_cooldown_key_for_decision(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
) -> Option<String> {
    let detector = incident_detector(&incident.incident_id);
    match &decision.action {
        ai::AiAction::BlockIp { ip, .. } => {
            Some(decision_cooldown_key("block_ip", detector, "ip", ip))
        }
        ai::AiAction::Monitor { ip } => Some(decision_cooldown_key("monitor", detector, "ip", ip)),
        ai::AiAction::Honeypot { ip } => {
            Some(decision_cooldown_key("honeypot", detector, "ip", ip))
        }
        ai::AiAction::SuspendUserSudo { user, .. } => Some(decision_cooldown_key(
            "suspend_user_sudo",
            detector,
            "user",
            user,
        )),
        ai::AiAction::Ignore { .. } | ai::AiAction::RequestConfirmation { .. } => None,
    }
}

fn decision_cooldown_key_from_entry(entry: &decisions::DecisionEntry) -> Option<String> {
    let detector = incident_detector(&entry.incident_id);
    match entry.action_type.as_str() {
        "block_ip" | "monitor" | "honeypot" => entry
            .target_ip
            .as_ref()
            .map(|ip| decision_cooldown_key(&entry.action_type, detector, "ip", ip)),
        "suspend_user_sudo" => entry
            .target_user
            .as_ref()
            .map(|user| decision_cooldown_key("suspend_user_sudo", detector, "user", user)),
        _ => None,
    }
}

fn recent_decision_dates() -> Vec<String> {
    let today = chrono::Local::now().date_naive();
    let mut dates = vec![today.format("%Y-%m-%d").to_string()];
    if let Some(prev) = today.pred_opt() {
        dates.push(prev.format("%Y-%m-%d").to_string());
    }
    dates
}

fn load_startup_decision_state(
    data_dir: &Path,
    preload_blocklist_from_system: bool,
) -> (
    skills::Blocklist,
    HashMap<String, chrono::DateTime<chrono::Utc>>,
) {
    let mut blocklist = skills::Blocklist::default();
    let mut cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();

    if preload_blocklist_from_system {
        // Caller is responsible for awaiting the async ufw load and inserting later.
    }

    for date in recent_decision_dates() {
        let decisions_path = data_dir.join(format!("decisions-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&decisions_path) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<decisions::DecisionEntry>(line) else {
                continue;
            };
            if entry.action_type == "block_ip" {
                if let Some(ip) = &entry.target_ip {
                    blocklist.insert(ip.clone());
                }
            }
            if let Some(key) = decision_cooldown_key_from_entry(&entry) {
                cooldowns
                    .entry(key)
                    .and_modify(|existing| {
                        if entry.ts > *existing {
                            *existing = entry.ts;
                        }
                    })
                    .or_insert(entry.ts);
            }
        }
    }

    (blocklist, cooldowns)
}

fn load_last_narrative_instant(data_dir: &Path) -> Option<std::time::Instant> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("summary-{today}.md"));
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.elapsed().ok()?;
    std::time::Instant::now().checked_sub(elapsed)
}

// ---------------------------------------------------------------------------
// Trust rules — data_dir/trust-rules.json
// ---------------------------------------------------------------------------

const TRUST_RULES_FILE: &str = "trust-rules.json";

/// Load trust rules from data_dir/trust-rules.json.
/// Returns a HashSet of "detector:action" keys. Fail-open: returns empty on any error.
fn load_trust_rules(data_dir: &Path) -> std::collections::HashSet<String> {
    let path = data_dir.join(TRUST_RULES_FILE);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return std::collections::HashSet::new();
    };
    let rules: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap_or_default();
    rules
        .into_iter()
        .filter_map(|r| {
            let d = r["detector"].as_str()?.to_string();
            let a = r["action"].as_str()?.to_string();
            Some(format!("{d}:{a}"))
        })
        .collect()
}

/// Append a trust rule to data_dir/trust-rules.json and update the in-memory set.
/// Fail-open: logs a warning on I/O errors.
fn append_trust_rule(
    data_dir: &Path,
    trust_rules: &mut std::collections::HashSet<String>,
    detector: &str,
    action: &str,
) {
    let key = format!("{detector}:{action}");
    if trust_rules.contains(&key) {
        return; // already trusted
    }
    trust_rules.insert(key);

    let path = data_dir.join(TRUST_RULES_FILE);
    let mut rules: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_default();
    rules.push(serde_json::json!({ "detector": detector, "action": action }));

    match serde_json::to_string_pretty(&rules) {
        Ok(content) => {
            if let Err(e) = std::fs::write(&path, content) {
                warn!("failed to write trust-rules.json: {e:#}");
            }
        }
        Err(e) => warn!("failed to serialise trust rules: {e:#}"),
    }
}

/// Returns true if a (detector, action) pair has been trusted by the operator.
fn is_trusted(trust_rules: &std::collections::HashSet<String>, detector: &str, action: &str) -> bool {
    trust_rules.contains(&format!("{detector}:{action}"))
        || trust_rules.contains(&format!("*:{action}"))
        || trust_rules.contains(&format!("{detector}:*"))
        || trust_rules.contains("*:*")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (fail-silent — production uses real env vars)
    match dotenvy::dotenv() {
        Ok(path) => debug!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // no .env file — that's fine
        Err(e) => warn!("could not parse .env file: {e}"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    if cli.dashboard_generate_password_hash {
        dashboard::generate_password_hash_interactive()?;
        return Ok(());
    }

    if cli.honeypot_sandbox_runner {
        let spec = cli
            .honeypot_sandbox_spec
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-spec"))?;
        let result = cli
            .honeypot_sandbox_result
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-result"))?;
        skills::builtin::run_honeypot_sandbox_worker(spec, result).await?;
        return Ok(());
    }

    if cli.report {
        let out_dir = cli.report_dir.as_deref().unwrap_or(&cli.data_dir);
        if let Some(d) = cli.report_dir.as_deref() {
            std::fs::create_dir_all(d)
                .with_context(|| format!("failed to create report-dir {}", d.display()))?;
        }
        let out = report::generate(&cli.data_dir, out_dir)?;
        info!(
            analyzed_date = %out.report.analyzed_date,
            markdown = %out.markdown_path.display(),
            json = %out.json_path.display(),
            "trial report generated"
        );
        println!(
            "Trial report generated:\n  {}\n  {}",
            out.markdown_path.display(),
            out.json_path.display()
        );
        return Ok(());
    }

    // Load config (optional — all fields have sensible defaults).
    // Done before dashboard check so action config can be wired in.
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    if cli.dashboard {
        let auth = dashboard::DashboardAuth::from_env()?;
        let action_cfg = dashboard::DashboardActionConfig {
            enabled: cfg.responder.enabled,
            dry_run: cfg.responder.dry_run,
            block_backend: cfg.responder.block_backend.clone(),
            allowed_skills: cfg.responder.allowed_skills.clone(),
        };
        dashboard::serve(
            cli.data_dir.clone(),
            cli.dashboard_bind.clone(),
            auth,
            action_cfg,
        )
        .await?;
        return Ok(());
    }

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        correlation = cfg.correlation.enabled,
        correlation_window_secs = cfg.correlation.window_seconds,
        telemetry = cfg.telemetry.enabled,
        honeypot_mode = %cfg.honeypot.mode,
        honeypot_bind_addr = %cfg.honeypot.bind_addr,
        honeypot_services = ?cfg.honeypot.services,
        honeypot_ssh_port = cfg.honeypot.port,
        honeypot_http_port = cfg.honeypot.http_port,
        honeypot_isolation_profile = %cfg.honeypot.isolation_profile,
        honeypot_forensics_keep_days = cfg.honeypot.forensics_keep_days,
        honeypot_forensics_max_total_mb = cfg.honeypot.forensics_max_total_mb,
        honeypot_sandbox = cfg.honeypot.sandbox.enabled,
        honeypot_containment_mode = %cfg.honeypot.containment.mode,
        honeypot_containment_jail_runner = %cfg.honeypot.containment.jail_runner,
        honeypot_containment_jail_profile = %cfg.honeypot.containment.jail_profile,
        honeypot_external_handoff = cfg.honeypot.external_handoff.enabled,
        honeypot_external_handoff_allowlist = cfg.honeypot.external_handoff.enforce_allowlist,
        honeypot_external_handoff_signature = cfg.honeypot.external_handoff.signature_enabled,
        honeypot_external_handoff_attestation = cfg.honeypot.external_handoff.attestation_enabled,
        honeypot_pcap_handoff = cfg.honeypot.pcap_handoff.enabled,
        honeypot_redirect = cfg.honeypot.redirect.enabled,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Clean up old data files on startup
    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
    if removed > 0 {
        info!(removed, "data_retention: cleaned up old files on startup");
    }

    // Build shared agent state
    // Pre-populate blocklist + decision cooldowns from recent (today + yesterday)
    // decision files so that IPs we already decided to block are skipped after a
    // restart, even in dry-run mode.
    let (decisions_bl, startup_cooldowns) = load_startup_decision_state(&cli.data_dir, false);

    let startup_blocklist = {
        let mut bl = if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        };
        // Merge IPs from recent decision files
        for ip in decisions_bl.as_vec() {
            bl.insert(ip);
        }
        bl
    };

    // Build Telegram client (None when disabled or misconfigured)
    let telegram_client: Option<Arc<telegram::TelegramClient>> = if cfg.telegram.enabled {
        let token = cfg.telegram.resolved_bot_token();
        let chat_id = cfg.telegram.resolved_chat_id();
        if token.is_empty() || chat_id.is_empty() {
            warn!("telegram.enabled = true but bot_token/chat_id not configured — disabling");
            None
        } else {
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            match telegram::TelegramClient::new(token, chat_id, dashboard_url) {
                Ok(c) => {
                    info!("Telegram client initialised (T.1 notifications enabled)");
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!("failed to create Telegram client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Create approval channel — polling task is spawned after state is built (continuous mode only)
    let (approval_tx, approval_rx_for_state) =
        tokio::sync::mpsc::channel::<telegram::ApprovalResult>(64);

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: startup_blocklist,
        decision_cooldowns: startup_cooldowns,
        correlator: correlation::TemporalCorrelator::new(cfg.correlation.window_seconds, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: if cfg.telemetry.enabled {
            match telemetry::TelemetryWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create telemetry writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        ai_provider: if cfg.ai.enabled {
            Some(Arc::from(ai::build_provider(&cfg.ai)))
        } else {
            None
        },
        decision_writer: if cfg.ai.enabled {
            match decisions::DecisionWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create decision writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        last_narrative_at: load_last_narrative_instant(&cli.data_dir),
        telegram_client,
        pending_confirmations: HashMap::new(),
        approval_rx: None, // set below in continuous mode
        trust_rules: load_trust_rules(&cli.data_dir),
    };

    let state_path = cli.data_dir.join("agent-state.json");
    let mut cursor = reader::AgentCursor::load(&state_path)?;

    if cli.once {
        let handled = process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
        let new_events =
            process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await?;
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        if let Some(w) = &mut state.telemetry_writer {
            w.flush();
        }
        cursor.save(&state_path)?;
        info!(new_events, incidents_handled = handled, "run complete");
    } else {
        // Activate approval channel and start Telegram polling task
        state.approval_rx = Some(approval_rx_for_state);
        if let Some(ref tg) = state.telegram_client {
            let tg_clone = tg.clone();
            tokio::spawn(async move { tg_clone.run_polling(approval_tx).await });
            info!("Telegram polling task started (T.2 approvals enabled)");
        }

        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker = tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    // Persist cursor after every incident tick — prevents double-processing on restart
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
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
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
            };

            if shutdown {
                if let Some(w) = &mut state.decision_writer {
                    w.flush();
                }
                if let Some(w) = &mut state.telemetry_writer {
                    w.flush();
                }
                cursor.save(&state_path)?;
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Incident tick — runs every 2s
//
// Responsibilities (in order, for every new incident):
//   1. Webhook: notify immediately for all incidents above min_severity
//   2. AI analysis: only for High/Critical that pass the algorithm gate
//
// The incident cursor is advanced and saved after every tick, so a crash
// between ticks never causes double-processing or lost webhook notifications.
// ---------------------------------------------------------------------------

/// Returns the number of incidents handled (webhook sent and/or AI analyzed).
async fn process_incidents(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> usize {
    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "suspend-user-sudo")
    {
        match skills::builtin::cleanup_expired_sudo_suspensions(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired sudo suspensions cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("suspend_user_sudo_cleanup");
                warn!("failed to cleanup expired sudo suspensions: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "rate-limit-nginx")
    {
        match skills::builtin::cleanup_expired_nginx_blocks(data_dir, cfg.responder.dry_run).await {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired nginx deny rules cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("rate_limit_nginx_cleanup");
                warn!("failed to cleanup expired nginx blocks: {e:#}");
            }
        }
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

    let new_incidents = match reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        cursor.incidents_offset(&today),
    ) {
        Ok(r) => r,
        Err(e) => {
            state.telemetry.observe_error("incident_reader");
            warn!("incident tick: failed to read incidents: {e:#}");
            return 0;
        }
    };

    if new_incidents.entries.is_empty() {
        return 0;
    }

    // Advance cursor before any async work — prevents double-processing on crash/restart
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    // Pre-compute webhook threshold once (None = webhook disabled)
    let webhook_min_rank: Option<u8> = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(webhook::severity_rank(&cfg.webhook.parsed_min_severity()))
    } else {
        None
    };

    // Pre-compute Telegram T.1 threshold (None = telegram disabled)
    let telegram_min_rank: Option<u8> = if cfg.telegram.enabled && state.telegram_client.is_some() {
        Some(webhook::severity_rank(&cfg.telegram.parsed_min_severity()))
    } else {
        None
    };

    // Drain any pending T.2 approval results from the Telegram polling task
    let pending_approvals: Vec<telegram::ApprovalResult> = {
        let mut results = Vec::new();
        if let Some(rx) = state.approval_rx.as_mut() {
            while let Ok(r) = rx.try_recv() {
                results.push(r);
            }
        }
        results
    };
    for approval in pending_approvals {
        process_telegram_approval(approval, data_dir, cfg, state).await;
    }

    // Expire stale pending confirmations
    let now = chrono::Utc::now();
    state
        .pending_confirmations
        .retain(|_, (pending, _, _)| pending.expires_at > now);

    // Pre-compute AI context (only if AI is configured)
    let ai_enabled = cfg.ai.enabled && state.ai_provider.is_some();
    let (all_events, skill_infos, ai_provider, provider_name, already_blocked, mut blocked_set) =
        if ai_enabled {
            let events_path = data_dir.join(format!("events-{today}.jsonl"));
            let events =
                reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)
                    .map(|r| r.entries)
                    .unwrap_or_default();
            let infos = state.skill_registry.infos();
            // Clone the Arc — owned handle, no borrow of `state`
            let prov: Arc<dyn ai::AiProvider> = state.ai_provider.as_ref().unwrap().clone();
            let pname = prov.name();
            let blocked = state.blocklist.as_vec();
            // Mutable so we can update it mid-tick to prevent duplicate AI calls
            // for the same IP when multiple incidents arrive in the same 2s window.
            let blocked_set: HashSet<String> = blocked.iter().cloned().collect();
            (events, infos, Some(prov), pname, blocked, blocked_set)
        } else {
            (vec![], vec![], None, "", vec![], HashSet::new())
        };

    let mut handled = 0;

    for incident in &new_incidents.entries {
        state.telemetry.observe_incident(incident);

        let related_incidents = if cfg.correlation.enabled {
            state
                .correlator
                .related_to(incident, cfg.correlation.max_related_incidents)
        } else {
            Vec::new()
        };
        if cfg.correlation.enabled {
            if !related_incidents.is_empty() {
                info!(
                    incident_id = %incident.incident_id,
                    correlated_count = related_incidents.len(),
                    "temporal correlation: related incidents found"
                );
            }
            // Observe early so correlation history stays consistent even when this
            // incident is later skipped by gate or AI call fails.
            state.correlator.observe(incident);
        }

        // 1. Webhook — fires for ALL incidents above configured threshold, regardless of AI gate
        if let Some(min_rank) = webhook_min_rank {
            if webhook::severity_rank(&incident.severity) >= min_rank {
                if let Err(e) =
                    webhook::send_incident(&cfg.webhook.url, cfg.webhook.timeout_secs, incident)
                        .await
                {
                    state.telemetry.observe_error("webhook");
                    warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
                }
            }
        }

        // 1b. Telegram T.1 — push notification for High/Critical incidents
        if let Some(min_rank) = telegram_min_rank {
            if webhook::severity_rank(&incident.severity) >= min_rank {
                // Clone the Arc to avoid holding a borrow on state during the await
                let tg = state.telegram_client.clone();
                if let Some(tg) = tg {
                    if let Err(e) = tg.send_incident_alert(incident).await {
                        warn!(incident_id = %incident.incident_id, "Telegram alert failed: {e:#}");
                    }
                }
            }
        }

        // 2. AI analysis — only when AI is enabled and incident passes the gate
        if !ai_enabled {
            handled += 1;
            continue;
        }

        if !ai::should_invoke_ai(incident, &blocked_set) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (low severity / private IP / already blocked)"
            );
            handled += 1;
            continue;
        }

        // Decision cooldown — suppress repeated AI decisions for the same
        // action:detector:entity scope within a 1-hour window.  This prevents
        // redundant API calls when the same attacker triggers multiple
        // incidents in rapid succession.
        let cooldown_cutoff =
            chrono::Utc::now() - chrono::Duration::seconds(DECISION_COOLDOWN_SECS);
        let candidates = decision_cooldown_candidates(incident);
        let in_cooldown = candidates.iter().any(|k| {
            state
                .decision_cooldowns
                .get(k)
                .is_some_and(|ts| *ts > cooldown_cutoff)
        });
        if in_cooldown {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (decision cooldown active)"
            );
            handled += 1;
            continue;
        }

        state.telemetry.observe_gate_pass();

        // ai_provider is Some when ai_enabled — safe to unwrap
        let provider = ai_provider.as_ref().unwrap();

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            correlated_count = related_incidents.len(),
            "sending incident to AI for analysis"
        );

        // Build context — filter events to those involving the same incident IPs/users
        let entity_ips: HashSet<&str> = incident
            .entities
            .iter()
            .filter(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str())
            .collect();
        let entity_users: HashSet<&str> = incident
            .entities
            .iter()
            .filter(|e| e.r#type == innerwarden_core::entities::EntityType::User)
            .map(|e| e.value.as_str())
            .collect();

        let recent: Vec<&innerwarden_core::event::Event> = all_events
            .iter()
            .filter(|ev| {
                ev.entities.iter().any(|e| {
                    (e.r#type == innerwarden_core::entities::EntityType::Ip
                        && entity_ips.contains(e.value.as_str()))
                        || (e.r#type == innerwarden_core::entities::EntityType::User
                            && entity_users.contains(e.value.as_str()))
                })
            })
            .rev()
            .take(cfg.ai.context_events)
            .collect();
        let related_refs: Vec<&innerwarden_core::incident::Incident> =
            related_incidents.iter().collect();

        let ctx = ai::DecisionContext {
            incident,
            recent_events: recent,
            related_incidents: related_refs,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos
                .iter()
                .map(|s| ai::SkillInfo {
                    id: s.id.clone(),
                    applicable_to: s.applicable_to.clone(),
                })
                .collect(),
        };

        state.telemetry.observe_ai_sent();
        let decision_start = Instant::now();
        let decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                state.telemetry.observe_error("ai_provider");
                warn!(incident_id = %incident.incident_id, "AI decision failed: {e:#}");
                handled += 1;
                continue;
            }
        };
        let latency_ms = decision_start.elapsed().as_millis();
        state
            .telemetry
            .observe_ai_decision(&decision.action, latency_ms);

        // Update the in-memory blocked_set immediately after a BlockIp decision.
        // This prevents a second incident from the same IP (arriving in the same 2s tick)
        // from triggering a duplicate AI call. The actual blocklist persists separately;
        // this is only a per-tick deduplication guard.
        if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
            blocked_set.insert(ip.clone());
        }

        // Record decision cooldown so the same action:detector:entity scope is not
        // re-evaluated by AI within the cooldown window (default 1h).
        if let Some(key) = decision_cooldown_key_for_decision(incident, &decision) {
            state.decision_cooldowns.insert(key, chrono::Utc::now());
        }

        // Update in-memory blocklist immediately for BlockIp decisions so subsequent
        // ticks don't re-evaluate the same IP even when the responder is disabled or
        // dry_run is true. Without this, state.blocklist is only updated inside
        // execute_decision (which is skipped when responder.enabled = false), leaving
        // cross-tick deduplication to the cooldown alone — which breaks on restart if
        // the decision was not yet flushed to the decisions file.
        if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
            state.blocklist.insert(ip.clone());
        }

        info!(
            incident_id = %incident.incident_id,
            action = ?decision.action,
            confidence = decision.confidence,
            auto_execute = decision.auto_execute,
            reason = %decision.reason,
            "AI decision"
        );

        // Execute if:
        //   (a) AI flagged auto_execute, OR operator has trusted this detector+action pair
        //   AND confidence >= threshold
        //   AND responder is enabled
        let detector = incident_detector(&incident.incident_id);
        let action_name = decision.action.name();
        let trusted = is_trusted(&state.trust_rules, detector, action_name);
        let execution_result = if (decision.auto_execute || trusted)
            && decision.confidence >= cfg.ai.confidence_threshold
            && cfg.responder.enabled
        {
            if trusted && !decision.auto_execute {
                info!(
                    incident_id = %incident.incident_id,
                    detector, action = action_name,
                    "trust rule override: executing without AI auto_execute flag"
                );
            }
            state
                .telemetry
                .observe_execution_path(cfg.responder.dry_run);
            execute_decision(&decision, incident, data_dir, cfg, state).await
        } else if !cfg.responder.enabled {
            "skipped: responder disabled".to_string()
        } else if !decision.auto_execute && !trusted {
            "skipped: AI did not recommend auto-execution (no trust rule)".to_string()
        } else {
            format!(
                "skipped: confidence {:.2} below threshold {:.2}",
                decision.confidence, cfg.ai.confidence_threshold
            )
        };

        // Write to audit trail
        if let Some(writer) = &mut state.decision_writer {
            let entry = decisions::build_entry(
                &incident.incident_id,
                &incident.host,
                provider_name,
                &decision,
                cfg.responder.dry_run,
                &execution_result,
            );
            if let Err(e) = writer.write(&entry) {
                state.telemetry.observe_error("decision_writer");
                warn!("failed to write decision entry: {e:#}");
            }
        }

        handled += 1;
    }

    let snapshot = state.telemetry.snapshot("incident_tick");
    let mut telemetry_write_failed = false;
    if let Some(writer) = &mut state.telemetry_writer {
        if let Err(e) = writer.write(&snapshot) {
            warn!("failed to write telemetry snapshot: {e:#}");
            telemetry_write_failed = true;
        }
    }
    if telemetry_write_failed {
        state.telemetry.observe_error("telemetry_writer");
    }

    handled
}

/// Execute an AI decision by finding and running the appropriate skill.
async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> String {
    use ai::AiAction;

    match &decision.action {
        AiAction::BlockIp { ip, skill_id } => {
            // Resolve the effective skill ID, honouring the allowed_skills whitelist.
            // If the AI selected a skill not in the whitelist, fall back to the
            // configured backend default. This prevents the AI from executing a
            // skill the operator did not explicitly allow.
            let effective_id: String = if cfg.responder.allowed_skills.contains(skill_id) {
                skill_id.clone()
            } else {
                let fallback = format!("block-ip-{}", cfg.responder.block_backend);
                if cfg.responder.allowed_skills.contains(&fallback) {
                    fallback
                } else {
                    return format!("skipped: skill '{skill_id}' not in allowed_skills");
                }
            };

            let skill = state.skill_registry.get(&effective_id).or_else(|| {
                state
                    .skill_registry
                    .block_skill_for_backend(&cfg.responder.block_backend)
            });

            match skill {
                Some(skill) => {
                    let ctx = skills::SkillContext {
                        incident: incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        duration_secs: None,
                        host: incident.host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: honeypot_runtime(cfg),
                    };
                    let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    // Always track the IP in the in-memory blocklist regardless of dry_run
                    // mode, so the same IP is not re-evaluated by AI on subsequent ticks
                    // or after a restart within the same day.
                    if result.success {
                        state.blocklist.insert(ip.clone());
                    }
                    result.message
                }
                None => format!("skipped: skill '{effective_id}' not found"),
            }
        }
        AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: monitor-ip skill not available".to_string()
            }
        }
        AiAction::Honeypot { ip } => {
            if let Some(skill) = state.skill_registry.get("honeypot") {
                let runtime = honeypot_runtime(cfg);
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: runtime.clone(),
                };
                let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                if result.success {
                    match append_honeypot_marker_event(
                        data_dir,
                        incident,
                        ip,
                        cfg.responder.dry_run,
                        &runtime,
                    )
                    .await
                    {
                        Ok(path) => format!(
                            "{} | honeypot marker written to {}",
                            result.message,
                            path.display()
                        ),
                        Err(e) => {
                            state.telemetry.observe_error("honeypot_marker_writer");
                            warn!("failed to write honeypot marker event: {e:#}");
                            format!(
                                "{} | warning: failed to write honeypot marker event: {e}",
                                result.message
                            )
                        }
                    }
                } else {
                    result.message
                }
            } else {
                "skipped: honeypot skill not available".to_string()
            }
        }
        AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return format!("skipped: skill '{skill_id}' not in allowed_skills");
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: suspend-user-sudo skill not available".to_string()
            }
        }
        AiAction::RequestConfirmation { summary } => {
            // T.2 — send inline keyboard approval request via Telegram when enabled
            let tg = state.telegram_client.clone();
            let req_detector = incident_detector(&incident.incident_id).to_string();
            let req_action = decision.action.name();
            if let Some(tg) = tg {
                let ttl = cfg.telegram.approval_ttl_secs;
                match tg
                    .send_confirmation_request(incident, summary, req_action, decision.confidence, ttl)
                    .await
                {
                    Ok(msg_id) => {
                        let now = chrono::Utc::now();
                        let pending = telegram::PendingConfirmation {
                            incident_id: incident.incident_id.clone(),
                            telegram_message_id: msg_id,
                            action_description: summary.clone(),
                            created_at: now,
                            expires_at: now + chrono::Duration::seconds(ttl as i64),
                            detector: req_detector,
                            action_name: req_action.to_string(),
                        };
                        state.pending_confirmations.insert(
                            incident.incident_id.clone(),
                            (pending, decision.clone(), incident.clone()),
                        );
                        return "pending: operator confirmation requested via Telegram".to_string();
                    }
                    Err(e) => {
                        warn!("Telegram confirmation request failed: {e:#}");
                    }
                }
            }
            // Fallback: webhook notification when Telegram is not configured
            if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
                let payload = serde_json::json!({
                    "type": "confirmation_required",
                    "incident_id": incident.incident_id,
                    "summary": summary,
                    "decision_reason": decision.reason,
                });
                let client = reqwest::Client::new();
                match client.post(&cfg.webhook.url).json(&payload).send().await {
                    Ok(_) => "confirmation request sent via webhook".to_string(),
                    Err(e) => format!("confirmation webhook failed: {e}"),
                }
            } else {
                "confirmation requested (no Telegram or webhook configured)".to_string()
            }
        }
        AiAction::Ignore { reason } => {
            format!("ignored: {reason}")
        }
    }
}

fn honeypot_runtime(cfg: &config::AgentConfig) -> skills::HoneypotRuntimeConfig {
    let mode = cfg.honeypot.mode.trim().to_ascii_lowercase();
    let normalized_mode = match mode.as_str() {
        "demo" | "listener" => mode,
        other => {
            warn!(mode = other, "unknown honeypot mode; falling back to demo");
            "demo".to_string()
        }
    };
    skills::HoneypotRuntimeConfig {
        mode: normalized_mode,
        bind_addr: cfg.honeypot.bind_addr.clone(),
        port: cfg.honeypot.port,
        http_port: cfg.honeypot.http_port,
        duration_secs: cfg.honeypot.duration_secs,
        services: if cfg.honeypot.services.is_empty() {
            vec!["ssh".to_string()]
        } else {
            cfg.honeypot.services.clone()
        },
        strict_target_only: cfg.honeypot.strict_target_only,
        allow_public_listener: cfg.honeypot.allow_public_listener,
        max_connections: cfg.honeypot.max_connections,
        max_payload_bytes: cfg.honeypot.max_payload_bytes,
        isolation_profile: cfg.honeypot.isolation_profile.clone(),
        require_high_ports: cfg.honeypot.require_high_ports,
        forensics_keep_days: cfg.honeypot.forensics_keep_days,
        forensics_max_total_mb: cfg.honeypot.forensics_max_total_mb,
        transcript_preview_bytes: cfg.honeypot.transcript_preview_bytes,
        lock_stale_secs: cfg.honeypot.lock_stale_secs,
        sandbox_enabled: cfg.honeypot.sandbox.enabled,
        sandbox_runner_path: cfg.honeypot.sandbox.runner_path.clone(),
        sandbox_clear_env: cfg.honeypot.sandbox.clear_env,
        pcap_handoff_enabled: cfg.honeypot.pcap_handoff.enabled,
        pcap_handoff_timeout_secs: cfg.honeypot.pcap_handoff.timeout_secs,
        pcap_handoff_max_packets: cfg.honeypot.pcap_handoff.max_packets,
        containment_mode: cfg.honeypot.containment.mode.clone(),
        containment_require_success: cfg.honeypot.containment.require_success,
        containment_namespace_runner: cfg.honeypot.containment.namespace_runner.clone(),
        containment_namespace_args: cfg.honeypot.containment.namespace_args.clone(),
        containment_jail_runner: cfg.honeypot.containment.jail_runner.clone(),
        containment_jail_args: cfg.honeypot.containment.jail_args.clone(),
        containment_jail_profile: cfg.honeypot.containment.jail_profile.clone(),
        containment_allow_namespace_fallback: cfg.honeypot.containment.allow_namespace_fallback,
        external_handoff_enabled: cfg.honeypot.external_handoff.enabled,
        external_handoff_command: cfg.honeypot.external_handoff.command.clone(),
        external_handoff_args: cfg.honeypot.external_handoff.args.clone(),
        external_handoff_timeout_secs: cfg.honeypot.external_handoff.timeout_secs,
        external_handoff_require_success: cfg.honeypot.external_handoff.require_success,
        external_handoff_clear_env: cfg.honeypot.external_handoff.clear_env,
        external_handoff_allowed_commands: cfg.honeypot.external_handoff.allowed_commands.clone(),
        external_handoff_enforce_allowlist: cfg.honeypot.external_handoff.enforce_allowlist,
        external_handoff_signature_enabled: cfg.honeypot.external_handoff.signature_enabled,
        external_handoff_signature_key_env: cfg.honeypot.external_handoff.signature_key_env.clone(),
        external_handoff_attestation_enabled: cfg.honeypot.external_handoff.attestation_enabled,
        external_handoff_attestation_key_env: cfg
            .honeypot
            .external_handoff
            .attestation_key_env
            .clone(),
        external_handoff_attestation_prefix: cfg
            .honeypot
            .external_handoff
            .attestation_prefix
            .clone(),
        external_handoff_attestation_expected_receiver: cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .clone(),
        redirect_enabled: cfg.honeypot.redirect.enabled,
        redirect_backend: cfg.honeypot.redirect.backend.clone(),
        interaction: cfg.honeypot.interaction.trim().to_ascii_lowercase(),
        ssh_max_auth_attempts: cfg.honeypot.ssh_max_auth_attempts,
        http_max_requests: cfg.honeypot.http_max_requests,
    }
}

async fn append_honeypot_marker_event(
    data_dir: &Path,
    incident: &innerwarden_core::incident::Incident,
    ip: &str,
    dry_run: bool,
    runtime: &skills::HoneypotRuntimeConfig,
) -> Result<std::path::PathBuf> {
    use tokio::io::AsyncWriteExt;

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    let is_listener = runtime.mode == "listener" && !dry_run;
    let (source, kind, summary) = if is_listener {
        let mut endpoints = Vec::new();
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("ssh"))
        {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("http"))
        {
            endpoints.push(format!("http:{}:{}", runtime.bind_addr, runtime.http_port));
        }
        if endpoints.is_empty() {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        (
            "agent.honeypot_listener",
            "honeypot.listener_session_started",
            format!(
                "Honeypot listener session started for attacker {ip} at {}",
                endpoints.join(", ")
            ),
        )
    } else {
        (
            "agent.honeypot_demo",
            "honeypot.demo_decoy_hit",
            format!(
                "DEMO/SIMULATION/DECOY: attacker {ip} marked as honeypot hit (controlled marker only)"
            ),
        )
    };

    let event = innerwarden_core::event::Event {
        ts: chrono::Utc::now(),
        host: incident.host.clone(),
        source: source.to_string(),
        kind: kind.to_string(),
        severity: innerwarden_core::event::Severity::Info,
        summary,
        details: serde_json::json!({
            "mode": runtime.mode,
            "simulation": !is_listener,
            "decoy": true,
            "target_ip": ip,
            "incident_id": incident.incident_id,
            "dry_run": dry_run,
            "listener_bind_addr": runtime.bind_addr,
            "listener_services": runtime.services.clone(),
            "listener_ssh_port": runtime.port,
            "listener_http_port": runtime.http_port,
            "listener_duration_secs": runtime.duration_secs,
            "listener_strict_target_only": runtime.strict_target_only,
            "listener_max_connections": runtime.max_connections,
            "listener_max_payload_bytes": runtime.max_payload_bytes,
            "listener_isolation_profile": runtime.isolation_profile,
            "listener_require_high_ports": runtime.require_high_ports,
            "listener_forensics_keep_days": runtime.forensics_keep_days,
            "listener_forensics_max_total_mb": runtime.forensics_max_total_mb,
            "listener_transcript_preview_bytes": runtime.transcript_preview_bytes,
            "listener_lock_stale_secs": runtime.lock_stale_secs,
            "listener_sandbox_enabled": runtime.sandbox_enabled,
            "listener_containment_mode": runtime.containment_mode,
            "listener_containment_jail_runner": runtime.containment_jail_runner,
            "listener_containment_jail_profile": runtime.containment_jail_profile,
            "listener_external_handoff_enabled": runtime.external_handoff_enabled,
            "listener_external_handoff_allowlist": runtime.external_handoff_enforce_allowlist,
            "listener_external_handoff_signature": runtime.external_handoff_signature_enabled,
            "listener_external_handoff_attestation": runtime.external_handoff_attestation_enabled,
            "listener_pcap_handoff_enabled": runtime.pcap_handoff_enabled,
            "listener_redirect_enabled": runtime.redirect_enabled,
            "listener_redirect_backend": runtime.redirect_backend,
            "note": if is_listener {
                "Real honeypot listener mode active with bounded decoys and local forensics."
            } else {
                "Demo-only marker; no real honeypot infrastructure is deployed in this mode."
            }
        }),
        tags: vec![
            "honeypot".to_string(),
            "decoy".to_string(),
            if is_listener {
                "listener".to_string()
            } else {
                "demo".to_string()
            },
            if is_listener {
                "real_mode".to_string()
            } else {
                "simulation".to_string()
            },
        ],
        entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
    };

    let line = serde_json::to_string(&event)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&events_path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;

    Ok(events_path)
}

// ---------------------------------------------------------------------------
// Telegram T.2 approval handler
// ---------------------------------------------------------------------------

/// Process a single operator approval result received from the Telegram polling task.
/// Resolves and executes (or discards) the pending confirmation, writes an audit entry,
/// and informs the operator via Telegram of the outcome.
async fn process_telegram_approval(
    result: telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // /status command — log it; a real status reply can be added later
    if result.incident_id == "__status__" {
        info!(operator = %result.operator_name, "Telegram /status command received");
        return;
    }

    let Some((pending, decision, incident)) =
        state.pending_confirmations.remove(&result.incident_id)
    else {
        debug!(
            incident_id = %result.incident_id,
            "Telegram approval for unknown or expired incident — ignoring"
        );
        return;
    };

    // If "Always" — save trust rule before executing
    if result.always {
        info!(
            detector = %pending.detector,
            action = %pending.action_name,
            operator = %result.operator_name,
            "operator added trust rule via Telegram"
        );
        append_trust_rule(data_dir, &mut state.trust_rules, &pending.detector, &pending.action_name);
    }

    // Acknowledge in Telegram: remove inline keyboard and add follow-up message
    let tg = state.telegram_client.clone();
    if let Some(ref tg) = tg {
        let _ = tg
            .resolve_confirmation(
                pending.telegram_message_id,
                result.approved,
                result.always,
                &result.operator_name,
            )
            .await;
    }

    let exec_result = if result.approved {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            always = result.always,
            "operator approved action via Telegram"
        );
        execute_decision(&decision, &incident, data_dir, cfg, state).await
    } else {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            "operator rejected action via Telegram"
        );
        format!("rejected by operator {}", result.operator_name)
    };

    // Audit trail with ai_provider = "telegram:<operator>"
    if let Some(writer) = &mut state.decision_writer {
        let provider = format!("telegram:{}", result.operator_name);
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            &provider,
            &decision,
            cfg.responder.dry_run,
            &exec_result,
        );
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write Telegram decision entry: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Narrative tick — runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
async fn process_narrative_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<usize> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    // Read new events and advance the events cursor
    let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
        &events_path,
        cursor.events_offset(&today),
    )
    .inspect_err(|_| {
        state.telemetry.observe_error("event_reader");
    })?;

    let events_count = new_events.entries.len();
    state.telemetry.observe_events(&new_events.entries);
    cursor.set_events_offset(&today, new_events.new_offset);

    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    // Rule: write if events arrived AND either (a) first write ever, or
    // (b) at least 5 minutes have passed since the last write.
    // Additionally, always write after 30 minutes regardless of event count, so
    // the summary doesn't become stale if a handful of events trickle in slowly.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
            // Always read from offset 0 — summary covers the full day, not just new entries
            let all_events =
                reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)
                    .inspect_err(|_| {
                        state.telemetry.observe_error("narrative_reader");
                    })?;
            let all_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
                &incidents_path,
                0,
            )
            .inspect_err(|_| {
                state.telemetry.observe_error("narrative_reader");
            })?;

            let host = all_events
                .entries
                .first()
                .map(|e| e.host.as_str())
                .or_else(|| all_incidents.entries.first().map(|i| i.host.as_str()))
                .unwrap_or("unknown");

            let md = narrative::generate(
                &today,
                host,
                &all_events.entries,
                &all_incidents.entries,
                cfg.correlation.window_seconds,
            );
            if let Err(e) = narrative::write(data_dir, &today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");
            }
        }
    }

    let snapshot = state.telemetry.snapshot("narrative_tick");
    let mut telemetry_write_failed = false;
    if let Some(writer) = &mut state.telemetry_writer {
        if let Err(e) = writer.write(&snapshot) {
            warn!("failed to write telemetry snapshot: {e:#}");
            telemetry_write_failed = true;
        }
    }
    if telemetry_write_failed {
        state.telemetry.observe_error("telemetry_writer");
    }

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // Minimal mock AI provider — returns a fixed decision, no network I/O
    // ------------------------------------------------------------------

    struct MockAiProvider {
        decision: ai::AiDecision,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for MockAiProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            Ok(self.decision.clone())
        }
    }

    struct CountingMockAiProvider {
        decision: ai::AiDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CountingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-counting"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    struct CorrelationInspectingMockAiProvider {
        decision: ai::AiDecision,
        last_related_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CorrelationInspectingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-correlation"
        }

        async fn decide(&self, ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.last_related_count
                .store(ctx.related_incidents.len(), Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    /// Write a minimal Incident JSON line (ssh brute-force from an external IP).
    fn incident_line(ip: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH Brute Force".to_string(),
            summary: format!("9 failed SSH attempts from {ip}"),
            evidence: serde_json::json!({"failed_attempts": 9}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    fn incident_line_with_kind(ip: &str, kind: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("{kind}:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: format!("{kind} detected"),
            summary: format!("{kind} from {ip}"),
            evidence: serde_json::json!({"kind": kind}),
            recommended_checks: vec![],
            tags: vec![kind.to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    // ------------------------------------------------------------------
    // Golden path: incident → algorithm gate → mock AI → dry-run block → decisions.jsonl
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn golden_path_dry_run_produces_decision_entry() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // 1. Plant a single brute-force incident from a routable external IP.
        //    Must NOT be RFC1918, loopback, or documentation (203.0.113.x / 198.51.100.x
        //    are TEST-NET ranges and would be filtered by the algorithm gate).
        let attacker_ip = "1.2.3.4";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        // 2. Config: AI enabled, responder dry_run=true, ufw backend allowed
        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // 3. Mock provider always recommends blocking the IP
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "9 SSH failures, no success, external IP — classic brute force".to_string(),
                alternatives: vec!["monitor".to_string()],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        // 4. Run the incident tick
        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;

        // Verify: one incident handled
        assert_eq!(handled, 1, "expected 1 incident handled");

        // Verify: cursor advanced (incident will not be re-read on next tick)
        assert!(
            cursor.incidents_offset(&today) > 0,
            "cursor should have advanced past the incident"
        );

        // Verify: decision written to audit trail
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert!(
            content.contains(attacker_ip),
            "decision must record the target IP"
        );
        assert!(
            content.contains("block_ip"),
            "decision must record action type"
        );
        assert!(
            content.contains("\"dry_run\":true"),
            "dry_run must be flagged in audit trail"
        );
        assert!(
            content.contains("mock"),
            "AI provider name must appear in audit trail"
        );
    }

    // ------------------------------------------------------------------
    // allowed_skills whitelist: AI selects a disallowed skill → fallback used
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_skills_whitelist_enforced() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // Use a routable external IP — TEST-NET ranges (203.0.113.x) are filtered by the gate
        let attacker_ip = "5.6.7.8";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                // Only ufw is allowed; AI picks iptables — should fall back silently
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // AI picks iptables (not in whitelist)
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-iptables".to_string(), // NOT in allowed_skills
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;

        // Still handled (not skipped entirely) — fell back to ufw
        assert_eq!(handled, 1);

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        // The execution used the ufw fallback, not iptables.
        // The audit trail still records the IP the AI identified.
        assert!(content.contains(attacker_ip));
    }

    #[tokio::test]
    async fn same_ip_in_same_tick_triggers_single_ai_call() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "9.8.7.6";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "duplicate IP in same tick".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;
        assert_eq!(handled, 2, "both incidents should be accounted for");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "same IP in same tick must call AI only once"
        );

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert_eq!(
            content.lines().count(),
            1,
            "only one decision should be recorded"
        );
    }

    #[tokio::test]
    async fn temporal_correlation_context_is_passed_to_ai() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "2.3.4.5";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line_with_kind(attacker_ip, "port_scan")).unwrap();
        writeln!(
            f,
            "{}",
            incident_line_with_kind(attacker_ip, "credential_stuffing")
        )
        .unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            correlation: config::CorrelationConfig {
                enabled: true,
                window_seconds: 300,
                max_related_incidents: 8,
            },
            responder: config::ResponderConfig {
                enabled: false,
                ..config::ResponderConfig::default()
            },
            ..config::AgentConfig::default()
        };

        let related_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CorrelationInspectingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: "test correlation".to_string(),
                },
                confidence: 0.9,
                auto_execute: false,
                reason: "test correlation".to_string(),
                alternatives: vec![],
                estimated_threat: "medium".to_string(),
            },
            last_related_count: related_count.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;
        assert_eq!(handled, 2);
        assert!(
            related_count.load(Ordering::SeqCst) >= 1,
            "second correlated incident should carry prior incident context"
        );
    }

    #[tokio::test]
    async fn honeypot_demo_writes_synthetic_decoy_event() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "7.7.7.7";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["honeypot".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Honeypot {
                    ip: attacker_ip.to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "demo honeypot test".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;
        assert_eq!(handled, 1);

        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        let content = std::fs::read_to_string(&events_path).unwrap();
        assert!(content.contains("honeypot.demo_decoy_hit"));
        assert!(content.contains("DEMO/SIMULATION/DECOY"));
        assert!(content.contains(attacker_ip));
    }

    // ------------------------------------------------------------------
    // Decision cooldown: second incident from same IP/detector is suppressed
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn decision_cooldown_suppresses_repeat() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "1.2.3.4";

        // Plant TWO identical brute-force incidents from the same IP
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            decision_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;

        // Both incidents are "handled" (counted), but the AI should be called
        // only ONCE — the second incident is suppressed by the decision
        // cooldown that was recorded after the first decision.
        assert_eq!(handled, 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "AI should be called once — second incident suppressed by cooldown"
        );

        // Verify the cooldown entry was recorded
        assert!(
            !state.decision_cooldowns.is_empty(),
            "decision cooldown should be recorded"
        );
    }
}
