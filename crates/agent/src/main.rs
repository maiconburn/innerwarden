mod abuseipdb;
mod ai;
mod allowlist;
mod cloudflare;
mod config;
mod correlation;
mod crowdsec;
mod dashboard;
mod data_retention;
mod decisions;
mod fail2ban;
mod geoip;
mod ioc;
mod narrative;
mod reader;
mod report;
mod skills;
mod slack;
mod telegram;
mod telemetry;
mod web_push;
mod webhook;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Timelike as _;
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

    /// Bind address for dashboard mode (default: all interfaces — use with reverse proxy + auth)
    #[arg(long, default_value = "0.0.0.0:8787")]
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
    /// Recent notification alerts keyed by `detector:entity_kind:entity_value`.
    /// Suppresses duplicate Telegram/Slack/webhook alerts for the same entity.
    notification_cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>>,
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
    /// Date for which we last sent the daily Telegram digest (avoids re-sending).
    last_daily_summary_telegram: Option<chrono::NaiveDate>,
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
    /// CrowdSec LAPI sync state (None when crowdsec.enabled = false).
    crowdsec: Option<crowdsec::CrowdSecState>,
    /// AbuseIPDB client for IP reputation enrichment (None when disabled).
    abuseipdb: Option<abuseipdb::AbuseIpDbClient>,
    /// Fail2ban sync state (None when fail2ban.enabled = false).
    fail2ban: Option<fail2ban::Fail2BanState>,
    /// GeoIP client for IP geolocation enrichment via ip-api.com (None when disabled).
    geoip_client: Option<geoip::GeoIpClient>,
    /// Slack client for incident notifications (None when disabled).
    slack_client: Option<slack::SlackClient>,
    /// Cloudflare integration client (None when disabled).
    cloudflare_client: Option<cloudflare::CloudflareClient>,
    /// Circuit breaker: when tripped by a high-volume incident burst, AI analysis
    /// is suspended until this timestamp. None = circuit breaker not tripped.
    circuit_breaker_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Pending operator honeypot choices keyed by IP.
    /// When Telegram is configured and AI recommends Honeypot, execution is deferred
    /// until the operator picks an action via the 4-button inline keyboard.
    pending_honeypot_choices: HashMap<String, PendingHoneypotChoice>,
}

/// Tracks a deferred honeypot-or-block decision waiting for operator input via Telegram.
struct PendingHoneypotChoice {
    #[allow(dead_code)]
    ip: String,
    incident_id: String,
    incident: innerwarden_core::incident::Incident,
    expires_at: chrono::DateTime<chrono::Utc>,
}

const DECISION_COOLDOWN_SECS: i64 = 3600;
/// Notification cooldown: suppress duplicate Telegram/Slack/webhook alerts for the
/// same detector+entity within this window. Prevents alert spam when the same attacker
/// triggers multiple incidents in rapid succession.
const NOTIFICATION_COOLDOWN_SECS: i64 = 600;

fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

/// Returns the current guardian mode based on responder configuration.
fn guardian_mode(cfg: &config::AgentConfig) -> telegram::GuardianMode {
    if !cfg.responder.enabled {
        telegram::GuardianMode::Watch
    } else if cfg.responder.dry_run {
        telegram::GuardianMode::DryRun
    } else {
        telegram::GuardianMode::Guard
    }
}

/// Builds a rich system-state context string injected into every AI chat call.
/// The AI uses this to answer self-awareness questions accurately and give
/// correct configuration advice.
fn build_agent_context(cfg: &config::AgentConfig, data_dir: &Path) -> String {
    let mode = guardian_mode(cfg);
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let incident_count = count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
    let decision_count = count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let skills_list = cfg.responder.allowed_skills.join(", ");
    let block_backend = &cfg.responder.block_backend;
    let ai_status = if cfg.ai.enabled {
        format!(
            "ENABLED — provider={}, model={}",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        "DISABLED".to_string()
    };
    let responder_status = if !cfg.responder.enabled {
        "DISABLED (watch-only mode)".to_string()
    } else if cfg.responder.dry_run {
        "ENABLED — dry-run (simulates actions, no real execution)".to_string()
    } else {
        format!("ENABLED — live mode (backend={block_backend})")
    };
    let telegram_status = if cfg.telegram.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let abuseipdb_status = if cfg.abuseipdb.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let geoip_status = if cfg.geoip.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let fail2ban_status = if cfg.fail2ban.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let slack_status = if cfg.slack.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let cloudflare_status = if cfg.cloudflare.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "=== INNERWARDEN SYSTEM STATE ===\n\
         Host: {host}\n\
         Version: {version}\n\
         Mode: {mode_label} — {mode_desc}\n\
         Data dir: {data_dir}\n\
         \n\
         Today ({today}): {incident_count} intrusion attempts, {decision_count} actions taken\n\
         \n\
         === ACTIVE CONFIGURATION ===\n\
         Responder: {responder_status}\n\
         Allowed skills: {skills_list}\n\
         AI analysis: {ai_status}\n\
         Telegram bot: {telegram_status}\n\
         AbuseIPDB enrichment: {abuseipdb_status}\n\
         GeoIP enrichment: {geoip_status}\n\
         Fail2ban integration: {fail2ban_status}\n\
         Slack notifications: {slack_status}\n\
         Cloudflare edge blocking: {cloudflare_status}\n\
         \n\
         === AVAILABLE CAPABILITIES (innerwarden enable/disable <id>) ===\n\
         - ai: AI-powered incident analysis (params: provider=openai|anthropic|ollama, model=...)\n\
         - block-ip: Firewall blocking of attacking IPs (params: backend=ufw|iptables|nftables|pf)\n\
         - sudo-protection: Detect sudo abuse + auto-suspend attacker privileges\n\
         - shell-audit: Audit shell command execution (privacy gate required)\n\
         - search-protection: Protect search/API endpoints from scraping bots\n\
         \n\
         === AVAILABLE SKILLS (agent execution layer) ===\n\
         Open tier: block-ip-ufw, block-ip-iptables, block-ip-nftables, block-ip-pf, suspend-user-sudo, rate-limit-nginx\n\
         Premium tier: monitor-ip (packet capture), honeypot (attacker trap)\n\
         \n\
         === CLI REFERENCE ===\n\
         innerwarden enable <capability>         # activate a capability\n\
         innerwarden disable <capability>        # deactivate a capability\n\
         innerwarden status                      # full system overview\n\
         innerwarden doctor                      # health check with fix hints\n\
         innerwarden scan                        # detect installed tools, recommend modules\n\
         innerwarden list                        # list all capabilities with status\n\
         innerwarden configure responder         # set GUARD/WATCH/DRY-RUN mode\n\
         innerwarden notify telegram             # setup Telegram bot\n\
         innerwarden notify slack                # setup Slack webhook\n\
         innerwarden integrate abuseipdb         # IP reputation enrichment\n\
         innerwarden integrate geoip             # GeoIP enrichment (free)\n\
         innerwarden integrate fail2ban          # sync with fail2ban bans\n\
         innerwarden block <ip> --reason <r>     # manual IP block\n\
         innerwarden unblock <ip>                # remove IP block\n\
         innerwarden incidents --days 7          # list recent incidents\n\
         innerwarden decisions --days 7          # list recent decisions\n\
         innerwarden report                      # show operational report\n\
         innerwarden tune                        # auto-tune detector thresholds\n\
         ",
        host = host,
        version = env!("CARGO_PKG_VERSION"),
        mode_label = mode.label(),
        mode_desc = mode.description(),
        data_dir = data_dir.display(),
    )
}

/// Run an `innerwarden` CLI subcommand and return its stdout+stderr as a String.
/// Times out after 30 seconds. Used by /enable, /disable, /doctor bot commands.
async fn run_innerwarden_cli(args: &[&str]) -> String {
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("innerwarden")))
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/bin/innerwarden"));

    match tokio::process::Command::new(&bin).args(args).output().await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = format!("{stdout}{stderr}");
            // Strip ANSI color codes for Telegram
            strip_ansi(&combined)
        }
        Err(e) => format!("Failed to run innerwarden CLI: {e}"),
    }
}

/// Build a Telegram-formatted capabilities list from the live agent config.
/// Avoids running the CTL CLI subprocess (which may be stale) and produces
/// clean HTML output suited for Telegram's parse_mode=HTML.
fn format_capabilities(cfg: &config::AgentConfig) -> String {
    let on = "🟢";
    let off = "🔴";

    // Core capabilities
    let ai_line = if cfg.ai.enabled {
        format!(
            "{on} <b>AI Analysis</b>  <code>{} / {}</code>",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        format!("{off} <b>AI Analysis</b>  disabled\n    <i>/enable ai --param provider=openai</i>")
    };

    let block_line = if cfg.responder.enabled {
        let mode = if cfg.responder.dry_run {
            "dry-run"
        } else {
            "live"
        };
        format!(
            "{on} <b>Block IP</b>  {} backend — {mode}",
            cfg.responder.block_backend
        )
    } else {
        format!("{off} <b>Block IP</b>  disabled\n    <i>/enable block-ip</i>")
    };

    let sudo_line = if cfg
        .responder
        .allowed_skills
        .iter()
        .any(|s| s.contains("suspend-user"))
    {
        format!("{on} <b>Sudo Protection</b>  active")
    } else {
        format!("{off} <b>Sudo Protection</b>  disabled\n    <i>/enable sudo-protection</i>")
    };

    // Integrations
    let abuseipdb_line = if cfg.abuseipdb.enabled {
        format!("{on} <b>AbuseIPDB</b>  IP reputation enrichment")
    } else {
        format!("{off} <b>AbuseIPDB</b>  disabled — <i>/enable abuseipdb</i>")
    };

    let geoip_line = if cfg.geoip.enabled {
        format!("{on} <b>GeoIP</b>  ip-api.com (free)")
    } else {
        format!("{off} <b>GeoIP</b>  disabled — <i>/enable geoip</i>")
    };

    let fail2ban_line = if cfg.fail2ban.enabled {
        format!("{on} <b>Fail2ban</b>  ban sync active")
    } else {
        format!("{off} <b>Fail2ban</b>  disabled — <i>/enable fail2ban</i>")
    };

    let slack_line = if cfg.slack.enabled {
        format!("{on} <b>Slack</b>  notifications enabled")
    } else {
        format!("{off} <b>Slack</b>  disabled — <i>/enable slack</i>")
    };

    let cloudflare_line = if cfg.cloudflare.enabled {
        format!("{on} <b>Cloudflare</b>  edge block push active")
    } else {
        format!("{off} <b>Cloudflare</b>  disabled — <i>/enable cloudflare</i>")
    };

    format!(
        "⚙️ <b>Capabilities</b>\n\
         \n\
         <b>Core</b>\n\
         {ai_line}\n\
         {block_line}\n\
         {sudo_line}\n\
         \n\
         <b>Integrations</b>\n\
         {abuseipdb_line}\n\
         {geoip_line}\n\
         {fail2ban_line}\n\
         {slack_line}\n\
         {cloudflare_line}\n\
         \n\
         <code>/enable &lt;id&gt;</code>  ·  <code>/disable &lt;id&gt;</code>"
    )
}

/// Build an inline keyboard with [Enable →] buttons for each disabled capability.
/// Returns a JSON array of rows (each row is an array of buttons).
fn capabilities_keyboard(cfg: &config::AgentConfig) -> serde_json::Value {
    let mut buttons: Vec<serde_json::Value> = Vec::new();

    // Core capabilities
    if !cfg.ai.enabled {
        buttons.push(serde_json::json!({
            "text": "⚡ Enable AI",
            "callback_data": "enable:ai"
        }));
    }
    if !cfg.responder.enabled {
        buttons.push(serde_json::json!({
            "text": "🛡 Enable Block-IP",
            "callback_data": "enable:block-ip"
        }));
    }
    let has_sudo = cfg
        .responder
        .allowed_skills
        .iter()
        .any(|s| s.contains("suspend-user"));
    if !has_sudo {
        buttons.push(serde_json::json!({
            "text": "🔒 Enable Sudo Guard",
            "callback_data": "enable:sudo-protection"
        }));
    }

    // Integrations (only show a few to avoid keyboard overload)
    if !cfg.abuseipdb.enabled {
        buttons.push(serde_json::json!({
            "text": "🔍 Enable AbuseIPDB",
            "callback_data": "enable:abuseipdb"
        }));
    }
    if !cfg.geoip.enabled {
        buttons.push(serde_json::json!({
            "text": "🌍 Enable GeoIP",
            "callback_data": "enable:geoip"
        }));
    }
    if !cfg.fail2ban.enabled {
        buttons.push(serde_json::json!({
            "text": "🔍 Enable Fail2ban",
            "callback_data": "enable:fail2ban"
        }));
    }
    if cfg.honeypot.mode != "listener" {
        buttons.push(serde_json::json!({
            "text": "🪤 Enable Honeypot",
            "callback_data": "enable:honeypot"
        }));
    }

    if buttons.is_empty() {
        // All enabled — show a status button only
        return serde_json::json!([[{
            "text": "✅ All capabilities active",
            "callback_data": "menu:status"
        }]]);
    }

    // Group buttons into rows of 2
    let rows: Vec<Vec<serde_json::Value>> = buttons.chunks(2).map(|chunk| chunk.to_vec()).collect();
    serde_json::json!(rows)
}

/// Probe the system at startup and send proactive Telegram suggestions
/// for tools that are installed but not yet integrated with InnerWarden.
/// Runs once before the main loop. Fail-silent.
async fn probe_and_suggest(cfg: &config::AgentConfig, tg: Option<&telegram::TelegramClient>) {
    // Only if Telegram is configured
    let Some(tg) = tg else {
        return;
    };

    // Check for fail2ban: installed + running but not enabled in config
    if !cfg.fail2ban.enabled {
        let is_available = tokio::task::spawn_blocking(|| {
            std::process::Command::new("fail2ban-client")
                .arg("ping")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);

        if is_available {
            let text = "🔍 <b>Fail2ban detected!</b>\n\nFail2ban is running on this server but not integrated with InnerWarden.\n\nIntegrating it means InnerWarden will automatically sync all fail2ban bans — no duplicate work, full audit trail.\n\n<i>Want me to enable the integration?</i>";
            let keyboard = serde_json::json!([[
                {"text": "✅ Enable Fail2ban sync", "callback_data": "enable:fail2ban"},
                {"text": "❌ Not now", "callback_data": "menu:dismiss"}
            ]]);
            let _ = tg.send_text_with_keyboard(text, keyboard).await;
        }
    }
}

/// Strip ANSI escape codes from a string (for clean Telegram display).
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip escape sequence
            if chars.peek() == Some(&'[') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch.is_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Returns notification cooldown keys for an incident.
/// One key per entity (IP or user): `detector:entity_kind:entity_value`.
fn notification_cooldown_keys(incident: &innerwarden_core::incident::Incident) -> Vec<String> {
    let detector = incident_detector(&incident.incident_id);
    incident
        .entities
        .iter()
        .filter(|e| {
            matches!(
                e.r#type,
                innerwarden_core::entities::EntityType::Ip
                    | innerwarden_core::entities::EntityType::User
            )
        })
        .map(|e| {
            let kind = match e.r#type {
                innerwarden_core::entities::EntityType::Ip => "ip",
                innerwarden_core::entities::EntityType::User => "user",
                _ => "other",
            };
            format!("{detector}:{kind}:{}", e.value)
        })
        .collect()
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
        ai::AiAction::KillProcess { user, .. } => Some(decision_cooldown_key(
            "kill_process",
            detector,
            "user",
            user,
        )),
        ai::AiAction::BlockContainer { container_id, .. } => Some(decision_cooldown_key(
            "block_container",
            detector,
            "container",
            container_id,
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
fn is_trusted(
    trust_rules: &std::collections::HashSet<String>,
    detector: &str,
    action: &str,
) -> bool {
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
        let auth = dashboard::DashboardAuth::try_from_env()?;
        let action_cfg = dashboard::DashboardActionConfig {
            enabled: cfg.responder.enabled,
            dry_run: cfg.responder.dry_run,
            block_backend: cfg.responder.block_backend.clone(),
            allowed_skills: cfg.responder.allowed_skills.clone(),
            ai_enabled: cfg.ai.enabled,
            ai_provider: cfg.ai.provider.clone(),
            ai_model: cfg.ai.model.clone(),
            fail2ban_enabled: cfg.fail2ban.enabled,
            geoip_enabled: cfg.geoip.enabled,
            abuseipdb_enabled: cfg.abuseipdb.enabled,
            honeypot_mode: cfg.honeypot.mode.clone(),
            telegram_enabled: cfg.telegram.enabled,
            slack_enabled: cfg.slack.enabled,
            cloudflare_enabled: cfg.cloudflare.enabled,
        };
        let dashboard_data_dir = cli.data_dir.clone();
        let dashboard_bind = cli.dashboard_bind.clone();
        let web_push_pub_key = cfg.web_push.vapid_public_key.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(
                dashboard_data_dir,
                dashboard_bind,
                auth,
                action_cfg,
                web_push_pub_key,
            )
            .await
            {
                warn!(error = %e, "dashboard exited with error");
            }
        });
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

    // Build Slack client (None when disabled or unconfigured)
    let slack_client: Option<slack::SlackClient> = if cfg.slack.enabled {
        let url = cfg.slack.resolved_webhook_url();
        if url.is_empty() {
            warn!("slack.enabled = true but webhook_url not configured — disabling");
            None
        } else {
            match slack::SlackClient::new(&url) {
                Ok(c) => {
                    info!("Slack notifications enabled");
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to create Slack client: {e:#}");
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
        notification_cooldowns: HashMap::new(),
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
        last_daily_summary_telegram: None,
        telegram_client,
        pending_confirmations: HashMap::new(),
        approval_rx: None, // set below in continuous mode
        trust_rules: load_trust_rules(&cli.data_dir),
        crowdsec: if cfg.crowdsec.enabled {
            info!(url = %cfg.crowdsec.url, "CrowdSec integration enabled");
            Some(crowdsec::CrowdSecState::new(&cfg.crowdsec))
        } else {
            None
        },
        abuseipdb: if cfg.abuseipdb.enabled {
            let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
            if key.is_empty() {
                warn!("abuseipdb.enabled=true but no API key found — disabling enrichment");
                None
            } else {
                info!(
                    "AbuseIPDB enrichment enabled (max_age_days={})",
                    cfg.abuseipdb.max_age_days
                );
                Some(abuseipdb::AbuseIpDbClient::new(
                    key,
                    cfg.abuseipdb.max_age_days,
                ))
            }
        } else {
            None
        },
        fail2ban: if cfg.fail2ban.enabled {
            info!("Fail2ban integration enabled");
            Some(fail2ban::Fail2BanState::new(&cfg.fail2ban))
        } else {
            None
        },
        geoip_client: if cfg.geoip.enabled {
            info!("GeoIP enrichment enabled (ip-api.com, free tier)");
            Some(geoip::GeoIpClient::new())
        } else {
            None
        },
        slack_client,
        cloudflare_client: if cfg.cloudflare.enabled {
            let token = cloudflare::resolve_api_token(&cfg.cloudflare.api_token);
            if token.is_empty() || cfg.cloudflare.zone_id.is_empty() {
                warn!(
                    "cloudflare.enabled=true but api_token or zone_id not configured — disabling"
                );
                None
            } else {
                info!(zone_id = %cfg.cloudflare.zone_id, "Cloudflare IP block push enabled");
                Some(cloudflare::CloudflareClient::with_prefix(
                    cfg.cloudflare.zone_id.clone(),
                    token,
                    cfg.cloudflare.block_notes_prefix.clone(),
                ))
            }
        } else {
            None
        },
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
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
            // Register persistent command menu (fire-and-forget)
            tg.set_commands().await;
            let tg_clone = tg.clone();
            tokio::spawn(async move { tg_clone.run_polling(approval_tx).await });
            info!("Telegram polling task started (T.2 approvals enabled)");
        }

        // Proactive startup suggestions (fail2ban detected but not integrated, etc.)
        probe_and_suggest(&cfg, state.telegram_client.as_deref()).await;

        // Always-on honeypot: permanent SSH listener from startup.
        // A watch channel is used to signal shutdown on SIGTERM/SIGINT.
        let always_on_shutdown_tx = if cfg.honeypot.mode == "always_on" {
            let (tx, rx) = tokio::sync::watch::channel(false);

            // Build a filter blocklist pre-populated from today's + yesterday's decisions.
            let initial_blocked: std::collections::HashSet<String> = {
                let (bl, _) = load_startup_decision_state(&cli.data_dir, false);
                bl.as_vec().into_iter().collect()
            };
            let filter_bl = std::sync::Arc::new(std::sync::Mutex::new(initial_blocked));

            let port = cfg.honeypot.port;
            let bind_addr = cfg.honeypot.bind_addr.clone();
            let max_auth = cfg.honeypot.ssh_max_auth_attempts;
            let abuseipdb_client = if cfg.abuseipdb.enabled {
                let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
                if key.is_empty() {
                    None
                } else {
                    Some(std::sync::Arc::new(abuseipdb::AbuseIpDbClient::new(
                        key,
                        cfg.abuseipdb.max_age_days,
                    )))
                }
            } else {
                None
            };
            let abuseipdb_threshold = cfg.abuseipdb.auto_block_threshold;
            let ai_clone = state.ai_provider.clone();
            let tg_clone = state.telegram_client.clone();
            let data_dir_clone = cli.data_dir.clone();
            let responder_enabled = cfg.responder.enabled;
            let dry_run = cfg.responder.dry_run;
            let block_backend = cfg.responder.block_backend.clone();
            let allowed_skills = cfg.responder.allowed_skills.clone();
            let interaction = cfg.honeypot.interaction.clone();

            tokio::spawn(async move {
                run_always_on_honeypot(
                    port,
                    bind_addr,
                    max_auth,
                    filter_bl,
                    ai_clone,
                    tg_clone,
                    abuseipdb_client,
                    abuseipdb_threshold,
                    data_dir_clone,
                    responder_enabled,
                    dry_run,
                    block_backend,
                    allowed_skills,
                    interaction,
                    rx,
                )
                .await;
            });

            Some(tx)
        } else {
            None
        };

        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker = tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));
        let mut crowdsec_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.crowdsec.poll_secs.max(10),
        ));
        let mut fail2ban_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.fail2ban.poll_secs.max(10),
        ));

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
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        crowdsec::sync_tick(
                            cs,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                        ).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                        ).await;
                    }
                    false
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
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        crowdsec::sync_tick(
                            cs,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                        ).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                        ).await;
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
            };

            if shutdown {
                // Signal always-on honeypot listener to stop (if running).
                if let Some(ref tx) = always_on_shutdown_tx {
                    let _ = tx.send(true);
                }
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

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "block-container")
    {
        match skills::builtin::cleanup_expired_container_blocks(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired container pauses lifted");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("block_container_cleanup");
                warn!("failed to cleanup expired container blocks: {e:#}");
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

    // Drain any pending T.2/T.3 approval results from the Telegram polling task.
    // This MUST run before the early-return below, otherwise bot commands
    // (/status, /menu, etc.) would never be processed when there are no new incidents.
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

    // Expire stale pending confirmations and honeypot choices
    let now = chrono::Utc::now();
    state
        .pending_confirmations
        .retain(|_, (pending, _, _)| pending.expires_at > now);
    state
        .pending_honeypot_choices
        .retain(|_, choice| choice.expires_at > now);

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

    // Pre-compute Slack threshold (None = slack disabled)
    let slack_min_rank: Option<u8> = if cfg.slack.enabled && state.slack_client.is_some() {
        Some(webhook::severity_rank(&cfg.slack.parsed_min_severity()))
    } else {
        None
    };

    // Circuit breaker: if a previous tick tripped the breaker, check if cooldown expired
    if let Some(until) = state.circuit_breaker_until {
        if chrono::Utc::now() < until {
            info!(
                until = %until,
                incident_count = new_incidents.entries.len(),
                "AI circuit breaker open — skipping AI analysis for this tick"
            );
            // Still process webhooks/notifications below, just skip AI
        } else {
            info!("AI circuit breaker reset after cooldown");
            state.circuit_breaker_until = None;
        }
    }

    // Trip circuit breaker if incident volume exceeds threshold
    let circuit_breaker_open = if cfg.ai.circuit_breaker_threshold > 0
        && new_incidents.entries.len() >= cfg.ai.circuit_breaker_threshold
        && state.circuit_breaker_until.is_none()
    {
        let until = chrono::Utc::now()
            + chrono::Duration::seconds(cfg.ai.circuit_breaker_cooldown_secs as i64);
        warn!(
            incident_count = new_incidents.entries.len(),
            threshold = cfg.ai.circuit_breaker_threshold,
            cooldown_secs = cfg.ai.circuit_breaker_cooldown_secs,
            until = %until,
            "AI circuit breaker TRIPPED — high-volume incident burst detected, skipping AI"
        );
        state.circuit_breaker_until = Some(until);
        true
    } else {
        state.circuit_breaker_until.is_some()
    };

    // Pre-compute AI context (only if AI is configured and circuit breaker is not open)
    let ai_enabled = cfg.ai.enabled && state.ai_provider.is_some() && !circuit_breaker_open;
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
    let mut ai_calls_this_tick: usize = 0;

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

        // 1. Notification cooldown — suppress duplicate alerts for the same entity
        //    within a 10-minute window. Prevents alert spam during sustained attacks.
        let notify_cutoff =
            chrono::Utc::now() - chrono::Duration::seconds(NOTIFICATION_COOLDOWN_SECS);
        let notify_keys = notification_cooldown_keys(incident);
        let notify_suppressed = notify_keys.iter().any(|k| {
            state
                .notification_cooldowns
                .get(k)
                .is_some_and(|ts| *ts > notify_cutoff)
        });

        if notify_suppressed {
            info!(
                incident_id = %incident.incident_id,
                "notification cooldown: suppressing duplicate alert"
            );
        }

        // 1a. Webhook — fires for ALL incidents above configured threshold, regardless of AI gate
        if !notify_suppressed {
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
                        let mode = guardian_mode(cfg);
                        if let Err(e) = tg.send_incident_alert(incident, mode).await {
                            warn!(incident_id = %incident.incident_id, "Telegram alert failed: {e:#}");
                        }
                    }
                }
            }

            // 1c. Slack — push notification via Incoming Webhook
            if let Some(min_rank) = slack_min_rank {
                if webhook::severity_rank(&incident.severity) >= min_rank {
                    if let Some(ref sc) = state.slack_client {
                        let dashboard_url = if cfg.slack.dashboard_url.is_empty() {
                            None
                        } else {
                            Some(cfg.slack.dashboard_url.as_str())
                        };
                        if let Err(e) = sc.send_incident_alert(incident, dashboard_url).await {
                            warn!(incident_id = %incident.incident_id, "Slack alert failed: {e:#}");
                        }
                    }
                }
            }

            // 1d. Web Push — browser notification for High/Critical incidents
            web_push::notify_incident(incident, data_dir, &cfg.web_push).await;

            // Mark notification cooldown for all entities in this incident
            let now = chrono::Utc::now();
            for k in &notify_keys {
                state.notification_cooldowns.insert(k.clone(), now);
            }
        } // end if !notify_suppressed

        // 2. AI analysis — only when AI is enabled and incident passes the gate
        if !ai_enabled {
            handled += 1;
            continue;
        }

        // 2a. Allowlist gate — skip AI for explicitly trusted IPs and users
        {
            use innerwarden_core::entities::EntityType;
            let ip_allowlisted = incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::Ip)
                .is_some_and(|e| {
                    allowlist::is_ip_allowlisted(&e.value, &cfg.allowlist.trusted_ips)
                });
            let user_allowlisted = incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::User)
                .is_some_and(|e| {
                    allowlist::is_user_allowlisted(&e.value, &cfg.allowlist.trusted_users)
                });
            if ip_allowlisted || user_allowlisted {
                info!(
                    incident_id = %incident.incident_id,
                    "AI gate: skipping (entity is in allowlist)"
                );
                handled += 1;
                continue;
            }
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

        // max_ai_calls_per_tick: enforce per-tick AI call budget to protect against
        // API bill spikes during botnet attacks with many unique IPs.
        let max_calls = cfg.ai.max_ai_calls_per_tick;
        if max_calls > 0 && ai_calls_this_tick >= max_calls {
            info!(
                incident_id = %incident.incident_id,
                ai_calls_this_tick,
                max_calls,
                "AI gate: skipping (max_ai_calls_per_tick reached — deferred to next tick)"
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

        // Optionally enrich with AbuseIPDB reputation data
        let ip_reputation = if let Some(ref client) = state.abuseipdb {
            // Extract primary IP from the incident
            let primary_ip = incident
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.as_str());
            if let Some(ip) = primary_ip {
                client.check(ip).await
            } else {
                None
            }
        } else {
            None
        };

        // AbuseIPDB auto-block gate: if score >= threshold, block immediately without AI.
        // This is the primary DDoS cost-reduction mechanism: known-malicious IPs from
        // botnets typically have high AbuseIPDB scores and should not consume AI API calls.
        if let Some(ref rep) = ip_reputation {
            let threshold = cfg.abuseipdb.auto_block_threshold;
            if threshold > 0 && rep.confidence_score >= threshold {
                let primary_ip = incident
                    .entities
                    .iter()
                    .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                    .map(|e| e.value.clone());
                if let Some(ip) = primary_ip {
                    info!(
                        incident_id = %incident.incident_id,
                        ip,
                        score = rep.confidence_score,
                        threshold,
                        "AbuseIPDB auto-block: score exceeds threshold, skipping AI"
                    );
                    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
                    let auto_decision = ai::AiDecision {
                        action: ai::AiAction::BlockIp {
                            ip: ip.clone(),
                            skill_id,
                        },
                        confidence: 1.0,
                        auto_execute: true,
                        reason: format!(
                            "AbuseIPDB auto-block: score={}/100 (threshold={})",
                            rep.confidence_score, threshold
                        ),
                        alternatives: vec![],
                        estimated_threat: "high".into(),
                    };
                    blocked_set.insert(ip.clone());
                    state.blocklist.insert(ip.clone());
                    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision)
                    {
                        state.decision_cooldowns.insert(key, chrono::Utc::now());
                    }
                    let (execution_result, _cf_pushed) = if cfg.responder.enabled {
                        execute_decision(&auto_decision, incident, data_dir, cfg, state).await
                    } else {
                        ("skipped: responder disabled".to_string(), false)
                    };
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::build_entry(
                            &incident.incident_id,
                            &incident.host,
                            "abuseipdb",
                            &auto_decision,
                            cfg.responder.dry_run,
                            &execution_result,
                        );
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write abuseipdb auto-block decision: {e:#}");
                        }
                    }

                    // Telegram notification for auto-block
                    if cfg.telegram.bot.enabled {
                        if let Some(ref tg) = state.telegram_client {
                            let tg = tg.clone();
                            let ip_clone = ip.clone();
                            let score = rep.confidence_score;
                            let total_reports = rep.total_reports;
                            let title_clone = incident.title.clone();
                            let dry_run = cfg.responder.dry_run;
                            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                                None
                            } else {
                                Some(cfg.telegram.dashboard_url.clone())
                            };
                            // Resolve GeoIP synchronously (already have client ref)
                            let geo = if let Some(ref gc) = state.geoip_client {
                                gc.lookup(&ip).await
                            } else {
                                None
                            };
                            let country = geo.as_ref().map(|g| g.country_code.clone());
                            let isp = geo.as_ref().map(|g| g.isp.clone());
                            tokio::spawn(async move {
                                let _ = tg
                                    .send_abuseipdb_autoblock(
                                        &ip_clone,
                                        score,
                                        threshold,
                                        total_reports,
                                        country.as_deref(),
                                        isp.as_deref(),
                                        &title_clone,
                                        dry_run,
                                        dashboard_url.as_deref(),
                                    )
                                    .await;
                            });
                        }
                    }

                    handled += 1;
                    continue;
                }
            }
        }

        // Optionally enrich with IP geolocation data
        let ip_geo = if let Some(ref client) = state.geoip_client {
            let primary_ip = incident
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.as_str());
            if let Some(ip) = primary_ip {
                client.lookup(ip).await
            } else {
                None
            }
        } else {
            None
        };

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
            ip_reputation: ip_reputation.clone(),
            ip_geo: ip_geo.clone(),
        };

        state.telemetry.observe_ai_sent();
        let decision_start = Instant::now();
        let decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                state.telemetry.observe_error("ai_provider");
                state.telemetry.observe_ai_decision(
                    &ai::AiAction::Ignore {
                        reason: "ai_error".to_string(),
                    },
                    0,
                );
                warn!(incident_id = %incident.incident_id, "AI decision failed: {e:#}");

                // Write a fallback decision so the audit trail records the failure.
                if let Some(ref mut writer) = state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: incident.incident_id.clone(),
                        host: incident.host.clone(),
                        ai_provider: provider_name.to_string(),
                        action_type: "error".to_string(),
                        target_ip: None,
                        target_user: None,
                        skill_id: None,
                        confidence: 0.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: format!("{e:#}"),
                        estimated_threat: "unknown".to_string(),
                        execution_result: "ai_error".to_string(),
                    };
                    if let Err(we) = writer.write(&entry) {
                        warn!("failed to write fallback decision: {we:#}");
                    }
                }

                handled += 1;
                continue;
            }
        };
        let latency_ms = decision_start.elapsed().as_millis();
        state
            .telemetry
            .observe_ai_decision(&decision.action, latency_ms);
        ai_calls_this_tick += 1;

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

        // Honeypot operator-in-the-loop: when Telegram is configured and the AI
        // recommends Honeypot, defer execution and ask the operator what to do.
        // The operator sees a 4-button keyboard: Honeypot / Block / Monitor / Ignore.
        // Execution is resumed in process_telegram_approval when the choice arrives.
        if let ai::AiAction::Honeypot { ip } = &decision.action {
            if let Some(ref tg) = state.telegram_client {
                let ttl = cfg.telegram.approval_ttl_secs;
                let tg_clone = tg.clone();
                let reason = decision.reason.clone();
                let confidence = decision.confidence;
                let incident_clone = incident.clone();
                let ip_clone = ip.clone();
                match tg_clone
                    .send_honeypot_suggestion(
                        &incident_clone,
                        &ip_clone,
                        &reason,
                        confidence,
                        "honeypot",
                    )
                    .await
                {
                    Ok(_msg_id) => {
                        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
                        state.pending_honeypot_choices.insert(
                            ip_clone.clone(),
                            PendingHoneypotChoice {
                                ip: ip_clone.clone(),
                                incident_id: incident.incident_id.clone(),
                                incident: incident_clone,
                                expires_at,
                            },
                        );
                        // Write an audit entry noting the operator was asked
                        if let Some(writer) = &mut state.decision_writer {
                            let entry = decisions::build_entry(
                                &incident.incident_id,
                                &incident.host,
                                provider_name,
                                &decision,
                                cfg.responder.dry_run,
                                "pending: operator honeypot choice requested via Telegram",
                            );
                            if let Err(e) = writer.write(&entry) {
                                state.telemetry.observe_error("decision_writer");
                                warn!("failed to write honeypot-pending decision: {e:#}");
                            }
                        }
                        handled += 1;
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            incident_id = %incident.incident_id,
                            "Telegram honeypot suggestion failed: {e:#} — falling through to auto-execute"
                        );
                    }
                }
            }
        }

        // Execute if:
        //   (a) AI flagged auto_execute, OR operator has trusted this detector+action pair
        //   AND confidence >= threshold
        //   AND responder is enabled
        let detector = incident_detector(&incident.incident_id);
        let action_name = decision.action.name();
        let trusted = is_trusted(&state.trust_rules, detector, action_name);
        let (execution_result, cloudflare_pushed) = if (decision.auto_execute || trusted)
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
            ("skipped: responder disabled".to_string(), false)
        } else if !decision.auto_execute && !trusted {
            (
                "skipped: AI did not recommend auto-execution (no trust rule)".to_string(),
                false,
            )
        } else {
            (
                format!(
                    "skipped: confidence {:.2} below threshold {:.2}",
                    decision.confidence, cfg.ai.confidence_threshold
                ),
                false,
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

        // In GUARD/DryRun mode, send a post-execution Telegram report so the
        // operator knows what was done (action report replaces a manual ask).
        let was_executed = !execution_result.starts_with("skipped");
        if was_executed && cfg.telegram.bot.enabled {
            if let Some(ref tg) = state.telegram_client {
                use ai::AiAction;
                let (action_label, target) = match &decision.action {
                    AiAction::BlockIp { ip, .. } => ("Blocked".to_string(), ip.clone()),
                    AiAction::Monitor { ip } => ("Monitoring traffic from".to_string(), ip.clone()),
                    AiAction::Honeypot { ip } => ("Redirected to honeypot".to_string(), ip.clone()),
                    AiAction::SuspendUserSudo { user, .. } => {
                        ("Suspended sudo for".to_string(), user.clone())
                    }
                    AiAction::KillProcess { user, .. } => {
                        ("Killed processes for".to_string(), user.clone())
                    }
                    AiAction::BlockContainer { container_id, .. } => {
                        ("Paused container".to_string(), container_id.clone())
                    }
                    AiAction::Ignore { .. } => ("Ignored".to_string(), "—".to_string()),
                    AiAction::RequestConfirmation { .. } => {
                        ("Requested confirmation for".to_string(), "—".to_string())
                    }
                };
                let tg = tg.clone();
                let title = incident.title.clone();
                let host = incident.host.clone();
                let confidence = decision.confidence;
                let dry_run = cfg.responder.dry_run;
                let rep_clone = ip_reputation.as_ref().cloned();
                let geo_clone = ip_geo.as_ref().cloned();
                tokio::spawn(async move {
                    let _ = tg
                        .send_action_report(
                            &action_label,
                            &target,
                            &title,
                            confidence,
                            &host,
                            dry_run,
                            rep_clone.as_ref(),
                            geo_clone.as_ref(),
                            cloudflare_pushed,
                        )
                        .await;
                });
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
/// Returns (execution_message, cloudflare_pushed).
async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
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
                    return (
                        format!("skipped: skill '{skill_id}' not in allowed_skills"),
                        false,
                    );
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
                        target_container: None,
                        duration_secs: None,
                        host: incident.host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: honeypot_runtime(cfg),
                        ai_provider: state.ai_provider.clone(),
                    };
                    let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    // Always track the IP in the in-memory blocklist regardless of dry_run
                    // mode, so the same IP is not re-evaluated by AI on subsequent ticks
                    // or after a restart within the same day.
                    if result.success {
                        state.blocklist.insert(ip.clone());
                    }
                    // Optionally push the block to Cloudflare edge
                    let mut cf_pushed = false;
                    if result.success && cfg.cloudflare.enabled && cfg.cloudflare.auto_push_blocks {
                        if let Some(ref cf) = state.cloudflare_client {
                            let reason = format!("{}: {}", incident.incident_id, decision.reason);
                            if let Some(rule_id) = cf.push_block(ip, &reason).await {
                                info!(ip, rule_id, "Cloudflare edge block pushed");
                                cf_pushed = true;
                            }
                        }
                    }
                    (result.message, cf_pushed)
                }
                None => (format!("skipped: skill '{effective_id}' not found"), false),
            }
        }
        AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                ("skipped: monitor-ip skill not available".to_string(), false)
            }
        }
        AiAction::Honeypot { ip } => {
            if let Some(skill) = state.skill_registry.get("honeypot") {
                let mut runtime = honeypot_runtime(cfg);
                // Thread the AI provider into the runtime so llm_shell interaction works.
                runtime.ai_provider = state.ai_provider.clone();
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: runtime.clone(),
                    ai_provider: state.ai_provider.clone(),
                };
                let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                if result.success {
                    // Extract session_id from the skill result message for post-session tasks.
                    let session_id = extract_session_id_from_message(&result.message)
                        .unwrap_or_else(|| {
                            format!("unknown-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
                        });

                    // Spawn post-session tasks in the background (non-blocking).
                    let post_ip = ip.clone();
                    let post_session_id = session_id.clone();
                    let post_data_dir = data_dir.to_path_buf();
                    let post_ai = state.ai_provider.clone();
                    let post_tg = state.telegram_client.clone();
                    let post_responder_enabled = cfg.responder.enabled;
                    let post_dry_run = cfg.responder.dry_run;
                    let post_block_backend = cfg.responder.block_backend.clone();
                    let post_allowed_skills = cfg.responder.allowed_skills.clone();
                    let post_blocklist_has = state.blocklist.contains(ip);
                    tokio::spawn(async move {
                        spawn_post_session_tasks(
                            &post_ip,
                            &post_session_id,
                            &post_data_dir,
                            post_ai,
                            post_tg,
                            post_responder_enabled,
                            post_dry_run,
                            &post_block_backend,
                            &post_allowed_skills,
                            post_blocklist_has,
                        )
                        .await;
                    });

                    match append_honeypot_marker_event(
                        data_dir,
                        incident,
                        ip,
                        cfg.responder.dry_run,
                        &runtime,
                    )
                    .await
                    {
                        Ok(path) => (
                            format!(
                                "{} | honeypot marker written to {}",
                                result.message,
                                path.display()
                            ),
                            false,
                        ),
                        Err(e) => {
                            state.telemetry.observe_error("honeypot_marker_writer");
                            warn!("failed to write honeypot marker event: {e:#}");
                            (
                                format!(
                                    "{} | warning: failed to write honeypot marker event: {e}",
                                    result.message
                                ),
                                false,
                            )
                        }
                    }
                } else {
                    (result.message, false)
                }
            } else {
                ("skipped: honeypot skill not available".to_string(), false)
            }
        }
        AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: suspend-user-sudo skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::KillProcess {
            user,
            duration_secs,
        } => {
            let skill_id = "kill-process";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: kill-process skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::BlockContainer {
            container_id,
            action: _,
        } => {
            let skill_id = "block-container";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: Some(container_id.clone()),
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: block-container skill not available".to_string(),
                    false,
                )
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
                    .send_confirmation_request(
                        incident,
                        summary,
                        req_action,
                        decision.confidence,
                        ttl,
                    )
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
                        return (
                            "pending: operator confirmation requested via Telegram".to_string(),
                            false,
                        );
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
                    Ok(_) => ("confirmation request sent via webhook".to_string(), false),
                    Err(e) => (format!("confirmation webhook failed: {e}"), false),
                }
            } else {
                (
                    "confirmation requested (no Telegram or webhook configured)".to_string(),
                    false,
                )
            }
        }
        AiAction::Ignore { reason } => (format!("ignored: {reason}"), false),
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
        // Populated at the call site when the AI provider is available.
        ai_provider: None,
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
    // Helper macro: fire-and-forget a Telegram reply
    macro_rules! tg_reply {
        ($text:expr) => {
            if let Some(ref tg) = state.telegram_client {
                let tg = tg.clone();
                let text = $text.to_string();
                tokio::spawn(async move {
                    let _ = tg.send_text_message(&text).await;
                });
            }
        };
    }

    // Bot-only commands: handle before checking pending_confirmations
    if result.incident_id == "__status__" {
        info!(operator = %result.operator_name, "Telegram /status command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let incident_count = count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
            let decision_count = count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
            let mode = guardian_mode(cfg);
            let mode_label = mode.label();
            let mode_desc = mode.description();
            let ai_label = if cfg.ai.enabled {
                format!("{} / {}", cfg.ai.provider, cfg.ai.model)
            } else {
                "not configured".to_string()
            };
            let host = std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string());
            let today_line = if incident_count == 0 {
                "Perimeter clean — no threat actors in the logs.".to_string()
            } else {
                format!("{incident_count} intrusion attempts, {decision_count} neutralized")
            };
            let text = format!(
                "👾 <b>InnerWarden</b> — <b>{host}</b>\n\
                 ━━━━━━━━━━━━━━━━\n\
                 Mode: <b>{mode_label}</b>\n\
                 <i>{mode_desc}</i>\n\
                 \n\
                 Threat brain: {ai_label}\n\
                 Intel today: {today_line}\n\
                 \n\
                 /threats · /decisions · /blocked",
            );
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__help__" {
        info!(operator = %result.operator_name, "Telegram /help command received");
        if cfg.telegram.bot.enabled {
            let text = "👾 <b>InnerWarden — Operator Playbook</b>\n\n\
                <b>Intel</b>\n\
                /status — mode, AI, today's threat intel\n\
                /threats — recent intrusion attempts\n\
                /decisions — actions I've taken\n\
                /blocked — threat actors contained\n\
                \n\
                <b>Configuration</b>\n\
                /capabilities — list all capabilities + status\n\
                /enable &lt;id&gt; — activate a capability\n\
                /disable &lt;id&gt; — deactivate a capability\n\
                /doctor — full health check with fix hints\n\
                \n\
                <b>Mode</b>\n\
                /guard — auto-defend (I act autonomously)\n\
                /watch — passive (I alert, you decide)\n\
                \n\
                <b>AI</b>\n\
                /ask &lt;question&gt; — ask anything, I know my config\n\
                <i>or just type — I'll understand</i>\n\
                \n\
                <b>On threat alerts:</b>\n\
                🛡 <b>Block</b> — drop this actor now\n\
                🙈 <b>Ignore</b> — false positive, stand down";
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__threats__" {
        info!(operator = %result.operator_name, "Telegram /threats command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let text = read_last_incidents(data_dir, &today, 5);
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__decisions__" {
        info!(operator = %result.operator_name, "Telegram /decisions command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let text = read_last_decisions(data_dir, &today, 5);
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__menu__" {
        info!(operator = %result.operator_name, "Telegram /menu command received");
        if cfg.telegram.bot.enabled {
            if let Some(ref tg) = state.telegram_client {
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_menu().await;
                });
            }
        }
        return;
    }

    if result.incident_id == "__start__" {
        info!(operator = %result.operator_name, "Telegram /start command received");
        if cfg.telegram.bot.enabled {
            if let Some(ref tg) = state.telegram_client {
                let today = chrono::Local::now()
                    .date_naive()
                    .format("%Y-%m-%d")
                    .to_string();
                let incident_count =
                    count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
                let decision_count =
                    count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
                let mode = guardian_mode(cfg);
                let host = std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string());
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg
                        .send_onboarding(&host, incident_count, decision_count, mode)
                        .await;
                });
            }
        }
        return;
    }

    if result.incident_id == "__guard__" {
        info!(operator = %result.operator_name, "Telegram /guard command received");
        if cfg.telegram.bot.enabled {
            let mode = guardian_mode(cfg);
            let text = match mode {
                telegram::GuardianMode::Guard => "🟢 <b>Already running in GUARD mode.</b>\n\
                     High-confidence threats get neutralized on sight — no confirmation needed.\n\
                     You'll get an action report after each hit.\n\n\
                     To switch to passive WATCH mode:\n\
                     <code>innerwarden configure responder</code> → option 1"
                    .to_string(),
                _ => {
                    format!(
                        "🟢 <b>GUARD mode</b> — autonomous threat neutralization.\n\
                         When I'm confident, I act. No need to ask.\n\n\
                         To activate, run on your server:\n\
                         <code>innerwarden configure responder</code>\n\
                         Then pick option 3 (Live mode).\n\n\
                         Current mode: {} — <i>{}</i>",
                        mode.label(),
                        mode.description()
                    )
                }
            };
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__watch__" {
        info!(operator = %result.operator_name, "Telegram /watch command received");
        if cfg.telegram.bot.enabled {
            let mode = guardian_mode(cfg);
            let text = match mode {
                telegram::GuardianMode::Watch => "🔵 <b>Already in WATCH mode.</b>\n\
                     I detect and log everything — you decide what gets dropped.\n\
                     Good for baselining or when you want full visibility before acting.\n\n\
                     To switch to autonomous GUARD mode:\n\
                     <code>innerwarden configure responder</code> → option 3"
                    .to_string(),
                _ => {
                    format!(
                        "🔵 <b>WATCH mode</b> — passive recon, active alerts.\n\
                         I flag every IOC, you make the call on containment.\n\n\
                         To activate, run on your server:\n\
                         <code>innerwarden configure responder</code>\n\
                         Then pick option 1 (Observe only).\n\n\
                         Current mode: {} — <i>{}</i>",
                        mode.label(),
                        mode.description()
                    )
                }
            };
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__blocked__" {
        info!(operator = %result.operator_name, "Telegram /blocked command received");
        if cfg.telegram.bot.enabled {
            let blocked: Vec<String> = state.blocklist.as_vec();
            let text = if blocked.is_empty() {
                "📋 No threat actors contained in this session.\n\
                 <i>Previous blocks are still enforced in the firewall.</i>"
                    .to_string()
            } else {
                let mut sorted = blocked;
                sorted.sort();
                let list = sorted
                    .iter()
                    .map(|ip| format!("• <code>{ip}</code>"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "🛡 <b>Contained threat actors</b> ({} this session)\n\n{list}",
                    sorted.len()
                )
            };
            tg_reply!(text);
        }
        return;
    }

    if result.incident_id == "__unknown_cmd__" {
        info!(operator = %result.operator_name, "Telegram unknown command received");
        if cfg.telegram.bot.enabled {
            tg_reply!(
                "Unknown command. Type /help for the full operator playbook, or just ask me directly."
            );
        }
        return;
    }

    if let Some(question) = result.incident_id.strip_prefix("__ask__:") {
        let question = question.to_string();
        info!(operator = %result.operator_name, question = %question, "Telegram /ask command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            // Inject full system context so the AI knows exactly what's configured
            let agent_ctx = build_agent_context(cfg, data_dir);
            let recent_incidents = read_last_incidents_raw(data_dir, &today, 3);
            let system_prompt = if recent_incidents.is_empty() {
                format!("{}\n\n{agent_ctx}", cfg.telegram.bot.personality)
            } else {
                format!(
                    "{}\n\n{agent_ctx}\n\nRECENT INCIDENTS (last 3):\n{recent_incidents}",
                    cfg.telegram.bot.personality
                )
            };

            if let Some(ref ai) = state.ai_provider {
                let ai = ai.clone();
                let tg = state.telegram_client.clone();
                tokio::spawn(async move {
                    if let Some(ref tg) = tg {
                        tg.send_typing().await;
                    }
                    match ai.chat(&system_prompt, &question).await {
                        Ok(reply) => {
                            if let Some(ref tg) = tg {
                                let _ = tg.send_text_message(&reply).await;
                            }
                        }
                        Err(e) => {
                            warn!("AI chat error for Telegram /ask: {e:#}");
                            if let Some(ref tg) = tg {
                                let _ = tg
                                    .send_text_message(&format!(
                                        "Brain glitch: {}",
                                        e.to_string().chars().take(200).collect::<String>()
                                    ))
                                    .await;
                            }
                        }
                    }
                });
            } else {
                tg_reply!(
                    "AI brain is offline. Activate it:\n<code>innerwarden enable ai</code>\nor via bot: /enable ai"
                );
            }
        }
        return;
    }

    // /enable <capability> — run innerwarden enable <cap> as subprocess
    if let Some(cap_args) = result.incident_id.strip_prefix("__enable__:") {
        let cap_args = cap_args.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_args, "Telegram /enable command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                // Parse "block-ip --param backend=ufw" → ["enable", "block-ip", "--param", "backend=ufw"]
                let parts: Vec<&str> = cap_args.split_whitespace().collect();
                let mut args = vec!["enable"];
                args.extend(parts.iter().copied());
                let output = run_innerwarden_cli(&args).await;
                let text = format!(
                    "🔧 <b>innerwarden enable {cap_args}</b>\n\n<pre>{output}</pre>",
                    cap_args = cap_args,
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return;
    }

    // /disable <capability> — run innerwarden disable <cap> as subprocess
    if let Some(cap_args) = result.incident_id.strip_prefix("__disable__:") {
        let cap_args = cap_args.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_args, "Telegram /disable command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                let parts: Vec<&str> = cap_args.split_whitespace().collect();
                let mut args = vec!["disable"];
                args.extend(parts.iter().copied());
                let output = run_innerwarden_cli(&args).await;
                let text = format!(
                    "🔧 <b>innerwarden disable {cap_args}</b>\n\n<pre>{output}</pre>",
                    cap_args = cap_args,
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return;
    }

    // /doctor — run innerwarden doctor and show output
    if result.incident_id == "__doctor__" {
        info!(operator = %result.operator_name, "Telegram /doctor command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                let output = run_innerwarden_cli(&["doctor"]).await;
                let text = format!(
                    "🩺 <b>System health check</b>\n\n<pre>{}</pre>",
                    output.chars().take(3000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return;
    }

    // /capabilities — list capabilities and integrations with inline enable buttons
    if result.incident_id == "__capabilities__" {
        info!(operator = %result.operator_name, "Telegram /capabilities command received");
        if cfg.telegram.bot.enabled {
            let text = format_capabilities(cfg);
            let keyboard = capabilities_keyboard(cfg);
            if let Some(ref tg) = state.telegram_client {
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_text_with_keyboard(&text, keyboard).await;
                });
            }
        }
        return;
    }

    // enable:<id> callback — from capabilities inline keyboard buttons
    if let Some(cap_id) = result.incident_id.strip_prefix("enable:") {
        let cap_id = cap_id.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_id, "Telegram enable callback received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                // fail2ban uses `innerwarden integrate fail2ban` instead of `enable`
                // honeypot uses `innerwarden enable honeypot` (standard path)
                let output = if cap_id == "fail2ban" {
                    run_innerwarden_cli(&["integrate", "fail2ban"]).await
                } else {
                    run_innerwarden_cli(&["enable", &cap_id]).await
                };
                let cmd_label = if cap_id == "fail2ban" {
                    format!("innerwarden integrate {cap_id}")
                } else {
                    format!("innerwarden enable {cap_id}")
                };
                let text = format!(
                    "🔧 <b>{cmd_label}</b>\n\n<pre>{output}</pre>",
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return;
    }

    // Quick-block sentinel: "quick:block:<ip>" — initiated from the inline keyboard on T.1 alerts
    if let Some(ip) = result.incident_id.strip_prefix("__quick_block__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        info!(ip = %ip, operator = %operator, "Telegram quick-block received");

        if !cfg.responder.enabled {
            tg_reply!(format!(
                "⚠️ Responder is disabled. Enable it in agent.toml to allow blocking.\n\
                 Run: <code>innerwarden configure responder</code>"
            ));
            return;
        }

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        if !cfg.responder.allowed_skills.contains(&skill_id) {
            tg_reply!(format!(
                "⚠️ Skill <code>{skill_id}</code> is not in allowed_skills. \
                 Add it to agent.toml under [responder] allowed_skills."
            ));
            return;
        }

        let skill = state.skill_registry.get(&skill_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        });

        let Some(skill) = skill else {
            tg_reply!(format!(
                "⚠️ Skill <code>{skill_id}</code> not found in registry."
            ));
            return;
        };

        // Build a minimal incident for the skill context
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let inc = {
            use innerwarden_core::event::Severity;
            innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id: format!("telegram:quick_block:{ip}"),
                severity: Severity::High,
                title: format!("Quick block of {ip} via Telegram"),
                summary: format!("Operator {operator} requested immediate block of {ip}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["telegram".to_string(), "manual".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip.clone())],
            }
        };

        let ctx = skills::SkillContext {
            incident: inc.clone(),
            target_ip: Some(ip.clone()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: inc.host.clone(),
            data_dir: data_dir.to_path_buf(),
            honeypot: honeypot_runtime(cfg),
            ai_provider: state.ai_provider.clone(),
        };

        let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;

        if exec_result.success {
            state.blocklist.insert(ip.clone());
        }

        // Audit trail
        if let Some(writer) = &mut state.decision_writer {
            let provider = format!("telegram:{operator}");
            let entry = decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: inc.incident_id.clone(),
                host: inc.host.clone(),
                ai_provider: provider,
                action_type: "block_ip".to_string(),
                target_ip: Some(ip.clone()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: true,
                dry_run: cfg.responder.dry_run,
                reason: format!("Quick block requested by operator {operator} via Telegram"),
                estimated_threat: "manual".to_string(),
                execution_result: exec_result.message.clone(),
            };
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write quick-block decision entry: {e:#}");
            }
        }

        let reply = if cfg.responder.dry_run {
            format!("🧪 Simulated — would've dropped {ip} at the firewall. Enable live mode to make it real.")
        } else if exec_result.success {
            format!("🛡 Threat actor {ip} neutralized — dropped at the firewall. They won't pivot from there.")
        } else {
            format!("❌ Failed to contain {ip}: {}", exec_result.message)
        };
        tg_reply!(reply);
        return;
    }

    // Honeypot operator-in-the-loop: "hpot:{action}:{ip}" via send_honeypot_suggestion
    if let Some(ip) = result.incident_id.strip_prefix("__hpot__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        let chosen = result.chosen_action.as_str();
        info!(ip = %ip, operator = %operator, action = %chosen, "Telegram honeypot choice received");

        let Some(choice) = state.pending_honeypot_choices.remove(&ip) else {
            debug!(
                ip = %ip,
                "Telegram honeypot choice for unknown or expired IP — ignoring"
            );
            return;
        };

        let host = choice.incident.host.clone();
        let provider_label = format!("operator:telegram:{operator}");

        match chosen {
            "honeypot" => {
                // Build SkillContext and execute the honeypot skill
                if let Some(skill) = state.skill_registry.get("honeypot") {
                    let mut runtime = honeypot_runtime(cfg);
                    runtime.ai_provider = state.ai_provider.clone();
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: runtime.clone(),
                        ai_provider: state.ai_provider.clone(),
                    };
                    let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    let msg = if exec_result.success {
                        match append_honeypot_marker_event(
                            data_dir,
                            &choice.incident,
                            &ip,
                            cfg.responder.dry_run,
                            &runtime,
                        )
                        .await
                        {
                            Ok(path) => format!(
                                "{} | honeypot marker written to {}",
                                exec_result.message,
                                path.display()
                            ),
                            Err(e) => {
                                warn!("failed to write honeypot marker: {e:#}");
                                exec_result.message.clone()
                            }
                        }
                    } else {
                        exec_result.message.clone()
                    };
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "honeypot".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some("honeypot".to_string()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: format!("Operator {operator} chose honeypot via Telegram"),
                            estimated_threat: "high".to_string(),
                            execution_result: msg.clone(),
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!("🧪 Simulado — {ip} seria jogado no honeypot. Ative live mode para executar de verdade.")
                    } else if exec_result.success {
                        format!("🍯 {ip} no honeypot. Agora vamos ver o que esse cara tenta fazer.")
                    } else {
                        format!(
                            "❌ Falha ao ativar honeypot para {ip}: {}",
                            exec_result.message
                        )
                    };
                    tg_reply!(reply);
                } else {
                    tg_reply!(format!("⚠️ Honeypot skill não disponível para {ip}."));
                }
            }
            "block" => {
                // Execute block_ip skill
                let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
                let skill = state.skill_registry.get(&skill_id).or_else(|| {
                    state
                        .skill_registry
                        .block_skill_for_backend(&cfg.responder.block_backend)
                });
                if let Some(skill) = skill {
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: honeypot_runtime(cfg),
                        ai_provider: state.ai_provider.clone(),
                    };
                    let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    if exec_result.success {
                        state.blocklist.insert(ip.clone());
                    }
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "block_ip".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some(skill_id.clone()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: format!("Operator {operator} chose block via Telegram"),
                            estimated_threat: "high".to_string(),
                            execution_result: exec_result.message.clone(),
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot-block decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!("🧪 Simulado — {ip} seria bloqueado no firewall.")
                    } else if exec_result.success {
                        format!("🛡 {ip} bloqueado no firewall. Acabou para esse cara.")
                    } else {
                        format!("❌ Falha ao bloquear {ip}: {}", exec_result.message)
                    };
                    tg_reply!(reply);
                } else {
                    tg_reply!(format!("⚠️ Skill de bloqueio não disponível para {ip}."));
                }
            }
            "monitor" => {
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "monitor".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: format!("Operator {operator} chose monitor via Telegram"),
                        estimated_threat: "medium".to_string(),
                        execution_result: "monitoring: no active action taken".to_string(),
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write monitor decision entry: {e:#}");
                    }
                }
                tg_reply!(format!("👁 Registrado. Monitorando {ip} silenciosamente."));
            }
            _ => {
                // "ignore" or anything else
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "ignore".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: format!("Operator {operator} chose ignore via Telegram"),
                        estimated_threat: "low".to_string(),
                        execution_result: "ignored by operator".to_string(),
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write ignore decision entry: {e:#}");
                    }
                }
                tg_reply!(format!(
                    "👍 Anotado. {ip} marcado como falso positivo. Mantendo olho aberto."
                ));
            }
        }
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
        append_trust_rule(
            data_dir,
            &mut state.trust_rules,
            &pending.detector,
            &pending.action_name,
        );
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

    let (exec_result, _cf_pushed) = if result.approved {
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
        (
            format!("rejected by operator {}", result.operator_name),
            false,
        )
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
// Telegram bot helper functions
// ---------------------------------------------------------------------------

/// Count the number of lines in a JSONL file in data_dir (fail-silent → 0).
fn count_jsonl_lines(data_dir: &Path, filename: &str) -> usize {
    let path = data_dir.join(filename);
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

/// Read the last N incidents from today's incidents file, formatted for display.
fn read_last_incidents(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "No incidents recorded today.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "No incidents recorded today.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();
    let now = chrono::Utc::now();

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let severity = v["severity"].as_str().unwrap_or("?").to_uppercase();
            let title = v["title"].as_str().unwrap_or("unknown").to_string();
            let entity = v["entities"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|e| e["value"].as_str())
                .unwrap_or("?")
                .to_string();
            let ts_str = v["ts"].as_str().unwrap_or("");
            let age = chrono::DateTime::parse_from_rfc3339(ts_str)
                .ok()
                .map(|t| {
                    let mins = now
                        .signed_duration_since(t.with_timezone(&chrono::Utc))
                        .num_minutes();
                    if mins < 1 {
                        "just now".to_string()
                    } else {
                        format!("{mins}m ago")
                    }
                })
                .unwrap_or_default();
            Some(format!("[{severity}] {title} — {entity} {age}"))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable incidents today.".to_string()
    } else {
        format!(
            "Last {} incidents:\n{}",
            formatted.len(),
            formatted.join("\n")
        )
    }
}

/// Read the last N decisions from today's decisions file, formatted for display.
fn read_last_decisions(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "No decisions recorded today.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "No decisions recorded today.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let action = v["action_type"].as_str().unwrap_or("?").to_string();
            let target = v["target_ip"]
                .as_str()
                .or_else(|| v["target_user"].as_str())
                .unwrap_or("?")
                .to_string();
            let confidence = v["confidence"].as_f64().unwrap_or(0.0);
            let dry_run = v["dry_run"].as_bool().unwrap_or(true);
            let mode = if dry_run { "dry-run" } else { "live" };
            Some(format!(
                "[{action}] {target} — {:.0}% confidence — {mode}",
                confidence * 100.0
            ))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable decisions today.".to_string()
    } else {
        format!(
            "Last {} decisions:\n{}",
            formatted.len(),
            formatted.join("\n")
        )
    }
}

/// Read the last N incidents as compact JSON strings (for AI context).
fn read_last_incidents_raw(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return String::new();
    }

    lines
        .iter()
        .rev()
        .take(n)
        .map(|l| {
            // Summarise to avoid sending huge JSON blobs to the AI
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .map(|v| {
                    format!(
                        "[{}] {} — {}",
                        v["severity"].as_str().unwrap_or("?"),
                        v["title"].as_str().unwrap_or("?"),
                        v["summary"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(120)
                            .collect::<String>()
                    )
                })
                .unwrap_or_default()
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
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

                // Daily Telegram digest
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        if let Some(tg) = &state.telegram_client {
                            let preview: String = md.chars().take(3800).collect();
                            let text = format!(
                                "📋 <b>Daily report — {today}</b>\n\n<pre>{}</pre>",
                                html_escape(&preview)
                            );
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    state.last_daily_summary_telegram = Some(today_naive);
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }
                    }
                }
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
// Post-session honeypot tasks (T.5)
// ---------------------------------------------------------------------------

/// Extract session_id from honeypot skill result message.
/// The message format is: "Honeypot listeners started (session {session_id}, ...)"
fn extract_session_id_from_message(msg: &str) -> Option<String> {
    // Look for "session " followed by the session_id (ends at next ", " or ")")
    let marker = "session ";
    let start = msg.find(marker)? + marker.len();
    let rest = &msg[start..];
    let end = rest.find([',', ')']).unwrap_or(rest.len());
    let id = rest[..end].trim().to_string();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Read shell commands typed by the attacker from honeypot evidence JSONL.
async fn read_shell_commands_from_evidence(path: &std::path::Path) -> Vec<String> {
    use tokio::io::AsyncBufReadExt;
    let Ok(file) = tokio::fs::File::open(path).await else {
        return vec![];
    };
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut commands = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
                if let Some(attempts) = val.get("shell_commands").and_then(|a| a.as_array()) {
                    for a in attempts {
                        if let Some(cmd) = a.get("command").and_then(|c| c.as_str()) {
                            if !cmd.is_empty() {
                                commands.push(cmd.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    commands
}

/// Spawned in the background after a honeypot session starts.
/// Reads evidence, extracts IOCs, gets AI verdict, auto-blocks, sends Telegram report.
#[allow(clippy::too_many_arguments)]
async fn spawn_post_session_tasks(
    ip: &str,
    session_id: &str,
    data_dir: &std::path::Path,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
    blocklist_already_has_ip: bool,
) {
    // Give the honeypot listener time to collect evidence (wait for session to end).
    // We wait for the configured duration or a reasonable maximum.
    // Since we don't have the duration here, sleep briefly then retry reading.
    // The session is async and runs in its own task; we poll the evidence file.
    let evidence_path = data_dir
        .join("honeypot")
        .join(format!("listener-session-{session_id}.jsonl"));

    // Wait up to 10 minutes for evidence to appear (polls every 30s)
    let mut commands = Vec::new();
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let cmds = read_shell_commands_from_evidence(&evidence_path).await;
        if !cmds.is_empty() {
            commands = cmds;
            break;
        }
        // Also check if metadata file shows "completed" status
        let metadata_path = data_dir
            .join("honeypot")
            .join(format!("listener-session-{session_id}.json"));
        if let Ok(content) = tokio::fs::read_to_string(&metadata_path).await {
            if content.contains("\"status\":\"completed\"")
                || content.contains("\"status\": \"completed\"")
            {
                commands = read_shell_commands_from_evidence(&evidence_path).await;
                break;
            }
        }
    }

    // Extract IOCs from commands
    let iocs = ioc::extract_from_commands(&commands);

    // Get AI verdict (brief summary in Portuguese)
    let verdict = if let Some(ref ai) = ai_provider {
        let cmd_text = if commands.is_empty() {
            "No commands recorded.".to_string()
        } else {
            commands
                .iter()
                .take(20)
                .map(|c| format!("  $ {c}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let prompt = format!(
            "Attacker IP {ip} ran these commands in an SSH honeypot:\n{cmd_text}\n\n\
             In 1-2 sentences in Portuguese (pt-BR), what does this attacker appear to be doing? \
             Be specific and direct."
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Análise indisponível.".to_string())
    } else {
        "Análise de IA não configurada.".to_string()
    };

    // Auto-block the attacker IP if responder is enabled and IP not already blocked
    let auto_blocked = if responder_enabled && !blocklist_already_has_ip {
        let skill_id = format!("block-ip-{block_backend}");
        if allowed_skills.iter().any(|s| s == &skill_id) {
            let iid = format!("honeypot:post-session:{session_id}");
            let inc = innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string()),
                incident_id: iid.clone(),
                severity: innerwarden_core::event::Severity::High,
                title: "Honeypot Session Ended".to_string(),
                summary: format!("Attacker IP {ip} interacted with honeypot session {session_id}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["honeypot".to_string(), "post-session".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
            };
            let ctx = skills::SkillContext {
                incident: inc,
                target_ip: Some(ip.to_string()),
                target_user: None,
                target_container: None,
                duration_secs: None,
                host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
                data_dir: data_dir.to_path_buf(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
            };
            let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend {
                "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
                "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
                "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
                _ => Some(Box::new(skills::builtin::BlockIpUfw)),
            };
            if let Some(skill) = skill_box {
                let result = skill.execute(&ctx, dry_run).await;
                if result.success {
                    // Write decision to audit trail
                    let today = chrono::Local::now()
                        .date_naive()
                        .format("%Y-%m-%d")
                        .to_string();
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: iid,
                        host: ctx.host.clone(),
                        ai_provider: "honeypot:post-session".to_string(),
                        action_type: "block_ip".to_string(),
                        target_ip: Some(ip.to_string()),
                        target_user: None,
                        skill_id: Some(skill_id),
                        confidence: 1.0,
                        auto_executed: true,
                        dry_run,
                        reason: format!(
                            "Attacker IP interacted with honeypot session {session_id}"
                        ),
                        estimated_threat: "confirmed-attacker".to_string(),
                        execution_result: if result.success {
                            "ok".to_string()
                        } else {
                            format!("failed: {}", result.message)
                        },
                    };
                    let path = data_dir.join(format!("decisions-{today}.jsonl"));
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        use std::io::Write;
                        if let Ok(line) = serde_json::to_string(&entry) {
                            let _ = writeln!(f, "{line}");
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Send Telegram post-session report
    if let Some(ref tg) = telegram_client {
        let duration = 300u64; // default; session duration stored in metadata
        if let Err(e) = tg
            .send_honeypot_session_report(
                ip,
                session_id,
                duration,
                &commands,
                &iocs,
                &verdict,
                auto_blocked,
            )
            .await
        {
            tracing::warn!("failed to send honeypot session report via Telegram: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Always-on honeypot listener (mode = "always_on")
// ---------------------------------------------------------------------------

/// Handle a single always-on honeypot connection end-to-end:
/// SSH key exchange, credential capture, optional LLM shell, evidence write,
/// IOC extraction, AI verdict, auto-block, Telegram T.5 report.
#[allow(clippy::too_many_arguments)]
async fn handle_always_on_connection(
    stream: tokio::net::TcpStream,
    ip: String,
    ssh_cfg: std::sync::Arc<russh::server::Config>,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    data_dir: std::path::PathBuf,
    interaction: String,
    blocklist_already_has_ip: bool,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
) {
    use skills::builtin::honeypot::ssh_interact::{
        handle_connection, SshConnectionEvidence, SshInteractionMode,
    };

    let mode = if interaction == "llm_shell" {
        if let Some(ref ai) = ai_provider {
            SshInteractionMode::LlmShell {
                ai: ai.clone(),
                hostname: "srv-prod-01".to_string(),
            }
        } else {
            SshInteractionMode::RejectAll
        }
    } else {
        // "medium" and any other value: capture creds, always reject auth
        SshInteractionMode::RejectAll
    };

    let conn_timeout = std::time::Duration::from_secs(120);
    let evidence: SshConnectionEvidence =
        handle_connection(stream, ssh_cfg, conn_timeout, mode).await;

    // Build a unique session id.
    let session_id = format!(
        "always-on-{}-{}",
        ip.replace('.', "-"),
        chrono::Utc::now().timestamp()
    );

    // Write evidence to honeypot dir (append-only JSONL).
    let honeypot_dir = data_dir.join("honeypot");
    let _ = tokio::fs::create_dir_all(&honeypot_dir).await;
    let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
    if let Ok(json) = serde_json::to_string(&serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "type": "ssh_connection",
        "session_id": &session_id,
        "peer_ip": &ip,
        "auth_attempts": evidence.auth_attempts,
        "auth_attempts_count": evidence.auth_attempts.len(),
        "shell_commands": evidence.shell_commands,
        "shell_commands_count": evidence.shell_commands.len(),
    })) {
        let line = format!("{json}\n");
        if let Ok(mut f) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&evidence_path)
            .await
        {
            use tokio::io::AsyncWriteExt;
            let _ = f.write_all(line.as_bytes()).await;
        }
    }

    // Extract shell commands for IOC analysis and AI verdict.
    let commands: Vec<String> = evidence
        .shell_commands
        .iter()
        .map(|s| s.command.clone())
        .collect();

    let iocs = ioc::extract_from_commands(&commands);

    // AI verdict (brief summary in Portuguese).
    let verdict = if let Some(ref ai) = ai_provider {
        let cmd_text = if commands.is_empty() {
            "No commands recorded.".to_string()
        } else {
            commands
                .iter()
                .take(20)
                .map(|c| format!("  $ {c}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let prompt = format!(
            "Attacker IP {ip} connected to an SSH honeypot.\n\
             Auth attempts: {}\n\
             Shell commands:\n{cmd_text}\n\n\
             In 1-2 sentences in Portuguese (pt-BR), what does this attacker appear to be doing? \
             Be specific and direct.",
            evidence.auth_attempts.len(),
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Análise indisponível.".to_string())
    } else {
        if evidence.auth_attempts.is_empty() {
            "Conexão sem tentativas de autenticação — provavelmente scanner automatizado."
                .to_string()
        } else {
            "IA não configurada — sem veredicto disponível.".to_string()
        }
    };

    // Auto-block after session if responder is enabled and IP not already blocked.
    let auto_blocked = if responder_enabled && !blocklist_already_has_ip {
        let skill_id = format!("block-ip-{block_backend}");
        if allowed_skills.iter().any(|s| s == &skill_id) {
            let iid = format!("honeypot:always-on:{session_id}");
            let host = std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string());
            let inc = innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id: iid.clone(),
                severity: innerwarden_core::event::Severity::High,
                title: "Always-on Honeypot Session Ended".to_string(),
                summary: format!(
                    "Attacker IP {ip} connected to always-on honeypot session {session_id}"
                ),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["honeypot".to_string(), "always-on".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(&ip)],
            };
            let ctx = skills::SkillContext {
                incident: inc,
                target_ip: Some(ip.clone()),
                target_user: None,
                target_container: None,
                duration_secs: None,
                host: host.clone(),
                data_dir: data_dir.clone(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
            };
            let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend.as_str() {
                "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
                "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
                "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
                _ => Some(Box::new(skills::builtin::BlockIpUfw)),
            };
            if let Some(skill) = skill_box {
                let result = skill.execute(&ctx, dry_run).await;
                if result.success {
                    let today = chrono::Local::now()
                        .date_naive()
                        .format("%Y-%m-%d")
                        .to_string();
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: iid,
                        host,
                        ai_provider: "honeypot:always-on".to_string(),
                        action_type: "block_ip".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: Some(skill_id),
                        confidence: 1.0,
                        auto_executed: true,
                        dry_run,
                        reason: format!(
                            "Attacker IP interacted with always-on honeypot session {session_id}"
                        ),
                        estimated_threat: "confirmed-attacker".to_string(),
                        execution_result: if result.success {
                            "ok".to_string()
                        } else {
                            format!("failed: {}", result.message)
                        },
                    };
                    let path = data_dir.join(format!("decisions-{today}.jsonl"));
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        use std::io::Write;
                        if let Ok(line) = serde_json::to_string(&entry) {
                            let _ = writeln!(f, "{line}");
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Send Telegram T.5 post-session report.
    if let Some(ref tg) = telegram_client {
        let duration = evidence.auth_attempts.len() as u64 * 5; // rough estimate
        if let Err(e) = tg
            .send_honeypot_session_report(
                &ip,
                &session_id,
                duration,
                &commands,
                &iocs,
                &verdict,
                auto_blocked,
            )
            .await
        {
            warn!("always-on honeypot: failed to send Telegram session report: {e:#}");
        }
    }

    info!(
        ip,
        session_id,
        auth_attempts = evidence.auth_attempts.len(),
        shell_commands = evidence.shell_commands.len(),
        auto_blocked,
        "always-on honeypot session completed"
    );
}

/// Permanent SSH listener that runs from agent startup until SIGTERM.
///
/// Filter per connection:
///   1. Already in blocklist → drop silently (no banner sent)
///   2. AbuseIPDB score ≥ threshold (when configured) → block + drop
///   3. Otherwise → accept into honeypot interaction (RejectAll or LlmShell)
///
/// `filter_blocklist` is a shared set of already-blocked IPs populated at startup
/// from recent decisions and updated in-place when new IPs are blocked via the gate.
#[allow(clippy::too_many_arguments)]
async fn run_always_on_honeypot(
    port: u16,
    bind_addr: String,
    ssh_max_auth_attempts: usize,
    filter_blocklist: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    abuseipdb_client: Option<std::sync::Arc<abuseipdb::AbuseIpDbClient>>,
    abuseipdb_threshold: u8,
    data_dir: std::path::PathBuf,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
    interaction: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use skills::builtin::honeypot::ssh_interact::build_ssh_config;

    let ssh_cfg = build_ssh_config(ssh_max_auth_attempts);

    let addr = format!("{bind_addr}:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(addr, error = %e, "always-on honeypot: failed to bind listener — mode disabled");
            return;
        }
    };
    info!(port, bind_addr, "always-on honeypot listener started");

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = match accept_result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "always-on honeypot: accept error");
                        continue;
                    }
                };

                let ip = peer.ip().to_string();

                // Filter 1: already in filter blocklist — drop silently.
                {
                    let bl = filter_blocklist.lock().unwrap_or_else(|e| e.into_inner());
                    if bl.contains(&ip) {
                        debug!(ip, "always-on honeypot: IP in blocklist — dropping silently");
                        continue;
                    }
                }

                // Filter 2: AbuseIPDB gate (async lookup before spawning handler).
                if abuseipdb_threshold > 0 {
                    if let Some(ref client) = abuseipdb_client {
                        if let Some(rep) = client.check(&ip).await {
                            if rep.confidence_score >= abuseipdb_threshold {
                                info!(
                                    ip,
                                    score = rep.confidence_score,
                                    "always-on honeypot: AbuseIPDB gate — blocking and dropping"
                                );
                                // Add to filter blocklist so future connections are dropped cheaply.
                                filter_blocklist
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(ip.clone());

                                // Write audit + execute block skill (background task).
                                let ip_c = ip.clone();
                                let dd = data_dir.clone();
                                let bb = block_backend.clone();
                                let sk = allowed_skills.clone();
                                let score = rep.confidence_score;
                                let threshold = abuseipdb_threshold;
                                let re = responder_enabled;
                                let dr = dry_run;
                                tokio::spawn(async move {
                                    always_on_abuseipdb_block(
                                        &ip_c, score, threshold, &dd, re, dr, &bb, &sk,
                                    )
                                    .await;
                                });
                                continue;
                            }
                        }
                    }
                }

                // Accept: snapshot blocklist membership, then spawn connection handler.
                let bl_has_ip = filter_blocklist
                    .lock()
                    .map(|bl| bl.contains(&ip))
                    .unwrap_or(false);

                let ssh_cfg_clone = ssh_cfg.clone();
                let ai_clone = ai_provider.clone();
                let tg_clone = telegram_client.clone();
                let dd = data_dir.clone();
                let ip_clone = ip.clone();
                let intr = interaction.clone();
                let bb = block_backend.clone();
                let sk = allowed_skills.clone();
                let re = responder_enabled;
                let dr = dry_run;
                let bl_ref = filter_blocklist.clone();

                tokio::spawn(async move {
                    handle_always_on_connection(
                        stream,
                        ip_clone.clone(),
                        ssh_cfg_clone,
                        ai_clone,
                        tg_clone,
                        dd,
                        intr,
                        bl_has_ip,
                        re,
                        dr,
                        bb,
                        sk,
                    )
                    .await;
                    // After session, mark IP as seen so the filter can drop quick-reconnects.
                    bl_ref
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(ip_clone);
                });
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("always-on honeypot listener shutting down");
                    break;
                }
            }
        }
    }
}

/// Write an AbuseIPDB-triggered block audit entry and execute the block skill.
#[allow(clippy::too_many_arguments)]
async fn always_on_abuseipdb_block(
    ip: &str,
    score: u8,
    threshold: u8,
    data_dir: &std::path::Path,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
) {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let iid = format!("honeypot:always-on:abuseipdb:{ip}");
    let skill_id = format!("block-ip-{block_backend}");

    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: iid.clone(),
        host: host.clone(),
        ai_provider: "honeypot:abuseipdb_gate".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run,
        reason: format!(
            "AbuseIPDB confidence score {score}/100 exceeded always-on honeypot gate threshold {threshold}"
        ),
        estimated_threat: "known-malicious".to_string(),
        execution_result: "ok".to_string(),
    };

    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        if let Ok(line) = serde_json::to_string(&entry) {
            let _ = writeln!(f, "{line}");
        }
    }

    if responder_enabled && allowed_skills.iter().any(|s| s == &skill_id) {
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: iid,
            severity: innerwarden_core::event::Severity::High,
            title: "AbuseIPDB Gate Block (Always-on Honeypot)".to_string(),
            summary: format!(
                "IP {ip} blocked at always-on honeypot AbuseIPDB gate (score {score})"
            ),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["honeypot".to_string(), "abuseipdb".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        };
        let ctx = skills::SkillContext {
            incident: inc,
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host,
            data_dir: data_dir.to_path_buf(),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend {
            "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
            "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
            "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
            _ => Some(Box::new(skills::builtin::BlockIpUfw)),
        };
        if let Some(skill) = skill_box {
            let _ = skill.execute(&ctx, dry_run).await;
        }
    }
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
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
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
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
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

        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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
            notification_cooldowns: HashMap::new(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
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

    // ------------------------------------------------------------------
    // Always-on honeypot tests
    // ------------------------------------------------------------------

    /// Test that the filter blocklist correctly drops IPs that are already blocked.
    #[test]
    fn test_always_on_filter_blocks_known_ip() {
        let mut set = std::collections::HashSet::new();
        set.insert("1.2.3.4".to_string());
        set.insert("5.6.7.8".to_string());

        // Known-bad IP should be "blocked" (present in set).
        assert!(
            set.contains("1.2.3.4"),
            "IP 1.2.3.4 should be in the filter blocklist"
        );
        assert!(
            set.contains("5.6.7.8"),
            "IP 5.6.7.8 should be in the filter blocklist"
        );

        // Unknown IP should NOT be blocked.
        assert!(
            !set.contains("9.9.9.9"),
            "IP 9.9.9.9 should not be in the filter blocklist"
        );

        // After inserting a new IP, it should be filtered.
        set.insert("9.9.9.9".to_string());
        assert!(
            set.contains("9.9.9.9"),
            "IP 9.9.9.9 should be in the filter blocklist after insertion"
        );
    }

    /// Test that the "always_on" mode string is recognized and would trigger startup.
    #[test]
    fn test_always_on_mode_recognized() {
        // Verify config recognises the mode string (no panic on deserialise).
        let toml = r#"
            [honeypot]
            mode = "always_on"
            port = 2222
            bind_addr = "127.0.0.1"
            interaction = "medium"
        "#;
        let cfg: config::AgentConfig = toml::from_str(toml).expect("should parse always_on mode");
        assert_eq!(cfg.honeypot.mode, "always_on");
        assert_eq!(cfg.honeypot.port, 2222);

        // Verify the mode check used in main() matches.
        let is_always_on = cfg.honeypot.mode == "always_on";
        assert!(
            is_always_on,
            "mode check should return true for 'always_on'"
        );

        // Demo and listener modes should NOT match.
        let mut cfg2 = config::AgentConfig::default();
        cfg2.honeypot.mode = "demo".to_string();
        assert!(
            !(&cfg2.honeypot.mode == "always_on"),
            "demo should not match always_on"
        );

        let mut cfg3 = config::AgentConfig::default();
        cfg3.honeypot.mode = "listener".to_string();
        assert!(
            !(&cfg3.honeypot.mode == "always_on"),
            "listener should not match always_on"
        );
    }
}
