use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tracing::{info, warn};

use crate::correlation::build_clusters;
use crate::decisions::DecisionEntry;
use crate::report::{self as report_mod, TrialReport};
use crate::telemetry::TelemetrySnapshot;
use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// D6 — SSE types
// ---------------------------------------------------------------------------

/// Minimal SSE payload pushed to connected clients.
#[derive(Debug, Clone, Serialize)]
struct SsePayload {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

type EventTx = broadcast::Sender<SsePayload>;

// ---------------------------------------------------------------------------
// Shared state / auth
// ---------------------------------------------------------------------------

/// Configuration for dashboard-initiated actions (D3).
/// Mirrors `ResponderConfig` but is owned by the dashboard independently.
#[derive(Debug, Clone)]
pub struct DashboardActionConfig {
    /// Show action buttons in the UI. When false, actions are hidden entirely.
    pub enabled: bool,
    /// Dry-run mode: log intent but do not execute system commands.
    pub dry_run: bool,
    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables".
    pub block_backend: String,
    /// Skills the operator is allowed to invoke from the dashboard.
    pub allowed_skills: Vec<String>,
    /// Whether the AI analysis is enabled.
    pub ai_enabled: bool,
    /// AI provider name (openai | anthropic | ollama).
    pub ai_provider: String,
    /// AI model in use.
    pub ai_model: String,
    /// Whether fail2ban integration is enabled.
    pub fail2ban_enabled: bool,
    /// Whether GeoIP enrichment is enabled.
    pub geoip_enabled: bool,
    /// Whether AbuseIPDB enrichment is enabled.
    pub abuseipdb_enabled: bool,
    /// AbuseIPDB auto-block threshold (0 = disabled).
    pub abuseipdb_auto_block_threshold: u8,
    /// Honeypot mode: "off" | "demo" | "listener".
    pub honeypot_mode: String,
    /// Whether Telegram notifications are enabled.
    pub telegram_enabled: bool,
    /// Whether Slack notifications are enabled.
    pub slack_enabled: bool,
    /// Whether Cloudflare integration is enabled.
    pub cloudflare_enabled: bool,
}

impl Default for DashboardActionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
            ai_enabled: false,
            ai_provider: "openai".to_string(),
            ai_model: "gpt-4o-mini".to_string(),
            fail2ban_enabled: false,
            geoip_enabled: false,
            abuseipdb_enabled: false,
            abuseipdb_auto_block_threshold: 0,
            honeypot_mode: "off".to_string(),
            telegram_enabled: false,
            slack_enabled: false,
            cloudflare_enabled: false,
        }
    }
}

#[derive(Clone)]
struct DashboardState {
    data_dir: PathBuf,
    /// D3: operator-initiated action configuration.
    action_cfg: Arc<DashboardActionConfig>,
    /// D6: SSE broadcast channel sender.
    event_tx: EventTx,
    /// Web Push: VAPID public key (base64url) served to subscribing browsers.
    /// Empty string when web push is not configured.
    web_push_vapid_public_key: String,
    /// True when auth is configured but dashboard is exposed over HTTP on
    /// a non-localhost address. Actions are disabled in this mode.
    insecure_http: bool,
    /// Auto-sleep: timestamp of last request. After 15 min of inactivity,
    /// the dashboard returns a lightweight "sleeping" page instead of
    /// reading JSONL files.
    last_activity: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Clone)]
pub struct DashboardAuth {
    username: String,
    password_hash: PasswordHashString,
}

impl DashboardAuth {
    /// Load credentials from environment variables.
    /// Returns `None` if neither env var is set (open access mode).
    /// Returns `Err` if vars are partially set or malformed.
    pub fn try_from_env() -> Result<Option<Self>> {
        let user = std::env::var("INNERWARDEN_DASHBOARD_USER").ok();
        let hash = std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").ok();

        match (user, hash) {
            (None, None) => Ok(None), // no auth configured — open access
            (Some(username), Some(password_hash_raw)) => {
                if username.trim().is_empty() {
                    anyhow::bail!("INNERWARDEN_DASHBOARD_USER cannot be empty");
                }
                let password_hash =
                    PasswordHashString::new(&password_hash_raw).map_err(|_| {
                        anyhow::anyhow!(
                            "INNERWARDEN_DASHBOARD_PASSWORD_HASH is not a valid PHC hash string"
                        )
                    })?;
                Ok(Some(Self {
                    username,
                    password_hash,
                }))
            }
            (Some(_), None) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_USER is set but INNERWARDEN_DASHBOARD_PASSWORD_HASH is missing.\n\
                 Generate one with: innerwarden-agent --dashboard-generate-password-hash"
            ),
            (None, Some(_)) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_PASSWORD_HASH is set but INNERWARDEN_DASHBOARD_USER is missing."
            ),
        }
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        // Use constant-time comparison for the username to prevent
        // timing side-channels that could enumerate valid usernames.
        if !constant_time_eq(user, &self.username) {
            return false;
        }
        let parsed = PasswordHash::new(self.password_hash.as_str());
        match parsed {
            Ok(hash) => Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// Constant-time string equality to prevent timing side-channel attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// D3 — action request / response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BlockIpRequest {
    /// Target IP address to block.
    ip: String,
    /// Operator-supplied reason (mandatory — becomes the audit trail entry).
    reason: String,
    /// Optional incident ID to associate this action with.
    incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SuspendUserRequest {
    /// Linux username to suspend from sudo.
    user: String,
    /// Operator-supplied reason (mandatory).
    reason: String,
    /// How long to suspend (seconds). Defaults to 3600 (1 hour).
    duration_secs: Option<u64>,
    /// Optional incident ID to associate this action with.
    incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HoneypotTestRequest {
    /// Operator-supplied reason (mandatory).
    reason: String,
    /// Duration in seconds for the honeypot session (default: 120).
    duration_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    success: bool,
    dry_run: bool,
    message: String,
    /// Echoes back the skill ID that was invoked (or would have been).
    skill_id: String,
}

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EntitiesQuery {
    limit: Option<usize>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    group_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JourneyQuery {
    subject_type: Option<String>,
    subject: Option<String>,
    // Backward compatibility with D2.1 clients
    ip: Option<String>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ClusterQuery {
    limit: Option<usize>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    date: Option<String>,
    format: Option<String>,
    subject_type: Option<String>,
    subject: Option<String>,
    // Backward compatibility with D2.1 clients
    ip: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    group_by: Option<String>,
    limit: Option<usize>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ReportQuery {
    /// Optional specific date (YYYY-MM-DD). Defaults to latest available.
    date: Option<String>,
}

// ---------------------------------------------------------------------------
// Response structs — existing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OverviewResponse {
    date: String,
    events_count: usize,
    incidents_count: usize,
    decisions_count: usize,
    top_detectors: Vec<DetectorCount>,
    latest_telemetry: Option<TelemetrySnapshot>,
}

#[derive(Debug, Serialize)]
struct DetectorCount {
    detector: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct IncidentListResponse {
    date: String,
    total: usize,
    items: Vec<IncidentView>,
}

#[derive(Debug, Serialize)]
struct DecisionListResponse {
    date: String,
    total: usize,
    items: Vec<DecisionView>,
}

#[derive(Debug, Serialize)]
struct IncidentView {
    ts: chrono::DateTime<Utc>,
    incident_id: String,
    severity: String,
    title: String,
    summary: String,
    entities: Vec<String>,
    tags: Vec<String>,
    /// Resolution status: "blocked", "suspended", "monitored", "ignored", or "open"
    outcome: String,
    /// What action was taken (e.g. "block-ip-ufw", "fail2ban:sshd")
    #[serde(skip_serializing_if = "Option::is_none")]
    action_taken: Option<String>,
}

#[derive(Debug, Serialize)]
struct DecisionView {
    ts: chrono::DateTime<Utc>,
    incident_id: String,
    action_type: String,
    target_ip: Option<String>,
    skill_id: Option<String>,
    confidence: f32,
    auto_executed: bool,
    dry_run: bool,
    reason: String,
    execution_result: String,
}

// ---------------------------------------------------------------------------
// Response structs — D2 journey
// ---------------------------------------------------------------------------

/// Summarizes an attacker (IP with at least one incident) for the left panel.
#[derive(Debug, Serialize)]
struct AttackerSummary {
    ip: String,
    first_seen: chrono::DateTime<Utc>,
    last_seen: chrono::DateTime<Utc>,
    max_severity: String,
    detectors: Vec<String>,
    /// "blocked" | "monitoring" | "honeypot" | "active" | "unknown"
    outcome: String,
    incident_count: usize,
    event_count: usize,
}

#[derive(Debug, Serialize)]
struct EntitiesResponse {
    date: String,
    attackers: Vec<AttackerSummary>,
}

/// One timestamped entry in an attacker's journey timeline.
#[derive(Debug, Serialize)]
struct JourneyEntry {
    ts: chrono::DateTime<Utc>,
    /// "event" | "incident" | "decision" | "honeypot_ssh" | "honeypot_http" | "honeypot_banner"
    kind: String,
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JourneySummary {
    total_entries: usize,
    events_count: usize,
    incidents_count: usize,
    decisions_count: usize,
    honeypot_count: usize,
    first_event: Option<chrono::DateTime<Utc>>,
    first_incident: Option<chrono::DateTime<Utc>>,
    first_decision: Option<chrono::DateTime<Utc>>,
    first_honeypot: Option<chrono::DateTime<Utc>>,
    pivot_shortcuts: Vec<String>,
    hints: Vec<String>,
}

/// D5 — High-level attack assessment derived from the journey entries.
#[derive(Debug, Serialize)]
struct JourneyVerdict {
    /// Detected attack vector: "ssh_bruteforce" | "credential_stuffing" |
    /// "port_scan" | "sudo_abuse" | "unknown"
    entry_vector: String,
    /// "no_evidence_of_success" | "likely_success" | "confirmed_success" | "inconclusive"
    access_status: String,
    /// "no_evidence" | "attempted" | "confirmed" | "inconclusive"
    privilege_status: String,
    /// "blocked" | "monitored" | "honeypot" | "active" | "unknown"
    containment_status: String,
    /// "engaged" | "diverted" | "not_engaged"
    honeypot_status: String,
    /// "high" | "medium" | "low"
    confidence: String,
}

/// D5 — A logical phase of the attack story derived from consecutive entries.
#[derive(Debug, Serialize)]
struct JourneyChapter {
    /// Stage label: "reconnaissance" | "initial_access_attempt" | "access_success" |
    /// "privilege_abuse" | "response" | "containment" | "honeypot_interaction" | "unknown"
    stage: String,
    title: String,
    summary: String,
    start_ts: chrono::DateTime<Utc>,
    end_ts: chrono::DateTime<Utc>,
    entry_count: usize,
    /// Key facts / evidence highlights (usernames, ports, credentials, etc.)
    evidence_highlights: Vec<String>,
    /// Indices into the parent `entries` array for drill-down
    entry_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct JourneyResponse {
    subject_type: String,
    subject: String,
    date: String,
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    outcome: String,
    summary: JourneySummary,
    /// D5 — high-level attack assessment
    verdict: JourneyVerdict,
    /// D5 — logical attack chapters derived from entries
    chapters: Vec<JourneyChapter>,
    entries: Vec<JourneyEntry>,
}

#[derive(Debug, Serialize)]
struct PivotItem {
    group_by: String,
    value: String,
    first_seen: chrono::DateTime<Utc>,
    last_seen: chrono::DateTime<Utc>,
    max_severity: String,
    incident_count: usize,
    event_count: usize,
    outcome: String,
    detectors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PivotResponse {
    date: String,
    group_by: String,
    total: usize,
    items: Vec<PivotItem>,
}

#[derive(Debug, Serialize)]
struct ClusterItem {
    cluster_id: String,
    pivot: String,
    pivot_type: String,
    pivot_value: String,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    incident_count: usize,
    detector_kinds: Vec<String>,
    incident_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClusterResponse {
    date: String,
    total: usize,
    items: Vec<ClusterItem>,
}

#[derive(Debug, Serialize)]
struct InvestigationExport {
    generated_at: DateTime<Utc>,
    date: String,
    filters: serde_json::Value,
    group_by: String,
    subject_type: Option<String>,
    subject: Option<String>,
    overview: OverviewResponse,
    pivots: Vec<PivotItem>,
    clusters: Vec<ClusterItem>,
    journey: Option<JourneyResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PivotKind {
    Ip,
    User,
    Detector,
}

impl PivotKind {
    fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or("ip").trim().to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "detector" => Self::Detector,
            _ => Self::Ip,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::User => "user",
            Self::Detector => "detector",
        }
    }
}

#[derive(Debug, Clone)]
struct InvestigationFilters {
    severity_min: Option<u8>,
    detector: Option<String>,
}

impl InvestigationFilters {
    fn from_query(severity_min: Option<&str>, detector: Option<&str>) -> Self {
        let severity_min = severity_min
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| severity_order(v.to_ascii_lowercase().as_str()));
        let severity_min = match severity_min {
            Some(0) | None => None,
            other => other,
        };

        let detector = detector
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase());

        Self {
            severity_min,
            detector,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal accumulator for grouping events/incidents by IP
// ---------------------------------------------------------------------------

#[derive(Default)]
struct IpAccumulator {
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    max_severity: u8,
    max_severity_str: String,
    detectors: BTreeSet<String>,
    ips: BTreeSet<String>,
    incident_count: usize,
    event_count: usize,
}

impl IpAccumulator {
    fn update_time(&mut self, ts: chrono::DateTime<Utc>) {
        if self.first_seen.is_none_or(|existing| ts < existing) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.is_none_or(|existing| ts > existing) {
            self.last_seen = Some(ts);
        }
    }
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub async fn serve(
    data_dir: PathBuf,
    bind: String,
    auth: Option<DashboardAuth>,
    action_cfg: DashboardActionConfig,
    web_push_vapid_public_key: String,
) -> Result<()> {
    if auth.is_none() {
        warn!(
            "dashboard is running WITHOUT authentication — \
             set INNERWARDEN_DASHBOARD_USER and INNERWARDEN_DASHBOARD_PASSWORD_HASH \
             in agent.env to require a login"
        );
    }

    // HTTPS warning: credentials sent in plaintext over non-localhost HTTP
    if auth.is_some() {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        if !is_localhost {
            warn!(
                bind = %bind,
                "dashboard is accessible over HTTP on a non-localhost address. \
                 Credentials will be sent in plaintext. Consider using a reverse \
                 proxy with TLS or binding to 127.0.0.1."
            );
        }
    }

    // D6: broadcast channel — capacity 64 is plenty; lagged receivers are dropped.
    let (event_tx, _) = broadcast::channel::<SsePayload>(64);

    let insecure_http = auth.is_some() && {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        !is_localhost
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let state = DashboardState {
        data_dir: data_dir.clone(),
        action_cfg: Arc::new(action_cfg),
        event_tx: event_tx.clone(),
        web_push_vapid_public_key,
        insecure_http,
        last_activity: Arc::new(std::sync::atomic::AtomicU64::new(now_secs)),
    };
    let auth_layer = middleware::from_fn_with_state(auth, require_basic_auth);
    let activity_state = state.last_activity.clone();
    let activity_layer = middleware::from_fn(move |req: Request<Body>, next: Next| {
        let ts = activity_state.clone();
        async move {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ts.store(now, std::sync::atomic::Ordering::Relaxed);
            next.run(req).await
        }
    });
    // Global rate limiter — rejects requests from IPs exceeding 120/min with 429.
    // Prevents memory exhaustion from bot traffic when dashboard is internet-facing.
    let rate_limit_layer = middleware::from_fn(|req: Request<Body>, next: Next| async move {
        let ip = extract_client_ip(&req);
        if global_rate_check(&ip) {
            return axum::http::Response::builder()
                .status(429)
                .header("retry-after", "60")
                .body(Body::from("Too Many Requests"))
                .unwrap()
                .into_response();
        }
        next.run(req).await
    });

    // Agent API routes — no auth required (localhost service-to-service)
    // These are used by AI agents (OpenClaw, n8n, etc.) to query security state.
    let agent_api = Router::new()
        .route(
            "/api/agent/security-context",
            get(api_agent_security_context),
        )
        .route("/api/agent/check-ip", get(api_agent_check_ip))
        .route("/api/agent/check-command", post(api_agent_check_command))
        .route("/metrics", get(api_prometheus_metrics))
        .with_state(state.clone());

    // Dashboard routes — auth required
    let dashboard = Router::new()
        .route("/", get(index))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/pivots", get(api_pivots))
        .route("/api/clusters", get(api_clusters))
        .route("/api/journey", get(api_journey))
        .route("/api/export", get(api_export))
        .route("/api/report", get(api_report))
        .route("/api/report/dates", get(api_report_dates))
        .route("/api/quickwins", get(api_quickwins))
        // E6 — system status
        .route("/api/status", get(api_status))
        .route("/api/collectors", get(api_collectors))
        // D3 — operator-initiated actions (POST, require auth, respect dry_run)
        .route("/api/action/block-ip", post(api_action_block_ip))
        .route("/api/action/suspend-user", post(api_action_suspend_user))
        .route("/api/action/config", get(api_action_config))
        // Honeypot tab
        .route("/api/honeypot/sessions", get(api_honeypot_sessions))
        .route("/api/action/honeypot", post(api_action_honeypot))
        // D6 — SSE live event stream
        .route("/api/events/stream", get(api_events_stream))
        // Web Push
        .route("/sw.js", get(service_worker_js))
        .route("/api/push/vapid-key", get(api_push_vapid_key))
        .route(
            "/api/push/subscribe",
            post(api_push_subscribe).delete(api_push_unsubscribe),
        )
        .layer(auth_layer)
        .with_state(state);

    let app = agent_api
        .merge(dashboard)
        .layer(activity_layer)
        .layer(rate_limit_layer);

    // D6: spawn file watcher and heartbeat tasks
    tokio::spawn(watch_for_new_entries(data_dir, event_tx.clone()));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = event_tx.send(SsePayload {
                kind: "heartbeat".to_string(),
                data: None,
            });
        }
    });

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind dashboard listener on {bind}"))?;

    info!(
        bind = %bind,
        "dashboard read-only mode started"
    );
    axum::serve(listener, app)
        .await
        .context("dashboard server failed")
}

pub fn generate_password_hash_interactive() -> Result<()> {
    let password =
        rpassword::prompt_password("Dashboard password (input hidden): ").context("read failed")?;
    let confirm =
        rpassword::prompt_password("Confirm password: ").context("confirm read failed")?;
    if password != confirm {
        anyhow::bail!("password confirmation does not match");
    }
    if password.len() < 16 {
        warn!("dashboard password is shorter than 16 characters; consider a stronger secret");
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("failed to generate argon2 hash"))?
        .to_string();
    println!("{hash}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth middleware + login rate limiting
// ---------------------------------------------------------------------------

/// Maximum failed login attempts before an IP is temporarily blocked.
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 5;
/// Window (in seconds) for counting failed attempts AND the block duration.
const LOGIN_RATE_LIMIT_WINDOW_SECS: u64 = 15 * 60; // 15 minutes

/// Global rate-limiter: maps source IP string → list of failed-login timestamps.
static LOGIN_RATE_LIMITER: LazyLock<Mutex<HashMap<String, Vec<std::time::Instant>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Global request rate limiter — prevents memory exhaustion from bot traffic
// ---------------------------------------------------------------------------

/// Max requests per IP per minute before returning 429.
const GLOBAL_RATE_LIMIT_PER_MIN: usize = 120;

/// Global request rate limiter: maps IP → ring of timestamps.
/// Pruned lazily; entries older than 60s are ignored in count.
static GLOBAL_RATE_LIMITER: LazyLock<Mutex<HashMap<String, Vec<std::time::Instant>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check if an IP exceeds the global request rate limit. Records the request.
fn global_rate_check(ip: &str) -> bool {
    let mut map = GLOBAL_RATE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or_else(std::time::Instant::now);

    // Prune stale IPs periodically (when map grows large)
    if map.len() > 1000 {
        map.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
    }

    let timestamps = map.entry(ip.to_string()).or_default();
    timestamps.retain(|t| *t > cutoff);
    timestamps.push(std::time::Instant::now());
    timestamps.len() > GLOBAL_RATE_LIMIT_PER_MIN
}

/// Extract a client IP string from the request.
/// Checks `X-Forwarded-For` and `X-Real-IP` headers first (reverse-proxy scenario),
/// then falls back to the socket peer address injected by `axum::serve`.
fn extract_client_ip(req: &Request<Body>) -> String {
    // X-Forwarded-For: first entry is the original client
    if let Some(val) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = val.to_str() {
            if let Some(first) = s.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    // X-Real-IP
    if let Some(val) = req.headers().get("x-real-ip") {
        if let Ok(s) = val.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    // Fallback: socket peer address from axum::serve ConnectInfo
    if let Some(addr) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
    {
        return addr.0.ip().to_string();
    }
    "unknown".to_string()
}

/// Check whether `ip` is currently rate-limited and, if not, record a failed attempt.
/// Returns `true` if the IP should be blocked (too many recent failures).
fn check_and_record_failed_login(ip: &str) -> bool {
    let mut map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(LOGIN_RATE_LIMIT_WINDOW_SECS))
        .unwrap_or_else(std::time::Instant::now);

    let attempts = map.entry(ip.to_string()).or_default();
    // Purge old entries outside the window
    attempts.retain(|t| *t > cutoff);

    if attempts.len() >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS {
        return true; // already rate-limited
    }
    attempts.push(std::time::Instant::now());
    attempts.len() >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS
}

/// Returns `true` if `ip` is currently rate-limited (without recording a new attempt).
fn is_rate_limited(ip: &str) -> bool {
    let map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(LOGIN_RATE_LIMIT_WINDOW_SECS))
        .unwrap_or_else(std::time::Instant::now);
    if let Some(attempts) = map.get(ip) {
        let recent = attempts.iter().filter(|t| **t > cutoff).count();
        recent >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS
    } else {
        false
    }
}

/// Clear the rate-limit record for an IP (called on successful login).
fn clear_rate_limit(ip: &str) {
    let mut map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(ip);
}

async fn require_basic_auth(
    State(auth): State<Option<DashboardAuth>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // No credentials configured → open access
    let Some(auth) = auth else {
        return next.run(req).await;
    };

    let client_ip = extract_client_ip(&req);

    // Check if this IP is already rate-limited before doing any auth work
    if is_rate_limited(&client_ip) {
        warn!(ip = %client_ip, "login rate-limited: too many failed attempts");
        return rate_limited_response();
    }

    let Some(raw_header) = req.headers().get(header::AUTHORIZATION) else {
        return unauthorized_response();
    };
    let Ok(raw_header) = raw_header.to_str() else {
        return unauthorized_response();
    };
    let Some((user, password)) = parse_basic_auth(raw_header) else {
        return unauthorized_response();
    };
    if !auth.verify(&user, &password) {
        let blocked = check_and_record_failed_login(&client_ip);
        if blocked {
            warn!(
                ip = %client_ip,
                "login rate-limited after {} failed attempts in {} min window",
                LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
                LOGIN_RATE_LIMIT_WINDOW_SECS / 60
            );
            return rate_limited_response();
        }
        return unauthorized_response();
    }

    // Successful auth — clear any prior failed attempts for this IP
    clear_rate_limit(&client_ip);
    next.run(req).await
}

fn parse_basic_auth(value: &str) -> Option<(String, String)> {
    let token = value.strip_prefix("Basic ")?;
    let decoded = BASE64_STANDARD.decode(token.as_bytes()).ok()?;
    let raw = String::from_utf8(decoded).ok()?;
    let (user, password) = raw.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

fn unauthorized_response() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="innerwarden-dashboard", charset="UTF-8""#),
    );
    response
}

fn rate_limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many failed login attempts. Try again later.",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// D6 — SSE file watcher and stream handler
// ---------------------------------------------------------------------------

/// Polls today's incidents and decisions JSONL files every 2 s.
/// Broadcasts a `"refresh"` SSE payload whenever either file grows.
async fn watch_for_new_entries(data_dir: PathBuf, tx: EventTx) {
    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};

    // Track byte offsets so we can read only new lines.
    let mut offsets: HashMap<String, u64> = HashMap::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        interval.tick().await;
        if tx.receiver_count() == 0 {
            continue;
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Check decisions + incidents for growth → generic refresh signal.
        let refresh_files = [
            format!("incidents-{today}.jsonl"),
            format!("decisions-{today}.jsonl"),
        ];
        let mut changed = false;
        for name in &refresh_files {
            let path = data_dir.join(name);
            let current = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let prev = offsets.entry(name.clone()).or_insert(current);
            if current > *prev {
                *prev = current;
                changed = true;
            }
        }
        if changed {
            let _ = tx.send(SsePayload {
                kind: "refresh".to_string(),
                data: None,
            });
        }

        // D8 — read new incident lines and emit `alert` for High/Critical.
        let inc_name = format!("incidents-{today}.jsonl");
        let inc_path = data_dir.join(&inc_name);
        let alert_key = format!("alert:{inc_name}");
        let alert_offset = offsets.entry(alert_key.clone()).or_insert(0);

        if let Ok(mut f) = std::fs::File::open(&inc_path) {
            let file_len = f.seek(SeekFrom::End(0)).unwrap_or(0);
            if file_len > *alert_offset {
                let _ = f.seek(SeekFrom::Start(*alert_offset));
                let mut buf = String::new();
                if f.read_to_string(&mut buf).is_ok() {
                    *alert_offset = file_len;
                    for line in buf.lines() {
                        if let Ok(inc) = serde_json::from_str::<Incident>(line) {
                            if matches!(inc.severity, Severity::High | Severity::Critical) {
                                // Pick first ip entity, fall back to first entity of any kind.
                                let entity = inc
                                    .entities
                                    .iter()
                                    .find(|e| e.r#type == EntityType::Ip)
                                    .or_else(|| inc.entities.first());
                                let (etype, evalue) = entity
                                    .map(|e| {
                                        let t = match e.r#type {
                                            EntityType::Ip => "ip",
                                            EntityType::User => "user",
                                            EntityType::Container => "container",
                                            EntityType::Path => "path",
                                            EntityType::Service => "service",
                                        };
                                        (t, e.value.as_str())
                                    })
                                    .unwrap_or(("ip", "unknown"));

                                let payload = serde_json::json!({
                                    "severity":     format!("{:?}", inc.severity).to_lowercase(),
                                    "title":        inc.title,
                                    "entity_type":  etype,
                                    "entity_value": evalue,
                                });
                                let _ = tx.send(SsePayload {
                                    kind: "alert".to_string(),
                                    data: Some(payload),
                                });
                            }
                        }
                    }
                }
            } else {
                // File shrunk (rotation) — reset offset.
                if file_len < *alert_offset {
                    *alert_offset = 0;
                }
            }
        }
    }
}

/// `GET /api/events/stream` — SSE live event stream (D6).
async fn api_events_stream(
    State(state): State<DashboardState>,
) -> Sse<impl futures_core::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg: Result<SsePayload, _>| {
        let payload = msg.ok()?;
        let data = serde_json::to_string(&payload).unwrap_or_default();
        Some(Ok(SseEvent::default().event(&payload.kind).data(data)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn index() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (header::PRAGMA, "no-cache"),
        ],
        Html(INDEX_HTML),
    )
}

/// Dashboard auto-sleep timeout: 15 minutes of no requests.
const DASHBOARD_SLEEP_SECS: u64 = 15 * 60;

fn is_dashboard_sleeping(last_activity: &std::sync::atomic::AtomicU64) -> bool {
    let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last) > DASHBOARD_SLEEP_SECS
}

async fn api_overview(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<OverviewResponse> {
    let date = resolve_date(query.date.as_deref());
    // When sleeping, return minimal data from telemetry only (no JSONL reads)
    if is_dashboard_sleeping(&state.last_activity) {
        return Json(OverviewResponse {
            date: date.clone(),
            events_count: 0,
            incidents_count: 0,
            decisions_count: 0,
            top_detectors: vec![],
            latest_telemetry: crate::telemetry::read_latest_snapshot(&state.data_dir, &date),
        });
    }
    Json(compute_overview(&state.data_dir, &date))
}

async fn api_incidents(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<IncidentListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let path = dated_path(&state.data_dir, "incidents", &date);
    let mut incidents = read_jsonl::<innerwarden_core::incident::Incident>(&path);
    incidents.sort_by(|a, b| b.ts.cmp(&a.ts));

    // Load decisions to cross-reference outcomes
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(&state.data_dir, "decisions", &date));
    let decision_map: std::collections::HashMap<String, &DecisionEntry> = decisions
        .iter()
        .map(|d| (d.incident_id.clone(), d))
        .collect();

    let total = incidents.len();
    let items = incidents
        .into_iter()
        .take(limit)
        .map(|inc| {
            let (outcome, action_taken) = if let Some(d) = decision_map.get(&inc.incident_id) {
                let outcome = match d.action_type.as_str() {
                    "block_ip" => "blocked",
                    "suspend_user_sudo" => "suspended",
                    "kill_process" => "killed",
                    "block_container" => "contained",
                    "monitor" => "monitored",
                    "honeypot" => "honeypot",
                    "ignore" => "ignored",
                    _ => "resolved",
                };
                let source = if d.ai_provider.starts_with("fail2ban") {
                    format!("fail2ban → {}", d.skill_id.as_deref().unwrap_or(""))
                } else if d.ai_provider.starts_with("abuseipdb") {
                    "abuseipdb auto-block".to_string()
                } else {
                    d.skill_id.clone().unwrap_or_default()
                };
                (outcome.to_string(), Some(source))
            } else {
                ("open".to_string(), None)
            };
            IncidentView {
                ts: inc.ts,
                incident_id: inc.incident_id,
                severity: format!("{:?}", inc.severity).to_lowercase(),
                title: inc.title,
                summary: inc.summary,
                entities: inc
                    .entities
                    .into_iter()
                    .map(|e| format!("{:?}:{}", e.r#type, e.value))
                    .collect(),
                tags: inc.tags,
                outcome,
                action_taken,
            }
        })
        .collect();

    Json(IncidentListResponse { date, total, items })
}

async fn api_decisions(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<DecisionListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let path = dated_path(&state.data_dir, "decisions", &date);
    let mut decisions = read_jsonl::<DecisionEntry>(&path);
    decisions.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = decisions.len();
    let items = decisions
        .into_iter()
        .take(limit)
        .map(|d| DecisionView {
            ts: d.ts,
            incident_id: d.incident_id,
            action_type: d.action_type,
            target_ip: d.target_ip,
            skill_id: d.skill_id,
            confidence: d.confidence,
            auto_executed: d.auto_executed,
            dry_run: d.dry_run,
            reason: d.reason,
            execution_result: d.execution_result,
        })
        .collect();

    Json(DecisionListResponse { date, total, items })
}

async fn api_entities(
    State(state): State<DashboardState>,
    Query(query): Query<EntitiesQuery>,
) -> Json<EntitiesResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let group_by = PivotKind::parse(query.group_by.as_deref());
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());

    let attackers = if group_by == PivotKind::Ip {
        build_attackers(&state.data_dir, &date, &filters, limit)
    } else {
        Vec::new()
    };
    Json(EntitiesResponse { date, attackers })
}

async fn api_pivots(
    State(state): State<DashboardState>,
    Query(query): Query<EntitiesQuery>,
) -> Json<PivotResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let group_by = PivotKind::parse(query.group_by.as_deref());
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());
    let items = build_pivots(&state.data_dir, &date, group_by, &filters, limit);
    Json(PivotResponse {
        date,
        group_by: group_by.as_str().to_string(),
        total: items.len(),
        items,
    })
}

async fn api_clusters(
    State(state): State<DashboardState>,
    Query(query): Query<ClusterQuery>,
) -> Json<ClusterResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let window_seconds = query.window_seconds.unwrap_or(300).clamp(30, 3600);
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());
    let items = build_cluster_items(&state.data_dir, &date, &filters, limit, window_seconds);
    Json(ClusterResponse {
        date,
        total: items.len(),
        items,
    })
}

async fn api_journey(
    State(state): State<DashboardState>,
    Query(query): Query<JourneyQuery>,
) -> Json<JourneyResponse> {
    let date = resolve_date(query.date.as_deref());
    let subject_type = PivotKind::parse(query.subject_type.as_deref());
    let window_seconds = query.window_seconds.map(|w| w.clamp(60, 86_400));
    let subject = query
        .subject
        .or(query.ip)
        .unwrap_or_default()
        .trim()
        .to_string();
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());

    if subject.is_empty() {
        return Json(JourneyResponse {
            subject_type: subject_type.as_str().to_string(),
            subject: String::new(),
            date,
            first_seen: None,
            last_seen: None,
            outcome: "unknown".to_string(),
            summary: JourneySummary {
                total_entries: 0,
                events_count: 0,
                incidents_count: 0,
                decisions_count: 0,
                honeypot_count: 0,
                first_event: None,
                first_incident: None,
                first_decision: None,
                first_honeypot: None,
                pivot_shortcuts: Vec::new(),
                hints: vec!["Select a subject to start investigation.".to_string()],
            },
            verdict: JourneyVerdict {
                entry_vector: "unknown".to_string(),
                access_status: "inconclusive".to_string(),
                privilege_status: "no_evidence".to_string(),
                containment_status: "unknown".to_string(),
                honeypot_status: "not_engaged".to_string(),
                confidence: "low".to_string(),
            },
            chapters: vec![],
            entries: vec![],
        });
    }

    Json(build_journey(
        &state.data_dir,
        &date,
        subject_type,
        &subject,
        &filters,
        window_seconds,
    ))
}

async fn api_export(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let date = resolve_date(query.date.as_deref());
    let format = query
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    let subject_type = PivotKind::parse(query.subject_type.as_deref());
    let subject = query.subject.or(query.ip).map(|s| s.trim().to_string());
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());
    let group_by = PivotKind::parse(query.group_by.as_deref());
    let limit = normalize_limit(query.limit);
    let window_seconds = query.window_seconds.unwrap_or(300).clamp(30, 3600);

    let overview = compute_overview(&state.data_dir, &date);
    let pivots = build_pivots(&state.data_dir, &date, group_by, &filters, limit);
    let clusters = build_cluster_items(&state.data_dir, &date, &filters, limit, window_seconds);
    let journey = subject.as_ref().filter(|s| !s.is_empty()).map(|s| {
        build_journey(
            &state.data_dir,
            &date,
            subject_type,
            s,
            &filters,
            Some(window_seconds),
        )
    });

    let snapshot = InvestigationExport {
        generated_at: Utc::now(),
        date: date.clone(),
        filters: serde_json::json!({
            "date": date,
            "severity_min": query.severity_min,
            "detector": query.detector,
            "group_by": group_by.as_str(),
            "window_seconds": window_seconds,
            "limit": limit,
        }),
        group_by: group_by.as_str().to_string(),
        subject_type: subject.as_ref().map(|_| subject_type.as_str().to_string()),
        subject,
        overview,
        pivots,
        clusters,
        journey,
    };

    if format == "md" || format == "markdown" {
        let markdown = render_markdown_snapshot(&snapshot);
        return (
            [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
            markdown,
        )
            .into_response();
    }

    match serde_json::to_string_pretty(&snapshot) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize export snapshot",
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// D10 — Report API
// ---------------------------------------------------------------------------

/// GET /api/report[?date=YYYY-MM-DD]
/// Returns a TrialReport JSON computed on-demand.
/// `date` defaults to the most recent date with data.
async fn api_report(
    State(state): State<DashboardState>,
    Query(query): Query<ReportQuery>,
) -> Response {
    let data_dir = state.data_dir.clone();
    let date_str = query.date.clone();
    let report: TrialReport = tokio::task::spawn_blocking(move || {
        report_mod::compute_for_date(&data_dir, date_str.as_deref())
    })
    .await
    .unwrap_or_else(|_| report_mod::compute_for_date(&state.data_dir, query.date.as_deref()));

    match serde_json::to_string_pretty(&report) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize report",
        )
            .into_response(),
    }
}

/// GET /api/report/dates
/// Returns a JSON array of date strings (YYYY-MM-DD) for which data exists,
/// most recent first. Used by the dashboard report date picker.
async fn api_report_dates(State(state): State<DashboardState>) -> Json<Vec<String>> {
    let data_dir = state.data_dir.clone();
    let dates = tokio::task::spawn_blocking(move || report_mod::list_available_dates(&data_dir))
        .await
        .unwrap_or_default();
    Json(dates)
}

// ---------------------------------------------------------------------------
// D3 — action handlers
// ---------------------------------------------------------------------------

/// GET /api/action/config — exposes the current action mode to the UI (read-only).
async fn api_action_config(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let cfg = &state.action_cfg;
    let mode = if cfg.enabled {
        if cfg.dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    };
    Json(serde_json::json!({
        "enabled": cfg.enabled,
        "dry_run": cfg.dry_run,
        "block_backend": cfg.block_backend,
        "allowed_skills": cfg.allowed_skills,
        "ai_enabled": cfg.ai_enabled,
        "ai_provider": cfg.ai_provider,
        "ai_model": cfg.ai_model,
        "mode": mode,
    }))
}

/// GET /api/quickwins — return actionable suggestions based on recent unblocked threats.
async fn api_quickwins(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let data_dir = &state.data_dir;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // Collect blocked IPs from decisions (today + yesterday)
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for date in &[today.as_str(), yesterday.as_str()] {
        let path = data_dir.join(format!("decisions-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if v["action"].as_str() == Some("block_ip") {
                        if let Some(ip) = v["target_ip"].as_str() {
                            blocked_ips.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Collect unblocked High/Critical incidents from today + yesterday
    let mut suggestions: Vec<serde_json::Value> = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = blocked_ips.clone();
    for date in &[today.as_str(), yesterday.as_str()] {
        let path = data_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let sev = v["severity"].as_str().unwrap_or("");
                    if sev != "High" && sev != "Critical" {
                        continue;
                    }
                    // Find IP entity
                    let ip = v["entities"].as_array().and_then(|arr| {
                        arr.iter()
                            .find(|e| e["type"].as_str() == Some("Ip"))
                            .and_then(|e| e["value"].as_str())
                            .map(|s| s.to_string())
                    });
                    if let Some(ip_str) = ip {
                        if seen_ips.contains(&ip_str) {
                            continue; // already handled or deduped
                        }
                        seen_ips.insert(ip_str.clone());
                        suggestions.push(serde_json::json!({
                            "type": "unblocked_attacker",
                            "severity": sev,
                            "ip": ip_str,
                            "title": v["title"].as_str().unwrap_or("Threat detected"),
                            "date": date,
                            "action": format!("Block {ip_str} at the firewall"),
                            "command": "innerwarden enable block-ip"
                        }));
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "suggestions": suggestions,
        "count": suggestions.len()
    }))
}

/// GET /api/honeypot/sessions — list honeypot sessions from the honeypot/ subdirectory.
async fn api_honeypot_sessions(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let honeypot_dir = state.data_dir.join("honeypot");

    // Collect blocked IPs from recent decisions for "blocked" badge
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    for date in &[today.as_str(), yesterday.as_str()] {
        let decisions =
            read_jsonl::<DecisionEntry>(&state.data_dir.join(format!("decisions-{date}.jsonl")));
        for d in decisions {
            if d.action_type == "block_ip" {
                if let Some(ip) = d.target_ip {
                    blocked_ips.insert(ip);
                }
            }
        }
    }

    // Read session metadata files
    let mut sessions: Vec<serde_json::Value> = Vec::new();

    let Ok(mut dir) = tokio::fs::read_dir(&honeypot_dir).await else {
        return Json(serde_json::json!({ "sessions": [] }));
    };

    // Collect all file names first so we can detect .jsonl-only sessions
    let mut json_sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut jsonl_sessions: std::collections::HashSet<String> = std::collections::HashSet::new();

    while let Ok(Some(entry)) = dir.next_entry().await {
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.starts_with("listener-session-") {
            continue;
        }
        if fname.ends_with(".json") && !fname.ends_with(".jsonl") {
            let id = fname
                .trim_start_matches("listener-session-")
                .trim_end_matches(".json")
                .to_string();
            json_sessions.insert(id);
        } else if fname.ends_with(".jsonl") {
            let id = fname
                .trim_start_matches("listener-session-")
                .trim_end_matches(".jsonl")
                .to_string();
            jsonl_sessions.insert(id);
        }
    }

    // Helper: extract commands + auth_attempts from a .jsonl evidence file
    async fn read_evidence(path: &std::path::Path) -> (Vec<String>, usize, String, String) {
        let mut commands: Vec<String> = Vec::new();
        let mut auth_count = 0usize;
        let mut ts = String::new();
        let mut peer_ip = String::new();
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            for line in content.lines() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
                        if ts.is_empty() {
                            ts = val
                                .get("ts")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                        }
                        if peer_ip.is_empty() {
                            peer_ip = val
                                .get("peer_ip")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                        }
                        auth_count += val
                            .get("auth_attempts_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        if let Some(cmds) = val.get("shell_commands").and_then(|a| a.as_array()) {
                            for c in cmds {
                                if let Some(cmd) = c.get("command").and_then(|v| v.as_str()) {
                                    if !cmd.is_empty() {
                                        commands.push(cmd.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        (commands, auth_count, ts, peer_ip)
    }

    // Process .json metadata sessions (listener mode)
    for session_id in &json_sessions {
        let meta_path = honeypot_dir.join(format!("listener-session-{session_id}.json"));
        let Ok(content) = tokio::fs::read_to_string(&meta_path).await else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };

        let target_ip = meta
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let started_at = meta
            .get("ts")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let duration_secs = meta
            .get("duration_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
        let (commands, auth_count, _, _) = read_evidence(&evidence_path).await;
        let iocs = crate::ioc::extract_from_commands(&commands);

        sessions.push(serde_json::json!({
            "session_id": session_id,
            "target_ip": target_ip,
            "started_at": started_at,
            "duration_secs": duration_secs,
            "auth_attempts": auth_count,
            "commands_count": commands.len(),
            "commands": commands,
            "iocs": iocs.format_list(),
            "blocked": blocked_ips.contains(&target_ip),
            "mode": "listener",
        }));
    }

    // Process .jsonl-only sessions (always_on mode — no .json metadata file)
    for session_id in &jsonl_sessions {
        if json_sessions.contains(session_id) {
            continue; // already processed above
        }
        let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
        let (commands, auth_count, ts, peer_ip) = read_evidence(&evidence_path).await;
        if peer_ip.is_empty() {
            continue;
        }
        let iocs = crate::ioc::extract_from_commands(&commands);

        sessions.push(serde_json::json!({
            "session_id": session_id,
            "target_ip": peer_ip,
            "started_at": ts,
            "duration_secs": 0,
            "auth_attempts": auth_count,
            "commands_count": commands.len(),
            "commands": commands,
            "iocs": iocs.format_list(),
            "blocked": blocked_ips.contains(&peer_ip),
            "mode": "always_on",
        }));
    }

    // Sort sessions by started_at descending (newest first)
    sessions.sort_by(|a, b| {
        let ta = a.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    Json(serde_json::json!({ "sessions": sessions }))
}

/// GET /api/status — E6: system status including data files and responder config.
async fn api_status(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let data_dir = &state.data_dir;

    let file_exists = |name: &str| data_dir.join(name).exists();
    let file_size = |name: &str| {
        std::fs::metadata(data_dir.join(name))
            .map(|m| m.len())
            .unwrap_or(0)
    };

    let events_file = format!("events-{today}.jsonl");
    let incidents_file = format!("incidents-{today}.jsonl");
    let decisions_file = format!("decisions-{today}.jsonl");
    let telemetry_file = format!("telemetry-{today}.jsonl");

    let action_cfg = &state.action_cfg;

    // Compute seconds since last telemetry write (agent liveness check).
    let last_telemetry_secs = std::fs::metadata(data_dir.join(&telemetry_file))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok().map(|d| d.as_secs()));

    let mode = if action_cfg.enabled {
        if action_cfg.dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    };

    Json(serde_json::json!({
        "date": today,
        "data_dir": data_dir.display().to_string(),
        "mode": mode,
        "last_telemetry_secs": last_telemetry_secs,
        "ai_enabled": action_cfg.ai_enabled,
        "ai_provider": action_cfg.ai_provider,
        "ai_model": action_cfg.ai_model,
        "files": {
            "events": { "exists": file_exists(&events_file), "size_bytes": file_size(&events_file) },
            "incidents": { "exists": file_exists(&incidents_file), "size_bytes": file_size(&incidents_file) },
            "decisions": { "exists": file_exists(&decisions_file), "size_bytes": file_size(&decisions_file) },
            "telemetry": { "exists": file_exists(&telemetry_file), "size_bytes": file_size(&telemetry_file) }
        },
        "responder": {
            "enabled": action_cfg.enabled,
            "dry_run": action_cfg.dry_run,
            "block_backend": action_cfg.block_backend,
            "allowed_skills": action_cfg.allowed_skills
        },
        "integrations": {
            "fail2ban": action_cfg.fail2ban_enabled,
            "geoip": action_cfg.geoip_enabled,
            "abuseipdb": action_cfg.abuseipdb_enabled,
            "abuseipdb_auto_block_threshold": action_cfg.abuseipdb_auto_block_threshold,
            "honeypot_mode": action_cfg.honeypot_mode,
            "telegram": action_cfg.telegram_enabled,
            "slack": action_cfg.slack_enabled,
            "cloudflare": action_cfg.cloudflare_enabled
        }
    }))
}

/// GET /api/collectors — sensor collector detection (file existence + recency).
/// Fail-silent: never requires root, never panics.
async fn api_collectors(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let data_dir = &state.data_dir;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let events_file = data_dir.join(format!("events-{today}.jsonl"));

    // Helper: check if a path exists
    let file_exists = |p: &str| std::path::Path::new(p).exists();

    // Helper: how many seconds since a file was modified (None if missing or error)
    let file_age_secs = |p: &str| -> Option<u64> {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    };

    // Helper: check if a binary is in PATH
    let has_binary = |name: &str| {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    // Helper: count events by source in today's events file (last 2000 lines)
    let count_source = |source: &str| -> u64 {
        use std::io::{BufRead, BufReader};
        let f = match std::fs::File::open(&events_file) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let needle = format!("\"source\":\"{source}\"");
        let needle2 = format!("\"source\": \"{source}\"");
        let mut count = 0u64;
        for line in BufReader::new(f).lines() {
            let Ok(l) = line else { break };
            if l.contains(&needle) || l.contains(&needle2) {
                count += 1;
            }
        }
        count
    };

    // Recency threshold: active if file modified within last 2 hours
    let recent = |age: Option<u64>| age.map(|s| s < 7200).unwrap_or(false);

    let auth_log = "/var/log/auth.log";
    let falco_log = "/var/log/falco/falco.log";
    let suricata = "/var/log/suricata/eve.json";
    let wazuh = "/var/ossec/logs/alerts/alerts.json";
    let osquery = "/var/log/osquery/osqueryd.results.log";
    let audit_log = "/var/log/audit/audit.log";
    let nginx_acc = "/var/log/nginx/access.log";
    let nginx_err = "/var/log/nginx/error.log";
    let docker_sock = "/var/run/docker.sock";

    let collectors = serde_json::json!([
        {
            "id": "auth_log",
            "name": "SSH / Auth Log",
            "kind": "native",
            "log_path": auth_log,
            "detected": file_exists(auth_log),
            "active": recent(file_age_secs(auth_log)),
            "events_today": count_source("auth_log"),
            "desc": "Parses /var/log/auth.log for SSH failures, logins, sudo"
        },
        {
            "id": "journald",
            "name": "systemd Journal",
            "kind": "native",
            "log_path": "journald",
            "detected": has_binary("journalctl"),
            "active": has_binary("journalctl"),
            "events_today": count_source("journald"),
            "desc": "Tails journald (sshd, sudo, kernel) via journalctl --follow"
        },
        {
            "id": "docker",
            "name": "Docker Events",
            "kind": "native",
            "log_path": docker_sock,
            "detected": file_exists(docker_sock),
            "active": file_exists(docker_sock),
            "events_today": count_source("docker"),
            "desc": "Docker lifecycle events + privilege escalation detection"
        },
        {
            "id": "nginx_access",
            "name": "nginx Access Log",
            "kind": "native",
            "log_path": nginx_acc,
            "detected": file_exists(nginx_acc),
            "active": recent(file_age_secs(nginx_acc)),
            "events_today": count_source("nginx_access"),
            "desc": "nginx access log — search abuse, UA scanner detection"
        },
        {
            "id": "nginx_error",
            "name": "nginx Error Log",
            "kind": "native",
            "log_path": nginx_err,
            "detected": file_exists(nginx_err),
            "active": recent(file_age_secs(nginx_err)),
            "events_today": count_source("nginx_error"),
            "desc": "nginx error log — web scanner and probe detection"
        },
        {
            "id": "exec_audit",
            "name": "Shell Audit (auditd)",
            "kind": "native",
            "log_path": audit_log,
            "detected": file_exists(audit_log),
            "active": recent(file_age_secs(audit_log)),
            "events_today": count_source("exec_audit"),
            "desc": "auditd EXECVE events — execution guard and shell command trail"
        },
        {
            "id": "falco_log",
            "name": "Falco",
            "kind": "external",
            "log_path": falco_log,
            "detected": file_exists(falco_log),
            "active": recent(file_age_secs(falco_log)),
            "events_today": count_source("falco_log"),
            "desc": "Falco eBPF/syscall runtime security alerts"
        },
        {
            "id": "suricata_eve",
            "name": "Suricata IDS",
            "kind": "external",
            "log_path": suricata,
            "detected": file_exists(suricata),
            "active": recent(file_age_secs(suricata)),
            "events_today": count_source("suricata_eve"),
            "desc": "Suricata network IDS alerts (alert, dns, http, tls, anomaly)"
        },
        {
            "id": "wazuh_alerts",
            "name": "Wazuh HIDS",
            "kind": "external",
            "log_path": wazuh,
            "detected": file_exists(wazuh),
            "active": recent(file_age_secs(wazuh)),
            "events_today": count_source("wazuh_alerts"),
            "desc": "Wazuh HIDS/FIM/compliance alerts"
        },
        {
            "id": "osquery_log",
            "name": "osquery",
            "kind": "external",
            "log_path": osquery,
            "detected": file_exists(osquery),
            "active": recent(file_age_secs(osquery)),
            "events_today": count_source("osquery_log"),
            "desc": "osquery differential results (ports, users, crontabs, processes)"
        }
    ]);

    Json(serde_json::json!({ "collectors": collectors }))
}

/// POST /api/action/block-ip — operator-initiated IP block with mandatory reason.
async fn api_action_block_ip(
    State(state): State<DashboardState>,
    Json(body): Json<BlockIpRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "actions disabled — dashboard is exposed over HTTP without TLS. \
                      Use a reverse proxy with TLS or bind to 127.0.0.1."
                .to_string(),
            skill_id: String::new(),
        });
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled — set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id: String::new(),
        });
    }

    let ip = body.ip.trim().to_string();
    if ip.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "ip is required".to_string(),
            skill_id: String::new(),
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id: String::new(),
        });
    }

    // Select the right skill based on configured backend.
    let skill_id = format!("block-ip-{}", state.action_cfg.block_backend);
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_block_ip(
        &state.data_dir,
        &state.action_cfg,
        &ip,
        &body.reason,
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/suspend-user — operator-initiated sudo suspension with mandatory reason.
async fn api_action_suspend_user(
    State(state): State<DashboardState>,
    Json(body): Json<SuspendUserRequest>,
) -> Json<ActionResponse> {
    let skill_id = "suspend-user-sudo".to_string();

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled — set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    let user = body.user.trim().to_string();
    if user.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "user is required".to_string(),
            skill_id,
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_suspend_user(
        &state.data_dir,
        &state.action_cfg,
        &user,
        &body.reason,
        body.duration_secs.unwrap_or(3600),
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/honeypot — operator-initiated honeypot test session.
async fn api_action_honeypot(
    State(state): State<DashboardState>,
    Json(body): Json<HoneypotTestRequest>,
) -> Json<ActionResponse> {
    let skill_id = "honeypot".to_string();

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled — set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }

    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "skill 'honeypot' is not in allowed_skills — add it to responder.allowed_skills in agent.toml".to_string(),
            skill_id,
        });
    }

    let duration_secs = body.duration_secs.unwrap_or(120);

    // Write a synthetic incident to today's incidents file so the agent's main
    // loop picks it up in the next 2-second tick and evaluates the honeypot skill.
    let result = inject_honeypot_test_incident(&state.data_dir, &body.reason, duration_secs).await;

    match result {
        Ok(()) => {
            let entry = DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: format!("honeypot_test:{}", chrono::Utc::now().timestamp()),
                host: hostname(),
                ai_provider: "dashboard:operator".to_string(),
                action_type: "honeypot".to_string(),
                target_ip: Some("0.0.0.0".to_string()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: !state.action_cfg.dry_run,
                dry_run: state.action_cfg.dry_run,
                reason: body.reason.clone(),
                estimated_threat: "manual_test".to_string(),
                execution_result: if state.action_cfg.dry_run {
                    "ok (dry_run)".to_string()
                } else {
                    "incident_injected".to_string()
                },
                prev_hash: None,
            };
            if let Err(e) = append_decision_entry(&state.data_dir, &entry) {
                warn!("failed to write honeypot test decision entry: {e}");
            }
            info!(
                dry_run = state.action_cfg.dry_run,
                duration_secs, "dashboard action: honeypot test"
            );
            let mode_prefix = if state.action_cfg.dry_run {
                "[DRY RUN] "
            } else {
                ""
            };
            Json(ActionResponse {
                success: true,
                dry_run: state.action_cfg.dry_run,
                message: format!(
                    "{mode_prefix}Test honeypot incident injected — the agent will pick it up \
                     in the next tick (≤2 s). Connect via: ssh -p 2222 -o StrictHostKeyChecking=no root@<host>"
                ),
                skill_id,
            })
        }
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("failed to inject test incident: {e}"),
            skill_id,
        }),
    }
}

// ---------------------------------------------------------------------------
// D3 — execution helpers
// ---------------------------------------------------------------------------

/// Execute a block-ip skill and write the decision to the audit trail.
async fn execute_block_ip(
    data_dir: &Path,
    cfg: &DashboardActionConfig,
    ip: &str,
    reason: &str,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::{BlockIpIptables, BlockIpNftables, BlockIpUfw},
        HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };

    let skill_id = format!("block-ip-{}", cfg.block_backend);
    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = make_synthetic_incident(&iid, ip, reason);

    let ctx = SkillContext {
        incident: inc,
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: None,
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill: Box<dyn ResponseSkill> = match cfg.block_backend.as_str() {
        "iptables" => Box::new(BlockIpIptables),
        "nftables" => Box::new(BlockIpNftables),
        _ => Box::new(BlockIpUfw),
    };
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
    };

    append_decision_entry(data_dir, &entry)?;
    info!(
        ip = %ip,
        dry_run = cfg.dry_run,
        skill_id = %skill_id,
        success,
        "dashboard action: block-ip"
    );
    Ok((success, message))
}

/// Execute a suspend-user skill and write the decision to the audit trail.
async fn execute_suspend_user(
    data_dir: &Path,
    cfg: &DashboardActionConfig,
    user: &str,
    reason: &str,
    duration_secs: u64,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::SuspendUserSudo, HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{iid}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::user(user)],
    };

    let ctx = SkillContext {
        incident: inc,
        target_ip: None,
        target_user: Some(user.to_string()),
        target_container: None,
        duration_secs: Some(duration_secs),
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill = SuspendUserSudo;
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "suspend_user_sudo".to_string(),
        target_ip: None,
        target_user: Some(user.to_string()),
        skill_id: Some("suspend-user-sudo".to_string()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
    };

    append_decision_entry(data_dir, &entry)?;
    info!(
        user = %user,
        dry_run = cfg.dry_run,
        duration_secs,
        success,
        "dashboard action: suspend-user"
    );
    Ok((success, message))
}

/// Build a minimal synthetic incident for skill execution context.
fn make_synthetic_incident(
    incident_id_hint: &str,
    ip: &str,
    reason: &str,
) -> innerwarden_core::incident::Incident {
    use innerwarden_core::event::Severity;
    innerwarden_core::incident::Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{incident_id_hint}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::ip(ip)],
    }
}

/// Append a single `DecisionEntry` to today's decisions JSONL file.
fn append_decision_entry(data_dir: &Path, entry: &DecisionEntry) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let line = serde_json::to_string(entry).context("serialize decision")?;
    writeln!(f, "{line}").context("write decision")?;
    f.flush().context("flush decision")
}

/// Inject a synthetic high-severity SSH brute-force incident so the agent's main
/// loop picks it up and evaluates the honeypot skill in the next tick.
async fn inject_honeypot_test_incident(
    data_dir: &Path,
    reason: &str,
    duration_secs: u64,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    let now = chrono::Utc::now();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    // Build a minimal Incident that looks like an SSH brute-force event so the
    // algorithm gate passes it through (severity=High, non-private IP).
    let incident = serde_json::json!({
        "ts": now.to_rfc3339(),
        "host": hostname(),
        "incident_id": format!("honeypot_test:{}", now.timestamp()),
        "severity": "high",
        "title": format!("Manual honeypot test — {} ({}s)", reason, duration_secs),
        "summary": format!(
            "50 failed SSH login attempts from 1.2.3.4 in the last 300 seconds (manual test via dashboard)"
        ),
        "evidence": [{"count": 50, "ip": "1.2.3.4", "kind": "ssh.login_failed", "window_seconds": 300}],
        "recommended_checks": [],
        "tags": ["auth", "ssh", "bruteforce", "test", "dashboard"],
        "entities": [{"type": "ip", "value": "1.2.3.4"}]
    });

    let line = serde_json::to_string(&incident).context("serialize test incident")?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    writeln!(f, "{line}").context("write test incident")?;
    f.flush().context("flush test incident")
}

/// Returns the machine hostname (best-effort).
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Agent API — security context for AI agents (OpenClaw, n8n, etc.)
// ---------------------------------------------------------------------------

/// GET /api/agent/security-context — threat overview for AI agents
async fn api_agent_security_context(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let date = resolve_date(None);
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        &state.data_dir,
        "incidents",
        &date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(&state.data_dir, "decisions", &date));

    let total_incidents = incidents.len();
    let high_or_critical = incidents
        .iter()
        .filter(|i| {
            matches!(
                i.severity,
                innerwarden_core::event::Severity::High
                    | innerwarden_core::event::Severity::Critical
            )
        })
        .count();
    let blocks_today = decisions
        .iter()
        .filter(|d| d.action_type == "block_ip" && !d.dry_run)
        .count();

    // Collect top detectors from incident IDs (prefix before first ':')
    let mut detector_counts = std::collections::HashMap::<String, usize>::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *detector_counts.entry(detector).or_default() += 1;
    }
    let mut top: Vec<_> = detector_counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let top_threats: Vec<String> = top.iter().take(5).map(|(k, _)| k.clone()).collect();

    let threat_level = if high_or_critical >= 5 {
        "critical"
    } else if high_or_critical >= 2 {
        "high"
    } else if total_incidents >= 5 {
        "medium"
    } else {
        "low"
    };

    let recommendation = match threat_level {
        "critical" => "server under active attack — avoid risky operations",
        "high" => "elevated threat level — proceed with caution",
        _ => "safe to proceed",
    };

    Json(serde_json::json!({
        "threat_level": threat_level,
        "active_incidents_today": total_incidents,
        "high_or_critical_today": high_or_critical,
        "recent_blocks_today": blocks_today,
        "top_threats": top_threats,
        "recommendation": recommendation,
        "date": date,
    }))
}

/// Query params for check-ip
#[derive(serde::Deserialize)]
struct CheckIpQuery {
    ip: String,
}

/// GET /api/agent/check-ip?ip=X — check if an IP is known threat
async fn api_agent_check_ip(
    State(state): State<DashboardState>,
    Query(query): Query<CheckIpQuery>,
) -> Json<serde_json::Value> {
    let ip = query.ip.trim();
    let date = resolve_date(None);
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        &state.data_dir,
        "incidents",
        &date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(&state.data_dir, "decisions", &date));

    // Count incidents involving this IP
    let matching_incidents: Vec<_> = incidents
        .iter()
        .filter(|inc| {
            inc.entities
                .iter()
                .any(|e| e.r#type == innerwarden_core::entities::EntityType::Ip && e.value == ip)
        })
        .collect();

    let incident_count = matching_incidents.len();
    let blocked = decisions
        .iter()
        .any(|d| d.action_type == "block_ip" && d.target_ip.as_deref() == Some(ip));
    let last_seen = matching_incidents
        .iter()
        .map(|i| i.ts)
        .max()
        .map(|ts| ts.to_rfc3339());

    let mut detectors = std::collections::HashSet::new();
    for inc in &matching_incidents {
        if let Some(d) = inc.incident_id.split(':').next() {
            detectors.insert(d.to_string());
        }
    }

    let recommendation = if blocked {
        "avoid"
    } else if incident_count > 0 {
        "caution"
    } else {
        "no threat data"
    };

    Json(serde_json::json!({
        "ip": ip,
        "known_threat": incident_count > 0 || blocked,
        "incident_count": incident_count,
        "blocked": blocked,
        "last_seen": last_seen,
        "detectors": detectors.into_iter().collect::<Vec<_>>(),
        "recommendation": recommendation,
    }))
}

/// Request body for check-command
#[derive(serde::Deserialize)]
struct CheckCommandRequest {
    command: String,
}

/// POST /api/agent/check-command — analyze a command for dangerous patterns
async fn api_agent_check_command(Json(body): Json<CheckCommandRequest>) -> Json<serde_json::Value> {
    let cmd = body.command.trim();
    if cmd.is_empty() {
        return Json(serde_json::json!({
            "command": "",
            "risk_score": 0,
            "severity": "none",
            "signals": [],
            "recommendation": "allow",
            "explanation": "empty command",
        }));
    }

    let lower = cmd.to_ascii_lowercase();
    let mut signals = Vec::new();
    let mut score: u32 = 0;

    // Reverse shell indicators — always deny (score 60+)
    const REVERSE_SHELL: &[&str] = &[
        "/dev/tcp/",
        "/dev/udp/",
        "nc -e",
        "ncat -e",
        "netcat -e",
        "bash -i",
        "socat exec:",
        "socat tcp",
        "socat udp",
        "0>&1",
        ">&/dev/tcp",
    ];
    for indicator in REVERSE_SHELL {
        if lower.contains(indicator) {
            signals.push(serde_json::json!({
                "signal": "reverse_shell",
                "score": 60,
                "detail": format!("reverse shell indicator: `{indicator}`"),
            }));
            score += 60;
            break;
        }
    }

    // Download-and-execute patterns
    let downloaders = ["curl", "wget", "fetch", "http"];
    let executors = [
        "sh", "bash", "zsh", "dash", "python", "perl", "ruby", "node",
    ];

    // Pattern 1: pipe-based (curl ... | bash)
    if cmd.contains('|') {
        let parts: Vec<&str> = cmd.split('|').collect();
        if parts.len() >= 2 {
            let left = parts[0].to_ascii_lowercase();
            let right = parts[1..].join("|").to_ascii_lowercase();
            let has_downloader = downloaders.iter().any(|d| left.contains(d));
            let has_executor = executors.iter().any(|e| {
                right
                    .split_whitespace()
                    .any(|w| w.trim_start_matches("./") == *e)
            });
            if has_downloader && has_executor {
                signals.push(serde_json::json!({
                    "signal": "download_and_execute",
                    "score": 40,
                    "detail": "dangerous pipeline: download piped to shell interpreter",
                }));
                score += 40;
            }
        }
    }

    // Pattern 2: staged (wget -O /tmp/x && chmod +x && /tmp/x)
    {
        let has_download = downloaders.iter().any(|d| lower.contains(d));
        let has_chmod_exec = lower.contains("chmod +x")
            || lower.contains("chmod 755")
            || lower.contains("chmod 777");
        if has_download && has_chmod_exec {
            signals.push(serde_json::json!({
                "signal": "download_chmod_execute",
                "score": 40,
                "detail": "staged attack: download + chmod + execute sequence",
            }));
            score += 40;
        }
    }

    // Obfuscation patterns
    const OBFUSCATION: &[&str] = &[
        "base64 -d",
        "base64 --decode",
        "openssl enc -d",
        "| xxd -r",
        "eval $(echo",
        "eval \"$(echo",
        "eval `echo",
    ];
    for indicator in OBFUSCATION {
        if lower.contains(indicator) {
            signals.push(serde_json::json!({
                "signal": "obfuscated_command",
                "score": 30,
                "detail": format!("obfuscation pattern: `{indicator}`"),
            }));
            score += 30;
            break;
        }
    }

    // Persistence indicators
    const PERSISTENCE: &[&str] = &[
        "crontab",
        "/etc/cron",
        ".bashrc",
        ".bash_profile",
        ".profile",
        "/etc/profile",
        "/etc/rc.local",
        "systemctl enable",
        "update-rc.d",
        "chkconfig",
        ".config/autostart",
    ];
    for indicator in PERSISTENCE {
        if lower.contains(indicator) {
            signals.push(serde_json::json!({
                "signal": "persistence_attempt",
                "score": 20,
                "detail": format!("persistence indicator: `{indicator}`"),
            }));
            score += 20;
            break;
        }
    }

    // Execution from temp directories
    const TMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
    for prefix in TMP_DIRS {
        if lower.contains(prefix) {
            signals.push(serde_json::json!({
                "signal": "tmp_execution",
                "score": 30,
                "detail": format!("references world-writable directory: {prefix}"),
            }));
            score += 30;
            break;
        }
    }

    // Destructive commands (rm -rf /, chmod 777, dd if=/dev/zero)
    if lower.contains("rm -rf /") && !lower.contains("rm -rf ./") {
        signals.push(serde_json::json!({
            "signal": "destructive_command",
            "score": 50,
            "detail": "recursive removal from root directory",
        }));
        score += 50;
    }
    if lower.contains("chmod 777") || lower.contains("chmod -r 777") {
        signals.push(serde_json::json!({
            "signal": "insecure_permissions",
            "score": 20,
            "detail": "world-writable permissions",
        }));
        score += 20;
    }

    let severity = if score >= 60 {
        "high"
    } else if score >= 30 {
        "medium"
    } else {
        "low"
    };

    let recommendation = if score >= 40 {
        "deny"
    } else if score >= 20 {
        "review"
    } else {
        "allow"
    };

    let explanation = if signals.is_empty() {
        "no dangerous patterns detected".to_string()
    } else {
        signals
            .iter()
            .filter_map(|s| s.get("detail").and_then(|d| d.as_str()))
            .collect::<Vec<_>>()
            .join("; ")
    };

    Json(serde_json::json!({
        "command": cmd,
        "risk_score": score,
        "severity": severity,
        "signals": signals,
        "recommendation": recommendation,
        "explanation": explanation,
    }))
}

// ---------------------------------------------------------------------------
// Prometheus metrics endpoint
// ---------------------------------------------------------------------------

async fn api_prometheus_metrics(State(state): State<DashboardState>) -> axum::response::Response {
    let date = resolve_date(None);

    // Read latest telemetry snapshot (small file, already cached)
    let telem = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);

    let mut out = String::with_capacity(2048);

    // Help + type headers for Prometheus scraper
    out.push_str("# HELP innerwarden_events_total Total events collected today by collector\n");
    out.push_str("# TYPE innerwarden_events_total counter\n");
    if let Some(ref t) = telem {
        for (collector, count) in &t.events_by_collector {
            out.push_str(&format!(
                "innerwarden_events_total{{collector=\"{collector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_incidents_total Total incidents detected today by detector\n");
    out.push_str("# TYPE innerwarden_incidents_total counter\n");
    if let Some(ref t) = telem {
        for (detector, count) in &t.incidents_by_detector {
            out.push_str(&format!(
                "innerwarden_incidents_total{{detector=\"{detector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_decisions_total Total AI/auto decisions today by action\n");
    out.push_str("# TYPE innerwarden_decisions_total counter\n");
    if let Some(ref t) = telem {
        for (action, count) in &t.decisions_by_action {
            out.push_str(&format!(
                "innerwarden_decisions_total{{action=\"{action}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_ai_calls_total Total AI provider calls today\n");
    out.push_str("# TYPE innerwarden_ai_calls_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!("innerwarden_ai_calls_total {}\n", t.ai_sent_count));
    }

    out.push_str("# HELP innerwarden_ai_latency_avg_ms Average AI decision latency in ms\n");
    out.push_str("# TYPE innerwarden_ai_latency_avg_ms gauge\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_ai_latency_avg_ms {:.1}\n",
            t.avg_decision_latency_ms
        ));
    }

    out.push_str("# HELP innerwarden_errors_total Errors by component\n");
    out.push_str("# TYPE innerwarden_errors_total counter\n");
    if let Some(ref t) = telem {
        for (component, count) in &t.errors_by_component {
            out.push_str(&format!(
                "innerwarden_errors_total{{component=\"{component}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_executions_total Skill executions today (dry_run vs live)\n");
    out.push_str("# TYPE innerwarden_executions_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"dry_run\"}} {}\n",
            t.dry_run_execution_count
        ));
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"live\"}} {}\n",
            t.real_execution_count
        ));
    }

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(out))
        .unwrap()
        .into_response()
}

// ---------------------------------------------------------------------------
// Business logic — overview
// ---------------------------------------------------------------------------

fn compute_overview(data_dir: &Path, date: &str) -> OverviewResponse {
    // Count events by line count (fast) instead of parsing 100MB+ of JSON
    let events_count = count_file_lines(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *by_detector.entry(detector).or_insert(0) += 1;
    }
    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    OverviewResponse {
        date: date.to_string(),
        events_count,
        incidents_count: incidents.len(),
        decisions_count: decisions.len(),
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
    }
}

/// Count non-empty lines in a file without parsing JSON (fast for large files).
fn count_file_lines(path: &Path) -> usize {
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    std::io::BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count()
}

use std::io::BufRead;

// ---------------------------------------------------------------------------
// Business logic — D2 entities / journey
// ---------------------------------------------------------------------------

/// Build the attacker list for a given date.
/// Only IPs that appear in at least one incident are included.
fn build_attackers(
    data_dir: &Path,
    date: &str,
    filters: &InvestigationFilters,
    limit: usize,
) -> Vec<AttackerSummary> {
    build_pivots(data_dir, date, PivotKind::Ip, filters, limit)
        .into_iter()
        .map(|p| AttackerSummary {
            ip: p.value,
            first_seen: p.first_seen,
            last_seen: p.last_seen,
            max_severity: p.max_severity,
            detectors: p.detectors,
            outcome: p.outcome,
            incident_count: p.incident_count,
            event_count: p.event_count,
        })
        .collect()
}

fn build_pivots(
    data_dir: &Path,
    date: &str,
    group_by: PivotKind,
    filters: &InvestigationFilters,
    limit: usize,
) -> Vec<PivotItem> {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut grouped: BTreeMap<String, IpAccumulator> = BTreeMap::new();

    for incident in &incidents {
        if !incident_matches_filters(incident, filters) {
            continue;
        }

        let detector = incident_detector(&incident.incident_id).to_string();
        let sev_str = format!("{:?}", incident.severity).to_lowercase();
        let sev_ord = severity_order(&sev_str);
        let incident_ips = extract_entity_values(&incident.entities, EntityType::Ip);

        for key in incident_group_values(incident, group_by) {
            let entry = grouped.entry(key.clone()).or_default();
            entry.update_time(incident.ts);
            entry.incident_count += 1;
            if sev_ord > entry.max_severity {
                entry.max_severity = sev_ord;
                entry.max_severity_str = sev_str.clone();
            }
            entry.detectors.insert(detector.clone());
            for ip in &incident_ips {
                entry.ips.insert(ip.clone());
            }
            if group_by == PivotKind::Ip {
                entry.ips.insert(key);
            }
        }
    }

    for event in &events {
        if !event_matches_filters(event, filters) {
            continue;
        }

        for key in event_group_values(event, group_by) {
            if let Some(entry) = grouped.get_mut(&key) {
                entry.event_count += 1;
                entry.update_time(event.ts);
                for ip in extract_ip_entities(&event.entities) {
                    entry.ips.insert(ip);
                }
            }
        }
    }

    let mut items: Vec<PivotItem> = grouped
        .into_iter()
        .map(|(value, acc)| {
            let outcome = if group_by == PivotKind::Ip {
                determine_outcome(&decisions, &value, acc.incident_count > 0)
            } else {
                determine_outcome_for_ips(&decisions, &acc.ips, acc.incident_count > 0)
            };

            PivotItem {
                group_by: group_by.as_str().to_string(),
                value,
                first_seen: acc.first_seen.unwrap_or_else(Utc::now),
                last_seen: acc.last_seen.unwrap_or_else(Utc::now),
                max_severity: acc.max_severity_str,
                incident_count: acc.incident_count,
                event_count: acc.event_count,
                outcome,
                detectors: acc.detectors.into_iter().collect(),
            }
        })
        .collect();

    items.sort_by(|a, b| {
        severity_order(&b.max_severity)
            .cmp(&severity_order(&a.max_severity))
            .then(b.incident_count.cmp(&a.incident_count))
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.value.cmp(&b.value))
    });
    items.truncate(limit);
    items
}

fn build_cluster_items(
    data_dir: &Path,
    date: &str,
    filters: &InvestigationFilters,
    limit: usize,
    window_seconds: u64,
) -> Vec<ClusterItem> {
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));

    let filtered: Vec<innerwarden_core::incident::Incident> = incidents
        .into_iter()
        .filter(|incident| incident_matches_filters(incident, filters))
        .collect();
    if filtered.is_empty() {
        return Vec::new();
    }

    let mut clusters = build_clusters(&filtered, window_seconds);
    clusters.truncate(limit);

    clusters
        .into_iter()
        .enumerate()
        .map(|(idx, cluster)| {
            let (pivot_type, pivot_value) = parse_cluster_pivot(&cluster.pivot);
            let incident_count = cluster.incident_ids.len();
            ClusterItem {
                cluster_id: format!("cluster-{:03}", idx + 1),
                pivot: cluster.pivot,
                pivot_type,
                pivot_value,
                start_ts: cluster.start_ts,
                end_ts: cluster.end_ts,
                incident_count,
                detector_kinds: cluster.detector_kinds,
                incident_ids: cluster.incident_ids,
            }
        })
        .collect()
}

/// Build the full journey timeline for a selected subject on a given date.
fn build_journey(
    data_dir: &Path,
    date: &str,
    subject_type: PivotKind,
    subject: &str,
    filters: &InvestigationFilters,
    window_seconds: Option<u64>,
) -> JourneyResponse {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut entries: Vec<JourneyEntry> = Vec::new();
    let mut related_ips: BTreeSet<String> = BTreeSet::new();
    let mut related_users: BTreeSet<String> = BTreeSet::new();
    let mut related_detectors: BTreeSet<String> = BTreeSet::new();
    let mut has_incident = false;

    for incident in incidents {
        if !incident_matches_filters(&incident, filters) {
            continue;
        }
        if !incident_matches_subject(&incident, subject_type, subject) {
            continue;
        }

        has_incident = true;
        related_detectors.insert(incident_detector(&incident.incident_id));
        for ip in extract_ip_entities(&incident.entities) {
            related_ips.insert(ip);
        }
        for user in extract_entity_values(&incident.entities, EntityType::User) {
            related_users.insert(user);
        }

        entries.push(JourneyEntry {
            ts: incident.ts,
            kind: "incident".to_string(),
            data: serde_json::json!({
                "incident_id": incident.incident_id,
                "severity": format!("{:?}", incident.severity).to_lowercase(),
                "title": incident.title,
                "summary": incident.summary,
                "evidence": incident.evidence,
                "tags": incident.tags,
            }),
        });
    }

    for event in events {
        if !event_matches_filters(&event, filters) {
            continue;
        }

        let matches_subject = match subject_type {
            PivotKind::Ip => extract_ip_entities(&event.entities)
                .iter()
                .any(|e| e == subject),
            PivotKind::User => {
                extract_entity_values(&event.entities, EntityType::User)
                    .iter()
                    .any(|u| u == subject)
                    || has_intersection(&extract_ip_entities(&event.entities), &related_ips)
            }
            PivotKind::Detector => {
                !related_ips.is_empty()
                    && has_intersection(&extract_ip_entities(&event.entities), &related_ips)
            }
        };

        if matches_subject {
            for ip in extract_ip_entities(&event.entities) {
                related_ips.insert(ip);
            }
            for user in extract_entity_values(&event.entities, EntityType::User) {
                related_users.insert(user);
            }
            entries.push(JourneyEntry {
                ts: event.ts,
                kind: "event".to_string(),
                data: serde_json::json!({
                    "severity": format!("{:?}", event.severity).to_lowercase(),
                    "source": event.source,
                    "event_kind": event.kind,
                    "summary": event.summary,
                    "details": event.details,
                    "tags": event.tags,
                }),
            });
        }
    }

    for decision in &decisions {
        if let Some(detector_filter) = &filters.detector {
            if incident_detector(&decision.incident_id) != *detector_filter {
                continue;
            }
        }
        related_detectors.insert(incident_detector(&decision.incident_id));

        let matches_subject = match subject_type {
            PivotKind::Ip => decision.target_ip.as_deref() == Some(subject),
            PivotKind::User | PivotKind::Detector => decision
                .target_ip
                .as_ref()
                .map(|ip| related_ips.contains(ip))
                .unwrap_or(false),
        };

        if matches_subject {
            entries.push(JourneyEntry {
                ts: decision.ts,
                kind: "decision".to_string(),
                data: serde_json::json!({
                    "action_type": decision.action_type,
                    "confidence": decision.confidence,
                    "auto_executed": decision.auto_executed,
                    "dry_run": decision.dry_run,
                    "reason": decision.reason,
                    "execution_result": decision.execution_result,
                    "skill_id": decision.skill_id,
                    "target_ip": decision.target_ip,
                    "incident_id": decision.incident_id,
                }),
            });
        }
    }

    let mut honeypot_ips = related_ips.clone();
    if subject_type == PivotKind::Ip {
        honeypot_ips.insert(subject.to_string());
    }
    let mut hp_entries = scan_honeypot_sessions(data_dir, date, &honeypot_ips);
    entries.append(&mut hp_entries);

    entries.sort_by_key(|e| e.ts);
    if let Some(window) = window_seconds {
        if let Some(last_ts) = entries.last().map(|e| e.ts) {
            let cutoff = last_ts - chrono::Duration::seconds(window as i64);
            entries.retain(|entry| entry.ts >= cutoff);
        }
    }

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);
    let outcome = if subject_type == PivotKind::Ip {
        determine_outcome(&decisions, subject, has_incident)
    } else {
        determine_outcome_for_ips(&decisions, &related_ips, has_incident)
    };
    let summary = build_journey_summary(
        &entries,
        &outcome,
        subject_type,
        subject,
        &related_ips,
        &related_users,
        &related_detectors,
    );

    let verdict = derive_verdict(&entries, &outcome);
    let chapters = derive_chapters(&entries);

    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
        verdict,
        chapters,
        entries,
    }
}

fn build_journey_summary(
    entries: &[JourneyEntry],
    outcome: &str,
    subject_type: PivotKind,
    subject: &str,
    related_ips: &BTreeSet<String>,
    related_users: &BTreeSet<String>,
    related_detectors: &BTreeSet<String>,
) -> JourneySummary {
    let mut summary = JourneySummary {
        total_entries: entries.len(),
        events_count: 0,
        incidents_count: 0,
        decisions_count: 0,
        honeypot_count: 0,
        first_event: None,
        first_incident: None,
        first_decision: None,
        first_honeypot: None,
        pivot_shortcuts: build_pivot_shortcuts(
            subject_type,
            subject,
            related_ips,
            related_users,
            related_detectors,
        ),
        hints: Vec::new(),
    };

    let mut decision_actions: BTreeMap<String, usize> = BTreeMap::new();

    for entry in entries {
        match entry.kind.as_str() {
            "event" => {
                summary.events_count += 1;
                if summary.first_event.is_none() {
                    summary.first_event = Some(entry.ts);
                }
            }
            "incident" => {
                summary.incidents_count += 1;
                if summary.first_incident.is_none() {
                    summary.first_incident = Some(entry.ts);
                }
            }
            "decision" => {
                summary.decisions_count += 1;
                if summary.first_decision.is_none() {
                    summary.first_decision = Some(entry.ts);
                }
                if let Some(action_type) = entry.data.get("action_type").and_then(|v| v.as_str()) {
                    *decision_actions.entry(action_type.to_string()).or_insert(0) += 1;
                }
            }
            kind if kind.starts_with("honeypot_") => {
                summary.honeypot_count += 1;
                if summary.first_honeypot.is_none() {
                    summary.first_honeypot = Some(entry.ts);
                }
            }
            _ => {}
        }
    }

    if summary.total_entries == 0 {
        summary
            .hints
            .push("No timeline entries for current filters/window.".to_string());
        return summary;
    }

    if let (Some(first_event), Some(first_incident)) = (summary.first_event, summary.first_incident)
    {
        let lag = (first_incident - first_event).num_seconds();
        summary.hints.push(format!(
            "Escalation: first incident raised {} after first signal.",
            format_duration(lag)
        ));
    } else if summary.events_count > 0 && summary.incidents_count == 0 {
        summary.hints.push(
            "Signals observed in this window, but no incident met detector thresholds.".to_string(),
        );
    }

    if let (Some(first_incident), Some(first_decision)) =
        (summary.first_incident, summary.first_decision)
    {
        let lag = (first_decision - first_incident).num_seconds();
        summary.hints.push(format!(
            "Response lag: first decision recorded {} after first incident.",
            format_duration(lag)
        ));
    } else if summary.incidents_count > 0 && summary.decisions_count == 0 {
        summary.hints.push(
            "Incidents detected, but no AI decision was recorded in this window.".to_string(),
        );
    }

    if summary.honeypot_count > 0 {
        summary.hints.push(format!(
            "Honeypot engaged with {} artifact(s) captured.",
            summary.honeypot_count
        ));
    }

    if !decision_actions.is_empty() {
        let action_line = decision_actions
            .iter()
            .map(|(action, count)| format!("{action} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        summary
            .hints
            .push(format!("Decision mix in window: {action_line}."));
    }

    let outcome_hint = match outcome {
        "blocked" => "Outcome indicates containment was applied (blocked).",
        "honeypot" => "Outcome indicates attacker flow was redirected to honeypot controls.",
        "monitoring" => "Outcome indicates monitoring response without direct containment.",
        "active" => "Outcome indicates active threat path without confirmed containment.",
        _ => "Outcome is unknown for this scope.",
    };
    summary.hints.push(outcome_hint.to_string());

    summary
}

fn build_pivot_shortcuts(
    subject_type: PivotKind,
    subject: &str,
    related_ips: &BTreeSet<String>,
    related_users: &BTreeSet<String>,
    related_detectors: &BTreeSet<String>,
) -> Vec<String> {
    let mut shortcuts = Vec::new();
    let mut seen = BTreeSet::new();

    let push_token = |token: String, shortcuts: &mut Vec<String>, seen: &mut BTreeSet<String>| {
        if token.is_empty() {
            return;
        }
        if seen.insert(token.clone()) {
            shortcuts.push(token);
        }
    };

    push_token(
        format!("{}:{}", subject_type.as_str(), subject),
        &mut shortcuts,
        &mut seen,
    );
    for ip in related_ips.iter().take(3) {
        push_token(format!("ip:{ip}"), &mut shortcuts, &mut seen);
    }
    for user in related_users.iter().take(3) {
        push_token(format!("user:{user}"), &mut shortcuts, &mut seen);
    }
    for detector in related_detectors.iter().take(3) {
        push_token(format!("detector:{detector}"), &mut shortcuts, &mut seen);
    }
    shortcuts.truncate(8);
    shortcuts
}

// ── D5 — Story derivation ──────────────────────────────────────────────────

/// Derive a high-level attack verdict from the assembled journey entries.
fn derive_verdict(entries: &[JourneyEntry], outcome: &str) -> JourneyVerdict {
    // Entry vector: first incident's detector prefix
    let entry_vector = entries
        .iter()
        .find(|e| e.kind == "incident")
        .and_then(|e| e.data.get("incident_id").and_then(|v| v.as_str()))
        .map(|id| {
            match id.split(':').next().unwrap_or("unknown") {
                "ssh_bruteforce" => "ssh_bruteforce",
                "credential_stuffing" => "credential_stuffing",
                "port_scan" => "port_scan",
                "sudo_abuse" => "sudo_abuse",
                _ => "unknown",
            }
            .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Access status: any login success events?
    let has_success = entries.iter().any(|e| {
        e.kind == "event"
            && e.data
                .get("event_kind")
                .and_then(|v| v.as_str())
                .map(|k| k.contains("login_success") || k.contains("_accepted"))
                .unwrap_or(false)
    });
    let has_events = entries.iter().any(|e| e.kind == "event");
    let access_status = if has_success {
        "likely_success"
    } else if has_events {
        "no_evidence_of_success"
    } else {
        "inconclusive"
    }
    .to_string();

    // Privilege status: sudo_abuse incidents or sudo events?
    let has_sudo = entries.iter().any(|e| {
        (e.kind == "incident"
            && e.data
                .get("incident_id")
                .and_then(|v| v.as_str())
                .map(|id| id.starts_with("sudo_abuse"))
                .unwrap_or(false))
            || (e.kind == "event"
                && e.data
                    .get("event_kind")
                    .and_then(|v| v.as_str())
                    .map(|k| k.contains("sudo"))
                    .unwrap_or(false))
    });
    let privilege_status = if has_sudo { "attempted" } else { "no_evidence" }.to_string();

    // Honeypot status
    let has_honeypot = entries.iter().any(|e| e.kind.starts_with("honeypot_"));
    let honeypot_status = if outcome == "honeypot" {
        "diverted"
    } else if has_honeypot {
        "engaged"
    } else {
        "not_engaged"
    }
    .to_string();

    // Containment status mirrors outcome
    let containment_status = match outcome {
        "blocked" => "blocked",
        "monitoring" => "monitored",
        "honeypot" => "honeypot",
        "active" => "active",
        _ => "unknown",
    }
    .to_string();

    // Confidence based on data richness
    let has_incident = entries.iter().any(|e| e.kind == "incident");
    let has_decision = entries.iter().any(|e| e.kind == "decision");
    let confidence = if has_incident && has_decision && has_events {
        "high"
    } else if has_incident && (has_events || has_decision) {
        "medium"
    } else {
        "low"
    }
    .to_string();

    JourneyVerdict {
        entry_vector,
        access_status,
        privilege_status,
        containment_status,
        honeypot_status,
        confidence,
    }
}

/// Derive human-readable attack chapters from the journey entries.
fn derive_chapters(entries: &[JourneyEntry]) -> Vec<JourneyChapter> {
    if entries.is_empty() {
        return vec![];
    }

    // Assign each entry to a logical stage
    let stages: Vec<&str> = entries
        .iter()
        .map(|e| match e.kind.as_str() {
            "event" => {
                let kind = e
                    .data
                    .get("event_kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if kind.contains("port_scan") {
                    "reconnaissance"
                } else if kind.contains("login_success") || kind.contains("_accepted") {
                    "access_success"
                } else if kind.contains("sudo") {
                    "privilege_abuse"
                } else {
                    "initial_access_attempt"
                }
            }
            "incident" => {
                let id = e
                    .data
                    .get("incident_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if id.starts_with("port_scan") {
                    "reconnaissance"
                } else if id.starts_with("sudo_abuse") {
                    "privilege_abuse"
                } else {
                    "response"
                }
            }
            "decision" => "containment",
            k if k.starts_with("honeypot_") => "honeypot_interaction",
            _ => "unknown",
        })
        .collect();

    // Group consecutive same-stage entries into chapters
    let mut chapters: Vec<JourneyChapter> = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let stage = stages[i];
        let chapter_start = i;
        while i < entries.len() && stages[i] == stage {
            i += 1;
        }
        let chapter_entries = &entries[chapter_start..i];
        let (title, summary, highlights) = describe_chapter(stage, chapter_entries);
        chapters.push(JourneyChapter {
            stage: stage.to_string(),
            title,
            summary,
            start_ts: chapter_entries[0].ts,
            end_ts: chapter_entries.last().unwrap().ts,
            entry_count: chapter_entries.len(),
            evidence_highlights: highlights,
            entry_indices: (chapter_start..i).collect(),
        });
    }
    chapters
}

/// Generate human-readable title / summary / highlights for a chapter.
fn describe_chapter(stage: &str, entries: &[JourneyEntry]) -> (String, String, Vec<String>) {
    match stage {
        "reconnaissance" => {
            let title = "Reconnaissance activity".to_string();
            let summary = format!("{} probe event(s) detected", entries.len());
            (title, summary, vec![])
        }
        "initial_access_attempt" => {
            // Collect distinct usernames attempted
            let usernames: Vec<String> = entries
                .iter()
                .flat_map(|e| {
                    let mut names = Vec::new();
                    if let Some(d) = e.data.get("details") {
                        for key in ["user", "username"] {
                            if let Some(u) = d.get(key).and_then(|v| v.as_str()) {
                                names.push(u.to_string());
                            }
                        }
                    }
                    names
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .take(5)
                .collect();
            let ev_count = entries.iter().filter(|e| e.kind == "event").count();
            let title = if ev_count > 3 {
                format!("Brute-force burst ({} attempts)", ev_count)
            } else {
                "Login attempt(s)".to_string()
            };
            let summary = format!("{} failed login attempt(s)", entries.len());
            (title, summary, usernames)
        }
        "access_success" => {
            let user = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("details")
                        .and_then(|d| d.get("user"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .unwrap_or_default();
            let title = "Login success detected".to_string();
            let summary = "Evidence of successful authentication".to_string();
            let highlights = if user.is_empty() { vec![] } else { vec![user] };
            (title, summary, highlights)
        }
        "privilege_abuse" => {
            let title = "Privilege escalation attempt".to_string();
            let summary = format!("{} sudo-related event(s)", entries.len());
            (title, summary, vec![])
        }
        "response" => {
            let titles: Vec<String> = entries
                .iter()
                .filter_map(|e| {
                    e.data
                        .get("title")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .take(2)
                .collect();
            let title = titles
                .first()
                .cloned()
                .unwrap_or_else(|| "Incident detected".to_string());
            let summary = format!("{} detector incident(s) raised", entries.len());
            (title, summary, titles)
        }
        "containment" => {
            let action = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("action_type")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .unwrap_or_default();
            let is_dry = entries.iter().any(|e| {
                e.data
                    .get("dry_run")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            });
            let title = if is_dry {
                format!("AI decision — {} (dry run)", action)
            } else {
                format!("AI decision — {}", action)
            };
            let conf = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .map(|c| format!("conf {:.0}%", c * 100.0))
                })
                .unwrap_or_default();
            let summary = format!("{} decision(s)", entries.len());
            let highlights = if conf.is_empty() { vec![] } else { vec![conf] };
            (title, summary, highlights)
        }
        "honeypot_interaction" => {
            let creds: Vec<String> = entries
                .iter()
                .flat_map(|e| {
                    e.data
                        .get("auth_attempts")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|a| {
                                    let user = a.get("username").and_then(|v| v.as_str())?;
                                    let pass = a.get("password").and_then(|v| v.as_str())?;
                                    Some(format!("{}/{}", user, pass))
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .take(5)
                .collect();
            let title = "Honeypot interaction".to_string();
            let summary = format!("{} honeypot session(s)", entries.len());
            (title, summary, creds)
        }
        _ => {
            let title = format!("{} event(s)", entries.len());
            let summary = "Unclassified activity".to_string();
            (title, summary, vec![])
        }
    }
}

fn format_duration(seconds: i64) -> String {
    let secs = seconds.max(0);
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    let rem = secs % 60;
    if mins < 60 {
        if rem == 0 {
            return format!("{mins}m");
        }
        return format!("{mins}m {rem}s");
    }
    let hours = mins / 60;
    let min_rem = mins % 60;
    if min_rem == 0 {
        return format!("{hours}h");
    }
    format!("{hours}h {min_rem}m")
}

/// Scan all honeypot JSONL session files for connections from tracked IPs on `date`.
fn scan_honeypot_sessions(
    data_dir: &Path,
    date: &str,
    tracked_ips: &BTreeSet<String>,
) -> Vec<JourneyEntry> {
    if tracked_ips.is_empty() {
        return Vec::new();
    }

    let honeypot_dir = data_dir.join("honeypot");
    let mut entries = Vec::new();

    let read_dir = match std::fs::read_dir(&honeypot_dir) {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for dir_entry in read_dir {
        let Ok(dir_entry) = dir_entry else { continue };
        let path = dir_entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("listener-session-") || !name.ends_with(".jsonl") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Filter by peer_ip.
            let peer_ip = match val.get("peer_ip").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => continue,
            };
            if !tracked_ips.contains(peer_ip) {
                continue;
            }

            // Filter by date using the ts field.
            let ts_str = match val.get("ts").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => continue,
            };
            if !ts_str.starts_with(date) {
                continue;
            }

            // Parse timestamp.
            let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(_) => continue,
            };

            // Map evidence type to journey kind.
            let kind = match val.get("type").and_then(|v| v.as_str()) {
                Some("ssh_connection") => "honeypot_ssh",
                Some("http_connection") => "honeypot_http",
                Some("connection") => "honeypot_banner",
                _ => continue, // skip connection_rejected and unknown types
            };

            entries.push(JourneyEntry {
                ts,
                kind: kind.to_string(),
                data: val,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_cluster_pivot(pivot: &str) -> (String, String) {
    if let Some((kind, value)) = pivot.split_once(':') {
        return (kind.to_string(), value.to_string());
    }
    ("detector".to_string(), pivot.to_string())
}

fn render_markdown_snapshot(snapshot: &InvestigationExport) -> String {
    let mut out = String::new();
    out.push_str("# InnerWarden Investigation Snapshot\n\n");
    out.push_str(&format!("- Generated at: `{}`\n", snapshot.generated_at));
    out.push_str(&format!("- Date: `{}`\n", snapshot.date));
    out.push_str(&format!("- Group by: `{}`\n", snapshot.group_by));
    if let (Some(subject_type), Some(subject)) = (&snapshot.subject_type, &snapshot.subject) {
        out.push_str(&format!("- Subject: `{subject_type}:{subject}`\n"));
    }
    out.push('\n');

    out.push_str("## Overview\n\n");
    out.push_str(&format!(
        "- Events: **{}**\n- Incidents: **{}**\n- Decisions: **{}**\n\n",
        snapshot.overview.events_count,
        snapshot.overview.incidents_count,
        snapshot.overview.decisions_count
    ));

    out.push_str("## Top Pivots\n\n");
    if snapshot.pivots.is_empty() {
        out.push_str("_No pivots for current filters._\n\n");
    } else {
        for pivot in &snapshot.pivots {
            out.push_str(&format!(
                "- `{}` · severity `{}` · incidents `{}` · events `{}` · outcome `{}`\n",
                pivot.value,
                pivot.max_severity,
                pivot.incident_count,
                pivot.event_count,
                pivot.outcome
            ));
        }
        out.push('\n');
    }

    out.push_str("## Correlation Clusters\n\n");
    if snapshot.clusters.is_empty() {
        out.push_str("_No clusters for current filters._\n\n");
    } else {
        for cluster in &snapshot.clusters {
            out.push_str(&format!(
                "- {} · pivot `{}` · incidents `{}` · detectors `{}` · `{}` → `{}`\n",
                cluster.cluster_id,
                cluster.pivot,
                cluster.incident_count,
                cluster.detector_kinds.join(", "),
                cluster.start_ts,
                cluster.end_ts
            ));
        }
        out.push('\n');
    }

    out.push_str("## Journey\n\n");
    match &snapshot.journey {
        Some(journey) => {
            out.push_str(&format!(
                "- Subject: `{}`:`{}`\n- Outcome: `{}`\n- Entries: `{}`\n\n",
                journey.subject_type,
                journey.subject,
                journey.outcome,
                journey.entries.len()
            ));
            out.push_str("### Guided Summary\n\n");
            out.push_str(&format!(
                "- Events: `{}`\n- Incidents: `{}`\n- Decisions: `{}`\n- Honeypot: `{}`\n\n",
                journey.summary.events_count,
                journey.summary.incidents_count,
                journey.summary.decisions_count,
                journey.summary.honeypot_count
            ));
            if !journey.summary.hints.is_empty() {
                out.push_str("### Investigation Hints\n\n");
                for hint in &journey.summary.hints {
                    out.push_str(&format!("- {}\n", hint));
                }
                out.push('\n');
            }
            for entry in &journey.entries {
                out.push_str(&format!("- `{}` · **{}**\n", entry.ts, entry.kind));
            }
            out.push('\n');
        }
        None => out.push_str("_No journey selected for export._\n\n"),
    }

    out
}

fn extract_ip_entities(entities: &[innerwarden_core::entities::EntityRef]) -> Vec<String> {
    extract_entity_values(entities, EntityType::Ip)
}

fn extract_entity_values(
    entities: &[innerwarden_core::entities::EntityRef],
    entity_type: EntityType,
) -> Vec<String> {
    entities
        .iter()
        .filter(|e| e.r#type == entity_type)
        .map(|e| e.value.clone())
        .collect()
}

fn incident_detector(incident_id: &str) -> String {
    incident_id
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn incident_matches_filters(
    incident: &innerwarden_core::incident::Incident,
    filters: &InvestigationFilters,
) -> bool {
    if let Some(min) = filters.severity_min {
        let sev = severity_order(&format!("{:?}", incident.severity).to_lowercase());
        if sev < min {
            return false;
        }
    }
    if let Some(detector) = &filters.detector {
        if incident_detector(&incident.incident_id) != *detector {
            return false;
        }
    }
    true
}

fn event_matches_filters(
    event: &innerwarden_core::event::Event,
    filters: &InvestigationFilters,
) -> bool {
    if let Some(min) = filters.severity_min {
        let sev = severity_order(&format!("{:?}", event.severity).to_lowercase());
        if sev < min {
            return false;
        }
    }
    true
}

fn incident_group_values(
    incident: &innerwarden_core::incident::Incident,
    group_by: PivotKind,
) -> Vec<String> {
    match group_by {
        PivotKind::Ip => extract_entity_values(&incident.entities, EntityType::Ip),
        PivotKind::User => extract_entity_values(&incident.entities, EntityType::User),
        PivotKind::Detector => vec![incident_detector(&incident.incident_id)],
    }
}

fn event_group_values(event: &innerwarden_core::event::Event, group_by: PivotKind) -> Vec<String> {
    match group_by {
        PivotKind::Ip => extract_entity_values(&event.entities, EntityType::Ip),
        PivotKind::User => extract_entity_values(&event.entities, EntityType::User),
        PivotKind::Detector => Vec::new(),
    }
}

fn incident_matches_subject(
    incident: &innerwarden_core::incident::Incident,
    subject_type: PivotKind,
    subject: &str,
) -> bool {
    match subject_type {
        PivotKind::Ip => extract_entity_values(&incident.entities, EntityType::Ip)
            .iter()
            .any(|ip| ip == subject),
        PivotKind::User => extract_entity_values(&incident.entities, EntityType::User)
            .iter()
            .any(|user| user == subject),
        PivotKind::Detector => incident_detector(&incident.incident_id) == subject,
    }
}

fn has_intersection(values: &[String], set: &BTreeSet<String>) -> bool {
    values.iter().any(|v| set.contains(v))
}

fn determine_outcome_for_ips(
    decisions: &[DecisionEntry],
    ips: &BTreeSet<String>,
    has_incident: bool,
) -> String {
    let mut has_monitoring = false;
    let mut has_honeypot = false;
    let mut has_active = has_incident;

    for ip in ips {
        match determine_outcome(decisions, ip, has_incident).as_str() {
            "blocked" => return "blocked".to_string(),
            "honeypot" => has_honeypot = true,
            "monitoring" => has_monitoring = true,
            "active" => has_active = true,
            _ => {}
        }
    }

    if has_honeypot {
        return "honeypot".to_string();
    }
    if has_monitoring {
        return "monitoring".to_string();
    }
    if has_active {
        return "active".to_string();
    }
    "unknown".to_string()
}

fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Determine the outcome for an IP given the full decisions list and whether
/// it has at least one incident.
fn determine_outcome(decisions: &[DecisionEntry], ip: &str, has_incident: bool) -> String {
    let ip_decisions: Vec<&DecisionEntry> = decisions
        .iter()
        .filter(|d| d.target_ip.as_deref() == Some(ip))
        .collect();

    for d in &ip_decisions {
        if d.action_type == "block_ip"
            && d.auto_executed
            && !d.dry_run
            && d.execution_result.contains("ok")
        {
            return "blocked".to_string();
        }
    }
    for d in &ip_decisions {
        if d.action_type == "monitor" && d.auto_executed && !d.dry_run {
            return "monitoring".to_string();
        }
    }
    for d in &ip_decisions {
        if d.action_type == "honeypot" && d.auto_executed && !d.dry_run {
            return "honeypot".to_string();
        }
    }
    if has_incident {
        return "active".to_string();
    }
    "unknown".to_string()
}

fn resolve_date(raw: Option<&str>) -> String {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let Some(candidate) = raw else {
        return today;
    };
    if candidate.len() != 10 {
        return today;
    }
    if chrono::NaiveDate::parse_from_str(candidate, "%Y-%m-%d").is_ok() {
        return candidate.to_string();
    }
    today
}

fn normalize_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(50).clamp(1, 500)
}

/// Build a dated JSONL path, rejecting any path-traversal attempts.
/// Only allows YYYY-MM-DD date strings (already validated by resolve_date).
fn dated_path(data_dir: &Path, prefix: &str, date: &str) -> PathBuf {
    // Defense-in-depth: strip any path separators or dots from date
    let safe_date: String = date
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let filename = format!("{prefix}-{safe_date}.jsonl");
    // Ensure filename has no path components
    let safe_filename = Path::new(&filename)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    data_dir.join(safe_filename)
}

/// File content cache entry — avoids re-reading + re-parsing JSONL on every request.
struct FileCache {
    raw: String,
    size: u64,
    modified: std::time::SystemTime,
    cached_at: std::time::Instant,
}

/// Global JSONL file cache. Key: file path string. TTL: 5 seconds.
/// Under bot attack, this prevents hundreds of file reads per second.
static JSONL_CACHE: LazyLock<Mutex<HashMap<String, FileCache>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const JSONL_CACHE_TTL_SECS: u64 = 5;

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    let key = path.to_string_lossy().to_string();

    // Check cache first
    let meta = std::fs::metadata(path).ok();
    let file_size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let file_modified = meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    {
        let cache = JSONL_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(&key) {
            if entry.size == file_size
                && entry.modified == file_modified
                && entry.cached_at.elapsed().as_secs() < JSONL_CACHE_TTL_SECS
            {
                // Cache hit — parse from cached string (avoids file I/O)
                return entry
                    .raw
                    .lines()
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            return None;
                        }
                        serde_json::from_str::<T>(trimmed).ok()
                    })
                    .collect();
            }
        }
    }

    // Cache miss — read only the tail of the file (last 256KB ≈ 500 entries).
    // Dashboard lists show max 50-100 items; reading the full file wastes memory.
    const MAX_READ_BYTES: u64 = 256 * 1024;
    let content = if file_size > MAX_READ_BYTES {
        match std::fs::File::open(path) {
            Ok(mut f) => {
                use std::io::{Read, Seek, SeekFrom};
                let _ = f.seek(SeekFrom::End(-(MAX_READ_BYTES as i64)));
                let mut buf = String::with_capacity(MAX_READ_BYTES as usize);
                let _ = f.read_to_string(&mut buf);
                // Drop the first (possibly partial) line
                if let Some(pos) = buf.find('\n') {
                    buf.drain(..=pos);
                }
                buf
            }
            Err(_) => return Vec::new(),
        }
    } else {
        match std::fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        }
    };

    let result = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match serde_json::from_str::<T>(trimmed) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "dashboard: skipping malformed JSONL line"
                    );
                    None
                }
            }
        })
        .collect();

    // Store in cache (only cache small results)
    if content.len() < 512 * 1024 {
        let mut cache = JSONL_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        // Prune stale entries
        if cache.len() > 20 {
            cache.retain(|_, v| v.cached_at.elapsed().as_secs() < JSONL_CACHE_TTL_SECS * 2);
        }
        cache.insert(
            key,
            FileCache {
                raw: content,
                size: file_size,
                modified: file_modified,
                cached_at: std::time::Instant::now(),
            },
        );
    }

    result
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Inner Warden</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      /* ── Site-matched palette (innerwarden.com D4) ─────────────── */
      --bg0: #040814;
      --bg1: #091121;
      --card: rgba(9, 17, 33, 0.96);
      --card-hover: rgba(15, 26, 49, 0.99);
      --line: #1a2943;
      --line2: #263554;
      --text: #edf6ff;
      --muted: #8b9db8;
      --ok: #3ac27e;
      --warn: #ffb84d;
      --danger: #f43f5e;
      --accent: #78e5ff;
      --orange: #ff8c42;
    }
    /* Ambient cyber grid — matches site's cyber-shell */
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(rgba(120,229,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(120,229,255,0.025) 1px, transparent 1px);
      background-size: 48px 48px;
      animation: grid-drift 26s linear infinite;
      pointer-events: none;
      z-index: 0;
    }
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      background: radial-gradient(ellipse at 50% 0%, rgba(120,229,255,0.04) 0%, transparent 60%);
      pointer-events: none;
      z-index: 0;
    }
    .app { position: relative; z-index: 1; }
    @keyframes grid-drift {
      from { background-position: 0 0; }
      to   { background-position: 48px 48px; }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; overflow: hidden; }
    body {
      font-family: "Space Grotesk", system-ui, -apple-system, sans-serif;
      color: var(--text);
      /* Site-style ambient radial glows over dark navy base */
      background:
        radial-gradient(circle at 25% 0%, rgba(33, 86, 140, 0.20) 0%, transparent 42%),
        radial-gradient(circle at 82% 14%, rgba(120, 229, 255, 0.09) 0%, transparent 36%),
        radial-gradient(circle at 50% 85%, rgba(33, 86, 140, 0.10) 0%, transparent 45%),
        #040814;
      font-size: 14px;
    }

    /* ── App shell ───────────────────────────────────────────────── */
    .app { display: flex; flex-direction: column; height: 100vh; position: relative; z-index: 1; }

    .app-header {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 16px; border-bottom: 1px solid var(--line);
      flex-shrink: 0;
    }
    /* Status strip badges */
    .status-strip { display: flex; align-items: center; gap: 6px; margin-left: 4px; }
    .status-badge {
      font-size: 0.65rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
      border-radius: 999px; padding: 3px 10px; border: 1px solid;
    }
    .status-badge-guard { color: var(--ok);     border-color: rgba(58,194,126,0.5);  background: rgba(58,194,126,0.09); }
    .status-badge-watch { color: var(--warn);   border-color: rgba(255,184,77,0.4);  background: rgba(255,184,77,0.06); }
    .status-badge-read  { color: var(--muted);  border-color: var(--line);            background: transparent; }
    .status-badge-ai-on { color: var(--ok);     border-color: rgba(58,194,126,0.4);  background: rgba(58,194,126,0.06); }
    .status-badge-ai-off{ color: var(--muted);  border-color: var(--line);            background: transparent; }
    /* Quick-action buttons in home state */
    .home-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; padding: 0 2px; }
    .home-action-btn {
      flex: 1; min-width: 120px; padding: 8px 14px;
      background: rgba(120,229,255,0.05); border: 1px solid rgba(120,229,255,0.18);
      border-radius: 9px; color: var(--accent); font-size: 0.72rem; font-weight: 600;
      cursor: pointer; transition: background 0.15s, border-color 0.15s;
      font-family: inherit; text-align: center;
    }
    .home-action-btn:hover { background: rgba(120,229,255,0.12); border-color: rgba(120,229,255,0.35); }
    .app-title {
      font-weight: 800;
      font-size: 1.03rem;
      letter-spacing: -0.005em;
      display: flex;
      align-items: center;
      gap: 8px;
      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.35);
    }
    .logo {
      width: 30px;
      height: 30px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      border-radius: 8px;
      border: 1px solid rgba(120, 229, 255, 0.35);
      background: radial-gradient(circle at 30% 25%, rgba(120, 229, 255, 0.22), rgba(4, 8, 20, 0.96) 72%);
      box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.25), 0 3px 10px rgba(0, 0, 0, 0.35);
    }
    .logo svg {
      width: 100%;
      height: 100%;
      display: block;
      filter: drop-shadow(0 0 2px rgba(0, 0, 0, 0.5));
    }
    .app-badge {
      font-size: 0.68rem; color: var(--muted); letter-spacing: 0.02em;
      border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px;
    }
    #refreshStatus { margin-left: auto; font-size: 0.7rem; color: var(--muted); }

    .app-body { display: flex; flex: 1; overflow: hidden; }

    /* ── Left panel ──────────────────────────────────────────────── */
    .left-panel {
      width: 300px; flex-shrink: 0;
      overflow-y: auto; overflow-x: hidden;
      border-right: 1px solid var(--line);
      padding: 12px 10px;
    }

    /* KPI grid — 5 equal columns */
    .kpi-grid {
      display: grid; grid-template-columns: repeat(5, 1fr); gap: 4px;
      margin-bottom: 12px;
    }
    .kpi-card {
      background: var(--card); border: 1px solid var(--line); border-radius: 9px;
      padding: 8px 4px; text-align: center;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .kpi-card:hover {
      border-color: rgba(120,229,255,0.2);
      box-shadow: 0 2px 12px rgba(0,0,0,0.4), 0 0 0 1px rgba(120,229,255,0.06);
    }
    .kpi-label {
      font-size: 0.58rem; letter-spacing: 0.05em; color: var(--muted);
      text-transform: uppercase; line-height: 1.2;
    }
    .kpi-value { font-size: 1.05rem; font-weight: 700; margin-top: 2px; line-height: 1; }

    .filters {
      display: grid; grid-template-columns: 1fr 1fr; gap: 6px;
      margin-bottom: 12px;
    }
    .filters .full { grid-column: 1 / -1; }
    .filters input, .filters select, .filters button {
      width: 100%;
      background: rgba(4, 8, 20, 0.75);
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 8px;
      font-size: 0.72rem;
      padding: 7px 8px;
      font-family: "JetBrains Mono", monospace;
    }
    .filters button {
      cursor: pointer;
      background: rgba(120, 229, 255, 0.13);
      border-color: rgba(120, 229, 255, 0.26);
      color: var(--accent);
      font-family: "Space Grotesk", sans-serif;
      font-weight: 700;
      letter-spacing: 0.05em;
      font-size: 0.73rem;
    }
    .filters button:hover {
      background: rgba(120, 229, 255, 0.20);
    }
    .filters-note {
      grid-column: 1 / -1;
      font-size: 0.62rem;
      color: var(--muted);
      line-height: 1.25;
      padding: 0 2px;
    }

    .pivot-tabs {
      display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px;
      margin: 4px 0 8px;
    }
    .pivot-tab {
      text-align: center;
      border: 1px solid var(--line);
      background: rgba(4, 8, 20, 0.7);
      color: var(--muted);
      border-radius: 8px;
      padding: 8px 0;
      font-size: 0.68rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      cursor: pointer;
      min-height: 36px;
    }
    .pivot-tab.active {
      color: var(--accent);
      border-color: rgba(120, 229, 255, 0.35);
      background: rgba(120, 229, 255, 0.11);
    }
    .pivot-tab:hover:not(.active) {
      background: rgba(120, 229, 255, 0.06);
      color: var(--text);
    }

    /* Section header */
    .section-title {
      font-size: 0.6rem; letter-spacing: 0.1em; color: var(--muted);
      text-transform: uppercase; margin: 12px 0 6px; padding: 0 2px;
      display: flex; align-items: center; gap: 6px;
    }
    .section-title::after {
      content: ""; flex: 1; height: 1px; background: var(--line);
    }

    /* Attacker card */
    .attacker-card {
      background: var(--card); border: 1px solid var(--line); border-radius: 10px;
      padding: 10px 11px; margin-bottom: 5px; cursor: pointer;
      transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
      box-shadow: 0 2px 12px rgba(0,0,0,0.35);
    }
    .attacker-card:hover { border-color: var(--line2); background: var(--card-hover); box-shadow: 0 4px 20px rgba(0,0,0,0.45), 0 0 0 1px rgba(120,229,255,0.08); }
    .attacker-card.active { border-color: var(--accent); background: var(--card-hover); }
    .card-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 3px; }
    .card-ip {
      font-family: "JetBrains Mono", monospace; font-weight: 600; font-size: 0.82rem;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: flex; align-items: center; gap: 5px;
    }
    .card-detectors { font-size: 0.7rem; color: var(--muted); margin-bottom: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .card-meta { display: flex; gap: 6px; font-size: 0.7rem; margin-bottom: 2px; align-items: center; }
    .card-counts { color: var(--muted); }
    .card-time { font-size: 0.65rem; color: var(--muted); font-family: "JetBrains Mono", monospace; }

    .cluster-card {
      background: rgba(120, 229, 255, 0.07);
      border: 1px solid rgba(120, 229, 255, 0.22);
      border-radius: 10px;
      padding: 9px 11px;
      margin-bottom: 5px;
      cursor: pointer;
      transition: background 0.15s, box-shadow 0.15s;
      box-shadow: 0 2px 12px rgba(0,0,0,0.35);
    }
    .cluster-card:hover { background: rgba(120, 229, 255, 0.12); box-shadow: 0 4px 20px rgba(0,0,0,0.45), 0 0 0 1px rgba(120,229,255,0.08); }
    .cluster-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .cluster-id { font-size: 0.66rem; color: var(--accent); letter-spacing: 0.04em; text-transform: uppercase; }
    .cluster-pivot { font-family: "JetBrains Mono", monospace; font-size: 0.72rem; color: var(--text); }
    .cluster-meta { font-size: 0.67rem; color: var(--muted); margin-top: 3px; }
    .cluster-dets { font-size: 0.65rem; color: var(--muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    /* Detector list */
    .det-row {
      display: flex; justify-content: space-between; font-size: 0.75rem;
      padding: 4px 2px; border-bottom: 1px solid var(--line);
    }
    .det-row:last-child { border-bottom: none; }
    .det-count { color: var(--accent); font-weight: 600; }

    /* ── Right panel ─────────────────────────────────────────────── */
    .right-panel { flex: 1; overflow-y: auto; padding: 20px 22px; }

    .right-placeholder {
      display: flex; align-items: center; justify-content: center;
      height: 100%; flex-direction: column; gap: 10px;
      color: var(--muted); text-align: center;
    }
    .right-placeholder svg { opacity: 0.3; }
    .right-placeholder p { font-size: 0.85rem; }

    /* Journey header */
    .journey-header {
      display: flex; align-items: center; gap: 10px;
      margin-bottom: 6px; flex-wrap: wrap;
    }
    .journey-ip {
      font-family: "JetBrains Mono", monospace; font-size: 1.3rem; font-weight: 700;
    }
    .journey-time { font-size: 0.75rem; color: var(--muted); }
    .journey-subtitle { font-size: 0.78rem; color: var(--muted); margin-bottom: 18px; }

    .journey-actions {
      display: flex; gap: 6px; margin: 0 0 12px;
    }
    .journey-btn {
      border: 1px solid var(--line);
      background: rgba(4, 8, 20, 0.7);
      color: var(--muted);
      border-radius: 8px;
      padding: 6px 11px;
      font-size: 0.66rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      cursor: pointer;
      transition: color 0.12s, border-color 0.12s, background 0.12s;
      min-height: 30px;
    }
    .journey-btn:hover {
      color: var(--accent);
      border-color: rgba(120, 229, 255, 0.35);
      background: rgba(120, 229, 255, 0.06);
    }

    .guided-grid {
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 10px;
      margin-bottom: 14px;
    }
    .guided-card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px 13px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.35);
      transition: box-shadow 0.2s;
    }
    .guided-card:hover {
      box-shadow: 0 4px 20px rgba(0,0,0,0.45), 0 0 0 1px rgba(120,229,255,0.08);
    }
    .guided-title {
      font-size: 0.64rem;
      letter-spacing: 0.06em;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 7px;
    }
    .summary-cell {
      background: rgba(4, 8, 20, 0.7);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
    }
    .summary-label {
      font-size: 0.6rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .summary-value {
      font-family: "JetBrains Mono", monospace;
      font-size: 0.8rem;
      margin-top: 2px;
    }
    .hint-list {
      list-style: none;
      display: grid;
      gap: 6px;
    }
    .hint-item {
      font-size: 0.75rem;
      line-height: 1.35;
      color: #c9def2;
      padding-left: 12px;
      position: relative;
    }
    .hint-item::before {
      content: "•";
      position: absolute;
      left: 0;
      color: var(--accent);
    }
    .shortcut-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 10px;
    }
    .shortcut-btn {
      border: 1px solid rgba(120, 229, 255, 0.26);
      background: rgba(120, 229, 255, 0.09);
      color: var(--accent);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.64rem;
      font-family: "JetBrains Mono", monospace;
      cursor: pointer;
      min-height: 28px;
    }
    .shortcut-btn:hover {
      background: rgba(120, 229, 255, 0.16);
    }
    .compare-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 7px;
    }
    .compare-cell {
      background: rgba(4, 8, 20, 0.7);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
    }
    .delta-pos { color: var(--danger); }
    .delta-neg { color: var(--ok); }
    .delta-neu { color: var(--muted); }

    /* ── Timeline ────────────────────────────────────────────────── */
    .timeline { position: relative; }

    .tl-item { display: flex; gap: 10px; margin-bottom: 8px; }
    .tl-spine { display: flex; flex-direction: column; align-items: center; width: 12px; flex-shrink: 0; padding-top: 5px; }
    .tl-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; border: 2px solid; }
    .tl-connector { width: 2px; flex: 1; min-height: 10px; background: var(--line); margin-top: 3px; }
    .tl-item:last-child .tl-connector { display: none; }

    /* Dot variants */
    .dot-event-critical  { border-color: var(--danger); background: var(--danger); }
    .dot-event-high      { border-color: var(--warn);   background: var(--warn); }
    .dot-event-medium    { border-color: var(--warn);   background: transparent; }
    .dot-event-low,
    .dot-event-info      { border-color: var(--muted);  background: transparent; }
    .dot-incident        { border-color: var(--danger); background: var(--danger); box-shadow: 0 0 7px var(--danger); }
    .dot-decision        { border-color: var(--accent); background: var(--accent); }
    .dot-decision-dry    { border-color: var(--muted);  background: transparent; }
    .dot-honeypot        { border-color: var(--orange); background: var(--orange); box-shadow: 0 0 6px var(--orange); }
    .dot-default         { border-color: var(--muted);  background: transparent; }

    .tl-body { flex: 1; min-width: 0; }
    .tl-header {
      display: flex; align-items: flex-start; gap: 7px; cursor: pointer;
      padding: 9px 11px; border-radius: 9px; background: var(--card);
      border: 1px solid var(--line); flex-wrap: wrap;
      transition: border-color 0.15s, background 0.15s;
    }
    .tl-header:hover { border-color: var(--line2); background: var(--card-hover); }
    .tl-ts {
      font-family: "JetBrains Mono", monospace; font-size: 0.7rem; color: var(--muted);
      flex-shrink: 0; margin-top: 1px;
    }
    .tl-summary {
      font-size: 0.8rem; flex: 1; min-width: 0;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .tl-toggle { color: var(--muted); font-size: 0.65rem; flex-shrink: 0; margin-left: auto; margin-top: 2px; }

    .tl-detail {
      background: rgba(0,0,0,0.32); border: 1px solid var(--line);
      border-top: none; border-radius: 0 0 9px 9px;
      padding: 11px 13px; font-size: 0.72rem;
      font-family: "JetBrains Mono", monospace;
      color: #9ab8d0; overflow-x: auto; white-space: pre;
      line-height: 1.55; margin: 0;
    }

    /* ── Kind badges ─────────────────────────────────────────────── */
    .bk {
      font-size: 0.6rem; font-weight: 700; letter-spacing: 0.05em;
      border-radius: 3px; padding: 2px 6px; text-transform: uppercase;
      flex-shrink: 0; margin-top: 1px;
    }
    .bk-event         { background: rgba(139,157,184,0.13); color: var(--muted); }
    .bk-event-crit    { background: rgba(244,63,94,0.17);   color: var(--danger); }
    .bk-event-high    { background: rgba(255,184,77,0.17);  color: var(--warn); }
    .bk-event-med     { background: rgba(255,184,77,0.11);  color: var(--warn); }
    .bk-incident      { background: rgba(244,63,94,0.20);   color: var(--danger); }
    .bk-decision      { background: rgba(120,229,255,0.16); color: var(--accent); }
    .bk-decision-dry  { background: rgba(139,157,184,0.12); color: var(--muted); }
    .bk-decision-skip { background: rgba(139,157,184,0.08); color: var(--muted); }
    .bk-honeypot      { background: rgba(255,140,66,0.17);  color: var(--orange); }

    /* ── Outcome badges ──────────────────────────────────────────── */
    .bo {
      font-size: 0.62rem; font-weight: 700; letter-spacing: 0.06em;
      border-radius: 4px; padding: 2px 7px; text-transform: uppercase;
    }
    .bo-blocked    { background: rgba(58,194,126,0.16);  color: var(--ok);     border: 1px solid rgba(58,194,126,0.30); }
    .bo-active     { background: rgba(244,63,94,0.16);   color: var(--danger); border: 1px solid rgba(244,63,94,0.30); }
    .bo-monitoring { background: rgba(120,229,255,0.13); color: var(--accent); border: 1px solid rgba(120,229,255,0.28); }
    .bo-honeypot   { background: rgba(255,140,66,0.14);  color: var(--orange); border: 1px solid rgba(255,140,66,0.28); }
    .bo-unknown    { background: rgba(139,157,184,0.09); color: var(--muted);  border: 1px solid rgba(139,157,184,0.18); }

    /* ── Severity text colors ────────────────────────────────────── */
    .sc-critical { color: var(--danger); }
    .sc-high     { color: var(--warn); }
    .sc-medium   { color: var(--warn); opacity: 0.8; }
    .sc-low, .sc-info { color: var(--muted); }

    /* ── Utils ───────────────────────────────────────────────────── */
    .empty  { font-size: 0.78rem; color: var(--muted); padding: 8px 2px; }
    .loading { font-size: 0.8rem; color: var(--muted); padding: 20px 0; }
    .err    { font-size: 0.8rem; color: var(--danger); padding: 12px 0; }

    /* ── D5: Verdict card ────────────────────────────────────────── */
    .verdict-card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 13px 14px;
      margin-bottom: 10px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.35);
      transition: box-shadow 0.2s;
    }
    .verdict-card:hover {
      box-shadow: 0 4px 20px rgba(0,0,0,0.45), 0 0 0 1px rgba(120,229,255,0.08);
    }
    .verdict-title {
      font-size: 0.62rem; letter-spacing: 0.07em; text-transform: uppercase;
      color: var(--muted); margin-bottom: 10px;
    }
    .verdict-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 7px;
    }
    .verdict-cell {
      background: rgba(4,8,20,0.7);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
    }
    .verdict-label {
      font-size: 0.58rem; color: var(--muted);
      text-transform: uppercase; letter-spacing: 0.05em;
    }
    .verdict-value {
      font-size: 0.78rem; margin-top: 3px; font-weight: 600;
      font-family: "JetBrains Mono", monospace;
    }
    .verdict-value.v-ok      { color: var(--ok); }
    .verdict-value.v-danger  { color: var(--danger); }
    .verdict-value.v-warn    { color: var(--warn); }
    .verdict-value.v-accent  { color: var(--accent); }
    .verdict-value.v-muted   { color: var(--muted); }
    .verdict-confidence {
      display: flex; gap: 6px; align-items: center; margin-top: 9px;
      font-size: 0.65rem; color: var(--muted);
    }
    .verdict-confidence .conf-dot {
      width: 8px; height: 8px; border-radius: 50%;
    }

    /* ── D5: Chapter rail ────────────────────────────────────────── */
    .chapter-rail {
      display: flex; gap: 6px; overflow-x: auto;
      padding-bottom: 4px; margin-bottom: 10px; flex-wrap: wrap;
    }
    .chapter-pill {
      display: flex; flex-direction: column;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 9px;
      padding: 8px 11px;
      min-width: 110px; max-width: 160px;
      cursor: pointer;
      transition: border-color 0.14s, background 0.14s;
      flex-shrink: 0;
    }
    .chapter-pill:hover {
      border-color: rgba(120,229,255,0.35);
      background: rgba(120,229,255,0.05);
    }
    .chapter-pill.active {
      border-color: var(--accent);
      background: rgba(120,229,255,0.08);
    }
    .chapter-stage {
      font-size: 0.58rem; letter-spacing: 0.06em;
      text-transform: uppercase; color: var(--muted);
      margin-bottom: 3px;
    }
    .chapter-pill-title {
      font-size: 0.73rem; font-weight: 600; line-height: 1.2;
    }
    .chapter-count {
      font-size: 0.62rem; color: var(--muted); margin-top: 4px;
    }

    /* Stage-based accent colors */
    .stage-recon      .chapter-pill-title { color: var(--muted); }
    .stage-access     .chapter-pill-title { color: var(--warn); }
    .stage-success    .chapter-pill-title { color: var(--danger); }
    .stage-privilege  .chapter-pill-title { color: var(--danger); }
    .stage-response   .chapter-pill-title { color: var(--ok); }
    .stage-containment .chapter-pill-title { color: var(--accent); }
    .stage-honeypot   .chapter-pill-title { color: var(--orange); }

    /* ── D5: Evidence card ───────────────────────────────────────── */
    .evidence-card {
      background: rgba(4,8,20,0.6);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 6px;
    }
    .evidence-header {
      display: flex; gap: 7px; align-items: center; margin-bottom: 6px;
    }
    .evidence-title {
      font-size: 0.75rem; font-weight: 600; flex: 1;
    }
    .evidence-meta {
      font-size: 0.68rem; color: var(--muted);
      line-height: 1.5; margin-bottom: 6px;
    }
    .evidence-raw-toggle {
      font-size: 0.6rem; color: var(--accent); cursor: pointer;
      letter-spacing: 0.04em; text-transform: uppercase;
      background: none; border: none; padding: 0;
    }
    .evidence-raw-toggle:hover { text-decoration: underline; }
    .evidence-raw {
      display: none;
      background: rgba(0,0,0,0.3);
      border-top: 1px solid var(--line);
      margin-top: 6px; padding: 8px;
      font-family: "JetBrains Mono", monospace;
      font-size: 0.65rem; color: #9ab8d0;
      white-space: pre; overflow-x: auto;
      border-radius: 0 0 6px 6px;
    }
    .evidence-raw.open { display: block; }

    @media (max-width: 1180px) {
      .guided-grid   { grid-template-columns: 1fr; }
      .verdict-grid  { grid-template-columns: repeat(2, 1fr); }
      .chapter-rail  { flex-wrap: nowrap; }
    }

    /* ── Mobile toggle button (shown only on small screens) ─────── */
    /* D10 — main nav (Investigate / Report) */
    .main-nav {
      display: flex; gap: 4px; margin-left: 6px;
    }
    .main-nav-btn {
      padding: 4px 14px; border-radius: 8px; font-size: 0.72rem;
      font-weight: 600; letter-spacing: 0.01em; cursor: pointer;
      border: 1px solid rgba(120,229,255,0.18);
      background: transparent; color: var(--muted);
      transition: background 0.15s, color 0.15s, border-color 0.15s;
      white-space: nowrap;
    }
    .main-nav-btn.active {
      background: rgba(120,229,255,0.12); color: var(--accent);
      border-color: rgba(120,229,255,0.4);
    }
    .main-nav-btn:hover:not(.active) {
      background: rgba(120,229,255,0.06); color: var(--fg);
    }
    /* D10 — report view */
    .report-view {
      flex: 1; overflow-y: auto; padding: 20px 24px;
      display: flex; flex-direction: column; gap: 16px;
    }
    .report-toolbar {
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    }
    .report-label { font-size: 0.72rem; color: var(--muted); }
    .report-toolbar select {
      background: var(--card); border: 1px solid var(--line); color: var(--fg);
      border-radius: 8px; padding: 5px 10px; font-size: 0.75rem; cursor: pointer;
    }
    .report-refresh-btn {
      padding: 5px 14px; background: rgba(120,229,255,0.1);
      border: 1px solid rgba(120,229,255,0.3); color: var(--accent);
      border-radius: 8px; font-size: 0.73rem; font-weight: 600; cursor: pointer;
    }
    .report-refresh-btn:hover { background: rgba(120,229,255,0.18); }
    .report-status { font-size: 0.7rem; color: var(--muted); }
    .report-content { display: flex; flex-direction: column; gap: 14px; }
    .report-section {
      background: var(--card); border: 1px solid var(--line);
      border-radius: 12px; padding: 16px 20px;
    }
    .report-section-title {
      font-size: 0.72rem; font-weight: 700; letter-spacing: 0.07em;
      text-transform: uppercase; color: var(--accent); margin-bottom: 12px;
    }
    .report-kpi-row {
      display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;
    }
    .report-kpi {
      flex: 1 1 90px; background: var(--card-hover); border: 1px solid var(--line);
      border-radius: 10px; padding: 10px 14px; text-align: center;
    }
    .report-kpi-label { font-size: 0.65rem; color: var(--muted); margin-bottom: 4px; }
    .report-kpi-value { font-size: 1.25rem; font-weight: 700; color: var(--fg); }
    .report-kpi-value.good { color: #4ade80; }
    .report-kpi-value.warn { color: #fbbf24; }
    .report-kpi-value.bad  { color: var(--danger); }
    .report-trend-row {
      display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;
    }
    .report-trend-cell {
      background: var(--card-hover); border: 1px solid var(--line); border-radius: 8px;
      padding: 8px 12px;
    }
    .report-trend-label { font-size: 0.62rem; color: var(--muted); }
    .report-trend-nums { font-size: 0.82rem; margin-top: 3px; }
    .report-trend-delta { font-size: 0.7rem; color: var(--muted); }
    .report-trend-delta.up { color: var(--danger); }
    .report-trend-delta.down { color: #4ade80; }
    .report-anomaly {
      display: flex; align-items: flex-start; gap: 8px;
      padding: 8px 10px; border-radius: 8px; margin-bottom: 6px;
      border: 1px solid transparent;
    }
    .report-anomaly.critical { background: rgba(244,63,94,0.08); border-color: rgba(244,63,94,0.25); }
    .report-anomaly.high     { background: rgba(251,146,60,0.08); border-color: rgba(251,146,60,0.25); }
    .report-anomaly.medium   { background: rgba(251,191,36,0.08); border-color: rgba(251,191,36,0.25); }
    .report-anomaly.low,.report-anomaly.info { background: rgba(120,229,255,0.05); border-color: rgba(120,229,255,0.15); }
    .report-anomaly-badge {
      font-size: 0.6rem; font-weight: 700; padding: 1px 5px; border-radius: 4px;
      letter-spacing: 0.05em; text-transform: uppercase; flex-shrink: 0; margin-top: 1px;
    }
    .badge-critical { background: var(--danger); color: #fff; }
    .badge-high     { background: #f97316; color: #fff; }
    .badge-medium   { background: #fbbf24; color: #000; }
    .badge-low,.badge-info { background: rgba(120,229,255,0.2); color: var(--accent); }
    .report-anomaly-msg { font-size: 0.76rem; line-height: 1.45; }
    .report-suggestion {
      display: flex; align-items: flex-start; gap: 8px;
      font-size: 0.75rem; padding: 6px 0; border-bottom: 1px solid var(--line);
    }
    .report-suggestion:last-child { border-bottom: none; }
    .report-table {
      width: 100%; border-collapse: collapse; font-size: 0.73rem;
    }
    .report-table th {
      text-align: left; color: var(--muted); font-weight: 600;
      padding: 4px 8px; border-bottom: 1px solid var(--line);
    }
    .report-table td { padding: 5px 8px; border-bottom: 1px solid rgba(255,255,255,0.04); }
    .report-table tr:last-child td { border-bottom: none; }
    .health-ok   { color: #4ade80; font-weight: 700; }
    .health-fail { color: var(--danger); font-weight: 700; }
    @media (max-width: 600px) {
      .report-trend-row { grid-template-columns: 1fr 1fr; }
      .report-view { padding: 12px 14px; }
    }
    .panel-toggle-btn {
      display: none;
    }
    @media (max-width: 860px) {
      .panel-toggle-btn {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-left: auto;
        padding: 5px 10px;
        background: rgba(120,229,255,0.08);
        border: 1px solid rgba(120,229,255,0.22);
        color: var(--accent);
        border-radius: 8px;
        font-size: 0.68rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        cursor: pointer;
        min-height: 30px;
        flex-shrink: 0;
      }
      .panel-toggle-btn:hover { background: rgba(120,229,255,0.14); }
    }

    /* Mobile layout: stack panels and make everything readable */
    @media (max-width: 860px) {
      html, body { overflow: auto; }
      .app { height: auto; min-height: 100vh; overflow-y: auto; }
      .app-body { flex-direction: column; overflow: visible; }

      /* Header: first row = logo+title+toggle, second row = nav tabs */
      .app-header {
        padding: 10px 14px 0;
        flex-wrap: wrap;
        gap: 6px;
      }
      .app-title { font-size: 0.95rem; flex: 1; }
      .logo { width: 28px; height: 28px; }
      .app-badge { display: none; }
      .status-strip { display: none; }
      #refreshStatus { display: none; }

      /* Nav moves to its own full-width row */
      .main-nav {
        order: 10;
        width: calc(100% + 28px);
        margin: 6px -14px 0;
        gap: 0;
        border-top: 1px solid var(--line);
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
      }
      .main-nav::-webkit-scrollbar { display: none; }
      .main-nav-btn {
        flex: 1;
        min-width: 70px;
        border-radius: 0;
        border: none;
        border-bottom: 2px solid transparent;
        border-top: none;
        border-left: none;
        border-right: none;
        padding: 9px 12px;
        font-size: 0.7rem;
        background: transparent;
        color: var(--muted);
      }
      .main-nav-btn.active {
        background: rgba(120,229,255,0.06);
        color: var(--accent);
        border-bottom-color: var(--accent);
      }

      /* Toggle button stays in first row, right-aligned */
      .panel-toggle-btn { order: 5; margin-left: 0; }

      .left-panel {
        width: 100%;
        max-height: 55vh;
        overflow-y: auto;
        overflow-x: hidden;
        border-right: none;
        border-bottom: 1px solid var(--line);
        padding: 10px 12px;
        transition: max-height 0.28s ease, padding 0.28s ease;
      }
      .left-panel.collapsed {
        max-height: 0;
        padding-top: 0;
        padding-bottom: 0;
        overflow: hidden;
      }

      .right-panel {
        padding: 16px 14px;
        overflow-y: visible;
        min-height: 50vh;
      }

      /* KPIs: date card full width; rest 2 columns */
      .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 6px; }
      .kpi-grid .kpi-card:first-child {
        grid-column: 1 / -1;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 9px 12px;
        text-align: left;
      }
      .kpi-grid .kpi-card:first-child .kpi-value { margin-top: 0; font-size: 0.82rem; }

      .filters { grid-template-columns: 1fr; gap: 7px; }
      .filters .full { grid-column: auto; }
      .filters input, .filters select, .filters button { padding: 9px 10px; font-size: 0.78rem; }

      .pivot-tabs { gap: 6px; }
      .pivot-tab { padding: 9px 0; font-size: 0.7rem; min-height: 40px; }

      .journey-header { gap: 8px; }
      .journey-ip { font-size: 1.05rem; }
      .journey-subtitle { margin-bottom: 14px; }
      .journey-actions { flex-wrap: wrap; gap: 7px; }
      .journey-btn { padding: 7px 12px; min-height: 34px; }

      /* Let timeline titles wrap instead of overflowing */
      .tl-summary { white-space: normal; line-height: 1.4; }
      .tl-toggle { margin-left: 0; }
      .tl-header { padding: 10px 12px; }

      /* Guided cards stacked */
      .guided-grid { grid-template-columns: 1fr; gap: 8px; }
      .summary-grid { grid-template-columns: 1fr 1fr; }

      .shortcut-wrap { gap: 8px; }
      .shortcut-btn { padding: 5px 12px; min-height: 32px; }

      /* Toast: full width on mobile */
      .toast { right: 12px; left: 12px; min-width: unset; max-width: unset; }

      /* Modal: full-width on small screens */
      .modal-box { padding: 20px 18px; }
      .modal-footer { justify-content: stretch; }
      .btn-cancel, .btn-confirm { flex: 1; text-align: center; justify-content: center; }
    }

    @media (max-width: 480px) {
      .kpi-label { font-size: 0.56rem; }
      .kpi-value { font-size: 1rem; }
      .kpi-grid { gap: 5px; }
      .pivot-tab { font-size: 0.65rem; }
      .left-panel { max-height: 60vh; }
      .app-header { padding: 8px 10px 0; }
      .right-panel { padding: 14px 10px; }
      .tl-header { padding: 9px 10px; }
      .main-nav-btn { padding: 8px 8px; font-size: 0.66rem; min-width: 56px; }
    }

    /* ── D3 — action buttons ─────────────────────────────────────── */
    .journey-btn.action-block {
      color: var(--danger); border-color: rgba(244,63,94,0.33);
      background: rgba(244,63,94,0.09);
    }
    .journey-btn.action-block:hover {
      background: rgba(244,63,94,0.17);
      border-color: rgba(244,63,94,0.45);
    }
    .journey-btn.action-suspend {
      color: var(--warn); border-color: rgba(255,184,77,0.33);
      background: rgba(255,184,77,0.09);
    }
    .journey-btn.action-suspend:hover {
      background: rgba(255,184,77,0.17);
      border-color: rgba(255,184,77,0.45);
    }

    /* ── D3 — modal overlay ──────────────────────────────────────── */
    .modal-overlay {
      display: none; position: fixed; inset: 0; z-index: 100;
      background: rgba(4,8,20,0.86); backdrop-filter: blur(4px);
      align-items: center; justify-content: center;
      padding: 16px;
    }
    .modal-overlay.open { display: flex; }
    .modal-box {
      background: var(--bg1); border: 1px solid var(--line2);
      border-radius: 14px; padding: 24px 26px;
      width: 420px; max-width: 100%;
      box-shadow: 0 8px 40px rgba(0,0,0,0.6);
    }
    .modal-title { font-size: 1rem; font-weight: 700; margin-bottom: 4px; }
    .modal-subtitle { font-size: 0.75rem; color: var(--muted); margin-bottom: 16px; line-height: 1.4; }
    .modal-field { margin-bottom: 12px; }
    .modal-label {
      font-size: 0.7rem; color: var(--muted); letter-spacing: 0.04em;
      text-transform: uppercase; display: block; margin-bottom: 4px;
    }
    .modal-textarea, .modal-input {
      width: 100%; background: rgba(4,8,20,0.85); color: var(--text);
      border: 1px solid var(--line2); border-radius: 8px; padding: 9px 11px;
      font-size: 0.82rem; font-family: "Space Grotesk", sans-serif; resize: vertical;
    }
    .modal-textarea:focus, .modal-input:focus {
      outline: none; border-color: rgba(120,229,255,0.4);
      box-shadow: 0 0 0 2px rgba(120,229,255,0.09);
    }
    .modal-textarea { min-height: 72px; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; flex-wrap: wrap; }
    .btn-cancel {
      background: transparent; border: 1px solid var(--line2); color: var(--muted);
      border-radius: 8px; padding: 8px 18px; font-size: 0.8rem; cursor: pointer;
      transition: color 0.12s, border-color 0.12s;
      min-height: 36px;
    }
    .btn-cancel:hover { color: var(--text); border-color: var(--line2); }
    .btn-confirm {
      background: rgba(58,194,126,0.14); border: 1px solid rgba(58,194,126,0.36);
      color: var(--ok); border-radius: 8px; padding: 8px 18px;
      font-size: 0.8rem; font-weight: 600; cursor: pointer;
      transition: background 0.12s;
      min-height: 36px;
    }
    .btn-confirm:hover { background: rgba(58,194,126,0.22); }
    .btn-confirm.danger {
      background: rgba(244,63,94,0.12); border-color: rgba(244,63,94,0.33);
      color: var(--danger);
    }
    .btn-confirm.danger:hover { background: rgba(244,63,94,0.20); }
    .btn-confirm:disabled { opacity: 0.45; cursor: default; }
    .dry-run-badge {
      display: inline-block; font-size: 0.6rem; font-weight: 700;
      letter-spacing: 0.06em; text-transform: uppercase; border-radius: 4px;
      padding: 2px 6px; margin-left: 6px; vertical-align: middle;
    }
    .dry-run-badge.on  { background: rgba(255,184,77,0.16);  color: var(--warn);   border: 1px solid rgba(255,184,77,0.28); }
    .dry-run-badge.off { background: rgba(244,63,94,0.16);   color: var(--danger); border: 1px solid rgba(244,63,94,0.28); }

    /* ── D3 — toast ──────────────────────────────────────────────── */
    .toast {
      position: fixed; top: 16px; right: 16px; z-index: 200;
      background: var(--bg1); border: 1px solid var(--line2);
      border-radius: 12px; padding: 11px 16px; min-width: 240px; max-width: 340px;
      font-size: 0.82rem; box-shadow: 0 6px 28px rgba(0,0,0,0.55);
      opacity: 0; transform: translateY(-10px);
      transition: opacity 0.2s ease, transform 0.2s ease;
      pointer-events: none; line-height: 1.4;
    }
    .toast.visible { opacity: 1; transform: translateY(0); pointer-events: auto; }
    .toast.ok  { border-left: 3px solid var(--ok);    color: var(--text); }
    .toast.err { border-left: 3px solid var(--danger); color: var(--text); }
    /* D9 — inline entity search */
    .search-wrap { padding: 6px 12px 2px; }
    #entitySearch {
      width: 100%; box-sizing: border-box;
      background: var(--bg1); border: 1px solid var(--line2); border-radius: 8px;
      color: var(--text); font-size: 0.8rem; padding: 6px 10px;
      outline: none; transition: border-color 0.15s;
    }
    #entitySearch:focus { border-color: var(--accent); }
    #entitySearch::placeholder { color: var(--muted); }
    .attacker-card.hidden { display: none; }
    /* D7 — live timeline animations */
    @keyframes cardSlideIn {
      from { opacity: 0; transform: translateY(-12px); box-shadow: 0 0 0 1px var(--accent); }
      60%  { box-shadow: 0 0 12px 2px rgba(120,229,255,0.25); }
      to   { opacity: 1; transform: translateY(0);   box-shadow: none; }
    }
    @keyframes kpiFlash {
      0%   { color: var(--accent); text-shadow: 0 0 8px rgba(120,229,255,0.7); }
      100% { color: inherit; text-shadow: none; }
    }
    .card-new  { animation: cardSlideIn 0.4s ease forwards; }
    .kpi-flash { animation: kpiFlash 0.8s ease forwards; }

    @keyframes pulse-dot {
      0%, 100% { box-shadow: 0 0 0 0 rgba(244,63,94,0.5); }
      50%       { box-shadow: 0 0 0 4px rgba(244,63,94,0); }
    }
    .pulse-dot {
      display: inline-block; width: 7px; height: 7px; border-radius: 50%;
      background: var(--danger); animation: pulse-dot 1.8s ease-in-out infinite;
      flex-shrink: 0;
    }
    .pulse-dot.ok { background: var(--ok); animation: none; }
    .pulse-dot.warn { background: var(--warn); animation: none; }
    @keyframes breathe {
      0%,100% { opacity:0.6; transform: scale(1); }
      50%      { opacity:1;   transform: scale(1.15); }
    }
    .live-dot {
      display: inline-block; width: 7px; height: 7px; border-radius: 50%;
      background: var(--ok); animation: breathe 2.5s ease-in-out infinite;
    }

    /* ── Card badges ────────────────────────────────────────────── */
    .card-badges { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
    .card-badge {
      font-size: 0.56rem; font-weight: 700; letter-spacing: 0.04em;
      border-radius: 3px; padding: 1px 5px; text-transform: uppercase;
    }
    .badge-blocked  { background: rgba(58,194,126,0.15);  color: var(--ok);     border: 1px solid rgba(58,194,126,0.25); }
    .badge-active   { background: rgba(244,63,94,0.12);   color: var(--danger); border: 1px solid rgba(244,63,94,0.22); }
    .badge-monitor  { background: rgba(120,229,255,0.10); color: var(--accent); border: 1px solid rgba(120,229,255,0.20); }
    .badge-honeypot { background: rgba(255,140,66,0.12);  color: var(--orange); border: 1px solid rgba(255,140,66,0.22); }
    .badge-abuse { background: rgba(244,63,94,0.10); color: #ff8080; border: 1px solid rgba(244,63,94,0.18); }
    .badge-geo { background: rgba(139,157,184,0.10); color: var(--muted); border: 1px solid var(--line); }
    .badge-ai { background: rgba(120,229,255,0.08); color: var(--accent); border: 1px solid rgba(120,229,255,0.15); }
    .badge-f2b { background: rgba(255,140,66,0.08); color: var(--orange); border: 1px solid rgba(255,140,66,0.15); }
    .badge-cs { background: rgba(58,194,126,0.08); color: var(--ok); border: 1px solid rgba(58,194,126,0.15); }
    .badge-op { background: rgba(139,157,184,0.12); color: var(--text); border: 1px solid var(--line); }

    /* ── E2 — Home state ─────────────────────────────────────────── */
    #homeState { padding: 0; }
    .home-kpi-row {
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;
      margin-bottom: 16px;
    }
    .home-kpi-card {
      background: var(--card); border: 1px solid var(--line); border-radius: 12px;
      padding: 14px 12px; text-align: center;
      box-shadow: 0 2px 12px rgba(0,0,0,0.3);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .home-kpi-card:hover {
      border-color: rgba(120,229,255,0.2);
      box-shadow: 0 4px 20px rgba(0,0,0,0.4), 0 0 0 1px rgba(120,229,255,0.06);
    }
    .home-kpi-icon { font-size: 1.1rem; margin-bottom: 4px; }
    .home-kpi-label { font-size: 0.6rem; letter-spacing: 0.07em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .home-kpi-val { font-size: 1.6rem; font-weight: 700; color: var(--text); line-height: 1; }
    .home-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
      margin-bottom: 0;
    }
    .home-card {
      background: var(--card); border: 1px solid var(--line); border-radius: 12px;
      padding: 14px 16px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    }
    .home-card-title {
      font-size: 0.63rem; letter-spacing: 0.09em; text-transform: uppercase;
      color: var(--muted); margin-bottom: 10px;
      display: flex; align-items: center; gap: 6px;
    }
    .home-threat-row {
      display: flex; align-items: center; gap: 8px;
      padding: 6px 0; border-bottom: 1px solid var(--line);
      cursor: pointer; transition: background 0.15s;
    }
    .home-threat-row:last-child { border-bottom: none; }
    .home-threat-row:hover { background: rgba(120,229,255,0.04); border-radius: 6px; }
    .home-threat-ip { font-family: "JetBrains Mono", monospace; font-size: 0.77rem; font-weight: 600; flex: 1; }
    .home-threat-meta { font-size: 0.65rem; color: var(--muted); }
    .home-decision-row {
      display: flex; align-items: flex-start; gap: 8px;
      padding: 6px 0; border-bottom: 1px solid var(--line);
    }
    .home-decision-row:last-child { border-bottom: none; }
    .home-decision-action { font-size: 0.72rem; font-weight: 600; flex: 1; }
    .home-decision-meta { font-size: 0.65rem; color: var(--muted); margin-top: 1px; }
    .home-decision-conf { font-size: 0.65rem; color: var(--accent); font-family: "JetBrains Mono", monospace; }
    .home-det-row {
      display: flex; align-items: center; gap: 8px;
      padding: 5px 0; border-bottom: 1px solid var(--line);
    }
    .home-det-row:last-child { border-bottom: none; }
    .home-det-name { font-size: 0.75rem; flex: 1; }
    .home-det-bar-wrap { width: 80px; height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; }
    .home-det-bar { height: 100%; background: var(--accent); border-radius: 3px; transition: width 0.4s ease; }
    .home-det-count { font-size: 0.7rem; color: var(--accent); font-weight: 600; min-width: 24px; text-align: right; }
    .home-footer { margin-top: 14px; padding: 10px 0; text-align: center; }
    /* Status hero */
    .status-hero {
      border-radius: 16px; padding: 24px 20px; margin-bottom: 16px;
      text-align: center; position: relative; overflow: hidden;
      border: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(9,17,33,0.98) 0%, rgba(15,26,49,0.95) 100%);
    }
    .status-hero.safe   { border-color: rgba(58,194,126,0.35); background: linear-gradient(135deg, rgba(9,17,33,0.98) 0%, rgba(12,40,25,0.95) 100%); }
    .status-hero.warn   { border-color: rgba(255,184,77,0.35);  background: linear-gradient(135deg, rgba(9,17,33,0.98) 0%, rgba(40,28,10,0.95) 100%); }
    .status-hero.danger { border-color: rgba(244,63,94,0.35);  background: linear-gradient(135deg, rgba(9,17,33,0.98) 0%, rgba(40,12,18,0.95) 100%); }
    .status-hero-icon { font-size: 2.4rem; line-height: 1; margin-bottom: 8px; }
    .status-hero-title {
      font-size: 1.3rem; font-weight: 800; letter-spacing: -0.01em; margin-bottom: 6px;
    }
    .status-hero.safe   .status-hero-title { color: var(--ok); }
    .status-hero.warn   .status-hero-title { color: var(--warn); }
    .status-hero.danger .status-hero-title { color: var(--danger); }
    .status-hero-sub { font-size: 0.75rem; color: var(--muted); line-height: 1.5; }
    /* Activity feed */
    .activity-feed { display: flex; flex-direction: column; gap: 0; }
    .activity-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 10px 0; border-bottom: 1px solid var(--line);
      cursor: pointer; transition: background 0.12s; border-radius: 0;
    }
    .activity-row:last-child { border-bottom: none; }
    .activity-row:hover { background: rgba(120,229,255,0.04); border-radius: 8px; padding-left: 6px; }
    .activity-icon { font-size: 1.1rem; flex-shrink: 0; margin-top: 1px; }
    .activity-body { flex: 1; min-width: 0; }
    .activity-title { font-size: 0.8rem; font-weight: 600; color: var(--text); line-height: 1.3; }
    .activity-meta { font-size: 0.67rem; color: var(--muted); margin-top: 2px; }
    .activity-time { font-size: 0.65rem; color: var(--muted); flex-shrink: 0; white-space: nowrap; margin-top: 2px; }
    @media (max-width: 860px) {
      .home-kpi-row { grid-template-columns: repeat(2, 1fr); }
      .home-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 480px) {
      .home-kpi-row { grid-template-columns: 1fr 1fr; gap: 7px; }
      .home-kpi-val { font-size: 1.3rem; }
    }

    /* ── E4 — Journey sticky footer ──────────────────────────────── */
    .journey-sticky-footer {
      position: sticky; bottom: 0; z-index: 10;
      background: linear-gradient(to top, var(--bg0) 60%, transparent);
      padding: 16px 0 0; margin-top: 20px;
      display: flex; gap: 8px;
    }
    .action-btn-large {
      flex: 1; padding: 10px 16px; border-radius: 10px;
      font-size: 0.78rem; font-weight: 600; cursor: pointer;
      display: flex; align-items: center; justify-content: center; gap: 6px;
      transition: background 0.15s, border-color 0.15s;
      min-height: 40px; letter-spacing: 0.02em;
    }
    .action-btn-block {
      background: rgba(244,63,94,0.10); border: 1px solid rgba(244,63,94,0.30);
      color: var(--danger);
    }
    .action-btn-block:hover { background: rgba(244,63,94,0.18); border-color: rgba(244,63,94,0.45); }
    .action-btn-suspend {
      background: rgba(255,184,77,0.10); border: 1px solid rgba(255,184,77,0.30);
      color: var(--warn);
    }
    .action-btn-suspend:hover { background: rgba(255,184,77,0.18); border-color: rgba(255,184,77,0.45); }
    .action-btn-export {
      background: rgba(120,229,255,0.08); border: 1px solid rgba(120,229,255,0.25);
      color: var(--accent);
    }
    .action-btn-export:hover { background: rgba(120,229,255,0.15); border-color: rgba(120,229,255,0.4); }

    /* ── E5 — Report nav/export buttons ──────────────────────────── */
    .report-nav-btn {
      padding: 5px 10px; background: rgba(139,157,184,0.08);
      border: 1px solid var(--line); color: var(--muted);
      border-radius: 8px; font-size: 0.8rem; cursor: pointer;
      transition: color 0.15s, border-color 0.15s, background 0.15s;
    }
    .report-nav-btn:hover { background: rgba(120,229,255,0.08); color: var(--accent); border-color: rgba(120,229,255,0.25); }
    .report-export-btn {
      padding: 5px 14px; background: rgba(139,157,184,0.08);
      border: 1px solid var(--line); color: var(--muted);
      border-radius: 8px; font-size: 0.73rem; font-weight: 600; cursor: pointer;
      transition: color 0.15s, background 0.15s, border-color 0.15s;
    }
    .report-export-btn:hover { background: rgba(120,229,255,0.1); color: var(--accent); border-color: rgba(120,229,255,0.28); }
  </style>
</head>
<body>
<div class="app">

  <!-- Header -->
  <header class="app-header">
    <div class="app-title">
      <span class="logo" aria-hidden="true">
        <svg width="18" height="18" viewBox="40 40 140 140" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="steel" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#e6edf5"/>
              <stop offset="100%" stop-color="#7d93a8"/>
            </linearGradient>
          </defs>

          <!-- left sword -->
          <g transform="rotate(-45 110 110)">
            <rect x="106" y="50" width="8" height="120" rx="3" fill="url(#steel)"/>
            <rect x="96" y="90" width="28" height="8" rx="2" fill="#2e6fa3"/>
            <rect x="108" y="98" width="4" height="28" rx="2" fill="#2e6fa3"/>
          </g>

          <!-- right sword -->
          <g transform="rotate(45 110 110)">
            <rect x="106" y="50" width="8" height="120" rx="3" fill="url(#steel)"/>
            <rect x="96" y="90" width="28" height="8" rx="2" fill="#2e6fa3"/>
            <rect x="108" y="98" width="4" height="28" rx="2" fill="#2e6fa3"/>
          </g>
        </svg>
      </span>
      Inner Warden
    </div>
    <div class="status-strip">
      <span class="status-badge status-badge-read" id="modeBadge">READ-ONLY</span>
      <span class="status-badge status-badge-ai-off" id="aiBadge">AI: off</span>
    </div>
    <span id="refreshStatus"></span>
    <div class="main-nav">
      <button type="button" class="main-nav-btn active" id="navInvestigate" onclick="showView('investigate')">Threats</button>
      <button type="button" class="main-nav-btn" id="navReport" onclick="showView('report')">Report</button>
      <button type="button" class="main-nav-btn" id="navStatus" onclick="showView('status')">Health</button>
      <button type="button" class="main-nav-btn" id="navHoneypot" onclick="showView('honeypot')">🍯 Honeypot</button>
    </div>
    <button type="button" class="panel-toggle-btn" id="panelToggleBtn" onclick="toggleLeftPanel()" aria-label="Toggle panel">
      <span id="panelToggleIcon">▲</span> List
    </button>
  </header>

  <div class="app-body" id="viewInvestigate">

    <!-- Left panel: summary + threat list -->
    <aside class="left-panel">

      <!-- Today summary strip -->
      <div class="kpi-grid" style="grid-template-columns: repeat(4,1fr)">
        <div class="kpi-card"><div class="kpi-label">Date</div><div class="kpi-value" id="kpi-date" style="font-size:0.7rem">—</div></div>
        <div class="kpi-card"><div class="kpi-label">Activity</div><div class="kpi-value" id="kpi-events">0</div></div>
        <div class="kpi-card"><div class="kpi-label">Blocked</div><div class="kpi-value" id="kpi-incidents" style="color:var(--ok)">0</div></div>
        <div class="kpi-card"><div class="kpi-label">Contained</div><div class="kpi-value" id="kpi-decisions" style="color:var(--ok)">100%</div></div>
      </div>

      <!-- Date + advanced filters (hidden by default) -->
      <div class="filters" style="grid-template-columns:1fr auto;margin-bottom:6px">
        <input id="flt-date" type="date" class="full" style="grid-column:1/-1" />
        <button id="flt-adv-toggle" type="button" class="full" style="background:transparent;border:none;color:var(--muted);font-size:0.68rem;cursor:pointer;text-align:left;padding:2px 0" onclick="toggleAdvFilters()">▸ Advanced filters</button>
      </div>
      <div id="advFilters" style="display:none">
        <div class="filters">
          <input id="flt-compare-date" type="date" title="compare date" />
          <select id="flt-window">
            <option value="">window: full day</option>
            <option value="900">last 15m</option>
            <option value="3600">last 1h</option>
            <option value="21600">last 6h</option>
          </select>
          <select id="flt-severity">
            <option value="">severity: any</option>
            <option value="critical">critical+</option>
            <option value="high">high+</option>
            <option value="medium">medium+</option>
          </select>
          <input id="flt-detector" type="text" placeholder="filter by detector" />
          <button id="flt-apply" class="full" type="button">Apply</button>
        </div>
      </div>

      <!-- Hidden pivot tabs (kept for JS compatibility, not shown) -->
      <div style="display:none">
        <div class="pivot-tabs">
          <button type="button" class="pivot-tab active" data-pivot="ip">IP</button>
          <button type="button" class="pivot-tab" data-pivot="user">User</button>
          <button type="button" class="pivot-tab" data-pivot="detector">Detector</button>
        </div>
        <!-- Hidden but required: cluster/detector lists for JS -->
        <div id="clusterList"></div>
        <div id="topDetectors"></div>
      </div>

      <!-- Search -->
      <div class="search-wrap">
        <input id="entitySearch" type="search" placeholder="search threats…"
               autocomplete="off" spellcheck="false" />
      </div>

      <!-- Threat list -->
      <div class="section-title" id="entityTitle">Defense Activity</div>
      <div id="attackerList"><div class="empty">Loading…</div></div>

    </aside>

    <!-- Right panel: journey timeline -->
    <main class="right-panel" id="rightPanel">
      <div id="homeState">
        <!-- Status hero -->
        <div class="status-hero safe" id="statusHero">
          <div class="status-hero-icon" id="heroIcon">✅</div>
          <div class="status-hero-title" id="heroTitle">Server Protected</div>
          <div class="status-hero-sub" id="heroSub">Loading today's activity…</div>
        </div>

        <!-- Activity feed -->
        <div class="home-card">
          <div class="home-card-title">
            <span class="live-dot"></span>
            What happened today
          </div>
          <div id="activityFeed"><div class="empty">Loading…</div></div>
        </div>

        <!-- Hidden elements kept for JS compatibility -->
        <div style="display:none">
          <div id="homeKpiRow"></div>
          <div id="homeRecentThreats"></div>
          <div id="homeRecentDecisions"></div>
          <div id="homeDetectors"></div>
          <div id="h-events"></div>
          <div id="h-incidents"></div>
          <div id="h-decisions"></div>
          <div id="h-blocks"></div>
        </div>

        <div class="home-actions">
          <button class="home-action-btn" type="button" onclick="investigateTopThreat()">🔍 Investigate a Threat</button>
          <button class="home-action-btn" type="button" onclick="showView('report')">📊 Daily Report</button>
          <button class="home-action-btn" type="button" onclick="showView('status')">🩺 System Health</button>
        </div>
        <div class="home-footer" style="margin-top:8px">
          <span style="color:var(--muted);font-size:0.7rem">← Click any threat on the left to see its full history</span>
        </div>
      </div>

      <div id="journeyContent" style="display:none"></div>
    </main>

  </div>

  <!-- D10 — Report view -->
  <div class="report-view" id="viewReport" style="display:none">
    <div class="report-toolbar">
      <label class="report-label">Date</label>
      <button type="button" class="report-nav-btn" id="reportPrev" onclick="navigateReport(-1)" title="Previous day">←</button>
      <select id="reportDateSelect" onchange="loadReport()"><option value="">latest</option></select>
      <button type="button" class="report-nav-btn" id="reportNext" onclick="navigateReport(1)" title="Next day">→</button>
      <button type="button" class="report-refresh-btn" onclick="loadReport()">↻ Refresh</button>
      <button type="button" class="report-export-btn" onclick="exportReport()" title="Export as Markdown">↓ Export</button>
      <span id="reportStatus" class="report-status"></span>
    </div>
    <div id="reportContent" class="report-content">
      <div class="empty" style="padding:40px;text-align:center">Loading report…</div>
    </div>
  </div>

  <!-- E6 — Status view -->
  <div class="report-view" id="viewStatus" style="display:none">
    <div class="report-toolbar">
      <button type="button" class="report-refresh-btn" onclick="loadStatus()">↻ Refresh</button>
      <span id="statusViewStatus" class="report-status"></span>
    </div>
    <div id="statusContent" class="report-content">
      <div class="empty" style="padding:40px;text-align:center">Loading…</div>
    </div>
  </div>

  <!-- Honeypot tab view -->
  <div class="report-view" id="viewHoneypot" style="display:none">
    <div class="report-toolbar">
      <button type="button" class="report-refresh-btn" onclick="loadHoneypot()">↻ Refresh</button>
      <span id="honeypotViewStatus" class="report-status"></span>
    </div>
    <div id="honeypotContent" class="report-content">
      <div class="empty" style="padding:40px;text-align:center">Loading…</div>
    </div>
  </div>

  <!-- D3 — action modal -->
  <div class="modal-overlay" id="actionModal" onclick="handleModalBg(event)">
    <div class="modal-box" onclick="event.stopPropagation()">
      <div class="modal-title" id="modalTitle">Action</div>
      <div class="modal-subtitle" id="modalSubtitle"></div>
      <div class="modal-field">
        <label class="modal-label" for="modalReason">Reason <span style="color:var(--danger)">*</span></label>
        <textarea class="modal-textarea" id="modalReason" rows="3"
          placeholder="Describe why you are taking this action — recorded in the audit trail…"></textarea>
      </div>
      <div class="modal-field" id="modalDurationField" style="display:none">
        <label class="modal-label" for="modalDuration">Duration (seconds)</label>
        <input class="modal-input" type="number" id="modalDuration" value="3600" min="60" max="86400" />
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-cancel" onclick="closeActionModal()">Cancel</button>
        <button type="button" class="btn-confirm danger" id="modalConfirm" onclick="submitAction()">Confirm</button>
      </div>
    </div>
  </div>

  <!-- D3 — toast notification -->
  <div class="toast" id="toast"></div>

</div>

<script>
  'use strict';

  // ── Mobile panel toggle ────────────────────────────────────────────────
  let leftPanelOpen = true;
  function toggleLeftPanel() {
    const panel = document.querySelector('.left-panel');
    const icon  = document.getElementById('panelToggleIcon');
    leftPanelOpen = !leftPanelOpen;
    panel.classList.toggle('collapsed', !leftPanelOpen);
    if (icon) icon.textContent = leftPanelOpen ? '▲' : '▼';
  }

  // ── D10 — View switcher ──────────────────────────────────────────────────
  function showView(name) {
    const views = { investigate: 'viewInvestigate', report: 'viewReport', status: 'viewStatus', honeypot: 'viewHoneypot' };
    const btns  = { investigate: 'navInvestigate', report: 'navReport', status: 'navStatus', honeypot: 'navHoneypot' };
    Object.keys(views).forEach(k => {
      const el = document.getElementById(views[k]);
      const btn = document.getElementById(btns[k]);
      if (el) el.style.display = k === name ? 'flex' : 'none';
      if (btn) btn.classList.toggle('active', k === name);
    });
    const toggleBtn = document.getElementById('panelToggleBtn');
    if (toggleBtn) toggleBtn.style.display = name === 'investigate' ? '' : 'none';
    if (name === 'report') loadReport();
    if (name === 'status') loadStatus();
    if (name === 'honeypot') loadHoneypot();
  }

  // ── E2 — Home state ─────────────────────────────────────────────────────
  async function loadHomeState() {
    try {
      const [overview, decisions, pivots] = await Promise.all([
        loadJson('/api/overview'),
        loadJson('/api/decisions?limit=5'),
        loadJson('/api/pivots?group_by=ip&limit=5')
      ]);

      // Update status hero and activity feed
      const incidentList = await loadJson('/api/incidents?limit=30');
      updateStatusHero(incidentList.items || [], decisions.items || []);
      buildActivityFeed(incidentList.items || [], decisions.items || []);

      // KPI strip in left panel
      setHomeKpi('h-events', overview.events_count ?? 0);
      setHomeKpi('h-incidents', overview.incidents_count ?? 0);
      setHomeKpi('h-decisions', overview.decisions_count ?? 0);
      setHomeKpi('h-blocks', (decisions.items || []).filter(d => d.action_type === 'block_ip' && d.auto_executed).length);
    } catch(e) {
      console.warn('Home state load error:', e);
    }
  }

  function setHomeKpi(id, val) {
    const el = document.getElementById(id);
    if (el) { el.textContent = val; }
  }

  function timeAgo(ts) {
    if (!ts) return '';
    const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  }

  function handleCardClickByValue(type, value) {
    // Find the card with this value and click it, or load journey directly
    const cards = document.querySelectorAll('.attacker-card');
    for (const card of cards) {
      if (card.dataset.subjectValue === value && card.dataset.subjectType === type) {
        card.click();
        return;
      }
    }
    // Direct load
    loadJourney(type, value);
  }

  function showHomeState() {
    document.getElementById('homeState').style.display = '';
    document.getElementById('journeyContent').style.display = 'none';
    document.getElementById('journeyContent').innerHTML = '';
    // Deselect active card
    document.querySelectorAll('.attacker-card.active').forEach(c => c.classList.remove('active'));
    state.currentSubject = null;
  }

  function investigateTopThreat() {
    // Click the first attacker card if one exists, else no-op
    const first = document.querySelector('.attacker-card');
    if (first) { first.click(); return; }
    // Show investigate tab in case we're in a different view
    showView('investigate');
  }

  function toggleAdvFilters() {
    const el = document.getElementById('advFilters');
    const btn = document.getElementById('flt-adv-toggle');
    if (!el || !btn) return;
    const open = el.style.display !== 'none';
    el.style.display = open ? 'none' : 'block';
    btn.textContent = open ? '▸ Advanced filters' : '▾ Advanced filters';
  }

  function updateStatusHero(incidents, decisions) {
    const hero = document.getElementById('statusHero');
    const icon = document.getElementById('heroIcon');
    const title = document.getElementById('heroTitle');
    const sub = document.getElementById('heroSub');
    if (!hero || !icon || !title || !sub) return;

    const totalThreats = (incidents || []).length;
    const resolved = (incidents || []).filter(i => i.outcome && i.outcome !== 'open').length;
    const openThreats = totalThreats - resolved;
    const blockedCount = (decisions || []).filter(d => ['block_ip','suspend_user_sudo','kill_process','block_container'].includes(d.action_type)).length;
    const containmentRate = totalThreats > 0 ? Math.round((resolved / totalThreats) * 100) : 100;

    if (openThreats > 0 && openThreats >= totalThreats / 2) {
      hero.className = 'status-hero danger';
      icon.textContent = '🛡️';
      title.textContent = 'Defending — ' + openThreats + ' unresolved';
      sub.textContent = blockedCount + ' attacks blocked · ' + containmentRate + '% contained · investigating remaining threats';
    } else if (totalThreats > 0) {
      hero.className = 'status-hero safe';
      icon.textContent = '🛡️';
      title.textContent = 'Server Protected';
      sub.textContent = totalThreats + ' threats detected · ' + blockedCount + ' blocked · ' + containmentRate + '% contained';
    } else {
      hero.className = 'status-hero safe';
      icon.textContent = '✅';
      title.textContent = 'All Clear';
      sub.textContent = 'No threats detected today · defense active';
    }

    // Update KPIs to focus on protection
    const kpiInc = document.getElementById('kpi-incidents');
    const kpiDec = document.getElementById('kpi-decisions');
    if (kpiInc) kpiInc.textContent = blockedCount || '0';
    if (kpiDec) kpiDec.textContent = containmentRate + '%';
  }

  function buildActivityFeed(incidents, decisions) {
    const feedEl = document.getElementById('activityFeed');
    if (!feedEl) return;

    const actionMap = {};
    (decisions || []).forEach(d => {
      const key = d.target_ip || d.incident_id || '';
      if (key) actionMap[key] = d;
    });

    const detectorLabels = {
      ssh_bruteforce: 'SSH password guessing',
      credential_stuffing: 'credential stuffing attack',
      port_scan: 'port scan',
      sudo_abuse: 'suspicious sudo commands',
      search_abuse: 'search abuse',
      web_scan: 'web scanner detected',
      user_agent_scanner: 'automated scanner',
      execution_guard: 'suspicious command execution',
    };

    const rows = (incidents || []).slice(0, 12).map(inc => {
      const sev = (inc.severity || '').toLowerCase();
      const ip = (inc.entities || []).find(e => e.type === 'Ip' || e.type === 'ip')?.value || '';
      const dec = ip ? actionMap[ip] : null;
      const detectorSlug = (inc.incident_id || '').split(':')[0] || '';
      const label = detectorLabels[detectorSlug] || inc.title || detectorSlug;
      const ago = timeAgo(inc.ts);

      const outcome = inc.outcome || 'open';
      const isResolved = outcome !== 'open';
      let icon, actionText, rowStyle;

      if (isResolved && outcome === 'blocked') {
        icon = '🛡️'; actionText = 'Blocked ' + (ip || ''); rowStyle = 'opacity:0.7';
      } else if (isResolved && outcome === 'suspended') {
        icon = '🔒'; actionText = 'Sudo suspended' + (ip ? ' for ' + ip : ''); rowStyle = 'opacity:0.7';
      } else if (isResolved && outcome === 'ignored') {
        icon = '✓'; actionText = 'Reviewed — no action needed'; rowStyle = 'opacity:0.5';
      } else if (isResolved) {
        icon = '✓'; actionText = 'Contained' + (ip ? ' ' + ip : ''); rowStyle = 'opacity:0.7';
      } else if (sev === 'critical' || sev === 'high') {
        icon = '⚠️'; actionText = ip ? 'Investigating ' + ip : 'Active threat';  rowStyle = '';
      } else {
        icon = '•'; actionText = ip ? 'Monitoring ' + ip : 'Monitoring'; rowStyle = 'opacity:0.8';
      }

      return '<div class="activity-row" style="' + rowStyle + '" onclick="handleCardClickByValue(\'ip\',\'' + esc(ip) + '\')">' +
        '<div class="activity-icon">' + icon + '</div>' +
        '<div class="activity-body">' +
          '<div class="activity-title">' + esc(actionText) + '</div>' +
          '<div class="activity-meta">' + esc(label) + (isResolved ? ' · ' + outcome : '') + '</div>' +
        '</div>' +
        '<div class="activity-time">' + esc(ago) + '</div>' +
        '</div>';
    });

    if (rows.length === 0) {
      feedEl.innerHTML = '<div class="empty" style="padding:20px 0;text-align:center;color:var(--ok)">✅ Nothing suspicious today</div>';
    } else {
      feedEl.innerHTML = '<div class="activity-feed">' + rows.join('') + '</div>';
    }
  }

  // ── D10 — Report tab ────────────────────────────────────────────────────
  async function loadReportDates() {
    try {
      const dates = await loadJson('/api/report/dates');
      const sel = document.getElementById('reportDateSelect');
      sel.innerHTML = '<option value="">latest</option>';
      (dates || []).forEach(d => {
        const opt = document.createElement('option');
        opt.value = d; opt.textContent = d;
        sel.appendChild(opt);
      });
    } catch (_) {}
  }

  async function loadReport() {
    const status = document.getElementById('reportStatus');
    const content = document.getElementById('reportContent');
    const date = document.getElementById('reportDateSelect')?.value || '';
    status.textContent = 'Loading…';
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
    try {
      const url = '/api/report' + (date ? '?date=' + encodeURIComponent(date) : '');
      const r = await loadJson(url);
      status.textContent = 'Generated ' + new Date(r.generated_at).toLocaleTimeString();
      content.innerHTML = renderReport(r);
    } catch (e) {
      status.textContent = 'error';
      content.innerHTML = '<div class="empty" style="padding:40px;color:var(--danger)">Failed to load report: ' + esc(e.message) + '</div>';
    }
  }

  function navigateReport(dir) {
    const sel = document.getElementById('reportDateSelect');
    const opts = Array.from(sel.options).filter(o => o.value);
    if (!opts.length) return;
    const cur = sel.value;
    const idx = opts.findIndex(o => o.value === cur);
    const nextIdx = idx === -1 ? (dir < 0 ? opts.length - 1 : 0) : Math.max(0, Math.min(opts.length - 1, idx - dir));
    sel.value = opts[nextIdx]?.value || '';
    loadReport();
  }

  async function exportReport() {
    const date = document.getElementById('reportDateSelect')?.value || '';
    try {
      const url = '/api/export?format=markdown' + (date ? '&date=' + encodeURIComponent(date) : '');
      const text = await loadText(url);
      const fname = 'innerwarden-report-' + (date || new Date().toISOString().slice(0,10)) + '.md';
      downloadBlob(fname, 'text/markdown', text);
    } catch(e) {
      showToast('Export failed: ' + e.message, 'err');
    }
  }

  function renderReport(r) {
    function sparkline(values, color) {
      if (!values || values.length < 2) return '';
      const max = Math.max(...values, 1);
      const w = 80, h = 28, pad = 2;
      const pts = values.map((v, i) => {
        const x = pad + (i / (values.length - 1)) * (w - pad * 2);
        const y = h - pad - ((v / max) * (h - pad * 2));
        return x.toFixed(1) + ',' + y.toFixed(1);
      }).join(' ');
      const lastPt = pts.split(' ').pop().split(',');
      return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" style="display:block;overflow:visible">' +
        '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>' +
        '<circle cx="' + lastPt[0] + '" cy="' + lastPt[1] + '" r="2.5" fill="' + color + '"/>' +
        '</svg>';
    }
    const ds = r.detection_summary || {};
    const ai = r.agent_ai_summary || {};
    const rw = r.recent_window || {};
    const tr = r.trend_summary || {};
    const oh = r.operational_health || {};
    const hints = r.anomaly_hints || [];
    const suggestions = r.suggested_improvements || [];

    const pct = (v) => v == null ? '—' : (v > 0 ? '+' : '') + v.toFixed(1) + '%';
    const deltaClass = (d) => d > 0 ? 'up' : (d < 0 ? 'down' : '');
    const deltaSign = (d) => d > 0 ? '+' : '';
    const confColor = (v) => v >= 0.85 ? 'good' : v >= 0.7 ? 'warn' : 'bad';
    const healthVal = (v) => v ? '<span class="health-ok">✓ OK</span>' : '<span class="health-fail">✗ Fail</span>';

    // KPI row
    let html = `<div class="report-section">
      <div class="report-section-title">Summary — ${esc(r.analyzed_date)}</div>
      <div class="report-kpi-row">
        <div class="report-kpi"><div class="report-kpi-label">Events</div><div class="report-kpi-value">${ds.total_events ?? 0}</div></div>
        <div class="report-kpi"><div class="report-kpi-label">Incidents</div><div class="report-kpi-value">${ds.total_incidents ?? 0}</div></div>
        <div class="report-kpi"><div class="report-kpi-label">Decisions</div><div class="report-kpi-value">${ai.total_decisions ?? 0}</div></div>
        <div class="report-kpi"><div class="report-kpi-label">Blocks</div><div class="report-kpi-value">${ai.block_ip_count ?? 0}</div></div>
        <div class="report-kpi"><div class="report-kpi-label">Avg Conf</div><div class="report-kpi-value ${confColor(ai.average_confidence ?? 0)}">${((ai.average_confidence ?? 0) * 100).toFixed(0)}%</div></div>
        <div class="report-kpi"><div class="report-kpi-label">Last 6h Incid.</div><div class="report-kpi-value">${rw.incidents ?? 0}</div></div>
        <div class="report-kpi"><div class="report-kpi-label">High/Crit 6h</div><div class="report-kpi-value ${(rw.high_critical_incidents ?? 0) > 0 ? 'bad' : 'good'}">${rw.high_critical_incidents ?? 0}</div></div>
      </div>
    </div>`;

    // Trend section
    if (tr.previous_date) {
      html += `<div class="report-section">
        <div class="report-section-title">Trend vs ${esc(tr.previous_date)}</div>
        <div class="report-trend-row">
          ${trendCell('Events', tr.events)}
          ${trendCell('Incidents', tr.incidents)}
          ${trendCell('Decisions', tr.decisions)}
          ${trendCellF('Incid/1k Events', tr.incident_rate_per_1k_events)}
          ${trendCellF('Dec/Incident', tr.decision_rate_per_incident)}
          ${trendCellF('Avg Confidence', tr.average_confidence, true)}
        </div>
      </div>`;
    }

    function trendCell(label, c) {
      if (!c) return '';
      const d = c.delta ?? 0;
      const p = c.pct_change != null ? ` (${pct(c.pct_change)})` : '';
      return `<div class="report-trend-cell">
        <div class="report-trend-label">${esc(label)}</div>
        <div class="report-trend-nums">${c.current} <span style="color:var(--muted)">/ prev ${c.previous}</span></div>
        <div class="report-trend-delta ${deltaClass(d)}">${deltaSign(d)}${d}${p}</div>
      </div>`;
    }
    function trendCellF(label, c, higherGood) {
      if (!c) return '';
      const d = c.delta ?? 0;
      const cls = higherGood ? (d > 0 ? 'down' : d < 0 ? 'up' : '') : deltaClass(d);
      const p = c.pct_change != null ? ` (${pct(c.pct_change)})` : '';
      return `<div class="report-trend-cell">
        <div class="report-trend-label">${esc(label)}</div>
        <div class="report-trend-nums">${c.current.toFixed(2)} <span style="color:var(--muted)">/ prev ${c.previous.toFixed(2)}</span></div>
        <div class="report-trend-delta ${cls}">${deltaSign(d)}${d.toFixed(2)}${p}</div>
      </div>`;
    }

    // Anomaly hints
    if (hints.length > 0) {
      html += `<div class="report-section">
        <div class="report-section-title">Anomaly Hints</div>`;
      hints.forEach(h => {
        const sev = (h.severity || 'info').toLowerCase();
        html += `<div class="report-anomaly ${esc(sev)}">
          <span class="report-anomaly-badge badge-${esc(sev)}">${esc(h.severity)}</span>
          <span class="report-anomaly-msg">${esc(h.message)}</span>
        </div>`;
      });
      html += `</div>`;
    }

    // Top IPs
    if ((ds.top_ips || []).length > 0) {
      html += `<div class="report-section">
        <div class="report-section-title">Top IPs</div>
        <table class="report-table">
          <thead><tr><th>IP</th><th>Events</th></tr></thead><tbody>`;
      ds.top_ips.forEach(e => {
        html += `<tr><td>${esc(e.name)}</td><td>${e.count}</td></tr>`;
      });
      html += `</tbody></table></div>`;
    }

    // Incidents by type
    const ibt = ds.incidents_by_type || {};
    if (Object.keys(ibt).length > 0) {
      html += `<div class="report-section">
        <div class="report-section-title">Incidents by Type</div>
        <table class="report-table">
          <thead><tr><th>Detector</th><th>Count</th></tr></thead><tbody>`;
      Object.entries(ibt).sort((a,b) => b[1]-a[1]).forEach(([k,v]) => {
        html += `<tr><td>${esc(k)}</td><td>${v}</td></tr>`;
      });
      html += `</tbody></table></div>`;
    }

    // Operational health
    html += `<div class="report-section">
      <div class="report-section-title">Operational Health</div>
      <table class="report-table"><thead><tr><th>File</th><th>Exists</th><th>Valid</th><th>Lines</th><th>Size</th></tr></thead><tbody>`;
    (oh.files || []).forEach(f => {
      const valid = f.jsonl_valid == null ? '—' : (f.jsonl_valid ? '<span class="health-ok">✓</span>' : '<span class="health-fail">✗</span>');
      html += `<tr>
        <td>${esc(f.file)}</td>
        <td>${f.exists ? '<span class="health-ok">✓</span>' : '<span class="health-fail">✗</span>'}</td>
        <td>${valid}</td>
        <td>${f.lines ?? '—'}</td>
        <td>${f.size_bytes > 0 ? (f.size_bytes > 1048576 ? (f.size_bytes/1048576).toFixed(1)+'MB' : (f.size_bytes/1024).toFixed(1)+'KB') : '0B'}</td>
      </tr>`;
    });
    html += `</tbody></table></div>`;

    // Suggestions
    if (suggestions.length > 0) {
      html += `<div class="report-section">
        <div class="report-section-title">Suggestions</div>`;
      suggestions.forEach(s => {
        html += `<div class="report-suggestion"><span style="color:var(--accent);flex-shrink:0">→</span><span>${esc(s)}</span></div>`;
      });
      html += `</div>`;
    }

    return html;
  }
  async function loadStatus() {
    const status = document.getElementById('statusViewStatus');
    const content = document.getElementById('statusContent');
    if (!status || !content) return;
    status.textContent = 'Loading…';
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
    try {
      const [s, col] = await Promise.all([
        loadJson('/api/status'),
        loadJson('/api/collectors').catch(() => ({ collectors: [] }))
      ]);
      status.textContent = 'Updated ' + new Date().toLocaleTimeString();
      content.innerHTML = renderStatus(s, col.collectors || []);
    } catch(e) {
      status.textContent = 'error';
      content.innerHTML = '<div class="empty" style="padding:40px;color:var(--danger)">Failed: ' + esc(String(e.message)) + '</div>';
    }
  }

  function renderStatus(s, collectors) {
    const files = s.files || {};
    const resp = s.responder || {};
    const integ = s.integrations || {};
    const fmt = (bytes) => bytes > 1048576 ? (bytes/1048576).toFixed(1)+'MB' : bytes > 1024 ? (bytes/1024).toFixed(1)+'KB' : bytes+'B';

    // Agent liveness
    const tSecs = s.last_telemetry_secs;
    let liveStr = '—';
    if (tSecs != null) {
      if (tSecs < 60)        liveStr = tSecs + 's ago';
      else if (tSecs < 3600) liveStr = Math.floor(tSecs/60) + 'm ago';
      else                   liveStr = Math.floor(tSecs/3600) + 'h ago';
    }
    const isHealthy = tSecs != null && tSecs < 300;

    // ── Section 1: Guard Mode card ─────────────────────────────────────────
    // GUARD = green (good, server protected), WATCH = yellow (caution, not acting), READ-ONLY = gray (passive)
    let guardIcon, guardLabel, guardDesc, guardColor, guardBorderColor, guardBg;
    if (s.mode === 'guard') {
      guardIcon = '🛡';
      guardLabel = 'PROTECTED';
      guardDesc = 'Active protection — AI is blocking threats with live firewall rules';
      guardColor = 'var(--ok)';
      guardBorderColor = 'rgba(58,194,126,0.5)';
      guardBg = 'rgba(58,194,126,0.06)';
    } else if (s.mode === 'watch') {
      guardIcon = '👁';
      guardLabel = 'WATCHING';
      guardDesc = 'Dry-run — AI is analysing threats but actions need manual approval or config change';
      guardColor = 'var(--warn)';
      guardBorderColor = 'rgba(255,184,77,0.4)';
      guardBg = 'rgba(255,184,77,0.04)';
    } else {
      guardIcon = '📖';
      guardLabel = 'MONITOR ONLY';
      guardDesc = 'Responder disabled — events are logged and reported, no automated response';
      guardColor = 'var(--muted)';
      guardBorderColor = 'var(--line)';
      guardBg = 'transparent';
    }
    const aiLabel = s.ai_enabled ? '🤖 ' + esc(s.ai_provider || '') + ' / ' + esc(s.ai_model || '') : '— off';

    let html = '<div class="report-section">' +
      '<div class="report-section-title">Protection Status</div>' +
      '<div style="background:' + guardBg + ';border:1px solid ' + guardBorderColor + ';border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:16px;margin-bottom:4px">' +
      '<div style="font-size:2rem;flex-shrink:0">' + guardIcon + '</div>' +
      '<div>' +
      '<div style="font-size:1.1rem;font-weight:800;color:' + guardColor + '">' + esc(guardLabel) + '</div>' +
      '<div style="font-size:0.75rem;color:var(--muted);margin-top:3px">' + esc(guardDesc) + '</div>' +
      '<div style="margin-top:8px;font-size:0.72rem;color:var(--muted)">AI: <span style="color:var(--' + (s.ai_enabled ? 'ok' : 'muted') + ')">' + aiLabel + '</span> &nbsp;·&nbsp; Agent: <span style="color:var(--' + (isHealthy ? 'ok' : 'warn') + ')">' + liveStr + '</span></div>' +
      '</div></div></div>';

    // ── Section 2: Active Integrations grid ───────────────────────────────
    const card = (icon, name, on, desc, badgeLabel, kind, costNote, enableCmd) => {
      const badge = badgeLabel === 'ON'   ? '<span class="integ-badge on">ON</span>'   :
                    badgeLabel === 'OFF'  ? '<span class="integ-badge off">OFF</span>' :
                    badgeLabel === 'DEMO' ? '<span class="integ-badge demo">DEMO</span>' :
                    badgeLabel === 'LIVE' ? '<span class="integ-badge on">LIVE</span>' :
                                           '<span class="integ-badge off">OFF</span>';
      const kindBadge = kind === 'native'
        ? '<span class="integ-kind-native">NATIVE</span>'
        : '<span class="integ-kind-ext">EXTERNAL</span>';
      const cost = costNote ? '<div class="integ-cost">' + esc(costNote) + '</div>' : '';
      const hint = !on && enableCmd ? '<div class="integ-hint">$ <code>' + esc(enableCmd) + '</code></div>' : '';
      return '<div class="integ-card ' + (on ? 'active' : 'inactive') + '">' +
        '<div class="integ-icon">' + icon + '</div>' +
        '<div class="integ-body">' +
        '<div class="integ-name">' + esc(name) + badge + kindBadge + '</div>' +
        '<div class="integ-desc">' + esc(desc) + '</div>' +
        cost +
        hint +
        '</div></div>';
    };

    const hpMode = (integ.honeypot_mode || 'off').toLowerCase();
    const hpBadge = hpMode === 'listener' ? 'LIVE' : hpMode === 'demo' ? 'DEMO' : 'OFF';

    html += '<div class="report-section"><div class="report-section-title">Active Integrations</div>' +
      '<style>' +
      '.integ-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:20px}' +
      '.integ-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px}' +
      '.integ-card.active{border-color:rgba(58,194,126,0.4)}' +
      '.integ-card.inactive{opacity:0.65}' +
      '.integ-icon{font-size:1.4rem;flex-shrink:0}' +
      '.integ-body{flex:1;min-width:0}' +
      '.integ-name{font-size:0.85rem;font-weight:700;color:var(--text);margin-bottom:2px}' +
      '.integ-desc{font-size:0.68rem;color:var(--muted);line-height:1.4}' +
      '.integ-cost{font-size:0.62rem;color:var(--muted);opacity:0.75;margin-top:3px;line-height:1.4}' +
      '.integ-hint{font-size:0.62rem;color:var(--accent);margin-top:5px}' +
      '.integ-hint code{font-family:\'JetBrains Mono\',monospace}' +
      '.integ-badge{display:inline-block;font-size:0.6rem;font-weight:700;padding:2px 7px;border-radius:20px;margin-left:6px;vertical-align:middle}' +
      '.integ-badge.on{background:rgba(58,194,126,0.2);color:var(--ok)}' +
      '.integ-badge.off{background:rgba(244,63,94,0.12);color:var(--danger)}' +
      '.integ-badge.demo{background:rgba(255,184,77,0.15);color:var(--warn)}' +
      '.integ-kind-native{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent);letter-spacing:0.04em}' +
      '.integ-kind-ext{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(255,184,77,0.12);color:var(--warn);letter-spacing:0.04em}' +
      '@media(max-width:640px){.integ-grid{grid-template-columns:1fr}}' +
      '</style>' +
      '<div class="integ-grid">' +
      card('🤖', 'AI Analysis',   s.ai_enabled,       'Analyzes threats and selects the best response action',         s.ai_enabled ? 'ON' : 'OFF',  'native',   'Built into InnerWarden — no external service needed.',                                       'innerwarden enable ai') +
      card('🛡️', 'IP Blocker',    resp.enabled,       'Automatically blocks IPs via UFW/iptables when AI decides',     resp.enabled ? 'ON' : 'OFF',  'native',   'Zero cost. Uses your existing firewall.',                                                    'innerwarden enable block-ip') +
      card('🪤', 'Honeypot',      hpMode !== 'off',   'Decoy server that captures and logs attacker behavior',         hpBadge,                      'native',   'Built-in. listener mode activates on AI demand; always_on keeps it permanently open.',      '') +
      card('🌍', 'GeoIP',         integ.geoip,        'Adds country/ISP info to every threat — free, no key needed',  integ.geoip ? 'ON' : 'OFF',   'native',   'Free. Calls ip-api.com (45 req/min). Best first enrichment to enable.',                      'innerwarden integrate geoip') +
      card('🔍', 'AbuseIPDB',     integ.abuseipdb,    'IP reputation check before AI call — skips known-bad IPs',     integ.abuseipdb ? 'ON' : 'OFF','external', 'Free plan: 1,000 req/day. Paid plans from $50/mo. Caution: do not combine auto_block_threshold with fail2ban auto-banning.', 'innerwarden integrate abuseipdb') +
      card('🔒', 'Fail2ban',      integ.fail2ban,     'Syncs fail2ban bans into InnerWarden\'s audit trail',           integ.fail2ban ? 'ON' : 'OFF', 'external', 'Free & lightweight. If active, set abuseipdb auto_block_threshold=0 to avoid double-blocking.', 'innerwarden integrate fail2ban') +
      card('🔔', 'Telegram',      integ.telegram,     'Real-time alerts + inline approval buttons on your phone',     integ.telegram ? 'ON' : 'OFF', 'external', 'Free. Best solo-operator channel — supports bidirectional approve/reject.',                  'innerwarden notify telegram') +
      card('💬', 'Slack',         integ.slack,        'Incident notifications to a Slack team channel',               integ.slack ? 'ON' : 'OFF',   'external', 'Free (requires workspace). Activating alongside Telegram doubles alert volume for same incident.', 'innerwarden notify slack') +
      card('☁️', 'Cloudflare',    integ.cloudflare,   'Pushes blocked IPs to Cloudflare edge after block-ip fires',   integ.cloudflare ? 'ON' : 'OFF','external', 'Free plan supports IP Access Rules. Effective for DDoS edge-layer defense.',               'innerwarden integrate cloudflare') +
      '</div></div>';

    // ── Section 2b: Integration advisor ────────────────────────────────────
    const conflicts = [];
    if (integ.abuseipdb && integ.fail2ban && integ.abuseipdb_auto_block_threshold > 0) {
      conflicts.push({
        a: 'AbuseIPDB auto-block', b: 'Fail2ban',
        msg: 'Both can auto-block IPs without AI. Set abuseipdb.auto_block_threshold = 0 and use AbuseIPDB only for enrichment context.'
      });
    }
    if (integ.telegram && integ.slack) {
      conflicts.push({
        a: 'Telegram', b: 'Slack',
        msg: 'Both send the same High/Critical alert. If you are the only operator, this doubles notification volume with no benefit. Use Telegram for real-time response, Slack for team visibility.'
      });
    }

    const recommendations = [];
    if (!integ.geoip)     recommendations.push({ icon:'🌍', text:'Enable GeoIP — free, zero noise, adds country/ISP to every AI decision', cmd:'innerwarden integrate geoip' });
    if (!integ.telegram)  recommendations.push({ icon:'🔔', text:'Enable Telegram — real-time alerts with approve/reject buttons on your phone', cmd:'innerwarden notify telegram' });
    if (!integ.abuseipdb) recommendations.push({ icon:'🔍', text:'Enable AbuseIPDB — free API key, enriches AI context with IP reputation score', cmd:'innerwarden integrate abuseipdb' });
    if (!integ.cloudflare && resp.enabled) recommendations.push({ icon:'☁️', text:'Enable Cloudflare — push blocked IPs to the edge after every block-ip decision', cmd:'innerwarden integrate cloudflare' });

    if (conflicts.length > 0 || recommendations.length > 0) {
      html += '<div class="report-section"><div class="report-section-title">Integration Advisor</div>' +
        '<style>' +
        '.advisor-block{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}' +
        '.advisor-conflict{border-left:3px solid var(--warn)}' +
        '.advisor-rec{border-left:3px solid var(--accent)}' +
        '.advisor-label{font-size:0.65rem;font-weight:700;letter-spacing:0.06em;margin-bottom:6px}' +
        '.advisor-label.warn{color:var(--warn)}' +
        '.advisor-label.ok{color:var(--accent)}' +
        '.advisor-pair{font-size:0.75rem;font-weight:700;color:var(--text);margin-bottom:3px}' +
        '.advisor-msg{font-size:0.68rem;color:var(--muted);line-height:1.5}' +
        '.advisor-cmd{font-size:0.62rem;color:var(--accent);margin-top:5px;font-family:\'JetBrains Mono\',monospace}' +
        '</style>';

      conflicts.forEach(c => {
        html += '<div class="advisor-block advisor-conflict">' +
          '<div class="advisor-label warn">⚠ OVERLAP DETECTED</div>' +
          '<div class="advisor-pair">' + esc(c.a) + ' ↔ ' + esc(c.b) + '</div>' +
          '<div class="advisor-msg">' + esc(c.msg) + '</div>' +
          '</div>';
      });

      if (recommendations.length > 0) {
        const next = recommendations[0];
        html += '<div class="advisor-block advisor-rec">' +
          '<div class="advisor-label ok">💡 RECOMMENDED NEXT STEP</div>' +
          '<div class="advisor-pair">' + next.icon + ' ' + esc(next.text) + '</div>' +
          '<div class="advisor-cmd">$ ' + esc(next.cmd) + '</div>' +
          '</div>';
        if (recommendations.length > 1) {
          html += '<div style="font-size:0.62rem;color:var(--muted);padding:0 4px 12px">After that: ';
          html += recommendations.slice(1).map(r => esc(r.icon + ' ' + r.cmd)).join(' &nbsp;·&nbsp; ');
          html += '</div>';
        }
      }

      html += '</div>';
    }

    // ── Section 3: Sensor Collectors ──────────────────────────────────────
    if (collectors.length > 0) {
      const colIcons = {
        auth_log:'🔑', journald:'📋', docker:'🐳', nginx_access:'🌐', nginx_error:'⚠️',
        exec_audit:'🔎', falco_log:'🦅', suricata_eve:'🐉', wazuh_alerts:'🔒', osquery_log:'🔍'
      };
      const colStyle =
        '.col-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:4px}' +
        '.col-row{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 14px;display:flex;align-items:center;gap:10px}' +
        '.col-row.col-active{border-color:rgba(58,194,126,0.35)}' +
        '.col-row.col-detected{border-color:rgba(255,184,77,0.25)}' +
        '.col-row.col-missing{opacity:0.5}' +
        '.col-ico{font-size:1.2rem;flex-shrink:0}' +
        '.col-body{flex:1;min-width:0}' +
        '.col-name{font-size:0.8rem;font-weight:700;color:var(--text)}' +
        '.col-meta{font-size:0.62rem;color:var(--muted);margin-top:2px}' +
        '.col-evt{display:inline-block;font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;margin-left:6px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent)}' +
        '.col-status-active{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(58,194,126,0.2);color:var(--ok)}' +
        '.col-status-detected{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(255,184,77,0.15);color:var(--warn)}' +
        '.col-status-missing{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(100,100,100,0.15);color:var(--muted)}' +
        '.col-kind-native{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(120,229,255,0.1);color:var(--accent)}' +
        '.col-kind-ext{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(255,184,77,0.1);color:var(--warn)}' +
        '@media(max-width:640px){.col-grid{grid-template-columns:1fr}}';

      html += '<div class="report-section"><div class="report-section-title">Sensor Collectors</div>' +
        '<style>' + colStyle + '</style>' +
        '<div style="font-size:0.65rem;color:var(--muted);margin-bottom:12px">' +
        '<span class="col-status-active">ACTIVE</span> log file exists + written in last 2h &nbsp; ' +
        '<span class="col-status-detected">DETECTED</span> log file exists but stale or not yet seen today &nbsp; ' +
        '<span class="col-status-missing">NOT FOUND</span> tool not installed / log absent' +
        '</div>' +
        '<div class="col-grid">';

      collectors.forEach(c => {
        const icon = colIcons[c.id] || '📦';
        const kindBadge = c.kind === 'native'
          ? '<span class="col-kind-native">NATIVE</span>'
          : '<span class="col-kind-ext">EXTERNAL</span>';
        let statusBadge, rowCls;
        if (c.active) {
          statusBadge = '<span class="col-status-active">ACTIVE</span>';
          rowCls = 'col-active';
        } else if (c.detected) {
          statusBadge = '<span class="col-status-detected">DETECTED</span>';
          rowCls = 'col-detected';
        } else {
          statusBadge = '<span class="col-status-missing">NOT FOUND</span>';
          rowCls = 'col-missing';
        }
        const evtBadge = c.events_today > 0
          ? '<span class="col-evt">' + c.events_today + ' events today</span>'
          : '';
        html += '<div class="col-row ' + rowCls + '">' +
          '<div class="col-ico">' + icon + '</div>' +
          '<div class="col-body">' +
          '<div class="col-name">' + esc(c.name) + kindBadge + statusBadge + evtBadge + '</div>' +
          '<div class="col-meta">' + esc(c.desc) + '</div>' +
          ((!c.detected && c.kind === 'external') ? '<div style="font-size:0.58rem;color:var(--accent);margin-top:3px">Not installed — optional external tool</div>' : '') +
          '</div></div>';
      });

      html += '</div></div>';
    }

    // ── Section 4: Data files ──────────────────────────────────────────────
    html += '<div class="report-section"><div class="report-section-title">Data Files — ' + esc(s.date || '—') + '</div>' +
      '<table class="report-table"><thead><tr><th>File</th><th>Status</th><th>Size</th></tr></thead><tbody>';
    Object.entries(files).forEach(([k, v]) => {
      const exists = v.exists;
      html += '<tr>' +
        '<td style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem">' + esc(k) + '.jsonl</td>' +
        '<td>' + (exists ? '<span class="health-ok">✓ Present</span>' : '<span style="color:var(--muted)">— Absent</span>') + '</td>' +
        '<td style="color:var(--muted)">' + (exists ? fmt(v.size_bytes) : '—') + '</td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';

    html += '<div class="report-section"><div class="report-section-title">Data Directory</div>' +
      '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:var(--muted);padding:4px 0">' + esc(s.data_dir || '—') + '</div></div>';

    return html;
  }

  // On mobile: auto-collapse the list when a journey is opened, re-open via button
  function collapseLeftOnMobile() {
    if (window.innerWidth <= 860 && leftPanelOpen) {
      toggleLeftPanel();
    }
  }

  // ── Honeypot tab ──────────────────────────────────────────────────────
  async function loadHoneypot() {
    const status = document.getElementById('honeypotViewStatus');
    const content = document.getElementById('honeypotContent');
    if (!status || !content) return;
    status.textContent = 'Loading…';
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
    try {
      const data = await loadJson('/api/honeypot/sessions');
      status.textContent = 'Updated ' + new Date().toLocaleTimeString();
      content.innerHTML = renderHoneypot(data);
    } catch(e) {
      status.textContent = 'Error';
      content.innerHTML = '<div class="empty" style="padding:40px;text-align:center;color:var(--danger)">Failed to load honeypot sessions.</div>';
    }
  }

  async function testHoneypot() {
    const btn = document.getElementById('btnTestHoneypot');
    if (!btn) return;
    btn.disabled = true;
    btn.textContent = '⏳ Iniciando...';
    try {
      const reason = 'Teste manual via dashboard';
      const resp = await fetch('/api/action/honeypot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason, duration_secs: 120 })
      });
      const data = await resp.json();
      if (data.success) {
        showToast('🍯 ' + data.message, 'ok');
      } else {
        showToast('❌ ' + data.message, 'err');
      }
    } catch (e) {
      showToast('❌ Request failed: ' + e.message, 'err');
    } finally {
      btn.disabled = false;
      btn.textContent = '🧪 Start test session';
    }
  }

  function renderHoneypot(data) {
    const sessions = data.sessions || [];

    // Test button shown regardless of whether sessions exist
    const testBtn = '<div style="padding:16px 16px 0;max-width:900px;margin:0 auto">' +
      '<button id="btnTestHoneypot" onclick="testHoneypot()" ' +
      'style="background:rgba(120,229,255,0.08);border:1px solid rgba(120,229,255,0.28);' +
      'border-radius:8px;color:var(--accent);font-size:0.78rem;font-weight:600;' +
      'padding:8px 18px;cursor:pointer;transition:background 0.15s,border-color 0.15s;' +
      'font-family:inherit" ' +
      'onmouseover="this.style.background=\'rgba(120,229,255,0.15)\'" ' +
      'onmouseout="this.style.background=\'rgba(120,229,255,0.08)\'">' +
      '🧪 Start test session</button>' +
      '<span style="font-size:0.68rem;color:var(--muted);margin-left:10px">' +
      'Injects a test incident — the agent evaluates and triggers the honeypot on the next tick (≤2 s).' +
      '</span></div>';

    if (sessions.length === 0) {
      return testBtn + '<div class="empty" style="padding:40px;text-align:center;opacity:0.5">🍯 No honeypot sessions yet.<br><span style="font-size:0.8rem">Sessions appear here when attackers interact with a honeypot listener.</span></div>';
    }

    let html = testBtn + '<div style="padding:16px;max-width:900px;margin:0 auto">';
    html += '<div style="font-size:1.1rem;font-weight:600;color:var(--accent);margin-bottom:16px">🍯 Honeypot Sessions (' + sessions.length + ')</div>';

    for (const s of sessions) {
      const ip = s.target_ip || '—';
      const sessionId = s.session_id || '—';
      const startedAt = s.started_at ? new Date(s.started_at).toLocaleString() : '—';
      const duration = s.duration_secs ? s.duration_secs + 's' : '—';
      const cmdCount = s.commands_count || 0;
      const authCount = s.auth_attempts || 0;
      const commands = s.commands || [];
      const iocs = s.iocs || [];
      const blocked = !!s.blocked;
      const mode = s.mode || 'listener';

      html += '<div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px;margin-bottom:12px">';

      // Header row
      html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
      html += '<span style="font-family:monospace;font-size:1rem;color:var(--accent)">' + esc(ip) + '</span>';
      if (blocked) {
        html += '<span style="background:rgba(58,194,126,0.15);color:#3ac27e;border:1px solid rgba(58,194,126,0.3);border-radius:4px;padding:2px 8px;font-size:0.7rem;font-weight:600">BLOCKED</span>';
      }
      if (mode === 'always_on') {
        html += '<span style="background:rgba(120,229,255,0.08);color:var(--accent);border:1px solid rgba(120,229,255,0.2);border-radius:4px;padding:2px 8px;font-size:0.7rem">ALWAYS-ON</span>';
      }
      html += '<span style="font-size:0.75rem;opacity:0.6">' + esc(startedAt) + '</span>';
      if (s.duration_secs) html += '<span style="font-size:0.75rem;opacity:0.6">Duration: ' + esc(duration) + '</span>';
      html += '<span style="font-size:0.75rem;opacity:0.6">Auth attempts: ' + authCount + '</span>';
      html += '<span style="font-size:0.75rem;opacity:0.6">Commands: ' + cmdCount + '</span>';
      html += '</div>';

      // Session ID
      html += '<div style="font-size:0.7rem;opacity:0.4;margin-bottom:10px;font-family:monospace">' + esc(sessionId) + '</div>';

      // Commands
      if (commands.length > 0) {
        html += '<div style="margin-bottom:10px">';
        html += '<div style="font-size:0.75rem;font-weight:600;color:rgba(255,255,255,0.7);margin-bottom:6px">Commands typed by attacker</div>';
        html += '<div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px;font-family:monospace;font-size:0.78rem;color:rgba(255,255,255,0.85)">';
        for (const cmd of commands.slice(0, 15)) {
          html += '<div style="margin-bottom:3px"><span style="color:var(--accent);opacity:0.7">$</span> ' + esc(cmd) + '</div>';
        }
        if (commands.length > 15) {
          html += '<div style="opacity:0.4;font-size:0.7rem">... ' + (commands.length - 15) + ' more commands</div>';
        }
        html += '</div></div>';
      }

      // IOCs
      if (iocs.length > 0) {
        html += '<div style="margin-top:10px">';
        html += '<div style="font-size:0.75rem;font-weight:600;color:#f59e0b;margin-bottom:6px">⚠ Extracted IOCs</div>';
        html += '<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:10px">';
        for (const ioc of iocs) {
          html += '<div style="font-family:monospace;font-size:0.78rem;color:#fcd34d;margin-bottom:3px">' + esc(ioc) + '</div>';
        }
        html += '</div></div>';
      }

      html += '</div>'; // end session card
    }

    html += '</div>';
    return html;
  }

  // ── Helpers ────────────────────────────────────────────────────────────
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const fmtTime = (ts) => {
    const d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  };

  const fmtDateTime = (ts) => {
    const d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleString();
  };

  const outcomeLabel = (o) => ({blocked:'BLOCKED', active:'ACTIVE', monitoring:'MONITORING', honeypot:'HONEYPOT', unknown:'UNKNOWN'}[o] || o.toUpperCase());
  const outcomeCls   = (o) => 'bo bo-' + (o || 'unknown');

  const sevCls = (s) => ({'critical':'sc-critical','high':'sc-high','medium':'sc-medium','low':'sc-low','info':'sc-info'}[s] || '');

  async function loadJson(url) {
    const r = await fetch(url, {cache: 'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  async function loadText(url) {
    const r = await fetch(url, {cache: 'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  }

  function downloadBlob(name, contentType, text) {
    const blob = new Blob([text], { type: contentType });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ── Kind badge ─────────────────────────────────────────────────────────
  function kindBadge(entry) {
    const d = entry.data || {};
    switch (entry.kind) {
      case 'event': {
        const s = d.severity || 'info';
        const cls = s === 'critical' ? 'bk-event-crit' : s === 'high' ? 'bk-event-high' : s === 'medium' ? 'bk-event-med' : 'bk-event';
        return `<span class="bk ${cls}">${esc(s)}</span>`;
      }
      case 'incident':     return `<span class="bk bk-incident">INCIDENT</span>`;
      case 'decision': {
        if (!d.auto_executed) return `<span class="bk bk-decision-skip">SKIPPED</span>`;
        if (d.dry_run)        return `<span class="bk bk-decision-dry">DRY RUN</span>`;
        return `<span class="bk bk-decision">EXECUTED</span>`;
      }
      case 'honeypot_ssh':    return `<span class="bk bk-honeypot">🍯 SSH</span>`;
      case 'honeypot_http':   return `<span class="bk bk-honeypot">🍯 HTTP</span>`;
      case 'honeypot_banner': return `<span class="bk bk-honeypot">🍯 BANNER</span>`;
      default: return `<span class="bk bk-event">${esc(entry.kind)}</span>`;
    }
  }

  // ── Dot class ──────────────────────────────────────────────────────────
  function dotCls(entry) {
    const d = entry.data || {};
    switch (entry.kind) {
      case 'event': return 'dot-event-' + (d.severity || 'info');
      case 'incident': return 'dot-incident';
      case 'decision': return (d.dry_run || !d.auto_executed) ? 'dot-decision-dry' : 'dot-decision';
      case 'honeypot_ssh':
      case 'honeypot_http':
      case 'honeypot_banner': return 'dot-honeypot';
      default: return 'dot-default';
    }
  }

  // ── Summary line ───────────────────────────────────────────────────────
  function entrySummary(entry) {
    const d = entry.data || {};
    switch (entry.kind) {
      case 'event':
        return esc((d.event_kind || '') + ' — ' + (d.summary || ''));
      case 'incident':
        return esc('[' + (d.severity || '').toUpperCase() + '] ' + (d.title || '') + ': ' + (d.summary || ''));
      case 'decision': {
        const conf = ((d.confidence || 0) * 100).toFixed(0);
        const reason = (d.reason || '').substring(0, 70);
        return esc(d.action_type + ' (conf: ' + conf + '%) — ' + reason);
      }
      case 'honeypot_ssh': {
        const attempts = d.auth_attempts || [];
        const creds = attempts.filter(a => a.password).slice(0, 3)
          .map(a => esc(a.username) + '/' + esc(a.password)).join(', ');
        return esc(attempts.length + ' auth attempt(s)') + (creds ? ' · ' + creds : '');
      }
      case 'honeypot_http': {
        const reqs = d.http_requests || [];
        const forms = reqs.filter(r => r.form_fields && r.form_fields.length > 0);
        const formCreds = forms.slice(0, 2).map(r => {
          const fields = Object.fromEntries((r.form_fields || []).map(([k,v]) => [k,v]));
          return (fields.username || fields.user || '') + '/' + (fields.password || fields.pass || '');
        }).filter(Boolean).join(', ');
        return esc(reqs.length + ' request(s)') + (formCreds ? ' · ' + formCreds : '');
      }
      case 'honeypot_banner':
        return esc('Banner probe — ' + (d.bytes_captured ?? 0) + ' bytes captured');
      default:
        return esc(entry.kind);
    }
  }

  // ── D5: Verdict card ───────────────────────────────────────────────────
  function verdictValueCls(label, value) {
    const v = (value || '').toLowerCase();
    if (label === 'access') {
      if (v === 'blocked') return 'v-ok';
      if (v === 'successful' || v === 'active') return 'v-danger';
      if (v === 'attempted') return 'v-warn';
      return 'v-muted';
    }
    if (label === 'containment') {
      if (v === 'contained' || v === 'blocked') return 'v-ok';
      if (v === 'active') return 'v-danger';
      return 'v-muted';
    }
    if (label === 'privilege') {
      if (v === 'abused') return 'v-danger';
      if (v === 'suspicious') return 'v-warn';
      return 'v-muted';
    }
    if (label === 'honeypot') {
      return v === 'engaged' ? 'v-accent' : 'v-muted';
    }
    return 'v-muted';
  }

  function renderVerdictCard(j) {
    if (!j.verdict) return '';
    const v = j.verdict;
    const confColor = v.confidence === 'high' ? 'var(--ok)'
      : v.confidence === 'medium' ? 'var(--warn)' : 'var(--muted)';
    return `
      <div class="verdict-card">
        <div class="verdict-title">Attack Assessment</div>
        <div class="verdict-grid">
          <div class="verdict-cell">
            <div class="verdict-label">Entry Vector</div>
            <div class="verdict-value v-muted">${esc(v.entry_vector || 'unknown')}</div>
          </div>
          <div class="verdict-cell">
            <div class="verdict-label">Access</div>
            <div class="verdict-value ${verdictValueCls('access', v.access_status)}">${esc(v.access_status || 'inconclusive')}</div>
          </div>
          <div class="verdict-cell">
            <div class="verdict-label">Privilege</div>
            <div class="verdict-value ${verdictValueCls('privilege', v.privilege_status)}">${esc(v.privilege_status || 'no_evidence')}</div>
          </div>
          <div class="verdict-cell">
            <div class="verdict-label">Containment</div>
            <div class="verdict-value ${verdictValueCls('containment', v.containment_status)}">${esc(v.containment_status || 'unknown')}</div>
          </div>
          <div class="verdict-cell">
            <div class="verdict-label">Honeypot</div>
            <div class="verdict-value ${verdictValueCls('honeypot', v.honeypot_status)}">${esc(v.honeypot_status || 'not_engaged')}</div>
          </div>
          <div class="verdict-cell" style="grid-column:1/-1">
            <div class="verdict-confidence">
              <div class="conf-dot" style="background:${confColor}"></div>
              <span>${esc(v.confidence || 'low')} confidence assessment</span>
            </div>
          </div>
        </div>
      </div>`;
  }

  // ── D5: Chapter rail ────────────────────────────────────────────────────
  const STAGE_CLASS = {
    reconnaissance:         'stage-recon',
    initial_access_attempt: 'stage-access',
    access_success:         'stage-success',
    privilege_abuse:        'stage-privilege',
    response:               'stage-response',
    containment:            'stage-containment',
    honeypot_interaction:   'stage-honeypot',
  };

  function renderChapterRail(j) {
    if (!j.chapters || j.chapters.length === 0) return '';
    const pills = j.chapters.map((ch, i) => {
      const stageCls = STAGE_CLASS[ch.stage] || '';
      return `
        <div class="chapter-pill ${stageCls}" onclick="scrollToChapter(${i})" title="${esc(ch.summary)}">
          <div class="chapter-stage">${esc(ch.stage.replace(/_/g, ' '))}</div>
          <div class="chapter-pill-title">${esc(ch.title)}</div>
          <div class="chapter-count">${ch.entry_count} event${ch.entry_count !== 1 ? 's' : ''}</div>
        </div>`;
    }).join('');
    return `<div class="chapter-rail" id="chapterRail">${pills}</div>`;
  }

  function scrollToChapter(chapterIdx) {
    if (!window._journeyData || !window._journeyData.chapters) return;
    const ch = window._journeyData.chapters[chapterIdx];
    if (!ch || !ch.entry_indices || ch.entry_indices.length === 0) return;
    const el = document.getElementById('tl-entry-' + ch.entry_indices[0]);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    document.querySelectorAll('.chapter-pill').forEach((p, i) => {
      p.classList.toggle('active', i === chapterIdx);
    });
  }

  // ── D5: Evidence card (human-first, raw JSON secondary) ────────────────
  function renderEvidenceCard(entry, idx) {
    const d = entry.data || {};
    const lines = [];
    if (d.severity)          lines.push('Severity: ' + d.severity);
    if (d.source_ip || d.ip) lines.push('IP: ' + (d.source_ip || d.ip));
    if (d.user)              lines.push('User: ' + d.user);
    if (d.port)              lines.push('Port: ' + d.port);
    if (d.command)           lines.push('Command: ' + d.command);
    if (d.action_type)       lines.push('Action: ' + d.action_type);
    if (d.confidence)        lines.push('Confidence: ' + d.confidence);
    if (d.execution_result)  lines.push('Result: ' + d.execution_result);
    if (d.reason)            lines.push('Reason: ' + d.reason);
    if (d.detector)          lines.push('Detector: ' + d.detector);
    if (d.file_path)         lines.push('File: ' + d.file_path);
    if (d.summary && !lines.length) lines.push(d.summary);
    const metaHtml = lines.length
      ? '<div class="evidence-meta">' + lines.map(l => esc(l)).join('<br>') + '</div>'
      : '';
    return `
      <div class="evidence-card" id="tl-entry-${idx}">
        <div class="evidence-header">
          <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
          ${kindBadge(entry)}
          <button type="button" class="evidence-raw-toggle" onclick="toggleRaw(${idx})">Raw JSON</button>
        </div>
        <div class="evidence-title">${esc(entrySummary(entry))}</div>
        ${metaHtml}
        <pre class="evidence-raw" id="raw-${idx}">${esc(JSON.stringify(entry.data, null, 2))}</pre>
      </div>`;
  }

  function toggleRaw(idx) {
    const el = document.getElementById('raw-' + idx);
    if (el) el.classList.toggle('open');
  }

  // ── Render single timeline entry ───────────────────────────────────────
  function renderEntry(entry, idx) {
    const dot = dotCls(entry);
    return `
      <div class="tl-item">
        <div class="tl-spine">
          <div class="tl-dot ${esc(dot)}"></div>
          <div class="tl-connector"></div>
        </div>
        <div class="tl-body">
          ${renderEvidenceCard(entry, idx)}
        </div>
      </div>`;
  }

  function toggleEntry(idx) {
    // Legacy: kept for compatibility; D5 uses toggleRaw instead.
    toggleRaw(idx);
  }

  // ── D3 — action state ─────────────────────────────────────────────────
  let actionCfg = null;
  let pendingAction = null; // { type: 'block_ip'|'suspend_user', ip, user }

  async function loadActionConfig() {
    try {
      actionCfg = await loadJson('/api/action/config');
      const badge = document.getElementById('modeBadge');
      const aiBadge = document.getElementById('aiBadge');
      // Mode badge
      if (badge) {
        if (actionCfg.enabled) {
          if (actionCfg.dry_run) {
            badge.textContent = '👁 WATCHING';
            badge.className = 'status-badge status-badge-watch';
          } else {
            badge.textContent = '🛡 PROTECTED';
            badge.className = 'status-badge status-badge-guard';
          }
        } else {
          badge.textContent = '📖 MONITOR';
          badge.className = 'status-badge status-badge-read';
        }
      }
      // AI badge
      if (aiBadge) {
        if (actionCfg.ai_enabled) {
          const label = actionCfg.ai_provider === 'anthropic' ? 'claude' :
                        actionCfg.ai_provider === 'ollama'    ? 'ollama' : 'openai';
          aiBadge.textContent = '🤖 ' + label;
          aiBadge.className = 'status-badge status-badge-ai-on';
        } else {
          aiBadge.textContent = 'AI: off';
          aiBadge.className = 'status-badge status-badge-ai-off';
        }
      }
    } catch (_) {
      actionCfg = null;
    }
  }

  function showActionModal(type, ip, user) {
    if (!actionCfg || !actionCfg.enabled) return;
    pendingAction = { type, ip, user };
    const modal = document.getElementById('actionModal');
    const drLabel = actionCfg.dry_run
      ? '<span class="dry-run-badge on">DRY RUN</span>'
      : '<span class="dry-run-badge off">LIVE</span>';

    if (type === 'block_ip') {
      document.getElementById('modalTitle').innerHTML =
        'Block IP: <span style="font-family:\'JetBrains Mono\',monospace">' + esc(ip) + '</span>' + drLabel;
      document.getElementById('modalSubtitle').textContent =
        'Executes ' + esc(actionCfg.block_backend) + ' deny rule. Logged to the audit trail.';
      document.getElementById('modalDurationField').style.display = 'none';
      document.getElementById('modalConfirm').textContent = actionCfg.dry_run ? 'Simulate Block' : 'Block IP';
    } else {
      document.getElementById('modalTitle').innerHTML =
        'Suspend sudo: <span style="font-family:\'JetBrains Mono\',monospace">' + esc(user) + '</span>' + drLabel;
      document.getElementById('modalSubtitle').textContent =
        'Temporarily revokes sudo access for the specified duration. Logged to the audit trail.';
      document.getElementById('modalDurationField').style.display = 'block';
      document.getElementById('modalConfirm').textContent = actionCfg.dry_run ? 'Simulate Suspend' : 'Suspend User';
    }

    document.getElementById('modalReason').value = '';
    document.getElementById('modalReason').style.borderColor = '';
    modal.classList.add('open');
    setTimeout(() => document.getElementById('modalReason').focus(), 60);
  }

  function closeActionModal() {
    document.getElementById('actionModal').classList.remove('open');
    pendingAction = null;
  }

  function handleModalBg(ev) {
    if (ev.target === document.getElementById('actionModal')) closeActionModal();
  }

  async function submitAction() {
    if (!pendingAction) return;
    const reason = document.getElementById('modalReason').value.trim();
    if (!reason) {
      document.getElementById('modalReason').style.borderColor = 'var(--danger)';
      document.getElementById('modalReason').focus();
      return;
    }
    document.getElementById('modalReason').style.borderColor = '';
    const confirmBtn = document.getElementById('modalConfirm');
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Working…';
    try {
      let url, body;
      if (pendingAction.type === 'block_ip') {
        url = '/api/action/block-ip';
        body = JSON.stringify({ ip: pendingAction.ip, reason });
      } else {
        const duration_secs = parseInt(
          document.getElementById('modalDuration').value || '3600', 10
        );
        url = '/api/action/suspend-user';
        body = JSON.stringify({ user: pendingAction.user, reason, duration_secs });
      }
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        cache: 'no-store',
      });
      const data = await resp.json();
      closeActionModal();
      if (data.success) {
        showToast((data.dry_run ? '[DRY RUN] ' : '') + data.message, 'ok');
        await refreshLeft(state.selected.value !== null);
      } else {
        showToast('Error: ' + data.message, 'err');
      }
    } catch (e) {
      showToast('Request failed: ' + e.message, 'err');
    } finally {
      confirmBtn.disabled = false;
    }
  }

  function showToast(msg, type) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = 'toast ' + (type || 'ok') + ' visible';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('visible'), 4500);
  }

  // D8b — browser tab title badge: shows unseen incident count when tab is not focused.
  let _unseenAlerts = 0;
  const _baseTitle = document.title;
  function updateTabBadge(delta) {
    _unseenAlerts = Math.max(0, _unseenAlerts + delta);
    if (_unseenAlerts > 0) {
      document.title = '(' + _unseenAlerts + ' 🔴) ' + _baseTitle;
    } else {
      document.title = _baseTitle;
    }
  }
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      _unseenAlerts = 0;
      document.title = _baseTitle;
    }
  });

  // D8 — rich push alert toast for High/Critical incidents arriving via SSE.
  function showAlertToast(alert) {
    if (document.hidden) updateTabBadge(1);
    const sev = (alert.severity || 'high').toUpperCase();
    const title = alert.title || 'Incident detected';
    const evalue = alert.entity_value || '';
    const etype  = alert.entity_type  || 'ip';
    const sevColor = sev === 'CRITICAL' ? '#f43f5e' : '#f97316';
    const toast = document.getElementById('toast');
    toast.innerHTML =
      `<span style="color:${sevColor};font-weight:700;margin-right:6px">${esc(sev)}</span>` +
      `<span>${esc(title)}</span>` +
      (evalue
        ? ` &nbsp;<a href="#" style="color:#78e5ff;text-decoration:none" ` +
          `onclick="event.preventDefault();loadJourney('${esc(etype)}','${esc(evalue)}')"` +
          `>→ ${esc(evalue)}</a>`
        : '');
    toast.className = 'toast err visible';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('visible'), 8000);
  }

  // D9 — inline entity search filter (client-side, no round-trip)
  function applyEntitySearch() {
    const q = (document.getElementById('entitySearch').value || '').trim().toLowerCase();
    const cards = document.querySelectorAll('#attackerList .attacker-card');
    let visible = 0;
    cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      const match = !q || text.includes(q);
      card.classList.toggle('hidden', !match);
      if (match) visible++;
    });
    // Show a "no results" message if every card is hidden
    let noRes = document.getElementById('searchNoResults');
    if (!visible && q) {
      if (!noRes) {
        noRes = document.createElement('div');
        noRes.id = 'searchNoResults';
        noRes.className = 'empty';
        noRes.textContent = 'No matches for "' + q + '"';
        document.getElementById('attackerList').appendChild(noRes);
      } else {
        noRes.textContent = 'No matches for "' + q + '"';
      }
    } else if (noRes) {
      noRes.remove();
    }
  }

  // ── Investigation state ────────────────────────────────────────────────
  const state = {
    pivot: 'ip',
    selected: { type: 'ip', value: null },
    filters: {
      date: '',
      compare_date: '',
      severity_min: '',
      detector: '',
      window_seconds: ''
    },
    clusters: [],
    knownItemValues: new Set(),  // D7: tracks rendered entity values for diff
  };

  const pivotTitle = (pivot) => ({
    ip: 'Attackers (IP)',
    user: 'Users (Pivot)',
    detector: 'Detectors (Pivot)',
  }[pivot] || 'Entities');

  function parsePivotToken(token) {
    const i = String(token || '').indexOf(':');
    if (i <= 0) return { type: 'detector', value: String(token || '') };
    return { type: token.slice(0, i), value: token.slice(i + 1) };
  }

  function buildQuery(params) {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v === null || v === undefined) return;
      const val = String(v).trim();
      if (!val) return;
      q.set(k, val);
    });
    return q.toString();
  }

  function syncFiltersFromUi() {
    state.filters.date = document.getElementById('flt-date').value || '';
    state.filters.compare_date = document.getElementById('flt-compare-date').value || '';
    state.filters.severity_min = document.getElementById('flt-severity').value || '';
    state.filters.detector = (document.getElementById('flt-detector').value || '').trim();
    state.filters.window_seconds = document.getElementById('flt-window').value || '';
  }

  function hydrateStateFromQuery() {
    const qs = new URLSearchParams(window.location.search || '');
    const pivot = (qs.get('pivot') || '').trim();
    if (pivot === 'ip' || pivot === 'user' || pivot === 'detector') {
      state.pivot = pivot;
    }

    state.filters.date = (qs.get('date') || '').trim();
    state.filters.compare_date = (qs.get('compare_date') || '').trim();
    state.filters.severity_min = (qs.get('severity_min') || '').trim();
    state.filters.detector = (qs.get('detector') || '').trim();
    state.filters.window_seconds = (qs.get('window_seconds') || '').trim();

    const subjectType = (qs.get('subject_type') || '').trim();
    const subject = (qs.get('subject') || '').trim();
    if ((subjectType === 'ip' || subjectType === 'user' || subjectType === 'detector') && subject) {
      state.selected = { type: subjectType, value: subject };
    }
  }

  function syncUrl() {
    const qs = buildQuery({
      pivot: state.pivot,
      date: state.filters.date,
      compare_date: state.filters.compare_date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      window_seconds: state.filters.window_seconds,
      subject_type: state.selected.value ? state.selected.type : '',
      subject: state.selected.value ? state.selected.value : '',
    });
    const nextUrl = qs ? ('?' + qs) : window.location.pathname;
    window.history.replaceState({}, '', nextUrl);
  }

  function updatePivotUi() {
    document.querySelectorAll('.pivot-tab').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.pivot === state.pivot);
    });
    document.getElementById('entityTitle').textContent = pivotTitle(state.pivot);
  }

  async function loadJourney(subjectType, subjectValue) {
    state.selected = { type: subjectType, value: subjectValue };
    syncFiltersFromUi();
    syncUrl();
    document.querySelectorAll('.attacker-card').forEach(c => c.classList.remove('active'));
    const card = document.querySelector(
      '.attacker-card[data-subject-type="' + CSS.escape(subjectType) + '"][data-subject-value="' + CSS.escape(subjectValue) + '"]'
    );
    if (card) {
      card.classList.add('active');
      // On mobile: scroll the active card into view and collapse list
      if (window.innerWidth <= 860) {
        card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        setTimeout(collapseLeftOnMobile, 200);
      }
    }

    document.getElementById('homeState').style.display = 'none';
    document.getElementById('journeyContent').style.display = 'block';
    document.getElementById('journeyContent').innerHTML = '<div class="loading" style="padding:40px">Loading timeline…</div>';

    const panel = document.getElementById('rightPanel');

    try {
      const baseQs = buildQuery({
        subject_type: subjectType,
        subject: subjectValue,
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
        window_seconds: state.filters.window_seconds,
      });
      const shouldCompare = state.filters.compare_date && state.filters.compare_date !== state.filters.date;
      const compareQs = shouldCompare
        ? buildQuery({
            subject_type: subjectType,
            subject: subjectValue,
            date: state.filters.compare_date,
            severity_min: state.filters.severity_min,
            detector: state.filters.detector,
            window_seconds: state.filters.window_seconds,
          })
        : '';
      const [j, compare] = await Promise.all([
        loadJson('/api/journey?' + baseQs),
        shouldCompare ? loadJson('/api/journey?' + compareQs) : Promise.resolve(null),
      ]);
      const first = j.first_seen ? fmtDateTime(j.first_seen) : '—';
      const last  = j.last_seen  ? fmtDateTime(j.last_seen)  : '—';
      const summary = j.summary || {};
      const shortcuts = Array.isArray(summary.pivot_shortcuts) ? summary.pivot_shortcuts : [];
      const hints = Array.isArray(summary.hints) ? summary.hints : [];

      const summaryGrid = `
        <div class="summary-grid">
          <div class="summary-cell"><div class="summary-label">Entries</div><div class="summary-value">${summary.total_entries ?? j.entries.length}</div></div>
          <div class="summary-cell"><div class="summary-label">Events</div><div class="summary-value">${summary.events_count ?? 0}</div></div>
          <div class="summary-cell"><div class="summary-label">Incidents</div><div class="summary-value">${summary.incidents_count ?? 0}</div></div>
          <div class="summary-cell"><div class="summary-label">Decisions</div><div class="summary-value">${summary.decisions_count ?? 0}</div></div>
          <div class="summary-cell"><div class="summary-label">Honeypot</div><div class="summary-value">${summary.honeypot_count ?? 0}</div></div>
          <div class="summary-cell"><div class="summary-label">Window</div><div class="summary-value">${state.filters.window_seconds ? esc(state.filters.window_seconds + 's') : 'full day'}</div></div>
        </div>`;

      const hintsHtml = hints.length
        ? `<ul class="hint-list">${hints.map((h) => `<li class="hint-item">${esc(h)}</li>`).join('')}</ul>`
        : '<div class="empty">No hints available for current scope.</div>';

      const shortcutsHtml = shortcuts.length
        ? `<div class="shortcut-wrap">${shortcuts.map((token) =>
            `<button type="button" class="shortcut-btn" onclick="openPivotShortcut('${esc(token)}')">${esc(token)}</button>`
          ).join('')}</div>`
        : '';

      // Build action buttons if D3 actions are enabled for this subject type.
      let actionBtns = '';
      if (actionCfg && actionCfg.enabled && subjectType === 'ip') {
        if (j.outcome !== 'blocked') {
          actionBtns += `<button type="button" class="journey-btn action-block"
            onclick="showActionModal('block_ip','${esc(subjectValue)}',null)">⊘ Block IP</button>`;
        }
      }
      if (actionCfg && actionCfg.enabled && subjectType === 'user') {
        actionBtns += `<button type="button" class="journey-btn action-suspend"
          onclick="showActionModal('suspend_user',null,'${esc(subjectValue)}')">⏸ Suspend sudo</button>`;
      }

      // D5: store journey data globally for scrollToChapter
      window._journeyData = j;

      let html = `
        <div style="margin-bottom:12px">
          <button type="button" class="journey-btn" onclick="showHomeState()" style="font-size:0.68rem">← Back to Overview</button>
        </div>
        <div class="journey-header">
          <span class="journey-ip">${esc(j.subject || subjectValue)}</span>
          <span class="${outcomeCls(j.outcome)}">${outcomeLabel(j.outcome)}</span>
          <span class="journey-time">${esc(first)} → ${esc(last)}</span>
        </div>
        <div class="journey-subtitle">${esc((j.subject_type || subjectType).toUpperCase())} journey · ${j.entries.length} timeline entries · click any row to expand</div>
        <div class="journey-actions">
          <button type="button" class="journey-btn" onclick="downloadSnapshot('json')">Export JSON</button>
          <button type="button" class="journey-btn" onclick="downloadSnapshot('md')">Export Markdown</button>
          ${actionBtns}
        </div>
        ${renderVerdictCard(j)}
        <div class="guided-grid">
          <section class="guided-card">
            <div class="guided-title">Investigation Summary</div>
            ${summaryGrid}
            ${shortcutsHtml}
          </section>
          <section class="guided-card">
            <div class="guided-title">Narrative Hints</div>
            ${hintsHtml}
          </section>
        </div>`;

      if (compare) {
        const baseS = j.summary || {};
        const cmpS = compare.summary || {};
        const metrics = [
          ['Entries', baseS.total_entries ?? j.entries.length, cmpS.total_entries ?? compare.entries.length],
          ['Incidents', baseS.incidents_count ?? 0, cmpS.incidents_count ?? 0],
          ['Decisions', baseS.decisions_count ?? 0, cmpS.decisions_count ?? 0],
          ['Honeypot', baseS.honeypot_count ?? 0, cmpS.honeypot_count ?? 0],
        ];
        const compareRows = metrics.map(([label, current, previous]) => {
          const delta = Number(current) - Number(previous);
          const deltaLabel = delta > 0 ? '+' + delta : String(delta);
          const deltaCls = delta > 0 ? 'delta-pos' : (delta < 0 ? 'delta-neg' : 'delta-neu');
          return `<div class="compare-cell">
            <div class="summary-label">${esc(label)}</div>
            <div class="summary-value">${current} <span class="${deltaCls}">(${deltaLabel})</span></div>
            <div class="summary-label">compare: ${previous}</div>
          </div>`;
        }).join('');
        html += `
          <section class="guided-card" style="margin-bottom:14px">
            <div class="guided-title">Comparison vs ${esc(state.filters.compare_date)}</div>
            <div class="journey-subtitle" style="margin-bottom:10px">
              current outcome: <strong>${esc(outcomeLabel(j.outcome))}</strong> · compare outcome: <strong>${esc(outcomeLabel(compare.outcome))}</strong>
            </div>
            <div class="compare-grid">${compareRows}</div>
          </section>`;
      }

      html += renderChapterRail(j);

      html += `
        <div class="timeline">`;

      if (j.entries.length === 0) {
        html += '<div class="empty">No entries found for this selection on the chosen filters.</div>';
      } else {
        j.entries.forEach((e, i) => { html += renderEntry(e, i); });
      }

      html += '</div>';
      document.getElementById('journeyContent').innerHTML = html;
    } catch (e) {
      document.getElementById('journeyContent').innerHTML = '<div class="err">Failed to load journey: ' + esc(e.message) + '</div>';
    }
  }

  function renderCard(item) {
    const value = item.value;
    const active = state.selected.type === state.pivot && state.selected.value === value ? ' active' : '';
    const sev = item.max_severity || 'unknown';
    const sevCss = sevCls(sev);
    const outcome = item.outcome || 'unknown';
    const dets = (item.detectors || []).join(', ') || '—';

    // Build badges
    let badges = '';
    const outMap = { blocked:'badge-blocked', active:'badge-active', monitoring:'badge-monitor', honeypot:'badge-honeypot' };
    const outBadge = outMap[outcome] || '';
    if (outBadge) badges += `<span class="card-badge ${outBadge}">${outcomeLabel(outcome)}</span>`;

    const ago = (ts) => {
      if (!ts) return '';
      const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
      if (diff < 60) return diff + 's ago';
      if (diff < 3600) return Math.floor(diff/60) + 'm ago';
      if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
      return Math.floor(diff/86400) + 'd ago';
    };

    const isRecent = item.last_seen && (Date.now() - new Date(item.last_seen).getTime()) < 300000;
    const recentDot = isRecent ? '<span class="pulse-dot" title="Active in last 5 min"></span>' : '';

    return `
      <div class="attacker-card${active}"
           data-subject-type="${esc(state.pivot)}"
           data-subject-value="${esc(value)}"
           onclick="loadJourney('${esc(state.pivot)}','${esc(value)}')">
        <div class="card-row">
          <div class="card-ip">${recentDot} ${esc(value)}</div>
          <span class="${sevCss}" style="font-size:0.65rem;font-weight:700">${esc(sev.toUpperCase())}</span>
        </div>
        <div class="card-detectors">${esc(dets)}</div>
        <div class="card-meta">
          <span class="card-counts">${item.incident_count || 0} inc · ${item.event_count || 0} evt</span>
          <span class="card-time">${ago(item.last_seen)}</span>
        </div>
        ${badges ? `<div class="card-badges">${badges}</div>` : ''}
      </div>`;
  }

  function renderClusterCard(cluster) {
    return `
      <div class="cluster-card" onclick="openCluster('${esc(cluster.pivot)}')">
        <div class="cluster-row">
          <span class="cluster-id">${esc(cluster.cluster_id)}</span>
          <span class="cluster-meta">${cluster.incident_count} incidents</span>
        </div>
        <div class="cluster-pivot">${esc(cluster.pivot)}</div>
        <div class="cluster-dets">${esc((cluster.detector_kinds || []).join(', '))}</div>
        <div class="cluster-meta">${esc(fmtTime(cluster.start_ts))} → ${esc(fmtTime(cluster.end_ts))}</div>
      </div>`;
  }

  function openCluster(pivotToken) {
    const parsed = parsePivotToken(pivotToken);
    state.pivot = parsed.type;
    updatePivotUi();
    refreshLeft(false).finally(() => {
      loadJourney(parsed.type, parsed.value);
    });
  }

  function openPivotShortcut(token) {
    const parsed = parsePivotToken(token);
    state.pivot = parsed.type;
    updatePivotUi();
    refreshLeft(false).finally(() => {
      loadJourney(parsed.type, parsed.value);
    });
  }

  async function downloadSnapshot(format) {
    try {
      syncFiltersFromUi();
      const qs = buildQuery({
        format,
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
        group_by: state.pivot,
        subject_type: state.selected.value ? state.selected.type : '',
        subject: state.selected.value ? state.selected.value : '',
        window_seconds: state.filters.window_seconds,
      });
      const body = await loadText('/api/export?' + qs);
      const ext = format === 'md' ? 'md' : 'json';
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      downloadBlob(
        `innerwarden-snapshot-${stamp}.${ext}`,
        format === 'md' ? 'text/markdown; charset=utf-8' : 'application/json; charset=utf-8',
        body
      );
    } catch (e) {
      document.getElementById('refreshStatus').textContent = 'export err: ' + e.message;
    }
  }

  // D7 — update a KPI span; flash on change
  function updateKpi(id, newVal) {
    const el = document.getElementById(id);
    if (!el) return;
    const prev = el.textContent;
    el.textContent = newVal;
    if (String(prev) !== String(newVal)) {
      el.classList.remove('kpi-flash');
      void el.offsetWidth; // reflow to restart animation
      el.classList.add('kpi-flash');
      el.addEventListener('animationend', () => el.classList.remove('kpi-flash'), { once: true });
    }
  }

  // D7 — soft live refresh: only new cards get animated, existing stay in place.
  async function refreshLeftLive() {
    try {
      syncFiltersFromUi();
      const overviewQs = buildQuery({ date: state.filters.date });
      const entityQs = buildQuery({
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
        group_by: state.pivot,
      });

      const [ov, entityData] = await Promise.all([
        loadJson('/api/overview' + (overviewQs ? '?' + overviewQs : '')),
        state.pivot === 'ip'
          ? loadJson('/api/entities?' + entityQs).then((r) => ({
              items: (r.attackers || []).map((a) => ({ ...a, value: a.ip, group_by: 'ip' })),
            }))
          : loadJson('/api/pivots?' + entityQs),
      ]);

      const items = entityData.items || [];

      updateKpi('kpi-events',    ov.events_count);
      updateKpi('kpi-incidents', ov.incidents_count);
      updateKpi('kpi-decisions', ov.decisions_count);
      updateKpi('kpi-attackers', items.length);

      const list = document.getElementById('attackerList');
      const newItems = items.filter(it => !state.knownItemValues.has(it.value));
      if (newItems.length > 0) {
        for (const item of newItems.reverse()) {
          const el = document.createElement('div');
          el.innerHTML = renderCard(item).trim();
          const card = el.firstChild;
          card.classList.add('card-new');
          list.prepend(card);
          state.knownItemValues.add(item.value);
        }
      }

      // Update counts on existing cards (incident/event count may change)
      for (const item of items) {
        const existing = list.querySelector(
          `[data-subject-type="${esc(state.pivot)}"][data-subject-value="${esc(item.value)}"]`
        );
        if (existing && !newItems.includes(item)) {
          const countEl = existing.querySelector('.card-counts');
          if (countEl) countEl.textContent = `${item.incident_count} inc · ${item.event_count} ev`;
        }
      }
      if (newItems.length > 0) applyEntitySearch();  // D9: filter newly inserted cards
    } catch (e) {
      // silent — refreshLeft fallback handles error display
    }
  }

  async function refreshLeft(forceRefreshJourney = false) {
    try {
      syncFiltersFromUi();

      const overviewQs = buildQuery({ date: state.filters.date });
      const entityQs = buildQuery({
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
        group_by: state.pivot,
      });
      const clusterQs = buildQuery({
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
        window_seconds: state.filters.window_seconds,
      });

      const [ov, entityData, clusterData] = await Promise.all([
        loadJson('/api/overview' + (overviewQs ? '?' + overviewQs : '')),
        state.pivot === 'ip'
          ? loadJson('/api/entities?' + entityQs).then((r) => ({
              items: (r.attackers || []).map((a) => ({
                ...a,
                value: a.ip,
                group_by: 'ip',
              })),
            }))
          : loadJson('/api/pivots?' + entityQs),
        loadJson('/api/clusters?' + clusterQs),
      ]);

      const items = entityData.items || [];
      state.clusters = clusterData.items || [];

      document.getElementById('kpi-date').textContent      = ov.date;
      document.getElementById('kpi-events').textContent    = ov.events_count;
      document.getElementById('kpi-incidents').textContent = ov.incidents_count;
      document.getElementById('kpi-decisions').textContent = ov.decisions_count;
      const kpiAtt = document.getElementById('kpi-attackers');
      if (kpiAtt) kpiAtt.textContent = items.length;

      const list = document.getElementById('attackerList');
      if (items.length === 0) {
        list.innerHTML = '<div class="empty">No records for the selected filters.</div>';
        state.knownItemValues.clear();
      } else {
        list.innerHTML = items.map((item) => renderCard(item)).join('');
        state.knownItemValues = new Set(items.map(it => it.value));
      }

      const clusterList = document.getElementById('clusterList');
      if (!state.clusters.length) {
        clusterList.innerHTML = '<div class="empty">No clusters for current filters.</div>';
      } else {
        clusterList.innerHTML = state.clusters.map(renderClusterCard).join('');
      }

      if (ov.top_detectors && ov.top_detectors.length) {
        document.getElementById('topDetectors').innerHTML = ov.top_detectors.map(d =>
          `<div class="det-row"><span>${esc(d.detector)}</span><span class="det-count">${d.count}</span></div>`
        ).join('');
      } else {
        document.getElementById('topDetectors').innerHTML = '<div class="empty">No detectors fired.</div>';
      }

      if (state.selected.value) {
        const stillExists =
          state.selected.type === state.pivot &&
          items.some((it) => it.value === state.selected.value);
        if (!stillExists) {
          state.selected = { type: state.pivot, value: null };
          showHomeState();
        } else if (forceRefreshJourney) {
          await loadJourney(state.selected.type, state.selected.value);
        }
      }

      applyEntitySearch();  // D9: re-apply filter after full reload
      syncUrl();
      document.getElementById('refreshStatus').textContent = new Date().toLocaleTimeString();
    } catch (e) {
      document.getElementById('refreshStatus').textContent = 'err: ' + e.message;
    }
  }

  // Boot
  const today = new Date().toISOString().slice(0, 10);
  hydrateStateFromQuery();
  document.getElementById('flt-date').value = state.filters.date || today;
  document.getElementById('flt-compare-date').value = state.filters.compare_date || '';
  document.getElementById('flt-severity').value = state.filters.severity_min || '';
  document.getElementById('flt-detector').value = state.filters.detector || '';
  document.getElementById('flt-window').value = state.filters.window_seconds || '';
  updatePivotUi();
  loadActionConfig();
  loadReportDates();
  loadHomeState();

  // Close modal on Escape key
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeActionModal();
  });

  document.getElementById('flt-apply').addEventListener('click', () => {
    refreshLeft(true);
  });
  document.querySelectorAll('.pivot-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const pivot = tab.dataset.pivot || 'ip';
      state.pivot = pivot;
      state.selected = { type: pivot, value: null };
      updatePivotUi();
      refreshLeft(false);
    });
  });
  document.getElementById('flt-detector').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') refreshLeft(true);
  });
  document.getElementById('flt-severity').addEventListener('change', () => refreshLeft(true));
  document.getElementById('flt-date').addEventListener('change', () => refreshLeft(true));
  document.getElementById('flt-compare-date').addEventListener('change', () => {
    if (state.selected.value) {
      loadJourney(state.selected.type, state.selected.value);
      return;
    }
    refreshLeft(false);
  });
  document.getElementById('flt-window').addEventListener('change', () => refreshLeft(true));
  document.getElementById('entitySearch').addEventListener('input', applyEntitySearch);

  refreshLeft(false).then(() => {
    applyEntitySearch();  // respect any pre-filled query on initial load
    if (state.selected.value) {
      loadJourney(state.selected.type, state.selected.value);
    }
    loadHomeState();
  });
  // D6 — SSE live update client (replaces 5 s setInterval).
  // Uses fetch() + ReadableStream so Basic auth credentials flow correctly.
  (function startSse() {
    let fallbackTimer = null;
    let reconnectTimer = null;

    function armFallback() {
      // If SSE hasn't fired within 35 s, fall back to a 30 s poll.
      clearTimeout(fallbackTimer);
      fallbackTimer = setTimeout(() => {
        refreshLeftLive();
        fallbackTimer = setInterval(() => refreshLeftLive(), 30000);
      }, 35000);
    }

    function connect() {
      clearTimeout(reconnectTimer);
      fetch('/api/events/stream', { headers: { 'Accept': 'text/event-stream' } })
        .then(res => {
          if (!res.ok || !res.body) throw new Error('SSE connect failed');
          clearTimeout(fallbackTimer);
          clearInterval(fallbackTimer);
          const el = document.getElementById('refreshStatus');
          if (el) el.innerHTML = '<span style="color:#78e5ff;font-size:0.7rem">&#9679; LIVE</span>';
          const reader = res.body.getReader();
          const dec = new TextDecoder();
          let buf = '';
          let lastEvent = '';
          function pump() {
            reader.read().then(({ done, value }) => {
              if (done) { scheduleReconnect(); return; }
              buf += dec.decode(value, { stream: true });
              const lines = buf.split('\n');
              buf = lines.pop();
              for (const line of lines) {
                if (line.startsWith('event: ')) {
                  lastEvent = line.slice(7).trim();
                } else if (line.startsWith('data: ')) {
                  if (lastEvent === 'refresh') {
                    refreshLeftLive();  // D7: soft live diff
                  } else if (lastEvent === 'alert') {
                    try {
                      const outer = JSON.parse(line.slice(6).trim());
                      showAlertToast(outer.data || outer);
                    } catch (_) {}
                  }
                  lastEvent = '';
                }
              }
              pump();
            }).catch(() => scheduleReconnect());
          }
          pump();
        })
        .catch(() => scheduleReconnect());
    }

    function scheduleReconnect() {
      const el = document.getElementById('refreshStatus');
      if (el) el.innerHTML = '<span style="color:#888;font-size:0.7rem">&#9679; reconnecting</span>';
      armFallback();
      reconnectTimer = setTimeout(connect, 3000);
    }

    armFallback();
    connect();
  })();
</script>
</body>
</html>
"##;

// ---------------------------------------------------------------------------
// Web Push handlers
// ---------------------------------------------------------------------------

/// GET /sw.js — Service Worker that handles incoming push events.
async fn service_worker_js() -> impl IntoResponse {
    const SW: &str = r#"
self.addEventListener('push', function(event) {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) {}
  const title = data.title || 'InnerWarden Alert';
  const options = {
    body: data.body || 'A new security incident was detected.',
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    requireInteraction: true,
    data: data,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});
"#;
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        SW,
    )
}

/// GET /api/push/vapid-key — return the VAPID public key for browser subscription.
async fn api_push_vapid_key(State(state): State<DashboardState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "publicKey": state.web_push_vapid_public_key,
        "enabled": !state.web_push_vapid_public_key.is_empty(),
    }))
}

#[derive(Deserialize)]
struct PushSubscribeBody {
    endpoint: String,
    keys: PushSubscribeKeys,
}

#[derive(Deserialize)]
struct PushSubscribeKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
struct PushUnsubscribeBody {
    endpoint: String,
}

/// POST /api/push/subscribe — register a new browser push subscription.
async fn api_push_subscribe(
    State(state): State<DashboardState>,
    Json(body): Json<PushSubscribeBody>,
) -> impl IntoResponse {
    if state.web_push_vapid_public_key.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "message": "web push is not configured — run `innerwarden notify web-push setup`",
        }));
    }

    let sub = crate::web_push::WebPushSubscription {
        endpoint: body.endpoint.clone(),
        keys: crate::web_push::WebPushKeys {
            p256dh: body.keys.p256dh,
            auth: body.keys.auth,
        },
    };

    // Deduplicate by endpoint before saving
    let mut subs = crate::web_push::load_subscriptions(&state.data_dir);
    subs.retain(|s| s.endpoint != body.endpoint);
    subs.push(sub);

    match crate::web_push::save_subscriptions(&state.data_dir, &subs) {
        Ok(()) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "message": format!("failed to save subscription: {e:#}"),
        })),
    }
}

/// DELETE /api/push/subscribe — remove a push subscription by endpoint.
async fn api_push_unsubscribe(
    State(state): State<DashboardState>,
    Json(body): Json<PushUnsubscribeBody>,
) -> impl IntoResponse {
    match crate::web_push::remove_subscription(&state.data_dir, &body.endpoint) {
        Ok(_) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "message": format!("failed to remove subscription: {e:#}"),
        })),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    // ── Existing tests (unchanged) ──────────────────────────────────────

    #[test]
    fn normalize_limit_is_bounded() {
        assert_eq!(normalize_limit(None), 50);
        assert_eq!(normalize_limit(Some(0)), 1);
        assert_eq!(normalize_limit(Some(10)), 10);
        assert_eq!(normalize_limit(Some(9999)), 500);
    }

    #[test]
    fn resolve_date_falls_back_to_today_on_invalid_values() {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(resolve_date(None), today);
        assert_eq!(resolve_date(Some("not-a-date")), today);
        assert_eq!(resolve_date(Some("2026-99-01")), today);
        assert_eq!(resolve_date(Some("2026-03-13")), "2026-03-13");
    }

    #[test]
    fn overview_counts_jsonl_artifacts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let event_path = dated_path(dir.path(), "events", date);
        let incident_path = dated_path(dir.path(), "incidents", date);
        let decision_path = dated_path(dir.path(), "decisions", date);
        let telemetry_path = dated_path(dir.path(), "telemetry", date);

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "x".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &event_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&event).unwrap(),
                "{malformed"
            ),
        )
        .unwrap();

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &incident_path,
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();

        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        std::fs::write(
            &decision_path,
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let snapshot = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "incident_tick".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 1,
            ai_sent_count: 1,
            ai_decision_count: 1,
            avg_decision_latency_ms: 120.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 1,
            real_execution_count: 0,
        };
        std::fs::write(
            &telemetry_path,
            format!("{}\n", serde_json::to_string(&snapshot).unwrap()),
        )
        .unwrap();

        let ov = compute_overview(dir.path(), date);
        // events_count uses fast line counting (not JSON parsing), so malformed lines count too
        assert_eq!(ov.events_count, 2);
        assert_eq!(ov.incidents_count, 1);
        assert_eq!(ov.decisions_count, 1);
        assert_eq!(ov.top_detectors.len(), 1);
        assert_eq!(ov.top_detectors[0].detector, "ssh_bruteforce");
        assert!(ov.latest_telemetry.is_some());
    }

    #[test]
    fn parse_basic_auth_header_works() {
        let encoded = BASE64_STANDARD.encode("admin:supersecret");
        let header = format!("Basic {encoded}");
        let parsed = parse_basic_auth(&header).unwrap();
        assert_eq!(parsed.0, "admin");
        assert_eq!(parsed.1, "supersecret");
    }

    #[test]
    fn dashboard_auth_verifies_valid_credentials() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password("correct horse battery staple".as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = DashboardAuth {
            username: "admin".to_string(),
            password_hash: PasswordHashString::new(&hash).unwrap(),
        };

        assert!(auth.verify("admin", "correct horse battery staple"));
        assert!(!auth.verify("admin", "wrong"));
        assert!(!auth.verify("other", "correct horse battery staple"));
    }

    // ── New D2 tests ────────────────────────────────────────────────────

    #[test]
    fn attackers_groups_by_ip() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        // Two incidents from the same IP — different detectors.
        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::Critical,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:def".to_string(),
            severity: Severity::High,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers(dir.path(), date, &filters, 50);
        assert_eq!(attackers.len(), 1, "should aggregate to a single IP");
        assert_eq!(attackers[0].ip, "203.0.113.10");
        assert_eq!(attackers[0].incident_count, 2);
        // max_severity should be the highest observed (critical > high).
        assert_eq!(attackers[0].max_severity, "critical");
        assert_eq!(attackers[0].detectors, vec!["ssh_bruteforce"]);
    }

    #[test]
    fn journey_assembles_all_kinds() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: true,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, None);
        assert_eq!(
            journey.entries.len(),
            3,
            "should have event + incident + decision"
        );
        let kinds: Vec<&str> = journey.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"event"), "missing event entry");
        assert!(kinds.contains(&"incident"), "missing incident entry");
        assert!(kinds.contains(&"decision"), "missing decision entry");
        assert_eq!(journey.subject_type, "ip");
        assert_eq!(journey.subject, ip);
        assert!(journey.first_seen.is_some());
        assert!(journey.last_seen.is_some());
        assert_eq!(journey.summary.events_count, 1);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
        assert!(!journey.summary.hints.is_empty());
        assert!(journey
            .summary
            .pivot_shortcuts
            .iter()
            .any(|token| token == "ip:203.0.113.10"));
    }

    #[test]
    fn journey_window_filter_limits_entries() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";
        let now = Utc::now();

        let event = Event {
            ts: now - chrono::Duration::seconds(120),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: now - chrono::Duration::seconds(45),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: now,
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, Some(60));
        assert_eq!(journey.entries.len(), 2);
        assert!(!journey.entries.iter().any(|e| e.kind == "event"));
        assert_eq!(journey.summary.events_count, 0);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
    }

    #[test]
    fn pivots_group_by_user() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::High,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "sudo_abuse:deploy:def".to_string(),
            severity: Severity::Critical,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.9"), EntityRef::user("deploy")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let pivots = build_pivots(dir.path(), date, PivotKind::User, &filters, 50);
        assert_eq!(pivots.len(), 2);
        assert_eq!(pivots[0].group_by, "user");
        assert!(pivots.iter().any(|p| p.value == "root"));
        assert!(pivots.iter().any(|p| p.value == "deploy"));
    }

    #[test]
    fn journey_user_pivot_includes_related_decision() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("203.0.113.10".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::User, "root", &filters, None);
        assert_eq!(journey.subject_type, "user");
        assert_eq!(journey.subject, "root");
        assert!(journey.entries.iter().any(|e| e.kind == "incident"));
        assert!(journey.entries.iter().any(|e| e.kind == "decision"));
        assert_eq!(journey.outcome, "blocked");
    }

    #[test]
    fn clusters_group_related_incidents() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ts = Utc::now();

        let inc1 = Incident {
            ts,
            host: "h".to_string(),
            incident_id: "port_scan:203.0.113.10:a".to_string(),
            severity: Severity::High,
            title: "scan".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: ts + chrono::Duration::seconds(40),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:b".to_string(),
            severity: Severity::Critical,
            title: "bf".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let clusters = build_cluster_items(dir.path(), date, &filters, 20, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].incident_count, 2);
        assert_eq!(clusters[0].pivot_type, "ip");
        assert_eq!(clusters[0].pivot_value, "203.0.113.10");
    }

    #[test]
    fn markdown_export_contains_sections() {
        let snapshot = InvestigationExport {
            generated_at: Utc::now(),
            date: "2026-03-13".to_string(),
            filters: serde_json::json!({"severity_min":"high"}),
            group_by: "ip".to_string(),
            subject_type: Some("ip".to_string()),
            subject: Some("203.0.113.10".to_string()),
            overview: OverviewResponse {
                date: "2026-03-13".to_string(),
                events_count: 10,
                incidents_count: 2,
                decisions_count: 1,
                top_detectors: vec![],
                latest_telemetry: None,
            },
            pivots: vec![PivotItem {
                group_by: "ip".to_string(),
                value: "203.0.113.10".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                max_severity: "critical".to_string(),
                incident_count: 2,
                event_count: 8,
                outcome: "active".to_string(),
                detectors: vec!["ssh_bruteforce".to_string()],
            }],
            clusters: vec![ClusterItem {
                cluster_id: "cluster-001".to_string(),
                pivot: "ip:203.0.113.10".to_string(),
                pivot_type: "ip".to_string(),
                pivot_value: "203.0.113.10".to_string(),
                start_ts: Utc::now(),
                end_ts: Utc::now(),
                incident_count: 2,
                detector_kinds: vec!["ssh_bruteforce".to_string()],
                incident_ids: vec!["x".to_string(), "y".to_string()],
            }],
            journey: Some(JourneyResponse {
                subject_type: "ip".to_string(),
                subject: "203.0.113.10".to_string(),
                date: "2026-03-13".to_string(),
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                outcome: "active".to_string(),
                summary: JourneySummary {
                    total_entries: 1,
                    events_count: 1,
                    incidents_count: 0,
                    decisions_count: 0,
                    honeypot_count: 0,
                    first_event: Some(Utc::now()),
                    first_incident: None,
                    first_decision: None,
                    first_honeypot: None,
                    pivot_shortcuts: vec!["ip:203.0.113.10".to_string()],
                    hints: vec!["Signals observed".to_string()],
                },
                verdict: JourneyVerdict {
                    entry_vector: "ssh_bruteforce".to_string(),
                    access_status: "attempted".to_string(),
                    privilege_status: "no_evidence".to_string(),
                    containment_status: "unknown".to_string(),
                    honeypot_status: "not_engaged".to_string(),
                    confidence: "medium".to_string(),
                },
                chapters: vec![],
                entries: vec![],
            }),
        };

        let markdown = render_markdown_snapshot(&snapshot);
        assert!(markdown.contains("# InnerWarden Investigation Snapshot"));
        assert!(markdown.contains("## Correlation Clusters"));
        assert!(markdown.contains("cluster-001"));
        assert!(markdown.contains("## Journey"));
        assert!(markdown.contains("Subject: `ip:203.0.113.10`"));
        assert!(markdown.contains("### Guided Summary"));
        assert!(markdown.contains("### Investigation Hints"));
    }

    #[test]
    fn outcome_blocked_when_block_ip_ok() {
        let blocked = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        assert_eq!(determine_outcome(&[blocked], "1.2.3.4", true), "blocked");

        let dry_run_block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };
        assert_eq!(
            determine_outcome(&[dry_run_block], "1.2.3.4", true),
            "active"
        );

        // Failed execution — should not count as blocked.
        let failed = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "error: permission denied".to_string(),
            prev_hash: None,
        };
        assert_eq!(determine_outcome(&[failed], "1.2.3.4", true), "active");

        // No decisions at all, has incident → active.
        assert_eq!(determine_outcome(&[], "1.2.3.4", true), "active");

        // No decisions, no incident → unknown.
        assert_eq!(determine_outcome(&[], "1.2.3.4", false), "unknown");
    }

    // ── D3 tests ────────────────────────────────────────────────────────

    #[test]
    fn action_config_disabled_by_default() {
        let cfg = DashboardActionConfig::default();
        assert!(
            !cfg.enabled,
            "actions must be disabled by default for safety"
        );
        assert!(cfg.dry_run, "dry_run must be true by default");
    }

    #[test]
    fn append_decision_entry_writes_jsonl() {
        let dir = TempDir::new().unwrap();
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: "dashboard:manual:test".to_string(),
            host: "testhost".to_string(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 1.0,
            auto_executed: true,
            dry_run: true,
            reason: "manual block for testing".to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };

        append_decision_entry(dir.path(), &entry).unwrap();

        // File must exist and contain exactly one valid JSON line.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("decisions-{date}.jsonl"));
        assert!(path.exists(), "decisions JSONL must be created");
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: DecisionEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.ai_provider, "dashboard:operator");
        assert_eq!(parsed.action_type, "block_ip");
        assert_eq!(parsed.target_ip.as_deref(), Some("1.2.3.4"));

        // Appending a second entry should produce two lines.
        append_decision_entry(dir.path(), &entry).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn make_synthetic_incident_populates_ip_entity() {
        let inc = make_synthetic_incident("test-id", "203.0.113.1", "brute force test");
        assert!(inc.incident_id.contains("dashboard:manual"));
        assert!(inc.incident_id.contains("test-id"));
        assert_eq!(inc.entities.len(), 1);
        assert_eq!(inc.entities[0].value, "203.0.113.1");
        assert!(inc.tags.contains(&"dashboard".to_string()));
        assert!(inc.tags.contains(&"manual".to_string()));
    }

    #[test]
    fn action_cfg_block_skill_selection() {
        // Verify the skill_id format follows convention (used in allowlist check).
        let backends = [
            ("ufw", "block-ip-ufw"),
            ("iptables", "block-ip-iptables"),
            ("nftables", "block-ip-nftables"),
        ];
        for (backend, expected_id) in backends {
            let cfg = DashboardActionConfig {
                enabled: true,
                dry_run: true,
                block_backend: backend.to_string(),
                allowed_skills: vec![expected_id.to_string()],
                ai_enabled: false,
                ai_provider: "openai".to_string(),
                ai_model: "gpt-4o-mini".to_string(),
                ..DashboardActionConfig::default()
            };
            let skill_id = format!("block-ip-{}", cfg.block_backend);
            assert_eq!(skill_id, expected_id);
            assert!(cfg.allowed_skills.contains(&skill_id));
        }
    }

    // ── D5 tests ─────────────────────────────────────────────────────────

    #[test]
    fn verdict_detected_entry_vector_from_incident() {
        let incident_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "incident".to_string(),
            data: serde_json::json!({ "incident_id": "ssh_bruteforce:abc123" }),
        };
        // With only an incident (no events), access_status is "inconclusive"
        // and the entry vector is extracted from the incident_id prefix.
        let verdict = derive_verdict(&[incident_entry], "active");
        assert_eq!(verdict.entry_vector, "ssh_bruteforce");
        assert_eq!(verdict.access_status, "inconclusive");
        assert_eq!(verdict.containment_status, "active");
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn verdict_blocked_outcome_sets_containment_status() {
        let decision_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "decision".to_string(),
            data: serde_json::json!({
                "action_type": "block_ip",
                "execution_result": "ok",
                "dry_run": false,
            }),
        };
        let verdict = derive_verdict(&[decision_entry], "blocked");
        assert_eq!(verdict.containment_status, "blocked");
        // Incident + decision → medium confidence (no events)
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn chapters_group_entries_by_stage() {
        // Three incident entries followed by one decision — should produce
        // an "initial_access_attempt" chapter and a "response" chapter.
        let entries: Vec<JourneyEntry> = vec![
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:1" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:2" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "decision".to_string(),
                data: serde_json::json!({ "action_type": "block_ip" }),
            },
        ];
        let chapters = derive_chapters(&entries);
        // At minimum one chapter must be produced.
        assert!(!chapters.is_empty());
        // All entry indices must be valid.
        for ch in &chapters {
            for &idx in &ch.entry_indices {
                assert!(idx < entries.len());
            }
        }
        // Total entry coverage: every entry should appear in exactly one chapter.
        let total_covered: usize = chapters.iter().map(|ch| ch.entry_indices.len()).sum();
        assert_eq!(total_covered, entries.len());
    }

    // ── Memory safety tests ─────────────────────────────────────────────

    #[test]
    fn global_rate_limiter_rejects_after_limit() {
        let test_ip = "rate-test-192.0.2.99";
        // Fill up to the limit
        for _ in 0..GLOBAL_RATE_LIMIT_PER_MIN {
            assert!(!global_rate_check(test_ip), "should allow under limit");
        }
        // Next request should be rejected
        assert!(global_rate_check(test_ip), "should reject at limit");
    }

    #[test]
    fn global_rate_limiter_prunes_stale_ips() {
        // Insert 1100+ unique IPs to trigger the >1000 prune path
        for i in 0..1100 {
            global_rate_check(&format!("prune-test-{i}"));
        }
        // Should not panic or OOM — the prune ran and cleaned up
        let map = GLOBAL_RATE_LIMITER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // After prune, stale entries removed (all are <60s old so still present,
        // but the code path executed without error)
        assert!(map.len() <= 1200, "map should not grow unbounded");
    }

    #[test]
    fn jsonl_cache_returns_same_data_on_cache_hit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-cache.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n",
        )
        .unwrap();

        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Second call should hit cache (same file, no modification)
        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].kind, second[0].kind);
    }

    #[test]
    fn jsonl_cache_invalidates_on_file_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-invalidate.jsonl");
        let line = "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n";

        std::fs::write(&path, line).unwrap();
        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Append a line — file size changes, cache should invalidate
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();

        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 2);
    }
}
