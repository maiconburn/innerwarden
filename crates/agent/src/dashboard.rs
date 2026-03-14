use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{info, warn};

use crate::correlation::build_clusters;
use crate::decisions::DecisionEntry;
use crate::telemetry::TelemetrySnapshot;
use innerwarden_core::entities::{EntityRef, EntityType};

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
}

impl Default for DashboardActionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
        }
    }
}

#[derive(Clone)]
struct DashboardState {
    data_dir: PathBuf,
    /// D3: operator-initiated action configuration.
    action_cfg: Arc<DashboardActionConfig>,
}

#[derive(Clone)]
pub struct DashboardAuth {
    username: String,
    password_hash: PasswordHashString,
}

impl DashboardAuth {
    pub fn from_env() -> Result<Self> {
        let username = std::env::var("INNERWARDEN_DASHBOARD_USER")
            .context("missing env var INNERWARDEN_DASHBOARD_USER for dashboard authentication")?;
        if username.trim().is_empty() {
            anyhow::bail!("INNERWARDEN_DASHBOARD_USER cannot be empty");
        }

        let password_hash_raw = std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").context(
            "missing env var INNERWARDEN_DASHBOARD_PASSWORD_HASH (generate one with: innerwarden-agent --dashboard-generate-password-hash)",
        )?;
        let password_hash = PasswordHashString::new(&password_hash_raw).map_err(|_| {
            anyhow::anyhow!("INNERWARDEN_DASHBOARD_PASSWORD_HASH is not a valid PHC hash string")
        })?;

        Ok(Self {
            username,
            password_hash,
        })
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        if user != self.username {
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

#[derive(Debug, Serialize)]
struct JourneyResponse {
    subject_type: String,
    subject: String,
    date: String,
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    outcome: String,
    summary: JourneySummary,
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
    auth: DashboardAuth,
    action_cfg: DashboardActionConfig,
) -> Result<()> {
    let state = DashboardState {
        data_dir,
        action_cfg: Arc::new(action_cfg),
    };
    let auth_layer = middleware::from_fn_with_state(auth, require_basic_auth);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/pivots", get(api_pivots))
        .route("/api/clusters", get(api_clusters))
        .route("/api/journey", get(api_journey))
        .route("/api/export", get(api_export))
        // D3 — operator-initiated actions (POST, require auth, respect dry_run)
        .route("/api/action/block-ip", post(api_action_block_ip))
        .route("/api/action/suspend-user", post(api_action_suspend_user))
        .route("/api/action/config", get(api_action_config))
        .layer(auth_layer)
        .with_state(state);

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
// Auth middleware
// ---------------------------------------------------------------------------

async fn require_basic_auth(
    State(auth): State<DashboardAuth>,
    req: Request<Body>,
    next: Next,
) -> Response {
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
        return unauthorized_response();
    }
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

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn api_overview(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<OverviewResponse> {
    let date = resolve_date(query.date.as_deref());
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

    let total = incidents.len();
    let items = incidents
        .into_iter()
        .take(limit)
        .map(|inc| IncidentView {
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
// D3 — action handlers
// ---------------------------------------------------------------------------

/// GET /api/action/config — exposes the current action mode to the UI (read-only).
async fn api_action_config(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "enabled": state.action_cfg.enabled,
        "dry_run": state.action_cfg.dry_run,
        "block_backend": state.action_cfg.block_backend,
        "allowed_skills": state.action_cfg.allowed_skills,
    }))
}

/// POST /api/action/block-ip — operator-initiated IP block with mandatory reason.
async fn api_action_block_ip(
    State(state): State<DashboardState>,
    Json(body): Json<BlockIpRequest>,
) -> Json<ActionResponse> {
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
        duration_secs: None,
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
    };

    let skill: Box<dyn ResponseSkill> = match cfg.block_backend.as_str() {
        "iptables" => Box::new(BlockIpIptables),
        "nftables" => Box::new(BlockIpNftables),
        _ => Box::new(BlockIpUfw),
    };
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run { "ok (dry_run)".to_string() } else { "ok".to_string() }
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
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
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
        duration_secs: Some(duration_secs),
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
    };

    let skill = SuspendUserSudo;
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run { "ok (dry_run)".to_string() } else { "ok".to_string() }
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
        skill_id: Some("suspend-user-sudo".to_string()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
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

/// Returns the machine hostname (best-effort).
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| {
            std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Business logic — overview
// ---------------------------------------------------------------------------

fn compute_overview(data_dir: &Path, date: &str) -> OverviewResponse {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
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
        events_count: events.len(),
        incidents_count: incidents.len(),
        decisions_count: decisions.len(),
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
    }
}

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

    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
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

fn dated_path(data_dir: &Path, prefix: &str, date: &str) -> PathBuf {
    data_dir.join(format!("{prefix}-{date}.jsonl"))
}

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    let content = match std::fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    content
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
        .collect()
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
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg0: #071218;
      --bg1: #0f1f2e;
      --card: rgba(18, 31, 47, 0.92);
      --card-hover: rgba(24, 40, 62, 0.98);
      --line: rgba(148, 190, 214, 0.18);
      --line2: rgba(148, 190, 214, 0.32);
      --text: #e7f2ff;
      --muted: #7a9bb5;
      --ok: #3ac27e;
      --warn: #ffb84d;
      --danger: #ff6b6b;
      --accent: #56c8ff;
      --orange: #ff8c42;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; overflow: hidden; }
    body {
      font-family: "Space Grotesk", system-ui, -apple-system, sans-serif;
      color: var(--text);
      background: linear-gradient(160deg, var(--bg0) 0%, var(--bg1) 100%);
      font-size: 14px;
    }

    /* ── App shell ───────────────────────────────────────────────── */
    .app { display: flex; flex-direction: column; height: 100vh; }

    .app-header {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 16px; border-bottom: 1px solid var(--line);
      flex-shrink: 0;
    }
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
      border: 1px solid rgba(86, 200, 255, 0.35);
      background: radial-gradient(circle at 30% 25%, rgba(86, 200, 255, 0.24), rgba(7, 18, 24, 0.96) 72%);
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
      background: var(--card); border: 1px solid var(--line); border-radius: 6px;
      padding: 7px 4px; text-align: center;
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
      background: rgba(9, 19, 30, 0.9);
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 6px;
      font-size: 0.72rem;
      padding: 6px 8px;
      font-family: "IBM Plex Mono", monospace;
    }
    .filters button {
      cursor: pointer;
      background: rgba(86, 200, 255, 0.14);
      border-color: rgba(86, 200, 255, 0.28);
      color: var(--accent);
      font-family: "Space Grotesk", sans-serif;
      font-weight: 700;
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
      background: rgba(9, 19, 30, 0.8);
      color: var(--muted);
      border-radius: 6px;
      padding: 6px 0;
      font-size: 0.68rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      cursor: pointer;
    }
    .pivot-tab.active {
      color: var(--accent);
      border-color: rgba(86, 200, 255, 0.35);
      background: rgba(86, 200, 255, 0.12);
    }

    /* Section header */
    .section-title {
      font-size: 0.65rem; letter-spacing: 0.07em; color: var(--muted);
      text-transform: uppercase; margin: 10px 0 5px; padding: 0 2px;
    }

    /* Attacker card */
    .attacker-card {
      background: var(--card); border: 1px solid var(--line); border-radius: 7px;
      padding: 9px 10px; margin-bottom: 5px; cursor: pointer;
      transition: border-color 0.12s, background 0.12s;
    }
    .attacker-card:hover { border-color: var(--line2); background: var(--card-hover); }
    .attacker-card.active { border-color: var(--accent); background: var(--card-hover); }
    .card-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 3px; }
    .card-ip {
      font-family: "IBM Plex Mono", monospace; font-weight: 600; font-size: 0.82rem;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .card-detectors { font-size: 0.7rem; color: var(--muted); margin-bottom: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .card-meta { display: flex; gap: 6px; font-size: 0.7rem; margin-bottom: 2px; align-items: center; }
    .card-counts { color: var(--muted); }
    .card-time { font-size: 0.65rem; color: var(--muted); font-family: "IBM Plex Mono", monospace; }

    .cluster-card {
      background: rgba(86, 200, 255, 0.08);
      border: 1px solid rgba(86, 200, 255, 0.24);
      border-radius: 7px;
      padding: 8px 10px;
      margin-bottom: 5px;
      cursor: pointer;
    }
    .cluster-card:hover { background: rgba(86, 200, 255, 0.12); }
    .cluster-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .cluster-id { font-size: 0.66rem; color: var(--accent); letter-spacing: 0.04em; text-transform: uppercase; }
    .cluster-pivot { font-family: "IBM Plex Mono", monospace; font-size: 0.72rem; color: var(--text); }
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
      font-family: "IBM Plex Mono", monospace; font-size: 1.3rem; font-weight: 700;
    }
    .journey-time { font-size: 0.75rem; color: var(--muted); }
    .journey-subtitle { font-size: 0.78rem; color: var(--muted); margin-bottom: 18px; }

    .journey-actions {
      display: flex; gap: 6px; margin: 0 0 12px;
    }
    .journey-btn {
      border: 1px solid var(--line);
      background: rgba(9, 19, 30, 0.85);
      color: var(--muted);
      border-radius: 6px;
      padding: 5px 9px;
      font-size: 0.66rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      cursor: pointer;
    }
    .journey-btn:hover {
      color: var(--accent);
      border-color: rgba(86, 200, 255, 0.35);
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
      border-radius: 8px;
      padding: 10px 11px;
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
      background: rgba(9, 19, 30, 0.82);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 8px;
    }
    .summary-label {
      font-size: 0.6rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .summary-value {
      font-family: "IBM Plex Mono", monospace;
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
      border: 1px solid rgba(86, 200, 255, 0.28);
      background: rgba(86, 200, 255, 0.1);
      color: var(--accent);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 0.64rem;
      font-family: "IBM Plex Mono", monospace;
      cursor: pointer;
    }
    .shortcut-btn:hover {
      background: rgba(86, 200, 255, 0.16);
    }
    .compare-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 7px;
    }
    .compare-cell {
      background: rgba(9, 19, 30, 0.82);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 8px;
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
      padding: 8px 10px; border-radius: 6px; background: var(--card);
      border: 1px solid var(--line); flex-wrap: wrap;
    }
    .tl-header:hover { border-color: var(--line2); }
    .tl-ts {
      font-family: "IBM Plex Mono", monospace; font-size: 0.7rem; color: var(--muted);
      flex-shrink: 0; margin-top: 1px;
    }
    .tl-summary {
      font-size: 0.8rem; flex: 1; min-width: 0;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .tl-toggle { color: var(--muted); font-size: 0.65rem; flex-shrink: 0; margin-left: auto; margin-top: 2px; }

    .tl-detail {
      background: rgba(0,0,0,0.28); border: 1px solid var(--line);
      border-top: none; border-radius: 0 0 6px 6px;
      padding: 10px 12px; font-size: 0.72rem;
      font-family: "IBM Plex Mono", monospace;
      color: #a8c4dc; overflow-x: auto; white-space: pre;
      line-height: 1.5; margin: 0;
    }

    /* ── Kind badges ─────────────────────────────────────────────── */
    .bk {
      font-size: 0.6rem; font-weight: 700; letter-spacing: 0.05em;
      border-radius: 3px; padding: 2px 6px; text-transform: uppercase;
      flex-shrink: 0; margin-top: 1px;
    }
    .bk-event         { background: rgba(122,155,181,0.12); color: var(--muted); }
    .bk-event-crit    { background: rgba(255,107,107,0.18); color: var(--danger); }
    .bk-event-high    { background: rgba(255,184,77,0.18);  color: var(--warn); }
    .bk-event-med     { background: rgba(255,184,77,0.12);  color: var(--warn); }
    .bk-incident      { background: rgba(255,107,107,0.22); color: var(--danger); }
    .bk-decision      { background: rgba(86,200,255,0.18);  color: var(--accent); }
    .bk-decision-dry  { background: rgba(122,155,181,0.12); color: var(--muted); }
    .bk-decision-skip { background: rgba(122,155,181,0.08); color: var(--muted); }
    .bk-honeypot      { background: rgba(255,140,66,0.18);  color: var(--orange); }

    /* ── Outcome badges ──────────────────────────────────────────── */
    .bo {
      font-size: 0.62rem; font-weight: 700; letter-spacing: 0.06em;
      border-radius: 4px; padding: 2px 7px; text-transform: uppercase;
    }
    .bo-blocked    { background: rgba(58,194,126,0.18);  color: var(--ok);     border: 1px solid rgba(58,194,126,0.3); }
    .bo-active     { background: rgba(255,107,107,0.18); color: var(--danger); border: 1px solid rgba(255,107,107,0.3); }
    .bo-monitoring { background: rgba(86,200,255,0.15);  color: var(--accent); border: 1px solid rgba(86,200,255,0.3); }
    .bo-honeypot   { background: rgba(255,140,66,0.15);  color: var(--orange); border: 1px solid rgba(255,140,66,0.3); }
    .bo-unknown    { background: rgba(122,155,181,0.1);  color: var(--muted);  border: 1px solid rgba(122,155,181,0.2); }

    /* ── Severity text colors ────────────────────────────────────── */
    .sc-critical { color: var(--danger); }
    .sc-high     { color: var(--warn); }
    .sc-medium   { color: var(--warn); opacity: 0.8; }
    .sc-low, .sc-info { color: var(--muted); }

    /* ── Utils ───────────────────────────────────────────────────── */
    .empty  { font-size: 0.78rem; color: var(--muted); padding: 8px 2px; }
    .loading { font-size: 0.8rem; color: var(--muted); padding: 20px 0; }
    .err    { font-size: 0.8rem; color: var(--danger); padding: 12px 0; }

    @media (max-width: 1180px) {
      .guided-grid {
        grid-template-columns: 1fr;
      }
    }

    /* Mobile layout: stack panels and make everything readable */
    @media (max-width: 860px) {
      html, body { overflow: auto; }
      .app { height: auto; min-height: 100vh; }
      .app-body { flex-direction: column; overflow: visible; }

      .app-header { padding: 10px 12px; }
      .app-title { font-size: 0.95rem; }
      .logo { width: 28px; height: 28px; }
      .app-badge { display: none; }

      .left-panel {
        width: 100%;
        max-height: 56vh;
        border-right: none;
        border-bottom: 1px solid var(--line);
        padding: 10px 10px;
      }

      .right-panel {
        padding: 14px 12px;
        overflow-y: visible;
      }

      /* KPIs: 1st card (date) full width; rest 2 columns */
      .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 6px; }
      .kpi-grid .kpi-card:first-child {
        grid-column: 1 / -1;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 10px;
        text-align: left;
      }
      .kpi-grid .kpi-card:first-child .kpi-value { margin-top: 0; font-size: 0.8rem; }

      .filters { grid-template-columns: 1fr; }
      .filters .full { grid-column: auto; }

      .pivot-tabs { grid-template-columns: repeat(3, 1fr); }

      .journey-ip { font-size: 1.05rem; }
      .journey-subtitle { margin-bottom: 12px; }

      /* Let timeline titles wrap instead of overflowing */
      .tl-summary { white-space: normal; }
      .tl-toggle { margin-left: 0; }
    }

    @media (max-width: 420px) {
      .left-panel { max-height: 60vh; }
      .kpi-label { font-size: 0.55rem; }
      .kpi-value { font-size: 1rem; }
      .pivot-tab { font-size: 0.64rem; }
    }

    /* ── D3 — action buttons ─────────────────────────────────────── */
    .journey-btn.action-block {
      color: var(--danger); border-color: rgba(255,107,107,0.35);
      background: rgba(255,107,107,0.10);
    }
    .journey-btn.action-block:hover { background: rgba(255,107,107,0.18); }
    .journey-btn.action-suspend {
      color: var(--warn); border-color: rgba(255,184,77,0.35);
      background: rgba(255,184,77,0.10);
    }
    .journey-btn.action-suspend:hover { background: rgba(255,184,77,0.18); }

    /* ── D3 — modal overlay ──────────────────────────────────────── */
    .modal-overlay {
      display: none; position: fixed; inset: 0; z-index: 100;
      background: rgba(7,18,24,0.82); backdrop-filter: blur(3px);
      align-items: center; justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal-box {
      background: var(--bg1); border: 1px solid var(--line2);
      border-radius: 10px; padding: 22px 24px;
      width: 400px; max-width: 92vw;
    }
    .modal-title { font-size: 1rem; font-weight: 700; margin-bottom: 4px; }
    .modal-subtitle { font-size: 0.75rem; color: var(--muted); margin-bottom: 16px; line-height: 1.4; }
    .modal-field { margin-bottom: 12px; }
    .modal-label {
      font-size: 0.7rem; color: var(--muted); letter-spacing: 0.04em;
      text-transform: uppercase; display: block; margin-bottom: 4px;
    }
    .modal-textarea, .modal-input {
      width: 100%; background: rgba(9,19,30,0.9); color: var(--text);
      border: 1px solid var(--line2); border-radius: 6px; padding: 8px 10px;
      font-size: 0.82rem; font-family: "Space Grotesk", sans-serif; resize: vertical;
    }
    .modal-textarea { min-height: 72px; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
    .btn-cancel {
      background: transparent; border: 1px solid var(--line2); color: var(--muted);
      border-radius: 6px; padding: 7px 16px; font-size: 0.8rem; cursor: pointer;
    }
    .btn-cancel:hover { color: var(--text); }
    .btn-confirm {
      background: rgba(58,194,126,0.15); border: 1px solid rgba(58,194,126,0.38);
      color: var(--ok); border-radius: 6px; padding: 7px 16px;
      font-size: 0.8rem; font-weight: 600; cursor: pointer;
    }
    .btn-confirm:hover { background: rgba(58,194,126,0.24); }
    .btn-confirm.danger {
      background: rgba(255,107,107,0.13); border-color: rgba(255,107,107,0.35);
      color: var(--danger);
    }
    .btn-confirm.danger:hover { background: rgba(255,107,107,0.22); }
    .btn-confirm:disabled { opacity: 0.45; cursor: default; }
    .dry-run-badge {
      display: inline-block; font-size: 0.6rem; font-weight: 700;
      letter-spacing: 0.06em; text-transform: uppercase; border-radius: 4px;
      padding: 2px 6px; margin-left: 6px; vertical-align: middle;
    }
    .dry-run-badge.on  { background: rgba(255,184,77,0.18);  color: var(--warn);   border: 1px solid rgba(255,184,77,0.3); }
    .dry-run-badge.off { background: rgba(255,107,107,0.18); color: var(--danger); border: 1px solid rgba(255,107,107,0.3); }

    /* ── D3 — toast ──────────────────────────────────────────────── */
    .toast {
      position: fixed; top: 16px; right: 16px; z-index: 200;
      background: var(--bg1); border: 1px solid var(--line2);
      border-radius: 8px; padding: 10px 16px; min-width: 240px; max-width: 340px;
      font-size: 0.82rem; box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      opacity: 0; transform: translateY(-8px);
      transition: opacity 0.18s ease, transform 0.18s ease;
      pointer-events: none; line-height: 1.4;
    }
    .toast.visible { opacity: 1; transform: translateY(0); pointer-events: auto; }
    .toast.ok  { border-left: 3px solid var(--ok);    color: var(--text); }
    .toast.err { border-left: 3px solid var(--danger); color: var(--text); }
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
    <div class="app-badge" id="modeBadge">read-only</div>
    <span id="refreshStatus"></span>
  </header>

  <div class="app-body">

    <!-- Left panel: KPIs + attacker list -->
    <aside class="left-panel">

      <!-- KPI row -->
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">Date</div><div class="kpi-value" id="kpi-date" style="font-size:0.7rem">—</div></div>
        <div class="kpi-card"><div class="kpi-label">Events</div><div class="kpi-value" id="kpi-events">0</div></div>
        <div class="kpi-card"><div class="kpi-label">Incid.</div><div class="kpi-value" id="kpi-incidents">0</div></div>
        <div class="kpi-card"><div class="kpi-label">Dec.</div><div class="kpi-value" id="kpi-decisions">0</div></div>
        <div class="kpi-card"><div class="kpi-label">Attk.</div><div class="kpi-value" id="kpi-attackers">0</div></div>
      </div>

      <div class="filters">
        <input id="flt-date" type="date" class="full" />
        <input id="flt-compare-date" type="date" title="compare date" />
        <select id="flt-window">
          <option value="">window: full day</option>
          <option value="900">window: last 15m</option>
          <option value="3600">window: last 1h</option>
          <option value="21600">window: last 6h</option>
        </select>
        <select id="flt-severity">
          <option value="">severity: any</option>
          <option value="critical">severity: critical+</option>
          <option value="high">severity: high+</option>
          <option value="medium">severity: medium+</option>
          <option value="low">severity: low+</option>
          <option value="info">severity: info+</option>
        </select>
        <input id="flt-detector" type="text" placeholder="detector (ex: ssh_bruteforce)" />
        <div class="filters-note">Comparison uses same subject + filters on selected compare date.</div>
        <button id="flt-apply" class="full" type="button">Apply Filters</button>
      </div>

      <div class="pivot-tabs">
        <button type="button" class="pivot-tab active" data-pivot="ip">IP</button>
        <button type="button" class="pivot-tab" data-pivot="user">User</button>
        <button type="button" class="pivot-tab" data-pivot="detector">Detector</button>
      </div>

      <!-- Entity list -->
      <div class="section-title" id="entityTitle">Attackers (IP)</div>
      <div id="attackerList"><div class="empty">Loading…</div></div>

      <!-- Correlation clusters -->
      <div class="section-title" style="margin-top:14px">Correlation Clusters</div>
      <div id="clusterList"><div class="empty">—</div></div>

      <!-- Top detectors -->
      <div class="section-title" style="margin-top:14px">Top Detectors</div>
      <div id="topDetectors"><div class="empty">—</div></div>

    </aside>

    <!-- Right panel: journey timeline -->
    <main class="right-panel" id="rightPanel">
      <div class="right-placeholder">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <p>Select an item on the left<br>to view its investigation timeline.</p>
      </div>
    </main>

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

  // ── Render single timeline entry ───────────────────────────────────────
  function renderEntry(entry, idx) {
    const ts   = fmtTime(entry.ts);
    const badge = kindBadge(entry);
    const dot   = dotCls(entry);
    const sum   = entrySummary(entry);
    return `
      <div class="tl-item">
        <div class="tl-spine">
          <div class="tl-dot ${esc(dot)}"></div>
          <div class="tl-connector"></div>
        </div>
        <div class="tl-body">
          <div class="tl-header" onclick="toggleEntry(${idx})">
            <span class="tl-ts">${esc(ts)}</span>
            ${badge}
            <span class="tl-summary">${sum}</span>
            <span class="tl-toggle" id="tlz-${idx}">▶</span>
          </div>
          <pre class="tl-detail" id="tld-${idx}" style="display:none">${esc(JSON.stringify(entry.data, null, 2))}</pre>
        </div>
      </div>`;
  }

  function toggleEntry(idx) {
    const el = document.getElementById('tld-' + idx);
    const ic = document.getElementById('tlz-' + idx);
    if (!el) return;
    const hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    if (ic) ic.textContent = hidden ? '▼' : '▶';
  }

  // ── D3 — action state ─────────────────────────────────────────────────
  let actionCfg = null;
  let pendingAction = null; // { type: 'block_ip'|'suspend_user', ip, user }

  async function loadActionConfig() {
    try {
      actionCfg = await loadJson('/api/action/config');
      const badge = document.getElementById('modeBadge');
      if (actionCfg.enabled) {
        badge.textContent = actionCfg.dry_run ? 'actions: dry-run' : 'actions: LIVE';
        badge.style.color = actionCfg.dry_run ? 'var(--warn)' : 'var(--danger)';
        badge.style.borderColor = actionCfg.dry_run
          ? 'rgba(255,184,77,0.4)' : 'rgba(255,107,107,0.4)';
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
        'Block IP: <span style="font-family:\'IBM Plex Mono\',monospace">' + esc(ip) + '</span>' + drLabel;
      document.getElementById('modalSubtitle').textContent =
        'Executes ' + esc(actionCfg.block_backend) + ' deny rule. Logged to the audit trail.';
      document.getElementById('modalDurationField').style.display = 'none';
      document.getElementById('modalConfirm').textContent = actionCfg.dry_run ? 'Simulate Block' : 'Block IP';
    } else {
      document.getElementById('modalTitle').innerHTML =
        'Suspend sudo: <span style="font-family:\'IBM Plex Mono\',monospace">' + esc(user) + '</span>' + drLabel;
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
    if (card) card.classList.add('active');

    const panel = document.getElementById('rightPanel');
    panel.innerHTML = '<div class="loading">Loading journey for ' + esc(subjectValue) + '…</div>';

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

      let html = `
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

      html += `
        <div class="timeline">`;

      if (j.entries.length === 0) {
        html += '<div class="empty">No entries found for this selection on the chosen filters.</div>';
      } else {
        j.entries.forEach((e, i) => { html += renderEntry(e, i); });
      }

      html += '</div>';
      panel.innerHTML = html;
    } catch (e) {
      panel.innerHTML = '<div class="err">Failed to load journey: ' + esc(e.message) + '</div>';
    }
  }

  function renderCard(item) {
    const value = item.value;
    const active = state.selected.type === state.pivot && state.selected.value === value ? ' active' : '';
    const detectors = (item.detectors || []).map(esc).join(', ') || '—';
    const outcome = item.outcome || 'unknown';

    return `
      <div class="attacker-card${active}"
           data-subject-type="${esc(state.pivot)}"
           data-subject-value="${esc(value)}"
           onclick="loadJourney('${esc(state.pivot)}','${esc(value)}')">
        <div class="card-row">
          <span class="card-ip">${esc(value)}</span>
          <span class="${outcomeCls(outcome)}">${outcomeLabel(outcome)}</span>
        </div>
        <div class="card-detectors">${detectors}</div>
        <div class="card-meta">
          <span class="${sevCls(item.max_severity)}">${esc((item.max_severity || 'unknown').toUpperCase())}</span>
          <span class="card-counts">${item.incident_count} inc · ${item.event_count} ev</span>
        </div>
        <div class="card-time">${esc(fmtTime(item.first_seen))} → ${esc(fmtTime(item.last_seen))}</div>
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
      document.getElementById('kpi-attackers').textContent = items.length;

      const list = document.getElementById('attackerList');
      if (items.length === 0) {
        list.innerHTML = '<div class="empty">No records for the selected filters.</div>';
      } else {
        list.innerHTML = items.map((item) => renderCard(item)).join('');
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
          document.getElementById('rightPanel').innerHTML = `
            <div class="right-placeholder">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <p>Current selection no longer matches filters.<br>Select another item to continue.</p>
            </div>`;
        } else if (forceRefreshJourney) {
          await loadJourney(state.selected.type, state.selected.value);
        }
      }

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

  refreshLeft(false).then(() => {
    if (state.selected.value) {
      loadJourney(state.selected.type, state.selected.value);
    }
  });
  setInterval(() => refreshLeft(false), 5000);
</script>
</body>
</html>
"##;

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
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
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
        assert_eq!(ov.events_count, 1);
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
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: true,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok (dry_run)".to_string(),
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
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
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
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
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
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
        };
        assert_eq!(determine_outcome(&[blocked], "1.2.3.4", true), "blocked");

        let dry_run_block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok (dry_run)".to_string(),
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
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "error: permission denied".to_string(),
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
        assert!(!cfg.enabled, "actions must be disabled by default for safety");
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
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 1.0,
            auto_executed: true,
            dry_run: true,
            reason: "manual block for testing".to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "ok (dry_run)".to_string(),
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
        let backends = [("ufw", "block-ip-ufw"), ("iptables", "block-ip-iptables"), ("nftables", "block-ip-nftables")];
        for (backend, expected_id) in backends {
            let cfg = DashboardActionConfig {
                enabled: true,
                dry_run: true,
                block_backend: backend.to_string(),
                allowed_skills: vec![expected_id.to_string()],
            };
            let skill_id = format!("block-ip-{}", cfg.block_backend);
            assert_eq!(skill_id, expected_id);
            assert!(cfg.allowed_skills.contains(&skill_id));
        }
    }
}
