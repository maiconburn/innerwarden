use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::Utc;
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{info, warn};

use crate::decisions::DecisionEntry;
use crate::telemetry::TelemetrySnapshot;
use innerwarden_core::entities::EntityType;

// ---------------------------------------------------------------------------
// Shared state / auth
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct DashboardState {
    data_dir: PathBuf,
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
// Query structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JourneyQuery {
    ip: Option<String>,
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
struct JourneyResponse {
    ip: String,
    date: String,
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    outcome: String,
    entries: Vec<JourneyEntry>,
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
    incident_count: usize,
    event_count: usize,
}

impl IpAccumulator {
    fn update_time(&mut self, ts: chrono::DateTime<Utc>) {
        if self.first_seen.map_or(true, |existing| ts < existing) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.map_or(true, |existing| ts > existing) {
            self.last_seen = Some(ts);
        }
    }
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub async fn serve(data_dir: PathBuf, bind: String, auth: DashboardAuth) -> Result<()> {
    let state = DashboardState { data_dir };
    let auth_layer = middleware::from_fn_with_state(auth, require_basic_auth);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/journey", get(api_journey))
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
    Query(query): Query<ListQuery>,
) -> Json<EntitiesResponse> {
    let date = resolve_date(query.date.as_deref());
    let attackers = build_attackers(&state.data_dir, &date);
    Json(EntitiesResponse { date, attackers })
}

async fn api_journey(
    State(state): State<DashboardState>,
    Query(query): Query<JourneyQuery>,
) -> Json<JourneyResponse> {
    let date = resolve_date(query.date.as_deref());
    let ip = query.ip.unwrap_or_default();
    if ip.is_empty() {
        return Json(JourneyResponse {
            ip: String::new(),
            date,
            first_seen: None,
            last_seen: None,
            outcome: "unknown".to_string(),
            entries: vec![],
        });
    }
    Json(build_journey(&state.data_dir, &date, &ip))
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
fn build_attackers(data_dir: &Path, date: &str) -> Vec<AttackerSummary> {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut ip_data: BTreeMap<String, IpAccumulator> = BTreeMap::new();

    // Seed from incidents (these define who is an "attacker").
    for inc in &incidents {
        let sev_str = format!("{:?}", inc.severity).to_lowercase();
        let sev_ord = severity_order(&sev_str);
        let detector = inc.incident_id.split(':').next().unwrap_or("unknown");

        for ip in extract_ip_entities(&inc.entities) {
            let entry = ip_data.entry(ip).or_default();
            entry.update_time(inc.ts);
            entry.incident_count += 1;
            if sev_ord > entry.max_severity {
                entry.max_severity = sev_ord;
                entry.max_severity_str = sev_str.clone();
            }
            entry.detectors.insert(detector.to_string());
        }
    }

    // Enrich with raw event counts for each attacker IP.
    for event in &events {
        for ip in extract_ip_entities(&event.entities) {
            if let Some(entry) = ip_data.get_mut(&ip) {
                entry.event_count += 1;
                entry.update_time(event.ts);
            }
        }
    }

    let mut result: Vec<AttackerSummary> = ip_data
        .into_iter()
        .map(|(ip, data)| {
            let outcome = determine_outcome(&decisions, &ip, true);
            AttackerSummary {
                ip,
                first_seen: data.first_seen.unwrap_or_else(Utc::now),
                last_seen: data.last_seen.unwrap_or_else(Utc::now),
                max_severity: data.max_severity_str,
                detectors: data.detectors.into_iter().collect(),
                outcome,
                incident_count: data.incident_count,
                event_count: data.event_count,
            }
        })
        .collect();

    // Sort by severity descending, then latest activity first.
    result.sort_by(|a, b| {
        severity_order(&b.max_severity)
            .cmp(&severity_order(&a.max_severity))
            .then(b.last_seen.cmp(&a.last_seen))
    });

    result
}

/// Build the full journey timeline for a single IP on a given date.
fn build_journey(data_dir: &Path, date: &str, ip: &str) -> JourneyResponse {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut entries: Vec<JourneyEntry> = Vec::new();

    // Raw events for this IP.
    for event in events {
        if extract_ip_entities(&event.entities)
            .iter()
            .any(|e| e == ip)
        {
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

    // Incidents for this IP.
    for incident in incidents {
        if extract_ip_entities(&incident.entities)
            .iter()
            .any(|e| e == ip)
        {
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
    }

    // Decisions for this IP.
    for decision in &decisions {
        if decision.target_ip.as_deref() == Some(ip) {
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

    // Honeypot sessions.
    let mut hp_entries = scan_honeypot_sessions(data_dir, date, ip);
    entries.append(&mut hp_entries);

    // Sort everything by timestamp.
    entries.sort_by_key(|e| e.ts);

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);
    let has_incident = entries.iter().any(|e| e.kind == "incident");
    let outcome = determine_outcome(&decisions, ip, has_incident);

    JourneyResponse {
        ip: ip.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        entries,
    }
}

/// Scan all honeypot JSONL session files for connections from `ip` on `date`.
fn scan_honeypot_sessions(data_dir: &Path, date: &str, ip: &str) -> Vec<JourneyEntry> {
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
            if peer_ip != ip {
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

fn extract_ip_entities(
    entities: &[innerwarden_core::entities::EntityRef],
) -> Vec<String> {
    entities
        .iter()
        .filter(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.clone())
        .collect()
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

const INDEX_HTML: &str = r#"<!doctype html>
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
    .app-title { font-weight: 700; font-size: 1rem; letter-spacing: -0.01em; }
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
  </style>
</head>
<body>
<div class="app">

  <!-- Header -->
  <header class="app-header">
    <div class="app-title">⚔ Inner Warden</div>
    <div class="app-badge">read-only · no actions</div>
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

      <!-- Attacker list -->
      <div class="section-title">Attackers</div>
      <div id="attackerList"><div class="empty">Loading…</div></div>

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
        <p>Select an attacker on the left<br>to view their full journey timeline.</p>
      </div>
    </main>

  </div>
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

  // ── Load journey for selected IP ───────────────────────────────────────
  let selectedIp = null;

  async function loadJourney(ip) {
    selectedIp = ip;
    document.querySelectorAll('.attacker-card').forEach(c => c.classList.remove('active'));
    const card = document.querySelector('.attacker-card[data-ip="' + CSS.escape(ip) + '"]');
    if (card) card.classList.add('active');

    const panel = document.getElementById('rightPanel');
    panel.innerHTML = '<div class="loading">Loading journey for ' + esc(ip) + '…</div>';

    try {
      const j = await loadJson('/api/journey?ip=' + encodeURIComponent(ip));
      const first = j.first_seen ? fmtDateTime(j.first_seen) : '—';
      const last  = j.last_seen  ? fmtDateTime(j.last_seen)  : '—';

      let html = `
        <div class="journey-header">
          <span class="journey-ip">${esc(ip)}</span>
          <span class="${outcomeCls(j.outcome)}">${outcomeLabel(j.outcome)}</span>
          <span class="journey-time">${esc(first)} → ${esc(last)}</span>
        </div>
        <div class="journey-subtitle">${j.entries.length} timeline entries · click any row to expand</div>
        <div class="timeline">`;

      if (j.entries.length === 0) {
        html += '<div class="empty">No entries found for this IP on the selected date.</div>';
      } else {
        j.entries.forEach((e, i) => { html += renderEntry(e, i); });
      }

      html += '</div>';
      panel.innerHTML = html;
    } catch (e) {
      panel.innerHTML = '<div class="err">Failed to load journey: ' + esc(e.message) + '</div>';
    }
  }

  // ── Attacker card ──────────────────────────────────────────────────────
  function renderCard(a) {
    const active = selectedIp === a.ip ? ' active' : '';
    return `
      <div class="attacker-card${active}" data-ip="${esc(a.ip)}" onclick="loadJourney('${esc(a.ip)}')">
        <div class="card-row">
          <span class="card-ip">${esc(a.ip)}</span>
          <span class="${outcomeCls(a.outcome)}">${outcomeLabel(a.outcome)}</span>
        </div>
        <div class="card-detectors">${a.detectors.map(esc).join(', ') || '—'}</div>
        <div class="card-meta">
          <span class="${sevCls(a.max_severity)}">${esc((a.max_severity || 'unknown').toUpperCase())}</span>
          <span class="card-counts">${a.incident_count} inc · ${a.event_count} ev</span>
        </div>
        <div class="card-time">${esc(fmtTime(a.first_seen))} → ${esc(fmtTime(a.last_seen))}</div>
      </div>`;
  }

  // ── Main refresh loop (attackers list only) ────────────────────────────
  async function refreshLeft() {
    try {
      const [ov, entities] = await Promise.all([
        loadJson('/api/overview'),
        loadJson('/api/entities'),
      ]);

      document.getElementById('kpi-date').textContent      = ov.date;
      document.getElementById('kpi-events').textContent    = ov.events_count;
      document.getElementById('kpi-incidents').textContent = ov.incidents_count;
      document.getElementById('kpi-decisions').textContent = ov.decisions_count;
      document.getElementById('kpi-attackers').textContent = entities.attackers.length;

      const list = document.getElementById('attackerList');
      if (entities.attackers.length === 0) {
        list.innerHTML = '<div class="empty">No attackers detected today.</div>';
      } else {
        list.innerHTML = entities.attackers.map(renderCard).join('');
      }

      if (ov.top_detectors && ov.top_detectors.length) {
        document.getElementById('topDetectors').innerHTML = ov.top_detectors.map(d =>
          `<div class="det-row"><span>${esc(d.detector)}</span><span class="det-count">${d.count}</span></div>`
        ).join('');
      } else {
        document.getElementById('topDetectors').innerHTML = '<div class="empty">No detectors fired.</div>';
      }

      document.getElementById('refreshStatus').textContent = new Date().toLocaleTimeString();
    } catch (e) {
      document.getElementById('refreshStatus').textContent = 'err: ' + e.message;
    }
  }

  // Boot
  refreshLeft();
  setInterval(refreshLeft, 5000);
</script>
</body>
</html>
"#;

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

        let attackers = build_attackers(dir.path(), date);
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

        let journey = build_journey(dir.path(), date, ip);
        assert_eq!(journey.entries.len(), 3, "should have event + incident + decision");
        let kinds: Vec<&str> = journey.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"event"), "missing event entry");
        assert!(kinds.contains(&"incident"), "missing incident entry");
        assert!(kinds.contains(&"decision"), "missing decision entry");
        assert!(journey.first_seen.is_some());
        assert!(journey.last_seen.is_some());
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
}
