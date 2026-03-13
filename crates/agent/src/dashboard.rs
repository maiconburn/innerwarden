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
    subject_type: String,
    subject: String,
    date: String,
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    outcome: String,
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
        .route("/api/pivots", get(api_pivots))
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

async fn api_journey(
    State(state): State<DashboardState>,
    Query(query): Query<JourneyQuery>,
) -> Json<JourneyResponse> {
    let date = resolve_date(query.date.as_deref());
    let subject_type = PivotKind::parse(query.subject_type.as_deref());
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
            entries: vec![],
        });
    }

    Json(build_journey(
        &state.data_dir,
        &date,
        subject_type,
        &subject,
        &filters,
    ))
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

/// Build the full journey timeline for a selected subject on a given date.
fn build_journey(
    data_dir: &Path,
    date: &str,
    subject_type: PivotKind,
    subject: &str,
    filters: &InvestigationFilters,
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
    let mut has_incident = false;

    for incident in incidents {
        if !incident_matches_filters(&incident, filters) {
            continue;
        }
        if !incident_matches_subject(&incident, subject_type, subject) {
            continue;
        }

        has_incident = true;
        for ip in extract_ip_entities(&incident.entities) {
            related_ips.insert(ip);
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

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);
    let outcome = if subject_type == PivotKind::Ip {
        determine_outcome(&decisions, subject, has_incident)
    } else {
        determine_outcome_for_ips(&decisions, &related_ips, has_incident)
    };

    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        entries,
    }
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

      <div class="filters">
        <input id="flt-date" type="date" class="full" />
        <select id="flt-severity">
          <option value="">severity: any</option>
          <option value="critical">severity: critical+</option>
          <option value="high">severity: high+</option>
          <option value="medium">severity: medium+</option>
          <option value="low">severity: low+</option>
          <option value="info">severity: info+</option>
        </select>
        <input id="flt-detector" type="text" placeholder="detector (ex: ssh_bruteforce)" />
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

  // ── Investigation state ────────────────────────────────────────────────
  const state = {
    pivot: 'ip',
    selected: { type: 'ip', value: null },
    filters: { date: '', severity_min: '', detector: '' },
  };

  const pivotTitle = (pivot) => ({
    ip: 'Attackers (IP)',
    user: 'Users (Pivot)',
    detector: 'Detectors (Pivot)',
  }[pivot] || 'Entities');

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
    state.filters.severity_min = document.getElementById('flt-severity').value || '';
    state.filters.detector = (document.getElementById('flt-detector').value || '').trim();
  }

  function updatePivotUi() {
    document.querySelectorAll('.pivot-tab').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.pivot === state.pivot);
    });
    document.getElementById('entityTitle').textContent = pivotTitle(state.pivot);
  }

  async function loadJourney(subjectType, subjectValue) {
    state.selected = { type: subjectType, value: subjectValue };
    document.querySelectorAll('.attacker-card').forEach(c => c.classList.remove('active'));
    const card = document.querySelector(
      '.attacker-card[data-subject-type="' + CSS.escape(subjectType) + '"][data-subject-value="' + CSS.escape(subjectValue) + '"]'
    );
    if (card) card.classList.add('active');

    const panel = document.getElementById('rightPanel');
    panel.innerHTML = '<div class="loading">Loading journey for ' + esc(subjectValue) + '…</div>';

    try {
      const qs = buildQuery({
        subject_type: subjectType,
        subject: subjectValue,
        date: state.filters.date,
        severity_min: state.filters.severity_min,
        detector: state.filters.detector,
      });
      const j = await loadJson('/api/journey?' + qs);
      const first = j.first_seen ? fmtDateTime(j.first_seen) : '—';
      const last  = j.last_seen  ? fmtDateTime(j.last_seen)  : '—';

      let html = `
        <div class="journey-header">
          <span class="journey-ip">${esc(j.subject || subjectValue)}</span>
          <span class="${outcomeCls(j.outcome)}">${outcomeLabel(j.outcome)}</span>
          <span class="journey-time">${esc(first)} → ${esc(last)}</span>
        </div>
        <div class="journey-subtitle">${esc((j.subject_type || subjectType).toUpperCase())} journey · ${j.entries.length} timeline entries · click any row to expand</div>
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

      const [ov, entityData] = await Promise.all([
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
      ]);

      const items = entityData.items || [];

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

      if (ov.top_detectors && ov.top_detectors.length) {
        document.getElementById('topDetectors').innerHTML = ov.top_detectors.map(d =>
          `<div class="det-row"><span>${esc(d.detector)}</span><span class="det-count">${d.count}</span></div>`
        ).join('');
      } else {
        document.getElementById('topDetectors').innerHTML = '<div class="empty">No detectors fired.</div>';
      }

      if (state.selected.value) {
        const stillExists = items.some((it) => it.value === state.selected.value);
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

      document.getElementById('refreshStatus').textContent = new Date().toLocaleTimeString();
    } catch (e) {
      document.getElementById('refreshStatus').textContent = 'err: ' + e.message;
    }
  }

  // Boot
  const today = new Date().toISOString().slice(0, 10);
  document.getElementById('flt-date').value = today;
  updatePivotUi();

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

  refreshLeft();
  setInterval(() => refreshLeft(false), 5000);
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
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters);
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
        let journey = build_journey(dir.path(), date, PivotKind::User, "root", &filters);
        assert_eq!(journey.subject_type, "user");
        assert_eq!(journey.subject, "root");
        assert!(journey.entries.iter().any(|e| e.kind == "incident"));
        assert!(journey.entries.iter().any(|e| e.kind == "decision"));
        assert_eq!(journey.outcome, "blocked");
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
