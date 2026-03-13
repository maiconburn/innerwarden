use std::collections::BTreeMap;
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

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    date: Option<String>,
}

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

pub async fn serve(data_dir: PathBuf, bind: String, auth: DashboardAuth) -> Result<()> {
    let state = DashboardState { data_dir };
    let auth_layer = middleware::from_fn_with_state(auth, require_basic_auth);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
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

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Inner Warden Dashboard (Read-Only)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg0: #071218;
      --bg1: #0f1f2e;
      --card: rgba(18, 31, 47, 0.9);
      --line: rgba(148, 190, 214, 0.24);
      --text: #e7f2ff;
      --muted: #93abc1;
      --ok: #3ac27e;
      --warn: #ffb84d;
      --danger: #ff6b6b;
      --accent: #56c8ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Space Grotesk", "Trebuchet MS", sans-serif;
      color: var(--text);
      background:
        radial-gradient(80rem 40rem at 95% -10%, rgba(86,200,255,0.16), transparent 60%),
        radial-gradient(60rem 30rem at -5% 0%, rgba(58,194,126,0.12), transparent 55%),
        linear-gradient(160deg, var(--bg0), var(--bg1));
      min-height: 100vh;
    }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 22px 16px 40px; }
    .head {
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
      margin-bottom: 16px;
    }
    .title { font-size: clamp(1.1rem, 1.8vw, 1.5rem); font-weight: 700; }
    .badge {
      border: 1px solid var(--line); border-radius: 999px; padding: 6px 12px;
      font-size: 0.78rem; color: var(--muted);
      background: rgba(0,0,0,0.16);
    }
    .cards {
      display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px;
    }
    .card {
      background: var(--card); border: 1px solid var(--line); border-radius: 12px;
      padding: 12px;
    }
    .k { font-size: 0.75rem; letter-spacing: 0.05em; color: var(--muted); text-transform: uppercase; }
    .v { font-size: 1.5rem; font-weight: 700; margin-top: 4px; }
    .grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
    }
    .panel {
      background: var(--card); border: 1px solid var(--line); border-radius: 12px;
      overflow: hidden;
    }
    .panel h3 {
      margin: 0; padding: 12px 14px; font-size: 0.95rem; border-bottom: 1px solid var(--line);
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left; padding: 9px 12px; border-bottom: 1px solid rgba(148,190,214,0.12);
      font-size: 0.84rem; vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .mono { font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
    .sev-high { color: var(--warn); }
    .sev-critical { color: var(--danger); }
    .footer { margin-top: 10px; color: var(--muted); font-size: 0.78rem; }
    @media (max-width: 980px) {
      .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <div class="title">Inner Warden Dashboard</div>
      <div class="badge">Read-only mode • no response actions exposed</div>
    </div>

    <section class="cards">
      <article class="card"><div class="k">Date</div><div class="v mono" id="date">-</div></article>
      <article class="card"><div class="k">Events</div><div class="v" id="events">0</div></article>
      <article class="card"><div class="k">Incidents</div><div class="v" id="incidents">0</div></article>
      <article class="card"><div class="k">Decisions</div><div class="v" id="decisions">0</div></article>
    </section>

    <section class="grid">
      <article class="panel">
        <h3>Recent Incidents</h3>
        <table>
          <thead><tr><th>Time</th><th>Severity</th><th>Incident</th><th>Summary</th></tr></thead>
          <tbody id="incidentsBody"></tbody>
        </table>
      </article>
      <article class="panel">
        <h3>Recent Decisions</h3>
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Confidence</th><th>Result</th></tr></thead>
          <tbody id="decisionsBody"></tbody>
        </table>
      </article>
    </section>

    <p class="footer" id="foot">refreshing…</p>
  </div>
  <script>
    const esc = (s) => String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");

    const fmtTs = (v) => {
      const d = new Date(v);
      if (Number.isNaN(d.getTime())) return esc(v);
      return d.toLocaleString();
    };

    const sevClass = (s) => {
      if (s === "critical") return "sev-critical";
      if (s === "high") return "sev-high";
      return "";
    };

    async function loadJson(url) {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    }

    async function refresh() {
      const [overview, incidents, decisions] = await Promise.all([
        loadJson("/api/overview"),
        loadJson("/api/incidents?limit=20"),
        loadJson("/api/decisions?limit=20"),
      ]);

      document.getElementById("date").textContent = overview.date;
      document.getElementById("events").textContent = overview.events_count;
      document.getElementById("incidents").textContent = overview.incidents_count;
      document.getElementById("decisions").textContent = overview.decisions_count;

      const ib = incidents.items.map((i) =>
        `<tr>
          <td class="mono">${esc(fmtTs(i.ts))}</td>
          <td class="${sevClass(i.severity)}">${esc(i.severity)}</td>
          <td class="mono">${esc(i.incident_id)}</td>
          <td>${esc(i.summary)}</td>
        </tr>`
      ).join("");
      document.getElementById("incidentsBody").innerHTML = ib || `<tr><td colspan="4">No incidents for selected date.</td></tr>`;

      const db = decisions.items.map((d) =>
        `<tr>
          <td class="mono">${esc(fmtTs(d.ts))}</td>
          <td class="mono">${esc(d.action_type)}</td>
          <td>${Number(d.confidence).toFixed(2)}</td>
          <td>${esc(d.execution_result)}</td>
        </tr>`
      ).join("");
      document.getElementById("decisionsBody").innerHTML = db || `<tr><td colspan="4">No decisions for selected date.</td></tr>`;

      document.getElementById("foot").textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
    }

    async function run() {
      try {
        await refresh();
      } catch (e) {
        document.getElementById("foot").textContent = `Dashboard refresh failed: ${e.message}`;
      } finally {
        setTimeout(run, 4000);
      }
    }
    run();
  </script>
</body>
</html>
"#;

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
}
