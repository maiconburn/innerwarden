use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDate, Utc};
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::Serialize;
use serde_json::Value;

use crate::decisions::DecisionEntry;
use crate::telemetry;

#[derive(Debug, Serialize)]
pub struct GeneratedReport {
    pub markdown_path: PathBuf,
    pub json_path: PathBuf,
    pub report: TrialReport,
}

#[derive(Debug, Serialize)]
pub struct TrialReport {
    pub generated_at: DateTime<Utc>,
    pub analyzed_date: String,
    pub data_dir: String,
    pub operational_health: OperationalHealth,
    pub operational_telemetry: OperationalTelemetry,
    pub detection_summary: DetectionSummary,
    pub agent_ai_summary: AgentAiSummary,
    pub trend_summary: TrendSummary,
    pub anomaly_hints: Vec<AnomalyHint>,
    pub data_quality: DataQuality,
    pub suggested_improvements: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OperationalHealth {
    pub expected_files_present: bool,
    pub state_json_readable: bool,
    pub agent_state_json_readable: bool,
    pub files: Vec<FileHealth>,
}

#[derive(Debug, Serialize)]
pub struct FileHealth {
    pub file: String,
    pub exists: bool,
    pub readable: bool,
    pub size_bytes: u64,
    pub modified_secs_ago: Option<u64>,
    pub jsonl_valid: Option<bool>,
    pub lines: Option<u64>,
    pub malformed_lines: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct OperationalTelemetry {
    pub available: bool,
    pub last_tick: Option<String>,
    pub events_by_collector: BTreeMap<String, u64>,
    pub incidents_by_detector: BTreeMap<String, u64>,
    pub gate_pass_count: u64,
    pub ai_sent_count: u64,
    pub ai_decision_count: u64,
    pub avg_decision_latency_ms: f64,
    pub errors_by_component: BTreeMap<String, u64>,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub dry_run_execution_count: u64,
    pub real_execution_count: u64,
}

#[derive(Debug, Serialize)]
pub struct DetectionSummary {
    pub total_events: u64,
    pub total_incidents: u64,
    pub incidents_by_type: BTreeMap<String, u64>,
    pub top_ips: Vec<NamedCount>,
    pub top_entities: Vec<NamedCount>,
}

#[derive(Debug, Serialize)]
pub struct AgentAiSummary {
    pub total_decisions: u64,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub average_confidence: f64,
    pub ignore_count: u64,
    pub block_ip_count: u64,
    pub dry_run_count: u64,
    pub skills_used: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct DataQuality {
    pub empty_files: Vec<String>,
    pub malformed_jsonl: BTreeMap<String, u64>,
    pub incidents_without_entities: u64,
    pub decisions_without_action: u64,
    pub files_not_growing: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TrendSummary {
    pub previous_date: Option<String>,
    pub events: CountDelta,
    pub incidents: CountDelta,
    pub decisions: CountDelta,
    pub incident_rate_per_1k_events: FloatDelta,
    pub decision_rate_per_incident: FloatDelta,
    pub average_confidence: FloatDelta,
}

#[derive(Debug, Serialize)]
pub struct CountDelta {
    pub current: u64,
    pub previous: u64,
    pub delta: i64,
    pub pct_change: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct FloatDelta {
    pub current: f64,
    pub previous: f64,
    pub delta: f64,
    pub pct_change: Option<f64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AnomalyHint {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Default, Clone)]
struct ParseOutcome {
    exists: bool,
    readable: bool,
    size_bytes: u64,
    modified_secs_ago: Option<u64>,
    lines: u64,
    malformed_lines: u64,
}

impl ParseOutcome {
    fn jsonl_valid(&self) -> bool {
        self.exists && self.readable && self.malformed_lines == 0
    }
}

#[derive(Debug, Default)]
struct Counters {
    total_events: u64,
    total_incidents: u64,
    total_decisions: u64,
    confidence_sum: f64,

    incidents_by_type: HashMap<String, u64>,
    ip_counts: HashMap<String, u64>,
    entity_counts: HashMap<String, u64>,
    decisions_by_action: HashMap<String, u64>,
    skills_used: HashMap<String, u64>,

    ignore_count: u64,
    block_ip_count: u64,
    dry_run_count: u64,

    incidents_without_entities: u64,
    decisions_without_action: u64,

    malformed_jsonl: BTreeMap<String, u64>,
    empty_files: Vec<String>,
    files_not_growing: Vec<String>,
}

pub fn generate(data_dir: &Path) -> Result<GeneratedReport> {
    let report_date = Local::now().date_naive().format("%Y-%m-%d").to_string();
    let analyzed_date = detect_latest_date(data_dir).unwrap_or_else(|| report_date.clone());
    let previous_date = detect_previous_date(data_dir, &analyzed_date);
    let analyzed_is_today = analyzed_date == report_date;

    let events = data_dir.join(format!("events-{analyzed_date}.jsonl"));
    let incidents = data_dir.join(format!("incidents-{analyzed_date}.jsonl"));
    let decisions = data_dir.join(format!("decisions-{analyzed_date}.jsonl"));
    let summary = data_dir.join(format!("summary-{analyzed_date}.md"));
    let state = data_dir.join("state.json");
    let agent_state = data_dir.join("agent-state.json");

    let mut counters = Counters::default();
    let mut files = Vec::new();

    let events_outcome = parse_events_file(&events, &mut counters);
    record_quality_hints("events", &events_outcome, analyzed_is_today, &mut counters);
    files.push(file_health_jsonl("events", &events_outcome));

    let incidents_outcome = parse_incidents_file(&incidents, &mut counters);
    record_quality_hints(
        "incidents",
        &incidents_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("incidents", &incidents_outcome));

    let decisions_outcome = parse_decisions_file(&decisions, &mut counters);
    record_quality_hints(
        "decisions",
        &decisions_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("decisions", &decisions_outcome));

    let summary_info = parse_plain_file(&summary);
    record_plain_file_hints("summary", &summary_info, analyzed_is_today, &mut counters);
    files.push(file_health_plain("summary", &summary_info));

    let state_info = parse_state_file(&state);
    record_plain_file_hints("state", &state_info, false, &mut counters);
    files.push(file_health_plain("state", &state_info));

    let agent_state_info = parse_state_file(&agent_state);
    record_plain_file_hints("agent-state", &agent_state_info, false, &mut counters);
    files.push(file_health_plain("agent-state", &agent_state_info));

    let expected_files_present = files.iter().all(|f| f.exists);
    let state_json_readable = state_info.exists && state_info.readable;
    let agent_state_json_readable = agent_state_info.exists && agent_state_info.readable;
    let operational_telemetry = build_operational_telemetry(data_dir, &analyzed_date);

    let detection_summary = DetectionSummary {
        total_events: counters.total_events,
        total_incidents: counters.total_incidents,
        incidents_by_type: to_btreemap(counters.incidents_by_type.clone()),
        top_ips: top_n(&counters.ip_counts, 10),
        top_entities: top_n(&counters.entity_counts, 10),
    };

    let avg_conf = if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    };
    let agent_ai_summary = AgentAiSummary {
        total_decisions: counters.total_decisions,
        decisions_by_action: to_btreemap(counters.decisions_by_action.clone()),
        average_confidence: avg_conf,
        ignore_count: counters.ignore_count,
        block_ip_count: counters.block_ip_count,
        dry_run_count: counters.dry_run_count,
        skills_used: to_btreemap(counters.skills_used.clone()),
    };

    let data_quality = DataQuality {
        empty_files: counters.empty_files.clone(),
        malformed_jsonl: counters.malformed_jsonl.clone(),
        incidents_without_entities: counters.incidents_without_entities,
        decisions_without_action: counters.decisions_without_action,
        files_not_growing: counters.files_not_growing.clone(),
    };

    let previous_counters = previous_date
        .as_ref()
        .map(|date| compute_day_counters(data_dir, date));

    let trend_summary = build_trend_summary(&counters, previous_counters.as_ref(), previous_date);
    let anomaly_hints = build_anomaly_hints(
        &detection_summary,
        &agent_ai_summary,
        &data_quality,
        &trend_summary,
        previous_counters.as_ref(),
    );

    let operational_health = OperationalHealth {
        expected_files_present,
        state_json_readable,
        agent_state_json_readable,
        files,
    };

    let mut report = TrialReport {
        generated_at: Utc::now(),
        analyzed_date,
        data_dir: data_dir.display().to_string(),
        operational_health,
        operational_telemetry,
        detection_summary,
        agent_ai_summary,
        trend_summary,
        anomaly_hints,
        data_quality,
        suggested_improvements: vec![],
    };
    report.suggested_improvements = build_suggestions(&report);

    let json_path = data_dir.join(format!("trial-report-{report_date}.json"));
    let md_path = data_dir.join(format!("trial-report-{report_date}.md"));

    let json_file = File::create(&json_path)
        .with_context(|| format!("failed to create {}", json_path.display()))?;
    serde_json::to_writer_pretty(json_file, &report)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    let markdown = render_markdown(&report);
    fs::write(&md_path, markdown)
        .with_context(|| format!("failed to write {}", md_path.display()))?;

    Ok(GeneratedReport {
        markdown_path: md_path,
        json_path,
        report,
    })
}

fn detect_latest_date(data_dir: &Path) -> Option<String> {
    collect_available_dates(data_dir).into_iter().max()
}

fn detect_previous_date(data_dir: &Path, analyzed_date: &str) -> Option<String> {
    collect_available_dates(data_dir)
        .into_iter()
        .filter(|date| date.as_str() < analyzed_date)
        .max()
}

fn collect_available_dates(data_dir: &Path) -> Vec<String> {
    let mut dates = BTreeSet::new();
    let entries = match fs::read_dir(data_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let candidate = extract_date(&name, "events-", ".jsonl")
            .or_else(|| extract_date(&name, "incidents-", ".jsonl"))
            .or_else(|| extract_date(&name, "decisions-", ".jsonl"))
            .or_else(|| extract_date(&name, "summary-", ".md"));
        if let Some(date) = candidate {
            dates.insert(date);
        }
    }

    dates.into_iter().collect()
}

fn build_operational_telemetry(data_dir: &Path, analyzed_date: &str) -> OperationalTelemetry {
    match telemetry::read_latest_snapshot(data_dir, analyzed_date) {
        Some(snapshot) => OperationalTelemetry {
            available: true,
            last_tick: Some(snapshot.tick),
            events_by_collector: snapshot.events_by_collector,
            incidents_by_detector: snapshot.incidents_by_detector,
            gate_pass_count: snapshot.gate_pass_count,
            ai_sent_count: snapshot.ai_sent_count,
            ai_decision_count: snapshot.ai_decision_count,
            avg_decision_latency_ms: snapshot.avg_decision_latency_ms,
            errors_by_component: snapshot.errors_by_component,
            decisions_by_action: snapshot.decisions_by_action,
            dry_run_execution_count: snapshot.dry_run_execution_count,
            real_execution_count: snapshot.real_execution_count,
        },
        None => OperationalTelemetry {
            available: false,
            last_tick: None,
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            ai_sent_count: 0,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        },
    }
}

fn extract_date(name: &str, prefix: &str, suffix: &str) -> Option<String> {
    let raw = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .map(|_| raw.to_string())
}

fn parse_events_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |event: Event| {
        counters.total_events += 1;

        for e in event.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

fn parse_incidents_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |incident: Incident| {
        counters.total_incidents += 1;

        let incident_type = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *counters.incidents_by_type.entry(incident_type).or_insert(0) += 1;

        if incident.entities.is_empty() {
            counters.incidents_without_entities += 1;
        }

        for e in incident.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

fn parse_decisions_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;

        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        let action_present = value
            .get("action_type")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !action_present {
            counters.decisions_without_action += 1;
        }

        let decision: DecisionEntry = match serde_json::from_value(value) {
            Ok(d) => d,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        counters.total_decisions += 1;
        counters.confidence_sum += f64::from(decision.confidence);

        *counters
            .decisions_by_action
            .entry(decision.action_type.clone())
            .or_insert(0) += 1;

        if decision.action_type == "ignore" {
            counters.ignore_count += 1;
        }
        if decision.action_type == "block_ip" {
            counters.block_ip_count += 1;
        }
        if decision.dry_run {
            counters.dry_run_count += 1;
        }
        if let Some(skill) = decision.skill_id {
            *counters.skills_used.entry(skill).or_insert(0) += 1;
        }
    }

    outcome
}

fn compute_day_counters(data_dir: &Path, date: &str) -> Counters {
    let events = data_dir.join(format!("events-{date}.jsonl"));
    let incidents = data_dir.join(format!("incidents-{date}.jsonl"));
    let decisions = data_dir.join(format!("decisions-{date}.jsonl"));

    let mut counters = Counters::default();
    parse_events_file(&events, &mut counters);
    parse_incidents_file(&incidents, &mut counters);
    parse_decisions_file(&decisions, &mut counters);
    counters
}

fn parse_state_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    let content = match fs::read_to_string(path) {
        Ok(c) => {
            outcome.readable = true;
            c
        }
        Err(_) => return outcome,
    };
    if serde_json::from_str::<Value>(&content).is_err() {
        outcome.readable = false;
    }
    outcome
}

fn parse_plain_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    if File::open(path).is_ok() {
        outcome.readable = true;
    }
    outcome
}

fn parse_jsonl<T, F>(path: &Path, mut on_item: F) -> ParseOutcome
where
    T: serde::de::DeserializeOwned,
    F: FnMut(T),
{
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;
        match serde_json::from_str::<T>(trimmed) {
            Ok(item) => on_item(item),
            Err(_) => outcome.malformed_lines += 1,
        }
    }

    outcome
}

fn file_info(path: &Path) -> ParseOutcome {
    match fs::metadata(path) {
        Ok(meta) => ParseOutcome {
            exists: true,
            size_bytes: meta.len(),
            modified_secs_ago: meta
                .modified()
                .ok()
                .and_then(|m| SystemTime::now().duration_since(m).ok())
                .map(|d| d.as_secs()),
            ..Default::default()
        },
        Err(_) => ParseOutcome::default(),
    }
}

fn file_health_jsonl(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: Some(outcome.jsonl_valid()),
        lines: Some(outcome.lines),
        malformed_lines: Some(outcome.malformed_lines),
    }
}

fn file_health_plain(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: None,
        lines: None,
        malformed_lines: None,
    }
}

fn record_quality_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if outcome.malformed_lines > 0 {
        counters
            .malformed_jsonl
            .insert(name.to_string(), outcome.malformed_lines);
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn record_plain_file_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn to_btreemap(map: HashMap<String, u64>) -> BTreeMap<String, u64> {
    map.into_iter().collect()
}

fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<NamedCount> {
    let mut items: Vec<NamedCount> = map
        .iter()
        .map(|(name, count)| NamedCount {
            name: name.clone(),
            count: *count,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    items.truncate(n);
    items
}

fn build_trend_summary(
    current: &Counters,
    previous: Option<&Counters>,
    previous_date: Option<String>,
) -> TrendSummary {
    let previous_events = previous.map(|c| c.total_events).unwrap_or(0);
    let previous_incidents = previous.map(|c| c.total_incidents).unwrap_or(0);
    let previous_decisions = previous.map(|c| c.total_decisions).unwrap_or(0);

    let current_incident_rate = incident_rate_per_1k_events(current);
    let previous_incident_rate = previous.map(incident_rate_per_1k_events).unwrap_or(0.0);

    let current_decision_rate = decision_rate_per_incident(current);
    let previous_decision_rate = previous.map(decision_rate_per_incident).unwrap_or(0.0);

    let current_avg_conf = average_confidence(current);
    let previous_avg_conf = previous.map(average_confidence).unwrap_or(0.0);

    TrendSummary {
        previous_date,
        events: count_delta(current.total_events, previous_events),
        incidents: count_delta(current.total_incidents, previous_incidents),
        decisions: count_delta(current.total_decisions, previous_decisions),
        incident_rate_per_1k_events: float_delta(current_incident_rate, previous_incident_rate),
        decision_rate_per_incident: float_delta(current_decision_rate, previous_decision_rate),
        average_confidence: float_delta(current_avg_conf, previous_avg_conf),
    }
}

fn build_anomaly_hints(
    detection_summary: &DetectionSummary,
    agent_ai_summary: &AgentAiSummary,
    data_quality: &DataQuality,
    trend_summary: &TrendSummary,
    previous: Option<&Counters>,
) -> Vec<AnomalyHint> {
    let mut hints = Vec::new();

    if !data_quality.malformed_jsonl.is_empty() {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "malformed_jsonl".to_string(),
            message: format!(
                "Malformed JSONL detected: {}.",
                map_or_none(&data_quality.malformed_jsonl)
            ),
        });
    }

    if detection_summary.total_events == 0 {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "no_events".to_string(),
            message:
                "No events captured for analyzed day; collectors may be blocked or misconfigured."
                    .to_string(),
        });
    }

    if detection_summary.total_incidents > 0 && agent_ai_summary.total_decisions == 0 {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "incident_without_ai_decision".to_string(),
            message: "Incidents exist but no AI decisions were recorded; check agent AI settings and credentials."
                .to_string(),
        });
    }

    if trend_summary.incidents.previous > 0
        && trend_summary.incidents.delta >= 5
        && trend_summary.incidents.pct_change.unwrap_or(0.0) >= 100.0
    {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "incident_spike".to_string(),
            message: format!(
                "Incidents doubled or more vs previous day (delta: {}).",
                signed_i64(trend_summary.incidents.delta)
            ),
        });
    }

    if trend_summary.average_confidence.delta <= -0.2
        && trend_summary.decisions.current >= 5
        && trend_summary.decisions.previous >= 5
    {
        hints.push(AnomalyHint {
            severity: "medium".to_string(),
            code: "confidence_drop".to_string(),
            message: format!(
                "Average AI confidence dropped from {:.3} to {:.3}.",
                trend_summary.average_confidence.previous, trend_summary.average_confidence.current
            ),
        });
    }

    if agent_ai_summary.total_decisions >= 10 {
        let ignore_ratio =
            agent_ai_summary.ignore_count as f64 / agent_ai_summary.total_decisions as f64;
        if ignore_ratio > 0.9 {
            hints.push(AnomalyHint {
                severity: "medium".to_string(),
                code: "ignore_saturation".to_string(),
                message: format!(
                    "Ignore ratio is {:.1}% ({} of {} decisions).",
                    ignore_ratio * 100.0,
                    agent_ai_summary.ignore_count,
                    agent_ai_summary.total_decisions
                ),
            });
        }
    }

    if let Some(previous) = previous {
        let mut new_incident_types = Vec::new();
        for (kind, count) in &detection_summary.incidents_by_type {
            let previous_count = previous.incidents_by_type.get(kind).copied().unwrap_or(0);
            if previous_count == 0 && *count >= 3 {
                new_incident_types.push(kind.clone());
            }
        }
        if !new_incident_types.is_empty() {
            new_incident_types.sort();
            hints.push(AnomalyHint {
                severity: "medium".to_string(),
                code: "new_incident_type".to_string(),
                message: format!(
                    "New incident types crossed noise floor: {}.",
                    new_incident_types.join(", ")
                ),
            });
        }
    }

    if !data_quality.files_not_growing.is_empty() {
        hints.push(AnomalyHint {
            severity: "medium".to_string(),
            code: "stale_ingest_files".to_string(),
            message: format!(
                "Some active-day artifacts look stale: {}.",
                list_or_none(&data_quality.files_not_growing)
            ),
        });
    }

    hints
}

fn count_delta(current: u64, previous: u64) -> CountDelta {
    CountDelta {
        current,
        previous,
        delta: signed_u64_diff(current, previous),
        pct_change: pct_change(current as f64, previous as f64),
    }
}

fn float_delta(current: f64, previous: f64) -> FloatDelta {
    FloatDelta {
        current,
        previous,
        delta: current - previous,
        pct_change: pct_change(current, previous),
    }
}

fn average_confidence(counters: &Counters) -> f64 {
    if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    }
}

fn incident_rate_per_1k_events(counters: &Counters) -> f64 {
    if counters.total_events > 0 {
        counters.total_incidents as f64 * 1000.0 / counters.total_events as f64
    } else {
        0.0
    }
}

fn decision_rate_per_incident(counters: &Counters) -> f64 {
    if counters.total_incidents > 0 {
        counters.total_decisions as f64 / counters.total_incidents as f64
    } else {
        0.0
    }
}

fn pct_change(current: f64, previous: f64) -> Option<f64> {
    if previous.abs() < f64::EPSILON {
        None
    } else {
        Some(((current - previous) / previous) * 100.0)
    }
}

fn signed_u64_diff(current: u64, previous: u64) -> i64 {
    if current >= previous {
        (current - previous).min(i64::MAX as u64) as i64
    } else {
        -((previous - current).min(i64::MAX as u64) as i64)
    }
}

fn build_suggestions(report: &TrialReport) -> Vec<String> {
    let mut suggestions = Vec::new();

    if !report.operational_health.expected_files_present {
        suggestions.push(
            "Some expected artifacts are missing; verify both sensor and agent services are running."
                .to_string(),
        );
    }
    if !report.operational_health.state_json_readable
        || !report.operational_health.agent_state_json_readable
    {
        suggestions.push(
            "State files could not be parsed; inspect state.json/agent-state.json integrity."
                .to_string(),
        );
    }
    if !report.data_quality.malformed_jsonl.is_empty() {
        suggestions.push(
            "Malformed JSONL lines detected; review producer logs and rotate corrupted files."
                .to_string(),
        );
    }
    if report.detection_summary.total_events == 0 {
        suggestions.push(
            "No events were captured; validate collector permissions (auth.log/journald access)."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents == 0 && report.detection_summary.total_events > 0 {
        suggestions.push(
            "Events exist but no incidents; run a controlled SSH brute-force test to validate detection."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents > 0 && report.agent_ai_summary.total_decisions == 0
    {
        suggestions.push(
            "Incidents exist but no AI decisions; verify agent AI config and API key availability."
                .to_string(),
        );
    }
    if report.agent_ai_summary.total_decisions > 0 {
        let ignore_ratio = report.agent_ai_summary.ignore_count as f64
            / report.agent_ai_summary.total_decisions as f64;
        if ignore_ratio > 0.8 {
            suggestions.push(
                "Most AI decisions are ignore; review detector thresholds and context_events for signal quality."
                    .to_string(),
            );
        }
    }
    if report.data_quality.incidents_without_entities > 0 {
        suggestions.push(
            "Some incidents were emitted without entities; improve detector payload completeness."
                .to_string(),
        );
    }
    if !report.data_quality.files_not_growing.is_empty() {
        suggestions.push(
            "Some active-day files appear stale (>6h without updates); verify ingest pipeline health."
                .to_string(),
        );
    }
    if !report.operational_telemetry.available {
        suggestions.push(
            "Operational telemetry snapshot not found; run agent with telemetry enabled to improve rollout confidence."
                .to_string(),
        );
    } else {
        if !report.operational_telemetry.errors_by_component.is_empty() {
            suggestions.push(
                "Operational telemetry reports component errors; inspect error counters before widening rollout."
                    .to_string(),
            );
        }
        if report.operational_telemetry.ai_decision_count > 0
            && report.operational_telemetry.avg_decision_latency_ms > 2000.0
        {
            suggestions.push(
                "AI decision latency is high (>2s avg); review provider/network latency before enabling broader active response."
                    .to_string(),
            );
        }
    }
    if !report.anomaly_hints.is_empty() {
        suggestions.push(
            "Review anomaly hints for day-over-day spikes and behavior shifts before changing responder settings."
                .to_string(),
        );
    }
    if suggestions.is_empty() {
        suggestions.push(
            "Trial looks healthy; proceed to next phase by enabling responder in dry-run mode."
                .to_string(),
        );
    }

    suggestions
}

fn render_markdown(report: &TrialReport) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "# InnerWarden Trial Report");
    let _ = writeln!(&mut out);
    let _ = writeln!(
        &mut out,
        "- Generated at: {}",
        report.generated_at.to_rfc3339()
    );
    let _ = writeln!(&mut out, "- Analyzed date: {}", report.analyzed_date);
    let _ = writeln!(&mut out, "- Data dir: `{}`", report.data_dir);
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Operational health");
    let _ = writeln!(
        &mut out,
        "- Expected files present: {}",
        yes_no(report.operational_health.expected_files_present)
    );
    let _ = writeln!(
        &mut out,
        "- state.json readable: {}",
        yes_no(report.operational_health.state_json_readable)
    );
    let _ = writeln!(
        &mut out,
        "- agent-state.json readable: {}",
        yes_no(report.operational_health.agent_state_json_readable)
    );
    let _ = writeln!(&mut out);
    let _ = writeln!(
        &mut out,
        "| File | Exists | Readable | Size (bytes) | JSONL valid | Lines | Malformed |"
    );
    let _ = writeln!(
        &mut out,
        "|------|--------|----------|--------------|-------------|-------|-----------|"
    );
    for f in &report.operational_health.files {
        let _ = writeln!(
            &mut out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            f.file,
            yes_no(f.exists),
            yes_no(f.readable),
            f.size_bytes,
            f.jsonl_valid.map(yes_no).unwrap_or_else(|| "-".to_string()),
            f.lines
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            f.malformed_lines
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Detection summary");
    let _ = writeln!(
        &mut out,
        "- Total events: {}",
        report.detection_summary.total_events
    );
    let _ = writeln!(
        &mut out,
        "- Total incidents: {}",
        report.detection_summary.total_incidents
    );
    let _ = writeln!(&mut out, "- Incidents by type:");
    if report.detection_summary.incidents_by_type.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.detection_summary.incidents_by_type {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Top IPs:");
    if report.detection_summary.top_ips.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_ips {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out, "- Most frequent entities:");
    if report.detection_summary.top_entities.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_entities {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Agent / AI summary");
    let _ = writeln!(
        &mut out,
        "- Total decisions: {}",
        report.agent_ai_summary.total_decisions
    );
    let _ = writeln!(
        &mut out,
        "- Average confidence: {:.3}",
        report.agent_ai_summary.average_confidence
    );
    let _ = writeln!(
        &mut out,
        "- Ignore decisions: {}",
        report.agent_ai_summary.ignore_count
    );
    let _ = writeln!(
        &mut out,
        "- block_ip decisions: {}",
        report.agent_ai_summary.block_ip_count
    );
    let _ = writeln!(
        &mut out,
        "- Dry-run decisions: {}",
        report.agent_ai_summary.dry_run_count
    );
    let _ = writeln!(&mut out, "- Decisions by action:");
    if report.agent_ai_summary.decisions_by_action.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.decisions_by_action {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Skills used:");
    if report.agent_ai_summary.skills_used.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.skills_used {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Operational telemetry");
    let _ = writeln!(
        &mut out,
        "- Available: {}",
        yes_no(report.operational_telemetry.available)
    );
    if let Some(last_tick) = &report.operational_telemetry.last_tick {
        let _ = writeln!(&mut out, "- Last tick snapshot: {}", last_tick);
    } else {
        let _ = writeln!(&mut out, "- Last tick snapshot: none");
    }
    let _ = writeln!(
        &mut out,
        "- Gate pass count: {}",
        report.operational_telemetry.gate_pass_count
    );
    let _ = writeln!(
        &mut out,
        "- AI sent count: {}",
        report.operational_telemetry.ai_sent_count
    );
    let _ = writeln!(
        &mut out,
        "- AI decision count: {}",
        report.operational_telemetry.ai_decision_count
    );
    let _ = writeln!(
        &mut out,
        "- Avg decision latency (ms): {:.2}",
        report.operational_telemetry.avg_decision_latency_ms
    );
    let _ = writeln!(
        &mut out,
        "- Dry-run executions: {}",
        report.operational_telemetry.dry_run_execution_count
    );
    let _ = writeln!(
        &mut out,
        "- Real executions: {}",
        report.operational_telemetry.real_execution_count
    );
    let _ = writeln!(&mut out, "- Events by collector:");
    if report.operational_telemetry.events_by_collector.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (collector, count) in &report.operational_telemetry.events_by_collector {
            let _ = writeln!(&mut out, "  - {}: {}", collector, count);
        }
    }
    let _ = writeln!(&mut out, "- Incidents by detector:");
    if report
        .operational_telemetry
        .incidents_by_detector
        .is_empty()
    {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (detector, count) in &report.operational_telemetry.incidents_by_detector {
            let _ = writeln!(&mut out, "  - {}: {}", detector, count);
        }
    }
    let _ = writeln!(&mut out, "- Errors by component:");
    if report.operational_telemetry.errors_by_component.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (component, count) in &report.operational_telemetry.errors_by_component {
            let _ = writeln!(&mut out, "  - {}: {}", component, count);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Trend deltas (v2)");
    match &report.trend_summary.previous_date {
        Some(previous_date) => {
            let _ = writeln!(&mut out, "- Previous date: {}", previous_date);
            let _ = writeln!(
                &mut out,
                "- Events: {}",
                render_count_delta(&report.trend_summary.events)
            );
            let _ = writeln!(
                &mut out,
                "- Incidents: {}",
                render_count_delta(&report.trend_summary.incidents)
            );
            let _ = writeln!(
                &mut out,
                "- Decisions: {}",
                render_count_delta(&report.trend_summary.decisions)
            );
            let _ = writeln!(
                &mut out,
                "- Incident rate / 1k events: {}",
                render_float_delta(&report.trend_summary.incident_rate_per_1k_events, 3)
            );
            let _ = writeln!(
                &mut out,
                "- Decision rate / incident: {}",
                render_float_delta(&report.trend_summary.decision_rate_per_incident, 3)
            );
            let _ = writeln!(
                &mut out,
                "- Average confidence: {}",
                render_float_delta(&report.trend_summary.average_confidence, 3)
            );
        }
        None => {
            let _ = writeln!(
                &mut out,
                "- No previous day artifacts found; trend deltas will appear after another full day."
            );
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Anomaly hints");
    if report.anomaly_hints.is_empty() {
        let _ = writeln!(&mut out, "- none");
    } else {
        for hint in &report.anomaly_hints {
            let _ = writeln!(
                &mut out,
                "- [{}] {}: {}",
                hint.severity, hint.code, hint.message
            );
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Data quality / anomalies");
    let _ = writeln!(
        &mut out,
        "- Empty files: {}",
        list_or_none(&report.data_quality.empty_files)
    );
    let _ = writeln!(
        &mut out,
        "- Malformed JSONL: {}",
        map_or_none(&report.data_quality.malformed_jsonl)
    );
    let _ = writeln!(
        &mut out,
        "- Incidents without entities: {}",
        report.data_quality.incidents_without_entities
    );
    let _ = writeln!(
        &mut out,
        "- Decisions without action: {}",
        report.data_quality.decisions_without_action
    );
    let _ = writeln!(
        &mut out,
        "- Files not growing (heuristic): {}",
        list_or_none(&report.data_quality.files_not_growing)
    );
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Suggested improvements");
    for suggestion in &report.suggested_improvements {
        let _ = writeln!(&mut out, "- {}", suggestion);
    }

    out
}

fn yes_no(v: bool) -> String {
    if v {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn render_count_delta(delta: &CountDelta) -> String {
    format!(
        "current={} previous={} delta={} ({})",
        delta.current,
        delta.previous,
        signed_i64(delta.delta),
        format_pct(delta.pct_change)
    )
}

fn render_float_delta(delta: &FloatDelta, precision: usize) -> String {
    format!(
        "current={cur:.p$} previous={prev:.p$} delta={signed} ({pct})",
        cur = delta.current,
        prev = delta.previous,
        p = precision,
        signed = signed_f64(delta.delta, precision),
        pct = format_pct(delta.pct_change)
    )
}

fn signed_i64(v: i64) -> String {
    if v > 0 {
        format!("+{v}")
    } else {
        v.to_string()
    }
}

fn signed_f64(v: f64, precision: usize) -> String {
    if v > 0.0 {
        format!("+{:.*}", precision, v)
    } else {
        format!("{:.*}", precision, v)
    }
}

fn format_pct(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{:+.1}%", v),
        None => "n/a".to_string(),
    }
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn map_or_none(items: &BTreeMap<String, u64>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    use crate::telemetry::TelemetrySnapshot;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    #[test]
    fn generates_report_files_and_counts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let decisions_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let summary_path = dir.path().join(format!("summary-{date}.md"));
        let state_path = dir.path().join("state.json");
        let agent_state_path = dir.path().join("agent-state.json");

        let e1 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
        };
        let e2 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail2".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &events_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&e1).unwrap(),
                serde_json::to_string(&e2).unwrap()
            ),
        )
        .unwrap();

        let inc = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &incidents_path,
            format!("{}\n", serde_json::to_string(&inc).unwrap()),
        )
        .unwrap();

        let dec = DecisionEntry {
            ts: Utc::now(),
            incident_id: inc.incident_id.clone(),
            host: "h".to_string(),
            ai_provider: "openai".to_string(),
            action_type: "ignore".to_string(),
            target_ip: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: false,
            dry_run: true,
            reason: "test".to_string(),
            estimated_threat: "low".to_string(),
            execution_result: "skipped".to_string(),
        };
        fs::write(
            &decisions_path,
            format!("{}\n", serde_json::to_string(&dec).unwrap()),
        )
        .unwrap();

        fs::write(&summary_path, "# summary\n").unwrap();
        fs::write(&state_path, r#"{"cursors":{"auth_log":10}}"#).unwrap();
        fs::write(
            &agent_state_path,
            r#"{"events":{"2026-03-13":10},"incidents":{"2026-03-13":5}}"#,
        )
        .unwrap();

        let out = generate(dir.path()).unwrap();
        assert!(out.markdown_path.exists());
        assert!(out.json_path.exists());
        assert_eq!(out.report.detection_summary.total_events, 2);
        assert_eq!(out.report.detection_summary.total_incidents, 1);
        assert_eq!(out.report.agent_ai_summary.total_decisions, 1);
        assert!(out.report.trend_summary.previous_date.is_none());
    }

    #[test]
    fn tracks_malformed_decisions_and_missing_action() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            "not-json\n",
        )
        .unwrap();
        fs::write(dir.path().join(format!("incidents-{date}.jsonl")), "").unwrap();
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            r#"{"foo":"bar","confidence":0.5}"#,
        )
        .unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let out = generate(dir.path()).unwrap();
        assert!(out.report.data_quality.decisions_without_action > 0);
        assert!(!out.report.data_quality.malformed_jsonl.is_empty());
        let anomaly_codes: HashSet<&str> = out
            .report
            .anomaly_hints
            .iter()
            .map(|hint| hint.code.as_str())
            .collect();
        assert!(anomaly_codes.contains("malformed_jsonl"));
    }

    #[test]
    fn computes_day_over_day_trends_and_anomalies() {
        let dir = TempDir::new().unwrap();
        let previous_date = "2026-03-12";
        let current_date = "2026-03-13";

        let previous_events = dir.path().join(format!("events-{previous_date}.jsonl"));
        let previous_incidents = dir.path().join(format!("incidents-{previous_date}.jsonl"));
        let previous_decisions = dir.path().join(format!("decisions-{previous_date}.jsonl"));
        let previous_summary = dir.path().join(format!("summary-{previous_date}.md"));

        let current_events = dir.path().join(format!("events-{current_date}.jsonl"));
        let current_incidents = dir.path().join(format!("incidents-{current_date}.jsonl"));
        let current_decisions = dir.path().join(format!("decisions-{current_date}.jsonl"));
        let current_summary = dir.path().join(format!("summary-{current_date}.md"));

        let state_path = dir.path().join("state.json");
        let agent_state_path = dir.path().join("agent-state.json");

        let prev_events_payload = (0..4)
            .map(|_| {
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "prev".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&previous_events, format!("{prev_events_payload}\n")).unwrap();

        let previous_incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:prev".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "prev".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &previous_incidents,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&previous_incident).unwrap(),
                serde_json::to_string(&previous_incident).unwrap()
            ),
        )
        .unwrap();

        let previous_decisions_payload = (0..6)
            .map(|i| {
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: format!("prev-{i}"),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: if i == 0 { "ignore" } else { "block_ip" }.to_string(),
                    target_ip: Some("1.2.3.4".to_string()),
                    skill_id: Some("block-ip-ufw".to_string()),
                    confidence: 0.95,
                    auto_executed: false,
                    dry_run: true,
                    reason: "prev".to_string(),
                    estimated_threat: "high".to_string(),
                    execution_result: "skipped".to_string(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            &previous_decisions,
            format!("{previous_decisions_payload}\n"),
        )
        .unwrap();
        fs::write(&previous_summary, "# prev\n").unwrap();

        let current_events_payload = (0..20)
            .map(|_| {
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "current".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&current_events, format!("{current_events_payload}\n")).unwrap();

        let current_bruteforce = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:current".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "current".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        let current_port_scan = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "port_scan:1.2.3.4:current".to_string(),
            severity: Severity::High,
            title: "port scan".to_string(),
            summary: "current".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        let current_incidents_payload = vec![
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
        ]
        .into_iter()
        .map(|incident| serde_json::to_string(incident).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        fs::write(&current_incidents, format!("{current_incidents_payload}\n")).unwrap();

        let current_decisions_payload = (0..12)
            .map(|i| {
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: format!("current-{i}"),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: if i < 11 { "ignore" } else { "block_ip" }.to_string(),
                    target_ip: Some("1.2.3.4".to_string()),
                    skill_id: Some("block-ip-ufw".to_string()),
                    confidence: 0.4,
                    auto_executed: false,
                    dry_run: true,
                    reason: "current".to_string(),
                    estimated_threat: "medium".to_string(),
                    execution_result: "skipped".to_string(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&current_decisions, format!("{current_decisions_payload}\n")).unwrap();

        fs::write(&current_summary, "# current\n").unwrap();
        fs::write(&state_path, r#"{"cursors":{"auth_log":10}}"#).unwrap();
        fs::write(
            &agent_state_path,
            r#"{"events":{"2026-03-13":10},"incidents":{"2026-03-13":5}}"#,
        )
        .unwrap();

        let out = generate(dir.path()).unwrap();

        assert_eq!(
            out.report.trend_summary.previous_date,
            Some(previous_date.to_string())
        );
        assert_eq!(out.report.trend_summary.incidents.current, 10);
        assert_eq!(out.report.trend_summary.incidents.previous, 2);
        assert_eq!(out.report.trend_summary.incidents.delta, 8);
        assert!(out.report.trend_summary.incidents.pct_change.unwrap_or(0.0) > 100.0);

        let anomaly_codes: HashSet<&str> = out
            .report
            .anomaly_hints
            .iter()
            .map(|hint| hint.code.as_str())
            .collect();
        assert!(anomaly_codes.contains("incident_spike"));
        assert!(anomaly_codes.contains("confidence_drop"));
        assert!(anomaly_codes.contains("ignore_saturation"));
        assert!(anomaly_codes.contains("new_incident_type"));
    }

    #[test]
    fn reads_operational_telemetry_snapshot() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "event".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4")],
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("incidents-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&Incident {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
                    severity: Severity::High,
                    title: "bruteforce".to_string(),
                    summary: "summary".to_string(),
                    evidence: serde_json::json!({}),
                    recommended_checks: vec![],
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4")],
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: "ignore".to_string(),
                    target_ip: None,
                    skill_id: None,
                    confidence: 0.9,
                    auto_executed: false,
                    dry_run: true,
                    reason: "test".to_string(),
                    estimated_threat: "low".to_string(),
                    execution_result: "skipped".to_string(),
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "# summary\n").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let mut events_by_collector = BTreeMap::new();
        events_by_collector.insert("auth.log".to_string(), 12);
        let mut incidents_by_detector = BTreeMap::new();
        incidents_by_detector.insert("ssh_bruteforce".to_string(), 4);
        let mut errors_by_component = BTreeMap::new();
        errors_by_component.insert("webhook".to_string(), 1);
        let mut decisions_by_action = BTreeMap::new();
        decisions_by_action.insert("block_ip".to_string(), 3);

        let snapshot = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "incident_tick".to_string(),
            events_by_collector,
            incidents_by_detector,
            gate_pass_count: 4,
            ai_sent_count: 4,
            ai_decision_count: 4,
            avg_decision_latency_ms: 210.0,
            errors_by_component,
            decisions_by_action,
            dry_run_execution_count: 3,
            real_execution_count: 0,
        };
        fs::write(
            dir.path().join(format!("telemetry-{date}.jsonl")),
            format!("{}\n", serde_json::to_string(&snapshot).unwrap()),
        )
        .unwrap();

        let out = generate(dir.path()).unwrap();
        assert!(out.report.operational_telemetry.available);
        assert_eq!(
            out.report
                .operational_telemetry
                .events_by_collector
                .get("auth.log")
                .copied(),
            Some(12)
        );
        assert_eq!(out.report.operational_telemetry.gate_pass_count, 4);
        assert_eq!(
            out.report
                .operational_telemetry
                .errors_by_component
                .get("webhook")
                .copied(),
            Some(1)
        );
    }
}
