use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use innerwarden_core::{event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ai::AiAction;
use crate::correlation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub ts: DateTime<Utc>,
    pub tick: String,
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

#[derive(Debug, Default)]
pub struct TelemetryState {
    events_by_collector: HashMap<String, u64>,
    incidents_by_detector: HashMap<String, u64>,
    gate_pass_count: u64,
    ai_sent_count: u64,
    ai_decision_count: u64,
    decision_latency_sum_ms: u128,
    errors_by_component: HashMap<String, u64>,
    decisions_by_action: HashMap<String, u64>,
    dry_run_execution_count: u64,
    real_execution_count: u64,
}

impl TelemetryState {
    pub fn observe_events(&mut self, events: &[Event]) {
        for event in events {
            *self
                .events_by_collector
                .entry(event.source.clone())
                .or_insert(0) += 1;
        }
    }

    pub fn observe_incident(&mut self, incident: &Incident) {
        let kind = correlation::detector_kind(incident);
        *self.incidents_by_detector.entry(kind).or_insert(0) += 1;
    }

    pub fn observe_gate_pass(&mut self) {
        self.gate_pass_count += 1;
    }

    pub fn observe_ai_sent(&mut self) {
        self.ai_sent_count += 1;
    }

    pub fn observe_ai_decision(&mut self, action: &AiAction, latency_ms: u128) {
        self.ai_decision_count += 1;
        self.decision_latency_sum_ms += latency_ms;
        *self
            .decisions_by_action
            .entry(action_tag(action).to_string())
            .or_insert(0) += 1;
    }

    pub fn observe_execution_path(&mut self, dry_run: bool) {
        if dry_run {
            self.dry_run_execution_count += 1;
        } else {
            self.real_execution_count += 1;
        }
    }

    pub fn observe_error(&mut self, component: &str) {
        *self
            .errors_by_component
            .entry(component.to_string())
            .or_insert(0) += 1;
    }

    pub fn snapshot(&self, tick: &str) -> TelemetrySnapshot {
        let avg_latency = if self.ai_decision_count > 0 {
            self.decision_latency_sum_ms as f64 / self.ai_decision_count as f64
        } else {
            0.0
        };

        TelemetrySnapshot {
            ts: Utc::now(),
            tick: tick.to_string(),
            events_by_collector: to_btreemap(self.events_by_collector.clone()),
            incidents_by_detector: to_btreemap(self.incidents_by_detector.clone()),
            gate_pass_count: self.gate_pass_count,
            ai_sent_count: self.ai_sent_count,
            ai_decision_count: self.ai_decision_count,
            avg_decision_latency_ms: avg_latency,
            errors_by_component: to_btreemap(self.errors_by_component.clone()),
            decisions_by_action: to_btreemap(self.decisions_by_action.clone()),
            dry_run_execution_count: self.dry_run_execution_count,
            real_execution_count: self.real_execution_count,
        }
    }
}

pub struct TelemetryWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
}

impl TelemetryWriter {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
        })
    }

    pub fn write(&mut self, snapshot: &TelemetrySnapshot) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            self.writer.flush().ok();
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today;
        }

        let line =
            serde_json::to_string(snapshot).context("failed to serialize telemetry snapshot")?;
        writeln!(self.writer, "{line}").context("failed to write telemetry snapshot")?;
        self.writer
            .flush()
            .context("failed to flush telemetry snapshot")?;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("telemetry writer flush failed: {e}");
        }
    }
}

pub fn read_latest_snapshot(data_dir: &Path, date: &str) -> Option<TelemetrySnapshot> {
    let path = data_dir.join(format!("telemetry-{date}.jsonl"));
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut latest: Option<TelemetrySnapshot> = None;
    for line in reader.lines() {
        let line = line.ok()?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let snapshot: TelemetrySnapshot = serde_json::from_str(trimmed).ok()?;
        match &latest {
            Some(current) if current.ts >= snapshot.ts => {}
            _ => latest = Some(snapshot),
        }
    }

    latest
}

fn action_tag(action: &AiAction) -> &'static str {
    match action {
        AiAction::BlockIp { .. } => "block_ip",
        AiAction::Monitor { .. } => "monitor",
        AiAction::Honeypot { .. } => "honeypot",
        AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
        AiAction::KillProcess { .. } => "kill_process",
        AiAction::BlockContainer { .. } => "block_container",
        AiAction::RequestConfirmation { .. } => "request_confirmation",
        AiAction::Ignore { .. } => "ignore",
    }
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let path = data_dir.join(format!("telemetry-{date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn to_btreemap(map: HashMap<String, u64>) -> BTreeMap<String, u64> {
    map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    #[test]
    fn telemetry_state_tracks_counts_and_latency() {
        let mut state = TelemetryState::default();

        let ev = Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Severity::Info,
            summary: "x".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_events(&[ev]);

        let inc = Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_incident(&inc);
        state.observe_gate_pass();
        state.observe_ai_sent();
        state.observe_ai_decision(
            &ai::AiAction::BlockIp {
                ip: "1.2.3.4".to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            120,
        );
        state.observe_execution_path(true);
        state.observe_error("ai_provider");

        let snap = state.snapshot("incident_tick");
        assert_eq!(snap.events_by_collector.get("auth.log").copied(), Some(1));
        assert_eq!(
            snap.incidents_by_detector.get("ssh_bruteforce").copied(),
            Some(1)
        );
        assert_eq!(snap.gate_pass_count, 1);
        assert_eq!(snap.ai_sent_count, 1);
        assert_eq!(snap.ai_decision_count, 1);
        assert_eq!(snap.avg_decision_latency_ms, 120.0);
        assert_eq!(snap.dry_run_execution_count, 1);
        assert_eq!(snap.real_execution_count, 0);
        assert_eq!(
            snap.errors_by_component.get("ai_provider").copied(),
            Some(1)
        );
        assert_eq!(snap.decisions_by_action.get("block_ip").copied(), Some(1));
    }

    #[test]
    fn telemetry_writer_and_reader_roundtrip() {
        let dir = TempDir::new().unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let mut writer = TelemetryWriter::new(dir.path()).unwrap();

        let mut state = TelemetryState::default();
        state.observe_gate_pass();
        let first = state.snapshot("incident_tick");
        writer.write(&first).unwrap();

        state.observe_ai_sent();
        let second = state.snapshot("incident_tick");
        writer.write(&second).unwrap();
        writer.flush();

        let latest = read_latest_snapshot(dir.path(), &date).unwrap();
        assert_eq!(latest.ai_sent_count, 1);
        assert_eq!(latest.gate_pass_count, 1);
    }
}
