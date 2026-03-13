use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ai::AiDecision;

// ---------------------------------------------------------------------------
// Decision log entry
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionEntry {
    pub ts: DateTime<Utc>,
    pub incident_id: String,
    pub host: String,
    pub ai_provider: String,

    /// Serialized AiAction tag (e.g. "block_ip", "ignore")
    pub action_type: String,
    pub target_ip: Option<String>,
    pub skill_id: Option<String>,

    pub confidence: f32,
    pub auto_executed: bool,
    pub dry_run: bool,

    /// AI's textual reasoning
    pub reason: String,
    pub estimated_threat: String,

    /// Result of skill execution ("ok", "skipped", "failed: ...")
    pub execution_result: String,
}

// ---------------------------------------------------------------------------
// Decision writer
// ---------------------------------------------------------------------------

pub struct DecisionWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
}

impl DecisionWriter {
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

    /// Append a decision to the daily JSONL.
    /// Rotates to a new file at midnight.
    pub fn write(&mut self, entry: &DecisionEntry) -> Result<()> {
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

        let line = serde_json::to_string(entry).context("failed to serialize decision entry")?;
        writeln!(self.writer, "{line}").context("failed to write decision entry")?;
        // Flush immediately — audit trail must survive a crash between decisions
        self.writer
            .flush()
            .context("failed to flush decision entry")?;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("decision writer flush failed: {e}");
        }
    }
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

// ---------------------------------------------------------------------------
// Helper: build DecisionEntry from an AiDecision
// ---------------------------------------------------------------------------

pub fn build_entry(
    incident_id: &str,
    host: &str,
    ai_provider: &str,
    decision: &AiDecision,
    dry_run: bool,
    execution_result: &str,
) -> DecisionEntry {
    use crate::ai::AiAction;

    let (action_type, target_ip, skill_id) = match &decision.action {
        AiAction::BlockIp { ip, skill_id } => (
            "block_ip".to_string(),
            Some(ip.clone()),
            Some(skill_id.clone()),
        ),
        AiAction::Monitor { ip } => ("monitor".to_string(), Some(ip.clone()), None),
        AiAction::Honeypot { ip } => ("honeypot".to_string(), Some(ip.clone()), None),
        AiAction::RequestConfirmation { .. } => ("request_confirmation".to_string(), None, None),
        AiAction::Ignore { .. } => ("ignore".to_string(), None, None),
    };

    DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.to_string(),
        host: host.to_string(),
        ai_provider: ai_provider.to_string(),
        action_type,
        target_ip,
        skill_id,
        confidence: decision.confidence,
        auto_executed: decision.auto_execute,
        dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.to_string(),
    }
}
