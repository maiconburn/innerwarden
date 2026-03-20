use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    pub skill_id: Option<String>,

    pub confidence: f32,
    pub auto_executed: bool,
    pub dry_run: bool,

    /// AI's textual reasoning
    pub reason: String,
    pub estimated_threat: String,

    /// Result of skill execution ("ok", "skipped", "failed: ...")
    pub execution_result: String,

    /// SHA-256 hash of the previous decision entry (tamper detection chain)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Decision writer
// ---------------------------------------------------------------------------

pub struct DecisionWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
    /// SHA-256 hash of the last written decision entry for hash chaining.
    last_hash: Option<String>,
}

impl DecisionWriter {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        let last_hash = read_last_hash(data_dir, &today);
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
            last_hash,
        })
    }

    /// Append a decision to the daily JSONL.
    /// Rotates to a new file at midnight.
    /// Each entry includes a hash chain pointer to the previous entry.
    pub fn write(&mut self, entry: &DecisionEntry) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            self.writer.flush().ok();
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today.clone();
            self.last_hash = read_last_hash(&self.data_dir, &today);
        }

        // Build a chained entry: set prev_hash from the last written entry.
        // Serialize immediately so the borrow of self.last_hash is released
        // before we update it with the new hash.
        let line = {
            let chained = ChainedEntry {
                ts: entry.ts,
                incident_id: &entry.incident_id,
                host: &entry.host,
                ai_provider: &entry.ai_provider,
                action_type: &entry.action_type,
                target_ip: entry.target_ip.as_deref(),
                target_user: entry.target_user.as_deref(),
                skill_id: entry.skill_id.as_deref(),
                confidence: entry.confidence,
                auto_executed: entry.auto_executed,
                dry_run: entry.dry_run,
                reason: &entry.reason,
                estimated_threat: &entry.estimated_threat,
                execution_result: &entry.execution_result,
                prev_hash: self.last_hash.as_deref(),
            };
            serde_json::to_string(&chained).context("failed to serialize decision entry")?
        };

        // Compute SHA-256 of the serialized entry for the next link in the chain
        self.last_hash = Some(sha256_hex(&line));

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

/// Internal serialization helper that borrows fields instead of cloning.
#[derive(Serialize)]
struct ChainedEntry<'a> {
    ts: DateTime<Utc>,
    incident_id: &'a str,
    host: &'a str,
    ai_provider: &'a str,
    action_type: &'a str,
    target_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_user: Option<&'a str>,
    skill_id: Option<&'a str>,
    confidence: f32,
    auto_executed: bool,
    dry_run: bool,
    reason: &'a str,
    estimated_threat: &'a str,
    execution_result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Read the last line of today's decisions file and compute its SHA-256 hash.
/// Returns None if the file doesn't exist or is empty.
fn read_last_hash(data_dir: &Path, date: &str) -> Option<String> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    let file = File::open(&path).ok()?;
    let reader = BufReader::new(file);
    let mut last_line: Option<String> = None;
    for l in reader.lines().map_while(Result::ok) {
        if !l.trim().is_empty() {
            last_line = Some(l);
        }
    }
    last_line.map(|l| sha256_hex(&l))
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

    let (action_type, target_ip, target_user, skill_id) = match &decision.action {
        AiAction::BlockIp { ip, skill_id } => (
            "block_ip".to_string(),
            Some(ip.clone()),
            None,
            Some(skill_id.clone()),
        ),
        AiAction::Monitor { ip } => ("monitor".to_string(), Some(ip.clone()), None, None),
        AiAction::Honeypot { ip } => ("honeypot".to_string(), Some(ip.clone()), None, None),
        AiAction::SuspendUserSudo { user, .. } => (
            "suspend_user_sudo".to_string(),
            None,
            Some(user.clone()),
            Some("suspend-user-sudo".to_string()),
        ),
        AiAction::KillProcess { user, .. } => (
            "kill_process".to_string(),
            None,
            Some(user.clone()),
            Some("kill-process".to_string()),
        ),
        AiAction::BlockContainer { container_id, .. } => (
            "block_container".to_string(),
            Some(container_id.clone()),
            None,
            Some("block-container".to_string()),
        ),
        AiAction::RequestConfirmation { .. } => {
            ("request_confirmation".to_string(), None, None, None)
        }
        AiAction::Ignore { .. } => ("ignore".to_string(), None, None, None),
    };

    DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.to_string(),
        host: host.to_string(),
        ai_provider: ai_provider.to_string(),
        action_type,
        target_ip,
        target_user,
        skill_id,
        confidence: decision.confidence,
        auto_executed: decision.auto_execute,
        dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.to_string(),
        prev_hash: None, // Set by DecisionWriter::write() via hash chaining
    }
}
