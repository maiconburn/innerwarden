use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use tracing::warn;

// ---------------------------------------------------------------------------
// JSONL incremental reader
// ---------------------------------------------------------------------------

/// Read new entries from a JSONL file starting at `offset` bytes.
/// Returns the parsed entries and the new byte offset (end of file).
pub fn read_new_entries<T: DeserializeOwned>(path: &Path, offset: u64) -> Result<ReadResult<T>> {
    if !path.exists() {
        return Ok(ReadResult {
            entries: Vec::new(),
            new_offset: 0,
        });
    }

    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let file_len = file.metadata()?.len();

    // File was truncated or rotated — reset to beginning
    let start = if offset > file_len { 0 } else { offset };

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(start))?;

    let mut entries = Vec::new();
    let mut line = String::new();
    let mut current_offset = start;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break; // EOF
        }
        current_offset += bytes_read as u64;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<T>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!(
                    path = %path.display(),
                    offset = current_offset,
                    "skipping malformed JSONL line: {e}"
                );
            }
        }
    }

    Ok(ReadResult {
        entries,
        new_offset: current_offset,
    })
}

pub struct ReadResult<T> {
    pub entries: Vec<T>,
    pub new_offset: u64,
}

// ---------------------------------------------------------------------------
// Agent cursor — tracks byte offsets per date file
// ---------------------------------------------------------------------------

/// Persists the agent's read position in each dated JSONL file.
/// Stored as `agent-state.json` (separate from the sensor's `state.json`).
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct AgentCursor {
    /// "YYYY-MM-DD" → byte offset in events-YYYY-MM-DD.jsonl
    #[serde(default)]
    events: HashMap<String, u64>,
    /// "YYYY-MM-DD" → byte offset in incidents-YYYY-MM-DD.jsonl
    #[serde(default)]
    incidents: HashMap<String, u64>,
}

impl AgentCursor {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Fall back to a fresh cursor on parse errors (e.g. power loss mid-write).
        // Consequence: incidents since the last saved offset are re-analyzed by AI.
        // The blocklist and decision cooldowns (pre-loaded from decisions-*.jsonl on
        // startup) prevent duplicate decisions for IPs/users already decided upon.
        match serde_json::from_str::<Self>(&content) {
            Ok(cursor) => Ok(cursor),
            Err(e) => {
                warn!(
                    path = %path.display(),
                    "agent-state.json corrupted ({e}) — starting with empty cursor, \
                     some incidents may be re-analyzed"
                );
                Ok(Self::default())
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, &content)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename to {}", path.display()))?;
        Ok(())
    }

    pub fn events_offset(&self, date: &str) -> u64 {
        self.events.get(date).copied().unwrap_or(0)
    }

    pub fn incidents_offset(&self, date: &str) -> u64 {
        self.incidents.get(date).copied().unwrap_or(0)
    }

    pub fn set_events_offset(&mut self, date: &str, offset: u64) {
        self.events.insert(date.to_string(), offset);
    }

    pub fn set_incidents_offset(&mut self, date: &str, offset: u64) {
        self.incidents.insert(date.to_string(), offset);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn reads_all_entries_from_zero() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"ts":"2026-01-01T00:00:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"a","details":{{}},"tags":[],"entities":[]}}"#).unwrap();
        writeln!(f, r#"{{"ts":"2026-01-01T00:01:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"b","details":{{}},"tags":[],"entities":[]}}"#).unwrap();
        f.flush().unwrap();

        let result = read_new_entries::<innerwarden_core::event::Event>(f.path(), 0).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert!(result.new_offset > 0);
    }

    #[test]
    fn incremental_read_skips_already_seen() {
        let mut f = NamedTempFile::new().unwrap();
        let line = r#"{"ts":"2026-01-01T00:00:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"first","details":{},"tags":[],"entities":[]}"#;
        writeln!(f, "{line}").unwrap();
        f.flush().unwrap();

        // First read
        let r1 = read_new_entries::<innerwarden_core::event::Event>(f.path(), 0).unwrap();
        assert_eq!(r1.entries.len(), 1);

        // Append more
        writeln!(f, r#"{{"ts":"2026-01-01T00:01:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"second","details":{{}},"tags":[],"entities":[]}}"#).unwrap();
        f.flush().unwrap();

        // Read from saved offset — should only get the new one
        let r2 =
            read_new_entries::<innerwarden_core::event::Event>(f.path(), r1.new_offset).unwrap();
        assert_eq!(r2.entries.len(), 1);
        assert_eq!(r2.entries[0].summary, "second");
    }

    #[test]
    fn handles_missing_file() {
        let result = read_new_entries::<innerwarden_core::event::Event>(
            Path::new("/nonexistent/file.jsonl"),
            0,
        )
        .unwrap();
        assert!(result.entries.is_empty());
        assert_eq!(result.new_offset, 0);
    }

    #[test]
    fn handles_file_rotation() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"ts":"2026-01-01T00:00:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"a","details":{{}},"tags":[],"entities":[]}}"#).unwrap();
        f.flush().unwrap();

        let r1 = read_new_entries::<innerwarden_core::event::Event>(f.path(), 0).unwrap();
        let big_offset = r1.new_offset + 99999; // simulate stale cursor bigger than file

        // Should reset to beginning and read all
        let r2 = read_new_entries::<innerwarden_core::event::Event>(f.path(), big_offset).unwrap();
        assert_eq!(r2.entries.len(), 1);
    }

    #[test]
    fn skips_malformed_lines() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "not valid json").unwrap();
        writeln!(f, r#"{{"ts":"2026-01-01T00:00:00Z","host":"h","source":"s","kind":"k","severity":"info","summary":"ok","details":{{}},"tags":[],"entities":[]}}"#).unwrap();
        f.flush().unwrap();

        let result = read_new_entries::<innerwarden_core::event::Event>(f.path(), 0).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].summary, "ok");
    }

    #[test]
    fn corrupted_cursor_falls_back_to_default() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent-state.json");
        std::fs::write(&path, "not valid json at all {{{{").unwrap();
        // Must not return Err — falls back to empty cursor
        let cursor = AgentCursor::load(&path).unwrap();
        assert_eq!(cursor.events_offset("2026-03-13"), 0);
        assert_eq!(cursor.incidents_offset("2026-03-13"), 0);
    }

    #[test]
    fn cursor_save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent-state.json");

        let mut c = AgentCursor::default();
        c.set_events_offset("2026-03-12", 1234);
        c.set_incidents_offset("2026-03-12", 56);
        c.save(&path).unwrap();

        let loaded = AgentCursor::load(&path).unwrap();
        assert_eq!(loaded.events_offset("2026-03-12"), 1234);
        assert_eq!(loaded.incidents_offset("2026-03-12"), 56);
        assert_eq!(loaded.events_offset("1999-01-01"), 0); // missing date
    }
}
