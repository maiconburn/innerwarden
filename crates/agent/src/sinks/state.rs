use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Persistent cursor state for all collectors.
/// Stored as state.json in the data directory.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Collector cursors keyed by collector name.
    /// Values are collector-specific (byte offset, journal cursor string, etc.)
    pub cursors: HashMap<String, serde_json::Value>,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read state: {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| "failed to parse state.json")
    }

    /// Atomic save: write to .tmp then rename to avoid partial writes.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, &content)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename state file to {}", path.display()))?;
        Ok(())
    }

    pub fn get_cursor(&self, collector: &str) -> Option<&serde_json::Value> {
        self.cursors.get(collector)
    }

    pub fn set_cursor(&mut self, collector: &str, value: serde_json::Value) {
        self.cursors.insert(collector.to_string(), value);
    }
}
