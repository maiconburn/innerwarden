use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct IntegrityCollector {
    paths: Vec<PathBuf>,
    host: String,
    poll_interval: Duration,
    /// path string → SHA-256 hex. Empty = no baseline yet (first run).
    known_hashes: HashMap<String, String>,
}

impl IntegrityCollector {
    pub fn new(
        paths: Vec<PathBuf>,
        host: impl Into<String>,
        poll_seconds: u64,
        known_hashes: HashMap<String, String>,
    ) -> Self {
        Self {
            paths,
            host: host.into(),
            poll_interval: Duration::from_secs(poll_seconds),
            known_hashes,
        }
    }

    /// `shared_hashes` is updated after every poll so callers can read
    /// the latest hashes at any time (e.g. on shutdown for persistence).
    pub async fn run(
        mut self,
        tx: mpsc::Sender<Event>,
        shared_hashes: Arc<Mutex<HashMap<String, String>>>,
    ) -> Result<()> {
        info!(
            paths = self.paths.len(),
            poll_secs = self.poll_interval.as_secs(),
            "integrity collector starting"
        );

        loop {
            let paths = self.paths.clone();
            let host = self.host.clone();
            let known = self.known_hashes.clone();

            let result =
                tokio::task::spawn_blocking(move || poll_integrity(&paths, &host, &known))
                    .await?;

            match result {
                Ok((events, new_hashes)) => {
                    self.known_hashes = new_hashes.clone();
                    *shared_hashes.lock().unwrap() = new_hashes;
                    for event in events {
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => warn!("integrity poll error: {e:#}"),
            }

            tokio::time::sleep(self.poll_interval).await;

            if tx.is_closed() {
                break;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Blocking poll
// ---------------------------------------------------------------------------

fn poll_integrity(
    paths: &[PathBuf],
    host: &str,
    known: &HashMap<String, String>,
) -> Result<(Vec<Event>, HashMap<String, String>)> {
    let mut events = Vec::new();
    let mut new_hashes = known.clone();

    for path in paths {
        let key = path.display().to_string();
        match hash_file(path) {
            Ok(hash) => match known.get(&key) {
                None => {
                    // First time seeing this file — establish baseline, no event.
                    info!(path = %path.display(), hash = %&hash[..12], "integrity baseline set");
                    new_hashes.insert(key, hash);
                }
                Some(prev) if *prev != hash => {
                    info!(path = %path.display(), "file changed");
                    events.push(make_change_event(path, &hash, prev, host));
                    new_hashes.insert(key, hash);
                }
                _ => {} // unchanged
            },
            Err(e) => {
                warn!(path = %path.display(), "cannot hash file: {e}");
            }
        }
    }

    Ok((events, new_hashes))
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn make_change_event(path: &Path, new_hash: &str, old_hash: &str, host: &str) -> Event {
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "integrity".to_string(),
        kind: "file.changed".to_string(),
        severity: Severity::High,
        summary: format!("Critical file modified: {}", path.display()),
        details: serde_json::json!({
            "path": path.display().to_string(),
            "old_hash": &old_hash[..12],  // short prefix for readability
            "new_hash": &new_hash[..12],
        }),
        tags: vec!["integrity".to_string(), "file".to_string()],
        entities: vec![EntityRef::path(path.display().to_string())],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn tmp_with(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f
    }

    #[test]
    fn baseline_established_no_event() {
        let f = tmp_with(b"hello");
        let (events, hashes) = poll_integrity(&[f.path().to_owned()], "host", &HashMap::new()).unwrap();
        assert!(events.is_empty(), "no event on first run");
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn unchanged_file_no_event() {
        let f = tmp_with(b"hello");
        let key = f.path().display().to_string();
        let hash = hash_file(f.path()).unwrap();
        let known = HashMap::from([(key, hash)]);
        let (events, _) = poll_integrity(&[f.path().to_owned()], "host", &known).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn changed_file_emits_event() {
        let mut f = tmp_with(b"original content");
        let key = f.path().display().to_string();
        let old_hash = hash_file(f.path()).unwrap();
        let known = HashMap::from([(key, old_hash.clone())]);

        // Modify the file
        f.write_all(b" modified").unwrap();

        let (events, new_hashes) = poll_integrity(&[f.path().to_owned()], "host", &known).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "file.changed");
        assert_eq!(events[0].severity, Severity::High);
        assert!(new_hashes[&f.path().display().to_string()] != old_hash);
    }

    #[test]
    fn missing_file_is_warned_not_panicked() {
        let known = HashMap::new();
        let result = poll_integrity(&[PathBuf::from("/nonexistent/file")], "host", &known);
        assert!(result.is_ok());
        let (events, _) = result.unwrap();
        assert!(events.is_empty());
    }
}
