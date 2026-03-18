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
                tokio::task::spawn_blocking(move || poll_integrity(&paths, &host, &known)).await?;

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
    // Detect authorized_keys changes — emit a specific event with username and MITRE tagging.
    if let Some(ev) = make_ssh_key_event(path, new_hash, old_hash, host) {
        return ev;
    }

    // Detect cron tampering — emit a specific event with MITRE T1053.003 tagging.
    if let Some(ev) = make_cron_event(path, new_hash, old_hash, host) {
        return ev;
    }

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

/// Returns a specific SSH key tampering event when `path` is an authorized_keys file.
/// Returns None for all other file types (caller falls through to generic event).
///
/// Extracts the username from the path: `/home/<user>/.ssh/authorized_keys` or
/// `/root/.ssh/authorized_keys`. Tagged as MITRE ATT&CK T1098.004 (Account Manipulation:
/// SSH Authorized Keys).
fn make_ssh_key_event(path: &Path, new_hash: &str, old_hash: &str, host: &str) -> Option<Event> {
    let filename = path.file_name()?.to_str()?;
    if filename != "authorized_keys" {
        return None;
    }

    // Extract username from path components:
    // /home/<user>/.ssh/authorized_keys → user = <user>
    // /root/.ssh/authorized_keys        → user = "root"
    let path_str = path.display().to_string();
    let username = extract_ssh_username(path);

    let summary = match &username {
        Some(user) => format!("SSH authorized_keys modified for user '{user}': {path_str}"),
        None => format!("SSH authorized_keys modified: {path_str}"),
    };

    let mut entities = vec![EntityRef::path(path_str.clone())];
    if let Some(ref user) = username {
        entities.push(EntityRef::user(user.clone()));
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "integrity".to_string(),
        kind: "ssh.authorized_keys_changed".to_string(),
        severity: Severity::High,
        summary,
        details: serde_json::json!({
            "path": path_str,
            "username": username,
            "old_hash": &old_hash[..12.min(old_hash.len())],
            "new_hash": &new_hash[..12.min(new_hash.len())],
            "mitre": { "technique": "T1098.004", "tactic": "Persistence", "name": "Account Manipulation: SSH Authorized Keys" },
        }),
        tags: vec![
            "integrity".to_string(),
            "ssh".to_string(),
            "persistence".to_string(),
            "T1098.004".to_string(),
        ],
        entities,
    })
}

/// Extract a username from an authorized_keys path.
/// `/home/<user>/.ssh/authorized_keys` → Some("<user>")
/// `/root/.ssh/authorized_keys`        → Some("root")
/// Anything else                       → None
fn extract_ssh_username(path: &Path) -> Option<String> {
    let components: Vec<_> = path.components().collect();
    // Minimum: / home <user> .ssh authorized_keys  → 5 components
    // or:      / root .ssh authorized_keys          → 4 components
    let n = components.len();
    if n < 4 {
        return None;
    }
    // Check that second-to-last component is ".ssh"
    let ssh_dir = components[n - 2].as_os_str().to_str()?;
    if ssh_dir != ".ssh" {
        return None;
    }
    // For /root/.ssh/authorized_keys the parent of .ssh is "root"
    // For /home/alice/.ssh/authorized_keys the parent of .ssh is "alice"
    let candidate = components[n - 3].as_os_str().to_str()?;
    if candidate.is_empty() {
        return None;
    }
    Some(candidate.to_string())
}

/// Returns a specific cron tampering event when `path` is a cron-related file.
/// Returns None for all other file types (caller falls through to generic event).
///
/// Detects changes to:
/// - `/etc/crontab`
/// - `/etc/cron.d/*` and `/etc/cron.{hourly,daily,weekly,monthly}/*`
/// - `/var/spool/cron/crontabs/<user>` (user crontabs — extracts username)
///
/// Tagged as MITRE ATT&CK T1053.003 (Scheduled Task/Job: Cron).
fn make_cron_event(path: &Path, new_hash: &str, old_hash: &str, host: &str) -> Option<Event> {
    let path_str = path.display().to_string();

    let is_etc_crontab = path_str == "/etc/crontab";
    let is_cron_dir = [
        "/etc/cron.d/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
    ]
    .iter()
    .any(|prefix| path_str.starts_with(prefix));
    // /var/spool/cron/crontabs/<user> (Linux) or /var/spool/cron/<user> (macOS/BSDs)
    let is_user_crontab = path_str.starts_with("/var/spool/cron/");

    if !is_etc_crontab && !is_cron_dir && !is_user_crontab {
        return None;
    }

    // For user crontabs, username is the last path component (the filename itself)
    let username: Option<String> = if is_user_crontab {
        path.file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .map(|n| n.to_string())
    } else {
        None
    };

    let summary = match &username {
        Some(user) => format!("Cron job modified for user '{user}': {path_str}"),
        None => format!("Cron configuration modified: {path_str}"),
    };

    let mut entities = vec![EntityRef::path(path_str.clone())];
    if let Some(ref user) = username {
        entities.push(EntityRef::user(user.clone()));
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "integrity".to_string(),
        kind: "cron.tampering".to_string(),
        severity: Severity::High,
        summary,
        details: serde_json::json!({
            "path": path_str,
            "username": username,
            "old_hash": &old_hash[..12.min(old_hash.len())],
            "new_hash": &new_hash[..12.min(new_hash.len())],
            "mitre": {
                "technique": "T1053.003",
                "tactic": "Persistence",
                "name": "Scheduled Task/Job: Cron"
            },
        }),
        tags: vec![
            "integrity".to_string(),
            "cron".to_string(),
            "persistence".to_string(),
            "T1053.003".to_string(),
        ],
        entities,
    })
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
        let (events, hashes) =
            poll_integrity(&[f.path().to_owned()], "host", &HashMap::new()).unwrap();
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

    // ---------------------------------------------------------------------------
    // SSH key tampering tests
    // ---------------------------------------------------------------------------

    #[test]
    fn authorized_keys_change_emits_ssh_specific_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/home/alice/.ssh/authorized_keys");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "ssh.authorized_keys_changed");
        assert_eq!(ev.severity, Severity::High);
        assert!(ev.summary.contains("alice"));
    }

    #[test]
    fn root_authorized_keys_extracts_root_username() {
        let path = Path::new("/root/.ssh/authorized_keys");
        let user = extract_ssh_username(path);
        assert_eq!(user.as_deref(), Some("root"));
    }

    #[test]
    fn home_user_authorized_keys_extracts_username() {
        let path = Path::new("/home/deploy/.ssh/authorized_keys");
        let user = extract_ssh_username(path);
        assert_eq!(user.as_deref(), Some("deploy"));
    }

    #[test]
    fn non_authorized_keys_file_uses_generic_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/ssh/sshd_config");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "file.changed");
    }

    #[test]
    fn authorized_keys_event_has_persistence_tags() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/home/bob/.ssh/authorized_keys");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert!(ev.tags.contains(&"T1098.004".to_string()));
        assert!(ev.tags.contains(&"persistence".to_string()));
        assert!(ev.tags.contains(&"ssh".to_string()));
    }

    #[test]
    fn authorized_keys_event_includes_user_entity() {
        use innerwarden_core::entities::EntityType;
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/home/carol/.ssh/authorized_keys");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        let has_user_entity = ev
            .entities
            .iter()
            .any(|e| e.r#type == EntityType::User && e.value == "carol");
        assert!(has_user_entity);
    }

    #[test]
    fn authorized_keys_event_has_mitre_in_details() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/home/dave/.ssh/authorized_keys");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.details["mitre"]["technique"], "T1098.004");
    }

    #[test]
    fn non_ssh_dir_path_returns_none_for_username() {
        // /etc/authorized_keys — not under .ssh/
        let path = Path::new("/etc/authorized_keys");
        let user = extract_ssh_username(path);
        assert!(user.is_none());
    }

    // ---------------------------------------------------------------------------
    // Cron tampering tests
    // ---------------------------------------------------------------------------

    #[test]
    fn etc_crontab_emits_cron_tampering_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/crontab");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "cron.tampering");
        assert_eq!(ev.severity, Severity::High);
        assert!(ev.tags.contains(&"T1053.003".to_string()));
        assert!(ev.tags.contains(&"persistence".to_string()));
    }

    #[test]
    fn cron_d_file_emits_cron_tampering_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/cron.d/my-job");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "cron.tampering");
        assert!(ev.tags.contains(&"cron".to_string()));
    }

    #[test]
    fn cron_daily_file_emits_cron_tampering_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/cron.daily/logrotate");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "cron.tampering");
    }

    #[test]
    fn user_crontab_extracts_username() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/var/spool/cron/crontabs/alice");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "cron.tampering");
        assert!(ev.summary.contains("alice"));
    }

    #[test]
    fn user_crontab_has_user_entity() {
        use innerwarden_core::entities::EntityType;
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/var/spool/cron/crontabs/bob");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        let has_user = ev
            .entities
            .iter()
            .any(|e| e.r#type == EntityType::User && e.value == "bob");
        assert!(has_user);
    }

    #[test]
    fn cron_tampering_has_mitre_in_details() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/crontab");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.details["mitre"]["technique"], "T1053.003");
        assert_eq!(ev.details["mitre"]["tactic"], "Persistence");
    }

    #[test]
    fn non_cron_file_falls_through_to_generic_event() {
        let fake_hash_old = "a".repeat(64);
        let fake_hash_new = "b".repeat(64);
        let path = Path::new("/etc/passwd");
        let ev = make_change_event(path, &fake_hash_new, &fake_hash_old, "host");
        assert_eq!(ev.kind, "file.changed");
    }
}
