//! Atomic, comment-preserving TOML editor using toml_edit.
//!
//! All write operations:
//! 1. Parse the existing file (or start with an empty document if absent)
//! 2. Apply the patch
//! 3. Write to a tmp file in the same directory, then `rename` (atomic on Linux)
//! 4. Backup the original to `.toml.bak` before overwriting
//!
//! Section paths support one or two levels via dot notation:
//!   - `"responder"` → `[responder]`
//!   - `"detectors.sudo_abuse"` → `[detectors.sudo_abuse]`

use anyhow::{Context, Result};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_doc(path: &Path) -> Result<DocumentMut> {
    if !path.exists() {
        return Ok(DocumentMut::default());
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    content
        .parse::<DocumentMut>()
        .with_context(|| format!("failed to parse TOML: {}", path.display()))
}

/// Parse a dotted section string into parts (max 2 levels).
fn section_parts(section: &str) -> Vec<&str> {
    section.split('.').collect()
}

/// Ensure the tables in `section` exist, creating them if absent.
/// Supports 1-level ("responder") and 2-level ("detectors.sudo_abuse").
fn ensure_section(doc: &mut DocumentMut, section: &str) {
    let parts = section_parts(section);
    match parts.as_slice() {
        [s1] => {
            if doc.get(s1).is_none_or(Item::is_none) {
                doc[s1] = toml_edit::table();
            }
        }
        [s1, s2] => {
            // Ensure outer table
            if doc.get(s1).is_none_or(Item::is_none) {
                doc[s1] = toml_edit::table();
            }
            // Ensure inner table using get to check without mutating
            let inner_absent = doc
                .get(s1)
                .and_then(|i| i.as_table())
                .and_then(|t| t.get(s2))
                .is_none_or(Item::is_none);
            if inner_absent {
                doc[s1][s2] = toml_edit::table();
            }
        }
        _ => {
            // Deeper nesting not needed for current capabilities
        }
    }
}

/// Set a value at `[section][key]`, handling 1- and 2-level section paths.
fn set_item(doc: &mut DocumentMut, section: &str, key: &str, val: toml_edit::Item) {
    ensure_section(doc, section);
    let parts = section_parts(section);
    match parts.as_slice() {
        [s1] => {
            doc[s1][key] = val;
        }
        [s1, s2] => {
            doc[s1][s2][key] = val;
        }
        _ => {}
    }
}

fn atomic_write(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        let backup = path.with_extension("toml.bak");
        fs::copy(path, &backup).with_context(|| format!("failed to backup {}", path.display()))?;
    }
    // Use tempfile::NamedTempFile in the same directory so rename is atomic
    // (same filesystem) and there are no races between concurrent calls.
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create tmp file in {}", dir.display()))?;
    tmp.write_all(content.as_bytes())
        .with_context(|| "failed to write TOML content to tmp file")?;
    tmp.flush().with_context(|| "failed to flush tmp file")?;
    tmp.persist(path)
        .with_context(|| format!("failed to persist tmp file to {}", path.display()))?;
    // Ensure the file is readable by the innerwarden service user (runs as
    // User=innerwarden in the systemd unit). chmod 640 + chgrp innerwarden so
    // root writes don't lock out the daemon. Fail-silent — may not be applicable
    // in all environments (e.g. local dev).
    ensure_service_readable(path);
    Ok(())
}

/// Set file to 640 and group to "innerwarden" so the service user can read it.
/// Silently ignored if the group doesn't exist or the chown call fails.
fn ensure_service_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // chmod 640
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o640));
    // chgrp innerwarden — best-effort via the `chgrp` binary
    let _ = std::process::Command::new("chgrp")
        .arg("innerwarden")
        .arg(path)
        .output();
}

// ---------------------------------------------------------------------------
// Read helpers — navigate without mutating
// ---------------------------------------------------------------------------

fn read_item<'doc>(doc: &'doc DocumentMut, section: &str, key: &str) -> Option<&'doc Item> {
    let parts = section_parts(section);
    match parts.as_slice() {
        [s1] => doc.get(s1)?.as_table()?.get(key),
        [s1, s2] => doc.get(s1)?.as_table()?.get(s2)?.as_table()?.get(key),
        _ => None,
    }
}

fn item_key_absent(doc: &DocumentMut, section: &str, key: &str) -> bool {
    read_item(doc, section, key).is_none_or(Item::is_none)
}

// ---------------------------------------------------------------------------
// Public write API
// ---------------------------------------------------------------------------

/// Set a boolean key in `[section]`.
/// Section supports dot notation: `"responder"` or `"detectors.sudo_abuse"`.
pub fn write_bool(path: &Path, section: &str, key: &str, val: bool) -> Result<()> {
    let mut doc = read_doc(path)?;
    set_item(&mut doc, section, key, toml_edit::value(val));
    atomic_write(path, &doc.to_string())
}

/// Set an integer key in `[section]`.
pub fn write_int(path: &Path, section: &str, key: &str, val: i64) -> Result<()> {
    let mut doc = read_doc(path)?;
    set_item(&mut doc, section, key, toml_edit::value(val));
    atomic_write(path, &doc.to_string())
}

/// Set a string key in `[section]`.
pub fn write_str(path: &Path, section: &str, key: &str, val: &str) -> Result<()> {
    let mut doc = read_doc(path)?;
    set_item(&mut doc, section, key, toml_edit::value(val));
    atomic_write(path, &doc.to_string())
}

/// Ensure a string value is present in an array key in `[section]`.
/// Returns `true` if the value was newly added, `false` if already present.
/// Creates the array if the key does not exist.
pub fn write_array_push(path: &Path, section: &str, key: &str, val: &str) -> Result<bool> {
    let mut doc = read_doc(path)?;
    ensure_section(&mut doc, section);

    // Check if value is already in the array (using non-mutating read path)
    let already_present = read_item(&doc, section, key)
        .and_then(|v| v.as_value())
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some(val)))
        .unwrap_or(false);

    if already_present {
        return Ok(false);
    }

    // Create an empty array if the key doesn't exist yet
    if item_key_absent(&doc, section, key) {
        set_item(&mut doc, section, key, toml_edit::value(Array::new()));
    }

    // Push the value into the array (now guaranteed to be Item::Value(Array))
    let parts = section_parts(section);
    let arr_item = match parts.as_slice() {
        [s1] => &mut doc[s1][key],
        [s1, s2] => &mut doc[s1][s2][key],
        _ => return Ok(false),
    };
    if let Some(arr) = arr_item.as_value_mut().and_then(|v| v.as_array_mut()) {
        arr.push(val);
    }

    atomic_write(path, &doc.to_string())?;
    Ok(true)
}

/// Remove all occurrences of a string value from an array key in `[section]`.
/// Returns `true` if the value was found and removed, `false` if it was absent.
/// No-ops gracefully if the key or section does not exist.
pub fn write_array_remove(path: &Path, section: &str, key: &str, val: &str) -> Result<bool> {
    let mut doc = read_doc(path)?;

    let already_absent = read_item(&doc, section, key)
        .and_then(|v| v.as_value())
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().all(|v| v.as_str() != Some(val)))
        .unwrap_or(true);

    if already_absent {
        return Ok(false);
    }

    let parts = section_parts(section);
    let arr_item = match parts.as_slice() {
        [s1] => &mut doc[s1][key],
        [s1, s2] => &mut doc[s1][s2][key],
        _ => return Ok(false),
    };
    if let Some(arr) = arr_item.as_value_mut().and_then(|v| v.as_array_mut()) {
        let indices: Vec<usize> = arr
            .iter()
            .enumerate()
            .filter(|(_, v)| v.as_str() == Some(val))
            .map(|(i, _)| i)
            .collect();
        for i in indices.into_iter().rev() {
            arr.remove(i);
        }
    }

    atomic_write(path, &doc.to_string())?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Public read API
// ---------------------------------------------------------------------------

/// Read a boolean key from `[section]`. Returns `false` if absent or on error.
pub fn read_bool(path: &Path, section: &str, key: &str) -> bool {
    let doc = match read_doc(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    read_item(&doc, section, key)
        .and_then(|v| v.as_value())
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Read a string key from `[section]`. Returns empty string if absent or on error.
pub fn read_str(path: &Path, section: &str, key: &str) -> String {
    let doc = match read_doc(path) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    read_item(&doc, section, key)
        .and_then(|v| v.as_value())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Read a string array key from `[section]`. Returns empty vec if absent or on error.
pub fn read_str_array(path: &Path, section: &str, key: &str) -> Vec<String> {
    let doc = match read_doc(path) {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    read_item(&doc, section, key)
        .and_then(|v| v.as_value())
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    // --- Single-level section ---

    #[test]
    fn write_bool_creates_section_and_key() {
        let f = NamedTempFile::new().unwrap();
        write_bool(f.path(), "responder", "enabled", true).unwrap();
        assert!(read_bool(f.path(), "responder", "enabled"));
    }

    #[test]
    fn write_bool_updates_existing_key() {
        let f = write_tmp("[responder]\nenabled = false\n");
        write_bool(f.path(), "responder", "enabled", true).unwrap();
        assert!(read_bool(f.path(), "responder", "enabled"));
    }

    #[test]
    fn write_bool_preserves_existing_keys() {
        let f = write_tmp("[responder]\ndry_run = true\n");
        write_bool(f.path(), "responder", "enabled", true).unwrap();
        assert!(read_bool(f.path(), "responder", "dry_run"));
        assert!(read_bool(f.path(), "responder", "enabled"));
    }

    #[test]
    fn write_bool_preserves_comments() {
        let f = write_tmp("[responder]\n# SAFETY: start in dry_run\ndry_run = true\n");
        write_bool(f.path(), "responder", "enabled", true).unwrap();
        let content = fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("# SAFETY: start in dry_run"));
    }

    #[test]
    fn write_str_sets_value() {
        let f = write_tmp("[responder]\nblock_backend = \"ufw\"\n");
        write_str(f.path(), "responder", "block_backend", "iptables").unwrap();
        let content = fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("iptables"));
    }

    #[test]
    fn write_array_push_creates_array_when_absent() {
        let f = write_tmp("[responder]\nenabled = true\n");
        let added =
            write_array_push(f.path(), "responder", "allowed_skills", "block-ip-ufw").unwrap();
        assert!(added);
        let skills = read_str_array(f.path(), "responder", "allowed_skills");
        assert_eq!(skills, vec!["block-ip-ufw"]);
    }

    #[test]
    fn write_array_push_appends_to_existing() {
        let f = write_tmp("[responder]\nallowed_skills = [\"monitor-ip\"]\n");
        let added =
            write_array_push(f.path(), "responder", "allowed_skills", "block-ip-ufw").unwrap();
        assert!(added);
        let skills = read_str_array(f.path(), "responder", "allowed_skills");
        assert!(skills.contains(&"block-ip-ufw".to_string()));
        assert!(skills.contains(&"monitor-ip".to_string()));
    }

    #[test]
    fn write_array_push_is_idempotent() {
        let f = write_tmp("[responder]\nallowed_skills = [\"block-ip-ufw\"]\n");
        let added =
            write_array_push(f.path(), "responder", "allowed_skills", "block-ip-ufw").unwrap();
        assert!(!added);
        let skills = read_str_array(f.path(), "responder", "allowed_skills");
        assert_eq!(skills.len(), 1);
    }

    // --- Two-level dotted section ---

    #[test]
    fn write_bool_nested_section_creates_tables() {
        let f = NamedTempFile::new().unwrap();
        write_bool(f.path(), "detectors.sudo_abuse", "enabled", true).unwrap();
        assert!(read_bool(f.path(), "detectors.sudo_abuse", "enabled"));
    }

    #[test]
    fn write_bool_nested_section_updates_existing() {
        let f = write_tmp("[detectors.sudo_abuse]\nenabled = false\nthreshold = 3\n");
        write_bool(f.path(), "detectors.sudo_abuse", "enabled", true).unwrap();
        assert!(read_bool(f.path(), "detectors.sudo_abuse", "enabled"));
        // Preserves sibling key
        let doc_content = fs::read_to_string(f.path()).unwrap();
        assert!(doc_content.contains("threshold"));
    }

    #[test]
    fn write_bool_nested_section_preserves_outer_section() {
        let f = write_tmp("[detectors.ssh_bruteforce]\nenabled = true\n");
        write_bool(f.path(), "detectors.sudo_abuse", "enabled", true).unwrap();
        // Both subsections coexist
        let doc_content = fs::read_to_string(f.path()).unwrap();
        assert!(doc_content.contains("ssh_bruteforce"));
        assert!(doc_content.contains("sudo_abuse"));
    }

    #[test]
    fn read_bool_nested_reads_correctly() {
        let f = write_tmp("[detectors.sudo_abuse]\nenabled = true\n");
        assert!(read_bool(f.path(), "detectors.sudo_abuse", "enabled"));
        assert!(!read_bool(
            f.path(),
            "detectors.sudo_abuse",
            "nonexistent_key"
        ));
    }

    #[test]
    fn read_bool_returns_false_for_missing_file() {
        assert!(!read_bool(
            Path::new("/nonexistent/agent.toml"),
            "responder",
            "enabled"
        ));
    }

    #[test]
    fn read_str_array_returns_empty_for_missing_file() {
        let arr = read_str_array(
            Path::new("/nonexistent/agent.toml"),
            "responder",
            "allowed_skills",
        );
        assert!(arr.is_empty());
    }

    #[test]
    fn write_array_remove_removes_value() {
        let f = write_tmp("[responder]\nallowed_skills = [\"block-ip-ufw\", \"monitor-ip\"]\n");
        let removed =
            write_array_remove(f.path(), "responder", "allowed_skills", "block-ip-ufw").unwrap();
        assert!(removed);
        let skills = read_str_array(f.path(), "responder", "allowed_skills");
        assert!(!skills.contains(&"block-ip-ufw".to_string()));
        assert!(skills.contains(&"monitor-ip".to_string()));
    }

    #[test]
    fn write_array_remove_returns_false_when_absent() {
        let f = write_tmp("[responder]\nallowed_skills = [\"monitor-ip\"]\n");
        let removed =
            write_array_remove(f.path(), "responder", "allowed_skills", "block-ip-ufw").unwrap();
        assert!(!removed);
        let skills = read_str_array(f.path(), "responder", "allowed_skills");
        assert_eq!(skills, vec!["monitor-ip"]);
    }

    #[test]
    fn write_array_remove_no_ops_on_missing_section() {
        let f = NamedTempFile::new().unwrap();
        let removed =
            write_array_remove(f.path(), "responder", "allowed_skills", "anything").unwrap();
        assert!(!removed);
    }

    #[test]
    fn write_array_remove_nested_section() {
        let f = write_tmp("[detectors.search_abuse]\ntags = [\"web\", \"abuse\"]\n");
        let removed =
            write_array_remove(f.path(), "detectors.search_abuse", "tags", "web").unwrap();
        assert!(removed);
        let tags = read_str_array(f.path(), "detectors.search_abuse", "tags");
        assert_eq!(tags, vec!["abuse"]);
    }

    #[test]
    fn atomic_write_creates_backup() {
        let f = write_tmp("[responder]\nenabled = false\n");
        write_bool(f.path(), "responder", "enabled", true).unwrap();
        let backup = f.path().with_extension("toml.bak");
        assert!(backup.exists(), "backup file should be created");
        let backup_content = fs::read_to_string(&backup).unwrap();
        assert!(backup_content.contains("enabled = false"));
    }
}
