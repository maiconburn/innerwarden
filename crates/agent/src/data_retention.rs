use std::fs;
use std::path::Path;

use chrono::{Local, NaiveDate};
use tracing::{debug, warn};

use crate::config::DataRetentionConfig;

/// Remove old data files from `data_dir` according to retention config.
///
/// Runs on agent startup and in the slow loop (once per day).
/// Never removes today's files regardless of keep_days.
/// Returns number of files deleted.
pub fn cleanup(data_dir: &Path, cfg: &DataRetentionConfig) -> usize {
    let today = Local::now().date_naive();

    // (prefix, suffix, keep_days)
    let patterns: &[(&str, &str, usize)] = &[
        ("events-", ".jsonl", cfg.events_keep_days),
        ("incidents-", ".jsonl", cfg.incidents_keep_days),
        ("decisions-", ".jsonl", cfg.decisions_keep_days),
        ("telemetry-", ".jsonl", cfg.telemetry_keep_days),
        ("trial-report-", ".json", cfg.reports_keep_days),
        ("trial-report-", ".md", cfg.reports_keep_days),
    ];

    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("data_retention: failed to read data_dir: {e:#}");
            return 0;
        }
    };

    let mut removed = 0usize;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        for (prefix, suffix, keep_days) in patterns {
            let Some(mid) = name.strip_prefix(prefix).and_then(|s| s.strip_suffix(*suffix)) else {
                continue;
            };
            let Ok(file_date) = NaiveDate::parse_from_str(mid, "%Y-%m-%d") else {
                continue;
            };
            let age_days = (today - file_date).num_days();
            if age_days <= 0 || age_days <= *keep_days as i64 {
                break; // within retention window
            }
            let path = entry.path();
            match fs::remove_file(&path) {
                Ok(()) => {
                    debug!(
                        path = %path.display(),
                        age_days,
                        keep_days,
                        "data_retention: removed old file"
                    );
                    removed += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), "data_retention: failed to remove: {e:#}");
                }
            }
            break; // matched this pattern, no need to check other patterns for same file
        }
    }

    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataRetentionConfig;
    use chrono::Duration;
    use std::fs::File;
    use std::io::Write;

    fn write_dated_file(dir: &Path, prefix: &str, suffix: &str, date: NaiveDate) {
        let name = format!("{prefix}{}{suffix}", date.format("%Y-%m-%d"));
        let mut f = File::create(dir.join(name)).unwrap();
        writeln!(f, "test").unwrap();
    }

    #[test]
    fn removes_files_beyond_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // events: keep 7 days — write one 8 days old (should be removed)
        let old = today - Duration::days(8);
        write_dated_file(tmp.path(), "events-", ".jsonl", old);

        // events: write one 6 days old (should be kept)
        let recent = today - Duration::days(6);
        write_dated_file(tmp.path(), "events-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 1, "only the 8-day-old file should be removed");
        assert!(!tmp.path().join(format!("events-{}.jsonl", old.format("%Y-%m-%d"))).exists());
        assert!(tmp.path().join(format!("events-{}.jsonl", recent.format("%Y-%m-%d"))).exists());
    }

    #[test]
    fn respects_decisions_longer_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // decisions: default keep 90 days — write one 60 days old (should be kept)
        let recent = today - Duration::days(60);
        write_dated_file(tmp.path(), "decisions-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 0);
        assert!(tmp.path().join(format!("decisions-{}.jsonl", recent.format("%Y-%m-%d"))).exists());
    }

    #[test]
    fn never_removes_todays_files() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        write_dated_file(tmp.path(), "events-", ".jsonl", today);

        let mut cfg = DataRetentionConfig::default();
        cfg.events_keep_days = 0; // even with keep=0, today must survive

        let removed = cleanup(tmp.path(), &cfg);
        assert_eq!(removed, 0);
    }
}
