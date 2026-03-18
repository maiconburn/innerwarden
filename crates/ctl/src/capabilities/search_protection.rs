use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::capability::{
    ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight,
};
use crate::config_editor;
use crate::preflight::{BinaryExists, DirectoryExists, UserExists};
use crate::sudoers::{search_protection_nginx_rule, SudoersDropIn};
use crate::systemd;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

pub struct SearchProtectionCapability;

impl SearchProtectionCapability {
    fn sudoers_name() -> &'static str {
        "innerwarden-search-protection"
    }
}

impl Capability for SearchProtectionCapability {
    fn id(&self) -> &'static str {
        "search-protection"
    }

    fn name(&self) -> &'static str {
        "Search Route Protection"
    }

    fn description(&self) -> &'static str {
        "Detect and block automated abuse of high-cost HTTP routes via nginx access log analysis"
    }

    fn preflights(&self, _opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
        vec![
            Box::new(BinaryExists {
                display_name: "nginx is installed",
                path: "/usr/sbin/nginx",
            }),
            Box::new(DirectoryExists {
                display_name: "/etc/sudoers.d/ directory exists",
                path: "/etc/sudoers.d",
            }),
            Box::new(UserExists {
                display_name: "'innerwarden' system user exists",
                username: "innerwarden",
            }),
        ]
    }

    fn planned_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let sensor = opts.sensor_config.display().to_string();
        let agent = opts.agent_config.display().to_string();
        vec![
            CapabilityEffect::new(format!(
                "Patch {sensor}: [collectors.nginx_access] enabled = true"
            )),
            CapabilityEffect::new(format!(
                "Patch {sensor}: [detectors.search_abuse] enabled = true"
            )),
            CapabilityEffect::new(format!("Patch {agent}: [responder] enabled = true")),
            CapabilityEffect::new("Add \"rate-limit-nginx\" to [responder] allowed_skills"),
            CapabilityEffect::new(format!(
                "Write /etc/sudoers.d/{} (validated with visudo)",
                Self::sudoers_name()
            )),
            CapabilityEffect::new("Create /etc/nginx/innerwarden-blocklist.conf placeholder"),
            CapabilityEffect::new("Restart innerwarden-sensor"),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();
        let mut warnings = Vec::new();

        // 1. Patch sensor: enable nginx_access collector
        config_editor::write_bool(
            &opts.sensor_config,
            "collectors.nginx_access",
            "enabled",
            true,
        )?;
        effects.push(CapabilityEffect::new(
            "[collectors.nginx_access] enabled = true",
        ));

        // 2. Patch sensor: enable search_abuse detector
        config_editor::write_bool(
            &opts.sensor_config,
            "detectors.search_abuse",
            "enabled",
            true,
        )?;
        effects.push(CapabilityEffect::new(
            "[detectors.search_abuse] enabled = true",
        ));

        // 3. Patch agent: responder enabled
        config_editor::write_bool(&opts.agent_config, "responder", "enabled", true)?;
        effects.push(CapabilityEffect::new("[responder] enabled = true"));

        // 4. Add skill to allowed_skills
        let added = config_editor::write_array_push(
            &opts.agent_config,
            "responder",
            "allowed_skills",
            "rate-limit-nginx",
        )?;
        if added {
            effects.push(CapabilityEffect::new(
                "Added \"rate-limit-nginx\" to [responder] allowed_skills",
            ));
        }

        // 5. Write sudoers drop-in
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), search_protection_nginx_rule());
        drop_in.install(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Wrote /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 6. Create placeholder blocklist file so nginx can include it immediately
        const BLOCKLIST_PATH: &str = "/etc/nginx/innerwarden-blocklist.conf";
        if !std::path::Path::new(BLOCKLIST_PATH).exists() {
            if opts.dry_run {
                warnings.push(format!(
                    "DRY RUN: would create {BLOCKLIST_PATH} placeholder"
                ));
            } else {
                create_nginx_placeholder(BLOCKLIST_PATH)?;
                effects.push(CapabilityEffect::new(format!(
                    "Created {BLOCKLIST_PATH} placeholder"
                )));
            }
        }

        // 7. Remind operator to add the nginx include directive
        warnings.push(
            "Add `include /etc/nginx/innerwarden-blocklist.conf;` inside an `http { }` block \
             in your nginx config, then run: sudo nginx -t && sudo nginx -s reload"
                .to_string(),
        );

        // 8. Restart sensor (nginx_access collector must pick up new config)
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        // 9. Restart agent (rate-limit-nginx skill is now in allowed_skills)
        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings,
        })
    }

    fn planned_disable_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let sensor = opts.sensor_config.display().to_string();
        let agent = opts.agent_config.display().to_string();
        vec![
            CapabilityEffect::new(format!(
                "Patch {sensor}: [collectors.nginx_access] enabled = false"
            )),
            CapabilityEffect::new(format!(
                "Patch {sensor}: [detectors.search_abuse] enabled = false"
            )),
            CapabilityEffect::new(format!(
                "Remove \"rate-limit-nginx\" from [responder] allowed_skills in {agent}"
            )),
            CapabilityEffect::new(format!("Remove /etc/sudoers.d/{}", Self::sudoers_name())),
            CapabilityEffect::new("Restart innerwarden-sensor"),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();
        let warnings = vec![
            "The file /etc/nginx/innerwarden-blocklist.conf was left in place to avoid \
             breaking nginx includes. You may remove it manually once you have updated \
             your nginx config."
                .to_string(),
        ];

        // 1. Disable collector
        config_editor::write_bool(
            &opts.sensor_config,
            "collectors.nginx_access",
            "enabled",
            false,
        )?;
        effects.push(CapabilityEffect::new(
            "[collectors.nginx_access] enabled = false",
        ));

        // 2. Disable detector
        config_editor::write_bool(
            &opts.sensor_config,
            "detectors.search_abuse",
            "enabled",
            false,
        )?;
        effects.push(CapabilityEffect::new(
            "[detectors.search_abuse] enabled = false",
        ));

        // 3. Remove skill from allowed_skills
        let removed = config_editor::write_array_remove(
            &opts.agent_config,
            "responder",
            "allowed_skills",
            "rate-limit-nginx",
        )?;
        if removed {
            effects.push(CapabilityEffect::new(
                "Removed \"rate-limit-nginx\" from [responder] allowed_skills",
            ));
        }

        // 4. Remove sudoers drop-in
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), String::new());
        drop_in.remove(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Removed /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 5 & 6. Restart both services
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings,
        })
    }

    fn is_enabled(&self, opts: &ActivationOptions) -> bool {
        config_editor::read_bool(&opts.sensor_config, "collectors.nginx_access", "enabled")
            && config_editor::read_bool(&opts.sensor_config, "detectors.search_abuse", "enabled")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an empty placeholder at `path` via `sudo install` so nginx can
/// include the file before any block rules have been written.
fn create_nginx_placeholder(path: &str) -> Result<()> {
    let comment = "# Managed by innerwarden — do not edit manually\n\
                   # Block rules populated automatically by the rate-limit-nginx skill\n";
    let tmp = PathBuf::from(format!(
        "/tmp/innerwarden-nginx-placeholder-{}",
        std::process::id()
    ));
    std::fs::write(&tmp, comment).context("failed to write nginx placeholder tmp file")?;

    let out = std::process::Command::new("sudo")
        .args([
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "644",
            tmp.to_str().unwrap(),
            path,
        ])
        .output()
        .context("failed to run sudo install for nginx placeholder")?;

    let _ = std::fs::remove_file(&tmp);

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("failed to create nginx placeholder {path}: {stderr}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_opts(sensor: &NamedTempFile, agent: &NamedTempFile) -> ActivationOptions {
        ActivationOptions {
            sensor_config: sensor.path().to_path_buf(),
            agent_config: agent.path().to_path_buf(),
            dry_run: true,
            params: HashMap::new(),
            yes: true,
        }
    }

    #[test]
    fn not_enabled_when_nginx_access_not_configured() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!SearchProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn not_enabled_when_search_abuse_not_configured() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[collectors.nginx_access]\nenabled = true\n").unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        // search_abuse is absent → not enabled
        assert!(!SearchProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn is_enabled_when_both_configured() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(
            sensor,
            "[collectors.nginx_access]\nenabled = true\n\
             [detectors.search_abuse]\nenabled = true\n"
        )
        .unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(SearchProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn not_enabled_when_search_abuse_explicitly_false() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(
            sensor,
            "[collectors.nginx_access]\nenabled = true\n\
             [detectors.search_abuse]\nenabled = false\n"
        )
        .unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!SearchProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn activate_dry_run_patches_sensor_config() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[responder]\nenabled = false\n").unwrap();
        let opts = make_opts(&sensor, &agent);

        SearchProtectionCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(
            sensor.path(),
            "collectors.nginx_access",
            "enabled"
        ));
        assert!(config_editor::read_bool(
            sensor.path(),
            "detectors.search_abuse",
            "enabled"
        ));
    }

    #[test]
    fn activate_dry_run_patches_agent_config() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[responder]\nenabled = false\n").unwrap();
        let opts = make_opts(&sensor, &agent);

        SearchProtectionCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(
            agent.path(),
            "responder",
            "enabled"
        ));
        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(skills.contains(&"rate-limit-nginx".to_string()));
    }

    #[test]
    fn activate_is_idempotent_for_skill_push() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nenabled = true\nallowed_skills = [\"rate-limit-nginx\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        SearchProtectionCapability.activate(&opts).unwrap();

        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        // No duplicate should appear
        let count = skills
            .iter()
            .filter(|s| s.as_str() == "rate-limit-nginx")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn planned_effects_includes_all_steps() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = SearchProtectionCapability.planned_effects(&opts);
        assert_eq!(effects.len(), 8);
    }

    #[test]
    fn deactivate_dry_run_disables_collector_and_detector() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(
            sensor,
            "[collectors.nginx_access]\nenabled = true\n\
             [detectors.search_abuse]\nenabled = true\n"
        )
        .unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"rate-limit-nginx\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        SearchProtectionCapability.deactivate(&opts).unwrap();

        assert!(!config_editor::read_bool(
            sensor.path(),
            "collectors.nginx_access",
            "enabled"
        ));
        assert!(!config_editor::read_bool(
            sensor.path(),
            "detectors.search_abuse",
            "enabled"
        ));
        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(!skills.contains(&"rate-limit-nginx".to_string()));
    }

    #[test]
    fn deactivate_preserves_unrelated_skills() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"rate-limit-nginx\", \"block-ip-ufw\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        SearchProtectionCapability.deactivate(&opts).unwrap();

        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(!skills.contains(&"rate-limit-nginx".to_string()));
        assert!(skills.contains(&"block-ip-ufw".to_string()));
    }

    #[test]
    fn planned_disable_effects_count() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = SearchProtectionCapability.planned_disable_effects(&opts);
        assert_eq!(effects.len(), 6);
    }

    #[test]
    fn sudoers_rule_contains_nginx_commands() {
        let rule = search_protection_nginx_rule();
        assert!(rule.contains("nginx -t"));
        assert!(rule.contains("nginx -s reload"));
        assert!(rule.contains("innerwarden-blocklist.conf"));
        assert!(rule.contains("NOPASSWD"));
    }
}
