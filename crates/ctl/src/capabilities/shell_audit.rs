use anyhow::Result;

use crate::capability::{
    ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight,
};
use crate::config_editor;
use crate::preflight::{BinaryExists, DirectoryExists};
use crate::systemd;

pub struct ShellAuditCapability;

const AUDITD_RULE_FILE: &str = "/etc/audit/rules.d/innerwarden-shell-audit.rules";
const AUDITD_RULES: &str = "\
# Managed by innerwarden-ctl — do not edit manually
# Captures all execve(2) syscalls for command execution audit trail.
# PRIVACY: this records all commands run on this host.
-a always,exit -F arch=b64 -S execve -k innerwarden_exec
-a always,exit -F arch=b32 -S execve -k innerwarden_exec
";

impl ShellAuditCapability {
    /// Print the privacy notice and prompt for explicit consent.
    /// Returns Ok(()) if the user confirms, Err if they decline or we can't prompt.
    fn confirm_privacy(&self, opts: &ActivationOptions) -> Result<()> {
        if opts.yes {
            return Ok(());
        }

        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║               WARNING: PRIVACY NOTICE                   ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║                                                          ║");
        eprintln!("║  Shell audit captures ALL executed commands on this      ║");
        eprintln!("║  host, including:                                        ║");
        eprintln!("║    - Commands run by ALL users (execve syscalls)         ║");
        eprintln!("║    - Command arguments (may include secrets/passwords)   ║");
        eprintln!("║                                                          ║");
        eprintln!("║  Before enabling, obtain authorization from:             ║");
        eprintln!("║    - The system owner or administrator                   ║");
        eprintln!("║    - All users whose activity will be monitored          ║");
        eprintln!("║    - Your security/legal/compliance team                 ║");
        eprintln!("║                                                          ║");
        eprintln!("║  To skip this prompt: innerwarden enable shell-audit --yes");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();

        eprint!("I confirm I have authorization to enable shell audit. [y/N] ");
        use std::io::Write;
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input == "y" || input == "yes" {
            Ok(())
        } else {
            anyhow::bail!("shell-audit not enabled — explicit authorization required");
        }
    }
}

impl Capability for ShellAuditCapability {
    fn id(&self) -> &'static str {
        "shell-audit"
    }

    fn name(&self) -> &'static str {
        "Shell Audit"
    }

    fn description(&self) -> &'static str {
        "Capture executed commands via auditd (requires explicit privacy authorization)"
    }

    fn preflights(&self, _opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
        vec![
            Box::new(BinaryExists {
                display_name: "auditd is installed",
                path: "/usr/sbin/auditd",
            }),
            Box::new(DirectoryExists {
                display_name: "/etc/audit/rules.d/ directory exists",
                path: "/etc/audit/rules.d",
            }),
        ]
    }

    fn planned_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let sensor = opts.sensor_config.display().to_string();
        vec![
            CapabilityEffect::new("[Privacy authorization required before applying changes]"),
            CapabilityEffect::new(format!(
                "Patch {sensor}: [collectors.exec_audit] enabled = true"
            )),
            CapabilityEffect::new(format!("Write {AUDITD_RULE_FILE}")),
            CapabilityEffect::new("Load audit rules (augenrules --load)"),
            CapabilityEffect::new("Restart innerwarden-sensor"),
        ]
    }

    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();
        let mut warnings = Vec::new();

        // Privacy gate — must happen before any mutation
        self.confirm_privacy(opts)?;

        // 1. Patch sensor config: collectors.exec_audit.enabled = true
        config_editor::write_bool(
            &opts.sensor_config,
            "collectors.exec_audit",
            "enabled",
            true,
        )?;
        effects.push(CapabilityEffect::new(
            "[collectors.exec_audit] enabled = true",
        ));

        // 2. Write auditd rule file
        if !opts.dry_run {
            if let Some(parent) = std::path::Path::new(AUDITD_RULE_FILE).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(AUDITD_RULE_FILE, AUDITD_RULES)?;
        }
        effects.push(CapabilityEffect::new(format!("Wrote {AUDITD_RULE_FILE}")));

        // 3. Load the audit rules
        if !opts.dry_run {
            load_audit_rules(AUDITD_RULE_FILE, &mut warnings)?;
        }
        effects.push(CapabilityEffect::new("Loaded audit rules"));

        // 4. Restart sensor
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings,
        })
    }

    fn planned_disable_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let sensor = opts.sensor_config.display().to_string();
        vec![
            CapabilityEffect::new(format!(
                "Patch {sensor}: [collectors.exec_audit] enabled = false"
            )),
            CapabilityEffect::new(format!("Remove {AUDITD_RULE_FILE}")),
            CapabilityEffect::new("Reload audit rules (augenrules --load)"),
            CapabilityEffect::new("Restart innerwarden-sensor"),
        ]
    }

    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();
        let mut warnings = Vec::new();

        // 1. Disable collector in sensor config
        config_editor::write_bool(
            &opts.sensor_config,
            "collectors.exec_audit",
            "enabled",
            false,
        )?;
        effects.push(CapabilityEffect::new(
            "[collectors.exec_audit] enabled = false",
        ));

        // 2. Remove auditd rule file
        if !opts.dry_run {
            let rule_path = std::path::Path::new(AUDITD_RULE_FILE);
            if rule_path.exists() {
                std::fs::remove_file(rule_path)?;
            }
        }
        effects.push(CapabilityEffect::new(format!("Removed {AUDITD_RULE_FILE}")));

        // 3. Reload audit rules so the execve filter is deactivated
        if !opts.dry_run {
            load_audit_rules(AUDITD_RULE_FILE, &mut warnings)?;
        }
        effects.push(CapabilityEffect::new("Reloaded audit rules"));

        // 4. Restart sensor
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings,
        })
    }

    fn is_enabled(&self, opts: &ActivationOptions) -> bool {
        config_editor::read_bool(&opts.sensor_config, "collectors.exec_audit", "enabled")
    }
}

/// Attempt to load audit rules via `augenrules --load`, fallback to `auditctl -R`.
fn load_audit_rules(rule_file: &str, warnings: &mut Vec<String>) -> Result<()> {
    // Try augenrules first (preferred: loads all rules from rules.d/)
    if std::path::Path::new("/usr/sbin/augenrules").exists() {
        let out = std::process::Command::new("augenrules")
            .arg("--load")
            .output()?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        warnings.push(format!("augenrules --load failed: {stderr}"));
    }

    // Fallback: auditctl -R <file>
    let auditctl = if std::path::Path::new("/usr/sbin/auditctl").exists() {
        "/usr/sbin/auditctl"
    } else if std::path::Path::new("/usr/bin/auditctl").exists() {
        "/usr/bin/auditctl"
    } else {
        warnings.push(
            "auditctl not found — audit rules written but not loaded. \
             Reboot or run 'augenrules --load' manually."
                .to_string(),
        );
        return Ok(());
    };

    let out = std::process::Command::new(auditctl)
        .args(["-R", rule_file])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        warnings.push(format!(
            "auditctl -R {rule_file} failed: {stderr} — \
             rules written but not active until reboot or manual load"
        ));
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
            yes: true, // skip privacy gate in tests
        }
    }

    #[test]
    fn not_enabled_when_collector_off() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!ShellAuditCapability.is_enabled(&opts));
    }

    #[test]
    fn is_enabled_when_collector_on() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[collectors.exec_audit]\nenabled = true\n").unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(ShellAuditCapability.is_enabled(&opts));
    }

    #[test]
    fn activate_dry_run_patches_sensor_config() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);

        ShellAuditCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(
            sensor.path(),
            "collectors.exec_audit",
            "enabled"
        ));
    }

    #[test]
    fn deactivate_dry_run_disables_collector() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[collectors.exec_audit]\nenabled = true\n").unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);

        ShellAuditCapability.deactivate(&opts).unwrap();

        assert!(!config_editor::read_bool(
            sensor.path(),
            "collectors.exec_audit",
            "enabled"
        ));
    }

    #[test]
    fn planned_disable_effects_count() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = ShellAuditCapability.planned_disable_effects(&opts);
        assert_eq!(effects.len(), 4);
    }

    #[test]
    fn planned_effects_includes_privacy_notice() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = ShellAuditCapability.planned_effects(&opts);
        assert!(effects[0].description.contains("Privacy"));
    }
}
