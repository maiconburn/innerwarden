use anyhow::Result;

use crate::capability::{
    ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight,
};
use crate::config_editor;
use crate::preflight::{DirectoryExists, UserExists, VisudoAvailable};
use crate::sudoers::{suspend_user_sudo_rule, SudoersDropIn};
use crate::systemd;

pub struct SudoProtectionCapability;

impl SudoProtectionCapability {
    fn sudoers_name() -> &'static str {
        "innerwarden-suspend-user"
    }
}

impl Capability for SudoProtectionCapability {
    fn id(&self) -> &'static str {
        "sudo-protection"
    }

    fn name(&self) -> &'static str {
        "Sudo Protection"
    }

    fn description(&self) -> &'static str {
        "Detect sudo abuse and temporarily suspend user sudo rights"
    }

    fn preflights(&self, _opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
        vec![
            Box::new(VisudoAvailable),
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
                "Patch {sensor}: [detectors.sudo_abuse] enabled = true"
            )),
            CapabilityEffect::new(format!("Patch {agent}: [responder] enabled = true")),
            CapabilityEffect::new(format!(
                "Add \"suspend-user-sudo\" to [responder] allowed_skills in {agent}"
            )),
            CapabilityEffect::new(format!(
                "Write /etc/sudoers.d/{} (validated with visudo)",
                Self::sudoers_name()
            )),
            CapabilityEffect::new("Restart innerwarden-sensor"),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();

        // 1. Patch sensor config: detectors.sudo_abuse.enabled = true
        config_editor::write_bool(&opts.sensor_config, "detectors.sudo_abuse", "enabled", true)?;
        effects.push(CapabilityEffect::new(
            "[detectors.sudo_abuse] enabled = true",
        ));

        // 2. Patch agent config: responder.enabled = true
        config_editor::write_bool(&opts.agent_config, "responder", "enabled", true)?;
        effects.push(CapabilityEffect::new("[responder] enabled = true"));

        // 3. Add suspend-user-sudo to allowed_skills
        let added = config_editor::write_array_push(
            &opts.agent_config,
            "responder",
            "allowed_skills",
            "suspend-user-sudo",
        )?;
        if added {
            effects.push(CapabilityEffect::new(
                "Added \"suspend-user-sudo\" to [responder] allowed_skills",
            ));
        }

        // 4. Write sudoers drop-in
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), suspend_user_sudo_rule());
        drop_in.install(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Wrote /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 5 & 6. Restart both services
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings: vec![],
        })
    }

    fn planned_disable_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let sensor = opts.sensor_config.display().to_string();
        let agent = opts.agent_config.display().to_string();
        vec![
            CapabilityEffect::new(format!(
                "Patch {sensor}: [detectors.sudo_abuse] enabled = false"
            )),
            CapabilityEffect::new(format!(
                "Remove \"suspend-user-sudo\" from [responder] allowed_skills in {agent}"
            )),
            CapabilityEffect::new(format!("Remove /etc/sudoers.d/{}", Self::sudoers_name())),
            CapabilityEffect::new("Restart innerwarden-sensor"),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();

        // 1. Disable detector in sensor config
        config_editor::write_bool(
            &opts.sensor_config,
            "detectors.sudo_abuse",
            "enabled",
            false,
        )?;
        effects.push(CapabilityEffect::new(
            "[detectors.sudo_abuse] enabled = false",
        ));

        // 2. Remove skill from allowed_skills
        let removed = config_editor::write_array_remove(
            &opts.agent_config,
            "responder",
            "allowed_skills",
            "suspend-user-sudo",
        )?;
        if removed {
            effects.push(CapabilityEffect::new(
                "Removed \"suspend-user-sudo\" from [responder] allowed_skills",
            ));
        }

        // 3. Remove sudoers drop-in
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), String::new());
        drop_in.remove(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Removed /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 4 & 5. Restart both services
        systemd::restart_service("innerwarden-sensor", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-sensor"));

        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings: vec![],
        })
    }

    fn is_enabled(&self, opts: &ActivationOptions) -> bool {
        // Both conditions must be true
        let detector_on =
            config_editor::read_bool(&opts.sensor_config, "detectors.sudo_abuse", "enabled");
        let skills =
            config_editor::read_str_array(&opts.agent_config, "responder", "allowed_skills");
        detector_on && skills.contains(&"suspend-user-sudo".to_string())
    }
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
    fn not_enabled_when_detector_off() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"suspend-user-sudo\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!SudoProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn not_enabled_when_skill_missing() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[detectors.sudo_abuse]\nenabled = true\n").unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!SudoProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn is_enabled_when_both_conditions_met() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[detectors.sudo_abuse]\nenabled = true\n").unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"suspend-user-sudo\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(SudoProtectionCapability.is_enabled(&opts));
    }

    #[test]
    fn deactivate_dry_run_disables_detector_and_removes_skill() {
        let mut sensor = NamedTempFile::new().unwrap();
        writeln!(sensor, "[detectors.sudo_abuse]\nenabled = true\n").unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"suspend-user-sudo\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        SudoProtectionCapability.deactivate(&opts).unwrap();

        assert!(!config_editor::read_bool(
            sensor.path(),
            "detectors.sudo_abuse",
            "enabled"
        ));
        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(!skills.contains(&"suspend-user-sudo".to_string()));
    }

    #[test]
    fn planned_disable_effects_count() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = SudoProtectionCapability.planned_disable_effects(&opts);
        assert_eq!(effects.len(), 5);
    }

    #[test]
    fn activate_dry_run_patches_both_configs() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);

        SudoProtectionCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(
            sensor.path(),
            "detectors.sudo_abuse",
            "enabled"
        ));
        assert!(config_editor::read_bool(
            agent.path(),
            "responder",
            "enabled"
        ));
        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(skills.contains(&"suspend-user-sudo".to_string()));
    }
}
