use anyhow::Result;

use crate::capability::{
    ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight,
};
use crate::config_editor;
use crate::preflight::{BinaryExists, DirectoryExists, UserExists};
use crate::sudoers::{block_ip_rule, SudoersDropIn};
use crate::systemd;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

pub struct BlockIpCapability;

const BLOCK_IP_BACKENDS: &[&str] = &["ufw", "iptables", "nftables"];

impl BlockIpCapability {
    fn backend<'a>(&self, opts: &'a ActivationOptions) -> &'a str {
        opts.params
            .get("backend")
            .map(|s| s.as_str())
            .unwrap_or("ufw")
    }

    fn skill_id(&self, backend: &str) -> String {
        format!("block-ip-{backend}")
    }

    fn sudoers_name() -> &'static str {
        "innerwarden-block-ip"
    }
}

impl Capability for BlockIpCapability {
    fn id(&self) -> &'static str {
        "block-ip"
    }

    fn name(&self) -> &'static str {
        "Block IP"
    }

    fn description(&self) -> &'static str {
        "Block attacking IPs via firewall (ufw / iptables / nftables)"
    }

    fn preflights(&self, opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
        let backend = self.backend(opts);
        let (display_name, path): (&'static str, &'static str) = match backend {
            "iptables" => ("iptables is installed", "/sbin/iptables"),
            "nftables" => ("nft is installed", "/usr/sbin/nft"),
            _ => ("ufw is installed", "/usr/sbin/ufw"),
        };
        vec![
            Box::new(BinaryExists { display_name, path }),
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
        let backend = self.backend(opts);
        let agent = opts.agent_config.display().to_string();
        let skill = self.skill_id(backend);
        vec![
            CapabilityEffect::new(format!("Patch {agent}: [responder] enabled = true")),
            CapabilityEffect::new(format!(
                "Patch {agent}: [responder] block_backend = \"{backend}\""
            )),
            CapabilityEffect::new(format!(
                "Add \"{skill}\" to [responder] allowed_skills in {agent}"
            )),
            CapabilityEffect::new(format!(
                "Write /etc/sudoers.d/{} (validated with visudo)",
                Self::sudoers_name()
            )),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let backend = self.backend(opts);

        if !["ufw", "iptables", "nftables"].contains(&backend) {
            anyhow::bail!(
                "unsupported backend '{}' — use one of: ufw, iptables, nftables",
                backend
            );
        }

        let skill = self.skill_id(backend);
        let mut effects = Vec::new();

        // 1. Patch agent.toml: responder.enabled = true
        config_editor::write_bool(&opts.agent_config, "responder", "enabled", true)?;
        effects.push(CapabilityEffect::new("[responder] enabled = true"));

        // 2. Patch agent.toml: responder.block_backend = backend
        config_editor::write_str(&opts.agent_config, "responder", "block_backend", backend)?;
        effects.push(CapabilityEffect::new(format!(
            "[responder] block_backend = \"{backend}\""
        )));

        // 3. Add skill to allowed_skills
        let added = config_editor::write_array_push(
            &opts.agent_config,
            "responder",
            "allowed_skills",
            &skill,
        )?;
        if added {
            effects.push(CapabilityEffect::new(format!(
                "Added \"{skill}\" to [responder] allowed_skills"
            )));
        }

        // 4. Write sudoers drop-in
        let rule = block_ip_rule(backend)
            .ok_or_else(|| anyhow::anyhow!("no sudoers rule for backend '{}'", backend))?;
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), rule);
        drop_in.install(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Wrote /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 5. Restart agent
        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings: vec![],
        })
    }

    fn planned_disable_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let agent = opts.agent_config.display().to_string();
        vec![
            CapabilityEffect::new(format!(
                "Remove block-ip-* skills from [responder] allowed_skills in {agent}"
            )),
            CapabilityEffect::new(format!("Remove /etc/sudoers.d/{}", Self::sudoers_name())),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();

        // 1. Remove all block-ip-* skills from allowed_skills
        for backend in BLOCK_IP_BACKENDS {
            let skill = self.skill_id(backend);
            let removed = config_editor::write_array_remove(
                &opts.agent_config,
                "responder",
                "allowed_skills",
                &skill,
            )?;
            if removed {
                effects.push(CapabilityEffect::new(format!(
                    "Removed \"{skill}\" from [responder] allowed_skills"
                )));
            }
        }

        // 2. Remove sudoers drop-in
        let drop_in = SudoersDropIn::new(Self::sudoers_name(), String::new());
        drop_in.remove(opts.dry_run)?;
        effects.push(CapabilityEffect::new(format!(
            "Removed /etc/sudoers.d/{}",
            Self::sudoers_name()
        )));

        // 3. Restart agent
        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings: vec![],
        })
    }

    fn is_enabled(&self, opts: &ActivationOptions) -> bool {
        // Enabled if responder is on and any block-ip skill is in allowed_skills
        if !config_editor::read_bool(&opts.agent_config, "responder", "enabled") {
            return false;
        }
        let skills =
            config_editor::read_str_array(&opts.agent_config, "responder", "allowed_skills");
        BLOCK_IP_BACKENDS
            .iter()
            .any(|backend| skills.contains(&format!("block-ip-{backend}")))
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
    fn not_enabled_when_responder_disabled() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[responder]\nenabled = false\n").unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!BlockIpCapability.is_enabled(&opts));
    }

    #[test]
    fn not_enabled_when_no_block_ip_skill() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nenabled = true\nallowed_skills = [\"monitor-ip\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(!BlockIpCapability.is_enabled(&opts));
    }

    #[test]
    fn is_enabled_when_responder_on_and_skill_present() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nenabled = true\nallowed_skills = [\"block-ip-ufw\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);
        assert!(BlockIpCapability.is_enabled(&opts));
    }

    #[test]
    fn activate_dry_run_patches_agent_config() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[responder]\nenabled = false\ndry_run = true\n").unwrap();
        let opts = make_opts(&sensor, &agent);

        // Even in dry_run, config patches are applied (dry_run only skips system calls)
        BlockIpCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(
            agent.path(),
            "responder",
            "enabled"
        ));
        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(skills.contains(&"block-ip-ufw".to_string()));
    }

    #[test]
    fn planned_effects_includes_all_steps() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = BlockIpCapability.planned_effects(&opts);
        assert_eq!(effects.len(), 5);
    }

    #[test]
    fn deactivate_dry_run_removes_skills_from_config() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nenabled = true\nallowed_skills = [\"block-ip-ufw\", \"monitor-ip\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        BlockIpCapability.deactivate(&opts).unwrap();

        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(!skills.contains(&"block-ip-ufw".to_string()));
        // unrelated skills are preserved
        assert!(skills.contains(&"monitor-ip".to_string()));
    }

    #[test]
    fn deactivate_removes_all_backend_variants() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(
            agent,
            "[responder]\nallowed_skills = [\"block-ip-ufw\", \"block-ip-iptables\"]\n"
        )
        .unwrap();
        let opts = make_opts(&sensor, &agent);

        BlockIpCapability.deactivate(&opts).unwrap();

        let skills = config_editor::read_str_array(agent.path(), "responder", "allowed_skills");
        assert!(skills.is_empty());
    }

    #[test]
    fn planned_disable_effects_count() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let opts = make_opts(&sensor, &agent);
        let effects = BlockIpCapability.planned_disable_effects(&opts);
        assert_eq!(effects.len(), 3);
    }
}
