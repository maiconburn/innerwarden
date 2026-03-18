//! Parses a `module.toml` manifest into a typed `ModuleManifest` struct.
//!
//! Also provides helpers used by `innerwarden module enable`:
//! - `collector_section` / `detector_section` — map module-provided IDs to sensor config keys
//! - `notifier_section` — map module-provided notifier IDs to agent config section names
//! - `generate_module_sudoers_rule` — build a sudoers drop-in from `[security].allowed_commands`
//! - `module_planned_effects` — human-readable list of what `enable` will do
//! - `is_module_enabled` — check whether all components are already active

use std::path::Path;

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    /// SemVer string from `[module].version` (optional)
    pub version: Option<String>,
    /// URL to the latest `.tar.gz` package for `module update-all` (optional)
    pub update_url: Option<String>,
    /// Collector IDs from `[provides].collectors`
    pub collectors: Vec<String>,
    /// Detector IDs from `[provides].detectors`
    pub detectors: Vec<String>,
    /// Unique skill IDs harvested from all `[[rules]].skill` entries
    pub skills: Vec<String>,
    /// Notifier IDs from `[provides].notifiers` (e.g. "slack", "cloudflare_push")
    pub notifiers: Vec<String>,
    /// Binary paths from `[security].allowed_commands` (used to build sudoers rule)
    pub allowed_commands: Vec<String>,
    /// Preflight specs from `[[preflights]]`
    pub preflights: Vec<ModulePreflightSpec>,
}

#[derive(Debug, Clone)]
pub struct ModulePreflightSpec {
    /// "binary_exists" | "directory_exists" | "user_exists"
    pub kind: String,
    pub value: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl ModuleManifest {
    pub fn from_path(module_path: &Path) -> Result<Self> {
        let manifest_path = module_path.join("module.toml");
        let src = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        let doc = src
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
        Self::from_doc(&doc)
    }

    fn from_doc(doc: &toml_edit::DocumentMut) -> Result<Self> {
        let module = doc
            .get("module")
            .and_then(|v| v.as_table())
            .ok_or_else(|| anyhow::anyhow!("missing [module] table in module.toml"))?;

        let id = module
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing [module].id"))?
            .to_string();

        let name = module
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        let builtin = module
            .get("builtin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let version = module
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);

        let update_url = module
            .get("update_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        // [provides]
        let provides = doc.get("provides").and_then(|v| v.as_table());
        let collectors = str_array(provides.as_ref().and_then(|t| t.get("collectors")));
        let detectors = str_array(provides.as_ref().and_then(|t| t.get("detectors")));
        let notifiers = str_array(provides.as_ref().and_then(|t| t.get("notifiers")));

        // [[rules]] — collect unique skills in declaration order
        let mut skills: Vec<String> = Vec::new();
        if let Some(rules) = doc.get("rules").and_then(|v| v.as_array_of_tables()) {
            for rule in rules.iter() {
                if let Some(skill) = rule.get("skill").and_then(|v| v.as_str()) {
                    if !skills.iter().any(|s| s == skill) {
                        skills.push(skill.to_string());
                    }
                }
            }
        }

        // [security]
        let security = doc.get("security").and_then(|v| v.as_table());
        let allowed_commands = str_array(security.as_ref().and_then(|t| t.get("allowed_commands")));

        // [[preflights]]
        let mut preflights = Vec::new();
        if let Some(pf_arr) = doc.get("preflights").and_then(|v| v.as_array_of_tables()) {
            for pf in pf_arr.iter() {
                if let (Some(kind), Some(value)) = (
                    pf.get("kind").and_then(|v| v.as_str()),
                    pf.get("value").and_then(|v| v.as_str()),
                ) {
                    preflights.push(ModulePreflightSpec {
                        kind: kind.to_string(),
                        value: value.to_string(),
                        reason: pf
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
        }

        Ok(Self {
            id,
            name,
            builtin,
            version,
            update_url,
            collectors,
            detectors,
            skills,
            notifiers,
            allowed_commands,
            preflights,
        })
    }
}

fn str_array(item: Option<&toml_edit::Item>) -> Vec<String> {
    item.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Collector / detector / notifier → config section mapping
// ---------------------------------------------------------------------------

/// Maps a module `[provides].collectors` ID to its `[section]` name in the sensor config.
pub fn collector_section(id: &str) -> Option<&'static str> {
    match id {
        // Native collectors
        "auth-log" => Some("collectors.auth_log"),
        "journald" => Some("collectors.journald"),
        "exec-audit" => Some("collectors.exec_audit"),
        "docker" => Some("collectors.docker"),
        "integrity" => Some("collectors.integrity"),
        "nginx-access-log" => Some("collectors.nginx_access"),
        "nginx-error-log" => Some("collectors.nginx_error"),
        "syslog-firewall" => Some("collectors.syslog_firewall"),
        "macos-log" => Some("collectors.macos_log"),
        // External collectors
        "falco-log" => Some("collectors.falco_log"),
        "suricata-eve" => Some("collectors.suricata_eve"),
        "wazuh-alerts" => Some("collectors.wazuh_alerts"),
        "osquery-log" => Some("collectors.osquery_log"),
        _ => None,
    }
}

/// Maps a module `[provides].detectors` ID to its `[section]` name in the sensor config.
pub fn detector_section(id: &str) -> Option<&'static str> {
    match id {
        "ssh-bruteforce" => Some("detectors.ssh_bruteforce"),
        "credential-stuffing" => Some("detectors.credential_stuffing"),
        "port-scan" => Some("detectors.port_scan"),
        "sudo-abuse" => Some("detectors.sudo_abuse"),
        "search-abuse" => Some("detectors.search_abuse"),
        "web-scan" => Some("detectors.web_scan"),
        "execution-guard" => Some("detectors.execution_guard"),
        "user-agent-scanner" => Some("detectors.user_agent_scanner"),
        _ => None,
    }
}

/// Maps a module `[provides].notifiers` ID to its `[section]` name in the agent config.
///
/// These sections have an `enabled` boolean that the enable/disable flow sets.
pub fn notifier_section(id: &str) -> Option<&'static str> {
    match id {
        "slack" => Some("slack"),
        "cloudflare_push" | "cloudflare" => Some("cloudflare"),
        "telegram" => Some("telegram"),
        "webhook" => Some("webhook"),
        "abuseipdb" => Some("abuseipdb"),
        "geoip" => Some("geoip"),
        "fail2ban" => Some("fail2ban"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Sudoers rule generator
// ---------------------------------------------------------------------------

/// Build a sudoers drop-in rule from `[security].allowed_commands`.
///
/// Entries that are bare binary paths (no spaces) get a trailing ` *` to allow
/// any arguments. Entries that already contain spaces are used verbatim.
pub fn generate_module_sudoers_rule(module_id: &str, allowed_commands: &[String]) -> String {
    let entries: Vec<String> = allowed_commands
        .iter()
        .map(|cmd| {
            if cmd.contains(' ') {
                cmd.clone()
            } else {
                format!("{cmd} *")
            }
        })
        .collect();
    let rules = entries.join(", \\\n  ");
    format!(
        "# Managed by innerwarden-ctl — do not edit manually\n\
         # Generated for module: {module_id}\n\
         innerwarden ALL=(ALL) NOPASSWD: \\\n  {rules}\n"
    )
}

// ---------------------------------------------------------------------------
// Enable helpers
// ---------------------------------------------------------------------------

/// Human-readable list of changes that `module enable` will apply.
pub fn module_planned_effects(
    sensor_config: &Path,
    agent_config: &Path,
    manifest: &ModuleManifest,
) -> Vec<String> {
    let sensor = sensor_config.display();
    let agent = agent_config.display();
    let mut effects = Vec::new();

    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            effects.push(format!("Patch {sensor}: [{section}] enabled = true"));
        } else {
            effects.push(format!("(skip) unknown collector '{id}'"));
        }
    }
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            effects.push(format!("Patch {sensor}: [{section}] enabled = true"));
        } else {
            effects.push(format!("(skip) unknown detector '{id}'"));
        }
    }
    if !manifest.skills.is_empty() {
        effects.push(format!("Patch {agent}: [responder] enabled = true"));
        for skill in &manifest.skills {
            effects.push(format!(
                "Add \"{skill}\" to [responder] allowed_skills in {agent}"
            ));
        }
    }
    for id in &manifest.notifiers {
        if let Some(section) = notifier_section(id) {
            effects.push(format!("Patch {agent}: [{section}] enabled = true"));
        } else {
            effects.push(format!("(skip) unknown notifier '{id}'"));
        }
    }
    if !manifest.allowed_commands.is_empty() {
        effects.push(format!(
            "Write /etc/sudoers.d/innerwarden-module-{} (validated with visudo)",
            manifest.id
        ));
    }
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty() || !manifest.notifiers.is_empty();
    if needs_sensor {
        effects.push("Restart innerwarden-sensor".to_string());
    }
    if needs_agent {
        effects.push("Restart innerwarden-agent".to_string());
    }
    effects
}

/// Human-readable list of changes that `module disable` will apply.
pub fn module_disable_effects(
    sensor_config: &Path,
    agent_config: &Path,
    manifest: &ModuleManifest,
) -> Vec<String> {
    let sensor = sensor_config.display();
    let agent = agent_config.display();
    let mut effects = Vec::new();

    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            effects.push(format!("Patch {sensor}: [{section}] enabled = false"));
        }
    }
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            effects.push(format!("Patch {sensor}: [{section}] enabled = false"));
        }
    }
    for skill in &manifest.skills {
        effects.push(format!(
            "Remove \"{skill}\" from [responder] allowed_skills in {agent}"
        ));
    }
    for id in &manifest.notifiers {
        if let Some(section) = notifier_section(id) {
            effects.push(format!("Patch {agent}: [{section}] enabled = false"));
        }
    }
    if !manifest.allowed_commands.is_empty() {
        effects.push(format!(
            "Remove /etc/sudoers.d/innerwarden-module-{}",
            manifest.id
        ));
    }
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty() || !manifest.notifiers.is_empty();
    if needs_sensor {
        effects.push("Restart innerwarden-sensor".to_string());
    }
    if needs_agent {
        effects.push("Restart innerwarden-agent".to_string());
    }
    effects
}

/// Scan `dir` for subdirectories that contain a `module.toml`, parse each and
/// return the successfully parsed manifests sorted by ID.
pub fn scan_modules_dir(dir: &Path) -> Vec<ModuleManifest> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut modules: Vec<ModuleManifest> = entries
        .flatten()
        .filter(|e| e.path().join("module.toml").exists())
        .filter_map(|e| ModuleManifest::from_path(&e.path()).ok())
        .collect();
    modules.sort_by(|a, b| a.id.cmp(&b.id));
    modules
}

/// Returns `true` if all collectors, detectors, skills, and notifiers declared
/// by the module are already active in their respective config files.
///
/// For skills: checks `[responder].allowed_skills` in the agent config.
/// For notifiers: checks `[<section>].enabled` in the agent config.
/// For modules with no checkable provides (all arrays empty), returns `true`.
pub fn is_module_enabled(
    sensor_config: &Path,
    agent_config: &Path,
    manifest: &ModuleManifest,
) -> bool {
    use crate::config_editor;

    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            if !config_editor::read_bool(sensor_config, section, "enabled") {
                return false;
            }
        }
    }
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            if !config_editor::read_bool(sensor_config, section, "enabled") {
                return false;
            }
        }
    }
    if !manifest.skills.is_empty() {
        let active = config_editor::read_str_array(agent_config, "responder", "allowed_skills");
        for skill in &manifest.skills {
            if !active.iter().any(|s| s == skill) {
                return false;
            }
        }
    }
    for id in &manifest.notifiers {
        if let Some(section) = notifier_section(id) {
            if !config_editor::read_bool(agent_config, section, "enabled") {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SEARCH_PROTECTION_TOML: &str = r#"
[module]
id          = "search-protection"
name        = "Search Route Protection"
version     = "0.1.0"
description = "Detect and block automated abuse of high-cost HTTP routes"
tier        = "open"
builtin     = true
min_innerwarden = "0.1.0"

[provides]
collectors = ["nginx-access-log"]
detectors  = ["search-abuse"]
skills     = ["rate-limit-nginx", "block-ip-ufw"]

[[rules]]
detector       = "search-abuse"
skill          = "rate-limit-nginx"
min_confidence = 0.8
auto_execute   = false

[[rules]]
detector       = "search-abuse"
skill          = "block-ip-ufw"
min_confidence = 0.9
auto_execute   = false

[security]
allowed_commands = ["/usr/sbin/ufw", "/usr/sbin/nginx"]

[[preflights]]
kind   = "binary_exists"
value  = "/usr/sbin/nginx"
reason = "nginx must be installed"

[[preflights]]
kind   = "binary_exists"
value  = "/usr/sbin/ufw"
reason = "ufw is required"
"#;

    const SLACK_NOTIFY_TOML: &str = r#"
[module]
id      = "slack-notify"
name    = "Slack Notifications"
version = "0.1.0"
description = "Sends incident alerts to a Slack channel via incoming webhook"
tier    = "open"
builtin = true

[provides]
notifiers = ["slack"]
"#;

    fn parse(toml: &str) -> ModuleManifest {
        let doc = toml.parse::<toml_edit::DocumentMut>().unwrap();
        ModuleManifest::from_doc(&doc).unwrap()
    }

    #[test]
    fn parses_basic_fields() {
        let m = parse(SEARCH_PROTECTION_TOML);
        assert_eq!(m.id, "search-protection");
        assert_eq!(m.name, "Search Route Protection");
        assert!(m.builtin);
        assert_eq!(m.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn parses_update_url_when_present() {
        let toml = r#"
[module]
id = "my-mod"
name = "My Mod"
version = "0.2.0"
update_url = "https://example.com/my-mod/latest.tar.gz"
description = "x"
tier = "open"
builtin = false
"#;
        let m = parse(toml);
        assert_eq!(m.version.as_deref(), Some("0.2.0"));
        assert_eq!(
            m.update_url.as_deref(),
            Some("https://example.com/my-mod/latest.tar.gz")
        );
    }

    #[test]
    fn version_and_update_url_are_none_when_absent() {
        let toml = "[module]\nid = \"x\"\nname = \"X\"\ndescription = \"x\"\ntier = \"open\"\nbuiltin = false\n";
        let m = parse(toml);
        assert!(m.version.is_none());
        assert!(m.update_url.is_none());
    }

    #[test]
    fn parses_provides() {
        let m = parse(SEARCH_PROTECTION_TOML);
        assert_eq!(m.collectors, vec!["nginx-access-log"]);
        assert_eq!(m.detectors, vec!["search-abuse"]);
        assert!(m.notifiers.is_empty());
    }

    #[test]
    fn parses_notifiers() {
        let m = parse(SLACK_NOTIFY_TOML);
        assert_eq!(m.notifiers, vec!["slack"]);
        assert!(m.collectors.is_empty());
        assert!(m.detectors.is_empty());
        assert!(m.skills.is_empty());
    }

    #[test]
    fn parses_cloudflare_notifier() {
        let toml = r#"
[module]
id = "cloudflare-integration"
name = "Cloudflare Integration"
version = "0.1.0"
description = "Pushes blocked IPs to Cloudflare edge"
tier = "open"
builtin = true

[provides]
notifiers = ["cloudflare_push"]
"#;
        let m = parse(toml);
        assert_eq!(m.notifiers, vec!["cloudflare_push"]);
        assert_eq!(notifier_section("cloudflare_push"), Some("cloudflare"));
    }

    #[test]
    fn skills_deduplicated_from_rules() {
        let m = parse(SEARCH_PROTECTION_TOML);
        assert_eq!(m.skills, vec!["rate-limit-nginx", "block-ip-ufw"]);
    }

    #[test]
    fn skills_deduplicated_when_same_skill_repeated() {
        let toml = r#"
[module]
id = "dup-test"
name = "Dup"
version = "0.1.0"
description = "x"
tier = "open"
builtin = false

[[rules]]
detector = "a"
skill = "my-skill"

[[rules]]
detector = "b"
skill = "my-skill"
"#;
        let m = parse(toml);
        assert_eq!(m.skills, vec!["my-skill"]);
    }

    #[test]
    fn parses_preflights() {
        let m = parse(SEARCH_PROTECTION_TOML);
        assert_eq!(m.preflights.len(), 2);
        assert_eq!(m.preflights[0].kind, "binary_exists");
        assert_eq!(m.preflights[0].value, "/usr/sbin/nginx");
        assert!(!m.preflights[0].reason.is_empty());
    }

    #[test]
    fn parses_allowed_commands() {
        let m = parse(SEARCH_PROTECTION_TOML);
        assert!(m.allowed_commands.contains(&"/usr/sbin/ufw".to_string()));
        assert!(m.allowed_commands.contains(&"/usr/sbin/nginx".to_string()));
    }

    #[test]
    fn collector_section_native_ids() {
        assert_eq!(collector_section("auth-log"), Some("collectors.auth_log"));
        assert_eq!(collector_section("journald"), Some("collectors.journald"));
        assert_eq!(
            collector_section("exec-audit"),
            Some("collectors.exec_audit")
        );
        assert_eq!(collector_section("docker"), Some("collectors.docker"));
        assert_eq!(collector_section("integrity"), Some("collectors.integrity"));
        assert_eq!(
            collector_section("nginx-access-log"),
            Some("collectors.nginx_access")
        );
        assert_eq!(
            collector_section("nginx-error-log"),
            Some("collectors.nginx_error")
        );
        assert_eq!(
            collector_section("syslog-firewall"),
            Some("collectors.syslog_firewall")
        );
        assert_eq!(collector_section("macos-log"), Some("collectors.macos_log"));
    }

    #[test]
    fn collector_section_external_ids() {
        assert_eq!(collector_section("falco-log"), Some("collectors.falco_log"));
        assert_eq!(
            collector_section("suricata-eve"),
            Some("collectors.suricata_eve")
        );
        assert_eq!(
            collector_section("wazuh-alerts"),
            Some("collectors.wazuh_alerts")
        );
        assert_eq!(
            collector_section("osquery-log"),
            Some("collectors.osquery_log")
        );
    }

    #[test]
    fn detector_section_all_ids() {
        assert_eq!(
            detector_section("ssh-bruteforce"),
            Some("detectors.ssh_bruteforce")
        );
        assert_eq!(
            detector_section("credential-stuffing"),
            Some("detectors.credential_stuffing")
        );
        assert_eq!(detector_section("port-scan"), Some("detectors.port_scan"));
        assert_eq!(detector_section("sudo-abuse"), Some("detectors.sudo_abuse"));
        assert_eq!(
            detector_section("search-abuse"),
            Some("detectors.search_abuse")
        );
        assert_eq!(detector_section("web-scan"), Some("detectors.web_scan"));
        assert_eq!(
            detector_section("execution-guard"),
            Some("detectors.execution_guard")
        );
        assert_eq!(
            detector_section("user-agent-scanner"),
            Some("detectors.user_agent_scanner")
        );
    }

    #[test]
    fn notifier_section_all_ids() {
        assert_eq!(notifier_section("slack"), Some("slack"));
        assert_eq!(notifier_section("cloudflare_push"), Some("cloudflare"));
        assert_eq!(notifier_section("cloudflare"), Some("cloudflare"));
        assert_eq!(notifier_section("telegram"), Some("telegram"));
        assert_eq!(notifier_section("webhook"), Some("webhook"));
        assert_eq!(notifier_section("abuseipdb"), Some("abuseipdb"));
        assert_eq!(notifier_section("geoip"), Some("geoip"));
        assert_eq!(notifier_section("fail2ban"), Some("fail2ban"));
    }

    #[test]
    fn unknown_ids_return_none() {
        assert!(collector_section("unknown-collector").is_none());
        assert!(detector_section("unknown-detector").is_none());
        assert!(notifier_section("unknown-notifier").is_none());
    }

    #[test]
    fn sudoers_rule_adds_wildcard_to_bare_paths() {
        let rule = generate_module_sudoers_rule(
            "my-module",
            &["/usr/sbin/ufw".to_string(), "/usr/sbin/nginx".to_string()],
        );
        assert!(rule.contains("/usr/sbin/ufw *"));
        assert!(rule.contains("/usr/sbin/nginx *"));
        assert!(rule.contains("NOPASSWD"));
        assert!(rule.contains("my-module"));
    }

    #[test]
    fn planned_effects_includes_notifiers() {
        let m = parse(SLACK_NOTIFY_TOML);
        let effects = module_planned_effects(
            Path::new("/etc/innerwarden/config.toml"),
            Path::new("/etc/innerwarden/agent.toml"),
            &m,
        );
        assert!(effects.iter().any(|e| e.contains("[slack] enabled = true")));
        assert!(effects.iter().any(|e| e.contains("innerwarden-agent")));
        assert!(!effects.iter().any(|e| e.contains("innerwarden-sensor")));
    }

    #[test]
    fn module_disable_effects_contains_expected_items() {
        let m = parse(SEARCH_PROTECTION_TOML);
        let effects = module_disable_effects(
            Path::new("/etc/innerwarden/config.toml"),
            Path::new("/etc/innerwarden/agent.toml"),
            &m,
        );
        assert!(effects
            .iter()
            .any(|e| e.contains("nginx_access") && e.contains("false")));
        assert!(effects
            .iter()
            .any(|e| e.contains("search_abuse") && e.contains("false")));
        assert!(effects
            .iter()
            .any(|e| e.contains("rate-limit-nginx") && e.contains("Remove")));
        assert!(effects.iter().any(|e| e.contains("innerwarden-sensor")));
        assert!(effects.iter().any(|e| e.contains("innerwarden-agent")));
    }

    #[test]
    fn disable_effects_includes_notifiers() {
        let m = parse(SLACK_NOTIFY_TOML);
        let effects = module_disable_effects(
            Path::new("/etc/innerwarden/config.toml"),
            Path::new("/etc/innerwarden/agent.toml"),
            &m,
        );
        assert!(effects
            .iter()
            .any(|e| e.contains("[slack] enabled = false")));
        assert!(effects.iter().any(|e| e.contains("innerwarden-agent")));
        assert!(!effects.iter().any(|e| e.contains("innerwarden-sensor")));
    }

    #[test]
    fn module_disable_effects_no_restart_when_no_collectors_or_detectors() {
        let toml = r#"
[module]
id = "skill-only"
name = "Skill Only"
version = "0.1.0"
description = "x"
tier = "open"
builtin = false

[provides]
skills = ["my-skill"]

[[rules]]
detector = "some-detector"
skill    = "my-skill"
"#;
        let m = parse(toml);
        let effects = module_disable_effects(
            Path::new("/tmp/sensor.toml"),
            Path::new("/tmp/agent.toml"),
            &m,
        );
        assert!(!effects.iter().any(|e| e.contains("innerwarden-sensor")));
        assert!(effects.iter().any(|e| e.contains("innerwarden-agent")));
    }

    #[test]
    fn scan_modules_dir_finds_modules() {
        use std::io::Write;
        use tempfile::TempDir;

        let root = TempDir::new().unwrap();

        // Module A
        let a = root.path().join("mod-a");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(a.join("docs")).unwrap();
        let toml_a =
            SEARCH_PROTECTION_TOML.replace("id          = \"search-protection\"", "id = \"mod-a\"");
        std::fs::File::create(a.join("module.toml"))
            .unwrap()
            .write_all(toml_a.as_bytes())
            .unwrap();

        // Module B
        let b = root.path().join("mod-b");
        std::fs::create_dir(&b).unwrap();
        let toml_b =
            SEARCH_PROTECTION_TOML.replace("id          = \"search-protection\"", "id = \"mod-b\"");
        std::fs::File::create(b.join("module.toml"))
            .unwrap()
            .write_all(toml_b.as_bytes())
            .unwrap();

        // Directory without module.toml — should be skipped
        std::fs::create_dir(root.path().join("not-a-module")).unwrap();

        let modules = scan_modules_dir(root.path());
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].id, "mod-a");
        assert_eq!(modules[1].id, "mod-b");
    }

    #[test]
    fn scan_modules_dir_returns_empty_for_missing_dir() {
        let modules = scan_modules_dir(Path::new("/nonexistent/modules-dir-xyz"));
        assert!(modules.is_empty());
    }

    #[test]
    fn sudoers_rule_preserves_commands_with_args() {
        let rule = generate_module_sudoers_rule("my-module", &["/usr/sbin/nginx -t".to_string()]);
        assert!(rule.contains("/usr/sbin/nginx -t"));
        assert!(!rule.contains("/usr/sbin/nginx -t *"));
    }
}
