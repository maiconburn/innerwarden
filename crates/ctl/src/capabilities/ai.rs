use anyhow::Result;

use crate::capability::{
    ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight, PreflightError,
};
use crate::config_editor;
use crate::systemd;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_PROVIDER: &str = "openai";
const DEFAULT_MODEL_OPENAI: &str = "gpt-4o-mini";
const DEFAULT_MODEL_ANTHROPIC: &str = "claude-haiku-4-5-20251001";
const DEFAULT_MODEL_OLLAMA: &str = "llama3.2";
const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";
const VALID_PROVIDERS: &[&str] = &[
    "openai",
    "anthropic",
    "ollama",
    "groq",
    "deepseek",
    "together",
    "minimax",
    "mistral",
    "xai",
    "fireworks",
    "openrouter",
    "gemini",
];

// ---------------------------------------------------------------------------
// Preflight: API key available
// ---------------------------------------------------------------------------

struct ApiKeyAvailable {
    provider: String,
}

impl Preflight for ApiKeyAvailable {
    fn name(&self) -> &str {
        "API key or endpoint reachable"
    }

    fn check(&self) -> Result<(), PreflightError> {
        match self.provider.as_str() {
            "openai" => {
                if std::env::var("OPENAI_API_KEY")
                    .unwrap_or_default()
                    .is_empty()
                {
                    return Err(PreflightError::new("OPENAI_API_KEY not set").with_hint(
                        "Export OPENAI_API_KEY or add it to /etc/innerwarden/agent.env",
                    ));
                }
                Ok(())
            }
            "anthropic" => {
                if std::env::var("ANTHROPIC_API_KEY")
                    .unwrap_or_default()
                    .is_empty()
                {
                    return Err(PreflightError::new("ANTHROPIC_API_KEY not set").with_hint(
                        "Export ANTHROPIC_API_KEY or add it to /etc/innerwarden/agent.env",
                    ));
                }
                Ok(())
            }
            "ollama" => {
                // Ollama doesn't need an API key — just needs to be reachable.
                // We don't check connectivity here (preflight should be fast/offline).
                Ok(())
            }
            _ => Err(PreflightError::new(format!(
                "unknown provider '{}' — use one of: {}",
                self.provider,
                VALID_PROVIDERS.join(", ")
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

pub struct AiCapability;

impl AiCapability {
    fn provider<'a>(&self, opts: &'a ActivationOptions) -> &'a str {
        opts.params
            .get("provider")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_PROVIDER)
    }

    fn model(&self, opts: &ActivationOptions) -> String {
        if let Some(m) = opts.params.get("model") {
            return m.clone();
        }
        match self.provider(opts) {
            "anthropic" => DEFAULT_MODEL_ANTHROPIC.to_string(),
            "ollama" => DEFAULT_MODEL_OLLAMA.to_string(),
            _ => DEFAULT_MODEL_OPENAI.to_string(),
        }
    }

    fn base_url(&self, opts: &ActivationOptions) -> Option<String> {
        if let Some(u) = opts.params.get("base_url") {
            return Some(u.clone());
        }
        if self.provider(opts) == "ollama" {
            return Some(DEFAULT_OLLAMA_BASE_URL.to_string());
        }
        None
    }
}

impl Capability for AiCapability {
    fn id(&self) -> &'static str {
        "ai"
    }

    fn name(&self) -> &'static str {
        "AI Analysis"
    }

    fn description(&self) -> &'static str {
        "Enable AI-powered incident analysis and automated response decisions"
    }

    fn preflights(&self, opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
        let provider = self.provider(opts).to_string();
        vec![Box::new(ApiKeyAvailable { provider })]
    }

    fn planned_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect> {
        let agent = opts.agent_config.display().to_string();
        let provider = self.provider(opts);
        let model = self.model(opts);
        let mut effects = vec![
            CapabilityEffect::new(format!("Patch {agent}: [ai] enabled = true")),
            CapabilityEffect::new(format!("Patch {agent}: [ai] provider = \"{provider}\"")),
            CapabilityEffect::new(format!("Patch {agent}: [ai] model = \"{model}\"")),
        ];
        if let Some(url) = self.base_url(opts) {
            effects.push(CapabilityEffect::new(format!(
                "Patch {agent}: [ai] base_url = \"{url}\""
            )));
        }
        effects.push(CapabilityEffect::new("Restart innerwarden-agent"));
        effects
    }

    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let provider = self.provider(opts);

        if !VALID_PROVIDERS.contains(&provider) {
            anyhow::bail!(
                "unsupported provider '{}' — use one of: {}",
                provider,
                VALID_PROVIDERS.join(", ")
            );
        }

        let model = self.model(opts);
        let mut effects = Vec::new();

        // 1. [ai] enabled = true
        config_editor::write_bool(&opts.agent_config, "ai", "enabled", true)?;
        effects.push(CapabilityEffect::new("[ai] enabled = true"));

        // 2. [ai] provider
        config_editor::write_str(&opts.agent_config, "ai", "provider", provider)?;
        effects.push(CapabilityEffect::new(format!(
            "[ai] provider = \"{provider}\""
        )));

        // 3. [ai] model
        config_editor::write_str(&opts.agent_config, "ai", "model", &model)?;
        effects.push(CapabilityEffect::new(format!("[ai] model = \"{model}\"")));

        // 4. [ai] base_url (only for ollama or explicit param)
        if let Some(url) = self.base_url(opts) {
            config_editor::write_str(&opts.agent_config, "ai", "base_url", &url)?;
            effects.push(CapabilityEffect::new(format!("[ai] base_url = \"{url}\"")));
        }

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
        let current = config_editor::read_str(&opts.agent_config, "ai", "provider");
        let provider_note = if current.is_empty() {
            String::new()
        } else {
            format!(" (current provider: {current})")
        };
        vec![
            CapabilityEffect::new(format!(
                "Patch {agent}: [ai] enabled = false{provider_note}"
            )),
            CapabilityEffect::new("Restart innerwarden-agent"),
        ]
    }

    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
        let mut effects = Vec::new();

        // 1. [ai] enabled = false
        config_editor::write_bool(&opts.agent_config, "ai", "enabled", false)?;
        effects.push(CapabilityEffect::new("[ai] enabled = false"));

        // 2. Restart agent
        systemd::restart_service("innerwarden-agent", opts.dry_run)?;
        effects.push(CapabilityEffect::new("Restarted innerwarden-agent"));

        Ok(ActivationReport {
            effects_applied: effects,
            warnings: vec![],
        })
    }

    fn is_enabled(&self, opts: &ActivationOptions) -> bool {
        config_editor::read_bool(&opts.agent_config, "ai", "enabled")
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

    fn make_opts(
        sensor: &NamedTempFile,
        agent: &NamedTempFile,
        params: HashMap<String, String>,
    ) -> ActivationOptions {
        ActivationOptions {
            sensor_config: sensor.path().to_path_buf(),
            agent_config: agent.path().to_path_buf(),
            dry_run: true,
            params,
            yes: true,
        }
    }

    #[test]
    fn not_enabled_when_ai_disabled() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = false\n").unwrap();
        let opts = make_opts(&sensor, &agent, HashMap::new());
        assert!(!AiCapability.is_enabled(&opts));
    }

    #[test]
    fn is_enabled_when_ai_on() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = true\n").unwrap();
        let opts = make_opts(&sensor, &agent, HashMap::new());
        assert!(AiCapability.is_enabled(&opts));
    }

    #[test]
    fn activate_patches_provider_and_model() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = false\n").unwrap();

        let mut params = HashMap::new();
        params.insert("provider".to_string(), "ollama".to_string());
        params.insert("model".to_string(), "mistral".to_string());
        let opts = make_opts(&sensor, &agent, params);

        AiCapability.activate(&opts).unwrap();

        assert!(config_editor::read_bool(agent.path(), "ai", "enabled"));
        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "provider"),
            "ollama"
        );
        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "model"),
            "mistral"
        );
        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "base_url"),
            "http://localhost:11434"
        );
    }

    #[test]
    fn activate_openai_no_base_url() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = false\n").unwrap();

        let mut params = HashMap::new();
        params.insert("provider".to_string(), "openai".to_string());
        let opts = make_opts(&sensor, &agent, params);

        // Set env var so preflight passes
        std::env::set_var("OPENAI_API_KEY", "sk-test");
        AiCapability.activate(&opts).unwrap();
        std::env::remove_var("OPENAI_API_KEY");

        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "provider"),
            "openai"
        );
        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "model"),
            "gpt-4o-mini"
        );
        // No base_url for openai
        assert_eq!(config_editor::read_str(agent.path(), "ai", "base_url"), "");
    }

    #[test]
    fn deactivate_sets_enabled_false() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = true\nprovider = \"ollama\"\n").unwrap();
        let opts = make_opts(&sensor, &agent, HashMap::new());

        AiCapability.deactivate(&opts).unwrap();

        assert!(!config_editor::read_bool(agent.path(), "ai", "enabled"));
        // Provider preserved (only enabled is toggled)
        assert_eq!(
            config_editor::read_str(agent.path(), "ai", "provider"),
            "ollama"
        );
    }

    #[test]
    fn default_model_per_provider() {
        let cap = AiCapability;
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();

        let mut p = HashMap::new();
        p.insert("provider".to_string(), "anthropic".to_string());
        let opts = make_opts(&sensor, &agent, p);
        assert_eq!(cap.model(&opts), "claude-haiku-4-5-20251001");

        let mut p = HashMap::new();
        p.insert("provider".to_string(), "ollama".to_string());
        let opts = make_opts(&sensor, &agent, p);
        assert_eq!(cap.model(&opts), "llama3.2");

        let opts = make_opts(&sensor, &agent, HashMap::new());
        assert_eq!(cap.model(&opts), "gpt-4o-mini");
    }

    #[test]
    fn planned_effects_with_ollama() {
        let sensor = NamedTempFile::new().unwrap();
        let agent = NamedTempFile::new().unwrap();
        let mut params = HashMap::new();
        params.insert("provider".to_string(), "ollama".to_string());
        let opts = make_opts(&sensor, &agent, params);
        let effects = AiCapability.planned_effects(&opts);
        // enabled + provider + model + base_url + restart
        assert_eq!(effects.len(), 5);
    }

    #[test]
    fn invalid_provider_fails() {
        let sensor = NamedTempFile::new().unwrap();
        let mut agent = NamedTempFile::new().unwrap();
        writeln!(agent, "[ai]\nenabled = false\n").unwrap();
        let mut params = HashMap::new();
        params.insert(
            "provider".to_string(),
            "nonexistent-provider-xyz".to_string(),
        );
        let opts = make_opts(&sensor, &agent, params);
        assert!(AiCapability.activate(&opts).is_err());
    }
}
