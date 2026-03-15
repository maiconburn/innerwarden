pub mod builtin;

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::info;

// ---------------------------------------------------------------------------
// Skill types
// ---------------------------------------------------------------------------

/// Tier determines whether a skill is open-source or requires a premium license.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillTier {
    /// Free and open-source — community contributions welcome.
    Open,
    /// Premium feature — requires a license or future subscription.
    /// Current premium stubs log a friendly message and return success without acting.
    Premium,
}

/// Context passed to a skill when it is executed.
// Fields `incident` and `host` are public API for community skill implementations;
// built-in skills only require `target_ip` today.
#[allow(dead_code)]
pub struct SkillContext {
    pub incident: Incident,
    /// Primary IP target, if applicable.
    pub target_ip: Option<String>,
    /// Primary user target, if applicable.
    pub target_user: Option<String>,
    /// Optional action duration (seconds), used by temporary containment skills.
    pub duration_secs: Option<u64>,
    pub host: String,
    /// Shared data dir used by sensor/agent artifacts.
    pub data_dir: PathBuf,
    /// Runtime honeypot config (used only by honeypot skill).
    pub honeypot: HoneypotRuntimeConfig,
}

#[derive(Debug, Clone)]
pub struct HoneypotRuntimeConfig {
    /// `demo` | `listener`
    pub mode: String,
    /// Listener bind address when mode = `listener`
    pub bind_addr: String,
    /// SSH decoy listener port when mode = `listener`
    pub port: u16,
    /// HTTP decoy listener port when mode = `listener`
    pub http_port: u16,
    /// Listener lifetime in seconds when mode = `listener`
    pub duration_secs: u64,
    /// Enabled decoy services. Supported: `ssh`, `http`.
    pub services: Vec<String>,
    /// Accept only the target IP while listener session is active.
    pub strict_target_only: bool,
    /// Allow non-loopback bind addresses.
    pub allow_public_listener: bool,
    /// Hard cap of accepted connections per service listener.
    pub max_connections: usize,
    /// Max payload bytes captured per connection.
    pub max_payload_bytes: usize,
    /// Isolation profile (`strict_local` | `standard`).
    pub isolation_profile: String,
    /// Require non-privileged listener ports (>= 1024).
    pub require_high_ports: bool,
    /// Retain honeypot forensics artifacts for this many days.
    pub forensics_keep_days: usize,
    /// Hard cap for total honeypot forensics storage in MB.
    pub forensics_max_total_mb: usize,
    /// Max bytes rendered in transcript preview fields.
    pub transcript_preview_bytes: usize,
    /// Active session lock stale threshold in seconds.
    pub lock_stale_secs: u64,
    /// Run listeners in dedicated subprocess workers.
    pub sandbox_enabled: bool,
    /// Optional runner binary path.
    pub sandbox_runner_path: String,
    /// Clear environment for runner subprocesses.
    pub sandbox_clear_env: bool,
    /// Run bounded pcap handoff capture at session end.
    pub pcap_handoff_enabled: bool,
    /// Handoff capture timeout in seconds.
    pub pcap_handoff_timeout_secs: u64,
    /// Handoff capture max packets.
    pub pcap_handoff_max_packets: u64,
    /// Containment mode (`process` | `namespace`).
    pub containment_mode: String,
    /// If true, fail when requested containment mode is unavailable.
    pub containment_require_success: bool,
    /// Namespace wrapper runner (e.g., `unshare`) when containment mode is `namespace`.
    pub containment_namespace_runner: String,
    /// Arguments passed to namespace wrapper before the agent runner.
    pub containment_namespace_args: Vec<String>,
    /// Jail wrapper runner (e.g., `bwrap`) when containment mode is `jail`.
    pub containment_jail_runner: String,
    /// Arguments passed to jail wrapper before the agent runner.
    pub containment_jail_args: Vec<String>,
    /// Jail profile preset (`standard` | `strict`).
    pub containment_jail_profile: String,
    /// Allow fallback from `jail` to `namespace` when jail runner is unavailable.
    pub containment_allow_namespace_fallback: bool,
    /// Execute optional external handoff command after session completion.
    pub external_handoff_enabled: bool,
    /// External handoff command.
    pub external_handoff_command: String,
    /// External handoff arguments with placeholder support.
    pub external_handoff_args: Vec<String>,
    /// External handoff timeout in seconds.
    pub external_handoff_timeout_secs: u64,
    /// Mark session as error if external handoff fails.
    pub external_handoff_require_success: bool,
    /// Clear environment before launching external handoff.
    pub external_handoff_clear_env: bool,
    /// Command allowlist for trusted external handoff.
    pub external_handoff_allowed_commands: Vec<String>,
    /// Require command allowlist match.
    pub external_handoff_enforce_allowlist: bool,
    /// Sign handoff result (HMAC-SHA256) when enabled.
    pub external_handoff_signature_enabled: bool,
    /// Env var name containing signing key.
    pub external_handoff_signature_key_env: String,
    /// Validate receiver attestation output from handoff command.
    pub external_handoff_attestation_enabled: bool,
    /// Env var name containing attestation key.
    pub external_handoff_attestation_key_env: String,
    /// Prefix used in attestation output lines.
    pub external_handoff_attestation_prefix: String,
    /// Optional pinned receiver identifier for attestation.
    pub external_handoff_attestation_expected_receiver: String,
    /// Optional selective redirection.
    pub redirect_enabled: bool,
    /// Redirect backend identifier.
    pub redirect_backend: String,
    /// Interaction level: `banner` (static banner only) | `medium` (protocol emulation).
    pub interaction: String,
    /// Max SSH auth attempts before disconnecting client (medium interaction only).
    pub ssh_max_auth_attempts: usize,
    /// Max HTTP requests per connection (medium interaction only).
    pub http_max_requests: usize,
}

impl Default for HoneypotRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: "demo".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            port: 2222,
            http_port: 8080,
            duration_secs: 300,
            services: vec!["ssh".to_string()],
            strict_target_only: true,
            allow_public_listener: false,
            max_connections: 64,
            max_payload_bytes: 512,
            isolation_profile: "strict_local".to_string(),
            require_high_ports: true,
            forensics_keep_days: 7,
            forensics_max_total_mb: 128,
            transcript_preview_bytes: 96,
            lock_stale_secs: 1800,
            sandbox_enabled: false,
            sandbox_runner_path: String::new(),
            sandbox_clear_env: true,
            pcap_handoff_enabled: false,
            pcap_handoff_timeout_secs: 15,
            pcap_handoff_max_packets: 120,
            containment_mode: "process".to_string(),
            containment_require_success: false,
            containment_namespace_runner: "unshare".to_string(),
            containment_namespace_args: vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
            ],
            containment_jail_runner: "bwrap".to_string(),
            containment_jail_args: vec![],
            containment_jail_profile: "standard".to_string(),
            containment_allow_namespace_fallback: true,
            external_handoff_enabled: false,
            external_handoff_command: String::new(),
            external_handoff_args: vec![],
            external_handoff_timeout_secs: 20,
            external_handoff_require_success: false,
            external_handoff_clear_env: true,
            external_handoff_allowed_commands: vec![],
            external_handoff_enforce_allowlist: false,
            external_handoff_signature_enabled: false,
            external_handoff_signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            external_handoff_attestation_enabled: false,
            external_handoff_attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            external_handoff_attestation_prefix: "IW_ATTEST".to_string(),
            external_handoff_attestation_expected_receiver: String::new(),
            redirect_enabled: false,
            redirect_backend: "iptables".to_string(),
            interaction: "banner".to_string(),
            ssh_max_auth_attempts: 6,
            http_max_requests: 10,
        }
    }
}

/// Result of a skill execution.
pub struct SkillResult {
    pub success: bool,
    /// Human-readable description of what happened (or would have happened in dry-run).
    pub message: String,
}

// ---------------------------------------------------------------------------
// ResponseSkill trait — implement this to add a new skill
// ---------------------------------------------------------------------------

/// A response skill is an action Inner Warden can take when an incident is detected.
///
/// ## Adding a community skill
///
/// 1. Create a struct that implements `ResponseSkill`.
/// 2. Register it in `SkillRegistry::default_builtin()`.
/// 3. Open a PR at https://github.com/maiconburn/innerwarden
///
/// All built-in skills follow the same pattern as `BlockIpUfw`.
pub trait ResponseSkill: Send + Sync {
    /// Unique identifier used by the AI to select this skill.
    /// Use kebab-case, e.g. "block-ip-ufw".
    fn id(&self) -> &'static str;

    /// Human-readable name shown in logs and the narrative.
    fn name(&self) -> &'static str;

    /// One-sentence description sent to the AI so it understands what this skill does.
    fn description(&self) -> &'static str;

    /// Open = free; Premium = paid / coming soon.
    fn tier(&self) -> SkillTier;

    /// Incident kinds this skill is applicable to (e.g. ["ssh_bruteforce"]).
    /// An empty slice means "applicable to all".
    fn applicable_to(&self) -> &'static [&'static str];

    /// Execute the skill.
    ///
    /// - `dry_run = true`: log what would happen but don't run system commands.
    /// - Always fail-open: return `SkillResult { success: false, message }` on error
    ///   rather than propagating to avoid crashing the agent.
    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Info (sent to AI as context)
// ---------------------------------------------------------------------------

/// Serializable summary of a skill, sent to the AI so it knows what options exist.
#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tier: SkillTier,
    pub applicable_to: Vec<String>,
}

// ---------------------------------------------------------------------------
// Skill Registry
// ---------------------------------------------------------------------------

pub struct SkillRegistry {
    skills: Vec<Box<dyn ResponseSkill>>,
}

impl SkillRegistry {
    /// Build the registry with all built-in skills.
    pub fn default_builtin() -> Self {
        use builtin::*;
        Self {
            skills: vec![
                Box::new(BlockIpUfw),
                Box::new(BlockIpIptables),
                Box::new(BlockIpNftables),
                Box::new(BlockIpPf),
                Box::new(MonitorIp),
                Box::new(Honeypot),
                Box::new(SuspendUserSudo),
                Box::new(RateLimitNginx),
            ],
        }
    }

    /// Returns skill metadata for all registered skills (sent to AI as context).
    pub fn infos(&self) -> Vec<SkillInfo> {
        self.skills
            .iter()
            .map(|s| SkillInfo {
                id: s.id().to_string(),
                name: s.name().to_string(),
                description: s.description().to_string(),
                tier: s.tier(),
                applicable_to: s.applicable_to().iter().map(|&k| k.to_string()).collect(),
            })
            .collect()
    }

    /// Look up a skill by ID.
    pub fn get(&self, id: &str) -> Option<&dyn ResponseSkill> {
        self.skills
            .iter()
            .find(|s| s.id() == id)
            .map(|s| s.as_ref())
    }

    /// Convenience: find the best block skill for the given backend.
    /// Falls back to ufw if the backend is unknown.
    pub fn block_skill_for_backend(&self, backend: &str) -> Option<&dyn ResponseSkill> {
        let id = match backend {
            "iptables" => "block-ip-iptables",
            "nftables" => "block-ip-nftables",
            _ => "block-ip-ufw",
        };
        self.get(id)
    }
}

// ---------------------------------------------------------------------------
// Blocklist (in-memory; prevents duplicate blocks)
// ---------------------------------------------------------------------------

/// Tracks IPs already blocked this session to avoid redundant system calls.
#[derive(Default)]
pub struct Blocklist {
    blocked: HashSet<String>,
}

impl Blocklist {
    #[allow(dead_code)] // public API — used by algorithm gate and future skills
    pub fn contains(&self, ip: &str) -> bool {
        self.blocked.contains(ip)
    }

    pub fn insert(&mut self, ip: impl Into<String>) {
        self.blocked.insert(ip.into());
    }

    pub fn as_vec(&self) -> Vec<String> {
        self.blocked.iter().cloned().collect()
    }

    /// Attempt to pre-populate from `ufw status` output.
    /// Silently skips if ufw is unavailable or the user lacks permissions.
    pub async fn load_from_ufw() -> Self {
        let mut list = Self::default();
        let Ok(out) = tokio::process::Command::new("sudo")
            .args(["ufw", "status"])
            .output()
            .await
        else {
            return list;
        };
        if !out.status.success() {
            return list;
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // Lines look like: "DENY IN   203.0.113.10"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "IN" {
                if let Ok(_addr) = parts[2].parse::<std::net::IpAddr>() {
                    list.blocked.insert(parts[2].to_string());
                }
            }
        }
        info!(
            count = list.blocked.len(),
            "blocklist loaded from ufw status"
        );
        list
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_all_builtin_skills() {
        let reg = SkillRegistry::default_builtin();
        assert!(reg.get("block-ip-ufw").is_some());
        assert!(reg.get("block-ip-iptables").is_some());
        assert!(reg.get("block-ip-nftables").is_some());
        assert!(reg.get("block-ip-pf").is_some());
        assert!(reg.get("monitor-ip").is_some());
        assert!(reg.get("honeypot").is_some());
        assert!(reg.get("suspend-user-sudo").is_some());
        assert!(reg.get("rate-limit-nginx").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn registry_infos_are_serializable() {
        let reg = SkillRegistry::default_builtin();
        let infos = reg.infos();
        assert_eq!(infos.len(), 8);
        let json = serde_json::to_string(&infos).unwrap();
        assert!(json.contains("block-ip-ufw"));
    }

    #[test]
    fn block_skill_for_backend_fallback() {
        let reg = SkillRegistry::default_builtin();
        assert_eq!(
            reg.block_skill_for_backend("ufw").unwrap().id(),
            "block-ip-ufw"
        );
        assert_eq!(
            reg.block_skill_for_backend("iptables").unwrap().id(),
            "block-ip-iptables"
        );
        assert_eq!(
            reg.block_skill_for_backend("unknown").unwrap().id(),
            "block-ip-ufw"
        );
    }

    #[tokio::test]
    async fn block_ip_ufw_dry_run() {
        use super::builtin::BlockIpUfw;
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: "id".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
        };
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }
}
