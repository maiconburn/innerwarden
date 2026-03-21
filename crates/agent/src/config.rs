use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_core::event::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub narrative: NarrativeConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub correlation: CorrelationConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub responder: ResponderConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub data: DataRetentionConfig,
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    #[serde(default)]
    pub abuseipdb: AbuseIpDbConfig,
    #[serde(default)]
    pub fail2ban: Fail2BanConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub slack: SlackConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub web_push: WebPushConfig,
    /// Mesh collaborative defense network
    #[serde(default)]
    pub mesh: MeshNetworkConfig,
}

/// Mesh network config — mirrors innerwarden_mesh::MeshConfig
/// but decoupled so the agent compiles without the mesh feature.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MeshNetworkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mesh_bind")]
    pub bind: String,
    #[serde(default)]
    pub peers: Vec<MeshPeerEntry>,
    #[serde(default = "default_mesh_poll_secs")]
    pub poll_secs: u64,
    #[serde(default = "default_true_val")]
    pub auto_broadcast: bool,
    #[serde(default = "default_mesh_max_signals")]
    pub max_signals_per_hour: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MeshPeerEntry {
    pub endpoint: String,
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl Default for MeshNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_mesh_bind(),
            peers: vec![],
            poll_secs: default_mesh_poll_secs(),
            auto_broadcast: true,
            max_signals_per_hour: default_mesh_max_signals(),
        }
    }
}

fn default_mesh_bind() -> String {
    "0.0.0.0:8790".to_string()
}
fn default_mesh_poll_secs() -> u64 {
    30
}
fn default_true_val() -> bool {
    true
}
fn default_mesh_max_signals() -> usize {
    50
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NarrativeConfig {
    /// Generate daily Markdown summaries (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of daily summaries to keep before removing older ones
    #[serde(default = "default_keep_days")]
    pub keep_days: usize,
}

impl Default for NarrativeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_days: default_keep_days(),
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WebhookConfig {
    /// Enable webhook notifications
    #[serde(default)]
    pub enabled: bool,

    /// HTTP endpoint to POST incident payloads to
    #[serde(default)]
    pub url: String,

    /// Minimum severity to notify (default: "medium")
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Request timeout in seconds (default: 10)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Payload format: "default", "pagerduty", "opsgenie" (default: "default")
    /// PagerDuty: set url to https://events.pagerduty.com/v2/enqueue?routing_key=YOUR_KEY
    /// Opsgenie: set url to https://api.opsgenie.com/v2/alerts with GenieKey header in url
    #[serde(default = "default_webhook_format")]
    pub format: String,
}

fn default_webhook_format() -> String {
    "default".to_string()
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: default_min_severity(),
            timeout_secs: default_timeout_secs(),
            format: default_webhook_format(),
        }
    }
}

impl WebhookConfig {
    /// Parse min_severity string into a Severity, defaulting to Medium on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised min_severity — defaulting to 'medium'"
                );
                Severity::Medium
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AI provider
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AiConfig {
    /// Enable AI-powered real-time incident analysis
    #[serde(default)]
    pub enabled: bool,

    /// AI provider to use: "openai" | "anthropic" (coming soon) | "ollama" (coming soon)
    #[serde(default = "default_ai_provider")]
    pub provider: String,

    /// API key for the provider. Prefer env var OPENAI_API_KEY / ANTHROPIC_API_KEY.
    #[serde(default)]
    pub api_key: String,

    /// Model identifier (provider-specific, e.g. "gpt-4o-mini")
    #[serde(default = "default_ai_model")]
    pub model: String,

    /// Number of recent events sent as context to the AI
    #[serde(default = "default_context_events")]
    pub context_events: usize,

    /// Minimum AI confidence (0.0–1.0) required to auto-execute a decision
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Poll interval for the fast incident-check loop (seconds)
    #[serde(default = "default_incident_poll_secs")]
    pub incident_poll_secs: u64,

    /// Base URL for the AI provider endpoint.
    /// - openai: defaults to https://api.openai.com (leave empty)
    /// - anthropic: defaults to https://api.anthropic.com (leave empty)
    /// - ollama: defaults to http://localhost:11434 (override for remote Ollama)
    ///   Can also be set via OLLAMA_BASE_URL env var for Ollama.
    #[serde(default)]
    pub base_url: String,

    /// Maximum number of AI calls per incident tick (default: 5).
    /// When more incidents arrive in a single tick than this limit, the excess
    /// are deferred to the next tick. Prevents API bill spikes during botnet attacks.
    /// Set to 0 to disable the limit (not recommended).
    #[serde(default = "default_max_ai_calls_per_tick")]
    pub max_ai_calls_per_tick: usize,

    /// Circuit breaker: if the number of new incidents in a single tick exceeds
    /// this threshold, skip AI analysis entirely for that tick and rely on
    /// deterministic blocklist/gate decisions only. 0 = disabled (default).
    /// Recommended value for DDoS scenarios: 20.
    #[serde(default)]
    pub circuit_breaker_threshold: usize,

    /// How long (seconds) to keep the circuit breaker open after it trips (default: 60).
    #[serde(default = "default_circuit_breaker_cooldown_secs")]
    pub circuit_breaker_cooldown_secs: u64,

    /// IPs that should NEVER be blocked, regardless of AI decision.
    /// Protects internal infrastructure from false positives.
    #[serde(default = "default_protected_ips")]
    pub protected_ips: Vec<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_ai_provider(),
            api_key: String::new(),
            model: default_ai_model(),
            context_events: default_context_events(),
            confidence_threshold: default_confidence_threshold(),
            incident_poll_secs: default_incident_poll_secs(),
            base_url: String::new(),
            max_ai_calls_per_tick: default_max_ai_calls_per_tick(),
            circuit_breaker_threshold: 0,
            circuit_breaker_cooldown_secs: default_circuit_breaker_cooldown_secs(),
            protected_ips: default_protected_ips(),
        }
    }
}

impl AiConfig {
    /// Resolve the API key: config field takes precedence, then env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        // Try provider-specific env vars
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "ollama" => "OLLAMA_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Temporal correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CorrelationConfig {
    /// Enable lightweight temporal incident correlation (window + entity pivots)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Correlation window in seconds
    #[serde(default = "default_correlation_window_secs")]
    pub window_seconds: u64,

    /// Max number of related incidents attached to AI context
    #[serde(default = "default_max_related_incidents")]
    pub max_related_incidents: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: default_correlation_window_secs(),
            max_related_incidents: default_max_related_incidents(),
        }
    }
}

// ---------------------------------------------------------------------------
// Operational telemetry
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TelemetryConfig {
    /// Enable local operational telemetry JSONL output
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// Honeypot
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HoneypotConfig {
    /// Honeypot mode:
    /// - `demo`: synthetic marker only (safe default)
    /// - `listener`: starts bounded real decoys (ssh/http) with optional redirect
    /// - `always_on`: permanent SSH listener from agent startup with smart per-connection
    ///   filter (blocklist check → AbuseIPDB gate → accept into LLM shell). Runs
    ///   indefinitely until SIGTERM; each session triggers post-session AI verdict,
    ///   IOC extraction, auto-block (when responder.enabled), and Telegram T.5 report.
    #[serde(default = "default_honeypot_mode")]
    pub mode: String,

    /// Bind address used in listener mode
    #[serde(default = "default_honeypot_bind_addr")]
    pub bind_addr: String,

    /// Listener port used in listener mode
    #[serde(default = "default_honeypot_port")]
    pub port: u16,

    /// Listener lifetime in seconds used in listener mode
    #[serde(default = "default_honeypot_duration_secs")]
    pub duration_secs: u64,

    /// Enabled decoy services in listener mode.
    /// Supported: `ssh`, `http`.
    #[serde(default = "default_honeypot_services")]
    pub services: Vec<String>,

    /// HTTP decoy port used when `http` service is enabled.
    #[serde(default = "default_honeypot_http_port")]
    pub http_port: u16,

    /// Accept only connections from the action target IP.
    #[serde(default = "default_true")]
    pub strict_target_only: bool,

    /// Allow binding listener on non-loopback addresses.
    /// Default false for safer isolation.
    #[serde(default)]
    pub allow_public_listener: bool,

    /// Hard cap of accepted honeypot connections per session.
    #[serde(default = "default_honeypot_max_connections")]
    pub max_connections: usize,

    /// Max inbound payload bytes captured per connection.
    #[serde(default = "default_honeypot_max_payload_bytes")]
    pub max_payload_bytes: usize,

    /// Isolation profile for listener mode:
    /// - `strict_local` (default): hard guardrails for safer operation
    /// - `standard`: keeps only baseline guards
    #[serde(default = "default_honeypot_isolation_profile")]
    pub isolation_profile: String,

    /// Require non-privileged listener ports (>= 1024).
    #[serde(default = "default_true")]
    pub require_high_ports: bool,

    /// Retain honeypot forensics artifacts for this many days.
    #[serde(default = "default_honeypot_forensics_keep_days")]
    pub forensics_keep_days: usize,

    /// Hard cap for total honeypot forensics storage in MB.
    #[serde(default = "default_honeypot_forensics_max_total_mb")]
    pub forensics_max_total_mb: usize,

    /// Max bytes to render as readable transcript preview in evidence lines.
    #[serde(default = "default_honeypot_transcript_preview_bytes")]
    pub transcript_preview_bytes: usize,

    /// Consider active session lock stale after this many seconds.
    #[serde(default = "default_honeypot_lock_stale_secs")]
    pub lock_stale_secs: u64,

    /// Interaction level for decoy listeners:
    /// - `banner` (default): send static banner, read one payload, close
    /// - `medium`: full protocol emulation (SSH auth capture, HTTP form capture)
    #[serde(default = "default_honeypot_interaction")]
    pub interaction: String,

    /// Max SSH auth attempts before disconnecting client (medium interaction only).
    #[serde(default = "default_honeypot_ssh_max_auth_attempts")]
    pub ssh_max_auth_attempts: usize,

    /// Max HTTP requests handled per connection (medium interaction only).
    #[serde(default = "default_honeypot_http_max_requests")]
    pub http_max_requests: usize,

    #[serde(default)]
    pub sandbox: HoneypotSandboxConfig,

    #[serde(default)]
    pub pcap_handoff: HoneypotPcapHandoffConfig,

    #[serde(default)]
    pub containment: HoneypotContainmentConfig,

    #[serde(default)]
    pub external_handoff: HoneypotExternalHandoffConfig,

    #[serde(default)]
    pub redirect: HoneypotRedirectConfig,
}

#[derive(Debug, Deserialize)]
pub struct HoneypotSandboxConfig {
    /// Run decoy listeners in dedicated subprocess workers.
    #[serde(default)]
    pub enabled: bool,

    /// Optional absolute path to runner binary.
    /// Empty means current innerwarden-agent executable.
    #[serde(default)]
    pub runner_path: String,

    /// Clear environment for sandbox workers.
    #[serde(default = "default_true")]
    pub clear_env: bool,
}

impl Default for HoneypotSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runner_path: String::new(),
            clear_env: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotPcapHandoffConfig {
    /// Run bounded pcap capture at session end.
    #[serde(default)]
    pub enabled: bool,

    /// Capture timeout in seconds.
    #[serde(default = "default_honeypot_pcap_timeout_secs")]
    pub timeout_secs: u64,

    /// Max captured packets.
    #[serde(default = "default_honeypot_pcap_max_packets")]
    pub max_packets: u64,
}

impl Default for HoneypotPcapHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_honeypot_pcap_timeout_secs(),
            max_packets: default_honeypot_pcap_max_packets(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotContainmentConfig {
    /// Containment mode:
    /// - `process`: standard subprocess runner (default)
    /// - `namespace`: try OS namespace wrapper (e.g., `unshare`)
    /// - `jail`: try dedicated jail wrapper (e.g., `bwrap`)
    #[serde(default = "default_honeypot_containment_mode")]
    pub mode: String,

    /// Fail execution if requested containment mode cannot be used.
    #[serde(default)]
    pub require_success: bool,

    /// Wrapper binary used in `namespace` mode.
    #[serde(default = "default_honeypot_namespace_runner")]
    pub namespace_runner: String,

    /// Arguments passed to namespace wrapper before the runner binary.
    #[serde(default = "default_honeypot_namespace_args")]
    pub namespace_args: Vec<String>,

    /// Wrapper binary used in `jail` mode.
    #[serde(default = "default_honeypot_jail_runner")]
    pub jail_runner: String,

    /// Arguments passed to jail wrapper before the runner binary.
    #[serde(default)]
    pub jail_args: Vec<String>,

    /// Jail policy preset:
    /// - `standard`: keep configured `jail_args` as-is
    /// - `strict`: append a hardened baseline profile for bwrap-style runners
    #[serde(default = "default_honeypot_jail_profile")]
    pub jail_profile: String,

    /// If true, `jail` mode can gracefully fall back to `namespace` mode.
    #[serde(default = "default_true")]
    pub allow_namespace_fallback: bool,
}

impl Default for HoneypotContainmentConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_containment_mode(),
            require_success: false,
            namespace_runner: default_honeypot_namespace_runner(),
            namespace_args: default_honeypot_namespace_args(),
            jail_runner: default_honeypot_jail_runner(),
            jail_args: Vec::new(),
            jail_profile: default_honeypot_jail_profile(),
            allow_namespace_fallback: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotExternalHandoffConfig {
    /// Execute optional external handoff command after session completion.
    #[serde(default)]
    pub enabled: bool,

    /// External command path/binary to execute.
    #[serde(default)]
    pub command: String,

    /// Command arguments. Supports placeholders:
    /// `{session_id}`, `{target_ip}`, `{metadata_path}`, `{evidence_path}`, `{pcap_path}`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Timeout for external handoff command.
    #[serde(default = "default_honeypot_external_handoff_timeout_secs")]
    pub timeout_secs: u64,

    /// Mark session as error if handoff command fails.
    #[serde(default)]
    pub require_success: bool,

    /// Clear environment variables before launching handoff command.
    #[serde(default = "default_true")]
    pub clear_env: bool,

    /// Optional command allowlist for trusted handoff integrations.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Require external command to be present in `allowed_commands`.
    #[serde(default)]
    pub enforce_allowlist: bool,

    /// Enable signed handoff result sidecar (HMAC-SHA256).
    #[serde(default)]
    pub signature_enabled: bool,

    /// Environment variable name containing handoff signing key.
    #[serde(default = "default_honeypot_external_handoff_signature_key_env")]
    pub signature_key_env: String,

    /// Enable receiver attestation checks on external handoff output.
    #[serde(default)]
    pub attestation_enabled: bool,

    /// Environment variable name containing the shared attestation key.
    #[serde(default = "default_honeypot_external_handoff_attestation_key_env")]
    pub attestation_key_env: String,

    /// Prefix used by receiver attestation lines on stdout/stderr.
    #[serde(default = "default_honeypot_external_handoff_attestation_prefix")]
    pub attestation_prefix: String,

    /// Optional pinned receiver identifier required by attestation.
    #[serde(default)]
    pub attestation_expected_receiver: String,
}

impl Default for HoneypotExternalHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: String::new(),
            args: Vec::new(),
            timeout_secs: default_honeypot_external_handoff_timeout_secs(),
            require_success: false,
            clear_env: true,
            allowed_commands: Vec::new(),
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: default_honeypot_external_handoff_signature_key_env(),
            attestation_enabled: false,
            attestation_key_env: default_honeypot_external_handoff_attestation_key_env(),
            attestation_prefix: default_honeypot_external_handoff_attestation_prefix(),
            attestation_expected_receiver: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotRedirectConfig {
    /// Enable selective redirection rules for target IP.
    #[serde(default)]
    pub enabled: bool,

    /// Redirect backend (`iptables` for now).
    #[serde(default = "default_honeypot_redirect_backend")]
    pub backend: String,
}

impl Default for HoneypotRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_honeypot_redirect_backend(),
        }
    }
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_mode(),
            bind_addr: default_honeypot_bind_addr(),
            port: default_honeypot_port(),
            duration_secs: default_honeypot_duration_secs(),
            services: default_honeypot_services(),
            http_port: default_honeypot_http_port(),
            strict_target_only: default_true(),
            allow_public_listener: false,
            max_connections: default_honeypot_max_connections(),
            max_payload_bytes: default_honeypot_max_payload_bytes(),
            isolation_profile: default_honeypot_isolation_profile(),
            require_high_ports: default_true(),
            forensics_keep_days: default_honeypot_forensics_keep_days(),
            forensics_max_total_mb: default_honeypot_forensics_max_total_mb(),
            transcript_preview_bytes: default_honeypot_transcript_preview_bytes(),
            lock_stale_secs: default_honeypot_lock_stale_secs(),
            interaction: default_honeypot_interaction(),
            ssh_max_auth_attempts: default_honeypot_ssh_max_auth_attempts(),
            http_max_requests: default_honeypot_http_max_requests(),
            sandbox: HoneypotSandboxConfig::default(),
            pcap_handoff: HoneypotPcapHandoffConfig::default(),
            containment: HoneypotContainmentConfig::default(),
            external_handoff: HoneypotExternalHandoffConfig::default(),
            redirect: HoneypotRedirectConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ResponderConfig {
    /// Enable skill execution on AI decisions
    #[serde(default)]
    pub enabled: bool,

    /// Dry-run mode: log decisions but don't execute any system commands.
    /// Start with true for safety; set false when ready to auto-respond.
    #[serde(default = "default_true")]
    pub dry_run: bool,

    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables"
    #[serde(default = "default_block_backend")]
    pub block_backend: String,

    /// Whitelist of skill IDs the agent is allowed to execute automatically.
    /// Example: ["block-ip-ufw", "monitor-ip"]
    #[serde(default = "default_allowed_skills")]
    pub allowed_skills: Vec<String>,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: default_block_backend(),
            allowed_skills: default_allowed_skills(),
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

/// Configuration for the Telegram conversational bot interface.
#[derive(Debug, Deserialize, Clone)]
pub struct TelegramBotConfig {
    /// Enable the conversational bot interface (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Personality prompt prepended to all bot AI interactions.
    #[serde(default = "default_bot_personality")]
    pub personality: String,
}

fn default_bot_personality() -> String {
    "You are InnerWarden, a security agent defending a server. \
     Be proportional: low-risk events get a calm one-liner, high-risk gets detailed analysis. \
     Most SSH brute-force from random IPs is bot noise — say so, don't dramatize. \
     Only escalate tone for coordinated attacks, successful logins, or privilege escalation. \
     Be concise. No markdown headers. Short sentences. \
     When something is noise, say 'bot noise, handled' and move on. \
     When it's serious, explain the TTPs and give actionable steps. \
     Never exaggerate severity — the operator trusts your judgment.\n\n\
     IMPORTANT SECURITY CONSTRAINT: You are an AI advisor — you can see, analyze, and \
     explain what's happening on the server, but you CANNOT execute commands, modify files, \
     change configurations, or take any direct action on the system. You are completely \
     isolated from the server's execution environment by design. When the operator asks \
     you to do something (block an IP, restart a service, change a config), explain that \
     you cannot do it directly and give them the exact command to run. For example: \
     'I can't run that — use: innerwarden block 1.2.3.4 --reason \"manual block\"'. \
     This isolation is a security feature, not a limitation."
        .to_string()
}

impl Default for TelegramBotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            personality: default_bot_personality(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TelegramConfig {
    /// Enable Telegram notifications (T.1) and approval bot (T.2)
    #[serde(default)]
    pub enabled: bool,

    /// Telegram bot token. Prefer env var TELEGRAM_BOT_TOKEN.
    #[serde(default)]
    pub bot_token: String,

    /// Telegram chat ID to send messages to. Prefer env var TELEGRAM_CHAT_ID.
    #[serde(default)]
    pub chat_id: String,

    /// Minimum severity to send T.1 notifications (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_telegram_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in notification messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,

    /// TTL in seconds for pending T.2 operator approval requests (default: 600 = 10 min).
    /// Unanswered requests are discarded as "ignore" when they expire.
    #[serde(default = "default_telegram_approval_ttl_secs")]
    pub approval_ttl_secs: u64,

    /// Send the daily Markdown summary via Telegram at this local hour (0–23).
    /// Set e.g. `daily_summary_hour = 8` for an 8:00 AM digest.
    /// Omit or comment out to disable.
    #[serde(default)]
    pub daily_summary_hour: Option<u8>,

    /// Conversational bot configuration.
    #[serde(default)]
    pub bot: TelegramBotConfig,
}

impl TelegramConfig {
    /// Resolve bot_token: config field takes precedence, then env var TELEGRAM_BOT_TOKEN.
    pub fn resolved_bot_token(&self) -> String {
        if !self.bot_token.is_empty() {
            return self.bot_token.clone();
        }
        std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default()
    }

    /// Resolve chat_id: config field takes precedence, then env var TELEGRAM_CHAT_ID.
    pub fn resolved_chat_id(&self) -> String {
        if !self.chat_id.is_empty() {
            return self.chat_id.clone();
        }
        std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised telegram min_severity — defaulting to 'high'"
                );
                Severity::High
            }
        }
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: default_telegram_min_severity(),
            dashboard_url: String::new(),
            approval_ttl_secs: default_telegram_approval_ttl_secs(),
            daily_summary_hour: None,
            bot: TelegramBotConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------

/// Configuration for Slack Incoming Webhook notifications.
#[derive(Debug, Deserialize)]
pub struct SlackConfig {
    /// Enable Slack notifications (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Slack Incoming Webhook URL.
    /// Example: "https://hooks.slack.com/services/T.../B.../..."
    /// Prefer env var SLACK_WEBHOOK_URL.
    #[serde(default)]
    pub webhook_url: String,

    /// Minimum severity to notify (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_slack_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,
}

impl SlackConfig {
    /// Resolve webhook_url: config field takes precedence, then env var SLACK_WEBHOOK_URL.
    pub fn resolved_webhook_url(&self) -> String {
        if !self.webhook_url.is_empty() {
            return self.webhook_url.clone();
        }
        std::env::var("SLACK_WEBHOOK_URL").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised slack min_severity — defaulting to 'high'"
                );
                Severity::High
            }
        }
    }
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: default_slack_min_severity(),
            dashboard_url: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    /// Enable Cloudflare IP block push (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Cloudflare Zone ID (from dashboard)
    #[serde(default)]
    pub zone_id: String,

    /// Cloudflare API token (or CLOUDFLARE_API_TOKEN env var)
    #[serde(default)]
    pub api_token: String,

    /// Push block decisions to Cloudflare edge (default: true when enabled)
    #[serde(default = "default_true")]
    pub auto_push_blocks: bool,

    /// Prefix for Cloudflare rule notes (default: "innerwarden")
    #[serde(default = "default_cloudflare_notes_prefix")]
    pub block_notes_prefix: String,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zone_id: String::new(),
            api_token: String::new(),
            auto_push_blocks: default_true(),
            block_notes_prefix: default_cloudflare_notes_prefix(),
        }
    }
}

fn default_cloudflare_notes_prefix() -> String {
    "innerwarden".to_string()
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Entities in the allowlist are still logged and notified but skip the AI
/// gate — no automated response skill is ever executed for them.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AllowlistConfig {
    /// IP addresses or CIDR ranges that are never auto-responded to.
    /// Examples: ["10.0.0.1", "192.168.0.0/24"]
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Usernames that are never auto-responded to.
    /// Examples: ["deploy", "backup"]
    #[serde(default)]
    pub trusted_users: Vec<String>,
}

// ---------------------------------------------------------------------------
// Web Push
// ---------------------------------------------------------------------------

/// Browser Web Push notification configuration (RFC 8291 / VAPID RFC 8292).
///
/// Generate keys with: `innerwarden notify web-push setup`
#[derive(Debug, Deserialize, Clone)]
pub struct WebPushConfig {
    /// Enable browser push notifications for High/Critical incidents.
    #[serde(default)]
    pub enabled: bool,

    /// VAPID subject — must be "mailto:..." or "https://..." for push service contact.
    #[serde(default = "default_vapid_subject")]
    pub vapid_subject: String,

    /// VAPID private key in PKCS#8 PEM format.
    /// Set via agent.env: INNERWARDEN_VAPID_PRIVATE_KEY=<pem>
    #[serde(default)]
    pub vapid_private_key: String,

    /// VAPID public key — base64url-encoded uncompressed P-256 point (65 bytes → 87 chars).
    /// This value is served to browsers at GET /api/push/vapid-key.
    #[serde(default)]
    pub vapid_public_key: String,

    /// Minimum severity for push notification: "high" or "critical" (default: "high")
    #[serde(default = "default_web_push_min_severity")]
    pub min_severity: String,
}

fn default_vapid_subject() -> String {
    "mailto:admin@example.com".to_string()
}

fn default_web_push_min_severity() -> String {
    "high".to_string()
}

impl Default for WebPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vapid_subject: default_vapid_subject(),
            vapid_private_key: String::new(),
            vapid_public_key: String::new(),
            min_severity: default_web_push_min_severity(),
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load agent config from a TOML file.
/// If the file doesn't exist, returns `AgentConfig::default()`.
pub fn load(path: &Path) -> Result<AgentConfig> {
    if !path.exists() {
        return Ok(AgentConfig::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read agent config {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("failed to parse agent config {}", path.display()))
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_keep_days() -> usize {
    7
}

fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_ai_provider() -> String {
    "openai".to_string()
}

fn default_ai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_context_events() -> usize {
    20
}

fn default_confidence_threshold() -> f32 {
    0.8
}

fn default_incident_poll_secs() -> u64 {
    2
}

fn default_max_ai_calls_per_tick() -> usize {
    5
}

fn default_circuit_breaker_cooldown_secs() -> u64 {
    60
}

fn default_protected_ips() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "::1/128".to_string(),
    ]
}

fn default_block_backend() -> String {
    "ufw".to_string()
}

fn default_correlation_window_secs() -> u64 {
    300
}

fn default_max_related_incidents() -> usize {
    8
}

fn default_allowed_skills() -> Vec<String> {
    vec!["block-ip-ufw".to_string(), "monitor-ip".to_string()]
}

fn default_honeypot_mode() -> String {
    "demo".to_string()
}

fn default_honeypot_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_honeypot_port() -> u16 {
    2222
}

fn default_honeypot_duration_secs() -> u64 {
    300
}

fn default_honeypot_services() -> Vec<String> {
    vec!["ssh".to_string()]
}

fn default_honeypot_http_port() -> u16 {
    8080
}

fn default_honeypot_max_connections() -> usize {
    64
}

fn default_honeypot_max_payload_bytes() -> usize {
    512
}

fn default_honeypot_isolation_profile() -> String {
    "strict_local".to_string()
}

fn default_honeypot_forensics_keep_days() -> usize {
    7
}

fn default_honeypot_forensics_max_total_mb() -> usize {
    128
}

fn default_honeypot_transcript_preview_bytes() -> usize {
    96
}

fn default_honeypot_lock_stale_secs() -> u64 {
    1800
}

fn default_honeypot_pcap_timeout_secs() -> u64 {
    15
}

fn default_honeypot_pcap_max_packets() -> u64 {
    120
}

fn default_honeypot_containment_mode() -> String {
    "process".to_string()
}

fn default_honeypot_namespace_runner() -> String {
    "unshare".to_string()
}

fn default_honeypot_namespace_args() -> Vec<String> {
    vec![
        "--fork".to_string(),
        "--pid".to_string(),
        "--mount-proc".to_string(),
    ]
}

fn default_honeypot_external_handoff_timeout_secs() -> u64 {
    20
}

fn default_honeypot_external_handoff_signature_key_env() -> String {
    "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string()
}

fn default_honeypot_jail_runner() -> String {
    "bwrap".to_string()
}

fn default_honeypot_jail_profile() -> String {
    "standard".to_string()
}

fn default_honeypot_external_handoff_attestation_key_env() -> String {
    "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string()
}

fn default_honeypot_external_handoff_attestation_prefix() -> String {
    "IW_ATTEST".to_string()
}

fn default_honeypot_redirect_backend() -> String {
    "iptables".to_string()
}

fn default_honeypot_interaction() -> String {
    "banner".to_string()
}

fn default_honeypot_ssh_max_auth_attempts() -> usize {
    6
}

fn default_honeypot_http_max_requests() -> usize {
    10
}

// ---------------------------------------------------------------------------
// Data retention
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DataRetentionConfig {
    /// Keep daily events JSONL for N days (default: 7)
    #[serde(default = "default_data_events_keep_days")]
    pub events_keep_days: usize,

    /// Keep daily incidents JSONL for N days (default: 30)
    #[serde(default = "default_data_incidents_keep_days")]
    pub incidents_keep_days: usize,

    /// Keep daily decisions JSONL for N days — audit trail (default: 90)
    #[serde(default = "default_data_decisions_keep_days")]
    pub decisions_keep_days: usize,

    /// Keep daily telemetry JSONL for N days (default: 14)
    #[serde(default = "default_data_telemetry_keep_days")]
    pub telemetry_keep_days: usize,

    /// Keep trial-report-*.{json,md} for N days (default: 30)
    #[serde(default = "default_data_reports_keep_days")]
    pub reports_keep_days: usize,
}

impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            events_keep_days: default_data_events_keep_days(),
            incidents_keep_days: default_data_incidents_keep_days(),
            decisions_keep_days: default_data_decisions_keep_days(),
            telemetry_keep_days: default_data_telemetry_keep_days(),
            reports_keep_days: default_data_reports_keep_days(),
        }
    }
}

fn default_data_events_keep_days() -> usize {
    7
}
fn default_data_incidents_keep_days() -> usize {
    30
}
fn default_data_decisions_keep_days() -> usize {
    90
}
fn default_data_telemetry_keep_days() -> usize {
    14
}
fn default_data_reports_keep_days() -> usize {
    30
}

fn default_telegram_min_severity() -> String {
    "high".to_string()
}

fn default_slack_min_severity() -> String {
    "high".to_string()
}

// ---------------------------------------------------------------------------
// CrowdSec
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CrowdSecConfig {
    /// Enable CrowdSec LAPI polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// CrowdSec Local API URL (default: http://localhost:8080)
    #[serde(default = "default_crowdsec_url")]
    pub url: String,

    /// CrowdSec LAPI API key. Can also be set via CROWDSEC_API_KEY env var.
    /// Find it in: /etc/crowdsec/local_api_credentials.yaml (password field)
    #[serde(default)]
    pub api_key: String,

    /// How often to poll the LAPI for new ban decisions (seconds, default: 60)
    #[serde(default = "default_crowdsec_poll_secs")]
    pub poll_secs: u64,

    /// Max new IPs to block per sync cycle (default: 50).
    /// CrowdSec CAPI can return thousands of IPs at once; blocking them all
    /// in a single tick stalls the agent and exhausts memory.
    /// Remaining IPs are processed in subsequent ticks.
    #[serde(default = "default_crowdsec_max_per_sync")]
    #[allow(dead_code)]
    pub max_per_sync: usize,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_crowdsec_url(),
            api_key: String::new(),
            poll_secs: default_crowdsec_poll_secs(),
            max_per_sync: default_crowdsec_max_per_sync(),
        }
    }
}

fn default_crowdsec_url() -> String {
    "http://localhost:8080".to_string()
}

fn default_crowdsec_poll_secs() -> u64 {
    60
}

fn default_crowdsec_max_per_sync() -> usize {
    50
}

fn default_telegram_approval_ttl_secs() -> u64 {
    600
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AbuseIpDbConfig {
    /// Enable AbuseIPDB IP reputation enrichment (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// AbuseIPDB API key. Can also be set via ABUSEIPDB_API_KEY env var.
    /// Free tier: 1,000 checks/day — sufficient for most self-hosted servers.
    #[serde(default)]
    pub api_key: String,

    /// Maximum age of abuse reports to consider (default: 30 days).
    #[serde(default = "default_abuseipdb_max_age_days")]
    pub max_age_days: u32,

    /// Auto-block threshold: if AbuseIPDB confidence score >= this value,
    /// block the IP immediately without calling the AI provider.
    /// 0 = disabled (default). Recommended: 75 for aggressive auto-blocking,
    /// 90 for conservative auto-blocking. Reduces AI API costs during attacks
    /// from known malicious IPs.
    #[serde(default)]
    pub auto_block_threshold: u8,

    /// Report blocked IPs back to AbuseIPDB (default: false).
    /// When enabled, every successful block_ip action is reported to the
    /// AbuseIPDB database with the appropriate attack categories.
    /// This contributes to the global threat intelligence network.
    #[serde(default)]
    pub report_blocks: bool,
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            max_age_days: default_abuseipdb_max_age_days(),
            auto_block_threshold: 0,
            report_blocks: false,
        }
    }
}

fn default_abuseipdb_max_age_days() -> u32 {
    30
}

// ---------------------------------------------------------------------------
// Fail2ban
// ---------------------------------------------------------------------------

/// Deprecated — InnerWarden's native detectors + XDP firewall supersede fail2ban.
/// Kept for config compatibility (existing agent.toml files won't break).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Fail2BanConfig {
    /// Enable fail2ban polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// How often to poll fail2ban for new ban decisions (seconds, default: 60)
    #[serde(default = "default_fail2ban_poll_secs")]
    pub poll_secs: u64,

    /// Jails to poll. Empty = all active jails (from `fail2ban-client status`).
    #[serde(default)]
    pub jails: Vec<String>,

    /// Prefix fail2ban-client calls with sudo (needed when agent runs as non-root,
    /// requires: `innerwarden ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *` in sudoers).
    #[serde(default)]
    pub use_sudo: bool,
}

impl Default for Fail2BanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_secs: default_fail2ban_poll_secs(),
            jails: vec![],
            use_sudo: false,
        }
    }
}

fn default_fail2ban_poll_secs() -> u64 {
    60
}

// ---------------------------------------------------------------------------
// GeoIP enrichment
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct GeoIpConfig {
    /// Enable IP geolocation enrichment via ip-api.com (default: false).
    /// No API key required. Free tier: 45 requests/minute.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn defaults_when_no_file() {
        let cfg = load(Path::new("/nonexistent/agent.toml")).unwrap();
        assert!(cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 7);
        assert!(!cfg.webhook.enabled);
        assert_eq!(cfg.webhook.min_severity, "medium");
        assert_eq!(cfg.webhook.timeout_secs, 10);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 300);
        assert_eq!(cfg.correlation.max_related_incidents, 8);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "demo");
        assert_eq!(cfg.honeypot.bind_addr, "127.0.0.1");
        assert_eq!(cfg.honeypot.port, 2222);
        assert_eq!(cfg.honeypot.duration_secs, 300);
        assert_eq!(cfg.honeypot.services, vec!["ssh".to_string()]);
        assert_eq!(cfg.honeypot.http_port, 8080);
        assert!(cfg.honeypot.strict_target_only);
        assert!(!cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 64);
        assert_eq!(cfg.honeypot.max_payload_bytes, 512);
        assert_eq!(cfg.honeypot.isolation_profile, "strict_local");
        assert!(cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 7);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 128);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 96);
        assert_eq!(cfg.honeypot.lock_stale_secs, 1800);
        assert_eq!(cfg.honeypot.interaction, "banner");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 6);
        assert_eq!(cfg.honeypot.http_max_requests, 10);
        assert!(!cfg.honeypot.sandbox.enabled);
        assert!(cfg.honeypot.sandbox.runner_path.is_empty());
        assert!(cfg.honeypot.sandbox.clear_env);
        assert!(!cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 15);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 120);
        assert_eq!(cfg.honeypot.containment.mode, "process");
        assert!(!cfg.honeypot.containment.require_success);
        assert_eq!(cfg.honeypot.containment.namespace_runner, "unshare");
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "bwrap");
        assert!(cfg.honeypot.containment.jail_args.is_empty());
        assert_eq!(cfg.honeypot.containment.jail_profile, "standard");
        assert!(cfg.honeypot.containment.allow_namespace_fallback);
        assert!(!cfg.honeypot.external_handoff.enabled);
        assert!(cfg.honeypot.external_handoff.command.is_empty());
        assert!(cfg.honeypot.external_handoff.args.is_empty());
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 20);
        assert!(!cfg.honeypot.external_handoff.require_success);
        assert!(cfg.honeypot.external_handoff.clear_env);
        assert!(cfg.honeypot.external_handoff.allowed_commands.is_empty());
        assert!(!cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(!cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "INNERWARDEN_HANDOFF_SIGNING_KEY"
        );
        assert!(!cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert!(cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .is_empty());
        assert!(!cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(!cfg.telegram.enabled);
        assert!(cfg.telegram.bot_token.is_empty());
        assert!(cfg.telegram.chat_id.is_empty());
        assert_eq!(cfg.telegram.min_severity, "high");
        assert!(cfg.telegram.dashboard_url.is_empty());
        assert_eq!(cfg.telegram.approval_ttl_secs, 600);
    }

    #[test]
    fn parses_full_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[narrative]
enabled = false
keep_days = 3

[webhook]
enabled = true
url = "https://hooks.example.com/notify"
min_severity = "high"
timeout_secs = 5

[correlation]
enabled = true
window_seconds = 120
max_related_incidents = 4

[telemetry]
enabled = true

[honeypot]
mode = "listener"
bind_addr = "0.0.0.0"
port = 2223
duration_secs = 120
services = ["ssh", "http"]
http_port = 8088
strict_target_only = true
allow_public_listener = true
max_connections = 10
max_payload_bytes = 256
isolation_profile = "standard"
require_high_ports = false
forensics_keep_days = 14
forensics_max_total_mb = 512
transcript_preview_bytes = 192
lock_stale_secs = 600
interaction = "medium"
ssh_max_auth_attempts = 3
http_max_requests = 5

[honeypot.sandbox]
enabled = true
runner_path = "/usr/local/bin/innerwarden-agent"
clear_env = false

[honeypot.pcap_handoff]
enabled = true
timeout_secs = 20
max_packets = 200

[honeypot.containment]
mode = "jail"
require_success = true
namespace_runner = "/usr/bin/unshare"
namespace_args = ["--fork", "--pid", "--mount-proc", "--net"]
jail_runner = "/usr/bin/bwrap"
jail_args = ["--die-with-parent", "--unshare-all"]
jail_profile = "strict"
allow_namespace_fallback = false

[honeypot.external_handoff]
enabled = true
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{{session_id}}", "--metadata", "{{metadata_path}}", "--evidence", "{{evidence_path}}", "--pcap", "{{pcap_path}}"]
timeout_secs = 25
require_success = true
clear_env = false
allowed_commands = ["/usr/local/bin/iw-handoff", "/usr/local/bin/iw-alt"]
enforce_allowlist = true
signature_enabled = true
signature_key_env = "IW_HANDOFF_KEY"
attestation_enabled = true
attestation_key_env = "IW_HANDOFF_ATTEST_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = "receiver-a"

[honeypot.redirect]
enabled = true
backend = "iptables"

[telegram]
enabled = true
bot_token = "1234567890:AAAAAAAAAA"
chat_id = "-1001234567890"
min_severity = "critical"
dashboard_url = "http://my-server:8787"
approval_ttl_secs = 300
"#
        )
        .unwrap();

        let cfg = load(f.path()).unwrap();
        assert!(!cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 3);
        assert!(cfg.webhook.enabled);
        assert_eq!(cfg.webhook.url, "https://hooks.example.com/notify");
        assert_eq!(cfg.webhook.parsed_min_severity(), Severity::High);
        assert_eq!(cfg.webhook.timeout_secs, 5);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 120);
        assert_eq!(cfg.correlation.max_related_incidents, 4);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "listener");
        assert_eq!(cfg.honeypot.bind_addr, "0.0.0.0");
        assert_eq!(cfg.honeypot.port, 2223);
        assert_eq!(cfg.honeypot.duration_secs, 120);
        assert_eq!(
            cfg.honeypot.services,
            vec!["ssh".to_string(), "http".to_string()]
        );
        assert_eq!(cfg.honeypot.http_port, 8088);
        assert!(cfg.honeypot.strict_target_only);
        assert!(cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 10);
        assert_eq!(cfg.honeypot.max_payload_bytes, 256);
        assert_eq!(cfg.honeypot.isolation_profile, "standard");
        assert!(!cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 14);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 512);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 192);
        assert_eq!(cfg.honeypot.lock_stale_secs, 600);
        assert_eq!(cfg.honeypot.interaction, "medium");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 3);
        assert_eq!(cfg.honeypot.http_max_requests, 5);
        assert!(cfg.honeypot.sandbox.enabled);
        assert_eq!(
            cfg.honeypot.sandbox.runner_path,
            "/usr/local/bin/innerwarden-agent"
        );
        assert!(!cfg.honeypot.sandbox.clear_env);
        assert!(cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 20);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 200);
        assert_eq!(cfg.honeypot.containment.mode, "jail");
        assert!(cfg.honeypot.containment.require_success);
        assert_eq!(
            cfg.honeypot.containment.namespace_runner,
            "/usr/bin/unshare"
        );
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
                "--net".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "/usr/bin/bwrap");
        assert_eq!(
            cfg.honeypot.containment.jail_args,
            vec!["--die-with-parent".to_string(), "--unshare-all".to_string()]
        );
        assert_eq!(cfg.honeypot.containment.jail_profile, "strict");
        assert!(!cfg.honeypot.containment.allow_namespace_fallback);
        assert!(cfg.honeypot.external_handoff.enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.command,
            "/usr/local/bin/iw-handoff"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.args,
            vec![
                "--session-id".to_string(),
                "{session_id}".to_string(),
                "--metadata".to_string(),
                "{metadata_path}".to_string(),
                "--evidence".to_string(),
                "{evidence_path}".to_string(),
                "--pcap".to_string(),
                "{pcap_path}".to_string(),
            ]
        );
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 25);
        assert!(cfg.honeypot.external_handoff.require_success);
        assert!(!cfg.honeypot.external_handoff.clear_env);
        assert_eq!(
            cfg.honeypot.external_handoff.allowed_commands,
            vec![
                "/usr/local/bin/iw-handoff".to_string(),
                "/usr/local/bin/iw-alt".to_string()
            ]
        );
        assert!(cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "IW_HANDOFF_KEY"
        );
        assert!(cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "IW_HANDOFF_ATTEST_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_expected_receiver,
            "receiver-a"
        );
        assert!(cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(cfg.telegram.enabled);
        assert_eq!(cfg.telegram.bot_token, "1234567890:AAAAAAAAAA");
        assert_eq!(cfg.telegram.chat_id, "-1001234567890");
        assert_eq!(cfg.telegram.parsed_min_severity(), Severity::Critical);
        assert_eq!(cfg.telegram.dashboard_url, "http://my-server:8787");
        assert_eq!(cfg.telegram.approval_ttl_secs, 300);
    }

    #[test]
    fn parsed_min_severity_unknown_defaults_to_medium() {
        let cfg = WebhookConfig {
            min_severity: "bogus".into(),
            ..Default::default()
        };
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }
}
