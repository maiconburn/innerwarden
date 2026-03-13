use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub collectors: CollectorsConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
}

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub host_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    pub data_dir: String,
    #[serde(default = "default_true")]
    pub write_events: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub auth_log: AuthLogConfig,
    #[serde(default)]
    pub integrity: IntegrityConfig,
    #[serde(default)]
    pub journald: JournaldConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub exec_audit: ExecAuditConfig,
}

#[derive(Debug, Deserialize)]
pub struct ExecAuditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_exec_audit_path")]
    pub path: String,
    #[serde(default)]
    pub include_tty: bool,
}

impl Default for ExecAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_exec_audit_path(),
            include_tty: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JournaldConfig {
    #[serde(default)]
    pub enabled: bool,
    /// systemd unit names to filter on (e.g. "sshd", "sudo"). Empty = all units.
    #[serde(default = "default_journald_units")]
    pub units: Vec<String>,
}

impl Default for JournaldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            units: default_journald_units(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DockerConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Deserialize)]
pub struct IntegrityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec![],
            poll_seconds: default_poll_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auth_log_path")]
    pub path: String,
}

impl Default for AuthLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_auth_log_path(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub ssh_bruteforce: SshBruteforceConfig,
    #[serde(default)]
    pub credential_stuffing: CredentialStuffingConfig,
    #[serde(default)]
    pub port_scan: PortScanConfig,
}

#[derive(Debug, Deserialize)]
pub struct SshBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: usize,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SshBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_threshold(),
            window_seconds: default_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CredentialStuffingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_credential_stuffing_threshold")]
    pub threshold: usize,
    #[serde(default = "default_credential_stuffing_window_seconds")]
    pub window_seconds: u64,
}

impl Default for CredentialStuffingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_credential_stuffing_threshold(),
            window_seconds: default_credential_stuffing_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortScanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_port_scan_threshold")]
    pub threshold: usize,
    #[serde(default = "default_port_scan_window_seconds")]
    pub window_seconds: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_port_scan_threshold(),
            window_seconds: default_port_scan_window_seconds(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_threshold() -> usize {
    8
}

fn default_port_scan_threshold() -> usize {
    12
}

fn default_credential_stuffing_threshold() -> usize {
    6
}

fn default_window_seconds() -> u64 {
    300
}

fn default_port_scan_window_seconds() -> u64 {
    60
}

fn default_credential_stuffing_window_seconds() -> u64 {
    300
}

fn default_poll_seconds() -> u64 {
    60
}

fn default_auth_log_path() -> String {
    "/var/log/auth.log".to_string()
}

fn default_exec_audit_path() -> String {
    "/var/log/audit/audit.log".to_string()
}

fn default_journald_units() -> Vec<String> {
    vec!["sshd".to_string(), "sudo".to_string()]
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("failed to read config: {path}"))?;
    toml::from_str(&content).with_context(|| "failed to parse config")
}
