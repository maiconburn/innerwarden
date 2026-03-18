use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;

// ---------------------------------------------------------------------------
// Activation options (passed to every capability method)
// ---------------------------------------------------------------------------

pub struct ActivationOptions {
    pub sensor_config: PathBuf,
    pub agent_config: PathBuf,
    pub dry_run: bool,
    /// KEY=VALUE parameters specific to the capability (e.g. backend=ufw)
    pub params: HashMap<String, String>,
    /// Skip interactive confirmation prompts (e.g. privacy gate for shell-audit)
    pub yes: bool,
}

// ---------------------------------------------------------------------------
// Capability effects (shown to operator before confirming)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CapabilityEffect {
    pub description: String,
}

impl CapabilityEffect {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Preflight checks
// ---------------------------------------------------------------------------

pub struct PreflightError {
    pub message: String,
    pub fix_hint: Option<String>,
}

impl PreflightError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fix_hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.fix_hint = Some(hint.into());
        self
    }
}

pub trait Preflight: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self) -> Result<(), PreflightError>;
}

// ---------------------------------------------------------------------------
// Activation result
// ---------------------------------------------------------------------------

pub struct ActivationReport {
    pub effects_applied: Vec<CapabilityEffect>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Capability trait
// ---------------------------------------------------------------------------

pub trait Capability: Send + Sync {
    /// Machine-readable ID: "block-ip", "sudo-protection", "shell-audit"
    fn id(&self) -> &'static str;

    /// Human-readable display name
    fn name(&self) -> &'static str;

    /// One-line description shown in `innerwarden list`
    fn description(&self) -> &'static str;

    /// Prerequisite checks — all must pass before any mutation.
    /// Receives `opts` so checks can depend on params (e.g. which backend to use).
    fn preflights(&self, opts: &ActivationOptions) -> Vec<Box<dyn Preflight>>;

    /// What activation will do, for dry-run display
    fn planned_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect>;

    /// Execute the activation. Must be idempotent.
    fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport>;

    /// What deactivation will do, for dry-run display.
    fn planned_disable_effects(&self, opts: &ActivationOptions) -> Vec<CapabilityEffect>;

    /// Reverse the activation. Must be idempotent.
    fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport>;

    /// Whether this capability is already enabled (derived from existing configs).
    fn is_enabled(&self, opts: &ActivationOptions) -> bool;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct CapabilityRegistry {
    caps: Vec<Box<dyn Capability>>,
}

impl CapabilityRegistry {
    pub fn default_all() -> Self {
        use crate::capabilities::{
            ai::AiCapability, block_ip::BlockIpCapability,
            search_protection::SearchProtectionCapability, shell_audit::ShellAuditCapability,
            sudo_protection::SudoProtectionCapability,
        };
        Self {
            caps: vec![
                Box::new(AiCapability),
                Box::new(BlockIpCapability),
                Box::new(SudoProtectionCapability),
                Box::new(ShellAuditCapability),
                Box::new(SearchProtectionCapability),
            ],
        }
    }

    pub fn get(&self, id: &str) -> Option<&dyn Capability> {
        self.caps.iter().find(|c| c.id() == id).map(|c| c.as_ref())
    }

    pub fn all(&self) -> impl Iterator<Item = &dyn Capability> {
        self.caps.iter().map(|c| c.as_ref())
    }
}
