//! Thin wrappers around systemctl for service lifecycle management.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Restart a systemd service unit.
/// In dry_run mode, prints the command without executing.
pub fn restart_service(unit: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    let out = Command::new("systemctl")
        .args(["restart", unit])
        .output()
        .with_context(|| format!("failed to run systemctl restart {unit}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("systemctl restart {unit} failed: {stderr}");
    }
    Ok(())
}

/// Restart a launchd service (macOS).
/// In dry_run mode, prints the command without executing.
pub fn restart_launchd(label: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    let out = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("system/{label}")])
        .output()
        .with_context(|| format!("failed to run launchctl kickstart -k system/{label}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("launchctl kickstart system/{label} failed: {stderr}");
    }
    Ok(())
}

/// Returns true if a service is currently active (running).
pub fn is_service_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_in_dry_run_does_not_error() {
        // Should succeed without actually calling systemctl
        assert!(restart_service("innerwarden-agent", true).is_ok());
    }
}
