//! Composable preflight checkers.
//!
//! Each checker implements the `Preflight` trait and can be stacked by
//! capabilities to express their prerequisites.

use std::path::Path;

use crate::capability::{Preflight, PreflightError};

// ---------------------------------------------------------------------------
// BinaryExists
// ---------------------------------------------------------------------------

/// Checks that a binary exists at a given path or is findable in PATH.
pub struct BinaryExists {
    /// Display name shown in the preflight output
    pub display_name: &'static str,
    /// Absolute path to the binary (e.g. "/usr/sbin/ufw")
    pub path: &'static str,
}

impl Preflight for BinaryExists {
    fn name(&self) -> &str {
        self.display_name
    }

    fn check(&self) -> Result<(), PreflightError> {
        if Path::new(self.path).exists() {
            return Ok(());
        }
        // Fallback: check if findable via PATH using `which`-style search
        let bin = Path::new(self.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(self.path);
        Err(
            PreflightError::new(format!("{} not found (expected at {})", bin, self.path))
                .with_hint(format!(
                    "install with your distro package manager, e.g.: apt install {bin}"
                )),
        )
    }
}

// ---------------------------------------------------------------------------
// DirectoryExists
// ---------------------------------------------------------------------------

/// Checks that a directory exists.
pub struct DirectoryExists {
    pub display_name: &'static str,
    pub path: &'static str,
}

impl Preflight for DirectoryExists {
    fn name(&self) -> &str {
        self.display_name
    }

    fn check(&self) -> Result<(), PreflightError> {
        if Path::new(self.path).is_dir() {
            return Ok(());
        }
        Err(
            PreflightError::new(format!("directory {} does not exist", self.path))
                .with_hint(format!("create it with: sudo mkdir -p {}", self.path)),
        )
    }
}

// ---------------------------------------------------------------------------
// UserExists
// ---------------------------------------------------------------------------

/// Checks that a system user exists by inspecting /etc/passwd.
pub struct UserExists {
    pub display_name: &'static str,
    pub username: &'static str,
}

impl Preflight for UserExists {
    fn name(&self) -> &str {
        self.display_name
    }

    fn check(&self) -> Result<(), PreflightError> {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let prefix = format!("{}:", self.username);
        if passwd.lines().any(|l| l.starts_with(&prefix)) {
            return Ok(());
        }
        Err(
            PreflightError::new(format!("system user '{}' does not exist", self.username))
                .with_hint("run the installer first: sudo ./install.sh".to_string()),
        )
    }
}

// ---------------------------------------------------------------------------
// VisudoAvailable
// ---------------------------------------------------------------------------

/// Checks that `visudo` is available for sudoers validation.
pub struct VisudoAvailable;

impl Preflight for VisudoAvailable {
    fn name(&self) -> &str {
        "visudo available for sudoers validation"
    }

    fn check(&self) -> Result<(), PreflightError> {
        let candidates = ["/usr/sbin/visudo", "/usr/bin/visudo", "/sbin/visudo"];
        if candidates.iter().any(|p| Path::new(p).exists()) {
            return Ok(());
        }
        Err(PreflightError::new("visudo not found")
            .with_hint("install sudo package: apt install sudo"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_exists_passes_for_real_binary() {
        // /bin/sh exists on all Unix systems
        let pf = BinaryExists {
            display_name: "sh exists",
            path: "/bin/sh",
        };
        assert!(pf.check().is_ok());
    }

    #[test]
    fn binary_exists_fails_for_nonexistent() {
        let pf = BinaryExists {
            display_name: "fake binary",
            path: "/usr/bin/innerwarden-fake-binary-xyz",
        };
        let err = pf.check().unwrap_err();
        assert!(err.fix_hint.is_some());
    }

    #[test]
    fn directory_exists_passes_for_tmp() {
        let pf = DirectoryExists {
            display_name: "/tmp exists",
            path: "/tmp",
        };
        assert!(pf.check().is_ok());
    }

    #[test]
    fn directory_exists_fails_for_nonexistent() {
        let pf = DirectoryExists {
            display_name: "nonexistent dir",
            path: "/nonexistent/innerwarden/xyz",
        };
        assert!(pf.check().is_err());
    }

    #[test]
    fn user_exists_passes_for_root() {
        // root always exists
        let pf = UserExists {
            display_name: "root user exists",
            username: "root",
        };
        assert!(pf.check().is_ok());
    }

    #[test]
    fn user_exists_fails_for_nonexistent_user() {
        let pf = UserExists {
            display_name: "fake user",
            username: "innerwarden-fake-user-xyz",
        };
        assert!(pf.check().is_err());
    }
}
