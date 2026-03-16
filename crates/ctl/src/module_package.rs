//! Module package helpers: download, extract, create tarballs, verify SHA-256.
//!
//! Package format (.tar.gz):
//!   A single top-level directory named after the module ID, containing:
//!     module.toml     (required)
//!     rules/          (optional)
//!     docs/           (optional)
//!     … any other files the module needs
//!
//! SHA-256 sidecar: optional file at <same-name>.sha256 (first token = hex hash).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const USER_AGENT: &str = concat!("innerwarden-ctl/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// Download `url` to a temp file inside `tmp_dir`. Returns the local path.
pub fn download(url: &str, tmp_dir: &Path) -> Result<PathBuf> {
    let filename = url
        .split('/')
        .next_back()
        .filter(|s| !s.is_empty())
        .unwrap_or("module.tar.gz");

    let dest = tmp_dir.join(filename);

    let resp = ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("failed to download {url}"))?;

    let mut file = std::fs::File::create(&dest)
        .with_context(|| format!("cannot create {}", dest.display()))?;

    let mut buf = [0u8; 65_536];
    let mut reader = resp.into_body().into_reader();
    loop {
        let n = reader
            .read(&mut buf)
            .context("read error during download")?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .context("write error during download")?;
    }

    Ok(dest)
}

/// Try to download a `.sha256` sidecar for `url` and return the expected hex hash.
/// Returns `None` if the sidecar does not exist (HTTP 404) or cannot be fetched.
pub fn fetch_sha256_sidecar(url: &str) -> Option<String> {
    let sha_url = format!("{url}.sha256");
    let resp = ureq::get(&sha_url)
        .header("User-Agent", USER_AGENT)
        .call()
        .ok()?;
    let text = resp.into_body().read_to_string().ok()?;
    let hash = text.split_whitespace().next()?.to_ascii_lowercase();
    if hash.len() == 64 {
        Some(hash)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/// Compute SHA-256 of a file and return lowercase hex string.
pub fn sha256_hex(path: &Path) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// Verify `path` against an expected hex hash. Returns `Err` on mismatch.
pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_hex(path)?;
    if actual != expected.trim().to_ascii_lowercase() {
        bail!(
            "SHA-256 mismatch for {}:\n  expected {}\n  got      {}",
            path.display(),
            expected,
            actual
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

/// Extract a `.tar.gz` tarball into `dest_dir` using the system `tar`.
pub fn extract_tarball(tarball: &Path, dest_dir: &Path) -> Result<()> {
    let out = std::process::Command::new("tar")
        .args([
            "-xzf",
            tarball.to_str().unwrap(),
            "-C",
            dest_dir.to_str().unwrap(),
        ])
        .output()
        .context("failed to run tar — is it installed?")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("tar extract failed: {stderr}");
    }
    Ok(())
}

/// Locate the module directory inside an extracted tarball.
///
/// Searches for `module.toml` at the top level or one level deep.
/// Returns the directory that *contains* `module.toml`.
pub fn find_module_dir(extract_dir: &Path) -> Result<PathBuf> {
    // Flat layout: module.toml at root of extracted dir
    if extract_dir.join("module.toml").exists() {
        return Ok(extract_dir.to_path_buf());
    }

    // Wrapped layout: <module-id>/module.toml
    for entry in std::fs::read_dir(extract_dir)
        .with_context(|| format!("cannot read {}", extract_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && path.join("module.toml").exists() {
            return Ok(path);
        }
    }

    bail!(
        "no module.toml found in the tarball \
         (checked top level and one directory deep)"
    )
}

// ---------------------------------------------------------------------------
// Create (publish)
// ---------------------------------------------------------------------------

/// Package `module_dir` into a `.tar.gz` at `output`.
/// The tarball wraps the directory as `<dirname>/module.toml …`.
pub fn create_tarball(module_dir: &Path, output: &Path) -> Result<()> {
    let parent = module_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("module directory has no parent"))?;
    let dirname = module_dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("module directory has no name"))?;

    let out = std::process::Command::new("tar")
        .args([
            "-czf",
            output.to_str().unwrap(),
            "-C",
            parent.to_str().unwrap(),
            dirname.to_str().unwrap(),
        ])
        .output()
        .context("failed to run tar")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("tar create failed: {stderr}");
    }
    Ok(())
}

/// Write a `.sha256` sidecar alongside `tarball` (same path + ".sha256").
pub fn write_sha256_sidecar(tarball: &Path) -> Result<PathBuf> {
    let hex = sha256_hex(tarball)?;
    let filename = tarball
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("tarball path has no filename"))?
        .to_string_lossy();
    let sidecar = tarball.with_file_name(format!("{filename}.sha256"));
    std::fs::write(&sidecar, format!("{hex}  {filename}\n"))
        .with_context(|| format!("cannot write {}", sidecar.display()))?;
    Ok(sidecar)
}

// ---------------------------------------------------------------------------
// Install (copy extracted dir → modules_dir/<id>/)
// ---------------------------------------------------------------------------

/// Recursively copy `src` directory into `dst` (created if absent).
pub fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("cannot create {}", dst.display()))?;

    for entry in std::fs::read_dir(src).with_context(|| format!("cannot read {}", src.display()))? {
        let entry = entry?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)
                .with_context(|| format!("cannot copy to {}", dest_path.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    fn write_file(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"innerwarden").unwrap();
        let h1 = sha256_hex(tmp.path()).unwrap();
        let h2 = sha256_hex(tmp.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_sha256_passes_on_correct_hash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello").unwrap();
        let hex = sha256_hex(tmp.path()).unwrap();
        assert!(verify_sha256(tmp.path(), &hex).is_ok());
    }

    #[test]
    fn verify_sha256_fails_on_wrong_hash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello").unwrap();
        let bad = "0".repeat(64);
        assert!(verify_sha256(tmp.path(), &bad).is_err());
    }

    #[test]
    fn find_module_dir_flat_layout() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "module.toml", "[module]\nid = \"test\"\n");
        let found = find_module_dir(dir.path()).unwrap();
        assert_eq!(found, dir.path());
    }

    #[test]
    fn find_module_dir_wrapped_layout() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("my-module");
        std::fs::create_dir_all(&sub).unwrap();
        write_file(&sub, "module.toml", "[module]\nid = \"my-module\"\n");
        let found = find_module_dir(dir.path()).unwrap();
        assert_eq!(found, sub);
    }

    #[test]
    fn find_module_dir_returns_err_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_module_dir(dir.path()).is_err());
    }

    #[test]
    fn copy_dir_copies_recursively() {
        let src = tempfile::tempdir().unwrap();
        let sub = src.path().join("rules");
        std::fs::create_dir_all(&sub).unwrap();
        write_file(src.path(), "module.toml", "# test");
        write_file(&sub, "rule.conf", "# rule");

        let dst = tempfile::tempdir().unwrap();
        copy_dir(src.path(), dst.path()).unwrap();

        assert!(dst.path().join("module.toml").exists());
        assert!(dst.path().join("rules/rule.conf").exists());
    }

    #[test]
    fn create_and_extract_tarball_roundtrip() {
        // Create a source module dir
        let src = tempfile::tempdir().unwrap();
        let module_dir = src.path().join("test-module");
        std::fs::create_dir_all(&module_dir).unwrap();
        write_file(
            &module_dir,
            "module.toml",
            "[module]\nid = \"test-module\"\n",
        );

        // Pack it
        let out_dir = tempfile::tempdir().unwrap();
        let tarball = out_dir.path().join("test-module.tar.gz");
        create_tarball(&module_dir, &tarball).unwrap();
        assert!(tarball.exists());

        // Extract it
        let extract_dir = tempfile::tempdir().unwrap();
        extract_tarball(&tarball, extract_dir.path()).unwrap();

        // Find module dir inside extraction
        let found = find_module_dir(extract_dir.path()).unwrap();
        assert!(found.join("module.toml").exists());
    }

    #[test]
    fn write_sha256_sidecar_creates_correct_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("module.tar.gz");
        std::fs::write(&file, b"fake tarball content").unwrap();

        let sidecar = write_sha256_sidecar(&file).unwrap();
        assert!(sidecar.exists());
        assert!(sidecar.to_str().unwrap().ends_with(".sha256"));

        let content = std::fs::read_to_string(&sidecar).unwrap();
        let hash_in_file = content.split_whitespace().next().unwrap();
        let computed = sha256_hex(&file).unwrap();
        assert_eq!(hash_in_file, computed);
    }
}
