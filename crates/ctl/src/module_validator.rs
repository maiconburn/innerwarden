/// Module validator — static analysis of a module package.
///
/// Checks manifest, directory structure, security constraints, docs and tests
/// without compiling anything. Called by `innerwarden module validate <path>`.
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Result;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ValidationReport {
    pub module_path: PathBuf,
    pub checks: Vec<Check>,
}

#[derive(Debug)]
pub struct Check {
    pub category: &'static str,
    pub name: String,
    pub result: CheckResult,
}

#[derive(Debug)]
pub enum CheckResult {
    Pass,
    Warn(String),
    Fail(String),
}

impl CheckResult {
    fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail(_))
    }
}

impl ValidationReport {
    pub fn passed(&self) -> bool {
        !self.checks.iter().any(|c| c.result.is_fail())
    }

    pub fn print(&self) {
        println!("Module: {}", self.module_path.display());
        println!("{}", "─".repeat(60));

        let mut current_cat = "";
        for check in &self.checks {
            if check.category != current_cat {
                println!("\n[{}]", check.category);
                current_cat = check.category;
            }
            match &check.result {
                CheckResult::Pass => println!("  ✓  {}", check.name),
                CheckResult::Warn(msg) => println!("  ⚠  {} — {}", check.name, msg),
                CheckResult::Fail(msg) => println!("  ✗  {} — {}", check.name, msg),
            }
        }

        println!();
        if self.passed() {
            println!("Result: PASS");
        } else {
            let fails = self.checks.iter().filter(|c| c.result.is_fail()).count();
            println!("Result: FAIL ({fails} error(s))");
        }
    }
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckResult::Pass => write!(f, "pass"),
            CheckResult::Warn(m) => write!(f, "warn: {m}"),
            CheckResult::Fail(m) => write!(f, "fail: {m}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Validate a module package at `module_path`.
/// `strict` enables additional security pattern checks.
pub fn validate(module_path: &Path, strict: bool) -> Result<ValidationReport> {
    let mut checks: Vec<Check> = Vec::new();

    // -----------------------------------------------------------------------
    // 1. Structure
    // -----------------------------------------------------------------------
    let manifest_path = module_path.join("module.toml");
    checks.push(check_file_exists(
        "Structure",
        "module.toml exists",
        &manifest_path,
    ));

    checks.push(check_file_exists(
        "Structure",
        "docs/README.md exists",
        &module_path.join("docs").join("README.md"),
    ));

    // Determine if this is a builtin module (tests live in crates/, not tests/)
    let is_builtin = manifest_path.exists() && {
        std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("module")
                    .and_then(|v| v.as_table())
                    .and_then(|t| t.get("builtin"))
                    .and_then(|v| v.as_bool())
            })
            .unwrap_or(false)
    };

    let tests_dir = module_path.join("tests");
    if is_builtin {
        checks.push(Check {
            category: "Structure",
            name: "tests/ (builtin — tests live in crates/)".into(),
            result: CheckResult::Pass,
        });
    } else {
        checks.push(check_tests_dir("Structure", &tests_dir));
    }

    // -----------------------------------------------------------------------
    // 2. Manifest
    // -----------------------------------------------------------------------
    if manifest_path.exists() {
        let toml_src = std::fs::read_to_string(&manifest_path)?;
        match toml_src.parse::<toml_edit::DocumentMut>() {
            Err(e) => {
                checks.push(Check {
                    category: "Manifest",
                    name: "module.toml is valid TOML".into(),
                    result: CheckResult::Fail(format!("parse error: {e}")),
                });
            }
            Ok(doc) => {
                checks.push(Check {
                    category: "Manifest",
                    name: "module.toml is valid TOML".into(),
                    result: CheckResult::Pass,
                });
                validate_manifest(&doc, &mut checks);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Docs
    // -----------------------------------------------------------------------
    let readme_path = module_path.join("docs").join("README.md");
    if readme_path.exists() {
        validate_readme(&readme_path, &mut checks)?;
    }

    // -----------------------------------------------------------------------
    // 4. Security (skills source if src/ exists)
    // -----------------------------------------------------------------------
    let skills_src_dir = module_path.join("src").join("skills");
    if skills_src_dir.exists() {
        validate_skills_security(&skills_src_dir, strict, &mut checks)?;
    } else if strict {
        checks.push(Check {
            category: "Security",
            name: "skills source dir".into(),
            result: CheckResult::Pass,
        });
    }

    Ok(ValidationReport {
        module_path: module_path.to_path_buf(),
        checks,
    })
}

// ---------------------------------------------------------------------------
// Structure helpers
// ---------------------------------------------------------------------------

fn check_file_exists(category: &'static str, name: &str, path: &Path) -> Check {
    Check {
        category,
        name: name.to_string(),
        result: if path.exists() {
            CheckResult::Pass
        } else {
            CheckResult::Fail(format!("not found: {}", path.display()))
        },
    }
}

fn check_tests_dir(category: &'static str, tests_dir: &Path) -> Check {
    if !tests_dir.exists() {
        return Check {
            category,
            name: "tests/ has at least one .rs file".into(),
            result: CheckResult::Fail(format!(
                "tests/ directory not found at {}",
                tests_dir.display()
            )),
        };
    }

    let has_rs = std::fs::read_dir(tests_dir)
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
        })
        .unwrap_or(false);

    Check {
        category,
        name: "tests/ has at least one .rs file".into(),
        result: if has_rs {
            CheckResult::Pass
        } else {
            CheckResult::Fail("tests/ exists but contains no .rs files".into())
        },
    }
}

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

fn validate_manifest(doc: &toml_edit::DocumentMut, checks: &mut Vec<Check>) {
    let module = match doc.get("module").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            checks.push(Check {
                category: "Manifest",
                name: "required [module] table".into(),
                result: CheckResult::Fail("no [module] table found in module.toml".into()),
            });
            return;
        }
    };

    // Required string fields
    for field in &["id", "name", "version", "description", "tier"] {
        let result = match module.get(field).and_then(|v| v.as_str()) {
            Some(v) if !v.is_empty() => CheckResult::Pass,
            Some(_) => CheckResult::Fail(format!("[module].{field} is empty")),
            None => CheckResult::Fail(format!("[module].{field} is missing")),
        };
        checks.push(Check {
            category: "Manifest",
            name: format!("[module].{field} present"),
            result,
        });
    }

    // id must be kebab-case
    if let Some(id) = module.get("id").and_then(|v| v.as_str()) {
        let valid = !id.is_empty()
            && id.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            && !id.starts_with('-')
            && !id.ends_with('-');
        checks.push(Check {
            category: "Manifest",
            name: "[module].id is kebab-case".into(),
            result: if valid {
                CheckResult::Pass
            } else {
                CheckResult::Fail(format!(
                    "'{id}' is not valid kebab-case (lowercase letters and hyphens only)"
                ))
            },
        });
    }

    // tier must be open or premium
    if let Some(tier) = module.get("tier").and_then(|v| v.as_str()) {
        checks.push(Check {
            category: "Manifest",
            name: "[module].tier is valid".into(),
            result: if tier == "open" || tier == "premium" {
                CheckResult::Pass
            } else {
                CheckResult::Fail(format!(
                    "tier '{tier}' is invalid — must be 'open' or 'premium'"
                ))
            },
        });
    }

    // version: basic semver format check (N.N.N)
    if let Some(ver) = module.get("version").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = ver.split('.').collect();
        let valid = parts.len() == 3 && parts.iter().all(|p| p.parse::<u64>().is_ok());
        checks.push(Check {
            category: "Manifest",
            name: "[module].version is semver".into(),
            result: if valid {
                CheckResult::Pass
            } else {
                CheckResult::Fail(format!("'{ver}' is not valid semver (expected N.N.N)"))
            },
        });
    }

    // [[rules]] validation
    validate_manifest_rules(doc, checks);
}

fn validate_manifest_rules(doc: &toml_edit::DocumentMut, checks: &mut Vec<Check>) {
    let rules = match doc.get("rules").and_then(|v| v.as_array_of_tables()) {
        Some(r) => r,
        None => return, // no rules — valid
    };

    // Collect declared detectors and skills from [provides]
    let provided_detectors: Vec<String> = doc
        .get("provides")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("detectors"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let provided_skills: Vec<String> = doc
        .get("provides")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("skills"))
        .map(|v| {
            v.as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    for (i, rule) in rules.iter().enumerate() {
        let rule_num = i + 1;

        // detector field
        if let Some(det) = rule.get("detector").and_then(|v| v.as_str()) {
            if !provided_detectors.is_empty() && !provided_detectors.contains(&det.to_string()) {
                checks.push(Check {
                    category: "Manifest",
                    name: format!("[[rules]][{rule_num}].detector references declared detector"),
                    result: CheckResult::Fail(format!("'{det}' is not in [provides].detectors")),
                });
            } else {
                checks.push(Check {
                    category: "Manifest",
                    name: format!("[[rules]][{rule_num}].detector references declared detector"),
                    result: CheckResult::Pass,
                });
            }
        }

        // skill field
        if let Some(skill) = rule.get("skill").and_then(|v| v.as_str()) {
            if !provided_skills.is_empty() && !provided_skills.contains(&skill.to_string()) {
                checks.push(Check {
                    category: "Manifest",
                    name: format!("[[rules]][{rule_num}].skill references declared skill"),
                    result: CheckResult::Fail(format!("'{skill}' is not in [provides].skills")),
                });
            } else {
                checks.push(Check {
                    category: "Manifest",
                    name: format!("[[rules]][{rule_num}].skill references declared skill"),
                    result: CheckResult::Pass,
                });
            }
        }

        // min_confidence range
        if let Some(conf) = rule
            .get("min_confidence")
            .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)))
        {
            checks.push(Check {
                category: "Manifest",
                name: format!("[[rules]][{rule_num}].min_confidence in [0.0, 1.0]"),
                result: if (0.0..=1.0).contains(&conf) {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail(format!("{conf} is out of range [0.0, 1.0]"))
                },
            });
        }

        // auto_execute safety
        if let Some(auto_exec) = rule.get("auto_execute").and_then(|v| v.as_bool()) {
            checks.push(Check {
                category: "Manifest",
                name: format!("[[rules]][{rule_num}].auto_execute default is safe"),
                result: if !auto_exec {
                    CheckResult::Pass
                } else {
                    CheckResult::Warn(
                        "auto_execute = true — verify this is intentional; it enables autonomous execution".into(),
                    )
                },
            });
        }
    }
}

// ---------------------------------------------------------------------------
// README validation
// ---------------------------------------------------------------------------

fn validate_readme(readme_path: &Path, checks: &mut Vec<Check>) -> Result<()> {
    let content = std::fs::read_to_string(readme_path)?;

    // Minimum length
    checks.push(Check {
        category: "Docs",
        name: "README.md minimum length (300 chars)".into(),
        result: if content.len() >= 300 {
            CheckResult::Pass
        } else {
            CheckResult::Fail(format!("{} chars — must be at least 300", content.len()))
        },
    });

    // Required sections
    for section in &["## Overview", "## Configuration", "## Security"] {
        checks.push(Check {
            category: "Docs",
            name: format!("README.md has '{section}' section"),
            result: if content.contains(section) {
                CheckResult::Pass
            } else {
                CheckResult::Fail(format!("missing section '{section}'"))
            },
        });
    }

    // Has a TOML code block (config example)
    checks.push(Check {
        category: "Docs",
        name: "README.md has TOML config example".into(),
        result: if content.contains("```toml") || content.contains("```bash") {
            CheckResult::Pass
        } else {
            CheckResult::Warn(
                "no ```toml or ```bash block found — consider adding a config example".into(),
            )
        },
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Security checks (static pattern analysis on skill source files)
// ---------------------------------------------------------------------------

fn validate_skills_security(
    skills_dir: &Path,
    strict: bool,
    checks: &mut Vec<Check>,
) -> Result<()> {
    let rs_files: Vec<PathBuf> = std::fs::read_dir(skills_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect();

    if rs_files.is_empty() {
        return Ok(());
    }

    for file in &rs_files {
        let src = std::fs::read_to_string(file)?;
        let file_name = file.file_name().unwrap_or_default().to_string_lossy();

        // .arg(format!(...)) — shell injection risk
        let arg_format_count = count_pattern(&src, ".arg(format!");
        checks.push(Check {
            category: "Security",
            name: format!("{file_name}: no .arg(format!(...)) calls"),
            result: if arg_format_count == 0 {
                CheckResult::Pass
            } else {
                CheckResult::Fail(format!(
                    "{arg_format_count} occurrence(s) of .arg(format!(...)) — \
                     dynamic strings in command args are a shell injection risk. \
                     Pass each argument as a separate .arg() call."
                ))
            },
        });

        // sh -c pattern
        let sh_c = src.contains("\"sh\"") && src.contains("\"-c\"")
            || src.contains("\"sh\",") && src.contains("\"-c\"")
            || src.contains("/bin/sh") && src.contains("-c")
            || src.contains("/bin/bash") && src.contains("-c");
        checks.push(Check {
            category: "Security",
            name: format!("{file_name}: no shell -c invocation"),
            result: if !sh_c {
                CheckResult::Pass
            } else {
                CheckResult::Fail(
                    "shell -c invocation detected — never pass dynamic strings through shell"
                        .into(),
                )
            },
        });

        // dry_run check
        checks.push(Check {
            category: "Security",
            name: format!("{file_name}: checks dry_run before executing"),
            result: if src.contains("dry_run") {
                CheckResult::Pass
            } else {
                CheckResult::Fail(
                    "no dry_run check found — skills must check dry_run and return early without executing".into(),
                )
            },
        });

        // unsafe without SAFETY comment
        if strict {
            let unsafe_count = count_pattern(&src, "unsafe {");
            let safety_count = count_pattern(&src, "// SAFETY:");
            checks.push(Check {
                category: "Security",
                name: format!("{file_name}: unsafe blocks have SAFETY comment"),
                result: if unsafe_count == 0 {
                    CheckResult::Pass
                } else if safety_count >= unsafe_count {
                    CheckResult::Warn(format!(
                        "{unsafe_count} unsafe block(s) — ensure each has a // SAFETY: comment and has been reviewed"
                    ))
                } else {
                    CheckResult::Fail(format!(
                        "{unsafe_count} unsafe block(s) but only {safety_count} // SAFETY: comment(s)"
                    ))
                },
            });
        }
    }

    Ok(())
}

fn count_pattern(src: &str, pattern: &str) -> usize {
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = src[start..].find(pattern) {
        count += 1;
        start += pos + pattern.len();
    }
    count
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn minimal_module_toml() -> &'static str {
        r#"
[module]
id          = "test-module"
name        = "Test Module"
version     = "0.1.0"
description = "A minimal test module"
tier        = "open"
builtin     = false
min_innerwarden = "0.1.0"

[provides]
detectors = ["my-detector"]
skills    = ["my-skill"]

[[rules]]
detector       = "my-detector"
skill          = "my-skill"
min_confidence = 0.8
auto_execute   = false
"#
    }

    fn minimal_readme() -> &'static str {
        r#"# test-module

A test module for validation tests.

## Overview

This module does something useful for testing purposes.

## Configuration

```toml
[detectors.my_detector]
enabled = true
threshold = 5
window_seconds = 300
```

## Security

Always run with dry_run = true first to validate decisions before enabling live execution.
This module is safe to use in all environments.
"#
    }

    fn make_valid_module(tmp: &TempDir) {
        write_file(tmp.path(), "module.toml", minimal_module_toml());
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(
            tmp.path(),
            "tests/integration.rs",
            "#[test]\nfn it_works() { assert!(true); }\n",
        );
    }

    #[test]
    fn valid_module_passes() {
        let tmp = TempDir::new().unwrap();
        make_valid_module(&tmp);
        let report = validate(tmp.path(), false).unwrap();
        assert!(
            report.passed(),
            "valid module should pass; failures: {:?}",
            report
                .checks
                .iter()
                .filter(|c| c.result.is_fail())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_manifest_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/integration.rs", "#[test]\nfn x() {}\n");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("module.toml")));
    }

    #[test]
    fn missing_readme_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "module.toml", minimal_module_toml());
        write_file(tmp.path(), "tests/integration.rs", "#[test]\nfn x() {}\n");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("README.md")));
    }

    #[test]
    fn missing_tests_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "module.toml", minimal_module_toml());
        write_file(tmp.path(), "docs/README.md", minimal_readme());

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("tests/")));
    }

    #[test]
    fn invalid_toml_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "module.toml", "this is not [valid toml ???");
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("valid TOML")));
    }

    #[test]
    fn invalid_tier_fails() {
        let tmp = TempDir::new().unwrap();
        let toml = minimal_module_toml().replace("tier        = \"open\"", "tier = \"enterprise\"");
        write_file(tmp.path(), "module.toml", &toml);
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("tier")));
    }

    #[test]
    fn non_kebab_id_fails() {
        let tmp = TempDir::new().unwrap();
        let toml =
            minimal_module_toml().replace("id          = \"test-module\"", "id = \"TestModule\"");
        write_file(tmp.path(), "module.toml", &toml);
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("kebab")));
    }

    #[test]
    fn rule_references_undeclared_detector_fails() {
        let tmp = TempDir::new().unwrap();
        let toml = minimal_module_toml().replace(
            "detector       = \"my-detector\"",
            "detector = \"unknown-detector\"",
        );
        write_file(tmp.path(), "module.toml", &toml);
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("detector")));
    }

    #[test]
    fn confidence_out_of_range_fails() {
        let tmp = TempDir::new().unwrap();
        let toml = minimal_module_toml().replace("min_confidence = 0.8", "min_confidence = 1.5");
        write_file(tmp.path(), "module.toml", &toml);
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("min_confidence")));
    }

    #[test]
    fn skill_with_format_arg_fails() {
        let tmp = TempDir::new().unwrap();
        make_valid_module(&tmp);
        write_file(
            tmp.path(),
            "src/skills/bad_skill.rs",
            r#"
fn execute(ip: &str, dry_run: bool) {
    if dry_run { return; }
    Command::new("/usr/sbin/tool")
        .arg(format!("deny from {ip}"))
        .output();
}
"#,
        );

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("format!")));
    }

    #[test]
    fn skill_without_dry_run_fails() {
        let tmp = TempDir::new().unwrap();
        make_valid_module(&tmp);
        write_file(
            tmp.path(),
            "src/skills/bad_skill.rs",
            r#"
fn execute(ip: &str) {
    Command::new("/usr/sbin/tool").arg("deny").arg(ip).output();
}
"#,
        );

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("dry_run")));
    }

    #[test]
    fn skill_with_sh_c_fails() {
        let tmp = TempDir::new().unwrap();
        make_valid_module(&tmp);
        write_file(
            tmp.path(),
            "src/skills/bad_skill.rs",
            r#"
fn execute(ip: &str, dry_run: bool) {
    if dry_run { return; }
    Command::new("sh").arg("-c").arg(format!("ufw deny {ip}")).output();
}
"#,
        );

        let report = validate(tmp.path(), false).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.result.is_fail() && c.name.contains("shell")));
    }

    #[test]
    fn auto_execute_true_is_warning_not_fail() {
        let tmp = TempDir::new().unwrap();
        let toml = minimal_module_toml().replace("auto_execute   = false", "auto_execute = true");
        write_file(tmp.path(), "module.toml", &toml);
        write_file(tmp.path(), "docs/README.md", minimal_readme());
        write_file(tmp.path(), "tests/t.rs", "#[test] fn x() {}");

        let report = validate(tmp.path(), false).unwrap();
        // Should still pass (warning, not failure)
        assert!(report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| matches!(c.result, CheckResult::Warn(_)) && c.name.contains("auto_execute")));
    }

    #[test]
    fn count_pattern_works() {
        let src = "foo bar foo baz foo";
        assert_eq!(count_pattern(src, "foo"), 3);
        assert_eq!(count_pattern(src, "qux"), 0);
    }
}
