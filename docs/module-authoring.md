# InnerWarden Module Authoring Guide

This guide explains how to create a module for InnerWarden — either manually or using an AI coding tool such as Claude Code, GitHub Copilot, or OpenAI Codex.

---

## Who this guide is for

- Contributors writing new detection or response capabilities
- AI tools (Claude Code, Codex, Copilot) generating modules from a problem description
- Security engineers adapting InnerWarden to a new environment

---

## What a module is

A module is a self-contained vertical solution for a specific security problem. It bundles one or more of:

- **Collector** — reads a data source and emits `Event` structs
- **Detector** — analyzes events and emits `Incident` structs when a pattern is found
- **Skill** — executes a response action when the agent decides to act
- **Rules** — default mappings from detector to skill (overridable in `agent.toml`)
- **Config examples** — copy-pasteable TOML snippets
- **Tests** — at least one test per component
- **Documentation** — `docs/README.md` explaining what the module does and when to use it

A module does **not** need all of these. A module that only adds a new skill is valid. A module that only adds a detector (with no skill) is valid.

### Built-in vs external modules

| Type | Where the code lives | When to use |
|------|---------------------|-------------|
| **Built-in** | `crates/sensor/` or `crates/agent/` | The module is part of the main repo (existing or accepted PR) |
| **External** | `modules/<id>/src/` | New module in development, not yet merged into crates |

External modules are developed in `modules/<id>/src/` and manually registered into the appropriate crate when ready for merge. There is no dynamic plugin loader.

---

## Directory structure

```
modules/
  my-module/
    module.toml               # manifest — required
    src/
      collectors/
        my_collector.rs       # optional — only if adding a new collector
      detectors/
        my_detector.rs        # optional — only if adding a new detector
      skills/
        my_skill.rs           # optional — only if adding a new skill
    config/
      sensor.example.toml     # copy-pasteable sensor config snippet
      agent.example.toml      # copy-pasteable agent config snippet
    tests/
      integration.rs          # required — at least one test
    docs/
      README.md               # required
```

---

## module.toml reference

```toml
[module]
id          = "my-module"          # kebab-case, globally unique
name        = "My Module"          # human-readable
version     = "0.1.0"             # semver
description = "One sentence: what problem this solves and how"
authors     = ["Name <email>"]
license     = "Apache-2.0"
tier        = "open"              # open | premium
builtin     = false               # true if code lives in crates/ already
min_innerwarden = "0.1.0"

# What this module provides — IDs must match struct/file names
[provides]
collectors = ["my-collector"]     # omit section if not providing collectors
detectors  = ["my-detector"]      # omit section if not providing detectors
skills     = ["my-skill"]         # omit section if not providing skills

# Event sources this module requires to function
[requires]
event_sources = ["auth_log", "journald.sshd"]

# Default rules linking detectors to skills
# The operator can override these in agent.toml
[[rules]]
detector       = "my-detector"
skill          = "my-skill"
min_confidence = 0.8
auto_execute   = false     # must be false by default — safety rule

# System commands this module's skills are allowed to run
[security]
allowed_commands        = ["/usr/sbin/example-tool"]
require_sudo_validation = true    # if skills write sudoers files
forbid_shell_expansion  = true    # always true

# Prerequisites that must be satisfied before the module can be activated
[[preflights]]
kind   = "binary_exists"          # binary_exists | directory_exists | user_exists
value  = "/usr/sbin/example-tool"
reason = "required for skill execution"
```

---

## Implementing a Collector

### Pattern

Collectors are `async fn run()` methods that tail a file, subprocess, or socket and send `Event` structs to the sensor pipeline via an `mpsc::Sender`.

```rust
use innerwarden_core::{Event, Severity, EntityRef};
use tokio::sync::mpsc;
use anyhow::Result;

pub struct MyCollector {
    pub path: String,
}

impl MyCollector {
    pub async fn run(self, tx: mpsc::Sender<Event>) -> Result<()> {
        loop {
            // Read from source...
            let event = Event {
                ts: chrono::Utc::now(),
                host: "my-host".into(),
                source: "my_collector".into(),   // snake_case, matches config key
                kind: "my.event_type".into(),    // dot-separated hierarchy
                severity: Severity::Low,
                summary: "Something happened".into(),
                details: serde_json::json!({ "key": "value" }),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            };

            if tx.send(event).await.is_err() {
                break; // pipeline closed, exit cleanly
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Ok(())
    }
}
```

### Rules

1. **Never use `?` at the top level of `run()`** — log errors with `tracing::warn!` and continue
2. **Never crash the process** — collectors must be fail-open
3. **Use `spawn_blocking` for synchronous file I/O** inside async tasks
4. `source` must be a stable snake_case string that matches the config key
5. `kind` must be a dot-separated string: `domain.event_type` (e.g., `ssh.login_failed`)

### Registration

After writing the collector, register it in `crates/sensor/src/main.rs`:

```rust
// 1. Add to Cargo.toml if needed
// 2. Spawn in main():
let my_collector = MyCollector { path: cfg.collectors.my.path.clone() };
let tx_clone = tx.clone();
tokio::spawn(async move {
    if let Err(e) = my_collector.run(tx_clone).await {
        tracing::warn!("my_collector exited: {e}");
    }
});
```

---

## Implementing a Detector

### Pattern

Detectors are structs with a `process(&mut self, event: &Event) -> Option<Incident>` method. They maintain internal state (sliding windows, counters) between calls.

```rust
use innerwarden_core::{Event, Incident, Severity, EntityRef};
use std::collections::HashMap;

pub struct MyDetector {
    host: String,
    threshold: usize,
    window_seconds: u64,
    state: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
}

impl MyDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            threshold,
            window_seconds,
            state: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only handle relevant events
        if event.kind != "my.relevant_kind" {
            return None;
        }

        let key = extract_key(event)?; // e.g., source IP
        let now = event.ts;
        let window = chrono::Duration::seconds(self.window_seconds as i64);

        // Sliding window: keep only events within the window
        let entries = self.state.entry(key.clone()).or_default();
        entries.retain(|&ts| now - ts < window);
        entries.push(now);

        if entries.len() >= self.threshold {
            return Some(Incident {
                ts: now,
                host: self.host.clone(),
                incident_id: format!("my_detector:{}:{}", key, now.to_rfc3339()),
                severity: Severity::High,
                title: format!("My pattern detected from {key}"),
                summary: format!("{} events in {}s from {key}", entries.len(), self.window_seconds),
                evidence: serde_json::json!({ "count": entries.len(), "key": key }),
                recommended_checks: vec!["Check source IP activity".into()],
                tags: vec!["my-detector".into()],
                entities: vec![EntityRef::ip(&key)],
            });
        }
        None
    }
}
```

### Rules

1. `incident_id` format: `"{detector_name}:{entity}:{iso_timestamp}"`
2. Always include entities: `EntityRef::ip()` for IPs, `EntityRef::user()` for users
3. The detector name in `incident_id` must match the id in `module.toml [provides].detectors`
4. Sliding window state is in-memory — it resets on restart (acceptable; detectors are stateless across restarts by design)

### Registration

Add to `crates/sensor/src/main.rs`:

```rust
// In DetectorSet struct:
my: Option<MyDetector>,

// In main(), conditional on config:
let my_detector = cfg.detectors.my.enabled.then(|| {
    MyDetector::new(&cfg.agent.host_id, cfg.detectors.my.threshold, cfg.detectors.my.window_seconds)
});

// In process_event():
if let Some(ref mut d) = detectors.my {
    if let Some(incident) = d.process(&event) {
        incident_writer.write_incident(&incident)?;
    }
}
```

---

## Implementing a Skill

### Pattern

Skills implement the `ResponseSkill` trait from `crates/agent/src/skills/mod.rs`.

```rust
use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};
use std::pin::Pin;
use std::future::Future;

pub struct MySkill;

impl ResponseSkill for MySkill {
    fn id(&self) -> &'static str { "my-skill" }
    fn name(&self) -> &'static str { "My Skill" }
    fn description(&self) -> &'static str {
        "Brief description sent to the AI to help it decide whether to use this skill"
    }
    fn tier(&self) -> SkillTier { SkillTier::Open }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["my-detector"]   // incident types this skill applies to; &[] means any
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let target = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => return SkillResult {
                    success: false,
                    message: "no target_ip in context".into(),
                },
            };

            if dry_run {
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would execute my-skill against {target}"),
                };
            }

            // Execute actual system action
            let output = tokio::process::Command::new("/usr/sbin/my-tool")
                .arg("action")
                .arg(&target)    // never format! dynamic strings into command args
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => SkillResult {
                    success: true,
                    message: format!("my-skill applied to {target}"),
                },
                Ok(o) => SkillResult {
                    success: false,
                    message: format!("my-tool failed: {}", String::from_utf8_lossy(&o.stderr)),
                },
                Err(e) => SkillResult {
                    success: false,
                    message: format!("failed to run my-tool: {e}"),
                },
            }
        })
    }
}
```

### Security rules (non-negotiable)

1. **Always check `dry_run`** and return a descriptive message without executing anything
2. **Never execute commands not in `module.toml [security].allowed_commands`**
3. **Never use `format!()` to build command arguments** — pass arguments as separate `.arg()` calls
4. **Never use shell expansion** — do not pass arguments through `sh -c`
5. **Never write files outside `ctx.data_dir`** except to paths declared in module.toml
6. **Never make outbound network calls** from skills — use the agent's webhook for notifications
7. **No `unsafe` blocks** without a `// SAFETY: <justification>` comment and explicit PR review

### Registration

Add to `crates/agent/src/skills/builtin/mod.rs`:

```rust
pub use my_skill::MySkill;

// In SkillRegistry::default_builtin():
Box::new(MySkill),
```

---

## Writing tests

Every module must have at least one test per component.

### Detector test (minimum)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{Event, Severity, EntityRef};

    fn make_event(kind: &str, ip: &str) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "test-host".into(),
            source: "my_collector".into(),
            kind: kind.into(),
            severity: Severity::Low,
            summary: "test event".into(),
            details: serde_json::Value::Null,
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn detector_triggers_at_threshold() {
        let mut d = MyDetector::new("test-host", 3, 300);
        let event = make_event("my.relevant_kind", "1.2.3.4");

        // Below threshold: no incident
        assert!(d.process(&event).is_none());
        assert!(d.process(&event).is_none());

        // At threshold: incident triggered
        let incident = d.process(&event);
        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn detector_ignores_unrelated_events() {
        let mut d = MyDetector::new("test-host", 3, 300);
        let event = make_event("unrelated.kind", "1.2.3.4");
        for _ in 0..10 {
            assert!(d.process(&event).is_none());
        }
    }
}
```

### Skill test (minimum)

```rust
#[tokio::test]
async fn skill_dry_run_is_noop() {
    let skill = MySkill;
    let ctx = make_test_context("1.2.3.4");
    let result = skill.execute(&ctx, true).await;
    assert!(result.success);
    assert!(result.message.contains("DRY RUN"));
    // Assert no system state was modified
}
```

---

## Documentation requirements

`docs/README.md` must contain these sections:

```markdown
# module-id

One sentence: what problem this solves.

## Overview
What the module does, which components it includes, and how they interact.

## Configuration
Table of tunable parameters with defaults and meaning.

## Security
Risks, tradeoffs, and how to use safely (especially dry_run guidance).

## Source code
Links to the relevant files in crates/.
```

Minimum length: 300 characters. Config examples must be copy-pasteable and correct.

---

## Validation

Before opening a PR, run:

```bash
innerwarden module validate ./modules/my-module
```

The validator checks:

| Check | What it verifies |
|-------|-----------------|
| Structure | `module.toml`, `docs/README.md`, `tests/` with at least one `.rs` file |
| Manifest | Required fields, kebab-case id, semver version, valid tier |
| Rules | `detector` and `skill` in `[[rules]]` are declared in `[provides]` |
| Confidence | `min_confidence` is between 0.0 and 1.0 |
| auto_execute | Must be `false` (or explicitly `true` with justification) |
| Security | Skills do not contain `format!()` in Command args, no `sh -c` patterns |
| Docs | README has minimum required sections and length |
| Tests | At least one `#[test]` or `#[tokio::test]` in `tests/` |

---

## Step-by-step: creating a module with Claude Code (or any AI tool)

This section describes how to use an AI coding assistant to generate a new module correctly.

### Why AI needs this guide

AI tools generate code from context. Without the right context, they will:
- Invent their own traits instead of implementing `ResponseSkill`
- Use `format!("sudo ufw deny {ip}")` in Command args (shell injection)
- Skip `dry_run` checks in skills
- Write detectors that crash on unexpected input instead of returning `None`
- Forget to register new components in the appropriate registry

With the right context, AI tools can generate correct, production-quality modules in minutes.

### Step 1 — Give the AI the right context

Before writing any prompt, make sure the AI has access to:

1. **This file** (`docs/module-authoring.md`) — the complete rules and patterns
2. **`CLAUDE.md`** — the full project architecture and conventions
3. **An existing module as reference** — e.g., `modules/ssh-protection/` for a full example
4. **The relevant trait files:**
   - `crates/agent/src/skills/mod.rs` — `ResponseSkill` trait
   - `crates/core/src/event.rs` — `Event` struct
   - `crates/core/src/incident.rs` — `Incident` struct

With Claude Code in your terminal:
```bash
# Claude Code automatically reads CLAUDE.md from the project root.
# No extra setup needed — just run it from the repo directory.
claude
```

With other tools (Copilot Chat, Codex, etc.), paste the contents of this file and CLAUDE.md at the start of the conversation.

### Step 2 — Write the problem description prompt

Use this template:

```
I want to create a new InnerWarden module called "<module-id>" that solves this problem:

<describe the security problem in 1-3 sentences>

The module should:
- Collect data from: <data source — e.g., "nginx access log at /var/log/nginx/access.log">
- Detect this pattern: <describe the detection logic — thresholds, windows, conditions>
- Respond with: <describe the response action>

Please:
1. Create `modules/<module-id>/module.toml` following the module-authoring.md spec
2. Create `modules/<module-id>/src/collectors/<name>.rs` if a new collector is needed
3. Create `modules/<module-id>/src/detectors/<name>.rs` if a new detector is needed
4. Create `modules/<module-id>/src/skills/<name>.rs` if a new skill is needed
5. Create `modules/<module-id>/config/sensor.example.toml`
6. Create `modules/<module-id>/config/agent.example.toml`
7. Create `modules/<module-id>/tests/integration.rs` with at least one test per component
8. Create `modules/<module-id>/docs/README.md`

Follow the patterns in modules/ssh-protection/ as reference for structure and style.
Follow all security rules in docs/module-authoring.md (dry_run, allowed_commands, no format! in args).
```

### Step 3 — Example prompt for a real module

```
I want to create a new InnerWarden module called "search-protection" that solves this problem:

Automated bots make expensive requests to our search API (/api/search), causing high database load.
We want to detect abusive clients and temporarily rate-limit or block them.

The module should:
- Collect data from: nginx access log at /var/log/nginx/access.log
- Detect this pattern: a single IP making more than 30 requests to /api/search within 60 seconds
- Respond with: block the IP via ufw for 10 minutes

Please create the full module structure following docs/module-authoring.md.
Use modules/ssh-protection/ as the structural reference.
The detector should track requests per IP per path with a sliding window.
The skill should reuse block-ip-ufw (already exists) — no new skill needed.
```

### Step 4 — Review the generated code

Before accepting the generated code, manually verify:

**Security checklist:**
- [ ] Skill checks `dry_run` before any system call
- [ ] `Command::new()` uses a literal path (not a variable or format string)
- [ ] Each `.arg()` call passes a single, validated value — no `sh -c` or shell string
- [ ] The skill command is listed in `module.toml [security].allowed_commands`
- [ ] No `unsafe` blocks

**Correctness checklist:**
- [ ] Detector returns `None` for unrelated event kinds (not just ignores them silently)
- [ ] Detector uses sliding window correctly (removes old entries before checking threshold)
- [ ] Collector's `source` string matches the config key
- [ ] `incident_id` format: `"detector_name:entity:timestamp"`
- [ ] Entities use `EntityRef::ip()` or `EntityRef::user()`
- [ ] `applicable_to()` lists the correct detector names
- [ ] `module.toml [[rules]]` references IDs that exist in `[provides]`

**Registration checklist (things AI often forgets):**
- [ ] Collector spawned in `crates/sensor/src/main.rs`
- [ ] Detector added to `DetectorSet` and called in `process_event()`
- [ ] Skill added to `SkillRegistry::default_builtin()`
- [ ] Config struct added to `crates/sensor/src/config.rs` if a new detector/collector

### Step 5 — Validate

```bash
innerwarden module validate ./modules/my-module
```

Fix any reported issues before proceeding.

### Step 6 — Run the tests

```bash
make test
```

All 195+ tests must pass. New tests from your module must also pass.

### Step 7 — Manual smoke test

```bash
# Build
make build

# Run sensor with your new config snippet active
make run-sensor

# Run agent
make run-agent

# Check the logs
tail -f ./data/events-*.jsonl
tail -f ./data/decisions-*.jsonl
```

### Step 8 — Register as a built-in (for PRs)

When the module is ready to be merged into the main codebase:

1. Move code from `modules/<id>/src/` to the appropriate crate (`crates/sensor/` or `crates/agent/`)
2. Set `builtin = true` in `module.toml`
3. Remove the `src/` directory from `modules/<id>/` (code now lives in crates)
4. Update `CLAUDE.md` — add the new capability to the relevant checklist section
5. Open a PR

---

## Common mistakes

| Mistake | Correct pattern |
|---------|----------------|
| `Command::new("sudo").arg(format!("ufw deny {ip}"))` | `Command::new("/usr/sbin/ufw").arg("deny").arg("from").arg(ip)` |
| Returning `Err(...)` in detector on bad event | Return `None` — detectors must be fail-open |
| Forgetting `dry_run` check in skill | Always first line: `if dry_run { return SkillResult { ... } }` |
| `incident_id = uuid::Uuid::new_v4().to_string()` | `format!("my_detector:{ip}:{}", ts.to_rfc3339())` — deterministic |
| `applicable_to: &[]` when skill is detector-specific | List specific detector names: `&["my-detector"]` |
| `auto_execute = true` in `[[rules]]` | Must be `false` by default — operator decides |

---

## Contributing a module

Community contributions are welcome. The process is a pull request to the main repository.

### What reviewers check

When your PR is reviewed, maintainers will run:

```bash
innerwarden module validate --strict modules/<your-id>
```

This checks:

| Category | What is verified |
|----------|-----------------|
| **Structure** | `module.toml`, `docs/README.md`, and `tests/` exist |
| **Manifest** | All required fields present; ID is kebab-case; version is semver; tier is `open` or `premium` |
| **Rules** | `[[rules]]` detectors and skills reference declared `[provides]` entries; `min_confidence` is in `[0.0, 1.0]` |
| **Docs** | README has `## Overview`, `## Configuration`, `## Security` sections and is at least 300 chars |
| **Security** | No `.arg(format!(...))` calls; no `sh -c` invocations; every skill checks `dry_run` before executing; `unsafe` blocks have `// SAFETY:` comments |

Validation failures block merge. Warnings are reviewed and may be accepted.

### Step-by-step submission

**1. Fork and branch**

```bash
git checkout -b module/<your-module-id>
```

**2. Create the module directory**

Follow the structure described above:

```
modules/your-module-id/
  module.toml
  docs/README.md
  tests/integration.rs
  config/your-module-id.example.toml   # optional
```

**3. Set `builtin = false`**

Community modules are external. Set `builtin = false` in `module.toml`. The `src/` directory holds your collector/detector/skill code if the module adds new logic.

**4. Validate locally**

```bash
cargo build --bin innerwarden --release
./target/release/innerwarden module validate --strict modules/your-module-id
```

All checks must pass before opening a PR.

**5. Run the test suite**

```bash
make test
```

Your module's tests must pass alongside the existing suite.

**6. Open a pull request**

Use the PR template. Fill in the **Module submission** section. The `Validate Modules` GitHub Actions workflow runs automatically on any PR that touches `modules/`.

**7. After merge**

Once merged, maintainers update `registry.toml` so the module becomes available via:

```bash
innerwarden module install your-module-id
```

### Branch naming

| PR type | Branch prefix |
|---------|---------------|
| New module | `module/<id>` |
| Fix existing module | `fix/module-<id>-<short-desc>` |
| Module docs update | `docs/module-<id>` |

### What makes a module accepted

- Solves a real, specific security problem
- Passes `innerwarden module validate --strict`
- Has at least one meaningful test
- `auto_execute = false` by default — operator must opt in to autonomous response
- `[security].allowed_commands` is minimal and accurate
- `docs/README.md` explains what the module does, what it requires, and what the security trade-offs are

---

## Existing modules (built-in)

| Module ID | Detectors | Skills | Tier |
|-----------|-----------|--------|------|
| [ssh-protection](../modules/ssh-protection/) | ssh-bruteforce, credential-stuffing | block-ip-* | Open |
| [network-defense](../modules/network-defense/) | port-scan | block-ip-* | Open |
| [sudo-protection](../modules/sudo-protection/) | sudo-abuse | suspend-user-sudo | Open |
| [file-integrity](../modules/file-integrity/) | — | — (webhook) | Open |
| [container-security](../modules/container-security/) | — | — (future) | Open |
| [threat-capture](../modules/threat-capture/) | — | monitor-ip, honeypot | Premium |
