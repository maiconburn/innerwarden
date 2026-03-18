# sudo-protection

Detects abusive sudo activity and temporarily suspends sudo access for the offending user.

## Overview

The `sudo-abuse` detector analyzes `sudo.command` events from journald (sudo unit). When a user runs too many suspicious privileged commands in a short window, an incident is raised. The `suspend-user-sudo` skill responds by writing a sudoers drop-in that denies all sudo for that user for a configurable TTL, then automatically removes the drop-in after expiry.

## What counts as "suspicious"

The detector classifies commands by risk pattern (e.g., `passwd`, `chown`, `chmod 777`, `curl | sh`, editing `/etc/sudoers`). Routine admin commands do not count toward the threshold.

## Skill behavior

`suspend-user-sudo`:
1. Writes `/etc/sudoers.d/zz-innerwarden-deny-<user>` with `<user> ALL=(ALL) !ALL`
2. Validates with `visudo -cf` before installing
3. Schedules automatic removal after `duration_secs` (default: 1 hour)
4. In `dry_run = true`: logs the intended action, writes no files

## Configuration

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `sudo_abuse.threshold` | 3 | Suspicious sudo commands per user before triggering |
| `sudo_abuse.window_seconds` | 300 | Sliding window duration |
| `ai.confidence_threshold` | 0.85 | Higher than default — privilege actions are sensitive |

## Security

- Recommend `dry_run = true` until you understand the noise level on your host
- Ensure the `innerwarden` system user has sudoers permission to manage `/etc/sudoers.d/`
- The `exec_audit` collector (shell trail) is optional — enable only with explicit host owner consent

## Source code

- Collector: `crates/sensor/src/collectors/journald.rs`, `crates/sensor/src/collectors/exec_audit.rs`
- Detector: `crates/sensor/src/detectors/sudo_abuse.rs`
- Skill: `crates/agent/src/skills/builtin/suspend_user_sudo.rs`
