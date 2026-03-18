# file-integrity

Monitors critical system files for unexpected changes using SHA-256 polling.

## Overview

The `integrity` collector computes SHA-256 hashes for a configured list of paths on a regular interval. When a hash changes, a `file.changed` event is emitted. The AI assesses the change and routes an alert via webhook.

Unlike other modules, file-integrity does **not** include an automated blocking skill — file changes require human review to determine intent before any response.

## Configuration

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `integrity.poll_seconds` | 60 | How often to re-hash watched files |
| `integrity.paths` | `[]` | List of absolute file paths to monitor |

## Recommended files to watch

```toml
paths = [
  "/etc/ssh/sshd_config",
  "/etc/sudoers",
  "/etc/passwd",
  "/etc/shadow",
  "/etc/crontab",
  "/etc/hosts",
]
```

## Security

- Polling is read-only — no system modifications
- Hash computation runs in a blocking thread pool (does not block the async runtime)
- Large files are hashed incrementally — no memory spike

## Source code

- Collector: `crates/sensor/src/collectors/integrity.rs`
