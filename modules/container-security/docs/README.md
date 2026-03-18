# container-security

Monitors Docker container lifecycle events for operational anomalies.

## Overview

The `docker` collector subscribes to the Docker events stream and emits structured events for container start, stop, die, and OOM (out-of-memory kill). These events appear in the dashboard timeline and are included in the AI correlation context.

## Current scope

This module currently provides **observability only**. No automated response skill is included yet. A container that crashes repeatedly or gets OOM-killed will appear in incident correlation context, where the AI can raise it as contributing evidence to a broader incident.

## Future

A future detector may identify: rapid restart loops, unexpected container spawns, or containers escaping their expected network namespace. The module.toml `[[rules]]` section will be populated when that detector is implemented.

## Configuration

```toml
[collectors.docker]
enabled = true
```

No additional parameters. The collector streams Docker events automatically.

## Security

- The `innerwarden` user must be in the `docker` group — this grants significant system access
- The collector is read-only (subscribes to events, does not start/stop containers)
- No automated response is triggered — container events appear in the dashboard and AI correlation context only

## Prerequisites

The `innerwarden` system user must be in the `docker` group:

```bash
sudo usermod -aG docker innerwarden
```

## Source code

- Collector: `crates/sensor/src/collectors/docker.rs`
