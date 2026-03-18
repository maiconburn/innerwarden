# Integration Recipes

InnerWarden can ingest events from any external security tool — Falco, Wazuh,
osquery, Suricata, and others — by writing a **collector** for that tool.

A **recipe** is a TOML file that describes a tool integration precisely enough
that a human, or an AI assistant, can generate a working InnerWarden collector
from it without needing to read the source tool's codebase.

The recipe does not contain Rust code. It describes the contract — input
format, field mappings, severity translations — and the collector author (or
an AI) uses it alongside the [module authoring guide](module-authoring.md) to
produce the implementation.

---

## How It Works

```
recipe.toml
    │
    ├─── describes ──► input mechanism (file_tail / subprocess / unix_socket / http)
    ├─── describes ──► event JSON schema (field names, types, example)
    ├─── describes ──► field mappings (tool field → Event field)
    ├─── describes ──► severity mappings (tool severity label → Severity enum)
    ├─── describes ──► entity extraction (how to get IP / user / container)
    └─── describes ──► config surface (what the user configures)
         │
         ▼
    [human or AI] reads recipe + module-authoring.md + collector pattern
         │
         ▼
    FooCollector (Rust) + module.toml + docs/README.md
         │
         ▼
    innerwarden module validate ./modules/foo-integration
         │
         ▼
    (optional) contribute to community registry
```

---

## Generating a Collector with an AI Assistant

Give your AI assistant the following context in a single prompt:

```
Context files (paste or attach):
  1. docs/integration-recipes.md      ← this file
  2. docs/module-authoring.md         ← module structure guide
  3. integrations/<tool>/recipe.toml  ← the specific recipe
  4. crates/core/src/event.rs         ← Event + Severity types
  5. crates/core/src/entities.rs      ← EntityRef constructors
  6. crates/sensor/src/collectors/docker.rs  ← reference collector pattern

Prompt:
  "Using the recipe in recipe.toml and following the InnerWarden collector
   pattern shown in docker.rs, generate:
   - crates/sensor/src/collectors/<id>.rs  (the collector)
   - modules/<id>-integration/module.toml
   - modules/<id>-integration/config/sensor.example.toml
   - modules/<id>-integration/docs/README.md

   The collector must be fail-open, async, send Event structs over the mpsc
   channel, and match all field/severity mappings in the recipe exactly."
```

The recipe is designed so that this prompt reliably produces a correct first
draft with minimal iteration.

---

## Recipe Format Reference

A recipe is a TOML file at `integrations/<tool>/recipe.toml`.

### `[recipe]` — metadata

```toml
[recipe]
id          = "falco"                   # used as collector_id and module prefix
name        = "Falco Runtime Security"
description = "Short description shown in innerwarden list"
tool        = "falco"                   # external tool name
tool_url    = "https://falco.org"
tool_version_min = "0.36"              # oldest tested version
collector_id = "falco_log"             # sensor config key: [collectors.falco_log]
author      = ""
license     = "Apache-2.0"
```

### `[input]` — how the tool outputs data

```toml
[input]
mechanism       = "file_tail"   # see: Mechanisms below
path_config_key = "path"        # sensor config key that holds the file path
path_default    = "/var/log/falco/falco.log"
format          = "jsonl"       # jsonl | text | binary
restart_on_eof  = true          # re-tail after EOF (handles log rotation)
reconnect_secs  = 5
```

**Mechanisms:**

| Value | Description | Reference collector |
|-------|-------------|-------------------|
| `file_tail` | Tail a log file line by line | `auth_log.rs`, `exec_audit.rs` |
| `subprocess_stdout` | Spawn a subprocess, read its stdout | `docker.rs`, `journald.rs` |
| `unix_socket` | Connect to a Unix domain socket (JSON stream) | *(new)* |
| `http_poll` | Poll an HTTP endpoint periodically | *(new)* |
| `grpc_stream` | Consume a gRPC streaming API | *(new)* |

### `[event_schema]` — raw event fields

Describe what one raw event looks like. Use dot notation for nested fields.

```toml
[event_schema]
ts_field      = "time"          # field containing the timestamp
ts_format     = "rfc3339"       # rfc3339 | unix_sec | unix_ms | strptime:<fmt>
summary_field = "output"        # human-readable description
severity_field = "priority"     # tool's severity label
kind_field    = "rule"          # event type / rule name
tags_field    = "tags"          # optional: array of string tags
extra_fields  = ["source", "output_fields"]  # additional fields → Event.details
```

Include a representative example in `[event_schema.example]`:

```toml
[event_schema.example]
raw = '''
{"output":"15:00:00 A shell was spawned in a container","priority":"Warning",
 "rule":"Terminal shell in container","source":"syscall",
 "tags":["container","shell","mitre_execution"],
 "time":"2026-03-15T15:00:00.000000000Z",
 "output_fields":{"container.id":"abc123def456","proc.name":"bash","user.name":"root"}}
'''
```

### `[severity_map]` — severity translation

```toml
[severity_map]
"Emergency"     = "critical"
"Alert"         = "critical"
"Critical"      = "critical"
"Error"         = "high"
"Warning"       = "high"
"Notice"        = "medium"
"Informational" = "low"
"Debug"         = "debug"
```

Valid InnerWarden severities: `debug` `info` `low` `medium` `high` `critical`.
Any unmapped value should default to `"info"`.

### `[kind_format]` — `Event.kind` string

```toml
[kind_format]
# Available tokens: {source} {rule} {rule_slug} {priority}
# rule_slug = rule lowercased with spaces and special chars → underscores
template = "falco.{rule_slug}"
```

Examples: `falco.terminal_shell_in_container`, `wazuh.sshd_brute_force`.

### `[[entity_extraction.rules]]` — extracting entities

```toml
[[entity_extraction.rules]]
field       = "output_fields.fd.sip"    # dot-path into the raw event JSON
entity_type = "ip"                      # ip | user | container | path | service
optional    = true                      # if true, skip silently when absent
transform   = "none"                    # none | short_id_12 | trim_whitespace

[[entity_extraction.rules]]
field       = "output_fields.user.name"
entity_type = "user"
optional    = true

[[entity_extraction.rules]]
field       = "output_fields.container.id"
entity_type = "container"
optional    = true
transform   = "short_id_12"
```

### `[tags]` — event tags

```toml
[tags]
static              = ["falco", "kernel", "ebpf"]  # always present
dynamic_from_event  = true   # also copy tags from the event's tags_field
```

### `[[config_schema.fields]]` — user-configurable fields

```toml
[[config_schema.fields]]
key         = "path"
type        = "string"
required    = false
default     = "/var/log/falco/falco.log"
description = "Path to Falco JSON log file"

[[config_schema.fields]]
key         = "enabled"
type        = "bool"
required    = false
default     = "false"
description = "Enable the Falco collector"
```

### `[[prerequisites]]` — what must exist

```toml
[[prerequisites]]
kind   = "binary_exists"
value  = "/usr/bin/falco"
reason = "Falco must be installed"

[[prerequisites]]
kind   = "file_readable"
value  = "{config.path}"
reason = "Falco log file must be readable"
```

### `[setup_notes]` — instructions shown at install time

```toml
[setup_notes]
required_tool_config = """
Add to /etc/falco/falco.yaml:
  json_output: true
  json_include_output_property: true
  file_output:
    enabled: true
    keep_alive: false
    filename: /var/log/falco/falco.log
"""
```

### `[module_manifest]` — how this becomes a module

```toml
[module_manifest]
module_id            = "falco-integration"
module_tier          = "open"
incident_passthrough = true   # Falco events are already threat detections;
                               # High/Critical events are promoted to incidents
                               # directly (no additional detector needed)
```

When `incident_passthrough = true`, the generated collector (or a thin shim in
the agent) promotes events at `high` or `critical` severity directly to
`incidents-YYYY-MM-DD.jsonl` without running them through an InnerWarden
detector. This is appropriate for tools that already perform detection
internally (Falco, Wazuh, Suricata).

---

## Community Contribution Flow

After you generate and test a collector:

1. Run `innerwarden module validate ./modules/<id>-integration`
2. Run `make test` — all 320 existing tests must still pass; add your own
3. Open a PR to `https://github.com/InnerWarden/innerwarden`
4. The maintainer reviews, merges, and publishes to the community registry
5. Other users can then `innerwarden module install <id>-integration`

If you used an AI to generate the collector, include the recipe and the
generation prompt in the PR description. This helps reviewers verify
correctness quickly.

---

## Existing Recipes

| Recipe | Tool | Mechanism | Status |
|--------|------|-----------|--------|
| [`integrations/falco/recipe.toml`](../integrations/falco/recipe.toml) | Falco | `file_tail` | reference |

---

## Adding a New Recipe

To add a recipe for a new tool:

1. Create `integrations/<tool>/recipe.toml` following the format above
2. Include a real `[event_schema.example]` from that tool's actual output
3. Map every severity label the tool emits
4. Cover all entity extraction paths you know about (mark unknown ones
   `optional = true`)
5. Add a row to the table above
6. Open a PR — recipes without Rust code are low-friction contributions

You do not need to write the collector Rust code to contribute a recipe.
A recipe alone is valuable: it lets anyone (or an AI) generate the collector
later.
