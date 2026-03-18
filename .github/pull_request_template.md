## Summary

## Type

- [ ] Bug fix
- [ ] New feature / capability
- [ ] New module (fill in the Module section below)
- [ ] Refactor / cleanup
- [ ] Docs / config only

## Validation

- [ ] `make check`
- [ ] `make test`

## Risk

- [ ] No config or schema changes
- [ ] Includes config or schema changes
- [ ] Includes responder or privileged behavior changes
- [ ] Includes dashboard or investigation UX changes

## Documentation

- [ ] No documentation updates needed
- [ ] Updated public docs
- [ ] Updated maintainer docs

---

## Module submission (fill in only for new modules)

**Module ID:** `my-module`
**Tier:** open / premium

### Checklist

- [ ] `modules/<id>/module.toml` — valid TOML, all required fields present, kebab-case ID
- [ ] `modules/<id>/docs/README.md` — has `## Overview`, `## Configuration`, `## Security` sections
- [ ] `modules/<id>/tests/` — at least one `.rs` test file (or `builtin = true` with tests in `crates/`)
- [ ] `[[rules]]` entries have `auto_execute = false` (default safe posture)
- [ ] Skills use separate `.arg()` calls — no `.arg(format!(...))` interpolation
- [ ] Skills check `dry_run` before executing any privileged command
- [ ] `[security].allowed_commands` lists every binary the module invokes
- [ ] `innerwarden module validate --strict modules/<id>` passes locally
