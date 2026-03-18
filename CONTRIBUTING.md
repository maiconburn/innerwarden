# Contributing

Thanks for contributing to InnerWarden.

## Before You Start

InnerWarden is a self-defending security agent. It detects threats on the host and responds with bounded, auditable defensive actions. Please optimize for:

- deterministic sensor behavior
- fail-open design for collectors and sinks
- conservative defaults (dry-run, observe-only)
- explicit documentation for any behavioral change
- safety in response skills (bounded, reversible, audited)

## Development Workflow

1. Create a topic branch.
2. Implement the change.
3. Run the local validation gate:

```bash
make check
make test
```

4. Update documentation affected by the change.
5. Open a pull request with a clear description of behavior, risk, and validation.

## Documentation Rule

If a change affects any of the following, update docs in the same PR:

- detection or response capabilities
- generated artifacts
- configuration
- deployment/update flow
- operational safety guidance

In practice, that often means updating one or more of:

- `README.md`
- `CLAUDE.md`
- files under `docs/`

## Commit Style

- Prefer concise commit messages in English.
- Keep commits coherent and reviewable.
- Avoid mixing unrelated refactors with behavior changes.

## Pull Request Expectations

Please include:

- what changed
- why it changed
- any migration or rollout impact
- commands you used to validate it

If you changed response skills, detection logic, or incident schemas, call that out explicitly.

## Scope Guidance

Good contributions:

- new detectors or detector improvements
- new response skills
- operational safety improvements
- test coverage and replay coverage
- documentation and setup guides
- module authoring

Changes that need extra care:

- auto-execution defaults
- new privileged response skills
- privacy-sensitive data collection
- schema-breaking output changes

## Questions

If you are unsure whether a change fits the project's current direction, open an issue or draft PR first.
