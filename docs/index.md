# InnerWarden — Documentation

## Start here

| Document | What it covers |
|----------|---------------|
| [README.md](../README.md) | Overview, install, CLI reference |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute code or modules |
| [SECURITY.md](../SECURITY.md) | Reporting vulnerabilities |
| [ROADMAP.md](../ROADMAP.md) | Planned features and milestones |
| [CHANGELOG.md](../CHANGELOG.md) | Release notes |

## Architecture and capabilities

| Document | What it covers |
|----------|---------------|
| [docs/sensor-capabilities.md](sensor-capabilities.md) | All collectors, detectors, and output format |
| [docs/agent-capabilities.md](agent-capabilities.md) | AI pipeline, skills, dashboard, notifications, enrichment |
| [docs/configuration.md](configuration.md) | Full TOML config reference + environment variables |
| [docs/operations.md](operations.md) | Build, deploy, CLI reference, permissions, service management |

## Extending InnerWarden

| Document | What it covers |
|----------|---------------|
| [docs/format.md](format.md) | JSONL output schema — Event, Incident, Decision fields |
| [docs/module-authoring.md](module-authoring.md) | How to build a custom detector, skill, or module |
| [docs/integration-recipes.md](integration-recipes.md) | Declarative recipe format for connecting external tools |
| [integrations/](../integrations/) | Ready-made recipes: Falco, Wazuh, osquery |

## For operators

| Document | What it covers |
|----------|---------------|
| [docs/integrated-setup.md](integrated-setup.md) | Full stack on Ubuntu 22.04: InnerWarden + Falco + Suricata + osquery + Telegram |
