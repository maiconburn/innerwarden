# Integration Recipes

This directory contains **integration recipes** — declarative specifications
that describe how to connect an external security tool to InnerWarden.

A recipe is precise enough that a human, or an AI assistant, can generate a
working InnerWarden collector from it without reading the external tool's
source code.

For the full specification, generation guide, and community contribution flow,
see [`docs/integration-recipes.md`](../docs/integration-recipes.md).

## Available Recipes

| Tool | Recipe | Mechanism | Incident passthrough |
|------|--------|-----------|----------------------|
| [Wazuh](https://wazuh.com) — HIDS, FIM, compliance | [`wazuh/recipe.toml`](wazuh/recipe.toml) | `file_tail` | yes (level ≥ 10) |
| [osquery](https://osquery.io) — host observability | [`osquery/recipe.toml`](osquery/recipe.toml) | `file_tail` | no |

## Adding a Recipe

You do not need to write Rust code to add a recipe. A recipe alone — describing
the tool's output format, field mappings, and entity extraction — is a
valuable contribution that lets anyone generate the collector later.

See [`docs/integration-recipes.md`](../docs/integration-recipes.md) for the
recipe format reference.
