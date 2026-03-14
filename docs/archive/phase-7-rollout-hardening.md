# Phase 7.1 — Production Rollout Hardening

Goal: enable InnerWarden in production with low risk, clear gates, and fast rollback.

## Scope

Included:
- Progressive enablement playbook (three stages)
- Pre-deploy and post-deploy smoke checks
- Minimal rollback commands
- Validation checklist for services, files, permissions, and `data_dir`

Not included:
- New AI providers
- Plugin marketplace or dynamic loading
- Multi-host centralization
- Real honeypot infrastructure

## Progressive Enablement

### Stage 1 — Observability only

Purpose: validate ingestion and artifacts without AI decisions or active response.

Recommended config (`/etc/innerwarden/agent.toml`):

```toml
[ai]
enabled = false

[responder]
enabled = false
```

Expected outcome:
- `events-*.jsonl`, `incidents-*.jsonl`, `summary-*.md` keep growing
- No active response execution

### Stage 2 — Semi-active (AI decides, no execution)

Purpose: validate decision quality and audit trail with zero enforcement risk.

Recommended config:

```toml
[ai]
enabled = true
confidence_threshold = 0.8

[responder]
enabled = false
```

Expected outcome:
- `decisions-*.jsonl` is generated
- No real execution (responder still disabled)

### Stage 3 — Active (single real skill, strict thresholds)

Purpose: controlled production enforcement with one skill and conservative policy.

Recommended config:

```toml
[ai]
enabled = true
confidence_threshold = 0.95

[responder]
enabled = true
dry_run = false
allowed_skills = ["block-ip-ufw"] # keep a single skill during first active rollout
```

Expected outcome:
- Real actions only for high-confidence decisions
- Scope limited to one execution path

## Pre-deploy smoke checks

Run from your workstation:

```bash
make rollout-precheck HOST=ubuntu@1.2.3.4
```

This validates:
- required binaries and config files
- `innerwarden` user and group prerequisites
- unit installation
- `data_dir` write permission for `innerwarden`

## Post-deploy smoke checks

Run after any deploy or stage change:

```bash
make rollout-postcheck HOST=ubuntu@1.2.3.4
```

This validates:
- `innerwarden-sensor` and `innerwarden-agent` are active
- core artifact files are present
- report generation works (`innerwarden-agent --report`)

## Fast rollback

Show rollback plan:

```bash
make rollout-rollback HOST=ubuntu@1.2.3.4
```

Emergency stop (agent only, keep sensor alive):

```bash
make rollout-stop-agent HOST=ubuntu@1.2.3.4
```

## Short rollout checklist

1. Run precheck and fix every failure before deploy.
2. Deploy binaries/config/service updates.
3. Run postcheck and inspect latest journals.
4. Keep each stage running long enough to observe stable behavior.
5. Promote to next stage only after explicit go/no-go.
6. If risk appears, rollback immediately to sensor-only mode.
