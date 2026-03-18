# slack-notify

Sends InnerWarden incident alerts to a Slack channel via an Incoming Webhook.

## What it does

When an incident at or above the configured severity threshold is detected,
InnerWarden posts a structured Block Kit message to the configured Slack
channel:

```
🔴 HIGH — SSH Brute-Force Detected
9 failed login attempts from 203.0.113.10 within 5 minutes

Host: `web-01`  |  IP: `203.0.113.10`  |  `ssh_bruteforce:203.0.113.10`

[ Investigate → ]
```

The message includes:
- **Severity badge + emoji** — coloured sidebar line (🚨 critical, 🔴 high, 🟠 medium, 🟡 low)
- **Title and summary** from the incident
- **Host, entity, and incident ID** in a context row
- **Deep-link button** to the InnerWarden dashboard (optional)

## When to use it

- You want real-time security alerts in a Slack channel alongside your team
- You want to complement Telegram approvals (T.2) with passive Slack visibility
- Free Incoming Webhooks — no Slack API token, no OAuth, no rate-limit issues

## Setup

### 1. Create an Incoming Webhook

1. Go to your Slack workspace → **Apps** → search **Incoming Webhooks**
2. Click **Add to Slack**
3. Choose a channel (e.g. `#security-alerts`)
4. Copy the **Webhook URL** — it looks like:
   `https://hooks.slack.com/services/T.../B.../...`

### 2. Configure InnerWarden

Add to your `agent.toml`:

```toml
[slack]
enabled       = true
webhook_url   = ""          # or set SLACK_WEBHOOK_URL env var
min_severity  = "high"      # minimum severity to notify
dashboard_url = ""          # optional: enables "Investigate →" button
```

Or set via environment:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... innerwarden-agent
```

### 3. Validate

```bash
innerwarden doctor
```

The doctor checks that `SLACK_WEBHOOK_URL` is set and matches the expected
format when `slack.enabled = true`.

## Privacy note

Only the incident metadata (title, summary, severity, host, entities) is sent
to Slack. No log lines, raw events, or attacker-controlled strings are
included in the notification.

## What it does NOT do

- Does not send T.2-style approvals (use Telegram for interactive approvals)
- Does not report decisions back to Slack — only incident notifications
- Does not affect detection or AI triage
