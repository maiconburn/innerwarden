# Agent Capabilities

`innerwarden-agent` — intelligent triage, AI decision-making, skill execution, and operational interfaces.

## Core Loop

Two independent loops in the same `tokio::select!`:
- **Fast loop (2s)** — incidents + webhook + Telegram T.1 + AI + skill execution + audit trail
- **Slow loop (30s)** — narrative generation (throttled to 5-minute minimum interval), telemetry, data retention

## Incident Processing Pipeline

```
incidents-*.jsonl
      ↓
Algorithm gate: skip low-severity, private IPs, already-blocked
      ↓
Deduplication (same IP in same tick)
      ↓
Decision cooldown check (1h per action:detector:entity scope)
      ↓
AbuseIPDB enrichment (if enabled) → auto-block gate
      ↓
GeoIP enrichment (if enabled)
      ↓
AI provider (OpenAI / Anthropic / Ollama) → AiDecision { action, confidence }
      ↓
Circuit breaker / rate limiter check
      ↓
Confidence threshold + auto_execute check
      ↓
Skill execution → decisions-*.jsonl audit trail
      ↓
Webhook + Telegram + Slack notifications
```

## AI Providers

12 providers supported via OpenAI-compatible API or native SDK:

| Provider | Default model | Notes |
|----------|--------------|-------|
| OpenAI | gpt-4o-mini | Native API |
| Anthropic | claude-haiku-4-5-20251001 | Native API |
| Ollama | llama3.2 | Fully local, no API key |
| Groq | llama-3.3-70b-versatile | Fast inference |
| DeepSeek | deepseek-chat | OpenAI-compatible |
| Mistral | mistral-small-latest | OpenAI-compatible |
| xAI | grok-2-latest | OpenAI-compatible |
| Gemini | gemini-2.0-flash | OpenAI-compatible endpoint |
| OpenRouter | meta-llama/llama-3.3-70b-instruct | Multi-model gateway |
| Together AI | meta-llama/Llama-3.3-70B-Instruct-Turbo | OpenAI-compatible |
| Fireworks | accounts/fireworks/models/llama-v3p3-70b-instruct | OpenAI-compatible |
| Cerebras | llama-3.3-70b | OpenAI-compatible |

Dynamic model discovery: `innerwarden configure ai` fetches available models from the provider's `/v1/models` endpoint.

All providers implement `AiProvider` trait; `Arc<dyn AiProvider>` in `AgentState`.

## Skills (Response Actions)

| Skill ID | What it does |
|----------|-------------|
| `block-ip-ufw` | `ufw deny from <IP>` |
| `block-ip-iptables` | `iptables -A INPUT -s <IP> -j DROP` |
| `block-ip-nftables` | `nft add element ... { <IP> }` |
| `block-ip-pf` | `pfctl -t innerwarden-blocked -T add <IP>` (macOS) |
| `suspend-user-sudo` | Drop-in file in `/etc/sudoers.d/` with TTL; auto-cleanup on expiry |
| `rate-limit-nginx` | nginx-layer deny (HTTP 403) with TTL + auto-cleanup |
| `monitor-ip` | Limited traffic capture via `tcpdump` + sidecar metadata `.pcap` |
| `kill-process` | Terminates all processes for a compromised user. TTL-bounded. |
| `block-container` | Pauses a Docker container. Auto-unpauses after TTL. |
| `honeypot` | SSH/HTTP decoy with LLM-powered shell, credential capture |

All skills: bounded, audited, reversible. Dry-run logs what would happen without executing.

## Blocklist

- In-memory, persisted across ticks
- Inserted immediately after any `block_ip` decision (even in dry-run) to prevent re-evaluation
- Pre-loaded from `decisions-*.jsonl` at startup (today + yesterday) to survive restarts

## Notification Channels

**Webhook** — HTTP POST to any endpoint; severity filter; fires on fast tick (real-time)

**Telegram T.1** — push notification for every High/Critical incident; severity badge, source icon, entity summary, optional dashboard deep-link

**Telegram T.2** — bidirectional approval via inline keyboard (✅ Approve / ❌ Reject); long-poll task (25s); TTL configurable (default 10 min); audit trail with `ai_provider: "telegram:<operator>"`

**Telegram T.3** — conversational bot: `/status`, `/help`, `/incidents`, `/decisions`, `/ask <question>`, free-text→AI; `/menu` inline keyboard; 10 tests

**Slack** — Incoming Webhook with Block Kit; emoji + colored sidebar + context row + optional dashboard deep-link

**Telegram daily summary** — `TelegramConfig.daily_summary_hour: Option<u8>`; sends daily Markdown summary at local configured hour (max once per day)

## Dashboard

Local authenticated HTTP server (`--dashboard`). HTTP Basic auth required.

**Tabs:**
- **Investigate** — entity timeline, journey viewer, pivots, clusters, export
- **Report** — operational metrics, trends, anomaly hints, top IPs, incidents by type

**Key endpoints:**
| Endpoint | Purpose |
|----------|---------|
| `GET /api/status` | services, guard mode, capabilities |
| `GET /api/collectors` | sensor collector status (ACTIVE/DETECTED/NOT FOUND) with event counts |
| `GET /api/entities` | entity list with incident counts |
| `GET /api/journey` | full IP/user timeline (D2.1) |
| `GET /api/pivots` | filters + pivots by ip/user/detector (D2.2) |
| `GET /api/clusters` | incident clusters (D2.3) |
| `GET /api/export` | JSON/Markdown snapshot export |
| `GET /api/quickwins` | actionable suggestions for unhandled High/Critical IPs |
| `GET /api/report` | computed trial report for a given date |
| `GET /api/report/dates` | available report dates |
| `GET /api/events/stream` | SSE live push (D6); heartbeat 30s; file watcher 2s |
| `POST /api/action/block-ip` | operator block action (requires `responder.enabled = true`) |
| `POST /api/action/suspend-user` | operator suspend action |
| `GET /api/action/config` | action config (enabled/disabled, dry-run mode) |

**Dashboard phases shipped:**
- D2 — Clarity-style investigation UX: entity journey, pivot filters, cluster view, snapshot export, guided investigation with narrative hints, temporal comparison, deep-link
- D3 — Operator actions: block IP, suspend user, mandatory reason field, confirmation modal with mode badge (DRY RUN / LIVE), toast feedback, full audit trail
- D4 — Visual redesign: navy `#040814` palette, cyan accent `#78e5ff`, danger `#f43f5e`, radial gradients, modern border-radius, mobile UX (collapsible panel, touch targets)
- D5 — Attacker path viewer: verdict card (entry vector, access status, privilege status, containment, honeypot), chapter rail (recon, initial access, access success, privilege abuse, response, containment, honeypot), evidence cards
- D6 — SSE live push: `fetch()+ReadableStream` (Basic auth compatible), auto-reconnect every 3s, `● LIVE` / `● reconnecting` indicator, poll fallback after 35s
- D7 — Live timeline: SSE triggers `refreshLeftLive()`; new entity cards with `cardSlideIn` animation; KPI values flash cyan (`kpiFlash`) on change; diff by `state.knownItemValues`
- D8 — Incident push alerts: file watcher reads new `incidents-*.jsonl` lines by byte offset; SSE `alert` event for High/Critical; `showAlertToast()` with colored badge, title, clickable link
- D9 — Inline entity search: `<input type="search">` filters cards client-side by any visible text; no round-trip; re-applied after `refreshLeft`/`refreshLeftLive`
- D10 — Report tab: `GET /api/report[?date=YYYY-MM-DD]`, date selector, KPIs, day-over-day trends, anomaly hints, operational health table, top IPs, incidents by type
- Mobile nav tab bar: nav moves to full-width second row below header; `flex-wrap: wrap` + `order: 10`; touch-friendly tab styling
- Protection Status UX: PROTECTED (green) / WATCHING (yellow) / MONITOR ONLY (gray) — replaces confusing red "GUARD"
- Sensor Collectors section: 10 collector cards with ACTIVE/DETECTED/NOT FOUND badges, event count, NATIVE/EXTERNAL badge
- Integration Advisor section: conflict detection (abuseipdb+fail2ban, telegram+slack), recommended next step

## Enrichment

**AbuseIPDB** — IP reputation lookup before AI call; injected into prompt as `IP REPUTATION (AbuseIPDB):`; fail-silent; `auto_block_threshold` (0-100, 0=disabled) — blocks known botnet IPs without calling AI; `ai_provider: "abuseipdb"` in audit trail; 6 tests

**GeoIP** — ip-api.com free (45 req/min, no API key); injected as `IP GEOLOCATION:`; `GeoInfo { country, country_code, city, isp, asn }`; fail-silent; 5 tests

## Integrations

**Fail2ban** — polls `fail2ban-client` CLI; bans not in blocklist are enforced via block skills; `ai_provider: "fail2ban:<jail>"`; 5 tests

**Cloudflare** — pushes blocked IPs to Cloudflare edge via IP Access Rules API; called after successful `block-ip-*` skill; `auto_push_blocks` config; fail-silent; 6 tests

## Reliability Features

- Incremental JSONL reading via byte-offset cursors (`agent-state.json`)
- Cursor fail-open: corrupted state file falls back to empty cursor (no crash)
- Audit trail with immediate flush per decision — survives crash between execution and shutdown
- `reqwest::Client` reused across AI calls (real connection pool)
- Decision cooldown (1h) pre-loaded from `decisions-*.jsonl` at startup
- AI rate limiting: `max_ai_calls_per_tick` (default 5); excess deferred to next tick
- AI circuit breaker: `circuit_breaker_threshold` suspends AI for tick when incident volume spikes; auto-reset after `circuit_breaker_cooldown_secs`
- `--once` mode for batch processing
- `--report` mode: generates operational trial report with day-over-day deltas + anomaly hints + 6h recent window

## Data Retention

Configurable in `[data]` section of `agent.toml`:
- `events_keep_days = 7`
- `incidents_keep_days = 30`
- `decisions_keep_days = 90`
- `telemetry_keep_days = 14`
- `reports_keep_days = 30`

Cleanup runs at startup and in the slow loop (30s).

## Output Files (per day)

| File | Writer | Content |
|------|--------|---------|
| `events-YYYY-MM-DD.jsonl` | sensor | One event per line |
| `incidents-YYYY-MM-DD.jsonl` | sensor | Detected incidents |
| `decisions-YYYY-MM-DD.jsonl` | agent | AI decisions with confidence, action, target, result |
| `telemetry-YYYY-MM-DD.jsonl` | agent | Operational snapshots (collectors, detectors, gate, AI, latency, errors) |
| `summary-YYYY-MM-DD.md` | agent | Daily Markdown narrative |
| `trial-report-YYYY-MM-DD.{md,json}` | agent | Operational trial report |
| `honeypot/listener-session-*.json` | agent | Honeypot session metadata |
| `honeypot/listener-session-*.jsonl` | agent | Per-connection evidence |
| `honeypot/listener-session-*.pcap` | agent | Optional forensic capture |
| `agent-state.json` | agent | JSONL read cursors by date |
