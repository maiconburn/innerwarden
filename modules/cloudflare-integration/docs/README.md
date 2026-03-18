# cloudflare-integration

Push IP block decisions from InnerWarden to Cloudflare's edge via IP Access Rules.

## What it does

When InnerWarden's AI decides to block an attacking IP at the host firewall (via `block-ip-ufw`, `block-ip-iptables`, or any other block-ip skill), this integration also pushes the block to Cloudflare's IP Access Rules API. The IP is then denied at the CDN edge **before** malicious traffic reaches the server at all.

This provides defence-in-depth: host-level blocking stops traffic that bypasses the CDN; Cloudflare-level blocking stops volumetric or L7 attacks that the host firewall sees too late.

## When to use

Enable this integration when:

- Your server sits behind Cloudflare (orange-clouded DNS).
- You want to act on attacker IPs at the CDN layer immediately after InnerWarden detects and blocks them on the host.
- You are dealing with SSH brute-force, port-scan, or web-scanner incidents from the same IPs that reach both your CDN and your host directly.

## Prerequisites

- A Cloudflare account with the target domain configured.
- The **Zone ID** for the domain (found on the Cloudflare dashboard → Overview → right sidebar).
- A Cloudflare **API token** with the `Zone > Firewall Services > Edit` permission.
  - Go to Cloudflare dashboard → My Profile → API Tokens → Create Token.
  - Use the "Edit zone DNS" template as a starting point, then change the permission to `Zone > Firewall Services > Edit`.
  - Scope the token to the specific zone.

> **Note:** IP Access Rules work on all Cloudflare plans (Free, Pro, Business, Enterprise). Advanced rate limiting requires Pro or higher and is outside the scope of this integration.

## How to configure

Add the following section to your `agent.toml`:

```toml
[cloudflare]
enabled = true
zone_id = "abc123..."           # Zone ID from Cloudflare dashboard
api_token = ""                  # Leave empty and set CLOUDFLARE_API_TOKEN env var instead
auto_push_blocks = true         # Push every successful block_ip decision to Cloudflare
block_notes_prefix = "innerwarden"  # Prefix added to the rule note in Cloudflare
```

Alternatively, set the API token via environment variable (recommended for production):

```bash
export CLOUDFLARE_API_TOKEN=your-token-here
```

Or add it to `/etc/innerwarden/agent.env`:

```
CLOUDFLARE_API_TOKEN=your-token-here
```

## Behaviour

- Runs **after** the host-level block skill executes successfully.
- Uses Cloudflare's [IP Access Rules API](https://developers.cloudflare.com/api/operations/ip-access-rules-for-a-zone-create-an-ip-access-rules) with `mode: "block"`.
- The Cloudflare rule note includes the InnerWarden incident ID and AI reason, e.g.:
  `innerwarden: ssh_bruteforce:20240315T142300Z: SSH brute-force from 1.2.3.4`
- **Fail-silent:** if the Cloudflare API is unreachable, rate-limited, or returns an error, a warning is logged and the agent continues normally. Cloudflare unavailability never blocks InnerWarden's own decision pipeline.
- The Cloudflare rule ID is logged at `INFO` level on success for auditability.

## Limitations

- This integration does not manage Cloudflare rule expiry or cleanup. Rules created via the API persist until manually removed or until you implement your own cleanup.
- IP Access Rules are per-zone. If you have multiple zones, configure a separate token and zone ID, or manage multi-zone via Cloudflare's account-level rules (not supported by this integration).
- The API token must have write access to Firewall Services for the target zone.
