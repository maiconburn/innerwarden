# Wazuh Integration

Ingests [Wazuh HIDS](https://wazuh.com) alerts from `/var/ossec/logs/alerts/alerts.json`
and routes High/Critical severity incidents through InnerWarden's AI triage and response pipeline.

## What Wazuh provides

Wazuh is an open-source HIDS (Host Intrusion Detection System) that delivers:

- **HIDS/FIM** — host intrusion detection and file integrity monitoring
- **MITRE ATT&CK mapping** — rule groups include MITRE technique identifiers
- **Vulnerability detection** — CVE scanning for installed packages
- **Compliance** — PCI-DSS, HIPAA, NIST 800-53, CIS benchmark reporting
- **Centralized alerts** — multi-agent alerts collected at the Wazuh manager

## What InnerWarden does with Wazuh alerts

InnerWarden tails Wazuh's `alerts.json` log and:

1. Parses each alert into a structured `Event` with severity, kind, summary, tags, and entities
2. Extracts attacker IP (`data.srcip`), target user (`data.dstuser`), and agent name for pivoting
3. For alerts with rule level >= 10 (High/Critical), promotes the event directly to an `Incident`
4. Routes incidents through the AI triage layer for confidence scoring and response decision
5. Records all decisions in the audit trail (`decisions-YYYY-MM-DD.jsonl`)

Wazuh performs the detection; InnerWarden provides AI-assisted triage and automated response.

## Severity mapping

| Wazuh rule level | InnerWarden severity |
|-----------------|---------------------|
| 0–2             | Debug               |
| 3–6             | Low                 |
| 7–9             | Medium              |
| 10–11           | High                |
| 12–15           | Critical            |

Only High and Critical alerts (level >= 10) are promoted to incidents and sent to AI triage.

## Prerequisites

- Wazuh 4.7+ (agent or manager) installed on the monitored host
- `alerts_log_format: json` enabled in `ossec.conf` (see Setup below)
- InnerWarden sensor running on the same host (or with access to the alerts file)

## Setup

### 1. Enable JSON alerts in Wazuh

Edit `/var/ossec/etc/ossec.conf` and add inside `<global>`:

```xml
<global>
  <alerts_log>yes</alerts_log>
  <logall_json>yes</logall_json>
</global>
```

Restart Wazuh:

```bash
sudo /var/ossec/bin/wazuh-control restart
```

Verify the alerts file is being written:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

### 2. Ensure InnerWarden can read the alerts file

The `innerwarden` user must have read access:

```bash
sudo usermod -aG ossec innerwarden
# or grant explicit read access:
sudo chmod o+r /var/ossec/logs/alerts/alerts.json
```

### 3. Enable the collector in sensor config

Add to your `config.toml`:

```toml
[collectors.wazuh_alerts]
enabled = true
path    = "/var/ossec/logs/alerts/alerts.json"
```

### 4. Restart the sensor

```bash
sudo systemctl restart innerwarden-sensor
```

## Event format

Each Wazuh alert becomes an InnerWarden event with:

- `source`: `"wazuh"`
- `kind`: `"wazuh.<first_group>"` (e.g. `wazuh.authentication_failures`)
- `tags`: `["wazuh", "hids"]` + all `rule.groups` elements
- `entities`: attacker IP (if public), target user, agent name (as service)
- `details`: rule level, description, groups, agent, and data fields

## Example event kinds

| Wazuh rule.groups[0]        | InnerWarden kind                        |
|-----------------------------|-----------------------------------------|
| `authentication_failures`   | `wazuh.authentication_failures`         |
| `sshd`                      | `wazuh.sshd`                            |
| `rootcheck`                 | `wazuh.rootcheck`                       |
| `syslog`                    | `wazuh.syslog`                          |
| `web`                       | `wazuh.web`                             |
| `mitre_lateral_movement`    | `wazuh.mitre_lateral_movement`          |

## References

- [Wazuh documentation](https://documentation.wazuh.com/)
- [Wazuh alert fields reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [MITRE ATT&CK mapping in Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)
- [InnerWarden integration recipes](../../integrations/wazuh/recipe.toml)
