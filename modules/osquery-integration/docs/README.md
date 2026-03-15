# osquery-integration

Integrates [osquery](https://osquery.io) differential results with InnerWarden
as host observability events.

osquery exposes the operating system as a relational database — you write SQL
queries against tables like `listening_ports`, `processes`, `crontab`,
`sudoers`, `authorized_keys`, and hundreds more. Results are delivered as
differential logs: when a new row appears (something changed), osquery writes
it to the results log.

InnerWarden ingests these differential results and:
- Classifies them by security relevance (High for sudoers changes, Medium for
  new listening ports, etc.)
- Extracts IP and path entities for correlation in the attacker journey view
- Provides rich context to the AI triage layer alongside Falco/Suricata events

osquery events are **not** incidents by themselves — they are observability
signals. A new listening port on `/usr/bin/nc` becomes significant *in context*
of an active Falco alert or suspicious SSH session. The dashboard correlates
these automatically.

## Severity Classification

| Query name contains | Severity |
|---|---|
| `sudoers`, `suid_bin`, `authorized_keys`, `crontab_modified` | High |
| `listening_ports`, `startup_items`, `crontab`, `shell_history`, `logged_in_users`, `process_open_sockets` | Medium |
| `processes`, `users`, `groups`, `mounts`, `dns_resolvers` | Low |
| anything else | Info |

## Recommended Queries

Add these to `/etc/osquery/osquery.conf` for maximum InnerWarden coverage:

```json
{
  "schedule": {
    "listening_ports": {
      "query": "SELECT pid, port, protocol, address, path FROM listening_ports;",
      "interval": 60
    },
    "process_open_sockets": {
      "query": "SELECT pid, remote_address, remote_port, local_address, local_port FROM process_open_sockets WHERE remote_address NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1');",
      "interval": 60
    },
    "crontab": {
      "query": "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
      "interval": 300
    },
    "startup_items": {
      "query": "SELECT name, path, status, type FROM startup_items;",
      "interval": 300
    },
    "authorized_keys": {
      "query": "SELECT uid, algorithm, key, comment, key_file FROM authorized_keys;",
      "interval": 300
    },
    "sudoers": {
      "query": "SELECT source, header_tag, rule_details FROM sudoers;",
      "interval": 300
    }
  }
}
```

Or use the [osquery incident-response pack](https://github.com/osquery/osquery/blob/master/packs/incident-response.conf)
which covers all of the above and more:

```json
{
  "packs": {
    "incident-response": "/usr/share/osquery/packs/incident-response.conf"
  }
}
```

## Setup

### 1. Install osquery

```bash
# Ubuntu/Debian
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt-get update
sudo apt-get install osquery
```

### 2. Configure

Copy the example queries above into `/etc/osquery/osquery.conf` and restart:

```bash
sudo systemctl restart osqueryd
```

### 3. Enable in InnerWarden

```bash
innerwarden enable osquery-integration
```

Or manually:

```toml
[collectors.osquery_log]
enabled = true
path    = "/var/log/osquery/osqueryd.results.log"
```
