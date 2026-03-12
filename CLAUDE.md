# Inner Warden — CLAUDE.md

Observabilidade de host com dois componentes Rust: **sensor** (coleta determinística) e **agent** (camada interpretativa).

---

## Arquitetura

```
host activity → innerwarden-sensor → JSONL outputs → innerwarden-agent → narrative / alerts
```

### Sensor (innerwarden-sensor)

```
collectors → mpsc::channel(1024) → main loop → detectors → sinks
                                                           ↘ events-YYYY-MM-DD.jsonl
                                                           ↘ incidents-YYYY-MM-DD.jsonl
                                                           ↘ state.json (cursors)
```

- **Collectors** rodam cada um em sua própria `tokio::task`. Usam `spawn_blocking` para I/O de arquivo. Enviam `Event` pelo canal.
- **Main loop** drena o canal via `tokio::select!`, passa cada evento pelos detectores e grava no sink.
- **Detectors** são síncronos, stateful, vivem no main loop.
- **Sinks** gravam JSONL append-only com rotação diária.
- **State** persiste cursors (offset auth_log, hashes de integridade, cursor journald, since docker) em `state.json` via escrita atômica (`.tmp` → rename).
- **Shutdown**: `SIGINT`/`SIGTERM` via `tokio::select!` → flush JSONL → ler Arcs → salvar state.json.

### Agent (innerwarden-agent)

```
events/incidents JSONL → reader (byte-offset cursor) → correlation → narrative / model API
```

- Lê JSONL incrementalmente via byte offsets (cursor próprio em `agent-state.json`).
- Modos: `--once` (processa e sai) ou contínuo (poll a cada N segundos).
- Sem dependência de LLM/HTTP no sensor — toda inteligência interpretativa fica no agent.
- Preparado para futura integração com model APIs.

---

## Workspace

```
crates/
  core/     — tipos compartilhados: Event, Incident, EntityRef, Severity
  sensor/   — binário innerwarden-sensor
    src/
      main.rs
      config.rs
      collectors/
        auth_log.rs    — tail de /var/log/auth.log, parser SSH
        integrity.rs   — SHA-256 polling de arquivos
        journald.rs    — subprocess journalctl --follow --output=json
        docker.rs      — subprocess docker events --format '{{json .}}'
      detectors/
        ssh_bruteforce.rs  — sliding window por IP
      sinks/
        jsonl.rs       — DatedWriter com rotação diária
        state.rs       — load/save atômico de cursors
  agent/    — binário innerwarden-agent
    src/
      main.rs          — CLI + continuous/once mode + SIGTERM
      reader.rs        — JSONL incremental reader + AgentCursor persistence
examples/
  systemd/innerwarden-sensor.service
```

---

## Comandos essenciais

```bash
# Build e teste (cargo não está no PATH padrão)
make test             # 32 testes (26 sensor + 6 agent)
make build            # debug build de ambos
make build-sensor     # só o sensor
make build-agent      # só o agent

# Rodar localmente
make run-sensor       # sensor com config.test.toml
make run-agent        # agent lendo ./data/

# Cross-compile para Linux arm64 (requer cargo-zigbuild + zig)
make build-linux      # → target/aarch64-unknown-linux-gnu/release/innerwarden-{sensor,agent}

# Deploy (ajustar HOST=user@servidor)
make deploy HOST=ubuntu@1.2.3.4
make deploy-config HOST=ubuntu@1.2.3.4
make deploy-service HOST=ubuntu@1.2.3.4

# Logs remotos
make logs HOST=ubuntu@1.2.3.4
make status HOST=ubuntu@1.2.3.4
```

`cargo` fica em `~/.cargo/bin/cargo` — o Makefile resolve via `CARGO` variable.

---

## Configuração

Arquivo TOML (usado pelo sensor). Exemplo mínimo para produção:

```toml
[agent]
host_id = "meu-servidor"

[output]
data_dir = "/var/lib/innerwarden"
write_events = true

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.journald]
enabled = true
units = ["sshd", "sudo"]   # "sshd" não "ssh"

[collectors.docker]
enabled = true

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300
```

Config de teste local: `config.test.toml` (aponta para `./testdata/`).

O agent usa `--data-dir` para apontar ao mesmo diretório de saída do sensor.

---

## Permissões em produção (Ubuntu 22.04)

```bash
# Criar usuário dedicado
sudo useradd -r -s /sbin/nologin innerwarden

# Acesso ao journal sem root
sudo usermod -aG systemd-journal innerwarden

# Acesso ao socket Docker
sudo usermod -aG docker innerwarden

# Diretório de dados
sudo mkdir -p /var/lib/innerwarden
sudo chown innerwarden:innerwarden /var/lib/innerwarden
```

O `data_dir` no config.toml **deve** bater com `ReadWritePaths` no service file.

---

## Formato de saída (JSONL)

Dois arquivos por dia em `data_dir/` (contrato entre sensor e agent):
- `events-YYYY-MM-DD.jsonl` — um JSON por linha
- `incidents-YYYY-MM-DD.jsonl` — um JSON por linha

Ver `docs/format.md` para schema completo.

State do sensor: `data_dir/state.json`.
State do agent: `data_dir/agent-state.json` (byte offsets por data).

---

## Testes

```bash
make test   # roda todos os 32 testes (sensor + agent)
```

Fixtures em `testdata/`:
- `sample-auth.log` — 20 linhas SSH (9 falhas de 203.0.113.10, 8 de 198.51.100.5)
- `watched/sshd_config`, `watched/sudoers` — fixtures para integrity watcher

Testes de integração local:
```bash
make run-sensor                       # grava em ./data/
make run-agent                        # lê de ./data/
innerwarden-agent --data-dir ./data --once   # roda uma vez e sai
```

---

## Convenções

- **Commits em inglês** — sem mensagens em português.
- **Sensor**: determinístico, sem HTTP/LLM/AI. Collectors são fail-open (`Ok(())`).
- **Agent**: camada interpretativa. Pode chamar APIs externas quando necessário.
- Cada collector: `run(tx, shared_state)` — async, nunca derruba o agente.
- Erros de I/O nos sinks: logar com `warn!`, não propagar com `?`.
- Novos tipos de evento: `source` descreve a origem, `kind` descreve o evento.
- `Event.details`: manter pequeno (< 16KB). Não incluir payloads arbitrários.
- `spawn_blocking` para qualquer I/O de arquivo síncrono dentro de tasks Tokio.

---

## Known issues / próximos passos

- Sensor: `process_event()` propaga erros de write com `?` — trocar para `warn!` + continua.
- Sensor: flush do JSONL é por contagem (a cada 50 eventos) — adicionar flush por tempo (5s interval).
- Sensor: journald faz double parse JSON por linha não-interessante — refatorar para parse único.
- Agent: implementar correlação de eventos e agrupamento temporal.
- Agent: adicionar geração de narrativa e integração com model APIs.
