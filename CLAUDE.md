# Inner Warden — CLAUDE.md

Agente leve de observabilidade de host. Coleta eventos de segurança (SSH, integridade de arquivos, journald, Docker), detecta incidentes e grava saída em JSONL.

---

## Arquitetura

```
collectors → mpsc::channel(1024) → main loop → detectors → sinks
                                                           ↘ JSONL (events / incidents)
                                                           ↘ state.json (cursors)
```

- **Collectors** rodam cada um em sua própria `tokio::task`. Usam `spawn_blocking` para I/O de arquivo. Enviam `Event` pelo canal.
- **Main loop** drena o canal via `tokio::select!`, passa cada evento pelos detectores e grava no sink.
- **Detectors** são síncronos, stateful, vivem no main loop.
- **Sinks** gravam JSONL append-only com rotação diária.
- **State** persiste cursors (offset auth_log, hashes de integridade, cursor journald, since docker) em `state.json` via escrita atômica (`.tmp` → rename).

### Shutdown

`SIGINT` e `SIGTERM` são capturados via `tokio::select!`. Ao sair: flush JSONL → ler Arcs compartilhados → salvar state.json.

---

## Workspace

```
crates/
  core/   — tipos compartilhados: Event, Incident, EntityRef, Severity
  agent/  — binário principal (innerwarden)
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
tools/
  narrator/narrate.py  — resumo Markdown dos JSONLs (Python 3.10+)
examples/
  systemd/innerwarden.service
  cron/innerwarden-narrate.cron
```

---

## Comandos essenciais

```bash
# Build e teste local (cargo não está no PATH padrão)
make test           # 26 testes unitários
make build          # debug build
make run            # roda com config.test.toml

# Cross-compile para Linux arm64 (requer cargo-zigbuild + zig)
make build-linux    # → target/aarch64-unknown-linux-gnu/release/innerwarden

# Deploy (ajustar HOST=user@servidor)
make deploy HOST=ubuntu@1.2.3.4
make deploy-config HOST=ubuntu@1.2.3.4   # copia config.prod.toml
make deploy-service HOST=ubuntu@1.2.3.4  # instala e habilita systemd unit

# Logs remotos
make logs HOST=ubuntu@1.2.3.4
make status HOST=ubuntu@1.2.3.4
```

`cargo` fica em `~/.cargo/bin/cargo` — o Makefile já resolve isso via `CARGO` variable.

---

## Configuração

Arquivo TOML. Exemplo mínimo para produção (Ubuntu arm64):

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

Dois arquivos por dia em `data_dir/`:
- `events-YYYY-MM-DD.jsonl` — um JSON por linha
- `incidents-YYYY-MM-DD.jsonl` — um JSON por linha

Ver `docs/format.md` para schema completo.

State de cursors: `data_dir/state.json`.

---

## Testes

```bash
make test   # roda todos os 26 testes unitários
```

Fixtures em `testdata/`:
- `sample-auth.log` — 20 linhas SSH (9 falhas de 203.0.113.10, 8 de 198.51.100.5)
- `watched/sshd_config`, `watched/sudoers` — fixtures para integrity watcher

Testes de integração local:
```bash
make run        # roda até Ctrl+C, grava em ./data/
cat data/state.json          # verificar cursors persistidos
wc -l data/events-*.jsonl    # contar eventos
```

---

## Convenções

- **Commits em inglês** — sem mensagens em português.
- Cada collector: `run(tx, shared_state)` — async, falha com `Ok(())` (fail-open), nunca derruba o agente.
- Erros de I/O nos sinks: logar com `warn!`, não propagar com `?`.
- Novos tipos de evento: `source` descreve a origem (`"auth.log"`, `"journald"`, `"docker"`, `"integrity"`), `kind` descreve o evento (`"ssh.login_failed"`, `"container.oom"`, etc.).
- `Event.details`: manter pequeno (< 16KB). Não incluir payloads arbitrários.
- `spawn_blocking` para qualquer I/O de arquivo síncrono dentro de tasks Tokio.

---

## Known issues / próximos passos

- `process_event()` propaga erros de write com `?` — muda para `warn!` + continua (ver análise de eficiência).
- Flush do JSONL é por contagem (a cada 50 eventos) — adicionar flush por tempo (5s interval).
- journald: double parse JSON por linha não-interessante — refatorar para parse único.
- `install.sh`: config template tem campo `socket` em `[collectors.docker]` (ignorado pelo serde, mas confuso).
- `narrate.py`: linha 99 usa f-string com aspas aninhadas (Python 3.12+) — incompatível com Ubuntu 22.04 (Python 3.10).
