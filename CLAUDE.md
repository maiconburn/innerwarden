# Inner Warden — CLAUDE.md

Observabilidade e resposta autônoma de host com dois componentes Rust:
**sensor** (coleta determinística, zero AI) e **agent** (inteligência em tempo real).

---

## O que o sistema faz hoje

### Sensor (`innerwarden-sensor`)
- ✅ Tail de `/var/log/auth.log` com parser SSH completo (falhas, logins, usuários inválidos)
- ✅ Integração com `journald` (sshd, sudo, qualquer systemd unit)
- ✅ Monitoramento de Docker events (start / stop / die / OOM)
- ✅ Integridade de arquivos via SHA-256 polling configurável
- ✅ Detector de SSH brute-force (sliding window por IP, threshold configurável)
- ✅ Output JSONL append-only com rotação diária automática
- ✅ Fail-open: erros de I/O em collectors são logados, nunca derrubam o agente
- ✅ Flush duplo: por contagem (50 eventos) + por tempo (intervalo de 5s)
- ✅ Graceful shutdown (SIGINT/SIGTERM) com persistência de cursors

### Agent (`innerwarden-agent`)
- ✅ Leitura incremental de JSONL via byte-offset cursors (sem re-leitura)
- ✅ Cursor fail-open: `agent-state.json` corrompido faz fallback para cursor vazio (sem crash)
- ✅ Config TOML com defaults sensatos — `--config` é opcional
- ✅ **Algorithm gate** — pré-filtra incidentes sem custo de API (severity, IP privado, já bloqueado)
- ✅ Deduplicação intra-tick por IP: evita chamadas AI duplicadas no mesmo tick de 2s
- ✅ **Multi-provider AI** — OpenAI real (MVP), Anthropic/Ollama como stubs extensíveis
- ✅ Análise AI em tempo real de incidentes High/Critical
- ✅ AI seleciona a melhor ação com confidence score (0.0–1.0)
- ✅ Sanitização de decisão AI: `block_ip` sem `target_ip` é rebaixado para `ignore`
- ✅ Auto-execução condicional: só age se `auto_execute=true` AND `confidence ≥ threshold`
- ✅ **Sistema de skills plugável** (open-core: tiers Open e Premium)
- ✅ Skills built-in: `block-ip-ufw`, `block-ip-iptables`, `block-ip-nftables`
- ✅ Stubs premium com mensagens amigáveis: `monitor-ip`, `honeypot`
- ✅ Dry-run por padrão (seguro para produção até o usuário habilitar)
- ✅ Blocklist em memória (evita bloquear o mesmo IP duas vezes)
- ✅ **Audit trail** append-only: `decisions-YYYY-MM-DD.jsonl`
- ✅ Webhook HTTP POST com filtragem por severidade mínima (dispara no tick rápido — em tempo real)
- ✅ Narrativa diária em Markdown: `summary-YYYY-MM-DD.md`
- ✅ Dois loops independentes no mesmo `tokio::select!`: rápido (incidentes + webhook + AI, 2s) + lento (narrativa, 30s)
- ✅ Cursor persistido após cada tick — fail-open em ambos os loops (crash nunca derruba o agent)
- ✅ `reqwest::Client` reutilizado entre chamadas AI (connection pool real, sem overhead de TLS por chamada)
- ✅ Audit trail com flush imediato por decisão — sobrevive a crash entre execução e shutdown
- ✅ Modo `--once` para processamento batch
- ✅ Carregamento automático de `.env` na inicialização (dotenvy, fail-silent)

---

## Fluxo completo do sistema

```
╔══════════════════════════════════════════════════════════════════════════╗
║                            HOST ACTIVITY                               ║
║   SSH logins · sudo commands · Docker events · File integrity checks   ║
╚═══════════════════════════════════════╦════════════════════════════════╝
                                        │
                                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                        innerwarden-sensor                              ║
║                                                                        ║
║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐          ║
║  │ auth_log │  │ journald │  │  docker  │  │  integrity   │          ║
║  │  (tail)  │  │(subproc) │  │(subproc) │  │ (SHA-256     │          ║
║  │ SSH/sudo │  │sshd/sudo │  │events    │  │  polling)    │          ║
║  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘          ║
║       └─────────────┴─────────────┴────────────────┘                   ║
║                           │  mpsc::channel(1024)                       ║
║                           ▼                                            ║
║              ┌─────────────────────────┐                               ║
║              │  Detectors (stateful)   │                               ║
║              │  ssh_bruteforce         │ ← sliding window por IP       ║
║              │  (mais no futuro)       │                               ║
║              └────────────┬────────────┘                               ║
║                           │ Events + Incidents                         ║
║                           ▼                                            ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │  JSONL Sinks — append-only, rotação diária                      │   ║
║  │  · events-YYYY-MM-DD.jsonl                                      │   ║
║  │  · incidents-YYYY-MM-DD.jsonl                                   │   ║
║  │  · state.json (cursors de leitura)                              │   ║
║  └─────────────────────────────────────────────────────────────────┘   ║
╚═══════════════════════════════════════╦════════════════════════════════╝
                                        │  data_dir compartilhado
                                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                        innerwarden-agent                               ║
║              (lê via byte-offset cursors — sem re-leitura)             ║
║                                                                        ║
║  ╔══════════════════════════════════════════════════════════════════╗   ║
║  ║  LOOP RÁPIDO — tick a cada 2s                                   ║   ║
║  ╠══════════════════════════════════════════════════════════════════╣   ║
║  ║                                                                  ║   ║
║  ║  Novos incidentes? ──── NÃO ──→ skip                           ║   ║
║  ║         │ SIM                                                   ║   ║
║  ║         ▼                                                       ║   ║
║  ║  ┌─────────────────────────────────────────────────────────┐   ║   ║
║  ║  │  Webhook (severity ≥ min_severity?) → HTTP POST         │   ║   ║
║  ║  │  Dispara para TODOS os incidentes acima do threshold    │   ║   ║
║  ║  └────────────────────────────┬────────────────────────────┘   ║   ║
║  ║                               │ (sempre, independente do AI)   ║   ║
║  ║                               ▼                                ║   ║
║  ║  ┌─────────────────────────────────────────────────────────┐   ║   ║
║  ║  │  Algorithm Gate  (puro, sem I/O, sem custo de API)      │   ║   ║
║  ║  │                                                          │   ║   ║
║  ║  │  Severity < High?     ──→  ignore (ruído)               │   ║   ║
║  ║  │  IP já na blocklist?  ──→  ignore (duplicado)           │   ║   ║
║  ║  │  IP RFC1918/loopback? ──→  ignore (interno)             │   ║   ║
║  ║  └────────────────────────────┬────────────────────────────┘   ║   ║
║  ║                               │ PASSA o gate                   ║   ║
║  ║                               ▼                                ║   ║
║  ║  ┌──────────────────────────────────────────────────────────┐  ║   ║
║  ║  │  AI Provider  (plugável via trait AiProvider)            │  ║   ║
║  ║  │                                                          │  ║   ║
║  ║  │  ● OpenAI gpt-4o-mini  ◄── real (MVP)                   │  ║   ║
║  ║  │  ○ Anthropic Claude    ◄── stub (contribua!)            │  ║   ║
║  ║  │  ○ Ollama (local LLM)  ◄── stub (contribua!)            │  ║   ║
║  ║  │                                                          │  ║   ║
║  ║  │  Contexto enviado para a AI:                             │  ║   ║
║  ║  │  · Incident (severity, entities, summary, evidence)      │  ║   ║
║  ║  │  · Últimos N eventos da mesma entidade (IP/user)         │  ║   ║
║  ║  │  · Lista de IPs já bloqueados                            │  ║   ║
║  ║  │  · Skills disponíveis com descrições                     │  ║   ║
║  ║  └───────────────────────────┬──────────────────────────────┘  ║   ║
║  ║                              │ AiDecision { action, confidence, ║   ║
║  ║                              │             auto_execute, reason }║   ║
║  ║                              ▼                                  ║   ║
║  ║  ┌──────────────────────────────────────────────────────────┐  ║   ║
║  ║  │  Executor  (confidence ≥ threshold AND auto_execute?)    │  ║   ║
║  ║  │                                                          │  ║   ║
║  ║  │  NÃO ──→ log "skipped: confidence X below threshold Y"  │  ║   ║
║  ║  └───────────────────────────┬──────────────────────────────┘  ║   ║
║  ║                              │ SIM                              ║   ║
║  ║            ┌─────────────────┼──────────────────┐              ║   ║
║  ║            │                 │                  │              ║   ║
║  ║       block_ip          monitor_ip          honeypot           ║   ║
║  ║   ┌────────────────┐  (premium stub)    (premium stub)        ║   ║
║  ║   │ block-ip-ufw   │                                           ║   ║
║  ║   │ block-ip-ipt   │  + request_confirmation                   ║   ║
║  ║   │ block-ip-nft   │    └→ webhook POST com payload            ║   ║
║  ║   └────────────────┘                                           ║   ║
║  ║                              │                                 ║   ║
║  ║                              ▼                                 ║   ║
║  ║  decisions-YYYY-MM-DD.jsonl  (audit trail imutável)           ║   ║
║  ╚══════════════════════════════════════════════════════════════╝   ║
║                                                                        ║
║  ╔══════════════════════════════════════════════════════════════════╗   ║
║  ║  LOOP LENTO — tick a cada 30s                                   ║   ║
║  ╠══════════════════════════════════════════════════════════════════╣   ║
║  ║  Novos eventos? → regenera summary-YYYY-MM-DD.md               ║   ║
║  ║  (webhook e incidentes ficam no loop rápido)                    ║   ║
║  ╚══════════════════════════════════════════════════════════════════╝   ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Saídas geradas por dia

| Arquivo | Quem escreve | Conteúdo |
|---------|-------------|---------|
| `events-YYYY-MM-DD.jsonl` | sensor | Um evento por linha (SSH, Docker, integrity, journald) |
| `incidents-YYYY-MM-DD.jsonl` | sensor | Incidentes detectados (brute-force, etc.) |
| `decisions-YYYY-MM-DD.jsonl` | agent | Decisões da AI com confidence, ação e resultado |
| `summary-YYYY-MM-DD.md` | agent | Narrativa Markdown diária (eventos, incidentes, IPs top) |
| `state.json` | sensor | Cursors dos collectors (offsets, hashes, timestamps) |
| `agent-state.json` | agent | Byte offsets de leitura JSONL por data |

---

## Workspace

```
crates/
  core/     — tipos compartilhados: Event, Incident, EntityRef, Severity, EntityType
  sensor/   — binário innerwarden-sensor
    src/
      main.rs
      config.rs
      collectors/
        auth_log.rs          — tail /var/log/auth.log, parser SSH
        integrity.rs         — SHA-256 polling de arquivos
        journald.rs          — subprocess journalctl --follow --output=json
        docker.rs            — subprocess docker events --format '{{json .}}'
      detectors/
        ssh_bruteforce.rs    — sliding window por IP
      sinks/
        jsonl.rs             — DatedWriter com rotação diária
        state.rs             — load/save atômico de cursors
  agent/    — binário innerwarden-agent
    src/
      main.rs                — CLI + dois loops (AI 2s + narrative 30s) + SIGTERM
      config.rs              — AgentConfig: narrative, webhook, ai, responder
      reader.rs              — JSONL incremental reader + AgentCursor persistence
      narrative.rs           — geração de Markdown diário (generate/write/cleanup)
      webhook.rs             — HTTP POST de notificações de incidente
      decisions.rs           — DecisionWriter + DecisionEntry (audit trail JSONL)
      ai/
        mod.rs               — AiProvider trait, AiDecision, AiAction, algorithm gate, factory
        openai.rs            — implementação real OpenAI (gpt-4o-mini)
        anthropic.rs         — stub "coming soon / contribute"
        ollama.rs            — stub "coming soon / contribute"
      skills/
        mod.rs               — ResponseSkill trait, SkillRegistry, Blocklist, SkillTier
        builtin/
          mod.rs
          block_ip_ufw.rs    — Open ✅
          block_ip_iptables.rs — Open ✅
          block_ip_nftables.rs — Open ✅
          monitor_ip.rs      — Premium stub 🔵
          honeypot.rs        — Premium stub 🔵
examples/
  systemd/innerwarden-sensor.service
```

---

## Comandos essenciais

```bash
# Build e teste (cargo não está no PATH padrão)
make test             # 57 testes (27 sensor + 30 agent)
make build            # debug build de ambos
make build-sensor     # só o sensor
make build-agent      # só o agent

# Instalação trial em servidor Linux (systemd)
./install.sh          # pede OPENAI_API_KEY, instala binários em /usr/local/bin,
                      # cria /etc/innerwarden/{config.toml,agent.toml,agent.env},
                      # cria/ativa innerwarden-sensor + innerwarden-agent,
                      # sobe em modo seguro (responder.enabled=false, dry_run=true)

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

### Sensor (`config.toml`)

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

### Variáveis de ambiente (`.env`)

```bash
# Copie o template e preencha sua chave:
cp .env.example .env

# .env (nunca commitar — está no .gitignore)
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...  # quando o provider Anthropic for implementado
# RUST_LOG=innerwarden_agent=debug
```

O agent carrega `.env` automaticamente ao iniciar. Em produção, use variáveis de ambiente reais — o `.env` é silenciosamente ignorado se não existir.

### Agent (`agent.toml`) — todos os campos têm defaults; arquivo é opcional

```toml
[narrative]
enabled = true       # gera summary-YYYY-MM-DD.md (default: true)
keep_days = 7        # quantos summaries manter (default: 7)

[webhook]
enabled = false
url = "https://hooks.example.com/notify"
min_severity = "medium"   # debug | info | low | medium | high | critical
timeout_secs = 10

[ai]
enabled = true
provider = "openai"        # openai | anthropic (stub) | ollama (stub)
# api_key = ""             # ou env var OPENAI_API_KEY
model = "gpt-4o-mini"      # qualquer modelo do provider
context_events = 20        # eventos recentes enviados como contexto
confidence_threshold = 0.8 # abaixo disso → não auto-executa
incident_poll_secs = 2     # intervalo do loop rápido

[responder]
enabled = true
dry_run = true             # SEGURANÇA: começa sempre em dry_run
block_backend = "ufw"      # ufw | iptables | nftables
allowed_skills = ["block-ip-ufw", "monitor-ip"]
```

Config de teste local: `config.test.toml` (aponta para `./testdata/`).
O agent usa `--data-dir` para apontar ao mesmo `data_dir` do sensor.

---

## Sistema de Skills (open-core)

```
Tier   │ ID                  │ Status
───────┼─────────────────────┼────────────────────────────────
Open   │ block-ip-ufw        │ ✅ executável
Open   │ block-ip-iptables   │ ✅ executável
Open   │ block-ip-nftables   │ ✅ executável
Premium│ monitor-ip          │ 🔵 stub — logs + "coming soon"
Premium│ honeypot            │ 🔵 stub — logs + "coming soon"
```

Para adicionar uma skill da comunidade:
1. Criar struct que implemente `ResponseSkill` trait em `skills/builtin/`
2. Registrar em `SkillRegistry::default_builtin()`
3. Abrir PR em https://github.com/maiconburn/innerwarden

O trait `ResponseSkill` exige: `id()`, `name()`, `description()`, `tier()`, `applicable_to()`, `execute()`.

---

## Multi-provider AI

Para adicionar um novo provider de AI:
1. Criar `crates/agent/src/ai/<nome>.rs` implementando `AiProvider` trait
2. Registrar em `build_provider()` em `ai/mod.rs`
3. Abrir PR

O trait requer apenas: `fn name() -> &'static str` e `async fn decide(ctx) -> Result<AiDecision>`.
Ver `openai.rs` como referência completa.

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

# Permissões para skills de bloqueio (escolha o backend)
# ufw:
echo "innerwarden ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from *" \
  | sudo tee /etc/sudoers.d/innerwarden

# iptables (alternativa):
echo "innerwarden ALL=(ALL) NOPASSWD: /sbin/iptables -A INPUT *" \
  | sudo tee /etc/sudoers.d/innerwarden

# nftables (alternativa):
echo "innerwarden ALL=(ALL) NOPASSWD: /usr/sbin/nft add element *" \
  | sudo tee /etc/sudoers.d/innerwarden
```

O `data_dir` no config.toml **deve** bater com `ReadWritePaths` no service file.

---

## Formato de saída (JSONL)

Arquivos em `data_dir/` — contrato entre sensor e agent:

```
data_dir/
  events-YYYY-MM-DD.jsonl       — eventos brutos
  incidents-YYYY-MM-DD.jsonl    — incidentes detectados
  decisions-YYYY-MM-DD.jsonl    — decisões da AI (audit trail)
  summary-YYYY-MM-DD.md         — narrativa diária em Markdown
  state.json                    — cursors do sensor
  agent-state.json              — cursors do agent (byte offsets)
```

Ver `docs/format.md` para schema completo de Event e Incident.

---

## Testes

```bash
make test   # 57 testes (27 sensor + 30 agent) — todos devem passar
```

Fixtures em `testdata/`:
- `sample-auth.log` — 20 linhas SSH (9 falhas de 203.0.113.10, 8 de 198.51.100.5)
- `watched/sshd_config`, `watched/sudoers` — fixtures para integrity watcher

Testes de integração local:
```bash
make run-sensor                              # grava em ./data/
make run-agent                              # lê de ./data/
innerwarden-agent --data-dir ./data --once  # roda uma vez e sai

# Smoke test com AI em dry_run (seguro):
# 1. Coloque OPENAI_API_KEY no .env
# 2. Rode o sensor para gerar dados: make run-sensor
# 3. Rode o agent com a config de teste:
innerwarden-agent --data-dir ./data --config agent-test.toml
# Deve logar: "DRY RUN: would execute: sudo ufw deny from X"
# Decisões ficam em: ./data/decisions-YYYY-MM-DD.jsonl
```

---

## Processo de desenvolvimento

**A cada feature ou correção, nesta ordem:**

```
1. implementar
2. make test         ← todos os testes devem passar antes de commitar
3. atualizar CLAUDE.md ← obrigatório: capabilities, workspace, config, próximos passos
4. git commit (inglês)
5. git push
```

> **Regra**: o CLAUDE.md é a fonte de verdade do projeto. Qualquer mudança no
> comportamento do sistema, nos arquivos gerados, na configuração ou nas dependências
> deve ser refletida no CLAUDE.md no mesmo commit. Se não está documentado aqui,
> não existe para quem retomar o projeto.

---

## Convenções

- **Commits em inglês** — sem mensagens em português.
- **CLAUDE.md sempre atualizado** — parte obrigatória do processo, não opcional.
- **Sensor**: determinístico, sem HTTP/LLM/AI. Collectors são fail-open.
- **Agent**: camada interpretativa. Pode chamar APIs externas.
- Cada collector: `run(tx, shared_state)` — async, nunca derruba o processo.
- Erros de I/O nos sinks: logar com `warn!`, não propagar com `?`.
- Novos tipos de evento: `source` descreve a origem, `kind` descreve o evento.
- `Event.details`: manter pequeno (< 16KB). Não incluir payloads arbitrários.
- `spawn_blocking` para qualquer I/O de arquivo síncrono dentro de tasks Tokio.
- AI provider em `AgentState` usa `Arc<dyn AiProvider>` (não `Box`) para evitar
  conflitos de borrow checker em async loops com `&mut state`.

---

## Próximos passos

- Agent: implementar provider Anthropic Claude (real)
- Agent: implementar provider Ollama (LLM local, air-gapped)
- Sensor: adicionar detectores (port scan, credential stuffing, Docker escape)
- Skills: monitor-ip real (captura de tráfego via tcpdump/ebpf)
- Skills: honeypot real (integração com cowrie ou similar)
- Skills: carregamento de skills da comunidade via `~/.config/innerwarden/skills/`
- Agent: correlação temporal entre múltiplos incidentes
- Agent: suporte multi-host (agent central lendo data_dirs remotos via SSH/S3)
- Dashboard TUI para visualização em tempo real
