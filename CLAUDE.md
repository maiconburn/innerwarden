# Inner Warden — CLAUDE.md

> Nota pública: este arquivo é um handbook detalhado de manutenção e operação.
> Para visão geral, instalação e uso inicial, comece por `README.md`.
> O conteúdo abaixo existe para preservar contexto operacional aprofundado do projeto.

Observabilidade e resposta autônoma de host com dois componentes Rust:
**sensor** (coleta determinística, zero AI) e **agent** (inteligência em tempo real).

---

## O que o sistema faz hoje

### Sensor (`innerwarden-sensor`)
- ✅ Tail de `/var/log/auth.log` com parser SSH completo (falhas, logins, usuários inválidos)
- ✅ Integração com `journald` (sshd, sudo, kernel/qualquer systemd unit)
- ✅ Trilha opcional de shell via `auditd` (`type=EXECVE`) com parser de comando executado
- ✅ Ingestão opcional de `auditd type=TTY` (alto impacto de privacidade, gated por config)
- ✅ Monitoramento de Docker events (start / stop / die / OOM)
- ✅ Integridade de arquivos via SHA-256 polling configurável
- ✅ Detector de SSH brute-force (sliding window por IP, threshold configurável)
- ✅ Detector de SSH credential stuffing por IP (spray de múltiplos usuários em janela)
- ✅ Detector de port scan por IP (sliding window por portas de destino únicas em logs de firewall)
- ✅ Detector de abuso de `sudo` por usuário (`sudo_abuse`: burst de comandos privilegiados suspeitos por janela)
- ✅ **Detector `execution_guard`** — análise estrutural de comandos via AST (`tree-sitter-bash`) + scoring de risco por evento + correlação de sequência por usuário (download→chmod→execute em janela deslizante); emite incidentes `suspicious_execution` com score, sinais e evidência; modo `observe` (apenas detecta, sem bloqueio); extensões planejadas: `contain` e `strict`
- ✅ Output JSONL append-only com rotação diária automática
- ✅ Fail-open: erros de I/O em collectors são logados, nunca derrubam o agente
- ✅ Flush duplo: por contagem (50 eventos) + por tempo (intervalo de 5s)
- ✅ Graceful shutdown (SIGINT/SIGTERM) com persistência de cursors
- ✅ **Collector `falco_log`** — tail de `/var/log/falco/falco.log` (JSONL); mapeia priority → Severity; extrai entidades de `output_fields` (IP, user, container, pod); incident passthrough automático para High/Critical (Falco já fez a detecção, InnerWarden só tria e responde); 12 testes
- ✅ **Collector `suricata_eve`** — tail de `/var/log/suricata/eve.json` (JSONL); suporta event_types configurável (alert, dns, http, tls, anomaly por default); mapeia severity Suricata inverso (1→Critical, 2→High, 3→Medium); incident passthrough para alert severity 1+2; builders por tipo (alert, dns, http, tls, anomaly); extrai IP, service (hostname HTTP); 10 testes

### Agent (`innerwarden-agent`)
- ✅ Leitura incremental de JSONL via byte-offset cursors (sem re-leitura)
- ✅ Cursor fail-open: `agent-state.json` corrompido faz fallback para cursor vazio (sem crash)
- ✅ Config TOML com defaults sensatos — `--config` é opcional
- ✅ **Algorithm gate** — pré-filtra incidentes sem custo de API (severity, IP privado, já bloqueado)
- ✅ Deduplicação intra-tick por IP: evita chamadas AI duplicadas no mesmo tick de 2s
- ✅ **Decision cooldown** (1h) — suprime chamadas AI repetidas para o mesmo scope `action:detector:entity` dentro de uma janela de 1h; pré-carregado de `decisions-*.jsonl` (hoje + ontem) na inicialização; suporta `suspend_user_sudo` (campo `target_user` em `DecisionEntry`)
- ✅ **Blocklist atualizada imediatamente** após qualquer decisão `block_ip`, mesmo quando `responder.enabled = false` — evita re-avaliação AI do mesmo IP em ticks seguintes
- ✅ **Multi-provider AI** — OpenAI real, Anthropic real (claude-haiku-4-5-20251001 default), Ollama real (local LLM — llama3.2, mistral, gemma2, qwen2.5, etc.)
- ✅ Análise AI em tempo real de incidentes High/Critical
- ✅ AI seleciona a melhor ação com confidence score (0.0–1.0)
- ✅ Sanitização de decisão AI: `block_ip` sem `target_ip` é rebaixado para `ignore`
- ✅ Nova ação AI: `suspend_user_sudo` (suspende sudo de usuário por janela limitada com TTL)
- ✅ Auto-execução condicional: só age se `auto_execute=true` AND `confidence ≥ threshold`
- ✅ **Sistema de skills plugável** (open-core: tiers Open e Premium)
- ✅ Skills built-in: `block-ip-ufw`, `block-ip-iptables`, `block-ip-nftables`
- ✅ Skill premium real: `monitor-ip` (captura de tráfego limitada em `.pcap` + metadata)
- ✅ Skill premium `honeypot` com hardening 8.7: perfis de jail (`standard|strict`) + handoff externo attested (receiver challenge/HMAC + pin opcional de `receiver_id`)
- ✅ Honeypot fase 8.8: interação média (`interaction = "medium"`) — SSH real via `russh` (key exchange + captura de credenciais, sem shell) + HTTP com parser manual (captura de formulário de login fake)
- ✅ Skill open real: `suspend-user-sudo` (negação temporária de sudo via drop-in em `/etc/sudoers.d` + cleanup automático de expiração)
- ✅ Dry-run por padrão (seguro para produção até o usuário habilitar)
- ✅ Blocklist em memória persistida entre ticks: inserção sempre feita (inclusive dry_run) + pré-carregamento de `decisions-*.jsonl` do dia na inicialização (evita bloquear o mesmo IP mesmo após restart em dry_run)
- ✅ **Audit trail** append-only: `decisions-YYYY-MM-DD.jsonl`
- ✅ Webhook HTTP POST com filtragem por severidade mínima (dispara no tick rápido — em tempo real)
- ✅ Narrativa diária em Markdown: `summary-YYYY-MM-DD.md` com throttle mínimo de 5min entre escritas (evita reescrita em cada tick); instante da última escrita recuperado via mtime do arquivo ao reiniciar
- ✅ Dois loops independentes no mesmo `tokio::select!`: rápido (incidentes + webhook + AI, 2s) + lento (narrativa, 30s)
- ✅ Cursor persistido após cada tick — fail-open em ambos os loops (crash nunca derruba o agent)
- ✅ `reqwest::Client` reutilizado entre chamadas AI (connection pool real, sem overhead de TLS por chamada)
- ✅ Audit trail com flush imediato por decisão — sobrevive a crash entre execução e shutdown
- ✅ Modo `--once` para processamento batch
- ✅ Modo `--report` v2: gera relatório operacional do trial com deltas dia-a-dia + anomaly hints + seção de telemetria (`trial-report-YYYY-MM-DD.{md,json}`) sem alterar estado; inclui seção `recent_window` com janela deslizante real de 6h (abrange ontem+hoje, usa campo `ts` e `action_type` corretos)
- ✅ Carregamento automático de `.env` na inicialização (dotenvy, fail-silent)
- ✅ Replay QA harness end-to-end (`make replay-qa`) com fixtures multi-source (auth_log + falco_log + suricata_eve + osquery_log) e assertions de source por collector
- ✅ Playbook de rollout hardening + smoke checks remotos (`make rollout-precheck/postcheck`)
- ✅ Correlação temporal leve de incidentes por janela + pivôs (`ip`, `user`, `detector`) com contexto para AI e clusters narráveis
- ✅ Telemetria operacional leve (JSONL) com métricas de ingestão, detectores, gate, AI, latência, erros e dry-run vs execução real
- ✅ Dashboard local autenticado (`--dashboard`) com visão operacional de eventos/incidentes/decisões/telemetria + autenticação HTTP Basic obrigatória
- ✅ Dashboard D2 — UX de investigação estilo Clarity: split-pane com investigação read-only em múltiplas etapas: D2.1 (jornada por IP com `/api/entities` + `/api/journey`), D2.2 (filtros + pivôs `ip|user|detector` com `/api/pivots`), D2.3 (cluster-first com `/api/clusters` + export de snapshot JSON/Markdown via `/api/export`) e D2.4 (investigação guiada com hints narrativos, atalhos de pivô, comparação temporal por data/janela e deep-link inicial por query string)
- ✅ Dashboard header com logo SVG de alto contraste (mesmo logo, melhor legibilidade visual no topo)
- ✅ Dashboard D4 — redesign visual site-matched (paleta navy `#040814`, acento `#78e5ff`, danger `#f43f5e`, radial gradients ambient, border-radius moderno, inputs/cards mais escuros) + mobile UX completo (collapsar/expandir painel via toggle button, touch targets, toast e modal full-width, layout responsivo melhorado)
- ✅ **Dashboard D3** — ações operacionais guardadas: operador pode bloquear IPs (`block-ip-*`) e suspender usuários (`suspend-user-sudo`) diretamente da timeline da investigação, com campo de razão obrigatório, modal de confirmação com badge de modo (DRY RUN / LIVE), toast de feedback e auditoria completa em `decisions-YYYY-MM-DD.jsonl` (ai_provider: `dashboard:operator`). Ações desabilitadas por padrão; requerem `responder.enabled = true` no agent.toml. Suporte a dry-run transparente (simula a ação sem executar comandos do sistema). Endpoints: `POST /api/action/block-ip`, `POST /api/action/suspend-user`, `GET /api/action/config`.
- ✅ **Dashboard D5** — attacker path viewer: `JourneyResponse` agora inclui `verdict` (attack assessment com entry_vector, access_status, privilege_status, containment_status, honeypot_status, confidence) e `chapters` (fases lógicas derivadas automaticamente: reconnaissance, initial_access_attempt, access_success, privilege_abuse, response, containment, honeypot_interaction). UI exibe verdict card antes da timeline, chapter rail navegável clicável e evidence cards com metadados humanos + Raw JSON secundário (toggle). `window._journeyData` armazena dados da jornada para scroll-to-chapter.
- ✅ **Dashboard D6** — notificações push em tempo real via Server-Sent Events (SSE): `GET /api/events/stream` com autenticação Basic. File watcher interno (2 s) detecta crescimento de `incidents-*.jsonl` e `decisions-*.jsonl` e faz push de evento `refresh` via broadcast channel (`tokio::sync::broadcast`, capacity 64). Heartbeat de 30 s mantém a conexão viva. Frontend usa `fetch()` + `ReadableStream` (compatível com Basic auth, diferente do `EventSource` nativo) com reconexão automática a cada 3 s. Indicador `● LIVE` / `● reconnecting` em `#refreshStatus` no header. Fallback para poll de 30 s se SSE não conectar em 35 s.
- ✅ **Dashboard D7** — timeline ao vivo: SSE aciona `refreshLeftLive()` em vez de reload completo. Novos cards de entidade aparecem com animação CSS `cardSlideIn` (slide + borda cyan). KPIs piscam em cyan (`kpiFlash`) quando o valor muda. Cards existentes têm contagens atualizadas silenciosamente. Scroll e seleção preservados. `state.knownItemValues` (Set) rastreia entidades renderizadas para diff incremental.
- ✅ **Dashboard D8** — alertas push de incidentes: file watcher lê novas linhas de `incidents-*.jsonl` por byte offset a cada 2 s; para severidade High/Critical emite evento SSE `alert` com payload `{ severity, title, entity_type, entity_value }`. Frontend exibe `showAlertToast()` — badge colorido (vermelho/laranja), título e link clicável `→ IP/entidade` que abre diretamente o journey panel. Toast persiste 8 s.
- ✅ **Dashboard D9** — busca inline de entidades: campo `<input type="search">` acima da lista filtra cards em tempo real por qualquer texto visível (IP, detector, severidade, contagens) — sem round-trip ao servidor, sem reload, scroll preservado. Mensagem "No matches for X" quando nenhum card passa no filtro. Filtro re-aplicado automaticamente após `refreshLeft()` e `refreshLeftLive()`.
- ✅ **Dashboard D10** — tab Report: navegação principal "Investigate / Report" no header. `GET /api/report[?date=YYYY-MM-DD]` computa `TrialReport` on-demand via `report::compute_for_date`. `GET /api/report/dates` lista datas disponíveis. Tab renderiza KPIs, tendências dia-a-dia, anomaly hints com badges de severidade, tabela de saúde operacional, top IPs, incidents by type e sugestões. Seletor de data para navegar histórico. `data_retention.rs`: limpeza automática de arquivos antigos por tipo (`events_keep_days`, `incidents_keep_days`, `decisions_keep_days`, `telemetry_keep_days`, `reports_keep_days`), configurável em `[data]` no agent.toml, rodada no startup e no loop lento (30s).
- ✅ **Telegram T.1** — notificações push: `send_incident_alert()` enviado para todo incidente High/Critical no tick rápido, com badge de severidade, ícone de fonte (🔬 falco, 🌐 suricata, 🔍 osquery, 🔐 ssh), resumo de entidades e botão deep-link opcional para o dashboard. Configurado via `[telegram]` no agent.toml ou vars de ambiente `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`.
- ✅ **Telegram T.2** — aprovações bidirecionais: quando AI retorna `RequestConfirmation`, o agent envia inline keyboard (✅ Aprovar / ❌ Rejeitar) via Telegram. Polling task long-poll (25 s) detecta resposta do operador; ao aprovar, executa a ação e registra em `decisions-*.jsonl` com `ai_provider: "telegram:<operador>"`. TTL configurável (default 10 min); expirado → descartado. Suporta comando `/status` no bot.

---

## Fluxo resumido

**sensor** coleta host activity (auth_log, journald, docker, integrity, exec_audit opcional) via `mpsc::channel(1024)`, passa por detectors stateful (ssh_bruteforce, credential_stuffing, port_scan, sudo_abuse) e escreve `events-*.jsonl` + `incidents-*.jsonl` no `data_dir` compartilhado.

**agent** lê incrementalmente via byte-offset cursors. Loop rápido (2s): webhook + Telegram T.1 → algorithm gate (severity < High / IP privado / já bloqueado → skip) → AI provider → executor (confidence ≥ threshold AND auto_execute) → skill (block_ip / monitor_ip / honeypot / suspend_user_sudo) → `decisions-*.jsonl`; Telegram T.2 polling task em background envia confirmações pendentes ao operador e executa ação aprovada. Loop lento (30s): regenera `summary-*.md` com throttle de 5min.

### Saídas geradas por dia

| Arquivo | Quem escreve | Conteúdo |
|---------|-------------|---------|
| `events-YYYY-MM-DD.jsonl` | sensor | Um evento por linha (SSH, Docker, integrity, journald, auditd opcional) |
| `incidents-YYYY-MM-DD.jsonl` | sensor | Incidentes detectados (brute-force, etc.) |
| `decisions-YYYY-MM-DD.jsonl` | agent | Decisões da AI com confidence, ação (`block_ip`/`monitor`/`honeypot`/`suspend_user_sudo`/`ignore`), `target_ip`, `target_user` e resultado |
| `telemetry-YYYY-MM-DD.jsonl` | agent | Snapshots operacionais (coletores, detectores, gate, AI, latência, erros, dry-run/real) |
| `honeypot/listener-session-*.json` | agent | Metadados de sessão do honeypot listener (serviços, redirecionamento, stats) |
| `honeypot/listener-session-*.jsonl` | agent | Evidências por conexão/sessão no honeypot listener |
| `honeypot/listener-session-*.pcap` | agent | Captura limitada opcional de handoff forense (`[honeypot.pcap_handoff]`) |
| `honeypot/listener-session-*.external-handoff.json` | agent | Resultado da integração externa de forense (`[honeypot.external_handoff]`) |
| `honeypot/listener-session-*.external-handoff.sig` | agent | Assinatura HMAC-SHA256 do handoff externo (`[honeypot.external_handoff]`) |
| `honeypot/listener-active.lock` | agent | Lock de sessão ativa (controle de concorrência + stale recovery) |
| `summary-YYYY-MM-DD.md` | agent | Narrativa Markdown diária (eventos, incidentes, IPs top) |
| `state.json` | sensor | Cursors dos collectors (offsets, hashes, timestamps) |
| `agent-state.json` | agent | Byte offsets de leitura JSONL por data |

---

## Workspace

```
crates/
  core/     — tipos compartilhados: Event, Incident, EntityRef, Severity, EntityType
  ctl/      — binário innerwarden-ctl, instalado como `innerwarden` (plano de controle)
    src/
      main.rs              — CLI: enable, disable, list, status, doctor, upgrade, module *
      capability.rs        — Capability trait + ActivationOptions + CapabilityRegistry
      config_editor.rs     — patch TOML atômico via toml_edit (preserva comentários)
      preflight.rs         — BinaryExists, DirectoryExists, UserExists, VisudoAvailable
      sudoers.rs           — SudoersDropIn: write + visudo validation + install
      systemd.rs           — restart_service / is_service_active
      capabilities/
        block_ip.rs           — enable/disable block-ip (ufw|iptables|nftables)
        sudo_protection.rs    — enable/disable sudo-protection (detector + skill)
        shell_audit.rs        — enable/disable shell-audit (privacy gate obrigatório)
        search_protection.rs  — enable/disable search-protection (nginx collector + search_abuse + rate-limit-nginx)
      module_manifest.rs     — ModuleManifest parser + collector/detector ID → config section lookup + sudoers rule generator
      module_validator.rs    — validação estática de pacotes de módulo
  sensor/   — binário innerwarden-sensor
    src/
      main.rs
      config.rs
      collectors/
        auth_log.rs          — tail /var/log/auth.log, parser SSH
        integrity.rs         — SHA-256 polling de arquivos
        journald.rs          — subprocess journalctl --follow --output=json
        exec_audit.rs        — tail /var/log/audit/audit.log (EXECVE + TTY opcional)
        docker.rs            — subprocess docker events --format '{{json .}}'
        nginx_access.rs      — tail nginx access log (Combined Log Format), emite http.request
        macos_log.rs         — subprocess `log stream` (macOS); reusa parser SSH; emite sudo.command
      detectors/
        ssh_bruteforce.rs    — sliding window por IP
        credential_stuffing.rs — spray de usuários distintos por IP
        port_scan.rs         — portas de destino únicas por IP (firewall logs)
        sudo_abuse.rs        — burst de comandos sudo suspeitos por usuário (janela + threshold)
        search_abuse.rs      — sliding window por IP+path (nginx http.request events)
        execution_guard.rs   — AST (tree-sitter-bash) + argv analysis + timeline correlation por usuário
      sinks/
        jsonl.rs             — DatedWriter com rotação diária
        state.rs             — load/save atômico de cursors
  agent/    — binário innerwarden-agent
    src/
      main.rs                — CLI + dois loops (AI 2s + narrative 30s) + SIGTERM
      config.rs              — AgentConfig: narrative, webhook, ai, correlation, telemetry, honeypot, responder
      reader.rs              — JSONL incremental reader + AgentCursor persistence
      correlation.rs         — correlação temporal leve + clusterização de incidentes
      telemetry.rs           — telemetria operacional leve (snapshot JSONL por tick)
      dashboard.rs           — servidor HTTP local autenticado + UI operacional/investigação
      report.rs              — relatório operacional v2 (`--report`) com tendências, anomaly hints e telemetria; `compute_for_date` + `list_available_dates` para API
      data_retention.rs      — limpeza automática de arquivos antigos por tipo (events/incidents/decisions/telemetry/reports)
      narrative.rs           — geração de Markdown diário (generate/write/cleanup)
      webhook.rs             — HTTP POST de notificações de incidente
      decisions.rs           — DecisionWriter + DecisionEntry (audit trail JSONL)
      telegram.rs            — TelegramClient: T.1 notifications + T.2 inline-keyboard approvals + polling loop
      ai/
        mod.rs               — AiProvider trait, AiDecision, AiAction, algorithm gate, factory
        openai.rs            — implementação real OpenAI (gpt-4o-mini)
        anthropic.rs         — implementação real Anthropic (claude-haiku-4-5-20251001 default; troca modelo OpenAI automaticamente)
        ollama.rs            — stub "coming soon / contribute"
      skills/
        mod.rs               — ResponseSkill trait, SkillRegistry, Blocklist, SkillTier
        builtin/
          mod.rs
          block_ip_ufw.rs    — Open ✅
          block_ip_iptables.rs — Open ✅
          block_ip_nftables.rs — Open ✅
          block_ip_pf.rs     — Open ✅ (macOS Packet Filter: pfctl -t innerwarden-blocked -T add <IP>)
          suspend_user_sudo.rs — Open ✅ (suspensão temporária de sudo com TTL + cleanup)
          monitor_ip.rs      — Premium ✅ (captura limitada via tcpdump + sidecar metadata)
          honeypot/
            mod.rs         — Premium ✅ (hardening 8.7: jail profile presets + receiver attestation no handoff externo)
            ssh_interact.rs  — interação SSH via russh (fase 8.8: key exchange + captura de credenciais)
            http_interact.rs — interação HTTP com login page fake (fase 8.8: captura de formulário)
examples/
  systemd/innerwarden-sensor.service
scripts/
  replay_qa.sh — harness de replay fim-a-fim (fixture log → sensor → agent --once → --report + telemetry assertions)
  rollout_smoke.sh — pre/post smoke checks + plano de rollback rápido para produção
modules/                           — soluções verticais empacotadas (ver docs/module-authoring.md)
  ssh-protection/                  — SSH brute-force + credential stuffing → block-ip (built-in)
    module.toml                    — manifest: id, version, provides, rules, security constraints
    config/                        — sensor.example.toml + agent.example.toml
    docs/README.md
  network-defense/                 — port scan → block-ip (built-in)
  sudo-protection/                 — sudo abuse → suspend-user-sudo (built-in)
  file-integrity/                  — SHA-256 file monitoring → webhook (built-in)
  container-security/              — Docker lifecycle events (built-in, observability only)
  threat-capture/                  — monitor-ip + honeypot (built-in, Premium)
  search-protection/               — nginx access log → search_abuse → block-ip (built-in, M.3)
  execution-guard/                 — shell.command_exec + sudo.command → execution_guard AST detector (built-in, observe mode)
  falco-integration/               — Falco eBPF/syscall alerts → incidents (built-in, incident passthrough High+)
  suricata-integration/            — Suricata network IDS alerts → incidents (built-in, incident passthrough sev 1-2)
  osquery-integration/             — osquery differential results → events (built-in, observability, sem passthrough)
docs/
  module-authoring.md              — guia completo para criar módulos + passo-a-passo Claude Code/Codex
  integration-recipes.md           — formato de recipe + guia de geração por AI + fluxo de contribuição
integrations/                      — integration recipes (declarative specs for external tool collectors)
  README.md                        — índice de recipes disponíveis
  falco/recipe.toml                — Falco eBPF/syscall runtime security (file_tail, incident_passthrough)
  wazuh/recipe.toml                — Wazuh HIDS / FIM / compliance (file_tail, incident_passthrough)
  osquery/recipe.toml              — osquery host observability (file_tail, no passthrough)
```

---

## Comandos essenciais

```bash
# Build e teste (cargo não está no PATH padrão)
make test             # 351 testes (110 sensor + 125 agent + 116 ctl)
make build            # debug build de todos (sensor + agent + ctl)
make build-sensor     # só o sensor
make build-agent      # só o agent
make build-ctl        # só o ctl (innerwarden binary)

# Capability management (após instalar)
innerwarden list                    # lista capabilities com status atual
innerwarden status                  # overview global: serviços + capabilities + módulos
innerwarden status block-ip         # status de uma capability específica
innerwarden enable block-ip         # ativa block-ip (ufw por default)
innerwarden enable block-ip --param backend=iptables  # backend alternativo
innerwarden enable sudo-protection  # ativa detector sudo_abuse + skill
innerwarden enable shell-audit      # ativa exec_audit (com privacy gate)
innerwarden enable shell-audit --yes  # pula confirmação interativa
innerwarden disable block-ip        # desativa capability (reverte config + sudoers + restart)
innerwarden --dry-run enable block-ip  # mostra o que seria feito
innerwarden doctor                  # diagnóstico completo com fix hints; exit 1 se houver issues
                                    # inclui seção Telegram quando enabled=true: valida bot_token
                                    # (formato <id>:<secret>) e chat_id (numérico), resolve via
                                    # config / env var / agent.env, hints passo-a-passo para @BotFather e @userinfobot
innerwarden upgrade                 # busca novo release no GitHub e instala atomicamente
innerwarden upgrade --check         # só verifica se há update disponível, não instala

# Module management
innerwarden module validate ./modules/ssh-protection   # valida manifest, segurança, testes, docs
innerwarden module install https://example.com/mod.tar.gz  # baixa, valida SHA-256, instala
innerwarden module install ./local-mod.tar.gz --enable  # instala + habilita imediatamente
innerwarden module uninstall <id>                       # desativa e remove
innerwarden module publish ./modules/my-module          # empacota em .tar.gz + gera .sha256
innerwarden module update-all                           # atualiza todos os módulos com update_url
innerwarden module update-all --check                   # só verifica atualizações, não instala
innerwarden module list                                 # lista módulos instalados com status
innerwarden module status <id>                          # detalhe de um módulo específico

# Instalação trial em servidor Linux (systemd)
./install.sh          # pede OPENAI_API_KEY, instala binários em /usr/local/bin,
                      # pede consentimento explícito para trilha de shell audit (opcional),
                      # cria /etc/innerwarden/{config.toml,agent.toml,agent.env},
                      # cria/ativa innerwarden-sensor + innerwarden-agent,
                      # sobe em modo seguro (responder.enabled=false, dry_run=true)

# Rodar localmente
make run-sensor       # sensor com config.test.toml
make run-agent        # agent lendo ./data/
make run-dashboard    # dashboard read-only em http://127.0.0.1:8787 (requer auth env vars)
innerwarden-agent --dashboard-generate-password-hash  # gera hash Argon2 para auth do dashboard
innerwarden-agent --report --data-dir ./data  # gera trial-report-YYYY-MM-DD.{md,json}
make replay-qa        # replay end-to-end multi-source (auth_log + falco_log + suricata_eve + osquery_log)
make ops-check DATA_DIR=./data  # quick ops-check da janela de 6h do último trial-report-*.json

# Cross-compile para Linux arm64 (requer cargo-zigbuild + zig)
make build-linux      # → target/aarch64-unknown-linux-gnu/release/innerwarden-{sensor,agent}

# Deploy (ajustar HOST=user@servidor)
make deploy HOST=ubuntu@1.2.3.4
make deploy-config HOST=ubuntu@1.2.3.4
make deploy-service HOST=ubuntu@1.2.3.4

# Rollout hardening (pré/pós deploy + rollback)
make rollout-precheck HOST=ubuntu@1.2.3.4
make rollout-postcheck HOST=ubuntu@1.2.3.4
make rollout-rollback HOST=ubuntu@1.2.3.4
make rollout-stop-agent HOST=ubuntu@1.2.3.4

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

[collectors.macos_log]
enabled = false   # macOS only; usa `log stream`; substitui auth_log + journald no Darwin

[collectors.journald]
enabled = true
units = ["sshd", "sudo", "kernel"]   # "sshd" não "ssh"; "kernel" habilita sinais de firewall/port scan

[collectors.exec_audit]
enabled = false
path = "/var/log/audit/audit.log"
include_tty = false   # alto impacto de privacidade; habilite só com autorização explícita

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

[detectors.credential_stuffing]
enabled = false       # recomendado habilitar após baseline de ruído no host
threshold = 6         # usuários distintos por IP na janela
window_seconds = 300

[detectors.port_scan]
enabled = false       # recomendado habilitar após validar volume de logs de firewall
threshold = 12        # portas de destino únicas por IP na janela
window_seconds = 60

[detectors.sudo_abuse]
enabled = false       # recomendado habilitar com política clara de resposta e governança
threshold = 3         # comandos sudo suspeitos por usuário na janela
window_seconds = 300
```

### Variáveis de ambiente (`.env`)

```bash
# Copie o template e preencha sua chave:
cp .env.example .env

# .env (nunca commitar — está no .gitignore)
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...  # provider Anthropic real; use com provider = "anthropic" no agent.toml
# RUST_LOG=innerwarden_agent=debug
```

O agent carrega `.env` automaticamente ao iniciar. Em produção, use variáveis de ambiente reais — o `.env` é silenciosamente ignorado se não existir.

Variáveis para dashboard (read-only + auth obrigatória):

```bash
# Usuário de login do dashboard
INNERWARDEN_DASHBOARD_USER=admin

# Hash Argon2 PHC gerado por:
# innerwarden-agent --dashboard-generate-password-hash
INNERWARDEN_DASHBOARD_PASSWORD_HASH=$argon2id$...
```

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
provider = "openai"        # openai | anthropic | ollama
# api_key = ""             # ou env var OPENAI_API_KEY / ANTHROPIC_API_KEY
model = "gpt-4o-mini"      # qualquer modelo do provider
# base_url = ""            # ollama: override endpoint (default http://localhost:11434)
                           # ou env var OLLAMA_BASE_URL
context_events = 20        # eventos recentes enviados como contexto
confidence_threshold = 0.8 # abaixo disso → não auto-executa
incident_poll_secs = 2     # intervalo do loop rápido

[correlation]
enabled = true
window_seconds = 300       # janela temporal para correlacionar incidentes
max_related_incidents = 8  # contexto correlacionado enviado para AI

[telemetry]
enabled = true             # escreve telemetry-YYYY-MM-DD.jsonl (default: true)

[honeypot]
mode = "demo"              # demo | listener (default: demo)
bind_addr = "127.0.0.1"    # listener mode
port = 2222                # ssh decoy port (listener mode)
http_port = 8080           # http decoy port (listener mode)
duration_secs = 300        # janela limitada da sessão
services = ["ssh"]         # ["ssh", "http"] para multi-serviço
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512
isolation_profile = "strict_local" # strict_local | standard
require_high_ports = true
forensics_keep_days = 7
forensics_max_total_mb = 128
transcript_preview_bytes = 96
lock_stale_secs = 1800
interaction = "banner"         # banner (default) | medium (Cowrie-style: SSH key exchange + HTTP login page)
ssh_max_auth_attempts = 6      # SSH auth rounds before disconnect (medium interaction only)
http_max_requests = 10         # max HTTP requests per connection (medium interaction only)

[honeypot.sandbox]
enabled = false
runner_path = ""            # vazio = usa o próprio binary do innerwarden-agent
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120

[honeypot.containment]
mode = "process"             # process | namespace | jail
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"    # standard | strict
allow_namespace_fallback = true

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--target", "{target_ip}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
allowed_commands = ["/usr/local/bin/iw-handoff"]
enforce_allowlist = false
signature_enabled = false
signature_key_env = "INNERWARDEN_HANDOFF_SIGNING_KEY"
attestation_enabled = false
attestation_key_env = "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = ""

[honeypot.redirect]
enabled = false
backend = "iptables"

[responder]
enabled = true
dry_run = true             # SEGURANÇA: começa sempre em dry_run
block_backend = "ufw"      # ufw | iptables | nftables
allowed_skills = ["block-ip-ufw", "monitor-ip"]  # adicione "honeypot" e/ou "suspend-user-sudo" para permitir execução dessas skills

[data]
events_keep_days = 7       # arquivos events-*.jsonl: janela curta (alto volume)
incidents_keep_days = 30   # arquivos incidents-*.jsonl
decisions_keep_days = 90   # arquivos decisions-*.jsonl — audit trail, manter mais
telemetry_keep_days = 14   # arquivos telemetry-*.jsonl
reports_keep_days = 30     # arquivos trial-report-*.{json,md}
```

Config de teste local: `config.test.toml` (aponta para `./testdata/`).
O agent usa `--data-dir` para apontar ao mesmo `data_dir` do sensor.

---

## Sistema de Módulos

Um **module** é uma solução vertical completa para um problema de segurança. Empacota collectors, detectors, skills e rules numa unidade coesa com manifest, config examples, testes e documentação.

```
modules/
  ssh-protection/       — SSH brute-force + credential stuffing → block-ip
  network-defense/      — port scan → block-ip
  sudo-protection/      — sudo abuse → suspend-user-sudo
  file-integrity/       — file hash monitoring → webhook alert
  container-security/   — docker lifecycle events (observability)
  threat-capture/       — monitor-ip + honeypot (Premium)
  search-protection/    — nginx access log → search_abuse → block-ip (M.3)
```

Cada módulo contém:
- `module.toml` — manifest com id, version, provides, rules, security constraints
- `config/sensor.example.toml` + `config/agent.example.toml` — snippets prontos para copiar
- `docs/README.md` — o que faz, quando usar, como configurar
- `tests/` — pelo menos um teste por componente
- `src/` — código Rust (apenas se o módulo adiciona novos collectors/detectors/skills)

**Módulos built-in** (`builtin = true` no module.toml): código vive em `crates/`, módulo serve como manifest + config examples + docs.

**Módulos externos** (novos): código começa em `modules/<id>/src/`, é registrado manualmente nos crates ao ser mergeado.

Comandos de validação:
```bash
innerwarden module validate ./modules/my-module   # valida estrutura, manifest, segurança, testes
```

Guia completo de criação de módulos (incluindo passo-a-passo para Claude Code/Codex):
→ `docs/module-authoring.md`

---

## Sistema de Skills (open-core)

```
Tier   │ ID                  │ Módulo            │ Status
───────┼─────────────────────┼───────────────────┼────────────────────────────────
Open   │ block-ip-ufw        │ ssh-protection    │ ✅ executável
Open   │ block-ip-iptables   │ ssh-protection    │ ✅ executável
Open   │ block-ip-nftables   │ ssh-protection    │ ✅ executável
Open   │ block-ip-pf         │ ssh-protection    │ ✅ executável — bloqueia IP via pfctl (macOS Packet Filter)
Open   │ suspend-user-sudo   │ sudo-protection   │ ✅ executável — nega sudo por TTL com cleanup automático
Open   │ rate-limit-nginx    │ search-protection │ ✅ executável — deny nginx layer (HTTP 403) com TTL + cleanup automático
Premium│ monitor-ip          │ threat-capture    │ ✅ executável — captura limitada (`tcpdump`) + metadata
Premium│ honeypot            │ threat-capture    │ ✅ hardening 8.7 (containment `process|namespace|jail` + jail_profile + handoff externo attested)
```

Para adicionar uma skill da comunidade:
1. Criar um module em `modules/<id>/` seguindo `docs/module-authoring.md`
2. Criar struct que implemente `ResponseSkill` trait em `skills/builtin/`
3. Registrar em `SkillRegistry::default_builtin()`
4. Abrir PR em https://github.com/maiconburn/innerwarden

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

# monitor-ip (premium, opcional):
# requer permissão sudo para timeout+tcpdump; ajuste paths conforme distro.
# Exemplo mínimo (revise com cuidado antes de usar em produção):
# innerwarden ALL=(ALL) NOPASSWD: /usr/bin/timeout *, /usr/sbin/tcpdump *

# suspend-user-sudo (open, opcional):
# requer gerenciamento de drop-ins do sudoers e validação visudo.
# Exemplo mínimo (revise com cuidado antes de usar em produção):
# innerwarden ALL=(ALL) NOPASSWD: /usr/bin/install *, /usr/sbin/visudo -cf *, /bin/rm -f /etc/sudoers.d/zz-innerwarden-deny-*

# Shell audit trail (opcional, alto impacto de privacidade):
# - habilite apenas com autorização explícita do dono do host
# - o install.sh pode criar automaticamente:
#   /etc/audit/rules.d/innerwarden-shell-audit.rules
# - se necessário, garanta acesso ao audit.log:
#   sudo usermod -aG adm innerwarden
#   sudo usermod -aG audit innerwarden   # quando o grupo existir
```

O `data_dir` no config.toml **deve** bater com `ReadWritePaths` no service file.

Ver `docs/format.md` para schema completo de Event e Incident.

---

## Testes

```bash
make test   # 351 testes (110 sensor + 125 agent + 116 ctl) — todos devem passar
```

Fixtures em `testdata/`:
- `sample-auth.log` — 20 linhas SSH (9 falhas de 203.0.113.10, 8 de 198.51.100.5)
- `sample-audit.log` — exemplos de `auditd` (`EXECVE` + `TTY`) para testes locais de shell trail
- `watched/sshd_config`, `watched/sudoers` — fixtures para integrity watcher

Testes de integração local:
```bash
make run-sensor                              # grava em ./data/
make run-agent                              # lê de ./data/
innerwarden-agent --data-dir ./data --once  # roda uma vez e sai
innerwarden-agent --report --data-dir ./data # gera relatório operacional do trial
make replay-qa                               # valida fluxo fixture → sensor → agent → report

# Smoke test com AI em dry_run (seguro):
# 1. Coloque OPENAI_API_KEY no .env
# 2. Rode o sensor para gerar dados: make run-sensor
# 3. Rode o agent com a config de teste:
innerwarden-agent --data-dir ./data --config agent-test.toml
# Deve logar: "DRY RUN: would execute: sudo ufw deny from X"
# Decisões ficam em: ./data/decisions-YYYY-MM-DD.jsonl
# Telemetria fica em: ./data/telemetry-YYYY-MM-DD.jsonl
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

> **Regra de manutenção**: para mantenedores, o CLAUDE.md continua sendo a
> referência operacional mais detalhada do projeto. Mudanças relevantes de
> comportamento, artefatos, configuração ou dependências devem ser refletidas
> aqui no mesmo commit para preservar contexto de continuidade.

Documentação pública do repositório:
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `docs/index.md`

**Durante o production trial (execução paralela):**

- Desenvolvimento contínuo em branch local dedicada de feature
- Host de trial permanece estável sem upgrade automático
- Promoção para produção só acontece por fase, com validação explícita
- Plano ativo versionado em `docs/development-plan.md`

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

Fases concluídas (1–8.8, D1–D9, robustez produção, C.1–C.5, M.1–M.8): ver `docs/archive/` e histórico de commits.

- **Fase M.1–M.8:** ✅ sistema de módulos completo — manifest, validação, enable/disable, install/uninstall/publish/update-all, `module_package.rs` (download+SHA-256+tarball), `upgrade.rs` (GitHub API + semver)
- **Fase C.2–C.5:** ✅ `innerwarden disable`, `status` global, `doctor` (diagnóstico + fix hints + exit 1), `upgrade` (GitHub API + SHA-256 + install atômico + restart)
- **Release CI/CD:** ✅ `.github/workflows/release.yml` — x86_64 + aarch64 via cargo-zigbuild+zig 0.13; 6 binários + 6 `.sha256` + `install.sh`; pre-release automático para tags com `-`
- **install.sh reescrito:** ✅ baixa binários pré-compilados por padrão (~10 s vs 5-10 min); `INNERWARDEN_BUILD_FROM_SOURCE=1` faz fallback para build local
- **Fase D6:** ✅ SSE live push — `GET /api/events/stream`, file watcher 2 s, broadcast channel, `fetch()+ReadableStream` JS, `● LIVE` indicator, reconexão automática, fallback poll 30 s
- **Fase D7:** ✅ timeline ao vivo — `refreshLeftLive()` via SSE: novos cards com animação `cardSlideIn`, KPIs piscam em cyan (`kpiFlash`), diff incremental por `state.knownItemValues`, scroll preservado
- **Fase D8:** ✅ alertas push de incidentes — watcher lê novas linhas de `incidents-*.jsonl` por byte offset; emite evento SSE `alert` para High/Critical; `showAlertToast()` com badge, título e link clicável
- **Fase D9:** ✅ busca inline — `<input type="search">` filtra cards client-side por qualquer texto visível; sem round-trip; re-aplicado após refreshLeft/refreshLeftLive
- **Anthropic provider real:** ✅ POST `/v1/messages`, modelo padrão `claude-haiku-4-5-20251001`, troca automática do default OpenAI, `extract_json()` tolerante a prose, reutiliza `parse_decision` do openai.rs; 5 testes

- **Telegram T.1 + T.2:** ✅ notificações High/Critical + aprovação inline keyboard; `telegram.rs` + config `[telegram]`; polling task em modo contínuo; 11 testes
- **Ollama provider real:** ✅ POST `/api/chat`, `format: "json"`, `message.content`, `extract_json()` para prose, 120s timeout; 5 testes
- **doctor provider-aware:** ✅ lê `[ai] provider` do agent.toml; valida OPENAI_API_KEY / ANTHROPIC_API_KEY / Ollama por provider; hints de rotação de chave + journalctl
- **doctor Telegram:** ✅ section só quando `telegram.enabled = true`; valida formato bot token + chat_id; hints @BotFather / @userinfobot para iniciantes
- **doctor integrations:** ✅ Falco (binary, service, log, json_output), Suricata (binary, service, eve.json, ET rules), osquery (binary, service, results log, schedule config)
- **Q.1 replay-qa multi-source:** ✅ fixtures `sample-falco.jsonl` + `sample-suricata-eve.jsonl` + `sample-osquery.jsonl`; assertions de source por collector em `events-*.jsonl`
- **L.1 install.sh --with-integrations:** ✅ detecta + oferece instalar Falco/Suricata/osquery; patches idempotentes no sensor.toml; reinicia sensor
- **L.2 README Telemetry Stack:** ✅ seção 4-layer detection table + Ollama + link integrated-setup.md
- **L.3 CI verde:** ✅ 365 testes passando (139 agent + 116 ctl + 110 sensor)
- **L.4 CHANGELOG v0.1.0:** ✅ `CHANGELOG.md` com entrada completa — sensor, agent, skills, dashboard, ctl, módulos, infra
- **Q.3 docs/integrated-setup.md:** ✅ guia Ubuntu 22.04: Falco + Suricata + osquery + InnerWarden + Telegram
- **Q.4 doctor integrations:** ✅ (ver doctor integrations acima)
- **Integration recipes:** ✅ sistema de recipes declarativo (`integrations/`) com specs para Falco, Wazuh, osquery; geração de collectors via AI a partir de recipe + module-authoring.md
- **FalcoLogCollector:** ✅ implementado; `crates/sensor/src/collectors/falco_log.rs`; incident passthrough para High/Critical; módulo `falco-integration/`; 12 testes
- **SuricataEveCollector:** ✅ implementado; `crates/sensor/src/collectors/suricata_eve.rs`; alert/dns/http/tls/anomaly; incident passthrough sev 1-2; módulo `suricata-integration/`; 10 testes
- **OsqueryLogCollector:** ✅ implementado; `crates/sensor/src/collectors/osquery_log.rs`; severity por prefixo de query name (4 tiers); `removed` actions filtradas; IP privado filtrado; extrai IP (remote), path, user (decorations); summarys contextuais por query slug; módulo `osquery-integration/`; 9 testes
- **block-ip-pf skill:** ✅ implementado; `crates/agent/src/skills/builtin/block_ip_pf.rs`; `pfctl -t innerwarden-blocked -T add <IP>`; Open tier; 3 testes
- **macos_log collector:** ✅ implementado; `crates/sensor/src/collectors/macos_log.rs`; `log stream` subprocess; reusa parser SSH (`parse_sshd_message`); emite `sudo.command`; restart loop; 3 testes
- **CI macOS builds:** ✅ job `build-release-macos` em `macos-latest`; `x86_64-apple-darwin` + `aarch64-apple-darwin`; assets `innerwarden-*-macos-{x86_64,aarch64}`; `needs: build-release`
- **install.sh macOS:** ✅ detecta `Darwin`; paths `/usr/local/etc/innerwarden` + `/usr/local/var/lib/innerwarden`; launchd plists em `/Library/LaunchDaemons`; `macos_log` collector; asset naming `macos-{arch}`; unsupported arch imprime URL de issue pré-preenchida

Próximas direções:
- **Q.2 — VM end-to-end:** subir Ubuntu 22.04 + Falco + Suricata + osquery + InnerWarden, gerar tráfego simulado, validar UC-1 a UC-4 (user-side)
- **L.5 — Repositório público:** confirmar sem credenciais, adicionar tópicos GitHub, habilitar Discussions
- **`innerwarden module search`** — registry central em TOML hospedado; `search <termo>` lista módulos da comunidade com `install_url`
- **Fase D11** — notificações por browser (Web Notifications API) quando o dashboard está em background
- **Windows (v0.3.0 planned):** `sysmon_evtx` collector + `windows_event_log` collector + `block-ip-netsh` skill + `chocolatey`/`winget` install recipe. Tracked via platform-support issues.

Referência do roadmap: `docs/development-plan.md`, `docs/dashboard-roadmap.md`, `docs/public-readiness-checklist.md`

---

## Future Track — Edge / Web Abuse Defense

Status: future exploration, not part of current MVP.

After the host-security core is stable, InnerWarden may evolve to cover high-cost web route protection as an additional product capability.

This future track is not about blocking all AI crawlers or all automation.
Its purpose would be to protect expensive or abuse-prone routes, such as:

- search endpoints
- repository queries
- advanced filters
- export/download routes
- other dynamic high-cost paths

Possible future direction:

- access log collectors for Nginx / Apache
- detectors for automated high-cost access
- route classification by cost/sensitivity
- optional response skills such as temporary deny or rate limiting
- reuse of the existing AI-assisted decision layer

This is currently out of scope for the active roadmap.
The current priority remains:

1. production rollout hardening
2. temporal correlation
3. operational telemetry
4. core host-security quality
