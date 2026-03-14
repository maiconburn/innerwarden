# Phase 8.8 — Honeypot Medium Interaction (Cowrie-style)

## Objetivo

Elevar o honeypot do modo `banner` (banner estático + captura de payload bruto) para o
modo `medium` (emulação real do protocolo) — estilo Cowrie — preservando 100% de
compatibilidade retroativa com o modo padrão.

**Resultado**: atacantes que tentam autenticar via SSH ou fazer login via HTTP recebem
respostas de protocolo reais. Suas credenciais são capturadas e registradas no JSONL de
evidências da sessão.

---

## Novos arquivos

```
crates/agent/src/skills/builtin/honeypot/
  mod.rs           — lógica principal (existia, atualizado)
  ssh_interact.rs  — NOVO: handler russh para SSH medium interaction
  http_interact.rs — NOVO: parser HTTP manual com login page fake
```

---

## Config (`agent.toml`)

```toml
[honeypot]
# Interação padrão: banner estático (sem protocolo real)
interaction = "banner"

# Para emulação de protocolo real (Cowrie-style):
# interaction = "medium"
ssh_max_auth_attempts = 6   # rounds SSH antes de desconectar (medium only)
http_max_requests = 10      # requests HTTP por conexão (medium only)
```

Backwards compatible: `interaction` não existia antes → default `"banner"` preserva
comportamento anterior para todos os usuários existentes.

---

## SSH Medium Interaction (`ssh_interact.rs`)

### Biblioteca
`russh = "0.46"` — servidor SSH assíncrono em Rust puro.

### Funcionamento

1. `build_ssh_config(max_auth_attempts)` → gera chave Ed25519 efêmera por sessão.
2. `handle_connection(TcpStream, config, timeout)` → aceita conexão TCP, executa
   handshake SSH completo (key exchange, algoritmos de cifra), captura cada tentativa
   de autenticação.
3. Métodos capturados: `none`, `password`, `publickey`, `keyboard-interactive`.
4. Todas as tentativas são rejeitadas (`Auth::Reject`). Nenhum shell é concedido.
5. `channel_open_session` retorna `false` — impossível abrir sessão mesmo se a auth
   fosse aceita.
6. Timeout enforçado (`conn_timeout = 60s`) sobre toda a conexão.

### Evidência gerada (entrada no JSONL da sessão)

```json
{
  "type": "ssh_connection",
  "ts": "2026-03-13T14:32:00Z",
  "peer": "203.0.113.10:54321",
  "auth_attempts": [
    { "ts": "...", "method": "password", "username": "root", "password": "123456" },
    { "ts": "...", "method": "publickey", "username": "root", "key_name": "ssh-rsa" }
  ]
}
```

### Segurança
- Chave Ed25519 efêmera: gerada no início da sessão, descartada ao fim.
- Nunca persiste chaves privadas em disco.
- Nenhum acesso a filesystem ou shell concedido.

---

## HTTP Medium Interaction (`http_interact.rs`)

### Protocolo
Parser HTTP/1.x manual — sem dependência de library HTTP de servidor.

### Funcionamento

1. Lê headers até `\r\n\r\n`.
2. Rota por método + path:
   - `GET /` → 302 redirect para `/login`
   - `GET /login` → 200 com página HTML de login fake
   - `POST /login` → captura body URL-encoded (`username=`, `password=`), retorna
     página de "login falhou"
   - `*` → 404
3. Repete até `max_requests` por conexão ou timeout.
4. Captura headers "interessantes" de cada request (excluindo `host`, `connection`,
   `content-*`).

### Evidência gerada (entrada no JSONL da sessão)

```json
{
  "type": "http_connection",
  "ts": "2026-03-13T14:32:05Z",
  "peer": "203.0.113.10:54400",
  "requests": [
    {
      "ts": "...",
      "method": "GET",
      "path": "/login",
      "captured_form": null,
      "headers": { "user-agent": "curl/7.88" }
    },
    {
      "ts": "...",
      "method": "POST",
      "path": "/login",
      "captured_form": { "username": "admin", "password": "admin123" },
      "headers": { "user-agent": "curl/7.88" }
    }
  ]
}
```

### Página de login fake
HTML simples com formulário padrão. Sem recursos externos, sem JavaScript.
Retorna `401 Unauthorized` implícito via `200 OK` com mensagem de "Login Failed" para
manter o atacante tentando mais credenciais.

---

## Fluxo de dispatch em `run_listener`

```
incoming connection
        │
        ├─ strict_target_only check (rejeita se IP diferente do alvo)
        │
        ├─ interaction == "medium"?
        │   ├─ service == "ssh"  → ssh_interact::handle_connection(...)
        │   │                      → evidence type: "ssh_connection"
        │   └─ service == "http" → http_interact::handle_connection(...)
        │                          → evidence type: "http_connection"
        │
        └─ interaction == "banner" (default)
            → capture_payload + write banner bytes (comportamento anterior)
            → evidence type: "banner"
```

---

## Compatibilidade e regressão

- Todos os testes existentes continuam passando (141 total).
- Novo `interaction` field tem default `"banner"` → zero breaking change.
- Modo `banner` não usa `russh` (sem overhead de lib quando não configurado).
- `SandboxWorkerSpec` atualizado para propagar `interaction`, `ssh_max_auth_attempts`,
  `http_max_requests` para subprocessos sandbox.

---

## Testes adicionados

| Arquivo | Testes |
|---------|--------|
| `ssh_interact.rs` | `build_ssh_config_generates_key`, `handler_records_password_attempt`, `handler_records_none_attempt`, `handler_always_rejects`, `handler_denies_shell` |
| `http_interact.rs` | `parse_urlencoded_basic`, `parse_urlencoded_plus_space`, `parse_urlencoded_empty`, `find_header_end_*`, `route_*`, `body_preview_sanitizes`, `interesting_headers_filters` |
| `honeypot/mod.rs` | `interaction_normalization_is_stable`, `listener_medium_dry_run_shows_interaction`, `config_defaults_to_banner_interaction` |

---

## Dependência adicionada

```toml
# crates/agent/Cargo.toml
russh = "0.46"
```

`async-trait` já era dependência transitiva; não foi adicionado separadamente.

---

## Uso em produção

```toml
# agent.toml — habilitar interação média
[honeypot]
mode = "listener"
services = ["ssh", "http"]
port = 2222
http_port = 8080
interaction = "medium"
ssh_max_auth_attempts = 6
http_max_requests = 10
duration_secs = 300
```

O modo `medium` exige que o serviço esteja em modo `listener`. Em modo `demo`, o
campo `interaction` é ignorado (o modo demo nunca abre sockets).
