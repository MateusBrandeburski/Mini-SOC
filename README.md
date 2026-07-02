# Mini SOC — Security Operations Dashboard

Aplicação web (FastAPI + SPA Tailwind/DaisyUI/Chart.js, zero-build) — um painel
de operações de segurança ("mini SOC") para **monitorar e gerenciar o CrowdSec**
(IDS/IPS) e **ler os logs de acesso do nginx**, rodando na própria máquina do
servidor (Debian).

- **Aba CrowdSec:** estatísticas, série temporal de bloqueios, rankings
  (países/cenários/ASN), tabela de decisões com filtros, e **ações de
  gerenciamento** (banir, desbanir, alterar duração, tornar permanente) +
  **alertas de novos bans** (webhook / Telegram / e-mail).
- **Aba Logs Nginx:** leitor/tailer dos `*access.log*` (incl. `.gz`), filtros,
  busca, estatísticas, **tail ao vivo (SSE)** e marcação de IPs banidos.

## Regra de ouro (leitura × escrita)

- **Leitura** (estatísticas/histórico): lê o banco do CrowdSec em **modo
  somente-leitura** (`PRAGMA query_only = ON` no SQLite, ou `mode=ro`). **Nunca
  escreve** nesse banco.
- **Escrita** (banir/desbanir/ajustar): **sempre** via `cscli` em `subprocess`
  com **lista de argumentos** (jamais `shell=True`). O CrowdSec é a fonte da
  verdade.
- **Estado da app** (config de alertas, marca d'água, auditoria): num SQLite
  **separado** (`./data/app.db`).

---

## Requisitos

- Debian, Python 3.11+.
- CrowdSec instalado; binário `cscli` no PATH (ou informe `CSCLI_BIN`).
- Banco do CrowdSec em SQLite (`/var/lib/crowdsec/data/crowdsec.db`) — ou
  MySQL/MariaDB, se migrado.
- nginx com logs em `/var/log/nginx/`.

## Instalação

```bash
cd /opt
git clone <repo> painel-crowdsec   # ou copie os arquivos para /opt/painel-crowdsec
cd painel-crowdsec

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Gere o segredo de sessão:
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Gere o hash da senha do admin:
python auth.py 'sua-senha-forte'
# Edite o .env com APP_SECRET e ADMIN_PASSWORD_HASH.
$EDITOR .env

python app.py
```

Acesse `http://<host>:8100/` e faça login com `ADMIN_USER` + a senha.

## Permissões

A app precisa **ler** `/var/lib/crowdsec/data/crowdsec.db` e `/var/log/nginx/`,
e **executar** `cscli`. O caminho mais simples numa máquina interna é rodar como
`root` (é o pressuposto deste projeto). Alternativa mais restrita: usuário
dedicado com ACLs de leitura no DB/logs e `sudoers` limitado ao `cscli decisions`.

## systemd

Veja `deploy/painel-crowdsec.service`:

```bash
sudo cp deploy/painel-crowdsec.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now painel-crowdsec
sudo systemctl status painel-crowdsec
journalctl -u painel-crowdsec -f
```

A unit usa `After=crowdsec.service` e `User=root`, e lê o `.env` via
`EnvironmentFile`.

## Reverse proxy nginx (com allowlist)

Veja `deploy/nginx-reverse-proxy.conf.example`. **Não exponha o painel na
internet** sem VPN / allowlist de IP / basic-auth, **além** do login da app.
O exemplo já desabilita buffering para o SSE do tail ao vivo.

---

## Configuração (`.env`)

Todas as variáveis estão documentadas em `.env.example`. Principais:

| Variável | Descrição |
|---|---|
| `CROWDSEC_DB_TYPE` | `sqlite` (padrão), `mysql` ou `mariadb` |
| `CROWDSEC_DB_PATH` | caminho do SQLite do CrowdSec |
| `CSCLI_BIN` | caminho do `cscli` (padrão: `cscli` no PATH) |
| `APP_SECRET` | segredo p/ assinar cookies (gere um forte) |
| `ADMIN_USER` / `ADMIN_PASSWORD_HASH` | credenciais de login |
| `NGINX_LOG_GLOB` | glob dos logs (padrão `/var/log/nginx/*access.log*`) |
| `NGINX_LOG_FORMAT_REGEX` | regex do `log_format` (padrão combined) |
| `ALERT_POLL_SECONDS` | intervalo do poller de novos bans |
| `ALERT_ORIGINS` | origens que disparam alerta (ex.: `crowdsec,cscli`) |
| `ALERT_WEBHOOK_URL` / `TELEGRAM_*` / `SMTP_*` | canais de notificação |

### MySQL/MariaDB

Se o banco do CrowdSec foi migrado, defina `CROWDSEC_DB_TYPE=mysql` e as
variáveis `CROWDSEC_DB_HOST/PORT/USER/PASSWORD/NAME`. As funções de data mudam
automaticamente entre SQLite (`date()`, `datetime('now')`) e MySQL (`DATE()`,
`UTC_TIMESTAMP()`).

---

## Alertas de novos bans

Um poller em background (`asyncio`) consulta o banco do CrowdSec a cada
`ALERT_POLL_SECONDS` por decisões com `id` acima da **marca d'água** salva no
`app.db`. Novos bans que passam pelos filtros (origem/cenário/threshold) são
notificados por **webhook**, **Telegram** e/ou **e-mail**, e registrados no
histórico. Configure canais e filtros direto na aba **Alertas** da interface, ou
via `.env`.

> **Nota:** o CrowdSec também tem notificações nativas
> (`/etc/crowdsec/profiles.yaml` + `/etc/crowdsec/notifications/*.yaml`). Esta
> app implementa alertas próprios para centralizar controle na interface — as
> duas abordagens podem coexistir.

## Ações de gerenciamento (importante)

- **Alterar duração** = `cscli decisions delete --ip <IP>` (limpa **todas** as
  decisões do IP) **+** `cscli decisions add --ip <IP> --duration <novo>`.
  Não existe `cscli decisions update`.
- **Unban pode ser temporário:** se o IP continuar casando num cenário/blocklist,
  o CrowdSec cria uma nova decisão no próximo hit. Para exceção permanente o
  caminho é a **allowlist** do CrowdSec (fora do escopo desta app — *TODO*).
- Toda decisão criada pela app usa um `--reason` identificável (ex.:
  `painel: banimento manual`) para rastreio, e é registrada na **auditoria**.

## Segurança

- **Autenticação obrigatória** em todos os endpoints (exceto `/login` e o HTML).
  Sessão via cookie assinado (`itsdangerous`); senha com hash bcrypt.
- `subprocess` sempre com **lista de argumentos**, **nunca** `shell=True`.
- IP/CIDR validados com `ipaddress` e duração validada (formato Go) **antes** de
  chegar ao `cscli`.
- Logs: só é possível ler arquivos que casem com o `NGINX_LOG_GLOB` — o cliente
  escolhe entre os arquivos descobertos, **nunca** digita caminho livre (proteção
  contra path traversal / LFI).
- **Não deixe o painel exposto na internet** sem VPN/allowlist/basic-auth no
  nginx, além do login.

## Endpoint de saúde

`GET /api/health` verifica a conexão com o banco do CrowdSec e a presença do
`cscli`.

---

## Estrutura

```
painel-crowdsec/
├── app.py            # FastAPI: rotas de API + serve o front
├── config.py         # configuração central (.env)
├── crowdsec.py       # leitura read-only do DB + wrapper cscli (subprocess)
├── nginx_logs.py     # descoberta/parse/tail dos logs
├── alerts.py         # poller de novos bans + canais de notificação
├── auth.py           # login/sessão (+ CLI p/ gerar hash de senha)
├── db.py             # app.db: config alertas, watermark, auditoria, histórico
├── static/index.html # SPA (Tailwind + DaisyUI + Chart.js), abas
├── requirements.txt
├── .env.example
└── deploy/
    ├── painel-crowdsec.service
    └── nginx-reverse-proxy.conf.example
```
# Mini-SOC
