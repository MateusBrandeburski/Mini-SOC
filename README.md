# Mini SOC — Security Operations Dashboard

Painel web (FastAPI + SPA Tailwind/DaisyUI/Chart.js) para **monitorar e gerenciar o
CrowdSec** (IDS/IPS) e **ler os logs de acesso do nginx**, rodando na própria máquina
do servidor (Debian). Feito para um "mini SOC" caseiro/interno.

- **CrowdSec:** estatísticas, série temporal de bloqueios, rankings (países/cenários/ASN),
  tabela de decisões com filtros, e **ações** (banir, desbanir, alterar duração, tornar
  permanente), geolocalização de IP sob demanda.
- **Logs Nginx:** leitor/tailer dos `*access.log*` (incl. `.gz`), filtros, busca,
  estatísticas em gráficos, **tail ao vivo (SSE)**, modal de detalhe e marcação de IPs banidos.
- **Configurações (⚙ na navbar):** páginas próprias de **Alertas** (webhook/Telegram/e-mail),
  **Auditoria** (log de toda ação de escrita) e **Whitelist** (allowlist do CrowdSec).

> Este README cobre a **aplicação**. A configuração do **CrowdSec/IDS em si** (cenários,
> profiles, bouncers, whitelist a nível de motor) está em **[`deploy/crowdsec/README.md`](deploy/crowdsec/README.md)**.

---
<img width="1845" height="934" alt="Captura de tela de 2026-07-04 19-25-20" src="https://github.com/user-attachments/assets/bafdfd13-c814-494d-8950-338097168ba3" />
<img width="1845" height="934" alt="image" src="https://github.com/user-attachments/assets/5b919ff7-ca78-4795-9be4-4989f197ba5f" />
<img width="1845" height="934" alt="Captura de tela de 2026-07-04 19-25-25" src="https://github.com/user-attachments/assets/8e29318f-c40d-4263-9ecc-99d09c8c02fe" />

## Sumário

- [Arquitetura (regra de ouro)](#arquitetura-regra-de-ouro)
- [Requisitos](#requisitos)
- [Início rápido (dev/local)](#início-rápido-devlocal)
- [Configuração (`.env`)](#configuração-env)
- [Autenticação](#autenticação)
- [Funcionalidades](#funcionalidades)
- [Deploy em produção](#deploy-em-produção)
- [Camadas de bloqueio / IDS](#camadas-de-bloqueio--ids-crowdsec--nginx)
- [Assets locais (sem CDN)](#assets-locais-sem-cdn)
- [Segurança](#segurança)
- [Referência de API](#referência-de-api)
- [Estrutura do projeto](#estrutura-do-projeto)

---

## Arquitetura (regra de ouro)

Separação estrita entre **leitura** e **escrita**:

- **Leitura** (estatísticas/histórico): lê o banco do CrowdSec em **modo somente-leitura**
  (`PRAGMA query_only = ON` no SQLite, ou `mode=ro`). **Nunca escreve** nesse banco.
- **Escrita** (banir/desbanir/duração/whitelist): **sempre** via `cscli` em `subprocess`
  com **lista de argumentos** (jamais `shell=True`). O CrowdSec é a fonte da verdade.
- **Estado da app** (config de alertas, marca d'água do poller, auditoria, cache de geoip):
  num SQLite **separado** (`./data/app.db`).

Front-end é uma **SPA single-file** (`static/index.html`) servida pelo FastAPI, com
roteamento por path no cliente (History API): `/crowdsec/painel`, `/crowdsec/decisoes`,
`/logs/listagem`, `/logs/estatisticas`, `/alertas`, `/auditoria`, `/whitelist`.

## Requisitos

- **Debian** (testado em 12/13), **Python 3.11+**.
- **CrowdSec** instalado; binário **`cscli`** no PATH (ou informe `CSCLI_BIN`).
- Banco do CrowdSec em **SQLite** (`/var/lib/crowdsec/data/crowdsec.db`) — ou MySQL/MariaDB, se migrado.
- **nginx** com logs em `/var/log/nginx/`.
- (Opcional) chave da API do **iplocation.net** para geolocalização de IP.

## Início rápido (dev/local)

```bash
git clone git@github.com:MateusBrandeburski/Mini-SOC.git painel-crowdsec
cd painel-crowdsec

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print('APP_SECRET=' + secrets.token_urlsafe(48))"   # cole no .env
python auth.py 'sua-senha-forte'                                               # gera ADMIN_PASSWORD_HASH
$EDITOR .env      # ajuste APP_SECRET, ADMIN_PASSWORD_HASH e caminhos

python app.py     # sobe em http://0.0.0.0:8100
```

Acesse `http://<host>:8100/` e faça login com `ADMIN_USER` + a senha.

> **Sem CrowdSec/nginx na máquina de dev?** As abas que dependem deles ficam vazias/erro,
> mas o app sobe. Para desenvolver, aponte `CROWDSEC_DB_PATH` para um SQLite de teste e
> `NGINX_LOG_GLOB` para um diretório com logs de exemplo.

## Configuração (`.env`)

Todas as variáveis estão comentadas em [`.env.example`](.env.example). Tabela completa:

| Variável | Padrão | Descrição |
|---|---|---|
| `CROWDSEC_DB_TYPE` | `sqlite` | `sqlite`, `mysql` ou `mariadb` |
| `CROWDSEC_DB_PATH` | `/var/lib/crowdsec/data/crowdsec.db` | caminho do SQLite do CrowdSec |
| `CROWDSEC_DB_READONLY` | `0` | informativo (a app sempre lê read-only; o `.env.example` envia `1`) |
| `CSCLI_BIN` | `cscli` | caminho do binário `cscli` |
| `CROWDSEC_DB_HOST/PORT/USER/NAME` | `127.0.0.1` / `3306` / `crowdsec` / `crowdsec` | só se `TYPE=mysql\|mariadb` |
| `CROWDSEC_DB_PASSWORD` | — | senha do MySQL/MariaDB (só se migrado) |
| `APP_SECRET` | — (obrigatório) | segredo p/ assinar cookies. **O painel recusa iniciar** sem ele (gere um forte) |
| `ADMIN_USER` | `admin` | usuário de login |
| `ADMIN_PASSWORD_HASH` | — | hash bcrypt da senha (gere com `python auth.py 'senha'`) |
| `ADMIN_PASSWORD` | — | senha em texto plano — **só dev**, deixe vazio em prod |
| `HOST` / `PORT` | `0.0.0.0` / `8100` | bind do servidor |
| `APP_DB_PATH` | `./data/app.db` | SQLite de estado da app |
| `SESSION_COOKIE` | `csdash_session` | nome do cookie |
| `SESSION_MAX_AGE` | `43200` | validade da sessão (s) |
| `COOKIE_SECURE` | `0` | `1` se servir por HTTPS |
| `IPLOCATION_API_KEY` | — | chave do iplocation.net (geoloc sob demanda) |
| `GEOIP_CACHE_TTL_DAYS` | `30` | TTL do cache de geoloc (0 = nunca expira) |
| `NGINX_LOG_GLOB` | `/var/log/nginx/*access.log*` | glob dos logs (inclui rotacionados e `.gz`) |
| `NGINX_LOG_FORMAT_REGEX` | combined | regex do `log_format` (grupos: ip,user,time,method,path,proto,status,size,referer,ua) |
| `ALERT_POLL_SECONDS` | `20` | intervalo do poller de novos bans |
| `ALERT_ORIGINS` | `crowdsec,cscli` | origens que disparam alerta (evite CAPI/lists — muito volume) |
| `ALERT_WEBHOOK_URL` | — | webhook (HTTP POST JSON) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | — | canal Telegram |
| `SMTP_HOST/USER/PASSWORD/FROM/TO` | — | canal e-mail (host/credenciais/remetente/destinos) |
| `SMTP_PORT` | `587` | porta SMTP |
| `SMTP_TLS` | `1` | STARTTLS |

### MySQL/MariaDB

Se o banco do CrowdSec foi migrado, defina `CROWDSEC_DB_TYPE=mysql` + `CROWDSEC_DB_HOST/PORT/USER/PASSWORD/NAME`.
As funções de data alternam automaticamente entre SQLite (`date()`, `datetime('now')`) e MySQL (`DATE()`, `UTC_TIMESTAMP()`).

## Autenticação

- Login obrigatório em todos os endpoints (exceto `/login` e o HTML). Sessão via cookie
  assinado (`itsdangerous`); senha com **hash bcrypt**.
- **Gerar/alterar a senha do admin:**
  ```bash
  python auth.py 'nova-senha-forte'     # imprime o hash bcrypt
  # cole em ADMIN_PASSWORD_HASH= no .env e reinicie o serviço
  ```
- A senha só existe como hash — **não é recuperável**. Se perder, gere uma nova como acima.

## Funcionalidades

**Aba CrowdSec**
- **Painel:** cards (bloqueados agora, IPs únicos ativos, novos hoje, últimas 24h, total de
  decisões, total de alertas), série temporal por dia, rankings top países/cenários/ASN.
- **Decisões:** tabela filtrável (IP, tipo, origem, só-ativos) — **filtros aplicam sozinhos**
  (selects na hora; campos de texto ao digitar, com debounce; sem botão "Aplicar").
  Ações por linha (⋯) e globais:
  - **Banir IP** (IP/CIDR + duração + tipo). Se o IP estiver na whitelist, aparece um aviso +
    switch **"Remover da whitelist e banir"** (usa `--bypass-allowlist`).
  - **Desbanir IP** (por linha ou botão global; por IP/CIDR digitado).
  - **Alterar duração** / **Tornar permanente**.
  - **Geolocalizar** (🌐) sob demanda via iplocation.net (cache no `app.db`).
  - Origens são exibidas com nomes amigáveis (CAPI → *CrowdSec - CTI*, crowdsec → *Customizado*,
    cscli → *Block Manual*); o valor real é preservado nos filtros.

**Aba Logs Nginx**
- **Listagem:** seletor de arquivo (por site/rotacionados), filtros que aplicam sozinhos,
  paginação, badge de IP banido, **tail ao vivo (SSE)**, e botão **Detalhe** (modal com
  User-Agent, acesso/domínio, rota completa, referer, etc. — mantém a tabela compacta).
- **Estatísticas:** requisições ao longo do tempo, distribuição de status, top IPs/rotas/UAs.

**Menu de engrenagem (⚙, navbar)** — páginas próprias:
- **Alertas:** liga/desliga, origens/cenários/threshold, canais (webhook/Telegram/e-mail),
  botão "enviar teste" e histórico de alertas emitidos.
- **Auditoria:** log paginado de toda ação de escrita (ator, ação, alvo, comando cscli, saída).
- **Whitelist:** IPs/CIDRs que **nunca são bloqueados** (allowlist do CrowdSec via
  `cscli allowlists`). Adicionar também **desbane** o IP na hora.

## Deploy em produção

O projeto é implantado num container/VM Debian via **`deploy.sh`** (tar-over-ssh — não usa
rsync/git no destino):

```bash
./deploy.sh                 # deploy no host padrão (root@SEU_SERVIDOR)
TARGET=root@10.0.0.5 ./deploy.sh
./deploy.sh --restart       # reinicia o serviço
./deploy.sh --logs          # journalctl -f
./deploy.sh --status        # status + porta
./deploy.sh --stop
```

O `deploy.sh`:
- instala `python3-venv` se faltar, cria/atualiza o venv e as deps;
- **preserva** o `.env` e o `data/app.db` remotos (não sobrescreve);
- no **primeiro** deploy gera `APP_SECRET` + senha do admin (mostrada **uma vez**);
- instala/atualiza a unit systemd `painel-crowdsec.service` (`After=crowdsec.service`, `User=root`) e reinicia com healthcheck.

Rodar a unit manualmente:
```bash
cp deploy/painel-crowdsec.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now painel-crowdsec
```

**Reverse proxy:** veja [`deploy/nginx-reverse-proxy.conf.example`](deploy/nginx-reverse-proxy.conf.example).
**Não exponha o painel na internet** sem VPN / allowlist de IP / basic-auth, **além** do login.

### Permissões

A app precisa **ler** o DB do CrowdSec e `/var/log/nginx/`, e **executar** `cscli`. Numa
máquina interna, o mais simples é rodar como `root` (pressuposto do projeto). Alternativa
restrita: usuário dedicado + ACLs de leitura + `sudoers` limitado ao `cscli`.

## Camadas de bloqueio / IDS (CrowdSec + nginx)

> Detalhes e comandos de instalação em **[`deploy/crowdsec/README.md`](deploy/crowdsec/README.md)**.

O CrowdSec **detecta** (lendo os logs) e **decide** banir; o bloqueio real é feito por
**bouncers**. Este setup usa **duas camadas**, porque o firewall sozinho não bloqueia quem
vem via Cloudflare:

1. **`cs-firewall-bouncer`** (camada 3/4, nftables/iptables): dropa pacotes pelo IP de origem.
   Cobre acesso **direto pelo IP** do servidor.
2. **`crowdsec-nginx-bouncer`** (camada 7, lua no nginx): checa o **IP real** do visitante
   (`CF-Connecting-IP`, resolvido pelo `real_ip` do nginx) e devolve **403** para banidos.
   Cobre tráfego **HTTP via Cloudflare** (onde o pacote chega com IP da borda da CF, e por
   isso o firewall-bouncer não pega o atacante). Use **`MODE=stream`** no bouncer.

**Detecção:** além dos cenários do hub, há um cenário custom que **bane na 1ª tentativa** de
acesso a arquivo sensível (`.env`, `.git/`, `.aws/`…) e outro para acesso direto pelo IP.
**Bans são permanentes** por padrão (`profiles.yaml` → `duration: 87600h`).

**Whitelist:** IPs/CIDRs na allowlist `painel` (gerida pela aba Whitelist) nunca são
bloqueados; também há whitelist a nível de parser (rede própria) e a collection
`whitelist-good-actors` (bots legítimos).

## Assets locais (sem CDN)

Tailwind, DaisyUI, Chart.js e marked são servidos de **`static/vendor/`** (não de CDN externo):
sem dependência de internet do cliente (o painel é de LAN) e sem *flash* de conteúdo sem
estilo no F5. Para atualizar uma lib, baixe a versão nova para `static/vendor/` (os caminhos
em `static/index.html` apontam para `/static/vendor/...`).

## Segurança

- **Autenticação obrigatória**; sessão assinada; senha bcrypt.
- `subprocess` **sempre** com lista de argumentos, **nunca** `shell=True`.
- IP/CIDR validados com `ipaddress` (rejeita catch-all `/0`) e duração validada (formato Go)
  **antes** de chegar ao `cscli`.
- Logs: só arquivos que casam com `NGINX_LOG_GLOB` (o cliente escolhe entre os descobertos,
  nunca digita caminho livre — anti path-traversal/LFI).
- **Não exponha o painel na internet** sem camada extra (VPN/allowlist/basic-auth).

## Referência de API

Todos exigem sessão autenticada (exceto `/login`).

| Método | Rota | Descrição |
|---|---|---|
| POST | `/login`, `/logout` | autenticação |
| GET | `/api/health` | saúde (CrowdSec + cscli) |
| GET | `/api/stats` | cards do painel |
| GET | `/api/timeseries?days&origin` | série temporal |
| GET | `/api/top/{countries\|scenarios\|asn}` | rankings |
| GET | `/api/origins` | origens distintas |
| GET | `/api/geoip?ip` | geolocaliza (cache) |
| GET | `/api/decisions?...` | lista decisões (filtros/paginação) |
| POST | `/api/decisions` | banir (`bypass_allowlist` opcional) |
| DELETE | `/api/decisions/by-ip?value` | desbanir por IP/CIDR |
| DELETE | `/api/decisions/{id}` | desbanir por id |
| PATCH | `/api/decisions/duration` | alterar duração |
| GET | `/api/whitelist` | lista a whitelist |
| GET | `/api/whitelist/check?value` | IP está na whitelist? |
| POST | `/api/whitelist` | adiciona (+ desbane) |
| DELETE | `/api/whitelist?value` | remove |
| GET/PUT | `/api/alerts/config` | config de alertas |
| GET | `/api/alerts/history` | histórico de alertas |
| POST | `/api/alerts/test` | envia teste |
| GET | `/api/audit` | auditoria |
| GET | `/api/logs/files` | arquivos de log |
| GET | `/api/logs?file&...` | consulta logs |
| GET | `/api/logs/stats?file` | estatísticas dos logs |
| GET | `/api/logs/stream?file` | tail ao vivo (SSE) |

## Estrutura do projeto

```
painel-crowdsec/
├── app.py              # FastAPI: rotas de API + serve a SPA (e os paths do roteador)
├── config.py           # configuração central (.env → Settings)
├── crowdsec.py         # leitura read-only do DB + wrapper cscli (decisões, allowlist)
├── nginx_logs.py       # descoberta / parse / tail dos logs
├── alerts.py           # poller de novos bans + canais (webhook/Telegram/e-mail)
├── geoip.py            # geolocalização sob demanda (iplocation.net) + cache
├── auth.py             # login/sessão (+ CLI p/ gerar hash de senha)
├── db.py               # app.db: config alertas, watermark, auditoria, geoip cache
├── static/
│   ├── index.html      # SPA (Tailwind + DaisyUI + Chart.js)
│   └── vendor/         # libs vendorizadas (tailwind, daisyui, chart.js, marked)
├── requirements.txt
├── .env.example
├── deploy.sh           # deploy tar-over-ssh + systemd + healthcheck
└── deploy/
    ├── painel-crowdsec.service
    ├── nginx-reverse-proxy.conf.example
    └── crowdsec/       # config do IDS (cenários, profiles, bouncers) + README
```

## Contribuindo

Contribuições são bem-vindas! Veja o guia em **[CONTRIBUTING.md](CONTRIBUTING.md)**
para saber como reportar bugs, sugerir melhorias e enviar Pull Requests.

## Licença

Este projeto é distribuído sob a licença [MIT](LICENSE) — uso livre e gratuito,
inclusive comercial. Você pode usar, copiar, modificar e distribuir o software,
bastando manter o aviso de copyright e a licença. Sem garantias.
