#!/usr/bin/env bash
# ============================================================================
# deploy.sh — Deploy do Mini SOC (Security Operations Dashboard) direto num LXC.
#
# Uso:
#   ./deploy.sh                      # deploy no host padrão (SEU_SERVIDOR)
#   TARGET=root@10.0.0.5 ./deploy.sh # outro host/usuário
#   ./deploy.sh --restart            # só reinicia o serviço remoto
#   ./deploy.sh --logs               # segue os logs (journalctl -f) do serviço
#   ./deploy.sh --status             # status do serviço
#
# Pré-requisitos LOCAIS: rsync, ssh, acesso SSH por chave ao TARGET.
# O LXC é Debian (PEP 668 / EXTERNALLY-MANAGED) — por isso usamos venv.
# ============================================================================
set -euo pipefail

# ------------------------------------------------------------------ parâmetros
TARGET="${TARGET:-root@SEU_SERVIDOR}"
REMOTE_DIR="${REMOTE_DIR:-/opt/painel-crowdsec}"
SERVICE="${SERVICE:-painel-crowdsec}"
PORT="${PORT:-8100}"
BIND_HOST="${BIND_HOST:-0.0.0.0}"

# Caminhos no LXC (confirmados no ambiente):
CROWDSEC_DB="/var/lib/crowdsec/data/crowdsec.db"
CSCLI_BIN="/usr/bin/cscli"
# Glob dos logs: *access.log* casa TANTO o access.log genérico QUANTO os logs
# por-vhost (hubble-front_access.log, cnn-front_access.log, direct-ip_access.log
# ...), incluindo rotacionados e .gz. O painel deriva o site/domínio do nome do
# arquivo, então queremos todos eles.
NGINX_GLOB="/var/log/nginx/*access.log*"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------ cores/log
c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
info()  { echo "$(c '1;34' '›') $*"; }
ok()    { echo "$(c '1;32' '✓') $*"; }
warn()  { echo "$(c '1;33' '!') $*"; }
die()   { echo "$(c '1;31' '✗') $*" >&2; exit 1; }

SSH() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$TARGET" "$@"; }

# ------------------------------------------------------------------ subcomandos rápidos
case "${1:-}" in
  --restart) info "reiniciando $SERVICE em $TARGET"; SSH "systemctl restart $SERVICE && systemctl --no-pager status $SERVICE | head -12"; exit 0 ;;
  --logs)    info "seguindo logs de $SERVICE (Ctrl-C p/ sair)"; SSH -t "journalctl -u $SERVICE -f -n 100"; exit 0 ;;
  --status)  SSH "systemctl --no-pager status $SERVICE | head -20; echo; ss -ltnp | grep :$PORT || echo 'porta $PORT sem listener'"; exit 0 ;;
  --stop)    info "parando $SERVICE"; SSH "systemctl stop $SERVICE"; ok "parado"; exit 0 ;;
  "" ) : ;; # deploy completo
  * ) die "argumento desconhecido: $1 (use --restart|--logs|--status|--stop)";;
esac

# ============================================================================
# 0. Sanidade local
# ============================================================================
command -v tar >/dev/null || die "tar não encontrado localmente"
command -v ssh >/dev/null || die "ssh não encontrado localmente"
[ -f "$SCRIPT_DIR/app.py" ] || die "app.py não encontrado em $SCRIPT_DIR"
[ -f "$SCRIPT_DIR/static/index.html" ] || die "static/index.html não encontrado — o front não foi gerado"

info "Testando conexão SSH com $TARGET ..."
SSH 'true' 2>/dev/null || die "não consegui conectar via SSH em $TARGET (configure chave SSH)"
ok "SSH OK"

# ============================================================================
# 1. Checagens no LXC
# ============================================================================
info "Verificando ambiente do LXC ..."
SSH bash -s <<REMOTE_CHECK
set -e
command -v python3 >/dev/null || { echo "ERRO: python3 ausente"; exit 1; }
# venv precisa de ensurepip (Debian separa em python3-venv). Instala se faltar.
if ! python3 -c 'import ensurepip' 2>/dev/null; then
  echo "ensurepip ausente — instalando python3-venv/python3-full ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq python3-venv python3-full >/dev/null 2>&1 || true
  python3 -c 'import ensurepip' 2>/dev/null || { echo "ERRO: não consegui habilitar venv (apt install python3-venv)"; exit 1; }
fi
[ -x "$CSCLI_BIN" ] || echo "AVISO: cscli não encontrado em $CSCLI_BIN — ações de escrita falharão"
[ -f "$CROWDSEC_DB" ] || echo "AVISO: DB do CrowdSec não encontrado em $CROWDSEC_DB"
command -v systemctl >/dev/null || { echo "ERRO: systemd ausente"; exit 1; }
echo "python: \$(python3 --version)"
REMOTE_CHECK
ok "ambiente do LXC verificado"

# ============================================================================
# 2. Envio do código via tar-over-ssh (rsync não existe no LXC; git também não)
# ============================================================================
info "Criando diretório remoto $REMOTE_DIR ..."
SSH "mkdir -p '$REMOTE_DIR' '$REMOTE_DIR/data'"

info "Enviando código (tar-over-ssh) ..."
# Empacota localmente excluindo venv/dados/pyc/segredos e extrai no LXC.
# Preserva o .env e o data/app.db remotos (não estão no tar).
tar -C "$SCRIPT_DIR" \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='data/app.db' \
  --exclude='.env' \
  --exclude='.git' \
  --exclude='.claude' \
  -czf - . | SSH "tar -C '$REMOTE_DIR' -xzf -"
ok "código enviado"

# ============================================================================
# 3. venv + dependências no LXC
# ============================================================================
info "Criando/atualizando venv e instalando dependências (pode demorar) ..."
SSH bash -s <<REMOTE_VENV
set -e
cd "$REMOTE_DIR"
# Recria o venv se não existir OU se estiver quebrado (ex.: criado sem ensurepip).
if [ ! -x .venv/bin/python ] || ! .venv/bin/python -m ensurepip --version >/dev/null 2>&1; then
  rm -rf .venv
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt
echo "deps instaladas"
REMOTE_VENV
ok "venv pronto"

# ============================================================================
# 4. .env de produção (gera segredo + senha se ainda não existir)
# ============================================================================
info "Configurando .env de produção ..."
# Geramos segredo e senha no LXC; a senha é capturada aqui e mostrada UMA vez
# ao final. Capturamos o stdout do SSH para pegar a linha GENERATED_PASSWORD=.
# Passamos os valores como variáveis de ambiente (via `env` no lado remoto) para
# evitar que o shell remoto re-expanda o `*` do glob nos argumentos posicionais.
ENV_OUT="$(SSH env \
  "P_DIR=$REMOTE_DIR" \
  "P_DB=$CROWDSEC_DB" \
  "P_CSCLI=$CSCLI_BIN" \
  "P_GLOB=$NGINX_GLOB" \
  "P_BHOST=$BIND_HOST" \
  "P_PORT=$PORT" \
  bash -s <<'REMOTE_ENV'
set -e
DIR="$P_DIR"; DB="$P_DB"; CSCLI="$P_CSCLI"; GLOB="$P_GLOB"; BHOST="$P_BHOST"; PORT="$P_PORT"
cd "$DIR"
PY=.venv/bin/python

if [ -f .env ]; then
  echo "ENV_EXISTS"   # já existe — preservamos credenciais atuais
  exit 0
fi

SECRET=$("$PY" -c 'import secrets; print(secrets.token_urlsafe(48))')
# Senha forte legível (sem caracteres problemáticos p/ shell/URL).
PLAIN=$("$PY" -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(20)))')
HASH=$("$PY" auth.py "$PLAIN")

cat > .env <<EOF
CROWDSEC_DB_TYPE=sqlite
CROWDSEC_DB_PATH=$DB
CROWDSEC_DB_READONLY=1
CSCLI_BIN=$CSCLI

APP_SECRET=$SECRET
ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$HASH
HOST=$BHOST
PORT=$PORT
APP_DB_PATH=$DIR/data/app.db
SESSION_COOKIE=csdash_session
SESSION_MAX_AGE=43200
COOKIE_SECURE=0

NGINX_LOG_GLOB=$GLOB

ALERT_POLL_SECONDS=20
ALERT_ORIGINS=crowdsec,cscli
ALERT_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_TO=
SMTP_TLS=1
EOF
chmod 600 .env
# Sinaliza a senha gerada para o script local capturar (uma única vez).
echo "GENERATED_PASSWORD=$PLAIN"
REMOTE_ENV
)"
# Extrai a senha gerada (se o .env foi criado agora). Se já existia, fica vazio.
SHOW_PW="$(printf '%s\n' "$ENV_OUT" | sed -n 's/^GENERATED_PASSWORD=//p')"
if printf '%s' "$ENV_OUT" | grep -q '^ENV_EXISTS'; then
  warn ".env já existia no LXC — credenciais preservadas (senha não é reexibida)"
fi
ok ".env configurado"

# ============================================================================
# 5. Unit systemd
# ============================================================================
info "Instalando unit systemd ($SERVICE.service) ..."
SSH bash -s -- "$REMOTE_DIR" "$SERVICE" <<'REMOTE_UNIT'
set -e
DIR="$1"; SVC="$2"
cat > /etc/systemd/system/$SVC.service <<EOF
[Unit]
Description=Mini SOC - Security Operations Dashboard (CrowdSec + Nginx)
After=network-online.target crowdsec.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$DIR
EnvironmentFile=$DIR/.env
ExecStart=$DIR/.venv/bin/python $DIR/app.py
Restart=on-failure
RestartSec=3
ProtectSystem=full
ReadWritePaths=$DIR/data

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable $SVC >/dev/null 2>&1 || true
REMOTE_UNIT
ok "unit instalada"

# ============================================================================
# 6. (Re)start e healthcheck
# ============================================================================
info "(Re)iniciando serviço ..."
SSH "systemctl restart $SERVICE"
sleep 3

info "Healthcheck ..."
# Testa a porta com o que existir no LXC (curl, wget ou o python do venv).
HC="curl -fsS -m 5 http://127.0.0.1:$PORT/ >/dev/null 2>&1 || \
wget -q -T 5 -O /dev/null http://127.0.0.1:$PORT/ 2>/dev/null || \
$REMOTE_DIR/.venv/bin/python -c 'import urllib.request,sys; urllib.request.urlopen(\"http://127.0.0.1:$PORT/\",timeout=5)' 2>/dev/null"
HEALTH_OK=""
for i in 1 2 3 4 5; do
  if SSH "$HC"; then HEALTH_OK=1; break; fi
  sleep 2
done

echo
if [ -n "$HEALTH_OK" ]; then
  ok "Serviço no ar!"
else
  warn "Serviço reiniciado mas o healthcheck HTTP não respondeu — veja os logs:"
  SSH "journalctl -u $SERVICE -n 30 --no-pager" || true
fi

echo
echo "======================================================================"
echo "  Mini SOC — deploy concluído"
echo "======================================================================"
echo "  URL:     http://SEU_SERVIDOR:$PORT/"
echo "  Usuário: admin"
if [ -n "${SHOW_PW:-}" ]; then
  echo "  Senha:   ${SHOW_PW}"
  echo "           ^ GUARDE esta senha — só é exibida agora."
  echo "           (trocar depois: python auth.py 'nova' no LXC e edite ADMIN_PASSWORD_HASH no .env)"
else
  echo "  Senha:   (mantida do .env já existente no LXC)"
fi
echo
echo "  Comandos úteis:"
echo "    ./deploy.sh --status    # status + porta"
echo "    ./deploy.sh --logs      # journalctl -f"
echo "    ./deploy.sh --restart   # reiniciar"
echo "======================================================================"
