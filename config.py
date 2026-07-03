"""Configuração central da aplicação.

Toda configuração vem do arquivo `.env` (carregado via python-dotenv). Este
módulo é a *única* fonte da verdade para configuração — todos os outros módulos
importam de `settings`.

Nada aqui deve executar I/O pesado no import; apenas leitura de variáveis de
ambiente e derivação de valores simples.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Carrega .env do diretório da aplicação (se existir). override=False para não
# sobrescrever variáveis já definidas no ambiente (ex.: systemd EnvironmentFile).
_BASE_DIR = Path(__file__).resolve().parent
load_dotenv(_BASE_DIR / ".env", override=False)


def _get(name: str, default: str = "") -> str:
    val = os.environ.get(name)
    return default if val is None else val


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


# Regex combined padrão do nginx. Grupos nomeados esperados pelo parser:
# ip, user, time, method, path, proto, status, size, referer, ua
#
# A "request line" entre aspas normalmente é "<method> <path> <proto>", mas
# clientes maliciosos/malformados mandam lixo que o nginx escapa e loga como
# uma request única sem os três campos (ex.: handshake SOCKS5 "\x05\x01\x00",
# scans que mandam só o método, requisições sem versão de protocolo etc.).
# Nesses casos o nginx responde 400. Para não perder essas linhas, o miolo da
# request é capturado inteiro em (?P<request>...) e depois quebrado em
# method/path/proto pelo parser, de forma tolerante.
DEFAULT_NGINX_REGEX = (
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# Formato de data do $time_local do nginx.
NGINX_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class Settings:
    # ------------------------------------------------------------------ CrowdSec
    crowdsec_db_type: str = field(default_factory=lambda: _get("CROWDSEC_DB_TYPE", "sqlite").lower())
    crowdsec_db_path: str = field(default_factory=lambda: _get("CROWDSEC_DB_PATH", "/var/lib/crowdsec/data/crowdsec.db"))
    crowdsec_db_readonly: bool = field(default_factory=lambda: _get_bool("CROWDSEC_DB_READONLY", False))
    cscli_bin: str = field(default_factory=lambda: _get("CSCLI_BIN", "cscli"))

    # MySQL/MariaDB (caso o DB do CrowdSec tenha sido migrado)
    crowdsec_db_host: str = field(default_factory=lambda: _get("CROWDSEC_DB_HOST", "127.0.0.1"))
    crowdsec_db_port: int = field(default_factory=lambda: _get_int("CROWDSEC_DB_PORT", 3306))
    crowdsec_db_user: str = field(default_factory=lambda: _get("CROWDSEC_DB_USER", "crowdsec"))
    crowdsec_db_password: str = field(default_factory=lambda: _get("CROWDSEC_DB_PASSWORD", ""))
    crowdsec_db_name: str = field(default_factory=lambda: _get("CROWDSEC_DB_NAME", "crowdsec"))

    # ------------------------------------------------------------------ App/auth
    app_secret: str = field(default_factory=lambda: _get("APP_SECRET", "CHANGE-ME-INSECURE-DEFAULT"))
    admin_user: str = field(default_factory=lambda: _get("ADMIN_USER", "admin"))
    admin_password_hash: str = field(default_factory=lambda: _get("ADMIN_PASSWORD_HASH", ""))
    admin_password_plain: str = field(default_factory=lambda: _get("ADMIN_PASSWORD", ""))
    host: str = field(default_factory=lambda: _get("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _get_int("PORT", 8100))
    app_db_path: str = field(default_factory=lambda: _get("APP_DB_PATH", "./data/app.db"))
    session_cookie: str = field(default_factory=lambda: _get("SESSION_COOKIE", "csdash_session"))
    session_max_age: int = field(default_factory=lambda: _get_int("SESSION_MAX_AGE", 60 * 60 * 12))
    cookie_secure: bool = field(default_factory=lambda: _get_bool("COOKIE_SECURE", False))

    # ------------------------------------------------------------------ Geolocalização de IP
    iplocation_api_key: str = field(default_factory=lambda: _get("IPLOCATION_API_KEY", ""))
    geoip_cache_ttl_days: int = field(default_factory=lambda: _get_int("GEOIP_CACHE_TTL_DAYS", 30))

    # ------------------------------------------------------------------ Nginx logs
    nginx_log_glob: str = field(default_factory=lambda: _get("NGINX_LOG_GLOB", "/var/log/nginx/*access.log*"))
    nginx_log_format_regex: str = field(default_factory=lambda: _get("NGINX_LOG_FORMAT_REGEX", DEFAULT_NGINX_REGEX))

    # ------------------------------------------------------------------ Alertas
    alert_poll_seconds: int = field(default_factory=lambda: _get_int("ALERT_POLL_SECONDS", 20))
    alert_origins: list[str] = field(default_factory=lambda: _get_list("ALERT_ORIGINS", ["crowdsec", "cscli"]))
    alert_webhook_url: str = field(default_factory=lambda: _get("ALERT_WEBHOOK_URL", ""))
    telegram_bot_token: str = field(default_factory=lambda: _get("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = field(default_factory=lambda: _get("TELEGRAM_CHAT_ID", ""))

    # SMTP (opcional / desejável)
    smtp_host: str = field(default_factory=lambda: _get("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _get_int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: _get("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: _get("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: _get("SMTP_FROM", ""))
    smtp_to: list[str] = field(default_factory=lambda: _get_list("SMTP_TO", []))
    smtp_tls: bool = field(default_factory=lambda: _get_bool("SMTP_TLS", True))

    # Timestamp de data do nginx (constante, mas exposto para conveniência)
    nginx_time_format: str = NGINX_TIME_FORMAT

    @property
    def is_sqlite(self) -> bool:
        return self.crowdsec_db_type == "sqlite"

    @property
    def is_mysql(self) -> bool:
        return self.crowdsec_db_type in ("mysql", "mariadb")

    @property
    def base_dir(self) -> Path:
        return _BASE_DIR


settings = Settings()
