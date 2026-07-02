"""Banco de dados *da própria aplicação* (app.db).

JAMAIS confundir com o banco do CrowdSec. Aqui guardamos:
  - config de alertas (chave/valor JSON)
  - marca d'água ("último ban visto") para o poller de alertas
  - histórico de alertas enviados
  - log de auditoria de toda ação de escrita (add/delete/ajuste de duração)

Usa sqlite3 da stdlib. O acesso é serializado por um lock, pois o poller de
alertas (thread/asyncio) e os handlers HTTP podem escrever concorrentemente.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor         TEXT,
    action        TEXT NOT NULL,        -- add | delete | duration_change | ...
    target        TEXT,                 -- IP/CIDR alvo
    detail        TEXT,                 -- JSON: {"old":"4h","new":"24h","reason":...}
    command       TEXT,                 -- comando cscli executado (argv, para rastreio)
    exit_code     INTEGER,
    stdout        TEXT,
    stderr        TEXT,
    success       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alert_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    decision_id   INTEGER,
    ip            TEXT,
    country       TEXT,
    asn           TEXT,
    scenario      TEXT,
    origin        TEXT,
    duration      TEXT,
    until         TEXT,
    channels      TEXT,                 -- JSON: {"telegram":true,"webhook":false,...}
    result        TEXT                  -- JSON: por canal, ok/erro
);

CREATE TABLE IF NOT EXISTS geoip_cache (
    ip            TEXT PRIMARY KEY,
    fetched_at    TEXT NOT NULL,         -- ISO8601 UTC de quando foi buscado
    data          TEXT NOT NULL          -- JSON com a resposta normalizada
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert_history(ts);
"""

# Configuração padrão de alertas — sobrescrita pelo que estiver salvo no DB.
DEFAULT_ALERT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "origins": settings.alert_origins,      # origens que disparam alerta
    "scenarios": [],                          # se não-vazio, só alerta estes cenários
    "threshold_count": 0,                     # 0 = desativado
    "threshold_minutes": 5,
    "channels": {
        "webhook": bool(settings.alert_webhook_url),
        "telegram": bool(settings.telegram_bot_token and settings.telegram_chat_id),
        "email": bool(settings.smtp_host and settings.smtp_to),
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    """Cria o arquivo/tabelas e semeia config padrão. Idempotente."""
    global _conn
    db_path = Path(settings.app_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        _conn = sqlite3.connect(str(db_path), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.commit()
        # Semeia config de alerta se ainda não existir.
        cur = _conn.execute("SELECT value FROM app_config WHERE key='alert_config'")
        if cur.fetchone() is None:
            _conn.execute(
                "INSERT INTO app_config(key, value) VALUES('alert_config', ?)",
                (json.dumps(DEFAULT_ALERT_CONFIG),),
            )
            _conn.commit()


def _require_conn() -> sqlite3.Connection:
    if _conn is None:
        raise RuntimeError("db.init_db() deve ser chamado antes de usar o app.db")
    return _conn


# --------------------------------------------------------------------- config
def get_alert_config() -> dict[str, Any]:
    with _lock:
        cur = _require_conn().execute("SELECT value FROM app_config WHERE key='alert_config'")
        row = cur.fetchone()
    if row is None:
        return dict(DEFAULT_ALERT_CONFIG)
    try:
        cfg = json.loads(row["value"])
    except (ValueError, TypeError):
        return dict(DEFAULT_ALERT_CONFIG)
    # Garante chaves ausentes com defaults.
    merged = dict(DEFAULT_ALERT_CONFIG)
    merged.update(cfg)
    if "channels" not in cfg:
        merged["channels"] = dict(DEFAULT_ALERT_CONFIG["channels"])
    return merged


def set_alert_config(cfg: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        conn = _require_conn()
        conn.execute(
            "INSERT INTO app_config(key, value) VALUES('alert_config', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(cfg),),
        )
        conn.commit()
    return cfg


def get_config_value(key: str, default: str | None = None) -> str | None:
    with _lock:
        cur = _require_conn().execute("SELECT value FROM app_config WHERE key=?", (key,))
        row = cur.fetchone()
    return row["value"] if row else default


def set_config_value(key: str, value: str) -> None:
    with _lock:
        conn = _require_conn()
        conn.execute(
            "INSERT INTO app_config(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()


# ---------------------------------------------------------------- marca d'água
def get_watermark() -> int:
    """Maior decision.id já processado pelo poller de alertas."""
    val = get_config_value("alert_watermark_id", "0")
    try:
        return int(val or "0")
    except ValueError:
        return 0


def set_watermark(decision_id: int) -> None:
    set_config_value("alert_watermark_id", str(int(decision_id)))


# ---------------------------------------------------------------------- audit
def add_audit(
    *,
    actor: str | None,
    action: str,
    target: str | None,
    detail: dict[str, Any] | None,
    command: list[str] | str | None,
    exit_code: int | None,
    stdout: str | None,
    stderr: str | None,
    success: bool,
) -> int:
    if isinstance(command, list):
        command = " ".join(command)
    with _lock:
        conn = _require_conn()
        cur = conn.execute(
            "INSERT INTO audit_log(ts, actor, action, target, detail, command, "
            "exit_code, stdout, stderr, success) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                _now_iso(),
                actor,
                action,
                target,
                json.dumps(detail) if detail is not None else None,
                command,
                exit_code,
                (stdout or "")[:8000],
                (stderr or "")[:8000],
                1 if success else 0,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_audit(limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
    with _lock:
        cur = _require_conn().execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("detail"):
            try:
                d["detail"] = json.loads(d["detail"])
            except (ValueError, TypeError):
                pass
        d["success"] = bool(d["success"])
        out.append(d)
    return out


def count_audit() -> int:
    with _lock:
        cur = _require_conn().execute("SELECT COUNT(*) AS n FROM audit_log")
        return int(cur.fetchone()["n"])


# -------------------------------------------------------------- alert history
def add_alert_history(
    *,
    decision_id: int | None,
    ip: str | None,
    country: str | None,
    asn: str | None,
    scenario: str | None,
    origin: str | None,
    duration: str | None,
    until: str | None,
    channels: dict[str, bool],
    result: dict[str, Any],
) -> int:
    with _lock:
        conn = _require_conn()
        cur = conn.execute(
            "INSERT INTO alert_history(ts, decision_id, ip, country, asn, scenario, "
            "origin, duration, until, channels, result) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                _now_iso(),
                decision_id,
                ip,
                country,
                asn,
                scenario,
                origin,
                duration,
                until,
                json.dumps(channels),
                json.dumps(result),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_alert_history(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with _lock:
        cur = _require_conn().execute(
            "SELECT * FROM alert_history ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for jkey in ("channels", "result"):
            if d.get(jkey):
                try:
                    d[jkey] = json.loads(d[jkey])
                except (ValueError, TypeError):
                    pass
        out.append(d)
    return out


def count_recent_alerts(minutes: int) -> int:
    """Quantos alertas enviados nos últimos `minutes` (para threshold)."""
    with _lock:
        cur = _require_conn().execute(
            "SELECT COUNT(*) AS n FROM alert_history "
            "WHERE ts >= datetime('now', ?)",
            (f"-{int(minutes)} minutes",),
        )
        return int(cur.fetchone()["n"])


# ------------------------------------------------------------- cache geoip
def get_geoip_cache(ip: str, ttl_days: int = 0) -> dict[str, Any] | None:
    """Retorna o registro em cache para `ip`, ou None se ausente/expirado.

    ttl_days=0 => nunca expira. O filtro de validade é feito em SQL para
    aproveitar o relógio do próprio SQLite (UTC).
    """
    with _lock:
        conn = _require_conn()
        if ttl_days and ttl_days > 0:
            cur = conn.execute(
                "SELECT ip, fetched_at, data FROM geoip_cache "
                "WHERE ip=? AND fetched_at >= datetime('now', ?)",
                (ip, f"-{int(ttl_days)} days"),
            )
        else:
            cur = conn.execute(
                "SELECT ip, fetched_at, data FROM geoip_cache WHERE ip=?", (ip,)
            )
        row = cur.fetchone()
    if row is None:
        return None
    try:
        data = json.loads(row["data"])
    except (ValueError, TypeError):
        return None
    return {"ip": row["ip"], "fetched_at": row["fetched_at"], "cached": True, **data}


def set_geoip_cache(ip: str, data: dict[str, Any]) -> None:
    """Grava/atualiza o cache de geolocalização de `ip`."""
    with _lock:
        conn = _require_conn()
        conn.execute(
            "INSERT INTO geoip_cache(ip, fetched_at, data) VALUES(?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET fetched_at=excluded.fetched_at, data=excluded.data",
            (ip, _now_iso(), json.dumps(data)),
        )
        conn.commit()
