"""Acesso ao CrowdSec.

Duas responsabilidades, estritamente separadas:

  LEITURA  → banco do CrowdSec em modo SOMENTE-LEITURA (nunca escrever).
             SQLite: PRAGMA query_only = ON (confiável em DB WAL ao vivo).
             MySQL/MariaDB: conexão via PyMySQL (opcional).
  ESCRITA  → SEMPRE via `cscli` (subprocess, lista de argumentos, sem shell).
             O CrowdSec é a fonte da verdade.

Conhecimento validado respeitado aqui:
  - País/ASN vivem em `alerts`, não em `decisions` → LEFT JOIN alerts a
    ON a.id = d.alert_decisions.
  - Timestamps do CrowdSec são UTC e o SQLite parseia nativamente.
  - Não existe `cscli decisions update` → mudar duração = delete + add.
  - `delete --ip` limpa TODAS as decisões daquele IP.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable

from config import settings

# ---------------------------------------------------------------------------
# Validação de entrada (defesa contra injeção antes do cscli)
# ---------------------------------------------------------------------------

# Duração no formato Go: sequência de <número><unidade> (ns,us,µs,ms,s,m,h) +
# opcionalmente sinal. Ex.: "4h", "30m", "168h", "1h30m", "87600h".
_GO_DURATION_RE = re.compile(
    r"^[+-]?(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$"
)


def validate_ip_or_cidr(value: str) -> tuple[str, str]:
    """Valida e normaliza um IP ou CIDR.

    Retorna (kind, normalized) onde kind ∈ {"ip", "range"}.
    Levanta ValueError se inválido.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("IP/CIDR vazio")
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        # Bloqueia range catch-all (/0): banir 0.0.0.0/0 seria auto-DoS e
        # allowlistar ::/0 desligaria todo o CrowdSec.
        if net.prefixlen == 0:
            raise ValueError("range catch-all (0.0.0.0/0 ou ::/0) não é permitido")
        # Se a máscara cobre um único host, tratamos como IP.
        if net.num_addresses == 1:
            return "ip", str(net.network_address)
        return "range", str(net)
    ip = ipaddress.ip_address(value)  # levanta ValueError se inválido
    return "ip", str(ip)


def validate_duration(value: str) -> str:
    """Valida uma duração no formato Go. Retorna normalizada (trim)."""
    value = (value or "").strip()
    if not _GO_DURATION_RE.match(value):
        raise ValueError(f"Duração inválida (formato Go esperado, ex. '24h', '30m'): {value!r}")
    return value


# ---------------------------------------------------------------------------
# Camada de LEITURA (somente-leitura)
# ---------------------------------------------------------------------------

# Funções de data específicas por backend. O SQL usa placeholders {NOW},
# {DATE}, {DATETIME} substituídos conforme o backend.
class _SqlDialect:
    """Encapsula as diferenças de SQL entre SQLite e MySQL."""

    def __init__(self, is_sqlite: bool):
        self.is_sqlite = is_sqlite

    def now(self) -> str:
        return "datetime('now')" if self.is_sqlite else "UTC_TIMESTAMP()"

    def date(self, col: str) -> str:
        return f"date({col})" if self.is_sqlite else f"DATE({col})"

    def datetime(self, col: str) -> str:
        return f"datetime({col})" if self.is_sqlite else col

    def days_ago(self, days: int) -> str:
        if self.is_sqlite:
            return f"datetime('now','-{int(days)} days')"
        return f"(UTC_TIMESTAMP() - INTERVAL {int(days)} DAY)"

    def today(self, col: str) -> str:
        if self.is_sqlite:
            return f"date({col}) = date('now')"
        return f"DATE({col}) = DATE(UTC_TIMESTAMP())"

    def hours_ago(self, hours: int) -> str:
        if self.is_sqlite:
            return f"datetime('now','-{int(hours)} hours')"
        return f"(UTC_TIMESTAMP() - INTERVAL {int(hours)} HOUR)"

    @property
    def ph(self) -> str:
        # placeholder de parâmetro
        return "?" if self.is_sqlite else "%s"


def _dialect() -> _SqlDialect:
    return _SqlDialect(settings.is_sqlite)


class ReadConn:
    """Context manager para conexão de leitura ao banco do CrowdSec.

    Uso:
        with ReadConn() as cur:
            cur.execute(...)
            rows = cur.fetchall()
    """

    def __init__(self):
        self._conn = None
        self._is_sqlite = settings.is_sqlite

    def __enter__(self):
        if self._is_sqlite:
            # mode=ro impede escrita a nível de URI; PRAGMA query_only reforça e
            # é a forma confiável em WAL ativo.
            uri = f"file:{settings.crowdsec_db_path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA query_only = ON")
            return self._conn.cursor()
        # MySQL / MariaDB
        try:
            import pymysql  # type: ignore
            from pymysql.cursors import DictCursor  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "CROWDSEC_DB_TYPE=mysql requer o pacote PyMySQL. "
                "Instale com: pip install PyMySQL"
            ) from exc
        self._conn = pymysql.connect(
            host=settings.crowdsec_db_host,
            port=settings.crowdsec_db_port,
            user=settings.crowdsec_db_user,
            password=settings.crowdsec_db_password,
            database=settings.crowdsec_db_name,
            cursorclass=DictCursor,
            read_default_group=None,
            connect_timeout=10,
        )
        # Sessão somente-leitura (best-effort; requer privilégio).
        try:
            with self._conn.cursor() as c:
                c.execute("SET SESSION TRANSACTION READ ONLY")
        except Exception:
            pass
        return self._conn.cursor()

    def __exit__(self, *exc):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        return False


def _row_to_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    try:
        return dict(row)
    except (TypeError, ValueError):
        return {}


def health() -> dict[str, Any]:
    """Verifica conexão com o banco do CrowdSec."""
    try:
        with ReadConn() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM decisions")
            row = _row_to_dict(cur.fetchone())
        return {"ok": True, "backend": settings.crowdsec_db_type, "decisions": int(list(row.values())[0])}
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "backend": settings.crowdsec_db_type, "error": str(exc)}


# ------------------------------------------------------------------- estatísticas
def get_stats() -> dict[str, Any]:
    d = _dialect()
    now = d.now()
    stats: dict[str, Any] = {}
    with ReadConn() as cur:
        # Bans ativos (bloqueados agora)
        cur.execute(
            f"SELECT COUNT(*) AS n FROM decisions "
            f"WHERE type='ban' AND {d.datetime('until')} > {now}"
        )
        stats["active_bans"] = int(_first_val(cur.fetchone()))

        # IPs únicos ativos
        cur.execute(
            f"SELECT COUNT(DISTINCT value) AS n FROM decisions "
            f"WHERE type='ban' AND {d.datetime('until')} > {now}"
        )
        stats["active_unique_ips"] = int(_first_val(cur.fetchone()))

        # Novos hoje (decisões criadas hoje, UTC)
        cur.execute(
            f"SELECT COUNT(*) AS n FROM decisions WHERE {d.today('created_at')}"
        )
        stats["new_today"] = int(_first_val(cur.fetchone()))

        # Últimas 24h
        cur.execute(
            f"SELECT COUNT(*) AS n FROM decisions "
            f"WHERE {d.datetime('created_at')} >= {d.hours_ago(24)}"
        )
        stats["last_24h"] = int(_first_val(cur.fetchone()))

        # Total histórico de decisões
        cur.execute("SELECT COUNT(*) AS n FROM decisions")
        stats["total_decisions"] = int(_first_val(cur.fetchone()))

        # Total de alertas
        cur.execute("SELECT COUNT(*) AS n FROM alerts")
        stats["total_alerts"] = int(_first_val(cur.fetchone()))
    return stats


def _first_val(row: Any) -> Any:
    d = _row_to_dict(row)
    if not d:
        return 0
    return list(d.values())[0] or 0


# --------------------------------------------------------------- série temporal
def get_timeseries(days: int = 30, origin: str | None = None) -> list[dict[str, Any]]:
    """Bloqueios (decisões criadas) por dia nos últimos `days` dias.

    Preenche dias sem bloqueio com zero para a série ficar contínua.
    """
    from datetime import date, timedelta

    days = max(1, min(int(days), 3650))
    d = _dialect()
    params: list[Any] = []
    where = [f"{d.datetime('created_at')} >= {d.days_ago(days)}"]
    if origin:
        where.append(f"origin = {d.ph}")
        params.append(origin)
    where_sql = " AND ".join(where)
    sql = (
        f"SELECT {d.date('created_at')} AS day, COUNT(*) AS n "
        f"FROM decisions WHERE {where_sql} "
        f"GROUP BY day ORDER BY day"
    )
    counts: dict[str, int] = {}
    with ReadConn() as cur:
        cur.execute(sql, params)
        for row in cur.fetchall():
            rd = _row_to_dict(row)
            day = str(rd.get("day"))
            counts[day] = int(rd.get("n") or 0)

    # Preenche o range completo com zeros (usa data UTC de hoje).
    import datetime as _dt

    today = _dt.datetime.now(_dt.timezone.utc).date()
    start = today - timedelta(days=days - 1)
    out: list[dict[str, Any]] = []
    cur_day = start
    while cur_day <= today:
        key = cur_day.isoformat()
        out.append({"day": key, "count": counts.get(key, 0)})
        cur_day += timedelta(days=1)
    return out


# ----------------------------------------------------------------- origens
def get_origins() -> list[str]:
    with ReadConn() as cur:
        cur.execute("SELECT DISTINCT origin FROM decisions WHERE origin IS NOT NULL ORDER BY origin")
        return [str(_first_val(r)) for r in cur.fetchall()]


# ----------------------------------------------------------------- rankings
def get_top(kind: str, limit: int = 10, active_only: bool = True) -> list[dict[str, Any]]:
    """Rankings das decisões (por padrão, ativas).

    kind ∈ {"countries", "scenarios", "asn"}. País/ASN vêm de `alerts` via JOIN.
    """
    d = _dialect()
    now = d.now()
    active_clause = f"AND d.type='ban' AND {d.datetime('d.until')} > {now}" if active_only else ""

    if kind == "scenarios":
        sql = (
            f"SELECT d.scenario AS label, COUNT(*) AS n FROM decisions d "
            f"WHERE d.scenario IS NOT NULL {active_clause} "
            f"GROUP BY d.scenario ORDER BY n DESC LIMIT {int(limit)}"
        )
    elif kind == "countries":
        sql = (
            f"SELECT a.source_country AS label, COUNT(*) AS n "
            f"FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_decisions "
            f"WHERE a.source_country IS NOT NULL AND a.source_country <> '' {active_clause} "
            f"GROUP BY a.source_country ORDER BY n DESC LIMIT {int(limit)}"
        )
    elif kind == "asn":
        sql = (
            f"SELECT a.source_as_name AS label, a.source_as_number AS asn, COUNT(*) AS n "
            f"FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_decisions "
            f"WHERE (a.source_as_name IS NOT NULL AND a.source_as_name <> '') {active_clause} "
            f"GROUP BY a.source_as_name, a.source_as_number ORDER BY n DESC LIMIT {int(limit)}"
        )
    else:
        raise ValueError(f"kind inválido: {kind}")

    out: list[dict[str, Any]] = []
    with ReadConn() as cur:
        cur.execute(sql)
        for row in cur.fetchall():
            rd = _row_to_dict(row)
            item = {"label": rd.get("label"), "count": int(rd.get("n") or 0)}
            if "asn" in rd:
                item["asn"] = rd.get("asn")
            out.append(item)
    return out


# ---------------------------------------------------------------- decisões
def list_decisions(
    *,
    search_ip: str | None = None,
    type_filter: str | None = None,
    origin: str | None = None,
    active_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Lista decisões com país/ASN (LEFT JOIN alerts) + filtros + paginação.

    Retorna {"items": [...], "total": N}.
    """
    d = _dialect()
    now = d.now()
    where: list[str] = ["1=1"]
    params: list[Any] = []

    if search_ip:
        where.append(f"d.value LIKE {d.ph}")
        params.append(f"%{search_ip}%")
    if type_filter:
        where.append(f"d.type = {d.ph}")
        params.append(type_filter)
    if origin:
        where.append(f"d.origin = {d.ph}")
        params.append(origin)
    if active_only:
        where.append(f"d.type='ban' AND {d.datetime('d.until')} > {now}")

    where_sql = " AND ".join(where)

    base_from = (
        f"FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_decisions "
        f"WHERE {where_sql}"
    )

    # total
    with ReadConn() as cur:
        cur.execute(f"SELECT COUNT(*) AS n {base_from}", params)
        total = int(_first_val(cur.fetchone()))

        sql = (
            f"SELECT d.id, d.created_at, d.until, d.scenario, d.type, d.scope, "
            f"d.value, d.origin, d.simulated, d.alert_decisions AS alert_id, "
            f"a.source_country AS country, a.source_as_name AS as_name, "
            f"a.source_as_number AS as_number "
            f"{base_from} ORDER BY d.id DESC LIMIT {int(limit)} OFFSET {int(offset)}"
        )
        cur.execute(sql, params)
        rows = [_row_to_dict(r) for r in cur.fetchall()]

    items = []
    for r in rows:
        items.append(
            {
                "id": r.get("id"),
                "created_at": _s(r.get("created_at")),
                "until": _s(r.get("until")),
                "scenario": r.get("scenario"),
                "type": r.get("type"),
                "scope": r.get("scope"),
                "value": r.get("value"),
                "origin": r.get("origin"),
                "simulated": bool(r.get("simulated")),
                "alert_id": r.get("alert_id"),
                "country": r.get("country"),
                "as_name": r.get("as_name"),
                "as_number": r.get("as_number"),
            }
        )
    return {"items": items, "total": total}


def _s(v: Any) -> str | None:
    if v is None:
        return None
    return str(v)


def get_active_banned_ips() -> set[str]:
    """Conjunto de IPs/valores atualmente banidos (para marcar nos logs)."""
    d = _dialect()
    now = d.now()
    out: set[str] = set()
    with ReadConn() as cur:
        cur.execute(
            f"SELECT DISTINCT value FROM decisions "
            f"WHERE type='ban' AND {d.datetime('until')} > {now}"
        )
        for row in cur.fetchall():
            v = _first_val(row)
            if v:
                out.add(str(v))
    return out


def get_new_decisions_since(watermark_id: int, origins: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Decisões com id > watermark (para o poller de alertas), com país/ASN."""
    d = _dialect()
    params: list[Any] = [watermark_id]
    where = [f"d.id > {d.ph}"]
    origins = list(origins or [])
    if origins:
        placeholders = ",".join([d.ph] * len(origins))
        where.append(f"d.origin IN ({placeholders})")
        params.extend(origins)
    where_sql = " AND ".join(where)
    sql = (
        f"SELECT d.id, d.created_at, d.until, d.scenario, d.type, d.scope, "
        f"d.value, d.origin, d.alert_decisions AS alert_id, "
        f"a.source_country AS country, a.source_as_name AS as_name, "
        f"a.source_as_number AS as_number "
        f"FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_decisions "
        f"WHERE {where_sql} ORDER BY d.id ASC LIMIT 500"
    )
    out = []
    with ReadConn() as cur:
        cur.execute(sql, params)
        for row in cur.fetchall():
            r = _row_to_dict(row)
            out.append(
                {
                    "id": r.get("id"),
                    "created_at": _s(r.get("created_at")),
                    "until": _s(r.get("until")),
                    "scenario": r.get("scenario"),
                    "type": r.get("type"),
                    "value": r.get("value"),
                    "origin": r.get("origin"),
                    "country": r.get("country"),
                    "as_name": r.get("as_name"),
                    "as_number": r.get("as_number"),
                }
            )
    return out


def get_max_decision_id() -> int:
    with ReadConn() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) AS m FROM decisions")
        return int(_first_val(cur.fetchone()))


# ---------------------------------------------------------------------------
# Camada de ESCRITA (via cscli, subprocess, lista de argumentos)
# ---------------------------------------------------------------------------

@dataclass
class CscliResult:
    ok: bool
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


def _run_cscli(args: list[str]) -> CscliResult:
    """Executa o cscli com lista de argumentos. NUNCA usa shell=True."""
    binpath = settings.cscli_bin
    argv = [binpath, *args]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return CscliResult(
            ok=(proc.returncode == 0),
            argv=argv,
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except FileNotFoundError:
        return CscliResult(False, argv, 127, "", f"cscli não encontrado: {binpath}")
    except subprocess.TimeoutExpired:
        return CscliResult(False, argv, 124, "", "timeout ao executar cscli")
    except Exception as exc:  # pragma: no cover
        return CscliResult(False, argv, 1, "", str(exc))


def cscli_available() -> bool:
    return shutil.which(settings.cscli_bin) is not None or "/" in settings.cscli_bin


def add_decision(
    *,
    value: str,
    duration: str,
    reason: str,
    type_: str = "ban",
    bypass_allowlist: bool = False,
) -> CscliResult:
    """Adiciona uma decisão (ban) via cscli. Valida IP/CIDR e duração.

    Usa --ip para host único e --range para CIDR. Com bypass_allowlist=True
    acrescenta --bypass-allowlist para banir mesmo que o IP esteja em ALGUMA
    allowlist (necessário quando o usuário confirma "banir mesmo na whitelist").
    """
    kind, normalized = validate_ip_or_cidr(value)
    dur = validate_duration(duration)
    reason = (reason or "painel: ação manual").strip()[:200]
    type_ = type_ if type_ in ("ban", "captcha") else "ban"

    flag = "--ip" if kind == "ip" else "--range"
    args = [
        "decisions", "add", flag, normalized,
        "--duration", dur,
        "--reason", reason,
        "--type", type_,
    ]
    if bypass_allowlist:
        args.append("--bypass-allowlist")
    return _run_cscli(args)


def delete_decision_by_ip(value: str, contained: bool = False) -> CscliResult:
    """Remove TODAS as decisões de um IP/range (unban completo).

    Para um range, contained=True acrescenta --contained, removendo também as
    decisões por-IP CONTIDAS na faixa (usado ao adicionar um CIDR à whitelist).
    """
    kind, normalized = validate_ip_or_cidr(value)
    flag = "--ip" if kind == "ip" else "--range"
    args = ["decisions", "delete", flag, normalized]
    if contained and kind == "range":
        args.append("--contained")
    return _run_cscli(args)


def delete_decision_by_id(decision_id: int) -> CscliResult:
    """Remove uma decisão específica por id."""
    return _run_cscli(["decisions", "delete", "--id", str(int(decision_id))])


def change_duration(*, value: str, new_duration: str, reason: str) -> CscliResult:
    """Altera a duração de um ban: delete --ip (todas) + add com nova duração.

    Segue o conhecimento validado: não há `update`; e delete --ip limpa todas
    as decisões do IP antes de recriar, evitando decisões órfãs.
    """
    kind, normalized = validate_ip_or_cidr(value)
    dur = validate_duration(new_duration)
    # 1) delete todas as decisões daquele IP/range
    del_res = delete_decision_by_ip(normalized)
    # 2) recria com a nova duração
    add_res = add_decision(value=normalized, duration=dur, reason=reason)
    # Consolida o resultado (sucesso se o add funcionou; delete pode retornar
    # 0 decisões se não havia — isso não é erro).
    combined_stdout = f"[delete]\n{del_res.stdout}\n[add]\n{add_res.stdout}"
    combined_stderr = f"[delete]\n{del_res.stderr}\n[add]\n{add_res.stderr}"
    return CscliResult(
        ok=add_res.ok,
        argv=del_res.argv + ["&&"] + add_res.argv,
        exit_code=add_res.exit_code,
        stdout=combined_stdout,
        stderr=combined_stderr,
    )


# ---------------------------------------------------------------------------
# ALLOWLIST (whitelist) — via `cscli allowlists`
# ---------------------------------------------------------------------------
# O painel gerencia UMA allowlist dedicada (ALLOWLIST_NAME). IPs/CIDRs nela
# NUNCA são bloqueados pelo CrowdSec: `cscli decisions add` num IP allowlistado
# é rejeitado (erro "use --bypass-allowlist"). Feature dinâmica: sem reiniciar o
# CrowdSec e sem editar arquivos de parser.
ALLOWLIST_NAME = "painel"
_ALLOWLIST_DESC = "Whitelist gerenciada pelo Mini SOC (nunca bloquear)"


def _ensure_allowlist() -> None:
    """Cria a allowlist do painel se ainda não existir (idempotente)."""
    res = _run_cscli(["allowlists", "create", ALLOWLIST_NAME, "-d", _ALLOWLIST_DESC])
    # 'already exists' não é erro para nós; qualquer outra falha é ignorada aqui
    # e vai reaparecer na operação seguinte (add), que reporta o erro real.


def allowlist_list() -> list[dict[str, Any]]:
    """Itens da allowlist do painel: [{value, description, created_at, expiration}].

    Somente-leitura. Se a allowlist ainda não existe, devolve lista vazia.
    """
    res = _run_cscli(["allowlists", "inspect", ALLOWLIST_NAME, "-o", "json"])
    if not res.ok:
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except (ValueError, TypeError):
        return []
    items = data.get("items") or []
    out: list[dict[str, Any]] = []
    for it in items:
        exp = it.get("expiration") or ""
        # CrowdSec usa 0001-01-01 para "sem expiração".
        if isinstance(exp, str) and exp.startswith("0001-01-01"):
            exp = None
        out.append({
            "value": it.get("value"),
            "description": it.get("description") or "",
            "created_at": it.get("created_at"),
            "expiration": exp,
        })
    return out


def allowlist_add(value: str, comment: str = "") -> CscliResult:
    """Adiciona um IP/CIDR à allowlist do painel (cria a allowlist se preciso)."""
    _kind, normalized = validate_ip_or_cidr(value)
    comment = (comment or "painel: whitelist manual").strip()[:200]
    _ensure_allowlist()
    return _run_cscli(["allowlists", "add", ALLOWLIST_NAME, normalized, "-d", comment])


def allowlist_remove(value: str) -> CscliResult:
    """Remove um IP/CIDR da allowlist do painel."""
    _kind, normalized = validate_ip_or_cidr(value)
    return _run_cscli(["allowlists", "remove", ALLOWLIST_NAME, normalized])


def allowlist_check(value: str) -> dict[str, Any]:
    """Verifica se um IP/CIDR está allowlistado (em QUALQUER allowlist).

    `cscli allowlists check` faz o casamento por CIDR e sempre sai com código 0;
    o resultado vem no texto ("... is allowlisted by ..." | "... is not allowlisted").
    Retorna {allowlisted: bool, detail: str}.
    """
    _kind, normalized = validate_ip_or_cidr(value)
    res = _run_cscli(["allowlists", "check", normalized])
    text = (res.stdout or "") + (res.stderr or "")
    low = text.lower()
    # "is not allowlisted" contém "allowlisted"; por isso testamos o negativo 1º.
    if "not allowlisted" in low:
        allowlisted = False
    elif "is allowlisted" in low or "allowlisted by" in low:
        allowlisted = True
    else:
        allowlisted = False
    return {"allowlisted": allowlisted, "detail": text.strip()}
