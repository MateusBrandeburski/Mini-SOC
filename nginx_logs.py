"""Leitura, parsing e estatísticas de logs de acesso do nginx.

Responsabilidades:
  - DESCOBERTA: enumerar arquivos que casem com `settings.nginx_log_glob`
    (inclui rotacionados e `.gz`) e validar qualquer caminho vindo do cliente
    contra esse conjunto (proteção contra path-traversal / LFI).
  - PARSING: aplicar `settings.nginx_log_format_regex` a cada linha, extraindo
    campos nomeados e normalizando status/size/time.
  - LEITURA EFICIENTE: ler as últimas N linhas sem carregar o arquivo inteiro
    (seek do fim em blocos; para `.gz`, descompressão em streaming com deque).
  - LISTAGEM/FILTROS/STATS: consultar as linhas recentes, filtrar e paginar
    (sempre limitado por `lines`, nunca o arquivo todo).
  - TAIL AO VIVO (SSE): gerador assíncrono que emite apenas as linhas novas,
    robusto a rotação (mudança de inode / arquivo encolheu).

Regras de segurança rígidas:
  - Só lemos arquivos cujo caminho *real* (os.path.realpath) esteja no conjunto
    produzido pelo glob configurado. Nunca aceitamos caminho arbitrário do
    cliente.
  - Nunca `shell=True`; nunca I/O pesado no import; nunca carregar arquivos
    grandes inteiros na memória para listagem/stats.
"""
from __future__ import annotations

import asyncio
import glob as _glob
import gzip
import ipaddress
import os
import re
from collections import Counter, deque
from datetime import datetime
from typing import Any, AsyncIterator, Iterable
from urllib.parse import urlsplit

from config import settings

# ---------------------------------------------------------------------------
# Detecção de IPs da Cloudflare
# ---------------------------------------------------------------------------
# Quando um site está atrás da Cloudflare e o nginx não reescreve o IP real
# (real_ip), o log grava o IP da borda da CF, não o do visitante. Detectamos
# esses ranges para marcar o IP e avisar. Fonte: cloudflare.com/ips (jul/2026).
_CLOUDFLARE_CIDRS = [
    # IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
_CLOUDFLARE_NETS = []
for _c in _CLOUDFLARE_CIDRS:
    try:
        _CLOUDFLARE_NETS.append(ipaddress.ip_network(_c))
    except ValueError:  # pragma: no cover
        pass


def is_cloudflare_ip(ip: str | None) -> bool:
    """True se o IP pertence a um range conhecido da Cloudflare."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUDFLARE_NETS)


# ---------------------------------------------------------------------------
# Derivação de site/domínio a partir do NOME do arquivo de log
# ---------------------------------------------------------------------------
# Convenção observada no servidor: cada vhost grava em <site>_access.log
# (ex.: hubble-front_access.log, cnn-front_access.log). O arquivo genérico
# "access.log" não identifica o site. "direct-ip_access.log" = tentativas de
# acesso pelo IP direto (sem domínio), derrubadas pelo vhost default.
def site_from_filename(name: str) -> str:
    """Extrai um rótulo de site/domínio do nome do arquivo de log.

    'hubble-front_access.log'      -> 'hubble-front'
    'cnn-front_access.log.2.gz'    -> 'cnn-front'
    'direct-ip_access.log'         -> 'IP direto'
    'access.log' / 'access.log.1'  -> '' (genérico, sem site)
    """
    base = os.path.basename(name or "")
    # Remove sufixos de rotação (.1, .2.gz, .gz) e o próprio 'access.log...'.
    m = re.match(r"^(?P<site>.+?)_access\.log", base)
    if not m:
        return ""  # access.log genérico ou nome fora da convenção
    site = m.group("site")
    if site in ("direct-ip", "direct_ip", "default"):
        return "IP direto"
    return site


def host_from_referer(referer: str | None) -> str | None:
    """Extrai o host de um Referer (https://dominio/... -> 'dominio')."""
    if not referer or referer == "-":
        return None
    try:
        netloc = urlsplit(referer).netloc
    except ValueError:
        return None
    if not netloc:
        return None
    # remove credenciais/porta se houver
    host = netloc.split("@")[-1].split(":")[0]
    return host or None

# ---------------------------------------------------------------------------
# Regex compilada (cache) — grupos nomeados esperados:
#   ip, user, time, method, path, proto, status, size, referer, ua
# ---------------------------------------------------------------------------
_regex_cache: tuple[str, re.Pattern[str]] | None = None


def _pattern() -> re.Pattern[str]:
    """Compila (e memoiza) a regex de formato do nginx configurada.

    A compilação é feita sob demanda — nunca no import — e reaproveitada
    enquanto o valor de `settings.nginx_log_format_regex` não mudar.
    """
    global _regex_cache
    raw = settings.nginx_log_format_regex
    if _regex_cache is None or _regex_cache[0] != raw:
        _regex_cache = (raw, re.compile(raw))
    return _regex_cache[1]


# ---------------------------------------------------------------------------
# Descoberta de arquivos + validação de caminho (anti path-traversal / LFI)
# ---------------------------------------------------------------------------

def _globbed_realpaths() -> dict[str, str]:
    """Mapa {realpath: caminho_original} de todos os arquivos que casam o glob.

    Usa `settings.nginx_log_glob` como *única* fonte da verdade. Só entram
    arquivos regulares (ignora diretórios/symlinks quebrados). O realpath é a
    chave usada para validar entradas do cliente.
    """
    out: dict[str, str] = {}
    for path in _glob.glob(settings.nginx_log_glob):
        try:
            if not os.path.isfile(path):
                continue
            real = os.path.realpath(path)
        except OSError:
            continue
        out[real] = path
    return out


def _is_gz(path: str) -> bool:
    return path.endswith(".gz")


def list_files() -> list[dict[str, Any]]:
    """Lista os arquivos de log descobertos pelo glob configurado.

    Cada item: {name, path, size, mtime (iso), gz (bool), site, rotated}.
    'site' é o vhost/domínio derivado do nome; 'rotated' indica se é um
    arquivo rotacionado (.1, .2.gz...). Ordenado do mais recentemente
    modificado para o mais antigo.
    """
    items: list[dict[str, Any]] = []
    for real, original in _globbed_realpaths().items():
        try:
            st = os.stat(real)
        except OSError:
            continue
        base = os.path.basename(original)
        # rotacionado = tem sufixo após "access.log" (ex.: access.log.1, .2.gz)
        rotated = bool(re.search(r"access\.log\.\d+", base))
        items.append(
            {
                "name": base,
                "path": original,
                "size": int(st.st_size),
                "mtime": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(),
                "gz": _is_gz(original),
                "site": site_from_filename(base),
                "rotated": rotated,
            }
        )
    items.sort(key=lambda it: it["mtime"], reverse=True)
    return items


def resolve_file(name_or_path: str) -> str:
    """Valida um nome/caminho vindo do cliente e devolve o caminho real seguro.

    O cliente pode passar o *basename* (ex.: "access.log") ou o caminho
    completo, mas ele SÓ é aceito se casar (via realpath) com um dos arquivos
    descobertos pelo glob. Caso contrário, `ValueError` (defesa contra
    path-traversal / LFI). Retorna o realpath do arquivo.
    """
    value = (name_or_path or "").strip()
    if not value:
        raise ValueError("Arquivo de log não informado")

    discovered = _globbed_realpaths()  # {realpath: original}
    if not discovered:
        raise ValueError("Nenhum arquivo de log disponível para o glob configurado")

    # 1) Match por caminho real (aceita caminho absoluto/relativo do cliente).
    try:
        candidate_real = os.path.realpath(value)
    except OSError:
        candidate_real = None
    if candidate_real is not None and candidate_real in discovered:
        return candidate_real

    # 2) Match por basename (o cliente normalmente manda só o nome).
    #    Compara contra o basename tanto do caminho original quanto do realpath.
    base = os.path.basename(value)
    if base:
        for real, original in discovered.items():
            if base in (os.path.basename(original), os.path.basename(real)):
                return real

    raise ValueError(f"Arquivo de log inválido ou não autorizado: {name_or_path!r}")


# ---------------------------------------------------------------------------
# Parsing de linha
# ---------------------------------------------------------------------------

def _to_int(value: str | None) -> int | None:
    """Converte para int; nginx grava '-' quando não há valor (ex.: size)."""
    if value is None:
        return None
    value = value.strip()
    if not value or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_time(raw: str | None) -> str | None:
    """Converte o $time_local do nginx para ISO-8601; None se não parsear."""
    if not raw:
        return None
    try:
        dt = datetime.strptime(raw, settings.nginx_time_format)
        return dt.isoformat()
    except (ValueError, OverflowError):
        return None


def parse_line(line: str) -> dict[str, Any]:
    """Faz o parse de uma única linha de acesso do nginx.

    Em caso de match, retorna um dict com matched=True e as chaves:
      ip, user, time_raw, time (iso|None), method, path, proto,
      status (int|None), size (int|None), referer, ua, raw.
    Linhas que não casam a regex: {"raw": line, "matched": False}.
    Jamais levanta exceção por linha malformada.
    """
    text = line.rstrip("\r\n")
    try:
        m = _pattern().match(text)
    except re.error:
        # Regex configurada inválida — trata como não-casada em vez de estourar.
        return {"raw": text, "matched": False}
    if not m:
        return {"raw": text, "matched": False}

    g = m.groupdict()
    time_raw = g.get("time")
    ip = g.get("ip")
    referer = g.get("referer")
    # host pode vir de um grupo nomeado do log_format (se configurado) ou do Referer.
    host = g.get("host") or None
    if host in ("", "-"):
        host = None
    return {
        "matched": True,
        "ip": ip,
        "user": g.get("user"),
        "time_raw": time_raw,
        "time": _parse_time(time_raw),
        "method": g.get("method"),
        "path": g.get("path"),
        "proto": g.get("proto"),
        "status": _to_int(g.get("status")),
        "size": _to_int(g.get("size")),
        "referer": referer,
        "referer_host": host_from_referer(referer),
        "host": host,                       # $host do log_format, se disponível
        "ua": g.get("ua"),
        "cf": is_cloudflare_ip(ip),         # IP pertence à Cloudflare?
        "raw": text,
    }


# ---------------------------------------------------------------------------
# Leitura eficiente das últimas N linhas
# ---------------------------------------------------------------------------

_CHUNK = 64 * 1024  # bloco de leitura ao caminhar do fim para o início


def _tail_plain(path: str, lines: int) -> list[str]:
    """Últimas `lines` linhas de um arquivo texto, sem carregar tudo.

    Faz seek a partir do fim, lendo blocos de trás para frente até acumular
    linhas suficientes (ou atingir o início). Devolve as linhas na ordem
    natural (mais antiga primeiro), já sem o '\\n'.
    """
    if lines <= 0:
        return []
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        if end == 0:
            return []
        buf = b""
        pos = end
        newlines = 0
        # Lê blocos do fim até juntar (lines + 1) quebras de linha ou o início.
        while pos > 0 and newlines <= lines:
            read_size = min(_CHUNK, pos)
            pos -= read_size
            fh.seek(pos)
            chunk = fh.read(read_size)
            buf = chunk + buf
            newlines = buf.count(b"\n")
        raw_lines = buf.split(b"\n")
    # Se o arquivo não terminava em '\n', o último elemento é a linha final;
    # se terminava, o split gera um '' no fim que descartamos.
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    tail = raw_lines[-lines:]
    return [b.decode("utf-8", errors="replace") for b in tail]


def _tail_gz(path: str, lines: int) -> list[str]:
    """Últimas `lines` linhas de um `.gz`, via descompressão em streaming.

    Como não dá para fazer seek no conteúdo descomprimido, lemos em streaming
    mantendo apenas as últimas `lines` num deque (uso de memória limitado a N).
    """
    if lines <= 0:
        return []
    tail: deque[str] = deque(maxlen=lines)
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            tail.append(line.rstrip("\r\n"))
    return list(tail)


def read_lines(file: str, lines: int = 200) -> list[str]:
    """Lê as últimas `lines` linhas de um arquivo de log (validado).

    Retorna a lista na ordem cronológica (mais antiga primeiro). Nunca carrega
    o arquivo inteiro na memória para arquivos texto; para `.gz` mantém só as
    últimas N linhas em um deque.
    """
    real = resolve_file(file)
    lines = max(0, int(lines))
    if _is_gz(real):
        return _tail_gz(real, lines)
    return _tail_plain(real, lines)


# ---------------------------------------------------------------------------
# Filtros de listagem
# ---------------------------------------------------------------------------

def _status_matches(status: int | None, wanted: str) -> bool:
    """Casa status por código exato (ex.: '404') ou por classe (ex.: '4xx')."""
    if status is None:
        return False
    wanted = wanted.strip().lower()
    if not wanted:
        return True
    if wanted.endswith("xx") and len(wanted) == 3 and wanted[0].isdigit():
        return (status // 100) == int(wanted[0])
    if wanted.isdigit():
        return status == int(wanted)
    return False


def _item_passes(
    item: dict[str, Any],
    *,
    ip: str | None,
    status: str | None,
    method: str | None,
    path: str | None,
    ua: str | None,
    q: str | None,
) -> bool:
    """Aplica todos os filtros a um item já parseado (AND entre filtros).

    Itens não-casados (matched=False) só passam pelo filtro de texto livre `q`
    (que age sobre o campo raw); qualquer filtro de campo estruturado os exclui.
    """
    matched = item.get("matched", False)

    if ip:
        val = item.get("ip") or ""
        if ip not in val:
            return False
    if status:
        if not _status_matches(item.get("status"), status):
            return False
    if method:
        if (item.get("method") or "").upper() != method.strip().upper():
            return False
    if path:
        if path not in (item.get("path") or ""):
            return False
    if ua:
        if ua.lower() not in (item.get("ua") or "").lower():
            return False
    if q:
        if q.lower() not in (item.get("raw") or "").lower():
            return False

    # Se há qualquer filtro de campo estruturado, linhas não-casadas não passam.
    if not matched and any((ip, status, method, path, ua)):
        return False
    return True


def _enrich_access(item: dict[str, Any], site: str) -> None:
    """Adiciona 'site' e 'access_via' ao item (forma de acesso / domínio).

    'site' vem do nome do arquivo (vhost). 'access_via' é um resumo legível:
    preferimos o host do $host (se logado), senão o do Referer, senão o site do
    arquivo; 'IP direto' quando o vhost é o de acesso por IP.
    """
    if not item.get("matched"):
        return
    item["site"] = site
    host = item.get("host") or item.get("referer_host")
    if site == "IP direto":
        item["access_via"] = "IP direto"
    elif host:
        item["access_via"] = host
    elif site:
        item["access_via"] = site
    else:
        item["access_via"] = "—"


def query_logs(
    *,
    file: str,
    ip: str | None = None,
    status: str | None = None,
    method: str | None = None,
    path: str | None = None,
    ua: str | None = None,
    q: str | None = None,
    lines: int = 2000,
    page: int = 1,
    page_size: int = 100,
    banned_ips: set[str] | None = None,
) -> dict[str, Any]:
    """Consulta linhas recentes com filtros e paginação (mais novas primeiro).

    Lê até `lines` linhas recentes, parseia, aplica os filtros, ordena do mais
    novo para o mais antigo e pagina. Se `banned_ips` for fornecido, marca
    item["banned"] em cada item. Cada item ganha 'site'/'access_via' (forma de
    acesso) e 'cf' (IP da Cloudflare). Retorna
    {"items": [...], "total": int, "page": int, "page_size": int, "site": str}.
    """
    lines = max(1, int(lines))
    page = max(1, int(page))
    page_size = max(1, int(page_size))

    site = site_from_filename(file)
    raw_lines = read_lines(file, lines=lines)
    # read_lines devolve cronológico (antigo->novo); queremos o mais novo antes.
    raw_lines.reverse()

    filtered: list[dict[str, Any]] = []
    for text in raw_lines:
        item = parse_line(text)
        _enrich_access(item, site)
        if _item_passes(
            item, ip=ip, status=status, method=method, path=path, ua=ua, q=q
        ):
            if banned_ips is not None:
                item_ip = item.get("ip")
                item["banned"] = bool(item_ip and item_ip in banned_ips)
            filtered.append(item)

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = filtered[start:end]

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "site": site,
    }


# ---------------------------------------------------------------------------
# Estatísticas
# ---------------------------------------------------------------------------

def _top(counter: Counter, key_name: str, limit: int = 15) -> list[dict[str, Any]]:
    """Converte um Counter nos `limit` itens mais frequentes."""
    return [{key_name: label, "count": count} for label, count in counter.most_common(limit)]


def log_stats(*, file: str, lines: int = 5000) -> dict[str, Any]:
    """Agrega estatísticas sobre as últimas `lines` linhas de um log.

    Retorna:
      top_ips, top_paths, top_uas: [{campo, count}] (top 15)
      status_dist: [{status, count}] ordenado por código asc
      over_time: [{bucket:"YYYY-MM-DDTHH:00", count}] por hora, asc
      total_parsed: linhas que casaram a regex
      total_lines: linhas lidas (casadas ou não)
    """
    lines = max(1, int(lines))
    raw_lines = read_lines(file, lines=lines)

    ip_c: Counter = Counter()
    status_c: Counter = Counter()
    path_c: Counter = Counter()
    ua_c: Counter = Counter()
    hour_c: Counter = Counter()

    total_parsed = 0
    for text in raw_lines:
        item = parse_line(text)
        if not item.get("matched"):
            continue
        total_parsed += 1
        if item.get("ip"):
            ip_c[item["ip"]] += 1
        if item.get("status") is not None:
            status_c[item["status"]] += 1
        if item.get("path"):
            path_c[item["path"]] += 1
        if item.get("ua"):
            ua_c[item["ua"]] += 1
        iso = item.get("time")
        if iso:
            # iso = "YYYY-MM-DDTHH:MM:SS[...]" → bucket por hora.
            hour_c[iso[:13] + ":00"] += 1

    status_dist = [
        {"status": code, "count": count}
        for code, count in sorted(status_c.items(), key=lambda kv: kv[0])
    ]
    over_time = [
        {"bucket": bucket, "count": count}
        for bucket, count in sorted(hour_c.items(), key=lambda kv: kv[0])
    ]

    return {
        "top_ips": _top(ip_c, "ip"),
        "status_dist": status_dist,
        "top_paths": _top(path_c, "path"),
        "top_uas": _top(ua_c, "ua"),
        "over_time": over_time,
        "total_parsed": total_parsed,
        "total_lines": len(raw_lines),
    }


# ---------------------------------------------------------------------------
# Tail ao vivo para SSE
# ---------------------------------------------------------------------------

_POLL_SECONDS = 1.0


async def tail_stream(file: str) -> AsyncIterator[dict[str, Any]]:
    """Gerador assíncrono que emite as *novas* linhas de um log conforme cresce.

    Acompanha o offset em bytes e o inode (st_ino). Se o inode mudar ou o
    arquivo encolher (logrotate), reabre a partir do início. Faz polling a cada
    ~1s. Emite apenas as linhas anexadas (parseadas). Arquivos `.gz` não são
    "tailáveis" e levantam ValueError.

    Uso típico (SSE):
        async for item in tail_stream(file):
            yield f"data: {json.dumps(item)}\\n\\n"
    """
    real = resolve_file(file)
    if _is_gz(real):
        raise ValueError("Arquivos .gz não podem ser acompanhados em tempo real")

    site = site_from_filename(file)
    offset = 0
    inode: int | None = None
    pending = b""  # buffer para uma última linha parcial (sem '\n' ainda)

    # Começa a partir do fim do arquivo: só interessam as linhas novas.
    try:
        st = os.stat(real)
        offset = int(st.st_size)
        inode = int(st.st_ino)
    except FileNotFoundError:
        # Arquivo pode ainda não existir/estar em rotação; começa do zero.
        offset = 0
        inode = None

    while True:
        try:
            st = os.stat(real)
        except FileNotFoundError:
            # Rotação transitória — aguarda o arquivo reaparecer.
            await asyncio.sleep(_POLL_SECONDS)
            continue

        cur_inode = int(st.st_ino)
        size = int(st.st_size)

        # Detecta rotação: inode mudou ou o arquivo encolheu (truncado/recriado).
        if inode is None:
            inode = cur_inode
        elif cur_inode != inode or size < offset:
            offset = 0
            inode = cur_inode
            pending = b""

        if size > offset:
            try:
                with open(real, "rb") as fh:
                    fh.seek(offset)
                    data = fh.read(size - offset)
                    offset = fh.tell()
            except FileNotFoundError:
                await asyncio.sleep(_POLL_SECONDS)
                continue

            buf = pending + data
            parts = buf.split(b"\n")
            # O último pedaço pode ser uma linha ainda incompleta.
            pending = parts.pop()
            for chunk in parts:
                text = chunk.rstrip(b"\r").decode("utf-8", errors="replace")
                if text:
                    item = parse_line(text)
                    _enrich_access(item, site)
                    yield item

        await asyncio.sleep(_POLL_SECONDS)
