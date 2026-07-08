"""Construção de um GRAFO INVESTIGATIVO de IPs a partir dos logs do nginx,
enriquecido com dados do CrowdSec (ban/cenário/ASN/país) e do cache de geoip.

Ideia central
-------------
Cada IP observado nos logs vira um nó. Além dele, criamos nós de ATRIBUTO
compartilhado — User-Agent, sub-rede /24, ASN/ISP, país, cenário do CrowdSec e
"rotas de scan" (paths suspeitos). Dois IPs que compartilham o mesmo atributo
ficam ligados ao MESMO nó de atributo — é assim que o grafo revela, visualmente,
relações IP↔IP (mesma ferramenta/botnet, mesma vizinhança de rede, mesma
campanha de varredura) sem explodir em O(n²) arestas.

Dois modos
----------
- **Visão geral** (sem `pivot`): os IPs mais ativos + os atributos compartilhados
  por vários deles (>= `min_shared`). Mostra as "campanhas" de relance.
- **Pivô** (`pivot=<ip>`): um IP no centro com TODOS os seus atributos, mais os
  IPs "irmãos" que compartilham qualquer atributo com ele — inclusive irmãos que
  ainda NÃO foram banidos. É o fluxo de "expandir a vizinhança" de um suspeito.

Custo/segurança
---------------
- Só lê as últimas N linhas de cada arquivo (via nginx_logs.read_lines — nunca o
  arquivo inteiro). Enriquecimento do CrowdSec é consultado só para os IPs do
  conjunto final (limitado por `max_ips`) e, para país/ASN/cenário, apenas para
  os que estão efetivamente banidos (poucas queries). Geoip é SÓ do cache (nunca
  dispara chamada externa).
- Nenhuma escrita, nenhum subprocess de mutação.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any

import crowdsec
import db
import nginx_logs

# ---------------------------------------------------------------------------
# Heurísticas de classificação de rotas
# ---------------------------------------------------------------------------
# Extensões de asset estático "normais" — paths assim NÃO viram nó de scan
# (são recursos legítimos de página, não sondagem).
_ASSET_EXT = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|"
    r"avif|bmp|json|xml|txt|pdf)(?:\?|$)",
    re.IGNORECASE,
)

# Padrões clássicos de sondagem/exploração. Um path que casa aqui é sempre
# tratado como "rota de scan" (mesmo que só 1 IP tenha tocado), pois o valor
# investigativo é alto.
_SCAN_HINTS = re.compile(
    r"(?:/\.env|/\.git|/\.aws|/\.ssh|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|"
    r"phpunit|/vendor/|/actuator|/solr|/boaform|/cgi-bin|/shell|/administrator|"
    r"eval-stdin|/config\.|/\.well-known/|/owa/|/manager/html|/druid/|"
    r"/console|/_ignition|/telescope|\.php$|/api/.*(?:token|key|secret))",
    re.IGNORECASE,
)


# User-Agents de FERRAMENTA (sempre clusterizam — sinal forte de mesmo toolkit).
_TOOL_UA = re.compile(
    r"(curl|wget|python-requests|libwww|zgrab|masscan|nmap|nikto|sqlmap|go-http|"
    r"okhttp|Java/|Apache-HttpClient|httpx|scrapy|axios|node-fetch|winhttp|"
    r"bot\b|spider|crawler|scan|censys|shodan|expanse|l9explore|zmap)",
    re.IGNORECASE,
)
# Browser "genérico" — NÃO clusteriza: senão vira um super-cluster falso (ex.:
# centenas de Chrome atrás da Cloudflare agrupados como se fossem uma campanha).
_BROWSER_UA = re.compile(r"Mozilla/.*(Chrome|Firefox|Safari|Edg|OPR|Gecko)", re.IGNORECASE)


def _ua_clusters(ua: str) -> bool:
    """True se o User-Agent deve virar nó de cluster (ferramenta ou UA incomum);
    False para browsers genéricos (ruído investigativo)."""
    if not ua:
        return False
    if _TOOL_UA.search(ua):
        return True
    if _BROWSER_UA.search(ua):
        return False
    return True  # UA curto/incomum/fora do padrão → pode ser sinal


def _subnet24(ip: str) -> str | None:
    """Devolve a /24 (IPv4) ou /64 (IPv6) do IP, como rótulo de vizinhança."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        net = ipaddress.ip_network(f"{ip}/64", strict=False)
    return str(net)


def _status_summary(status_counter: Counter) -> str:
    """Resumo legível da distribuição de status de um IP (ex.: 'maioria 404')."""
    if not status_counter:
        return "—"
    total = sum(status_counter.values())
    code, n = status_counter.most_common(1)[0]
    pct = round(100 * n / total) if total else 0
    if code is None:
        return "—"
    if pct >= 80:
        return f"quase só {code}"
    if pct >= 50:
        return f"maioria {code}"
    return f"{code} (misto)"


def _is_asset(path: str | None) -> bool:
    return bool(path) and bool(_ASSET_EXT.search(path))


def _looks_like_scan(path: str | None, ip_count: int, min_shared: int) -> bool:
    """Um path é 'rota de scan' se casa um padrão de sondagem, OU se é um path
    não-asset (e não a raiz) tocado por >= min_shared IPs distintos."""
    if not path or path in ("/", ""):
        return False
    if _SCAN_HINTS.search(path):
        return True
    if not _is_asset(path) and ip_count >= max(2, min_shared):
        return True
    return False


def _ua_id(ua: str) -> str:
    """ID curto e estável para um User-Agent (evita nós com strings gigantes)."""
    # hash simples e determinístico (não-cripto) só para gerar um id compacto.
    h = 0
    for ch in ua:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return f"ua:{h:08x}"


def _short_ua(ua: str, n: int = 42) -> str:
    ua = ua.strip()
    return ua if len(ua) <= n else ua[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Enriquecimento (CrowdSec + geoip cache) — barato e sob demanda
# ---------------------------------------------------------------------------

def _enrich_ip(ip: str, banned: bool) -> dict[str, Any]:
    """País/ASN/cenário para um IP. Para banidos, consulta a decisão (poucos);
    para os demais, tenta só o cache de geoip (nunca chama API externa)."""
    out: dict[str, Any] = {"country": None, "asn": None, "scenarios": []}
    if banned:
        try:
            res = crowdsec.list_decisions(search_ip=ip, limit=5)
            for it in res.get("items", []):
                if it.get("value") != ip:
                    continue
                out["country"] = out["country"] or it.get("country")
                name = it.get("as_name")
                num = it.get("as_number")
                if name or num:
                    out["asn"] = out["asn"] or (
                        f"AS{num} {name}".strip() if num else str(name)
                    )
                sc = it.get("scenario")
                if sc and sc not in out["scenarios"]:
                    out["scenarios"].append(sc)
        except Exception:
            pass
    if not out["country"] or not out["asn"]:
        try:
            cached = db.get_geoip_cache(ip, ttl_days=0)  # ttl_days=0 = qualquer registro
        except Exception:
            cached = None
        if cached:
            out["country"] = out["country"] or cached.get("country_code") or cached.get("country_name")
            if not out["asn"] and cached.get("isp"):
                out["asn"] = cached.get("isp")
    return out


# ---------------------------------------------------------------------------
# Construção do grafo
# ---------------------------------------------------------------------------

def _collect_files(file: str | None) -> list[str]:
    """Arquivos a ler: um específico (validado) ou todos os logs 'atuais'
    (não-rotacionados, não-.gz) — para uma visão cruzando domínios."""
    if file and file not in ("__all__", "all", "*"):
        return [file]
    files = []
    for it in nginx_logs.list_files():
        if it.get("rotated") or it.get("gz"):
            continue
        files.append(it["name"])
    return files


def build_graph(
    *,
    file: str | None = None,
    lines: int = 3000,
    pivot: str | None = None,
    min_shared: int = 2,
    max_ips: int = 60,
    banned_ips: set[str] | None = None,
) -> dict[str, Any]:
    """Monta {nodes, edges, stats} a partir dos logs.

    - `file`: nome de um arquivo de log OU None/"__all__" para agregar todos os
      logs atuais (cruzando domínios).
    - `lines`: linhas lidas por arquivo.
    - `pivot`: IP central (modo investigação de vizinhança) ou None (visão geral).
    - `min_shared`: nº mínimo de IPs distintos para um atributo virar nó/cluster.
    - `max_ips`: teto de nós de IP (na visão geral, pegamos os mais ativos).
    """
    lines = max(1, int(lines))
    min_shared = max(1, int(min_shared))
    max_ips = max(1, int(max_ips))
    pivot = (pivot or "").strip() or None

    files = _collect_files(file)

    # --- 1) Agregação por IP + índices globais de atributos ---
    ip_reqs: Counter = Counter()
    ip_domains: dict[str, set[str]] = defaultdict(set)
    ip_paths: dict[str, Counter] = defaultdict(Counter)
    ip_status: dict[str, Counter] = defaultdict(Counter)
    ip_ua: dict[str, Counter] = defaultdict(Counter)
    ip_cf: dict[str, bool] = {}
    ip_first: dict[str, str] = {}
    ip_last: dict[str, str] = {}

    ua_ips: dict[str, set[str]] = defaultdict(set)      # ua_full -> {ips}
    subnet_ips: dict[str, set[str]] = defaultdict(set)  # /24 -> {ips}
    path_ips: dict[str, set[str]] = defaultdict(set)    # path -> {ips}

    lines_read = 0
    for f in files:
        try:
            raw = nginx_logs.read_lines(f, lines=lines)
        except ValueError:
            continue
        for text in raw:
            lines_read += 1
            item = nginx_logs.parse_line(text)
            if not item.get("matched"):
                continue
            ip = item.get("ip")
            if not ip:
                continue
            ip_reqs[ip] += 1
            # domínio ACESSADO: $host (se logado) ou o site derivado do nome do
            # arquivo do vhost. NÃO usamos o referer aqui (é "de onde veio", não
            # "o que acessou"). "IP direto" é o vhost default (acesso sem domínio).
            site = nginx_logs.site_from_filename(f)
            if site == "IP direto":
                dom = "IP direto"
            else:
                dom = item.get("host") or (site or None)
            if dom:
                ip_domains[ip].add(dom)
            path = item.get("path")
            if path:
                ip_paths[ip][path] += 1
                path_ips[path].add(ip)
            st = item.get("status")
            ip_status[ip][st] += 1
            ua = (item.get("ua") or "").strip()
            if ua and ua != "-":
                ip_ua[ip][ua] += 1
                # browsers genéricos NÃO entram no índice de cluster (evita
                # super-cluster falso); ferramentas/UAs incomuns sim.
                if _ua_clusters(ua):
                    ua_ips[ua].add(ip)
            if item.get("cf"):
                ip_cf[ip] = True
            t = item.get("time") or item.get("time_raw")
            if t:
                if ip not in ip_first or t < ip_first[ip]:
                    ip_first[ip] = t
                if ip not in ip_last or t > ip_last[ip]:
                    ip_last[ip] = t
            # sub-rede /24: IPs da borda Cloudflare NÃO agrupam por rede (o IP é
            # da CF, não do visitante — agruparia visitantes sem relação).
            sub = _subnet24(ip)
            if sub and not item.get("cf"):
                subnet_ips[sub].add(ip)

    if not ip_reqs:
        return {
            "nodes": [], "edges": [],
            "stats": {"ips": 0, "lines_read": lines_read, "files": files, "pivot": pivot, "note": "nenhum IP encontrado"},
        }

    banned = banned_ips
    if banned is None:
        try:
            banned = crowdsec.get_active_banned_ips()
        except Exception:
            banned = set()

    # --- 2) Selecionar o conjunto de IPs a exibir ---
    if pivot:
        # vizinhança: pivô + IPs que compartilham UA / subnet / scanpath com ele
        siblings: dict[str, set[str]] = defaultdict(set)  # ip -> {motivos}
        for ua, ips in ua_ips.items():
            if pivot in ips:
                for o in ips:
                    if o != pivot:
                        siblings[o].add(f"UA")
        for sub, ips in subnet_ips.items():
            if pivot in ips:
                for o in ips:
                    if o != pivot:
                        siblings[o].add(f"/24 {sub}")
        for path, ips in path_ips.items():
            if pivot in ips and _looks_like_scan(path, len(ips), min_shared):
                for o in ips:
                    if o != pivot:
                        siblings[o].add("rota de scan")
        selected = {pivot} | set(siblings.keys())
        # se o pivô não apareceu nos logs, ainda montamos o nó dele (só atributos vazios)
        # limita irmãos aos mais ativos
        if len(selected) > max_ips:
            ranked = sorted(siblings.keys(), key=lambda i: ip_reqs.get(i, 0), reverse=True)[: max_ips - 1]
            selected = {pivot} | set(ranked)
    else:
        selected = set([ip for ip, _ in ip_reqs.most_common(max_ips)])

    # --- 3) Construir nós/arestas ---
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    def add_node(nid: str, ntype: str, label: str, weight: float, meta: dict[str, Any] | None = None):
        if nid in seen_nodes:
            # atualiza peso (soma de grau) se já existe
            for n in nodes:
                if n["id"] == nid:
                    n["weight"] = max(n["weight"], weight)
                    return
        seen_nodes.add(nid)
        nodes.append({"id": nid, "type": ntype, "label": label, "weight": weight, "meta": meta or {}})

    def add_edge(src: str, dst: str, etype: str, weight: float = 1.0):
        edges.append({"source": src, "target": dst, "type": etype, "weight": weight})

    # nós de IP
    for ip in selected:
        enr = _enrich_ip(ip, ip in (banned or set()))
        nid = f"ip:{ip}"
        top_paths = [p for p, _ in ip_paths[ip].most_common(6)]
        top_ua = ip_ua[ip].most_common(1)[0][0] if ip_ua[ip] else None
        add_node(
            nid, "ip", ip, float(ip_reqs.get(ip, 0)),
            {
                "requests": ip_reqs.get(ip, 0),
                "domains": sorted(ip_domains[ip]),
                "top_paths": top_paths,
                "status": _status_summary(ip_status[ip]),
                "ua": top_ua,
                "cf": ip_cf.get(ip, False),
                "country": enr["country"],
                "asn": enr["asn"],
                "scenarios": enr["scenarios"],
                "subnet": _subnet24(ip),
                "banned": ip in (banned or set()),
                "first_seen": ip_first.get(ip),
                "last_seen": ip_last.get(ip),
                "is_pivot": ip == pivot,
            },
        )

    # helper: um atributo é "elegível" se conecta >= min_shared IPs SELECIONADOS,
    # ou (no modo pivô) se toca o próprio pivô.
    def eligible(ips_with_attr: set[str]) -> set[str]:
        inter = ips_with_attr & selected
        if pivot and pivot in inter:
            return inter
        if len(inter) >= min_shared:
            return inter
        return set()

    # domínios (sempre mostrados; poucos) — ligam IP -> domínio
    dom_ips: dict[str, set[str]] = defaultdict(set)
    for ip in selected:
        for d in ip_domains[ip]:
            dom_ips[d].add(ip)
    for d, ips in dom_ips.items():
        did = f"dom:{d}"
        add_node(did, "domain", d, float(len(ips)), {"ips": len(ips)})
        for ip in ips:
            add_edge(f"ip:{ip}", did, "acessou")

    # User-Agents compartilhados
    for ua, ips_all in ua_ips.items():
        ips = eligible(ips_all)
        if not ips:
            continue
        uid = _ua_id(ua)
        add_node(uid, "ua", _short_ua(ua), float(len(ips)), {"ips": len(ips), "full": ua})
        for ip in ips:
            add_edge(f"ip:{ip}", uid, "usou")

    # sub-redes /24 compartilhadas
    for sub, ips_all in subnet_ips.items():
        ips = eligible(ips_all)
        if len(ips) < 2:  # subnet só interessa se agrupa >=2 IPs
            continue
        sid = f"net:{sub}"
        add_node(sid, "subnet", sub, float(len(ips)), {"ips": len(ips)})
        for ip in ips:
            add_edge(f"ip:{ip}", sid, "mesma-rede")

    # rotas de scan compartilhadas
    scan_added = 0
    for path, ips_all in sorted(path_ips.items(), key=lambda kv: len(kv[1] & selected), reverse=True):
        ips = eligible(ips_all)
        if not ips:
            continue
        if not _looks_like_scan(path, len(ips), min_shared):
            continue
        if scan_added >= 30 and not (pivot and pivot in ips):
            continue
        pid = f"scan:{path}"
        add_node(pid, "scanpath", path if len(path) <= 40 else path[:39] + "…", float(len(ips)), {"ips": len(ips), "full": path})
        for ip in ips:
            add_edge(f"ip:{ip}", pid, "sondou")
        scan_added += 1

    # país / ASN / cenário (do enriquecimento dos nós de IP já calculado)
    country_ips: dict[str, set[str]] = defaultdict(set)
    asn_ips: dict[str, set[str]] = defaultdict(set)
    scen_ips: dict[str, set[str]] = defaultdict(set)
    for n in nodes:
        if n["type"] != "ip":
            continue
        ip = n["label"]
        m = n["meta"]
        if m.get("country"):
            country_ips[m["country"]].add(ip)
        if m.get("asn"):
            asn_ips[m["asn"]].add(ip)
        for sc in m.get("scenarios", []):
            scen_ips[sc].add(ip)

    for c, ips in country_ips.items():
        if pivot or len(ips) >= min_shared:
            cid = f"country:{c}"
            add_node(cid, "country", c, float(len(ips)), {"ips": len(ips)})
            for ip in ips:
                add_edge(f"ip:{ip}", cid, "país")
    for a, ips in asn_ips.items():
        if pivot or len(ips) >= min_shared:
            aid = f"asn:{a}"
            add_node(aid, "asn", a if len(a) <= 40 else a[:39] + "…", float(len(ips)), {"ips": len(ips), "full": a})
            for ip in ips:
                add_edge(f"ip:{ip}", aid, "ASN")
    for sc, ips in scen_ips.items():
        sid = f"scen:{sc}"
        add_node(sid, "scenario", sc, float(len(ips)), {"ips": len(ips)})
        for ip in ips:
            add_edge(f"ip:{ip}", sid, "cenário")

    # remove arestas para nós inexistentes (segurança)
    valid = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in valid and e["target"] in valid]

    # --- 4) Stats ---
    ip_nodes = [n for n in nodes if n["type"] == "ip"]
    banned_count = sum(1 for n in ip_nodes if n["meta"].get("banned"))
    type_counts: Counter = Counter(n["type"] for n in nodes)
    stats = {
        "ips": len(ip_nodes),
        "banned": banned_count,
        "nodes": len(nodes),
        "edges": len(edges),
        "node_types": dict(type_counts),
        "lines_read": lines_read,
        "files": files,
        "pivot": pivot,
        "min_shared": min_shared,
        "total_ips_seen": len(ip_reqs),
    }
    return {"nodes": nodes, "edges": edges, "stats": stats}
