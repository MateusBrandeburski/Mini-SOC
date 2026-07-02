"""Geolocalização de IP sob demanda, com cache em SQLite (app.db).

O fluxo é sempre: consulta o cache primeiro; só bate na API externa
(iplocation.net) se não houver registro válido em cache. O resultado é
normalizado e persistido para as próximas consultas.

A busca NUNCA é automática — é disparada pelo botão de geolocalização na
tabela (endpoint /api/geoip). Assim respeitamos a cota da API e evitamos
tráfego externo desnecessário.

Referência da API: https://api.iplocation.net/
  GET https://api.iplocation.net/?ip=<IP>&key=<KEY>&format=json
  -> {ip, ip_number, ip_version, country_name, country_code2, isp,
      response_code, response_message}
"""
from __future__ import annotations

import ipaddress
from typing import Any

import httpx

import db
from config import settings

_API_URL = "https://api.iplocation.net/"
_HTTP_TIMEOUT = 10.0


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Extrai apenas os campos que nos interessam da resposta da API."""
    return {
        "country_name": raw.get("country_name") or None,
        "country_code": raw.get("country_code2") or None,
        "isp": raw.get("isp") or None,
        "ip_version": raw.get("ip_version"),
        "source": "iplocation.net",
    }


async def lookup(ip: str) -> dict[str, Any]:
    """Geolocaliza `ip`, usando cache quando possível.

    Retorna um dict com pelo menos: ip, country_name, country_code, isp,
    cached (bool) e — em caso de erro — a chave `error`.

    Levanta ValueError se o IP for inválido.
    """
    # Valida/normaliza. Só aceitamos IP único (não faz sentido geolocalizar CIDR).
    addr = ipaddress.ip_address((ip or "").strip())
    ip = str(addr)

    # 1) Cache primeiro.
    cached = db.get_geoip_cache(ip, ttl_days=settings.geoip_cache_ttl_days)
    if cached is not None:
        return cached

    # 2) Consulta a API externa.
    params: dict[str, str] = {"ip": ip, "format": "json"}
    if settings.iplocation_api_key:
        params["key"] = settings.iplocation_api_key

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(_API_URL, params=params)
    except Exception as exc:  # noqa: BLE001 — falha de rede não deve derrubar a request
        return {"ip": ip, "cached": False, "error": f"falha de rede: {exc}"}

    if resp.status_code >= 400:
        return {"ip": ip, "cached": False, "error": f"HTTP {resp.status_code}"}

    try:
        raw = resp.json()
    except ValueError:
        return {"ip": ip, "cached": False, "error": "resposta não-JSON da API"}

    # A API sinaliza erros de negócio via response_code (string "200" = OK).
    code = str(raw.get("response_code", "")).strip()
    if code and code != "200":
        msg = raw.get("response_message") or f"response_code={code}"
        return {"ip": ip, "cached": False, "error": str(msg)}

    data = _normalize(raw)
    # 3) Persiste no cache e devolve.
    db.set_geoip_cache(ip, data)
    return {"ip": ip, "cached": False, **data}
