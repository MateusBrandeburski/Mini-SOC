"""Mini SOC — Security Operations Dashboard (CrowdSec + Logs Nginx) — FastAPI.

Serve a SPA (static/index.html) e expõe a API que:
  - LÊ estatísticas/histórico direto do banco do CrowdSec (somente-leitura);
  - ESCREVE (bane/desbane/ajusta duração) SEMPRE via cscli (subprocess);
  - guarda estado próprio (config de alertas, watermark, auditoria) em app.db.

Autenticação obrigatória em todos os endpoints exceto /login e estáticos.
Toda ação de escrita é registrada na auditoria.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles

import alerts
import auth
import crowdsec
import db
from config import settings

STATIC_DIR = settings.base_dir / "static"
INDEX_FILE = STATIC_DIR / "index.html"


# --------------------------------------------------------------------------- lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa o app.db (config alertas, watermark, auditoria).
    db.init_db()
    # Inicia o poller de alertas em background.
    try:
        await alerts.start(app)
    except Exception as exc:  # pragma: no cover
        print(f"[app] falha ao iniciar poller de alertas: {exc}")
    yield
    # Encerramento gracioso do poller.
    try:
        await alerts.stop(app)
    except Exception:
        pass


app = FastAPI(title="Mini SOC — Security Operations Dashboard", version="1.0.0", lifespan=lifespan)


# --------------------------------------------------------------------------- helpers
def _actor(request: Request) -> str:
    return auth.current_user(request) or "?"


def _cscli_response(request: Request, *, action: str, target: str,
                    detail: dict[str, Any] | None, result: crowdsec.CscliResult) -> JSONResponse:
    """Registra na auditoria e devolve JSON padronizado para ações cscli."""
    db.add_audit(
        actor=_actor(request),
        action=action,
        target=target,
        detail=detail,
        command=result.argv,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        success=result.ok,
    )
    status = 200 if result.ok else 400
    return JSONResponse(
        {
            "ok": result.ok,
            "action": action,
            "target": target,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
        status_code=status,
    )


# ============================================================================ AUTH
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if not auth.verify_login(username, password):
        return JSONResponse({"ok": False, "error": "credenciais inválidas"}, status_code=401)
    resp = JSONResponse({"ok": True})
    auth.create_session_cookie(resp, username)
    return resp


@app.post("/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    auth.clear_session_cookie(resp)
    return resp


# ============================================================================ SPA
@app.get("/")
async def index(request: Request):
    # Se não autenticado, ainda servimos a página; a SPA detecta 401 nas chamadas
    # /api e exibe o overlay de login. (Mantém uma única página.)
    if not INDEX_FILE.exists():
        return JSONResponse({"error": "static/index.html não encontrado"}, status_code=500)
    return FileResponse(str(INDEX_FILE))


# ============================================================================ API (leitura)
@app.get("/api/health")
async def api_health(user: str = Depends(auth.require_auth)):
    cs = crowdsec.health()
    return {
        "ok": cs.get("ok", False),
        "crowdsec": cs,
        "cscli_available": crowdsec.cscli_available(),
    }


@app.get("/api/stats")
async def api_stats(user: str = Depends(auth.require_auth)):
    return crowdsec.get_stats()


@app.get("/api/timeseries")
async def api_timeseries(
    days: int = Query(30, ge=1, le=3650),
    origin: str | None = Query(None),
    user: str = Depends(auth.require_auth),
):
    return crowdsec.get_timeseries(days=days, origin=origin or None)


@app.get("/api/top/{kind}")
async def api_top(
    kind: str,
    limit: int = Query(10, ge=1, le=100),
    active_only: bool = Query(True),
    user: str = Depends(auth.require_auth),
):
    if kind not in ("countries", "scenarios", "asn"):
        raise HTTPException(status_code=404, detail="tipo de ranking inválido")
    return crowdsec.get_top(kind, limit=limit, active_only=active_only)


@app.get("/api/origins")
async def api_origins(user: str = Depends(auth.require_auth)):
    return crowdsec.get_origins()


@app.get("/api/decisions")
async def api_decisions(
    search: str | None = Query(None),
    type: str | None = Query(None),
    origin: str | None = Query(None),
    active_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    user: str = Depends(auth.require_auth),
):
    offset = (page - 1) * page_size
    res = crowdsec.list_decisions(
        search_ip=search or None,
        type_filter=type or None,
        origin=origin or None,
        active_only=active_only,
        limit=page_size,
        offset=offset,
    )
    res["page"] = page
    res["page_size"] = page_size
    return res


# ============================================================================ API (escrita)
@app.post("/api/decisions")
async def api_ban(request: Request, user: str = Depends(auth.require_auth)):
    body = await request.json()
    value = (body.get("value") or "").strip()
    duration = (body.get("duration") or "4h").strip()
    reason = (body.get("reason") or "painel: banimento manual").strip()
    type_ = (body.get("type") or "ban").strip()
    # Validação antes de tocar no cscli.
    try:
        crowdsec.validate_ip_or_cidr(value)
        crowdsec.validate_duration(duration)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result = crowdsec.add_decision(value=value, duration=duration, reason=reason, type_=type_)
    return _cscli_response(
        request,
        action="add",
        target=value,
        detail={"duration": duration, "reason": reason, "type": type_},
        result=result,
    )


@app.delete("/api/decisions/by-ip")
async def api_unban_by_ip(request: Request, value: str = Query(...), user: str = Depends(auth.require_auth)):
    try:
        crowdsec.validate_ip_or_cidr(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result = crowdsec.delete_decision_by_ip(value)
    return _cscli_response(request, action="delete", target=value, detail=None, result=result)


@app.delete("/api/decisions/{decision_id}")
async def api_unban_by_id(request: Request, decision_id: int, user: str = Depends(auth.require_auth)):
    result = crowdsec.delete_decision_by_id(decision_id)
    return _cscli_response(
        request, action="delete", target=f"id={decision_id}", detail=None, result=result
    )


@app.patch("/api/decisions/duration")
async def api_change_duration(request: Request, user: str = Depends(auth.require_auth)):
    body = await request.json()
    value = (body.get("value") or "").strip()
    new_duration = (body.get("duration") or "").strip()
    reason = (body.get("reason") or "painel: ajuste manual de duração").strip()
    try:
        crowdsec.validate_ip_or_cidr(value)
        crowdsec.validate_duration(new_duration)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result = crowdsec.change_duration(value=value, new_duration=new_duration, reason=reason)
    return _cscli_response(
        request,
        action="duration_change",
        target=value,
        detail={"new": new_duration, "reason": reason},
        result=result,
    )


# ============================================================================ API (alertas)
@app.get("/api/alerts/config")
async def api_alerts_config_get(user: str = Depends(auth.require_auth)):
    return db.get_alert_config()


@app.put("/api/alerts/config")
async def api_alerts_config_put(request: Request, user: str = Depends(auth.require_auth)):
    body = await request.json()
    current = db.get_alert_config()
    # Merge tolerante: aceita chaves conhecidas.
    for key in ("enabled", "origins", "scenarios", "threshold_count", "threshold_minutes", "channels"):
        if key in body:
            current[key] = body[key]
    saved = db.set_alert_config(current)
    db.add_audit(
        actor=_actor(request),
        action="alert_config",
        target=None,
        detail=saved,
        command=None,
        exit_code=0,
        stdout=None,
        stderr=None,
        success=True,
    )
    return saved


@app.get("/api/alerts/history")
async def api_alerts_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    user: str = Depends(auth.require_auth),
):
    offset = (page - 1) * page_size
    return {"items": db.list_alert_history(limit=page_size, offset=offset), "page": page, "page_size": page_size}


@app.post("/api/alerts/test")
async def api_alerts_test(user: str = Depends(auth.require_auth)):
    return await alerts.send_test_notification()


# ============================================================================ API (auditoria)
@app.get("/api/audit")
async def api_audit(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    user: str = Depends(auth.require_auth),
):
    offset = (page - 1) * page_size
    return {
        "items": db.list_audit(limit=page_size, offset=offset),
        "total": db.count_audit(),
        "page": page,
        "page_size": page_size,
    }


# ============================================================================ API (logs nginx)
import nginx_logs  # noqa: E402  (import tardio p/ manter agrupamento lógico)


@app.get("/api/logs/files")
async def api_logs_files(user: str = Depends(auth.require_auth)):
    return nginx_logs.list_files()


@app.get("/api/logs")
async def api_logs(
    file: str = Query(...),
    ip: str | None = Query(None),
    status: str | None = Query(None),
    method: str | None = Query(None),
    path: str | None = Query(None),
    ua: str | None = Query(None),
    q: str | None = Query(None),
    lines: int = Query(2000, ge=1, le=100000),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    user: str = Depends(auth.require_auth),
):
    try:
        banned = crowdsec.get_active_banned_ips()
    except Exception:
        banned = set()
    try:
        return nginx_logs.query_logs(
            file=file,
            ip=ip or None,
            status=status or None,
            method=method or None,
            path=path or None,
            ua=ua or None,
            q=q or None,
            lines=lines,
            page=page,
            page_size=page_size,
            banned_ips=banned,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/logs/stats")
async def api_logs_stats(
    file: str = Query(...),
    lines: int = Query(5000, ge=1, le=200000),
    user: str = Depends(auth.require_auth),
):
    try:
        return nginx_logs.log_stats(file=file, lines=lines)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/logs/stream")
async def api_logs_stream(request: Request, file: str = Query(...), user: str = Depends(auth.require_auth)):
    # Valida o arquivo antes de abrir o stream (proteção path traversal delegada
    # ao nginx_logs.resolve_file dentro do tail_stream).
    async def event_gen():
        try:
            async for item in nginx_logs.tail_stream(file):
                if await request.is_disconnected():
                    break
                yield f"data: {json.dumps(item, default=str)}\n\n"
        except ValueError as exc:
            yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # pragma: no cover
            yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ============================================================================ estáticos
# Monta /static para eventuais assets adicionais (a index é servida em "/").
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def main() -> None:
    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
