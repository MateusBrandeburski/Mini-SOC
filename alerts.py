"""Poller de alertas de novos bans + canais de notificação.

Responsabilidades deste módulo:

  1. POLLER  → um laço `asyncio` (sem APScheduler) que a cada
     `settings.alert_poll_seconds` verifica no banco do CrowdSec se surgiram
     novas decisões (bans) acima da marca d'água (`db.get_watermark()`) e, se
     configurado, dispara notificações. Nunca morre por exceção de um tick.

  2. CANAIS  → webhook (HTTP POST JSON), Telegram (Bot API) e e-mail (SMTP).
     Cada canal degrada graciosamente quando não configurado e NUNCA propaga
     exceção para o poller — sempre retorna {"ok": bool, "detail": ...}.

Regras importantes respeitadas:
  - Na PRIMEIRÍSSIMA execução (watermark == 0) apenas alinhamos a marca d'água
    ao maior id de decisão existente, SEM alertar o backlog histórico.
  - A marca d'água avança para o maior id VISTO no tick (mesmo decisões
    filtradas), para nunca reprocessar.
  - Nada é iniciado no import: o laço só roda depois de `start(app)`.

O acesso de leitura ao CrowdSec é síncrono (sqlite3/PyMySQL); por isso as
chamadas bloqueantes rodam em `asyncio.to_thread` para não travar o event loop.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from html import escape as _html_escape
from typing import Any

import httpx

import crowdsec
import db
from config import settings

logger = logging.getLogger("painel_crowdsec.alerts")

# Nome do atributo em app.state onde guardamos a task e o evento de parada.
_TASK_ATTR = "alert_poller_task"
_STOP_ATTR = "alert_poller_stop"

# Timeout padrão (segundos) para requisições HTTP dos canais.
_HTTP_TIMEOUT = 10.0


# ===========================================================================
# Formatação de mensagem
# ===========================================================================
def _fmt_asn(decision: dict[str, Any]) -> str:
    """Monta um rótulo de ASN legível a partir de nome/número."""
    name = (decision.get("as_name") or "").strip()
    number = decision.get("as_number")
    number_s = "" if number in (None, "") else str(number).strip()
    if name and number_s:
        return f"{name} (AS{number_s})"
    if name:
        return name
    if number_s:
        return f"AS{number_s}"
    return "-"


def _v(value: Any, default: str = "-") -> str:
    """Normaliza um valor para exibição, tratando None/vazio."""
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


def format_decision_message(decision: dict[str, Any]) -> tuple[str, str, str, dict[str, Any]]:
    """Formata uma decisão em (assunto, texto_plano, texto_html, payload_dict).

    O payload é a estrutura JSON enviada ao webhook. Os textos servem para
    Telegram (HTML) e e-mail (plano).
    """
    ip = _v(decision.get("value"))
    country = _v(decision.get("country"))
    asn = _fmt_asn(decision)
    scenario = _v(decision.get("scenario"))
    origin = _v(decision.get("origin"))
    created_at = _v(decision.get("created_at"))
    until = _v(decision.get("until"))
    decision_id = decision.get("id")

    subject = f"[CrowdSec] Novo ban: {ip} ({scenario})"

    text_plain = (
        "Novo bloqueio detectado pelo CrowdSec\n"
        f"IP/valor : {ip}\n"
        f"País     : {country}\n"
        f"ASN      : {asn}\n"
        f"Cenário  : {scenario}\n"
        f"Origem   : {origin}\n"
        f"Expira em: {until}\n"
        f"Horário  : {created_at}\n"
    )

    text_html = (
        "<b>🚫 Novo bloqueio detectado pelo CrowdSec</b>\n\n"
        f"<b>IP/valor:</b> <code>{_html_escape(ip)}</code>\n"
        f"<b>País:</b> {_html_escape(country)}\n"
        f"<b>ASN:</b> {_html_escape(asn)}\n"
        f"<b>Cenário:</b> {_html_escape(scenario)}\n"
        f"<b>Origem:</b> {_html_escape(origin)}\n"
        f"<b>Expira em:</b> {_html_escape(until)}\n"
        f"<b>Horário:</b> {_html_escape(created_at)}\n"
    )

    payload: dict[str, Any] = {
        "event": "crowdsec_new_ban",
        "decision_id": decision_id,
        "ip": None if ip == "-" else ip,
        "value": None if ip == "-" else ip,
        "country": None if country == "-" else country,
        "as_name": decision.get("as_name"),
        "as_number": decision.get("as_number"),
        "asn": None if asn == "-" else asn,
        "scenario": None if scenario == "-" else scenario,
        "origin": None if origin == "-" else origin,
        "type": decision.get("type"),
        "created_at": None if created_at == "-" else created_at,
        "until": None if until == "-" else until,
    }
    return subject, text_plain, text_html, payload


# ===========================================================================
# Canais de notificação (cada um blindado; nunca levanta para o poller)
# ===========================================================================
async def send_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    """Envia o payload JSON via HTTP POST para settings.alert_webhook_url.

    Ignora silenciosamente se a URL não estiver configurada.
    """
    url = (settings.alert_webhook_url or "").strip()
    if not url:
        return {"ok": False, "detail": "webhook não configurado"}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
        ok = resp.status_code < 400
        return {"ok": ok, "detail": f"HTTP {resp.status_code}"}
    except Exception as exc:  # noqa: BLE001 — canal nunca deve derrubar o poller
        logger.warning("Falha ao enviar webhook: %s", exc)
        return {"ok": False, "detail": str(exc)}


async def send_telegram(text: str) -> dict[str, Any]:
    """Envia uma mensagem via Telegram Bot API (parse_mode=HTML).

    Ignora silenciosamente se token ou chat_id não estiverem configurados.
    """
    token = (settings.telegram_bot_token or "").strip()
    chat_id = (settings.telegram_chat_id or "").strip()
    if not token or not chat_id:
        return {"ok": False, "detail": "telegram não configurado"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(url, json=data)
        if resp.status_code < 400:
            return {"ok": True, "detail": f"HTTP {resp.status_code}"}
        # A API do Telegram devolve JSON com o motivo do erro.
        detail = f"HTTP {resp.status_code}"
        try:
            body = resp.json()
            if isinstance(body, dict) and body.get("description"):
                detail = f"HTTP {resp.status_code}: {body['description']}"
        except Exception:  # noqa: BLE001
            pass
        return {"ok": False, "detail": detail}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao enviar telegram: %s", exc)
        return {"ok": False, "detail": str(exc)}


def _smtp_configured() -> bool:
    return bool(
        (settings.smtp_host or "").strip()
        and (settings.smtp_from or "").strip()
        and settings.smtp_to
    )


def send_email(subject: str, body: str) -> dict[str, Any]:
    """Envia um e-mail via SMTP (síncrono, para uso em thread).

    Usa STARTTLS quando settings.smtp_tls. Autentica se usuário/senha estiverem
    configurados. Ignora silenciosamente quando o SMTP não estiver configurado.
    Nunca levanta exceção — retorna {"ok": bool, "detail": ...}.
    """
    if not _smtp_configured():
        return {"ok": False, "detail": "smtp não configurado"}

    recipients = [addr for addr in (settings.smtp_to or []) if addr.strip()]
    if not recipients:
        return {"ok": False, "detail": "sem destinatários (SMTP_TO)"}

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    host = settings.smtp_host
    port = int(settings.smtp_port or 0) or (587 if settings.smtp_tls else 25)
    try:
        with smtplib.SMTP(host, port, timeout=_HTTP_TIMEOUT) as server:
            server.ehlo()
            if settings.smtp_tls:
                server.starttls()
                server.ehlo()
            if (settings.smtp_user or "").strip():
                server.login(settings.smtp_user, settings.smtp_password or "")
            server.send_message(msg, from_addr=settings.smtp_from, to_addrs=recipients)
        return {"ok": True, "detail": f"enviado para {len(recipients)} destinatário(s)"}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao enviar e-mail: %s", exc)
        return {"ok": False, "detail": str(exc)}


async def send_email_async(subject: str, body: str) -> dict[str, Any]:
    """Wrapper assíncrono de send_email() usando asyncio.to_thread.

    Mantém o SMTP bloqueante fora do event loop.
    """
    try:
        return await asyncio.to_thread(send_email, subject, body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao enviar e-mail (thread): %s", exc)
        return {"ok": False, "detail": str(exc)}


# ===========================================================================
# Dispatch para os canais habilitados
# ===========================================================================
def _enabled_channels(cfg: dict[str, Any]) -> dict[str, bool]:
    """Extrai o dicionário de canais habilitados da config, com defaults."""
    channels = cfg.get("channels") or {}
    return {
        "webhook": bool(channels.get("webhook")),
        "telegram": bool(channels.get("telegram")),
        "email": bool(channels.get("email")),
    }


async def notify(decision: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Notifica uma decisão nos canais habilitados em cfg["channels"].

    Retorna um dict com o resultado por canal (apenas os habilitados). Os canais
    são disparados concorrentemente. Nenhum canal derruba os demais.
    """
    subject, text_plain, text_html, payload = format_decision_message(decision)
    channels = _enabled_channels(cfg)

    tasks: dict[str, Any] = {}
    if channels["webhook"]:
        tasks["webhook"] = send_webhook(payload)
    if channels["telegram"]:
        tasks["telegram"] = send_telegram(text_html)
    if channels["email"]:
        tasks["email"] = send_email_async(subject, text_plain)

    results: dict[str, Any] = {}
    if tasks:
        names = list(tasks.keys())
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, res in zip(names, gathered):
            if isinstance(res, Exception):
                results[name] = {"ok": False, "detail": str(res)}
            else:
                results[name] = res
    return results


async def send_test_notification() -> dict[str, Any]:
    """Envia uma mensagem de teste para todos os canais habilitados/configurados.

    Usada por POST /api/alerts/test. Considera a config salva (canais
    habilitados) mas dispara mesmo que o canal esteja "off" na config se ele
    estiver configurado no ambiente? Não: respeitamos a config; porém se um
    canal habilitado não estiver configurado, o próprio canal reporta o motivo.

    Retorna {"channels": {...}, "sent": bool}.
    """
    cfg = db.get_alert_config()
    channels = _enabled_channels(cfg)

    subject = "[CrowdSec] Notificação de teste"
    text_plain = (
        "Esta é uma notificação de TESTE do Painel CrowdSec.\n"
        "Se você recebeu esta mensagem, o canal está funcionando corretamente.\n"
    )
    text_html = (
        "<b>✅ Notificação de teste — Painel CrowdSec</b>\n\n"
        "Se você recebeu esta mensagem, o canal está funcionando corretamente."
    )
    payload = {
        "event": "crowdsec_test",
        "message": "Notificação de teste do Painel CrowdSec",
    }

    tasks: dict[str, Any] = {}
    if channels["webhook"]:
        tasks["webhook"] = send_webhook(payload)
    if channels["telegram"]:
        tasks["telegram"] = send_telegram(text_html)
    if channels["email"]:
        tasks["email"] = send_email_async(subject, text_plain)

    results: dict[str, Any] = {}
    if tasks:
        names = list(tasks.keys())
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, res in zip(names, gathered):
            if isinstance(res, Exception):
                results[name] = {"ok": False, "detail": str(res)}
            else:
                results[name] = res

    sent = any(isinstance(r, dict) and r.get("ok") for r in results.values())
    return {"channels": results, "sent": sent}


# ===========================================================================
# Núcleo do poller: verificar novas decisões e notificar
# ===========================================================================
def _scenario_allowed(decision: dict[str, Any], scenarios: list[str]) -> bool:
    """Aplica o filtro de cenários: se a lista não é vazia, só passam esses."""
    if not scenarios:
        return True
    return (decision.get("scenario") or "") in scenarios


async def check_and_notify() -> None:
    """Um tick do poller: detecta novas decisões e (talvez) notifica.

    Lógica:
      - watermark == 0 (primeira execução): alinha a marca d'água ao maior id
        atual SEM alertar o backlog; persiste e retorna.
      - alertas desabilitados: avança a marca d'água silenciosamente e retorna.
      - caso contrário: busca decisões novas (opcionalmente filtrando por
        origens), aplica filtro de cenário, aplica threshold e notifica.

    Toda leitura bloqueante do CrowdSec roda via asyncio.to_thread.
    """
    watermark = await asyncio.to_thread(db.get_watermark)

    # --- Primeira execução: apenas alinhar, sem alertar backlog histórico. ---
    if watermark == 0:
        max_id = await asyncio.to_thread(crowdsec.get_max_decision_id)
        await asyncio.to_thread(db.set_watermark, max_id)
        logger.info("Poller inicializado: marca d'água alinhada em id=%s (sem alertar backlog).", max_id)
        return

    cfg = await asyncio.to_thread(db.get_alert_config)

    # --- Alertas desabilitados: avançar silenciosamente para não acumular. ---
    if not cfg.get("enabled"):
        max_id = await asyncio.to_thread(crowdsec.get_max_decision_id)
        if max_id > watermark:
            await asyncio.to_thread(db.set_watermark, max_id)
        return

    origins = [o for o in (cfg.get("origins") or []) if str(o).strip()]
    scenarios = [s for s in (cfg.get("scenarios") or []) if str(s).strip()]

    new_decisions = await asyncio.to_thread(
        crowdsec.get_new_decisions_since,
        watermark,
        origins if origins else None,
    )
    if not new_decisions:
        return

    # Só notificamos bans. Outros tipos apenas avançam a marca d'água.
    threshold_count = int(cfg.get("threshold_count") or 0)
    threshold_minutes = int(cfg.get("threshold_minutes") or 5)

    max_seen = watermark
    for decision in new_decisions:
        try:
            did = decision.get("id")
            if isinstance(did, int) and did > max_seen:
                max_seen = did

            # Só interessa notificar bloqueios efetivos.
            if (decision.get("type") or "").lower() != "ban":
                continue

            # Filtro de cenário.
            if not _scenario_allowed(decision, scenarios):
                continue

            # --- Threshold: só ENVIA se ultrapassar o limite na janela. ---
            channels = _enabled_channels(cfg)
            if threshold_count > 0:
                recent = await asyncio.to_thread(db.count_recent_alerts, threshold_minutes)
                # +1 conta o alerta atual que estamos avaliando.
                if (recent + 1) <= threshold_count:
                    await _record_suppressed(decision, channels, threshold_count, threshold_minutes)
                    continue

            # --- Envio efetivo. ---
            results = await notify(decision, cfg)
            await asyncio.to_thread(
                db.add_alert_history,
                decision_id=decision.get("id"),
                ip=decision.get("value"),
                country=decision.get("country"),
                asn=_fmt_asn(decision) if (decision.get("as_name") or decision.get("as_number")) else None,
                scenario=decision.get("scenario"),
                origin=decision.get("origin"),
                duration=None,
                until=decision.get("until"),
                channels=channels,
                result=results,
            )
        except Exception as exc:  # noqa: BLE001 — uma decisão ruim não trava o tick
            logger.warning("Falha ao processar decisão id=%s: %s", decision.get("id"), exc)

    # A marca d'água avança para o maior id VISTO (mesmo filtrados), evitando
    # reprocessamento no próximo tick.
    if max_seen > watermark:
        await asyncio.to_thread(db.set_watermark, max_seen)


async def _record_suppressed(
    decision: dict[str, Any],
    channels: dict[str, bool],
    threshold_count: int,
    threshold_minutes: int,
) -> None:
    """Registra no histórico um alerta suprimido pelo threshold (sem enviar)."""
    note = {
        "suppressed_by_threshold": True,
        "threshold_count": threshold_count,
        "threshold_minutes": threshold_minutes,
    }
    await asyncio.to_thread(
        db.add_alert_history,
        decision_id=decision.get("id"),
        ip=decision.get("value"),
        country=decision.get("country"),
        asn=_fmt_asn(decision) if (decision.get("as_name") or decision.get("as_number")) else None,
        scenario=decision.get("scenario"),
        origin=decision.get("origin"),
        duration=None,
        until=decision.get("until"),
        channels=channels,
        result=note,
    )


# ===========================================================================
# Laço do poller e ciclo de vida (start/stop)
# ===========================================================================
async def poller_loop(stop_event: asyncio.Event) -> None:
    """Laço principal do poller.

    A cada `settings.alert_poll_seconds` chama check_and_notify(), capturando e
    logando qualquer exceção do tick (o laço nunca morre). Entre os ticks
    aguarda de forma que acorde imediatamente se `stop_event` for setado.
    """
    interval = max(1, int(settings.alert_poll_seconds or 20))
    logger.info("Poller de alertas iniciado (intervalo=%ss).", interval)
    while not stop_event.is_set():
        try:
            await check_and_notify()
        except Exception as exc:  # noqa: BLE001 — o poller jamais deve morrer
            logger.exception("Erro no tick do poller de alertas: %s", exc)

        # Dorme até o próximo tick, mas acorda cedo se pedirem parada.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass  # tempo normal do intervalo transcorreu → próximo tick
    logger.info("Poller de alertas encerrado.")


async def start(app: Any) -> None:
    """Cria o stop_event e a task do poller em app.state (idempotente)."""
    existing = getattr(app.state, _TASK_ATTR, None)
    if existing is not None and not existing.done():
        logger.debug("Poller já em execução; start() ignorado.")
        return

    stop_event = asyncio.Event()
    task = asyncio.create_task(poller_loop(stop_event), name="alert-poller")
    setattr(app.state, _STOP_ATTR, stop_event)
    setattr(app.state, _TASK_ATTR, task)


async def stop(app: Any) -> None:
    """Sinaliza parada, aguarda o encerramento gracioso e limpa o estado."""
    stop_event: asyncio.Event | None = getattr(app.state, _STOP_ATTR, None)
    task: asyncio.Task | None = getattr(app.state, _TASK_ATTR, None)

    if stop_event is not None:
        stop_event.set()

    if task is not None:
        try:
            # Dá um tempo para o laço acordar do wait_for e sair sozinho.
            await asyncio.wait_for(asyncio.shield(task), timeout=_HTTP_TIMEOUT)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("Poller encerrou com erro: %s", exc)

    setattr(app.state, _STOP_ATTR, None)
    setattr(app.state, _TASK_ATTR, None)
