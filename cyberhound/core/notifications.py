"""
Sistema de notificaciones de CyberHound Pro.

Canales soportados:
  - Email (SMTP con TLS)
  - Webhook genérico (Slack, Teams, cualquier HTTP endpoint)

Las notificaciones se guardan primero en BD y se envían en background,
así si el envío falla quedan pendientes para reintentar.
"""
from __future__ import annotations

import json
import smtplib
import ssl
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiohttp

from cyberhound.core.logging import get_logger

logger = get_logger("notifications")


@dataclass
class NotificationConfig:
    # Email
    email_enabled: bool = False
    smtp_host:     str  = "smtp.gmail.com"
    smtp_port:     int  = 587
    smtp_user:     str  = ""
    smtp_password: str  = ""
    email_from:    str  = ""
    email_to:      list[str] = field(default_factory=list)

    # Webhook (Slack, Teams, Discord, cualquier HTTP)
    webhook_enabled: bool = False
    webhook_url:     str  = ""
    webhook_headers: dict = field(default_factory=dict)

    # Filtro de nivel mínimo para notificar
    min_level: str = "warning"   # info | warning | critical

    _LEVEL_ORDER = {"info": 0, "warning": 1, "critical": 2}

    def should_notify(self, level: str) -> bool:
        return self._LEVEL_ORDER.get(level, 0) >= self._LEVEL_ORDER.get(self.min_level, 1)


class NotificationManager:
    def __init__(self, cfg: NotificationConfig, db=None) -> None:
        self.cfg = cfg
        self.db = db   # Database | None

    async def send(
        self, message: str, level: str = "info", scan_id: int | None = None
    ) -> None:
        """Envía una notificación por todos los canales configurados."""
        # Guardar en BD primero
        if self.db:
            await self.db.add_notification(message, level, scan_id)

        if not self.cfg.should_notify(level):
            return

        errors = []

        if self.cfg.email_enabled and self.cfg.email_to:
            try:
                await self._send_email(message, level)
            except Exception as e:
                logger.error("Error enviando email: %s", e)
                errors.append(f"email: {e}")

        if self.cfg.webhook_enabled and self.cfg.webhook_url:
            try:
                await self._send_webhook(message, level)
            except Exception as e:
                logger.error("Error enviando webhook: %s", e)
                errors.append(f"webhook: {e}")

        if not errors:
            logger.info("Notificación enviada [%s]: %s", level.upper(), message[:80])

    async def _send_email(self, message: str, level: str) -> None:
        icons = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
        icon = icons.get(level, "📋")
        subject = f"{icon} CyberHound Pro — Alerta de seguridad [{level.upper()}]"

        html_body = f"""
        <html><body style="font-family:system-ui,sans-serif;background:#f5f5f5;padding:20px">
        <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;
                    padding:24px;border-left:4px solid {'#f85149' if level=='critical' else '#d29922'}">
          <h2 style="color:#0d1117;margin-top:0">🐾 CyberHound Pro</h2>
          <div style="background:#f8f8f8;padding:12px;border-radius:6px;
                      font-size:1.05rem;margin:16px 0">{message}</div>
          <p style="color:#666;font-size:.85rem">
            Este es un mensaje automático de CyberHound Pro.<br>
            Para gestionar las notificaciones, accede a la interfaz web.
          </p>
        </div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.cfg.email_from or self.cfg.smtp_user
        msg["To"]      = ", ".join(self.cfg.email_to)
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Enviar en executor para no bloquear el event loop
        import asyncio
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._smtp_send, msg)

    def _smtp_send(self, msg: MIMEMultipart) -> None:
        context = ssl.create_default_context()
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(self.cfg.smtp_user, self.cfg.smtp_password)
            server.send_message(msg)

    async def _send_webhook(self, message: str, level: str) -> None:
        colors = {"critical": "#f85149", "warning": "#d29922", "info": "#58a6ff"}
        color = colors.get(level, "#58a6ff")

        # Formato compatible con Slack y Teams
        payload = {
            "text": message,
            "attachments": [{
                "color": color,
                "text": message,
                "footer": "CyberHound Pro",
            }],
        }

        headers = {"Content-Type": "application/json", **self.cfg.webhook_headers}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.cfg.webhook_url,
                data=json.dumps(payload),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status not in (200, 201, 204):
                    text = await resp.text()
                    raise RuntimeError(f"Webhook respondió {resp.status}: {text[:200]}")

    async def test(self) -> dict[str, bool]:
        """Prueba todos los canales configurados. Para la UI de config."""
        results = {}
        test_msg = "✓ Test de notificación de CyberHound Pro — si recibes esto, funciona correctamente."

        if self.cfg.email_enabled:
            try:
                await self._send_email(test_msg, "info")
                results["email"] = True
            except Exception as e:
                logger.error("Test email falló: %s", e)
                results["email"] = False

        if self.cfg.webhook_enabled:
            try:
                await self._send_webhook(test_msg, "info")
                results["webhook"] = True
            except Exception as e:
                logger.error("Test webhook falló: %s", e)
                results["webhook"] = False

        return results
