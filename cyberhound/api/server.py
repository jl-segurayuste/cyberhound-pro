"""
Servidor web de CyberHound Pro v6.1
====================================
Integra:
- Base de datos SQLite (histórico, inventario, usuarios, supresiones)
- Scheduler de auditorías automáticas
- Notificaciones email/webhook
- WebSocket streaming con persistencia automática
- Gestión de múltiples usuarios con roles
- Endpoints REST completos
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
from datetime import datetime
from pathlib import Path

from aiohttp import web

from cyberhound.core import passwords
from cyberhound.core.auth import AuthConfig, auth_middleware, setup_auth_routes
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import AssetRecord, UserRecord
from cyberhound.core.licensing import license_manager
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.models import Finding, ScanReport
from cyberhound.core.notifications import NotificationConfig, NotificationManager
from cyberhound.core.scheduler import Scheduler, build_scheduler
from cyberhound.core.security import (
    CsrfProtection,
    InputValidator,
    TLSManager,
    ValidationError,
)

logger = get_logger("api")


async def _read_json(request) -> dict:
    """
    Lee el body JSON de un request de forma robusta.
    Maneja: whitespace extra, encoding issues, body vacío.
    Fallback a {} si el body está vacío o no es JSON válido.
    """
    import json as _json
    try:
        raw = await request.read()
        if not raw or not raw.strip():
            return {}
        # Limpiar whitespace al final que puede causar "Extra data"
        text = raw.strip().decode("utf-8", errors="replace")
        return _json.loads(text)
    except Exception:
        # Intentar con el método nativo de aiohttp
        try:
            return await _read_json(request)
        except Exception:
            return {}


# ── Repositorios de reglas YARA públicos ──────────────────────────────────────
YARA_SOURCES = {
    "default": [
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
         "ransomware.yar"),
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_webshell.yar",
         "webshells.yar"),
        ("https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Backdoor.yar",
         "linux_backdoor.yar"),
    ],
    "community": [
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Coinminer.yar",
         "coinminer.yar"),
    ],
}


async def _update_yara_rules(sources: list[str]) -> dict:
    """Descarga reglas YARA de repositorios públicos."""
    import aiohttp
    yara_dir = Path.home() / ".cyberhound" / "yara"
    yara_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, list] = {"updated": [], "errors": [], "skipped": []}
    urls: list[tuple[str, str]] = []
    for src in sources:
        urls.extend(YARA_SOURCES.get(src, []))

    if not urls:
        return {"error": f"Fuente desconocida: {sources}"}

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        for url, filename in urls:
            dest = yara_dir / filename
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Verificar que es YARA válido (tiene al menos una rule)
                        if "rule " in content:
                            dest.write_text(content, encoding="utf-8")
                            results["updated"].append(filename)
                            logger.info("YARA actualizado: %s (%d bytes)", filename, len(content))
                        else:
                            results["errors"].append(f"{filename}: contenido no parece YARA válido")
                    else:
                        results["errors"].append(f"{filename}: HTTP {resp.status}")
            except Exception as e:
                results["errors"].append(f"{filename}: {e}")

    return results

# Roles y sus permisos
ROLE_PERMISSIONS = {
    "admin":    {"scan", "fix", "config", "users", "view"},
    "operator": {"scan", "fix", "view"},
    "viewer":   {"view"},
}


def _requires_role(*roles: str):
    """Decorator para proteger endpoints por rol."""
    def decorator(handler):
        async def wrapper(self, request: web.Request) -> web.Response:
            user = request.get("auth_user", "")
            db_user = await self.db.get_user(user) if user else None
            role = db_user["role"] if db_user else "viewer"
            required = set(roles)
            allowed = ROLE_PERMISSIONS.get(role, set())
            if not required.issubset(allowed):
                return web.json_response(
                    {"error": f"Permiso denegado. Rol requerido: {roles}"},
                    status=403,
                )
            request["user_role"] = role
            return await handler(self, request)
        return wrapper
    return decorator


# ── Métricas (formato Prometheus, sin dependencias) ───────────────────────────

class _Metrics:
    """Contadores en proceso, expuestos en /metrics (texto Prometheus)."""

    def __init__(self) -> None:
        self._start = time.time()
        self._requests: dict[tuple[str, str], int] = {}
        self._duration_ms = 0.0
        self._count = 0

    def observe(self, method: str, status: int, ms: float) -> None:
        key = (method, f"{status // 100}xx")
        self._requests[key] = self._requests.get(key, 0) + 1
        self._duration_ms += ms
        self._count += 1

    def render(self) -> str:
        out = [
            "# HELP cyberhound_up 1 si el servicio responde",
            "# TYPE cyberhound_up gauge",
            "cyberhound_up 1",
            "# HELP cyberhound_uptime_seconds Segundos desde el arranque",
            "# TYPE cyberhound_uptime_seconds gauge",
            f"cyberhound_uptime_seconds {time.time() - self._start:.0f}",
            "# HELP cyberhound_http_requests_total Peticiones por método y clase de estado",
            "# TYPE cyberhound_http_requests_total counter",
        ]
        for (method, status), n in sorted(self._requests.items()):
            out.append(
                f'cyberhound_http_requests_total{{method="{method}",status="{status}"}} {n}'
            )
        out += [
            "# HELP cyberhound_http_request_duration_ms_sum Suma de latencias (ms)",
            "# TYPE cyberhound_http_request_duration_ms_sum counter",
            f"cyberhound_http_request_duration_ms_sum {self._duration_ms:.0f}",
        ]
        return "\n".join(out) + "\n"


METRICS = _Metrics()


# ── Middlewares ───────────────────────────────────────────────────────────────

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    # Nonce por petición: los <script> inline llevan este nonce, de modo que un
    # <script> inyectado (sin nonce) queda bloqueado por la CSP. Los manejadores
    # de eventos inline (onclick…) siguen permitidos vía script-src-attr
    # (endurecimiento futuro: eliminarlos y quitar también 'unsafe-inline' ahí).
    nonce = secrets.token_urlsafe(16)
    request["csp_nonce"] = nonce
    response = await handler(request)
    response.headers.update({
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "X-XSS-Protection":        "1; mode=block",
        "Referrer-Policy":         "strict-origin-when-cross-origin",
        "Cache-Control":           "no-store",
        "Content-Security-Policy": (
            f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
            "script-src-attr 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' ws: wss:;"
        ),
    })
    return response


@web.middleware
async def request_logger_middleware(request: web.Request, handler):
    start = time.monotonic()
    try:
        response = await handler(request)
        elapsed = (time.monotonic() - start) * 1000
        METRICS.observe(request.method, response.status, elapsed)
        logger.info("%s %s %d %.0fms user=%s",
                    request.method, request.path, response.status, elapsed,
                    request.get("auth_user", "anonymous"))
        return response
    except web.HTTPException as e:
        elapsed = (time.monotonic() - start) * 1000
        METRICS.observe(request.method, e.status, elapsed)
        logger.warning("%s %s %d %.0fms", request.method, request.path, e.status, elapsed)
        raise


# ── Servidor principal ────────────────────────────────────────────────────────

class CyberHoundServer:

    def __init__(self, cfg: CyberHoundConfig) -> None:
        self.cfg = cfg
        self._app: web.Application | None = None
        self._findings_cache: dict[str, list[Finding]] = {}
        self._scan_id_cache:  dict[str, int] = {}
        self._push_clients:   set = set()  # WebSocket push connections   # ws_id → scan_id en BD

        # Inicializar DB, notificaciones y scheduler
        from cyberhound.core.database_pg import create_database
        db_url = getattr(cfg, "db_url", "") or ""
        self.db = create_database(db_url=db_url, db_path=cfg.db_path)
        self.notification_manager = NotificationManager(
            NotificationConfig(
                email_enabled=cfg.notifications.email_enabled,
                smtp_host=cfg.notifications.smtp_host,
                smtp_port=cfg.notifications.smtp_port,
                smtp_user=cfg.notifications.smtp_user,
                smtp_password=cfg.notifications.smtp_password,
                email_from=cfg.notifications.email_from,
                email_to=cfg.notifications.email_to,
                webhook_enabled=cfg.notifications.webhook_enabled,
                webhook_url=cfg.notifications.webhook_url,
                min_level=cfg.notifications.min_level,
            ),
            db=self.db,
        )
        # SIEM integration
        from cyberhound.core.siem import SIEMConfig, SIEMIntegration
        self.siem = SIEMIntegration(SIEMConfig(
            wazuh_enabled=cfg.siem.wazuh_enabled,
            wazuh_host=cfg.siem.wazuh_host,
            wazuh_port=cfg.siem.wazuh_port,
            wazuh_api_url=cfg.siem.wazuh_api_url,
            elk_enabled=cfg.siem.elk_enabled,
            elk_url=cfg.siem.elk_url,
            elk_index=cfg.siem.elk_index,
            elk_api_key=cfg.siem.elk_api_key,
            splunk_enabled=cfg.siem.splunk_enabled,
            splunk_hec_url=cfg.siem.splunk_hec_url,
            splunk_hec_token=cfg.siem.splunk_hec_token,
            min_severity=cfg.siem.min_severity,
        ))
        self.scheduler: Scheduler | None = None
        self._sbom_cache: dict | None = None
        self._ansible_jobs: list = []
        self._tenant_store = None
        self._ebpf_monitor = None

        # Modo agente
        from cyberhound.core.agent import AgentConfig, AgentManager, AgentReporter
        agent_cfg = AgentConfig(
            mode=cfg.agent.mode,
            manager_url=cfg.agent.manager_url,
            agent_key=cfg.agent.agent_key,
            agent_name=cfg.agent.agent_name,
        )
        self.agent_manager  = AgentManager(self.db, agent_cfg)
        self.agent_reporter = AgentReporter(agent_cfg) if cfg.agent.mode == "agent" else None

    def build_app(self) -> web.Application:
        auth_cfg = AuthConfig(
            mode=self.cfg.auth.mode, secret=self.cfg.auth.secret,
            username=self.cfg.auth.username, password_hash=self.cfg.auth.password_hash,
            token_ttl_hours=self.cfg.auth.token_ttl_hours,
            localhost_only=self.cfg.auth.localhost_only,
        )
        app = web.Application(
            middlewares=[
                security_headers_middleware, request_logger_middleware,
                CsrfProtection().middleware_factory(is_https=True), auth_middleware,
            ],
            client_max_size=10 * 1024 * 1024,
        )
        app["auth_config"] = auth_cfg
        app["server"] = self

        setup_auth_routes(app, auth_cfg)

        static_dir = Path(__file__).parent.parent / "ui" / "static"
        if static_dir.exists():
            app.router.add_static("/static", static_dir)

        app.router.add_get("/", self.serve_spa)
        app.router.add_get("/ws",     self.websocket_handler)
        app.router.add_get("/ws/push", self.push_websocket_handler)

        # ── Escaneos ──────────────────────────────────────────────────────────
        app.router.add_post("/api/fix/local",    self.api_fix_local)
        app.router.add_post("/api/fix/remote",   self.api_fix_remote)
        app.router.add_post("/api/findings/explain", self.api_explain_finding)
        app.router.add_get ("/api/rollback",      self.api_rollback_list)
        app.router.add_post("/api/rollback/local", self.api_rollback_local)
        app.router.add_get ("/metrics",           self.api_metrics)
        app.router.add_post("/api/report/{fmt}", self.api_report)

        # ── Histórico y resultados ────────────────────────────────────────────
        app.router.add_get("/api/history",               self.api_history)
        app.router.add_get("/api/history/{scan_id}",     self.api_history_detail)
        app.router.add_get("/api/history/{scan_id}/compare", self.api_compare)
        app.router.add_get("/api/score/trend",           self.api_score_trend)
        app.router.add_get("/api/score/detail",          self.api_score_detail)
        app.router.add_get("/api/dashboard",             self.api_dashboard)

        # ── Inventario de red ────────────────────────────────────────────────
        app.router.add_get ("/api/assets",              self.api_assets)
        app.router.add_post("/api/assets/{ip}/authorize", self.api_asset_authorize)
        app.router.add_get ("/api/network/discover",    self.api_discover)

        # ── Supresiones (falsos positivos) ───────────────────────────────────
        app.router.add_get   ("/api/suppressions",      self.api_suppressions_list)
        app.router.add_post  ("/api/suppressions",      self.api_suppressions_add)
        app.router.add_delete("/api/suppressions/{pattern}", self.api_suppressions_delete)

        # ── Usuarios ─────────────────────────────────────────────────────────
        app.router.add_get   ("/api/users",             self.api_users_list)
        app.router.add_post  ("/api/users",             self.api_users_create)
        app.router.add_patch ("/api/users/{username}",  self.api_users_update)
        app.router.add_delete("/api/users/{username}",  self.api_users_delete)

        # ── Scheduler ────────────────────────────────────────────────────────
        app.router.add_get ("/api/scheduler",           self.api_scheduler_list)
        app.router.add_post("/api/scheduler/{name}/run",   self.api_scheduler_run)
        app.router.add_post("/api/scheduler/{name}/toggle", self.api_scheduler_toggle)

        # ── Configuración ────────────────────────────────────────────────────
        app.router.add_get ("/api/config/keys",         self.api_get_keys)
        app.router.add_post("/api/config/keys",         self.api_save_keys)
        app.router.add_get ("/api/config/notifications",self.api_get_notifications_cfg)
        app.router.add_post("/api/config/notifications",self.api_save_notifications_cfg)
        app.router.add_post("/api/config/notifications/test", self.api_test_notifications)
        app.router.add_get ("/api/config/siem",         self.api_get_siem)
        app.router.add_post("/api/config/siem",         self.api_save_siem)
        app.router.add_post("/api/config/siem/test",    self.api_test_siem)

        # ── Modo agente ───────────────────────────────────────────────────────
        app.router.add_get ("/api/config/agent",     self.api_get_agent_cfg)
        app.router.add_post("/api/config/agent",     self.api_save_agent_cfg)
        app.router.add_post("/api/agent/report",     self.api_agent_report)
        app.router.add_post("/api/agent/heartbeat",  self.api_agent_heartbeat)
        app.router.add_get ("/api/agent/list",       self.api_agent_list)

        # ── PDF + Compliance ─────────────────────────────────────────────────────
        app.router.add_post("/api/report/pdf",           self.api_report_pdf)
        app.router.add_post("/api/compliance",           self.api_compliance)
        app.router.add_get ("/api/compliance",           self.api_compliance_get)

        # ── Cuarentena ───────────────────────────────────────────────────────────
        app.router.add_get ("/api/quarantine",              self.api_quarantine_list)
        app.router.add_post("/api/quarantine",              self.api_quarantine_add)
        app.router.add_post("/api/quarantine/{name}/restore", self.api_quarantine_restore)
        app.router.add_delete("/api/quarantine/{name}",    self.api_quarantine_delete)
        app.router.add_get ("/api/quarantine/stats",       self.api_quarantine_stats)

        # ── OpenAPI / Swagger ─────────────────────────────────────────────────────
        app.router.add_get ("/api/openapi.json",       self.api_openapi_spec)
        app.router.add_get ("/api/docs",               self.api_swagger_ui)

        # ── Ansible AWX/Tower ────────────────────────────────────────────────────
        app.router.add_post("/api/ansible/run",        self.api_ansible_run)
        app.router.add_get ("/api/ansible/jobs",       self.api_ansible_jobs)
        app.router.add_get ("/api/ansible/templates",  self.api_ansible_templates)

        # ── Multi-tenant ──────────────────────────────────────────────────────────
        app.router.add_get ("/api/tenants",            self.api_tenants_list)
        app.router.add_post("/api/tenants",            self.api_tenants_create)
        app.router.add_get ("/api/tenants/{slug}",     self.api_tenant_get)
        app.router.add_patch("/api/tenants/{slug}",    self.api_tenant_update)
        app.router.add_delete("/api/tenants/{slug}",   self.api_tenant_delete)

        # ── Runtime container scan ────────────────────────────────────────────────
        app.router.add_post("/api/scan/runtime",       self.api_runtime_scan)

        # ── Importación de auditorías externas ──────────────────────────────────────
        app.router.add_post("/api/import/audit",      self.api_import_audit)
        app.router.add_get ("/api/import/formats",    self.api_import_formats)

        # ── Docker image deep scan ───────────────────────────────────────────────
        app.router.add_post("/api/scan/docker-image",   self.api_docker_image_scan)

        # ── Monitor status ───────────────────────────────────────────────────────
        app.router.add_get("/api/monitor/status",       self.api_monitor_status)

        # ── SBOM ─────────────────────────────────────────────────────────────────
        app.router.add_post("/api/sbom/generate",           self.api_sbom_generate)
        app.router.add_get ("/api/sbom/latest",             self.api_sbom_latest)

        # ── Licencias ─────────────────────────────────────────────────────────
        app.router.add_get ("/api/license",            self.api_license_info)
        app.router.add_post("/api/license/activate",   self.api_license_activate)

        # ── LDAP / AD ─────────────────────────────────────────────────────────
        app.router.add_post("/api/scan/ldap",          self.api_ldap_scan)

        # ── WebSocket push (notificaciones sin polling) ───────────────────────
        app.router.add_get("/ws/push",  self.push_websocket_handler)

        # ── 2FA / TOTP ────────────────────────────────────────────────────────
        app.router.add_post("/api/auth/2fa/setup",    self.api_2fa_setup)
        app.router.add_post("/api/auth/2fa/activate", self.api_2fa_activate)
        app.router.add_post("/api/auth/2fa/disable",  self.api_2fa_disable)
        app.router.add_get ("/api/auth/2fa/status",   self.api_2fa_status)

        # ── YARA update ───────────────────────────────────────────────────────
        app.router.add_post("/api/yara/update",        self.api_yara_update)
        app.router.add_get ("/api/yara/rules",         self.api_yara_list)

        self._app = app
        return app

    async def serve_spa(self, request: web.Request) -> web.Response:
        spa_path = Path(__file__).parent.parent / "ui" / "static" / "index.html"
        if spa_path.exists():
            html = spa_path.read_text(encoding="utf-8")
            nonce = request.get("csp_nonce", "")
            # Solo los <script> inline (no los <script src=...>) reciben el nonce.
            html = html.replace("<script>", f'<script nonce="{nonce}">')
            return web.Response(text=html, content_type="text/html")
        return web.Response(text="<h1>UI no encontrada</h1>", content_type="text/html")

    # ── WebSocket ─────────────────────────────────────────────────────────────

    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        ws_id = str(id(ws))
        user = request.get("auth_user", "anonymous")
        logger.info("WS conectado: %s user=%s", ws_id, user)

        async def send(msg: dict) -> None:
            if not ws.closed:
                try:
                    await ws.send_json(msg)
                except Exception:
                    pass

        async def log(level: str, text: str) -> None:
            await send({"type": "log", "level": level, "text": text})

        try:
            msg_raw = await asyncio.wait_for(ws.receive_json(), timeout=30)
        except (TimeoutError, Exception) as e:
            logger.error("WS receive error: %s", e)
            await ws.close()
            return ws

        try:
            msg = InputValidator.ws_message(msg_raw)
        except ValidationError as e:
            await send({"type": "error", "text": f"Input inválido: {e.field} — {e.reason}"})
            await ws.close()
            return ws

        task = msg["task"]
        audit_log.scan_started(msg.get("target", "localhost"), task, user)

        # Crear scan en BD
        scan_id = await self.db.create_scan(task, triggered_by="manual")
        self._scan_id_cache[ws_id] = scan_id

        try:
            if task == "audit":
                await self._run_local_audit(msg, ws_id, send, log, scan_id)
            elif task == "malware":
                await self._run_malware_scan(msg, ws_id, send, log, scan_id)
            elif task == "network":
                await self._run_network_scan(msg, ws_id, send, log, scan_id)
            elif task == "ssh":
                await self._run_ssh_scan(msg, ws_id, send, log, scan_id)
            elif task == "code":
                await self._run_code_audit(msg, ws_id, send, log, scan_id)
            elif task == "intel":
                await self._run_intel_scan(msg, ws_id, send, log, scan_id)
            elif task == "docker":
                await self._run_docker_scan(msg, ws_id, send, log, scan_id)
            elif task == "services":
                await self._run_services_audit(msg, ws_id, send, log, scan_id)
            elif task == "tls":
                await self._run_tls_scan(msg, ws_id, send, log, scan_id)
            elif task == "web_headers":
                await self._run_web_headers_scan(msg, ws_id, send, log, scan_id)
            elif task == "dns":
                await self._run_dns_scan(msg, ws_id, send, log, scan_id)
            elif task == "web_exposure":
                await self._run_web_exposure_scan(msg, ws_id, send, log, scan_id)
            elif task == "api_security":
                await self._run_api_security_scan(msg, ws_id, send, log, scan_id)
            elif task == "subdomain_enum":
                await self._run_subdomain_enum_scan(msg, ws_id, send, log, scan_id)
            elif task == "nuclei":
                await self._run_nuclei_scan(msg, ws_id, send, log, scan_id)
            else:
                await send({"type": "error", "text": f"Tarea desconocida: {task}"})
        except Exception as e:
            logger.error("Error en tarea WS %s: %s", task, e, exc_info=True)
            await self.db.fail_scan(scan_id)
            await send({"type": "error", "text": f"Error interno: {e}"})

        await ws.close()
        return ws

    async def _emit_findings(
        self, findings: list[Finding], ws_id: str, send, scan_id: int
    ) -> None:
        """
        Filtra supresiones, guarda en BD y hace streaming al cliente.
        Los findings se envían uno a uno según llegan — no se acumulan en memoria.
        """
        findings = await self.db.filter_suppressed(findings)
        self._findings_cache.setdefault(ws_id, []).extend(findings)

        # Guardar en BD
        await self.db.complete_scan(scan_id, findings)

        # Comparación con scan anterior
        comparison = await self.db.get_comparison(scan_id)
        new_critical = [f for f in comparison.get("new", []) if f.get("severity") == "critical"]
        if new_critical:
            await send({"type": "new_critical", "count": len(new_critical)})

        # Streaming ordenado por severidad, con yield para no bloquear el event loop
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 5)):
            await send({"type": "finding", "data": f.to_dict()})
            # Enviar al SIEM en background (no bloquea si falla)
            if any([self.cfg.siem.wazuh_enabled,
                    self.cfg.siem.elk_enabled,
                    self.cfg.siem.splunk_enabled]):
                asyncio.ensure_future(
                    self.siem.send_finding(f, self._scan_id_cache.get(ws_id, "unknown"))
                )
            await asyncio.sleep(0)  # yield al event loop entre findings

        history = await self.db.get_scan_history(limit=1)
        score = history[0]["score"] if history else None
        await send({"type": "done", "count": len(findings), "scan_id": scan_id, "score": score})

        # Notificar a clientes push si hay críticos
        critical = [f for f in findings if f.severity == "critical"]
        if critical:
            asyncio.ensure_future(self._broadcast_push("new_findings", {
                "scan_id": scan_id,
                "score":   score,
                "critical": len(critical),
                "total":   len(findings),
                "titles":  [f.title for f in critical[:3]],
            }))

        # En modo agente: enviar al manager en background
        if self.agent_reporter:
            scan_type = self._scan_id_cache.get(ws_id, "audit")
            asyncio.ensure_future(
                self.agent_reporter.report_scan(findings, str(scan_type), score)
            )

    async def _stream_findings(
        self,
        source,           # AsyncIterator[Finding] o Callable que acepta callback
        ws_id: str,
        send,
        scan_id: int,
        log,
    ) -> None:
        """
        Variante de _emit_findings para scans que producen findings de forma
        incremental (generators). Envía cada finding en cuanto llega sin esperar
        a que termine el scan completo.
        """
        collected: list[Finding] = []
        async for finding in source:
            if await self.db.is_suppressed(finding.id):
                continue
            collected.append(finding)
            self._findings_cache.setdefault(ws_id, []).append(finding)
            await send({"type": "finding", "data": finding.to_dict()})
            await asyncio.sleep(0)

        # Guardar en BD al terminar
        await self.db.complete_scan(scan_id, collected)
        comparison = await self.db.get_comparison(scan_id)
        new_critical = [f for f in comparison.get("new", []) if f.get("severity") == "critical"]
        if new_critical:
            await send({"type": "new_critical", "count": len(new_critical)})
        history = await self.db.get_scan_history(limit=1)
        score = history[0]["score"] if history else None
        await send({"type": "done", "count": len(collected), "scan_id": scan_id, "score": score})

    async def _run_local_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.hardening import HardeningAuditor
        await log("section", "Iniciando Hardening Audit local…")
        findings = await HardeningAuditor.full_audit(cfg=self.cfg)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_docker_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.docker_scan import DockerScanner
        await log("section", "Iniciando análisis de contenedores Docker + Kubernetes…")
        scan_images = params.get("scan_images_cve", True)
        scan_k8s    = params.get("scan_k8s", True)
        findings = await DockerScanner.full_scan(
            scan_images_cve=scan_images,
            scan_k8s=scan_k8s,
        )
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_services_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.services_audit import ServicesAuditor
        services = params.get("services") or None
        svc_str = ", ".join(services) if services else "nginx, apache, mysql, postgresql, redis, mongodb"
        await log("section", f"Auditando servicios: {svc_str}…")
        findings = await ServicesAuditor.full_audit(services=services)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_tls_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.tls_scan import TLSScanner
        # params.targets: lista de "host:port"; si no, usa defaults
        raw = params.get("targets") or []
        targets = None
        if raw:
            targets = []
            for t in raw:
                if ":" in str(t):
                    h, p = str(t).rsplit(":", 1)
                    targets.append((h, int(p)))
                else:
                    targets.append((str(t), 443))
        tgt_str = ", ".join(f"{h}:{p}" for h, p in (targets or TLSScanner.DEFAULT_TARGETS))
        await log("section", f"Escaneando TLS/SSL: {tgt_str}…")
        findings = await TLSScanner.full_scan(targets=targets)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_dns_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.dns_security import DNSSecurityScanner
        domains = params.get("domains") or []
        if not domains:
            await log("section", "No se indicaron dominios para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Auditando seguridad DNS: {', '.join(domains)}…")
        findings = await DNSSecurityScanner.full_scan(domains=domains)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_web_headers_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.web_headers import WebHeadersScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando cabeceras de seguridad: {', '.join(urls)}…")
        findings = await WebHeadersScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_web_exposure_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.web_exposure import WebExposureScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando exposición web: {', '.join(urls)}…")
        findings = await WebExposureScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_api_security_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.api_security import APISecurityScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando seguridad de API/CORS: {', '.join(urls)}…")
        findings = await APISecurityScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_subdomain_enum_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.subdomain_enum import SubdomainEnumScanner
        domains = params.get("domains") or []
        if not domains:
            await log("section", "No se indicaron dominios para enumerar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Enumerando subdominios (CT logs): {', '.join(domains)}…")
        findings = await SubdomainEnumScanner.full_scan(domains=domains)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_nuclei_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.nuclei_scan import NucleiScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para escanear con Nuclei")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        severities = params.get("severities") or None
        await log("section", f"Ejecutando Nuclei sobre: {', '.join(urls)}…")
        findings = await NucleiScanner.full_scan(urls=urls, severities=severities)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_malware_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.malware import MalwareScanner
        skip = params.get("skip", [])
        await log("section", f"Iniciando Malware Scan (skip: {skip or 'ninguno'})…")
        findings = await MalwareScanner.full_scan(
            cfg=self.cfg, skip_modules=skip or None,
            yara_rules=params.get("yara_rules"),
            yara_paths=params.get("yara_paths") or None,
            web_roots=params.get("web_roots") or None,
        )
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_code_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.code import CodeAuditor
        from cyberhound.scanners.secrets import SecretScanner
        path = params.get("path", "")
        if not Path(path).exists():
            await send({"type": "error", "text": f"Ruta no existe: {path}"})
            await self.db.fail_scan(scan_id)
            return
        await log("section", f"Analizando código en: {path}")
        findings = await CodeAuditor.full_analysis(Path(path))
        findings += await SecretScanner.scan(path)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_network_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.network import NetworkScanner
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
        networks = [n.strip() for n in params.get("networks", "").split(",") if n.strip()] or None
        await log("section", "Fase 1/3: Descubriendo dispositivos…")
        scanner = NetworkScanner(nmap_timeout=self.cfg.scan.nmap_timeout)
        devices = await scanner.scan_network(
            networks=networks, deep=True,
            vuln_scan=params.get("vuln_scan", False),
        )
        await send({"type": "devices", "data": [d.to_dict() for d in devices]})
        await log("ok", f"✓ {len(devices)} dispositivos encontrados")

        # Actualizar inventario
        new_ips = []
        for dev in devices:
            asset = AssetRecord(
                ip=dev.ip, mac=dev.mac, hostname=dev.hostname,
                vendor=dev.vendor, os_name=dev.os_name,
                open_ports=json.dumps([
                    {"port": p.port, "service": p.service} for p in dev.open_ports
                ]),
                risk_level=dev.risk_level,
            )
            if await self.db.upsert_asset(asset):
                new_ips.append(dev.ip)
        if new_ips:
            await send({"type": "new_assets", "ips": new_ips})
            await log("warn", f"⚠ Nuevos dispositivos: {', '.join(new_ips)}")

        if not params.get("ssh_audit"):
            await self._emit_findings([], ws_id, send, scan_id)
            return

        ssh_hosts = [d for d in devices if d.has_ssh]
        if not ssh_hosts:
            await log("info", "Sin hosts SSH en los dispositivos detectados")
            await self._emit_findings([], ws_id, send, scan_id)
            return

        await log("section", f"Fase 2/3: SSH audit en {len(ssh_hosts)} hosts…")
        creds = SSHCredentials(
            username=params.get("ssh_user", self.cfg.scan.ssh_default_user),
            port=int(params.get("ssh_port", self.cfg.scan.ssh_default_port)),
            key_path=params.get("ssh_key") or self.cfg.scan.ssh_key_path,
            password=params.get("ssh_password") or None,
        )
        results = await RemoteAuditor.scan_multiple(
            [d.ip for d in ssh_hosts], creds,
            concurrency=self.cfg.scan.ssh_concurrency,
        )
        all_findings: list[Finding] = []
        for hr in results:
            await send({"type": "host_result", "data": {
                "host": hr.host, "status": hr.status,
                "count": len(hr.findings), "error": hr.error,
                "scan_time": hr.scan_time, "os_info": hr.os_info,
            }})
            if hr.status == "ok":
                all_findings.extend(hr.findings)
                await log("ok", f"✓ {hr.host}: {len(hr.findings)} hallazgos")
            else:
                await log("warn", f"✗ {hr.host}: {hr.status} — {hr.error}")
        await log("section", "Fase 3/3: Consolidando…")
        await self._emit_findings(all_findings, ws_id, send, scan_id)

    async def _run_ssh_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
        hosts = [h.strip() for h in re.split(r"[,\s\n]+", params.get("hosts", "")) if h.strip()]
        if not hosts:
            await send({"type": "error", "text": "Sin hosts"})
            await self.db.fail_scan(scan_id)
            return
        await log("section", f"SSH Scan en {len(hosts)} hosts…")
        creds = SSHCredentials(
            username=params.get("ssh_user", self.cfg.scan.ssh_default_user),
            port=int(params.get("ssh_port", self.cfg.scan.ssh_default_port)),
            key_path=params.get("ssh_key") or self.cfg.scan.ssh_key_path,
            password=params.get("ssh_password") or None,
        )
        results = await RemoteAuditor.scan_multiple(
            hosts, creds, concurrency=self.cfg.scan.ssh_concurrency
        )
        all_findings: list[Finding] = []
        for hr in results:
            await send({"type": "host_result", "data": hr.to_dict()})
            if hr.status == "ok":
                all_findings.extend(hr.findings)
                await log("ok", f"✓ {hr.host}: {len(hr.findings)} hallazgos")
            else:
                level = "warn" if hr.status == "unreachable" else "error"
                await log(level, f"✗ {hr.host}: {hr.status} — {hr.error}")
        await self._emit_findings(all_findings, ws_id, send, scan_id)

    async def _run_intel_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.intel import IntelScanner
        target = params.get("target", "")
        modules = params.get("modules", ["shodan", "virustotal", "abuseipdb"])
        await log("section", f"Intel scan: {target}")
        scanner = IntelScanner(self.cfg.api_keys)
        results = await scanner.scan(target, modules)
        for item in results:
            await send({"type": "intel", "data": item.to_dict()})
            await log("ok", f"✓ {item.source}: datos obtenidos")
        await self.db.complete_scan(scan_id, [])
        await send({"type": "done", "count": len(results), "scan_id": scan_id})

    # ── Fix local ─────────────────────────────────────────────────────────────

    async def api_fix_local(self, request: web.Request) -> web.Response:
        try:
            body  = await _read_json(request)
            fid   = body.get("finding_id")
            dry   = body.get("dry_run", False)
            user  = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"})
            from cyberhound.scanners.hardening import HardeningFixer
            fixer = HardeningFixer(dry_run=dry)
            ok, msg = await fixer.fix(finding)
            audit_log.fix_applied(fid, user, "localhost", dry)
            # Marcar como corregido en BD si tenemos el scan_id
            if ok and not dry:
                # Registrar en el journal de rollback para poder deshacer el fix.
                if fixer.rollback_actions:
                    from cyberhound.core.rollback import RollbackEntry
                    self._rollback_journal().append(RollbackEntry(
                        finding_id=fid, host="localhost", user=user, ts=time.time(),
                        fix_message=msg or finding.remediation,
                        actions=fixer.rollback_actions,
                    ))
                for ws_id, findings in self._findings_cache.items():
                    if any(f.id == fid for f in findings):
                        scan_id = self._scan_id_cache.get(ws_id)
                        if scan_id:
                            await self.db.mark_finding_fixed(scan_id, fid, user)
                        break
            return web.json_response(
                {"ok": ok, "message": msg, "reversible": bool(fixer.rollback_actions) and not dry}
            )
        except Exception as e:
            logger.error("api_fix_local: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_fix_remote(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            fid  = body.get("finding_id")
            host = body.get("host", "")
            user = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"})
            from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
            creds = SSHCredentials(
                username=body.get("ssh_user", self.cfg.scan.ssh_default_user),
                port=int(body.get("ssh_port", self.cfg.scan.ssh_default_port)),
                key_path=body.get("ssh_key") or self.cfg.scan.ssh_key_path,
                password=body.get("ssh_password") or None,
            )
            ok, msg = await RemoteAuditor(creds).apply_fix_remote(host, finding.remediation)
            audit_log.fix_applied(fid, user, host, False)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_fix_remote: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Rollback de fixes locales ───────────────────────────────────────────────

    def _rollback_journal(self):
        from cyberhound.core.rollback import RollbackJournal
        return RollbackJournal(Path(self.cfg.server.log_dir) / "rollback-journal.jsonl")

    async def api_rollback_list(self, request: web.Request) -> web.Response:
        """Lista los fixes locales que aún se pueden deshacer."""
        try:
            entries = self._rollback_journal().list_active()
            return web.json_response({"ok": True, "entries": [
                {"finding_id": e.finding_id, "host": e.host, "user": e.user,
                 "ts": e.ts, "reversible": e.reversible, "fix_message": e.fix_message}
                for e in sorted(entries, key=lambda e: e.ts, reverse=True)
            ]})
        except Exception as e:
            logger.error("api_rollback_list: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_rollback_local(self, request: web.Request) -> web.Response:
        """Revierte el último fix local aplicado a un finding."""
        try:
            body = await _read_json(request)
            fid  = body.get("finding_id")
            user = request.get("auth_user", "unknown")
            if not fid:
                return web.json_response({"ok": False, "error": "finding_id requerido"}, status=400)
            from cyberhound.core.rollback import rollback_finding
            ok, msg = await rollback_finding(self._rollback_journal(), fid, host="localhost")
            audit_log.fix_rolled_back(fid, user, "localhost", ok)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_rollback_local: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Observabilidad ─────────────────────────────────────────────────────────

    async def api_metrics(self, request: web.Request) -> web.Response:
        """Métricas en formato Prometheus (texto). Ruta pública (PUBLIC_ROUTES)."""
        return web.Response(text=METRICS.render(), content_type="text/plain")

    # ── Explicación de hallazgos (LLM local) ───────────────────────────────────

    async def api_explain_finding(self, request: web.Request) -> web.Response:
        """Explica un hallazgo en lenguaje llano con el LLM local (best-effort)."""
        try:
            body = await _read_json(request)
            finding = self._find_cached(body.get("finding_id"))
            if not finding:
                return web.json_response({"error": "Finding no encontrado"}, status=404)
            from cyberhound.core.llm import explain_finding
            explanation = await explain_finding(finding.to_dict())
            if explanation is None:
                return web.json_response(
                    {"explanation": None, "detail": "El asistente LLM no está disponible ahora."}
                )
            return web.json_response({"explanation": explanation})
        except Exception as e:  # noqa: BLE001
            logger.error("api_explain_finding: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Histórico ─────────────────────────────────────────────────────────────

    async def api_history(self, request: web.Request) -> web.Response:
        scan_type = request.rel_url.query.get("type")
        limit = int(request.rel_url.query.get("limit", 50))
        history = await self.db.get_scan_history(scan_type, limit)
        return web.json_response(history)

    async def api_history_detail(self, request: web.Request) -> web.Response:
        try:
            scan_id = int(request.match_info["scan_id"])
            findings = await self.db.get_scan_findings(scan_id)
            return web.json_response(findings)
        except ValueError:
            return web.json_response({"error": "scan_id inválido"}, status=400)

    async def api_compare(self, request: web.Request) -> web.Response:
        try:
            scan_id = int(request.match_info["scan_id"])
            comparison = await self.db.get_comparison(scan_id)
            return web.json_response(comparison)
        except ValueError:
            return web.json_response({"error": "scan_id inválido"}, status=400)

    async def api_score_trend(self, request: web.Request) -> web.Response:
        scan_type = request.rel_url.query.get("type", "audit")
        days = int(request.rel_url.query.get("days", 30))
        trend = await self.db.get_score_trend(scan_type, days)
        return web.json_response(trend)

    async def api_score_detail(self, request: web.Request) -> web.Response:
        """Devuelve el score detallado con desglose contextual del último audit."""
        try:
            scan_id_str = request.rel_url.query.get("scan_id")
            if scan_id_str:
                scan_id = int(scan_id_str)
            else:
                history = await self.db.get_scan_history("audit", limit=1)
                if not history:
                    return web.json_response({"error": "Sin scans"}, status=404)
                scan_id = history[0]["id"]

            findings_raw = await self.db.get_scan_findings(scan_id)
            from cyberhound.core.models import Finding
            from cyberhound.core.scoring import compute_score
            findings = [Finding(
                id=f["finding_id"], category=f["category"], severity=f["severity"],
                title=f["title"], description=f.get("description", ""),
                remediation=f.get("remediation", ""),
                auto_fix=bool(f.get("auto_fix")),
            ) for f in findings_raw]
            result = compute_score(findings)
            return web.json_response(result.to_dict())
        except Exception as e:
            logger.error("api_score_detail: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_dashboard(self, request: web.Request) -> web.Response:
        stats = await self.db.get_dashboard_stats()
        return web.json_response(stats)

    # ── Inventario ────────────────────────────────────────────────────────────

    async def api_assets(self, request: web.Request) -> web.Response:
        assets = await self.db.get_assets()
        return web.json_response(assets)

    async def api_asset_authorize(self, request: web.Request) -> web.Response:
        try:
            ip = request.match_info["ip"]
            body = await _read_json(request)
            authorized = bool(body.get("authorized", True))
            notes = str(body.get("notes", ""))[:500]
            await self.db.set_asset_authorized(ip, authorized, notes)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_discover(self, request: web.Request) -> web.Response:
        try:
            networks_raw = request.rel_url.query.get("networks", "")
            networks = [n.strip() for n in networks_raw.split(",") if n.strip()] or None
            from cyberhound.scanners.network import NetworkScanner
            ips = await NetworkScanner().discover_hosts(networks=networks)
            return web.json_response({"hosts": ips})
        except Exception as e:
            logger.error("api_discover: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Supresiones ───────────────────────────────────────────────────────────

    async def api_suppressions_list(self, request: web.Request) -> web.Response:
        return web.json_response(await self.db.get_suppressions())

    async def api_suppressions_add(self, request: web.Request) -> web.Response:
        try:
            body    = await _read_json(request)
            pattern = str(body.get("pattern", "")).strip()[:200]
            reason  = str(body.get("reason", "")).strip()[:500]
            expires = body.get("expires_at")
            user    = request.get("auth_user", "unknown")
            if not pattern or not reason:
                return web.json_response({"error": "pattern y reason son obligatorios"}, status=400)
            await self.db.add_suppression(pattern, reason, user, expires)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_suppressions_delete(self, request: web.Request) -> web.Response:
        from urllib.parse import unquote
        pattern = unquote(request.match_info["pattern"])
        await self.db.remove_suppression(pattern)
        return web.json_response({"ok": True})

    # ── Usuarios ──────────────────────────────────────────────────────────────

    async def api_users_list(self, request: web.Request) -> web.Response:
        users = await self.db.list_users()
        return web.json_response(users)

    async def api_users_create(self, request: web.Request) -> web.Response:
        try:
            body     = await _read_json(request)
            username = str(body.get("username", "")).strip()[:32]
            password = str(body.get("password", ""))
            role     = str(body.get("role", "viewer"))
            if not username or not password:
                return web.json_response({"error": "username y password son obligatorios"}, status=400)
            if role not in ("admin", "operator", "viewer"):
                return web.json_response({"error": "Rol inválido"}, status=400)
            if len(password) < 8:
                return web.json_response({"error": "Contraseña mínimo 8 caracteres"}, status=400)
            if not re.match(r'^[a-zA-Z0-9_\-]{1,32}$', username):
                return web.json_response({"error": "Username inválido"}, status=400)
            pw_hash = passwords.hash_password(password)
            await self.db.create_user(UserRecord(
                username=username, password_hash=pw_hash, role=role
            ))
            logger.info("Usuario '%s' creado con rol '%s' por %s",
                        username, role, request.get("auth_user"))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_update(self, request: web.Request) -> web.Response:
        try:
            username = request.match_info["username"]
            body = await _read_json(request)
            updates = {}
            if "role" in body:
                if body["role"] not in ("admin", "operator", "viewer"):
                    return web.json_response({"error": "Rol inválido"}, status=400)
                updates["role"] = body["role"]
            if "password" in body:
                if len(body["password"]) < 8:
                    return web.json_response({"error": "Contraseña mínimo 8 caracteres"}, status=400)
                updates["password_hash"] = passwords.hash_password(body["password"])
            if "active" in body:
                updates["active"] = int(bool(body["active"]))
            if updates:
                await self.db.update_user(username, **updates)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_delete(self, request: web.Request) -> web.Response:
        username = request.match_info["username"]
        current  = request.get("auth_user", "")
        if username == current:
            return web.json_response({"error": "No puedes eliminar tu propio usuario"}, status=400)
        await self.db.update_user(username, active=0)
        return web.json_response({"ok": True})

    # ── Scheduler ─────────────────────────────────────────────────────────────

    async def api_scheduler_list(self, request: web.Request) -> web.Response:
        if not self.scheduler:
            return web.json_response([])
        return web.json_response(self.scheduler.list_entries())

    async def api_scheduler_run(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if not self.scheduler:
            return web.json_response({"error": "Scheduler no activo"}, status=503)
        ok = await self.scheduler.run_now(name)
        return web.json_response({"ok": ok, "error": "Tarea no encontrada" if not ok else None})

    async def api_scheduler_toggle(self, request: web.Request) -> web.Response:
        try:
            name = request.match_info["name"]
            body = await _read_json(request)
            enabled = bool(body.get("enabled", True))
            if not self.scheduler:
                return web.json_response({"error": "Scheduler no activo"}, status=503)
            ok = self.scheduler.enable(name, enabled)
            return web.json_response({"ok": ok})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Configuración ─────────────────────────────────────────────────────────

    async def api_get_keys(self, request: web.Request) -> web.Response:
        keys = {
            k: (v[:4] + "***" if v else None)
            for k, v in self.cfg.api_keys.__dict__.items()
        }
        return web.json_response(keys)

    async def api_save_keys(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            for attr in ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"):
                v = body.get(attr, "")
                if v and not v.endswith("***"):
                    setattr(self.cfg.api_keys, attr, v)
            self.cfg.save()
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_get_notifications_cfg(self, request: web.Request) -> web.Response:
        n = self.cfg.notifications
        return web.json_response({
            "email_enabled":   n.email_enabled,
            "smtp_host":       n.smtp_host,
            "smtp_port":       n.smtp_port,
            "smtp_user":       n.smtp_user,
            "email_from":      n.email_from,
            "email_to":        n.email_to,
            "webhook_enabled": n.webhook_enabled,
            "webhook_url":     n.webhook_url,
            "min_level":       n.min_level,
            # contraseña SMTP nunca se devuelve
        })

    async def api_save_notifications_cfg(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            n = self.cfg.notifications
            for field in ("email_enabled","smtp_host","smtp_port","smtp_user",
                          "email_from","email_to","webhook_enabled","webhook_url","min_level"):
                if field in body:
                    setattr(n, field, body[field])
            if "smtp_password" in body and body["smtp_password"]:
                n.smtp_password = body["smtp_password"]
            self.cfg.save()
            # Actualizar el notification manager en caliente
            self.notification_manager.cfg.email_enabled   = n.email_enabled
            self.notification_manager.cfg.webhook_enabled = n.webhook_enabled
            self.notification_manager.cfg.webhook_url     = n.webhook_url
            self.notification_manager.cfg.email_to        = n.email_to
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_test_notifications(self, request: web.Request) -> web.Response:
        results = await self.notification_manager.test()
        return web.json_response(results)

    async def api_get_siem(self, request: web.Request) -> web.Response:
        s = self.cfg.siem
        return web.json_response({
            "wazuh_enabled": s.wazuh_enabled,
            "wazuh_host":    s.wazuh_host,
            "wazuh_port":    s.wazuh_port,
            "wazuh_api_url": s.wazuh_api_url,
            "elk_enabled":   s.elk_enabled,
            "elk_url":       s.elk_url,
            "elk_index":     s.elk_index,
            "splunk_enabled":   s.splunk_enabled,
            "splunk_hec_url":   s.splunk_hec_url,
            "splunk_index":     s.splunk_index,
            "min_severity":     s.min_severity,
            # Tokens/passwords nunca se devuelven
        })

    async def api_save_siem(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            s = self.cfg.siem
            for field in ("wazuh_enabled", "wazuh_host", "wazuh_port", "wazuh_api_url",
                          "wazuh_api_user", "elk_enabled", "elk_url", "elk_index",
                          "elk_user", "elk_api_key", "splunk_enabled", "splunk_hec_url",
                          "splunk_index", "min_severity"):
                if field in body:
                    setattr(s, field, body[field])
            # Passwords solo si no están vacíos
            for env_field, cfg_field in [
                ("wazuh_api_pass", "wazuh_api_pass"),
                ("elk_pass", "elk_pass"),
                ("splunk_hec_token", "splunk_hec_token"),
            ]:
                if body.get(env_field):
                    setattr(s, cfg_field, body[env_field])
            self.cfg.save()
            # Reinicializar SIEM en caliente
            from cyberhound.core.siem import SIEMConfig, SIEMIntegration
            self.siem = SIEMIntegration(SIEMConfig(
                wazuh_enabled=s.wazuh_enabled, wazuh_host=s.wazuh_host,
                wazuh_port=s.wazuh_port, elk_enabled=s.elk_enabled,
                elk_url=s.elk_url, elk_api_key=s.elk_api_key,
                splunk_enabled=s.splunk_enabled, splunk_hec_url=s.splunk_hec_url,
                splunk_hec_token=s.splunk_hec_token, min_severity=s.min_severity,
            ))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_test_siem(self, request: web.Request) -> web.Response:
        results = await self.siem.test()
        return web.json_response(results)

    # ── WebSocket push — notificaciones sin polling ───────────────────────────

    async def push_websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """
        WebSocket de solo lectura para recibir notificaciones en tiempo real.
        El cliente se conecta una vez y recibe eventos conforme ocurren,
        sin necesidad de polling periódico.
        """
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._push_clients.add(ws)
        logger.info("Push WS conectado: %d clientes activos", len(self._push_clients))
        try:
            # Enviar estado inicial al conectar
            stats = await self.db.get_dashboard_stats()
            await ws.send_json({"type": "initial", "data": stats})
            # Mantener conexión abierta esperando mensajes del cliente (ping/pong)
            async for msg in ws:
                if msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        finally:
            self._push_clients.discard(ws)
        return ws

    async def _broadcast_push(self, event_type: str, data: dict) -> None:
        """Envía un evento a todos los clientes push conectados."""
        if not self._push_clients:
            return
        message = {"type": event_type, "data": data, "ts": asyncio.get_event_loop().time()}
        dead = set()
        for ws in self._push_clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        self._push_clients -= dead

    # ── OpenAPI / Swagger ─────────────────────────────────────────────────────

    async def api_openapi_spec(self, request: web.Request) -> web.Response:
        from cyberhound.core.openapi import build_openapi_spec
        scheme = "https" if request.secure else "http"
        server_url = f"{scheme}://{request.host}"
        return web.json_response(build_openapi_spec(server_url))

    async def api_swagger_ui(self, request: web.Request) -> web.Response:
        from cyberhound.core.openapi import SWAGGER_UI_HTML
        nonce = request.get("csp_nonce", "")
        html = SWAGGER_UI_HTML.replace("<script>", f'<script nonce="{nonce}">')
        return web.Response(text=html, content_type="text/html")

    # ── Ansible AWX/Tower ─────────────────────────────────────────────────────

    async def api_ansible_run(self, request: web.Request) -> web.Response:
        try:
            body     = await _read_json(request)
            scan_id  = body.get("scan_id")
            target   = body.get("target", "localhost")
            mode     = body.get("mode", "local")  # local | awx

            # Cargar findings del scan
            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
                from cyberhound.core.models import Finding as F
                findings = [F(
                    id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    description=f.get("description",""), remediation=f.get("remediation",""),
                    auto_fix=bool(f.get("auto_fix")),
                ) for f in findings_raw]
            else:
                findings = []

            from cyberhound.core.ansible_integration import generate_playbook, run_playbook_local
            playbook = generate_playbook(findings, target)
            if not playbook:
                return web.json_response({"error": "Sin hallazgos con corrección automática"}, status=400)

            if mode == "local":
                job = await run_playbook_local(playbook, target)
            else:
                # AWX mode
                awx_cfg = getattr(self.cfg, 'awx', None)
                if not awx_cfg or not getattr(awx_cfg, 'enabled', False):
                    return web.json_response({"error": "AWX no configurado"}, status=400)
                from cyberhound.core.ansible_integration import AWXClient, AWXConfig
                client = AWXClient(AWXConfig(
                    url=awx_cfg.url, token=awx_cfg.token,
                    org_id=getattr(awx_cfg,'org_id',1),
                ))
                template_id = body.get("template_id", 1)
                job = await client.launch_job_template(int(template_id))

            self._ansible_jobs.insert(0, {
                "job_id": job.job_id, "status": job.status,
                "target": target, "mode": mode,
                "started_at": job.started_at,
                "output_preview": job.output[:500] if job.output else "",
            })
            return web.json_response({
                "job_id":  job.job_id,
                "status":  job.status,
                "output":  job.output[-3000:] if job.output else "",
                "playbook": playbook[:2000],
            })
        except Exception as e:
            logger.error("api_ansible_run: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_ansible_jobs(self, request: web.Request) -> web.Response:
        return web.json_response(self._ansible_jobs[:20])

    async def api_ansible_templates(self, request: web.Request) -> web.Response:
        awx_cfg = getattr(self.cfg, 'awx', None)
        if not awx_cfg or not getattr(awx_cfg, 'enabled', False):
            return web.json_response({"error": "AWX no configurado"}, status=400)
        from cyberhound.core.ansible_integration import AWXClient, AWXConfig
        client = AWXClient(AWXConfig(url=awx_cfg.url, token=awx_cfg.token))
        templates = await client.list_job_templates()
        return web.json_response(templates)

    # ── Multi-tenant ──────────────────────────────────────────────────────────

    def _get_tenant_store(self):
        if not self._tenant_store:
            from cyberhound.core.multitenancy import TenantStore
            self._tenant_store = TenantStore()
        return self._tenant_store

    async def api_tenants_list(self, request: web.Request) -> web.Response:
        store = self._get_tenant_store()
        return web.json_response([t.to_dict() for t in store.list()])

    async def api_tenants_create(self, request: web.Request) -> web.Response:
        try:
            body   = await _read_json(request)
            store  = self._get_tenant_store()
            tenant = store.create(
                slug=body.get("slug",""),
                name=body.get("name",""),
                admin_email=body.get("admin_email",""),
                plan=body.get("plan","starter"),
            )
            logger.info("Tenant creado por %s: %s", request.get("auth_user"), tenant.slug)
            return web.json_response(tenant.to_dict(include_key=True), status=201)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_tenant_get(self, request: web.Request) -> web.Response:
        slug   = request.match_info["slug"]
        store  = self._get_tenant_store()
        tenant = store.get(slug)
        if not tenant:
            return web.json_response({"error": f"Tenant '{slug}' no encontrado"}, status=404)
        return web.json_response(tenant.to_dict())

    async def api_tenant_update(self, request: web.Request) -> web.Response:
        slug  = request.match_info["slug"]
        store = self._get_tenant_store()
        body  = await _read_json(request)
        t     = store.update(slug, **body)
        if not t:
            return web.json_response({"error": "No encontrado"}, status=404)
        return web.json_response(t.to_dict())

    async def api_tenant_delete(self, request: web.Request) -> web.Response:
        slug  = request.match_info["slug"]
        store = self._get_tenant_store()
        ok    = store.delete(slug)
        return web.json_response({"ok": ok})

    # ── Runtime container scan ────────────────────────────────────────────────

    async def api_runtime_scan(self, request: web.Request) -> web.Response:
        try:
            body       = await _read_json(request)
            containers = body.get("containers") or None
            from cyberhound.scanners.runtime_scan import RuntimeScanner
            scan_id  = await self.db.create_scan("runtime", triggered_by="manual")
            findings = await RuntimeScanner.full_scan(containers=containers)
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_runtime_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Importación de auditorías externas ───────────────────────────────────

    async def api_import_formats(self, request: web.Request) -> web.Response:
        """GET /api/import/formats — formatos soportados y sus descripciones."""
        return web.json_response({
            "formats": [
                {
                    "id":          "nessus",
                    "name":        "Tenable Nessus (.nessus)",
                    "description": "Exportación XML de Tenable Nessus, Tenable.io o Tenable.sc",
                    "extensions":  [".nessus", ".xml"],
                    "type":        "vulnerability",
                },
                {
                    "id":          "xccdf",
                    "name":        "OpenSCAP / XCCDF (.xml)",
                    "description": "Resultados XCCDF de oscap, Red Hat Satellite, Ansible Security. "
                                   "Compatible con perfiles CIS y STIG para RHEL 7/8/9.",
                    "extensions":  [".xml"],
                    "type":        "compliance",
                },
                {
                    "id":          "csv",
                    "name":        "CSV genérico",
                    "description": "Exportaciones CSV de Tenable, Qualys, OpenVAS o cualquier herramienta.",
                    "extensions":  [".csv"],
                    "type":        "vulnerability",
                },
                {
                    "id":          "json",
                    "name":        "JSON (CyberHound o genérico)",
                    "description": "Formato JSON propio de CyberHound o lista de findings.",
                    "extensions":  [".json"],
                    "type":        "generic",
                },
            ],
            "note": "CyberHound distingue entre hallazgos de CUMPLIMIENTO (compliance/*, "
                    "procedentes de XCCDF/CIS/STIG) y VULNERABILIDADES (vulnerability/*, "
                    "procedentes de Nessus/CVE). Ambos tipos se pueden ver por separado en la UI.",
        })

    async def api_import_audit(self, request: web.Request) -> web.Response:
        """
        POST /api/import/audit — importa un fichero de auditoría externo.

        Acepta multipart/form-data con:
          - file: el fichero de auditoría
          - format: (opcional) forzar formato ("nessus", "xccdf", "csv", "json")
          - scan_type: (opcional) tipo de scan a crear (default: "imported")
          - target: (opcional) objetivo/host del scan
        """
        try:
            reader = await request.multipart()
            content = b""
            filename = ""
            fmt = None
            scan_type = "imported"
            target = "imported"

            async for part in reader:
                if part.name == "file":
                    filename = part.filename or "upload"
                    content = await part.read(decode=True)
                elif part.name == "format":
                    fmt = (await part.read(decode=True)).decode().strip()
                elif part.name == "scan_type":
                    scan_type = (await part.read(decode=True)).decode().strip()
                elif part.name == "target":
                    target = (await part.read(decode=True)).decode().strip()

            if not content:
                return web.json_response(
                    {"error": "No se recibió ningún fichero. Envía 'file' como campo multipart."},
                    status=400,
                )

            from cyberhound.scanners.audit_import import import_audit_file
            result = import_audit_file(content, filename, fmt or None)

            if result.errors and not result.findings:
                return web.json_response(
                    {"error": result.errors[0], "all_errors": result.errors},
                    status=400,
                )

            # Guardar en la BD como un scan de tipo "imported" / "xccdf" / "nessus"
            actual_scan_type = result.source if result.source != "unknown" else scan_type
            scan_id = await self.db.create_scan(
                actual_scan_type, target=target or filename,
                triggered_by="import",
            )
            filtered = await self.db.filter_suppressed(result.findings)
            await self.db.complete_scan(scan_id, filtered)

            logger.info(
                "Auditoría importada: %s → scan_id=%d, %d findings (%d skipped)",
                filename, scan_id, result.imported, result.skipped,
            )

            return web.json_response({
                "scan_id":   scan_id,
                "source":    result.source,
                "filename":  filename,
                "imported":  result.imported,
                "skipped":   result.skipped,
                "total":     result.total,
                "errors":    result.errors,
                "metadata":  result.metadata,
                "findings":  [f.to_dict() for f in filtered[:50]],  # preview
                "note": (
                    "Los hallazgos de tipo 'compliance/*' son checks de bastionado/cumplimiento. "
                    "Los de 'vulnerability/*' son vulnerabilidades CVE/CVSSv3."
                ),
            })

        except Exception as e:
            logger.error("api_import_audit: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Docker image deep scan ────────────────────────────────────────────────

    async def api_docker_image_scan(self, request: web.Request) -> web.Response:
        """Análisis profundo del filesystem de imágenes Docker."""
        try:
            body      = await _read_json(request)
            images    = body.get("images") or None
            deep      = body.get("deep", True)
            max_imgs  = min(int(body.get("max_images", 5)), 10)
            max_mb    = int(body.get("max_size_mb", 200))
            user      = request.get("auth_user", "unknown")

            from cyberhound.scanners.docker_image_scan import DockerImageScanner
            scan_id  = await self.db.create_scan("docker_image", triggered_by=user)
            findings = await DockerImageScanner.scan_images(
                images=images, max_images=max_imgs,
                deep_scan=deep, max_size_mb=max_mb,
            )
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_docker_image_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Monitor status ────────────────────────────────────────────────────────

    async def api_monitor_status(self, request: web.Request) -> web.Response:
        """Estado del monitor eBPF/auditd en tiempo real."""
        monitor = self._ebpf_monitor
        if not monitor:
            return web.json_response({
                "active": False, "mode": "none",
                "message": "Monitor no iniciado",
            })
        return web.json_response({
            "active":  self._ebpf_monitor.mode != "none",
            "mode":    self._ebpf_monitor.mode,
            "message": f"Monitor activo en modo {self._ebpf_monitor.mode}",
        })

    # ── PDF Report ────────────────────────────────────────────────────────────

    async def api_report_pdf(self, request: web.Request) -> web.Response:
        """Genera un informe PDF del último scan o de los findings proporcionados."""
        try:
            body       = await _read_json(request)
            scan_id    = body.get("scan_id")
            scan_type  = body.get("scan_type", "audit")
            target     = body.get("target", "localhost")

            # Cargar findings
            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
                findings = [Finding(
                    id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    description=f.get("description",""), remediation=f.get("remediation",""),
                    auto_fix=bool(f.get("auto_fix")),
                ) for f in findings_raw]
                # Obtener score del scan
                history = await self.db.get_scan_history(limit=1)
                score = next((h["score"] for h in history if h["id"] == int(scan_id)), None)
            else:
                findings_raw = body.get("findings", [])
                findings = [Finding.from_dict(f) for f in findings_raw]
                score = body.get("score")

            from cyberhound.core.licensing import license_manager
            from cyberhound.scanners.pdf_report import generate_pdf
            lic = license_manager.get()

            pdf_bytes = generate_pdf(
                findings, target=target, scan_type=scan_type,
                score=score, licensee=lic.licensee,
            )

            # Determinar tipo de contenido
            content_type = "application/pdf" if pdf_bytes[:4] == b"%PDF" else "text/html"
            ext = "pdf" if content_type == "application/pdf" else "html"
            filename = f"cyberhound-report-{scan_type}-{datetime.now().strftime('%Y%m%d')}.{ext}"

            return web.Response(
                body=pdf_bytes,
                content_type=content_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )
        except Exception as e:
            logger.error("api_report_pdf: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Compliance ────────────────────────────────────────────────────────────

    async def api_compliance(self, request: web.Request) -> web.Response:
        """Analiza compliance a partir de los findings del último scan o scan_id."""
        try:
            body       = await _read_json(request)
            scan_id    = body.get("scan_id")
            frameworks = body.get("frameworks") or None

            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
            else:
                history = await self.db.get_scan_history("audit", limit=1)
                if not history:
                    return web.json_response({"error": "Sin scans disponibles"}, status=404)
                findings_raw = await self.db.get_scan_findings(history[0]["id"])

            findings = [Finding(
                id=f["finding_id"], category=f["category"],
                severity=f["severity"], title=f["title"],
                description=f.get("description",""), remediation=f.get("remediation",""),
            ) for f in findings_raw]

            from cyberhound.scanners.compliance import analyze_compliance, compliance_to_dict
            results = analyze_compliance(findings, frameworks=frameworks)
            return web.json_response(compliance_to_dict(results))
        except Exception as e:
            logger.error("api_compliance: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_compliance_get(self, request: web.Request) -> web.Response:
        """GET /api/compliance — compliance del último audit automáticamente."""
        frameworks_param = request.rel_url.query.get("frameworks", "")
        frameworks = frameworks_param.split(",") if frameworks_param else None
        history = await self.db.get_scan_history("audit", limit=1)
        if not history:
            return web.json_response({})
        findings_raw = await self.db.get_scan_findings(history[0]["id"])
        findings = [Finding(
            id=f["finding_id"], category=f["category"],
            severity=f["severity"], title=f["title"],
            description=f.get("description",""), remediation=f.get("remediation",""),
        ) for f in findings_raw]
        from cyberhound.scanners.compliance import analyze_compliance, compliance_to_dict
        results = analyze_compliance(findings, frameworks=frameworks)
        return web.json_response(compliance_to_dict(results))

    # ── Cuarentena ────────────────────────────────────────────────────────────

    async def api_quarantine_list(self, request: web.Request) -> web.Response:
        from cyberhound.core.quarantine import list_quarantine
        return web.json_response(list_quarantine())

    async def api_quarantine_stats(self, request: web.Request) -> web.Response:
        from cyberhound.core.quarantine import quarantine_stats
        return web.json_response(quarantine_stats())

    async def api_quarantine_add(self, request: web.Request) -> web.Response:
        try:
            body       = await _read_json(request)
            filepath   = str(body.get("filepath", "")).strip()
            finding_id = str(body.get("finding_id", ""))
            title      = str(body.get("title", ""))
            user       = request.get("auth_user", "unknown")
            if not filepath:
                return web.json_response({"ok": False, "error": "filepath requerido"}, status=400)
            from cyberhound.core.quarantine import quarantine_file
            ok, msg = quarantine_file(filepath, finding_id, title, quarantined_by=user)
            logger.info("Cuarentena [%s]: %s → %s", user, filepath, "OK" if ok else msg)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_quarantine_restore(self, request: web.Request) -> web.Response:
        try:
            name = request.match_info["name"]
            body = await _read_json(request)
            restore_path = body.get("path") or None
            from cyberhound.core.quarantine import restore_file
            ok, msg = restore_file(name, restore_path)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_quarantine_delete(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        from cyberhound.core.quarantine import delete_quarantined
        ok, msg = delete_quarantined(name)
        return web.json_response({"ok": ok, "message": msg})

    # ── SBOM ──────────────────────────────────────────────────────────────────

    async def api_sbom_generate(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            include   = body.get("include") or None
            pip_venvs = body.get("pip_venvs") or None
            from cyberhound.scanners.sbom import SBOMGenerator
            sbom = await SBOMGenerator.generate(include=include, pip_venvs=pip_venvs)
            fmt  = body.get("format", "json")   # json | cyclonedx | spdx

            if fmt == "cyclonedx":
                return web.json_response(sbom.to_cyclonedx())
            elif fmt == "spdx":
                return web.Response(text=sbom.to_spdx_basic(), content_type="text/plain",
                    headers={"Content-Disposition": "attachment; filename=sbom.spdx"})
            else:
                data = sbom.to_dict()
                self._sbom_cache = data
                return web.json_response(data)
        except Exception as e:
            logger.error("api_sbom_generate: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_sbom_latest(self, request: web.Request) -> web.Response:
        if self._sbom_cache:
            return web.json_response(self._sbom_cache)
        return web.json_response({"error": "Sin SBOM generado — ejecuta /api/sbom/generate"}, status=404)

    # ── Licencias ─────────────────────────────────────────────────────────────

    async def api_license_info(self, request: web.Request) -> web.Response:
        return web.json_response(license_manager.get().to_dict())

    async def api_license_activate(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            key  = str(body.get("key", "")).strip()
            if not key:
                return web.json_response({"ok": False, "error": "Clave vacía"}, status=400)
            ok, msg = license_manager.activate(key)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── LDAP / AD ─────────────────────────────────────────────────────────────

    async def api_ldap_scan(self, request: web.Request) -> web.Response:
        """Ejecuta un audit de LDAP/AD y devuelve los hallazgos."""
        try:
            body   = await _read_json(request)
            user   = request.get("auth_user", "unknown")
            from cyberhound.scanners.ldap_audit import LDAPAuditor
            scan_id = await self.db.create_scan("ldap", triggered_by=user)
            findings = await LDAPAuditor.full_audit(
                uri=body.get("uri", ""),
                base=body.get("base", ""),
                binddn=body.get("binddn", ""),
                bindpw=body.get("bindpw", ""),
            )
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_ldap_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Modo agente ───────────────────────────────────────────────────────────

    async def api_get_agent_cfg(self, request: web.Request) -> web.Response:
        a = self.cfg.agent
        return web.json_response({
            "mode":        a.mode,
            "manager_url": a.manager_url,
            "agent_name":  a.agent_name,
            "has_key":     bool(a.agent_key),   # la clave nunca se devuelve
        })

    async def api_save_agent_cfg(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            a = self.cfg.agent
            mode = body.get("mode")
            if mode in ("standalone", "manager", "agent"):
                a.mode = mode
            for field in ("manager_url", "agent_name"):
                if field in body:
                    setattr(a, field, str(body[field] or ""))
            if body.get("agent_key"):            # solo si no está vacío
                a.agent_key = str(body["agent_key"])
            self.cfg.save()
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def api_agent_report(self, request: web.Request) -> web.Response:
        """Recibe hallazgos enviados por un agente remoto."""
        # Verificar clave del agente (no JWT)
        auth  = request.headers.get("Authorization", "")
        key   = self.agent_manager.extract_agent_key(auth)
        if not self.agent_manager.verify_agent_key(key):
            return web.json_response({"error": "Clave de agente inválida"}, status=401)
        try:
            payload = await _read_json(request)
            result  = await self.agent_manager.receive_report(payload)
            return web.json_response(result)
        except Exception as e:
            logger.error("api_agent_report: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_agent_heartbeat(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        key  = self.agent_manager.extract_agent_key(auth)
        if not self.agent_manager.verify_agent_key(key):
            return web.json_response({"error": "Clave inválida"}, status=401)
        payload = await _read_json(request)
        await self.agent_manager.receive_heartbeat(payload)
        return web.json_response({"ok": True})

    async def api_agent_list(self, request: web.Request) -> web.Response:
        return web.json_response(self.agent_manager.list_agents())

    # ── 2FA / TOTP ────────────────────────────────────────────────────────────

    async def api_2fa_setup(self, request: web.Request) -> web.Response:
        """Inicia la configuración de 2FA — devuelve QR y secreto."""
        user = request.get("auth_user", "")
        if not user:
            return web.json_response({"error": "Sin sesión"}, status=401)
        from cyberhound.core.totp import TOTPManager
        mgr = TOTPManager(self.db)
        data = await mgr.setup_2fa(user)
        return web.json_response({
            "secret":         data["secret"],
            "uri":            data["uri"],
            "qr_svg":         data["qr_svg"],
            "recovery_codes": data["recovery_codes"],
        })

    async def api_2fa_activate(self, request: web.Request) -> web.Response:
        """Activa el 2FA verificando el primer código."""
        user = request.get("auth_user", "")
        try:
            body = await _read_json(request)
            code = str(body.get("code", "")).strip()
        except Exception:
            return web.json_response({"ok": False, "error": "Body inválido"}, status=400)
        from cyberhound.core.totp import TOTPManager
        ok = await TOTPManager(self.db).activate_2fa(user, code)
        if ok:
            logger.info("2FA activado para '%s'", user)
        return web.json_response({"ok": ok, "error": None if ok else "Código incorrecto"})

    async def api_2fa_disable(self, request: web.Request) -> web.Response:
        """Desactiva el 2FA del usuario actual."""
        user = request.get("auth_user", "")
        from cyberhound.core.totp import TOTPManager
        await TOTPManager(self.db).disable_2fa(user)
        logger.info("2FA desactivado para '%s'", user)
        return web.json_response({"ok": True})

    async def api_2fa_status(self, request: web.Request) -> web.Response:
        """Devuelve el estado del 2FA del usuario actual."""
        user = request.get("auth_user", "")
        db_user = await self.db.get_user(user) if user else None
        enabled = bool(db_user.get("totp_enabled")) if db_user else False
        return web.json_response({"enabled": enabled, "user": user})

    # ── YARA update ───────────────────────────────────────────────────────────

    async def api_yara_update(self, request: web.Request) -> web.Response:
        """Descarga y actualiza reglas YARA desde repositorios públicos."""
        try:
            body = await _read_json(request)
            sources = body.get("sources", ["default"])
        except Exception:
            sources = ["default"]

        results = await _update_yara_rules(sources)
        return web.json_response(results)

    async def api_yara_list(self, request: web.Request) -> web.Response:
        """Lista las reglas YARA disponibles."""
        yara_dir = Path.home() / ".cyberhound" / "yara"
        yara_dir.mkdir(exist_ok=True)
        rules = []
        for f in sorted(yara_dir.glob("*.yar")) + sorted(yara_dir.glob("*.yara")):
            try:
                stat = f.stat()
                rules.append({
                    "name": f.name,
                    "path": str(f),
                    "size_kb": round(stat.st_size / 1024, 1),
                    "modified": stat.st_mtime,
                })
            except OSError:
                pass
        return web.json_response(rules)

    # ── Informes ──────────────────────────────────────────────────────────────

    async def api_report(self, request: web.Request) -> web.Response:
        fmt = request.match_info.get("fmt", "html")
        try:
            body     = await _read_json(request)
            findings = [Finding.from_dict(d) for d in body.get("findings", [])]
            report   = ScanReport(target=body.get("source", "localhost"), local_findings=findings)
            from cyberhound.scanners.reports import ReportGenerator
            if fmt == "html":
                content = await ReportGenerator.html_report(report)
                return web.Response(body=content.encode(), content_type="text/html",
                                    headers={"Content-Disposition": "attachment; filename=report.html"})
            elif fmt == "ansible":
                content = ReportGenerator.ansible_playbook(findings)
                return web.Response(body=content.encode(), content_type="text/yaml",
                                    headers={"Content-Disposition": "attachment; filename=remediation.yml"})
            return web.json_response({"error": f"Formato desconocido: {fmt}"}, status=400)
        except Exception as e:
            logger.error("api_report: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_cached(self, finding_id: str) -> Finding | None:
        for fl in self._findings_cache.values():
            for f in fl:
                if f.id == finding_id:
                    return f
        return None

    # ── Start ─────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        # 0. Validación eager de configuración
        errors = self.cfg.validate()
        if errors:
            print("\n❌ Errores de configuración detectados al arrancar:\n")
            for err in errors:
                print(f"   • {err}")
            print(
                "\n   Edita la configuración: sudo cyberhound setup\n"
                "   O directamente: nano ~/.cyberhound/config.yaml\n"
            )
            raise SystemExit(1)

        # Persistir el secreto JWT si aún no estaba guardado en config
        # (evita invalidar sesiones en cada reinicio del servidor)
        config_path = Path(self.cfg.db_path).parent / "config.yaml"
        if not self.cfg.auth.secret:
            import secrets as _sec
            self.cfg.auth.secret = _sec.token_hex(32)
        # Guardar solo si el secreto no estaba ya en el fichero
        try:
            import yaml as _yaml
            if config_path.exists():
                raw = _yaml.safe_load(config_path.read_text()) or {}
                if not raw.get("auth", {}).get("secret"):
                    self.cfg.save(config_path)
                    logger.info("JWT secret persistido en %s", config_path)
        except Exception as e:
            logger.warning("No se pudo persistir el JWT secret: %s", e)

        # 1. Inicializar BD
        await self.db.init()
        await self.db.ensure_admin_exists(
            self.cfg.auth.username,
            self.cfg.auth.password_hash or passwords.hash_password("cyberhound"),
        )

        # Cargar licencia
        lic = license_manager.load()
        logger.info("Licencia: %s (%s)", lic.tier, lic.licensee)

        # 2. Construir app
        app = self.build_app()
        runner = web.AppRunner(app)
        await runner.setup()

        # 3. TLS
        ssl_ctx = None
        proto = "http"
        try:
            ssl_ctx = TLSManager.create_ssl_context(
                cert_path=self.cfg.server.tls_cert,
                key_path=self.cfg.server.tls_key,
            )
            proto = "https"
        except Exception as e:
            logger.error("TLS no disponible: %s — arrancando en HTTP (inseguro)", e)

        # 4. Bind
        site = web.TCPSite(runner, self.cfg.server.host, self.cfg.server.port, ssl_context=ssl_ctx)
        try:
            await site.start()
        except OSError as e:
            if e.errno == 98:
                import subprocess
                proc = subprocess.run(
                    ["ss", "-tlnp", f"sport = :{self.cfg.server.port}"],
                    capture_output=True, text=True,
                )
                print(
                    f"\n❌ Puerto {self.cfg.server.port} ya en uso.\n"
                    f"   Liberar: sudo pkill -f 'cyberhound web'\n"
                    f"   O usar otro: sudo cyberhound web --port 9443\n"
                    f"   {proc.stdout.strip()}\n"
                )
                raise SystemExit(1) from None
            raise

        # 5. Scheduler
        if self.cfg.scheduler.enabled:
            self.scheduler = build_scheduler(self, self.cfg.scheduler)
            await self.scheduler.start()

        # 6. Monitor eBPF/auditd en tiempo real (si está habilitado en config)
        if getattr(self.cfg, 'monitor_enabled', True):
            from cyberhound.core.ebpf_monitor import EBPFMonitor
            self._ebpf_monitor = EBPFMonitor(self)
            await self._ebpf_monitor.start()
            if self._ebpf_monitor.mode != "none":
                logger.info("Monitor en tiempo real activo (modo: %s)", self._ebpf_monitor.mode)

        cert_info = ""
        if ssl_ctx and not self.cfg.server.tls_cert:
            cert_path, _ = TLSManager.cert_paths()
            cert_info = f"\n   Certificado : {cert_path} (auto-firmado)"

        logger.info("CyberHound Pro v6.1 en %s://%s:%d",
                    proto, self.cfg.server.host, self.cfg.server.port)
        print(
            f"\n🐾 CyberHound Pro v6.1 listo en "
            f"{proto}://{self.cfg.server.host}:{self.cfg.server.port}"
            f"{cert_info}"
            f"\n   Login: '{self.cfg.auth.username}'"
            f"\n   BD: {self.cfg.db_path}"
            f"\n   Scheduler: {'activo' if self.cfg.scheduler.enabled else 'desactivado'}\n"
        )
        await asyncio.Event().wait()
