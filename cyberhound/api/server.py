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
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Optional

from aiohttp import web

from cyberhound.core.auth import AuthConfig, auth_middleware, setup_auth_routes
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import AssetRecord, Database, UserRecord
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.models import Finding, ScanReport
from cyberhound.core.notifications import NotificationConfig, NotificationManager
from cyberhound.core.scheduler import Scheduler, build_scheduler
from cyberhound.core.security import (
    CsrfProtection, InputValidator, TLSManager, ValidationError, _get_real_ip,
)

logger = get_logger("api")

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


# ── Middlewares ───────────────────────────────────────────────────────────────

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    response = await handler(request)
    response.headers.update({
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "X-XSS-Protection":        "1; mode=block",
        "Referrer-Policy":         "strict-origin-when-cross-origin",
        "Cache-Control":           "no-store",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
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
        logger.info("%s %s %d %.0fms user=%s",
                    request.method, request.path, response.status, elapsed,
                    request.get("auth_user", "anonymous"))
        return response
    except web.HTTPException as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("%s %s %d %.0fms", request.method, request.path, e.status, elapsed)
        raise


# ── Servidor principal ────────────────────────────────────────────────────────

class CyberHoundServer:

    def __init__(self, cfg: CyberHoundConfig) -> None:
        self.cfg = cfg
        self._app: Optional[web.Application] = None
        self._findings_cache: dict[str, list[Finding]] = {}
        self._scan_id_cache:  dict[str, int] = {}   # ws_id → scan_id en BD

        # Inicializar DB, notificaciones y scheduler
        self.db = Database(Path(cfg.db_path))
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
        self.scheduler: Optional[Scheduler] = None

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
        app.router.add_get("/ws", self.websocket_handler)

        # ── Escaneos ──────────────────────────────────────────────────────────
        app.router.add_post("/api/fix/local",    self.api_fix_local)
        app.router.add_post("/api/fix/remote",   self.api_fix_remote)
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

        self._app = app
        return app

    async def serve_spa(self, request: web.Request) -> web.Response:
        spa_path = Path(__file__).parent.parent / "ui" / "static" / "index.html"
        if spa_path.exists():
            return web.Response(text=spa_path.read_text(encoding="utf-8"), content_type="text/html")
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
        except (asyncio.TimeoutError, Exception) as e:
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
            body  = await request.json()
            fid   = body.get("finding_id")
            dry   = body.get("dry_run", False)
            user  = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"})
            from cyberhound.scanners.hardening import HardeningFixer
            ok, msg = await HardeningFixer(dry_run=dry).fix(finding)
            audit_log.fix_applied(fid, user, "localhost", dry)
            # Marcar como corregido en BD si tenemos el scan_id
            if ok and not dry:
                for ws_id, findings in self._findings_cache.items():
                    if any(f.id == fid for f in findings):
                        scan_id = self._scan_id_cache.get(ws_id)
                        if scan_id:
                            await self.db.mark_finding_fixed(scan_id, fid, user)
                        break
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_fix_local: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_fix_remote(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
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
            from cyberhound.core.scoring import compute_score, ScoringContext
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
            body = await request.json()
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
            body    = await request.json()
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
            body     = await request.json()
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
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
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
            body = await request.json()
            updates = {}
            if "role" in body:
                if body["role"] not in ("admin", "operator", "viewer"):
                    return web.json_response({"error": "Rol inválido"}, status=400)
                updates["role"] = body["role"]
            if "password" in body:
                if len(body["password"]) < 8:
                    return web.json_response({"error": "Contraseña mínimo 8 caracteres"}, status=400)
                updates["password_hash"] = hashlib.sha256(body["password"].encode()).hexdigest()
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
            body = await request.json()
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
            body = await request.json()
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
            body = await request.json()
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
            body = await request.json()
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

    # ── Informes ──────────────────────────────────────────────────────────────

    async def api_report(self, request: web.Request) -> web.Response:
        fmt = request.match_info.get("fmt", "html")
        try:
            body     = await request.json()
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

    def _find_cached(self, finding_id: str) -> Optional[Finding]:
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
        from cyberhound.core.config import DEFAULT_CONFIG_PATH
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
            self.cfg.auth.password_hash or hashlib.sha256(b"cyberhound").hexdigest(),
        )

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
                raise SystemExit(1)
            raise

        # 5. Scheduler
        if self.cfg.scheduler.enabled:
            self.scheduler = build_scheduler(self, self.cfg.scheduler)
            await self.scheduler.start()

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
