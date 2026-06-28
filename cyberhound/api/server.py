"""
Servidor web de CyberHound con:
- Autenticación JWT en todas las rutas
- Rate limiting en /login
- Validación de todos los inputs WebSocket
- CSRF protection en formularios
- TLS automático (auto-signed o Let's Encrypt)
- Headers de seguridad en todas las respuestas
- Logging estructurado de cada petición
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Optional

from aiohttp import web

from cyberhound.core.auth import AuthConfig, auth_middleware, setup_auth_routes
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.models import Finding, HostResult, ScanReport
from cyberhound.core.security import (
    CsrfProtection, InputValidator, RateLimiter,
    TLSManager, ValidationError, _get_real_ip,
)

logger = get_logger("api")


@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    """Añade headers de seguridad HTTP a todas las respuestas."""
    response = await handler(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    # CSP restrictivo — solo permite recursos locales
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:;"
    )
    return response


@web.middleware
async def request_logger_middleware(request: web.Request, handler):
    """Loguea todas las peticiones con tiempo de respuesta."""
    start = time.monotonic()
    try:
        response = await handler(request)
        elapsed = (time.monotonic() - start) * 1000
        logger.info(
            "%s %s %d %.0fms user=%s",
            request.method, request.path, response.status, elapsed,
            request.get("auth_user", "anonymous"),
        )
        return response
    except web.HTTPException as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning(
            "%s %s %d %.0fms [%s]",
            request.method, request.path, e.status, elapsed, str(e.reason),
        )
        raise


class CyberHoundServer:
    """
    Servidor principal. Gestiona:
    - Rutas REST y WebSocket
    - Caché de findings por sesión WS
    - Ejecución de escaneos con streaming
    """

    def __init__(self, cfg: CyberHoundConfig) -> None:
        self.cfg = cfg
        # Importaciones lazy para no cargar todo en el __init__
        self._app: Optional[web.Application] = None
        # Caché de findings por conexión WS (ws_id → list[Finding])
        self._findings_cache: dict[str, list[Finding]] = {}

    def build_app(self) -> web.Application:
        auth_cfg = AuthConfig(
            mode=           self.cfg.auth.mode,
            secret=         self.cfg.auth.secret,
            username=       self.cfg.auth.username,
            password_hash=  self.cfg.auth.password_hash,
            token_ttl_hours=self.cfg.auth.token_ttl_hours,
            localhost_only= self.cfg.auth.localhost_only,
        )

        csrf = CsrfProtection()

        app = web.Application(
            middlewares=[
                security_headers_middleware,
                request_logger_middleware,
                csrf.middleware_factory(),
                auth_middleware,
            ],
            client_max_size=10 * 1024 * 1024,
        )
        app["auth_config"] = auth_cfg
        app["server"] = self

        # Rutas de autenticación (públicas)
        setup_auth_routes(app, auth_cfg)

        # Servir la SPA desde ui/static/
        static_dir = Path(__file__).parent.parent / "ui" / "static"
        if static_dir.exists():
            app.router.add_static("/static", static_dir)

        # Página principal (SPA)
        app.router.add_get("/", self.serve_spa)

        # WebSocket (streaming de escaneos)
        app.router.add_get("/ws", self.websocket_handler)

        # REST API
        app.router.add_post("/api/fix/local",   self.api_fix_local)
        app.router.add_post("/api/fix/remote",  self.api_fix_remote)
        app.router.add_post("/api/report/{fmt}", self.api_report)
        app.router.add_get ("/api/config/keys", self.api_get_keys)
        app.router.add_post("/api/config/keys", self.api_save_keys)
        app.router.add_get ("/api/network/discover", self.api_discover)

        self._app = app
        return app

    async def serve_spa(self, request: web.Request) -> web.Response:
        """Sirve la SPA desde archivo estático."""
        spa_path = Path(__file__).parent.parent / "ui" / "static" / "index.html"
        if spa_path.exists():
            content = spa_path.read_text(encoding="utf-8")
            return web.Response(text=content, content_type="text/html")
        return web.Response(
            text="<h1>CyberHound Pro — UI no encontrada</h1>"
                 "<p>Ejecuta el instalador para generar los ficheros estáticos.</p>",
            content_type="text/html",
        )

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
                except Exception as e:
                    logger.debug("WS send error: %s", e)

        async def log(level: str, text: str) -> None:
            await send({"type": "log", "level": level, "text": text})

        try:
            msg_raw = await asyncio.wait_for(ws.receive_json(), timeout=30)
        except asyncio.TimeoutError:
            await ws.close()
            return ws
        except Exception as e:
            logger.error("WS receive error: %s", e)
            await ws.close()
            return ws

        # ── Validar y sanitizar el mensaje antes de procesarlo ────────────────
        try:
            msg = InputValidator.ws_message(msg_raw)
        except ValidationError as e:
            logger.warning(
                "WS input inválido de %s: %s=%s",
                _get_real_ip(request), e.field, e.reason,
            )
            await send({"type": "error", "text": f"Input inválido: {e.field} — {e.reason}"})
            await ws.close()
            return ws

        task = msg.get("task", "")
        audit_log.scan_started(
            target=msg.get("target", "localhost"),
            scan_type=task,
            user=user,
        )

        try:
            if task == "audit":
                await self._run_local_audit(msg, ws_id, send, log)

            elif task == "malware":
                await self._run_malware_scan(msg, ws_id, send, log)

            elif task == "network":
                await self._run_network_scan(msg, ws_id, send, log)

            elif task == "ssh":
                await self._run_ssh_scan(msg, ws_id, send, log)

            elif task == "code":
                await self._run_code_audit(msg, ws_id, send, log)

            elif task == "intel":
                await self._run_intel_scan(msg, ws_id, send, log)

            else:
                await send({"type": "error", "text": f"Tarea desconocida: {task}"})

        except Exception as e:
            logger.error("Error en tarea WS %s: %s", task, e, exc_info=True)
            await send({"type": "error", "text": f"Error interno: {e}"})

        await ws.close()
        logger.info("WS cerrado: %s", ws_id)
        return ws

    async def _emit_findings(
        self,
        findings: list[Finding],
        ws_id: str,
        send,
    ) -> None:
        """Emite findings al cliente y los cachea para el fix handler."""
        self._findings_cache.setdefault(ws_id, []).extend(findings)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.severity, 5))
        for f in sorted_findings:
            await send({"type": "finding", "data": f.to_dict()})
        await send({"type": "done", "count": len(findings)})

    async def _run_local_audit(self, params: dict, ws_id: str, send, log) -> None:
        from cyberhound.scanners.hardening import HardeningAuditor
        await log("section", "Iniciando Hardening Audit local…")
        findings = await HardeningAuditor.full_audit(cfg=self.cfg)
        await self._emit_findings(findings, ws_id, send)

    async def _run_malware_scan(self, params: dict, ws_id: str, send, log) -> None:
        from cyberhound.scanners.malware import MalwareScanner
        skip = params.get("skip", [])
        await log("section", f"Iniciando Malware Scan (módulos skip: {skip or 'ninguno'})…")
        findings = await MalwareScanner.full_scan(
            cfg=self.cfg,
            skip_modules=skip or None,
            yara_rules=params.get("yara_rules"),
            yara_paths=params.get("yara_paths") or None,
            web_roots=params.get("web_roots") or None,
        )
        await self._emit_findings(findings, ws_id, send)

    async def _run_code_audit(self, params: dict, ws_id: str, send, log) -> None:
        from cyberhound.scanners.code import CodeAuditor
        from cyberhound.scanners.secrets import SecretScanner
        path = params.get("path", "")
        if not Path(path).exists():
            await send({"type": "error", "text": f"Ruta no existe: {path}"})
            return
        await log("section", f"Analizando código en: {path}")
        code_findings = await CodeAuditor.full_analysis(Path(path))
        secret_findings = await SecretScanner.scan(path)
        all_findings = code_findings + secret_findings
        await self._emit_findings(all_findings, ws_id, send)

    async def _run_network_scan(self, params: dict, ws_id: str, send, log) -> None:
        from cyberhound.scanners.network import NetworkScanner
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials

        networks = [n.strip() for n in params.get("networks", "").split(",") if n.strip()] or None
        await log("section", "Fase 1/3: Descubriendo dispositivos en la red…")

        scanner = NetworkScanner(nmap_timeout=self.cfg.scan.nmap_timeout)
        devices = await scanner.scan_network(
            networks=networks,
            deep=True,
            vuln_scan=params.get("vuln_scan", False),
            concurrency=10,
        )

        await send({"type": "devices", "data": [d.to_dict() for d in devices]})
        await log("ok", f"✓ {len(devices)} dispositivos encontrados")

        # SSH audit en los que tienen SSH abierto
        ssh_hosts = [d for d in devices if d.has_ssh and d.scan_status == "scanned"]
        if not ssh_hosts or not params.get("ssh_audit"):
            await send({"type": "done", "count": 0})
            return

        await log("section", f"Fase 2/3: Audit SSH en {len(ssh_hosts)} hosts…")
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
                await log("ok", f"✓ {hr.host}: {len(hr.findings)} hallazgos ({hr.scan_time:.1f}s)")
            else:
                await log("warn", f"✗ {hr.host}: {hr.status} — {hr.error}")

        await log("section", f"Fase 3/3: Consolidando resultados…")
        await self._emit_findings(all_findings, ws_id, send)

    async def _run_ssh_scan(self, params: dict, ws_id: str, send, log) -> None:
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials

        hosts_raw = params.get("hosts", "")
        hosts = [h.strip() for h in re.split(r"[,\s\n]+", hosts_raw) if h.strip()]
        if not hosts:
            await send({"type": "error", "text": "Sin hosts especificados"})
            return

        await log("section", f"SSH Scan en {len(hosts)} hosts: {', '.join(hosts)}")
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
                await log("warn" if hr.status == "unreachable" else "error",
                          f"✗ {hr.host}: {hr.status} — {hr.error}")

        await self._emit_findings(all_findings, ws_id, send)

    async def _run_intel_scan(self, params: dict, ws_id: str, send, log) -> None:
        """Consulta APIs de inteligencia externa."""
        target = params.get("target", "")
        modules = params.get("modules", ["shodan", "virustotal", "abuseipdb"])
        if not target:
            await send({"type": "error", "text": "Sin objetivo especificado"})
            return

        await log("section", f"Intel scan: {target}")
        from cyberhound.scanners.intel import IntelScanner
        scanner = IntelScanner(self.cfg.api_keys)
        results = await scanner.scan(target, modules)
        for item in results:
            await send({"type": "intel", "data": item.to_dict()})
            await log("ok", f"✓ {item.source}: datos obtenidos")
        await send({"type": "done", "count": len(results)})

    # ── REST endpoints ─────────────────────────────────────────────────────────

    async def api_fix_local(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            finding_id = body.get("finding_id")
            dry_run = body.get("dry_run", False)
            user = request.get("auth_user", "unknown")

            finding = self._find_cached(finding_id)
            if not finding:
                return web.json_response(
                    {"ok": False, "error": "Finding no encontrado en caché de sesión"}
                )

            from cyberhound.scanners.hardening import HardeningFixer
            fixer = HardeningFixer(dry_run=dry_run)
            ok, msg = await fixer.fix(finding)
            audit_log.fix_applied(finding_id, user, "localhost", dry_run)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_fix_local error: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_fix_remote(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            finding_id = body.get("finding_id")
            host = body.get("host", "")
            user = request.get("auth_user", "unknown")

            finding = self._find_cached(finding_id)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"})

            from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
            creds = SSHCredentials(
                username=body.get("ssh_user", self.cfg.scan.ssh_default_user),
                port=int(body.get("ssh_port", self.cfg.scan.ssh_default_port)),
                key_path=body.get("ssh_key") or self.cfg.scan.ssh_key_path,
                password=body.get("ssh_password") or None,
            )
            auditor = RemoteAuditor(creds)
            ok, msg = await auditor.apply_fix_remote(host, finding.remediation)
            audit_log.fix_applied(finding_id, user, host, False)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_fix_remote error: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_report(self, request: web.Request) -> web.Response:
        fmt = request.match_info.get("fmt", "html")
        try:
            body = await request.json()
            findings_data = body.get("findings", [])
            findings = [Finding.from_dict(d) for d in findings_data]
            report = ScanReport(
                target=body.get("source", "localhost"),
                local_findings=findings,
            )
            from cyberhound.scanners.reports import ReportGenerator
            if fmt == "html":
                content = await ReportGenerator.html_report(report)
                return web.Response(
                    body=content.encode(),
                    content_type="text/html",
                    headers={"Content-Disposition": "attachment; filename=report.html"},
                )
            elif fmt == "ansible":
                content = ReportGenerator.ansible_playbook(findings)
                return web.Response(
                    body=content.encode(),
                    content_type="text/yaml",
                    headers={"Content-Disposition": "attachment; filename=remediation.yml"},
                )
            return web.json_response({"error": f"Formato desconocido: {fmt}"}, status=400)
        except Exception as e:
            logger.error("api_report error: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_get_keys(self, request: web.Request) -> web.Response:
        keys = {}
        for attr in ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"):
            val = getattr(self.cfg.api_keys, attr, None)
            if val:
                keys[attr] = val[:4] + "***"  # nunca exponer la clave completa
        return web.json_response(keys)

    async def api_save_keys(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            for attr in ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"):
                val = body.get(attr, "")
                if val and not val.endswith("***"):
                    setattr(self.cfg.api_keys, attr, val)
            self.cfg.save()
            return web.json_response({"ok": True})
        except Exception as e:
            logger.error("api_save_keys error: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_discover(self, request: web.Request) -> web.Response:
        try:
            networks_raw = request.rel_url.query.get("networks", "")
            networks = [n.strip() for n in networks_raw.split(",") if n.strip()] or None
            from cyberhound.scanners.network import NetworkScanner
            scanner = NetworkScanner()
            ips = await scanner.discover_hosts(networks=networks)
            return web.json_response({"hosts": ips})
        except Exception as e:
            logger.error("api_discover error: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_cached(self, finding_id: str) -> Optional[Finding]:
        for findings_list in self._findings_cache.values():
            for f in findings_list:
                if f.id == finding_id:
                    return f
        return None

    async def start(self) -> None:
        app = self.build_app()
        runner = web.AppRunner(app)
        await runner.setup()

        # ── TLS: auto-signed por defecto, certificado externo si se configura ──
        ssl_ctx = None
        try:
            ssl_ctx = TLSManager.create_ssl_context(
                cert_path=self.cfg.server.tls_cert,
                key_path=self.cfg.server.tls_key,
            )
            proto = "https"
        except Exception as e:
            logger.error(
                "No se pudo activar TLS: %s\n"
                "El servidor arrancará en HTTP — INSEGURO para producción.\n"
                "Instala 'cryptography' para TLS automático: pip install cryptography",
                e,
            )
            proto = "http"

        site = web.TCPSite(
            runner,
            self.cfg.server.host,
            self.cfg.server.port,
            ssl_context=ssl_ctx,
        )
        await site.start()

        cert_info = ""
        if ssl_ctx and not self.cfg.server.tls_cert:
            cert_path, _ = TLSManager.cert_paths()
            cert_info = (
                f"\n   Certificado : {cert_path} (auto-firmado)"
                f"\n   ⚠ Para evitar avisos del navegador, importa el cert o usa Let's Encrypt"
            )

        logger.info(
            "CyberHound Pro escuchando en %s://%s:%d",
            proto, self.cfg.server.host, self.cfg.server.port,
        )
        print(
            f"\n🐾 CyberHound Pro listo en "
            f"{proto}://{self.cfg.server.host}:{self.cfg.server.port}"
            f"{cert_info}"
            f"\n   Login: usuario='{self.cfg.auth.username}'"
            f"\n   Cambia la contraseña con: cyberhound setup\n"
        )
        await asyncio.Event().wait()
