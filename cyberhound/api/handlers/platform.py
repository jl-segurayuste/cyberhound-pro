"""Organizaciones, informes, compliance, importación, SBOM, cuarentena, LDAP, Ansible, push y OpenAPI."""
from __future__ import annotations

import asyncio
from datetime import datetime

from aiohttp import web

from cyberhound.api.common import (
    _read_json,
    _scope_status,
)
from cyberhound.core import passwords
from cyberhound.core.auth import (
    TENANT_COOKIE,
)
from cyberhound.core.database import UserRecord
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding, ScanReport
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)

logger = get_logger("api")


class PlatformHandlers:
    # ── WebSocket push — notificaciones sin polling ───────────────────────────

    async def push_websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """
        WebSocket de solo lectura para recibir notificaciones en tiempo real.
        El cliente se conecta una vez y recibe eventos conforme ocurren,
        sin necesidad de polling periódico.
        """
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._push_clients[ws] = current_tenant.get()
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
            self._push_clients.pop(ws, None)
        return ws

    async def _broadcast_push(self, event_type: str, data: dict) -> None:
        """Envía un evento a todos los clientes push conectados."""
        if not self._push_clients:
            return
        message = {"type": event_type, "data": data, "ts": asyncio.get_event_loop().time()}
        tenant = current_tenant.get()   # el del escaneo que genera el evento
        for ws, ws_tenant in list(self._push_clients.items()):
            if ws_tenant != tenant:
                continue
            try:
                await ws.send_json(message)
            except Exception:
                self._push_clients.pop(ws, None)

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
            target   = str(body.get("target") or "localhost").strip()
            mode     = body.get("mode", "local")  # local | awx

            # Cargar findings del scan
            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
                from cyberhound.core.models import Finding as F
                findings = [F(
                    id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    description=f.get("description",""), remediation=f.get("remediation",""),
                    auto_fix=bool(f.get("auto_fix")), file_path=f.get("file_path") or "",
                    source_host=f.get("source_host") or "",
                ) for f in findings_raw]
            else:
                findings = []

            from cyberhound.core.ansible_integration import build_playbook, run_playbook_local
            if mode == "local":
                # ansible-playbook local corre con --connection=local: solo puede corregir este servidor.
                # Antes los hallazgos de hosts remotos del análisis se "corregían" aquí.
                if target not in ("localhost", "127.0.0.1"):
                    return web.json_response({"error": "En modo local el playbook se aplica en este servidor: "
                                                       "para otros hosts usa AWX o descarga el playbook"}, status=400)
                findings = [f for f in findings if f.source_host in ("", "localhost", "127.0.0.1")]
                target = "localhost"            # el inventario de run_playbook_local es "localhost,"
            try:
                playbook, _n, _manual = build_playbook(findings, target)
            except ValueError as e:
                return web.json_response({"error": str(e)}, status=400)
            if not playbook:
                return web.json_response({"error": "Sin hallazgos de este servidor que Ansible pueda corregir"
                                          if mode == "local" else "Sin hallazgos con corrección automática"},
                                         status=400)

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

    async def api_tenants_list(self, request: web.Request) -> web.Response:
        return web.json_response([t.to_dict() for t in self.tenants.list()])

    async def api_tenants_create(self, request: web.Request) -> web.Response:
        """Crea el tenant, su BD y (opcional) su primer administrador."""
        try:
            body = await _read_json(request)
            admin_user = str(body.get("admin_username") or "").strip()
            admin_pw = str(body.get("admin_password") or "")
            if admin_user and len(admin_pw) < 8:
                return web.json_response({"error": "La contraseña del administrador necesita 8 caracteres"},
                                         status=400)
            tenant = self.tenants.create(
                slug=str(body.get("slug", "")).strip().lower(), name=str(body.get("name", "")),
                admin_email=str(body.get("admin_email", "")), plan=str(body.get("plan", "starter")),
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        await self.tenant_dbs.ensure(tenant.slug)
        if admin_user:
            ctx = current_tenant.set(tenant.slug)
            try:
                await self.db.create_user(UserRecord(username=admin_user, role="admin",
                                                     password_hash=passwords.hash_password(admin_pw)))
            finally:
                current_tenant.reset(ctx)
        logger.info("Tenant creado por %s: %s", request.get("auth_user"), tenant.slug)
        return web.json_response(tenant.to_dict(include_key=True), status=201)

    async def api_tenant_get(self, request: web.Request) -> web.Response:
        tenant = self.tenants.get(request.match_info["slug"])
        if not tenant or not tenant.active:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response(tenant.to_dict())

    async def api_tenant_update(self, request: web.Request) -> web.Response:
        try:
            t = self.tenants.update(request.match_info["slug"], **(await _read_json(request)))
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if not t:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response(t.to_dict())

    async def api_tenant_delete(self, request: web.Request) -> web.Response:
        """Baja: el tenant deja de funcionar y sus datos se archivan (no se borran)."""
        slug = request.match_info["slug"]
        if not self.tenants.delete(slug):
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        await self.tenant_dbs.archive(slug)
        logger.info("Tenant dado de baja por %s: %s", request.get("auth_user"), slug)
        return web.json_response({"ok": True})

    async def api_tenant_rotate_key(self, request: web.Request) -> web.Response:
        key = self.tenants.rotate_api_key(request.match_info["slug"])
        if not key:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response({"api_key": key})

    async def api_tenant_agent_key(self, request: web.Request) -> web.Response:
        """API key del tenant actual, para configurar sus agentes. Solo su administrador."""
        tenant = self.tenants.get(current_tenant.get())
        if not self.cfg.multi_tenant.enabled or not tenant:
            return web.json_response({"error": "Solo en una organización (modo multi-tenant)"}, status=404)
        if request.get("user_role") != "admin":
            return web.json_response({"error": "Solo el administrador de la organización"}, status=403)
        return web.json_response({"tenant": tenant.slug, "api_key": tenant.api_key})

    async def api_tenant_switch(self, request: web.Request) -> web.Response:
        """El superadmin elige qué tenant mira la UI (cookie ch_tenant)."""
        if not self.cfg.multi_tenant.enabled or not request.get("superadmin"):
            return web.json_response({"error": "Solo el administrador de la plataforma"}, status=403)
        slug = str((await _read_json(request)).get("slug") or DEFAULT_TENANT)
        if slug != DEFAULT_TENANT and not self.tenants.is_active(slug):
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        resp = web.json_response({"ok": True, "tenant": slug})
        resp.set_cookie(TENANT_COOKIE, slug, httponly=True, samesite="Strict", secure=request.secure,
                        max_age=int(self.cfg.auth.token_ttl_hours) * 3600)
        return resp

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
                # Score del scan pedido (antes solo se miraba el último scan del historial)
                scan = await self.db.get_scan(int(scan_id))
                score = scan["score"] if scan else None
            else:
                findings_raw = body.get("findings", [])
                findings = [Finding.from_dict(f) for f in findings_raw]
                score = body.get("score")

            from cyberhound.scanners.pdf_report import generate_pdf
            tenant = self.tenants.get(current_tenant.get())
            pdf_bytes = generate_pdf(
                findings, target=target, scan_type=scan_type,
                score=score, organization=tenant.name if tenant else "",
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

    # ── LDAP / AD ─────────────────────────────────────────────────────────────

    async def api_ldap_scan(self, request: web.Request) -> web.Response:
        """Ejecuta un audit de LDAP/AD y devuelve los hallazgos."""
        try:
            body   = await _read_json(request)
            user   = request.get("auth_user", "unknown")
            if err := await self._out_of_scope([body.get("uri", "")]):
                return web.json_response({"error": err}, status=_scope_status(err))
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
