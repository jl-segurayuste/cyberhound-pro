"""Análisis por WebSocket: recibe la tarea, la ejecuta y emite los hallazgos."""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from aiohttp import web

from cyberhound.api.common import (
    HOST_TASKS,
    NO_TARGETS,
    WS_RUNNERS,
)
from cyberhound.core.database import AssetRecord
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.models import Finding
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)
from cyberhound.core.scope import Scope, ws_targets as scope_targets
from cyberhound.core.security import (
    InputValidator,
    ValidationError,
)
from cyberhound.core.ssh_host_keys import HostKeyStore

logger = get_logger("api")


class ScanHandlers:
    # ── WebSocket ─────────────────────────────────────────────────────────────

    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        ws_id = self._new_ws_id()
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
        if task in HOST_TASKS and not self._may_touch_host(request):
            await send({"type": "error", "text": "Ese análisis actúa sobre el propio servidor: "
                                                  "solo lo puede lanzar el administrador de la plataforma"})
            await ws.close()
            return ws
        if err := ((await self._out_of_scope(scope_targets(msg))) or self._tenant_ssh_key_error(msg.get("ssh_key"))
                   or await self._ssh_credential_error(msg.get("ssh_credential"))):
            await send({"type": "error", "text": err})
            await ws.close()
            return ws
        audit_log.scan_started(msg.get("target", "localhost"), task, user)

        # Crear scan en BD
        scan_id = await self.db.create_scan(task, triggered_by="manual")
        self._scan_id_cache[ws_id] = scan_id

        try:
            runner = getattr(self, WS_RUNNERS.get(task, ""), None)
            if runner:
                await runner(msg, ws_id, send, log, scan_id)
            else:
                await send({"type": "error", "text": f"Tarea desconocida: {task}"})
        except Exception as e:
            logger.error("Error en tarea WS %s: %s", task, e, exc_info=True)
            await self.db.fail_scan(scan_id)
            await send({"type": "error", "text": f"Error interno: {e}"})

        await ws.close()
        return ws

    async def _out_of_scope(self, targets: list[str] | None) -> str | None:
        """En una organización (multi-tenant), motivo por el que algún objetivo queda fuera de su ámbito.

        targets=None: la tarea no actúa sobre la red. Lista vacía: el escáner elegiría solo
        (p. ej. las redes del propio servidor), y eso a una organización no se le permite."""
        slug = current_tenant.get()
        if targets is None or not self.cfg.multi_tenant.enabled or slug == DEFAULT_TENANT:
            return None
        tenant = self.tenants.get(slug)
        allowed = (tenant.settings.get("allowed_targets") if tenant else None) or []
        if not allowed:
            return ("Esta organización todavía no tiene redes ni dominios permitidos: "
                    "pídeselo al administrador de la plataforma")
        if not targets:
            return NO_TARGETS
        return await Scope(allowed).check_all(targets)

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
            siem_cfg = self._integration_settings("siem")
            if siem_cfg.wazuh_enabled or siem_cfg.elk_enabled or siem_cfg.splunk_enabled:
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
        from cyberhound.scanners.ssh_audit import RemoteAuditor
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
        creds = await self._ssh_creds(params)
        results = await RemoteAuditor.scan_multiple(
            [d.ip for d in ssh_hosts], creds,
            concurrency=self.cfg.scan.ssh_concurrency, host_keys=HostKeyStore(self.db),
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
        from cyberhound.scanners.ssh_audit import RemoteAuditor
        hosts = [h.strip() for h in re.split(r"[,\s\n]+", params.get("hosts", "")) if h.strip()]
        if not hosts:
            await send({"type": "error", "text": "Sin hosts"})
            await self.db.fail_scan(scan_id)
            return
        await log("section", f"SSH Scan en {len(hosts)} hosts…")
        creds = await self._ssh_creds(params)
        results = await RemoteAuditor.scan_multiple(
            hosts, creds, concurrency=self.cfg.scan.ssh_concurrency, host_keys=HostKeyStore(self.db)
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
        await log("section", f"Intel scan: {target}")
        scanner = IntelScanner(self.cfg.api_keys)
        if not scanner.configured_modules():
            await log("warn", "Sin API keys de threat intelligence configuradas")
        findings = await scanner.scan_findings(target, params.get("modules") or None)
        await self._emit_findings(findings, ws_id, send, scan_id)
