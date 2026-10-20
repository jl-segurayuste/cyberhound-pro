"""
Endpoints de Inteligencia de Amenazas (Threat Intelligence) para CyberHound Pro.

Integra múltiples fuentes de intel para contexto de amenazas:
  - Shodan: exposición de servicios en internet
  - VirusTotal: reputación de IPs, dominios y ficheros
  - AbuseIPDB: IPs reportadas como maliciosas
  - GreyNoise: clasificación de scanners y bots
  - HIBP (Have I Been Pwned): cuentas comprometidas en brechas
"""
from __future__ import annotations

import ipaddress
import json

from aiohttp import web

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("api.intel")


async def _read_json(request) -> dict:
    try:
        raw = await request.read()
        if not raw or not raw.strip():
            return {}
        return json.loads(raw.strip().decode("utf-8", errors="replace"))
    except Exception:
        try:
            return await request.json()
        except Exception:
            return {}


async def _targets_from_last_network_scan(db, limit: int = 10) -> list[str]:
    """IPs del último scan de red: hosts con hallazgos primero, luego el inventario de activos.

    Ningún scanner escribe la IP en `evidence`; el scan de red sí rellena
    `source_host` de cada hallazgo y la tabla `assets` con cada dispositivo.
    """
    ips: list[str] = []

    def _add(value: str) -> None:
        try:
            ip = str(ipaddress.ip_address((value or "").strip()))
        except ValueError:
            return
        if ip not in ips:
            ips.append(ip)

    history = await db.get_scan_history("network", limit=1)
    if history:
        for f in await db.get_scan_findings(history[0]["id"]):
            _add(f.get("source_host", ""))
    for asset in await db.get_assets():
        _add(asset.get("ip", ""))
    return ips[:limit]


async def api_intel_scan(request: web.Request) -> web.Response:
    """
    POST /api/intel/scan
    Lanza un análisis de threat intelligence sobre IPs/dominios.

    Body: {"targets": ["1.2.3.4", "evil.com"], "modules": ["shodan","vt","abuseipdb"]}
    """
    server = request.app["server"]
    try:
        body    = await _read_json(request)
        targets = body.get("targets") or []
        modules = body.get("modules") or []
        if not isinstance(targets, list) or not isinstance(modules, list):
            return web.json_response({"error": "'targets' y 'modules' deben ser listas"}, status=400)

        from cyberhound.scanners.intel import ALL_MODULES, IntelScanner, indicator_kind
        bad = [t for t in targets if not isinstance(t, str) or indicator_kind(t) is None]
        if bad:
            return web.json_response({"error": f"Indicador no válido: {bad[0]!r}"}, status=400)
        if any(m not in ALL_MODULES for m in modules):
            return web.json_response({"error": f"Módulos admitidos: {', '.join(ALL_MODULES)}"}, status=400)
        scanner = IntelScanner(server.cfg.api_keys)
        if not scanner.configured_modules():
            return web.json_response(
                {"error": "No hay ninguna API key de threat intelligence configurada (Configuración › API Keys)."},
                status=400,
            )

        if not targets:
            targets = await _targets_from_last_network_scan(server.db)

        if not targets:
            return web.json_response(
                {"error": "No hay targets. Proporciona 'targets' o ejecuta un scan de red primero."},
                status=400,
            )

        all_findings: list[Finding] = []
        for target in targets[:10]:  # máximo 10 targets por petición
            all_findings.extend(await scanner.scan_findings(target, modules))

        # Guardar en BD
        if all_findings:
            scan_id = await server.db.create_scan("intel", triggered_by="manual")
            all_findings = await server.db.filter_suppressed(all_findings)
            await server.db.complete_scan(scan_id, all_findings)
        else:
            scan_id = None

        return web.json_response({
            "scan_id":  scan_id,
            "targets":  targets,
            "count":    len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
            "summary": _build_intel_summary(all_findings),
        })

    except Exception as e:
        logger.error("api_intel_scan: %s", e, exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def api_intel_lookup(request: web.Request) -> web.Response:
    """
    GET /api/intel/lookup?target=1.2.3.4&modules=shodan,vt
    Búsqueda rápida de una sola IP/dominio.
    """
    server = request.app["server"]
    try:
        target  = request.rel_url.query.get("target", "").strip()
        modules = request.rel_url.query.get("modules", "").split(",")
        modules = [m.strip() for m in modules if m.strip()]

        if not target:
            return web.json_response({"error": "Parámetro 'target' requerido"}, status=400)

        from cyberhound.scanners.intel import ALL_MODULES, IntelScanner, indicator_kind
        if indicator_kind(target) is None:
            return web.json_response({"error": "Introduce una IP, dominio, hash (MD5/SHA1/SHA256) o email"},
                                     status=400)
        if any(m not in ALL_MODULES for m in modules):
            return web.json_response({"error": f"Módulos admitidos: {', '.join(ALL_MODULES)}"}, status=400)
        scanner = IntelScanner(server.cfg.api_keys)
        if not scanner.configured_modules():
            return web.json_response(
                {"error": "No hay ninguna API key de threat intelligence configurada (Configuración › API Keys)."},
                status=400,
            )
        findings = await scanner.scan_findings(target, modules)

        return web.json_response({
            "target":   target,
            "count":    len(findings),
            "findings": [f.to_dict() for f in findings],
            "summary":  _build_intel_summary(findings),
        })

    except Exception as e:
        logger.error("api_intel_lookup: %s", e, exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def api_intel_history(request: web.Request) -> web.Response:
    """GET /api/intel/history — historial de scans de intel."""
    server = request.app["server"]
    try:
        limit = max(1, min(int(request.rel_url.query.get("limit", "20")), 200))
    except ValueError:
        return web.json_response({"error": "limit debe ser un entero"}, status=400)
    history = await server.db.get_scan_history("intel", limit=limit)
    return web.json_response(history)


async def api_intel_config(request: web.Request) -> web.Response:
    """GET /api/intel/config — qué módulos están disponibles (tienen API key)."""
    server = request.app["server"]
    keys = server.cfg.api_keys
    from cyberhound.scanners.intel import ALL_MODULES
    status = {m: bool(getattr(keys, m, None)) for m in ALL_MODULES}
    return web.json_response({**status, "configured_count": sum(status.values())})


def _build_intel_summary(findings: list[Finding]) -> dict:
    """Construye un resumen de los hallazgos de intel."""
    by_module: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    malicious_count = 0

    for f in findings:
        cat = f.category or ""
        module = cat.split("/")[-1] if "/" in cat else cat
        by_module[module] = by_module.get(module, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if f.severity in ("critical", "high"):
            malicious_count += 1

    return {
        "total":          len(findings),
        "malicious":      malicious_count,
        "by_module":      by_module,
        "by_severity":    by_severity,
        "risk_level":     (
            "critical" if by_severity.get("critical", 0) > 0 else
            "high"     if by_severity.get("high", 0) > 0 else
            "medium"   if by_severity.get("medium", 0) > 0 else
            "low"      if findings else "none"
        ),
    }


def register_routes(app: web.Application) -> None:
    """Registra las rutas de intel en la aplicación."""
    app.router.add_post("/api/intel/scan",    api_intel_scan)
    app.router.add_get ("/api/intel/lookup",  api_intel_lookup)
    app.router.add_get ("/api/intel/history", api_intel_history)
    app.router.add_get ("/api/intel/config",  api_intel_config)
