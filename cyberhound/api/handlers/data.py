"""Consulta: histórico, inventario, supresiones, métricas y explicación de hallazgos."""
from __future__ import annotations

from aiohttp import web

from cyberhound.api.common import (
    METRICS,
    _read_json,
    _scope_status,
)
from cyberhound.core.logging import get_logger

logger = get_logger("api")


class DataHandlers:
    # ── Observabilidad ─────────────────────────────────────────────────────────

    async def api_metrics(self, request: web.Request) -> web.Response:
        """Métricas en formato Prometheus (texto). Sin sesión solo desde el propio host (LOOPBACK_ROUTES)."""
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
            if err := await self._out_of_scope(networks or []):
                return web.json_response({"error": err}, status=_scope_status(err))
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
