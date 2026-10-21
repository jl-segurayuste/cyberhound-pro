"""Corrección de hallazgos: fix local, rollback, fix remoto y deshacer."""
from __future__ import annotations

import time
from pathlib import Path

from aiohttp import web

from cyberhound.api.common import (
    _read_json,
)
from cyberhound.core.logging import audit_log, get_logger

logger = get_logger("api")


class FixHandlers:
    # ── Fix local ─────────────────────────────────────────────────────────────

    async def api_fix_local(self, request: web.Request) -> web.Response:
        try:
            body  = await _read_json(request)
            fid   = body.get("finding_id")
            dry   = body.get("dry_run", False)
            user  = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"}, status=404)
            if finding.source_host and finding.source_host not in ("localhost", "127.0.0.1"):
                # Sin esto el fix de un hallazgo remoto se aplicaba en este servidor
                return web.json_response({"ok": False, "error": "Hallazgo de otro host: usa el fix remoto"},
                                         status=400)
            from cyberhound.scanners.hardening import HardeningFixer
            fixer = HardeningFixer(dry_run=dry, keep_open_ports=(self.cfg.server.port,))
            ok, msg = await fixer.fix(finding)
            if not ok:
                return web.json_response({"ok": False, "error": msg or "El fix no se pudo aplicar"}, status=422)
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
                for ws_id, findings in self._own_caches():
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
            user = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"}, status=404)
            # El fix se aplica en el host donde se encontró el hallazgo, no en el que diga la petición
            host = finding.source_host or body.get("host", "")
            if not host or host in ("localhost", "127.0.0.1"):
                return web.json_response({"ok": False, "error": "El hallazgo no es de un host remoto"}, status=400)
            if err := await self._out_of_scope([host]):
                return web.json_response({"ok": False, "error": err}, status=403)
            if err := self._tenant_ssh_key_error(body.get("ssh_key")):
                return web.json_response({"ok": False, "error": err}, status=400)
            from cyberhound.scanners.ssh_audit import RemoteAuditor
            action = RemoteAuditor.remote_fix_action(finding)
            ok, msg, undo = await RemoteAuditor(self._ssh_creds(body)).apply_fix_remote(host, finding)
            audit_log.fix_applied(fid, user, host, False)
            fix_id = None
            if ok:
                fix_id = await self.db.add_remote_fix(host, fid, action, undo, username=user, message=msg)
            await self._audit(request, "fix_remote", f"{host} {fid}", msg, ok=ok)
            return web.json_response({"ok": ok, "message": msg, "fix_id": fix_id, "reversible": bool(undo),
                                      **({} if ok else {"error": msg or "El fix no se pudo aplicar"})},
                                     status=200 if ok else 422)
        except Exception as e:
            logger.error("api_fix_remote: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    def _ssh_creds(self, body: dict):
        from cyberhound.scanners.ssh_audit import SSHCredentials
        return SSHCredentials(
            username=body.get("ssh_user", self.cfg.scan.ssh_default_user),
            port=int(body.get("ssh_port", self.cfg.scan.ssh_default_port)),
            key_path=self._ssh_key(body.get("ssh_key")),
            password=body.get("ssh_password") or None,
        )

    def _ssh_key(self, given: str | None) -> str | None:
        """Clave SSH a usar. Una organización no puede usar ficheros del servidor (ni la clave de la
        plataforma, ni otra ruta que indique): entraría en sus hosts con la identidad de la plataforma."""
        if self._tenant_obj() is not None:
            return None
        return given or self.cfg.scan.ssh_key_path

    def _tenant_ssh_key_error(self, given: str | None) -> str | None:
        if given and self._tenant_obj() is not None:
            return "Una organización no puede usar claves SSH guardadas en el servidor: usa usuario y contraseña"
        return None

    async def api_fix_remote_history(self, request: web.Request) -> web.Response:
        """Fixes remotos aplicados en esta organización, con los que aún se pueden deshacer."""
        try:
            limit = int(request.rel_url.query.get("limit", "100"))
        except ValueError:
            return web.json_response({"error": "limit debe ser un entero"}, status=400)
        return web.json_response(await self.db.list_remote_fixes(limit))

    async def api_fix_remote_undo(self, request: web.Request) -> web.Response:
        body = await _read_json(request)
        fix = await self.db.get_remote_fix(str(body.get("fix_id", "")))
        if not fix:
            return web.json_response({"ok": False, "error": "Fix no encontrado"}, status=404)
        if not fix["reversible"]:
            why = "ya se deshizo" if fix.get("undone_at") else "no se guardó cómo deshacerlo"
            return web.json_response({"ok": False, "error": f"Este fix no se puede deshacer: {why}"}, status=409)
        if err := await self._out_of_scope([fix["host"]]):
            return web.json_response({"ok": False, "error": err}, status=403)
        if err := self._tenant_ssh_key_error(body.get("ssh_key")):
            return web.json_response({"ok": False, "error": err}, status=400)
        user = request.get("auth_user", "unknown")
        if not await self.db.mark_remote_fix_undone(fix["id"], user):
            return web.json_response({"ok": False, "error": "Este fix no se puede deshacer: ya se deshizo"}, status=409)
        from cyberhound.scanners.ssh_audit import RemoteAuditor
        ok, msg = await RemoteAuditor(self._ssh_creds(body)).undo_fix_remote(fix["host"], fix["undo"])
        if not ok:
            await self.db.clear_remote_fix_undone(fix["id"])
        audit_log.fix_rolled_back(fix["finding_id"], user, fix["host"], ok)
        await self._audit(request, "fix_remote_undo", f"{fix['host']} {fix['finding_id']}", msg, ok=ok)
        return web.json_response({"ok": ok, "message": msg, **({} if ok else {"error": msg or "No se pudo deshacer"})},
                                 status=200 if ok else 422)

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
