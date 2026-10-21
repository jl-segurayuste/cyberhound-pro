"""Scheduler de la plataforma y análisis programados de cada organización."""
from __future__ import annotations

import asyncio
from datetime import datetime

from aiohttp import web

from cyberhound.api.common import (
    ROLE_PERMISSIONS,
    WS_RUNNERS,
    _read_json,
)
from cyberhound.core import schedules
from cyberhound.core.logging import get_logger
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)
from cyberhound.core.scheduler import ENTRY_FLAGS
from cyberhound.core.scope import ws_targets as scope_targets

logger = get_logger("api")


class ScheduleHandlers:
    # ── Scheduler ─────────────────────────────────────────────────────────────

    async def api_scheduler_list(self, request: web.Request) -> web.Response:
        if not self.scheduler:
            return web.json_response([])
        return web.json_response(self.scheduler.list_entries())

    async def api_me(self, request: web.Request) -> web.Response:
        """Usuario de la sesión, su rol y permisos (la UI desactiva lo que daría 403)."""
        role = request.get("user_role", "admin")   # sin auth (localhost) todo está permitido
        slug = current_tenant.get()
        tenant = self.tenants.get(slug)
        return web.json_response({
            "username": request.get("auth_user", ""), "role": role,
            "permissions": sorted(ROLE_PERMISSIONS.get(role, set())),
            "multi_tenant": self.cfg.multi_tenant.enabled,
            "tenant": slug, "tenant_name": tenant.name if tenant else "Plataforma",
            "superadmin": bool(request.get("superadmin")) or not request.get("auth_user"),
            # False = la UI oculta lo que actúa sobre el servidor o es configuración global
            "host_access": self._may_touch_host(request),
        })

    async def api_scheduler_run(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if not self.scheduler:
            return web.json_response({"error": "Scheduler no activo"}, status=503)
        ok = await self.scheduler.run_now(name)
        return web.json_response({"ok": ok, "error": "Tarea no encontrada" if not ok else None}, status=200 if ok else 404)

    async def api_scheduler_toggle(self, request: web.Request) -> web.Response:
        try:
            name = request.match_info["name"]
            body = await _read_json(request)
            enabled = bool(body.get("enabled", True))
            if not self.scheduler:
                return web.json_response({"error": "Scheduler no activo"}, status=503)
            ok = self.scheduler.enable(name, enabled)
            if ok and name in ENTRY_FLAGS:          # que sobreviva a un reinicio
                setattr(self.cfg.scheduler, ENTRY_FLAGS[name], enabled)
                self.cfg.save()
            return web.json_response({"ok": ok}, status=200 if ok else 404)
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Análisis programados (de cada organización) ───────────────────────────

    async def api_schedules_list(self, request: web.Request) -> web.Response:
        rows = await self.db.list_schedules()
        running = {sid for slug, sid in self._schedules_running if slug == current_tenant.get()}
        return web.json_response([{**r, "running": r["id"] in running} for r in rows])

    async def _schedule_problem(self, data: dict) -> str | None:
        cred = data.get("ssh_credential")
        try:
            schedules.check_credential(data["task"], cred)
            schedules.check_targets(data["task"], data["targets"], cred)
        except ValueError as e:
            return str(e)
        if err := await self._ssh_credential_error(cred):
            return err
        return await self._out_of_scope(scope_targets(schedules.ws_message(data["task"], data["targets"], cred)))

    async def api_schedules_create(self, request: web.Request) -> web.Response:
        try:
            data = schedules.validate(await _read_json(request))
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if err := await self._schedule_problem(data):
            return web.json_response({"error": err}, status=400)
        if await self.db.count_schedules() >= schedules.MAX_PER_TENANT:
            return web.json_response({"error": f"Máximo {schedules.MAX_PER_TENANT} programaciones"}, status=400)
        sid = await self.db.create_schedule(data, created_by=request.get("auth_user", ""))
        await self._audit(request, "schedule_create", data["name"], f"{data['task']} {','.join(data['targets'])[:150]}")
        return web.json_response(await self.db.get_schedule(sid), status=201)

    async def api_schedules_update(self, request: web.Request) -> web.Response:
        sid = request.match_info["sid"]
        current = await self.db.get_schedule(sid)
        if not current:
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        try:
            data = schedules.validate(await _read_json(request), partial=True)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if {"task", "targets", "ssh_credential"} & data.keys():
            if err := await self._schedule_problem({**current, **data}):
                return web.json_response({"error": err}, status=400)
        await self.db.update_schedule(sid, data)
        await self._audit(request, "schedule_update", current["name"], ",".join(sorted(data)))
        return web.json_response(await self.db.get_schedule(sid))

    async def api_schedules_delete(self, request: web.Request) -> web.Response:
        sid = request.match_info["sid"]
        current = await self.db.get_schedule(sid)
        if not current or not await self.db.delete_schedule(sid):
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        await self._audit(request, "schedule_delete", current["name"])
        return web.json_response({"ok": True})

    async def api_schedules_run(self, request: web.Request) -> web.Response:
        sched = await self.db.get_schedule(request.match_info["sid"])
        if not sched:
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        slug = current_tenant.get()
        if (slug, sched["id"]) in self._schedules_running:
            return web.json_response({"error": "Ya se está ejecutando"}, status=409)
        self._start_schedule(slug, sched, triggered_by=request.get("auth_user", "manual"))
        await self._audit(request, "schedule_run", sched["name"])
        return web.json_response({"ok": True, "started": True}, status=202)

    def _schedule_slugs(self) -> list[str]:
        slugs = [DEFAULT_TENANT]
        if self.cfg.multi_tenant.enabled:
            slugs += [t.slug for t in self.tenants.list()]
        return slugs

    async def _schedules_tick(self, now: datetime | None = None) -> list[asyncio.Task]:
        """Lanza las programaciones que tocan en este minuto (hora local, como el scheduler)."""
        now = now or datetime.now()
        started = []
        for slug in self._schedule_slugs():
            ctx = current_tenant.set(slug)
            try:
                for sched in await self.db.list_schedules():
                    if schedules.is_due(sched, now) and (slug, sched["id"]) not in self._schedules_running:
                        started.append(self._start_schedule(slug, sched, triggered_by="schedule", now=now))
            except Exception as e:  # noqa: BLE001 — una organización con la BD rota no para a las demás
                logger.error("Programaciones de %s: %s", slug, e)
            finally:
                current_tenant.reset(ctx)
        return started

    async def _schedules_loop(self) -> None:
        while True:
            try:
                await self._schedules_tick()
            except Exception as e:  # noqa: BLE001
                logger.error("Bucle de programaciones: %s", e, exc_info=True)
            now = datetime.now()
            await asyncio.sleep(60 - now.second - now.microsecond / 1_000_000)

    def _start_schedule(self, slug: str, sched: dict, triggered_by: str, now: datetime | None = None) -> asyncio.Task:
        key = (slug, sched["id"])
        self._schedules_running.add(key)
        ctx = current_tenant.set(slug)        # la tarea hereda el contexto: BD e integraciones del tenant
        try:
            task = asyncio.ensure_future(self._run_schedule(slug, sched, triggered_by, now or datetime.now()))
        finally:
            current_tenant.reset(ctx)
        task.add_done_callback(lambda _t: self._schedules_running.discard(key))
        return task

    async def _run_schedule(self, slug: str, sched: dict, triggered_by: str, now: datetime) -> None:
        when = now.isoformat(timespec="seconds")
        await self.db.mark_schedule_run(sched["id"], when, "en curso", None)
        scan_id = None
        try:
            msg = schedules.ws_message(sched["task"], sched["targets"], sched.get("ssh_credential"))
            if err := await self._out_of_scope(scope_targets(msg)):   # el ámbito pudo cambiar después
                await self.db.mark_schedule_run(sched["id"], when, f"fuera de ámbito: {err}", None)
                return
            scan_id = await self.db.create_scan(sched["task"], triggered_by=f"schedule:{triggered_by}")
            ws_id = f"sched:{slug}:{sched['id']}:{scan_id}"
            self._scan_id_cache[ws_id] = scan_id
            seen: dict = {"findings": [], "error": ""}

            async def send(m: dict) -> None:
                if m.get("type") == "finding":
                    seen["findings"].append(m["data"].get("severity"))
                elif m.get("type") == "error":
                    seen["error"] = m.get("text", "")

            async def log(level: str, text: str) -> None:
                return None

            try:
                await getattr(self, WS_RUNNERS[sched["task"]])(msg, ws_id, send, log, scan_id)
            finally:
                self._findings_cache.pop(ws_id, None)
                self._scan_id_cache.pop(ws_id, None)
            crit = seen["findings"].count("critical")
            status = f"error: {seen['error']}" if seen["error"] else f"ok: {len(seen['findings'])} hallazgos"
            await self.db.mark_schedule_run(sched["id"], when, status, scan_id)
            if crit:
                await self.notification_manager.send(
                    f"⏰ {sched['name']}: {crit} hallazgo(s) CRÍTICO(S)", level="critical", scan_id=scan_id)
        except Exception as e:  # noqa: BLE001
            logger.error("Programación %s/%s: %s", slug, sched["id"], e, exc_info=True)
            if scan_id:
                await self.db.fail_scan(scan_id)
            await self.db.mark_schedule_run(sched["id"], when, f"error: {e}", scan_id)
