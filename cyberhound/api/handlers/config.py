"""Configuración: API keys, integraciones (notificaciones, SIEM, ticketing), modo agente y reglas YARA."""
from __future__ import annotations

import dataclasses

from aiohttp import web

from cyberhound.api.common import (
    _read_json,
    _update_yara_rules,
)
from cyberhound.core import integrations, ssh_credentials
from cyberhound.core.logging import get_logger
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)
from cyberhound.core.paths import YARA_DIR

logger = get_logger("api")


class ConfigHandlers:
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

    # ── Integraciones: notificaciones, SIEM y ticketing ─────────────────────────

    def _tenant_obj(self):
        slug = current_tenant.get()
        if not self.cfg.multi_tenant.enabled or slug == DEFAULT_TENANT:
            return None
        return self.tenants.get(slug)

    def _integration_settings(self, kind: str):
        """Ajustes del canal para la organización actual (la plataforma: los de config.yaml)."""
        tenant = self._tenant_obj()
        if tenant is None:
            return getattr(self.cfg, kind)
        return integrations.settings_from_dict(kind, tenant.settings.get("integrations", {}).get(kind))

    def _integration(self, kind: str):
        slug = current_tenant.get() if self._tenant_obj() else DEFAULT_TENANT
        key = (slug, kind)
        if key not in self._integrations:
            settings = self._integration_settings(kind)
            mgr = integrations.build(kind, settings, db=self.db)
            if slug != DEFAULT_TENANT:
                allowed = self.tenants.get(slug).settings.get("allowed_targets", [])
                mgr = integrations.GuardedIntegration(kind, mgr, settings, allowed, logger)
            self._integrations[key] = mgr
        return self._integrations[key]

    @property
    def notification_manager(self):
        return self._integration("notifications")

    @property
    def siem(self):
        return self._integration("siem")

    @property
    def ticketing(self):
        return self._integration("ticketing")

    async def _get_integration(self, kind: str) -> web.Response:
        return web.json_response(integrations.public_view(kind, self._integration_settings(kind)))

    async def _save_integration(self, request: web.Request, kind: str) -> web.Response:
        body = await _read_json(request)
        settings = self._integration_settings(kind)
        try:
            integrations.apply_update(kind, settings, body)
        except ValueError as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)
        tenant = self._tenant_obj()
        if tenant is not None:
            if problem := await integrations.outbound_problem(kind, settings, tenant.settings.get("allowed_targets", [])):
                return web.json_response({"ok": False, "error": problem}, status=400)
            self.tenants.set_setting(tenant.slug, "integrations",
                                     {**tenant.settings.get("integrations", {}), kind: dataclasses.asdict(settings)})
        else:
            self.cfg.save()
        self._integrations.pop((tenant.slug if tenant else DEFAULT_TENANT, kind), None)   # se reconstruye con todo
        await self._audit(request, f"config_{kind}", kind)
        return web.json_response({"ok": True})

    async def _test_integration(self, kind: str) -> web.Response:
        return web.json_response(await self._integration(kind).test())

    async def api_get_notifications_cfg(self, request: web.Request) -> web.Response:
        return await self._get_integration("notifications")

    async def api_save_notifications_cfg(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "notifications")

    async def api_test_notifications(self, request: web.Request) -> web.Response:
        return await self._test_integration("notifications")

    async def api_get_siem(self, request: web.Request) -> web.Response:
        return await self._get_integration("siem")

    async def api_save_siem(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "siem")

    async def api_test_siem(self, request: web.Request) -> web.Response:
        return await self._test_integration("siem")

    async def api_get_ticketing(self, request: web.Request) -> web.Response:
        return await self._get_integration("ticketing")

    async def api_save_ticketing(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "ticketing")

    async def api_test_ticketing(self, request: web.Request) -> web.Response:
        return await self._test_integration("ticketing")

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
            # el AgentManager se creó al arrancar con una copia: sin esto la clave nueva no valía hasta reiniciar
            for field in ("mode", "manager_url", "agent_key", "agent_name"):
                setattr(self.agent_manager.cfg, field, getattr(a, field))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def api_agent_report(self, request: web.Request) -> web.Response:
        """Recibe hallazgos enviados por un agente remoto."""
        # Verificar clave del agente (no JWT)
        auth  = request.headers.get("Authorization", "")
        key   = self.agent_manager.extract_agent_key(auth)
        # Clave global (tenant "default") o la API key del tenant (la reconoce tenant_middleware)
        if not (request.get("tenant_agent_key") or self.agent_manager.verify_agent_key(key)):
            return web.json_response({"error": "Clave de agente inválida"}, status=401)
        try:
            payload = await _read_json(request)
            result  = await self.agent_manager.receive_report(payload)
            return web.json_response(result)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            logger.error("api_agent_report: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_agent_heartbeat(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        key  = self.agent_manager.extract_agent_key(auth)
        if not (request.get("tenant_agent_key") or self.agent_manager.verify_agent_key(key)):
            return web.json_response({"error": "Clave inválida"}, status=401)
        payload = await _read_json(request)
        await self.agent_manager.receive_heartbeat(payload)
        return web.json_response({"ok": True})

    async def api_agent_list(self, request: web.Request) -> web.Response:
        return web.json_response(self.agent_manager.list_agents())

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
        yara_dir = YARA_DIR
        yara_dir.mkdir(parents=True, exist_ok=True)
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

    # ── Credenciales SSH guardadas ────────────────────────────────────────────

    async def api_ssh_credentials_list(self, request: web.Request) -> web.Response:
        return web.json_response(await self.db.list_ssh_credentials())

    async def api_ssh_credentials_create(self, request: web.Request) -> web.Response:
        try:
            data = ssh_credentials.prepare(await _read_json(request), self._auth_secret, current_tenant.get())
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if await self.db.count_ssh_credentials() >= ssh_credentials.MAX_PER_TENANT:
            return web.json_response({"error": f"Máximo {ssh_credentials.MAX_PER_TENANT} credenciales"}, status=400)
        cid = await self.db.create_ssh_credential(data, created_by=request.get("auth_user", ""))
        await self._audit(request, "ssh_credential_create", data["name"],
                          f"{data['username']}, puerto {data['port']}, {data['fingerprint'] or 'contraseña'}")
        return web.json_response(ssh_credentials.public_view(await self.db.get_ssh_credential(cid)), status=201)

    async def api_ssh_credentials_update(self, request: web.Request) -> web.Response:
        cid = request.match_info["cid"]
        current = await self.db.get_ssh_credential(cid)
        if not current:
            return web.json_response({"error": "Credencial no encontrada"}, status=404)
        try:
            data = ssh_credentials.prepare(await _read_json(request), self._auth_secret, current_tenant.get(),
                                           partial=True)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        await self.db.update_ssh_credential(cid, data)
        await self._audit(request, "ssh_credential_update", current["name"], ",".join(sorted(data)))
        return web.json_response(ssh_credentials.public_view(await self.db.get_ssh_credential(cid)))

    async def api_ssh_credentials_delete(self, request: web.Request) -> web.Response:
        cid = request.match_info["cid"]
        current = await self.db.get_ssh_credential(cid)
        if not current:
            return web.json_response({"error": "Credencial no encontrada"}, status=404)
        if used := await self.db.schedules_using_credential(cid):
            return web.json_response({"error": "La usan estos análisis programados: " + ", ".join(used)}, status=409)
        await self.db.delete_ssh_credential(cid)
        await self._audit(request, "ssh_credential_delete", current["name"])
        return web.json_response({"ok": True})

    # ── Claves de host SSH conocidas (TOFU) ───────────────────────────────────

    async def api_ssh_host_keys_list(self, request: web.Request) -> web.Response:
        return web.json_response(await self.db.list_ssh_host_keys())

    async def api_ssh_host_keys_delete(self, request: web.Request) -> web.Response:
        """Olvida la clave guardada de host:puerto; la próxima conexión guarda la que presente."""
        host = request.match_info["host"]
        try:
            port = int(request.match_info["port"])
        except ValueError:
            return web.json_response({"error": "Puerto no válido"}, status=400)
        current = await self.db.get_ssh_host_key(host, port)
        if not current or not await self.db.delete_ssh_host_key(host, port):
            return web.json_response({"error": "Clave de host no encontrada"}, status=404)
        await self._audit(request, "ssh_hostkey_forget", f"{host}:{port}", current["fingerprint"])
        return web.json_response({"ok": True})
