"""Usuarios, la cuenta propia (contraseña, sesiones, tokens) y 2FA."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from aiohttp import web

from cyberhound.api.common import (
    ROLE_PERMISSIONS,
    _in_own_tenant,
    _own_tenant_ctx,
    _read_json,
)
from cyberhound.core import passwords
from cyberhound.core.auth import (
    cap_role,
    make_api_token,
)
from cyberhound.core.database import UserRecord
from cyberhound.core.logging import get_logger
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)
from cyberhound.core.security import (
    _get_real_ip,
)

logger = get_logger("api")


class AccountHandlers:
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
            if (username == self.cfg.auth.username and current_tenant.get() == DEFAULT_TENANT) \
                    or await self.db.get_user(username):
                return web.json_response({"error": f"El usuario '{username}' ya existe"}, status=409)
            pw_hash = passwords.hash_password(password)
            try:
                await self.db.create_user(UserRecord(
                    username=username, password_hash=pw_hash, role=role
                ))
            except Exception:
                # el borrado es lógico (active=0): reutilizar el nombre reactiva la fila
                await self.db.update_user(username, password_hash=pw_hash, role=role, active=1)
            logger.info("Usuario '%s' creado con rol '%s' por %s",
                        username, role, request.get("auth_user"))
            await self._audit(request, "user_create", username, f"rol={role}")
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_update(self, request: web.Request) -> web.Response:
        try:
            username = request.match_info["username"]
            body = await _read_json(request)
            if username in (request.get("auth_user"), self.cfg.auth.username) and (
                ("role" in body and body["role"] != "admin") or ("active" in body and not body["active"])
            ):
                return web.json_response(
                    {"error": "No puedes quitarte el rol de admin ni desactivar tu propio usuario"}, status=400,
                )
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
            if not await self._user_exists(username):
                return web.json_response({"error": "Usuario no encontrado"}, status=404)
            if updates:
                await self.db.update_user(username, **updates)
            if "password_hash" in updates or updates.get("active") == 0:
                # Contraseña nueva o cuenta desactivada: fuera todas sus sesiones y tokens
                await self.db.revoke_user_sessions(username)
                await self.db.revoke_user_api_tokens(username)
            await self._audit(request, "user_update", username,
                              ", ".join(f"{k}={'***' if k == 'password_hash' else v}" for k, v in updates.items()))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_delete(self, request: web.Request) -> web.Response:
        username = request.match_info["username"]
        current  = request.get("auth_user", "")
        if username in (current, self.cfg.auth.username):
            return web.json_response({"error": "No puedes eliminar tu propio usuario ni el admin principal"}, status=400)
        if not await self._user_exists(username):
            return web.json_response({"error": "Usuario no encontrado"}, status=404)
        await self.db.update_user(username, active=0)
        await self.db.revoke_user_sessions(username)
        await self.db.revoke_user_api_tokens(username)
        await self._audit(request, "user_delete", username)
        return web.json_response({"ok": True})

    async def api_users_revoke_sessions(self, request: web.Request) -> web.Response:
        """Admin: cierra todas las sesiones y tokens de un usuario (p. ej. si pierde el portátil)."""
        username = request.match_info["username"]
        if not await self._user_exists(username):
            return web.json_response({"error": "Usuario no encontrado"}, status=404)
        n = await self.db.revoke_user_sessions(username, keep_jti=request.get("auth_jti"))
        t = await self.db.revoke_user_api_tokens(username)
        await self._audit(request, "sessions_revoke", username, f"{n} sesiones, {t} tokens")
        return web.json_response({"ok": True, "sessions": n, "tokens": t})

    # ── Mi cuenta: contraseña, sesiones y tokens ──────────────────────────────

    async def _audit(self, request: web.Request, action: str, target: str = "", detail: str = "",
                     ok: bool = True, own: bool = False) -> None:
        """Evento de auditoría (Configuración › Auditoría) en la BD del tenant actual; con own=True en la
        del propio usuario: lo que el superadmin hace con su cuenta no aparece en la organización que mira."""
        try:
            args = (action, request.get("auth_user", "") or "", _get_real_ip(request), target, detail, ok)
            if own:
                await _in_own_tenant(request, "add_audit_event", *args)
            else:
                await self.db.add_audit_event(*args)
        except Exception as e:  # noqa: BLE001 — la auditoría nunca rompe la operación
            logger.warning("Auditoría: %s", e)

    def _browser_session_only(self, request: web.Request) -> web.Response | None:
        """Con un token de API no se gestionan credenciales (contraseña, 2FA, sesiones, tokens)."""
        if request.get("auth_token_id"):
            return web.json_response({"error": "Necesita una sesión de navegador, no un token de API"}, status=403)
        if not request.get("auth_user"):
            return web.json_response({"error": "Sin sesión"}, status=401)
        return None

    async def api_me_password(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        body = await _read_json(request)
        current, new = str(body.get("current", "")), str(body.get("new", ""))
        user = request["auth_user"]
        if len(new) < 8:
            return web.json_response({"error": "La contraseña nueva necesita 8 caracteres"}, status=400)
        platform_admin = bool(request.get("superadmin"))
        if platform_admin:
            ok = passwords.verify_password(current, self.cfg.auth.password_hash or "")
        else:
            db_user = await _in_own_tenant(request, "get_user", user)
            ok = bool(db_user) and passwords.verify_password(current, db_user.get("password_hash") or "")
        if not ok:
            await self._audit(request, "password_change", user, "contraseña actual incorrecta", ok=False, own=True)
            return web.json_response({"error": "La contraseña actual no es correcta"}, status=400)
        new_hash = passwords.hash_password(new)
        if platform_admin:   # el admin de la plataforma vive en config.yaml
            self.cfg.auth.password_hash = new_hash
            request.app["auth_config"].password_hash = new_hash
            self.cfg.save()
        await _in_own_tenant(request, "update_user", user, password_hash=new_hash)
        n = await _in_own_tenant(request, "revoke_user_sessions", user, keep_jti=request.get("auth_jti"))
        await self._audit(request, "password_change", user, f"{n} sesiones cerradas", own=True)
        return web.json_response({"ok": True, "sessions_closed": n})

    async def api_sessions_list(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        jti = request.get("auth_jti")
        rows = await _in_own_tenant(request, "list_sessions", request["auth_user"])
        return web.json_response([{**{k: v for k, v in r.items() if k != "jti"}, "id": r["jti"][:8],
                                   "current": r["jti"] == jti} for r in rows])

    async def api_session_revoke(self, request: web.Request) -> web.Response:
        """Cierra una sesión propia por su id corto (los 8 primeros caracteres)."""
        if err := self._browser_session_only(request):
            return err
        short = request.match_info["jti"]
        own = await _in_own_tenant(request, "list_sessions", request["auth_user"])
        mine = [r["jti"] for r in own if r["jti"].startswith(short)]
        if len(short) < 8 or len(mine) != 1:
            return web.json_response({"error": "Sesión no encontrada"}, status=404)
        await _in_own_tenant(request, "revoke_session", mine[0], request["auth_user"])
        await self._audit(request, "session_revoke", request["auth_user"], short, own=True)
        return web.json_response({"ok": True, "current": mine[0] == request.get("auth_jti")})

    async def api_sessions_revoke_others(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        n = await _in_own_tenant(request, "revoke_user_sessions", request["auth_user"],
                                 keep_jti=request.get("auth_jti"))
        await self._audit(request, "sessions_revoke", request["auth_user"], f"{n} sesiones (menos la actual)", own=True)
        return web.json_response({"ok": True, "closed": n})

    async def api_tokens_list(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        return web.json_response(await _in_own_tenant(request, "list_api_tokens", request["auth_user"]))

    async def api_tokens_create(self, request: web.Request) -> web.Response:
        """Token de API para scripts/CI. El secreto solo se muestra ahora; se guarda su hash."""
        if err := self._browser_session_only(request):
            return err
        body = await _read_json(request)
        name = str(body.get("name", "")).strip()
        role = str(body.get("role") or request.get("user_role", "viewer"))
        days = body.get("expires_days", 90)
        if not name:
            return web.json_response({"error": "Ponle un nombre al token"}, status=400)
        if role not in ROLE_PERMISSIONS or cap_role(request.get("user_role", "viewer"), role) != role:
            return web.json_response({"error": "El token no puede tener más permisos que tu rol"}, status=400)
        if days not in (None, 0) and not (isinstance(days, int) and 1 <= days <= 365):
            return web.json_response({"error": "Caducidad entre 1 y 365 días (o sin caducidad)"}, status=400)
        token, token_id, token_hash = make_api_token(request.get("auth_tenant", DEFAULT_TENANT))
        expires = (datetime.now(UTC) + timedelta(days=days)).isoformat() if days else None
        await _in_own_tenant(request, "create_api_token", token_id, request["auth_user"], name,
                             token_hash, role, expires)
        await self._audit(request, "token_create", name, f"rol={role} caduca={expires or 'nunca'}", own=True)
        return web.json_response({"id": token_id, "token": token, "role": role, "expires_at": expires}, status=201)

    async def api_token_revoke(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        tid = request.match_info["token_id"]
        if not await _in_own_tenant(request, "revoke_api_token", tid, request["auth_user"]):
            return web.json_response({"error": "Token no encontrado"}, status=404)
        await self._audit(request, "token_revoke", tid, own=True)
        return web.json_response({"ok": True})

    async def api_audit_list(self, request: web.Request) -> web.Response:
        """Eventos de auditoría de la organización actual, con filtros."""
        q = request.rel_url.query
        try:
            limit = int(q.get("limit", "200"))
        except ValueError:
            return web.json_response({"error": "limit debe ser un entero"}, status=400)
        return web.json_response(await self.db.list_audit_events(
            limit=limit, action=q.get("action", ""), username=q.get("user", ""), q=q.get("q", ""),
            only_failures=q.get("failures") in ("1", "true")))

    async def _user_exists(self, username: str) -> bool:
        """Incluye desactivados (se pueden reactivar). Antes un usuario inexistente daba 200."""
        return any(u["username"] == username for u in await self.db.list_users())

    # ── 2FA / TOTP ────────────────────────────────────────────────────────────

    async def api_2fa_setup(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_setup(request)

    async def _api_2fa_setup(self, request: web.Request) -> web.Response:
        """Inicia la configuración de 2FA — devuelve QR y secreto."""
        if err := self._browser_session_only(request):
            return err
        user = request.get("auth_user", "")
        if not user:
            return web.json_response({"error": "Sin sesión"}, status=401)
        from cyberhound.core.totp import TOTPManager
        mgr = TOTPManager(self.db, request.app["auth_config"].secret)
        data = await mgr.setup_2fa(user)
        return web.json_response({
            "secret":         data["secret"],
            "uri":            data["uri"],
            "qr_svg":         data["qr_svg"],
            "recovery_codes": data["recovery_codes"],
        })

    async def api_2fa_activate(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_activate(request)

    async def _api_2fa_activate(self, request: web.Request) -> web.Response:
        """Activa el 2FA verificando el primer código."""
        if err := self._browser_session_only(request):
            return err
        user = request.get("auth_user", "")
        try:
            body = await _read_json(request)
            code = str(body.get("code", "")).strip()
        except Exception:
            return web.json_response({"ok": False, "error": "Body inválido"}, status=400)
        from cyberhound.core.totp import TOTPManager
        ok = await TOTPManager(self.db, request.app["auth_config"].secret).activate_2fa(user, code)
        if ok:
            logger.info("2FA activado para '%s'", user)
        await self._audit(request, "2fa_enable", user, "" if ok else "código incorrecto", ok=ok, own=True)
        return web.json_response({"ok": ok, "error": None if ok else "Código incorrecto"}, status=200 if ok else 400)

    async def api_2fa_disable(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_disable(request)

    async def _api_2fa_disable(self, request: web.Request) -> web.Response:
        """Desactiva el 2FA del usuario actual: exige un código válido (TOTP o de recuperación).
        Antes no pedía nada y quien tuviera una sesión robada podía quitar el 2FA de la cuenta."""
        user = request.get("auth_user", "")
        if err := self._browser_session_only(request):
            return err
        from cyberhound.core.totp import TOTPManager
        mgr = TOTPManager(self.db, request.app["auth_config"].secret)
        status = await self.db.get_user(user)
        if status and status.get("totp_enabled"):
            code = str((await _read_json(request)).get("code", "")).strip()
            ok, _reason = await mgr.verify(user, code)
            if not ok:
                await self._audit(request, "2fa_disable", user, "código incorrecto", ok=False, own=True)
                return web.json_response({"ok": False, "error": "Código incorrecto"}, status=400)
        await mgr.disable_2fa(user)
        logger.info("2FA desactivado para '%s'", user)
        await self._audit(request, "2fa_disable", user, own=True)
        return web.json_response({"ok": True})

    async def api_2fa_status(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_status(request)

    async def _api_2fa_status(self, request: web.Request) -> web.Response:
        """Devuelve el estado del 2FA del usuario actual."""
        user = request.get("auth_user", "")
        db_user = await self.db.get_user(user) if user else None
        enabled = bool(db_user.get("totp_enabled")) if db_user else False
        return web.json_response({"enabled": enabled, "user": user})
