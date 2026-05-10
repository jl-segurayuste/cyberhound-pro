"""
Autenticación para la API de CyberHound.

Niveles disponibles (configurables en config.yaml):
  - jwt:   JWT firmado con HS256. Recomendado para producción local.
  - basic: HTTP Basic Auth sobre HTTPS. Mínimo aceptable.
  - none:  Sin autenticación (solo para localhost en desarrollo).

NUNCA exponer sin autenticación en una red no aislada.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional

import jwt  # PyJWT
from aiohttp import web

from cyberhound.core.logging import audit_log, get_logger

logger = get_logger("auth")

# Cabecera estándar
AUTH_COOKIE = "ch_token"
AUTH_HEADER = "Authorization"

# Rutas que no requieren autenticación
PUBLIC_ROUTES = {"/health", "/login", "/static"}


class AuthConfig:
    def __init__(
        self,
        mode: str = "jwt",          # jwt | basic | none
        secret: Optional[str] = None,
        username: str = "admin",
        password_hash: Optional[str] = None,  # SHA-256 hex del password
        token_ttl_hours: int = 8,
        localhost_only: bool = False,
    ) -> None:
        self.mode = mode
        # Generar secreto aleatorio si no se provee (se pierde al reiniciar → sesiones cortas)
        self.secret = secret or secrets.token_hex(32)
        self.username = username
        self.password_hash = password_hash or self._default_hash()
        self.token_ttl = timedelta(hours=token_ttl_hours)
        self.localhost_only = localhost_only

    @staticmethod
    def _default_hash() -> str:
        """Hash del password por defecto 'cyberhound' — CAMBIAR EN PRODUCCIÓN."""
        return hashlib.sha256(b"cyberhound").hexdigest()

    def verify_password(self, password: str) -> bool:
        given_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(given_hash, self.password_hash)

    def issue_jwt(self, username: str) -> str:
        payload = {
            "sub": username,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + self.token_ttl,
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def verify_jwt(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, self.secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logger.warning("JWT expirado")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("JWT inválido: %s", e)
            return None


def _is_localhost(request: web.Request) -> bool:
    peer = request.transport and request.transport.get_extra_info("peername")
    if peer:
        ip = peer[0]
        return ip in ("127.0.0.1", "::1", "localhost")
    return False


def _extract_token(request: web.Request) -> Optional[str]:
    """Extrae el token de Authorization header o cookie."""
    # Bearer token en cabecera
    auth_header = request.headers.get(AUTH_HEADER, "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Cookie
    return request.cookies.get(AUTH_COOKIE)


def _extract_basic(request: web.Request) -> Optional[tuple[str, str]]:
    """Extrae usuario/password de Basic Auth."""
    auth_header = request.headers.get(AUTH_HEADER, "")
    if not auth_header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(auth_header[6:]).decode()
        user, _, pwd = decoded.partition(":")
        return user, pwd
    except Exception:
        return None


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """
    Middleware de autenticación para aiohttp.
    Se añade a la app en api/server.py.
    """
    cfg: AuthConfig = request.app["auth_config"]

    # Rutas públicas siempre pasan
    if any(request.path.startswith(p) for p in PUBLIC_ROUTES):
        return await handler(request)

    # Modo none: solo permitir desde localhost
    if cfg.mode == "none":
        if not _is_localhost(request):
            audit_log.auth_failure(
                str(request.remote), "modo=none pero petición no es localhost"
            )
            raise web.HTTPForbidden(reason="Solo acceso desde localhost en modo sin autenticación")
        return await handler(request)

    # Modo basic
    if cfg.mode == "basic":
        creds = _extract_basic(request)
        if not creds or creds[0] != cfg.username or not cfg.verify_password(creds[1]):
            audit_log.auth_failure(str(request.remote), "Basic Auth fallido")
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="CyberHound"'}
            )
        audit_log.auth_success(str(request.remote), creds[0])
        request["auth_user"] = creds[0]
        return await handler(request)

    # Modo JWT (por defecto)
    token = _extract_token(request)
    if not token:
        # Si la petición es del navegador y no tiene token → redirigir al login
        if "text/html" in request.headers.get("Accept", ""):
            raise web.HTTPFound("/login")
        raise web.HTTPUnauthorized(reason="Token JWT requerido")

    payload = cfg.verify_jwt(token)
    if not payload:
        audit_log.auth_failure(str(request.remote), "JWT inválido o expirado")
        raise web.HTTPUnauthorized(reason="Token JWT inválido o expirado")

    audit_log.auth_success(str(request.remote), payload["sub"])
    request["auth_user"] = payload["sub"]
    return await handler(request)


def setup_auth_routes(app: web.Application, cfg: AuthConfig) -> None:
    """Registra las rutas de login/logout en la app."""
    app["auth_config"] = cfg

    async def login_page(request: web.Request) -> web.Response:
        html = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>CyberHound — Login</title>
<style>
  body{background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;
       display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:320px}
  h2{text-align:center;color:#58a6ff;margin-bottom:24px}
  input{width:100%;background:#21262d;border:1px solid #30363d;color:#e6edf3;
        padding:9px 12px;border-radius:6px;font-size:.9rem;box-sizing:border-box;margin-bottom:12px}
  input:focus{outline:none;border-color:#58a6ff}
  button{width:100%;background:#58a6ff;color:#0d1117;border:none;padding:10px;
         border-radius:6px;font-weight:700;font-size:.95rem;cursor:pointer;margin-top:4px}
  button:hover{opacity:.85}
  .err{color:#f85149;font-size:.82rem;margin-top:8px;text-align:center}
  .logo{text-align:center;font-size:2rem;margin-bottom:8px}
</style></head>
<body><div class="box">
  <div class="logo">🐾</div>
  <h2>CyberHound Pro</h2>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Usuario" autocomplete="username" required>
    <input type="password" name="password" placeholder="Contraseña" autocomplete="current-password" required>
    <button type="submit">Entrar</button>
  </form>
  __ERROR__
</div></body></html>"""
        error = request.query.get("error", "")
        err_html = f'<p class="err">❌ {error}</p>' if error else ""
        return web.Response(text=html.replace("__ERROR__", err_html), content_type="text/html")

    async def login_post(request: web.Request) -> web.Response:
        try:
            data = await request.post()
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
        except Exception:
            raise web.HTTPBadRequest()

        if username != cfg.username or not cfg.verify_password(password):
            audit_log.auth_failure(str(request.remote), f"Login fallido para '{username}'")
            raise web.HTTPFound("/login?error=Credenciales+incorrectas")

        token = cfg.issue_jwt(username)
        audit_log.auth_success(str(request.remote), username)
        response = web.HTTPFound("/")
        response.set_cookie(
            AUTH_COOKIE, token,
            httponly=True, samesite="Strict",
            max_age=int(cfg.token_ttl.total_seconds()),
        )
        return response

    async def logout(request: web.Request) -> web.Response:
        response = web.HTTPFound("/login")
        response.del_cookie(AUTH_COOKIE)
        return response

    async def health(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "version": "6.0.0"})

    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_post)
    app.router.add_get("/logout", logout)
    app.router.add_get("/health", health)
