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
from cyberhound.core.security import CsrfProtection, RateLimiter, _get_real_ip

logger = get_logger("auth")

# Cabecera estándar
AUTH_COOKIE = "ch_token"
AUTH_HEADER = "Authorization"

# Rutas que no requieren autenticación
PUBLIC_ROUTES = {"/health", "/login", "/static"}

# Rate limiter global para /login (5 intentos / 15 minutos)
_login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=900, block_seconds=900)
_csrf = CsrfProtection()


class AuthConfig:
    def __init__(
        self,
        mode: str = "jwt",
        secret: Optional[str] = None,
        username: str = "admin",
        password_hash: Optional[str] = None,
        token_ttl_hours: int = 8,
        localhost_only: bool = False,
    ) -> None:
        self.mode = mode
        # Secreto persistente — si no hay en config, se genera y se advierte
        if secret:
            self.secret = secret
        else:
            self.secret = secrets.token_hex(32)
            logger.warning(
                "JWT secret no configurado — se usará uno temporal que se invalida al reiniciar. "
                "Añade 'auth.secret' a config.yaml para sesiones persistentes."
            )
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
            # Nonce para invalidar tokens individuales si es necesario
            "jti": secrets.token_hex(8),
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
    auth_header = request.headers.get(AUTH_HEADER, "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get(AUTH_COOKIE)


def _extract_basic(request: web.Request) -> Optional[tuple[str, str]]:
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
    """Middleware de autenticación con rate limiting integrado."""
    cfg: AuthConfig = request.app["auth_config"]

    # Rutas públicas siempre pasan
    if any(request.path.startswith(p) for p in PUBLIC_ROUTES):
        return await handler(request)

    # Modo none: solo localhost
    if cfg.mode == "none":
        if not _is_localhost(request):
            audit_log.auth_failure(str(request.remote), "modo=none, no es localhost")
            raise web.HTTPForbidden(reason="Solo acceso desde localhost en modo sin autenticación")
        return await handler(request)

    # Modo basic con rate limiting
    if cfg.mode == "basic":
        ip = _get_real_ip(request)
        allowed, wait = await _login_rate_limiter.is_allowed(ip)
        if not allowed:
            raise web.HTTPTooManyRequests(
                reason=f"Demasiados intentos. Espera {wait}s.",
                headers={"Retry-After": str(wait)},
            )
        creds = _extract_basic(request)
        if not creds or creds[0] != cfg.username or not cfg.verify_password(creds[1]):
            await _login_rate_limiter.record_failure(ip)
            audit_log.auth_failure(ip, "Basic Auth fallido")
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="CyberHound"'}
            )
        await _login_rate_limiter.record_success(ip)
        audit_log.auth_success(ip, creds[0])
        request["auth_user"] = creds[0]
        return await handler(request)

    # Modo JWT
    token = _extract_token(request)
    if not token:
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
    """Registra las rutas de login/logout con rate limiting y CSRF."""
    app["auth_config"] = cfg

    # Tarea periódica de limpieza del rate limiter
    async def _cleanup_task():
        while True:
            await asyncio.sleep(300)  # cada 5 minutos
            await _login_rate_limiter.cleanup_expired()

    async def on_startup(app):
        app["_rl_cleanup"] = asyncio.ensure_future(_cleanup_task())

    async def on_cleanup(app):
        app["_rl_cleanup"].cancel()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    async def login_page(request: web.Request) -> web.Response:
        csrf_token = CsrfProtection.get_or_create_token(request)
        error = request.query.get("error", "")
        err_html = f'<p class="err">❌ {_h(error)}</p>' if error else ""
        html = _LOGIN_HTML.replace("__ERROR__", err_html).replace("__CSRF__", csrf_token)
        response = web.Response(text=html, content_type="text/html")
        CsrfProtection.inject_token(response, csrf_token)
        return response

    async def login_post(request: web.Request) -> web.Response:
        ip = _get_real_ip(request)

        # Rate limiting ANTES de procesar credenciales
        allowed, wait = await _login_rate_limiter.is_allowed(ip)
        if not allowed:
            logger.warning("Login bloqueado por rate limit: %s (espera %ds)", ip, wait)
            raise web.HTTPFound(f"/login?error=Demasiados+intentos.+Espera+{wait}+segundos.")

        try:
            data = await request.post()
            username = str(data.get("username", "")).strip()[:64]
            password = str(data.get("password", ""))
        except Exception:
            raise web.HTTPBadRequest()

        if username != cfg.username or not cfg.verify_password(password):
            blocked, block_time = await _login_rate_limiter.record_failure(ip)
            audit_log.auth_failure(ip, f"Login fallido para '{username}'")
            if blocked:
                raise web.HTTPFound(
                    f"/login?error=Cuenta+bloqueada+{block_time}+segundos+por+múltiples+intentos."
                )
            raise web.HTTPFound("/login?error=Credenciales+incorrectas")

        # Login exitoso
        await _login_rate_limiter.record_success(ip)
        token = cfg.issue_jwt(username)
        audit_log.auth_success(ip, username)

        response = web.HTTPFound("/")
        response.set_cookie(
            AUTH_COOKIE, token,
            httponly=True,
            samesite="Strict",
            secure=True,   # Solo enviar por HTTPS
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


def _h(s: str) -> str:
    """Escapar HTML básico para evitar XSS en mensajes de error."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


import asyncio  # noqa: E402 — import al final para evitar circular

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>CyberHound — Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;
       display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#161b22;border:1px solid #30363d;border-radius:12px;
       padding:40px;width:320px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  h2{text-align:center;color:#58a6ff;margin-bottom:24px;font-size:1.1rem}
  .logo{text-align:center;font-size:2.2rem;margin-bottom:8px}
  input[type=text],input[type=password]{
    width:100%;background:#21262d;border:1px solid #30363d;color:#e6edf3;
    padding:10px 12px;border-radius:6px;font-size:.9rem;
    box-sizing:border-box;margin-bottom:12px;outline:none}
  input:focus{border-color:#58a6ff}
  button{width:100%;background:#58a6ff;color:#0d1117;border:none;padding:11px;
         border-radius:6px;font-weight:700;font-size:.95rem;cursor:pointer;
         margin-top:4px;transition:opacity .15s}
  button:hover{opacity:.85}
  .err{color:#f85149;font-size:.82rem;margin-top:10px;text-align:center;
       background:rgba(248,81,73,.1);padding:8px;border-radius:6px}
  .hint{color:#8b949e;font-size:.72rem;text-align:center;margin-top:14px}
</style></head>
<body><div class="box">
  <div class="logo">🐾</div>
  <h2>CyberHound Pro</h2>
  <form method="POST" action="/login">
    <input type="hidden" name="_csrf" value="__CSRF__">
    <input type="text" name="username" placeholder="Usuario"
           autocomplete="username" required autofocus>
    <input type="password" name="password" placeholder="Contraseña"
           autocomplete="current-password" required>
    <button type="submit">Entrar</button>
  </form>
  __ERROR__
  <p class="hint">Conexión cifrada con TLS</p>
</div></body></html>"""

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
