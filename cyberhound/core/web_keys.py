"""Claves tipadas de aiohttp para ``app[...]`` y ``request[...]``.

aiohttp recomienda ``web.AppKey``/``web.RequestKey`` en lugar de cadenas: evitan colisiones entre
módulos, dan tipos a mypy y no emiten ``NotAppKeyWarning``.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from cyberhound.api.server import CyberHoundServer
    from cyberhound.core.auth import AuthConfig

# ── Aplicación ───────────────────────────────────────────────────────────────
SERVER_KEY: web.AppKey[CyberHoundServer] = web.AppKey("server")
AUTH_CONFIG_KEY: web.AppKey[AuthConfig] = web.AppKey("auth_config")
RL_CLEANUP_KEY: web.AppKey[asyncio.Future[None]] = web.AppKey("_rl_cleanup")

# ── Petición (los rellenan los middlewares) ──────────────────────────────────
AUTH_USER = web.RequestKey("auth_user", str)
AUTH_TENANT = web.RequestKey("auth_tenant", str)
AUTH_JTI: web.RequestKey[str | None] = web.RequestKey("auth_jti")
AUTH_TOKEN_ID: web.RequestKey[str | None] = web.RequestKey("auth_token_id")
AUTH_TOKEN_ROLE: web.RequestKey[str | None] = web.RequestKey("auth_token_role")
TENANT = web.RequestKey("tenant", str)
SUPERADMIN = web.RequestKey("superadmin", bool)
USER_ROLE = web.RequestKey("user_role", str)
TENANT_AGENT_KEY = web.RequestKey("tenant_agent_key", bool)
CSP_NONCE = web.RequestKey("csp_nonce", str)
