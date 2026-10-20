"""Tokens y rutas públicas.

Bug real corregido 2026-10-20 (bypass del 2FA): el token intermedio "contraseña OK,
falta el código" se firma con el mismo secreto que el de sesión y auth_middleware no
miraba su `purpose`. Quien supiera la contraseña recibía la cookie ch_2fa_pending y,
enviándola como "Authorization: Bearer …" o como ch_token, entraba sin código.
"""
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords, totp
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import UserRecord
from cyberhound.core.totp import TOTPManager

_PW = "clave-de-prueba-2fa"


@pytest_asyncio.fixture
async def server(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.db_path = str(tmp_path / "tok.db")
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password("otra-clave-admin")
    cfg.auth.secret = "s" * 64
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    await srv.db.create_user(UserRecord(username="ana", password_hash=passwords.hash_password(_PW), role="admin"))
    secret = totp.generate_secret()
    await srv.db.set_totp_pending("ana", secret, totp.generate_recovery_codes())
    await TOTPManager(srv.db).activate_2fa("ana", totp.generate_totp(secret))
    return srv


async def _client(server):
    c = TestClient(TestServer(server.build_app()))
    await c.start_server()
    return c


async def test_token_pendiente_de_2fa_no_sirve_como_sesion(server):
    c = await _client(server)
    try:
        await c.get("/login")
        csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
        r = await c.post("/login", data={"username": "ana", "password": _PW, "_csrf": csrf}, allow_redirects=False)
        assert r.headers["Location"] == "/login"
        pending = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_2fa_pending").value
        bearer = await c.get("/api/history", headers={"Authorization": f"Bearer {pending}"}, allow_redirects=False)
        assert bearer.status == 401
        c.session.cookie_jar.update_cookies({"ch_token": pending})
        assert (await c.get("/api/history", allow_redirects=False)).status == 401
    finally:
        await c.close()


async def test_rutas_publicas_son_exactas(server):
    c = await _client(server)
    try:
        assert (await c.get("/health")).status == 200
        assert (await c.get("/healthz", allow_redirects=False)).status in (401, 404)
        assert (await c.get("/loginx", allow_redirects=False)).status in (401, 404)
    finally:
        await c.close()


async def test_metrics_requiere_sesion_salvo_desde_loopback(server, monkeypatch):
    from cyberhound.core import auth
    c = await _client(server)
    try:
        monkeypatch.setattr(auth, "_is_localhost", lambda request: False)
        assert (await c.get("/metrics", allow_redirects=False)).status == 401
        monkeypatch.setattr(auth, "_is_localhost", lambda request: True)
        assert (await c.get("/metrics")).status == 200   # Prometheus en el propio host
    finally:
        await c.close()


def test_sin_hash_configurado_no_vale_la_clave_por_defecto():
    from cyberhound.core.auth import AuthConfig
    assert not AuthConfig(password_hash=None, secret="x" * 32).verify_password("cyberhound")
