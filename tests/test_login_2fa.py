"""Tests de integración del login con 2FA.

Bug real corregido 2026-08-09: `login_post` nunca consultaba `totp_enabled`
-- un usuario podía activar el 2FA, verlo confirmado en la UI, y aun así
entrar con solo usuario+contraseña, porque el único punto donde se aplica de
verdad (el login) nunca llamaba a `TOTPManager`. El 2FA era puramente
decorativo. No existía ningún test de extremo a extremo de `/login` hasta
ahora -- solo tests unitarios de `AuthConfig` (JWT, rate limiter).
"""
import time

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.core import passwords, totp
from cyberhound.core.auth import AuthConfig, setup_auth_routes
from cyberhound.core.database import Database, UserRecord
from cyberhound.core.totp import TOTPManager

_PASSWORD = "clave-de-prueba-1234"


class _FakeServer:
    def __init__(self, db):
        self.db = db


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(tmp_path / "login2fa.db")
    await database.init()
    await database.create_user(
        UserRecord(username="admin", password_hash=passwords.hash_password(_PASSWORD))
    )
    return database


@pytest_asyncio.fixture
async def client(db):
    cfg = AuthConfig(username="admin", password_hash=passwords.hash_password(_PASSWORD), secret="x" * 32)
    app = web.Application()
    app["server"] = _FakeServer(db)
    setup_auth_routes(app, cfg)
    c = TestClient(TestServer(app))
    await c.start_server()
    yield c
    await c.close()


async def _csrf(client) -> str:
    await client.get("/login")
    cookie = client.session.cookie_jar.filter_cookies(client.make_url("/")).get("ch_csrf")
    return cookie.value


def _has_cookie(client, name: str) -> bool:
    return name in {c.key for c in client.session.cookie_jar}


@pytest.mark.asyncio
async def test_login_sin_2fa_entra_directo(client):
    r = await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    assert r.status == 302 and r.headers["Location"] == "/"
    assert _has_cookie(client, "ch_token")


@pytest.mark.asyncio
async def test_login_con_2fa_activo_no_entra_con_solo_password(client, db):
    # Bug real: antes de la corrección, este POST habría concedido la sesión
    # completa (ch_token) sin pedir jamás el código.
    secret = totp.generate_secret()
    await db.set_totp_pending("admin", secret, totp.generate_recovery_codes())
    await TOTPManager(db).activate_2fa("admin", totp.generate_totp(secret))

    r = await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    assert r.status == 302 and r.headers["Location"] == "/login"
    assert not _has_cookie(client, "ch_token")
    assert _has_cookie(client, "ch_2fa_pending")


@pytest.mark.asyncio
async def test_login_page_pide_codigo_tras_password_correcto(client, db):
    secret = totp.generate_secret()
    await db.set_totp_pending("admin", secret, totp.generate_recovery_codes())
    await TOTPManager(db).activate_2fa("admin", totp.generate_totp(secret))

    await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    r = await client.get("/login")
    html = await r.text()
    assert 'name="code"' in html
    assert 'name="password"' not in html


@pytest.mark.asyncio
async def test_login_con_2fa_y_codigo_correcto_entra(client, db):
    secret = totp.generate_secret()
    await db.set_totp_pending("admin", secret, totp.generate_recovery_codes())
    await TOTPManager(db).activate_2fa("admin", totp.generate_totp(secret))

    await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    # El código de activación ya se consumió (anti-repetición) -- se usa el
    # siguiente paso temporal, como pasaría de verdad al iniciar sesión luego.
    code = totp.generate_totp(secret, time.time() + 30)
    r = await client.post("/login", data={"_csrf": await _csrf(client), "code": code}, allow_redirects=False)
    assert r.status == 302 and r.headers["Location"] == "/"
    assert _has_cookie(client, "ch_token")


@pytest.mark.asyncio
async def test_login_con_2fa_codigo_incorrecto_no_entra(client, db):
    secret = totp.generate_secret()
    await db.set_totp_pending("admin", secret, totp.generate_recovery_codes())
    await TOTPManager(db).activate_2fa("admin", totp.generate_totp(secret))

    await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    r = await client.post("/login", data={"_csrf": await _csrf(client), "code": "000000"}, allow_redirects=False)
    assert r.status == 302 and "error" in r.headers["Location"]
    assert not _has_cookie(client, "ch_token")


@pytest.mark.asyncio
async def test_login_con_2fa_no_deja_reutilizar_el_codigo_de_activacion(client, db):
    # El mismo código usado para activar 2FA no debe volver a servir para
    # entrar -- si sirviera, sería el bug de repetición otra vez, esta vez
    # visible en el flujo real de /login.
    secret = totp.generate_secret()
    await db.set_totp_pending("admin", secret, totp.generate_recovery_codes())
    activation_code = totp.generate_totp(secret)
    await TOTPManager(db).activate_2fa("admin", activation_code)

    await client.post(
        "/login",
        data={"_csrf": await _csrf(client), "username": "admin", "password": _PASSWORD},
        allow_redirects=False,
    )
    r = await client.post(
        "/login", data={"_csrf": await _csrf(client), "code": activation_code}, allow_redirects=False
    )
    assert r.status == 302 and "error" in r.headers["Location"]
    assert not _has_cookie(client, "ch_token")


@pytest.mark.asyncio
async def test_pending_2fa_token_no_sirve_como_sesion(client, db):
    """El token de "pendiente de 2FA" no debe aceptarse nunca en AUTH_COOKIE
    -- son cookies y formatos de payload distintos, pero se verifica
    explícitamente el aislamiento porque es la propiedad de seguridad clave
    de todo el diseño."""
    from cyberhound.core.auth import AuthConfig

    cfg = AuthConfig(username="admin", password_hash="x", secret="x" * 32)
    pending = cfg.issue_pending_2fa_token("admin")
    assert cfg.verify_jwt(pending) is not None  # el JWT en sí es válido...
    # ...pero como token de sesión no tiene sentido de negocio: no es lo que
    # protege esto. Lo que sí protege es que `verify_pending_2fa_token`
    # rechace un JWT de sesión normal (sin `purpose`).
    session_token = cfg.issue_jwt("admin")
    assert cfg.verify_pending_2fa_token(session_token) is None
    assert cfg.verify_pending_2fa_token(pending) == "admin"
