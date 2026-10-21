"""Sesiones revocables, tokens de API, cambio de contraseña y auditoría, sobre la app real.

Antes de 2026-10-21 salir o cambiar la contraseña solo borraba la cookie: un token robado valía hasta
caducar (8 h). Desactivar el 2FA tampoco pedía código: bastaba una sesión robada para quitarlo.
"""
import time

import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords, totp
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import UserRecord

ADMIN_PW, PW = "clave-admin-1234", "clave-usuaria-1234"


@pytest_asyncio.fixture
async def server(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.config_path = tmp_path / "config.yaml"
    cfg.db_path = str(tmp_path / "s.db")
    cfg.server.log_dir = str(tmp_path)
    cfg.auth.username, cfg.auth.secret = "admin", "s" * 64
    cfg.auth.password_hash = passwords.hash_password(ADMIN_PW)
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    await srv.db.ensure_admin_exists("admin", cfg.auth.password_hash)
    await srv.db.create_user(UserRecord(username="ana", password_hash=passwords.hash_password(PW), role="operator"))
    return srv


@pytest_asyncio.fixture
async def clients(server):
    opened = []

    async def login(user, pw):
        c = TestClient(TestServer(server.build_app()))
        await c.start_server()
        opened.append(c)
        await c.get("/login")
        csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
        r = await c.post("/login", data={"username": user, "password": pw, "_csrf": csrf}, allow_redirects=False)
        c.location = r.headers.get("Location")
        return c

    async def anon():
        c = TestClient(TestServer(server.build_app()))
        await c.start_server()
        opened.append(c)
        return c
    login.anon = anon
    yield login
    for c in opened:
        await c.close()


def _cookie(c, name="ch_token"):
    ck = c.session.cookie_jar.filter_cookies(c.make_url("/")).get(name)
    return ck.value if ck else None


async def test_logout_revoca_la_sesion_aunque_se_copie_la_cookie(clients):
    a = await clients("ana", PW)
    stolen = _cookie(a)
    other = await clients.anon()
    assert (await other.get("/api/me", headers={"Authorization": f"Bearer {stolen}"})).status == 200
    await a.get("/logout", allow_redirects=False)
    assert (await other.get("/api/me", headers={"Authorization": f"Bearer {stolen}"})).status == 401


async def test_mis_sesiones_y_cerrar_las_demas(clients):
    a1, a2 = await clients("ana", PW), await clients("ana", PW)
    ss = await (await a1.get("/api/sessions")).json()
    assert len(ss) == 2 and sum(s["current"] for s in ss) == 1 and all("jti" not in s for s in ss)
    r = await a1.post("/api/sessions/revoke-others")
    assert (await r.json())["closed"] == 1
    assert (await a1.get("/api/me")).status == 200 and (await a2.get("/api/me")).status == 401
    me = [s for s in await (await a1.get("/api/sessions")).json() if s["current"]][0]
    assert (await a1.delete(f"/api/sessions/{me['id']}")).status == 200
    assert (await a1.get("/api/me")).status == 401
    assert (await a1.delete("/api/sessions/x")).status in (401, 404)


async def test_cambiar_mi_contrasena(clients, server):
    a1, a2 = await clients("ana", PW), await clients("ana", PW)
    assert (await a1.post("/api/me/password", json={"current": "mala", "new": "nueva-clave-99"})).status == 400
    assert (await a1.post("/api/me/password", json={"current": PW, "new": "corta"})).status == 400
    r = await a1.post("/api/me/password", json={"current": PW, "new": "nueva-clave-99"})
    assert r.status == 200 and (await r.json())["sessions_closed"] == 1
    assert (await a1.get("/api/me")).status == 200 and (await a2.get("/api/me")).status == 401
    assert (await clients("ana", "nueva-clave-99")).location == "/"
    assert "error" in (await clients("ana", PW)).location


async def test_admin_de_la_plataforma_cambia_su_contrasena(clients, server):
    adm = await clients("admin", ADMIN_PW)
    assert (await adm.post("/api/me/password", json={"current": ADMIN_PW, "new": "otra-admin-77"})).status == 200
    assert passwords.verify_password("otra-admin-77", server.cfg.auth.password_hash)
    assert (await clients("admin", "otra-admin-77")).location == "/"


async def test_admin_cierra_todo_de_un_usuario_y_desactivar_o_cambiar_clave_tambien(clients):
    adm, ana = await clients("admin", ADMIN_PW), await clients("ana", PW)
    tok = (await (await ana.post("/api/tokens", json={"name": "ci"})).json())["token"]
    r = await adm.delete("/api/users/ana/sessions")
    assert (await r.json()) == {"ok": True, "sessions": 1, "tokens": 1}
    assert (await ana.get("/api/me")).status == 401
    anon = await clients.anon()
    assert (await anon.get("/api/me", headers={"Authorization": f"Bearer {tok}"})).status == 401
    ana2 = await clients("ana", PW)
    await adm.patch("/api/users/ana", json={"password": "reseteada-1234"})
    assert (await ana2.get("/api/me")).status == 401


async def test_tokens_de_api(clients):
    ana = await clients("ana", PW)
    r = await ana.post("/api/tokens", json={"name": "backup", "role": "viewer", "expires_days": 30})
    assert r.status == 201
    d = await r.json()
    assert d["token"].startswith("cht_default.") and d["role"] == "viewer"
    anon = await clients.anon()
    h = {"Authorization": f"Bearer {d['token']}"}
    me = await (await anon.get("/api/me", headers=h)).json()
    assert me["username"] == "ana" and me["role"] == "viewer"          # tope de rol del token
    assert (await anon.get("/api/history", headers=h)).status == 200
    assert (await anon.post("/api/suppressions", json={"pattern": "x", "reason": "r"}, headers=h)).status == 403
    # con un token no se gestionan credenciales
    for m, path in (("POST", "/api/tokens"), ("GET", "/api/sessions"), ("POST", "/api/me/password"),
                    ("POST", "/api/auth/2fa/setup"), ("POST", "/api/auth/2fa/disable")):
        assert (await anon.request(m, path, json={}, headers=h)).status == 403, path
    listed = await (await ana.get("/api/tokens")).json()
    assert [t["name"] for t in listed] == ["backup"] and "token_hash" not in listed[0] and listed[0]["last_used"]
    assert (await ana.delete(f"/api/tokens/{d['id']}")).status == 200
    assert (await anon.get("/api/me", headers=h)).status == 401
    bad = d["token"][:-3] + "xyz"
    assert (await anon.get("/api/me", headers={"Authorization": f"Bearer {bad}"})).status == 401


async def test_token_no_supera_el_rol_ni_caduca_mal(clients):
    ana = await clients("ana", PW)   # operator
    assert (await ana.post("/api/tokens", json={"name": "x", "role": "admin"})).status == 400
    assert (await ana.post("/api/tokens", json={"name": ""})).status == 400
    assert (await ana.post("/api/tokens", json={"name": "x", "expires_days": 999})).status == 400
    d = await (await ana.post("/api/tokens", json={"name": "sin-caducidad", "expires_days": 0})).json()
    assert d["expires_at"] is None and d["role"] == "operator"


async def test_desactivar_2fa_exige_codigo(clients, server):
    from cyberhound.core.totp import TOTPManager
    ana = await clients("ana", PW)
    data = await (await ana.post("/api/auth/2fa/setup", json={})).json()
    assert (await ana.post("/api/auth/2fa/activate", json={"code": totp.generate_totp(data["secret"])})).status == 200
    assert (await ana.post("/api/auth/2fa/disable", json={})).status == 400
    assert (await ana.post("/api/auth/2fa/disable", json={"code": "000000"})).status == 400
    code = totp.generate_totp(data["secret"], timestamp=time.time() + 30)
    assert (await ana.post("/api/auth/2fa/disable", json={"code": code})).status == 200
    assert not (await server.db.get_user("ana"))["totp_enabled"]
    assert TOTPManager  # importado para dejar claro qué valida el endpoint


async def test_auditoria(clients):
    adm = await clients("admin", ADMIN_PW)
    await clients("ana", "mala")
    ana = await clients("ana", PW)
    await adm.post("/api/users", json={"username": "luis", "password": "x" * 10, "role": "viewer"})
    await ana.post("/api/tokens", json={"name": "ci"})
    ev = await (await adm.get("/api/audit")).json()
    actions = [(e["action"], e["username"], e["ok"]) for e in ev]
    assert ("login", "ana", 0) in actions and ("login", "ana", 1) in actions
    assert ("user_create", "admin", 1) in actions and ("token_create", "ana", 1) in actions
    assert [e["username"] for e in await (await adm.get("/api/audit?failures=1")).json()] == ["ana"]
    assert all(e["action"] == "login" for e in await (await adm.get("/api/audit?action=login")).json())
    assert (await ana.get("/api/audit")).status == 403          # solo admin
    assert (await adm.get("/api/audit?limit=x")).status == 400


async def test_interruptor_del_scheduler_se_guarda(clients, server):
    """Antes el interruptor solo cambiaba la memoria: tras reiniciar la tarea volvía a su estado."""
    from cyberhound.core.scheduler import build_platform_scheduler
    server.scheduler = build_platform_scheduler(server, server.cfg.scheduler)
    adm = await clients("admin", ADMIN_PW)
    assert (await adm.post("/api/scheduler/weekly_malware/toggle", json={"enabled": False})).status == 200
    assert server.cfg.scheduler.malware_enabled is False
    assert (await adm.post("/api/scheduler/no_existe/toggle", json={"enabled": False})).status == 404
