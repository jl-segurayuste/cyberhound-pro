"""Multi-tenant de extremo a extremo: lo de un tenant no se ve ni se toca desde otro.

Antes de 2026-10-20 el modo multi-tenant solo existía como API para crear tenants:
ningún dato estaba separado. Con CH_DB_URL=postgresql://… estos tests comprueban
también el aislamiento por esquema de PostgreSQL.
"""
import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords, totp
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.models import Finding
from cyberhound.core.multitenancy import current_tenant

SA_PW = "clave-superadmin-1234"
PW = "clave-del-tenant-1234"


@pytest_asyncio.fixture
async def server(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.config_path = tmp_path / "config.yaml"
    cfg.db_path = str(tmp_path / "cyberhound.db")
    cfg.server.log_dir = str(tmp_path)
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password(SA_PW)
    cfg.auth.secret = "s" * 64
    cfg.multi_tenant.enabled = True
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    srv.agent_manager.cfg.agent_key = "clave-agente-global"
    return srv


class Clients:
    def __init__(self, server):
        self.server, self.open = server, []

    async def login(self, username, password, tenant=""):
        c = TestClient(TestServer(self.server.build_app()))
        await c.start_server()
        self.open.append(c)
        await c.get("/login")
        csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
        r = await c.post("/login", data={"username": username, "password": password, "tenant": tenant,
                                         "_csrf": csrf}, allow_redirects=False)
        c.login_location = r.headers.get("Location")
        return c

    async def close(self):
        for c in self.open:
            await c.close()


@pytest_asyncio.fixture
async def env(server):
    cl = Clients(server)
    sa = await cl.login("admin", SA_PW)
    for slug, name in (("acme", "ACME"), ("contoso", "Contoso")):
        r = await sa.post("/api/tenants", json={"slug": slug, "name": name,
                                                 "admin_username": "jefa", "admin_password": PW})
        assert r.status == 201, await r.text()
        cl.__dict__[f"{slug}_key"] = (await r.json())["api_key"]
    cl.sa = sa
    cl.acme = await cl.login("jefa", PW, "acme")
    cl.contoso = await cl.login("jefa", PW, "contoso")
    yield cl
    await cl.close()


async def _report(client, key, agent="srv-1", n=2):
    findings = [{"id": f"f{i}", "category": "ssh", "severity": "high", "title": f"Hallazgo {i}"} for i in range(n)]
    return await client.post("/api/agent/report", json={"agent_name": agent, "findings": findings, "score": 70},
                             headers={"Authorization": f"AgentKey {key}"})


async def _history(client, **headers):
    return await (await client.get("/api/history", headers=headers)).json()


# ── Login ─────────────────────────────────────────────────────────────────────

async def test_login_por_organizacion(env):
    assert env.acme.login_location == "/" and env.contoso.login_location == "/"
    wrong = await env.login("jefa", PW)                 # sin organización = plataforma
    assert "error" in wrong.login_location
    other = await env.login("jefa", PW, "no-existe")
    assert "error" in other.login_location
    me = await (await env.acme.get("/api/me")).json()
    assert me["tenant"] == "acme" and me["tenant_name"] == "ACME" and me["superadmin"] is False
    assert me["host_access"] is False and me["multi_tenant"] is True
    sa = await (await env.sa.get("/api/me")).json()
    assert sa["tenant"] == "default" and sa["superadmin"] is True and sa["host_access"] is True


async def test_el_admin_de_la_plataforma_no_entra_como_usuario_de_un_tenant(env):
    c = await env.login("admin", SA_PW, "acme")         # no existe "admin" en la BD de acme
    assert "error" in c.login_location


# ── Datos ─────────────────────────────────────────────────────────────────────

async def test_datos_separados_por_tenant(env):
    assert (await _report(env.acme, env.acme_key)).status == 200
    assert [h["scan_type"] for h in await _history(env.acme)] == ["audit"]
    assert await _history(env.contoso) == []
    assert await _history(env.sa) == []                                   # "default"
    assert len(await _history(env.sa, **{"X-Tenant": "acme"})) == 1       # superadmin mirando acme
    # un usuario de tenant no puede elegir otro con la cabecera
    assert await _history(env.contoso, **{"X-Tenant": "acme"}) == []


async def test_usuarios_y_supresiones_separados(env):
    assert (await env.acme.post("/api/users", json={"username": "ana", "password": "x" * 10,
                                                    "role": "viewer"})).status == 200
    acme_users = {u["username"] for u in await (await env.acme.get("/api/users")).json()}
    contoso_users = {u["username"] for u in await (await env.contoso.get("/api/users")).json()}
    assert acme_users == {"jefa", "ana"} and contoso_users == {"jefa"}
    assert (await env.contoso.patch("/api/users/ana", json={"role": "admin"})).status == 404
    await env.acme.post("/api/suppressions", json={"pattern": "ssh_*", "reason": "r"})
    assert len(await (await env.acme.get("/api/suppressions")).json()) == 1
    assert await (await env.contoso.get("/api/suppressions")).json() == []


async def test_agentes_con_la_api_key_de_su_tenant(env):
    await env.acme.get("/api/me")
    hb = await env.acme.post("/api/agent/heartbeat", json={"agent_name": "srv-acme"},
                             headers={"Authorization": f"AgentKey {env.acme_key}"})
    assert hb.status == 200
    assert [a["name"] for a in await (await env.acme.get("/api/agent/list")).json()] == ["srv-acme"]
    assert await (await env.contoso.get("/api/agent/list")).json() == []
    assert (await _report(env.acme, "clave-inventada")).status == 401
    # la clave global sigue yendo a "default"
    assert (await _report(env.sa, "clave-agente-global")).status == 200
    assert len(await _history(env.sa)) == 1 and await _history(env.acme) == []


async def test_cache_de_hallazgos_no_cruza_tenants(env, monkeypatch):
    f = Finding(id="10.0.0.9::ssh_PermitRootLogin", category="ssh", severity="high", title="t",
                description="", remediation="r", auto_fix=True, source_host="10.0.0.9")
    env.server._findings_cache["acme:conexion"] = [f]
    from cyberhound.scanners.ssh_audit import RemoteAuditor

    async def fake(self, host, finding):
        return True, ""
    monkeypatch.setattr(RemoteAuditor, "apply_fix_remote", fake)
    body = {"finding_id": f.id}
    assert (await env.contoso.post("/api/fix/remote", json=body)).status == 404
    assert (await env.acme.post("/api/fix/remote", json=body)).status == 200


async def test_push_solo_a_su_tenant(env):
    sent = []

    class FakeWS:
        def __init__(self, name):
            self.name = name

        async def send_json(self, msg):
            sent.append(self.name)
    srv = env.server
    srv._push_clients = {FakeWS("acme"): "acme", FakeWS("contoso"): "contoso", FakeWS("default"): "default"}
    tok = current_tenant.set("acme")
    try:
        await srv._broadcast_push("new_findings", {"count": 1})
    finally:
        current_tenant.reset(tok)
    assert sent == ["acme"]


# ── Lo que es de la plataforma ────────────────────────────────────────────────

async def test_operaciones_de_plataforma_reservadas_al_superadmin(env):
    for method, path in (("GET", "/api/config/keys"), ("GET", "/api/tenants"), ("POST", "/api/fix/local"),
                         ("GET", "/api/scheduler"), ("POST", "/api/yara/update"), ("GET", "/api/quarantine")):
        r = await env.acme.request(method, path, json={})
        assert r.status == 403, (method, path, r.status)
    assert (await env.sa.get("/api/config/keys")).status == 200
    assert (await env.sa.get("/api/tenants")).status == 200


async def test_ws_tareas_sobre_el_servidor_solo_superadmin(env):
    async with env.acme.ws_connect("/ws") as ws:
        await ws.send_json({"task": "audit"})
        msg = await ws.receive_json()
        assert msg["type"] == "error" and "plataforma" in msg["text"]


# ── Ciclo de vida del tenant ──────────────────────────────────────────────────

async def test_baja_corta_sesiones_y_el_slug_reutilizado_empieza_vacio(env):
    await _report(env.acme, env.acme_key)
    assert (await env.sa.delete("/api/tenants/acme")).status == 200
    assert (await env.acme.get("/api/history")).status == 401          # sesión abierta, fuera
    assert (await _report(env.sa, env.acme_key)).status == 401          # su API key ya no vale
    assert "error" in (await env.login("jefa", PW, "acme")).login_location
    r = await env.sa.post("/api/tenants", json={"slug": "acme", "name": "Otra ACME",
                                                 "admin_username": "nuevo", "admin_password": PW})
    assert r.status == 201
    nuevo = await env.login("nuevo", PW, "acme")
    assert nuevo.login_location == "/"
    assert await _history(nuevo) == []                                  # no hereda datos de la anterior
    assert {u["username"] for u in await (await nuevo.get("/api/users")).json()} == {"nuevo"}


async def test_rotar_api_key(env):
    r = await env.sa.post("/api/tenants/acme/rotate-key")
    new_key = (await r.json())["api_key"]
    assert (await _report(env.acme, env.acme_key)).status == 401
    assert (await _report(env.acme, new_key)).status == 200


async def test_superadmin_cambia_de_tenant_y_un_tenant_no_puede(env):
    await _report(env.acme, env.acme_key)
    assert (await env.sa.post("/api/tenant/switch", json={"slug": "acme"})).status == 200
    assert (await (await env.sa.get("/api/me")).json())["tenant"] == "acme"
    assert len(await _history(env.sa)) == 1
    assert (await env.sa.post("/api/tenant/switch", json={"slug": "no-existe"})).status == 404
    assert (await env.acme.post("/api/tenant/switch", json={"slug": "contoso"})).status == 403
    await env.sa.post("/api/tenant/switch", json={"slug": "default"})
    assert await _history(env.sa) == []


async def test_validacion_al_crear(env):
    for body in ({"slug": "default", "name": "X"}, {"slug": "A B", "name": "X"}, {"slug": "acme", "name": "X"},
                 {"slug": "nuevo-ok", "name": ""},
                 {"slug": "nuevo-ok", "name": "X", "admin_username": "a", "admin_password": "corta"}):
        assert (await env.sa.post("/api/tenants", json=body)).status == 400, body


async def test_2fa_de_un_usuario_de_tenant(env):
    srv = env.server
    tok = current_tenant.set("acme")
    try:
        secret = totp.generate_secret()
        await srv.db.set_totp_pending("jefa", secret, totp.generate_recovery_codes())
        from cyberhound.core.totp import TOTPManager
        await TOTPManager(srv.db).activate_2fa("jefa", totp.generate_totp(secret))
    finally:
        current_tenant.reset(tok)
    c = await env.login("jefa", PW, "acme")
    assert c.login_location == "/login"                                 # pide código
    csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf")
    if csrf is None:
        await c.get("/login")
        csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf")
    import time
    code = totp.generate_totp(secret, timestamp=time.time() + 30)
    r = await c.post("/login", data={"code": code, "_csrf": csrf.value}, allow_redirects=False)
    assert r.headers["Location"] == "/"
    assert (await (await c.get("/api/me")).json())["tenant"] == "acme"
    # el de contoso (mismo usuario "jefa", otra BD) sigue sin 2FA
    assert (await env.login("jefa", PW, "contoso")).login_location == "/"


async def test_sesion_de_tenant_no_vale_si_se_desactiva_el_modo(env):
    env.server.cfg.multi_tenant.enabled = False
    assert (await env.acme.get("/api/history")).status == 401
    assert (await env.sa.get("/api/history")).status == 200
