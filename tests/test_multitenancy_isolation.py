"""Multi-tenant de extremo a extremo: lo de un tenant no se ve ni se toca desde otro.

Antes de 2026-10-20 el modo multi-tenant solo existía como API para crear tenants:
ningún dato estaba separado. Con CH_DB_URL=postgresql://… estos tests comprueban
también el aislamiento por esquema de PostgreSQL.
"""
from datetime import datetime

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
        return True, "", None
    monkeypatch.setattr(RemoteAuditor, "apply_fix_remote", fake)
    body = {"finding_id": f.id}
    assert (await env.contoso.post("/api/fix/remote", json=body)).status == 404
    assert (await env.acme.post("/api/fix/remote", json=body)).status == 403     # fuera de su ámbito
    await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.0.0.0/24"]})
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


async def test_cuenta_del_superadmin_mirando_otra_organizacion(env):
    """Su sesión, tokens y 2FA viven en "default" aunque esté viendo acme."""
    await env.sa.post("/api/tenant/switch", json={"slug": "acme"})
    assert (await env.sa.get("/api/me")).status == 200
    assert len(await (await env.sa.get("/api/sessions")).json()) == 1
    tok = await (await env.sa.post("/api/tokens", json={"name": "ci"})).json()
    assert tok["token"].startswith("cht_default.")
    assert (await env.sa.get("/api/auth/2fa/status")).status == 200
    # la auditoría de lo hecho en acme queda en acme
    await env.sa.post("/api/suppressions", json={"pattern": "p_*", "reason": "r"})
    acme_ev = await (await env.acme.get("/api/audit")).json()
    assert not any(e["action"] == "token_create" for e in acme_ev)


async def test_token_de_api_de_un_tenant(env):
    tok = (await (await env.acme.post("/api/tokens", json={"name": "ci"})).json())["token"]
    assert tok.startswith("cht_acme.")
    anon = await env.login("nadie", "x")
    h = {"Authorization": f"Bearer {tok}"}
    me = await (await anon.get("/api/me", headers=h)).json()
    assert me["tenant"] == "acme" and me["superadmin"] is False
    assert (await anon.get("/api/config/keys", headers=h)).status == 403        # de la plataforma
    forged = tok.replace("cht_acme.", "cht_contoso.")
    assert (await anon.get("/api/me", headers={"Authorization": f"Bearer {forged}"})).status == 401


async def test_ambito_de_analisis_por_organizacion(env):
    async def ws_error(client, msg):
        async with client.ws_connect("/ws") as ws:
            await ws.send_json(msg)
            return await ws.receive_json()

    web = {"task": "web_headers", "urls": ["http://10.10.0.9"]}
    msg = await ws_error(env.acme, web)                        # sin ámbito: nada
    assert msg["type"] == "error" and "permitidos" in msg["text"]
    assert (await env.acme.patch("/api/tenants/acme", json={"allowed_targets": ["10.10.0.0/24"]})).status == 403
    r = await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.0.0.0/8"]})
    assert r.status == 400
    r = await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.10.0.0/24", "ejemplo-demo.es"]})
    assert (await r.json())["allowed_targets"] == ["10.10.0.0/24", "ejemplo-demo.es"]
    msg = await ws_error(env.acme, {"task": "web_headers", "urls": ["http://192.168.1.1"]})
    assert msg["type"] == "error" and "fuera" in msg["text"]
    msg = await ws_error(env.acme, {"task": "network", "networks": ""})   # el escáner elegiría las del servidor
    assert msg["type"] == "error" and "Indica" in msg["text"]
    msg = await ws_error(env.contoso, web)                     # el ámbito de acme no vale para contoso
    assert msg["type"] == "error"
    assert (await env.acme.get("/api/network/discover?networks=192.168.1.0/24")).status == 403
    assert (await env.acme.get("/api/network/discover")).status == 403
    assert (await env.acme.post("/api/scan/ldap", json={"uri": "ldap://192.168.1.5"})).status == 403
    # dentro del ámbito el análisis arranca (no hay servidor en 10.10.0.9: sale info, no error de ámbito)
    msg = await ws_error(env.acme, web)
    assert not (msg["type"] == "error" and "permit" in msg["text"]), msg
    # el superadmin en su plataforma no tiene ámbito
    msg = await ws_error(env.sa, {"task": "web_headers", "urls": ["http://192.168.1.1"]})
    assert not (msg["type"] == "error" and "permit" in msg["text"]), msg


async def test_integraciones_propias_de_cada_organizacion(env, monkeypatch):
    import ipaddress

    from cyberhound.core import integrations

    async def fake(host):
        return [ipaddress.ip_address({"hooks.ejemplo-demo.es": "1.2.3.4"}.get(host, "127.0.0.1"))]
    monkeypatch.setattr(integrations, "_resolve", fake)
    hook = {"webhook_enabled": True, "webhook_url": "https://hooks.ejemplo-demo.es/acme", "smtp_password": "p"}
    r = await env.acme.post("/api/config/notifications", json=hook)
    assert r.status == 200, await r.text()
    acme = await (await env.acme.get("/api/config/notifications")).json()
    assert acme["webhook_url"].endswith("/acme") and "smtp_password" not in acme and acme["secrets_set"] == ["smtp_password"]
    assert (await (await env.contoso.get("/api/config/notifications")).json())["webhook_url"] == ""
    assert (await (await env.sa.get("/api/config/notifications")).json())["webhook_url"] == ""
    assert env.server.cfg.notifications.webhook_url == ""
    # el gestor de la organización usa sus ajustes, no los de la plataforma
    token = current_tenant.set("acme")
    try:
        assert env.server.notification_manager.cfg.webhook_url.endswith("/acme")
    finally:
        current_tenant.reset(token)
    # SSRF: ni loopback ni la LAN del servidor
    for url in ("http://127.0.0.1:8765/api/x", "http://192.168.1.67/"):
        r = await env.acme.post("/api/config/siem", json={"elk_enabled": True, "elk_url": url})
        assert r.status == 400 and "interna" in (await r.json())["error"], url
    # el superadmin sí puede usar destinos internos en la plataforma
    assert (await env.sa.post("/api/config/siem", json={"elk_enabled": True, "elk_url": "http://127.0.0.1:9200"})).status == 200
    assert (await env.acme.get("/api/config/keys")).status == 403


async def test_analisis_programados_por_organizacion(env, monkeypatch):
    srv = env.server
    sched = {"name": "Cabeceras", "task": "web_headers", "targets": ["http://10.10.0.9"], "hour": 3, "minute": 0}
    r = await env.acme.post("/api/schedules", json=sched)
    assert r.status == 400 and "permitidos" in (await r.json())["error"]       # sin ámbito
    await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.10.0.0/24"]})
    r = await env.acme.post("/api/schedules", json={**sched, "targets": ["http://192.168.1.1"]})
    assert r.status == 400 and "fuera" in (await r.json())["error"]
    assert (await env.acme.post("/api/schedules", json={**sched, "task": "audit"})).status == 400
    r = await env.acme.post("/api/schedules", json=sched)
    assert r.status == 201, await r.text()
    sid = (await r.json())["id"]
    assert [s["id"] for s in await (await env.acme.get("/api/schedules")).json()] == [sid]
    assert await (await env.contoso.get("/api/schedules")).json() == []
    assert (await env.contoso.delete(f"/api/schedules/{sid}")).status == 404
    assert (await env.contoso.post(f"/api/schedules/{sid}/run")).status == 404

    ran = []

    async def fake_run(self, params, ws_id, send, log, scan_id):
        ran.append((current_tenant.get(), params["urls"]))
        f = Finding(id="hdr1", category="web", severity="critical", title="Sin HSTS", description="", remediation="")
        await self._emit_findings([f], ws_id, send, scan_id)
    monkeypatch.setattr(type(srv), "_run_web_headers_scan", fake_run)
    sent = []

    async def fake_send(message, level="info", scan_id=None):
        sent.append((current_tenant.get(), message))
    token = current_tenant.set("acme")
    try:
        monkeypatch.setattr(srv.notification_manager, "send", fake_send)
    finally:
        current_tenant.reset(token)
    tasks = await srv._schedules_tick(datetime(2026, 10, 21, 3, 0, 10))
    assert len(tasks) == 1
    await tasks[0]
    assert ran == [("acme", ["http://10.10.0.9"])] and sent and sent[0][0] == "acme"
    assert await srv._schedules_tick(datetime(2026, 10, 21, 3, 0, 40)) == []      # no se repite en el mismo minuto
    s = (await (await env.acme.get("/api/schedules")).json())[0]
    assert s["last_status"].startswith("ok: 1") and s["last_scan_id"]
    assert await _history(env.acme)
    assert await _history(env.contoso) == []
    # si el ámbito se reduce, la programación ya no se ejecuta
    await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.20.0.0/24"]})
    tasks = await srv._schedules_tick(datetime(2026, 10, 22, 3, 0, 10))
    await tasks[0]
    s = (await (await env.acme.get("/api/schedules")).json())[0]
    assert s["last_status"].startswith("fuera de ámbito") and len(ran) == 1
    assert (await env.acme.patch(f"/api/schedules/{sid}", json={"enabled": False})).status == 200
    assert await srv._schedules_tick(datetime(2026, 10, 23, 3, 0, 10)) == []
    assert (await env.acme.delete(f"/api/schedules/{sid}")).status == 200


async def test_deshacer_fix_remoto_solo_en_su_organizacion(env, monkeypatch):
    from cyberhound.scanners.ssh_audit import RemoteAuditor
    await env.sa.patch("/api/tenants/acme", json={"allowed_targets": ["10.0.0.0/24"]})
    f = Finding(id="10.0.0.9::svc_telnet", category="svc", severity="high", title="t",
                description="", remediation="r", auto_fix=True, source_host="10.0.0.9")
    env.server._findings_cache["acme:conexion"] = [f]
    calls = []

    async def fake(self, host, action):
        calls.append((host, action))
        return {"ok": True, "msg": "", "before": {"active": True, "enabled": True}}
    monkeypatch.setattr(RemoteAuditor, "_run_remote_action", fake)
    body = {"finding_id": f.id, "ssh_password": "x"}
    assert (await env.acme.post("/api/fix/remote", json={**body, "ssh_key": "/data/id_rsa"})).status == 400
    d = await (await env.acme.post("/api/fix/remote", json=body)).json()
    assert d["ok"] and d["reversible"] and d["fix_id"]
    assert [h["id"] for h in await (await env.acme.get("/api/fix/remote/history")).json()] == [d["fix_id"]]
    assert await (await env.contoso.get("/api/fix/remote/history")).json() == []
    assert (await env.contoso.post("/api/fix/remote/undo", json={"fix_id": d["fix_id"]})).status == 404
    r = await env.acme.post("/api/fix/remote/undo", json={"fix_id": d["fix_id"], "ssh_password": "x"})
    assert r.status == 200, await r.text()
    assert calls[-1] == ("10.0.0.9", {"action": "svc_undo", "svc": "telnet", "active": True, "enabled": True})
    assert (await env.acme.post("/api/fix/remote/undo", json={"fix_id": d["fix_id"]})).status == 409
    hist = await (await env.acme.get("/api/fix/remote/history")).json()
    assert hist[0]["undone_by"] == "jefa" and hist[0]["reversible"] is False
