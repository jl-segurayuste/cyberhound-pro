"""Roles, usuarios de la BD y agentes, de extremo a extremo sobre la app real.

Bugs reales corregidos 2026-10-20 (encontrados con una batería de pruebas de la UI):
- ROLE_PERMISSIONS y el decorador `_requires_role` existían pero ningún endpoint
  los usaba: un `viewer` podía cambiar la configuración o crear administradores.
- El login solo aceptaba el usuario de config.yaml: los usuarios creados en
  Ajustes › Usuarios se guardaban pero nunca podían iniciar sesión.
- El middleware JWT rechazaba "Authorization: AgentKey ..." antes de llegar al
  handler, así que los agentes remotos nunca podían reportar.
- El admin podía quitarse a sí mismo el rol de admin desde la UI.
"""
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import UserRecord

_ADMIN_PW = "clave-admin-de-prueba"
_USER_PW = "clave-usuario-de-prueba"


@pytest_asyncio.fixture
async def server(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.db_path = tmp_path / "rbac.db"
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password(_ADMIN_PW)
    cfg.auth.secret = "s" * 64
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    await srv.db.ensure_admin_exists("admin", cfg.auth.password_hash)
    for name, role in (("lector", "viewer"), ("operador", "operator")):
        await srv.db.create_user(UserRecord(username=name, password_hash=passwords.hash_password(_USER_PW), role=role))
    return srv


async def _client(server) -> TestClient:
    c = TestClient(TestServer(server.build_app()))
    await c.start_server()
    return c


async def _login(server, username, password) -> TestClient:
    c = await _client(server)
    await c.get("/login")
    csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
    await c.post("/login", data={"username": username, "password": password, "_csrf": csrf}, allow_redirects=False)
    return c


async def test_usuario_de_la_bd_puede_iniciar_sesion(server):
    c = await _login(server, "lector", _USER_PW)
    try:
        assert (await c.get("/api/history")).status == 200
    finally:
        await c.close()


async def test_usuario_de_la_bd_con_clave_erronea_no_entra(server):
    c = await _login(server, "lector", "otra-clave")
    try:
        assert (await c.get("/api/history", allow_redirects=False)).status == 401
    finally:
        await c.close()


async def test_viewer_solo_lee(server):
    c = await _login(server, "lector", _USER_PW)
    try:
        assert (await c.get("/api/dashboard")).status == 200
        assert (await c.post("/api/config/keys", json={"shodan": "x"})).status == 403
        assert (await c.post("/api/users", json={"username": "x", "password": "12345678", "role": "admin"})).status == 403
        assert (await c.post("/api/fix/local", json={"finding_id": "x"})).status == 403
        assert (await c.post("/api/scan/runtime", json={})).status == 403
    finally:
        await c.close()


async def test_operator_escanea_pero_no_configura(server):
    c = await _login(server, "operador", _USER_PW)
    try:
        assert (await c.post("/api/config/keys", json={"shodan": "x"})).status == 403
        assert (await c.get("/api/users")).status == 403
        assert (await c.post("/api/fix/local", json={"finding_id": "no_existe"})).status != 403
    finally:
        await c.close()


async def test_admin_de_config_siempre_es_admin(server):
    # aunque su fila en la BD diga otra cosa, el admin de config.yaml no se queda fuera
    await server.db.update_user("admin", role="viewer")
    c = await _login(server, "admin", _ADMIN_PW)
    try:
        assert (await c.post("/api/config/keys", json={})).status == 200
    finally:
        await c.close()


async def test_admin_no_puede_quitarse_el_rol_ni_borrarse(server):
    c = await _login(server, "admin", _ADMIN_PW)
    try:
        assert (await c.patch("/api/users/admin", json={"role": "viewer"})).status == 400
        assert (await c.patch("/api/users/admin", json={"active": False})).status == 400
        assert (await c.delete("/api/users/admin")).status == 400
        assert (await c.patch("/api/users/lector", json={"role": "operator"})).status == 200
    finally:
        await c.close()


async def test_usuario_desactivado_pierde_la_sesion(server):
    c = await _login(server, "lector", _USER_PW)
    try:
        assert (await c.get("/api/history")).status == 200
        await server.db.update_user("lector", active=0)
        assert (await c.get("/api/history")).status == 401
    finally:
        await c.close()


async def test_agente_con_su_clave_llega_al_handler(server):
    server.agent_manager.cfg.agent_key = "clave-agente"
    c = await _client(server)
    try:
        ok = await c.post("/api/agent/heartbeat", json={"agent_name": "a1"},
                          headers={"Authorization": "AgentKey clave-agente"})
        assert ok.status == 200
        bad = await c.post("/api/agent/heartbeat", json={"agent_name": "a1"},
                           headers={"Authorization": "AgentKey otra"})
        assert bad.status in (401, 403)
    finally:
        await c.close()


async def test_guardar_clave_de_agente_aplica_sin_reiniciar(server):
    c = await _login(server, "admin", _ADMIN_PW)
    try:
        assert (await c.post("/api/config/agent", json={"mode": "manager", "agent_key": "nueva-clave"})).status == 200
        assert server.agent_manager.verify_agent_key("nueva-clave")
    finally:
        await c.close()


async def test_get_scan_devuelve_el_scan_pedido(server):
    old = await server.db.create_scan("audit")
    await server.db.complete_scan(old, [], score=42)
    new = await server.db.create_scan("audit")
    await server.db.complete_scan(new, [], score=90)
    assert (await server.db.get_scan(old))["score"] == 42
    assert await server.db.get_scan(999999) is None


async def test_usuario_borrado_se_puede_volver_a_crear(server):
    c = await _login(server, "admin", _ADMIN_PW)
    try:
        assert (await c.delete("/api/users/lector")).status == 200
        r = await c.post("/api/users", json={"username": "lector", "password": "otra-clave-nueva", "role": "operator"})
        assert r.status == 200
        assert (await c.post("/api/users", json={"username": "lector", "password": "x" * 10, "role": "viewer"})).status == 409
    finally:
        await c.close()
    c = await _login(server, "lector", "otra-clave-nueva")
    try:
        assert (await c.get("/api/history")).status == 200
    finally:
        await c.close()


async def test_api_rechaza_escrituras_de_otro_origen(server):
    """Defensa en profundidad: SameSite=Strict no cubre otro subdominio del mismo sitio."""
    c = await _login(server, "admin", _ADMIN_PW)
    try:
        body = {"pattern": "x_*", "reason": "r"}
        assert (await c.post("/api/suppressions", json=body, headers={"Sec-Fetch-Site": "same-site"})).status == 403
        assert (await c.post("/api/suppressions", json=body, headers={"Sec-Fetch-Site": "cross-site"})).status == 403
        assert (await c.post("/api/suppressions", json=body, headers={"Origin": "https://otro.ejemplo.es"})).status == 403
        assert (await c.post("/api/suppressions", json=body, headers={"Sec-Fetch-Site": "same-origin"})).status == 200
        assert (await c.post("/api/suppressions", json=body)).status == 200   # cliente sin navegador
        assert (await c.get("/api/history", headers={"Sec-Fetch-Site": "cross-site"})).status == 200  # leer no
    finally:
        await c.close()
