"""Corrección de hallazgos local y remota.

Bugs reales corregidos 2026-10-20:
- El fix remoto ejecutaba por shell, tal cual, la remediación que devolvía el host
  auditado (con nombres de fichero del propio host): un usuario sin privilegios
  podía inyectar comandos creando un fichero world-writable con `;` en el nombre.
- El script de auditoría se escribía en /tmp con nombre predecible y luego se
  ejecutaba con sudo: un usuario local del host podía sustituirlo.
- Los checks de kernel remotos nunca saltaban (ruta "/proc/sys/net/ ipv4/...").
- /api/fix/local quitaba el prefijo "host::" y aplicaba en ESTE servidor el fix
  de un hallazgo remoto.
- ssh_hostkey_perm_* y passwd_perm_* se marcaban corregibles pero el fixer no
  sabía corregirlos; activar ufw no abría antes SSH ni el puerto de la web.
"""
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.models import Finding
from cyberhound.scanners import hardening
from cyberhound.scanners.hardening import HardeningFixer
from cyberhound.scanners.ssh_audit import RemoteAuditor


def _f(fid, **kw):
    return Finding(id=fid, category="x", severity="high", title="t", description="d",
                   remediation=kw.pop("remediation", "r"), auto_fix=True, **kw)


def test_accion_remota_se_construye_del_id_no_de_la_remediacion():
    f = _f("10.0.0.5::ssh_PermitRootLogin", remediation="rm -rf / ; echo")
    assert RemoteAuditor.remote_fix_action(f) == {"action": "ssh_param", "param": "PermitRootLogin", "value": "no"}
    assert RemoteAuditor.remote_fix_action(_f("h::kernel_net.ipv4.ip_forward"))["value"] == "0"
    assert RemoteAuditor.remote_fix_action(_f("h::svc_telnet"))["svc"] == "telnet"


def test_accion_remota_rechaza_rutas_y_ids_fuera_de_lista():
    assert RemoteAuditor.remote_fix_action(_f("h::ww_x", file_path="/etc/a; useradd x")) is None
    assert RemoteAuditor.remote_fix_action(_f("h::ww_x", file_path="/etc/../root/x")) is None
    assert RemoteAuditor.remote_fix_action(_f("h::ww_x", file_path="/home/u/x")) is None
    assert RemoteAuditor.remote_fix_action(_f("h::svc_sshd")) is None
    assert RemoteAuditor.remote_fix_action(_f("h::ssh_AllowUsers")) is None
    assert RemoteAuditor.remote_fix_action(_f("h::ww_x", file_path="/etc/cron.d/job"))["path"] == "/etc/cron.d/job"


def test_payload_remoto_lleva_la_accion_como_dato():
    action = {"action": "chmod_ow", "path": "/etc/a'\"\\\n__import__('os')"}
    payload = RemoteAuditor._fix_payload(action)
    first = payload.splitlines()[0]
    ns = {}
    exec(first, ns)  # solo la línea que define A
    assert ns["A"] == action
    compile(payload, "<remote-fix>", "exec")


class _FakeConn:
    def __init__(self, sudo_ok=True, stdout="[]"):
        self.calls, self.sudo_ok, self.stdout = [], sudo_ok, stdout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def run(self, cmd, input=None, timeout=None):
        self.calls.append((cmd, input))
        ok = self.sudo_ok if cmd == "sudo -n true" else True
        out = self.stdout if input else "Python 3.12"
        return type("R", (), {"exit_status": 0 if ok else 1, "stdout": out, "stderr": ""})()


async def test_auditoria_remota_va_por_stdin_sin_ficheros_en_tmp(monkeypatch):
    from cyberhound.scanners import ssh_audit
    conn = _FakeConn(stdout='[{"id": "ssh_PermitRootLogin", "category": "ssh", "severity": "high", '
                            '"title": "t", "description": "", "remediation": "r", "auto_fix": true}]')
    monkeypatch.setattr(ssh_audit.asyncssh, "connect", lambda host, **kw: conn)
    res = await RemoteAuditor(ssh_audit.SSHCredentials()).audit_host("10.0.0.5")
    assert res.status == "ok" and res.findings[0].id == "10.0.0.5::ssh_PermitRootLogin"
    assert all("/tmp" not in cmd for cmd, _ in conn.calls)
    assert ("sudo -n python3 -", RemoteAuditor.REMOTE_AUDIT_SCRIPT) in conn.calls
    # sin sudo: misma auditoría, sin elevar
    conn2 = _FakeConn(sudo_ok=False)
    monkeypatch.setattr(ssh_audit.asyncssh, "connect", lambda host, **kw: conn2)
    await RemoteAuditor(ssh_audit.SSHCredentials()).audit_host("10.0.0.5")
    assert ("python3 -", RemoteAuditor.REMOTE_AUDIT_SCRIPT) in conn2.calls


def test_scripts_remotos_compilan_y_ruta_de_kernel_correcta():
    assert 'param.replace(".","/")' in RemoteAuditor.REMOTE_AUDIT_SCRIPT
    compile(RemoteAuditor.REMOTE_AUDIT_SCRIPT, "<remote-audit>", "exec")
    compile(RemoteAuditor._fix_payload({"action": "x"}), "<remote-fix>", "exec")


def test_script_de_fix_remoto_funciona_de_verdad(tmp_path):
    """Ejecuta el script real de fix (acción chmod_ow) sobre un fichero temporal."""
    import os
    import subprocess
    import sys
    target = tmp_path / "f"
    target.write_text("x")
    os.chmod(target, 0o666)
    payload = RemoteAuditor._fix_payload({"action": "chmod_ow", "path": str(target)})
    out = subprocess.run([sys.executable, "-"], input=payload, capture_output=True, text=True, timeout=30)
    assert '"ok": true' in out.stdout
    assert os.stat(target).st_mode & 0o777 == 0o664
    link = tmp_path / "l"
    link.symlink_to(target)
    out = subprocess.run([sys.executable, "-"], input=RemoteAuditor._fix_payload({"action": "chmod_ow", "path": str(link)}),
                         capture_output=True, text=True, timeout=30)
    assert '"ok": true' not in out.stdout   # O_NOFOLLOW: no sigue enlaces


class _Recorder(HardeningFixer):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.cmds = []

    async def _run(self, cmd, timeout=60):
        self.cmds.append(cmd)
        return True, ""


async def test_fix_permisos_de_claves_de_host_y_passwd(tmp_path):
    key = tmp_path / "ssh_host_ed25519_key"
    key.write_text("k")
    fx = _Recorder()
    assert (await fx.fix(_f("ssh_hostkey_perm_ssh_host_ed25519_key", file_path=str(key))))[0]
    assert fx.cmds[-1] == ["chmod", "600", str(key)]
    assert (await fx.fix(_f("passwd_perm_shadow", file_path="/etc/shadow")))[0]
    assert fx.cmds[-1] == ["chmod", "640", "/etc/shadow"]
    assert (await fx.fix(_f("passwd_perm_passwd", file_path="/etc/passwd")))[0]
    assert fx.cmds[-1] == ["chmod", "644", "/etc/passwd"]


async def test_svc_listen_all_no_intenta_desactivar_un_servicio_inventado():
    fx = _Recorder()
    ok, _ = await fx.fix(_f("svc_listen_all_6379"))
    assert not ok and fx.cmds == []


async def test_activar_ufw_abre_antes_ssh_y_la_web(monkeypatch):
    monkeypatch.setattr(hardening, "command_exists", lambda c: c == "ufw")
    monkeypatch.setattr(HardeningFixer, "_sshd_ports", staticmethod(lambda: [2222]))
    fx = _Recorder(keep_open_ports=(8443,))
    assert (await fx.fix(_f("fw_ufw_inactive")))[0]
    assert fx.cmds == [["ufw", "allow", "2222/tcp"], ["ufw", "allow", "8443/tcp"], ["ufw", "--force", "enable"]]


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.db_path = tmp_path / "fix.db"
    cfg.server.log_dir = str(tmp_path)
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password("clave-de-prueba")
    cfg.auth.secret = "s" * 64
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    remote = _f("10.0.0.5::ssh_PermitRootLogin")
    remote.source_host = "10.0.0.5"
    srv._findings_cache["default:ws"] = [remote]   # caché de una conexión WS del tenant "default"
    c = TestClient(TestServer(srv.build_app()))
    await c.start_server()
    await c.get("/login")
    csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
    await c.post("/login", data={"username": "admin", "password": "clave-de-prueba", "_csrf": csrf},
                 allow_redirects=False)
    c.srv = srv
    yield c
    await c.close()


async def test_fix_local_no_aplica_hallazgos_remotos_en_este_servidor(client, monkeypatch):
    called = []
    monkeypatch.setattr(HardeningFixer, "fix", lambda self, f: called.append(f))
    r = await client.post("/api/fix/local", json={"finding_id": "10.0.0.5::ssh_PermitRootLogin"})
    assert r.status == 400 and called == []
    assert (await client.post("/api/fix/local", json={"finding_id": "no-existe"})).status == 404


async def test_fix_remoto_usa_el_host_del_hallazgo(client, monkeypatch):
    seen = []

    async def fake(self, host, finding):
        seen.append(host)
        return False, "sin conexión", None
    monkeypatch.setattr(RemoteAuditor, "apply_fix_remote", fake)
    r = await client.post("/api/fix/remote", json={"finding_id": "10.0.0.5::ssh_PermitRootLogin",
                                                    "host": "10.9.9.9"})
    d = await r.json()
    assert seen == ["10.0.0.5"]
    assert d["ok"] is False and d["error"] == "sin conexión"  # la UI muestra d.error


def test_accion_inversa_solo_con_estado_previo_valido():
    ua = RemoteAuditor.undo_action
    ssh = {"action": "ssh_param", "param": "PermitRootLogin", "value": "no"}
    assert ua(ssh, {"line": "PermitRootLogin yes"}) == {"action": "ssh_param_undo", "param": "PermitRootLogin",
                                                        "line": "PermitRootLogin yes"}
    assert ua(ssh, {"line": None})["line"] is None                  # no estaba: se quita la línea
    assert ua(ssh, {"line": "PermitRootLogin yes\nMatch all"}) is None
    assert ua(ssh, {"line": "PasswordAuthentication yes"}) is None   # otra directiva: el host miente
    assert ua({"action": "ufw_enable"}, {"active": False}) == {"action": "ufw_disable"}
    assert ua({"action": "ufw_enable"}, {"active": True}) is None   # ya estaba activo: nada que deshacer
    sysctl = {"action": "sysctl", "param": "net.ipv4.ip_forward", "value": "0"}
    assert ua(sysctl, {"value": "1", "conf_added": True})["value"] == "1"
    assert ua(sysctl, {"value": "1; reboot"}) is None
    assert ua({"action": "chmod_ow", "path": "/etc/a"}, {"mode": 0o666})["mode"] == 0o666
    assert ua({"action": "chmod_ow", "path": "/etc/a"}, {"mode": "777"}) is None
    assert ua({"action": "svc_disable", "svc": "telnet"}, None) is None


def test_deshacer_chmod_con_el_script_real(tmp_path):
    import json
    import os
    import subprocess
    import sys
    target = tmp_path / "f"
    target.write_text("x")
    os.chmod(target, 0o646)
    action = {"action": "chmod_ow", "path": str(target)}

    def run(a):
        out = subprocess.run([sys.executable, "-"], input=RemoteAuditor._fix_payload(a),
                             capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout.strip().splitlines()[-1])
    res = run(action)
    assert res["ok"] and os.stat(target).st_mode & 0o777 == 0o644
    undo = RemoteAuditor.undo_action(action, res["before"])
    assert run(undo)["ok"] and os.stat(target).st_mode & 0o777 == 0o646


def test_deshacer_ssh_param_con_el_script_real(tmp_path):
    """Fix y deshacer de sshd_config con el script real (sshd -t y systemctl simulados)."""
    import json
    import os
    import subprocess
    import sys
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sshd", "systemctl"):
        (bin_dir / tool).write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / tool).chmod(0o755)
    conf = tmp_path / "sshd_config"
    original = "Port 22\nPermitRootLogin yes\nUsePAM yes\n"

    def run(a):
        payload = RemoteAuditor._fix_payload(a).replace("/etc/ssh/sshd_config", str(conf))
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
        out = subprocess.run([sys.executable, "-"], input=payload, capture_output=True, text=True, timeout=30, env=env)
        return json.loads(out.stdout.strip().splitlines()[-1])
    for start, param in ((original, "PermitRootLogin"), (original, "X11Forwarding")):
        conf.write_text(start)
        action = {"action": "ssh_param", "param": param, "value": "no"}
        res = run(action)
        assert res["ok"] and f"{param} no" in conf.read_text()
        assert run(RemoteAuditor.undo_action(action, res["before"]))["ok"]
        assert conf.read_text().strip() == start.strip(), param
