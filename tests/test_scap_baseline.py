"""Bastionado con perfiles SCAP (CCN-STIC y DISA STIG): scanners/scap_baseline.py.

Bug real que cubre (2026-10-27, contenedor de pruebas): oscap 1.3 ignora --rule en
`xccdf generate fix` y devuelve el script del perfil entero, así que corregir «una regla»
aplicaba las 140 del perfil. Ahora solo se ejecuta el bloque de esa regla, y si no se puede
aislar exactamente uno no se ejecuta nada.
"""
import subprocess
import sys

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from cyberhound.api.server import CyberHoundServer
from cyberhound.core import passwords
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.models import Finding
from cyberhound.core.scope import ws_targets
from cyberhound.core.security import InputValidator, ValidationError
from cyberhound.scanners import scap_baseline as sb
from cyberhound.scanners.compliance import analyze_compliance
from cyberhound.scanners.ssh_audit import RemoteAuditor

R = sb.RULE_PREFIX
DS = "/usr/share/xml/scap/ssg/content/ssg-cs9-ds.xml"


def _block(i, n, rule, body):
    return (f"###############################################################################\n"
            f"# BEGIN fix ({i} / {n}) for '{R}{rule}'\n"
            f"###############################################################################\n"
            f"(>&2 echo \"Remediating rule {i}/{n}: '{R}{rule}'\"); (\n{body}\n) # END fix for '{R}{rule}'\n\n")


# Mismo formato que genera oscap 1.3.16 con SSG 0.1.82
SCRIPT = ("#!/usr/bin/env bash\n# Bash Remediation Script for CCN\n\n"
          + _block(1, 3, "banner_etc_issue", "echo hola > /etc/issue")
          + _block(2, 3, "banner_etc_issue_net", "echo hola > /etc/issue.net")
          + _block(3, 3, "sshd_disable_root_login", "sed -i 's/yes/no/' /etc/ssh/sshd_config"))


# ── Extracción de una sola regla ──────────────────────────────────────────────

def test_extrae_solo_la_regla_pedida():
    out = sb.extract_rule_fix(SCRIPT, R + "banner_etc_issue")
    assert out.startswith("#!/usr/bin/env bash\n")
    assert "/etc/issue\n" in out and "issue.net" not in out and "sshd_config" not in out
    assert out.count("# BEGIN fix") == 1 and out.count(") # END fix for") == 1


def test_no_confunde_reglas_con_el_mismo_prefijo():
    out = sb.extract_rule_fix(SCRIPT, R + "banner_etc_issue_net")
    assert "issue.net" in out and "> /etc/issue\n" not in out


@pytest.mark.parametrize("script", [
    "",
    SCRIPT.replace(") # END fix for '" + R + "banner_etc_issue'", ""),        # sin final
    SCRIPT + _block(9, 9, "banner_etc_issue", "rm -rf /"),                     # duplicada
    _block(1, 1, "banner_etc_issue", "x").replace(                             # otra regla dentro
        "x\n", "x\n# BEGIN fix (2 / 2) for '" + R + "otra'\n"),
])
def test_sin_un_bloque_exacto_no_hay_script(script):
    assert sb.extract_rule_fix(script, R + "banner_etc_issue") is None


def test_regla_inexistente():
    assert sb.extract_rule_fix(SCRIPT, R + "no_existe") is None


# ── Hallazgos a partir de lo que devuelve el host ─────────────────────────────

def _data(**kw):
    d = {"os": "CentOS Stream 9", "ds": DS, "counts": {"pass": 3, "fail": 2, "error": 0, "notapplicable": 5},
         "fails": [{"rule": R + "banner_etc_issue", "result": "fail", "title": "Banner", "severity": "medium",
                    "fix": True},
                   {"rule": R + "sshd_disable_root_login", "result": "fail", "title": "Root", "severity": "high",
                    "fix": True}]}
    d.update(kw)
    return d


def test_hallazgos_ccn():
    fs = sb.findings_from(_data(), "10.0.0.5", "ccn_intermediate")
    assert [f.id for f in fs] == ["10.0.0.5::scap.ccn_intermediate.banner_etc_issue",
                                  "10.0.0.5::scap.ccn_intermediate.sshd_disable_root_login",
                                  "10.0.0.5::scap.ccn_intermediate._resumen"]
    assert all(f.category == "ccn-stic" and f.source_host == "10.0.0.5" for f in fs)
    assert fs[0].auto_fix and fs[0].file_path == DS and fs[0].title == "CCN-STIC intermedio: Banner"
    assert "pide confirmación" in fs[1].remediation
    assert fs[-1].passed and fs[-1].title == "CCN-STIC intermedio: 60 % de cumplimiento"


def test_hallazgos_stig_con_categoria_disa():
    fs = sb.findings_from(_data(), "h", "stig")
    assert fs[0].category == "disa-stig" and fs[0].title == "DISA STIG (CAT II): Banner"
    assert fs[1].title.startswith("DISA STIG (CAT I): ")


def test_lo_que_manda_el_host_se_valida():
    with pytest.raises(ValueError):
        sb.findings_from(_data(ds="/tmp/x.xml; rm -rf /"), "h", "stig")
    bad = _data(fails=[{"rule": "otra_cosa"}, {"rule": R + "a;b"}, "x", {"rule": R + "ok_rule", "fix": "true"}],
                counts={"pass": True, "fail": "9"})
    fs = sb.findings_from(bad, "h", "stig")
    assert [f.id for f in fs] == ["h::scap.stig.ok_rule", "h::scap.stig._resumen"]
    assert fs[0].auto_fix is False   # solo True literal


# ── Acciones de corrección y de deshacer ──────────────────────────────────────

def test_accion_de_correccion():
    f = sb.findings_from(_data(), "h", "ccn_basic")[0]
    a = RemoteAuditor.remote_fix_action(f)          # RemoteAuditor la delega en scap_baseline
    assert {k: a[k] for k in ("action", "profile", "rule", "ds")} == {
        "action": "scap_rule", "profile": "ccn_basic", "rule": "banner_etc_issue", "ds": DS}
    assert len(a["bid"]) == 16


def test_sin_accion_para_resumen_ni_hallazgos_raros():
    fs = sb.findings_from(_data(), "h", "ccn_basic")
    assert sb.remote_fix_action(fs[-1]) is None
    f = fs[0]
    f.file_path = "/etc/passwd"
    assert sb.remote_fix_action(f) is None
    other = Finding(id="h::scap.ccn_basic.x", category="ssh", severity="low", title="t", description="",
                    remediation="", auto_fix=True, file_path=DS)
    assert sb.remote_fix_action(other) is None and not sb.needs_confirmation(other)


def test_confirmacion_en_reglas_que_pueden_cortar_el_acceso():
    banner, root = sb.findings_from(_data(), "h", "stig")[:2]
    assert not sb.needs_confirmation(banner) and sb.needs_confirmation(root)


def test_payload_remoto_lleva_la_accion_como_dato_y_compila():
    a = {"action": "scap_rule", "profile": "stig", "rule": "x", "ds": DS, "bid": "a'\"\\\n__import__('os')"}
    payload = RemoteAuditor._fix_payload(a)
    ns = {}
    exec(payload.splitlines()[0], ns)
    assert ns["A"] == a
    compile(payload, "<scap-fix>", "exec")
    compile(sb._audit_payload("ccn_advanced"), "<scap-audit>", "exec")


def test_script_remoto_se_niega_sin_root():
    """El script entero se ejecuta de verdad (sin root): sale sin tocar nada."""
    a = {"action": "scap_rule", "profile": "stig", "rule": "x", "ds": DS, "bid": "0" * 16}
    r = subprocess.run([sys.executable, "-"], input=sb.fix_payload(a), capture_output=True, text=True, timeout=30)
    assert '"ok": false' in r.stdout and "root" in r.stdout


def test_deshacer_solo_con_estado_previo_valido():
    a = {"action": "scap_rule", "bid": "ab" * 8}
    good = {"bid": "ab" * 8, "changed": ["/etc/issue"], "removed": [], "added": ["/etc/modprobe.d/udf.conf"]}
    assert RemoteAuditor.undo_action(a, good) == {"action": "scap_undo", "bid": "ab" * 8,
                                                  "added": ["/etc/modprobe.d/udf.conf"], "files": 1}
    for bad in ({**good, "bid": "cd" * 8}, {**good, "added": ["/root/.ssh/authorized_keys"]},
                {**good, "changed": ["/etc/../root/x"]}, {**good, "removed": "/etc/issue"},
                {**good, "changed": ["/etc/a;b"]}):
        assert sb.undo_action(a, bad) is None, bad


# ── Validación, ámbito y cumplimiento ─────────────────────────────────────────

def test_mensaje_ws():
    m = InputValidator.ws_message({"task": "scap", "hosts": "10.0.0.5, 10.0.0.6", "profile": "stig"})
    assert m["hosts"] == "10.0.0.5 10.0.0.6" and m["profile"] == "stig"
    assert ws_targets(m) == ["10.0.0.5", "10.0.0.6"]
    assert InputValidator.ws_message({"task": "scap", "hosts": "h1"})["profile"] == sb.DEFAULT_PROFILE
    for bad in ({"task": "scap", "hosts": "h1", "profile": "../x"},
                {"task": "scap", "hosts": "h1; id", "profile": "stig"}):
        with pytest.raises(ValidationError):
            InputValidator.ws_message(bad)


def test_cumplimiento_ens_sin_contar_el_resumen():
    fs = sb.findings_from(_data(), "h", "ccn_intermediate")
    ens = analyze_compliance(fs, ["ens"])["ens"]
    assert "ENS-OP.EXP.2" in {c["id"] for c in ens.failed_controls}
    assert analyze_compliance([fs[-1]], ["ens"])["ens"].failed == 0   # el resumen no es un fallo


# ── API: confirmación de correcciones peligrosas ──────────────────────────────

@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setattr(CyberHoundConfig, "save", lambda self, *a, **k: None)
    cfg = CyberHoundConfig()
    cfg.db_path = tmp_path / "scap.db"
    cfg.server.log_dir = str(tmp_path)
    cfg.auth.username = "admin"
    cfg.auth.password_hash = passwords.hash_password("clave-de-prueba")
    cfg.auth.secret = "s" * 64
    srv = CyberHoundServer(cfg)
    await srv.db.init()
    srv._findings_cache["default:ws"] = sb.findings_from(_data(), "10.0.0.5", "ccn_intermediate")
    c = TestClient(TestServer(srv.build_app()))
    await c.start_server()
    await c.get("/login")
    csrf = c.session.cookie_jar.filter_cookies(c.make_url("/")).get("ch_csrf").value
    await c.post("/login", data={"username": "admin", "password": "clave-de-prueba", "_csrf": csrf},
                 allow_redirects=False)
    yield c
    await c.close()


async def test_fix_peligroso_pide_confirmacion(client, monkeypatch):
    seen = []

    async def fake(self, host, finding, action=None):
        seen.append(action)
        return True, "", {"action": "scap_undo", "bid": action["bid"], "added": [], "files": 1}
    monkeypatch.setattr(RemoteAuditor, "apply_fix_remote", fake)
    fid = "10.0.0.5::scap.ccn_intermediate.sshd_disable_root_login"
    r = await client.post("/api/fix/remote", json={"finding_id": fid})
    d = await r.json()
    assert r.status == 409 and d["needs_confirmation"] is True and not seen
    r = await client.post("/api/fix/remote", json={"finding_id": fid, "confirm": True})
    d = await r.json()
    assert r.status == 200 and d["reversible"] is True
    assert seen[0]["rule"] == "sshd_disable_root_login"
    # Lo que se registra es la acción que se ejecutó (mismo bid que el del deshacer)
    hist = await (await client.get("/api/fix/remote/history")).json()
    assert hist[0]["action"]["bid"] == seen[0]["bid"] == hist[0]["undo"]["bid"]


async def test_fix_sin_riesgo_no_pide_confirmacion(client, monkeypatch):
    async def fake(self, host, finding, action=None):
        return True, "", None
    monkeypatch.setattr(RemoteAuditor, "apply_fix_remote", fake)
    r = await client.post("/api/fix/remote", json={"finding_id": "10.0.0.5::scap.ccn_intermediate.banner_etc_issue"})
    assert r.status == 200
