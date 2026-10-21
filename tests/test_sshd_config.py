"""Configuración efectiva de sshd (cyberhound/core/sshd_config.py), auditoría y fix local de SSH.

sshd usa el primer valor de cada opción, lee los Include donde aparecen y lo de un Match solo vale
para esas conexiones. Antes la auditoría y el fix solo miraban sshd_config."""
import pytest

from cyberhound.core import sshd_config
from cyberhound.core.models import Finding
from cyberhound.scanners import hardening

MAIN = ("Include sshd_config.d/*.conf\n"
        "PermitRootLogin no\n"
        "X11Forwarding yes\n"
        "X11Forwarding no\n"
        "MaxAuthTries=3\n"
        "\n"
        "Match User deploy\n"
        "    PasswordAuthentication yes\n"
        "    PermitRootLogin yes\n")


@pytest.fixture
def conf(tmp_path, monkeypatch):
    (tmp_path / "sshd_config.d").mkdir()
    (tmp_path / "sshd_config").write_text(MAIN)
    (tmp_path / "sshd_config.d/50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    (tmp_path / "sshd_config.d/10-a.conf").write_text("# comentario\nUsePAM yes\n")
    monkeypatch.setattr(sshd_config, "SSHD_CONFIG", str(tmp_path / "sshd_config"))
    return tmp_path


def test_valor_efectivo(conf):
    eff = sshd_config.effective()
    assert eff["passwordauthentication"] == ("yes", str(conf / "sshd_config.d/50-cloud-init.conf"))
    assert eff["x11forwarding"][0] == "yes"                    # el primero gana
    assert eff["permitrootlogin"][0] == "no"                   # el del Match no cuenta
    assert eff["maxauthtries"][0] == "3" and eff["usepam"][0] == "yes"   # "=" y orden de los includes


def test_plan_cambia_todas_las_globales_y_respeta_match(conf):
    new, changes = sshd_config.plan_set("X11Forwarding", "no")
    assert list(new) == [str(conf / "sshd_config")]
    assert new[str(conf / "sshd_config")].count("X11Forwarding no") == 2
    assert changes == [{"file": "sshd_config", "old": "X11Forwarding yes", "new": "X11Forwarding no"}]
    new, changes = sshd_config.plan_set("PermitRootLogin", "no")
    assert new == {} and changes == []                        # ya estaba bien; el Match no se toca
    new, changes = sshd_config.plan_set("PermitEmptyPasswords", "no")
    text = new[str(conf / "sshd_config")]
    assert text.index("PermitEmptyPasswords no") < text.index("Match User deploy")   # no dentro del Match
    assert changes[0]["old"] is None


def test_plan_y_deshacer(conf):
    before = {p.name: p.read_text() for p in conf.rglob("*") if p.is_file()}
    new, changes = sshd_config.plan_set("PasswordAuthentication", "no")
    for path, text in new.items():
        open(path, "w").write(text)
    assert sshd_config.effective()["passwordauthentication"][0] == "no"
    assert "    PasswordAuthentication yes" in (conf / "sshd_config").read_text()
    for path, text in sshd_config.plan_undo(changes).items():
        open(path, "w").write(text)
    assert {p.name: p.read_text() for p in conf.rglob("*") if p.is_file()} == before


def test_include_fuera_del_directorio_no_se_toca(conf, tmp_path_factory):
    other = tmp_path_factory.mktemp("fuera") / "x.conf"
    other.write_text("X11Forwarding yes\n")
    (conf / "sshd_config").write_text(f"Include {other}\nX11Forwarding no\n")
    new, _ = sshd_config.plan_set("X11Forwarding", "no")
    assert str(other) not in new


def test_el_script_remoto_lo_lleva_y_es_python_36():
    """El módulo viaja delante de los scripts remotos, que tienen que funcionar con el python3 de RHEL 8 (3.6)."""
    import ast

    from cyberhound.scanners.ssh_audit import RemoteAuditor
    for script in (RemoteAuditor.REMOTE_AUDIT_SCRIPT, RemoteAuditor.REMOTE_FIX_SCRIPT):
        assert "def plan_set(" in script and "def effective(" in script
        ast.parse(script, feature_version=(3, 6))
        assert ".removesuffix(" not in script and ".removeprefix(" not in script
        # subprocess.run(capture_output=, text=) es de 3.7: en RHEL 8 el fix remoto fallaba siempre y la
        # auditoría se saltaba sin avisar los checks que lanzan comandos
        assert "capture_output" not in script and "text=True" not in script


async def test_auditoria_local_ve_el_drop_in(conf):
    ids = {f.id: f for f in await hardening.check_ssh()}
    assert "ssh_PasswordAuthentication" in ids and "50-cloud-init.conf" in ids["ssh_PasswordAuthentication"].evidence
    assert "ssh_X11Forwarding" in ids and "ssh_PermitRootLogin" not in ids and "ssh_MaxAuthTries" not in ids


async def test_fix_local_cambia_el_drop_in(conf, monkeypatch):
    fixer = hardening.HardeningFixer()
    ran = []

    async def fake_run(cmd, timeout=60):
        ran.append(cmd)
        return True, ""
    monkeypatch.setattr(fixer, "_run", fake_run)
    f = Finding(id="ssh_PasswordAuthentication", category="ssh", severity="high", title="t", description="",
                remediation="", auto_fix=True)
    ok, msg = await fixer.fix(f)
    assert ok and "50-cloud-init.conf" in msg
    assert sshd_config.effective()["passwordauthentication"][0] == "no"
    assert ["sshd", "-t"] in ran and ["systemctl", "reload", "sshd"] in ran
    assert len(fixer.rollback_actions) == 2                    # recargar + copia del drop-in

    async def sshd_rejects(cmd, timeout=60):
        return (cmd != ["sshd", "-t"]), "bad config"
    monkeypatch.setattr(fixer, "_run", sshd_rejects)
    before = (conf / "sshd_config").read_text()
    f.id = "ssh_X11Forwarding"
    ok, msg = await fixer.fix(f)
    assert not ok and (conf / "sshd_config").read_text() == before      # sshd -t lo rechaza: restaurado
