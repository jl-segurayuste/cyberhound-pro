"""
Integración con Ansible AWX / Tower para CyberHound Pro.

Permite lanzar playbooks de remediación directamente desde la UI de CyberHound
cuando se detectan hallazgos con corrección automática.

Modos:
  1. Ansible local — ejecuta ansible-playbook directamente en el servidor
  2. AWX/Tower API — lanza job templates via REST API de AWX

Los playbooks de remediación se generan automáticamente desde los hallazgos
de CyberHound en formato Ansible estándar (roles, tasks, handlers).
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

import yaml

from cyberhound import __version__
from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("ansible")


@dataclass
class AWXConfig:
    """Configuración de Ansible AWX/Tower."""
    enabled:      bool = False
    url:          str  = ""          # https://awx.empresa.com
    token:        str  = ""          # Personal Access Token de AWX
    org_id:       int  = 1
    inventory_id: int  = 1
    verify_ssl:   bool = True


@dataclass
class AnsibleJob:
    """Resultado de un job Ansible."""
    job_id:     str
    status:     str    # pending | running | successful | failed
    playbook:   str
    started_at: str
    finished_at: str | None = None
    output:     str = ""
    findings_fixed: list[str] = field(default_factory=list)


# ── Generador de playbooks ────────────────────────────────────────────────────
# El playbook se construye como datos y se vuelca con el SafeDumper de PyYAML: nunca se pega texto del
# hallazgo en el YAML ni en una tarea. El título, la remediación o el id de un hallazgo remoto los
# escribe el host auditado; antes iban a un f-string (una comilla rompía el YAML) y, en el export de
# informes, la remediación se ejecutaba tal cual con ansible.builtin.shell y become. Además Ansible
# evalúa las plantillas {{ … }} de los valores de una tarea en la máquina de control. Por eso las
# tareas solo llevan valores fijos de este catálogo o validados (rutas, servicios, usuarios, hosts).

SSHD_CONFIG = "/etc/ssh/sshd_config"
SYSCTL_FILE = "/etc/sysctl.d/99-cyberhound.conf"
SSH_PARAMS = {"PermitRootLogin": "no", "PasswordAuthentication": "no", "PermitEmptyPasswords": "no",
              "X11Forwarding": "no", "MaxAuthTries": "4"}
LOGIN_DEFS = {"PASS_MAX_DAYS": "90", "PASS_MIN_DAYS": "1", "PASS_WARN_AGE": "7", "LOGIN_RETRIES": "5"}
BANNER_FILES = {"no_banner_issue": "/etc/issue", "no_banner_issue_net": "/etc/issue.net"}
BANNER = ("AVISO: Este sistema es de uso exclusivo para personal autorizado.\n"
          "Toda actividad es registrada y supervisada.\n"
          "El acceso no autorizado está prohibido y puede ser objeto de acciones legales.\n")
_SAFE_PATH = re.compile(r"/[\w./+@-]+")
_SAFE_NAME = re.compile(r"[\w.@-]{1,64}")
_SAFE_USER = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
_SAFE_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")   # sin ":" (en hosts: une patrones)
_SSHD_HANDLER = "CyberHound: recargar sshd"


def _path(p: str | None, prefixes: tuple[str, ...] = ("/",)) -> str | None:
    p = p or ""
    return p if _SAFE_PATH.fullmatch(p) and ".." not in p and p.startswith(prefixes) else None


def _sshd(param: str, value: str) -> list[dict]:
    """sshd usa el PRIMER valor de cada opción y lee antes los sshd_config.d/*.conf incluidos al
    principio (p. ej. el de cloud-init con PasswordAuthentication yes). Un lineinfile solo cambiaba
    la última línea: con "X11Forwarding yes" de serie más arriba, el valor inseguro seguía mandando.

    Solo se tocan las líneas sin sangría (la sección global): las de un bloque Match, que por
    convención van sangradas, son excepciones que ha puesto el administrador."""
    regexp, line = rf"^{param}[ \t]+.*$", f"{param} {value}"
    found = f"cyberhound_sshd_{param}"
    return [
        {"name": f"CyberHound: {line} en sshd_config",
         "ansible.builtin.replace": {"path": SSHD_CONFIG, "regexp": regexp, "replace": line,
                                     "validate": "/usr/sbin/sshd -t -f %s"},
         "notify": _SSHD_HANDLER},
        {"name": f"CyberHound: {line} en sshd_config (si no estaba)",
         "ansible.builtin.lineinfile": {"path": SSHD_CONFIG, "regexp": rf"^{param}\s", "line": line,
                                        "insertbefore": r"^\s*Match\s", "firstmatch": True,
                                        "validate": "/usr/sbin/sshd -t -f %s"},
         "notify": _SSHD_HANDLER},
        {"name": f"CyberHound: {param} en sshd_config.d",
         "ansible.builtin.find": {"paths": "/etc/ssh/sshd_config.d", "patterns": "*.conf",
                                  "contains": rf"^{param}\s"},
         "register": found},
        {"name": f"CyberHound: {line} en sshd_config.d",
         "ansible.builtin.replace": {"path": "{{ item.path }}", "regexp": regexp, "replace": line},
         "loop": f"{{{{ {found}.files }}}}", "notify": _SSHD_HANDLER},
    ]


def _service(name: str, enabled: bool) -> dict:
    return {"name": f"CyberHound: {'activar' if enabled else 'desactivar'} {name}",
            "ansible.builtin.systemd_service": {"name": name, "enabled": enabled,
                                                "state": "started" if enabled else "stopped"}}


def _package(name: str) -> dict:
    return {"name": f"CyberHound: instalar {name}", "ansible.builtin.package": {"name": name, "state": "present"}}


def _mode(path: str, mode: str) -> dict:
    return {"name": f"CyberHound: permisos {mode} en {path}",
            "ansible.builtin.file": {"path": path, "mode": mode}}


def _sysctl(param: str, value: str) -> dict:
    return {"name": f"CyberHound: {param} = {value}",
            "ansible.posix.sysctl": {"name": param, "value": value, "sysctl_file": SYSCTL_FILE, "reload": True}}


def _only_file(dest: str, deny: str) -> list[dict]:
    return [{"name": f"CyberHound: solo root en {dest}",
             "ansible.builtin.copy": {"dest": dest, "content": "root\n", "owner": "root", "mode": "0600"}},
            {"name": f"CyberHound: quitar {deny}", "ansible.builtin.file": {"path": deny, "state": "absent"}}]


def _firewall_ufw() -> list[dict]:
    # Antes de activar, abrir el puerto SSH por el que entra Ansible: si no, la propia tarea deja
    # el host inaccesible (el fix local hace lo mismo con los puertos de sshd).
    return [{"name": "CyberHound: permitir SSH en ufw",
             "community.general.ufw": {"rule": "allow", "port": "{{ ansible_port | default(22) | string }}",
                                       "proto": "tcp"}},
            {"name": "CyberHound: activar ufw (entrada denegada por defecto)",
             "community.general.ufw": {"state": "enabled", "policy": "deny", "direction": "incoming"}}]


_EXACT: dict[str, list[dict]] = {
    "ssh_protocol1": [{"name": "CyberHound: quitar Protocol 1 de sshd_config",
                       "ansible.builtin.lineinfile": {"path": SSHD_CONFIG, "regexp": r"^\s*Protocol\s+1",
                                                      "state": "absent"},
                       "notify": _SSHD_HANDLER}],
    "fw_firewalld_inactive": [_service("firewalld", True)],
    "no_auditd": [_package("auditd"), _service("auditd", True)],
    "auditd_inactive": [_service("auditd", True)],
    "apparmor_inactive": [_service("apparmor", True)],
    "no_aide": [_package("aide")],
    "aide_db_missing": [
        {"name": "CyberHound: inicializar la base de datos de AIDE",
         "ansible.builtin.command": {"cmd": "aideinit -y -f", "creates": "/var/lib/aide/aide.db"}}],
    "no_unattended_upgrades": [
        _package("unattended-upgrades"),
        {"name": "CyberHound: activar las actualizaciones automáticas",
         "ansible.builtin.copy": {"dest": "/etc/apt/apt.conf.d/20auto-upgrades", "mode": "0644",
                                  "content": 'APT::Periodic::Update-Package-Lists "1";\n'
                                             'APT::Periodic::Unattended-Upgrade "1";\n'}}],
    "no_ntp": [_package("chrony"),
               {"name": "CyberHound: activar chrony",
                "ansible.builtin.systemd_service": {
                    "name": "{{ 'chrony' if ansible_facts.os_family == 'Debian' else 'chronyd' }}",
                    "enabled": True, "state": "started"}}],
    "tmp_no_sticky_bit": [_mode("/tmp", "1777")],
    "ctrlaltdel_enabled": [{"name": "CyberHound: enmascarar ctrl-alt-del.target",
                            "ansible.builtin.systemd_service": {"name": "ctrl-alt-del.target", "masked": True}}],
    "core_dumps_enabled": [
        {"name": "CyberHound: sin volcados de memoria (limits.conf)",
         "ansible.builtin.blockinfile": {"path": "/etc/security/limits.conf", "marker": "# {mark} CyberHound core",
                                         "block": "* hard core 0\n* soft core 0"}},
        _sysctl("fs.suid_dumpable", "0")],
    "usb_storage_enabled": [
        {"name": "CyberHound: directorio /etc/modprobe.d",
         "ansible.builtin.file": {"path": "/etc/modprobe.d", "state": "directory", "mode": "0755"}},
        {"name": "CyberHound: bloquear el módulo usb-storage",
         "ansible.builtin.copy": {"dest": "/etc/modprobe.d/cyberhound-usb.conf", "mode": "0644",
                                  "content": "blacklist usb-storage\ninstall usb-storage /bin/false\n"}}],
    "no_pam_faillock": [
        {"name": "CyberHound: pam_faillock en common-auth",
         "ansible.builtin.lineinfile": {"path": "/etc/pam.d/common-auth", "insertbefore": r"^\s*auth\s",
                                        "firstmatch": True, "regexp": r"^auth\s+required\s+pam_faillock\.so",
                                        "line": "auth required pam_faillock.so preauth silent deny=5 unlock_time=600"},
         "when": "ansible_facts.os_family == 'Debian'"},
        {"name": "CyberHound: pam_faillock en common-account",
         "ansible.builtin.lineinfile": {"path": "/etc/pam.d/common-account",
                                        "line": "account required pam_faillock.so"},
         "when": "ansible_facts.os_family == 'Debian'"}],
    "cron_no_restriction": _only_file("/etc/cron.allow", "/etc/cron.deny"),
    "cron_unrestricted": _only_file("/etc/cron.allow", "/etc/cron.deny"),
    "at_no_restriction": _only_file("/etc/at.allow", "/etc/at.deny"),
}


def finding_tasks(f: Finding) -> list[dict]:
    """Tareas Ansible que corrigen el hallazgo, o [] si necesita intervención manual."""
    fid = (f.id or "").split("::", 1)[-1]
    from cyberhound.scanners.hardening import KERNEL_PARAMS
    if fid in _EXACT:
        return copy.deepcopy(_EXACT[fid])
    if fid.startswith("ssh_") and fid[4:] in SSH_PARAMS:
        return _sshd(fid[4:], SSH_PARAMS[fid[4:]])
    if fid in ("fw_ufw_inactive", "fw_inactive"):
        return _firewall_ufw()
    if fid.startswith("kernel_"):
        name = fid[7:]
        for param, (value, _sev, _desc) in KERNEL_PARAMS.items():
            if name in (param, param.replace(".", "_")):
                return [_sysctl(param, value)]
        return []
    if fid.startswith("svc_") and not fid.startswith("svc_listen_all_") and _SAFE_NAME.fullmatch(fid[4:]):
        return [_service(fid[4:], False)]
    if fid.startswith("login_defs_") and fid[11:] in LOGIN_DEFS:
        param = fid[11:]
        return [{"name": f"CyberHound: login.defs {param}",
                 "ansible.builtin.lineinfile": {"path": "/etc/login.defs", "regexp": rf"^\s*{param}\s",
                                                "line": f"{param}\t{LOGIN_DEFS[param]}"}}]
    if fid in BANNER_FILES:
        return [{"name": f"CyberHound: banner en {BANNER_FILES[fid]}",
                 "ansible.builtin.copy": {"dest": BANNER_FILES[fid], "content": BANNER, "mode": "0644"}}]
    if fid.startswith("passwd_perm_") and fid[12:] in ("passwd", "shadow"):
        return [_mode(f"/etc/{fid[12:]}", "0640" if fid.endswith("shadow") else "0644")]
    if fid.startswith("ssh_hostkey_perm_") and (path := _path(f.file_path, ("/etc/ssh/",))):
        return [_mode(path, "0600")]
    if fid.startswith("ww_") and (path := _path(f.file_path)):
        return [_mode(path, "o-w")]
    if fid.startswith("log_perm_") and (path := _path(f.file_path, ("/var/log/",))):
        return [_mode(path, "o-r")]
    if fid.startswith("umask_insecure_") and (path := _path(f.file_path, ("/etc/",))):
        return [{"name": f"CyberHound: umask 027 en {path}",
                 "ansible.builtin.replace": {"path": path, "regexp": r"(umask\s+)0?22\b", "replace": r"\g<1>027"}}]
    if fid.startswith("empty_password_") and _SAFE_USER.fullmatch(fid[15:]):
        return [{"name": f"CyberHound: bloquear la cuenta sin contraseña {fid[15:]}",
                 "ansible.builtin.user": {"name": fid[15:], "password_lock": True}}]
    if fid.startswith("openssh_cve_"):
        return [{"name": "CyberHound: actualizar openssh-server",
                 "ansible.builtin.package": {"name": "openssh-server", "state": "latest", "update_cache": True}}]
    return []


def _one_line(text: str, limit: int = 120) -> str:
    return " ".join(str(text).split())[:limit]


def _host_of(f: Finding, local: str) -> str | None:
    host = (f.source_host or "").strip()
    if not host or host in ("localhost", "127.0.0.1"):
        return local
    return host if valid_target(host) else None


def valid_target(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 4      # una IPv6 en hosts: se lee como patrones
    except ValueError:
        return bool(_SAFE_HOST.fullmatch(target or ""))


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data) -> bool:
        return True


def build_playbook(findings: list[Finding], target: str = "localhost") -> tuple[str, int, list[Finding]]:
    """(playbook, tareas, hallazgos que requieren intervención manual).

    Un play por host: los hallazgos remotos se corrigen en el host donde se encontraron
    (source_host) y los locales en `target`. Playbook vacío si nada se puede automatizar."""
    if not valid_target(target):
        raise ValueError(f"Objetivo no válido: {target!r}")
    plays: dict[str, list[dict]] = {}
    manual: list[Finding] = []
    for f in findings:
        host = _host_of(f, target)
        tasks = finding_tasks(f) if host else []
        if not tasks:
            if f.severity != "info":
                manual.append(f)
            continue
        tag = re.sub(r"[^\w.-]", "_", (f.id or "").split("::", 1)[-1])[:80]
        plays.setdefault(host, []).extend({**t, "tags": ["cyberhound", tag]} for t in tasks)
    if not plays:
        return "", 0, manual
    doc = []
    for host, tasks in plays.items():
        play: dict = {"name": f"CyberHound Pro — remediación en {host}", "hosts": host, "become": True,
                      "gather_facts": True, "tasks": tasks}
        if any(t.get("notify") == _SSHD_HANDLER for t in tasks):
            play["handlers"] = [{"name": _SSHD_HANDLER, "ansible.builtin.systemd_service": {
                "name": "{{ 'ssh' if ansible_facts.os_family == 'Debian' else 'sshd' }}", "state": "reloaded"}}]
        doc.append(play)
    n = sum(len(t) for t in plays.values())
    header = [f"# CyberHound Pro {__version__} — playbook de remediación",
              f"# Generado: {datetime.now(UTC).isoformat(timespec='seconds')}",
              f"# Tareas: {n} en {len(plays)} host(s). Revísalo antes de ejecutarlo; prueba con --check --diff.",
              "# Colecciones: ansible.posix y community.general (incluidas en el paquete 'ansible')."]
    if manual:
        header.append(f"# Requieren intervención manual ({len(manual)}):")
        header += [f"#   - [{_one_line(f.severity, 10)}] {_one_line(f.title)}"
                   + (f" ({_one_line(f.source_host, 60)})" if f.source_host else "") for f in manual[:200]]
    body = yaml.dump(doc, Dumper=_NoAliases, sort_keys=False, allow_unicode=True, width=1000)
    return "\n".join(header) + "\n---\n" + body, n, manual


def generate_playbook(findings: list[Finding], target: str = "localhost") -> str:
    """Playbook de remediación de los hallazgos ("" si ninguno se puede corregir con Ansible)."""
    return build_playbook(findings, target)[0]


# ── Ejecución local ───────────────────────────────────────────────────────────

async def run_playbook_local(
    playbook_content: str,
    target: str = "localhost",
    inventory: str = "localhost,",
    extra_vars: dict | None = None,
) -> AnsibleJob:
    """Ejecuta un playbook Ansible en local."""
    if not command_exists("ansible-playbook"):
        return AnsibleJob(
            job_id="local_unavailable",
            status="failed",
            playbook="",
            started_at=datetime.now(UTC).isoformat(),
            output="ansible-playbook no está instalado. Instala con: apt install ansible",
        )

    import os
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(playbook_content)
        pb_path = f.name

    job_id = f"local_{int(datetime.now(UTC).timestamp())}"
    started_at = datetime.now(UTC).isoformat()

    try:
        cmd = ["ansible-playbook", pb_path, "-i", inventory, "--connection=local"]
        if extra_vars:
            cmd += ["--extra-vars", json.dumps(extra_vars)]

        proc = await run_command(cmd, timeout=300, check=False)
        status = "successful" if proc.returncode == 0 else "failed"
        return AnsibleJob(
            job_id=job_id, status=status,
            playbook=pb_path, started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            output=proc.stdout[-5000:] if proc.stdout else proc.stderr[-2000:],
        )
    finally:
        os.unlink(pb_path)


# ── AWX/Tower API ─────────────────────────────────────────────────────────────

class AWXClient:
    """Cliente para Ansible AWX / Ansible Tower API v2."""

    def __init__(self, cfg: AWXConfig) -> None:
        self.cfg = cfg

    async def launch_job_template(self, template_id: int, extra_vars: dict = None) -> AnsibleJob:
        """Lanza un job template en AWX y devuelve el job."""
        import ssl

        import aiohttp
        ssl_ctx = None if self.cfg.verify_ssl else ssl.create_default_context()
        if ssl_ctx:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        headers = {
            "Authorization": f"Bearer {self.cfg.token}",
            "Content-Type":  "application/json",
        }
        payload = {}
        if extra_vars:
            payload["extra_vars"] = json.dumps(extra_vars)

        url = f"{self.cfg.url.rstrip('/')}/api/v2/job_templates/{template_id}/launch/"
        started_at = datetime.now(UTC).isoformat()

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post(url, json=payload, ssl=ssl_ctx) as resp:
                    if resp.status not in (200, 201, 202):
                        body = await resp.text()
                        return AnsibleJob(
                            job_id="awx_error", status="failed",
                            playbook=f"template_{template_id}",
                            started_at=started_at,
                            output=f"AWX error {resp.status}: {body[:200]}",
                        )
                    data = await resp.json()
                    job_id = str(data.get("id", "?"))
                    logger.info("AWX job lanzado: #%s", job_id)
                    return AnsibleJob(
                        job_id=job_id, status="pending",
                        playbook=f"template_{template_id}",
                        started_at=started_at,
                    )
        except Exception as e:
            return AnsibleJob(
                job_id="awx_error", status="failed",
                playbook=f"template_{template_id}",
                started_at=started_at,
                output=f"Error conectando a AWX: {e}",
            )

    async def get_job_status(self, job_id: str) -> dict:
        """Obtiene el estado de un job en AWX."""
        import aiohttp
        url = f"{self.cfg.url.rstrip('/')}/api/v2/jobs/{job_id}/"
        headers = {"Authorization": f"Bearer {self.cfg.token}"}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {"status": "unknown", "error": f"HTTP {resp.status}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def list_job_templates(self) -> list[dict]:
        """Lista los job templates disponibles en AWX."""
        import aiohttp
        url = f"{self.cfg.url.rstrip('/')}/api/v2/job_templates/?page_size=50"
        headers = {"Authorization": f"Bearer {self.cfg.token}"}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("results", [])
                    return []
        except Exception as e:
            logger.error("Error listando templates AWX: %s", e)
            return []
