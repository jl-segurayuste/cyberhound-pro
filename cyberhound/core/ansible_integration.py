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

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

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

def generate_playbook(findings: list[Finding], target: str = "localhost") -> str:
    """
    Genera un playbook Ansible de remediación a partir de los hallazgos.
    Solo incluye findings con auto_fix=True.
    """
    fixable = [f for f in findings if f.auto_fix]
    if not fixable:
        return ""

    tasks = []
    for f in fixable:
        task = _finding_to_task(f)
        if task:
            tasks.append(task)

    if not tasks:
        return ""

    tasks_yaml = "\n".join(tasks)
    return f"""---
# CyberHound Pro — Playbook de remediación
# Generado: {datetime.now(UTC).isoformat()}
# Objetivo: {target}
# Hallazgos: {len(fixable)} con corrección automática disponible

- name: CyberHound Pro — Remediación de seguridad
  hosts: {target}
  become: yes
  gather_facts: yes

  vars:
    cyberhound_version: "6.2.0"
    cyberhound_target: "{target}"

  tasks:
{tasks_yaml}

  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted

    - name: reload sysctl
      command: sysctl --system

    - name: enable ufw
      ufw:
        state: enabled
"""


def _finding_to_task(f: Finding) -> str:
    """Convierte un Finding en una task Ansible."""
    fid = f.id or ""
    rem = f.remediation or ""

    indent = "    "

    # SSH fixes
    if "ssh_PermitRootLogin" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar login root via SSH"
{indent}  lineinfile:
{indent}    path: /etc/ssh/sshd_config
{indent}    regexp: '^#?PermitRootLogin'
{indent}    line: 'PermitRootLogin no'
{indent}    state: present
{indent}  notify: restart sshd"""

    if "ssh_PasswordAuthentication" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar autenticación por contraseña SSH"
{indent}  lineinfile:
{indent}    path: /etc/ssh/sshd_config
{indent}    regexp: '^#?PasswordAuthentication'
{indent}    line: 'PasswordAuthentication no'
{indent}    state: present
{indent}  notify: restart sshd"""

    if "ssh_MaxAuthTries" in fid:
        return f"""{indent}- name: "CyberHound: Limitar intentos de autenticación SSH"
{indent}  lineinfile:
{indent}    path: /etc/ssh/sshd_config
{indent}    regexp: '^#?MaxAuthTries'
{indent}    line: 'MaxAuthTries 4'
{indent}    state: present
{indent}  notify: restart sshd"""

    if "ssh_X11Forwarding" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar X11 forwarding"
{indent}  lineinfile:
{indent}    path: /etc/ssh/sshd_config
{indent}    regexp: '^#?X11Forwarding'
{indent}    line: 'X11Forwarding no'
{indent}    state: present
{indent}  notify: restart sshd"""

    # Firewall fixes
    if "fw_ufw_inactive" in fid:
        return f"""{indent}- name: "CyberHound: Activar UFW"
{indent}  ufw:
{indent}    state: enabled
{indent}    policy: deny
{indent}  when: ansible_os_family == 'Debian'"""

    if "fw_firewalld_inactive" in fid:
        return f"""{indent}- name: "CyberHound: Activar firewalld"
{indent}  service:
{indent}    name: firewalld
{indent}    state: started
{indent}    enabled: yes
{indent}  when: ansible_os_family == 'RedHat'"""

    # Kernel / sysctl
    if "kernel_aslr" in fid:
        return f"""{indent}- name: "CyberHound: Activar ASLR"
{indent}  sysctl:
{indent}    name: kernel.randomize_va_space
{indent}    value: '2'
{indent}    sysctl_file: /etc/sysctl.d/99-cyberhound.conf
{indent}    reload: yes"""

    if "kernel_syn_cookies" in fid:
        return f"""{indent}- name: "CyberHound: Activar SYN cookies"
{indent}  sysctl:
{indent}    name: net.ipv4.tcp_syncookies
{indent}    value: '1'
{indent}    sysctl_file: /etc/sysctl.d/99-cyberhound.conf
{indent}    reload: yes"""

    if "kernel_ip_forward" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar IP forwarding"
{indent}  sysctl:
{indent}    name: net.ipv4.ip_forward
{indent}    value: '0'
{indent}    sysctl_file: /etc/sysctl.d/99-cyberhound.conf
{indent}    reload: yes"""

    # Auditd no instalado
    if "no_auditd" in fid:
        return f"""{indent}- name: "CyberHound: Instalar y activar auditd"
{indent}  package:
{indent}    name: auditd
{indent}    state: present
{indent}- name: "CyberHound: Activar servicio auditd"
{indent}  service:
{indent}    name: auditd
{indent}    state: started
{indent}    enabled: yes"""

    # Auditd instalado pero inactivo
    if "auditd_inactive" in fid:
        return f"""{indent}- name: "CyberHound: Activar servicio auditd"
{indent}  service:
{indent}    name: auditd
{indent}    state: started
{indent}    enabled: yes"""

    # Sticky bit en /tmp
    if "tmp_no_sticky_bit" in fid:
        return f"""{indent}- name: "CyberHound: Aplicar sticky bit a /tmp"
{indent}  file:
{indent}    path: /tmp
{indent}    mode: '1777'
{indent}    state: directory"""

    # Restricción de cron (crear cron.allow con solo root)
    if "cron_no_restriction" in fid or "cron_unrestricted" in fid:
        return f"""{indent}- name: "CyberHound: Restringir cron a root"
{indent}  copy:
{indent}    dest: /etc/cron.allow
{indent}    content: "root\\n"
{indent}    mode: '0600'
{indent}- name: "CyberHound: Eliminar cron.deny"
{indent}  file:
{indent}    path: /etc/cron.deny
{indent}    state: absent"""

    # Restricción de at
    if "at_no_restriction" in fid:
        return f"""{indent}- name: "CyberHound: Restringir at a root"
{indent}  copy:
{indent}    dest: /etc/at.allow
{indent}    content: "root\\n"
{indent}    mode: '0600'
{indent}- name: "CyberHound: Eliminar at.deny"
{indent}  file:
{indent}    path: /etc/at.deny
{indent}    state: absent"""

    # Umask inseguro (configurar 027 en login.defs)
    if "umask_insecure" in fid:
        return f"""{indent}- name: "CyberHound: Establecer UMASK 027 en login.defs"
{indent}  lineinfile:
{indent}    path: /etc/login.defs
{indent}    regexp: '^UMASK'
{indent}    line: 'UMASK 027'
{indent}    state: present"""

    # NTP
    if "no_ntp" in fid:
        return f"""{indent}- name: "CyberHound: Instalar chrony"
{indent}  package:
{indent}    name: chrony
{indent}    state: present
{indent}- name: "CyberHound: Activar servicio chrony"
{indent}  service:
{indent}    name: chronyd
{indent}    state: started
{indent}    enabled: yes"""

    # Banners
    if "no_banner_issue" in fid:
        return f"""{indent}- name: "CyberHound: Crear banner /etc/issue"
{indent}  copy:
{indent}    dest: /etc/issue
{indent}    content: |
{indent}      ***** AVISO DE SEGURIDAD *****
{indent}      Acceso restringido. Solo usuarios autorizados.
{indent}      Toda actividad puede ser registrada y auditada.
{indent}      *******************************
{indent}    mode: '0644'"""

    # AppArmor
    if "apparmor_inactive" in fid:
        return f"""{indent}- name: "CyberHound: Activar AppArmor"
{indent}  service:
{indent}    name: apparmor
{indent}    state: started
{indent}    enabled: yes
{indent}  when: ansible_os_family == 'Debian'"""

    # Core dumps
    if "core_dumps_enabled" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar core dumps"
{indent}  sysctl:
{indent}    name: kernel.core_pattern
{indent}    value: '|/bin/false'
{indent}    sysctl_file: /etc/sysctl.d/99-cyberhound.conf
{indent}    reload: yes"""

    # Ctrl+Alt+Del
    if "ctrlaltdel_enabled" in fid:
        return f"""{indent}- name: "CyberHound: Deshabilitar Ctrl+Alt+Del"
{indent}  systemd:
{indent}    name: ctrl-alt-del.target
{indent}    masked: yes"""

    # Generic: usar el texto de remediación como comentario informativo
    if rem:
        first_line = rem.split("\n")[0][:100]
        return f"""{indent}- name: "CyberHound: {f.title[:60]}"
{indent}  debug:
{indent}    msg: "Remediación manual requerida: {first_line}"
{indent}  # TODO: implementar remediación automatizada para {f.id}"""

    return ""


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
