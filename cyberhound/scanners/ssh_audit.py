"""
Auditoría remota via SSH usando asyncssh.

Ventajas sobre sshpass + subprocess:
- Las credenciales NUNCA aparecen en ps aux ni en la tabla de procesos.
- Soporte nativo de claves Ed25519/RSA/ECDSA y agente SSH.
- Control de errores tipado (asyncssh.Error → subclases específicas).
- Multiplexación de conexiones (una conexión → múltiples comandos).
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding, HostResult

logger = get_logger("ssh_audit")

REMOTE_SCRIPT = "/tmp/.ch_audit_{pid}.py"
REMOTE_OUTPUT = "/tmp/.ch_result_{pid}.json"


@dataclass
class SSHCredentials:
    """
    Credenciales SSH.
    NUNCA almacenar passwords en texto plano en logs o variables de entorno.
    Preferir siempre clave privada o agente SSH.
    """
    username:   str = "root"
    port:       int = 22
    # Autenticación por clave (recomendada)
    key_path:   str | None = None
    passphrase: str | None = None   # passphrase de la clave, NO la contraseña del sistema
    # Autenticación por contraseña (solo si no hay alternativa)
    password:   str | None = None   # Se maneja en memoria, nunca en disco ni logs
    # Opciones de conexión
    known_hosts: str | None = None  # None = no verificar (aceptar al primero, TOFU)
    connect_timeout: int = 15

    def to_asyncssh_opts(self) -> dict:
        opts: dict = {
            "username":         self.username,
            "port":             self.port,
            "connect_timeout":  self.connect_timeout,
            "known_hosts":      self.known_hosts,
        }
        if self.key_path:
            opts["client_keys"] = [self.key_path]
            if self.passphrase:
                opts["passphrase"] = self.passphrase
        elif self.password:
            opts["password"] = self.password
        else:
            # Intentar con el agente SSH del sistema
            opts["agent_path"] = None  # asyncssh usa SSH_AUTH_SOCK automáticamente
        return opts


class RemoteAuditor:
    """
    Ejecuta el audit de CyberHound en hosts remotos via asyncssh.

    Flujo:
    1. Conectar al host
    2. Verificar Python3
    3. Copiar el módulo de auditoría minimal (no el script completo)
    4. Ejecutar y recoger JSON
    5. Limpiar ficheros temporales
    """

    # Script mínimo de audit que se copia al host remoto
    # Solo contiene los checks de hardening, sin la UI ni las dependencias web
    REMOTE_AUDIT_SCRIPT = '''
import json, os, re, shutil, subprocess, sys
from pathlib import Path

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1

findings = []

def add(fid, cat, sev, title, desc, rem, evidence="", auto_fix=False, file_path=""):
    findings.append({
        "id": fid, "category": cat, "severity": sev, "title": title,
        "description": desc, "remediation": rem, "evidence": evidence[:500],
        "auto_fix": auto_fix, "file_path": file_path,
        "passed": False, "line_number": 0, "code_snippet": "",
    })

# SSH
sshd = Path("/etc/ssh/sshd_config")
if sshd.exists():
    c = sshd.read_text()
    for param, bad in [("PermitRootLogin","yes"),("PasswordAuthentication","yes"),
                       ("PermitEmptyPasswords","yes"),("X11Forwarding","yes")]:
        if re.search(rf"^\\s*{param}\\s+{bad}", c, re.MULTILINE|re.IGNORECASE):
            add(f"ssh_{param}","ssh","high",f"{param} inseguro",f"Valor: {bad}",
                f"Establecer {param} no en sshd_config", auto_fix=True)

# Firewall
ufw = shutil.which("ufw")
if ufw:
    out,_,_ = run(["ufw","status"])
    if "inactive" in out.lower():
        add("fw_inactive","firewall","critical","UFW inactivo","","ufw enable",auto_fix=True)

# Kernel params
for param, expected in [
    ("net.ipv4.ip_forward","0"),("net.ipv4.tcp_syncookies","1"),
    ("kernel.randomize_va_space","2"),("net.ipv4.conf.all.accept_source_route","0"),
]:
    p = Path("/proc/sys")/param.replace(".","/ ")
    if p.exists():
        v = p.read_text().strip()
        if v != expected:
            add(f"kernel_{param}","kernel","high",f"Parámetro inseguro: {param}",
                f"Actual:{v} Esperado:{expected}",f"sysctl -w {param}={expected}",auto_fix=True)

# PAM faillock
pam_ok = any("faillock" in Path(f).read_text()
              for f in ["/etc/pam.d/common-auth","/etc/pam.d/system-auth"]
              if Path(f).exists())
if not pam_ok:
    add("no_pam_faillock","authentication","high","pam_faillock no configurado",
        "Sin bloqueo por intentos fallidos","Configurar pam_faillock en /etc/pam.d/common-auth")

# World-writable (solo directorios clave, no / completo para ser rápido)
for scan_dir in ["/etc","/usr/bin","/usr/sbin","/bin","/sbin"]:
    out,_,rc = run(["find",scan_dir,"-xdev","-type","f","-perm","-o+w",
                    "-not","-path","/proc/*"],timeout=20)
    for f in out.splitlines()[:20]:
        if f.strip():
            fid = "ww_"+f.replace("/","_").strip("_")[:50]
            add(fid,"filesystem","high",f"World-writable: {f}","",f"chmod o-w {f}",
                auto_fix=True, file_path=f)

# Servicios inseguros
out,_,_ = run(["systemctl","list-units","--type=service","--state=active","--no-pager"])
for svc in ["telnet","rsh","nis","finger","tftp"]:
    if svc in out.lower():
        add(f"svc_{svc}","services","high",f"Servicio inseguro: {svc}","",
            f"systemctl disable --now {svc}",auto_fix=True)

# sudoers NOPASSWD
for sf in ["/etc/sudoers"]+list(Path("/etc/sudoers.d").glob("*") if Path("/etc/sudoers.d").exists() else []):
    try:
        for i,line in enumerate(Path(sf).read_text().splitlines(),1):
            if "NOPASSWD" in line and not line.strip().startswith("#"):
                add(f"sudoers_nopasswd_{Path(sf).name}_{i}","sudo","high",
                    f"NOPASSWD en sudoers",line.strip(),
                    "Revisar si NOPASSWD es necesario",evidence=line)
    except: pass

print(json.dumps(findings))
'''

    def __init__(self, credentials: SSHCredentials) -> None:
        if not ASYNCSSH_AVAILABLE:
            raise RuntimeError(
                "asyncssh no está instalado. "
                "Instala con: pip install asyncssh\n"
                "asyncssh es necesario para el análisis SSH seguro "
                "(alternativa a sshpass que expone credenciales en ps aux)."
            )
        self.creds = credentials

    async def audit_host(self, host: str) -> HostResult:
        start = time.monotonic()
        result = HostResult(
            host=host, port=self.creds.port,
            user=self.creds.username, status="error",
        )

        try:
            async with asyncssh.connect(
                host, **self.creds.to_asyncssh_opts()
            ) as conn:
                logger.info("SSH conectado a %s", host)

                # Obtener info del sistema
                info_cmds = [
                    "uname -a",
                    "cat /etc/os-release 2>/dev/null | head -5",
                    "hostname",
                ]
                for cmd in info_cmds:
                    try:
                        r = await conn.run(cmd, timeout=10)
                        if r.exit_status == 0:
                            result.os_info += r.stdout.strip() + " | "
                    except Exception:
                        pass

                # Verificar Python3
                py_check = await conn.run("python3 --version 2>&1", timeout=10)
                if py_check.exit_status != 0 or "Python 3" not in py_check.stdout + py_check.stderr:
                    result.status = "error"
                    result.error = "Python3 no disponible en el host remoto"
                    logger.warning("%s: %s", host, result.error)
                    return result

                # Copiar script de audit inline (sin SCP, usa stdin)
                import os as _os
                pid = _os.getpid()
                script_path = f"/tmp/.ch_audit_{pid}.py"
                output_path = f"/tmp/.ch_result_{pid}.json"

                # Escribir script via echo/cat para evitar SCP
                # Usamos sftp (incluido en asyncssh) que es seguro y no expone datos en ps
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open(script_path, "w") as f:
                        await f.write(self.REMOTE_AUDIT_SCRIPT)

                # Ejecutar con sudo -n (no interactivo): los checks necesitan
                # visibilidad real de root (shadow, sudoers, servicios) — sin
                # esto, conectar como usuario normal da una auditoría incompleta
                # y potencialmente engañosa (igual que el problema original de
                # auditar "localhost" sin visibilidad real del host).
                # Si el usuario no tiene sudo sin contraseña, sudo -n falla
                # limpiamente (no se queda colgado esperando un prompt) y el
                # script cae de vuelta a ejecutar sin privilegios elevados.
                run_cmd = (
                    f"sudo -n python3 {script_path} > {output_path} 2>/dev/null"
                    f" || python3 {script_path} > {output_path} 2>/dev/null"
                    f" ; cat {output_path}"
                    f" ; rm -f {script_path} {output_path}"
                )
                exec_result = await conn.run(run_cmd, timeout=120)

                # Parsear
                stdout = exec_result.stdout.strip()
                json_start = stdout.find("[")
                if json_start == -1:
                    result.status = "error"
                    result.error = f"Sin JSON en salida. stderr: {exec_result.stderr[:200]}"
                    logger.error("%s: %s", host, result.error)
                    return result

                data = json.loads(stdout[json_start:])
                findings = []
                for d in data:
                    f = Finding.from_dict(d)
                    f.id = f"{host}::{f.id}"
                    f.source_host = host
                    findings.append(f)

                result.findings = findings
                result.status = "ok"
                result.scan_time = time.monotonic() - start
                logger.info(
                    "%s: ✓ %d hallazgos en %.1fs",
                    host, len(findings), result.scan_time,
                )

        except asyncssh.DisconnectError as e:
            result.status = "unreachable"
            result.error = f"Conexión rechazada: {e}"
            logger.warning("%s: %s", host, result.error)
        except asyncssh.PermissionDenied:
            result.status = "auth_failed"
            result.error = "Autenticación SSH fallida (clave o contraseña incorrecta)"
            logger.warning("%s: %s", host, result.error)
        except asyncssh.HostKeyNotVerifiable:
            result.status = "error"
            result.error = "Host key no verificable. Añade el host a known_hosts primero."
            logger.error("%s: %s", host, result.error)
        except (ConnectionRefusedError, OSError) as e:
            result.status = "unreachable"
            result.error = str(e)
            logger.warning("%s inalcanzable: %s", host, e)
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            logger.error("%s: error inesperado: %s", host, e, exc_info=True)

        return result

    async def apply_fix_remote(self, host: str, remediation_cmd: str) -> tuple[bool, str]:
        """
        Aplica un comando de remediación en el host remoto.
        Solo permite comandos de una lista blanca.
        """
        SAFE_PREFIXES = (
            "chmod ", "chown ", "systemctl ", "sysctl -w ",
            "sed -i ", "ufw ", "apt-get install ",
        )
        cmd = remediation_cmd.split("\n")[0].strip()
        if not any(cmd.startswith(p) for p in SAFE_PREFIXES):
            return False, f"Comando bloqueado por política de seguridad: {cmd}"

        try:
            async with asyncssh.connect(host, **self.creds.to_asyncssh_opts()) as conn:
                r = await conn.run(cmd, timeout=60)
                if r.exit_status == 0:
                    logger.info("Fix remoto aplicado en %s: %s", host, cmd)
                    return True, ""
                else:
                    stderr = str(r.stderr) if r.stderr else ""
                    logger.error("Fix remoto falló en %s: %s", host, stderr)
                    return False, stderr[:300]
        except Exception as e:
            logger.error("Error aplicando fix remoto en %s: %s", host, e)
            return False, str(e)

    @classmethod
    async def scan_multiple(
        cls,
        hosts: list[str],
        credentials: SSHCredentials,
        concurrency: int = 5,
    ) -> list[HostResult]:
        auditor = cls(credentials)
        sem = asyncio.Semaphore(concurrency)

        async def _one(host: str) -> HostResult:
            async with sem:
                return await auditor.audit_host(host)

        return list(await asyncio.gather(*[_one(h) for h in hosts]))
