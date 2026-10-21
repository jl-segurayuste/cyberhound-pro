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
import re
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

# Lo que se puede corregir en remoto. El comando se construye aquí a partir del id
# del hallazgo: nunca se ejecuta la remediación que devuelve el host auditado.
REMOTE_SSH_PARAMS = ("PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords", "X11Forwarding")
REMOTE_SYSCTL = {
    "net.ipv4.ip_forward": "0", "net.ipv4.tcp_syncookies": "1",
    "kernel.randomize_va_space": "2", "net.ipv4.conf.all.accept_source_route": "0",
}
REMOTE_SERVICES = ("telnet", "rsh", "nis", "finger", "tftp")
REMOTE_WW_DIRS = ("/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")


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
    p = Path("/proc/sys")/param.replace(".","/")
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

# Servicios inseguros (match exacto por nombre de unidad, no substring del
# bloque completo: "nis" hacia substring coincidia con la palabra "finishes"
# en la descripcion de plymouth-quit-wait.service - falso positivo puro)
out,_,_ = run(["systemctl","list-units","--type=service","--state=active","--no-pager","--plain","--no-legend"])
unit_names = {ln.split()[0].lower().removesuffix(".service") for ln in out.splitlines() if ln.strip()}
for svc in ["telnet","rsh","nis","finger","tftp"]:
    if any(name == svc or name.startswith(svc + "-") or name.startswith(svc + "@") for name in unit_names):
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

                # El script va por stdin: nada en /tmp que otro usuario del host pueda
                # sustituir antes de que se ejecute con sudo. Con sudo -n (no interactivo)
                # los checks ven shadow, sudoers y servicios; sin sudo la auditoría es parcial.
                exec_result = await conn.run(await self._python_cmd(conn), input=self.REMOTE_AUDIT_SCRIPT,
                                             timeout=120)

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

    @staticmethod
    async def _python_cmd(conn) -> str:
        try:
            ok = (await conn.run("sudo -n true", timeout=10)).exit_status == 0
        except Exception:
            ok = False
        return "sudo -n python3 -" if ok else "python3 -"

    @staticmethod
    def remote_fix_action(finding: Finding) -> dict | None:
        """Acción de corrección para un hallazgo de la auditoría remota (None si no hay)."""
        fid = finding.id.split("::", 1)[-1]
        if fid.startswith("ssh_") and fid[4:] in REMOTE_SSH_PARAMS:
            return {"action": "ssh_param", "param": fid[4:], "value": "no"}
        if fid == "fw_inactive":
            return {"action": "ufw_enable"}
        if fid.startswith("kernel_") and fid[7:] in REMOTE_SYSCTL:
            return {"action": "sysctl", "param": fid[7:], "value": REMOTE_SYSCTL[fid[7:]]}
        if fid.startswith("svc_") and fid[4:] in REMOTE_SERVICES:
            return {"action": "svc_disable", "svc": fid[4:]}
        path = finding.file_path or ""
        if (fid.startswith("ww_") and path.startswith(REMOTE_WW_DIRS) and ".." not in path
                and re.fullmatch(r"/[\w./+@-]+", path)):
            return {"action": "chmod_ow", "path": path}
        return None

    REMOTE_FIX_SCRIPT = '''
import json, os, re, shutil, stat, subprocess, sys
def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]
def done(ok, msg="", before=None):
    print(json.dumps({"ok": ok, "msg": msg, "before": before})); sys.exit(0)
def sshd_apply(new, old, before):
    path = "/etc/ssh/sshd_config"
    open(path, "w").write(new)
    ok, err = run(["sshd", "-t"]) if shutil.which("sshd") else run(["/usr/sbin/sshd", "-t"])
    if not ok:
        open(path, "w").write(old); done(False, "sshd -t rechaza el cambio, restaurado: " + err)
    for unit in ("ssh", "sshd"):
        if run(["systemctl", "reload", unit])[0]:
            done(True, "", before)
    done(True, "aplicado; recarga sshd a mano", before)
act = A["action"]
if act in ("ssh_param", "ssh_param_undo"):
    path = "/etc/ssh/sshd_config"; old = open(path).read()
    pat = re.compile(r"^\\s*" + re.escape(A["param"]) + r"\\s+.*$", re.M | re.I)
    m = pat.search(old)
    if act == "ssh_param":
        line = A["param"] + " " + A["value"]
        new = pat.sub(line, old, count=1) if m else old.rstrip("\\n") + "\\n" + line + "\\n"
        shutil.copy2(path, path + ".cyberhound.bak")
        sshd_apply(new, old, {"line": m.group(0) if m else None})
    if A.get("line") is None:
        new = pat.sub("", old, count=1).replace("\\n\\n\\n", "\\n\\n") if m else old
    else:
        new = pat.sub(lambda _m: A["line"], old, count=1) if m else old.rstrip("\\n") + "\\n" + A["line"] + "\\n"
    sshd_apply(new, old, None)
if act == "ufw_enable":
    was_active = "Status: active" in subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
    ports = re.findall(r"^\\s*Port\\s+(\\d+)", open("/etc/ssh/sshd_config").read(), re.M) or ["22"]
    for p in ports:
        run(["ufw", "allow", p + "/tcp"])
    ok, err = run(["ufw", "--force", "enable"])
    done(ok, err, {"active": was_active})
if act == "ufw_disable":
    done(*run(["ufw", "--force", "disable"]))
if act in ("sysctl", "sysctl_undo"):
    conf = "/etc/sysctl.d/99-cyberhound.conf"
    cur = open(conf).read() if os.path.exists(conf) else ""
    if act == "sysctl":
        prev = subprocess.run(["sysctl", "-n", A["param"]], capture_output=True, text=True).stdout.strip()
        ok, err = run(["sysctl", "-w", A["param"] + "=" + A["value"]])
        added = False
        if ok and A["param"] not in cur:
            open(conf, "a").write(A["param"] + " = " + A["value"] + "\\n"); added = True
        done(ok, err, {"value": prev, "conf_added": added})
    ok, err = run(["sysctl", "-w", A["param"] + "=" + A["value"]])
    if ok and A.get("conf_added"):
        keep = [l for l in cur.splitlines(True) if not re.match(r"^\\s*" + re.escape(A["param"]) + r"\\s*=", l)]
        open(conf, "w").write("".join(keep))
    done(ok, err)
if act == "svc_disable":
    q = lambda *c: subprocess.run(["systemctl", *c, A["svc"]], capture_output=True, text=True).stdout.strip()
    before = {"active": q("is-active") == "active", "enabled": q("is-enabled") == "enabled"}
    ok, err = run(["systemctl", "disable", "--now", A["svc"]])
    done(ok, err, before)
if act == "svc_undo":
    if A.get("enabled"):
        ok, err = run(["systemctl", "enable", A["svc"]])
        if not ok: done(False, err)
    if A.get("active"):
        ok, err = run(["systemctl", "start", A["svc"]])
        if not ok: done(False, err)
    done(True)
if act in ("chmod_ow", "chmod_restore"):
    fd = os.open(A["path"], os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        done(False, "no es un fichero regular")
    mode = stat.S_IMODE(st.st_mode)
    os.fchmod(fd, mode & ~0o002 if act == "chmod_ow" else A["mode"])
    done(True, "", {"mode": mode} if act == "chmod_ow" else None)
done(False, "acción desconocida")
'''

    @staticmethod
    def undo_action(action: dict, before) -> dict | None:
        """Acción que deshace `action` a partir del estado previo que devolvió el host.

        `before` viene del host remoto, así que se valida aquí: lo que se guarda y se vuelve a
        enviar son solo valores con forma conocida, no lo que el host quiera."""
        if not isinstance(before, dict):
            return None
        act = action.get("action")
        if act == "ssh_param":
            line = before.get("line")
            if line is not None and not (isinstance(line, str) and len(line) < 200 and re.fullmatch(
                    r"\s*" + re.escape(action["param"]) + r"\s+[\w .,:@/=+-]*", line, re.I)):
                return None
            return {"action": "ssh_param_undo", "param": action["param"], "line": line}
        if act == "ufw_enable":
            return None if before.get("active") is not False else {"action": "ufw_disable"}
        if act == "sysctl":
            value = before.get("value")
            if not (isinstance(value, str) and re.fullmatch(r"[\w .:/-]{1,100}", value)):
                return None
            return {"action": "sysctl_undo", "param": action["param"], "value": " ".join(value.split()),
                    "conf_added": before.get("conf_added") is True}
        if act == "svc_disable":
            return {"action": "svc_undo", "svc": action["svc"], "active": before.get("active") is True,
                    "enabled": before.get("enabled") is True}
        if act == "chmod_ow":
            mode = before.get("mode")
            if not (isinstance(mode, int) and not isinstance(mode, bool) and 0 <= mode <= 0o7777):
                return None
            return {"action": "chmod_restore", "path": action["path"], "mode": mode}
        return None

    @classmethod
    def _fix_payload(cls, action: dict) -> str:
        # repr() de un str es un literal Python válido: la acción viaja como dato, no como código
        return f"A = __import__('json').loads({json.dumps(action)!r})\n" + cls.REMOTE_FIX_SCRIPT

    async def _run_remote_action(self, host: str, action: dict) -> dict:
        try:
            async with asyncssh.connect(host, **self.creds.to_asyncssh_opts()) as conn:
                r = await conn.run(await self._python_cmd(conn), input=self._fix_payload(action), timeout=90)
                out = (r.stdout or "").strip().splitlines()
                res = json.loads(out[-1]) if out else {"ok": False, "msg": (r.stderr or "")[:300]}
        except Exception as e:
            logger.error("Error en acción remota en %s: %s", host, e)
            return {"ok": False, "msg": str(e)}
        if res.get("ok"):
            logger.info("Acción remota en %s: %s", host, action)
        else:
            logger.error("Acción remota falló en %s: %s", host, res.get("msg"))
        return res

    async def apply_fix_remote(self, host: str, finding: Finding) -> tuple[bool, str, dict | None]:
        """Aplica en el host remoto la corrección de un hallazgo de su auditoría.

        Devuelve (ok, mensaje, acción para deshacerla o None si no se puede deshacer)."""
        action = self.remote_fix_action(finding)
        if action is None:
            return False, f"Sin corrección remota automática para {finding.id}", None
        res = await self._run_remote_action(host, action)
        ok = bool(res.get("ok"))
        return ok, res.get("msg", ""), self.undo_action(action, res.get("before")) if ok else None

    async def undo_fix_remote(self, host: str, undo: dict) -> tuple[bool, str]:
        res = await self._run_remote_action(host, undo)
        return bool(res.get("ok")), res.get("msg", "")

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
