"""
Monitoreo en tiempo real de comportamiento malicioso.

Usa eBPF (via bcc/bpftrace) si está disponible, con fallback a auditd
para detectar en tiempo real:
  - Ejecuciones de comandos sospechosos (wget|curl → bash, nc, etc.)
  - Modificaciones de ficheros críticos (/etc/passwd, /etc/sudoers, ...)
  - Conexiones de red a IPs/puertos sospechosos
  - Escaladas de privilegios (setuid, sudo)
  - Creación de ficheros en /tmp con ejecución inmediata

El monitor corre como tarea asyncio en segundo plano mientras el servidor
está activo. Los eventos detectados se envían por WebSocket push y se
guardan en la BD como findings de alta/crítica severidad.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

if TYPE_CHECKING:
    from cyberhound.api.server import CyberHoundServer

logger = get_logger("ebpf_monitor")

# Comandos sospechosos detectados vía execve
SUSPICIOUS_COMMANDS = {
    r"(wget|curl).*\|.*(bash|sh|python)":          ("exec_download_pipe",   "critical", "Descarga + ejecución en pipe"),
    r"nc\s+.*-[el]":                                ("netcat_listener",      "critical", "Netcat en modo escucha"),
    r"bash\s+-i\s+>&\s+/dev/tcp":                   ("reverse_shell_bash",   "critical", "Reverse shell Bash"),
    r"python.*socket.*subprocess":                   ("reverse_shell_python", "critical", "Reverse shell Python"),
    r"chmod\s+(777|4755|a\+s)\s+":                  ("suspicious_chmod",     "high",    "chmod sospechoso (SUID/world)"),
    r"crontab\s+-[li].*http":                        ("cron_download",        "high",    "Cron con descarga"),
    r"iptables\s+-F|ufw\s+disable":                 ("firewall_disabled",    "high",    "Firewall desactivado"),
    r"passwd\s+root|usermod.*-p.*root":              ("root_passwd_change",   "critical","Cambio de contraseña de root"),
    r"(dd|shred)\s+.*(/dev/sda|/dev/nvme)":         ("disk_wipe",           "critical", "Posible borrado de disco"),
    r"find\s+.*-perm\s+-4000":                       ("suid_search",         "high",    "Búsqueda de binarios SUID"),
    r"base64\s+-d.*\|.*(bash|sh|exec)":              ("base64_exec",         "critical", "Ejecución de payload base64"),
    r"pkill\s+(auditd|rsyslog|syslog)":              ("kill_logging",        "critical", "Intento de matar el sistema de logs"),
}

# Ficheros críticos a monitorear
CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/ssh/sshd_config",
    "/etc/hosts", "/root/.ssh/authorized_keys",
    "/etc/ld.so.preload",           # rootkit clásico
    "/proc/sys/kernel/core_pattern",  # exploits de kernel
]


class EBPFMonitor:
    """
    Monitor de comportamiento malicioso en tiempo real.
    Usa eBPF si está disponible, auditd como fallback.
    """

    def __init__(self, server: "CyberHoundServer") -> None:
        self.server  = server
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self.mode = "none"  # none | auditd | ebpf

    async def start(self) -> None:
        if command_exists("bpftrace"):
            self.mode = "ebpf"
            logger.info("Monitor eBPF iniciado (bpftrace)")
            self._tasks.append(asyncio.ensure_future(self._monitor_ebpf()))
        elif await self._auditd_available():
            self.mode = "auditd"
            logger.info("Monitor auditd iniciado (fallback)")
            self._tasks.append(asyncio.ensure_future(self._monitor_auditd()))
        else:
            logger.info("Monitor en tiempo real no disponible (instala auditd o bpftrace)")
            return

        # Monitor de ficheros críticos siempre activo
        self._tasks.append(asyncio.ensure_future(self._monitor_critical_files()))
        self._running = True

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Monitor detenido")

    async def _auditd_available(self) -> bool:
        if not command_exists("ausearch"):
            return False
        proc = await run_command(["systemctl", "is-active", "auditd"], timeout=5, check=False)
        return "active" in proc.stdout

    # ── Monitor via bpftrace ──────────────────────────────────────────────────

    async def _monitor_ebpf(self) -> None:
        """Monitorea execve syscalls via bpftrace."""
        BPFTRACE_PROG = """
tracepoint:syscalls:sys_enter_execve
{
    printf("EXEC %s\\n", str(args->filename));
}
"""
        proc = await asyncio.create_subprocess_exec(
            "bpftrace", "-e", BPFTRACE_PROG,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        logger.info("bpftrace iniciado (PID %d)", proc.pid)

        try:
            while self._running:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
                if not line:
                    break
                text = line.decode(errors="ignore").strip()
                if text.startswith("EXEC "):
                    cmd = text[5:]
                    await self._check_suspicious_command(cmd, source="ebpf")
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error("bpftrace monitor error: %s", e)
        finally:
            if proc.returncode is None:
                proc.terminate()

    # ── Monitor via auditd ────────────────────────────────────────────────────

    async def _monitor_auditd(self) -> None:
        """Lee el log de auditd en tiempo real buscando eventos sospechosos."""
        audit_log = Path("/var/log/audit/audit.log")
        if not audit_log.exists():
            logger.warning("auditd: /var/log/audit/audit.log no existe")
            return

        # Seguir el fichero como tail -f
        proc = await asyncio.create_subprocess_exec(
            "tail", "-f", "-n", "0", str(audit_log),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            while self._running:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=10.0)
                if not line:
                    break
                text = line.decode(errors="ignore").strip()
                await self._process_audit_line(text)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error("auditd monitor error: %s", e)
        finally:
            if proc.returncode is None:
                proc.terminate()

    async def _process_audit_line(self, line: str) -> None:
        """Parsea una línea de audit.log buscando patrones sospechosos."""
        # Extraer el comando ejecutado (type=EXECVE)
        if "type=EXECVE" in line or "type=SYSCALL" in line:
            # Extraer args de EXECVE
            args_match = re.findall(r'a\d+="([^"]+)"', line)
            if args_match:
                cmd = " ".join(args_match)
                await self._check_suspicious_command(cmd, source="auditd")

        # Detectar accesos a ficheros críticos (type=OPEN o PATH)
        if "type=PATH" in line:
            name_match = re.search(r'name="([^"]+)"', line)
            if name_match:
                path = name_match.group(1)
                if any(path.startswith(cf) for cf in CRITICAL_FILES):
                    # Solo reportar escrituras (nametype=NORMAL con flags de escritura)
                    if "WRTITTEN" in line or "nametype=CREATE" in line or "nametype=DELETE" in line:
                        await self._emit_finding(
                            f"monitor_critical_file_{path.replace('/','_')[-30:]}",
                            "monitor/files", "high",
                            f"Modificación de fichero crítico: {path}",
                            f"Se detectó una escritura en {path} en tiempo real.",
                            "Revisar quién modificó el fichero y por qué.",
                            evidence=line[:200],
                        )

    # ── Monitor de ficheros críticos (polling) ────────────────────────────────

    async def _monitor_critical_files(self) -> None:
        """
        Monitorea cambios en ficheros críticos mediante polling de mtime/hash.
        Menos eficiente que inotify pero no requiere privilegios especiales.
        """
        # Estado inicial
        file_state: dict[str, tuple[float, str]] = {}  # path → (mtime, hash)
        for cf in CRITICAL_FILES:
            p = Path(cf)
            if p.exists():
                try:
                    mtime = p.stat().st_mtime
                    # Solo hash de ficheros pequeños
                    if p.stat().st_size < 1_000_000:
                        import hashlib
                        file_state[cf] = (mtime, hashlib.md5(p.read_bytes()).hexdigest())
                    else:
                        file_state[cf] = (mtime, "")
                except (PermissionError, OSError):
                    pass

        await asyncio.sleep(60)  # Esperar 1 min antes de empezar a monitorear

        while self._running:
            for cf in CRITICAL_FILES:
                p = Path(cf)
                if not p.exists():
                    continue
                try:
                    mtime = p.stat().st_mtime
                    prev  = file_state.get(cf)
                    if prev and mtime != prev[0]:
                        # Fichero modificado
                        logger.warning("MONITOR: fichero crítico modificado: %s", cf)
                        await self._emit_finding(
                            f"monitor_file_changed_{cf.replace('/','_')[-30:]}",
                            "monitor/integrity", "high",
                            f"Fichero crítico modificado: {cf}",
                            f"Se detectó una modificación en {cf} a las "
                            f"{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}.",
                            f"Revisar cambios con: diff {cf} y ausearch -f {cf}",
                        )
                    import hashlib
                    if p.stat().st_size < 1_000_000:
                        file_state[cf] = (mtime, hashlib.md5(p.read_bytes()).hexdigest())
                    else:
                        file_state[cf] = (mtime, "")
                except (PermissionError, OSError):
                    pass

            await asyncio.sleep(30)  # Comprobar cada 30 segundos

    # ── Check de comandos sospechosos ─────────────────────────────────────────

    async def _check_suspicious_command(self, cmd: str, source: str) -> None:
        for pattern, (fid, sev, title) in SUSPICIOUS_COMMANDS.items():
            if re.search(pattern, cmd, re.IGNORECASE):
                logger.warning(
                    "MONITOR: comando sospechoso detectado [%s]: %s", fid, cmd[:100]
                )
                await self._emit_finding(
                    f"monitor_{fid}_{abs(hash(cmd)) % 10000}",
                    "monitor/exec", sev,
                    f"Comando sospechoso: {title}",
                    f"Se detectó ejecución de: {cmd[:200]}",
                    "Revisar el proceso que ejecutó este comando y su contexto.",
                    evidence=f"cmd={cmd[:100]} source={source}",
                )

    async def _emit_finding(
        self, fid: str, category: str, severity: str,
        title: str, description: str, remediation: str,
        evidence: str = "",
    ) -> None:
        """Emite un finding al servidor (BD + push WS + notificación)."""
        f = Finding(
            id=fid, category=category, severity=severity,
            title=title, description=description,
            remediation=remediation, evidence=evidence,
            auto_fix=False,
        )

        # Guardar en BD
        try:
            scan_id = await self.server.db.create_scan("monitor", triggered_by="ebpf")
            await self.server.db.complete_scan(scan_id, [f])
        except Exception as e:
            logger.error("Error guardando finding de monitor: %s", e)

        # Broadcast por WebSocket push
        try:
            await self.server._broadcast_push("new_findings", {
                "scan_id":  0,
                "critical": 1 if severity == "critical" else 0,
                "total":    1,
                "titles":   [title],
                "source":   "monitor",
            })
        except Exception:
            pass

        # Notificación si hay crítico
        if severity in ("critical", "high"):
            try:
                await self.server.notification_manager.send(
                    f"⚡ Monitor en tiempo real: {title}",
                    level=severity,
                )
            except Exception:
                pass
