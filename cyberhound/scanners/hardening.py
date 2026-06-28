"""
Auditoría de hardening local.

Cada check devuelve List[Finding]. Los errores de permisos (SELinux/AppArmor)
se loguean como información de seguridad, no se silencian.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import TYPE_CHECKING

from cyberhound.core.executor import command_exists, read_file_async, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

if TYPE_CHECKING:
    pass

logger = get_logger("hardening")

# ──────────────────────────────────────────────────────────────────────────────
# Helper para construir Findings de forma concisa
# ──────────────────────────────────────────────────────────────────────────────

def _f(
    id: str, category: str, severity: str,
    title: str, description: str, remediation: str,
    evidence: str = "", auto_fix: bool = False, file_path: str = "",
) -> Finding:
    return Finding(
        id=id, category=category, severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=auto_fix, file_path=file_path,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Checks individuales
# ──────────────────────────────────────────────────────────────────────────────

async def check_ssh() -> list[Finding]:
    results = []
    path = "/etc/ssh/sshd_config"
    content = await read_file_async(path)
    if content is None:
        return [_f("ssh_config_unreadable", "ssh", "medium",
                   "sshd_config no accesible",
                   "No se pudo leer /etc/ssh/sshd_config",
                   "Verificar permisos y SELinux/AppArmor")]

    dangerous = {
        "PermitRootLogin":      ("yes",  "high"),
        "PasswordAuthentication": ("yes", "high"),
        "PermitEmptyPasswords": ("yes",  "critical"),
        "X11Forwarding":        ("yes",  "medium"),
    }
    for param, (bad_val, sev) in dangerous.items():
        if re.search(rf"^\s*{param}\s+{bad_val}\s*$", content, re.MULTILINE | re.IGNORECASE):
            results.append(_f(
                f"ssh_{param}", "ssh", sev,
                f"SSH: {param} = {bad_val}",
                f"El parámetro {param} tiene un valor inseguro ({bad_val}).",
                f"Editar /etc/ssh/sshd_config → establecer {param} no",
                evidence=f"{param} {bad_val}", auto_fix=True,
            ))

    # MaxAuthTries
    m = re.search(r"^\s*MaxAuthTries\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
    if not m or int(m.group(1)) > 4:
        val = m.group(1) if m else "6 (por defecto)"
        results.append(_f(
            "ssh_MaxAuthTries", "ssh", "medium",
            "SSH: MaxAuthTries demasiado alto",
            f"Valor actual: {val}. Facilita ataques de fuerza bruta.",
            "Establecer MaxAuthTries 4 en /etc/ssh/sshd_config",
            auto_fix=True,
        ))

    # Protocol (solo relevante en sistemas legacy)
    if re.search(r"^\s*Protocol\s+1", content, re.MULTILINE):
        results.append(_f(
            "ssh_protocol1", "ssh", "critical",
            "SSH Protocol 1 habilitado",
            "SSHv1 tiene vulnerabilidades conocidas y no debe usarse.",
            "Eliminar 'Protocol 1' de sshd_config o establecer 'Protocol 2'",
            auto_fix=True,
        ))

    return results


async def check_firewall() -> list[Finding]:
    if command_exists("ufw"):
        proc = await run_command(["ufw", "status"], timeout=10)
        if "inactive" in proc.stdout.lower():
            return [_f("fw_ufw_inactive", "firewall", "critical",
                       "Firewall (UFW) inactivo",
                       "El firewall no está activo. El sistema no tiene filtrado de red.",
                       "ufw enable", auto_fix=True)]
        return []

    if command_exists("firewall-cmd"):
        proc = await run_command(["firewall-cmd", "--state"], timeout=10)
        if "running" not in proc.stdout.lower():
            return [_f("fw_firewalld_inactive", "firewall", "critical",
                       "Firewall (firewalld) inactivo", "",
                       "systemctl enable --now firewalld", auto_fix=True)]
        return []

    return [_f("fw_none", "firewall", "critical",
               "Sin firewall detectado",
               "No se encontró ufw ni firewalld en el sistema.",
               "sudo apt install ufw && ufw enable", auto_fix=False)]


async def check_kernel_params() -> list[Finding]:
    results = []
    PARAMS = {
        "net.ipv4.ip_forward":              ("0",  "high",   "Reenvío IP activo (gateway no intencionado)"),
        "net.ipv4.conf.all.send_redirects": ("0",  "high",   "Envío de ICMP redirects activo"),
        "net.ipv4.conf.all.accept_source_route": ("0", "high", "Enrutamiento por origen aceptado"),
        "kernel.randomize_va_space":        ("2",  "high",   "ASLR desactivado o parcial"),
        "net.ipv4.tcp_syncookies":          ("1",  "high",   "SYN cookies desactivadas (vulnerable a SYN flood)"),
        "net.ipv4.conf.all.log_martians":   ("1",  "medium", "Paquetes martian no registrados"),
        "net.ipv4.conf.all.rp_filter":      ("1",  "medium", "Filtro de ruta inversa desactivado"),
        "kernel.dmesg_restrict":            ("1",  "medium", "dmesg accesible por usuarios sin privilegios"),
        "kernel.perf_event_paranoid":       ("2",  "medium", "Eventos perf accesibles sin privilegios"),
        "net.ipv6.conf.all.disable_ipv6":   ("1",  "info",   "IPv6 activo (considera deshabilitarlo si no se usa)"),
    }
    for param, (expected, sev, desc) in PARAMS.items():
        sysfs = Path("/proc/sys") / param.replace(".", "/")
        if not sysfs.exists():
            continue
        content = await read_file_async(str(sysfs))
        if content is None:
            continue
        current = content.strip()
        if current != expected:
            results.append(_f(
                f"kernel_{param.replace('.','_')}", "kernel", sev,
                f"Parámetro kernel inseguro: {param}",
                f"{desc}\nActual: {current} | Esperado: {expected}",
                f"sysctl -w {param}={expected}",
                evidence=f"{param}={current}", auto_fix=True,
            ))
    return results


async def check_world_writable(max_findings: int = 200) -> list[Finding]:
    """
    Busca ficheros world-writable en directorios críticos.
    Usa un generator interno para no acumular todos los paths en memoria.
    """
    SCAN_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    SAFE_PREFIXES = ["/var/lib/kubelet/", "/var/lib/docker/", "/run/", "/proc/", "/sys/"]
    results = []

    for scan_dir in SCAN_DIRS:
        if not Path(scan_dir).exists():
            continue
        try:
            proc = await run_command(
                ["find", scan_dir, "-xdev", "-type", "f", "-perm", "-o+w"],
                timeout=30,
            )
            for filepath in proc.stdout.splitlines():
                filepath = filepath.strip()
                if not filepath:
                    continue
                if any(filepath.startswith(p) for p in SAFE_PREFIXES):
                    continue
                fid = "ww_" + re.sub(r"[^a-z0-9]", "_", filepath.lower())[:60]
                results.append(_f(
                    fid, "filesystem", "high",
                    f"Fichero world-writable: {filepath}",
                    "Cualquier usuario del sistema puede escribir en este fichero.",
                    f"chmod o-w {filepath}",
                    evidence=filepath, auto_fix=True, file_path=filepath,
                ))
                if len(results) >= max_findings:
                    logger.warning(
                        "world_writable: límite %d alcanzado — hay más ficheros inseguros.",
                        max_findings,
                    )
                    return results
        except Exception as e:
            logger.error("check_world_writable error en %s: %s", scan_dir, e)

    return results


async def check_pam_faillock() -> list[Finding]:
    pam_files = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    for pf in pam_files:
        content = await read_file_async(pf)
        if content and "faillock" in content:
            return []  # OK

    return [_f(
        "no_pam_faillock", "authentication", "high",
        "pam_faillock no configurado",
        "Sin bloqueo de cuenta por intentos fallidos de autenticación. "
        "Facilita ataques de fuerza bruta contra contraseñas locales.",
        "Configurar pam_faillock en /etc/pam.d/common-auth:\n"
        "auth required pam_faillock.so preauth silent deny=5 unlock_time=600",
        auto_fix=True,
    )]


async def check_password_policy() -> list[Finding]:
    results: list[Finding] = []
    content = await read_file_async("/etc/login.defs")
    if not content:
        return results

    checks = {
        r"PASS_MAX_DAYS\s+(\d+)": ("PASS_MAX_DAYS",  90,  "<=", "medium"),
        r"PASS_MIN_DAYS\s+(\d+)": ("PASS_MIN_DAYS",   1,  ">=", "low"),
        r"PASS_WARN_AGE\s+(\d+)": ("PASS_WARN_AGE",   7,  ">=", "low"),
        r"LOGIN_RETRIES\s+(\d+)": ("LOGIN_RETRIES",    5,  "<=", "medium"),
    }
    for pattern, (param, threshold, op, sev) in checks.items():
        m = re.search(pattern, content)
        if m:
            val = int(m.group(1))
            fail = (op == "<=" and val > threshold) or (op == ">=" and val < threshold)
            if fail:
                results.append(_f(
                    f"login_defs_{param}", "authentication", sev,
                    f"Política de contraseñas: {param} no óptimo",
                    f"Valor actual: {val} | Recomendado: {op} {threshold}",
                    f"Editar /etc/login.defs → {param} {threshold}",
                    auto_fix=True,
                ))
    return results


async def check_auditd() -> list[Finding]:
    if not command_exists("auditd") and not command_exists("auditctl"):
        return [_f("no_auditd", "audit", "high",
                   "auditd no instalado",
                   "Sin sistema de auditoría de eventos del kernel.",
                   "apt install auditd && systemctl enable --now auditd",
                   auto_fix=True)]
    proc = await run_command(["systemctl", "is-active", "auditd"], timeout=10)
    if "active" not in proc.stdout:
        return [_f("auditd_inactive", "audit", "high",
                   "auditd instalado pero inactivo",
                   f"Estado: {proc.stdout.strip()}",
                   "systemctl enable --now auditd",
                   auto_fix=True)]
    return []


async def check_services() -> list[Finding]:
    UNWANTED = ["telnet", "rsh", "rlogin", "finger", "talk", "tftp", "xinetd", "nis"]
    proc = await run_command(
        ["systemctl", "list-units", "--type=service", "--state=active", "--no-pager"],
        timeout=15,
    )
    active = proc.stdout.lower()
    return [
        _f(f"svc_{svc}", "services", "high",
           f"Servicio inseguro activo: {svc}",
           f"El servicio '{svc}' tiene vulnerabilidades conocidas y no debería estar activo.",
           f"systemctl disable --now {svc}",
           auto_fix=True)
        for svc in UNWANTED if svc in active
    ]


async def check_sudoers() -> list[Finding]:
    results = []
    sudoers_files = [Path("/etc/sudoers")] + list(
        Path("/etc/sudoers.d").glob("*") if Path("/etc/sudoers.d").exists() else []
    )
    for sf in sudoers_files:
        content = await read_file_async(str(sf))
        if content is None:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "NOPASSWD" in stripped:
                results.append(_f(
                    f"sudoers_nopasswd_{sf.name}_{i}", "sudo", "high",
                    f"NOPASSWD en sudoers: {sf.name}:{i}",
                    f"La entrada permite escalar privilegios sin contraseña:\n{stripped}",
                    "Revisar si NOPASSWD es estrictamente necesario. "
                    "Si no, eliminar la entrada.",
                    evidence=stripped, auto_fix=False, file_path=str(sf),
                ))
    return results


async def check_apparmor() -> list[Finding]:
    if not Path("/sys/kernel/security/apparmor").exists():
        return []  # sistema sin AppArmor (quizás usa SELinux)
    proc = await run_command(["systemctl", "is-active", "apparmor"], timeout=10)
    if "active" not in proc.stdout:
        return [_f("apparmor_inactive", "mac", "medium",
                   "AppArmor instalado pero inactivo",
                   "El sistema de control de acceso obligatorio no está activo.",
                   "systemctl enable --now apparmor",
                   auto_fix=True)]
    return []


async def check_core_dumps() -> list[Finding]:
    content = await read_file_async("/etc/security/limits.conf")
    if content and "* hard core 0" in content:
        return []
    return [_f("core_dumps_enabled", "kernel", "medium",
               "Core dumps no deshabilitados",
               "Los core dumps pueden contener contraseñas y datos sensibles en memoria.",
               "Añadir a /etc/security/limits.conf:\n* hard core 0\n* soft core 0",
               auto_fix=True)]


async def check_usb_storage() -> list[Finding]:
    for conf_file in Path("/etc/modprobe.d").glob("*.conf"):
        content = await read_file_async(str(conf_file))
        if content and ("blacklist usb-storage" in content or "install usb-storage /bin/false" in content):
            return []
    return [_f("usb_storage_enabled", "storage", "medium",
               "USB storage no deshabilitado",
               "Los dispositivos USB de almacenamiento pueden usarse para exfiltración de datos.",
               "echo 'blacklist usb-storage' > /etc/modprobe.d/cyberhound-usb.conf",
               auto_fix=True)]


async def check_ctrlaltdel() -> list[Finding]:
    proc = await run_command(["systemctl", "is-enabled", "ctrl-alt-del.target"], timeout=10)
    if "enabled" in proc.stdout:
        return [_f("ctrlaltdel_enabled", "system", "medium",
                   "Ctrl+Alt+Del no deshabilitado",
                   "Ctrl+Alt+Del reinicia el sistema sin autenticación.",
                   "systemctl mask ctrl-alt-del.target",
                   auto_fix=True)]
    return []


async def check_cron_restrictions() -> list[Finding]:
    allow = Path("/etc/cron.allow")
    deny = Path("/etc/cron.deny")
    if not allow.exists() and not deny.exists():
        return [_f("cron_unrestricted", "cron", "low",
                   "Sin restricciones de acceso a cron",
                   "Cualquier usuario puede programar tareas cron.",
                   "Crear /etc/cron.allow con la lista de usuarios autorizados",
                   auto_fix=False)]
    return []


async def check_log_permissions() -> list[Finding]:
    results: list[Finding] = []
    log_dir = Path("/var/log")
    if not log_dir.exists():
        return results
    for log_file in log_dir.iterdir():
        if not log_file.is_file():
            continue
        try:
            mode = log_file.stat().st_mode & 0o777
            if mode & 0o004:  # world-readable
                results.append(_f(
                    f"log_perm_{log_file.name}", "logging", "low",
                    f"Log legible por todos: {log_file.name}",
                    f"Permisos actuales: {oct(mode)}. Los logs pueden contener info sensible.",
                    f"chmod o-r {log_file}",
                    evidence=str(log_file), auto_fix=True, file_path=str(log_file),
                ))
        except PermissionError:
            logger.warning(
                "Sin permisos para stat %s — posible restricción SELinux/AppArmor", log_file
            )
        except OSError as e:
            logger.warning("Sin permisos para leer %s (SELinux/AppArmor): %s", log_file, e)
    return results


async def check_unattended_upgrades() -> list[Finding]:
    proc = await run_command(["dpkg", "-l", "unattended-upgrades"], timeout=10)
    if "ii" not in proc.stdout:
        return [_f("no_unattended_upgrades", "updates", "medium",
                   "Actualizaciones automáticas no instaladas",
                   "El sistema no aplica parches de seguridad automáticamente.",
                   "apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades",
                   auto_fix=True)]
    return []


async def check_aide() -> list[Finding]:
    if not command_exists("aide"):
        return [_f("no_aide", "integrity", "high",
                   "AIDE (monitor de integridad) no instalado",
                   "Sin sistema de detección de modificaciones en ficheros del sistema.",
                   "apt install aide && aideinit",
                   auto_fix=True)]
    for db in [Path("/var/lib/aide/aide.db"), Path("/var/lib/aide/aide.db.gz")]:
        if db.exists():
            return []
    return [_f("aide_db_missing", "integrity", "high",
               "AIDE instalado pero base de datos no inicializada",
               "Sin base de datos de referencia AIDE no puede detectar cambios.",
               "aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
               auto_fix=True)]


async def check_umask() -> list[Finding]:
    """Verifica que el umask del sistema sea 027 o más restrictivo."""
    results = []
    for path in ["/etc/profile", "/etc/bash.bashrc", "/etc/login.defs"]:
        content = await read_file_async(path)
        if content and re.search(r"umask\s+0?22", content):
            results.append(_f(
                f"umask_insecure_{Path(path).name}", "filesystem", "medium",
                f"Umask permisivo (022) en {path}",
                "Un umask de 022 crea ficheros legibles por todos los usuarios. "
                "El valor recomendado es 027 (grupo puede leer, otros sin acceso).",
                f"Cambiar en {path}: umask 027",
                evidence=f"umask 022 en {path}", auto_fix=True, file_path=path,
            ))
    return results


async def check_ntp() -> list[Finding]:
    """Verifica que el sistema tenga sincronización de tiempo configurada."""
    for svc in ["chrony", "chronyd", "ntpd", "timesyncd", "ntp"]:
        if command_exists(svc):
            proc = await run_command(["systemctl", "is-active", svc], timeout=10)
            if "active" in proc.stdout:
                return []
    # Comprobar timedatectl como fallback
    proc = await run_command(["timedatectl", "status"], timeout=10)
    if "synchronized: yes" in proc.stdout.lower() or "ntp service: active" in proc.stdout.lower():
        return []
    return [_f(
        "no_ntp", "time", "medium",
        "Sin sincronización de tiempo (NTP) activa",
        "Sin NTP los logs tendrán timestamps incorrectos, lo que invalida "
        "cualquier auditoría forense y correlación de eventos.",
        "apt install chrony && systemctl enable --now chrony",
        auto_fix=True,
    )]


async def check_login_banners() -> list[Finding]:
    """Verifica que los banners de login estén configurados (requisito legal ENS/ISO27001)."""
    results = []
    for banner_file, banner_type in [
        ("/etc/issue", "consola local (pre-login)"),
        ("/etc/issue.net", "SSH (pre-login remoto)"),
        ("/etc/motd", "mensaje post-login"),
    ]:
        content = await read_file_async(banner_file)
        if not content or len(content.strip()) < 10:
            results.append(_f(
                f"no_banner_{Path(banner_file).name.replace('.','_')}",
                "compliance", "low",
                f"Banner de login ausente: {banner_file}",
                f"El banner {banner_type} está vacío o no configurado. "
                "Es un requisito legal en muchos entornos regulados (ENS, ISO 27001, PCI-DSS).",
                f"echo 'Acceso restringido a usuarios autorizados. "
                f"Toda actividad es registrada.' > {banner_file}",
                auto_fix=True, file_path=banner_file,
            ))
    return results


async def check_empty_passwords() -> list[Finding]:
    """Detecta cuentas de sistema sin contraseña en /etc/shadow."""
    content = await read_file_async("/etc/shadow")
    if content is None:
        return [_f("shadow_unreadable", "authentication", "info",
                   "No se pudo leer /etc/shadow (requiere root)",
                   "", "Ejecutar como root para verificar contraseñas vacías")]
    results = []
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, pw_field = parts[0], parts[1]
        # Campo vacío = sin contraseña; ! o * = bloqueada (OK)
        if pw_field == "" or pw_field == "U6aMy0wojraho":  # hash conocido de vacío
            results.append(_f(
                f"empty_password_{username}", "authentication", "critical",
                f"Cuenta sin contraseña: {username}",
                f"La cuenta '{username}' no tiene contraseña establecida. "
                "Cualquier usuario puede autenticarse sin credenciales.",
                f"passwd -l {username}  # bloquear cuenta\n"
                f"# O establecer contraseña: passwd {username}",
                evidence=f"shadow: {username}::",
                auto_fix=True,
            ))
    return results


async def check_duplicate_uid0() -> list[Finding]:
    """Detecta cuentas con UID 0 distintas de root (backdoor clásico)."""
    content = await read_file_async("/etc/passwd")
    if content is None:
        return []
    results = []
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        username, uid = parts[0], parts[2]
        if uid == "0" and username != "root":
            results.append(_f(
                f"duplicate_uid0_{username}", "authentication", "critical",
                f"UID 0 duplicado: cuenta '{username}' tiene privilegios de root",
                f"La cuenta '{username}' tiene UID 0, lo que le otorga privilegios "
                "equivalentes a root. Esto es un indicador de compromiso.",
                f"usermod -u $(awk -F: '($3>999){{print $3}}' /etc/passwd | sort -n | tail -1) {username}\n"
                f"# O si es una cuenta no legítima: userdel {username}",
                evidence=f"/etc/passwd: {line}", auto_fix=False,
            ))
    return results


async def check_tmp_noexec() -> list[Finding]:
    """Verifica que /tmp y /var/tmp estén montados con noexec y nosuid."""
    content = await read_file_async("/proc/mounts")
    if content is None:
        return []
    results = []
    for mount_point, check_label in [("/tmp", "tmp"), ("/var/tmp", "var_tmp")]:
        mounted_noexec = False
        mounted_nosuid = False
        for line in content.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[1] != mount_point:
                continue
            opts = parts[3].split(",")
            mounted_noexec = "noexec" in opts
            mounted_nosuid = "nosuid" in opts
            break
        missing = []
        if not mounted_noexec:
            missing.append("noexec")
        if not mounted_nosuid:
            missing.append("nosuid")
        if missing:
            results.append(_f(
                f"tmp_{check_label}_{'_'.join(missing)}", "filesystem", "high",
                f"{mount_point} sin {', '.join(missing)}",
                f"{mount_point} permite ejecución de binarios o SUID. "
                "Es el vector de ataque más común para escalada de privilegios.",
                f"Añadir a /etc/fstab:\n"
                f"tmpfs {mount_point} tmpfs defaults,noexec,nosuid,nodev 0 0\n"
                f"mount -o remount,noexec,nosuid,nodev {mount_point}",
                auto_fix=False,  # requiere verificar que no rompe nada
            ))
    return results


async def check_services_listening_all() -> list[Finding]:
    """Detecta servicios escuchando en 0.0.0.0 que no deberían estar expuestos."""
    SAFE_PORTS = {
        22,    # SSH — esperado
        80,    # HTTP
        443,   # HTTPS
        8080,  # HTTP alt
        8443,  # HTTPS alt (CyberHound mismo)
    }
    SUSPICIOUS_SERVICES = {
        "mysql", "mysqld", "postgres", "redis", "mongodb", "memcached",
        "elasticsearch", "kibana", "grafana", "rabbitmq", "activemq",
    }
    proc = await run_command(["ss", "-tlnp"], timeout=15)
    if proc.returncode != 0:
        proc = await run_command(["netstat", "-tlnp"], timeout=15)
    results = []
    for line in proc.stdout.splitlines()[1:]:  # saltar cabecera
        # Buscar servicios en 0.0.0.0 o :::
        if "0.0.0.0:" not in line and ":::":
            continue
        # Extraer puerto
        port_match = re.search(r'[0:]:(\d+)\s', line)
        if not port_match:
            continue
        port = int(port_match.group(1))
        if port in SAFE_PORTS:
            continue
        # Extraer nombre del proceso si está disponible
        proc_match = re.search(r'users:\(\("([^"]+)"', line)
        proc_name = proc_match.group(1) if proc_match else "desconocido"
        if proc_name.lower() in SUSPICIOUS_SERVICES:
            sev = "high"
            desc = (f"El servicio '{proc_name}' está escuchando en todas las interfaces "
                    f"(puerto {port}). Servicios de BD/cache nunca deben ser accesibles "
                    "desde la red externa.")
        else:
            sev = "medium"
            desc = (f"Servicio '{proc_name}' escuchando en todas las interfaces "
                    f"(puerto {port}). Verificar si es intencional.")
        results.append(_f(
            f"svc_listen_all_{port}", "network", sev,
            f"Servicio en todas las interfaces: {proc_name}:{port}",
            desc,
            f"Configurar {proc_name} para escuchar solo en 127.0.0.1 o la IP necesaria.\n"
            f"Ejemplo: bind-address = 127.0.0.1 en la configuración del servicio.",
            evidence=line.strip(), auto_fix=False,
        ))
    return results


async def _openssh_patched_via_distro(cve: str) -> bool:
    """¿La distro ha backporteado el parche del CVE en su paquete openssh?

    Debian/Ubuntu/RHEL corrigen vulnerabilidades manteniendo el número de
    versión upstream (p. ej. 9.6p1), por lo que el banner de `ssh -V` no basta:
    hay que mirar el changelog del paquete. Evita falsos positivos.
    """
    import glob
    import gzip
    import shutil as _shutil

    cve = cve.upper()
    # Debian / Ubuntu
    for path in glob.glob("/usr/share/doc/openssh-*/changelog.Debian.gz"):
        try:
            with gzip.open(path, "rt", errors="replace") as fh:
                if cve in fh.read():
                    return True
        except OSError:
            continue
    # RHEL / derivados
    rpm = _shutil.which("rpm")
    if rpm:
        proc = await run_command([rpm, "-q", "--changelog", "openssh-server"], timeout=10)
        if cve in (proc.stdout or ""):
            return True
    return False


async def check_openssh_version() -> list[Finding]:
    """Verifica la versión de OpenSSH contra CVEs conocidos."""
    # CVEs relevantes por versión (simplificado, las más críticas)
    VULNERABLE_VERSIONS = {
        # (max_versión_vulnerable, CVE, severidad, descripción)
        (9, 2, 0): ("CVE-2023-38408", "critical",
                    "regreSSHion: RCE sin autenticación vía ssh-agent forwarding"),
        (9, 5, 0): ("CVE-2023-51385", "high",
                    "Inyección de comandos vía nombres de host con metacaracteres"),
        (9, 7, 0): ("CVE-2024-6387", "critical",
                    "regreSSHion: condición de carrera en signal handler, RCE sin auth"),
    }
    proc = await run_command(["ssh", "-V"], timeout=10)
    version_str = proc.stderr or proc.stdout
    m = re.search(r"OpenSSH[_/](\d+)\.(\d+)(?:p(\d+))?", version_str)
    if not m:
        return []
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    current = (major, minor, patch)
    findings = []
    for (vuln_maj, vuln_min, vuln_pat), (cve, sev, desc) in VULNERABLE_VERSIONS.items():
        if current <= (vuln_maj, vuln_min, vuln_pat):
            # El banner indica versión vulnerable, pero la distro puede haber
            # backporteado el parche (mismo número de versión). Si es así, no
            # es vulnerable → evitamos el falso positivo.
            if await _openssh_patched_via_distro(cve):
                continue
            findings.append(_f(
                f"openssh_cve_{cve.replace('-','_').lower()}",
                "ssh/cve", sev,
                f"OpenSSH {major}.{minor}p{patch} vulnerable a {cve}",
                f"{desc}\nVersión actual: OpenSSH {major}.{minor}p{patch}",
                "apt update && apt upgrade openssh-server",
                evidence=f"Versión detectada: {version_str.strip()}", auto_fix=True,
            ))
    return findings


async def check_sticky_bit_tmp() -> list[Finding]:
    """Verifica que /tmp tenga sticky bit activado."""
    try:
        mode = Path("/tmp").stat().st_mode
        if not (mode & 0o1000):  # sticky bit
            return [_f(
                "tmp_no_sticky_bit", "filesystem", "high",
                "/tmp sin sticky bit",
                "Sin sticky bit en /tmp cualquier usuario puede borrar ficheros de otros usuarios.",
                "chmod +t /tmp",
                auto_fix=True,
            )]
    except OSError:
        pass
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Nuevos checks v6.3
# ──────────────────────────────────────────────────────────────────────────────

async def check_ssh_host_keys() -> list[Finding]:
    """Verifica que las claves de host SSH tienen los permisos correctos."""
    findings = []
    for key_path in ["/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key",
                     "/etc/ssh/ssh_host_ecdsa_key"]:
        p = Path(key_path)
        if not p.exists():
            continue
        mode = p.stat().st_mode & 0o777
        if mode != 0o600:
            findings.append(Finding(
                id=f"ssh_hostkey_perm_{p.name}",
                category="ssh", severity="high",
                title=f"Permisos incorrectos en clave de host SSH: {key_path}",
                description=f"La clave {key_path} tiene permisos {oct(mode)} — deberían ser 0o600.",
                remediation=f"chmod 600 {key_path}",
                file_path=key_path, auto_fix=True,
            ))
    return findings


async def check_passwd_integrity() -> list[Finding]:
    """Verifica la integridad de /etc/passwd y /etc/shadow."""
    findings = []
    # /etc/passwd debe ser readable por todos pero no writable
    for path, expected_max_mode in [("/etc/passwd", 0o644), ("/etc/shadow", 0o640)]:
        p = Path(path)
        if not p.exists():
            continue
        mode = p.stat().st_mode & 0o777
        if mode > expected_max_mode:
            findings.append(Finding(
                id=f"passwd_perm_{Path(path).name}",
                category="filesystem", severity="critical",
                title=f"Permisos excesivos en {path}: {oct(mode)}",
                description=f"{path} tiene permisos {oct(mode)}. Deberían ser {oct(expected_max_mode)}.",
                remediation=f"chmod {oct(expected_max_mode)[2:]} {path}",
                file_path=path, auto_fix=True,
            ))
    return findings


async def check_at_cron_allow() -> list[Finding]:
    """Verifica que at/cron están restringidos a usuarios específicos."""
    findings = []
    # Si /etc/cron.deny no existe pero tampoco /etc/cron.allow → sin restricción
    cron_allow = Path("/etc/cron.allow")
    cron_deny  = Path("/etc/cron.deny")
    at_allow   = Path("/etc/at.allow")

    if not cron_allow.exists() and not cron_deny.exists():
        findings.append(Finding(
            id="cron_no_restriction",
            category="authentication", severity="medium",
            title="Sin restricciones de acceso a cron",
            description="No existe /etc/cron.allow ni /etc/cron.deny. Todos los usuarios pueden usar cron.",
            remediation="Crear /etc/cron.allow con solo los usuarios autorizados:\necho 'root' > /etc/cron.allow\nchmod 600 /etc/cron.allow",
            auto_fix=False,
        ))
    if not at_allow.exists():
        findings.append(Finding(
            id="at_no_restriction",
            category="authentication", severity="low",
            title="Sin restricciones de acceso a at",
            description="No existe /etc/at.allow. Todos los usuarios podrían usar el comando at.",
            remediation="echo 'root' > /etc/at.allow && chmod 600 /etc/at.allow",
            auto_fix=False,
        ))
    return findings


async def check_grub_password() -> list[Finding]:
    """Verifica si el bootloader tiene contraseña configurada."""
    grub_paths = [
        "/etc/grub.d/40_custom",
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
    ]
    for gpath in grub_paths:
        p = Path(gpath)
        if p.exists():
            content = p.read_text(errors="ignore") if p.stat().st_size < 100_000 else ""
            if "password_pbkdf2" in content or "set superusers" in content:
                return []  # Contraseña configurada
    return [Finding(
        id="grub_no_password",
        category="authentication", severity="medium",
        title="Bootloader GRUB sin contraseña",
        description="El bootloader no tiene contraseña configurada. "
                    "Alguien con acceso físico podría modificar parámetros de arranque.",
        remediation="Configurar contraseña en GRUB:\ngrub-mkpasswd-pbkdf2 → copiar el hash\n"
                    "Añadir en /etc/grub.d/40_custom:\nset superusers='admin'\n"
                    "password_pbkdf2 admin <hash>",
        auto_fix=False,
    )]


async def check_ipv6_disabled_if_unused() -> list[Finding]:
    """Avisa si IPv6 está habilitado pero no configurado (superficie de ataque innecesaria)."""
    proc = await run_command(["ip", "-6", "addr", "show"], timeout=10, check=False)
    if proc.returncode != 0:
        return []
    lines = [l for l in proc.stdout.splitlines()
             if "inet6" in l
             and " scope global" in l   # solo IPs con scope global = IPs públicas/privadas reales
             and "fe80" not in l]       # excluir link-local
    if lines:
        return []  # IPv6 en uso con IPs globales — OK

    # Comprobar si ya está explícitamente deshabilitado en sysctl
    sysctl_path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    if sysctl_path.exists() and sysctl_path.read_text().strip() == "1":
        return []  # ya deshabilitado

    return [Finding(
        id="ipv6_enabled_unused",
        category="kernel", severity="low",
        title="IPv6 habilitado sin uso detectado",
        description="IPv6 está habilitado pero no hay IPs globales asignadas. "
                    "Si no se usa IPv6, deshabilitarlo reduce la superficie de ataque.",
        remediation=(
            "Añadir a /etc/sysctl.d/99-cyberhound.conf:\n"
            "net.ipv6.conf.all.disable_ipv6 = 1\n"
            "net.ipv6.conf.default.disable_ipv6 = 1\n"
            "Aplicar: sysctl --system"
        ),
        auto_fix=False,
    )]

# ──────────────────────────────────────────────────────────────────────────────
# Orquestador
# ──────────────────────────────────────────────────────────────────────────────

class HardeningAuditor:
    CHECKS = [
        check_ssh,
        check_firewall,
        check_kernel_params,
        check_world_writable,
        check_pam_faillock,
        check_password_policy,
        check_auditd,
        check_services,
        check_sudoers,
        check_apparmor,
        check_core_dumps,
        check_usb_storage,
        check_ctrlaltdel,
        check_cron_restrictions,
        check_log_permissions,
        check_unattended_upgrades,
        check_aide,
        # v6.1
        check_umask,
        check_ntp,
        check_login_banners,
        check_empty_passwords,
        check_duplicate_uid0,
        check_tmp_noexec,
        check_sticky_bit_tmp,
        check_services_listening_all,
        check_openssh_version,
        # v6.3
        check_ssh_host_keys,
        check_passwd_integrity,
        check_at_cron_allow,
        check_grub_password,
        check_ipv6_disabled_if_unused,
    ]

    @classmethod
    async def full_audit(cls, cfg=None) -> list[Finding]:
        max_ww = getattr(getattr(cfg, "scan", None), "max_ww_files", 200) if cfg else 200
        results = await asyncio.gather(
            *[c() if c != check_world_writable else check_world_writable(max_ww)
              for c in cls.CHECKS],
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for check_fn, result in zip(cls.CHECKS, results, strict=False):
            if isinstance(result, list):
                findings.extend(result)
            else:
                logger.error("Check %s falló: %s", check_fn.__name__, result, exc_info=False)
        logger.info("HardeningAuditor: %d hallazgos", len(findings))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Remediación
# ──────────────────────────────────────────────────────────────────────────────

class HardeningFixer:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    async def fix(self, finding: Finding) -> tuple[bool, str]:
        """
        Aplica el fix para un finding.
        Devuelve (ok, mensaje).
        """
        fid = finding.id
        # Quitar prefijo de host remoto si existe
        if "::" in fid:
            fid = fid.split("::", 1)[1]

        if self.dry_run:
            logger.info("[DRY-RUN] fix: %s → %s", fid, finding.remediation)
            return True, f"[DRY-RUN] {finding.remediation}"

        # Routing por categoría/id
        try:
            if fid.startswith("ssh_"):
                return await self._fix_ssh(fid, finding)
            if fid.startswith("fw_"):
                return await self._fix_firewall(fid)
            if fid.startswith("kernel_") or fid.startswith("sysctl_"):
                return await self._fix_sysctl(finding)
            if fid.startswith("ww_"):
                return await self._fix_world_writable(finding)
            if fid.startswith("log_perm_"):
                return await self._fix_log_perm(finding)
            if fid.startswith("svc_"):
                return await self._fix_service(fid)
            if fid.startswith("login_defs_"):
                return await self._fix_login_defs(fid)
            if fid.startswith("umask_insecure_"):
                return await self._fix_umask(finding)
            if fid.startswith("no_banner_"):
                return await self._fix_login_banner(finding)
            if fid.startswith("empty_password_"):
                username = fid.replace("empty_password_", "")
                return await self._run(["passwd", "-l", username])
            if fid.startswith("openssh_cve_"):
                return await self._fix_openssh()
            # Fixes por ID exacto
            dispatch = {
                "no_pam_faillock":       self._fix_pam_faillock,
                "core_dumps_enabled":    self._fix_core_dumps,
                "usb_storage_enabled":   self._fix_usb_storage,
                "ctrlaltdel_enabled":    self._fix_ctrlaltdel,
                "apparmor_inactive":     self._fix_apparmor,
                "no_auditd":             self._fix_auditd,
                "auditd_inactive":       self._fix_auditd,
                "no_unattended_upgrades":self._fix_unattended,
                "no_aide":               self._fix_aide,
                "aide_db_missing":       self._fix_aide_db,
                # Nuevos v6.1
                "no_ntp":                self._fix_ntp,
                "tmp_no_sticky_bit":     self._fix_sticky_bit,
                "openssh_cve_cve_2024_6387": self._fix_openssh,
                "openssh_cve_cve_2023_38408": self._fix_openssh,
                "openssh_cve_cve_2023_51385": self._fix_openssh,
            }
            if fid in dispatch:
                return await dispatch[fid]()
            return False, f"Sin fix automático para: {fid}"
        except Exception as e:
            logger.error("Error aplicando fix %s: %s", fid, e, exc_info=True)
            return False, str(e)

    async def _run(self, cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
        proc = await run_command(cmd, timeout=timeout, check=False)
        ok = proc.returncode == 0
        if not ok:
            logger.error("Fix cmd falló (%d): %s\n%s", proc.returncode, cmd, proc.stderr[:300])
        return ok, proc.stderr[:300] if not ok else ""

    async def _fix_ssh(self, fid: str, finding: Finding) -> tuple[bool, str]:
        param_map = {
            "ssh_PermitRootLogin":        ("PermitRootLogin", "no"),
            "ssh_PasswordAuthentication": ("PasswordAuthentication", "no"),
            "ssh_PermitEmptyPasswords":   ("PermitEmptyPasswords", "no"),
            "ssh_X11Forwarding":          ("X11Forwarding", "no"),
            "ssh_MaxAuthTries":           ("MaxAuthTries", "4"),
            "ssh_protocol1":              (None, None),
        }
        if fid not in param_map:
            return False, f"SSH param desconocido: {fid}"
        param, value = param_map[fid]
        if param is None:
            # Eliminar Protocol 1
            ok, err = await self._run(["sed", "-i", r"/^\s*Protocol\s*1/d", "/etc/ssh/sshd_config"])
        else:
            path = "/etc/ssh/sshd_config"
            # Reemplazar si existe, añadir si no
            ok, err = await self._run(
                ["sed", "-i", rf"s/^\s*{param}\s.*/{param} {value}/", path]
            )
            # Verificar que se aplicó; si no existía, añadir
            content = await read_file_async(path) or ""
            if f"{param} {value}" not in content:
                with open(path, "a") as f:
                    f.write(f"\n{param} {value}\n")
        if ok:
            await self._run(["systemctl", "reload", "sshd"], timeout=15)
        return ok, err

    async def _fix_firewall(self, fid: str) -> tuple[bool, str]:
        if command_exists("ufw"):
            return await self._run(["ufw", "--force", "enable"])
        return await self._run(["systemctl", "enable", "--now", "firewalld"])

    async def _fix_sysctl(self, finding: Finding) -> tuple[bool, str]:
        # Extraer "param=value" de la remediación
        m = re.search(r"sysctl\s+-w\s+([\w.]+)=(\S+)", finding.remediation)
        if not m:
            return False, "No se pudo parsear el comando sysctl de la remediación"
        param, value = m.group(1), m.group(2)
        ok, err = await self._run(["sysctl", "-w", f"{param}={value}"])
        if ok:
            conf = Path("/etc/sysctl.d/99-cyberhound.conf")
            existing = conf.read_text() if conf.exists() else ""
            if param not in existing:
                with open(conf, "a") as f:
                    f.write(f"{param} = {value}\n")
        return ok, err

    async def _fix_world_writable(self, finding: Finding) -> tuple[bool, str]:
        if not finding.file_path:
            return False, "file_path vacío"
        return await self._run(["chmod", "o-w", finding.file_path])

    async def _fix_log_perm(self, finding: Finding) -> tuple[bool, str]:
        if not finding.file_path:
            return False, "file_path vacío"
        return await self._run(["chmod", "o-r", finding.file_path])

    async def _fix_service(self, fid: str) -> tuple[bool, str]:
        svc = fid.removeprefix("svc_")
        return await self._run(["systemctl", "disable", "--now", svc])

    async def _fix_login_defs(self, fid: str) -> tuple[bool, str]:
        param_vals = {
            "login_defs_PASS_MAX_DAYS":  ("PASS_MAX_DAYS", "90"),
            "login_defs_PASS_MIN_DAYS":  ("PASS_MIN_DAYS", "1"),
            "login_defs_PASS_WARN_AGE":  ("PASS_WARN_AGE", "7"),
            "login_defs_LOGIN_RETRIES":  ("LOGIN_RETRIES",  "5"),
        }
        if fid not in param_vals:
            return False, f"Param desconocido: {fid}"
        param, value = param_vals[fid]
        path = Path("/etc/login.defs")
        content = (await read_file_async(str(path))) or ""
        if re.search(rf"^\s*{param}\s+", content, re.MULTILINE):
            content = re.sub(rf"^\s*{param}\s+.*", f"{param}\t{value}", content, flags=re.MULTILINE)
        else:
            content += f"\n{param}\t{value}\n"
        path.write_text(content)
        return True, ""

    async def _fix_pam_faillock(self) -> tuple[bool, str]:
        pam = Path("/etc/pam.d/common-auth")
        if not pam.exists():
            return False, "/etc/pam.d/common-auth no encontrado"
        content = pam.read_text()
        if "pam_faillock" in content:
            return True, "Ya configurado"
        line = "auth required pam_faillock.so preauth silent deny=5 unlock_time=600\n"
        lines = content.splitlines(keepends=True)
        new_lines = []
        inserted = False
        for l in lines:
            if not inserted and re.match(r"^\s*auth\s+", l) and not l.strip().startswith("#"):
                new_lines.append(line)
                inserted = True
            new_lines.append(l)
        if not inserted:
            new_lines.append(line)
        pam.write_text("".join(new_lines))
        # También añadir a common-account
        account = Path("/etc/pam.d/common-account")
        if account.exists():
            acct_content = account.read_text()
            if "pam_faillock" not in acct_content:
                with open(account, "a") as f:
                    f.write("account required pam_faillock.so\n")
        return True, ""

    async def _fix_core_dumps(self) -> tuple[bool, str]:
        conf = Path("/etc/security/limits.conf")
        content = conf.read_text() if conf.exists() else ""
        if "* hard core 0" not in content:
            with open(conf, "a") as f:
                f.write("\n* hard core 0\n* soft core 0\n")
        await self._run(["sysctl", "-w", "fs.suid_dumpable=0"])
        return True, ""

    async def _fix_usb_storage(self) -> tuple[bool, str]:
        conf = Path("/etc/modprobe.d/cyberhound-usb.conf")
        conf.write_text("blacklist usb-storage\ninstall usb-storage /bin/false\n")
        await self._run(["modprobe", "-r", "usb-storage"])
        return True, ""

    async def _fix_ctrlaltdel(self) -> tuple[bool, str]:
        return await self._run(["systemctl", "mask", "ctrl-alt-del.target"])

    async def _fix_apparmor(self) -> tuple[bool, str]:
        return await self._run(["systemctl", "enable", "--now", "apparmor"])

    async def _fix_auditd(self) -> tuple[bool, str]:
        await self._run(["apt-get", "install", "-y", "auditd"], timeout=120)
        return await self._run(["systemctl", "enable", "--now", "auditd"])

    async def _fix_unattended(self) -> tuple[bool, str]:
        ok, err = await self._run(["apt-get", "install", "-y", "unattended-upgrades"], timeout=120)
        if ok:
            await self._run(["dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"])
        return ok, err

    async def _fix_aide(self) -> tuple[bool, str]:
        return await self._run(["apt-get", "install", "-y", "aide"], timeout=120)

    async def _fix_aide_db(self) -> tuple[bool, str]:
        ok, err = await self._run(["aideinit"], timeout=300)
        if ok:
            src = Path("/var/lib/aide/aide.db.new")
            dst = Path("/var/lib/aide/aide.db")
            if src.exists():
                src.rename(dst)
        return ok, err

    async def _fix_ntp(self) -> tuple[bool, str]:
        ok, err = await self._run(["apt-get", "install", "-y", "chrony"], timeout=120)
        if ok:
            await self._run(["systemctl", "enable", "--now", "chrony"])
        return ok, err

    async def _fix_sticky_bit(self) -> tuple[bool, str]:
        return await self._run(["chmod", "+t", "/tmp"])

    async def _fix_openssh(self) -> tuple[bool, str]:
        ok, err = await self._run(["apt-get", "update"], timeout=60)
        if ok:
            ok, err = await self._run(
                ["apt-get", "install", "--only-upgrade", "-y", "openssh-server"],
                timeout=120,
            )
        return ok, err

    async def _fix_umask(self, finding: Finding) -> tuple[bool, str]:
        path = finding.file_path
        if not path:
            return False, "file_path vacío"
        content = await read_file_async(path)
        if content is None:
            return False, f"No se pudo leer {path}"
        content = re.sub(r"(umask\s+)0?22\b", r"\g<1>027", content)
        Path(path).write_text(content)
        return True, ""

    async def _fix_login_banner(self, finding: Finding) -> tuple[bool, str]:
        path = finding.file_path
        if not path:
            return False, "file_path vacío"
        msg = (
            "AVISO: Este sistema es de uso exclusivo para personal autorizado.\n"
            "Toda actividad es registrada y supervisada.\n"
            "El acceso no autorizado está prohibido y puede ser objeto de acciones legales.\n"
        )
        Path(path).write_text(msg)
        return True, ""
