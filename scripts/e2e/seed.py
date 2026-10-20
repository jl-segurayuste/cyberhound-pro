"""Siembra una BD de demo con datos ficticios para las capturas del README."""
import asyncio, sys, random, sqlite3
from datetime import datetime, timedelta, UTC
from pathlib import Path
from cyberhound.core.database import Database, AssetRecord
from cyberhound.core.models import Finding

db_path = Path(sys.argv[1])
random.seed(7)

AUDIT = [
    ("ssh_root_login", "ssh", "critical", "Login SSH como root permitido", "PermitRootLogin yes en /etc/ssh/sshd_config", "Establecer PermitRootLogin no", True),
    ("ssh_password_auth", "ssh", "high", "Autenticación SSH por contraseña", "PasswordAuthentication yes", "Usar solo claves (PasswordAuthentication no)", True),
    ("firewall_disabled", "firewall", "high", "Firewall inactivo", "ufw status: inactive", "Activar ufw con política deny por defecto", True),
    ("pending_security_updates", "updates", "medium", "12 actualizaciones de seguridad pendientes", "apt list --upgradable", "Aplicar unattended-upgrades", True),
    ("world_writable_files", "filesystem", "medium", "Ficheros con permisos 777 en /var/www", "/var/www/html/uploads", "chmod 750 y revisar propietario", False),
    ("auditd_missing", "logging", "low", "auditd no instalado", "", "Instalar y habilitar auditd", True),
    ("core_dumps", "kernel", "low", "Core dumps habilitados", "fs.suid_dumpable=1", "fs.suid_dumpable=0", True),
]

def mk(items, host):
    return [Finding(id=i, category=c, severity=s, title=t, description=d, remediation=r,
                    evidence=d, auto_fix=a, source_host=host) for i, c, s, t, d, r, a in items]

async def main():
    db = Database(db_path); await db.init()
    now = datetime.now(UTC)
    for day in range(14, -1, -1):
        n = max(2, len(AUDIT) - (14 - day) // 3)
        sid = await db.create_scan("audit", "demo-web-01", "scheduler")
        await db.complete_scan(sid, mk(AUDIT[-n:] if day < 14 else AUDIT, "demo-web-01"))
        ts = (now - timedelta(days=day, hours=random.randint(0, 3))).isoformat()
        with sqlite3.connect(db_path) as c:
            c.execute("UPDATE scans SET started_at=?, finished_at=? WHERE id=?", (ts, ts, sid))
    # último audit: hallazgos realistas de un servidor a medio bastionar
    sid = await db.create_scan("audit", "demo-web-01", "manual")
    await db.complete_scan(sid, mk(AUDIT[:2] + AUDIT[3:6], "demo-web-01"))
    sid = await db.create_scan("malware", "demo-web-01", "scheduler")
    await db.complete_scan(sid, mk([("webshell_php", "malware", "high", "Posible webshell PHP", "eval(base64_decode(...)) en uploads/img.php", "Poner en cuarentena y revisar acceso", False)], "demo-web-01"))
    sid = await db.create_scan("code", "/srv/demo-app", "manual")
    await db.complete_scan(sid, mk([("B105", "code", "medium", "Contraseña hardcodeada", "settings.py:12", "Mover a variable de entorno", False),
                                    ("SC2086", "code", "low", "Variable sin comillas en script", "deploy.sh:40", "Entrecomillar \"$VAR\"", False)], "localhost"))
    sid = await db.create_scan("network", "10.10.0.0/24", "scheduler")
    await db.complete_scan(sid, mk([("telnet_open", "network", "high", "Telnet abierto en 10.10.0.23", "23/tcp open", "Deshabilitar telnet", False)], "10.10.0.23"))
    hosts = [("10.10.0.1", "router-demo", "Linux 5.x", "[22,53,80,443]", "low", 1),
             ("10.10.0.10", "demo-web-01", "Ubuntu 24.04", "[22,80,443]", "medium", 1),
             ("10.10.0.11", "demo-db-01", "Debian 12", "[22,5432]", "low", 1),
             ("10.10.0.20", "nas-demo", "Linux 6.x", "[22,445,5000]", "medium", 1),
             ("10.10.0.23", "impresora-demo", "Embedded", "[23,80,9100]", "high", 0),
             ("10.10.0.42", "", "Android", "[]", "unknown", 0)]
    for ip, hn, os_, ports, risk, auth in hosts:
        await db.upsert_asset(AssetRecord(ip=ip, hostname=hn, os_name=os_, open_ports=ports, risk_level=risk, is_authorized=auth,
                                          mac="02:00:00:%02x:%02x:%02x" % (random.randrange(256), random.randrange(256), random.randrange(256))))

asyncio.run(main())
