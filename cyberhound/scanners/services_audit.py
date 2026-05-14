"""
Auditoría de configuración de servicios específicos.

Checks implementados por servicio:
  nginx   — TLS, headers de seguridad, autoindex, server tokens, rate limiting
  apache  — TLS, .htaccess, directory listing, mod_security, server tokens
  mysql   — bind-address, auth plugin, usuarios anónimos, historial SQL
  postgresql — pg_hba.conf, SSL, roles con superuser
  redis   — bind, requirepass, protected-mode, comandos peligrosos
  mongodb — auth habilitada, bind_ip, TLS
  openssh — ya cubierto en hardening.py (omitido aquí)

Cada check detecta si el servicio está instalado/activo antes de analizar.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

from cyberhound.core.executor import command_exists, read_file_async, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("services_audit")


def _f(id, category, severity, title, description, remediation,
       evidence="", auto_fix=False, file_path="") -> Finding:
    return Finding(
        id=id, category=f"services/{category}", severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=auto_fix, file_path=file_path,
    )


async def _service_active(name: str) -> bool:
    proc = await run_command(["systemctl", "is-active", name], timeout=8, check=False)
    return "active" in proc.stdout.lower()


async def _find_config(candidates: list[str]) -> Optional[str]:
    for path in candidates:
        if Path(path).exists():
            return path
    return None


# ── NGINX ─────────────────────────────────────────────────────────────────────

async def audit_nginx() -> list[Finding]:
    if not command_exists("nginx") and not await _service_active("nginx"):
        return []

    findings = []
    config_dirs = ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled"]

    # Recopilar todos los ficheros de config
    config_files: list[str] = []
    if Path("/etc/nginx/nginx.conf").exists():
        config_files.append("/etc/nginx/nginx.conf")
    for d in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]:
        p = Path(d)
        if p.is_dir():
            config_files.extend(str(f) for f in p.glob("*.conf"))

    full_config = ""
    for cf in config_files:
        c = await read_file_async(cf)
        if c:
            full_config += c + "\n"

    if not full_config:
        return []

    # server_tokens
    if "server_tokens off" not in full_config:
        findings.append(_f(
            "nginx_server_tokens", "nginx", "low",
            "Nginx: server_tokens no deshabilitado",
            "Nginx revela su versión en las cabeceras de respuesta, facilitando ataques dirigidos.",
            "Añadir en el bloque http: server_tokens off;",
            auto_fix=False,
        ))

    # autoindex
    if re.search(r"autoindex\s+on", full_config):
        findings.append(_f(
            "nginx_autoindex", "nginx", "high",
            "Nginx: autoindex activado — listado de directorios",
            "El listado de directorios permite a atacantes ver el contenido de carpetas.",
            "Cambiar a: autoindex off;",
            auto_fix=False,
        ))

    # TLS — verificar si hay server blocks sin SSL
    servers_without_ssl = re.findall(
        r"server\s*\{[^}]*listen\s+80[^}]*\}",
        full_config, re.DOTALL
    )
    has_redirect = "return 301 https" in full_config or "return 302 https" in full_config
    if servers_without_ssl and not has_redirect:
        findings.append(_f(
            "nginx_no_https_redirect", "nginx", "high",
            "Nginx: sin redirección HTTP → HTTPS",
            "Hay bloques server escuchando en puerto 80 sin redirigir a HTTPS.",
            "Añadir en el bloque server del puerto 80:\nreturn 301 https://$host$request_uri;",
            auto_fix=False,
        ))

    # Security headers
    security_headers = {
        "X-Frame-Options": ("nginx_no_xframe", "medium",
            "Nginx: sin X-Frame-Options", "Vulnerable a clickjacking.",
            "add_header X-Frame-Options DENY;"),
        "X-Content-Type-Options": ("nginx_no_xcto", "medium",
            "Nginx: sin X-Content-Type-Options", "Permite MIME sniffing.",
            "add_header X-Content-Type-Options nosniff;"),
        "Strict-Transport-Security": ("nginx_no_hsts", "medium",
            "Nginx: sin HSTS", "Sin HSTS los navegadores pueden conectar por HTTP.",
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';"),
    }
    for header, (fid, sev, title, desc, fix) in security_headers.items():
        if header not in full_config:
            findings.append(_f(fid, "nginx", sev, title, desc, fix))

    # SSL — versiones antiguas
    if re.search(r"ssl_protocols.*TLSv1[^.2]", full_config):
        findings.append(_f(
            "nginx_old_tls", "nginx", "high",
            "Nginx: TLS 1.0 o 1.1 habilitado",
            "Versiones TLS antiguas tienen vulnerabilidades conocidas (POODLE, BEAST).",
            "ssl_protocols TLSv1.2 TLSv1.3;",
            auto_fix=False,
        ))

    # Rate limiting global
    if "limit_req_zone" not in full_config:
        findings.append(_f(
            "nginx_no_rate_limit", "nginx", "medium",
            "Nginx: sin rate limiting configurado",
            "Sin rate limiting la aplicación es vulnerable a ataques de fuerza bruta y DDoS.",
            "Añadir en el bloque http:\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n"
            "Y en los location blocks: limit_req zone=api burst=20 nodelay;",
            auto_fix=False,
        ))

    logger.info("nginx: %d hallazgos", len(findings))
    return findings


# ── APACHE ────────────────────────────────────────────────────────────────────

async def audit_apache() -> list[Finding]:
    if not command_exists("apache2") and not command_exists("httpd") \
            and not await _service_active("apache2"):
        return []

    findings = []
    config_dirs = [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
    ]
    config_file = await _find_config(config_dirs)
    if not config_file:
        return []

    # Recopilar configs incluyendo sites-enabled
    full_config = await read_file_async(config_file) or ""
    for d in ["/etc/apache2/sites-enabled", "/etc/apache2/conf-enabled"]:
        p = Path(d)
        if p.is_dir():
            for f in p.glob("*.conf"):
                c = await read_file_async(str(f))
                if c:
                    full_config += c + "\n"

    # ServerTokens
    if "ServerTokens Prod" not in full_config and "ServerTokens Min" not in full_config:
        findings.append(_f(
            "apache_server_tokens", "apache", "low",
            "Apache: ServerTokens no restringido",
            "Apache revela versión y OS en cabeceras. Facilita ataques dirigidos.",
            "Añadir en apache2.conf:\nServerTokens Prod\nServerSignature Off",
            auto_fix=False,
        ))

    # Directory listing
    if re.search(r"Options\s+[^\n]*Indexes", full_config):
        findings.append(_f(
            "apache_directory_listing", "apache", "high",
            "Apache: Directory listing habilitado (Options Indexes)",
            "Permite ver el contenido de directorios sin index.html.",
            "Reemplazar 'Options Indexes' por 'Options -Indexes' en la configuración.",
            auto_fix=False,
        ))

    # AllowOverride All — riesgo si .htaccess puede ser modificado
    if re.search(r"AllowOverride\s+All", full_config):
        findings.append(_f(
            "apache_allowoverride_all", "apache", "medium",
            "Apache: AllowOverride All — .htaccess puede sobreescribir config",
            "Si un atacante puede escribir .htaccess puede ejecutar código PHP o reescribir URLs.",
            "Cambiar a AllowOverride None o AllowOverride específico (AuthConfig, Limit, etc.)",
            auto_fix=False,
        ))

    # mod_security / mod_evasive
    proc = await run_command(["apache2ctl", "-M"], timeout=15, check=False)
    modules = proc.stdout.lower()
    if "security2" not in modules:
        findings.append(_f(
            "apache_no_modsecurity", "apache", "medium",
            "Apache: mod_security no activo",
            "Sin WAF (Web Application Firewall) el servidor es más vulnerable a ataques HTTP.",
            "apt install libapache2-mod-security2 && a2enmod security2",
            auto_fix=False,
        ))

    # TLS
    if "SSLProtocol" in full_config and re.search(r"SSLProtocol.*TLSv1[^.2]", full_config):
        findings.append(_f(
            "apache_old_tls", "apache", "high",
            "Apache: TLS 1.0 o 1.1 habilitado",
            "Versiones TLS obsoletas tienen vulnerabilidades conocidas.",
            "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            auto_fix=False,
        ))

    logger.info("apache: %d hallazgos", len(findings))
    return findings


# ── MYSQL / MARIADB ───────────────────────────────────────────────────────────

async def audit_mysql() -> list[Finding]:
    if not command_exists("mysql") and not await _service_active("mysql") \
            and not await _service_active("mariadb"):
        return []

    findings = []

    # Configuración
    config_candidates = ["/etc/mysql/mysql.conf.d/mysqld.cnf",
                         "/etc/mysql/my.cnf", "/etc/my.cnf"]
    config_file = await _find_config(config_candidates)
    if config_file:
        config = await read_file_async(config_file) or ""

        # bind-address
        if "bind-address" not in config:
            findings.append(_f(
                "mysql_no_bind_address", "mysql", "high",
                "MySQL: bind-address no configurado",
                "MySQL puede estar escuchando en todas las interfaces (0.0.0.0), "
                "exponiéndose a la red.",
                "Añadir en [mysqld]:\nbind-address = 127.0.0.1",
                auto_fix=False,
            ))
        elif "0.0.0.0" in config or "bind-address = ::" in config:
            findings.append(_f(
                "mysql_bind_all", "mysql", "critical",
                "MySQL escuchando en todas las interfaces",
                "MySQL es accesible desde cualquier IP de la red. "
                "Las BDs no deben estar expuestas directamente.",
                "Cambiar a: bind-address = 127.0.0.1",
                auto_fix=False,
            ))

        # SQL mode — sin STRICT
        if "sql_mode" in config and "STRICT_" not in config:
            findings.append(_f(
                "mysql_no_strict_mode", "mysql", "low",
                "MySQL: SQL strict mode no configurado",
                "Sin strict mode MySQL acepta datos inconsistentes silenciosamente.",
                "sql_mode = STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,"
                "ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
                auto_fix=False,
            ))

        # SSL
        if "ssl" not in config.lower() and "tls" not in config.lower():
            findings.append(_f(
                "mysql_no_ssl", "mysql", "medium",
                "MySQL: SSL/TLS no configurado",
                "Las conexiones a MySQL viajan sin cifrar por la red.",
                "Añadir en [mysqld]:\nssl-ca=/etc/mysql/ssl/ca.pem\n"
                "ssl-cert=/etc/mysql/ssl/server-cert.pem\n"
                "ssl-key=/etc/mysql/ssl/server-key.pem\nrequire_secure_transport=ON",
                auto_fix=False,
            ))

    # Usuarios anónimos — requiere acceso como root
    proc = await run_command(
        ["mysql", "-u", "root", "--batch", "-e",
         "SELECT user,host FROM mysql.user WHERE user='' OR authentication_string='';"],
        timeout=10, check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        findings.append(_f(
            "mysql_anonymous_users", "mysql", "critical",
            "MySQL: usuarios anónimos o sin contraseña detectados",
            f"Usuarios encontrados: {proc.stdout.strip()[:200]}",
            "mysql -u root -e \"DELETE FROM mysql.user WHERE user=''; FLUSH PRIVILEGES;\"",
            evidence=proc.stdout.strip()[:200],
            auto_fix=False,
        ))

    # historial de comandos MySQL (~/.mysql_history)
    history = Path.home() / ".mysql_history"
    if history.exists() and history.stat().st_size > 0:
        findings.append(_f(
            "mysql_history_file", "mysql", "medium",
            "MySQL: historial de comandos guardado en ~/.mysql_history",
            "El historial puede contener contraseñas y datos sensibles ejecutados en el cliente.",
            "rm ~/.mysql_history && ln -s /dev/null ~/.mysql_history",
            auto_fix=False,
            file_path=str(history),
        ))

    logger.info("mysql: %d hallazgos", len(findings))
    return findings


# ── POSTGRESQL ────────────────────────────────────────────────────────────────

async def audit_postgresql() -> list[Finding]:
    if not command_exists("psql") and not await _service_active("postgresql"):
        return []

    findings = []

    # Buscar pg_hba.conf
    proc = await run_command(
        ["find", "/etc/postgresql", "/var/lib/pgsql", "-name", "pg_hba.conf"],
        timeout=10, check=False,
    )
    hba_files = [p.strip() for p in proc.stdout.splitlines() if p.strip()]

    for hba_file in hba_files:
        content = await read_file_async(hba_file)
        if not content:
            continue

        # trust sin restricción de host
        if re.search(r"^\s*(host|local)\s+all\s+all\s+\S*\s+trust", content, re.MULTILINE):
            findings.append(_f(
                "pg_trust_auth", "postgresql", "critical",
                f"PostgreSQL: autenticación 'trust' en {hba_file}",
                "Cualquier usuario puede conectarse sin contraseña. "
                "Es el método de autenticación más inseguro.",
                "Cambiar 'trust' por 'scram-sha-256' o 'md5' en pg_hba.conf",
                evidence=f"trust en {hba_file}", auto_fix=False,
                file_path=hba_file,
            ))

        # Acceso desde 0.0.0.0/0
        if "0.0.0.0/0" in content or "::/0" in content:
            findings.append(_f(
                "pg_open_access", "postgresql", "high",
                "PostgreSQL: acceso desde cualquier IP configurado",
                "pg_hba.conf permite conexiones desde cualquier IP (0.0.0.0/0).",
                "Restringir a IPs específicas o usar 127.0.0.1/32 para acceso local.",
                auto_fix=False, file_path=hba_file,
            ))

    # postgresql.conf — SSL y listen_addresses
    proc2 = await run_command(
        ["find", "/etc/postgresql", "/var/lib/pgsql", "-name", "postgresql.conf"],
        timeout=10, check=False,
    )
    for pg_conf in [p.strip() for p in proc2.stdout.splitlines() if p.strip()]:
        content = await read_file_async(pg_conf)
        if not content:
            continue

        if re.search(r"ssl\s*=\s*off", content, re.IGNORECASE):
            findings.append(_f(
                "pg_ssl_off", "postgresql", "high",
                "PostgreSQL: SSL desactivado",
                "Las conexiones a PostgreSQL no están cifradas.",
                "Cambiar en postgresql.conf: ssl = on",
                auto_fix=False, file_path=pg_conf,
            ))

        if re.search(r"listen_addresses\s*=\s*['\"]?\*['\"]?", content):
            findings.append(_f(
                "pg_listen_all", "postgresql", "high",
                "PostgreSQL: listen_addresses = '*' — escuchando en todas las interfaces",
                "PostgreSQL acepta conexiones desde cualquier interfaz de red.",
                "Cambiar a: listen_addresses = 'localhost'",
                auto_fix=False, file_path=pg_conf,
            ))

    logger.info("postgresql: %d hallazgos", len(findings))
    return findings


# ── REDIS ─────────────────────────────────────────────────────────────────────

async def audit_redis() -> list[Finding]:
    if not command_exists("redis-cli") and not await _service_active("redis") \
            and not await _service_active("redis-server"):
        return []

    findings = []
    config_candidates = ["/etc/redis/redis.conf", "/etc/redis.conf"]
    config_file = await _find_config(config_candidates)

    if config_file:
        content = await read_file_async(config_file) or ""

        # bind — si escucha en todas las interfaces
        bind_match = re.search(r"^\s*bind\s+(.+)", content, re.MULTILINE)
        if not bind_match or "0.0.0.0" in bind_match.group(1):
            findings.append(_f(
                "redis_bind_all", "redis", "critical",
                "Redis: escuchando en todas las interfaces de red",
                "Redis sin autenticación expuesto en la red es un vector de ataque crítico. "
                "Permite leer/escribir datos y en algunas versiones ejecutar comandos.",
                "Cambiar en redis.conf:\nbind 127.0.0.1\nprotected-mode yes",
                auto_fix=False,
            ))

        # requirepass
        if not re.search(r"^\s*requirepass\s+\S+", content, re.MULTILINE):
            findings.append(_f(
                "redis_no_password", "redis", "critical",
                "Redis: sin contraseña (requirepass no configurado)",
                "Cualquier cliente puede conectarse a Redis y leer/modificar todos los datos.",
                "Añadir en redis.conf:\nrequirepass TuContraseñaSegura",
                auto_fix=False,
            ))

        # protected-mode
        if re.search(r"^\s*protected-mode\s+no", content, re.MULTILINE):
            findings.append(_f(
                "redis_protected_mode_off", "redis", "high",
                "Redis: protected-mode desactivado",
                "Con protected-mode desactivado Redis acepta conexiones externas sin restricción.",
                "Cambiar a: protected-mode yes",
                auto_fix=False,
            ))

        # Comandos peligrosos no renombrados
        for cmd in ["CONFIG", "DEBUG", "EVAL", "FLUSHALL", "KEYS"]:
            if f"rename-command {cmd}" not in content:
                findings.append(_f(
                    f"redis_cmd_{cmd.lower()}", "redis", "medium",
                    f"Redis: comando peligroso no renombrado: {cmd}",
                    f"El comando {cmd} puede usarse para examinar o destruir todos los datos.",
                    f"Añadir en redis.conf:\nrename-command {cmd} \"\"  # o nombre aleatorio",
                    auto_fix=False,
                ))

    logger.info("redis: %d hallazgos", len(findings))
    return findings


# ── MONGODB ───────────────────────────────────────────────────────────────────

async def audit_mongodb() -> list[Finding]:
    if not command_exists("mongod") and not await _service_active("mongod") \
            and not await _service_active("mongodb"):
        return []

    findings = []
    config_candidates = ["/etc/mongod.conf", "/etc/mongodb.conf"]
    config_file = await _find_config(config_candidates)

    if not config_file:
        return []

    content = await read_file_async(config_file) or ""

    # auth
    if not re.search(r"authorization\s*:\s*enabled", content) and \
       "security.authorization" not in content:
        if "auth = true" not in content and "auth=true" not in content:
            findings.append(_f(
                "mongo_no_auth", "mongodb", "critical",
                "MongoDB: autenticación no habilitada",
                "MongoDB sin autenticación permite acceso libre a todos los datos. "
                "Ha sido vector de múltiples brechas masivas (ransomware de MongoDB).",
                "Añadir en /etc/mongod.conf:\nsecurity:\n  authorization: enabled",
                auto_fix=False,
            ))

    # bindIp
    bind_match = re.search(r"bindIp\s*:\s*(.+)", content)
    if bind_match:
        bind_val = bind_match.group(1).strip()
        if "0.0.0.0" in bind_val:
            findings.append(_f(
                "mongo_bind_all", "mongodb", "critical",
                "MongoDB: escuchando en todas las interfaces (0.0.0.0)",
                "MongoDB es accesible desde cualquier IP. Combinado con sin auth es catastrófico.",
                "Cambiar en /etc/mongod.conf:\nnet:\n  bindIp: 127.0.0.1",
                auto_fix=False,
            ))
    else:
        # Sin bindIp explícito — puede escuchar en todas
        findings.append(_f(
            "mongo_no_bindip", "mongodb", "high",
            "MongoDB: bindIp no configurado explícitamente",
            "Sin bindIp explícito MongoDB puede escuchar en todas las interfaces.",
            "Añadir en /etc/mongod.conf:\nnet:\n  bindIp: 127.0.0.1",
            auto_fix=False,
        ))

    # TLS
    if "tls" not in content.lower() and "ssl" not in content.lower():
        findings.append(_f(
            "mongo_no_tls", "mongodb", "medium",
            "MongoDB: TLS/SSL no configurado",
            "Las conexiones a MongoDB viajan sin cifrar.",
            "Añadir en /etc/mongod.conf:\nnet:\n  tls:\n    mode: requireTLS\n"
            "    certificateKeyFile: /etc/ssl/mongodb.pem",
            auto_fix=False,
        ))

    logger.info("mongodb: %d hallazgos", len(findings))
    return findings


# ── Orquestador ───────────────────────────────────────────────────────────────

class ServicesAuditor:
    """Ejecuta todos los audits de servicios en paralelo."""

    AUDITS = {
        "nginx":      audit_nginx,
        "apache":     audit_apache,
        "mysql":      audit_mysql,
        "postgresql": audit_postgresql,
        "redis":      audit_redis,
        "mongodb":    audit_mongodb,
    }

    @classmethod
    async def full_audit(
        cls, services: Optional[list[str]] = None
    ) -> list[Finding]:
        """
        Audita todos los servicios instalados.
        Si se especifica `services`, solo audita esos.
        """
        targets = {k: v for k, v in cls.AUDITS.items()
                   if not services or k in services}

        results = await asyncio.gather(
            *[fn() for fn in targets.values()],
            return_exceptions=True,
        )

        findings: list[Finding] = []
        for service, result in zip(targets.keys(), results):
            if isinstance(result, list):
                findings.extend(result)
                if result:
                    logger.info("services/%s: %d hallazgos", service, len(result))
            elif isinstance(result, Exception):
                logger.error("services/%s error: %s", service, result)

        logger.info("ServicesAuditor: %d hallazgos totales", len(findings))
        return findings
