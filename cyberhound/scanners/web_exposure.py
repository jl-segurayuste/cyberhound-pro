"""
Escáner de exposición web para CyberHound Pro.

Detecta recursos sensibles accesibles públicamente en un sitio:
  - Repositorios de código expuestos (.git/, .svn/)
  - Configuración y secretos (.env y sus backups)
  - Copias de seguridad (backup.zip, dump.sql, …)
  - Directory listing habilitado
  - Métodos HTTP peligrosos (TRACE, PUT, DELETE)

Usa aiohttp (ya es dependencia). Defensivo: un fallo de conexión no aborta
el resto. Incluye baseline anti *soft-404* (sitios que responden 200 a todo)
y validadores de contenido para minimizar falsos positivos.
"""
from __future__ import annotations

import asyncio
import secrets as _secrets

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("web_exposure")

# (ruta, severidad, título, descripción, validador|None)
# El validador recibe el cuerpo (str) y confirma que el recurso es real.
SENSITIVE_PATHS: list[tuple[str, str, str, str, object]] = [
    (".git/HEAD", "critical", "Repositorio Git expuesto",
     "El directorio .git es accesible: permite reconstruir todo el código e historial.",
     lambda b: b.lstrip().startswith("ref:") or "refs/" in b),
    (".git/config", "high", "Configuración Git expuesta",
     "El archivo .git/config es accesible (puede revelar remotes y credenciales).",
     lambda b: "[core]" in b or "[remote" in b),
    (".env", "critical", "Archivo .env expuesto",
     "Variables de entorno/credenciales potencialmente accesibles en público.",
     lambda b: "=" in b and "<html" not in b.lower()),
    (".env.bak", "critical", "Backup de .env expuesto",
     "Copia de seguridad de variables de entorno accesible.",
     lambda b: "=" in b and "<html" not in b.lower()),
    (".svn/entries", "high", "Repositorio SVN expuesto",
     "Metadatos SVN accesibles: pueden revelar estructura y código.", None),
    ("server-status", "medium", "Apache server-status expuesto",
     "mod_status revela peticiones, IPs y rutas internas.",
     lambda b: "Apache Server Status" in b),
    ("phpinfo.php", "medium", "phpinfo() expuesto",
     "Revela configuración de PHP, rutas absolutas y módulos.",
     lambda b: "phpinfo()" in b or "PHP Version" in b),
    (".DS_Store", "low", "Archivo .DS_Store expuesto",
     "Metadatos de macOS que filtran nombres de archivos del directorio.", None),
    ("backup.sql", "high", "Volcado SQL expuesto",
     "Posible backup de base de datos descargable.", None),
    ("dump.sql", "high", "Volcado SQL expuesto",
     "Posible backup de base de datos descargable.", None),
    ("backup.zip", "high", "Backup comprimido expuesto",
     "Archivo de copia de seguridad accesible.", None),
    ("wp-config.php.bak", "critical", "Backup de wp-config expuesto",
     "Copia de la configuración de WordPress con credenciales de BD.", None),
    ("config.php.bak", "high", "Backup de config.php expuesto",
     "Copia de configuración accesible (posibles credenciales).", None),
    ("web.config", "medium", "web.config expuesto",
     "Configuración de IIS/ASP.NET accesible.", lambda b: "<configuration" in b),
]

# Métodos que no deberían estar habilitados de cara al público.
DANGEROUS_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


def _f(fid, severity, title, description, remediation, evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="web_exposure", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def _fetch(session, url, timeout):
    """GET defensivo → (status, body_text, content_type). (-1, '', '') si falla."""
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False,
        ) as resp:
            ctype = resp.headers.get("content-type", "")
            body = await resp.text(errors="replace")
            return resp.status, body[:4096], ctype
    except (TimeoutError, aiohttp.ClientError, OSError, UnicodeError) as e:
        logger.debug("fetch %s: %s", url, e)
        return -1, "", ""


async def scan_url(url: str, timeout: int = 10) -> list[Finding]:
    """Analiza la exposición de recursos sensibles de una URL."""
    findings: list[Finding] = []
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    base = url.rstrip("/") + "/"
    host = base.split("://", 1)[-1].split("/", 1)[0]

    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp no disponible — scanner de exposición deshabilitado")
        return findings

    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # Baseline anti soft-404: una ruta aleatoria que no debería existir.
            rnd = _secrets.token_hex(10)
            s404_status, s404_body, _ = await _fetch(session, base + rnd, timeout)
            s404_len = len(s404_body)

            async def check(path, severity, title, desc, validator):
                status, body, ctype = await _fetch(session, base + path, timeout)
                if status != 200:
                    return None
                # soft-404: si la ruta aleatoria también da 200 y tamaño similar → ignorar
                if s404_status == 200 and abs(len(body) - s404_len) < 48:
                    return None
                if validator is not None:
                    if not validator(body):
                        return None
                elif "text/html" in ctype.lower():
                    # sin validador, un HTML suele ser una página de error/genérica
                    return None
                return _f(
                    f"webexp_{path.replace('/', '_').replace('.', '')}_{host}",
                    severity, f"{title} en {host}", desc,
                    f"Bloquear el acceso público a /{path} (regla en el servidor/proxy "
                    "o eliminar el recurso del webroot).",
                    evidence=f"{base}{path} → 200 ({len(body)}B)", host=host,
                )

            results = await asyncio.gather(
                *(check(*p) for p in SENSITIVE_PATHS), return_exceptions=True,
            )
            for r in results:
                if isinstance(r, Finding):
                    findings.append(r)

            # ── Directory listing ────────────────────────────────────────────
            status, body, _ = await _fetch(session, base, timeout)
            if status == 200 and ("Index of /" in body or "<title>Directory listing" in body):
                findings.append(_f(
                    f"webexp_dirlisting_{host}", "medium",
                    f"Directory listing habilitado en {host}",
                    "El servidor lista el contenido de los directorios, exponiendo archivos.",
                    "Deshabilitar el autoindex (Apache: 'Options -Indexes'; nginx: 'autoindex off').",
                    evidence=f"{base} muestra 'Index of /'", host=host,
                ))

            # ── Métodos HTTP peligrosos ──────────────────────────────────────
            try:
                async with session.options(
                    base, timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    allow = resp.headers.get("Allow", "")
                bad = sorted(DANGEROUS_METHODS & {m.strip().upper() for m in allow.split(",")})
                if bad:
                    findings.append(_f(
                        f"webexp_methods_{host}", "medium",
                        f"Métodos HTTP peligrosos habilitados en {host}",
                        f"El servidor permite: {', '.join(bad)}.",
                        "Deshabilitar los métodos no usados (TRACE/PUT/DELETE) en el servidor/proxy.",
                        evidence=f"Allow: {allow[:80]}", host=host,
                    ))
            except (TimeoutError, aiohttp.ClientError, OSError) as e:
                logger.debug("OPTIONS %s: %s", base, e)
    except (aiohttp.ClientError, OSError) as e:
        logger.debug("No se pudo escanear %s: %s", url, e)

    return findings


class WebExposureScanner:
    """Escanea la exposición de recursos sensibles de múltiples URLs en paralelo."""

    @classmethod
    async def full_scan(cls, urls: list[str] | None = None) -> list[Finding]:
        urls = urls or []
        if not urls:
            return []
        results = await asyncio.gather(
            *(scan_url(u) for u in urls), return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug("Error en scan de exposición: %s", r)
        return findings
