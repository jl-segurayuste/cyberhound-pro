"""
Escáner de cabeceras de seguridad web para CyberHound Pro.

Analiza las cabeceras HTTP de respuesta de un sitio y detecta:
  - Cabeceras de seguridad ausentes o mal configuradas
    (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
     Permissions-Policy)
  - Cookies inseguras (sin Secure / HttpOnly / SameSite)
  - Fuga de información (Server, X-Powered-By con versiones)

No requiere herramientas externas: usa aiohttp (ya es dependencia).
Defensivo: un fallo de conexión no aborta el resto.
"""
from __future__ import annotations

import asyncio

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("web_headers")

# Cabeceras de seguridad esperadas: (severidad, remediación, validador)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "high",
        "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        lambda v: "max-age" in v.lower(),
    ),
    "content-security-policy": (
        "high",
        "Definir una CSP estricta. Mínimo: default-src 'self'",
        lambda v: "default-src" in v.lower() or "script-src" in v.lower(),
    ),
    "x-content-type-options": (
        "medium",
        "Añadir: X-Content-Type-Options: nosniff",
        lambda v: v.lower().strip() == "nosniff",
    ),
    "x-frame-options": (
        "medium",
        "Añadir: X-Frame-Options: DENY (o usar CSP frame-ancestors)",
        lambda v: v.upper().strip() in ("DENY", "SAMEORIGIN"),
    ),
    "referrer-policy": (
        "low",
        "Añadir: Referrer-Policy: strict-origin-when-cross-origin",
        lambda v: len(v.strip()) > 0,
    ),
    "permissions-policy": (
        "low",
        "Añadir: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        lambda v: len(v.strip()) > 0,
    ),
}

# Cabeceras que revelan información del stack
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


def _f(fid, severity, title, description, remediation, evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="web_headers", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def scan_url(url: str, timeout: int = 12) -> list[Finding]:
    """Analiza las cabeceras de seguridad de una URL."""
    findings: list[Finding] = []
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp no disponible — scanner de cabeceras deshabilitado")
        return findings

    # Identificador estable basado en el host
    host = url.split("://", 1)[-1].split("/", 1)[0]

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
            ) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.getall("set-cookie", [])
    except (TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.debug("No se pudo conectar a %s: %s", url, e)
        return findings

    # ── Cabeceras de seguridad ausentes / mal configuradas ──────────────────
    for header, (severity, remediation, validator) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_f(
                f"webhdr_missing_{header}_{host}", severity,
                f"Cabecera de seguridad ausente: {header}",
                f"La respuesta de {host} no incluye {header}.",
                remediation, evidence=f"url={url}", host=host,
            ))
        elif not validator(headers[header]):
            findings.append(_f(
                f"webhdr_weak_{header}_{host}", "low",
                f"Cabecera {header} mal configurada en {host}",
                f"Valor actual: {headers[header][:80]}",
                remediation, evidence=f"{header}={headers[header][:80]}", host=host,
            ))

    # ── Cookies inseguras ────────────────────────────────────────────────────
    for cookie in cookies:
        cl = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()
        issues = []
        if "secure" not in cl:
            issues.append("Secure")
        if "httponly" not in cl:
            issues.append("HttpOnly")
        if "samesite" not in cl:
            issues.append("SameSite")
        if issues:
            findings.append(_f(
                f"webhdr_insecure_cookie_{cookie_name}_{host}", "medium",
                f"Cookie insegura '{cookie_name}' en {host}",
                f"La cookie carece de atributos: {', '.join(issues)}.",
                f"Añadir los atributos {', '.join(issues)} a la cookie '{cookie_name}'.",
                evidence=f"cookie={cookie[:80]}", host=host,
            ))

    # ── Fuga de información ───────────────────────────────────────────────────
    for header in LEAKY_HEADERS:
        if header in headers:
            val = headers[header]
            # Solo avisar si revela versión (contiene dígitos)
            if any(c.isdigit() for c in val):
                findings.append(_f(
                    f"webhdr_info_leak_{header}_{host}", "low",
                    f"Fuga de información: {header} en {host}",
                    f"La cabecera {header} revela: {val[:60]}",
                    f"Ocultar/genérico la cabecera {header} para no exponer versiones.",
                    evidence=f"{header}={val[:60]}", host=host,
                ))

    return findings


class WebHeadersScanner:
    """Escanea las cabeceras de seguridad de múltiples URLs en paralelo."""

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
                logger.debug("Error en scan de cabeceras: %s", r)
        return findings
