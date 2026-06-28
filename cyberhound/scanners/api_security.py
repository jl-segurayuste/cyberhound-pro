"""
Escáner de seguridad de API/CORS para CyberHound Pro.

Detecta problemas frecuentes en APIs y aplicaciones web:
  - CORS mal configurado (origen reflejado, '*' con credenciales, 'null')
  - Documentación de API expuesta (OpenAPI/Swagger, api-docs)
  - GraphQL con introspection habilitada
  - Fuga del descriptor OpenID (.well-known)

Usa aiohttp (ya es dependencia). Defensivo: un fallo de conexión no aborta
el resto. Dirigido por URL, como los demás scanners web.
"""
from __future__ import annotations

import asyncio

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("api_security")

# Origen atacante usado para sondear el comportamiento CORS.
EVIL_ORIGIN = "https://evil.attacker.example"

# Rutas típicas de documentación/descriptor de API (superficie expuesta).
API_DOC_PATHS = (
    ("openapi.json", "Especificación OpenAPI expuesta"),
    ("swagger.json", "Especificación Swagger expuesta"),
    ("v2/api-docs", "Swagger (springfox) expuesto"),
    ("api-docs", "Documentación de API expuesta"),
    ("swagger-ui.html", "Swagger UI expuesto"),
    (".well-known/openid-configuration", "Descriptor OpenID Connect expuesto"),
)

# Query mínima de introspección GraphQL.
GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'


def _f(fid, severity, title, description, remediation, evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="api_security", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def _check_cors(session, url, host, timeout) -> list[Finding]:
    """Sondea la política CORS enviando un Origin atacante."""
    import aiohttp
    findings: list[Finding] = []
    try:
        async with session.get(
            url, headers={"Origin": EVIL_ORIGIN},
            timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True,
        ) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    except (TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.debug("CORS %s: %s", url, e)
        return findings

    if acao == EVIL_ORIGIN:
        # El servidor refleja cualquier Origin → CORS roto.
        sev = "high" if acac == "true" else "medium"
        extra = " con credenciales (robo de sesión posible)" if acac == "true" else ""
        findings.append(_f(
            f"api_cors_reflect_{host}", sev,
            f"CORS refleja cualquier origen en {host}",
            f"El servidor devuelve Access-Control-Allow-Origin = origen del atacante{extra}.",
            "No reflejar el Origin: usar una allowlist explícita de dominios de confianza.",
            evidence=f"Origin: {EVIL_ORIGIN} → ACAO reflejado; ACAC={acac or 'no'}", host=host,
        ))
    elif acao == "*" and acac == "true":
        findings.append(_f(
            f"api_cors_wildcard_creds_{host}", "high",
            f"CORS '*' con credenciales en {host}",
            "Combinar Access-Control-Allow-Origin: * con Allow-Credentials: true es inseguro.",
            "Usar una allowlist explícita en vez de '*' si se envían credenciales.",
            evidence=f"ACAO=*; ACAC={acac}", host=host,
        ))
    elif acao == "null":
        findings.append(_f(
            f"api_cors_null_{host}", "medium",
            f"CORS acepta origen 'null' en {host}",
            "Permitir el origen 'null' habilita ataques desde iframes sandbox/datos locales.",
            "No incluir 'null' en la allowlist de orígenes permitidos.",
            evidence="ACAO=null", host=host,
        ))
    return findings


async def _check_api_docs(session, base, host, timeout) -> list[Finding]:
    """Detecta documentación/descriptor de API accesible públicamente."""
    import aiohttp
    findings: list[Finding] = []

    async def probe(path, title):
        try:
            async with session.get(
                base + path, timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    return None
                ctype = resp.headers.get("content-type", "").lower()
                body = (await resp.text(errors="replace"))[:512]
        except (TimeoutError, aiohttp.ClientError, OSError, UnicodeError):
            return None
        # Confirmar que parece una spec real (json/yaml/swagger), no una SPA genérica.
        looks_real = (
            "json" in ctype or "yaml" in ctype
            or any(k in body for k in ('"openapi"', '"swagger"', "openid", "issuer"))
        )
        if not looks_real:
            return None
        return _f(
            f"api_docs_{path.replace('/', '_').replace('.', '')}_{host}", "low",
            f"{title} en {host}",
            "La documentación/descriptor de la API es accesible sin autenticación: "
            "facilita el mapeo de endpoints a un atacante.",
            f"Restringir el acceso a /{path} (autenticación o red interna) si no es público.",
            evidence=f"{base}{path} → 200", host=host,
        )

    results = await asyncio.gather(
        *(probe(p, t) for p, t in API_DOC_PATHS), return_exceptions=True,
    )
    for r in results:
        if isinstance(r, Finding):
            findings.append(r)
    return findings


async def _check_graphql(session, base, host, timeout) -> list[Finding]:
    """Detecta GraphQL con introspección habilitada."""
    import aiohttp
    findings: list[Finding] = []
    for path in ("graphql", "api/graphql"):
        try:
            async with session.post(
                base + path, data=GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    continue
                body = (await resp.text(errors="replace"))[:512]
        except (TimeoutError, aiohttp.ClientError, OSError, UnicodeError):
            continue
        if "__schema" in body or '"queryType"' in body:
            findings.append(_f(
                f"api_graphql_introspection_{host}", "medium",
                f"GraphQL con introspection habilitada en {host}",
                "La introspección expone todo el esquema (tipos, queries, mutations) "
                "a cualquiera, facilitando el descubrimiento de la API.",
                "Deshabilitar la introspección en producción.",
                evidence=f"{base}{path} responde al query __schema", host=host,
            ))
            break
    return findings


async def scan_url(url: str, timeout: int = 10) -> list[Finding]:
    """Analiza la seguridad de API/CORS de una URL."""
    findings: list[Finding] = []
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    base = url.rstrip("/") + "/"
    host = base.split("://", 1)[-1].split("/", 1)[0]

    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp no disponible — scanner de API deshabilitado")
        return findings

    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(
                _check_cors(session, url, host, timeout),
                _check_api_docs(session, base, host, timeout),
                _check_graphql(session, base, host, timeout),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)
                elif isinstance(r, Exception):
                    logger.debug("Error en sub-check de API: %s", r)
    except (aiohttp.ClientError, OSError) as e:
        logger.debug("No se pudo escanear %s: %s", url, e)

    return findings


class APISecurityScanner:
    """Escanea la seguridad de API/CORS de múltiples URLs en paralelo."""

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
                logger.debug("Error en scan de API: %s", r)
        return findings
