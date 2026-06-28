"""
Escáner de enumeración de subdominios para CyberHound Pro.

Descubre subdominios de un dominio consultando los registros públicos de
Certificate Transparency (crt.sh) y comprueba cuáles resuelven a una IP
(superficie de ataque real). Reconocimiento defensivo: saber qué tienes
publicado antes que un atacante.

Usa aiohttp (crt.sh) + dnspython (resolución async). Defensivo: un fallo de
red devuelve lista vacía sin abortar.
"""
from __future__ import annotations

import asyncio

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("subdomain_enum")

# Límite de subdominios a resolver (evita escaneos enormes/lentos).
MAX_RESOLVE = 200


def _f(fid, severity, title, description, remediation, evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="subdomain_enum", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def _crtsh_subdomains(session, domain: str, timeout: int) -> set[str]:
    """Consulta crt.sh (Certificate Transparency) y devuelve subdominios únicos."""
    import aiohttp
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: set[str] = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                return subs
            data = await resp.json(content_type=None)
    except (TimeoutError, aiohttp.ClientError, OSError, ValueError) as e:
        logger.debug("crt.sh %s: %s", domain, e)
        return subs
    for entry in data or []:
        for name in (entry.get("name_value", "") or "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain) and name != domain and " " not in name:
                subs.add(name)
    return subs


async def _resolve(sub: str) -> str | None:
    """Devuelve la primera IP A del subdominio, o None si no resuelve."""
    try:
        import dns.asyncresolver
        ans = await dns.asyncresolver.resolve(sub, "A")
        return str(ans[0]) if ans else None
    except Exception as e:  # NXDOMAIN, timeout, etc. — no resuelve
        logger.debug("resolve %s: %s", sub, e)
        return None


async def scan_domain(domain: str, timeout: int = 30) -> list[Finding]:
    """Enumera subdominios de un dominio vía CT logs y marca los activos."""
    findings: list[Finding] = []
    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return findings

    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp no disponible — scanner de subdominios deshabilitado")
        return findings

    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            subs = await _crtsh_subdomains(session, domain, timeout)
    except (aiohttp.ClientError, OSError) as e:
        logger.debug("crt.sh sesión %s: %s", domain, e)
        return findings

    if not subs:
        return findings

    ordered = sorted(subs)[:MAX_RESOLVE]
    resolved = await asyncio.gather(*(_resolve(s) for s in ordered), return_exceptions=True)
    active = [(s, ip) for s, ip in zip(ordered, resolved, strict=False) if isinstance(ip, str) and ip]

    # Resumen
    sample = ", ".join(s for s, _ in active[:20]) + ("…" if len(active) > 20 else "")
    findings.append(_f(
        f"subenum_summary_{domain}", "info",
        f"{len(subs)} subdominios en CT logs de {domain} ({len(active)} activos)",
        f"Subdominios publicados en Certificate Transparency. Activos (resuelven): {sample or '—'}",
        "Revisa que cada subdominio publicado deba existir; retira los que no uses "
        "(reducen la superficie de ataque).",
        evidence=f"CT total: {len(subs)} · activos: {len(active)}", host=domain,
    ))

    # Uno por subdominio activo (superficie real)
    for s, ip in active:
        findings.append(_f(
            f"subenum_active_{s}", "low",
            f"Subdominio activo: {s}",
            f"{s} resuelve a {ip} — forma parte de la superficie expuesta.",
            "Confirma que este subdominio debe estar publicado y correctamente protegido.",
            evidence=f"{s} -> {ip}", host=s,
        ))

    return findings


class SubdomainEnumScanner:
    """Enumera subdominios de varios dominios en paralelo (CT logs)."""

    @classmethod
    async def full_scan(cls, domains: list[str] | None = None) -> list[Finding]:
        domains = domains or []
        if not domains:
            return []
        results = await asyncio.gather(
            *(scan_domain(d) for d in domains), return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug("Error en enum de subdominios: %s", r)
        return findings
