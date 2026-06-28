"""
Escáner de seguridad DNS para CyberHound Pro.

Audita la configuración DNS de seguridad de un dominio:
  - SPF   (Sender Policy Framework) — registro y política
  - DMARC — registro, política (none/quarantine/reject) y rua
  - DKIM  — presencia en selectores comunes
  - DNSSEC — firma de la zona
  - CAA   — Certificate Authority Authorization
  - MX    — registros de correo (informativo)
  - Registros peligrosos (SPF con +all, DMARC p=none)

Usa dnspython (async). Defensivo: si una consulta falla, no aborta el resto.
"""
from __future__ import annotations

import asyncio

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("dns_security")

# Selectores DKIM comunes a comprobar
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]


def _f(fid, severity, title, description, remediation, evidence="", host="") -> Finding:
    return Finding(
        id=fid, category="dns", severity=severity, title=title,
        description=description, remediation=remediation,
        evidence=evidence, source_host=host,
    )


async def _query(resolver, name: str, rtype: str):
    """Consulta DNS defensiva: devuelve lista de strings o []."""
    try:
        ans = await resolver.resolve(name, rtype)
        return [r.to_text().strip('"') for r in ans]
    except Exception:
        return []


async def scan_domain(domain: str) -> list[Finding]:
    """Audita la configuración DNS de seguridad de un dominio."""
    findings: list[Finding] = []
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        return findings

    try:
        import dns.asyncresolver
        import dns.dnssec
        import dns.resolver
    except ImportError:
        logger.warning("dnspython no disponible — scanner DNS deshabilitado")
        return findings

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10
    resolver.timeout = 5

    # ── SPF ──────────────────────────────────────────────────────────────────
    txt_records = await _query(resolver, domain, "TXT")
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(_f(
            f"dns_no_spf_{domain}", "high",
            f"Sin registro SPF en {domain}",
            "El dominio no tiene SPF; facilita la suplantación de correo (spoofing).",
            "Añadir un registro TXT SPF, p.ej. 'v=spf1 include:_spf.google.com -all'.",
            host=domain,
        ))
    else:
        # SPF demasiado permisivo (+all o ?all)
        if "+all" in spf or spf.rstrip().endswith("?all"):
            findings.append(_f(
                f"dns_spf_weak_{domain}", "high",
                f"SPF permisivo en {domain}",
                f"El SPF usa una política débil: {spf[:80]}",
                "Cambiar a '-all' (hardfail) o '~all' (softfail).",
                evidence=spf[:120], host=domain,
            ))

    # ── DMARC ────────────────────────────────────────────────────────────────
    dmarc_records = await _query(resolver, f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_records if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append(_f(
            f"dns_no_dmarc_{domain}", "high",
            f"Sin registro DMARC en {domain}",
            "Sin DMARC no hay política de tratamiento del correo no autenticado.",
            "Añadir TXT en _dmarc.{dominio}: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{dominio}'.",
            host=domain,
        ))
    else:
        policy = ""
        for part in dmarc.split(";"):
            if part.strip().lower().startswith("p="):
                policy = part.split("=", 1)[1].strip().lower()
        if policy == "none":
            findings.append(_f(
                f"dns_dmarc_none_{domain}", "medium",
                f"DMARC en modo monitorización (p=none) en {domain}",
                "DMARC con p=none solo reporta, no protege contra spoofing.",
                "Endurecer a 'p=quarantine' o 'p=reject' tras validar los informes.",
                evidence=dmarc[:120], host=domain,
            ))
        if "rua=" not in dmarc.lower():
            findings.append(_f(
                f"dns_dmarc_no_rua_{domain}", "low",
                f"DMARC sin dirección de informes (rua) en {domain}",
                "Sin 'rua' no recibes informes agregados de DMARC.",
                "Añadir 'rua=mailto:dmarc@{dominio}' al registro DMARC.",
                host=domain,
            ))

    # ── DKIM ─────────────────────────────────────────────────────────────────
    has_mx = bool(await _query(resolver, domain, "MX"))
    if has_mx:
        dkim_found = False
        for sel in COMMON_DKIM_SELECTORS:
            rec = await _query(resolver, f"{sel}._domainkey.{domain}", "TXT")
            if any("v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r for r in rec):
                dkim_found = True
                break
        if not dkim_found:
            findings.append(_f(
                f"dns_no_dkim_{domain}", "medium",
                f"Sin DKIM detectado en {domain}",
                "No se encontró DKIM en los selectores comunes (el correo puede no firmarse).",
                "Configurar DKIM en tu proveedor de correo y publicar la clave pública.",
                host=domain,
            ))

    # ── DNSSEC ───────────────────────────────────────────────────────────────
    dnskey = await _query(resolver, domain, "DNSKEY")
    if not dnskey:
        findings.append(_f(
            f"dns_no_dnssec_{domain}", "low",
            f"DNSSEC no habilitado en {domain}",
            "Sin DNSSEC, las respuestas DNS pueden ser manipuladas (cache poisoning).",
            "Habilitar DNSSEC en tu proveedor DNS (Cloudflare: DNS → Settings → DNSSEC).",
            host=domain,
        ))

    # ── CAA ──────────────────────────────────────────────────────────────────
    caa = await _query(resolver, domain, "CAA")
    if not caa:
        findings.append(_f(
            f"dns_no_caa_{domain}", "low",
            f"Sin registros CAA en {domain}",
            "Sin CAA, cualquier CA puede emitir certificados para el dominio.",
            "Añadir CAA, p.ej. 0 issue \"letsencrypt.org\".",
            host=domain,
        ))

    return findings


class DNSSecurityScanner:
    """Audita la seguridad DNS de múltiples dominios en paralelo."""

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
                logger.debug("Error en scan DNS: %s", r)
        return findings
