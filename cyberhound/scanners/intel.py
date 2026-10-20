"""
Clientes de APIs de inteligencia externa.

Cada fuente devuelve su JSON en bruto (ExternalIntel) y `to_findings()` lo traduce
a hallazgos normalizados (categoría "intel/<fuente>"), que son lo que guardan la BD,
el resumen y la UI.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import quote

import aiohttp

from cyberhound.core.logging import get_logger
from cyberhound.core.models import ExternalIntel, Finding

logger = get_logger("intel")

ALL_MODULES = ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp")
# Qué tipo de indicador entiende cada fuente
MODULE_KINDS = {
    "shodan": {"ip"}, "abuseipdb": {"ip"}, "greynoise": {"ip"},
    "virustotal": {"ip", "domain", "hash"}, "otx": {"ip", "domain", "hash"}, "hibp": {"email"},
}
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s/]{1,64}@[^@\s/]{1,253}$")


def indicator_kind(target: str) -> str | None:
    """ip | domain | hash | email, o None si no es un indicador válido."""
    t = (target or "").strip()
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", t):
        return "hash"
    if _EMAIL_RE.match(t) and _HOST_RE.match(t.split("@", 1)[1]):
        return "email"
    if _HOST_RE.match(t):
        return "domain"
    return None


class IntelScanner:
    def __init__(self, api_keys) -> None:
        self.keys = api_keys

    def configured_modules(self) -> list[str]:
        return [m for m in ALL_MODULES if getattr(self.keys, m, None)]

    async def scan(self, target: str, modules: list[str] | None = None) -> list[ExternalIntel]:
        """Consulta las fuentes pedidas (todas las configuradas si no se indica ninguna)."""
        kind = indicator_kind(target)
        if kind is None:
            raise ValueError(f"Indicador no válido: {target!r}")
        wanted = [m for m in (modules or self.configured_modules()) if m in ALL_MODULES]
        results: list[ExternalIntel] = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            tasks = {m: getattr(self, f"_{m}")(session, target, kind) for m in wanted
                     if getattr(self.keys, m, None) and kind in MODULE_KINDS[m]}
            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for source, res in zip(tasks.keys(), gathered, strict=False):
                if isinstance(res, Exception):
                    logger.warning("Intel %s error: %s", source, res)
                elif res is not None:
                    results.append(ExternalIntel(source=source, indicator=target, data=res))
        return results

    async def scan_findings(self, target: str, modules: list[str] | None = None) -> list[Finding]:
        return [f for item in await self.scan(target, modules) for f in to_findings(item)]

    @staticmethod
    async def _get(s, url, **kw):
        async with s.get(url, **kw) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            if r.status == 404:
                return {}   # la fuente no conoce el indicador
            logger.warning("Intel %s → HTTP %s", url.split("?")[0], r.status)
            return None

    async def _shodan(self, s, ip, kind):
        return await self._get(s, f"https://api.shodan.io/shodan/host/{quote(ip)}", params={"key": self.keys.shodan})

    async def _virustotal(self, s, target, kind):
        path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
        return await self._get(s, f"https://www.virustotal.com/api/v3/{path}/{quote(target)}",
                               headers={"x-apikey": self.keys.virustotal})

    async def _abuseipdb(self, s, ip, kind):
        return await self._get(s, "https://api.abuseipdb.com/api/v2/check", headers={"Key": self.keys.abuseipdb,
                               "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90})

    async def _greynoise(self, s, ip, kind):
        return await self._get(s, f"https://api.greynoise.io/v3/community/{quote(ip)}",
                               headers={"key": self.keys.greynoise})

    async def _otx(self, s, target, kind):
        section = {"ip": "IPv6" if ":" in target else "IPv4", "domain": "domain", "hash": "file"}[kind]
        return await self._get(s, f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(target)}/general",
                               headers={"X-OTX-API-KEY": self.keys.otx})

    async def _hibp(self, s, email, kind):
        data = await self._get(s, f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                               headers={"hibp-api-key": self.keys.hibp, "user-agent": "cyberhound"},
                               params={"truncateResponse": "false"})
        return {"breaches": data if isinstance(data, list) else []} if data is not None else None


def _finding(item: ExternalIntel, key: str, severity: str, title: str, description: str,
             remediation: str, evidence: str) -> Finding:
    kind = indicator_kind(item.indicator) or "target"
    return Finding(
        id=f"intel_{item.source}_{key}_{re.sub(r'[^a-z0-9]', '_', item.indicator.lower())[:60]}",
        category=f"intel/{item.source}", severity=severity, title=title, description=description,
        remediation=remediation, evidence=f"{kind}={item.indicator} {evidence}".strip(),
        source_host=item.indicator if kind in ("ip", "domain") else "",
    )


def to_findings(item: ExternalIntel) -> list[Finding]:
    """Traduce la respuesta de una fuente a hallazgos (lista vacía si no hay nada relevante)."""
    d = item.data or {}
    src, ind = item.source, item.indicator
    out: list[Finding] = []
    if src == "shodan" and d:
        ports = sorted({p for p in d.get("ports", []) if isinstance(p, int)})
        raw_vulns = d.get("vulns") or []
        vulns = sorted(raw_vulns if isinstance(raw_vulns, list) else raw_vulns.keys())
        if ports:
            out.append(_finding(item, "ports", "medium", f"{ind} expone {len(ports)} puerto(s) en Internet",
                                "Shodan ha indexado servicios accesibles públicamente en esta IP.",
                                "Cierra o filtra en el firewall los puertos que no deban ser públicos.",
                                f"puertos={','.join(map(str, ports[:30]))}"))
        if vulns:
            out.append(_finding(item, "vulns", "critical" if len(vulns) >= 5 else "high",
                                f"{ind}: {len(vulns)} CVE(s) según Shodan",
                                "Shodan asocia vulnerabilidades conocidas a los servicios expuestos.",
                                "Actualiza los servicios afectados y vuelve a escanear.", f"cves={','.join(vulns[:20])}"))
    elif src == "virustotal" and d:
        attrs = (d.get("data") or {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        if mal or sus:
            sev = "critical" if mal >= 5 else "high" if mal else "medium"
            out.append(_finding(item, "detections", sev, f"VirusTotal: {mal} motor(es) lo marcan malicioso",
                                f"{mal} detecciones maliciosas y {sus} sospechosas en el último análisis.",
                                "Investiga el indicador; si es tuyo, revisa si está comprometido.",
                                f"malicious={mal} suspicious={sus} reputation={attrs.get('reputation', 0)}"))
    elif src == "abuseipdb" and d:
        info = d.get("data") or {}
        score = int(info.get("abuseConfidenceScore", 0) or 0)
        if score > 0:
            sev = "critical" if score >= 75 else "high" if score >= 25 else "medium"
            out.append(_finding(item, "abuse", sev, f"AbuseIPDB: confianza de abuso {score}%",
                                f"{info.get('totalReports', 0)} denuncias en 90 días.",
                                "Bloquea la IP si no es legítima o revisa si un equipo tuyo está comprometido.",
                                f"score={score} reports={info.get('totalReports', 0)} isp={info.get('isp', '')}"))
    elif src == "greynoise" and d:
        cls = d.get("classification", "")
        if cls == "malicious":
            out.append(_finding(item, "malicious", "high", "GreyNoise: IP clasificada como maliciosa",
                                "La IP aparece escaneando o atacando Internet de forma activa.",
                                "Bloquea la IP en el perímetro.", f"name={d.get('name', '')}"))
        elif d.get("noise"):
            out.append(_finding(item, "noise", "low", "GreyNoise: IP que escanea Internet",
                                "Ruido de fondo de Internet (escáneres masivos), sin clasificación maliciosa.",
                                "Normalmente basta con no exponer servicios innecesarios.", f"class={cls}"))
    elif src == "otx" and d:
        pulses = int((d.get("pulse_info") or {}).get("count", 0) or 0)
        if pulses:
            out.append(_finding(item, "pulses", "high" if pulses >= 3 else "medium",
                                f"AlienVault OTX: aparece en {pulses} pulso(s) de amenazas",
                                "El indicador figura en informes de amenazas de la comunidad OTX.",
                                "Revisa los pulsos y bloquea el indicador si procede.", f"pulses={pulses}"))
    elif src == "hibp":
        breaches = d.get("breaches", [])
        if breaches:
            names = ",".join(b.get("Name", "?") for b in breaches[:15])
            out.append(_finding(item, "breaches", "high", f"{ind} aparece en {len(breaches)} brecha(s) de datos",
                                "La cuenta figura en filtraciones públicas (Have I Been Pwned).",
                                "Cambia la contraseña en esos servicios y activa 2FA.", f"brechas={names}"))
    return out
