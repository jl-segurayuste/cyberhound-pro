"""
Escáner Nuclei para CyberHound Pro.

Envuelve el motor open-source **Nuclei** (ProjectDiscovery): miles de plantillas
de detección de CVEs, configuraciones inseguras y exposiciones, mantenidas por la
comunidad. CyberHound no reimplementa la lógica de detección — orquesta Nuclei y
normaliza su salida a `Finding` para unificar scoring, triaje e informes con el
resto de scanners.

Invoca el binario `nuclei` (debe estar instalado, con sus plantillas) en modo
JSONL y mapea cada coincidencia a un `Finding`. Defensivo: si el binario no está
disponible o falla, devuelve lista vacía sin abortar el resto del escaneo.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from urllib.parse import urlsplit

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("nuclei")

# Binario externo y límites por defecto.
NUCLEI_BIN = "nuclei"
DEFAULT_TIMEOUT = 600          # segundos para todo el escaneo (asíncrono)
MAX_FINDINGS = 2000            # tope defensivo de hallazgos por ejecución

# Severidades válidas de Nuclei → severidad de CyberHound (mismas cadenas salvo
# "unknown", que cae a "info").
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def map_severity(value: str | None) -> str:
    """Normaliza la severidad de Nuclei a la de CyberHound (default: info)."""
    return _SEVERITY_MAP.get((value or "").strip().lower(), "info")


def _host_of(value: str) -> str:
    """Devuelve el host (netloc) de una URL/host, sin esquema ni ruta."""
    if not value:
        return ""
    split = urlsplit(value if "://" in value else "//" + value)
    return split.netloc or split.path.split("/", 1)[0]


def finding_from_result(obj: dict) -> Finding | None:
    """Convierte un objeto JSON de salida de Nuclei en un `Finding`.

    Función pura (sin E/S): testeable sin el binario. Devuelve None si el objeto
    no tiene un identificador de plantilla utilizable.
    """
    template_id = (obj.get("template-id") or obj.get("templateID") or "").strip()
    if not template_id:
        return None

    info = obj.get("info") or {}
    name = (info.get("name") or template_id).strip()
    severity = map_severity(info.get("severity"))

    matched_at = (obj.get("matched-at") or obj.get("matched") or obj.get("host") or "").strip()
    host = _host_of(obj.get("host") or matched_at)

    # Clasificación (CVE/CWE) y referencias, si las hay.
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or classification.get("cve_id") or []
    if isinstance(cves, str):
        cves = [cves]
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    description = (info.get("description") or "").strip() or (
        f"La plantilla Nuclei «{template_id}» coincidió en el objetivo."
    )
    if cves:
        description += f" CVE: {', '.join(cves)}."
    if tags:
        description += f" Tags: {', '.join(tags[:8])}."

    remediation = (info.get("remediation") or "").strip() or (
        "Revisa la plantilla y su referencia, y aplica el parche o la "
        "reconfiguración recomendada por el fabricante."
    )
    if refs:
        remediation += f" Referencias: {', '.join(refs[:3])}."

    extracted = obj.get("extracted-results") or obj.get("extracted_results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    evidence_parts = [f"[{template_id}] {matched_at}"]
    if extracted:
        evidence_parts.append("extraído: " + ", ".join(str(e) for e in extracted[:5]))
    evidence = " · ".join(evidence_parts)[:1000]

    # ID estable y único: plantilla + dónde coincidió.
    digest = hashlib.sha1(f"{template_id}|{matched_at}".encode()).hexdigest()[:10]

    return Finding(
        id=f"nuclei_{template_id}_{digest}",
        category="nuclei",
        severity=severity,
        title=f"{name} en {host}" if host else name,
        description=description,
        remediation=remediation,
        evidence=evidence,
        source_host=host,
    )


def _normalize_targets(urls: list[str]) -> list[str]:
    """Limpia y deduplica los objetivos, conservando el orden."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        if "://" not in u:
            u = "https://" + u
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def scan_urls(
    urls: list[str],
    severities: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[Finding]:
    """Ejecuta Nuclei contra una lista de URLs y devuelve los `Finding`."""
    findings: list[Finding] = []
    targets = _normalize_targets(urls)
    if not targets:
        return findings

    binary = shutil.which(NUCLEI_BIN)
    if not binary:
        logger.warning("binario 'nuclei' no encontrado en PATH — scanner Nuclei deshabilitado")
        return findings

    cmd = [binary, "-jsonl", "-silent", "-disable-update-check", "-no-color"]
    if severities:
        valid = [s for s in severities if s in _SEVERITY_MAP]
        if valid:
            cmd += ["-severity", ",".join(valid)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as e:
        logger.warning("no se pudo lanzar nuclei: %s", e)
        return findings

    payload = ("\n".join(targets) + "\n").encode()
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(payload), timeout)
    except TimeoutError:
        logger.warning("nuclei excedió el timeout (%ss) — abortando", timeout)
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return findings

    if stderr:
        logger.debug("nuclei stderr: %s", stderr.decode(errors="replace")[:500])

    seen_ids: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith(b"{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        finding = finding_from_result(obj)
        if finding is None or finding.id in seen_ids:
            continue
        seen_ids.add(finding.id)
        findings.append(finding)
        if len(findings) >= MAX_FINDINGS:
            logger.warning("nuclei: alcanzado el tope de %d hallazgos", MAX_FINDINGS)
            break

    return findings


class NucleiScanner:
    """Orquesta Nuclei sobre varias URLs y normaliza la salida a `Finding`."""

    @classmethod
    async def full_scan(
        cls,
        urls: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> list[Finding]:
        urls = urls or []
        if not urls:
            return []
        return await scan_urls(urls, severities=severities)
