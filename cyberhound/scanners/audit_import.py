"""
Importador de auditorías externas para CyberHound Pro.

Permite importar resultados de herramientas de auditoría de terceros
y normalizarlos al formato de Finding de CyberHound:

  1. Tenable Nessus (.nessus XML)
     - Exportación de Tenable.io, Tenable.sc o Nessus Professional
     - Incluye: CVE, CVSS, plugin ID, descripción, solución

  2. OpenSCAP (XCCDF/ARF XML)
     - Estándar NIST SP 800-126
     - Usado por: oscap, Satellite, Ansible Security, OpenSCAP-daemon
     - Perfiles: CIS, STIG, PCI-DSS para RHEL/Fedora/SLES
     - Libros blancos Red Hat: RHEL 7/8/9 STIG, CIS Level 1/2

  3. CSV genérico
     - Exportaciones de cualquier herramienta
     - Detección automática de columnas por nombre

  4. JSON genérico
     - Formato propio de CyberHound o de otras herramientas

La distinción cumplimiento/vulnerabilidades:
  - XCCDF/CIS/STIG → se importan como findings de CATEGORÍA "compliance/*"
  - Nessus/CVE → se importan como findings de CATEGORÍA "vulnerability/*"
  - Esta distinción permite filtrar por tipo en la UI y reportes

Referencia de libros blancos Red Hat:
  https://access.redhat.com/articles/rhel-limits
  RHEL 9 STIG: https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("audit_import")

# ── Mapeo de severidad ────────────────────────────────────────────────────────

NESSUS_SEV_MAP = {
    "4": "critical",   # Critical
    "3": "high",       # High
    "2": "medium",     # Medium
    "1": "low",        # Low
    "0": "info",       # Informational
}

XCCDF_RESULT_MAP = {
    "fail":          "high",    # Check failed
    "error":         "medium",  # Check error
    "unknown":       "medium",  # Unknown
    "notchecked":    "info",
    "notselected":   "info",
    "informational": "info",
    "pass":          None,      # No finding
    "notapplicable": None,
}

CVSS_TO_SEV = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def cvss_to_severity(score: float) -> str:
    for threshold, sev in CVSS_TO_SEV:
        if score >= threshold:
            return sev
    return "info"


# ── Tipos de fichero ──────────────────────────────────────────────────────────

@dataclass
class ImportResult:
    findings:    list[Finding]
    source:      str      # "nessus", "xccdf", "csv", "json"
    source_file: str
    total:       int
    imported:    int
    skipped:     int      # passes, N/A
    errors:      list[str] = field(default_factory=list)
    metadata:    dict = field(default_factory=dict)


def detect_format(content: str | bytes, filename: str = "") -> str:
    """Detecta el formato del fichero de auditoría."""
    if isinstance(content, bytes):
        try:
            text = content[:2048].decode("utf-8", errors="ignore")
        except Exception:
            text = ""
    else:
        text = content[:2048]

    filename_lower = filename.lower()

    # Por extensión
    if filename_lower.endswith(".nessus"):
        return "nessus"
    if filename_lower.endswith(".xml"):
        if "<NessusClientData_v2" in text or "nessus" in text.lower()[:200]:
            return "nessus"
        if "xccdf" in text.lower() or "arf" in text.lower() or "<TestResult" in text:
            return "xccdf"
        return "xml_unknown"
    if filename_lower.endswith(".csv"):
        return "csv"
    if filename_lower.endswith(".json"):
        return "json"

    # Por contenido
    if "<NessusClientData_v2" in text:
        return "nessus"
    if "xccdf" in text.lower() and ("<Benchmark" in text or "<TestResult" in text):
        return "xccdf"
    if text.strip().startswith("[") or text.strip().startswith("{"):
        return "json"
    if "," in text and "\n" in text:
        return "csv"

    return "unknown"


# ── Parser Nessus ─────────────────────────────────────────────────────────────

def parse_nessus(content: str | bytes, source_file: str = "scan.nessus") -> ImportResult:
    """
    Parsea un fichero .nessus (XML de Tenable Nessus / Tenable.io).

    Estructura del .nessus:
      NessusClientData_v2
        Report
          ReportHost (name=IP)
            ReportItem (port, svc_name, protocol, severity, pluginID, pluginName)
              description, solution, cvss_base_score, cve, synopsis
    """
    findings: list[Finding] = []
    errors: list[str] = []
    skipped = 0
    metadata: dict = {}

    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        root = ET.fromstring(content)

        # Buscar Report o Policy para metadata
        report = root.find(".//Report")
        if report is not None:
            metadata["report_name"] = report.get("name", "")

        for host in root.findall(".//ReportHost"):
            host_ip = host.get("name", "unknown")

            for item in host.findall("ReportItem"):
                sev_int = item.get("severity", "0")
                severity = NESSUS_SEV_MAP.get(sev_int, "info")

                if severity == "info" and sev_int == "0":
                    skipped += 1
                    continue  # Saltar informational por defecto

                plugin_id   = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "")
                port        = item.get("port", "0")
                protocol    = item.get("protocol", "tcp")
                svc_name    = item.get("svc_name", "")

                description  = _get_text(item, "description")
                solution     = _get_text(item, "solution")
                synopsis     = _get_text(item, "synopsis")
                cvss_score   = _get_text(item, "cvss_base_score")
                cvss3_score  = _get_text(item, "cvss3_base_score")
                cves         = [c.text for c in item.findall("cve") if c.text]
                _get_text(item, "risk_factor")

                # Recalcular severidad con CVSS si está disponible
                for cvss_str in [cvss3_score, cvss_score]:
                    try:
                        cvss_f = float(cvss_str)
                        severity = cvss_to_severity(cvss_f)
                        break
                    except (ValueError, TypeError):
                        pass

                # Determinar categoría
                category = _nessus_category(plugin_name, svc_name, cves)

                fid = f"nessus_{plugin_id}_{host_ip}_{port}"
                title = plugin_name or f"Plugin {plugin_id}"

                # Evidencia estructurada
                evidence_parts = [f"host={host_ip}", f"port={port}/{protocol}"]
                if cves:
                    evidence_parts.append(f"cve={','.join(cves[:3])}")
                if cvss3_score:
                    evidence_parts.append(f"cvss3={cvss3_score}")
                elif cvss_score:
                    evidence_parts.append(f"cvss={cvss_score}")

                findings.append(Finding(
                    id=fid,
                    category=category,
                    severity=severity,
                    title=title,
                    description=synopsis or description[:500],
                    remediation=solution[:500] if solution else "",
                    evidence=" ".join(evidence_parts),
                    source_host=host_ip,
                    auto_fix=False,
                ))

    except ET.ParseError as e:
        errors.append(f"XML inválido: {e}")
    except Exception as e:
        errors.append(f"Error parseando Nessus: {e}")
        logger.error("parse_nessus: %s", e, exc_info=True)

    logger.info("Nessus import: %d findings, %d skipped, %d errors",
                len(findings), skipped, len(errors))

    return ImportResult(
        findings=findings, source="nessus", source_file=source_file,
        total=len(findings) + skipped, imported=len(findings),
        skipped=skipped, errors=errors, metadata=metadata,
    )


def _nessus_category(plugin_name: str, svc_name: str, cves: list[str]) -> str:
    """Determina la categoría de un hallazgo Nessus."""
    name_lower = plugin_name.lower()
    if cves:
        return "vulnerability/cve"
    if "ssl" in name_lower or "tls" in name_lower:
        return "vulnerability/tls"
    if "ssh" in name_lower:
        return "vulnerability/ssh"
    if "smb" in name_lower or "windows" in name_lower:
        return "vulnerability/windows"
    if "web" in name_lower or "http" in name_lower:
        return "vulnerability/web"
    if "patch" in name_lower or "update" in name_lower or "outdated" in name_lower:
        return "vulnerability/patch"
    if "password" in name_lower or "auth" in name_lower:
        return "vulnerability/auth"
    if svc_name:
        return f"vulnerability/{svc_name.lower().split('?')[0][:20]}"
    return "vulnerability/other"


# ── Parser XCCDF / OpenSCAP ───────────────────────────────────────────────────

# Namespaces comunes de XCCDF
XCCDF_NS = {
    "xccdf11":  "http://checklists.nist.gov/xccdf/1.1",
    "xccdf12":  "http://checklists.nist.gov/xccdf/1.2",
    "arf":      "http://scap.nist.gov/schema/asset-reporting-format/1.1",
    "oval":     "http://oval.mitre.org/XMLSchema/oval-results-5",
}


def parse_xccdf(content: str | bytes, source_file: str = "results.xml") -> ImportResult:
    """
    Parsea resultados XCCDF (OpenSCAP, RHEL STIG, CIS Benchmarks).

    Soporta:
    - XCCDF 1.1 y 1.2
    - Formato ARF (Asset Reporting Format)
    - Resultados de oscap, Satellite, Ansible Security

    Libros blancos Red Hat compatibles:
    - ssg-rhel7-ds.xml, ssg-rhel8-ds.xml, ssg-rhel9-ds.xml
    - Perfiles: CIS Level 1, CIS Level 2, STIG, PCI-DSS
    """
    findings: list[Finding] = []
    errors: list[str] = []
    skipped = 0
    metadata: dict = {}

    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        root = ET.fromstring(content)

        # Detectar namespace
        ns_prefix = ""
        tag = root.tag
        if "{" in tag:
            ns_uri = tag[1:tag.index("}")]
            for _prefix, uri in XCCDF_NS.items():
                if uri == ns_uri:
                    ns_prefix = f"{{{uri}}}"
                    break
            if not ns_prefix:
                ns_prefix = f"{{{ns_uri}}}"

        def find_all(element, path):
            # Intentar con y sin namespace
            results = element.findall(f".//{ns_prefix}{path}")
            if not results:
                results = element.findall(f".//{path}")
            return results

        def find_one(element, path):
            r = find_all(element, path)
            return r[0] if r else None

        # Extraer metadata del benchmark
        # El Benchmark puede ser el root o estar anidado
        if "Benchmark" in root.tag:
            benchmark = root
        else:
            benchmark = find_one(root, "Benchmark")

        if benchmark is not None:
            title_el = find_one(benchmark, "title")
            if title_el is None:
                # Buscar directo con namespace
                title_el = benchmark.find(f"{ns_prefix}title") or benchmark.find("title")
            if title_el is not None:
                metadata["benchmark"] = title_el.text or ""
            version_el = find_one(benchmark, "version")
            if version_el is not None:
                metadata["version"] = version_el.text or ""

        # Buscar TestResult(s)
        test_results = find_all(root, "TestResult")
        if not test_results:
            # Puede estar directamente en root
            test_results = [root] if "TestResult" in root.tag else []

        for test_result in test_results:
            # Metadata del TestResult
            score_el = find_one(test_result, "score")
            if score_el is not None:
                try:
                    metadata["score"] = float(score_el.text or "0")
                except ValueError:
                    pass

            target_el = find_one(test_result, "target")
            host = target_el.text if target_el is not None else "unknown"

            # Procesar cada rule-result
            for rule_result in find_all(test_result, "rule-result"):
                result_el = find_one(rule_result, "result")
                if result_el is None:
                    continue

                result_text = (result_el.text or "").strip().lower()
                severity = XCCDF_RESULT_MAP.get(result_text)

                if severity is None:
                    skipped += 1
                    continue  # pass, notapplicable → no finding

                rule_id = rule_result.get("idref", "")
                rule_severity = rule_result.get("severity", "")

                # Mapear severidad XCCDF (high/medium/low)
                if rule_severity in ("high", "medium", "low", "critical"):
                    severity = rule_severity if rule_severity != "high" else "high"

                # Buscar la definición de la regla en el Benchmark
                title = rule_id
                description = ""
                remediation = ""
                refs: list[str] = []

                if benchmark is not None:
                    rule_def = None
                    # Si benchmark es el root, buscar directamente
                    for r in (benchmark.findall(f"{ns_prefix}Rule") or
                               benchmark.findall("Rule") or
                               find_all(benchmark, "Rule")):
                        if r.get("id") == rule_id:
                            rule_def = r
                            break

                    if rule_def is not None:
                        title_el = find_one(rule_def, "title")
                        if title_el is not None:
                            title = title_el.text or rule_id

                        desc_el = find_one(rule_def, "description")
                        if desc_el is not None:
                            description = ET.tostring(desc_el, encoding="unicode", method="text")[:500]

                        fix_el = find_one(rule_def, "fix")
                        if fix_el is not None:
                            remediation = ET.tostring(fix_el, encoding="unicode", method="text")[:500]
                        elif find_one(rule_def, "fixtext"):
                            remediation = ET.tostring(
                                find_one(rule_def, "fixtext"), encoding="unicode", method="text"
                            )[:500]

                        for ref in find_all(rule_def, "reference"):
                            if ref.text:
                                refs.append(ref.text.strip())

                # Determinar categoría basada en el ID de la regla
                category = _xccdf_category(rule_id, title)

                findings.append(Finding(
                    id=f"xccdf_{rule_id.replace('/', '_')[:60]}_{host}",
                    category=category,
                    severity=severity,
                    title=title[:200],
                    description=description.strip(),
                    remediation=remediation.strip(),
                    evidence=f"rule={rule_id} result={result_text} host={host} refs={','.join(refs[:2])}",
                    source_host=host,
                    auto_fix=False,
                ))

    except ET.ParseError as e:
        errors.append(f"XML inválido: {e}")
    except Exception as e:
        errors.append(f"Error parseando XCCDF: {e}")
        logger.error("parse_xccdf: %s", e, exc_info=True)

    logger.info("XCCDF import: %d findings, %d skipped, %d errors",
                len(findings), skipped, len(errors))

    return ImportResult(
        findings=findings, source="xccdf", source_file=source_file,
        total=len(findings) + skipped, imported=len(findings),
        skipped=skipped, errors=errors, metadata=metadata,
    )


def _xccdf_category(rule_id: str, title: str) -> str:
    """Determina la categoría de un check XCCDF."""
    text = (rule_id + " " + title).lower()

    # Mapeo por palabras clave
    if any(k in text for k in ("ssh", "sshd")):
        return "compliance/ssh"
    if any(k in text for k in ("password", "passwd", "pam")):
        return "compliance/authentication"
    if any(k in text for k in ("audit", "auditd", "log")):
        return "compliance/logging"
    if any(k in text for k in ("firewall", "iptables", "nftables", "firewalld")):
        return "compliance/firewall"
    if any(k in text for k in ("kernel", "sysctl")):
        return "compliance/kernel"
    if any(k in text for k in ("selinux", "apparmor")):
        return "compliance/mandatory_access"
    if any(k in text for k in ("mount", "partition", "filesystem", "tmp")):
        return "compliance/filesystem"
    if any(k in text for k in ("cron", "at", "schedule")):
        return "compliance/cron"
    if any(k in text for k in ("sudo", "privilege", "root")):
        return "compliance/privilege"
    if any(k in text for k in ("banner", "motd", "issue")):
        return "compliance/banner"
    if any(k in text for k in ("update", "patch", "yum", "dnf")):
        return "compliance/updates"
    if any(k in text for k in ("usb", "storage", "removable")):
        return "compliance/physical"
    if "cis" in text:
        return "compliance/cis"
    if "stig" in text or "disa" in text:
        return "compliance/stig"
    return "compliance/system"


# ── Parser CSV genérico ───────────────────────────────────────────────────────

# Columnas que se buscan por nombre (insensible a mayúsculas)
CSV_COLUMN_ALIASES = {
    "title":       ["title", "name", "vulnerability", "finding", "check", "plugin_name", "rule"],
    "severity":    ["severity", "risk", "priority", "cvss_risk", "risk_factor", "criticality"],
    "description": ["description", "synopsis", "detail", "details", "info", "summary"],
    "remediation": ["remediation", "solution", "fix", "recommendation", "resolution"],
    "host":        ["host", "ip", "ip_address", "hostname", "target", "affected_host"],
    "category":    ["category", "type", "family", "plugin_family", "service", "class"],
    "cvss":        ["cvss", "cvss_score", "cvss3", "cvss3_score", "cvss_base_score"],
    "cve":         ["cve", "cves", "cve_id"],
    "evidence":    ["evidence", "output", "plugin_output", "details"],
}


def parse_csv(content: str | bytes, source_file: str = "scan.csv") -> ImportResult:
    """
    Parsea un CSV de auditoría con detección automática de columnas.

    Compatible con exportaciones de:
    - Tenable Nessus (CSV export)
    - Qualys (CSV export)
    - OpenVAS (CSV export)
    - Cualquier herramienta con columnas nombradas
    """
    findings: list[Finding] = []
    errors: list[str] = []
    skipped = 0

    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig", errors="replace")  # BOM

        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            return ImportResult(
                findings=[], source="csv", source_file=source_file,
                total=0, imported=0, skipped=0,
                errors=["CSV sin cabecera"],
            )

        # Mapear columnas
        col_map: dict[str, str] = {}
        normalized_fields = {f.lower().strip(): f for f in reader.fieldnames}

        for semantic_col, aliases in CSV_COLUMN_ALIASES.items():
            for alias in aliases:
                if alias in normalized_fields:
                    col_map[semantic_col] = normalized_fields[alias]
                    break

        if "title" not in col_map:
            errors.append("CSV sin columna de título/nombre reconocible")

        sev_normalizer = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "informational": "info",
            "4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info",
            "none": "info", "minimal": "low",
        }

        def get(row, col):
            key = col_map.get(col)
            return row.get(key, "").strip() if key else ""

        for i, row in enumerate(reader):

            title = get(row, "title")
            if not title:
                skipped += 1
                continue

            severity_raw = get(row, "severity").lower()
            severity = sev_normalizer.get(severity_raw, "medium")

            # Intentar CVSS si severity no reconocido
            if severity == "medium" and not severity_raw:
                cvss_str = get(row, "cvss")
                try:
                    severity = cvss_to_severity(float(cvss_str))
                except (ValueError, TypeError):
                    pass

            host     = get(row, "host")
            category = get(row, "category") or "vulnerability/imported"
            if category and "/" not in category:
                category = f"vulnerability/{category.lower()[:30]}"

            evidence_parts = []
            if host:
                evidence_parts.append(f"host={host}")
            cve = get(row, "cve")
            if cve:
                evidence_parts.append(f"cve={cve[:50]}")
            cvss = get(row, "cvss")
            if cvss:
                evidence_parts.append(f"cvss={cvss}")
            ev_out = get(row, "evidence")
            if ev_out:
                evidence_parts.append(ev_out[:100])

            findings.append(Finding(
                id=f"csv_{i}_{re.sub(r'[^a-z0-9]', '_', title.lower())[:40]}",
                category=category,
                severity=severity,
                title=title[:200],
                description=get(row, "description")[:500],
                remediation=get(row, "remediation")[:500],
                evidence=" ".join(evidence_parts),
                source_host=host,
                auto_fix=False,
            ))

    except Exception as e:
        errors.append(f"Error parseando CSV: {e}")
        logger.error("parse_csv: %s", e, exc_info=True)

    return ImportResult(
        findings=findings, source="csv", source_file=source_file,
        total=len(findings) + skipped, imported=len(findings),
        skipped=skipped, errors=errors,
    )


# ── Dispatcher principal ──────────────────────────────────────────────────────

def import_audit_file(
    content: str | bytes,
    filename: str = "",
    fmt: str | None = None,
) -> ImportResult:
    """
    Importa un fichero de auditoría de cualquier formato soportado.

    Args:
        content: Contenido del fichero (bytes o str)
        filename: Nombre del fichero (para detectar el formato)
        fmt: Formato explícito ("nessus", "xccdf", "csv", "json")

    Returns:
        ImportResult con los findings normalizados
    """
    if not fmt:
        fmt = detect_format(content, filename)

    logger.info("Importando auditoría: fmt=%s file=%s bytes=%d",
                fmt, filename, len(content) if content else 0)

    if fmt == "nessus":
        return parse_nessus(content, filename)
    elif fmt == "xccdf":
        return parse_xccdf(content, filename)
    elif fmt == "csv":
        return parse_csv(content, filename)
    elif fmt == "json":
        return _parse_json(content, filename)
    else:
        return ImportResult(
            findings=[], source=fmt, source_file=filename,
            total=0, imported=0, skipped=0,
            errors=[f"Formato no soportado: '{fmt}'. "
                    "Formatos válidos: nessus, xccdf, csv, json"],
        )


def _parse_json(content: str | bytes, source_file: str) -> ImportResult:
    """Parsea JSON — formato propio de CyberHound o exportación simple."""
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        data = json.loads(content)

        # Aceptar lista de findings o dict con campo "findings"
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("findings", data.get("results", data.get("vulnerabilities", [])))
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            f = Finding(
                id=item.get("id", f"json_{len(findings)}"),
                category=item.get("category", "vulnerability/imported"),
                severity=item.get("severity", "medium"),
                title=item.get("title", item.get("name", ""))[:200],
                description=item.get("description", "")[:500],
                remediation=item.get("remediation", item.get("solution", ""))[:500],
                evidence=item.get("evidence", ""),
                source_host=item.get("source_host", item.get("host", "")),
                auto_fix=bool(item.get("auto_fix", False)),
            )
            if f.title:
                findings.append(f)

    except json.JSONDecodeError as e:
        errors.append(f"JSON inválido: {e}")
    except Exception as e:
        errors.append(f"Error: {e}")

    return ImportResult(
        findings=findings, source="json", source_file=source_file,
        total=len(findings), imported=len(findings),
        skipped=0, errors=errors,
    )


# ── Helper XML ────────────────────────────────────────────────────────────────

def _get_text(element, tag: str, default: str = "") -> str:
    child = element.find(tag)
    return (child.text or default).strip() if child is not None else default
