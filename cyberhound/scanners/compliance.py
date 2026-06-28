"""
Compliance automático para CyberHound Pro.

Mapea los hallazgos detectados a controles de los principales marcos normativos:
  - ENS (Esquema Nacional de Seguridad) — España, obligatorio para AAPP
  - ISO 27001:2022 — estándar internacional de SGSI
  - PCI-DSS v4.0 — sector de pagos
  - CIS Controls v8 — Centro de Seguridad de Internet

Cada finding de CyberHound tiene un ID y categoría que se mapea a los
controles correspondientes. El resultado es un informe de cumplimiento
que muestra qué controles están cubiertos, cuáles no, y el nivel de
cumplimiento global por marco.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cyberhound.core.models import Finding


# ── Mapeo finding_category → controles ───────────────────────────────────────

@dataclass
class Control:
    id:          str
    title:       str
    framework:   str     # ens | iso27001 | pci-dss | cis
    section:     str
    priority:    str = "medium"   # low | medium | high | critical


# Mapeo: categoría del finding → lista de controles que aborda
CATEGORY_TO_CONTROLS: dict[str, list[Control]] = {

    # ── SSH ──────────────────────────────────────────────────────────────────
    "ssh": [
        Control("ENS-MP.SI.1",   "Control de acceso remoto",         "ens",      "Marco Operacional — Protección de los Sistemas", "high"),
        Control("ISO-A.9.4.2",   "Procedimientos de inicio de sesión seguro", "iso27001", "A.9 Control de acceso", "high"),
        Control("PCI-8.6",       "Gestión de autenticación",         "pci-dss",  "Requerimiento 8", "high"),
        Control("CIS-4.1",       "Configuración segura de software",  "cis",      "Control 4", "high"),
    ],
    "ssh/cve": [
        Control("ENS-MP.SI.1",   "Control de acceso remoto",         "ens",      "Marco Operacional", "critical"),
        Control("ISO-A.12.6.1",  "Gestión de vulnerabilidades técnicas", "iso27001", "A.12 Seguridad en operaciones", "critical"),
        Control("PCI-6.3.3",     "Actualización de parches de seguridad", "pci-dss", "Requerimiento 6", "critical"),
        Control("CIS-7.1",       "Gestión continua de vulnerabilidades", "cis",    "Control 7", "critical"),
    ],

    # ── Firewall / Red ────────────────────────────────────────────────────────
    "firewall": [
        Control("ENS-MP.COM.1",  "Perimetría de seguridad",          "ens",      "Marco Operacional — Comunicaciones", "high"),
        Control("ISO-A.13.1.1",  "Controles de red",                 "iso27001", "A.13 Seguridad de red", "high"),
        Control("PCI-1.2",       "Configuración del firewall",        "pci-dss",  "Requerimiento 1", "high"),
        Control("CIS-12.1",      "Infraestructura de red segura",    "cis",       "Control 12", "high"),
    ],
    "network": [
        Control("ENS-MP.COM.1",  "Perimetría de seguridad",          "ens",      "Marco Operacional", "high"),
        Control("ISO-A.13.1.2",  "Seguridad de servicios de red",    "iso27001", "A.13", "medium"),
        Control("CIS-12.2",      "Monitoreo de la red",              "cis",      "Control 12", "medium"),
    ],

    # ── Autenticación ─────────────────────────────────────────────────────────
    "authentication": [
        Control("ENS-OP.ACC.2",  "Identificación y autenticación",   "ens",      "Marco Operacional — Control de acceso", "critical"),
        Control("ISO-A.9.2.1",   "Registro de usuarios",             "iso27001", "A.9 Control de acceso", "high"),
        Control("PCI-8.2",       "Identificación única de usuarios",  "pci-dss",  "Requerimiento 8", "critical"),
        Control("CIS-5.1",       "Gestión de cuentas",               "cis",      "Control 5", "high"),
    ],
    "passwords": [
        Control("ENS-OP.ACC.3",  "Control de contraseñas",           "ens",      "Marco Operacional", "high"),
        Control("ISO-A.9.4.3",   "Gestión de contraseñas",           "iso27001", "A.9", "high"),
        Control("PCI-8.3",       "Seguridad de contraseñas",         "pci-dss",  "Requerimiento 8", "high"),
        Control("CIS-5.2",       "Gestión de privilegios",           "cis",      "Control 5", "high"),
    ],

    # ── Kernel / Sistema ──────────────────────────────────────────────────────
    "kernel": [
        Control("ENS-MP.SI.2",   "Configuración segura del SO",      "ens",      "Marco Operacional", "high"),
        Control("ISO-A.14.2.2",  "Procedimientos de cambio en el SO", "iso27001", "A.14 Adquisición y desarrollo", "medium"),
        Control("CIS-4.1",       "Configuración segura de SO",       "cis",      "Control 4", "high"),
    ],
    "integrity": [
        Control("ENS-MP.SI.3",   "Verificación de integridad",       "ens",      "Marco Operacional", "high"),
        Control("ISO-A.12.2.1",  "Controles contra malware",         "iso27001", "A.12", "high"),
        Control("PCI-11.3",      "Detección de cambios no autorizados", "pci-dss", "Requerimiento 11", "high"),
        Control("CIS-10.1",      "Defensa contra malware",           "cis",      "Control 10", "high"),
    ],

    # ── Auditoría y logs ──────────────────────────────────────────────────────
    "audit": [
        Control("ENS-OP.EXP.8",  "Registro de actividad",            "ens",      "Marco Operacional — Explotación", "high"),
        Control("ISO-A.12.4.1",  "Registro y monitorización",        "iso27001", "A.12", "high"),
        Control("PCI-10.2",      "Registro de auditoría",            "pci-dss",  "Requerimiento 10", "high"),
        Control("CIS-8.1",       "Auditoría de logs",                "cis",      "Control 8", "high"),
    ],
    "logging": [
        Control("ENS-OP.EXP.8",  "Registro de actividad",            "ens",      "Marco Operacional", "medium"),
        Control("ISO-A.12.4.2",  "Protección de logs",               "iso27001", "A.12", "medium"),
        Control("PCI-10.3",      "Protección de logs de auditoría",  "pci-dss",  "Requerimiento 10", "medium"),
    ],

    # ── Filesystem / Permisos ────────────────────────────────────────────────
    "filesystem": [
        Control("ENS-MP.SI.2",   "Configuración del sistema de ficheros", "ens", "Marco Operacional", "medium"),
        Control("ISO-A.9.4.1",   "Restricción de acceso a información", "iso27001", "A.9", "medium"),
        Control("CIS-3.1",       "Protección de datos",              "cis",      "Control 3", "medium"),
    ],

    # ── Actualizaciones ───────────────────────────────────────────────────────
    "updates": [
        Control("ENS-MP.SI.2",   "Gestión de actualizaciones",       "ens",      "Marco Operacional", "high"),
        Control("ISO-A.12.6.1",  "Gestión de vulnerabilidades",      "iso27001", "A.12", "high"),
        Control("PCI-6.3.3",     "Actualizaciones de seguridad",     "pci-dss",  "Requerimiento 6", "high"),
        Control("CIS-7.4",       "Gestión de parches",               "cis",      "Control 7", "high"),
    ],

    # ── Docker / Kubernetes ──────────────────────────────────────────────────
    "docker/privilege": [
        Control("ENS-MP.SI.2",   "Seguridad de contenedores",        "ens",      "Marco Operacional", "high"),
        Control("ISO-A.12.6.2",  "Restricciones sobre instalación de software", "iso27001", "A.12", "high"),
        Control("CIS-16.6",      "Gestión de contenedores",          "cis",      "Control 16", "high"),
    ],
    "kubernetes/rbac": [
        Control("ENS-OP.ACC.4",  "Derechos de acceso",               "ens",      "Marco Operacional", "high"),
        Control("ISO-A.9.2.3",   "Gestión de derechos de acceso privilegiado", "iso27001", "A.9", "critical"),
        Control("CIS-5.4",       "Gestión de cuentas de servicio",   "cis",      "Control 5", "high"),
    ],

    # ── Cumplimiento ─────────────────────────────────────────────────────────
    "compliance": [
        Control("ENS-GEN",       "Cumplimiento general ENS",         "ens",      "Marco General", "medium"),
        Control("ISO-A.18.1",    "Cumplimiento con requisitos legales", "iso27001", "A.18 Cumplimiento", "medium"),
    ],

    # ── LDAP / AD ────────────────────────────────────────────────────────────
    "ldap/accounts": [
        Control("ENS-OP.ACC.2",  "Gestión de identidades",           "ens",      "Marco Operacional", "high"),
        Control("ISO-A.9.2.1",   "Registro y baja de usuarios",      "iso27001", "A.9", "high"),
        Control("CIS-5.1",       "Inventario de cuentas",            "cis",      "Control 5", "high"),
    ],
    "ldap/policy": [
        Control("ENS-OP.ACC.3",  "Política de contraseñas",          "ens",      "Marco Operacional", "high"),
        Control("ISO-A.9.4.3",   "Sistema de gestión de contraseñas", "iso27001", "A.9", "high"),
        Control("PCI-8.3.6",     "Longitud mínima de contraseña",    "pci-dss",  "Requerimiento 8", "high"),
    ],

    # ── Malware ──────────────────────────────────────────────────────────────
    "malware/yara": [
        Control("ENS-MP.SI.4",   "Protección antimalware",           "ens",      "Marco Operacional", "critical"),
        Control("ISO-A.12.2.1",  "Controles contra código malicioso", "iso27001", "A.12", "critical"),
        Control("PCI-5.2",       "Protección de sistemas contra malware", "pci-dss", "Requerimiento 5", "critical"),
        Control("CIS-10.2",      "Anti-malware",                     "cis",      "Control 10", "critical"),
    ],
    "malware/webshell": [
        Control("ENS-MP.SI.4",   "Protección de servicios web",      "ens",      "Marco Operacional", "critical"),
        Control("ISO-A.12.2.1",  "Controles contra código malicioso", "iso27001", "A.12", "critical"),
        Control("PCI-6.4",       "Seguridad de aplicaciones web",    "pci-dss",  "Requerimiento 6", "critical"),
    ],

    # ── Monitor en tiempo real ────────────────────────────────────────────────
    "monitor/exec": [
        Control("ENS-OP.EXP.9",  "Registro de actividad de usuarios", "ens",    "Marco Operacional", "critical"),
        Control("ISO-A.12.4.1",  "Registro de eventos",              "iso27001", "A.12", "critical"),
        Control("CIS-8.11",      "Conducta de alertas",              "cis",      "Control 8", "critical"),
    ],
    "monitor/integrity": [
        Control("ENS-MP.SI.3",   "Integridad del sistema",           "ens",      "Marco Operacional", "high"),
        Control("ISO-A.12.4.3",  "Logs de administración",           "iso27001", "A.12", "high"),
        Control("PCI-10.4",      "Sincronización de tiempo",         "pci-dss",  "Requerimiento 10", "high"),
    ],

    # ── Servicios ─────────────────────────────────────────────────────────────
    "services/nginx": [
        Control("ENS-MP.COM.2",  "Protección de servicios web",      "ens",      "Marco Operacional", "high"),
        Control("ISO-A.14.1.2",  "Seguridad de servicios de aplicación", "iso27001", "A.14", "high"),
        Control("PCI-6.2",       "Protección de aplicaciones orientadas al público", "pci-dss", "Requerimiento 6", "high"),
    ],
    "services/mysql": [
        Control("ENS-MP.SI.2",   "Seguridad de bases de datos",      "ens",      "Marco Operacional", "high"),
        Control("ISO-A.13.1.3",  "Separación de redes",              "iso27001", "A.13", "high"),
        Control("PCI-3.4",       "Protección de datos almacenados",  "pci-dss",  "Requerimiento 3", "critical"),
    ],
}


# ── Generador de informe de compliance ───────────────────────────────────────

@dataclass
class ComplianceResult:
    framework:     str
    total_controls: int
    covered:        int
    failed:         int
    not_applicable: int
    score_pct:      float
    failed_controls: list[dict] = field(default_factory=list)
    covered_controls: list[dict] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.score_pct >= 90:
            return "CONFORME"
        elif self.score_pct >= 70:
            return "PARCIALMENTE_CONFORME"
        else:
            return "NO_CONFORME"


def analyze_compliance(
    findings: list[Finding],
    frameworks: Optional[list[str]] = None,
) -> dict[str, ComplianceResult]:
    """
    Analiza el cumplimiento normativo a partir de los hallazgos.

    Args:
        findings: Lista de hallazgos de CyberHound
        frameworks: Marcos a analizar (None = todos)

    Returns:
        Dict framework → ComplianceResult
    """
    target_frameworks = set(frameworks or ["ens", "iso27001", "pci-dss", "cis"])

    # Recopilar todos los controles definidos
    all_controls: dict[str, Control] = {}
    for controls in CATEGORY_TO_CONTROLS.values():
        for ctrl in controls:
            if ctrl.framework in target_frameworks:
                all_controls[ctrl.id] = ctrl

    # Identificar qué controles están fallando (tienen un finding asociado)
    failed_control_ids: dict[str, list[str]] = {}  # ctrl_id → finding_titles
    for finding in findings:
        category = finding.category or ""
        # Buscar también por prefijo de categoría
        matched_controls = CATEGORY_TO_CONTROLS.get(category, [])
        if not matched_controls:
            for cat, controls in CATEGORY_TO_CONTROLS.items():
                if category.startswith(cat) or cat.startswith(category.split("/")[0]):
                    matched_controls = controls
                    break

        for ctrl in matched_controls:
            if ctrl.framework in target_frameworks:
                if ctrl.id not in failed_control_ids:
                    failed_control_ids[ctrl.id] = []
                failed_control_ids[ctrl.id].append(finding.title or finding.id)

    # Construir resultado por framework
    results: dict[str, ComplianceResult] = {}
    for fw in target_frameworks:
        fw_controls = {cid: ctrl for cid, ctrl in all_controls.items() if ctrl.framework == fw}
        total = len(fw_controls)
        if total == 0:
            continue

        failed_list = []
        covered_list = []

        for cid, ctrl in fw_controls.items():
            if cid in failed_control_ids:
                failed_list.append({
                    "id":       cid,
                    "title":    ctrl.title,
                    "section":  ctrl.section,
                    "priority": ctrl.priority,
                    "findings": failed_control_ids[cid][:3],  # max 3 findings por control
                })
            else:
                covered_list.append({
                    "id":      cid,
                    "title":   ctrl.title,
                    "section": ctrl.section,
                })

        failed_count   = len(failed_list)
        covered_count  = total - failed_count
        score_pct      = round((covered_count / total) * 100, 1) if total > 0 else 100.0

        results[fw] = ComplianceResult(
            framework=fw,
            total_controls=total,
            covered=covered_count,
            failed=failed_count,
            not_applicable=0,
            score_pct=score_pct,
            failed_controls=sorted(
                failed_list,
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["priority"], 4)
            ),
            covered_controls=covered_list,
        )

    return results


def compliance_to_dict(results: dict[str, ComplianceResult]) -> dict:
    """Serializa los resultados de compliance a dict para la API."""
    return {
        fw: {
            "framework":        res.framework,
            "status":           res.status,
            "score_pct":        res.score_pct,
            "total_controls":   res.total_controls,
            "covered":          res.covered,
            "failed":           res.failed,
            "failed_controls":  res.failed_controls,
            "covered_controls": res.covered_controls[:20],  # max 20 en la API
        }
        for fw, res in results.items()
    }


FRAMEWORK_NAMES = {
    "ens":      "ENS — Esquema Nacional de Seguridad",
    "iso27001": "ISO 27001:2022",
    "pci-dss":  "PCI-DSS v4.0",
    "cis":      "CIS Controls v8",
}
