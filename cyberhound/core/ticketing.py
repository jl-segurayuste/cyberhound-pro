"""
Integración de ticketing para CyberHound Pro.

Crea tickets automáticamente en sistemas externos cuando aparecen hallazgos
CRÍTICOS NUEVOS (no en cada scan — solo cuando el hallazgo no estaba en el
scan anterior; ver scheduler._audit, que ya calcula esa comparación para la
notificación "nuevos hallazgos críticos"). Evita spamear un ticket por día
mientras el hallazgo siga sin remediar.

Sistemas soportados:
  - Jira Cloud (REST API v2, auth Basic email+API token)
  - ServiceNow (Table API, auth Basic usuario+contraseña)

Todos los envíos son async, no bloquean el scan en curso. Los fallos se
loguean pero nunca interrumpen la auditoría (mismo patrón que siem.py).
"""
from __future__ import annotations

from dataclasses import dataclass

import aiohttp

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("ticketing")


@dataclass
class TicketingConfig:
    # Jira Cloud
    jira_enabled:     bool = False
    jira_url:         str  = ""   # p.ej. https://tuempresa.atlassian.net
    jira_email:       str  = ""
    jira_api_token:   str  = ""
    jira_project_key: str  = ""
    jira_issue_type:  str  = "Bug"

    # ServiceNow
    servicenow_enabled:      bool = False
    servicenow_instance_url: str  = ""   # p.ej. https://tuempresa.service-now.com
    servicenow_user:         str  = ""
    servicenow_password:     str  = ""
    servicenow_table:        str  = "incident"

    # Filtro mínimo (no abrir tickets para hallazgos de baja prioridad)
    min_severity: str = "critical"   # critical | high | medium | low

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def should_create(self, severity: str) -> bool:
        return self._SEV_ORDER.get(severity, 5) <= self._SEV_ORDER.get(self.min_severity, 0)


@dataclass
class TicketResult:
    system:      str   # "jira" | "servicenow"
    external_id: str   # p.ej. "SEC-123" o "INC0012345"
    url:         str


def _finding_body(f: Finding) -> str:
    parts = [f.description]
    if f.remediation:
        parts.append(f"\nRemediación sugerida:\n{f.remediation}")
    if f.evidence:
        parts.append(f"\nEvidencia:\n{f.evidence}")
    if f.source_host:
        parts.append(f"\nHost: {f.source_host}")
    parts.append(f"\nGenerado automáticamente por CyberHound Pro — hallazgo {f.id} ({f.category}).")
    return "\n".join(parts)


class TicketingIntegration:
    def __init__(self, cfg: TicketingConfig) -> None:
        self.cfg = cfg

    async def create_ticket(self, f: Finding, scan_type: str = "audit") -> list[TicketResult]:
        """Crea el ticket en todos los sistemas configurados para este hallazgo.
        Best-effort: un sistema que falla no impide crear el ticket en el otro."""
        if not self.cfg.should_create(f.severity):
            return []

        import asyncio
        tasks = []
        systems = []
        if self.cfg.jira_enabled:
            tasks.append(self._create_jira(f))
            systems.append("jira")
        if self.cfg.servicenow_enabled:
            tasks.append(self._create_servicenow(f))
            systems.append("servicenow")
        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[TicketResult] = []
        for system, result in zip(systems, results, strict=False):
            if isinstance(result, Exception):
                logger.warning("Ticketing %s: error creando ticket para %s: %s", system, f.id, result)
            else:
                out.append(result)
                logger.info("Ticket %s creado para hallazgo %s: %s", system, f.id, result.external_id)
        return out

    # ── Jira ──────────────────────────────────────────────────────────────────

    async def _create_jira(self, f: Finding) -> TicketResult:
        url = f"{self.cfg.jira_url.rstrip('/')}/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": self.cfg.jira_project_key},
                "summary": f"[CyberHound] {f.title}"[:255],
                "description": _finding_body(f),
                "issuetype": {"name": self.cfg.jira_issue_type},
                "labels": ["cyberhound", f.severity, f.category],
            }
        }
        auth = aiohttp.BasicAuth(self.cfg.jira_email, self.cfg.jira_api_token)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.post(url, json=payload, auth=auth) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    raise RuntimeError(f"Jira respondió {resp.status}: {body[:200]}")
                data = await resp.json()
                key = data.get("key", "")
                return TicketResult(system="jira", external_id=key, url=f"{self.cfg.jira_url.rstrip('/')}/browse/{key}")

    # ── ServiceNow ────────────────────────────────────────────────────────────

    async def _create_servicenow(self, f: Finding) -> TicketResult:
        table = self.cfg.servicenow_table
        url = f"{self.cfg.servicenow_instance_url.rstrip('/')}/api/now/table/{table}"
        urgency = {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get(f.severity, "3")
        impact = {"critical": "1", "high": "2", "medium": "2", "low": "3"}.get(f.severity, "3")
        payload = {
            "short_description": f"[CyberHound] {f.title}"[:160],
            "description": _finding_body(f),
            "urgency": urgency,
            "impact": impact,
            "category": "security",
        }
        auth = aiohttp.BasicAuth(self.cfg.servicenow_user, self.cfg.servicenow_password)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.post(url, json=payload, auth=auth, headers=headers) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    raise RuntimeError(f"ServiceNow respondió {resp.status}: {body[:200]}")
                data = await resp.json()
                result = data.get("result", {})
                sys_id = result.get("sys_id", "")
                number = result.get("number", sys_id)
                nav_url = f"{self.cfg.servicenow_instance_url.rstrip('/')}/nav_to.do?uri={table}.do?sys_id={sys_id}"
                return TicketResult(system="servicenow", external_id=number, url=nav_url)

    async def test(self) -> dict[str, bool]:
        """Prueba conectividad creando un ticket de prueba real (visible para el usuario
        que valida la integración — igual que hace `notifications.test()` con un email real)."""
        results = {}
        test_finding = Finding(
            id="ticketing_test", category="config", severity="critical",
            title="Test de conectividad de CyberHound Pro",
            description="Ticket de prueba generado al validar la integración de ticketing. Puedes cerrarlo.",
            remediation="Ninguna acción requerida — es solo una prueba.",
        )
        if self.cfg.jira_enabled:
            try:
                await self._create_jira(test_finding)
                results["jira"] = True
            except Exception as e:
                logger.warning("Test ticketing jira falló: %s", e)
                results["jira"] = False
        if self.cfg.servicenow_enabled:
            try:
                await self._create_servicenow(test_finding)
                results["servicenow"] = True
            except Exception as e:
                logger.warning("Test ticketing servicenow falló: %s", e)
                results["servicenow"] = False
        return results
