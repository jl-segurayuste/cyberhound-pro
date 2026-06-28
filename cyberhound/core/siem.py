"""
Integración SIEM para CyberHound Pro.

Envía hallazgos en tiempo real a sistemas SIEM externos:
  - Wazuh (agente activo o API REST)
  - Elasticsearch / ELK Stack
  - Splunk HEC (HTTP Event Collector)

Todos los envíos son async, no bloquean el scan en curso.
Los fallos se loguean pero nunca interrumpen la auditoría.
"""
from __future__ import annotations

import json
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("siem")


@dataclass
class SIEMConfig:
    # Wazuh
    wazuh_enabled:  bool = False
    wazuh_host:     str  = "localhost"
    wazuh_port:     int  = 1514          # puerto del agente activo
    wazuh_api_url:  str  = ""           # alternativa: API REST de Wazuh
    wazuh_api_user: str  = ""
    wazuh_api_pass: str  = ""

    # Elasticsearch
    elk_enabled: bool = False
    elk_url:     str  = "http://localhost:9200"
    elk_index:   str  = "cyberhound-findings"
    elk_user:    str  = ""
    elk_pass:    str  = ""
    elk_api_key: str  = ""             # alternativa a user/pass

    # Splunk HEC
    splunk_enabled:   bool = False
    splunk_hec_url:   str  = "https://localhost:8088/services/collector"
    splunk_hec_token: str  = ""
    splunk_index:     str  = "cyberhound"
    splunk_source:    str  = "cyberhound_pro"

    # Filtro mínimo (no enviar findings de baja prioridad)
    min_severity: str = "medium"   # critical | high | medium | low

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def should_send(self, severity: str) -> bool:
        return self._SEV_ORDER.get(severity, 5) <= self._SEV_ORDER.get(self.min_severity, 2)


def _finding_to_event(f: Finding, scan_type: str = "audit", hostname: str = "") -> dict:
    """Convierte un Finding al formato de evento SIEM estándar."""
    return {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "hostname":    hostname or socket.gethostname(),
        "source":      "cyberhound_pro",
        "scan_type":   scan_type,
        "finding_id":  f.id,
        "category":    f.category,
        "severity":    f.severity,
        "title":       f.title,
        "description": f.description,
        "remediation": f.remediation,
        "evidence":    f.evidence or "",
        "auto_fix":    f.auto_fix,
        "file_path":   f.file_path or "",
        "source_host": f.source_host or "",
        # Campos para correlación SIEM
        "rule.name":   f"cyberhound_{f.id}",
        "rule.level":  {"critical": 15, "high": 12, "medium": 8, "low": 4}.get(f.severity, 0),
        "rule.group":  ["cyberhound", f.category, f.severity],
    }


class SIEMIntegration:
    def __init__(self, cfg: SIEMConfig) -> None:
        self.cfg = cfg
        self._hostname = socket.gethostname()

    async def send_finding(self, f: Finding, scan_type: str = "audit") -> None:
        """Envía un finding a todos los SIEMs configurados."""
        if not self.cfg.should_send(f.severity):
            return

        event = _finding_to_event(f, scan_type, self._hostname)
        tasks = []

        if self.cfg.wazuh_enabled:
            tasks.append(self._send_wazuh(event))
        if self.cfg.elk_enabled:
            tasks.append(self._send_elk(event))
        if self.cfg.splunk_enabled:
            tasks.append(self._send_splunk(event))

        if not tasks:
            return

        import asyncio
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for name, result in zip(["wazuh", "elk", "splunk"], results):
            if isinstance(result, Exception):
                logger.warning("SIEM %s: error enviando finding %s: %s", name, f.id, result)

    async def send_scan_summary(
        self, findings: list[Finding], scan_type: str, score: int
    ) -> None:
        """Envía un resumen del scan completo al SIEM."""
        from cyberhound.core.models import Finding
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1

        summary_event = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "hostname":    self._hostname,
            "source":      "cyberhound_pro",
            "event_type":  "scan_summary",
            "scan_type":   scan_type,
            "score":       score,
            "total":       len(findings),
            **{f"count_{k}": v for k, v in counts.items()},
            "rule.name":   "cyberhound_scan_summary",
            "rule.level":  15 if counts["critical"] > 0 else 8 if counts["high"] > 0 else 3,
            "rule.group":  ["cyberhound", "summary", scan_type],
        }

        import asyncio
        tasks = []
        if self.cfg.wazuh_enabled:
            tasks.append(self._send_wazuh(summary_event))
        if self.cfg.elk_enabled:
            tasks.append(self._send_elk(summary_event))
        if self.cfg.splunk_enabled:
            tasks.append(self._send_splunk(summary_event))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Wazuh ──────────────────────────────────────────────────────────────────

    async def _send_wazuh(self, event: dict) -> None:
        """
        Envía al agente activo de Wazuh via socket UDP/TCP.
        Formato: longitud(4 bytes) + JSON
        Compatible con Wazuh active response y custom decoders.
        """
        import asyncio
        payload = json.dumps(event).encode("utf-8")
        # Prefijo de longitud (protocolo Wazuh)
        msg = struct.pack(">I", len(payload)) + payload

        loop = asyncio.get_event_loop()
        try:
            if self.cfg.wazuh_api_url:
                await self._send_wazuh_api(event)
            else:
                # UDP socket (no bloqueante)
                await loop.run_in_executor(
                    None, self._send_wazuh_udp, msg
                )
        except Exception as e:
            raise RuntimeError(f"Wazuh send error: {e}") from e

    def _send_wazuh_udp(self, msg: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(msg, (self.cfg.wazuh_host, self.cfg.wazuh_port))
        finally:
            sock.close()

    async def _send_wazuh_api(self, event: dict) -> None:
        """Envía via API REST de Wazuh Manager."""
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Obtener token JWT de Wazuh
            auth = aiohttp.BasicAuth(self.cfg.wazuh_api_user, self.cfg.wazuh_api_pass)
            async with session.post(
                f"{self.cfg.wazuh_api_url}/security/user/authenticate",
                auth=auth,
            ) as resp:
                data = await resp.json()
                token = data.get("data", {}).get("token", "")

            if not token:
                raise RuntimeError("No se pudo obtener token de Wazuh API")

            # Enviar evento al manager
            async with session.post(
                f"{self.cfg.wazuh_api_url}/manager/alerts",
                headers={"Authorization": f"Bearer {token}"},
                json=event,
            ) as resp:
                if resp.status not in (200, 201):
                    raise RuntimeError(f"Wazuh API respondió {resp.status}")

    # ── Elasticsearch ─────────────────────────────────────────────────────────

    async def _send_elk(self, event: dict) -> None:
        """Indexa el evento en Elasticsearch."""
        index = self.cfg.elk_index
        url = f"{self.cfg.elk_url}/{index}/_doc"

        headers = {"Content-Type": "application/json"}
        if self.cfg.elk_api_key:
            headers["Authorization"] = f"ApiKey {self.cfg.elk_api_key}"
        elif self.cfg.elk_user:
            import base64
            creds = base64.b64encode(
                f"{self.cfg.elk_user}:{self.cfg.elk_pass}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.post(url, json=event, headers=headers) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    raise RuntimeError(f"ELK respondió {resp.status}: {body[:100]}")

    # ── Splunk HEC ────────────────────────────────────────────────────────────

    async def _send_splunk(self, event: dict) -> None:
        """Envía al Splunk HTTP Event Collector."""
        payload = {
            "time":       time.time(),
            "host":       self._hostname,
            "source":     self.cfg.splunk_source,
            "sourcetype": "_json",
            "index":      self.cfg.splunk_index,
            "event":      event,
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.post(
                self.cfg.splunk_hec_url,
                json=payload,
                headers={
                    "Authorization": f"Splunk {self.cfg.splunk_hec_token}",
                    "Content-Type": "application/json",
                },
            ) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    raise RuntimeError(f"Splunk HEC respondió {resp.status}: {body[:100]}")

    async def test(self) -> dict[str, bool]:
        """Prueba la conectividad con todos los SIEMs configurados."""
        test_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self._hostname,
            "source": "cyberhound_pro",
            "event_type": "connectivity_test",
            "message": "Test de conectividad CyberHound Pro",
        }
        results = {}
        if self.cfg.wazuh_enabled:
            try:
                await self._send_wazuh(test_event)
                results["wazuh"] = True
            except Exception as e:
                logger.warning("SIEM test wazuh falló: %s", e)
                results["wazuh"] = False
        if self.cfg.elk_enabled:
            try:
                await self._send_elk(test_event)
                results["elk"] = True
            except Exception as e:
                logger.warning("SIEM test elk falló: %s", e)
                results["elk"] = False
        if self.cfg.splunk_enabled:
            try:
                await self._send_splunk(test_event)
                results["splunk"] = True
            except Exception as e:
                logger.warning("SIEM test splunk falló: %s", e)
                results["splunk"] = False
        return results
