"""
Modo agente de CyberHound Pro.

Permite desplegar CyberHound en múltiples servidores y agregar
los resultados en una instancia central (manager).

Arquitectura:
  Manager  — instancia principal con UI completa, recibe resultados de agentes
  Agent    — instancia ligera en cada servidor que envía hallazgos al manager

El agente:
  1. Ejecuta los scans configurados localmente
  2. POST los resultados al endpoint /api/agent/report del manager
  3. El manager los almacena en su BD bajo el hostname del agente

Comunicación: HTTPS + API key compartida (no JWT)
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("agent")

AGENT_API_VERSION = "v1"


@dataclass
class AgentConfig:
    """Configuración del modo agente."""
    # Modo de operación
    mode: str = "standalone"          # standalone | agent | manager

    # Si mode == "agent": dónde enviar los resultados
    manager_url: str = ""             # https://cyberhound-manager:8443
    agent_key:   str = ""             # clave API compartida con el manager
    agent_name:  str = ""             # nombre identificativo (default: hostname)

    # Si mode == "manager": qué agentes están registrados
    registered_agents: list[str] = None   # lista de agent_names permitidos

    def __post_init__(self):
        if not self.agent_name:
            self.agent_name = socket.gethostname()
        if self.registered_agents is None:
            self.registered_agents = []


class AgentReporter:
    """
    Envía hallazgos al manager central.
    Usado por instancias en modo 'agent'.
    """

    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg

    async def report_scan(
        self,
        findings: list[Finding],
        scan_type: str,
        score: Optional[int] = None,
    ) -> bool:
        """Envía los hallazgos de un scan al manager."""
        if not self.cfg.manager_url or not self.cfg.agent_key:
            logger.warning("Agente no configurado: manager_url o agent_key vacíos")
            return False

        payload = {
            "agent_name":  self.cfg.agent_name,
            "scan_type":   scan_type,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "score":       score,
            "findings":    [f.to_dict() for f in findings],
            "total":       len(findings),
            "hostname":    socket.gethostname(),
        }

        url = f"{self.cfg.manager_url.rstrip('/')}/api/agent/report"
        headers = {
            "Authorization": f"AgentKey {self.cfg.agent_key}",
            "Content-Type":  "application/json",
            "X-Agent-Name":  self.cfg.agent_name,
            "X-API-Version": AGENT_API_VERSION,
        }

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False),  # acepta certs auto-firmados
            ) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        logger.info(
                            "Agente '%s': %d hallazgos enviados al manager (%s)",
                            self.cfg.agent_name, len(findings), self.cfg.manager_url,
                        )
                        return True
                    else:
                        body = await resp.text()
                        logger.error(
                            "Manager respondió %d al report del agente: %s",
                            resp.status, body[:200],
                        )
                        return False
        except aiohttp.ClientConnectorError as e:
            logger.error("No se pudo conectar al manager %s: %s", self.cfg.manager_url, e)
            return False
        except Exception as e:
            logger.error("Error enviando report al manager: %s", e, exc_info=True)
            return False

    async def heartbeat(self) -> bool:
        """Envía un ping al manager para indicar que el agente está activo."""
        if not self.cfg.manager_url:
            return False
        url = f"{self.cfg.manager_url.rstrip('/')}/api/agent/heartbeat"
        headers = {
            "Authorization": f"AgentKey {self.cfg.agent_key}",
            "X-Agent-Name":  self.cfg.agent_name,
        }
        payload = {
            "agent_name": self.cfg.agent_name,
            "hostname":   socket.gethostname(),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "version":    AGENT_API_VERSION,
        }
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.debug("Heartbeat falló: %s", e)
            return False


class AgentManager:
    """
    Gestiona los agentes remotos en la instancia manager.
    Recibe y almacena los hallazgos enviados por los agentes.
    """

    def __init__(self, db, cfg: AgentConfig) -> None:
        self.db  = db
        self.cfg = cfg
        self._agents: dict[str, dict] = {}   # agent_name → info

    def verify_agent_key(self, key: str) -> bool:
        """Verifica la clave API del agente."""
        import hmac as _hmac
        if not self.cfg.agent_key or not key:
            return False
        return _hmac.compare_digest(self.cfg.agent_key, key)

    def extract_agent_key(self, auth_header: str) -> str:
        """Extrae la clave del header Authorization: AgentKey XXX."""
        if auth_header and auth_header.startswith("AgentKey "):
            return auth_header[9:]
        return ""

    async def receive_report(self, payload: dict) -> dict:
        """Procesa un report de un agente y lo guarda en BD."""
        agent_name = payload.get("agent_name", "unknown")
        scan_type  = payload.get("scan_type", "audit")
        findings_raw = payload.get("findings", [])
        score      = payload.get("score")
        timestamp  = payload.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Reconstruir objetos Finding con source_host = agent_name
        findings = []
        for fd in findings_raw:
            f = Finding(
                id=f"{agent_name}::{fd.get('id', fd.get('finding_id', ''))}",
                category=fd.get("category", "unknown"),
                severity=fd.get("severity", "info"),
                title=fd.get("title", ""),
                description=fd.get("description", ""),
                remediation=fd.get("remediation", ""),
                evidence=fd.get("evidence", ""),
                auto_fix=fd.get("auto_fix", False),
                file_path=fd.get("file_path", ""),
                source_host=agent_name,
            )
            findings.append(f)

        # Guardar en BD
        scan_id = await self.db.create_scan(
            scan_type, target=agent_name, triggered_by="agent"
        )
        await self.db.complete_scan(scan_id, findings, score=score)

        # Actualizar registro del agente
        self._agents[agent_name] = {
            "name":        agent_name,
            "hostname":    payload.get("hostname", agent_name),
            "last_seen":   timestamp,
            "last_scan":   scan_type,
            "total":       len(findings),
            "score":       score,
        }

        logger.info(
            "Manager: recibido report de agente '%s' — %d hallazgos, score=%s",
            agent_name, len(findings), score,
        )
        return {"ok": True, "scan_id": scan_id, "received": len(findings)}

    async def receive_heartbeat(self, payload: dict) -> None:
        agent_name = payload.get("agent_name", "unknown")
        self._agents[agent_name] = {
            **self._agents.get(agent_name, {}),
            "name":      agent_name,
            "hostname":  payload.get("hostname", agent_name),
            "last_seen": payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "online":    True,
        }

    def list_agents(self) -> list[dict]:
        return list(self._agents.values())
