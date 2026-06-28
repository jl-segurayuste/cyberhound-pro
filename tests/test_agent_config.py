"""Tests del endpoint de configuración del modo agente (/api/config/agent)."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from cyberhound.api.server import CyberHoundServer
from cyberhound.core.config import CyberHoundConfig


def _req(body: dict):
    r = SimpleNamespace()
    r.read = AsyncMock(return_value=json.dumps(body).encode())
    return r


def _server(tmp_path):
    cfg = CyberHoundConfig()
    srv = SimpleNamespace(cfg=cfg)
    # Evitar escribir el config real en disco
    cfg.save = lambda path=None: None
    return srv


class TestAgentConfig:
    @pytest.mark.asyncio
    async def test_get_returns_mode_without_key(self, tmp_path):
        srv = _server(tmp_path)
        srv.cfg.agent.mode = "manager"
        srv.cfg.agent.agent_key = "secreto"
        resp = await CyberHoundServer.api_get_agent_cfg(srv, _req({}))
        data = json.loads(resp.body.decode())
        assert data["mode"] == "manager"
        assert data["has_key"] is True
        assert "agent_key" not in data          # la clave NUNCA se devuelve

    @pytest.mark.asyncio
    async def test_save_updates_config(self, tmp_path):
        srv = _server(tmp_path)
        resp = await CyberHoundServer.api_save_agent_cfg(
            srv, _req({"mode": "agent", "manager_url": "https://m:8443",
                       "agent_name": "web-01", "agent_key": "k123"})
        )
        assert json.loads(resp.body.decode())["ok"] is True
        assert srv.cfg.agent.mode == "agent"
        assert srv.cfg.agent.manager_url == "https://m:8443"
        assert srv.cfg.agent.agent_name == "web-01"
        assert srv.cfg.agent.agent_key == "k123"

    @pytest.mark.asyncio
    async def test_save_rejects_invalid_mode(self, tmp_path):
        srv = _server(tmp_path)
        srv.cfg.agent.mode = "standalone"
        await CyberHoundServer.api_save_agent_cfg(srv, _req({"mode": "hacker"}))
        assert srv.cfg.agent.mode == "standalone"   # modo inválido ignorado

    @pytest.mark.asyncio
    async def test_save_keeps_key_when_empty(self, tmp_path):
        srv = _server(tmp_path)
        srv.cfg.agent.agent_key = "existente"
        await CyberHoundServer.api_save_agent_cfg(srv, _req({"agent_key": ""}))
        assert srv.cfg.agent.agent_key == "existente"   # no se borra con vacío
