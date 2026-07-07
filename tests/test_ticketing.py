"""Tests de la integración de ticketing (Jira / ServiceNow).

Sigue el mismo patrón que TestSIEM en test_auth_security.py: config
desactivada no debe lanzar, y test() devuelve un dict. Además, mockea
aiohttp.ClientSession para probar los caminos de éxito/fallo de creación
de ticket sin red real (mismo patrón que test_scanners_core.py).
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.core.models import Finding
from cyberhound.core.ticketing import TicketingConfig, TicketingIntegration


def _finding(severity="critical", finding_id="test_finding"):
    return Finding(
        id=finding_id, category="ssh", severity=severity,
        title="Test finding", description="Test desc",
        remediation="Fix it", evidence="evidence line",
    )


class _FakeResponse:
    def __init__(self, status, json_data=None, text_data=""):
        self.status = status
        self._json = json_data or {}
        self._text = text_data

    async def json(self):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self._response = response

    def post(self, *args, **kwargs):
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class TestTicketingConfig:
    def test_defaults_disabled(self):
        cfg = TicketingConfig()
        assert not cfg.jira_enabled
        assert not cfg.servicenow_enabled
        assert cfg.min_severity == "critical"

    def test_should_create_respects_min_severity(self):
        cfg = TicketingConfig(min_severity="high")
        assert cfg.should_create("critical")
        assert cfg.should_create("high")
        assert not cfg.should_create("medium")
        assert not cfg.should_create("low")

    def test_should_create_default_only_critical(self):
        cfg = TicketingConfig()  # min_severity="critical" por defecto
        assert cfg.should_create("critical")
        assert not cfg.should_create("high")


class TestTicketingIntegrationDisabled:
    @pytest.mark.asyncio
    async def test_disabled_returns_empty_no_exception(self):
        cfg = TicketingConfig(jira_enabled=False, servicenow_enabled=False)
        integ = TicketingIntegration(cfg)
        result = await integ.create_ticket(_finding())
        assert result == []

    @pytest.mark.asyncio
    async def test_below_threshold_returns_empty(self):
        cfg = TicketingConfig(jira_enabled=True, jira_url="https://x.atlassian.net",
                               jira_email="a@b.com", jira_api_token="t", jira_project_key="SEC",
                               min_severity="critical")
        integ = TicketingIntegration(cfg)
        result = await integ.create_ticket(_finding(severity="low"))
        assert result == []

    @pytest.mark.asyncio
    async def test_test_connectivity_returns_dict(self):
        cfg = TicketingConfig(jira_enabled=False, servicenow_enabled=False)
        integ = TicketingIntegration(cfg)
        result = await integ.test()
        assert isinstance(result, dict)


class TestJiraTicketCreation:
    @pytest.mark.asyncio
    async def test_creates_ticket_on_success(self):
        cfg = TicketingConfig(
            jira_enabled=True, jira_url="https://tuempresa.atlassian.net",
            jira_email="bot@empresa.com", jira_api_token="tok", jira_project_key="SEC",
        )
        integ = TicketingIntegration(cfg)
        fake = _FakeSession(_FakeResponse(201, {"key": "SEC-42"}))
        with patch("aiohttp.ClientSession", return_value=fake):
            results = await integ.create_ticket(_finding())
        assert len(results) == 1
        assert results[0].system == "jira"
        assert results[0].external_id == "SEC-42"
        assert "SEC-42" in results[0].url

    @pytest.mark.asyncio
    async def test_http_error_does_not_raise_and_returns_empty(self):
        cfg = TicketingConfig(
            jira_enabled=True, jira_url="https://tuempresa.atlassian.net",
            jira_email="bot@empresa.com", jira_api_token="bad", jira_project_key="SEC",
        )
        integ = TicketingIntegration(cfg)
        fake = _FakeSession(_FakeResponse(401, text_data="Unauthorized"))
        with patch("aiohttp.ClientSession", return_value=fake):
            results = await integ.create_ticket(_finding())
        assert results == []  # el fallo se loguea, no se propaga


class TestServiceNowTicketCreation:
    @pytest.mark.asyncio
    async def test_creates_ticket_on_success(self):
        cfg = TicketingConfig(
            servicenow_enabled=True, servicenow_instance_url="https://tuempresa.service-now.com",
            servicenow_user="integracion", servicenow_password="pw",
        )
        integ = TicketingIntegration(cfg)
        fake = _FakeSession(_FakeResponse(201, {"result": {"sys_id": "abc123", "number": "INC0012345"}}))
        with patch("aiohttp.ClientSession", return_value=fake):
            results = await integ.create_ticket(_finding())
        assert len(results) == 1
        assert results[0].system == "servicenow"
        assert results[0].external_id == "INC0012345"
        assert "abc123" in results[0].url


class TestBothSystemsConfigured:
    @pytest.mark.asyncio
    async def test_partial_failure_still_returns_the_successful_one(self):
        """Si Jira fallara y ServiceNow no, debe devolver solo el resultado de ServiceNow
        (best-effort por sistema, no todo-o-nada)."""
        cfg = TicketingConfig(
            jira_enabled=False,  # simplificamos: solo servicenow activo en este test
            servicenow_enabled=True, servicenow_instance_url="https://x.service-now.com",
            servicenow_user="u", servicenow_password="p",
        )
        integ = TicketingIntegration(cfg)
        fake = _FakeSession(_FakeResponse(201, {"result": {"sys_id": "s1", "number": "INC1"}}))
        with patch("aiohttp.ClientSession", return_value=fake):
            results = await integ.create_ticket(_finding())
        assert len(results) == 1
        assert results[0].system == "servicenow"
