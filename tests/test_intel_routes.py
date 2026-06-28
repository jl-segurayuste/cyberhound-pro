"""Tests del router de Inteligencia de Amenazas."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.core.models import Finding


class TestIntelRoutes:

    def _make_finding(self, severity="high", category="intel/vt"):
        return Finding(
            id="intel_test", category=category, severity=severity,
            title="IP maliciosa detectada", description="15 engines detected.",
            remediation="Bloquear en firewall",
            evidence="ip=1.2.3.4 detections=15",
        )

    def test_intel_routes_module_importable(self):
        """El módulo de rutas es importable."""
        from cyberhound.api.routes.intel_routes import (
            _build_intel_summary,
            api_intel_lookup,
            api_intel_scan,
            register_routes,
        )
        assert callable(register_routes)
        assert callable(_build_intel_summary)

    def test_build_intel_summary_empty(self):
        """Resumen con findings vacío."""
        from cyberhound.api.routes.intel_routes import _build_intel_summary
        summary = _build_intel_summary([])
        assert summary["total"] == 0
        assert summary["malicious"] == 0
        assert summary["risk_level"] == "none"

    def test_build_intel_summary_with_critical(self):
        """Resumen con finding crítico."""
        from cyberhound.api.routes.intel_routes import _build_intel_summary
        findings = [
            self._make_finding("critical", "intel/shodan"),
            self._make_finding("high",     "intel/vt"),
            self._make_finding("medium",   "intel/abuseipdb"),
        ]
        summary = _build_intel_summary(findings)
        assert summary["total"] == 3
        assert summary["malicious"] == 2  # critical + high
        assert summary["risk_level"] == "critical"
        assert "shodan" in summary["by_module"]

    def test_build_intel_summary_risk_levels(self):
        """Niveles de riesgo calculados correctamente."""
        from cyberhound.api.routes.intel_routes import _build_intel_summary

        assert _build_intel_summary([self._make_finding("critical")])["risk_level"] == "critical"
        assert _build_intel_summary([self._make_finding("high")])["risk_level"] == "high"
        assert _build_intel_summary([self._make_finding("medium")])["risk_level"] == "medium"
        assert _build_intel_summary([self._make_finding("low")])["risk_level"] == "low"
        assert _build_intel_summary([])["risk_level"] == "none"

    def test_build_intel_summary_by_module(self):
        """Contadores por módulo."""
        from cyberhound.api.routes.intel_routes import _build_intel_summary
        findings = [
            self._make_finding(category="intel/shodan"),
            self._make_finding(category="intel/shodan"),
            self._make_finding(category="intel/vt"),
        ]
        summary = _build_intel_summary(findings)
        assert summary["by_module"]["shodan"] == 2
        assert summary["by_module"]["vt"] == 1

    def test_register_routes(self):
        """register_routes añade las rutas a la app."""
        from aiohttp import web

        from cyberhound.api.routes.intel_routes import register_routes
        app = web.Application()
        register_routes(app)
        # Obtener los paths de las rutas registradas
        routes = [str(r) for r in app.router.resources()]
        assert any("intel" in r for r in routes), f"Intel routes no encontradas en: {routes[:5]}"

    def test_build_summary_by_severity(self):
        """Severidades correctamente contadas."""
        from cyberhound.api.routes.intel_routes import _build_intel_summary
        findings = [
            self._make_finding("critical"),
            self._make_finding("critical"),
            self._make_finding("high"),
            self._make_finding("medium"),
            self._make_finding("low"),
        ]
        summary = _build_intel_summary(findings)
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 1
        assert summary["malicious"] == 3  # critical + high
