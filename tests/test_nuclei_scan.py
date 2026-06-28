"""Tests del escáner Nuclei (parseo puro + degradación sin binario)."""
import pytest

from cyberhound.scanners import nuclei_scan
from cyberhound.scanners.nuclei_scan import (
    NucleiScanner,
    _normalize_targets,
    finding_from_result,
    map_severity,
    scan_urls,
)


class TestSeverityMap:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("critical", "critical"),
            ("HIGH", "high"),
            ("  medium ", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("unknown", "info"),
            ("", "info"),
            (None, "info"),
            ("nonsense", "info"),
        ],
    )
    def test_map(self, raw, expected):
        assert map_severity(raw) == expected


class TestNormalizeTargets:
    def test_adds_scheme_and_dedups(self):
        out = _normalize_targets(["example.com", "https://example.com", " ", "http://a.io"])
        assert out == ["https://example.com", "http://a.io"]

    def test_empty(self):
        assert _normalize_targets([]) == []


class TestFindingFromResult:
    def _sample(self):
        return {
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "description": "Log4Shell.",
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "tags": ["cve", "rce", "log4j"],
                "remediation": "Actualiza Log4j a 2.17+.",
                "classification": {"cve-id": ["CVE-2021-44228"]},
            },
            "host": "https://victim.example.com",
            "matched-at": "https://victim.example.com/api",
            "extracted-results": ["jndi:ldap"],
        }

    def test_maps_core_fields(self):
        f = finding_from_result(self._sample())
        assert f is not None
        assert f.category == "nuclei"
        assert f.severity == "critical"
        assert "Apache Log4j RCE" in f.title
        assert f.source_host == "victim.example.com"
        assert f.id.startswith("nuclei_CVE-2021-44228_")
        assert "CVE-2021-44228" in f.description
        assert "Actualiza Log4j" in f.remediation
        assert "victim.example.com/api" in f.evidence

    def test_stable_id(self):
        a = finding_from_result(self._sample())
        b = finding_from_result(self._sample())
        assert a.id == b.id

    def test_missing_template_id_returns_none(self):
        assert finding_from_result({"info": {"name": "x"}}) is None

    def test_minimal_object_defaults(self):
        f = finding_from_result({"template-id": "exposed-panel", "matched-at": "http://h/p"})
        assert f is not None
        assert f.severity == "info"
        assert f.remediation  # remediación genérica no vacía


class TestNucleiScanner:
    @pytest.mark.asyncio
    async def test_empty_urls_returns_empty(self):
        assert await NucleiScanner.full_scan([]) == []

    @pytest.mark.asyncio
    async def test_missing_binary_degrades(self, monkeypatch):
        # Sin binario en PATH → lista vacía, sin lanzar nada.
        monkeypatch.setattr(nuclei_scan.shutil, "which", lambda _: None)
        assert await scan_urls(["example.com"]) == []
