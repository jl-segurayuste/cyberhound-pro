"""Tests del escáner de seguridad de API/CORS."""
import pytest

from cyberhound.scanners.api_security import (
    API_DOC_PATHS,
    EVIL_ORIGIN,
    APISecurityScanner,
    scan_url,
)


class TestAPISecurityConfig:
    def test_doc_paths_not_empty(self):
        assert len(API_DOC_PATHS) >= 4

    def test_doc_paths_well_formed(self):
        for path, title in API_DOC_PATHS:
            assert isinstance(path, str) and path
            assert isinstance(title, str) and title

    def test_evil_origin_is_external(self):
        assert EVIL_ORIGIN.startswith("https://")
        assert "attacker" in EVIL_ORIGIN or "evil" in EVIL_ORIGIN

    def test_common_specs_present(self):
        paths = [p for p, _ in API_DOC_PATHS]
        assert "openapi.json" in paths
        assert any("openid" in p for p in paths)


class TestAPISecurityScanner:
    @pytest.mark.asyncio
    async def test_empty_urls_returns_empty(self):
        findings = await APISecurityScanner.full_scan([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_unreachable_url_no_crash(self):
        findings = await APISecurityScanner.full_scan(["https://127.0.0.1:59994"])
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_url_adds_scheme(self):
        # No debe lanzar aunque la URL no tenga esquema
        findings = await scan_url("127.0.0.1:59993", timeout=2)
        assert isinstance(findings, list)
