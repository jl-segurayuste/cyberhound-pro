"""Tests del escáner de cabeceras de seguridad web."""
import pytest

from cyberhound.scanners.web_headers import (
    LEAKY_HEADERS,
    SECURITY_HEADERS,
    WebHeadersScanner,
)


class TestSecurityHeadersConfig:
    def test_core_headers_present(self):
        for h in ("strict-transport-security", "content-security-policy",
                  "x-frame-options", "x-content-type-options"):
            assert h in SECURITY_HEADERS

    def test_each_header_has_validator(self):
        for header, (sev, rem, validator) in SECURITY_HEADERS.items():
            assert sev in ("high", "medium", "low")
            assert callable(validator)
            assert len(rem) > 0

    def test_hsts_validator(self):
        _, _, validator = SECURITY_HEADERS["strict-transport-security"]
        assert validator("max-age=31536000; includeSubDomains")
        assert not validator("")

    def test_csp_validator(self):
        _, _, validator = SECURITY_HEADERS["content-security-policy"]
        assert validator("default-src 'self'")
        assert validator("script-src 'self'")
        assert not validator("upgrade-insecure-requests")

    def test_xcto_validator_strict(self):
        _, _, validator = SECURITY_HEADERS["x-content-type-options"]
        assert validator("nosniff")
        assert not validator("sniff")

    def test_leaky_headers_defined(self):
        assert "server" in LEAKY_HEADERS
        assert "x-powered-by" in LEAKY_HEADERS


class TestWebHeadersScanner:
    @pytest.mark.asyncio
    async def test_empty_urls_returns_empty(self):
        findings = await WebHeadersScanner.full_scan([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_unreachable_url_no_crash(self):
        findings = await WebHeadersScanner.full_scan(["https://127.0.0.1:59998"])
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_url_adds_scheme(self):
        from cyberhound.scanners.web_headers import scan_url
        # No debe lanzar aunque la URL no tenga esquema
        findings = await scan_url("127.0.0.1:59997", timeout=2)
        assert isinstance(findings, list)
