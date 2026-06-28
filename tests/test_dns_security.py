"""Tests del escáner de seguridad DNS."""
import pytest

from cyberhound.scanners.dns_security import (
    COMMON_DKIM_SELECTORS,
    DNSSecurityScanner,
    scan_domain,
)


class TestDNSConfig:
    def test_dkim_selectors_defined(self):
        assert "default" in COMMON_DKIM_SELECTORS
        assert "google" in COMMON_DKIM_SELECTORS
        assert len(COMMON_DKIM_SELECTORS) >= 5


class TestDNSScanner:
    @pytest.mark.asyncio
    async def test_empty_domains_returns_empty(self):
        assert await DNSSecurityScanner.full_scan([]) == []

    @pytest.mark.asyncio
    async def test_empty_domain_string(self):
        assert await scan_domain("") == []

    @pytest.mark.asyncio
    async def test_nonexistent_domain_no_crash(self):
        # Dominio inexistente: sin SPF/DMARC → genera findings, no lanza
        findings = await scan_domain("nonexistent-xyz-123456789.invalid")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_full_scan_returns_list(self):
        findings = await DNSSecurityScanner.full_scan(["example.invalid"])
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_findings_have_dns_category(self):
        findings = await scan_domain("test-no-records-987654321.invalid")
        for f in findings:
            assert f.category == "dns"
            assert f.severity in ("critical", "high", "medium", "low", "info")
