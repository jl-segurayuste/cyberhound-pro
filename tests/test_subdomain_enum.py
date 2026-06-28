"""Tests del escáner de enumeración de subdominios."""
import pytest

from cyberhound.scanners.subdomain_enum import (
    MAX_RESOLVE,
    SubdomainEnumScanner,
    scan_domain,
)


class TestSubdomainEnumConfig:
    def test_max_resolve_sane(self):
        assert 10 <= MAX_RESOLVE <= 1000


class TestSubdomainEnumScanner:
    @pytest.mark.asyncio
    async def test_empty_domains_returns_empty(self):
        assert await SubdomainEnumScanner.full_scan([]) == []

    @pytest.mark.asyncio
    async def test_blank_domain_no_network(self):
        # dominio en blanco → retorna sin tocar la red
        assert await scan_domain("   ") == []

    @pytest.mark.asyncio
    async def test_wildcard_only_no_network(self):
        # "*." se normaliza a vacío → retorna sin tocar la red
        assert await scan_domain("*.") == []
