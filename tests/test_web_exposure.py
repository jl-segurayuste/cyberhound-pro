"""Tests del escáner de exposición web."""
import pytest

from cyberhound.scanners.web_exposure import (
    DANGEROUS_METHODS,
    SENSITIVE_PATHS,
    WebExposureScanner,
    scan_url,
)


def _validator_for(path):
    for p, _sev, _title, _desc, validator in SENSITIVE_PATHS:
        if p == path:
            return validator
    return None


class TestSensitivePathsConfig:
    def test_paths_not_empty(self):
        assert len(SENSITIVE_PATHS) >= 10

    def test_each_path_well_formed(self):
        for path, sev, title, desc, validator in SENSITIVE_PATHS:
            assert isinstance(path, str) and path
            assert sev in ("critical", "high", "medium", "low")
            assert title and desc
            assert validator is None or callable(validator)

    def test_critical_paths_present(self):
        paths = [p[0] for p in SENSITIVE_PATHS]
        assert ".git/HEAD" in paths
        assert ".env" in paths

    def test_git_head_validator(self):
        v = _validator_for(".git/HEAD")
        assert v is not None
        assert v("ref: refs/heads/main")
        assert not v("<html><body>404 Not Found</body></html>")

    def test_env_validator_rejects_html(self):
        v = _validator_for(".env")
        assert v is not None
        assert v("SECRET_KEY=abc123\nDB_PASS=xyz")
        assert not v("<html>Página no encontrada</html>")

    def test_dangerous_methods_defined(self):
        for m in ("TRACE", "PUT", "DELETE"):
            assert m in DANGEROUS_METHODS


class TestWebExposureScanner:
    @pytest.mark.asyncio
    async def test_empty_urls_returns_empty(self):
        findings = await WebExposureScanner.full_scan([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_unreachable_url_no_crash(self):
        findings = await WebExposureScanner.full_scan(["https://127.0.0.1:59996"])
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_url_adds_scheme(self):
        # No debe lanzar aunque la URL no tenga esquema
        findings = await scan_url("127.0.0.1:59995", timeout=2)
        assert isinstance(findings, list)
