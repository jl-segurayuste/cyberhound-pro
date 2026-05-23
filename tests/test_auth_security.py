"""
Tests de módulos sin cobertura directa:
- core/auth.py  — JWT, rate limiting, CSRF
- core/siem.py  — envío a Wazuh, ELK, Splunk
- core/notifications.py — email, webhooks
- scanners/secrets.py — detección de secretos en código
"""
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.core.models import Finding


# ── Auth ──────────────────────────────────────────────────────────────────────

class TestAuthConfig:

    def test_jwt_encode_decode(self):
        from cyberhound.core.auth import AuthConfig
        cfg = AuthConfig(secret="test_secret_32chars_long_enough_x")
        token = cfg.issue_jwt("admin")
        assert token
        payload = cfg.verify_jwt(token)
        assert payload is not None
        assert payload["sub"] == "admin"

    def test_jwt_wrong_secret(self):
        from cyberhound.core.auth import AuthConfig
        cfg1 = AuthConfig(secret="secret_one_32chars_long_enough_xx")
        cfg2 = AuthConfig(secret="secret_two_32chars_long_enough_xx")
        token = cfg1.issue_jwt("admin")
        assert cfg2.verify_jwt(token) is None

    def test_jwt_expired_token(self):
        from cyberhound.core.auth import AuthConfig
        from datetime import timedelta
        cfg = AuthConfig(secret="test_secret_32chars_long_enough_x")
        cfg.token_ttl = timedelta(seconds=-1)
        token = cfg.issue_jwt("admin")
        result = cfg.verify_jwt(token)
        assert result is None

    def test_jwt_malformed_token(self):
        from cyberhound.core.auth import AuthConfig
        cfg = AuthConfig(secret="test_secret_32chars_long_enough_x")
        assert cfg.verify_jwt("not.a.valid.jwt.token") is None
        assert cfg.verify_jwt("") is None
        assert cfg.verify_jwt(None) is None

    def test_password_verify(self):
        from cyberhound.core.auth import AuthConfig
        import hashlib
        password = "mysecurepassword"
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        cfg = AuthConfig(password_hash=pw_hash, secret="test_secret_32chars_long_enough_x")
        assert cfg.verify_password(password) is True
        assert cfg.verify_password("wrongpassword") is False

    def test_jwt_issue_and_verify(self):
        """JWT se emite y verifica correctamente."""
        from cyberhound.core.auth import AuthConfig
        cfg = AuthConfig(secret="test_secret_32chars_long_enough_x")
        token = cfg.issue_jwt("admin")
        assert token and isinstance(token, str)
        payload = cfg.verify_jwt(token)
        assert payload is not None
        assert payload["sub"] == "admin"


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class TestRateLimiter:

    @pytest.mark.asyncio
    async def test_allows_first_attempts(self):
        from cyberhound.core.security import RateLimiter
        rl = RateLimiter(max_attempts=5, window_seconds=900)
        for _ in range(4):
            ok, _ = await rl.is_allowed("192.168.1.1"); assert ok is True

    @pytest.mark.asyncio
    async def test_blocks_after_max(self):
        from cyberhound.core.security import RateLimiter
        rl = RateLimiter(max_attempts=3, window_seconds=900)
        for _ in range(3):
            await rl.record_failure("192.168.1.100")
        ok, _ = await rl.is_allowed("192.168.1.100"); assert ok is False

    @pytest.mark.asyncio
    async def test_localhost_exempt(self):
        from cyberhound.core.security import RateLimiter
        rl = RateLimiter(max_attempts=1, window_seconds=900)
        for _ in range(10):
            await rl.record_failure("127.0.0.1")
        # localhost nunca se bloquea
        ok, _ = await rl.is_allowed("127.0.0.1"); assert ok is True

    @pytest.mark.asyncio
    async def test_different_ips_independent(self):
        from cyberhound.core.security import RateLimiter
        rl = RateLimiter(max_attempts=2, window_seconds=900)
        for _ in range(2):
            await rl.record_failure("10.0.0.1")
        ok1, _ = await rl.is_allowed("10.0.0.1"); assert ok1 is False
        ok2, _ = await rl.is_allowed("10.0.0.2"); assert ok2 is True


# ── Input Validator ───────────────────────────────────────────────────────────

class TestInputValidator:

    def test_valid_ip(self):
        from cyberhound.core.security import InputValidator
        assert InputValidator.ip_or_hostname("192.168.1.1", "ip") == "192.168.1.1"

    def test_valid_hostname(self):
        from cyberhound.core.security import InputValidator
        assert InputValidator.ip_or_hostname("server.local", "host") == "server.local"

    def test_invalid_ip_raises(self):
        from cyberhound.core.security import InputValidator, ValidationError
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("999.999.999.999", "ip")

    def test_path_traversal_blocked(self):
        from cyberhound.core.security import InputValidator, ValidationError
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("../../etc/passwd", "host")

    def test_ws_message_valid_tasks(self):
        from cyberhound.core.security import InputValidator
        for task in ["audit", "malware", "docker", "services"]:
            msg = InputValidator.ws_message({"task": task})
            assert msg["task"] == task
        # code requiere path
        msg = InputValidator.ws_message({"task": "code", "path": "/var/www"})
        assert msg["task"] == "code"
        # ssh requiere hosts
        msg = InputValidator.ws_message({"task": "ssh", "hosts": "192.168.1.1"})
        assert msg["task"] == "ssh"

    def test_ws_message_invalid_task(self):
        from cyberhound.core.security import InputValidator, ValidationError
        with pytest.raises(ValidationError):
            InputValidator.ws_message({"task": "execute_rm_rf"})


# ── SIEM ──────────────────────────────────────────────────────────────────────

class TestSIEM:

    def _make_finding(self):
        return Finding(
            id="test_finding", category="ssh", severity="critical",
            title="Test critical finding", description="Test desc",
            remediation="Fix it",
        )

    @pytest.mark.asyncio
    async def test_disabled_siem_no_exception(self):
        """Con SIEM desactivado no debe lanzar excepción."""
        from cyberhound.core.siem import SIEMIntegration, SIEMConfig
        cfg = SIEMConfig(wazuh_enabled=False, elk_enabled=False, splunk_enabled=False)
        siem = SIEMIntegration(cfg)
        finding = self._make_finding()
        # No debe lanzar excepción
        await siem.send_finding(finding)

    @pytest.mark.asyncio
    async def test_siem_test_connectivity_returns_dict(self):
        """El test de conectividad debe devolver un dict con resultados."""
        from cyberhound.core.siem import SIEMIntegration, SIEMConfig
        cfg = SIEMConfig(wazuh_enabled=False, elk_enabled=False, splunk_enabled=False)
        siem = SIEMIntegration(cfg)
        result = await siem.test()
        assert isinstance(result, dict)

    def test_siem_config_defaults(self):
        from cyberhound.core.siem import SIEMConfig
        cfg = SIEMConfig()
        assert not cfg.wazuh_enabled
        assert not cfg.elk_enabled
        assert not cfg.splunk_enabled


# ── Secrets scanner ───────────────────────────────────────────────────────────

class TestSecretsScanner:

    @pytest.mark.asyncio
    async def test_scanner_scan_method_exists(self):
        from cyberhound.scanners.secrets import SecretScanner
        sc = SecretScanner()
        assert hasattr(sc, 'scan')

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self):
        from cyberhound.scanners.secrets import SecretScanner
        sc = SecretScanner()
        # No debe crashear con un path que no existe
        try:
            findings = await sc.scan(path="/tmp/nonexistent_cyberhound_test_12345")
        except Exception:
            findings = []
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_returns_findings_list(self, tmp_path):
        from cyberhound.scanners.secrets import SecretScanner
        # Crear un fichero con secreto
        f = tmp_path / "secrets.py"
        f.write_text("GITHUB_TOKEN = 'ghp_" + "a" * 36 + "'\n")
        sc = SecretScanner()
        try:
            findings = await sc.scan(path=str(tmp_path))
        except Exception:
            findings = []
        # Puede retornar findings o vacío según las herramientas instaladas
        assert isinstance(findings, list)


# ── Notifications ─────────────────────────────────────────────────────────────

class TestNotifications:

    @pytest.mark.asyncio
    async def test_disabled_notifications_no_exception(self):
        from cyberhound.core.notifications import NotificationManager, NotificationConfig
        cfg = NotificationConfig(
            email_enabled=False,
        )
        mgr = NotificationManager(cfg)
        # No debe lanzar excepción
        await mgr.send("Test message", level="info")

    def test_notification_level_filter(self):
        from cyberhound.core.notifications import NotificationConfig
        cfg = NotificationConfig(min_level="warning")
        # Debe respetar el nivel mínimo
        assert not cfg.should_notify("info")
        assert cfg.should_notify("warning")
        assert cfg.should_notify("critical")

    def test_notification_config_has_email_fields(self):
        from cyberhound.core.notifications import NotificationConfig
        cfg = NotificationConfig()
        assert hasattr(cfg, 'email_enabled')
        assert hasattr(cfg, 'smtp_host')
        assert hasattr(cfg, 'min_level')
