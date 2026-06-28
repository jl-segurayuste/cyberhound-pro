"""Tests de validación eager de configuración."""
import hashlib
import tempfile
from pathlib import Path

import pytest

from cyberhound.core.config import CyberHoundConfig


@pytest.fixture
def valid_cfg(tmp_path):
    cfg = CyberHoundConfig()
    cfg.auth.password_hash = hashlib.sha256(b"test1234").hexdigest()
    cfg.auth.secret = "x" * 32
    return cfg


class TestConfigValidation:

    def test_valid_config_no_errors(self, valid_cfg):
        assert valid_cfg.validate() == []

    def test_invalid_auth_mode(self, valid_cfg):
        valid_cfg.auth.mode = "ldap"
        errors = valid_cfg.validate()
        assert any("auth.mode" in e for e in errors)

    def test_invalid_port_zero(self, valid_cfg):
        valid_cfg.server.port = 0
        errors = valid_cfg.validate()
        assert any("server.port" in e for e in errors)

    def test_invalid_port_too_high(self, valid_cfg):
        valid_cfg.server.port = 99999
        errors = valid_cfg.validate()
        assert any("server.port" in e for e in errors)

    def test_tls_cert_without_key(self, valid_cfg, tmp_path):
        cert = tmp_path / "cert.pem"
        cert.write_text("fake")
        valid_cfg.server.tls_cert = str(cert)
        valid_cfg.server.tls_key = None
        errors = valid_cfg.validate()
        assert any("tls_cert" in e and "tls_key" in e for e in errors)

    def test_tls_cert_not_exists(self, valid_cfg):
        valid_cfg.server.tls_cert = "/nonexistent/cert.pem"
        valid_cfg.server.tls_key = "/nonexistent/key.pem"
        errors = valid_cfg.validate()
        assert any("tls_cert" in e for e in errors)

    def test_ssh_concurrency_too_high(self, valid_cfg):
        valid_cfg.scan.ssh_concurrency = 100
        errors = valid_cfg.validate()
        assert any("ssh_concurrency" in e for e in errors)

    def test_ssh_key_insecure_permissions(self, valid_cfg, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text("fake key")
        key.chmod(0o644)  # permisos inseguros
        valid_cfg.scan.ssh_key_path = str(key)
        errors = valid_cfg.validate()
        assert any("ssh_key_path" in e and "permiso" in e.lower() for e in errors)

    def test_ssh_key_correct_permissions(self, valid_cfg, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text("fake key")
        key.chmod(0o600)  # permisos correctos
        valid_cfg.scan.ssh_key_path = str(key)
        errors = valid_cfg.validate()
        assert not any("ssh_key_path" in e for e in errors)

    def test_scheduler_hour_out_of_range(self, valid_cfg):
        valid_cfg.scheduler.audit_hour = 25
        errors = valid_cfg.validate()
        assert any("audit_hour" in e for e in errors)

    def test_scheduler_malware_day_invalid(self, valid_cfg):
        valid_cfg.scheduler.malware_day = 7  # solo 0-6
        errors = valid_cfg.validate()
        assert any("malware_day" in e for e in errors)

    def test_email_enabled_without_smtp_host(self, valid_cfg):
        valid_cfg.notifications.email_enabled = True
        valid_cfg.notifications.smtp_host = ""
        valid_cfg.notifications.email_to = ["admin@example.com"]
        valid_cfg.notifications.smtp_user = "user@example.com"
        errors = valid_cfg.validate()
        assert any("smtp_host" in e for e in errors)

    def test_email_enabled_without_recipients(self, valid_cfg):
        valid_cfg.notifications.email_enabled = True
        valid_cfg.notifications.smtp_host = "smtp.gmail.com"
        valid_cfg.notifications.email_to = []
        valid_cfg.notifications.smtp_user = "user"
        errors = valid_cfg.validate()
        assert any("email_to" in e for e in errors)

    def test_webhook_without_url(self, valid_cfg):
        valid_cfg.notifications.webhook_enabled = True
        valid_cfg.notifications.webhook_url = ""
        errors = valid_cfg.validate()
        assert any("webhook_url" in e for e in errors)

    def test_webhook_http_not_https(self, valid_cfg):
        valid_cfg.notifications.webhook_enabled = True
        valid_cfg.notifications.webhook_url = "http://hooks.slack.com/..."
        errors = valid_cfg.validate()
        assert any("HTTPS" in e for e in errors)

    def test_invalid_min_level(self, valid_cfg):
        valid_cfg.notifications.min_level = "debug"
        errors = valid_cfg.validate()
        assert any("min_level" in e for e in errors)

    def test_multiple_errors_returned(self, valid_cfg):
        valid_cfg.auth.mode = "ldap"
        valid_cfg.server.port = 0
        valid_cfg.scheduler.audit_hour = 99
        errors = valid_cfg.validate()
        assert len(errors) >= 3

    def test_token_ttl_too_low(self, valid_cfg):
        valid_cfg.auth.token_ttl_hours = 0
        errors = valid_cfg.validate()
        assert any("token_ttl_hours" in e for e in errors)

    def test_token_ttl_too_high(self, valid_cfg):
        valid_cfg.auth.token_ttl_hours = 200
        errors = valid_cfg.validate()
        assert any("token_ttl_hours" in e for e in errors)

    def test_save_and_reload(self, valid_cfg, tmp_path):
        config_path = tmp_path / "config.yaml"
        valid_cfg.save(config_path)
        assert config_path.exists()
        assert oct(config_path.stat().st_mode & 0o777) == "0o600"
        reloaded = CyberHoundConfig.load(config_path)
        assert reloaded.auth.mode == valid_cfg.auth.mode
        assert reloaded.server.port == valid_cfg.server.port

    def test_saved_config_has_no_smtp_password(self, valid_cfg, tmp_path):
        valid_cfg.notifications.smtp_password = "supersecret"
        config_path = tmp_path / "config.yaml"
        valid_cfg.save(config_path)
        content = config_path.read_text()
        assert "supersecret" not in content

    def test_hash_password(self):
        h = CyberHoundConfig.hash_password("test1234")
        assert len(h) == 64  # SHA-256 hex
        assert h == CyberHoundConfig.hash_password("test1234")  # determinista
        assert h != CyberHoundConfig.hash_password("other")
