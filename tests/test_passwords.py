"""Tests del hashing de contraseñas (PBKDF2 + retrocompatibilidad SHA-256)."""
import hashlib

from cyberhound.core import passwords
from cyberhound.core.auth import AuthConfig
from cyberhound.core.config import CyberHoundConfig


class TestPbkdf2:
    def test_hash_format(self):
        h = passwords.hash_password("s3cret")
        assert h.startswith("pbkdf2_sha256$")
        assert len(h.split("$")) == 4

    def test_roundtrip_ok(self):
        h = passwords.hash_password("Correct-Horse-1")
        assert passwords.verify_password("Correct-Horse-1", h) is True

    def test_wrong_password(self):
        h = passwords.hash_password("Correct-Horse-1")
        assert passwords.verify_password("wrong", h) is False

    def test_salt_is_random(self):
        assert passwords.hash_password("x") != passwords.hash_password("x")

    def test_empty_stored_is_false(self):
        assert passwords.verify_password("x", "") is False


class TestLegacyCompat:
    def test_legacy_sha256_verifies(self):
        legacy = hashlib.sha256(b"oldpass").hexdigest()
        assert passwords.verify_password("oldpass", legacy) is True
        assert passwords.verify_password("nope", legacy) is False

    def test_needs_rehash(self):
        legacy = hashlib.sha256(b"oldpass").hexdigest()
        assert passwords.needs_rehash(legacy) is True
        assert passwords.needs_rehash(passwords.hash_password("oldpass")) is False


class TestIntegration:
    def test_authconfig_new_hash(self):
        cfg = AuthConfig(password_hash=passwords.hash_password("pw12345"))
        assert cfg.verify_password("pw12345") is True
        assert cfg.verify_password("bad") is False

    def test_authconfig_legacy_hash(self):
        cfg = AuthConfig(password_hash=hashlib.sha256(b"pw12345").hexdigest())
        assert cfg.verify_password("pw12345") is True
        assert cfg.verify_password("bad") is False

    def test_config_hash_password_is_salted(self):
        h = CyberHoundConfig.hash_password("pw12345")
        assert h.startswith("pbkdf2_sha256$")
        assert passwords.verify_password("pw12345", h) is True
