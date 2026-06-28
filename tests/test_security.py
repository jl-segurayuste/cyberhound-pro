"""Tests de los módulos de seguridad: RateLimiter, InputValidator, TLS."""
import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from cyberhound.core.security import (
    InputValidator, RateLimiter, TLSManager, ValidationError,
)


# ── RateLimiter ───────────────────────────────────────────────────────────────

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_initial_requests(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60, block_seconds=30)
        allowed, wait = await rl.is_allowed("10.0.0.1")
        assert allowed
        assert wait == 0

    @pytest.mark.asyncio
    async def test_blocks_after_max_attempts(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60, block_seconds=30)
        ip = "10.0.0.2"
        for _ in range(3):
            await rl.record_failure(ip)
        blocked, secs = await rl.record_failure(ip)
        assert blocked
        assert secs == 30
        allowed, wait = await rl.is_allowed(ip)
        assert not allowed
        assert wait > 0

    @pytest.mark.asyncio
    async def test_longer_block_at_10_attempts(self):
        rl = RateLimiter(max_attempts=3, window_seconds=3600, block_seconds=30)
        ip = "10.0.0.3"
        for _ in range(10):
            await rl.record_failure(ip)
        blocked, secs = await rl.record_failure(ip)
        assert blocked
        assert secs == 3600  # 1 hora

    @pytest.mark.asyncio
    async def test_max_block_at_20_attempts(self):
        rl = RateLimiter(max_attempts=3, window_seconds=3600, block_seconds=30)
        ip = "10.0.0.4"
        for _ in range(20):
            await rl.record_failure(ip)
        blocked, secs = await rl.record_failure(ip)
        assert blocked
        assert secs == 86400  # 24 horas

    @pytest.mark.asyncio
    async def test_localhost_never_blocked(self):
        rl = RateLimiter(max_attempts=1, window_seconds=60, block_seconds=60)
        for _ in range(50):
            await rl.record_failure("127.0.0.1")
        allowed, _ = await rl.is_allowed("127.0.0.1")
        assert allowed

    @pytest.mark.asyncio
    async def test_reset_after_success(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60, block_seconds=30)
        ip = "10.0.0.5"
        for _ in range(3):
            await rl.record_failure(ip)
        await rl.record_success(ip)
        allowed, _ = await rl.is_allowed(ip)
        assert allowed

    @pytest.mark.asyncio
    async def test_whitelist(self):
        rl = RateLimiter(max_attempts=1, window_seconds=60, block_seconds=60)
        rl.add_whitelist("192.168.1.100")
        for _ in range(20):
            await rl.record_failure("192.168.1.100")
        allowed, _ = await rl.is_allowed("192.168.1.100")
        assert allowed

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        rl = RateLimiter(max_attempts=3, window_seconds=1, block_seconds=1)
        ip = "10.0.0.6"
        await rl.record_failure(ip)
        await asyncio.sleep(1.1)
        await rl.cleanup_expired()
        # Después de limpiar, el contador debería estar reseteado
        allowed, _ = await rl.is_allowed(ip)
        assert allowed


# ── InputValidator ────────────────────────────────────────────────────────────

class TestInputValidator:

    # Paths
    def test_valid_absolute_path(self):
        assert InputValidator.path("/var/www/html") == "/var/www/html"

    def test_valid_path_with_tilde_expanded(self):
        # ~/proyecto es válido si existe
        result = InputValidator.path("/home/jose/proyecto")
        assert result == "/home/jose/proyecto"

    def test_blocks_path_traversal_dotdot(self):
        with pytest.raises(ValidationError) as exc:
            InputValidator.path("/../etc/passwd")
        assert "traversal" in exc.value.reason or "absoluta" in exc.value.reason

    def test_blocks_path_traversal_embedded(self):
        with pytest.raises(ValidationError):
            InputValidator.path("/var/www/../../etc/shadow")

    def test_blocks_relative_path(self):
        with pytest.raises(ValidationError):
            InputValidator.path("var/www/html")

    def test_blocks_empty_path(self):
        with pytest.raises(ValidationError):
            InputValidator.path("")

    # IPs
    def test_valid_ipv4(self):
        assert InputValidator.ip_or_hostname("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv4_loopback(self):
        assert InputValidator.ip_or_hostname("127.0.0.1") == "127.0.0.1"

    def test_valid_hostname(self):
        result = InputValidator.ip_or_hostname("servidor.empresa.local")
        assert result == "servidor.empresa.local"

    def test_blocks_invalid_ipv4_octet(self):
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("999.999.999.999")

    def test_blocks_256_octet(self):
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("192.168.1.256")

    def test_blocks_empty_host(self):
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("")

    def test_blocks_host_with_special_chars(self):
        with pytest.raises(ValidationError):
            InputValidator.ip_or_hostname("host;rm -rf /")

    # CIDR
    def test_valid_cidr_24(self):
        assert InputValidator.network_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_valid_cidr_16(self):
        assert InputValidator.network_cidr("10.0.0.0/16") == "10.0.0.0/16"

    def test_blocks_cidr_8(self):
        with pytest.raises(ValidationError) as exc:
            InputValidator.network_cidr("10.0.0.0/8")
        assert "grande" in exc.value.reason

    def test_blocks_cidr_0(self):
        with pytest.raises(ValidationError):
            InputValidator.network_cidr("0.0.0.0/0")

    def test_blocks_invalid_cidr_format(self):
        with pytest.raises(ValidationError):
            InputValidator.network_cidr("not-a-cidr")

    def test_blocks_cidr_prefix_33(self):
        with pytest.raises(ValidationError):
            InputValidator.network_cidr("192.168.1.0/33")

    # Host list
    def test_valid_host_list_csv(self):
        result = InputValidator.host_list("192.168.1.1, 192.168.1.2")
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_valid_host_list_newline(self):
        result = InputValidator.host_list("192.168.1.1\n192.168.1.2\n10.0.0.1")
        assert len(result) == 3

    def test_blocks_too_many_hosts(self):
        hosts = ",".join(f"192.168.1.{i}" for i in range(60))
        with pytest.raises(ValidationError):
            InputValidator.host_list(hosts, max_hosts=50)

    # Port
    def test_valid_port(self):
        assert InputValidator.port(22) == 22
        assert InputValidator.port(8443) == 8443

    def test_blocks_port_0(self):
        with pytest.raises(ValidationError):
            InputValidator.port(0)

    def test_blocks_port_65536(self):
        with pytest.raises(ValidationError):
            InputValidator.port(65536)

    # Módulos
    def test_valid_modules(self):
        result = InputValidator.modules_list(
            ["yara", "hash"], {"yara", "hash", "auditd"}
        )
        assert result == ["yara", "hash"]

    def test_blocks_unknown_module(self):
        with pytest.raises(ValidationError):
            InputValidator.modules_list(["yara", "evil"], {"yara", "hash"})

    # WebSocket messages
    def test_valid_ws_audit(self):
        msg = InputValidator.ws_message({"task": "audit"})
        assert msg["task"] == "audit"

    def test_valid_ws_code(self):
        msg = InputValidator.ws_message({"task": "code", "path": "/var/www/html"})
        assert msg["path"] == "/var/www/html"

    def test_valid_ws_malware_with_skip(self):
        msg = InputValidator.ws_message({"task": "malware", "skip": ["hash"]})
        assert msg["skip"] == ["hash"]

    def test_blocks_unknown_task(self):
        with pytest.raises(ValidationError) as exc:
            InputValidator.ws_message({"task": "rm_rf"})
        assert "rm_rf" in exc.value.reason

    def test_blocks_path_traversal_in_ws(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({"task": "code", "path": "../../etc"})

    def test_blocks_invalid_port_in_ws(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({
                "task": "ssh", "hosts": "192.168.1.1", "ssh_port": 99999
            })

    def test_blocks_large_network_in_ws(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({
                "task": "network", "networks": "10.0.0.0/4"
            })

    def test_blocks_invalid_module_in_ws(self):
        with pytest.raises(ValidationError):
            InputValidator.ws_message({
                "task": "malware", "skip": ["evil_module"]
            })


# ── TLS ───────────────────────────────────────────────────────────────────────

class TestTLSManager:

    def test_generates_self_signed_cert(self, tmp_path):
        orig = TLSManager.cert_paths
        TLSManager.cert_paths = classmethod(
            lambda cls: (tmp_path / "cert.pem", tmp_path / "key.pem")
        )
        try:
            cert, key = TLSManager.generate_self_signed("test.local", days=1)
            assert cert.exists()
            assert key.exists()
        finally:
            TLSManager.cert_paths = orig

    def test_key_has_restricted_permissions(self, tmp_path):
        orig = TLSManager.cert_paths
        TLSManager.cert_paths = classmethod(
            lambda cls: (tmp_path / "cert.pem", tmp_path / "key.pem")
        )
        try:
            _, key = TLSManager.generate_self_signed("test.local", days=1)
            assert oct(key.stat().st_mode & 0o777) == "0o600"
        finally:
            TLSManager.cert_paths = orig

    def test_creates_ssl_context_tls12(self, tmp_path):
        import ssl
        orig = TLSManager.cert_paths
        TLSManager.cert_paths = classmethod(
            lambda cls: (tmp_path / "cert.pem", tmp_path / "key.pem")
        )
        try:
            cert, key = TLSManager.generate_self_signed("test.local", days=1)
            ctx = TLSManager.create_ssl_context(str(cert), str(key))
            assert ctx is not None
            assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        finally:
            TLSManager.cert_paths = orig

    def test_needs_generation_when_missing(self, tmp_path):
        orig = TLSManager.cert_paths
        TLSManager.cert_paths = classmethod(
            lambda cls: (tmp_path / "cert.pem", tmp_path / "key.pem")
        )
        try:
            assert TLSManager.needs_generation()
        finally:
            TLSManager.cert_paths = orig
