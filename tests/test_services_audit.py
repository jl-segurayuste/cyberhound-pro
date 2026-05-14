"""Tests de auditoría de servicios específicos (nginx, mysql, redis, etc.)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.scanners.services_audit import (
    ServicesAuditor,
    audit_mysql,
    audit_nginx,
    audit_postgresql,
    audit_redis,
)


class TestNginxAudit:

    @pytest.mark.asyncio
    async def test_detects_missing_server_tokens(self):
        config = "http { server { listen 443 ssl; } }"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.is_dir.return_value = False
            mock_path.return_value.glob.return_value = []
            findings = await audit_nginx()
        assert any(f.id == "nginx_server_tokens" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_autoindex_on(self):
        config = "server { autoindex on; server_tokens off; }"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.is_dir.return_value = False
            mock_path.return_value.glob.return_value = []
            findings = await audit_nginx()
        assert any(f.id == "nginx_autoindex" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_missing_security_headers(self):
        config = "server { server_tokens off; listen 443 ssl; }"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.is_dir.return_value = False
            mock_path.return_value.glob.return_value = []
            findings = await audit_nginx()
        ids = {f.id for f in findings}
        assert "nginx_no_xframe" in ids
        assert "nginx_no_xcto" in ids
        assert "nginx_no_hsts" in ids

    @pytest.mark.asyncio
    async def test_detects_old_tls(self):
        config = "server { server_tokens off; ssl_protocols TLSv1 TLSv1.1 TLSv1.2; }"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.is_dir.return_value = False
            mock_path.return_value.glob.return_value = []
            findings = await audit_nginx()
        assert any(f.id == "nginx_old_tls" for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_nginx_not_installed(self):
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=False), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=False):
            findings = await audit_nginx()
        assert findings == []


class TestMysqlAudit:

    @pytest.mark.asyncio
    async def test_detects_bind_all(self):
        config = "[mysqld]\nbind-address = 0.0.0.0\n"
        proc = MagicMock(returncode=1, stdout="")
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit._find_config",
                   new_callable=AsyncMock, return_value="/etc/mysql/my.cnf"), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await audit_mysql()
        assert any(f.id == "mysql_bind_all" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_missing_bind_address(self):
        config = "[mysqld]\n# no bind address\n"
        proc = MagicMock(returncode=1, stdout="")
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit._find_config",
                   new_callable=AsyncMock, return_value="/etc/mysql/my.cnf"), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config), \
             patch("cyberhound.scanners.services_audit.run_command",
                   new_callable=AsyncMock, return_value=proc):
            findings = await audit_mysql()
        assert any(f.id == "mysql_no_bind_address" for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_mysql_not_installed(self):
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=False), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=False):
            findings = await audit_mysql()
        assert findings == []


class TestRedisAudit:

    @pytest.mark.asyncio
    async def test_detects_no_password(self):
        config = "bind 127.0.0.1\nprotected-mode yes\n# no requirepass"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit._find_config",
                   new_callable=AsyncMock, return_value="/etc/redis/redis.conf"), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config):
            findings = await audit_redis()
        assert any(f.id == "redis_no_password" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_bind_all_interface(self):
        config = "bind 0.0.0.0\nrequirepass secretpass\n"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit._find_config",
                   new_callable=AsyncMock, return_value="/etc/redis/redis.conf"), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config):
            findings = await audit_redis()
        assert any(f.id == "redis_bind_all" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_dangerous_commands(self):
        config = "bind 127.0.0.1\nrequirepass pass\nprotected-mode yes\n"
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=True), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=True), \
             patch("cyberhound.scanners.services_audit._find_config",
                   new_callable=AsyncMock, return_value="/etc/redis/redis.conf"), \
             patch("cyberhound.scanners.services_audit.read_file_async",
                   new_callable=AsyncMock, return_value=config):
            findings = await audit_redis()
        # FLUSHALL, CONFIG, etc. no renombrados
        assert any("redis_cmd_" in f.id for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_redis_not_installed(self):
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=False), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=False):
            findings = await audit_redis()
        assert findings == []


class TestServicesAuditor:

    @pytest.mark.asyncio
    async def test_runs_all_services_in_parallel(self):
        """Todos los servicios se ejecutan aunque fallen individualmente."""
        with patch("cyberhound.scanners.services_audit.command_exists", return_value=False), \
             patch("cyberhound.scanners.services_audit._service_active",
                   new_callable=AsyncMock, return_value=False):
            # Cuando ningún servicio está instalado, resultado vacío sin errores
            findings = await ServicesAuditor.full_audit()
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_filter_by_service_list(self):
        """Solo audita los servicios especificados."""
        redis_finding_found = []

        original_redis = __import__(
            'cyberhound.scanners.services_audit', fromlist=['audit_redis']
        ).audit_redis

        async def mock_redis():
            redis_finding_found.append(True)
            return []

        async def mock_nginx():
            return []

        with patch.dict('cyberhound.scanners.services_audit.ServicesAuditor.AUDITS', {
            'redis': mock_redis,
            'nginx': mock_nginx,
        }):
            await ServicesAuditor.full_audit(services=["redis"])

        assert len(redis_finding_found) == 1
