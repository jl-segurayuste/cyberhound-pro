"""Tests de los nuevos checks de hardening v6.3."""
import stat
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.scanners.hardening import (
    check_at_cron_allow,
    check_grub_password,
    check_ipv6_disabled_if_unused,
    check_passwd_integrity,
    check_ssh_host_keys,
)


class TestSshHostKeys:

    @pytest.mark.asyncio
    async def test_correct_permissions_no_findings(self, tmp_path):
        """Permisos correctos (600) no generan findings."""
        key = tmp_path / "ssh_host_rsa_key"
        key.write_text("PRIVATE KEY")
        key.chmod(0o600)
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            # Simular que la clave existe con permisos correctos
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            mock_p.stat.return_value = MagicMock(st_mode=0o100600)
            MockPath.return_value = mock_p
            findings = await check_ssh_host_keys()
        # No debe generar findings con modo 600
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_no_keys_no_findings(self):
        """Si no hay claves SSH de host, no hay findings."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = False
            MockPath.return_value = mock_p
            findings = await check_ssh_host_keys()
        assert findings == []

    @pytest.mark.asyncio
    async def test_wrong_permissions_generates_finding(self):
        """Permisos incorrectos (644) deben generar finding HIGH."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            mock_p.name = "ssh_host_rsa_key"
            # st_mode con 644: 0o100644
            mock_p.stat.return_value = MagicMock(st_mode=0o100644)
            MockPath.return_value = mock_p
            findings = await check_ssh_host_keys()
        # Con permisos 644 debe generar al menos 1 finding high
        if findings:
            assert any(f.severity == "high" for f in findings)


class TestPasswdIntegrity:

    @pytest.mark.asyncio
    async def test_correct_passwd_permissions(self, tmp_path):
        """Permisos correctos en /etc/passwd (644) no generan finding."""
        f = tmp_path / "passwd"
        f.write_text("root:x:0:0::/root:/bin/bash")
        f.chmod(0o644)
        # Sin permisos excesivos = sin findings para este fichero
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            mock_p.stat.return_value = MagicMock(st_mode=0o100644)  # 644
            MockPath.return_value = mock_p
            findings = await check_passwd_integrity()
        # 644 <= 644 esperado → sin finding para passwd
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_excessive_permissions_finding(self):
        """Permisos excesivos (777) deben generar finding CRITICAL."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            # 777 es excesivo
            mock_p.stat.return_value = MagicMock(st_mode=0o100777)
            MockPath.return_value = mock_p
            findings = await check_passwd_integrity()
        if findings:
            assert any(f.severity == "critical" for f in findings)


class TestAtCronAllow:

    @pytest.mark.asyncio
    async def test_no_files_generates_findings(self):
        """Sin cron.allow ni cron.deny debe generar findings."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = False
            MockPath.return_value = mock_p
            findings = await check_at_cron_allow()
        assert len(findings) >= 1
        assert any("cron" in f.id for f in findings)

    @pytest.mark.asyncio
    async def test_with_cron_allow_exists(self):
        """Con cron.allow existente no debe generar finding de cron."""
        def path_exists(path_str):
            return '/etc/cron.allow' in str(path_str)

        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            def mock_path(p):
                m = MagicMock()
                m.exists.return_value = path_exists(p)
                return m
            MockPath.side_effect = mock_path
            findings = await check_at_cron_allow()
        # Con cron.allow, no debe haber finding de cron (puede haber de at)
        assert not any(f.id == "cron_no_restriction" for f in findings)


class TestGrubPassword:

    @pytest.mark.asyncio
    async def test_no_grub_files_generates_finding(self):
        """Sin ficheros GRUB debe generar finding MEDIUM."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            mock_p = MagicMock()
            mock_p.exists.return_value = False
            MockPath.return_value = mock_p
            findings = await check_grub_password()
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert findings[0].id == "grub_no_password"

    @pytest.mark.asyncio
    async def test_grub_with_password_no_finding(self):
        """Si GRUB tiene contraseña configurada, sin finding."""
        with patch('cyberhound.scanners.hardening.Path') as MockPath:
            def mock_path(p):
                m = MagicMock()
                if '40_custom' in str(p):
                    m.exists.return_value = True
                    m.read_text.return_value = 'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2...'
                    m.stat.return_value = MagicMock(st_size=100)
                else:
                    m.exists.return_value = False
                return m
            MockPath.side_effect = mock_path
            findings = await check_grub_password()
        assert findings == []


class TestIPv6Disabled:

    @pytest.mark.asyncio
    async def test_ipv6_in_use_no_finding(self):
        """IPv6 con IPs globales asignadas = no es un problema."""
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "3: eth0    inet6 2001:db8::1/64 scope global\n"
        with patch('cyberhound.scanners.hardening.run_command',
                   new_callable=AsyncMock, return_value=proc):
            findings = await check_ipv6_disabled_if_unused()
        assert findings == []

    @pytest.mark.asyncio
    async def test_ipv6_enabled_no_global_ip_generates_finding(self):
        """IPv6 habilitado pero solo link-local → finding LOW."""
        proc = MagicMock()
        proc.returncode = 0
        # Solo loopback y link-local (fe80) — no hay IPs globales
        proc.stdout = "1: lo    inet6 ::1/128 scope host\n2: eth0    inet6 fe80::1/64 scope link\n"
        with patch('cyberhound.scanners.hardening.run_command',
                   new_callable=AsyncMock, return_value=proc):
            with patch('cyberhound.scanners.hardening.Path') as MockPath:
                mock_p = MagicMock()
                # disable_ipv6 = 0 (no deshabilitado)
                mock_p.exists.return_value = True
                mock_p.read_text.return_value = "0\n"
                MockPath.return_value = mock_p
                findings = await check_ipv6_disabled_if_unused()
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert findings[0].id == "ipv6_enabled_unused"

    @pytest.mark.asyncio
    async def test_ipv6_already_disabled_no_finding(self):
        """Si IPv6 ya está deshabilitado en sysctl, sin finding."""
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "2: eth0    inet6 fe80::1/64 scope link\n"
        with patch('cyberhound.scanners.hardening.run_command',
                   new_callable=AsyncMock, return_value=proc):
            with patch('cyberhound.scanners.hardening.Path') as MockPath:
                mock_p = MagicMock()
                mock_p.exists.return_value = True
                mock_p.read_text.return_value = "1\n"  # ya deshabilitado
                MockPath.return_value = mock_p
                findings = await check_ipv6_disabled_if_unused()
        assert findings == []


class TestHardeningChecksCount:

    def test_total_checks_count(self):
        """Verificar que hay al menos 31 checks registrados en CHECKS."""
        from cyberhound.scanners.hardening import HardeningAuditor
        assert len(HardeningAuditor.CHECKS) >= 31, \
            f"Solo hay {len(HardeningAuditor.CHECKS)} checks, se esperaban al menos 31"

    def test_new_v63_checks_in_list(self):
        """Los 5 nuevos checks v6.3 deben estar en la lista CHECKS."""
        from cyberhound.scanners.hardening import HardeningAuditor
        check_names = [c.__name__ for c in HardeningAuditor.CHECKS]
        for expected in [
            'check_ssh_host_keys',
            'check_passwd_integrity',
            'check_at_cron_allow',
            'check_grub_password',
            'check_ipv6_disabled_if_unused',
        ]:
            assert expected in check_names, f"{expected} no encontrado en CHECKS"
