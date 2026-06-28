"""
Tests de los checks de hardening.

La mayoría de checks leen ficheros del sistema o ejecutan comandos.
Usamos mocking para aislar la lógica de validación sin depender del SO.
"""
import re
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.core.models import Finding
from cyberhound.scanners.hardening import (
    HardeningFixer,
    check_duplicate_uid0,
    check_empty_passwords,
    check_login_banners,
    check_openssh_version,
    check_password_policy,
    check_sticky_bit_tmp,
    check_umask,
    check_ntp,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_proc(stdout="", stderr="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


# ── check_empty_passwords ──────────────────────────────────────────────────────

class TestCheckEmptyPasswords:

    @pytest.mark.asyncio
    async def test_detects_empty_password(self):
        shadow_content = "root:!:19000:::::::\nuser1::19000:::::::\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=shadow_content
        ):
            findings = await check_empty_passwords()
        assert len(findings) == 1
        assert findings[0].id == "empty_password_user1"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_findings_when_all_locked(self):
        shadow_content = "root:!:19000:::::::\nuser1:$6$hash:19000:::::::\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=shadow_content
        ):
            findings = await check_empty_passwords()
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_returns_info_when_unreadable(self):
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=None
        ):
            findings = await check_empty_passwords()
        assert len(findings) == 1
        assert findings[0].severity == "info"


# ── check_duplicate_uid0 ──────────────────────────────────────────────────────

class TestCheckDuplicateUID0:

    @pytest.mark.asyncio
    async def test_detects_non_root_uid0(self):
        passwd = "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/:/bin/bash\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=passwd
        ):
            findings = await check_duplicate_uid0()
        assert len(findings) == 1
        assert findings[0].id == "duplicate_uid0_backdoor"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_findings_with_only_root(self):
        passwd = "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000::/home/user1:/bin/bash\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=passwd
        ):
            findings = await check_duplicate_uid0()
        assert len(findings) == 0


# ── check_sticky_bit_tmp ──────────────────────────────────────────────────────

class TestCheckStickyBit:

    @pytest.mark.asyncio
    async def test_detects_missing_sticky_bit(self):
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o777  # sin sticky bit
        with patch("cyberhound.scanners.hardening.Path") as mock_path:
            mock_path.return_value.stat.return_value = mock_stat
            findings = await check_sticky_bit_tmp()
        assert len(findings) == 1
        assert findings[0].id == "tmp_no_sticky_bit"

    @pytest.mark.asyncio
    async def test_ok_with_sticky_bit(self):
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o1777  # con sticky bit
        with patch("pathlib.Path.stat", return_value=mock_stat):
            findings = await check_sticky_bit_tmp()
        assert len(findings) == 0


# ── check_umask ───────────────────────────────────────────────────────────────

class TestCheckUmask:

    @pytest.mark.asyncio
    async def test_detects_umask_022(self):
        content = "# Default umask\numask 022\nexport PATH"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=content
        ):
            findings = await check_umask()
        assert len(findings) >= 1
        assert any("022" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_with_027(self):
        content = "umask 027"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=content
        ):
            findings = await check_umask()
        assert len(findings) == 0


# ── check_login_banners ───────────────────────────────────────────────────────

class TestCheckLoginBanners:

    @pytest.mark.asyncio
    async def test_detects_empty_banner(self):
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=""
        ):
            findings = await check_login_banners()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_no_findings_with_proper_banner(self):
        content = "Acceso restringido. Toda actividad es registrada y supervisada."
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=content
        ):
            findings = await check_login_banners()
        assert len(findings) == 0


# ── check_openssh_version ─────────────────────────────────────────────────────

class TestCheckOpenSSHVersion:

    @pytest.mark.asyncio
    async def test_detects_regresshion_vulnerability(self):
        proc = make_proc(stderr="OpenSSH_9.6p1 Ubuntu-3ubuntu13.3")
        with patch(
            "cyberhound.scanners.hardening.run_command",
            new_callable=AsyncMock, return_value=proc
        ):
            findings = await check_openssh_version()
        assert len(findings) >= 1
        assert any("CVE-2024-6387" in f.id.upper() or "regresshion" in f.description.lower()
                   for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_for_latest_version(self):
        proc = make_proc(stderr="OpenSSH_9.9p1")
        with patch(
            "cyberhound.scanners.hardening.run_command",
            new_callable=AsyncMock, return_value=proc
        ):
            findings = await check_openssh_version()
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_findings_when_version_unparseable(self):
        proc = make_proc(stderr="")
        with patch(
            "cyberhound.scanners.hardening.run_command",
            new_callable=AsyncMock, return_value=proc
        ):
            findings = await check_openssh_version()
        assert len(findings) == 0


# ── check_password_policy ─────────────────────────────────────────────────────

class TestCheckPasswordPolicy:

    @pytest.mark.asyncio
    async def test_detects_too_long_max_days(self):
        content = "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\nLOGIN_RETRIES 5\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=content
        ):
            findings = await check_password_policy()
        assert any("PASS_MAX_DAYS" in f.id for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_with_good_policy(self):
        content = "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nLOGIN_RETRIES 5\n"
        with patch(
            "cyberhound.scanners.hardening.read_file_async",
            new_callable=AsyncMock, return_value=content
        ):
            findings = await check_password_policy()
        assert len(findings) == 0


# ── check_ntp ─────────────────────────────────────────────────────────────────

class TestCheckNTP:

    @pytest.mark.asyncio
    async def test_detects_missing_ntp(self):
        proc_inactive = make_proc(stdout="inactive")
        proc_timedatectl = make_proc(stdout="NTP service: inactive")
        with patch("cyberhound.scanners.hardening.command_exists", return_value=False), \
             patch("cyberhound.scanners.hardening.run_command",
                   new_callable=AsyncMock, return_value=proc_timedatectl):
            findings = await check_ntp()
        assert len(findings) == 1
        assert findings[0].id == "no_ntp"

    @pytest.mark.asyncio
    async def test_ok_when_chrony_active(self):
        proc_active = make_proc(stdout="active")
        with patch("cyberhound.scanners.hardening.command_exists", return_value=True), \
             patch("cyberhound.scanners.hardening.run_command",
                   new_callable=AsyncMock, return_value=proc_active):
            findings = await check_ntp()
        assert len(findings) == 0


# ── HardeningFixer ────────────────────────────────────────────────────────────

class TestHardeningFixer:

    @pytest.mark.asyncio
    async def test_dry_run_returns_ok_without_executing(self):
        fixer = HardeningFixer(dry_run=True)
        f = Finding(
            id="fw_ufw_inactive", category="firewall", severity="critical",
            title="UFW inactivo", description="", remediation="ufw enable",
            auto_fix=True,
        )
        ok, msg = await fixer.fix(f)
        assert ok
        assert "[DRY-RUN]" in msg

    @pytest.mark.asyncio
    async def test_unknown_finding_returns_false(self):
        fixer = HardeningFixer()
        f = Finding(
            id="unknown_finding_xyz", category="test", severity="low",
            title="Unknown", description="", remediation="",
        )
        ok, msg = await fixer.fix(f)
        assert not ok
        assert "Sin fix" in msg

    @pytest.mark.asyncio
    async def test_strips_remote_prefix(self):
        """El fixer debe quitar el prefijo '192.168.1.1::' del finding ID."""
        fixer = HardeningFixer(dry_run=True)
        f = Finding(
            id="192.168.1.1::fw_ufw_inactive", category="firewall", severity="critical",
            title="UFW", description="", remediation="ufw enable", auto_fix=True,
        )
        ok, msg = await fixer.fix(f)
        assert ok  # DRY-RUN debe funcionar igualmente

    @pytest.mark.asyncio
    async def test_fix_sticky_bit(self):
        fixer = HardeningFixer()
        f = Finding(
            id="tmp_no_sticky_bit", category="filesystem", severity="high",
            title="No sticky bit", description="", remediation="chmod +t /tmp",
            auto_fix=True,
        )
        proc = make_proc(returncode=0)
        with patch(
            "cyberhound.scanners.hardening.run_command",
            new_callable=AsyncMock, return_value=proc
        ):
            ok, msg = await fixer.fix(f)
        assert ok
