"""El detector de CVEs de OpenSSH no debe dar falso positivo si la distro
backporteó el parche (mismo número de versión upstream en el banner)."""
import glob as glob_mod
import gzip
import shutil as shutil_mod

import pytest

from cyberhound.scanners import hardening


@pytest.mark.asyncio
async def test_patched_detected_via_changelog(tmp_path, monkeypatch):
    gz = tmp_path / "changelog.Debian.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write("openssh (1:9.6p1-3ubuntu13.16) noble-security\n"
                 "  * Fix CVE-2024-6387.patch: regreSSHion.\n")
    monkeypatch.setattr(glob_mod, "glob", lambda pattern: [str(gz)])
    assert await hardening._openssh_patched_via_distro("CVE-2024-6387") is True


@pytest.mark.asyncio
async def test_not_patched_when_absent(tmp_path, monkeypatch):
    gz = tmp_path / "changelog.Debian.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write("openssh (1:9.6p1-3ubuntu13.1) noble\n  * Otra cosa.\n")
    monkeypatch.setattr(glob_mod, "glob", lambda pattern: [str(gz)])
    monkeypatch.setattr(shutil_mod, "which", lambda _: None)  # sin rpm
    assert await hardening._openssh_patched_via_distro("CVE-2024-6387") is False


@pytest.mark.asyncio
async def test_no_changelog_no_rpm(monkeypatch):
    monkeypatch.setattr(glob_mod, "glob", lambda pattern: [])
    monkeypatch.setattr(shutil_mod, "which", lambda _: None)
    assert await hardening._openssh_patched_via_distro("CVE-2024-6387") is False
