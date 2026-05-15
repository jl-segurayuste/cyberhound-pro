"""Tests de cuarentena de ficheros y SBOM."""
import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyberhound.core.quarantine import (
    QUARANTINE_KEY,
    _xor_bytes,
    delete_quarantined,
    list_quarantine,
    quarantine_file,
    quarantine_stats,
    restore_file,
)
from cyberhound.scanners.sbom import SBOM, SBOMGenerator


# ── Cuarentena ────────────────────────────────────────────────────────────────

@pytest.fixture
def quarantine_env(tmp_path, monkeypatch):
    """Aísla la cuarentena en un directorio temporal."""
    q_dir  = tmp_path / "quarantine"
    q_meta = q_dir / "index.json"
    q_dir.mkdir()
    monkeypatch.setattr("cyberhound.core.quarantine.QUARANTINE_DIR", q_dir)
    monkeypatch.setattr("cyberhound.core.quarantine.QUARANTINE_META", q_meta)
    return q_dir


@pytest.fixture
def malicious_file(tmp_path):
    """Crea un fichero de prueba para cuarentena."""
    f = tmp_path / "malware.sh"
    f.write_text("#!/bin/bash\nrm -rf /\n")
    return f


class TestQuarantine:

    def test_xor_roundtrip(self):
        data = b"Hello World! This is a test."
        encrypted = _xor_bytes(data, QUARANTINE_KEY)
        decrypted = _xor_bytes(encrypted, QUARANTINE_KEY)
        assert decrypted == data
        assert encrypted != data

    def test_quarantine_moves_file(self, quarantine_env, malicious_file):
        assert malicious_file.exists()
        ok, msg = quarantine_file(
            str(malicious_file), "test_finding", "Test malware", "admin"
        )
        assert ok
        assert not malicious_file.exists()  # original eliminado

    def test_quarantine_creates_encrypted_copy(self, quarantine_env, malicious_file):
        original_content = malicious_file.read_bytes()
        ok, _ = quarantine_file(str(malicious_file), "fid", "title", "admin")
        assert ok
        # Buscar el fichero .quar
        quar_files = list(quarantine_env.glob("*.quar"))
        assert len(quar_files) == 1
        # El contenido debe estar cifrado (diferente al original)
        encrypted = quar_files[0].read_bytes()
        assert encrypted != original_content

    def test_quarantine_records_metadata(self, quarantine_env, malicious_file):
        quarantine_file(str(malicious_file), "find123", "Malware Test", "user1")
        items = list_quarantine()
        assert len(items) == 1
        assert items[0]["finding_id"] == "find123"
        assert items[0]["quarantined_by"] == "user1"
        assert "sha256" in items[0]

    def test_quarantine_nonexistent_file(self, quarantine_env):
        ok, msg = quarantine_file("/nonexistent/file.sh", "fid", "title")
        assert not ok
        assert "no encontrado" in msg.lower()

    def test_restore_verifies_integrity(self, quarantine_env, malicious_file, tmp_path):
        original_content = malicious_file.read_text()
        quarantine_file(str(malicious_file), "fid", "title")
        items = list_quarantine()
        name = items[0]["quarantine_name"]
        # Restaurar a una nueva ruta
        restore_path = str(tmp_path / "restored.sh")
        ok, msg = restore_file(name, restore_path)
        assert ok
        restored = Path(restore_path)
        assert restored.exists()
        assert restored.read_text() == original_content

    def test_restore_rejects_tampered_file(self, quarantine_env, malicious_file, tmp_path):
        quarantine_file(str(malicious_file), "fid", "title")
        items = list_quarantine()
        name = items[0]["quarantine_name"]
        # Corromper el fichero en cuarentena
        quar_path = quarantine_env / name
        quar_path.write_bytes(b"corrupted data")
        ok, msg = restore_file(name, str(tmp_path / "restored.sh"))
        assert not ok
        assert "integridad" in msg.lower() or "hash" in msg.lower()

    def test_delete_removes_file(self, quarantine_env, malicious_file):
        quarantine_file(str(malicious_file), "fid", "title")
        items = list_quarantine()
        name = items[0]["quarantine_name"]
        ok, _ = delete_quarantined(name)
        assert ok
        quar_path = quarantine_env / name
        assert not quar_path.exists()

    def test_deleted_not_in_list(self, quarantine_env, malicious_file):
        quarantine_file(str(malicious_file), "fid", "title")
        items = list_quarantine()
        name = items[0]["quarantine_name"]
        delete_quarantined(name)
        remaining = list_quarantine()
        assert len(remaining) == 0

    def test_stats(self, quarantine_env, tmp_path):
        for i in range(3):
            f = tmp_path / f"file{i}.sh"
            f.write_text(f"content {i}")
            quarantine_file(str(f), f"fid{i}", f"title{i}")
        stats = quarantine_stats()
        assert stats["total"] == 3
        assert stats["pending"] == 3
        assert stats["size_bytes"] > 0


# ── SBOM ──────────────────────────────────────────────────────────────────────

class TestSBOM:

    def test_sbom_to_dict_format(self):
        components = [
            {"name": "bash", "version": "5.1.4", "type": "deb", "manager": "dpkg"},
            {"name": "requests", "version": "2.28.0", "type": "python", "manager": "pip"},
        ]
        sbom = SBOM(components)
        d = sbom.to_dict()
        assert d["total"] == 2
        assert "generated_at" in d
        assert "components" in d
        assert "summary" in d
        assert d["summary"]["dpkg"] == 1
        assert d["summary"]["pip"] == 1

    def test_sbom_to_cyclonedx(self):
        components = [
            {"name": "nginx", "version": "1.18.0", "type": "deb", "manager": "dpkg"},
        ]
        sbom = SBOM(components)
        cdx = sbom.to_cyclonedx()
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.4"
        assert len(cdx["components"]) == 1
        assert cdx["components"][0]["name"] == "nginx"

    def test_sbom_cyclonedx_purl(self):
        components = [
            {"name": "requests", "version": "2.28.0", "type": "python", "manager": "pip"},
            {"name": "nginx", "version": "1.18.0", "type": "deb", "manager": "dpkg"},
            {"name": "lodash", "version": "4.17.21", "type": "nodejs", "manager": "npm"},
        ]
        sbom = SBOM(components)
        cdx = sbom.to_cyclonedx()
        purls = [c["purl"] for c in cdx["components"]]
        assert "pkg:pypi/requests@2.28.0" in purls
        assert "pkg:deb/nginx@1.18.0" in purls
        assert "pkg:npm/lodash@4.17.21" in purls

    def test_sbom_to_spdx(self):
        components = [
            {"name": "bash", "version": "5.1.4", "type": "deb", "manager": "dpkg"},
        ]
        sbom = SBOM(components)
        spdx = sbom.to_spdx_basic()
        assert "SPDXVersion: SPDX-2.3" in spdx
        assert "PackageName: bash" in spdx
        assert "PackageVersion: 5.1.4" in spdx

    def test_sbom_diff_detects_added(self):
        sbom1 = SBOM([{"name": "bash", "version": "5.0", "type": "deb"}])
        sbom2 = SBOM([
            {"name": "bash", "version": "5.0", "type": "deb"},
            {"name": "curl", "version": "7.80", "type": "deb"},
        ])
        diff = sbom1.diff(sbom2)
        assert len(diff["added"]) == 1
        assert diff["added"][0]["name"] == "curl"
        assert len(diff["removed"]) == 0

    def test_sbom_diff_detects_removed(self):
        sbom1 = SBOM([
            {"name": "bash", "version": "5.0", "type": "deb"},
            {"name": "old-package", "version": "1.0", "type": "deb"},
        ])
        sbom2 = SBOM([{"name": "bash", "version": "5.0", "type": "deb"}])
        diff = sbom1.diff(sbom2)
        assert len(diff["removed"]) == 1
        assert diff["removed"][0]["name"] == "old-package"

    def test_sbom_diff_detects_updated(self):
        sbom1 = SBOM([{"name": "bash", "version": "5.0", "type": "deb"}])
        sbom2 = SBOM([{"name": "bash", "version": "5.2", "type": "deb"}])
        diff = sbom1.diff(sbom2)
        assert len(diff["updated"]) == 1
        assert diff["updated"][0]["from"] == "5.0"
        assert diff["updated"][0]["to"] == "5.2"

    def test_sbom_diff_empty_when_identical(self):
        components = [{"name": "bash", "version": "5.0", "type": "deb"}]
        sbom = SBOM(components)
        diff = sbom.diff(SBOM(components))
        assert diff["summary"]["added"] == 0
        assert diff["summary"]["removed"] == 0
        assert diff["summary"]["updated"] == 0

    @pytest.mark.asyncio
    async def test_sbom_generator_runs(self):
        """El generador no debe lanzar excepciones aunque los comandos fallen."""
        proc = __import__('unittest.mock', fromlist=['MagicMock']).MagicMock()
        proc.returncode = 1
        proc.stdout = ""
        with patch("cyberhound.scanners.sbom.run_command",
                   new_callable=AsyncMock, return_value=proc):
            sbom = await SBOMGenerator.generate()
        # Sin comandos disponibles, el SBOM puede estar vacío pero no fallar
        assert isinstance(sbom, SBOM)
        assert isinstance(sbom.components, list)

    @pytest.mark.asyncio
    async def test_sbom_kernel_collected(self):
        """El kernel siempre se puede detectar."""
        proc = __import__('unittest.mock', fromlist=['MagicMock']).MagicMock()
        proc.returncode = 0
        proc.stdout = "5.15.0-generic\n"
        with patch("cyberhound.scanners.sbom.run_command",
                   new_callable=AsyncMock, return_value=proc), \
             patch("cyberhound.scanners.sbom.command_exists", return_value=True):
            from cyberhound.scanners.sbom import collect_kernel
            components = await collect_kernel()
        assert len(components) == 1
        assert components[0]["name"] == "linux-kernel"
        assert "5.15" in components[0]["version"]
