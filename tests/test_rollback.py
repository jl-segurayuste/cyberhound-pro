"""Tests del rollback de remediaciones de hardening."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyberhound.core.models import Finding
from cyberhound.core.rollback import (
    Action,
    RollbackEntry,
    RollbackJournal,
    command_undo,
    irreversible,
    perform_rollback,
    rollback_finding,
    snapshot_chmod,
    snapshot_file,
)
from cyberhound.scanners.hardening import HardeningFixer


def _proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _fake_runner(calls):
    async def runner(cmd, timeout=60, check=False):
        calls.append(cmd)
        return _proc(0)
    return runner


# ── Snapshots y undo de ficheros ────────────────────────────────────────────────

class TestFileAction:
    async def test_restores_existing_file_content_and_mode(self, tmp_path):
        f = tmp_path / "conf"
        f.write_text("original\n")
        os.chmod(f, 0o600)
        action = snapshot_file(str(f))
        # Mutación posterior
        f.write_text("modificado\n")
        os.chmod(f, 0o644)
        ok, _ = await perform_rollback(RollbackEntry("x", "localhost", "u", 0, "", [action]))
        assert ok
        assert f.read_text() == "original\n"
        assert (os.stat(f).st_mode & 0o7777) == 0o600

    async def test_deletes_file_that_did_not_exist(self, tmp_path):
        f = tmp_path / "nuevo.conf"
        action = snapshot_file(str(f))  # no existe → existed=False
        f.write_text("creado por el fix\n")
        ok, _ = await perform_rollback(RollbackEntry("x", "localhost", "u", 0, "", [action]))
        assert ok
        assert not f.exists()

    async def test_chmod_snapshot_restores_mode(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("x")
        os.chmod(f, 0o644)
        action = snapshot_chmod(str(f))
        os.chmod(f, 0o600)
        ok, _ = await perform_rollback(RollbackEntry("x", "localhost", "u", 0, "", [action]))
        assert ok
        assert (os.stat(f).st_mode & 0o7777) == 0o644


# ── Acciones de servicio / comando / irreversibles ──────────────────────────────

class TestServiceAndCommand:
    async def test_service_restores_disabled_inactive(self):
        calls = []
        a = Action(kind="service", service="firewalld", was_active=False, was_enabled=False)
        ok, _ = await perform_rollback(
            RollbackEntry("x", "localhost", "u", 0, "", [a]), runner=_fake_runner(calls)
        )
        assert ok
        assert ["systemctl", "disable", "firewalld"] in calls
        assert ["systemctl", "stop", "firewalld"] in calls

    async def test_service_restores_enabled_active(self):
        calls = []
        a = Action(kind="service", service="apparmor", was_active=True, was_enabled=True)
        await perform_rollback(
            RollbackEntry("x", "localhost", "u", 0, "", [a]), runner=_fake_runner(calls)
        )
        assert ["systemctl", "enable", "apparmor"] in calls
        assert ["systemctl", "start", "apparmor"] in calls

    async def test_command_undo_runs(self):
        calls = []
        a = command_undo(["passwd", "-u", "bob"])
        ok, _ = await perform_rollback(
            RollbackEntry("x", "localhost", "u", 0, "", [a]), runner=_fake_runner(calls)
        )
        assert ok
        assert ["passwd", "-u", "bob"] in calls

    async def test_irreversible_does_not_fail_global(self):
        a = irreversible("instalación de paquete")
        ok, msgs = await perform_rollback(RollbackEntry("x", "localhost", "u", 0, "", [a]))
        assert ok
        assert any("no reversible" in m for m in msgs)

    async def test_actions_undone_in_reverse_order(self, tmp_path):
        # Restaurar fichero y LUEGO recargar servicio (orden de _fix_ssh).
        calls = []
        f = tmp_path / "sshd_config"
        f.write_text("PermitRootLogin yes\n")
        entry = RollbackEntry("ssh", "localhost", "u", 0, "", [
            command_undo(["systemctl", "reload", "sshd"]),
            snapshot_file(str(f)),
        ])
        f.write_text("PermitRootLogin no\n")
        ok, _ = await perform_rollback(entry, runner=_fake_runner(calls))
        assert ok
        assert f.read_text() == "PermitRootLogin yes\n"
        assert calls == [["systemctl", "reload", "sshd"]]  # el comando corrió tras el fichero


# ── Journal ─────────────────────────────────────────────────────────────────────

class TestJournal:
    def test_entry_roundtrip(self):
        e = RollbackEntry("fid", "localhost", "jose", 123.0, "msg",
                          [Action(kind="chmod", path="x", mode=0o644)])
        e2 = RollbackEntry.from_dict(e.to_dict())
        assert e2.finding_id == "fid"
        assert e2.actions[0].kind == "chmod"
        assert e2.actions[0].mode == 0o644

    def test_append_latest_and_mark(self, tmp_path):
        j = RollbackJournal(tmp_path / "journal.jsonl")
        j.append(RollbackEntry("f1", "localhost", "u", 1.0, "m", [Action(kind="irreversible", note="n")]))
        j.append(RollbackEntry("f1", "localhost", "u", 2.0, "m", [Action(kind="irreversible", note="n")]))
        latest = j.latest_active("f1")
        assert latest is not None and latest.ts == 2.0
        assert len(j.list_active()) == 2
        j.mark_rolled_back(latest)
        # Tras revertir la última, la activa pasa a ser la de ts=1.0
        assert j.latest_active("f1").ts == 1.0
        assert len(j.list_active()) == 1

    def test_latest_active_none_when_absent(self, tmp_path):
        j = RollbackJournal(tmp_path / "journal.jsonl")
        assert j.latest_active("nope") is None


# ── rollback_finding (integración journal + ejecución) ──────────────────────────

class TestRollbackFinding:
    async def test_restores_file_and_marks_entry(self, tmp_path):
        f = tmp_path / "login.defs"
        f.write_text("PASS_MAX_DAYS 99999\n")
        j = RollbackJournal(tmp_path / "journal.jsonl")
        j.append(RollbackEntry("login_defs_PASS_MAX_DAYS", "localhost", "u", 1.0, "m",
                               [snapshot_file(str(f))]))
        f.write_text("PASS_MAX_DAYS 90\n")  # simula el fix aplicado
        ok, _ = await rollback_finding(j, "login_defs_PASS_MAX_DAYS")
        assert ok
        assert f.read_text() == "PASS_MAX_DAYS 99999\n"
        # Ya no queda activa (no se puede revertir dos veces)
        assert j.latest_active("login_defs_PASS_MAX_DAYS") is None

    async def test_no_entry_returns_false(self, tmp_path):
        j = RollbackJournal(tmp_path / "journal.jsonl")
        ok, msg = await rollback_finding(j, "inexistente")
        assert not ok
        assert "No hay" in msg


# ── HardeningFixer registra acciones de reversión ───────────────────────────────

class TestFixerRecordsActions:
    async def test_world_writable_records_chmod(self, tmp_path):
        target = tmp_path / "ww"
        target.write_text("x")
        os.chmod(target, 0o666)
        f = Finding(id="ww_/x", category="filesystem", severity="high",
                    title="", description="", remediation="", file_path=str(target))
        fixer = HardeningFixer()
        with patch("cyberhound.scanners.hardening.run_command",
                   new_callable=AsyncMock, return_value=_proc(0)):
            ok, _ = await fixer.fix(f)
        assert ok
        assert any(a.kind == "chmod" and a.path == str(target) for a in fixer.rollback_actions)

    async def test_login_banner_roundtrip(self, tmp_path):
        """Fin a fin: aplicar el banner registra snapshot; revertir restaura el original."""
        issue = tmp_path / "issue"
        issue.write_text("contenido original\n")
        f = Finding(id="no_banner_/etc/issue", category="auth", severity="low",
                    title="", description="", remediation="", file_path=str(issue))
        fixer = HardeningFixer()
        ok, _ = await fixer.fix(f)
        assert ok
        assert "AVISO" in issue.read_text()        # el fix se aplicó
        assert fixer.rollback_actions               # registró cómo revertir
        ok2, _ = await perform_rollback(
            RollbackEntry("no_banner", "localhost", "u", 0, "", fixer.rollback_actions))
        assert ok2
        assert issue.read_text() == "contenido original\n"

    async def test_dry_run_records_nothing(self):
        f = Finding(id="fw_ufw_inactive", category="firewall", severity="critical",
                    title="", description="", remediation="ufw enable", auto_fix=True)
        fixer = HardeningFixer(dry_run=True)
        ok, _ = await fixer.fix(f)
        assert ok
        assert fixer.rollback_actions == []

    async def test_package_install_marked_irreversible(self):
        f = Finding(id="no_auditd", category="audit", severity="medium",
                    title="", description="", remediation="")
        fixer = HardeningFixer()
        with patch("cyberhound.scanners.hardening.run_command",
                   new_callable=AsyncMock, return_value=_proc(0)):
            await fixer.fix(f)
        assert any(a.kind == "irreversible" for a in fixer.rollback_actions)
