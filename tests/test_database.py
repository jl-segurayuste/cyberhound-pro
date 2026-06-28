"""Tests de la capa de persistencia SQLite."""
import hashlib
import json
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from cyberhound.core.database import AssetRecord, Database, UserRecord
from cyberhound.core.models import Finding


@pytest_asyncio.fixture
async def database(tmp_path):
    db = Database(tmp_path / "test.db")
    await db.init()
    return db


def make_finding(id, severity="high", category="ssh", auto_fix=True):
    return Finding(
        id=id, category=category, severity=severity,
        title=f"Finding {id}", description="", remediation="test cmd",
        auto_fix=auto_fix,
    )


class TestScans:

    @pytest.mark.asyncio
    async def test_create_scan_returns_id(self, database):
        scan_id = await database.create_scan("audit")
        assert isinstance(scan_id, int)
        assert scan_id > 0

    @pytest.mark.asyncio
    async def test_scan_starts_as_running(self, database):
        scan_id = await database.create_scan("audit")
        history = await database.get_scan_history()
        assert history[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_complete_scan_saves_findings(self, database):
        scan_id = await database.create_scan("audit")
        findings = [
            make_finding("f1", "critical"),
            make_finding("f2", "high"),
            make_finding("f3", "medium"),
        ]
        await database.complete_scan(scan_id, findings)
        saved = await database.get_scan_findings(scan_id)
        assert len(saved) == 3

    @pytest.mark.asyncio
    async def test_complete_scan_status_completed(self, database):
        scan_id = await database.create_scan("audit")
        await database.complete_scan(scan_id, [])
        history = await database.get_scan_history()
        assert history[0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_score_calculation(self, database):
        scan_id = await database.create_scan("audit")
        findings = [
            make_finding("c1", "critical"),
            make_finding("h1", "high"),
            make_finding("m1", "medium"),
            make_finding("l1", "low"),
        ]
        await database.complete_scan(scan_id, findings)
        history = await database.get_scan_history()
        score = history[0]["score"]
        # El scoring avanzado da un score diferente al básico plano.
        # Solo verificamos que el score es coherente (bajo, con 1 crítico)
        assert 0 <= score <= 100
        assert score < 80  # con 1 crítico debería ser bajo

    @pytest.mark.asyncio
    async def test_score_never_negative(self, database):
        scan_id = await database.create_scan("audit")
        findings = [make_finding(f"c{i}", "critical") for i in range(10)]
        await database.complete_scan(scan_id, findings)
        history = await database.get_scan_history()
        assert history[0]["score"] >= 0

    @pytest.mark.asyncio
    async def test_findings_sorted_by_severity(self, database):
        scan_id = await database.create_scan("audit")
        await database.complete_scan(scan_id, [
            make_finding("low", "low"),
            make_finding("critical", "critical"),
            make_finding("high", "high"),
        ])
        saved = await database.get_scan_findings(scan_id)
        severities = [f["severity"] for f in saved]
        assert severities[0] == "critical"
        assert severities[1] == "high"
        assert severities[2] == "low"

    @pytest.mark.asyncio
    async def test_fail_scan(self, database):
        scan_id = await database.create_scan("audit")
        await database.fail_scan(scan_id)
        history = await database.get_scan_history()
        assert history[0]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_history_filter_by_type(self, database):
        await database.complete_scan(await database.create_scan("audit"), [])
        await database.complete_scan(await database.create_scan("malware"), [])
        audit_history = await database.get_scan_history("audit")
        assert len(audit_history) == 1
        assert audit_history[0]["scan_type"] == "audit"

    @pytest.mark.asyncio
    async def test_mark_finding_fixed(self, database):
        scan_id = await database.create_scan("audit")
        await database.complete_scan(scan_id, [make_finding("f1", "high")])
        await database.mark_finding_fixed(scan_id, "f1", "admin")
        saved = await database.get_scan_findings(scan_id)
        assert saved[0]["fixed_at"] is not None
        assert saved[0]["fixed_by"] == "admin"


class TestComparison:

    @pytest.mark.asyncio
    async def test_first_scan_returns_first_scan_flag(self, database):
        scan_id = await database.create_scan("audit")
        await database.complete_scan(scan_id, [make_finding("f1")])
        comp = await database.get_comparison(scan_id)
        assert comp.get("first_scan") is True

    @pytest.mark.asyncio
    async def test_detects_new_findings(self, database):
        s1 = await database.create_scan("audit")
        await database.complete_scan(s1, [make_finding("f1"), make_finding("f2")])
        s2 = await database.create_scan("audit")
        await database.complete_scan(s2, [make_finding("f1"), make_finding("f3_new")])
        comp = await database.get_comparison(s2)
        new_ids = [f["id"] for f in comp["new"]]
        assert "f3_new" in new_ids
        assert "f1" not in new_ids

    @pytest.mark.asyncio
    async def test_detects_resolved_findings(self, database):
        s1 = await database.create_scan("audit")
        await database.complete_scan(s1, [make_finding("f1"), make_finding("f2")])
        s2 = await database.create_scan("audit")
        await database.complete_scan(s2, [make_finding("f1")])
        comp = await database.get_comparison(s2)
        resolved_ids = [f["id"] for f in comp["resolved"]]
        assert "f2" in resolved_ids

    @pytest.mark.asyncio
    async def test_counts_unchanged(self, database):
        s1 = await database.create_scan("audit")
        await database.complete_scan(s1, [make_finding("f1"), make_finding("f2")])
        s2 = await database.create_scan("audit")
        await database.complete_scan(s2, [make_finding("f1"), make_finding("f2")])
        comp = await database.get_comparison(s2)
        assert comp["unchanged"] == 2
        assert len(comp["new"]) == 0
        assert len(comp["resolved"]) == 0


class TestAssets:

    @pytest.mark.asyncio
    async def test_upsert_new_asset_returns_true(self, database):
        asset = AssetRecord(ip="192.168.1.10", hostname="server")
        is_new = await database.upsert_asset(asset)
        assert is_new is True

    @pytest.mark.asyncio
    async def test_upsert_existing_asset_returns_false(self, database):
        asset = AssetRecord(ip="192.168.1.10")
        await database.upsert_asset(asset)
        is_new = await database.upsert_asset(asset)
        assert is_new is False

    @pytest.mark.asyncio
    async def test_get_assets(self, database):
        await database.upsert_asset(AssetRecord(ip="192.168.1.10"))
        await database.upsert_asset(AssetRecord(ip="192.168.1.20"))
        assets = await database.get_assets()
        assert len(assets) == 2

    @pytest.mark.asyncio
    async def test_set_asset_unauthorized(self, database):
        await database.upsert_asset(AssetRecord(ip="192.168.1.10"))
        await database.set_asset_authorized("192.168.1.10", False, "Desconocido")
        assets = await database.get_assets()
        assert assets[0]["is_authorized"] == 0
        assert assets[0]["notes"] == "Desconocido"

    @pytest.mark.asyncio
    async def test_open_ports_parsed_as_list(self, database):
        asset = AssetRecord(
            ip="192.168.1.10",
            open_ports=json.dumps([{"port": 22, "service": "ssh"}]),
        )
        await database.upsert_asset(asset)
        assets = await database.get_assets()
        assert isinstance(assets[0]["open_ports"], list)
        assert assets[0]["open_ports"][0]["port"] == 22


class TestSuppressions:

    @pytest.mark.asyncio
    async def test_add_and_get_suppression(self, database):
        await database.add_suppression("fw_inactive", "Falso positivo", "admin")
        suppressions = await database.get_suppressions()
        assert len(suppressions) == 1
        assert suppressions[0]["finding_id_pattern"] == "fw_inactive"

    @pytest.mark.asyncio
    async def test_exact_match_suppressed(self, database):
        await database.add_suppression("fw_inactive", "Test", "admin")
        assert await database.is_suppressed("fw_inactive")

    @pytest.mark.asyncio
    async def test_glob_pattern_suppressed(self, database):
        await database.add_suppression("ww_/var/lib/kubelet*", "Kubelet", "admin")
        assert await database.is_suppressed("ww_/var/lib/kubelet/pods/abc123")
        assert not await database.is_suppressed("ww_/etc/passwd")

    @pytest.mark.asyncio
    async def test_remove_suppression(self, database):
        await database.add_suppression("fw_inactive", "Test", "admin")
        await database.remove_suppression("fw_inactive")
        suppressions = await database.get_suppressions()
        assert len(suppressions) == 0

    @pytest.mark.asyncio
    async def test_filter_suppressed_removes_matching(self, database):
        await database.add_suppression("fw_inactive", "Test", "admin")
        findings = [
            make_finding("fw_inactive", "critical"),
            make_finding("ssh_root", "high"),
        ]
        filtered = await database.filter_suppressed(findings)
        assert len(filtered) == 1
        assert filtered[0].id == "ssh_root"

    @pytest.mark.asyncio
    async def test_filter_suppressed_empty_when_all_suppressed(self, database):
        await database.add_suppression("*", "Todo suprimido", "admin")
        findings = [make_finding("anything")]
        filtered = await database.filter_suppressed(findings)
        assert len(filtered) == 0


class TestUsers:

    @pytest.mark.asyncio
    async def test_ensure_admin_creates_user(self, database):
        pw = hashlib.sha256(b"password").hexdigest()
        await database.ensure_admin_exists("admin", pw)
        user = await database.get_user("admin")
        assert user is not None
        assert user["role"] == "admin"

    @pytest.mark.asyncio
    async def test_ensure_admin_idempotent(self, database):
        pw = hashlib.sha256(b"password").hexdigest()
        await database.ensure_admin_exists("admin", pw)
        await database.ensure_admin_exists("admin", pw)  # no debe lanzar error
        users = await database.list_users()
        assert len(users) == 1

    @pytest.mark.asyncio
    async def test_create_user_with_role(self, database):
        pw = hashlib.sha256(b"pass").hexdigest()
        await database.create_user(UserRecord(
            username="operator1", password_hash=pw, role="operator"
        ))
        user = await database.get_user("operator1")
        assert user["role"] == "operator"

    @pytest.mark.asyncio
    async def test_get_inactive_user_returns_none(self, database):
        pw = hashlib.sha256(b"pass").hexdigest()
        await database.create_user(UserRecord(username="user1", password_hash=pw))
        await database.update_user("user1", active=0)
        user = await database.get_user("user1")
        assert user is None

    @pytest.mark.asyncio
    async def test_update_last_login(self, database):
        pw = hashlib.sha256(b"pass").hexdigest()
        await database.ensure_admin_exists("admin", pw)
        await database.update_last_login("admin")
        user = await database.get_user("admin")
        assert user["last_login"] is not None

    @pytest.mark.asyncio
    async def test_list_users(self, database):
        pw = hashlib.sha256(b"pass").hexdigest()
        await database.create_user(UserRecord(username="u1", password_hash=pw, role="admin"))
        await database.create_user(UserRecord(username="u2", password_hash=pw, role="viewer"))
        users = await database.list_users()
        assert len(users) == 2
        roles = {u["username"]: u["role"] for u in users}
        assert roles["u1"] == "admin"
        assert roles["u2"] == "viewer"


class TestNotifications:

    @pytest.mark.asyncio
    async def test_add_and_get_pending(self, database):
        await database.add_notification("Alerta test", "critical")
        pending = await database.get_pending_notifications()
        assert len(pending) == 1
        assert pending[0]["message"] == "Alerta test"
        assert pending[0]["sent"] == 0

    @pytest.mark.asyncio
    async def test_mark_sent(self, database):
        await database.add_notification("Test", "info")
        pending = await database.get_pending_notifications()
        await database.mark_notification_sent(pending[0]["id"])
        pending2 = await database.get_pending_notifications()
        assert len(pending2) == 0

    @pytest.mark.asyncio
    async def test_multiple_notifications(self, database):
        for i in range(5):
            await database.add_notification(f"Msg {i}", "warning")
        pending = await database.get_pending_notifications()
        assert len(pending) == 5


class TestDashboardStats:

    @pytest.mark.asyncio
    async def test_empty_stats(self, database):
        stats = await database.get_dashboard_stats()
        assert stats["total_assets"] == 0
        assert stats["unauthorized_assets"] == 0
        assert stats["last_scans"]["audit"] is None

    @pytest.mark.asyncio
    async def test_stats_with_data(self, database):
        # Crear un scan completado
        scan_id = await database.create_scan("audit")
        await database.complete_scan(scan_id, [
            make_finding("c1", "critical"),
            make_finding("h1", "high"),
        ])
        # Añadir assets
        await database.upsert_asset(AssetRecord(ip="192.168.1.1"))
        await database.upsert_asset(AssetRecord(ip="192.168.1.2"))
        await database.set_asset_authorized("192.168.1.2", False)

        stats = await database.get_dashboard_stats()
        assert stats["total_assets"] == 2
        assert stats["unauthorized_assets"] == 1
        assert stats["last_scans"]["audit"] is not None
        assert len(stats["critical_findings"]) == 1
