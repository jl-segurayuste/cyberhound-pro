"""Tests del sistema de licencias."""
import base64
import hashlib
import hmac
import json
import tempfile
from datetime import UTC
from pathlib import Path

import pytest

from cyberhound.core.licensing import (
    LICENSE_VERIFY_KEY,
    TIER_LIMITS,
    License,
    LicenseManager,
)


def make_license_key(tier="starter", licensee="Test Corp",
                     valid_until=None, expired=False) -> str:
    """Genera una clave de licencia válida para tests."""
    from datetime import datetime, timedelta, timezone
    if expired:
        valid_until = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    payload = {
        "tier": tier,
        "licensee": licensee,
        "valid_until": valid_until,
        "issued_at": datetime.now(UTC).isoformat(),
        "license_id": "test-123",
    }
    payload_str = json.dumps(payload, sort_keys=True)
    sig = hmac.new(LICENSE_VERIFY_KEY.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
    data = json.dumps({"payload": payload, "signature": sig})
    return base64.b64encode(data.encode()).decode()


class TestLicenseManager:

    def test_community_license_when_no_file(self, tmp_path):
        mgr = LicenseManager()
        lic = mgr.load(tmp_path / "nonexistent.json")
        assert lic.tier == "community"
        assert not lic.is_expired

    def test_activate_valid_license(self, tmp_path):
        mgr = LicenseManager()
        key = make_license_key("professional", "ACME Corp")
        ok, msg = mgr.activate(key, tmp_path / "license.json")
        assert ok
        assert "professional" in msg.lower()

    def test_activated_license_persisted(self, tmp_path):
        mgr = LicenseManager()
        key = make_license_key("starter", "My Company")
        mgr.activate(key, tmp_path / "license.json")
        # Crear nuevo manager y cargar
        mgr2 = LicenseManager()
        lic = mgr2.load(tmp_path / "license.json")
        assert lic.tier == "starter"
        assert lic.licensee == "My Company"

    def test_reject_tampered_license(self, tmp_path):
        mgr = LicenseManager()
        # Crear una clave con firma incorrecta
        payload = {"tier": "enterprise", "licensee": "Hacker", "valid_until": None}
        payload_str = json.dumps(payload, sort_keys=True)
        bad_sig = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        data = json.dumps({"payload": payload, "signature": bad_sig})
        bad_key = base64.b64encode(data.encode()).decode()
        ok, msg = mgr.activate(bad_key, tmp_path / "license.json")
        assert not ok
        assert "firma" in msg.lower() or "inválida" in msg.lower()

    def test_reject_expired_license(self, tmp_path):
        mgr = LicenseManager()
        key = make_license_key("professional", "Old Corp", expired=True)
        ok, msg = mgr.activate(key, tmp_path / "license.json")
        assert not ok
        assert "expira" in msg.lower() or "expirada" in msg.lower()

    def test_invalid_base64_key(self, tmp_path):
        mgr = LicenseManager()
        ok, msg = mgr.activate("not-valid-base64!!!", tmp_path / "license.json")
        assert not ok
        assert "inválida" in msg.lower() or "formato" in msg.lower()

    def test_license_file_has_restricted_permissions(self, tmp_path):
        mgr = LicenseManager()
        key = make_license_key("starter")
        lic_path = tmp_path / "license.json"
        mgr.activate(key, lic_path)
        # Permisos deben ser 600
        assert oct(lic_path.stat().st_mode & 0o777) == "0o600"


class TestLicenseLimits:

    def test_community_limits(self):
        limits = TIER_LIMITS["community"]
        assert not limits.siem_enabled
        assert not limits.agent_enabled
        assert not limits.intel_enabled

    def test_professional_limits(self):
        limits = TIER_LIMITS["professional"]
        assert limits.siem_enabled
        assert limits.agent_enabled
        assert limits.max_hosts == 50
        assert limits.max_agents == 3

    def test_enterprise_unlimited(self):
        limits = TIER_LIMITS["enterprise"]
        assert limits.max_hosts == 0   # ilimitado
        assert limits.max_agents == 0  # ilimitado

    def test_can_scan_host_unlimited(self):
        lic = License(tier="enterprise", limits=TIER_LIMITS["enterprise"])
        assert lic.can_scan_host(9999)

    def test_can_scan_host_limited(self):
        lic = License(tier="starter", limits=TIER_LIMITS["starter"])
        assert lic.can_scan_host(4)     # bajo el límite
        assert not lic.can_scan_host(5) # en el límite


class TestLicense:

    def test_not_expired_community(self):
        lic = License()
        assert not lic.is_expired

    def test_is_expired_past_date(self):
        lic = License(valid_until="2020-01-01T00:00:00+00:00")
        assert lic.is_expired

    def test_days_remaining_future(self):
        from datetime import datetime, timedelta, timezone
        future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        lic = License(valid_until=future)
        assert lic.days_remaining >= 29

    def test_days_remaining_none_when_perpetual(self):
        lic = License(valid_until=None)
        assert lic.days_remaining is None

    def test_to_dict_has_required_keys(self):
        lic = License()
        d = lic.to_dict()
        assert "tier" in d
        assert "licensee" in d
        assert "is_expired" in d
        assert "limits" in d
        assert "max_hosts" in d["limits"]


class TestLicenseCheckFeature:

    def test_community_no_siem(self):
        mgr = LicenseManager()
        mgr._license = License(tier="community", limits=TIER_LIMITS["community"])
        allowed, msg = mgr.check_feature("siem")
        assert not allowed
        assert "Starter" in msg or "licencia" in msg.lower()

    def test_professional_has_all_features(self):
        mgr = LicenseManager()
        mgr._license = License(tier="professional", limits=TIER_LIMITS["professional"])
        assert mgr.check_feature("siem")[0]
        assert mgr.check_feature("agent")[0]
        assert mgr.check_feature("intel")[0]

    def test_unknown_feature_allowed(self):
        mgr = LicenseManager()
        mgr._license = License(tier="community", limits=TIER_LIMITS["community"])
        allowed, _ = mgr.check_feature("unknown_feature")
        assert allowed  # features no definidas están permitidas por defecto
