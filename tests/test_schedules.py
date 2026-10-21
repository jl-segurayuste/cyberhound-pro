"""Análisis programados: validación y cuándo tocan (cyberhound/core/schedules.py)."""
from datetime import datetime

import pytest

from cyberhound.core import schedules
from cyberhound.core.config import SchedulerSettings
from cyberhound.core.scheduler import build_platform_scheduler


def test_validacion():
    d = schedules.validate({"name": " Web ", "task": "web_headers", "targets": "https://a.es, https://b.es",
                            "hour": 5, "minute": 30, "days": [4, 0, 0]})
    assert d == {"name": "Web", "task": "web_headers", "targets": ["https://a.es", "https://b.es"],
                 "hour": 5, "minute": 30, "days": [0, 4]}
    for bad in ({"task": "audit"}, {"task": "ssh"}, {"targets": []}, {"hour": 24}, {"minute": "5"},
                {"days": [7]}, {"days": []}, {"enabled": "sí"}, {"name": ""}, {"hour": True}):
        with pytest.raises(ValueError):
            schedules.validate({"name": "x", "task": "tls", "targets": ["a.es"], **bad})
    assert schedules.validate({"enabled": False}, partial=True) == {"enabled": False}
    with pytest.raises(ValueError):
        schedules.check_targets("web_headers", ["https://a.es; rm -rf /"])
    assert schedules.ws_message("network", ["10.10.0.0/24"])["ssh_audit"] is False


def test_cuando_toca():
    s = {"enabled": True, "days": [2], "hour": 4, "minute": 30, "last_run": None}
    wed = datetime(2026, 10, 21, 4, 30, 5)
    assert schedules.is_due(s, wed)
    assert not schedules.is_due({**s, "last_run": "2026-10-21T04:30:00"}, wed)     # ya lanzada este minuto
    assert schedules.is_due({**s, "last_run": "2026-10-14T04:30:00"}, wed)
    assert not schedules.is_due({**s, "enabled": False}, wed)
    assert not schedules.is_due(s, wed.replace(minute=31))
    assert not schedules.is_due(s, datetime(2026, 10, 22, 4, 30))


def test_scheduler_de_plataforma_crea_todas_las_tareas():
    """Antes una tarea desactivada en config.yaml ni se creaba: no se podía encender desde la UI."""
    s = build_platform_scheduler(None, SchedulerSettings(malware_enabled=False))
    entries = {e["name"]: e["enabled"] for e in s.list_entries()}
    assert entries == {"daily_audit": True, "weekly_malware": False, "daily_network": True}
