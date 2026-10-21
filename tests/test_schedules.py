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
                 "hour": 5, "minute": 30, "days": [0, 4], "ssh_credential": None}
    for bad in ({"task": "audit"}, {"task": "code"}, {"targets": []}, {"ssh_credential": "../x"}, {"hour": 24}, {"minute": "5"},
                {"days": [7]}, {"days": []}, {"enabled": "sí"}, {"name": ""}, {"hour": True}):
        with pytest.raises(ValueError):
            schedules.validate({"name": "x", "task": "tls", "targets": ["a.es"], **bad})
    assert schedules.validate({"enabled": False}, partial=True) == {"enabled": False}
    with pytest.raises(ValueError):
        schedules.check_targets("web_headers", ["https://a.es; rm -rf /"])
    assert schedules.ws_message("network", ["10.10.0.0/24"])["ssh_audit"] is False


def test_programados_ssh_necesitan_credencial():
    """SSH programado entra con una credencial guardada; sin ella no hay a quién pedirle la contraseña."""
    with pytest.raises(ValueError, match="credencial"):
        schedules.check_credential("ssh", None)
    with pytest.raises(ValueError, match="Solo"):
        schedules.check_credential("tls", "0a1b2c3d")
    schedules.check_credential("ssh", "0a1b2c3d")
    schedules.check_credential("network", None)
    msg = schedules.ws_message("ssh", ["10.10.0.5", "10.10.0.6"], "0a1b2c3d")
    assert msg["hosts"] == "10.10.0.5 10.10.0.6" and msg["ssh_credential"] == "0a1b2c3d"
    net = schedules.ws_message("network", ["10.10.0.0/24"], "0a1b2c3d")
    assert net["ssh_audit"] is True and net["ssh_credential"] == "0a1b2c3d"
    with pytest.raises(ValueError):
        schedules.check_targets("ssh", ["10.10.0.5; reboot"], "0a1b2c3d")


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
