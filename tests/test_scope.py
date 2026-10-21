"""Ámbito de análisis por organización (cyberhound/core/scope.py)."""
import ipaddress

import pytest

from cyberhound.core import scope as scope_mod
from cyberhound.core.scope import Scope, host_of, parse_scope, ws_targets


def test_parse_scope_normaliza_y_valida():
    assert parse_scope(["10.10.0.5/24", "*.Ejemplo-Demo.es", "203.0.113.7", "ejemplo-demo.es", ""]) == [
        "10.10.0.0/24", "ejemplo-demo.es", "203.0.113.7/32"]
    assert parse_scope("10.10.0.0/24, ejemplo-demo.es") == ["10.10.0.0/24", "ejemplo-demo.es"]
    for bad in (["10.0.0.0/8"], ["127.0.0.0/24"], ["169.254.169.254"], ["no es nada"], ["a;b.es"], 5):
        with pytest.raises(ValueError):
            parse_scope(bad)


def test_host_of():
    assert host_of("https://Web.Ejemplo-Demo.es:8443/x?y") == "web.ejemplo-demo.es"
    assert host_of("ldap://10.10.0.9:389") == "10.10.0.9"
    assert host_of("root@10.10.0.9") == "10.10.0.9"
    assert host_of("ejemplo-demo.es") == "ejemplo-demo.es"


@pytest.fixture
def dns(monkeypatch):
    table = {}

    async def fake(host):
        return [ipaddress.ip_address(a) for a in table.get(host, [])]
    monkeypatch.setattr(scope_mod, "_resolve", fake)
    return table


async def test_redes_ips_y_dominios(dns):
    s = Scope(parse_scope(["10.10.0.0/24", "ejemplo-demo.es"]))
    dns["web.ejemplo-demo.es"] = ["1.2.3.4"]
    dns["intranet.ejemplo-demo.es"] = ["10.10.0.20"]
    dns["trampa.ejemplo-demo.es"] = ["192.168.1.1"]
    assert await s.check("10.10.0.0/25") is None
    assert "fuera" in await s.check("10.10.0.0/16")
    assert await s.check("10.10.0.7") is None
    assert "fuera" in await s.check("10.10.1.7")
    assert await s.check("https://web.ejemplo-demo.es/login") is None
    assert await s.check("intranet.ejemplo-demo.es") is None          # privada pero en red permitida
    assert "interna" in await s.check("trampa.ejemplo-demo.es")        # dominio propio apuntando a la LAN
    assert "dominios" in await s.check("otro.es")
    assert "dominios" in await s.check("ejemplo-demo.es.evil.es")
    assert await s.check_all(["10.10.0.7", "otro.es"])


def test_objetivos_por_tarea():
    assert ws_targets({"task": "network", "networks": "10.0.0.0/24,10.0.1.0/24"}) == ["10.0.0.0/24", "10.0.1.0/24"]
    assert ws_targets({"task": "network", "networks": ""}) == []
    assert ws_targets({"task": "ssh", "hosts": "a b"}) == ["a", "b"]
    assert ws_targets({"task": "tls", "targets": ["x"]}) == ["x"]
    assert ws_targets({"task": "intel", "target": "x"}) is None
