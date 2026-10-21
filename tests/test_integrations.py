"""Construcción de las integraciones desde los ajustes (cyberhound/core/integrations.py)."""
import ipaddress

import pytest

from cyberhound.core import integrations, scope
from cyberhound.core.config import NotificationSettings, SIEMSettings, TicketingSettings


def test_build_copia_todos_los_campos():
    """Antes la recarga en caliente se dejaba el servidor SMTP, las credenciales de Wazuh/ELK y el índice de Splunk."""
    n = NotificationSettings(smtp_host="smtp.ejemplo-demo.es", smtp_user="u", smtp_password="p", email_from="a@b.es")
    cfg = integrations.build("notifications", n).cfg
    assert (cfg.smtp_host, cfg.smtp_user, cfg.smtp_password, cfg.email_from) == ("smtp.ejemplo-demo.es", "u", "p", "a@b.es")
    s = SIEMSettings(wazuh_api_user="w", wazuh_api_pass="wp", elk_index="idx", elk_user="e", elk_pass="ep",
                     splunk_index="spl")
    c = integrations.build("siem", s).cfg
    assert (c.wazuh_api_user, c.wazuh_api_pass, c.elk_index, c.elk_user, c.elk_pass, c.splunk_index) == (
        "w", "wp", "idx", "e", "ep", "spl")
    t = integrations.build("ticketing", TicketingSettings(jira_url="https://j.ejemplo-demo.es", jira_api_token="t")).cfg
    assert t.jira_url == "https://j.ejemplo-demo.es" and t.jira_api_token == "t"


def test_vista_publica_y_actualizacion():
    s = SIEMSettings(splunk_hec_token="secreto")
    view = integrations.public_view("siem", s)
    assert "splunk_hec_token" not in view and view["secrets_set"] == ["splunk_hec_token"]
    integrations.apply_update("siem", s, {"splunk_hec_token": "", "wazuh_port": "1515", "nada": 1})
    assert s.splunk_hec_token == "secreto" and s.wazuh_port == 1515
    n = NotificationSettings()
    integrations.apply_update("notifications", n, {"email_to": "a@b.es; c@d.es"})
    assert n.email_to == ["a@b.es", "c@d.es"]
    for bad in ({"email_enabled": "sí"}, {"smtp_port": "x"}, {"email_to": 5}):
        with pytest.raises(ValueError):
            integrations.apply_update("notifications", NotificationSettings(), bad)


@pytest.fixture
def dns(monkeypatch):
    table = {}

    async def fake(host):
        return [ipaddress.ip_address(a) for a in table.get(host, [])]
    monkeypatch.setattr(scope, "_resolve", fake)
    monkeypatch.setattr(integrations, "_resolve", fake)
    return table


async def test_destinos_internos_bloqueados(dns):
    dns["hooks.ejemplo-demo.es"] = ["1.2.3.4"]
    dns["rebind.ejemplo-demo.es"] = ["127.0.0.1"]
    n = NotificationSettings(webhook_enabled=True, webhook_url="https://hooks.ejemplo-demo.es/x")
    assert await integrations.outbound_problem("notifications", n, []) is None
    for url in ("http://127.0.0.1:8080/", "http://192.168.1.10/", "http://rebind.ejemplo-demo.es/", "http://no-resuelve.es/"):
        n.webhook_url = url
        assert await integrations.outbound_problem("notifications", n, []), url
    n.webhook_url = "http://10.10.0.5/"
    assert await integrations.outbound_problem("notifications", n, ["10.10.0.0/24"]) is None
    n.webhook_enabled = False                   # un canal apagado no se comprueba
    n.webhook_url = "http://127.0.0.1/"
    assert await integrations.outbound_problem("notifications", n, []) is None


async def test_el_guardia_vuelve_a_comprobar_al_enviar(dns):
    dns["hooks.ejemplo-demo.es"] = ["1.2.3.4"]
    n = NotificationSettings(webhook_enabled=True, webhook_url="https://hooks.ejemplo-demo.es/x")
    sent = []

    class Inner:
        async def send(self, *a, **k):
            sent.append(a)

        async def test(self):
            return {"webhook": True}
    g = integrations.GuardedIntegration("notifications", Inner(), n, [])
    await g.send("hola")
    dns["hooks.ejemplo-demo.es"] = ["127.0.0.1"]           # cambia de IP después de guardarlo
    await g.send("otra")
    assert sent == [("hola",)] and "error" in await g.test()
