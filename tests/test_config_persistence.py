"""Persistencia de la configuración.

Bugs reales corregidos 2026-10-20:
- save() escribía siempre en ~/.cyberhound/config.yaml aunque se hubiera cargado otro
  fichero (--config): en Docker (/data/config.yaml) todo lo guardado desde la UI se
  perdía al recrear el contenedor.
- La contraseña SMTP, tokens de SIEM/ticketing y la clave de agente no se guardaban:
  funcionaban hasta el siguiente reinicio.
- Los defaults de --host/--port de la CLI pisaban siempre server.host/port del YAML.
- db_url no existía en la configuración: PostgreSQL no se podía activar.
"""
import os
import stat
import sys

import yaml

from cyberhound.core.config import CyberHoundConfig


def _write(path, data):
    path.write_text(yaml.safe_dump(data))
    return path


def test_save_escribe_en_el_fichero_cargado_con_secretos_y_0600(tmp_path, monkeypatch):
    for env in ("CH_SMTP_PASSWORD", "CH_AGENT_KEY", "CH_JIRA_TOKEN", "CH_DB_URL"):
        monkeypatch.delenv(env, raising=False)
    path = _write(tmp_path / "config.yaml", {"auth": {"username": "admin", "password_hash": "h"}})
    cfg = CyberHoundConfig.load(path)
    cfg.notifications.smtp_password = "smtp-secreto"
    cfg.agent.agent_key = "clave-agente"
    cfg.ticketing.jira_api_token = "jira-token"
    cfg.auth.localhost_only = True
    cfg.save()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = CyberHoundConfig.load(path)
    assert again.notifications.smtp_password == "smtp-secreto"
    assert again.agent.agent_key == "clave-agente"
    assert again.ticketing.jira_api_token == "jira-token"
    assert again.auth.localhost_only is True
    assert again.auth.secret and again.auth.secret == cfg.auth.secret


def test_secretos_del_entorno_mandan_y_no_se_copian_al_fichero(tmp_path, monkeypatch):
    path = _write(tmp_path / "c.yaml", {"notifications": {"smtp_password": "del-yaml"},
                                        "api_keys": {"shodan": "yaml-key"}})
    monkeypatch.setenv("CH_SMTP_PASSWORD", "del-entorno")
    monkeypatch.setenv("SHODAN_API_KEY", "env-key")
    cfg = CyberHoundConfig.load(path)
    assert cfg.notifications.smtp_password == "del-entorno"
    assert cfg.api_keys.shodan == "env-key"
    cfg.save()
    raw = yaml.safe_load(path.read_text())
    assert raw["notifications"]["smtp_password"] is None
    assert "shodan" not in raw["api_keys"]


def test_db_url_desde_yaml_o_entorno(tmp_path, monkeypatch):
    monkeypatch.delenv("CH_DB_URL", raising=False)
    path = _write(tmp_path / "c.yaml", {"db_url": "postgresql://u:p@db:5432/ch"})
    assert CyberHoundConfig.load(path).db_url == "postgresql://u:p@db:5432/ch"
    monkeypatch.setenv("CH_DB_URL", "postgresql://u:p@otro:5432/ch")
    assert CyberHoundConfig.load(path).db_url == "postgresql://u:p@otro:5432/ch"


def test_variables_de_wazuh_del_entorno(tmp_path, monkeypatch):
    monkeypatch.setenv("CH_WAZUH_URL", "https://127.0.0.1:55000")
    monkeypatch.setenv("CH_WAZUH_USER", "wazuh-wui")
    cfg = CyberHoundConfig.load(tmp_path / "no-existe.yaml")
    assert cfg.siem.wazuh_api_url == "https://127.0.0.1:55000" and cfg.siem.wazuh_api_user == "wazuh-wui"


def test_sin_contrasena_la_validacion_lo_dice(tmp_path):
    cfg = CyberHoundConfig.load(tmp_path / "no-existe.yaml")
    assert any("password_hash" in e for e in cfg.validate())


def test_cli_sin_flags_respeta_host_y_puerto_del_yaml(tmp_path, monkeypatch):
    from cyberhound import __main__ as cli
    from cyberhound.api import server as srv_mod
    path = _write(tmp_path / "c.yaml", {"server": {"host": "0.0.0.0", "port": 9443}})
    seen = {}

    async def fake_start(self):
        seen.update(host=self.cfg.server.host, port=self.cfg.server.port)
    monkeypatch.setattr(srv_mod.CyberHoundServer, "start", fake_start)
    monkeypatch.setattr(sys, "argv", ["cyberhound", "web", "--config", str(path)])
    cli.main()
    assert seen == {"host": "0.0.0.0", "port": 9443}
    monkeypatch.setattr(sys, "argv", ["cyberhound", "web", "--config", str(path), "--host", "127.0.0.1"])
    cli.main()
    assert seen["host"] == "127.0.0.1" and seen["port"] == 9443
