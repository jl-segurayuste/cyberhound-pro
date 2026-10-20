"""IP real del cliente tras proxies inversos (base del rate limit del login).

Bug real 2026-10-20: de X-Forwarded-For se tomaba la PRIMERA entrada, que pone
el propio cliente -> enviando una IP falsa distinta en cada intento nunca se
llegaba al bloqueo. Y no había forma de confiar en un proxy en otra máquina
(Caddy en el homelab), así que todos los clientes compartían su IP.
"""
from unittest.mock import MagicMock

import pytest
from aiohttp.test_utils import make_mocked_request

from cyberhound.core import security
from cyberhound.core.security import _get_real_ip, set_trusted_proxies


def _req(peer: str, xff: str | None = None):
    transport = MagicMock()
    transport.get_extra_info.return_value = (peer, 12345)
    headers = {"X-Forwarded-For": xff} if xff is not None else {}
    return make_mocked_request("GET", "/login", headers=headers, transport=transport)


@pytest.fixture(autouse=True)
def _reset():
    set_trusted_proxies([])
    yield
    set_trusted_proxies([])


def test_cliente_directo_ignora_cabeceras():
    assert _get_real_ip(_req("203.0.113.5", "1.2.3.4")) == "203.0.113.5"


def test_proxy_local_toma_la_ip_que_anade_el_proxy():
    # el cliente envía "6.6.6.6" falsa; el proxy añade su IP real a la derecha
    assert _get_real_ip(_req("127.0.0.1", "6.6.6.6, 203.0.113.5")) == "203.0.113.5"


def test_proxy_remoto_solo_si_esta_en_trusted_proxies():
    assert _get_real_ip(_req("192.168.1.67", "203.0.113.5")) == "192.168.1.67"
    set_trusted_proxies(["192.168.1.67"])
    assert _get_real_ip(_req("192.168.1.67", "6.6.6.6, 203.0.113.5")) == "203.0.113.5"


def test_cadena_de_proxies_de_confianza():
    set_trusted_proxies(["10.0.0.0/8"])
    assert _get_real_ip(_req("10.0.0.2", "203.0.113.5, 10.0.0.9")) == "203.0.113.5"


def test_entrada_basura_no_se_acepta():
    set_trusted_proxies(["192.168.1.67"])
    assert _get_real_ip(_req("192.168.1.67", "203.0.113.5, no-es-ip")) == "192.168.1.67"


def test_entradas_invalidas_de_config_se_ignoran():
    set_trusted_proxies(["no-es-una-red", "192.168.1.0/24"])
    assert len(security._trusted_proxies) == 1
