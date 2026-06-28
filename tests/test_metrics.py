"""Endpoint /metrics (Prometheus) y el registro de métricas del request logger."""
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from cyberhound.api.server import METRICS, _Metrics, request_logger_middleware


def test_render_formato_prometheus():
    m = _Metrics()
    m.observe("GET", 200, 5.0)
    m.observe("POST", 404, 3.0)
    out = m.render()
    assert "cyberhound_up 1" in out
    assert "cyberhound_uptime_seconds" in out
    assert 'cyberhound_http_requests_total{method="GET",status="2xx"} 1' in out
    assert 'cyberhound_http_requests_total{method="POST",status="4xx"} 1' in out
    assert "cyberhound_http_request_duration_ms_sum 8" in out  # 5 + 3
    # Cada métrica con su HELP/TYPE.
    assert out.count("# TYPE") >= 3


@pytest.mark.asyncio
async def test_middleware_cuenta_peticion_ok():
    before = METRICS._count

    async def handler(_req):
        return web.Response(text="ok")

    resp = await request_logger_middleware(make_mocked_request("GET", "/x"), handler)
    assert resp.status == 200
    assert METRICS._count == before + 1
    assert 'cyberhound_http_requests_total{method="GET",status="2xx"}' in METRICS.render()


@pytest.mark.asyncio
async def test_middleware_cuenta_error_http():
    before = METRICS._count

    async def handler(_req):
        raise web.HTTPUnauthorized()

    with pytest.raises(web.HTTPException):
        await request_logger_middleware(make_mocked_request("GET", "/x"), handler)
    assert METRICS._count == before + 1  # los errores también se contabilizan


def test_metrics_es_ruta_publica():
    from cyberhound.core.auth import PUBLIC_ROUTES
    assert "/metrics" in PUBLIC_ROUTES
