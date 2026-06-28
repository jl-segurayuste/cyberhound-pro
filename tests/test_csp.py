"""La CSP usa nonce para los scripts inline (no 'unsafe-inline' en script-src)."""
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from cyberhound.api.server import security_headers_middleware


@pytest.mark.asyncio
async def test_csp_script_src_uses_nonce_not_unsafe_inline():
    async def handler(request):
        # El middleware fija un nonce por petición antes de llamar al handler.
        assert request["csp_nonce"]
        return web.Response(text="ok")

    req = make_mocked_request("GET", "/")
    resp = await security_headers_middleware(req, handler)
    csp = resp.headers["Content-Security-Policy"]

    script_src = next(d.strip() for d in csp.split(";")
                      if d.strip().startswith("script-src "))
    assert "nonce-" in script_src
    assert "'unsafe-inline'" not in script_src   # bloquea <script> inyectados
    # Los manejadores de eventos inline siguen permitidos por su directiva propia.
    assert "script-src-attr 'unsafe-inline'" in csp


@pytest.mark.asyncio
async def test_csp_nonce_is_per_request():
    async def handler(request):
        return web.Response(text="ok")

    nonces = set()
    for _ in range(3):
        req = make_mocked_request("GET", "/")
        resp = await security_headers_middleware(req, handler)
        csp = resp.headers["Content-Security-Policy"]
        nonces.add(csp.split("nonce-")[1].split("'")[0])
    assert len(nonces) == 3   # nonce distinto en cada respuesta
