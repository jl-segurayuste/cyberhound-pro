"""Cada endpoint que llama el frontend existe en la app real.

Bug real 2026-10-20: el panel Intel llamaba a /api/intel/{config,scan,history}
y daba 404 -- `intel_routes.register_routes` existía (y tenía su propio test),
pero `build_app` nunca lo invocaba. Este test monta la app de verdad y cruza
cada `fetch('/api/...')` de la UI (static/js) con las rutas registradas.
"""
import re
from pathlib import Path

from cyberhound.api.server import CyberHoundServer
from cyberhound.core.config import CyberHoundConfig

JS_DIR = Path(__file__).parent.parent / "cyberhound" / "ui" / "static" / "js"


def _frontend_paths() -> set[str]:
    src = "\n".join(p.read_text(encoding="utf-8") for p in sorted(JS_DIR.glob("*.js")))
    raw = re.findall(r"fetch\(\s*[`'\"](/api/[^`'\"?]*)", src)
    # ${...} en template strings → segmento variable
    return {re.sub(r"\$\{[^}]*\}", "X", p).rstrip("/") for p in raw}


def _route_regexes(app) -> list[re.Pattern]:
    out = []
    for res in app.router.resources():
        canon = res.canonical
        out.append(re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(canon)) + "$"))
    return out


def test_every_frontend_api_call_has_a_route(tmp_path):
    cfg = CyberHoundConfig()
    cfg.db_path = tmp_path / "routes.db"
    app = CyberHoundServer(cfg).build_app()
    routes = _route_regexes(app)
    paths = _frontend_paths()
    assert paths, "no se encontró ningún fetch('/api/...') en static/js"
    missing = sorted(p for p in paths if not any(r.match(p) for r in routes))
    assert not missing, f"el frontend llama a endpoints que no existen: {missing}"
