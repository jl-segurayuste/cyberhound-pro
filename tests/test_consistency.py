"""Coherencia entre código, UI y documentación (lo que antes se desfasaba sin que nada avisara)."""
import re
from pathlib import Path

from cyberhound import __version__
from cyberhound.api.server import ROLE_PERMISSIONS, CyberHoundServer, _required_permission
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.openapi import ENDPOINT_DOCS, build_openapi_spec

ROOT = Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "cyberhound/ui/static/app.js").read_text()
INTERNAL = {"GET /", "GET /static", "GET /login", "GET /ws", "GET /ws/push"}


def _routes() -> set[str]:
    cfg = CyberHoundConfig()
    cfg.auth.secret = "s" * 64
    out = set()
    for r in CyberHoundServer(cfg).build_app().router.routes():
        if r.method in ("HEAD", "*"):
            continue
        info = r.resource.get_info()
        out.add(f"{r.method} {info.get('path') or info.get('formatter') or info.get('prefix')}")
    return out


def test_toda_ruta_esta_documentada_en_openapi_y_viceversa():
    routes = _routes()
    assert sorted(routes - set(ENDPOINT_DOCS) - INTERNAL) == []
    assert sorted(set(ENDPOINT_DOCS) - routes) == []


def test_openapi_lleva_la_version_y_licencia_del_proyecto():
    info = build_openapi_spec()["info"]
    assert info["version"] == __version__
    assert info["license"]["name"] == "AGPL-3.0"
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (ROOT / "LICENSE").read_text()


def test_una_sola_version_en_todo_el_proyecto():
    """Las versiones a mano (6.0, 6.1.0, 6.2.0, 6.3.0…) no deben volver."""
    files = ["Dockerfile", "install.sh", "docker-compose.yml", "docker-compose.production.yml",
             "docker/entrypoint.sh", "cyberhound/ui/static/app.js", "cyberhound/ui/static/index.html"]
    files += [str(p.relative_to(ROOT)) for p in (ROOT / "cyberhound").rglob("*.py")]
    for f in files:
        text = (ROOT / f).read_text()
        assert not re.search(r"(?:\bv|[Vv][Ee][Rr][Ss][Ii][Oo][Nn]\W{1,4}|CyberHound Pro )6\.\d", text), \
            f"versión a mano en {f}"
    readme = (ROOT / "README.md").read_text()
    assert f"v{__version__}" in readme


def _fn_perms() -> dict[str, str]:
    block = re.search(r"const FN_PERMS = \{(.*?)\};", APP_JS, re.S).group(1)
    return dict(re.findall(r"(\w+): '(\w+)'", block))


def _js_function(fn: str) -> str | None:
    """Cuerpo de una función de app.js, contando llaves desde la que la abre."""
    m = re.search(rf"^(?:async )?function {fn}\s*\([^)]*\)\s*\{{", APP_JS, re.M)
    if not m:
        return None
    depth, i = 1, m.end()
    while depth and i < len(APP_JS):
        depth += {"{": 1, "}": -1}.get(APP_JS[i], 0)
        i += 1
    return APP_JS[m.start():i]


def _write_endpoints(fn: str, seen=None) -> set[tuple[str, str]]:
    """Endpoints de escritura (y /ws) que usa una función de app.js, siguiendo las que llama."""
    seen = seen or set()
    if fn in seen:
        return set()
    seen.add(fn)
    body = _js_function(fn)
    if body is None:
        return set()
    out = set()
    for call in re.finditer(r"fetch\(\s*[`'\"]([^`'\"]+)[`'\"](?:\s*,\s*\{([^}]*)\})?", body):
        method = re.search(r"method:\s*'(\w+)'", call.group(2) or "")
        path = re.sub(r"\$\{[^}]+\}", "x", call.group(1)).split("?")[0]
        out.add((method.group(1) if method else "GET", path))
    if "wsRun(" in body or "wsRunWithActivity(" in body:
        out.add(("GET", "/ws"))
    for task in re.findall(r"wsRun(?:WithActivity)?\('(\w+)'", body):
        out.add(("WS", task))
    for callee in set(re.findall(r"\b([a-zA-Z_]\w*)\(", body)) - {fn}:
        if callee in ("appendLog", "toast", "showPanel", "showCfgTab", "loadDashboard", "esc", "on"):
            continue
        out |= _write_endpoints(callee, seen)
    return out


def test_permisos_de_la_ui_coinciden_con_el_servidor():
    perms = _fn_perms()
    handlers = set(re.findall(r'data-on-[a-z]+="(\w+)"', (ROOT / "cyberhound/ui/static/index.html").read_text()))
    handlers |= set(re.findall(r"on\('[a-z]+', '(\w+)'", APP_JS))
    # showCfgTab abre cualquier pestaña de Ajustes: la de Usuarios la oculta applyRole() a quien no es admin
    # showPanel carga Ajustes y loadUsers se salta sola si el rol no es admin
    for fn in sorted(handlers - {"showCfgTab", "showPanel"}):
        needed = {_required_permission(m, p) for m, p in _write_endpoints(fn) if m != "WS"} - {"view"}
        # la UI debe pedir al menos el permiso más alto que exige el servidor
        if needed:
            assert fn in perms, f"{fn} usa {needed} pero no está en FN_PERMS"
            order = ["view", "scan", "fix", "config", "users"]
            assert all(p in ROLE_PERMISSIONS["admin"] for p in needed)
            if len(needed) == 1:
                assert perms[fn] == next(iter(needed)), f"{fn}: FN_PERMS={perms[fn]} servidor={needed}"
            else:
                assert perms[fn] in needed, f"{fn}: FN_PERMS={perms[fn]} servidor={needed}"
                assert order.index(perms[fn]) <= max(order.index(p) for p in needed)
    assert set(perms.values()) <= set(ROLE_PERMISSIONS["admin"])
    assert "applyRole" in APP_JS and '[data-cfg="users"]' in APP_JS
    assert re.search(r"async function loadUsers\(\) \{\n  if \(!USER\.permissions\.includes\('users'\)\) return;", APP_JS)


def test_acciones_sobre_el_servidor_coinciden_con_el_servidor():
    """Multi-tenant: lo que la UI oculta a un tenant (HOST_FNS) = lo que el servidor le niega."""
    from cyberhound.api.server import HOST_TASKS, _platform_only
    host_fns = set(re.findall(r"'(\w+)'", re.search(r"const HOST_FNS = new Set\(\[(.*?)\]\);", APP_JS, re.S).group(1)))
    handlers = set(re.findall(r'data-on-[a-z]+="(\w+)"', (ROOT / "cyberhound/ui/static/index.html").read_text()))
    handlers |= set(re.findall(r"on\('[a-z]+', '(\w+)'", APP_JS))
    for fn in sorted(handlers - {"showCfgTab", "showPanel"}):
        eps = _write_endpoints(fn)
        touches_host = any((m == "WS" and p in HOST_TASKS) or (m != "WS" and _platform_only(p)) for m, p in eps)
        if fn in ("createTenant", "deleteTenant", "rotateTenantKey", "switchTenant", "saveTenantScope"):
            continue   # gestión de tenants: solo se muestra al superadmin
        assert touches_host == (fn in host_fns), f"{fn}: toca el servidor={touches_host}, en HOST_FNS={fn in host_fns}"


def test_loaders_de_plataforma_no_se_lanzan_para_un_tenant():
    for name in re.findall(r"^(?:async )?function (load\w+)\(\)", APP_JS, re.M):
        body = _js_function(name).split("{", 1)[1]
        paths = {re.sub(r"\$\{[^}]+\}", "x", u).split("?")[0] for u in re.findall(r"fetch\(\s*[`'\"]([^`'\"]+)", body)}
        from cyberhound.api.server import _platform_only
        if name in ("loadTenants", "loadTenantSwitch"):
            continue   # comprueban superadmin
        if any(_platform_only(p) for p in paths):
            assert body.lstrip().startswith("if (!hostAccess()) return;"), name
