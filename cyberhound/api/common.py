"""Middlewares, permisos y utilidades compartidas por el servidor y sus handlers."""
from __future__ import annotations

import contextlib
import secrets
import time

from aiohttp import web

from cyberhound.core.auth import (
    AGENT_ROUTES,
    TENANT_COOKIE,
    cap_role,
)
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    current_tenant,
)
from cyberhound.core.paths import YARA_DIR
from cyberhound.core.security import (
    _get_real_ip,
)

logger = get_logger("api")

async def _read_json(request) -> dict:
    """
    Lee el body JSON de un request de forma robusta.
    Maneja: whitespace extra, encoding issues, body vacío.
    Fallback a {} si el body está vacío o no es JSON válido.
    """
    import json as _json
    try:
        raw = await request.read()
        if not raw or not raw.strip():
            return {}
        # Limpiar whitespace al final que puede causar "Extra data"
        text = raw.strip().decode("utf-8", errors="replace")
        return _json.loads(text)
    except Exception:
        # Intentar con el método nativo de aiohttp
        try:
            return await _read_json(request)
        except Exception:
            return {}


# ── Repositorios de reglas YARA públicos ──────────────────────────────────────
YARA_SOURCES = {
    "default": [
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
         "ransomware.yar"),
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_webshell.yar",
         "webshells.yar"),
        ("https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Backdoor.yar",
         "linux_backdoor.yar"),
    ],
    "community": [
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Coinminer.yar",
         "coinminer.yar"),
    ],
}


async def _update_yara_rules(sources: list[str]) -> dict:
    """Descarga reglas YARA de repositorios públicos."""
    import aiohttp
    yara_dir = YARA_DIR
    yara_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, list] = {"updated": [], "errors": [], "skipped": []}
    urls: list[tuple[str, str]] = []
    for src in sources:
        urls.extend(YARA_SOURCES.get(src, []))

    if not urls:
        return {"error": f"Fuente desconocida: {sources}"}

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        for url, filename in urls:
            dest = yara_dir / filename
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Verificar que es YARA válido (tiene al menos una rule)
                        if "rule " in content:
                            dest.write_text(content, encoding="utf-8")
                            results["updated"].append(filename)
                            logger.info("YARA actualizado: %s (%d bytes)", filename, len(content))
                        else:
                            results["errors"].append(f"{filename}: contenido no parece YARA válido")
                    else:
                        results["errors"].append(f"{filename}: HTTP {resp.status}")
            except Exception as e:
                results["errors"].append(f"{filename}: {e}")

    return results

# Roles y sus permisos
ROLE_PERMISSIONS = {
    "admin":    {"scan", "fix", "config", "users", "view"},
    "operator": {"scan", "fix", "view"},
    "viewer":   {"view"},
}


def _required_permission(method: str, path: str) -> str:
    """Permiso de ROLE_PERMISSIONS que exige cada petición. Leer siempre es "view"."""
    write = method not in ("GET", "HEAD", "OPTIONS")
    if path.startswith(("/api/users", "/api/tenants", "/api/audit")):
        return "users"
    if path.startswith(("/api/fix/", "/api/rollback/local", "/api/ansible/run")) or (
        write and path.startswith(("/api/quarantine", "/api/assets/"))
    ):
        return "fix"
    if path == "/ws" or path.startswith((
        "/api/scan/", "/api/intel/scan", "/api/sbom/generate", "/api/import/audit",
        "/api/network/discover", "/api/findings/explain",
    )) or (write and (path == "/api/compliance" or (path.startswith(("/api/scheduler/", "/api/schedules/"))
                                                    and path.endswith("/run")))):
        return "scan"
    if write and path.startswith((
        "/api/config/", "/api/suppressions", "/api/scheduler/", "/api/yara/", "/api/schedules",
    )):
        return "config"
    return "view"


# WS tasks y rutas que actúan sobre ESTE servidor o su configuración global: en
# multi-tenant solo las usa el superadmin (un tenant no puede auditar ni tocar la
# máquina que comparte con los demás, ni leer las credenciales de la plataforma)
HOST_TASKS = {"audit", "malware", "docker", "services", "code"}
_PLATFORM_PREFIXES = (
    "/api/tenants", "/api/fix/local", "/api/rollback", "/api/quarantine", "/api/scan/runtime",
    "/api/scan/docker-image", "/api/sbom", "/api/yara", "/api/monitor", "/api/ansible",
    "/api/config/keys", "/api/config/agent", "/api/scheduler", "/metrics",
)


# Tarea WS → método que la ejecuta (también lo usan los análisis programados)
WS_RUNNERS = {
    "audit": "_run_local_audit", "malware": "_run_malware_scan", "network": "_run_network_scan",
    "ssh": "_run_ssh_scan", "code": "_run_code_audit", "intel": "_run_intel_scan",
    "docker": "_run_docker_scan", "services": "_run_services_audit", "tls": "_run_tls_scan",
    "web_headers": "_run_web_headers_scan", "dns": "_run_dns_scan", "web_exposure": "_run_web_exposure_scan",
    "api_security": "_run_api_security_scan", "subdomain_enum": "_run_subdomain_enum_scan",
    "nuclei": "_run_nuclei_scan",
}


NO_TARGETS = "Indica qué redes o equipos analizar (dentro del ámbito de la organización)"


def _scope_status(err: str) -> int:
    """400 si faltan o no valen los objetivos (error de entrada); 403 si están fuera del ámbito."""
    return 400 if err == NO_TARGETS or err.startswith("Objetivo no válido") else 403


def _platform_only(path: str) -> bool:
    return path.startswith(_PLATFORM_PREFIXES)


@web.middleware
async def tenant_middleware(request: web.Request, handler):
    """Fija el tenant de la petición (current_tenant) y con él la BD que usa self.db.

    Sale del JWT, que firma el login: un usuario de un tenant no puede cambiarlo. El
    superadmin (admin de config.yaml en "default") puede mirar otro con X-Tenant o
    la cookie ch_tenant. Los agentes se identifican con la API key de su tenant.
    """
    server = request.app["server"]
    slug, superadmin = DEFAULT_TENANT, False
    user = request.get("auth_user")
    if user:
        superadmin = request.get("auth_tenant", DEFAULT_TENANT) == DEFAULT_TENANT and user == server.cfg.auth.username
    if server.cfg.multi_tenant.enabled:
        if request.path in AGENT_ROUTES:
            tenant = server.tenants.get_by_api_key(
                server.agent_manager.extract_agent_key(request.headers.get("Authorization", "")))
            if tenant:
                slug = tenant.slug
                request["tenant_agent_key"] = True
        elif user:
            slug = request.get("auth_tenant", DEFAULT_TENANT)
            if superadmin:
                wanted = request.headers.get("X-Tenant") or request.cookies.get(TENANT_COOKIE) or DEFAULT_TENANT
                if wanted != DEFAULT_TENANT and server.tenants.is_active(wanted):
                    slug = wanted
            elif not server.tenants.is_active(slug):
                return web.json_response({"error": "Organización desactivada"}, status=401)
    elif user and request.get("auth_tenant", DEFAULT_TENANT) != DEFAULT_TENANT:
        # Sesión de un tenant con el modo multi-tenant ya desactivado: no vale en "default"
        return web.json_response({"error": "Sesión de una organización: el modo multi-tenant está desactivado"},
                                 status=401)
    request["tenant"], request["superadmin"] = slug, superadmin
    await server.tenant_dbs.ensure(slug)
    ctx = current_tenant.set(slug)
    try:
        return await handler(request)
    finally:
        current_tenant.reset(ctx)


@contextlib.contextmanager
def _own_tenant_ctx(request: web.Request):
    ctx = current_tenant.set(request.get("auth_tenant", DEFAULT_TENANT))
    try:
        yield
    finally:
        current_tenant.reset(ctx)


async def _in_own_tenant(request: web.Request, method: str, *args, **kwargs):
    """Llama a db.<method> en la BD del tenant del propio usuario: la sesión, los tokens y la cuenta
    del superadmin viven en "default" aunque esté mirando otra organización. Se pasa el nombre y no
    el método porque self.db.<x> ya resuelve la BD del tenant que está activo al evaluarlo."""
    ctx = current_tenant.set(request.get("auth_tenant", DEFAULT_TENANT))
    try:
        return await getattr(request.app["server"].db, method)(*args, **kwargs)
    finally:
        current_tenant.reset(ctx)


@web.middleware
async def rbac_middleware(request: web.Request, handler):
    """Aplica ROLE_PERMISSIONS. Antes los roles se guardaban pero ningún endpoint los comprobaba."""
    user = request.get("auth_user")
    if not user or request.path in AGENT_ROUTES:   # modo sin auth, rutas públicas o agentes
        return await handler(request)
    server = request.app["server"]
    jti = request.get("auth_jti")
    if jti and not await _in_own_tenant(request, "get_active_session", jti):
        # Sesión cerrada (logout, cambio de contraseña, "cerrar todas") aunque el JWT no haya caducado
        if "text/html" in request.headers.get("Accept", "") or request.path == "/":
            resp = web.HTTPFound("/login?error=Sesión+cerrada.+Inicia+sesión+de+nuevo.")
            resp.del_cookie("ch_token")
            return resp
        return web.json_response({"error": "Sesión cerrada"}, status=401)
    if server.cfg.multi_tenant.enabled and not request.get("superadmin") and _platform_only(request.path):
        return web.json_response({"error": "Reservado al administrador de la plataforma"}, status=403)
    if request.get("superadmin"):
        role = "admin"   # el admin de config.yaml nunca puede quedarse sin acceso
    else:
        db_user = await server.db.get_user(user)
        if not db_user:  # desactivado después de iniciar sesión
            return web.json_response({"error": "Usuario desactivado"}, status=401)
        role = db_user["role"]
    role = cap_role(role, request.get("auth_token_role"))
    request["user_role"] = role
    needed = _required_permission(request.method, request.path)
    if needed not in ROLE_PERMISSIONS.get(role, set()):
        audit_log.auth_failure(_get_real_ip(request), f"'{user}' ({role}) sin permiso '{needed}' en {request.path}")
        return web.json_response({"error": f"Permiso denegado: tu rol ({role}) no permite '{needed}'"}, status=403)
    return await handler(request)


# ── Métricas (formato Prometheus, sin dependencias) ───────────────────────────

class _Metrics:
    """Contadores en proceso, expuestos en /metrics (texto Prometheus)."""

    def __init__(self) -> None:
        self._start = time.time()
        self._requests: dict[tuple[str, str], int] = {}
        self._duration_ms = 0.0
        self._count = 0

    def observe(self, method: str, status: int, ms: float) -> None:
        key = (method, f"{status // 100}xx")
        self._requests[key] = self._requests.get(key, 0) + 1
        self._duration_ms += ms
        self._count += 1

    def render(self) -> str:
        out = [
            "# HELP cyberhound_up 1 si el servicio responde",
            "# TYPE cyberhound_up gauge",
            "cyberhound_up 1",
            "# HELP cyberhound_uptime_seconds Segundos desde el arranque",
            "# TYPE cyberhound_uptime_seconds gauge",
            f"cyberhound_uptime_seconds {time.time() - self._start:.0f}",
            "# HELP cyberhound_http_requests_total Peticiones por método y clase de estado",
            "# TYPE cyberhound_http_requests_total counter",
        ]
        for (method, status), n in sorted(self._requests.items()):
            out.append(
                f'cyberhound_http_requests_total{{method="{method}",status="{status}"}} {n}'
            )
        out += [
            "# HELP cyberhound_http_request_duration_ms_sum Suma de latencias (ms)",
            "# TYPE cyberhound_http_request_duration_ms_sum counter",
            f"cyberhound_http_request_duration_ms_sum {self._duration_ms:.0f}",
        ]
        return "\n".join(out) + "\n"


METRICS = _Metrics()


# ── Middlewares ───────────────────────────────────────────────────────────────

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    # Nonce por petición: los <script> inline llevan este nonce, de modo que un
    # <script> inyectado (sin nonce) queda bloqueado por la CSP. La UI no usa
    # atributos on* (eventos delegados vía data-on-*), así que script-src-attr
    # es 'none': ni siquiera un atributo inyectado puede ejecutar JS.
    nonce = secrets.token_urlsafe(16)
    request["csp_nonce"] = nonce
    response = await handler(request)
    response.headers.update({
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "X-XSS-Protection":        "1; mode=block",
        "Referrer-Policy":         "strict-origin-when-cross-origin",
        "Cache-Control":           "no-store",
        "Content-Security-Policy": (
            f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
            "script-src-attr 'none'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' ws: wss:;"
        ),
    })
    return response


@web.middleware
async def request_logger_middleware(request: web.Request, handler):
    start = time.monotonic()
    try:
        response = await handler(request)
        elapsed = (time.monotonic() - start) * 1000
        METRICS.observe(request.method, response.status, elapsed)
        logger.info("%s %s %d %.0fms user=%s",
                    request.method, request.path, response.status, elapsed,
                    request.get("auth_user", "anonymous"))
        return response
    except web.HTTPException as e:
        elapsed = (time.monotonic() - start) * 1000
        METRICS.observe(request.method, e.status, elapsed)
        logger.warning("%s %s %d %.0fms", request.method, request.path, e.status, elapsed)
        raise


# ── Servidor principal ────────────────────────────────────────────────────────
