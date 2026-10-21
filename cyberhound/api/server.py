"""
Servidor web de CyberHound Pro
====================================
Integra:
- Base de datos SQLite (histórico, inventario, usuarios, supresiones)
- Scheduler de auditorías automáticas
- Notificaciones email/webhook
- WebSocket streaming con persistencia automática
- Gestión de múltiples usuarios con roles
- Endpoints REST completos
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aiohttp import web

from cyberhound import __version__
from cyberhound.api.routes.intel_routes import register_routes as register_intel_routes
from cyberhound.core import integrations, passwords, schedules
from cyberhound.core.auth import (
    AGENT_ROUTES,
    TENANT_COOKIE,
    AuthConfig,
    auth_middleware,
    cap_role,
    make_api_token,
    setup_auth_routes,
)
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import AssetRecord, UserRecord
from cyberhound.core.logging import audit_log, get_logger
from cyberhound.core.models import Finding, ScanReport
from cyberhound.core.multitenancy import (
    DEFAULT_TENANT,
    TenantDatabases,
    TenantRouter,
    TenantStore,
    current_tenant,
)
from cyberhound.core.paths import YARA_DIR
from cyberhound.core.scheduler import ENTRY_FLAGS, Scheduler, build_platform_scheduler
from cyberhound.core.scope import Scope
from cyberhound.core.scope import ws_targets as scope_targets
from cyberhound.core.security import (
    CsrfProtection,
    InputValidator,
    TLSManager,
    ValidationError,
    _get_real_ip,
    set_trusted_proxies,
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

class CyberHoundServer:

    def __init__(self, cfg: CyberHoundConfig) -> None:
        self.cfg = cfg
        set_trusted_proxies(cfg.server.trusted_proxies)
        self._app: web.Application | None = None
        # Hallazgos y scan de cada conexión WS. La clave es "<tenant>:<aleatorio>": antes era
        # str(id(ws)), que Python reutiliza, y una conexión nueva heredaba la entrada de otra.
        self._findings_cache: dict[str, list[Finding]] = {}
        self._scan_id_cache:  dict[str, int] = {}
        self._push_clients:   dict = {}   # WebSocket push → tenant que recibe sus eventos

        # BD: self.db enruta cada llamada a la BD del tenant de la petición ("default" sin multi-tenant)
        from cyberhound.core.database_pg import create_database
        db_url = getattr(cfg, "db_url", "") or ""
        self.tenant_dbs = TenantDatabases(create_database(db_url=db_url, db_path=cfg.db_path),
                                          db_url=db_url, db_path=str(cfg.db_path))
        self.db = TenantRouter(self.tenant_dbs)
        self.tenants = TenantStore(Path(cfg.config_path).parent / "tenants.json")
        # Notificaciones, SIEM y ticketing: de la plataforma o de cada organización (ver _integration)
        self._integrations: dict[tuple[str, str], object] = {}
        self._schedules_running: set[tuple[str, str]] = set()
        self.scheduler: Scheduler | None = None
        self._sbom_cache: dict | None = None
        self._ansible_jobs: list = []
        self._ebpf_monitor = None

        # Modo agente
        from cyberhound.core.agent import AgentConfig, AgentManager, AgentReporter
        agent_cfg = AgentConfig(
            mode=cfg.agent.mode,
            manager_url=cfg.agent.manager_url,
            agent_key=cfg.agent.agent_key,
            agent_name=cfg.agent.agent_name,
        )
        self.agent_manager  = AgentManager(self.db, agent_cfg)
        self.agent_reporter = AgentReporter(agent_cfg) if cfg.agent.mode == "agent" else None

    def build_app(self) -> web.Application:
        auth_cfg = AuthConfig(
            mode=self.cfg.auth.mode, secret=self.cfg.auth.secret,
            username=self.cfg.auth.username, password_hash=self.cfg.auth.password_hash,
            token_ttl_hours=self.cfg.auth.token_ttl_hours,
            localhost_only=self.cfg.auth.localhost_only,
        )
        app = web.Application(
            middlewares=[
                security_headers_middleware, request_logger_middleware,
                CsrfProtection().middleware_factory(is_https=True), auth_middleware, tenant_middleware,
                rbac_middleware,
            ],
            client_max_size=10 * 1024 * 1024,
        )
        app["auth_config"] = auth_cfg
        app["server"] = self

        setup_auth_routes(app, auth_cfg)
        register_intel_routes(app)

        static_dir = Path(__file__).parent.parent / "ui" / "static"
        if static_dir.exists():
            app.router.add_static("/static", static_dir)

        app.router.add_get("/", self.serve_spa)
        app.router.add_get("/ws",     self.websocket_handler)
        app.router.add_get("/ws/push", self.push_websocket_handler)

        # ── Escaneos ──────────────────────────────────────────────────────────
        app.router.add_post("/api/fix/local",    self.api_fix_local)
        app.router.add_post("/api/fix/remote",   self.api_fix_remote)
        app.router.add_post("/api/findings/explain", self.api_explain_finding)
        app.router.add_get ("/api/rollback",      self.api_rollback_list)
        app.router.add_post("/api/rollback/local", self.api_rollback_local)
        app.router.add_get ("/metrics",           self.api_metrics)
        app.router.add_post("/api/report/{fmt}", self.api_report)

        # ── Histórico y resultados ────────────────────────────────────────────
        app.router.add_get("/api/history",               self.api_history)
        app.router.add_get("/api/history/{scan_id}",     self.api_history_detail)
        app.router.add_get("/api/history/{scan_id}/compare", self.api_compare)
        app.router.add_get("/api/score/trend",           self.api_score_trend)
        app.router.add_get("/api/score/detail",          self.api_score_detail)
        app.router.add_get("/api/dashboard",             self.api_dashboard)
        app.router.add_get("/api/me",                    self.api_me)
        app.router.add_post("/api/me/password",          self.api_me_password)
        app.router.add_get ("/api/sessions",             self.api_sessions_list)
        app.router.add_post("/api/sessions/revoke-others", self.api_sessions_revoke_others)
        app.router.add_delete("/api/sessions/{jti}",     self.api_session_revoke)
        app.router.add_get ("/api/tokens",               self.api_tokens_list)
        app.router.add_post("/api/tokens",               self.api_tokens_create)
        app.router.add_delete("/api/tokens/{token_id}",  self.api_token_revoke)
        app.router.add_get ("/api/audit",                self.api_audit_list)

        # ── Inventario de red ────────────────────────────────────────────────
        app.router.add_get ("/api/assets",              self.api_assets)
        app.router.add_post("/api/assets/{ip}/authorize", self.api_asset_authorize)
        app.router.add_get ("/api/network/discover",    self.api_discover)

        # ── Supresiones (falsos positivos) ───────────────────────────────────
        app.router.add_get   ("/api/suppressions",      self.api_suppressions_list)
        app.router.add_post  ("/api/suppressions",      self.api_suppressions_add)
        app.router.add_delete("/api/suppressions/{pattern}", self.api_suppressions_delete)

        # ── Usuarios ─────────────────────────────────────────────────────────
        app.router.add_get   ("/api/users",             self.api_users_list)
        app.router.add_post  ("/api/users",             self.api_users_create)
        app.router.add_patch ("/api/users/{username}",  self.api_users_update)
        app.router.add_delete("/api/users/{username}",  self.api_users_delete)
        app.router.add_delete("/api/users/{username}/sessions", self.api_users_revoke_sessions)

        # ── Scheduler ────────────────────────────────────────────────────────
        app.router.add_get ("/api/scheduler",           self.api_scheduler_list)
        app.router.add_post("/api/scheduler/{name}/run",   self.api_scheduler_run)
        app.router.add_post("/api/scheduler/{name}/toggle", self.api_scheduler_toggle)
        app.router.add_get   ("/api/schedules",            self.api_schedules_list)
        app.router.add_post  ("/api/schedules",            self.api_schedules_create)
        app.router.add_patch ("/api/schedules/{sid}",      self.api_schedules_update)
        app.router.add_delete("/api/schedules/{sid}",      self.api_schedules_delete)
        app.router.add_post  ("/api/schedules/{sid}/run",  self.api_schedules_run)

        # ── Configuración ────────────────────────────────────────────────────
        app.router.add_get ("/api/config/keys",         self.api_get_keys)
        app.router.add_post("/api/config/keys",         self.api_save_keys)
        app.router.add_get ("/api/config/notifications",self.api_get_notifications_cfg)
        app.router.add_post("/api/config/notifications",self.api_save_notifications_cfg)
        app.router.add_post("/api/config/notifications/test", self.api_test_notifications)
        app.router.add_get ("/api/config/siem",         self.api_get_siem)
        app.router.add_post("/api/config/siem",         self.api_save_siem)
        app.router.add_post("/api/config/siem/test",    self.api_test_siem)
        app.router.add_get ("/api/config/ticketing",      self.api_get_ticketing)
        app.router.add_post("/api/config/ticketing",      self.api_save_ticketing)
        app.router.add_post("/api/config/ticketing/test", self.api_test_ticketing)

        # ── Modo agente ───────────────────────────────────────────────────────
        app.router.add_get ("/api/config/agent",     self.api_get_agent_cfg)
        app.router.add_post("/api/config/agent",     self.api_save_agent_cfg)
        app.router.add_post("/api/agent/report",     self.api_agent_report)
        app.router.add_post("/api/agent/heartbeat",  self.api_agent_heartbeat)
        app.router.add_get ("/api/agent/list",       self.api_agent_list)

        # ── PDF + Compliance ─────────────────────────────────────────────────────
        app.router.add_post("/api/report/pdf",           self.api_report_pdf)
        app.router.add_post("/api/compliance",           self.api_compliance)
        app.router.add_get ("/api/compliance",           self.api_compliance_get)

        # ── Cuarentena ───────────────────────────────────────────────────────────
        app.router.add_get ("/api/quarantine",              self.api_quarantine_list)
        app.router.add_post("/api/quarantine",              self.api_quarantine_add)
        app.router.add_post("/api/quarantine/{name}/restore", self.api_quarantine_restore)
        app.router.add_delete("/api/quarantine/{name}",    self.api_quarantine_delete)
        app.router.add_get ("/api/quarantine/stats",       self.api_quarantine_stats)

        # ── OpenAPI / Swagger ─────────────────────────────────────────────────────
        app.router.add_get ("/api/openapi.json",       self.api_openapi_spec)
        app.router.add_get ("/api/docs",               self.api_swagger_ui)

        # ── Ansible AWX/Tower ────────────────────────────────────────────────────
        app.router.add_post("/api/ansible/run",        self.api_ansible_run)
        app.router.add_get ("/api/ansible/jobs",       self.api_ansible_jobs)
        app.router.add_get ("/api/ansible/templates",  self.api_ansible_templates)

        # ── Multi-tenant ──────────────────────────────────────────────────────────
        app.router.add_get ("/api/tenants",            self.api_tenants_list)
        app.router.add_post("/api/tenants",            self.api_tenants_create)
        app.router.add_get ("/api/tenants/{slug}",     self.api_tenant_get)
        app.router.add_patch("/api/tenants/{slug}",    self.api_tenant_update)
        app.router.add_delete("/api/tenants/{slug}",   self.api_tenant_delete)
        app.router.add_post("/api/tenants/{slug}/rotate-key", self.api_tenant_rotate_key)
        app.router.add_post("/api/tenant/switch",      self.api_tenant_switch)
        app.router.add_get ("/api/tenant/agent-key",   self.api_tenant_agent_key)

        # ── Runtime container scan ────────────────────────────────────────────────
        app.router.add_post("/api/scan/runtime",       self.api_runtime_scan)

        # ── Importación de auditorías externas ──────────────────────────────────────
        app.router.add_post("/api/import/audit",      self.api_import_audit)
        app.router.add_get ("/api/import/formats",    self.api_import_formats)

        # ── Docker image deep scan ───────────────────────────────────────────────
        app.router.add_post("/api/scan/docker-image",   self.api_docker_image_scan)

        # ── Monitor status ───────────────────────────────────────────────────────
        app.router.add_get("/api/monitor/status",       self.api_monitor_status)

        # ── SBOM ─────────────────────────────────────────────────────────────────
        app.router.add_post("/api/sbom/generate",           self.api_sbom_generate)
        app.router.add_get ("/api/sbom/latest",             self.api_sbom_latest)


        # ── LDAP / AD ─────────────────────────────────────────────────────────
        app.router.add_post("/api/scan/ldap",          self.api_ldap_scan)

        # ── WebSocket push (notificaciones sin polling) ───────────────────────
        app.router.add_get("/ws/push",  self.push_websocket_handler)

        # ── 2FA / TOTP ────────────────────────────────────────────────────────
        app.router.add_post("/api/auth/2fa/setup",    self.api_2fa_setup)
        app.router.add_post("/api/auth/2fa/activate", self.api_2fa_activate)
        app.router.add_post("/api/auth/2fa/disable",  self.api_2fa_disable)
        app.router.add_get ("/api/auth/2fa/status",   self.api_2fa_status)

        # ── YARA update ───────────────────────────────────────────────────────
        app.router.add_post("/api/yara/update",        self.api_yara_update)
        app.router.add_get ("/api/yara/rules",         self.api_yara_list)

        async def _close_tenant_dbs(_app):
            await self.tenant_dbs.close()
        app.on_cleanup.append(_close_tenant_dbs)

        self._app = app
        return app

    async def serve_spa(self, request: web.Request) -> web.Response:
        spa_path = Path(__file__).parent.parent / "ui" / "static" / "index.html"
        if spa_path.exists():
            html = spa_path.read_text(encoding="utf-8")
            nonce = request.get("csp_nonce", "")
            # Solo los <script> inline (no los <script src=...>) reciben el nonce.
            html = html.replace("<script>", f'<script nonce="{nonce}">')
            return web.Response(text=html, content_type="text/html")
        return web.Response(text="<h1>UI no encontrada</h1>", content_type="text/html")

    # ── WebSocket ─────────────────────────────────────────────────────────────

    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        ws_id = self._new_ws_id()
        user = request.get("auth_user", "anonymous")
        logger.info("WS conectado: %s user=%s", ws_id, user)

        async def send(msg: dict) -> None:
            if not ws.closed:
                try:
                    await ws.send_json(msg)
                except Exception:
                    pass

        async def log(level: str, text: str) -> None:
            await send({"type": "log", "level": level, "text": text})

        try:
            msg_raw = await asyncio.wait_for(ws.receive_json(), timeout=30)
        except (TimeoutError, Exception) as e:
            logger.error("WS receive error: %s", e)
            await ws.close()
            return ws

        try:
            msg = InputValidator.ws_message(msg_raw)
        except ValidationError as e:
            await send({"type": "error", "text": f"Input inválido: {e.field} — {e.reason}"})
            await ws.close()
            return ws

        task = msg["task"]
        if task in HOST_TASKS and not self._may_touch_host(request):
            await send({"type": "error", "text": "Ese análisis actúa sobre el propio servidor: "
                                                  "solo lo puede lanzar el administrador de la plataforma"})
            await ws.close()
            return ws
        if err := await self._out_of_scope(scope_targets(msg)):
            await send({"type": "error", "text": err})
            await ws.close()
            return ws
        audit_log.scan_started(msg.get("target", "localhost"), task, user)

        # Crear scan en BD
        scan_id = await self.db.create_scan(task, triggered_by="manual")
        self._scan_id_cache[ws_id] = scan_id

        try:
            runner = getattr(self, WS_RUNNERS.get(task, ""), None)
            if runner:
                await runner(msg, ws_id, send, log, scan_id)
            else:
                await send({"type": "error", "text": f"Tarea desconocida: {task}"})
        except Exception as e:
            logger.error("Error en tarea WS %s: %s", task, e, exc_info=True)
            await self.db.fail_scan(scan_id)
            await send({"type": "error", "text": f"Error interno: {e}"})

        await ws.close()
        return ws

    async def _out_of_scope(self, targets: list[str] | None) -> str | None:
        """En una organización (multi-tenant), motivo por el que algún objetivo queda fuera de su ámbito.

        targets=None: la tarea no actúa sobre la red. Lista vacía: el escáner elegiría solo
        (p. ej. las redes del propio servidor), y eso a una organización no se le permite."""
        slug = current_tenant.get()
        if targets is None or not self.cfg.multi_tenant.enabled or slug == DEFAULT_TENANT:
            return None
        tenant = self.tenants.get(slug)
        allowed = (tenant.settings.get("allowed_targets") if tenant else None) or []
        if not allowed:
            return ("Esta organización todavía no tiene redes ni dominios permitidos: "
                    "pídeselo al administrador de la plataforma")
        if not targets:
            return "Indica qué redes o equipos analizar (dentro del ámbito de la organización)"
        return await Scope(allowed).check_all(targets)

    async def _emit_findings(
        self, findings: list[Finding], ws_id: str, send, scan_id: int
    ) -> None:
        """
        Filtra supresiones, guarda en BD y hace streaming al cliente.
        Los findings se envían uno a uno según llegan — no se acumulan en memoria.
        """
        findings = await self.db.filter_suppressed(findings)
        self._findings_cache.setdefault(ws_id, []).extend(findings)

        # Guardar en BD
        await self.db.complete_scan(scan_id, findings)

        # Comparación con scan anterior
        comparison = await self.db.get_comparison(scan_id)
        new_critical = [f for f in comparison.get("new", []) if f.get("severity") == "critical"]
        if new_critical:
            await send({"type": "new_critical", "count": len(new_critical)})

        # Streaming ordenado por severidad, con yield para no bloquear el event loop
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 5)):
            await send({"type": "finding", "data": f.to_dict()})
            # Enviar al SIEM en background (no bloquea si falla)
            siem_cfg = self._integration_settings("siem")
            if siem_cfg.wazuh_enabled or siem_cfg.elk_enabled or siem_cfg.splunk_enabled:
                asyncio.ensure_future(
                    self.siem.send_finding(f, self._scan_id_cache.get(ws_id, "unknown"))
                )
            await asyncio.sleep(0)  # yield al event loop entre findings

        history = await self.db.get_scan_history(limit=1)
        score = history[0]["score"] if history else None
        await send({"type": "done", "count": len(findings), "scan_id": scan_id, "score": score})

        # Notificar a clientes push si hay críticos
        critical = [f for f in findings if f.severity == "critical"]
        if critical:
            asyncio.ensure_future(self._broadcast_push("new_findings", {
                "scan_id": scan_id,
                "score":   score,
                "critical": len(critical),
                "total":   len(findings),
                "titles":  [f.title for f in critical[:3]],
            }))

        # En modo agente: enviar al manager en background
        if self.agent_reporter:
            scan_type = self._scan_id_cache.get(ws_id, "audit")
            asyncio.ensure_future(
                self.agent_reporter.report_scan(findings, str(scan_type), score)
            )

    async def _stream_findings(
        self,
        source,           # AsyncIterator[Finding] o Callable que acepta callback
        ws_id: str,
        send,
        scan_id: int,
        log,
    ) -> None:
        """
        Variante de _emit_findings para scans que producen findings de forma
        incremental (generators). Envía cada finding en cuanto llega sin esperar
        a que termine el scan completo.
        """
        collected: list[Finding] = []
        async for finding in source:
            if await self.db.is_suppressed(finding.id):
                continue
            collected.append(finding)
            self._findings_cache.setdefault(ws_id, []).append(finding)
            await send({"type": "finding", "data": finding.to_dict()})
            await asyncio.sleep(0)

        # Guardar en BD al terminar
        await self.db.complete_scan(scan_id, collected)
        comparison = await self.db.get_comparison(scan_id)
        new_critical = [f for f in comparison.get("new", []) if f.get("severity") == "critical"]
        if new_critical:
            await send({"type": "new_critical", "count": len(new_critical)})
        history = await self.db.get_scan_history(limit=1)
        score = history[0]["score"] if history else None
        await send({"type": "done", "count": len(collected), "scan_id": scan_id, "score": score})

    async def _run_local_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.hardening import HardeningAuditor
        await log("section", "Iniciando Hardening Audit local…")
        findings = await HardeningAuditor.full_audit(cfg=self.cfg)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_docker_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.docker_scan import DockerScanner
        await log("section", "Iniciando análisis de contenedores Docker + Kubernetes…")
        scan_images = params.get("scan_images_cve", True)
        scan_k8s    = params.get("scan_k8s", True)
        findings = await DockerScanner.full_scan(
            scan_images_cve=scan_images,
            scan_k8s=scan_k8s,
        )
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_services_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.services_audit import ServicesAuditor
        services = params.get("services") or None
        svc_str = ", ".join(services) if services else "nginx, apache, mysql, postgresql, redis, mongodb"
        await log("section", f"Auditando servicios: {svc_str}…")
        findings = await ServicesAuditor.full_audit(services=services)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_tls_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.tls_scan import TLSScanner
        # params.targets: lista de "host:port"; si no, usa defaults
        raw = params.get("targets") or []
        targets = None
        if raw:
            targets = []
            for t in raw:
                if ":" in str(t):
                    h, p = str(t).rsplit(":", 1)
                    targets.append((h, int(p)))
                else:
                    targets.append((str(t), 443))
        tgt_str = ", ".join(f"{h}:{p}" for h, p in (targets or TLSScanner.DEFAULT_TARGETS))
        await log("section", f"Escaneando TLS/SSL: {tgt_str}…")
        findings = await TLSScanner.full_scan(targets=targets)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_dns_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.dns_security import DNSSecurityScanner
        domains = params.get("domains") or []
        if not domains:
            await log("section", "No se indicaron dominios para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Auditando seguridad DNS: {', '.join(domains)}…")
        findings = await DNSSecurityScanner.full_scan(domains=domains)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_web_headers_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.web_headers import WebHeadersScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando cabeceras de seguridad: {', '.join(urls)}…")
        findings = await WebHeadersScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_web_exposure_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.web_exposure import WebExposureScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando exposición web: {', '.join(urls)}…")
        findings = await WebExposureScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_api_security_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.api_security import APISecurityScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para analizar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Analizando seguridad de API/CORS: {', '.join(urls)}…")
        findings = await APISecurityScanner.full_scan(urls=urls)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_subdomain_enum_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.subdomain_enum import SubdomainEnumScanner
        domains = params.get("domains") or []
        if not domains:
            await log("section", "No se indicaron dominios para enumerar")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        await log("section", f"Enumerando subdominios (CT logs): {', '.join(domains)}…")
        findings = await SubdomainEnumScanner.full_scan(domains=domains)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_nuclei_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.nuclei_scan import NucleiScanner
        urls = params.get("urls") or []
        if not urls:
            await log("section", "No se indicaron URLs para escanear con Nuclei")
            await self._emit_findings([], ws_id, send, scan_id)
            return
        severities = params.get("severities") or None
        await log("section", f"Ejecutando Nuclei sobre: {', '.join(urls)}…")
        findings = await NucleiScanner.full_scan(urls=urls, severities=severities)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_malware_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.malware import MalwareScanner
        skip = params.get("skip", [])
        await log("section", f"Iniciando Malware Scan (skip: {skip or 'ninguno'})…")
        findings = await MalwareScanner.full_scan(
            cfg=self.cfg, skip_modules=skip or None,
            yara_rules=params.get("yara_rules"),
            yara_paths=params.get("yara_paths") or None,
            web_roots=params.get("web_roots") or None,
        )
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_code_audit(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.code import CodeAuditor
        from cyberhound.scanners.secrets import SecretScanner
        path = params.get("path", "")
        if not Path(path).exists():
            await send({"type": "error", "text": f"Ruta no existe: {path}"})
            await self.db.fail_scan(scan_id)
            return
        await log("section", f"Analizando código en: {path}")
        findings = await CodeAuditor.full_analysis(Path(path))
        findings += await SecretScanner.scan(path)
        await self._emit_findings(findings, ws_id, send, scan_id)

    async def _run_network_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.network import NetworkScanner
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
        networks = [n.strip() for n in params.get("networks", "").split(",") if n.strip()] or None
        await log("section", "Fase 1/3: Descubriendo dispositivos…")
        scanner = NetworkScanner(nmap_timeout=self.cfg.scan.nmap_timeout)
        devices = await scanner.scan_network(
            networks=networks, deep=True,
            vuln_scan=params.get("vuln_scan", False),
        )
        await send({"type": "devices", "data": [d.to_dict() for d in devices]})
        await log("ok", f"✓ {len(devices)} dispositivos encontrados")

        # Actualizar inventario
        new_ips = []
        for dev in devices:
            asset = AssetRecord(
                ip=dev.ip, mac=dev.mac, hostname=dev.hostname,
                vendor=dev.vendor, os_name=dev.os_name,
                open_ports=json.dumps([
                    {"port": p.port, "service": p.service} for p in dev.open_ports
                ]),
                risk_level=dev.risk_level,
            )
            if await self.db.upsert_asset(asset):
                new_ips.append(dev.ip)
        if new_ips:
            await send({"type": "new_assets", "ips": new_ips})
            await log("warn", f"⚠ Nuevos dispositivos: {', '.join(new_ips)}")

        if not params.get("ssh_audit"):
            await self._emit_findings([], ws_id, send, scan_id)
            return

        ssh_hosts = [d for d in devices if d.has_ssh]
        if not ssh_hosts:
            await log("info", "Sin hosts SSH en los dispositivos detectados")
            await self._emit_findings([], ws_id, send, scan_id)
            return

        await log("section", f"Fase 2/3: SSH audit en {len(ssh_hosts)} hosts…")
        creds = SSHCredentials(
            username=params.get("ssh_user", self.cfg.scan.ssh_default_user),
            port=int(params.get("ssh_port", self.cfg.scan.ssh_default_port)),
            key_path=params.get("ssh_key") or self.cfg.scan.ssh_key_path,
            password=params.get("ssh_password") or None,
        )
        results = await RemoteAuditor.scan_multiple(
            [d.ip for d in ssh_hosts], creds,
            concurrency=self.cfg.scan.ssh_concurrency,
        )
        all_findings: list[Finding] = []
        for hr in results:
            await send({"type": "host_result", "data": {
                "host": hr.host, "status": hr.status,
                "count": len(hr.findings), "error": hr.error,
                "scan_time": hr.scan_time, "os_info": hr.os_info,
            }})
            if hr.status == "ok":
                all_findings.extend(hr.findings)
                await log("ok", f"✓ {hr.host}: {len(hr.findings)} hallazgos")
            else:
                await log("warn", f"✗ {hr.host}: {hr.status} — {hr.error}")
        await log("section", "Fase 3/3: Consolidando…")
        await self._emit_findings(all_findings, ws_id, send, scan_id)

    async def _run_ssh_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
        hosts = [h.strip() for h in re.split(r"[,\s\n]+", params.get("hosts", "")) if h.strip()]
        if not hosts:
            await send({"type": "error", "text": "Sin hosts"})
            await self.db.fail_scan(scan_id)
            return
        await log("section", f"SSH Scan en {len(hosts)} hosts…")
        creds = SSHCredentials(
            username=params.get("ssh_user", self.cfg.scan.ssh_default_user),
            port=int(params.get("ssh_port", self.cfg.scan.ssh_default_port)),
            key_path=params.get("ssh_key") or self.cfg.scan.ssh_key_path,
            password=params.get("ssh_password") or None,
        )
        results = await RemoteAuditor.scan_multiple(
            hosts, creds, concurrency=self.cfg.scan.ssh_concurrency
        )
        all_findings: list[Finding] = []
        for hr in results:
            await send({"type": "host_result", "data": hr.to_dict()})
            if hr.status == "ok":
                all_findings.extend(hr.findings)
                await log("ok", f"✓ {hr.host}: {len(hr.findings)} hallazgos")
            else:
                level = "warn" if hr.status == "unreachable" else "error"
                await log(level, f"✗ {hr.host}: {hr.status} — {hr.error}")
        await self._emit_findings(all_findings, ws_id, send, scan_id)

    async def _run_intel_scan(self, params, ws_id, send, log, scan_id):
        from cyberhound.scanners.intel import IntelScanner
        target = params.get("target", "")
        await log("section", f"Intel scan: {target}")
        scanner = IntelScanner(self.cfg.api_keys)
        if not scanner.configured_modules():
            await log("warn", "Sin API keys de threat intelligence configuradas")
        findings = await scanner.scan_findings(target, params.get("modules") or None)
        await self._emit_findings(findings, ws_id, send, scan_id)

    # ── Fix local ─────────────────────────────────────────────────────────────

    async def api_fix_local(self, request: web.Request) -> web.Response:
        try:
            body  = await _read_json(request)
            fid   = body.get("finding_id")
            dry   = body.get("dry_run", False)
            user  = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"}, status=404)
            if finding.source_host and finding.source_host not in ("localhost", "127.0.0.1"):
                # Sin esto el fix de un hallazgo remoto se aplicaba en este servidor
                return web.json_response({"ok": False, "error": "Hallazgo de otro host: usa el fix remoto"},
                                         status=400)
            from cyberhound.scanners.hardening import HardeningFixer
            fixer = HardeningFixer(dry_run=dry, keep_open_ports=(self.cfg.server.port,))
            ok, msg = await fixer.fix(finding)
            if not ok:
                return web.json_response({"ok": False, "error": msg or "El fix no se pudo aplicar"}, status=422)
            audit_log.fix_applied(fid, user, "localhost", dry)
            # Marcar como corregido en BD si tenemos el scan_id
            if ok and not dry:
                # Registrar en el journal de rollback para poder deshacer el fix.
                if fixer.rollback_actions:
                    from cyberhound.core.rollback import RollbackEntry
                    self._rollback_journal().append(RollbackEntry(
                        finding_id=fid, host="localhost", user=user, ts=time.time(),
                        fix_message=msg or finding.remediation,
                        actions=fixer.rollback_actions,
                    ))
                for ws_id, findings in self._own_caches():
                    if any(f.id == fid for f in findings):
                        scan_id = self._scan_id_cache.get(ws_id)
                        if scan_id:
                            await self.db.mark_finding_fixed(scan_id, fid, user)
                        break
            return web.json_response(
                {"ok": ok, "message": msg, "reversible": bool(fixer.rollback_actions) and not dry}
            )
        except Exception as e:
            logger.error("api_fix_local: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_fix_remote(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            fid  = body.get("finding_id")
            user = request.get("auth_user", "unknown")
            finding = self._find_cached(fid)
            if not finding:
                return web.json_response({"ok": False, "error": "Finding no encontrado"}, status=404)
            # El fix se aplica en el host donde se encontró el hallazgo, no en el que diga la petición
            host = finding.source_host or body.get("host", "")
            if not host or host in ("localhost", "127.0.0.1"):
                return web.json_response({"ok": False, "error": "El hallazgo no es de un host remoto"}, status=400)
            if err := await self._out_of_scope([host]):
                return web.json_response({"ok": False, "error": err}, status=403)
            from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials
            creds = SSHCredentials(
                username=body.get("ssh_user", self.cfg.scan.ssh_default_user),
                port=int(body.get("ssh_port", self.cfg.scan.ssh_default_port)),
                key_path=body.get("ssh_key") or self.cfg.scan.ssh_key_path,
                password=body.get("ssh_password") or None,
            )
            ok, msg = await RemoteAuditor(creds).apply_fix_remote(host, finding)
            audit_log.fix_applied(fid, user, host, False)
            return web.json_response({"ok": ok, "message": msg, **({} if ok else {"error": msg or "El fix no se pudo aplicar"})},
                                     status=200 if ok else 422)
        except Exception as e:
            logger.error("api_fix_remote: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Rollback de fixes locales ───────────────────────────────────────────────

    def _rollback_journal(self):
        from cyberhound.core.rollback import RollbackJournal
        return RollbackJournal(Path(self.cfg.server.log_dir) / "rollback-journal.jsonl")

    async def api_rollback_list(self, request: web.Request) -> web.Response:
        """Lista los fixes locales que aún se pueden deshacer."""
        try:
            entries = self._rollback_journal().list_active()
            return web.json_response({"ok": True, "entries": [
                {"finding_id": e.finding_id, "host": e.host, "user": e.user,
                 "ts": e.ts, "reversible": e.reversible, "fix_message": e.fix_message}
                for e in sorted(entries, key=lambda e: e.ts, reverse=True)
            ]})
        except Exception as e:
            logger.error("api_rollback_list: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_rollback_local(self, request: web.Request) -> web.Response:
        """Revierte el último fix local aplicado a un finding."""
        try:
            body = await _read_json(request)
            fid  = body.get("finding_id")
            user = request.get("auth_user", "unknown")
            if not fid:
                return web.json_response({"ok": False, "error": "finding_id requerido"}, status=400)
            from cyberhound.core.rollback import rollback_finding
            ok, msg = await rollback_finding(self._rollback_journal(), fid, host="localhost")
            audit_log.fix_rolled_back(fid, user, "localhost", ok)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            logger.error("api_rollback_local: %s", e, exc_info=True)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Observabilidad ─────────────────────────────────────────────────────────

    async def api_metrics(self, request: web.Request) -> web.Response:
        """Métricas en formato Prometheus (texto). Sin sesión solo desde el propio host (LOOPBACK_ROUTES)."""
        return web.Response(text=METRICS.render(), content_type="text/plain")

    # ── Explicación de hallazgos (LLM local) ───────────────────────────────────

    async def api_explain_finding(self, request: web.Request) -> web.Response:
        """Explica un hallazgo en lenguaje llano con el LLM local (best-effort)."""
        try:
            body = await _read_json(request)
            finding = self._find_cached(body.get("finding_id"))
            if not finding:
                return web.json_response({"error": "Finding no encontrado"}, status=404)
            from cyberhound.core.llm import explain_finding
            explanation = await explain_finding(finding.to_dict())
            if explanation is None:
                return web.json_response(
                    {"explanation": None, "detail": "El asistente LLM no está disponible ahora."}
                )
            return web.json_response({"explanation": explanation})
        except Exception as e:  # noqa: BLE001
            logger.error("api_explain_finding: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Histórico ─────────────────────────────────────────────────────────────

    async def api_history(self, request: web.Request) -> web.Response:
        scan_type = request.rel_url.query.get("type")
        limit = int(request.rel_url.query.get("limit", 50))
        history = await self.db.get_scan_history(scan_type, limit)
        return web.json_response(history)

    async def api_history_detail(self, request: web.Request) -> web.Response:
        try:
            scan_id = int(request.match_info["scan_id"])
            findings = await self.db.get_scan_findings(scan_id)
            return web.json_response(findings)
        except ValueError:
            return web.json_response({"error": "scan_id inválido"}, status=400)

    async def api_compare(self, request: web.Request) -> web.Response:
        try:
            scan_id = int(request.match_info["scan_id"])
            comparison = await self.db.get_comparison(scan_id)
            return web.json_response(comparison)
        except ValueError:
            return web.json_response({"error": "scan_id inválido"}, status=400)

    async def api_score_trend(self, request: web.Request) -> web.Response:
        scan_type = request.rel_url.query.get("type", "audit")
        days = int(request.rel_url.query.get("days", 30))
        trend = await self.db.get_score_trend(scan_type, days)
        return web.json_response(trend)

    async def api_score_detail(self, request: web.Request) -> web.Response:
        """Devuelve el score detallado con desglose contextual del último audit."""
        try:
            scan_id_str = request.rel_url.query.get("scan_id")
            if scan_id_str:
                scan_id = int(scan_id_str)
            else:
                history = await self.db.get_scan_history("audit", limit=1)
                if not history:
                    return web.json_response({"error": "Sin scans"}, status=404)
                scan_id = history[0]["id"]

            findings_raw = await self.db.get_scan_findings(scan_id)
            from cyberhound.core.models import Finding
            from cyberhound.core.scoring import compute_score
            findings = [Finding(
                id=f["finding_id"], category=f["category"], severity=f["severity"],
                title=f["title"], description=f.get("description", ""),
                remediation=f.get("remediation", ""),
                auto_fix=bool(f.get("auto_fix")),
            ) for f in findings_raw]
            result = compute_score(findings)
            return web.json_response(result.to_dict())
        except Exception as e:
            logger.error("api_score_detail: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_dashboard(self, request: web.Request) -> web.Response:
        stats = await self.db.get_dashboard_stats()
        return web.json_response(stats)

    # ── Inventario ────────────────────────────────────────────────────────────

    async def api_assets(self, request: web.Request) -> web.Response:
        assets = await self.db.get_assets()
        return web.json_response(assets)

    async def api_asset_authorize(self, request: web.Request) -> web.Response:
        try:
            ip = request.match_info["ip"]
            body = await _read_json(request)
            authorized = bool(body.get("authorized", True))
            notes = str(body.get("notes", ""))[:500]
            await self.db.set_asset_authorized(ip, authorized, notes)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_discover(self, request: web.Request) -> web.Response:
        try:
            networks_raw = request.rel_url.query.get("networks", "")
            networks = [n.strip() for n in networks_raw.split(",") if n.strip()] or None
            if err := await self._out_of_scope(networks or []):
                return web.json_response({"error": err}, status=403)
            from cyberhound.scanners.network import NetworkScanner
            ips = await NetworkScanner().discover_hosts(networks=networks)
            return web.json_response({"hosts": ips})
        except Exception as e:
            logger.error("api_discover: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Supresiones ───────────────────────────────────────────────────────────

    async def api_suppressions_list(self, request: web.Request) -> web.Response:
        return web.json_response(await self.db.get_suppressions())

    async def api_suppressions_add(self, request: web.Request) -> web.Response:
        try:
            body    = await _read_json(request)
            pattern = str(body.get("pattern", "")).strip()[:200]
            reason  = str(body.get("reason", "")).strip()[:500]
            expires = body.get("expires_at")
            user    = request.get("auth_user", "unknown")
            if not pattern or not reason:
                return web.json_response({"error": "pattern y reason son obligatorios"}, status=400)
            await self.db.add_suppression(pattern, reason, user, expires)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_suppressions_delete(self, request: web.Request) -> web.Response:
        from urllib.parse import unquote
        pattern = unquote(request.match_info["pattern"])
        await self.db.remove_suppression(pattern)
        return web.json_response({"ok": True})

    # ── Usuarios ──────────────────────────────────────────────────────────────

    async def api_users_list(self, request: web.Request) -> web.Response:
        users = await self.db.list_users()
        return web.json_response(users)

    async def api_users_create(self, request: web.Request) -> web.Response:
        try:
            body     = await _read_json(request)
            username = str(body.get("username", "")).strip()[:32]
            password = str(body.get("password", ""))
            role     = str(body.get("role", "viewer"))
            if not username or not password:
                return web.json_response({"error": "username y password son obligatorios"}, status=400)
            if role not in ("admin", "operator", "viewer"):
                return web.json_response({"error": "Rol inválido"}, status=400)
            if len(password) < 8:
                return web.json_response({"error": "Contraseña mínimo 8 caracteres"}, status=400)
            if not re.match(r'^[a-zA-Z0-9_\-]{1,32}$', username):
                return web.json_response({"error": "Username inválido"}, status=400)
            if (username == self.cfg.auth.username and current_tenant.get() == DEFAULT_TENANT) \
                    or await self.db.get_user(username):
                return web.json_response({"error": f"El usuario '{username}' ya existe"}, status=409)
            pw_hash = passwords.hash_password(password)
            try:
                await self.db.create_user(UserRecord(
                    username=username, password_hash=pw_hash, role=role
                ))
            except Exception:
                # el borrado es lógico (active=0): reutilizar el nombre reactiva la fila
                await self.db.update_user(username, password_hash=pw_hash, role=role, active=1)
            logger.info("Usuario '%s' creado con rol '%s' por %s",
                        username, role, request.get("auth_user"))
            await self._audit(request, "user_create", username, f"rol={role}")
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_update(self, request: web.Request) -> web.Response:
        try:
            username = request.match_info["username"]
            body = await _read_json(request)
            if username in (request.get("auth_user"), self.cfg.auth.username) and (
                ("role" in body and body["role"] != "admin") or ("active" in body and not body["active"])
            ):
                return web.json_response(
                    {"error": "No puedes quitarte el rol de admin ni desactivar tu propio usuario"}, status=400,
                )
            updates = {}
            if "role" in body:
                if body["role"] not in ("admin", "operator", "viewer"):
                    return web.json_response({"error": "Rol inválido"}, status=400)
                updates["role"] = body["role"]
            if "password" in body:
                if len(body["password"]) < 8:
                    return web.json_response({"error": "Contraseña mínimo 8 caracteres"}, status=400)
                updates["password_hash"] = passwords.hash_password(body["password"])
            if "active" in body:
                updates["active"] = int(bool(body["active"]))
            if not await self._user_exists(username):
                return web.json_response({"error": "Usuario no encontrado"}, status=404)
            if updates:
                await self.db.update_user(username, **updates)
            if "password_hash" in updates or updates.get("active") == 0:
                # Contraseña nueva o cuenta desactivada: fuera todas sus sesiones y tokens
                await self.db.revoke_user_sessions(username)
                await self.db.revoke_user_api_tokens(username)
            await self._audit(request, "user_update", username,
                              ", ".join(f"{k}={'***' if k == 'password_hash' else v}" for k, v in updates.items()))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_users_delete(self, request: web.Request) -> web.Response:
        username = request.match_info["username"]
        current  = request.get("auth_user", "")
        if username in (current, self.cfg.auth.username):
            return web.json_response({"error": "No puedes eliminar tu propio usuario ni el admin principal"}, status=400)
        if not await self._user_exists(username):
            return web.json_response({"error": "Usuario no encontrado"}, status=404)
        await self.db.update_user(username, active=0)
        await self.db.revoke_user_sessions(username)
        await self.db.revoke_user_api_tokens(username)
        await self._audit(request, "user_delete", username)
        return web.json_response({"ok": True})

    async def api_users_revoke_sessions(self, request: web.Request) -> web.Response:
        """Admin: cierra todas las sesiones y tokens de un usuario (p. ej. si pierde el portátil)."""
        username = request.match_info["username"]
        if not await self._user_exists(username):
            return web.json_response({"error": "Usuario no encontrado"}, status=404)
        n = await self.db.revoke_user_sessions(username, keep_jti=request.get("auth_jti"))
        t = await self.db.revoke_user_api_tokens(username)
        await self._audit(request, "sessions_revoke", username, f"{n} sesiones, {t} tokens")
        return web.json_response({"ok": True, "sessions": n, "tokens": t})

    # ── Mi cuenta: contraseña, sesiones y tokens ──────────────────────────────

    async def _audit(self, request: web.Request, action: str, target: str = "", detail: str = "",
                     ok: bool = True, own: bool = False) -> None:
        """Evento de auditoría (Configuración › Auditoría) en la BD del tenant actual; con own=True en la
        del propio usuario: lo que el superadmin hace con su cuenta no aparece en la organización que mira."""
        try:
            args = (action, request.get("auth_user", "") or "", _get_real_ip(request), target, detail, ok)
            if own:
                await _in_own_tenant(request, "add_audit_event", *args)
            else:
                await self.db.add_audit_event(*args)
        except Exception as e:  # noqa: BLE001 — la auditoría nunca rompe la operación
            logger.warning("Auditoría: %s", e)

    def _browser_session_only(self, request: web.Request) -> web.Response | None:
        """Con un token de API no se gestionan credenciales (contraseña, 2FA, sesiones, tokens)."""
        if request.get("auth_token_id"):
            return web.json_response({"error": "Necesita una sesión de navegador, no un token de API"}, status=403)
        if not request.get("auth_user"):
            return web.json_response({"error": "Sin sesión"}, status=401)
        return None

    async def api_me_password(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        body = await _read_json(request)
        current, new = str(body.get("current", "")), str(body.get("new", ""))
        user = request["auth_user"]
        if len(new) < 8:
            return web.json_response({"error": "La contraseña nueva necesita 8 caracteres"}, status=400)
        platform_admin = bool(request.get("superadmin"))
        if platform_admin:
            ok = passwords.verify_password(current, self.cfg.auth.password_hash or "")
        else:
            db_user = await _in_own_tenant(request, "get_user", user)
            ok = bool(db_user) and passwords.verify_password(current, db_user.get("password_hash") or "")
        if not ok:
            await self._audit(request, "password_change", user, "contraseña actual incorrecta", ok=False, own=True)
            return web.json_response({"error": "La contraseña actual no es correcta"}, status=400)
        new_hash = passwords.hash_password(new)
        if platform_admin:   # el admin de la plataforma vive en config.yaml
            self.cfg.auth.password_hash = new_hash
            request.app["auth_config"].password_hash = new_hash
            self.cfg.save()
        await _in_own_tenant(request, "update_user", user, password_hash=new_hash)
        n = await _in_own_tenant(request, "revoke_user_sessions", user, keep_jti=request.get("auth_jti"))
        await self._audit(request, "password_change", user, f"{n} sesiones cerradas", own=True)
        return web.json_response({"ok": True, "sessions_closed": n})

    async def api_sessions_list(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        jti = request.get("auth_jti")
        rows = await _in_own_tenant(request, "list_sessions", request["auth_user"])
        return web.json_response([{**{k: v for k, v in r.items() if k != "jti"}, "id": r["jti"][:8],
                                   "current": r["jti"] == jti} for r in rows])

    async def api_session_revoke(self, request: web.Request) -> web.Response:
        """Cierra una sesión propia por su id corto (los 8 primeros caracteres)."""
        if err := self._browser_session_only(request):
            return err
        short = request.match_info["jti"]
        own = await _in_own_tenant(request, "list_sessions", request["auth_user"])
        mine = [r["jti"] for r in own if r["jti"].startswith(short)]
        if len(short) < 8 or len(mine) != 1:
            return web.json_response({"error": "Sesión no encontrada"}, status=404)
        await _in_own_tenant(request, "revoke_session", mine[0], request["auth_user"])
        await self._audit(request, "session_revoke", request["auth_user"], short, own=True)
        return web.json_response({"ok": True, "current": mine[0] == request.get("auth_jti")})

    async def api_sessions_revoke_others(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        n = await _in_own_tenant(request, "revoke_user_sessions", request["auth_user"],
                                 keep_jti=request.get("auth_jti"))
        await self._audit(request, "sessions_revoke", request["auth_user"], f"{n} sesiones (menos la actual)", own=True)
        return web.json_response({"ok": True, "closed": n})

    async def api_tokens_list(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        return web.json_response(await _in_own_tenant(request, "list_api_tokens", request["auth_user"]))

    async def api_tokens_create(self, request: web.Request) -> web.Response:
        """Token de API para scripts/CI. El secreto solo se muestra ahora; se guarda su hash."""
        if err := self._browser_session_only(request):
            return err
        body = await _read_json(request)
        name = str(body.get("name", "")).strip()
        role = str(body.get("role") or request.get("user_role", "viewer"))
        days = body.get("expires_days", 90)
        if not name:
            return web.json_response({"error": "Ponle un nombre al token"}, status=400)
        if role not in ROLE_PERMISSIONS or cap_role(request.get("user_role", "viewer"), role) != role:
            return web.json_response({"error": "El token no puede tener más permisos que tu rol"}, status=400)
        if days not in (None, 0) and not (isinstance(days, int) and 1 <= days <= 365):
            return web.json_response({"error": "Caducidad entre 1 y 365 días (o sin caducidad)"}, status=400)
        token, token_id, token_hash = make_api_token(request.get("auth_tenant", DEFAULT_TENANT))
        expires = (datetime.now(UTC) + timedelta(days=days)).isoformat() if days else None
        await _in_own_tenant(request, "create_api_token", token_id, request["auth_user"], name,
                             token_hash, role, expires)
        await self._audit(request, "token_create", name, f"rol={role} caduca={expires or 'nunca'}", own=True)
        return web.json_response({"id": token_id, "token": token, "role": role, "expires_at": expires}, status=201)

    async def api_token_revoke(self, request: web.Request) -> web.Response:
        if err := self._browser_session_only(request):
            return err
        tid = request.match_info["token_id"]
        if not await _in_own_tenant(request, "revoke_api_token", tid, request["auth_user"]):
            return web.json_response({"error": "Token no encontrado"}, status=404)
        await self._audit(request, "token_revoke", tid, own=True)
        return web.json_response({"ok": True})

    async def api_audit_list(self, request: web.Request) -> web.Response:
        """Eventos de auditoría de la organización actual, con filtros."""
        q = request.rel_url.query
        try:
            limit = int(q.get("limit", "200"))
        except ValueError:
            return web.json_response({"error": "limit debe ser un entero"}, status=400)
        return web.json_response(await self.db.list_audit_events(
            limit=limit, action=q.get("action", ""), username=q.get("user", ""), q=q.get("q", ""),
            only_failures=q.get("failures") in ("1", "true")))

    async def _user_exists(self, username: str) -> bool:
        """Incluye desactivados (se pueden reactivar). Antes un usuario inexistente daba 200."""
        return any(u["username"] == username for u in await self.db.list_users())

    # ── Scheduler ─────────────────────────────────────────────────────────────

    async def api_scheduler_list(self, request: web.Request) -> web.Response:
        if not self.scheduler:
            return web.json_response([])
        return web.json_response(self.scheduler.list_entries())

    async def api_me(self, request: web.Request) -> web.Response:
        """Usuario de la sesión, su rol y permisos (la UI desactiva lo que daría 403)."""
        role = request.get("user_role", "admin")   # sin auth (localhost) todo está permitido
        slug = current_tenant.get()
        tenant = self.tenants.get(slug)
        return web.json_response({
            "username": request.get("auth_user", ""), "role": role,
            "permissions": sorted(ROLE_PERMISSIONS.get(role, set())),
            "multi_tenant": self.cfg.multi_tenant.enabled,
            "tenant": slug, "tenant_name": tenant.name if tenant else "Plataforma",
            "superadmin": bool(request.get("superadmin")) or not request.get("auth_user"),
            # False = la UI oculta lo que actúa sobre el servidor o es configuración global
            "host_access": self._may_touch_host(request),
        })

    async def api_scheduler_run(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if not self.scheduler:
            return web.json_response({"error": "Scheduler no activo"}, status=503)
        ok = await self.scheduler.run_now(name)
        return web.json_response({"ok": ok, "error": "Tarea no encontrada" if not ok else None}, status=200 if ok else 404)

    async def api_scheduler_toggle(self, request: web.Request) -> web.Response:
        try:
            name = request.match_info["name"]
            body = await _read_json(request)
            enabled = bool(body.get("enabled", True))
            if not self.scheduler:
                return web.json_response({"error": "Scheduler no activo"}, status=503)
            ok = self.scheduler.enable(name, enabled)
            if ok and name in ENTRY_FLAGS:          # que sobreviva a un reinicio
                setattr(self.cfg.scheduler, ENTRY_FLAGS[name], enabled)
                self.cfg.save()
            return web.json_response({"ok": ok}, status=200 if ok else 404)
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Análisis programados (de cada organización) ───────────────────────────

    async def api_schedules_list(self, request: web.Request) -> web.Response:
        rows = await self.db.list_schedules()
        running = {sid for slug, sid in self._schedules_running if slug == current_tenant.get()}
        return web.json_response([{**r, "running": r["id"] in running} for r in rows])

    async def _schedule_problem(self, data: dict) -> str | None:
        try:
            schedules.check_targets(data["task"], data["targets"])
        except ValueError as e:
            return str(e)
        return await self._out_of_scope(scope_targets(schedules.ws_message(data["task"], data["targets"])))

    async def api_schedules_create(self, request: web.Request) -> web.Response:
        try:
            data = schedules.validate(await _read_json(request))
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if err := await self._schedule_problem(data):
            return web.json_response({"error": err}, status=400)
        if await self.db.count_schedules() >= schedules.MAX_PER_TENANT:
            return web.json_response({"error": f"Máximo {schedules.MAX_PER_TENANT} programaciones"}, status=400)
        sid = await self.db.create_schedule(data, created_by=request.get("auth_user", ""))
        await self._audit(request, "schedule_create", data["name"], f"{data['task']} {','.join(data['targets'])[:150]}")
        return web.json_response(await self.db.get_schedule(sid), status=201)

    async def api_schedules_update(self, request: web.Request) -> web.Response:
        sid = request.match_info["sid"]
        current = await self.db.get_schedule(sid)
        if not current:
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        try:
            data = schedules.validate(await _read_json(request), partial=True)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if "task" in data or "targets" in data:
            if err := await self._schedule_problem({**current, **data}):
                return web.json_response({"error": err}, status=400)
        await self.db.update_schedule(sid, data)
        await self._audit(request, "schedule_update", current["name"], ",".join(sorted(data)))
        return web.json_response(await self.db.get_schedule(sid))

    async def api_schedules_delete(self, request: web.Request) -> web.Response:
        sid = request.match_info["sid"]
        current = await self.db.get_schedule(sid)
        if not current or not await self.db.delete_schedule(sid):
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        await self._audit(request, "schedule_delete", current["name"])
        return web.json_response({"ok": True})

    async def api_schedules_run(self, request: web.Request) -> web.Response:
        sched = await self.db.get_schedule(request.match_info["sid"])
        if not sched:
            return web.json_response({"error": "Programación no encontrada"}, status=404)
        slug = current_tenant.get()
        if (slug, sched["id"]) in self._schedules_running:
            return web.json_response({"error": "Ya se está ejecutando"}, status=409)
        self._start_schedule(slug, sched, triggered_by=request.get("auth_user", "manual"))
        await self._audit(request, "schedule_run", sched["name"])
        return web.json_response({"ok": True, "started": True}, status=202)

    def _schedule_slugs(self) -> list[str]:
        slugs = [DEFAULT_TENANT]
        if self.cfg.multi_tenant.enabled:
            slugs += [t.slug for t in self.tenants.list()]
        return slugs

    async def _schedules_tick(self, now: datetime | None = None) -> list[asyncio.Task]:
        """Lanza las programaciones que tocan en este minuto (hora local, como el scheduler)."""
        now = now or datetime.now()
        started = []
        for slug in self._schedule_slugs():
            ctx = current_tenant.set(slug)
            try:
                for sched in await self.db.list_schedules():
                    if schedules.is_due(sched, now) and (slug, sched["id"]) not in self._schedules_running:
                        started.append(self._start_schedule(slug, sched, triggered_by="schedule", now=now))
            except Exception as e:  # noqa: BLE001 — una organización con la BD rota no para a las demás
                logger.error("Programaciones de %s: %s", slug, e)
            finally:
                current_tenant.reset(ctx)
        return started

    async def _schedules_loop(self) -> None:
        while True:
            try:
                await self._schedules_tick()
            except Exception as e:  # noqa: BLE001
                logger.error("Bucle de programaciones: %s", e, exc_info=True)
            now = datetime.now()
            await asyncio.sleep(60 - now.second - now.microsecond / 1_000_000)

    def _start_schedule(self, slug: str, sched: dict, triggered_by: str, now: datetime | None = None) -> asyncio.Task:
        key = (slug, sched["id"])
        self._schedules_running.add(key)
        ctx = current_tenant.set(slug)        # la tarea hereda el contexto: BD e integraciones del tenant
        try:
            task = asyncio.ensure_future(self._run_schedule(slug, sched, triggered_by, now or datetime.now()))
        finally:
            current_tenant.reset(ctx)
        task.add_done_callback(lambda _t: self._schedules_running.discard(key))
        return task

    async def _run_schedule(self, slug: str, sched: dict, triggered_by: str, now: datetime) -> None:
        when = now.isoformat(timespec="seconds")
        await self.db.mark_schedule_run(sched["id"], when, "en curso", None)
        scan_id = None
        try:
            msg = schedules.ws_message(sched["task"], sched["targets"])
            if err := await self._out_of_scope(scope_targets(msg)):   # el ámbito pudo cambiar después
                await self.db.mark_schedule_run(sched["id"], when, f"fuera de ámbito: {err}", None)
                return
            scan_id = await self.db.create_scan(sched["task"], triggered_by=f"schedule:{triggered_by}")
            ws_id = f"sched:{slug}:{sched['id']}:{scan_id}"
            self._scan_id_cache[ws_id] = scan_id
            seen: dict = {"findings": [], "error": ""}

            async def send(m: dict) -> None:
                if m.get("type") == "finding":
                    seen["findings"].append(m["data"].get("severity"))
                elif m.get("type") == "error":
                    seen["error"] = m.get("text", "")

            async def log(level: str, text: str) -> None:
                return None

            try:
                await getattr(self, WS_RUNNERS[sched["task"]])(msg, ws_id, send, log, scan_id)
            finally:
                self._findings_cache.pop(ws_id, None)
                self._scan_id_cache.pop(ws_id, None)
            crit = seen["findings"].count("critical")
            status = f"error: {seen['error']}" if seen["error"] else f"ok: {len(seen['findings'])} hallazgos"
            await self.db.mark_schedule_run(sched["id"], when, status, scan_id)
            if crit:
                await self.notification_manager.send(
                    f"⏰ {sched['name']}: {crit} hallazgo(s) CRÍTICO(S)", level="critical", scan_id=scan_id)
        except Exception as e:  # noqa: BLE001
            logger.error("Programación %s/%s: %s", slug, sched["id"], e, exc_info=True)
            if scan_id:
                await self.db.fail_scan(scan_id)
            await self.db.mark_schedule_run(sched["id"], when, f"error: {e}", scan_id)

    # ── Configuración ─────────────────────────────────────────────────────────

    async def api_get_keys(self, request: web.Request) -> web.Response:
        keys = {
            k: (v[:4] + "***" if v else None)
            for k, v in self.cfg.api_keys.__dict__.items()
        }
        return web.json_response(keys)

    async def api_save_keys(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            for attr in ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"):
                v = body.get(attr, "")
                if v and not v.endswith("***"):
                    setattr(self.cfg.api_keys, attr, v)
            self.cfg.save()
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    # ── Integraciones: notificaciones, SIEM y ticketing ─────────────────────────

    def _tenant_obj(self):
        slug = current_tenant.get()
        if not self.cfg.multi_tenant.enabled or slug == DEFAULT_TENANT:
            return None
        return self.tenants.get(slug)

    def _integration_settings(self, kind: str):
        """Ajustes del canal para la organización actual (la plataforma: los de config.yaml)."""
        tenant = self._tenant_obj()
        if tenant is None:
            return getattr(self.cfg, kind)
        return integrations.settings_from_dict(kind, tenant.settings.get("integrations", {}).get(kind))

    def _integration(self, kind: str):
        slug = current_tenant.get() if self._tenant_obj() else DEFAULT_TENANT
        key = (slug, kind)
        if key not in self._integrations:
            settings = self._integration_settings(kind)
            mgr = integrations.build(kind, settings, db=self.db)
            if slug != DEFAULT_TENANT:
                allowed = self.tenants.get(slug).settings.get("allowed_targets", [])
                mgr = integrations.GuardedIntegration(kind, mgr, settings, allowed, logger)
            self._integrations[key] = mgr
        return self._integrations[key]

    @property
    def notification_manager(self):
        return self._integration("notifications")

    @property
    def siem(self):
        return self._integration("siem")

    @property
    def ticketing(self):
        return self._integration("ticketing")

    async def _get_integration(self, kind: str) -> web.Response:
        return web.json_response(integrations.public_view(kind, self._integration_settings(kind)))

    async def _save_integration(self, request: web.Request, kind: str) -> web.Response:
        body = await _read_json(request)
        settings = self._integration_settings(kind)
        try:
            integrations.apply_update(kind, settings, body)
        except ValueError as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)
        tenant = self._tenant_obj()
        if tenant is not None:
            if problem := await integrations.outbound_problem(kind, settings, tenant.settings.get("allowed_targets", [])):
                return web.json_response({"ok": False, "error": problem}, status=400)
            self.tenants.set_setting(tenant.slug, "integrations",
                                     {**tenant.settings.get("integrations", {}), kind: dataclasses.asdict(settings)})
        else:
            self.cfg.save()
        self._integrations.pop((tenant.slug if tenant else DEFAULT_TENANT, kind), None)   # se reconstruye con todo
        await self._audit(request, f"config_{kind}", kind)
        return web.json_response({"ok": True})

    async def _test_integration(self, kind: str) -> web.Response:
        return web.json_response(await self._integration(kind).test())

    async def api_get_notifications_cfg(self, request: web.Request) -> web.Response:
        return await self._get_integration("notifications")

    async def api_save_notifications_cfg(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "notifications")

    async def api_test_notifications(self, request: web.Request) -> web.Response:
        return await self._test_integration("notifications")

    async def api_get_siem(self, request: web.Request) -> web.Response:
        return await self._get_integration("siem")

    async def api_save_siem(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "siem")

    async def api_test_siem(self, request: web.Request) -> web.Response:
        return await self._test_integration("siem")

    async def api_get_ticketing(self, request: web.Request) -> web.Response:
        return await self._get_integration("ticketing")

    async def api_save_ticketing(self, request: web.Request) -> web.Response:
        return await self._save_integration(request, "ticketing")

    async def api_test_ticketing(self, request: web.Request) -> web.Response:
        return await self._test_integration("ticketing")

    # ── WebSocket push — notificaciones sin polling ───────────────────────────

    async def push_websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """
        WebSocket de solo lectura para recibir notificaciones en tiempo real.
        El cliente se conecta una vez y recibe eventos conforme ocurren,
        sin necesidad de polling periódico.
        """
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._push_clients[ws] = current_tenant.get()
        logger.info("Push WS conectado: %d clientes activos", len(self._push_clients))
        try:
            # Enviar estado inicial al conectar
            stats = await self.db.get_dashboard_stats()
            await ws.send_json({"type": "initial", "data": stats})
            # Mantener conexión abierta esperando mensajes del cliente (ping/pong)
            async for msg in ws:
                if msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        finally:
            self._push_clients.pop(ws, None)
        return ws

    async def _broadcast_push(self, event_type: str, data: dict) -> None:
        """Envía un evento a todos los clientes push conectados."""
        if not self._push_clients:
            return
        message = {"type": event_type, "data": data, "ts": asyncio.get_event_loop().time()}
        tenant = current_tenant.get()   # el del escaneo que genera el evento
        for ws, ws_tenant in list(self._push_clients.items()):
            if ws_tenant != tenant:
                continue
            try:
                await ws.send_json(message)
            except Exception:
                self._push_clients.pop(ws, None)

    # ── OpenAPI / Swagger ─────────────────────────────────────────────────────

    async def api_openapi_spec(self, request: web.Request) -> web.Response:
        from cyberhound.core.openapi import build_openapi_spec
        scheme = "https" if request.secure else "http"
        server_url = f"{scheme}://{request.host}"
        return web.json_response(build_openapi_spec(server_url))

    async def api_swagger_ui(self, request: web.Request) -> web.Response:
        from cyberhound.core.openapi import SWAGGER_UI_HTML
        nonce = request.get("csp_nonce", "")
        html = SWAGGER_UI_HTML.replace("<script>", f'<script nonce="{nonce}">')
        return web.Response(text=html, content_type="text/html")

    # ── Ansible AWX/Tower ─────────────────────────────────────────────────────

    async def api_ansible_run(self, request: web.Request) -> web.Response:
        try:
            body     = await _read_json(request)
            scan_id  = body.get("scan_id")
            target   = body.get("target", "localhost")
            mode     = body.get("mode", "local")  # local | awx

            # Cargar findings del scan
            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
                from cyberhound.core.models import Finding as F
                findings = [F(
                    id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    description=f.get("description",""), remediation=f.get("remediation",""),
                    auto_fix=bool(f.get("auto_fix")),
                ) for f in findings_raw]
            else:
                findings = []

            from cyberhound.core.ansible_integration import generate_playbook, run_playbook_local
            playbook = generate_playbook(findings, target)
            if not playbook:
                return web.json_response({"error": "Sin hallazgos con corrección automática"}, status=400)

            if mode == "local":
                job = await run_playbook_local(playbook, target)
            else:
                # AWX mode
                awx_cfg = getattr(self.cfg, 'awx', None)
                if not awx_cfg or not getattr(awx_cfg, 'enabled', False):
                    return web.json_response({"error": "AWX no configurado"}, status=400)
                from cyberhound.core.ansible_integration import AWXClient, AWXConfig
                client = AWXClient(AWXConfig(
                    url=awx_cfg.url, token=awx_cfg.token,
                    org_id=getattr(awx_cfg,'org_id',1),
                ))
                template_id = body.get("template_id", 1)
                job = await client.launch_job_template(int(template_id))

            self._ansible_jobs.insert(0, {
                "job_id": job.job_id, "status": job.status,
                "target": target, "mode": mode,
                "started_at": job.started_at,
                "output_preview": job.output[:500] if job.output else "",
            })
            return web.json_response({
                "job_id":  job.job_id,
                "status":  job.status,
                "output":  job.output[-3000:] if job.output else "",
                "playbook": playbook[:2000],
            })
        except Exception as e:
            logger.error("api_ansible_run: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_ansible_jobs(self, request: web.Request) -> web.Response:
        return web.json_response(self._ansible_jobs[:20])

    async def api_ansible_templates(self, request: web.Request) -> web.Response:
        awx_cfg = getattr(self.cfg, 'awx', None)
        if not awx_cfg or not getattr(awx_cfg, 'enabled', False):
            return web.json_response({"error": "AWX no configurado"}, status=400)
        from cyberhound.core.ansible_integration import AWXClient, AWXConfig
        client = AWXClient(AWXConfig(url=awx_cfg.url, token=awx_cfg.token))
        templates = await client.list_job_templates()
        return web.json_response(templates)

    # ── Multi-tenant ──────────────────────────────────────────────────────────

    async def api_tenants_list(self, request: web.Request) -> web.Response:
        return web.json_response([t.to_dict() for t in self.tenants.list()])

    async def api_tenants_create(self, request: web.Request) -> web.Response:
        """Crea el tenant, su BD y (opcional) su primer administrador."""
        try:
            body = await _read_json(request)
            admin_user = str(body.get("admin_username") or "").strip()
            admin_pw = str(body.get("admin_password") or "")
            if admin_user and len(admin_pw) < 8:
                return web.json_response({"error": "La contraseña del administrador necesita 8 caracteres"},
                                         status=400)
            tenant = self.tenants.create(
                slug=str(body.get("slug", "")).strip().lower(), name=str(body.get("name", "")),
                admin_email=str(body.get("admin_email", "")), plan=str(body.get("plan", "starter")),
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        await self.tenant_dbs.ensure(tenant.slug)
        if admin_user:
            ctx = current_tenant.set(tenant.slug)
            try:
                await self.db.create_user(UserRecord(username=admin_user, role="admin",
                                                     password_hash=passwords.hash_password(admin_pw)))
            finally:
                current_tenant.reset(ctx)
        logger.info("Tenant creado por %s: %s", request.get("auth_user"), tenant.slug)
        return web.json_response(tenant.to_dict(include_key=True), status=201)

    async def api_tenant_get(self, request: web.Request) -> web.Response:
        tenant = self.tenants.get(request.match_info["slug"])
        if not tenant or not tenant.active:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response(tenant.to_dict())

    async def api_tenant_update(self, request: web.Request) -> web.Response:
        try:
            t = self.tenants.update(request.match_info["slug"], **(await _read_json(request)))
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if not t:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response(t.to_dict())

    async def api_tenant_delete(self, request: web.Request) -> web.Response:
        """Baja: el tenant deja de funcionar y sus datos se archivan (no se borran)."""
        slug = request.match_info["slug"]
        if not self.tenants.delete(slug):
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        await self.tenant_dbs.archive(slug)
        logger.info("Tenant dado de baja por %s: %s", request.get("auth_user"), slug)
        return web.json_response({"ok": True})

    async def api_tenant_rotate_key(self, request: web.Request) -> web.Response:
        key = self.tenants.rotate_api_key(request.match_info["slug"])
        if not key:
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        return web.json_response({"api_key": key})

    async def api_tenant_agent_key(self, request: web.Request) -> web.Response:
        """API key del tenant actual, para configurar sus agentes. Solo su administrador."""
        tenant = self.tenants.get(current_tenant.get())
        if not self.cfg.multi_tenant.enabled or not tenant:
            return web.json_response({"error": "Solo en una organización (modo multi-tenant)"}, status=404)
        if request.get("user_role") != "admin":
            return web.json_response({"error": "Solo el administrador de la organización"}, status=403)
        return web.json_response({"tenant": tenant.slug, "api_key": tenant.api_key})

    async def api_tenant_switch(self, request: web.Request) -> web.Response:
        """El superadmin elige qué tenant mira la UI (cookie ch_tenant)."""
        if not self.cfg.multi_tenant.enabled or not request.get("superadmin"):
            return web.json_response({"error": "Solo el administrador de la plataforma"}, status=403)
        slug = str((await _read_json(request)).get("slug") or DEFAULT_TENANT)
        if slug != DEFAULT_TENANT and not self.tenants.is_active(slug):
            return web.json_response({"error": "Tenant no encontrado"}, status=404)
        resp = web.json_response({"ok": True, "tenant": slug})
        resp.set_cookie(TENANT_COOKIE, slug, httponly=True, samesite="Strict", secure=request.secure,
                        max_age=int(self.cfg.auth.token_ttl_hours) * 3600)
        return resp

    # ── Runtime container scan ────────────────────────────────────────────────

    async def api_runtime_scan(self, request: web.Request) -> web.Response:
        try:
            body       = await _read_json(request)
            containers = body.get("containers") or None
            from cyberhound.scanners.runtime_scan import RuntimeScanner
            scan_id  = await self.db.create_scan("runtime", triggered_by="manual")
            findings = await RuntimeScanner.full_scan(containers=containers)
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_runtime_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Importación de auditorías externas ───────────────────────────────────

    async def api_import_formats(self, request: web.Request) -> web.Response:
        """GET /api/import/formats — formatos soportados y sus descripciones."""
        return web.json_response({
            "formats": [
                {
                    "id":          "nessus",
                    "name":        "Tenable Nessus (.nessus)",
                    "description": "Exportación XML de Tenable Nessus, Tenable.io o Tenable.sc",
                    "extensions":  [".nessus", ".xml"],
                    "type":        "vulnerability",
                },
                {
                    "id":          "xccdf",
                    "name":        "OpenSCAP / XCCDF (.xml)",
                    "description": "Resultados XCCDF de oscap, Red Hat Satellite, Ansible Security. "
                                   "Compatible con perfiles CIS y STIG para RHEL 7/8/9.",
                    "extensions":  [".xml"],
                    "type":        "compliance",
                },
                {
                    "id":          "csv",
                    "name":        "CSV genérico",
                    "description": "Exportaciones CSV de Tenable, Qualys, OpenVAS o cualquier herramienta.",
                    "extensions":  [".csv"],
                    "type":        "vulnerability",
                },
                {
                    "id":          "json",
                    "name":        "JSON (CyberHound o genérico)",
                    "description": "Formato JSON propio de CyberHound o lista de findings.",
                    "extensions":  [".json"],
                    "type":        "generic",
                },
            ],
            "note": "CyberHound distingue entre hallazgos de CUMPLIMIENTO (compliance/*, "
                    "procedentes de XCCDF/CIS/STIG) y VULNERABILIDADES (vulnerability/*, "
                    "procedentes de Nessus/CVE). Ambos tipos se pueden ver por separado en la UI.",
        })

    async def api_import_audit(self, request: web.Request) -> web.Response:
        """
        POST /api/import/audit — importa un fichero de auditoría externo.

        Acepta multipart/form-data con:
          - file: el fichero de auditoría
          - format: (opcional) forzar formato ("nessus", "xccdf", "csv", "json")
          - scan_type: (opcional) tipo de scan a crear (default: "imported")
          - target: (opcional) objetivo/host del scan
        """
        try:
            reader = await request.multipart()
            content = b""
            filename = ""
            fmt = None
            scan_type = "imported"
            target = "imported"

            async for part in reader:
                if part.name == "file":
                    filename = part.filename or "upload"
                    content = await part.read(decode=True)
                elif part.name == "format":
                    fmt = (await part.read(decode=True)).decode().strip()
                elif part.name == "scan_type":
                    scan_type = (await part.read(decode=True)).decode().strip()
                elif part.name == "target":
                    target = (await part.read(decode=True)).decode().strip()

            if not content:
                return web.json_response(
                    {"error": "No se recibió ningún fichero. Envía 'file' como campo multipart."},
                    status=400,
                )

            from cyberhound.scanners.audit_import import import_audit_file
            result = import_audit_file(content, filename, fmt or None)

            if result.errors and not result.findings:
                return web.json_response(
                    {"error": result.errors[0], "all_errors": result.errors},
                    status=400,
                )

            # Guardar en la BD como un scan de tipo "imported" / "xccdf" / "nessus"
            actual_scan_type = result.source if result.source != "unknown" else scan_type
            scan_id = await self.db.create_scan(
                actual_scan_type, target=target or filename,
                triggered_by="import",
            )
            filtered = await self.db.filter_suppressed(result.findings)
            await self.db.complete_scan(scan_id, filtered)

            logger.info(
                "Auditoría importada: %s → scan_id=%d, %d findings (%d skipped)",
                filename, scan_id, result.imported, result.skipped,
            )

            return web.json_response({
                "scan_id":   scan_id,
                "source":    result.source,
                "filename":  filename,
                "imported":  result.imported,
                "skipped":   result.skipped,
                "total":     result.total,
                "errors":    result.errors,
                "metadata":  result.metadata,
                "findings":  [f.to_dict() for f in filtered[:50]],  # preview
                "note": (
                    "Los hallazgos de tipo 'compliance/*' son checks de bastionado/cumplimiento. "
                    "Los de 'vulnerability/*' son vulnerabilidades CVE/CVSSv3."
                ),
            })

        except Exception as e:
            logger.error("api_import_audit: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Docker image deep scan ────────────────────────────────────────────────

    async def api_docker_image_scan(self, request: web.Request) -> web.Response:
        """Análisis profundo del filesystem de imágenes Docker."""
        try:
            body      = await _read_json(request)
            images    = body.get("images") or None
            deep      = body.get("deep", True)
            max_imgs  = min(int(body.get("max_images", 5)), 10)
            max_mb    = int(body.get("max_size_mb", 200))
            user      = request.get("auth_user", "unknown")

            from cyberhound.scanners.docker_image_scan import DockerImageScanner
            scan_id  = await self.db.create_scan("docker_image", triggered_by=user)
            findings = await DockerImageScanner.scan_images(
                images=images, max_images=max_imgs,
                deep_scan=deep, max_size_mb=max_mb,
            )
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_docker_image_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Monitor status ────────────────────────────────────────────────────────

    async def api_monitor_status(self, request: web.Request) -> web.Response:
        """Estado del monitor eBPF/auditd en tiempo real."""
        monitor = self._ebpf_monitor
        if not monitor:
            return web.json_response({
                "active": False, "mode": "none",
                "message": "Monitor no iniciado",
            })
        return web.json_response({
            "active":  self._ebpf_monitor.mode != "none",
            "mode":    self._ebpf_monitor.mode,
            "message": f"Monitor activo en modo {self._ebpf_monitor.mode}",
        })

    # ── PDF Report ────────────────────────────────────────────────────────────

    async def api_report_pdf(self, request: web.Request) -> web.Response:
        """Genera un informe PDF del último scan o de los findings proporcionados."""
        try:
            body       = await _read_json(request)
            scan_id    = body.get("scan_id")
            scan_type  = body.get("scan_type", "audit")
            target     = body.get("target", "localhost")

            # Cargar findings
            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
                findings = [Finding(
                    id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    description=f.get("description",""), remediation=f.get("remediation",""),
                    auto_fix=bool(f.get("auto_fix")),
                ) for f in findings_raw]
                # Score del scan pedido (antes solo se miraba el último scan del historial)
                scan = await self.db.get_scan(int(scan_id))
                score = scan["score"] if scan else None
            else:
                findings_raw = body.get("findings", [])
                findings = [Finding.from_dict(f) for f in findings_raw]
                score = body.get("score")

            from cyberhound.scanners.pdf_report import generate_pdf
            tenant = self.tenants.get(current_tenant.get())
            pdf_bytes = generate_pdf(
                findings, target=target, scan_type=scan_type,
                score=score, organization=tenant.name if tenant else "",
            )

            # Determinar tipo de contenido
            content_type = "application/pdf" if pdf_bytes[:4] == b"%PDF" else "text/html"
            ext = "pdf" if content_type == "application/pdf" else "html"
            filename = f"cyberhound-report-{scan_type}-{datetime.now().strftime('%Y%m%d')}.{ext}"

            return web.Response(
                body=pdf_bytes,
                content_type=content_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )
        except Exception as e:
            logger.error("api_report_pdf: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Compliance ────────────────────────────────────────────────────────────

    async def api_compliance(self, request: web.Request) -> web.Response:
        """Analiza compliance a partir de los findings del último scan o scan_id."""
        try:
            body       = await _read_json(request)
            scan_id    = body.get("scan_id")
            frameworks = body.get("frameworks") or None

            if scan_id:
                findings_raw = await self.db.get_scan_findings(int(scan_id))
            else:
                history = await self.db.get_scan_history("audit", limit=1)
                if not history:
                    return web.json_response({"error": "Sin scans disponibles"}, status=404)
                findings_raw = await self.db.get_scan_findings(history[0]["id"])

            findings = [Finding(
                id=f["finding_id"], category=f["category"],
                severity=f["severity"], title=f["title"],
                description=f.get("description",""), remediation=f.get("remediation",""),
            ) for f in findings_raw]

            from cyberhound.scanners.compliance import analyze_compliance, compliance_to_dict
            results = analyze_compliance(findings, frameworks=frameworks)
            return web.json_response(compliance_to_dict(results))
        except Exception as e:
            logger.error("api_compliance: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_compliance_get(self, request: web.Request) -> web.Response:
        """GET /api/compliance — compliance del último audit automáticamente."""
        frameworks_param = request.rel_url.query.get("frameworks", "")
        frameworks = frameworks_param.split(",") if frameworks_param else None
        history = await self.db.get_scan_history("audit", limit=1)
        if not history:
            return web.json_response({})
        findings_raw = await self.db.get_scan_findings(history[0]["id"])
        findings = [Finding(
            id=f["finding_id"], category=f["category"],
            severity=f["severity"], title=f["title"],
            description=f.get("description",""), remediation=f.get("remediation",""),
        ) for f in findings_raw]
        from cyberhound.scanners.compliance import analyze_compliance, compliance_to_dict
        results = analyze_compliance(findings, frameworks=frameworks)
        return web.json_response(compliance_to_dict(results))

    # ── Cuarentena ────────────────────────────────────────────────────────────

    async def api_quarantine_list(self, request: web.Request) -> web.Response:
        from cyberhound.core.quarantine import list_quarantine
        return web.json_response(list_quarantine())

    async def api_quarantine_stats(self, request: web.Request) -> web.Response:
        from cyberhound.core.quarantine import quarantine_stats
        return web.json_response(quarantine_stats())

    async def api_quarantine_add(self, request: web.Request) -> web.Response:
        try:
            body       = await _read_json(request)
            filepath   = str(body.get("filepath", "")).strip()
            finding_id = str(body.get("finding_id", ""))
            title      = str(body.get("title", ""))
            user       = request.get("auth_user", "unknown")
            if not filepath:
                return web.json_response({"ok": False, "error": "filepath requerido"}, status=400)
            from cyberhound.core.quarantine import quarantine_file
            ok, msg = quarantine_file(filepath, finding_id, title, quarantined_by=user)
            logger.info("Cuarentena [%s]: %s → %s", user, filepath, "OK" if ok else msg)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_quarantine_restore(self, request: web.Request) -> web.Response:
        try:
            name = request.match_info["name"]
            body = await _read_json(request)
            restore_path = body.get("path") or None
            from cyberhound.core.quarantine import restore_file
            ok, msg = restore_file(name, restore_path)
            return web.json_response({"ok": ok, "message": msg})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_quarantine_delete(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        from cyberhound.core.quarantine import delete_quarantined
        ok, msg = delete_quarantined(name)
        return web.json_response({"ok": ok, "message": msg})

    # ── SBOM ──────────────────────────────────────────────────────────────────

    async def api_sbom_generate(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            include   = body.get("include") or None
            pip_venvs = body.get("pip_venvs") or None
            from cyberhound.scanners.sbom import SBOMGenerator
            sbom = await SBOMGenerator.generate(include=include, pip_venvs=pip_venvs)
            fmt  = body.get("format", "json")   # json | cyclonedx | spdx

            if fmt == "cyclonedx":
                return web.json_response(sbom.to_cyclonedx())
            elif fmt == "spdx":
                return web.Response(text=sbom.to_spdx_basic(), content_type="text/plain",
                    headers={"Content-Disposition": "attachment; filename=sbom.spdx"})
            else:
                data = sbom.to_dict()
                self._sbom_cache = data
                return web.json_response(data)
        except Exception as e:
            logger.error("api_sbom_generate: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_sbom_latest(self, request: web.Request) -> web.Response:
        if self._sbom_cache:
            return web.json_response(self._sbom_cache)
        return web.json_response({"error": "Sin SBOM generado — ejecuta /api/sbom/generate"}, status=404)

    # ── LDAP / AD ─────────────────────────────────────────────────────────────

    async def api_ldap_scan(self, request: web.Request) -> web.Response:
        """Ejecuta un audit de LDAP/AD y devuelve los hallazgos."""
        try:
            body   = await _read_json(request)
            user   = request.get("auth_user", "unknown")
            if err := await self._out_of_scope([body.get("uri", "")]):
                return web.json_response({"error": err}, status=403)
            from cyberhound.scanners.ldap_audit import LDAPAuditor
            scan_id = await self.db.create_scan("ldap", triggered_by=user)
            findings = await LDAPAuditor.full_audit(
                uri=body.get("uri", ""),
                base=body.get("base", ""),
                binddn=body.get("binddn", ""),
                bindpw=body.get("bindpw", ""),
            )
            findings = await self.db.filter_suppressed(findings)
            await self.db.complete_scan(scan_id, findings)
            return web.json_response({
                "scan_id":  scan_id,
                "count":    len(findings),
                "findings": [f.to_dict() for f in findings],
            })
        except Exception as e:
            logger.error("api_ldap_scan: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Modo agente ───────────────────────────────────────────────────────────

    async def api_get_agent_cfg(self, request: web.Request) -> web.Response:
        a = self.cfg.agent
        return web.json_response({
            "mode":        a.mode,
            "manager_url": a.manager_url,
            "agent_name":  a.agent_name,
            "has_key":     bool(a.agent_key),   # la clave nunca se devuelve
        })

    async def api_save_agent_cfg(self, request: web.Request) -> web.Response:
        try:
            body = await _read_json(request)
            a = self.cfg.agent
            mode = body.get("mode")
            if mode in ("standalone", "manager", "agent"):
                a.mode = mode
            for field in ("manager_url", "agent_name"):
                if field in body:
                    setattr(a, field, str(body[field] or ""))
            if body.get("agent_key"):            # solo si no está vacío
                a.agent_key = str(body["agent_key"])
            self.cfg.save()
            # el AgentManager se creó al arrancar con una copia: sin esto la clave nueva no valía hasta reiniciar
            for field in ("mode", "manager_url", "agent_key", "agent_name"):
                setattr(self.agent_manager.cfg, field, getattr(a, field))
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def api_agent_report(self, request: web.Request) -> web.Response:
        """Recibe hallazgos enviados por un agente remoto."""
        # Verificar clave del agente (no JWT)
        auth  = request.headers.get("Authorization", "")
        key   = self.agent_manager.extract_agent_key(auth)
        # Clave global (tenant "default") o la API key del tenant (la reconoce tenant_middleware)
        if not (request.get("tenant_agent_key") or self.agent_manager.verify_agent_key(key)):
            return web.json_response({"error": "Clave de agente inválida"}, status=401)
        try:
            payload = await _read_json(request)
            result  = await self.agent_manager.receive_report(payload)
            return web.json_response(result)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            logger.error("api_agent_report: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def api_agent_heartbeat(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        key  = self.agent_manager.extract_agent_key(auth)
        if not (request.get("tenant_agent_key") or self.agent_manager.verify_agent_key(key)):
            return web.json_response({"error": "Clave inválida"}, status=401)
        payload = await _read_json(request)
        await self.agent_manager.receive_heartbeat(payload)
        return web.json_response({"ok": True})

    async def api_agent_list(self, request: web.Request) -> web.Response:
        return web.json_response(self.agent_manager.list_agents())

    # ── 2FA / TOTP ────────────────────────────────────────────────────────────

    async def api_2fa_setup(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_setup(request)

    async def _api_2fa_setup(self, request: web.Request) -> web.Response:
        """Inicia la configuración de 2FA — devuelve QR y secreto."""
        if err := self._browser_session_only(request):
            return err
        user = request.get("auth_user", "")
        if not user:
            return web.json_response({"error": "Sin sesión"}, status=401)
        from cyberhound.core.totp import TOTPManager
        mgr = TOTPManager(self.db, request.app["auth_config"].secret)
        data = await mgr.setup_2fa(user)
        return web.json_response({
            "secret":         data["secret"],
            "uri":            data["uri"],
            "qr_svg":         data["qr_svg"],
            "recovery_codes": data["recovery_codes"],
        })

    async def api_2fa_activate(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_activate(request)

    async def _api_2fa_activate(self, request: web.Request) -> web.Response:
        """Activa el 2FA verificando el primer código."""
        if err := self._browser_session_only(request):
            return err
        user = request.get("auth_user", "")
        try:
            body = await _read_json(request)
            code = str(body.get("code", "")).strip()
        except Exception:
            return web.json_response({"ok": False, "error": "Body inválido"}, status=400)
        from cyberhound.core.totp import TOTPManager
        ok = await TOTPManager(self.db, request.app["auth_config"].secret).activate_2fa(user, code)
        if ok:
            logger.info("2FA activado para '%s'", user)
        await self._audit(request, "2fa_enable", user, "" if ok else "código incorrecto", ok=ok, own=True)
        return web.json_response({"ok": ok, "error": None if ok else "Código incorrecto"}, status=200 if ok else 400)

    async def api_2fa_disable(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_disable(request)

    async def _api_2fa_disable(self, request: web.Request) -> web.Response:
        """Desactiva el 2FA del usuario actual: exige un código válido (TOTP o de recuperación).
        Antes no pedía nada y quien tuviera una sesión robada podía quitar el 2FA de la cuenta."""
        user = request.get("auth_user", "")
        if err := self._browser_session_only(request):
            return err
        from cyberhound.core.totp import TOTPManager
        mgr = TOTPManager(self.db, request.app["auth_config"].secret)
        status = await self.db.get_user(user)
        if status and status.get("totp_enabled"):
            code = str((await _read_json(request)).get("code", "")).strip()
            ok, _reason = await mgr.verify(user, code)
            if not ok:
                await self._audit(request, "2fa_disable", user, "código incorrecto", ok=False, own=True)
                return web.json_response({"ok": False, "error": "Código incorrecto"}, status=400)
        await mgr.disable_2fa(user)
        logger.info("2FA desactivado para '%s'", user)
        await self._audit(request, "2fa_disable", user, own=True)
        return web.json_response({"ok": True})

    async def api_2fa_status(self, request: web.Request) -> web.Response:
        with _own_tenant_ctx(request):   # el 2FA es de la cuenta, no del tenant que se mira
            return await self._api_2fa_status(request)

    async def _api_2fa_status(self, request: web.Request) -> web.Response:
        """Devuelve el estado del 2FA del usuario actual."""
        user = request.get("auth_user", "")
        db_user = await self.db.get_user(user) if user else None
        enabled = bool(db_user.get("totp_enabled")) if db_user else False
        return web.json_response({"enabled": enabled, "user": user})

    # ── YARA update ───────────────────────────────────────────────────────────

    async def api_yara_update(self, request: web.Request) -> web.Response:
        """Descarga y actualiza reglas YARA desde repositorios públicos."""
        try:
            body = await _read_json(request)
            sources = body.get("sources", ["default"])
        except Exception:
            sources = ["default"]

        results = await _update_yara_rules(sources)
        return web.json_response(results)

    async def api_yara_list(self, request: web.Request) -> web.Response:
        """Lista las reglas YARA disponibles."""
        yara_dir = YARA_DIR
        yara_dir.mkdir(parents=True, exist_ok=True)
        rules = []
        for f in sorted(yara_dir.glob("*.yar")) + sorted(yara_dir.glob("*.yara")):
            try:
                stat = f.stat()
                rules.append({
                    "name": f.name,
                    "path": str(f),
                    "size_kb": round(stat.st_size / 1024, 1),
                    "modified": stat.st_mtime,
                })
            except OSError:
                pass
        return web.json_response(rules)

    # ── Informes ──────────────────────────────────────────────────────────────

    async def api_report(self, request: web.Request) -> web.Response:
        fmt = request.match_info.get("fmt", "html")
        try:
            body     = await _read_json(request)
            findings = [Finding.from_dict(d) for d in body.get("findings", [])]
            report   = ScanReport(target=body.get("source", "localhost"), local_findings=findings)
            from cyberhound.scanners.reports import ReportGenerator
            if fmt == "html":
                content = await ReportGenerator.html_report(report)
                return web.Response(body=content.encode(), content_type="text/html",
                                    headers={"Content-Disposition": "attachment; filename=report.html"})
            elif fmt == "ansible":
                content = ReportGenerator.ansible_playbook(findings)
                return web.Response(body=content.encode(), content_type="text/yaml",
                                    headers={"Content-Disposition": "attachment; filename=remediation.yml"})
            return web.json_response({"error": f"Formato desconocido: {fmt}"}, status=400)
        except Exception as e:
            logger.error("api_report: %s", e, exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _new_ws_id(self) -> str:
        # Solo se guardan las últimas conexiones: antes la caché crecía sin límite
        for old in list(self._findings_cache)[:-200]:
            self._findings_cache.pop(old, None)
            self._scan_id_cache.pop(old, None)
        return f"{current_tenant.get()}:{secrets.token_hex(8)}"

    def _own_caches(self):
        """Cachés de WS del tenant actual (nunca las de otro)."""
        prefix = current_tenant.get() + ":"
        return [(k, v) for k, v in self._findings_cache.items() if k.startswith(prefix)]

    def _may_touch_host(self, request: web.Request) -> bool:
        """Lo que actúa sobre este servidor: en multi-tenant solo el superadmin."""
        return not self.cfg.multi_tenant.enabled or bool(request.get("superadmin"))

    def _find_cached(self, finding_id: str) -> Finding | None:
        for _ws, fl in self._own_caches():
            for f in fl:
                if f.id == finding_id:
                    return f
        return None

    # ── Start ─────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        # 0. Validación eager de configuración
        errors = self.cfg.validate()
        if errors:
            print("\n❌ Errores de configuración detectados al arrancar:\n")
            for err in errors:
                print(f"   • {err}")
            print(
                f"\n   Edita la configuración: cyberhound setup --config {self.cfg.config_path}\n"
                f"   O directamente: {self.cfg.config_path}\n"
            )
            raise SystemExit(1)

        # Persistir el secreto JWT si aún no estaba guardado en config
        # (evita invalidar sesiones en cada reinicio del servidor)
        config_path = Path(self.cfg.config_path)
        if not self.cfg.auth.secret:
            import secrets as _sec
            self.cfg.auth.secret = _sec.token_hex(32)
        # Guardar solo si el secreto no estaba ya en el fichero
        try:
            import yaml as _yaml
            if config_path.exists():
                raw = _yaml.safe_load(config_path.read_text()) or {}
                if not raw.get("auth", {}).get("secret"):
                    self.cfg.save(config_path)
                    logger.info("JWT secret persistido en %s", config_path)
        except Exception as e:
            logger.warning("No se pudo persistir el JWT secret: %s", e)

        # 1. Inicializar BD
        await self.db.init()
        await self.db.ensure_admin_exists(
            self.cfg.auth.username,
            # sin contraseña configurada la fila de la BD lleva un hash inutilizable (nunca "cyberhound")
            self.cfg.auth.password_hash or passwords.hash_password(secrets.token_urlsafe(32)),
        )


        # 2. Construir app
        app = self.build_app()
        runner = web.AppRunner(app)
        await runner.setup()

        # 3. TLS
        ssl_ctx = None
        proto = "http"
        try:
            ssl_ctx = TLSManager.create_ssl_context(
                cert_path=self.cfg.server.tls_cert,
                key_path=self.cfg.server.tls_key,
            )
            proto = "https"
        except Exception as e:
            logger.error("TLS no disponible: %s — arrancando en HTTP (inseguro)", e)

        # 4. Bind
        site = web.TCPSite(runner, self.cfg.server.host, self.cfg.server.port, ssl_context=ssl_ctx)
        try:
            await site.start()
        except OSError as e:
            if e.errno == 98:
                import subprocess
                proc = subprocess.run(
                    ["ss", "-tlnp", f"sport = :{self.cfg.server.port}"],
                    capture_output=True, text=True,
                )
                print(
                    f"\n❌ Puerto {self.cfg.server.port} ya en uso.\n"
                    f"   Liberar: sudo pkill -f 'cyberhound web'\n"
                    f"   O usar otro: sudo cyberhound web --port 9443\n"
                    f"   {proc.stdout.strip()}\n"
                )
                raise SystemExit(1) from None
            raise

        # 5. Scheduler
        if self.cfg.scheduler.enabled:
            self.scheduler = build_platform_scheduler(self, self.cfg.scheduler)
            await self.scheduler.start()

        # Análisis programados de cada organización (y de la plataforma)
        self._schedules_task = asyncio.ensure_future(self._schedules_loop())

        # 6. Monitor eBPF/auditd en tiempo real (si está habilitado en config)
        if getattr(self.cfg, 'monitor_enabled', True):
            from cyberhound.core.ebpf_monitor import EBPFMonitor
            self._ebpf_monitor = EBPFMonitor(self)
            await self._ebpf_monitor.start()
            if self._ebpf_monitor.mode != "none":
                logger.info("Monitor en tiempo real activo (modo: %s)", self._ebpf_monitor.mode)

        cert_info = ""
        if ssl_ctx and not self.cfg.server.tls_cert:
            cert_path, _ = TLSManager.cert_paths()
            cert_info = f"\n   Certificado : {cert_path} (auto-firmado)"

        logger.info("CyberHound Pro v%s en %s://%s:%d",
                    __version__, proto, self.cfg.server.host, self.cfg.server.port)
        print(
            f"\n🐾 CyberHound Pro v{__version__} listo en "
            f"{proto}://{self.cfg.server.host}:{self.cfg.server.port}"
            f"{cert_info}"
            f"\n   Login: '{self.cfg.auth.username}'"
            f"\n   BD: {self.cfg.db_path}"
            f"\n   Scheduler: {'activo' if self.cfg.scheduler.enabled else 'desactivado'}\n"
        )
        await asyncio.Event().wait()
