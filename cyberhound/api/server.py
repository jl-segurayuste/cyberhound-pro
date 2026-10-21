"""
Servidor web de CyberHound Pro (aiohttp): estado, registro de rutas y arranque.

Los endpoints viven en cyberhound/api/handlers/ (un mixin por área: análisis, fixes, datos,
cuentas, programados, configuración y plataforma); middlewares, permisos y utilidades
compartidas, en cyberhound/api/common.py. Este módulo reexporta lo de common para quien lo
importe desde aquí.
"""
from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

from aiohttp import web

from cyberhound import __version__

# Se reexportan para quien importe desde cyberhound.api.server (tests, scripts)
from cyberhound.api.common import (
    _PLATFORM_PREFIXES as _PLATFORM_PREFIXES,
    HOST_TASKS as HOST_TASKS,
    METRICS as METRICS,
    NO_TARGETS as NO_TARGETS,
    ROLE_PERMISSIONS as ROLE_PERMISSIONS,
    WS_RUNNERS as WS_RUNNERS,
    YARA_SOURCES as YARA_SOURCES,
    _in_own_tenant as _in_own_tenant,
    _Metrics as _Metrics,
    _own_tenant_ctx as _own_tenant_ctx,
    _platform_only as _platform_only,
    _read_json as _read_json,
    _required_permission as _required_permission,
    _scope_status as _scope_status,
    _update_yara_rules as _update_yara_rules,
    rbac_middleware as rbac_middleware,
    request_logger_middleware as request_logger_middleware,
    security_headers_middleware as security_headers_middleware,
    tenant_middleware as tenant_middleware,
)
from cyberhound.api.handlers.accounts import AccountHandlers
from cyberhound.api.handlers.config import ConfigHandlers
from cyberhound.api.handlers.data import DataHandlers
from cyberhound.api.handlers.fixes import FixHandlers
from cyberhound.api.handlers.platform import PlatformHandlers
from cyberhound.api.handlers.scans import ScanHandlers
from cyberhound.api.handlers.schedules import ScheduleHandlers
from cyberhound.api.routes.intel_routes import register_routes as register_intel_routes
from cyberhound.core import passwords
from cyberhound.core.auth import (
    AuthConfig,
    auth_middleware,
    setup_auth_routes,
)
from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding
from cyberhound.core.multitenancy import (
    TenantDatabases,
    TenantRouter,
    TenantStore,
    current_tenant,
)
from cyberhound.core.scheduler import Scheduler, build_platform_scheduler
from cyberhound.core.security import (
    CsrfProtection,
    TLSManager,
    set_trusted_proxies,
)

logger = get_logger("api")


class CyberHoundServer(ScanHandlers, FixHandlers, DataHandlers, AccountHandlers, ScheduleHandlers, ConfigHandlers,
                       PlatformHandlers):
    """Estado del servidor, rutas y arranque. Los endpoints están en cyberhound/api/handlers/ por áreas;
    middlewares, permisos y utilidades comunes, en cyberhound/api/common.py."""

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
        self._auth_secret: str | None = cfg.auth.secret
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
        self._auth_secret = auth_cfg.secret     # cifra las credenciales SSH guardadas
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
        app.router.add_get ("/api/fix/remote/history", self.api_fix_remote_history)
        app.router.add_post("/api/fix/remote/undo",    self.api_fix_remote_undo)
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
        app.router.add_get   ("/api/config/ssh-credentials",       self.api_ssh_credentials_list)
        app.router.add_post  ("/api/config/ssh-credentials",       self.api_ssh_credentials_create)
        app.router.add_patch ("/api/config/ssh-credentials/{cid}", self.api_ssh_credentials_update)
        app.router.add_delete("/api/config/ssh-credentials/{cid}", self.api_ssh_credentials_delete)
        app.router.add_get   ("/api/config/ssh-host-keys",         self.api_ssh_host_keys_list)
        app.router.add_delete("/api/config/ssh-host-keys/{host}/{port}", self.api_ssh_host_keys_delete)
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
