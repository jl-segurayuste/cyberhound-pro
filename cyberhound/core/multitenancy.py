"""
Soporte multi-tenant para CyberHound Pro.

Permite que múltiples organizaciones usen la misma instancia de CyberHound
con datos completamente separados. Útil para MSPs (Managed Service Providers)
o despliegues SaaS.

Modelo de datos:
  - Cada tenant tiene un slug único (p.ej. "acme", "contoso")
  - Los usuarios pertenecen a un tenant
  - Los scans, findings, assets y configuración son por tenant
  - El usuario "superadmin" puede ver todos los tenants

Implementación:
  - Prefijado de tablas por tenant en SQLite (tenant_slug_scans, etc.)
  - En PostgreSQL: schemas separados (acme.scans, contoso.scans)
  - Middleware aiohttp que inyecta el tenant en cada request
  - El tenant se detecta por: subdominio, header X-Tenant, o JWT claim

Activación:
  - Establecer multi_tenant.enabled: true en config.yaml
  - Crear tenants via POST /api/tenants
  - Los usuarios se asignan a tenants en su creación
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cyberhound.core.logging import get_logger

logger = get_logger("multitenancy")

TENANT_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$")


@dataclass
class Tenant:
    slug:        str              # identificador único (URL-safe)
    name:        str              # nombre visible
    admin_email: str = ""
    plan:        str = "starter"  # community | starter | professional | enterprise
    active:      bool = True
    created_at:  str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    api_key:     str = field(default_factory=lambda: secrets.token_urlsafe(32))
    settings:    dict = field(default_factory=dict)

    def __post_init__(self):
        if not TENANT_SLUG_RE.match(self.slug):
            raise ValueError(
                f"Slug de tenant inválido: '{self.slug}'. "
                "Solo minúsculas, números y guiones (3-32 chars)."
            )

    def to_dict(self, include_key: bool = False) -> dict:
        d = {
            "slug":        self.slug,
            "name":        self.name,
            "admin_email": self.admin_email,
            "plan":        self.plan,
            "active":      self.active,
            "created_at":  self.created_at,
        }
        if include_key:
            d["api_key"] = self.api_key
        return d

    @property
    def db_prefix(self) -> str:
        """Prefijo para tablas SQLite: 'acme_'"""
        return f"{self.slug}_"

    @property
    def pg_schema(self) -> str:
        """Schema PostgreSQL: 'tenant_acme'"""
        return f"tenant_{self.slug}"


class TenantStore:
    """
    Almacén de tenants. Usa un fichero JSON simple para guardar los tenants,
    ya que el número de tenants suele ser pequeño y no justifica una tabla extra.
    """

    STORE_PATH = Path.home() / ".cyberhound" / "tenants.json"

    def __init__(self, path: Path | None = None):
        self._path = path or self.STORE_PATH
        self._tenants: dict[str, Tenant] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        import json
        try:
            data = json.loads(self._path.read_text())
            for slug, td in data.items():
                self._tenants[slug] = Tenant(
                    slug=td["slug"], name=td["name"],
                    admin_email=td.get("admin_email", ""),
                    plan=td.get("plan", "starter"),
                    active=td.get("active", True),
                    created_at=td.get("created_at", ""),
                    api_key=td.get("api_key", secrets.token_urlsafe(32)),
                    settings=td.get("settings", {}),
                )
        except Exception as e:
            logger.error("Error cargando tenants: %s", e)

    def _save(self) -> None:
        import json
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({s: t.to_dict(include_key=True) for s, t in self._tenants.items()},
                       indent=2)
        )
        self._path.chmod(0o600)

    def create(self, slug: str, name: str, admin_email: str = "",
               plan: str = "starter") -> Tenant:
        if slug in self._tenants:
            raise ValueError(f"Tenant '{slug}' ya existe")
        tenant = Tenant(slug=slug, name=name, admin_email=admin_email, plan=plan)
        self._tenants[slug] = tenant
        self._save()
        logger.info("Tenant creado: %s (%s)", slug, name)
        return tenant

    def get(self, slug: str) -> Tenant | None:
        return self._tenants.get(slug)

    def get_by_api_key(self, key: str) -> Tenant | None:
        for tenant in self._tenants.values():
            if secrets.compare_digest(tenant.api_key, key):
                return tenant
        return None

    def list(self) -> list[Tenant]:
        return [t for t in self._tenants.values() if t.active]

    def update(self, slug: str, **kwargs) -> Tenant | None:
        tenant = self._tenants.get(slug)
        if not tenant:
            return None
        allowed = {"name", "admin_email", "plan", "active", "settings"}
        for k, v in kwargs.items():
            if k in allowed:
                setattr(tenant, k, v)
        self._save()
        return tenant

    def delete(self, slug: str) -> bool:
        if slug not in self._tenants:
            return False
        # Soft delete
        self._tenants[slug].active = False
        self._save()
        logger.info("Tenant desactivado: %s", slug)
        return True

    def rotate_api_key(self, slug: str) -> str | None:
        tenant = self._tenants.get(slug)
        if not tenant:
            return None
        tenant.api_key = secrets.token_urlsafe(32)
        self._save()
        return tenant.api_key


class TenantMiddleware:
    """
    Middleware aiohttp que detecta el tenant de cada request.

    Orden de detección:
    1. Header X-Tenant: acme
    2. Subdominio: acme.cyberhound.empresa.com
    3. Query param: ?tenant=acme
    4. JWT claim "tenant" (si está en el token)
    5. Tenant por defecto: "default"
    """

    def __init__(self, store: TenantStore, default_slug: str = "default"):
        self.store   = store
        self.default = default_slug

    async def __call__(self, request, handler):
        from aiohttp import web
        slug = self._detect_tenant(request)
        tenant = self.store.get(slug)

        if tenant is None and slug != self.default:
            # Tenant no encontrado — crear implícitamente si es el default
            if slug == self.default:
                tenant = self.store.create(self.default, "Default Organization")
            else:
                return web.json_response(
                    {"error": f"Tenant '{slug}' no encontrado"},
                    status=404,
                )

        request["tenant"] = tenant or Tenant(slug=self.default, name="Default")
        return await handler(request)

    def _detect_tenant(self, request) -> str:
        # 1. Header explícito
        header = request.headers.get("X-Tenant", "").strip().lower()
        if header and TENANT_SLUG_RE.match(header):
            return header

        # 2. Subdominio
        host = request.headers.get("Host", "")
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain = parts[0].lower()
            if TENANT_SLUG_RE.match(subdomain) and subdomain not in ("www", "api", "app"):
                return subdomain

        # 3. Query param
        qparam = request.rel_url.query.get("tenant", "").strip().lower()
        if qparam and TENANT_SLUG_RE.match(qparam):
            return qparam

        return self.default


# ── Global store (singleton) ──────────────────────────────────────────────────
tenant_store = TenantStore()


def get_current_tenant(request) -> Tenant:
    """Helper para obtener el tenant del request actual."""
    return request.get("tenant", Tenant(slug="default", name="Default"))
