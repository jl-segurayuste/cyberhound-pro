"""
Multi-tenant: varias organizaciones aisladas en una sola instancia de CyberHound.

Modelo:
  - Cada tenant (slug "acme", "contoso"…) tiene su propia base de datos: un fichero
    SQLite en <dir de la BD>/tenants/<slug>.db o un esquema "tenant_<slug>" en
    PostgreSQL. Escaneos, hallazgos, activos, supresiones, usuarios y agentes de un
    tenant no comparten tabla con los de otro.
  - El tenant "default" es la BD de siempre (db_path / db_url): activar el modo
    multi-tenant no mueve ni cambia datos existentes.
  - El tenant de cada petición vive en `current_tenant` (ContextVar). Lo fija el
    middleware a partir del JWT; las tareas que lanza una petición (escaneos por
    WebSocket, envíos a SIEM…) heredan el contexto, y lo que corre fuera de una
    petición (scheduler) trabaja sobre "default".
  - `TenantRouter` es lo que el servidor usa como `self.db`: delega cada llamada en
    la BD del tenant actual.
  - El admin de config.yaml es el superadmin de la plataforma: gestiona tenants y
    puede entrar en cualquiera. Lo que actúa sobre el propio servidor (auditoría
    local, fixes, malware, Docker, configuración global…) queda reservado a él.

Activación: `multi_tenant: {enabled: true}` en config.yaml; los tenants se crean
desde Configuración › Organizaciones o con POST /api/tenants.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cyberhound.core.logging import get_logger
from cyberhound.core.paths import DATA_DIR

logger = get_logger("multitenancy")

DEFAULT_TENANT = "default"
TENANT_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$")
# No se pueden usar como slug: "default" es la BD original y el resto chocan con rutas o subdominios
RESERVED_SLUGS = {DEFAULT_TENANT, "www", "api", "app", "admin", "static", "login", "public"}

current_tenant: ContextVar[str] = ContextVar("current_tenant", default=DEFAULT_TENANT)


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
            "allowed_targets": self.settings.get("allowed_targets", []),
        }
        if include_key:
            d["api_key"] = self.api_key
        return d

    @property
    def pg_schema(self) -> str:
        return schema_for(self.slug)


def schema_for(slug: str) -> str:
    """Esquema PostgreSQL de un tenant ("tenant_acme"); el slug ya está validado."""
    return "tenant_" + slug.replace("-", "_")


def tenant_from_host(host: str) -> str:
    """Slug candidato del subdominio (acme.cyberhound.empresa.es → "acme"), o ""."""
    name = (host or "").rsplit(":", 1)[0].strip("[]").lower()
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", name):   # una IP no tiene subdominio
        return ""
    parts = name.split(".")
    if len(parts) >= 3 and TENANT_SLUG_RE.match(parts[0]) and parts[0] not in RESERVED_SLUGS:
        return parts[0]
    return ""


class TenantStore:
    """Tenants en un JSON (0600) junto a config.yaml: suelen ser pocos y no justifican tabla."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._tenants: dict[str, Tenant] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
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
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({s: t.to_dict(include_key=True) | {"settings": t.settings}
                       for s, t in self._tenants.items()}, f, indent=2)
        self._path.chmod(0o600)

    def create(self, slug: str, name: str, admin_email: str = "", plan: str = "starter") -> Tenant:
        if slug in RESERVED_SLUGS:
            raise ValueError(f"'{slug}' es un nombre reservado")
        if not (name or "").strip():
            raise ValueError("El nombre del tenant es obligatorio")
        # El borrado es lógico: un slug borrado se puede volver a crear (API key y datos nuevos)
        if slug in self._tenants and self._tenants[slug].active:
            raise ValueError(f"Tenant '{slug}' ya existe")
        tenant = Tenant(slug=slug, name=name.strip(), admin_email=admin_email, plan=plan)
        self._tenants[slug] = tenant
        self._save()
        logger.info("Tenant creado: %s (%s)", slug, name)
        return tenant

    def get(self, slug: str) -> Tenant | None:
        return self._tenants.get(slug)

    def is_active(self, slug: str) -> bool:
        if slug == DEFAULT_TENANT:
            return True
        t = self._tenants.get(slug)
        return bool(t and t.active)

    def get_by_api_key(self, key: str) -> Tenant | None:
        for tenant in self._tenants.values():
            if key and tenant.active and secrets.compare_digest(tenant.api_key, key):
                return tenant
        return None

    def list(self) -> list[Tenant]:
        return [t for t in self._tenants.values() if t.active]

    def update(self, slug: str, **kwargs) -> Tenant | None:
        tenant = self._tenants.get(slug)
        if not tenant or not tenant.active:
            return None
        if "name" in kwargs and not str(kwargs["name"] or "").strip():
            raise ValueError("El nombre del tenant es obligatorio")
        for k in ("name", "admin_email", "plan"):
            if k in kwargs and isinstance(kwargs[k], str):
                setattr(tenant, k, kwargs[k].strip())
        if "allowed_targets" in kwargs:
            from cyberhound.core.scope import parse_scope
            tenant.settings["allowed_targets"] = parse_scope(kwargs["allowed_targets"])
        self._save()
        return tenant

    def set_setting(self, slug: str, key: str, value) -> None:
        tenant = self._tenants[slug]
        tenant.settings[key] = value
        self._save()

    def delete(self, slug: str) -> bool:
        tenant = self._tenants.get(slug)
        if not tenant or not tenant.active:
            return False
        tenant.active = False
        self._save()
        logger.info("Tenant desactivado: %s", slug)
        return True

    def rotate_api_key(self, slug: str) -> str | None:
        tenant = self._tenants.get(slug)
        if not tenant or not tenant.active:
            return None
        tenant.api_key = secrets.token_urlsafe(32)
        self._save()
        return tenant.api_key


class TenantDatabases:
    """Una BD por tenant, abierta e inicializada la primera vez que se usa."""

    def __init__(self, default_db, db_url: str = "", db_path: str = "") -> None:
        self._dbs = {DEFAULT_TENANT: default_db}
        self._db_url = db_url or ""
        self._dir = (Path(db_path).parent if db_path else DATA_DIR) / "tenants"

    @property
    def default(self):
        return self._dbs[DEFAULT_TENANT]

    def get(self, slug: str):
        db = self._dbs.get(slug)
        if db is None:
            # Nunca caer en silencio en la BD por defecto: eso mezclaría datos de tenants
            raise LookupError(f"BD del tenant '{slug}' no abierta")
        return db

    async def ensure(self, slug: str):
        if slug in self._dbs:
            return self._dbs[slug]
        if not TENANT_SLUG_RE.match(slug) or slug in RESERVED_SLUGS:
            raise ValueError(f"Tenant inválido: {slug!r}")
        if self._db_url.startswith("postgresql://"):
            from cyberhound.core.database_pg import DatabasePG
            db = DatabasePG(self._db_url, schema=schema_for(slug))
        else:
            from cyberhound.core.database import Database
            db = Database(self._dir / f"{slug}.db")
        await db.init()
        self._dbs[slug] = db
        return db

    async def archive(self, slug: str) -> None:
        """Aparta los datos de un tenant dado de baja: si alguien vuelve a crear el mismo
        slug, empieza con una BD vacía y no hereda los datos de otra organización."""
        db = self._dbs.pop(slug, None)
        if db is not None and hasattr(db, "close"):
            await db.close()
        stamp = time.strftime("%Y%m%d%H%M%S")
        if self._db_url.startswith("postgresql://"):
            import asyncpg
            conn = await asyncpg.connect(self._db_url)
            try:
                if await conn.fetchval("SELECT 1 FROM pg_namespace WHERE nspname=$1", schema_for(slug)):
                    await conn.execute(f'ALTER SCHEMA "{schema_for(slug)}" RENAME TO "{schema_for(slug)}_baja_{stamp}"')
            finally:
                await conn.close()
        else:
            for suffix in ("", "-wal", "-shm"):
                f = self._dir / f"{slug}.db{suffix}"
                if f.exists():
                    f.rename(self._dir / f"{slug}.db.baja-{stamp}{suffix}")
        logger.info("Datos del tenant %s archivados (%s)", slug, stamp)

    async def close(self) -> None:
        for slug, db in list(self._dbs.items()):
            if slug != DEFAULT_TENANT and hasattr(db, "close"):
                await db.close()


class TenantRouter:
    """Se usa como la BD del servidor: cada llamada va a la BD del tenant actual."""

    def __init__(self, databases: TenantDatabases) -> None:
        self._databases = databases

    @property
    def databases(self) -> TenantDatabases:
        return self._databases

    def __getattr__(self, name):
        return getattr(self._databases.get(current_tenant.get()), name)
