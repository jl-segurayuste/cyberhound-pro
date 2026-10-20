"""Fixtures compartidas para todos los tests de CyberHound."""
import asyncio
import hashlib
import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from cyberhound.core.config import CyberHoundConfig
from cyberhound.core.database import Database
from cyberhound.core.models import Finding

# ── PostgreSQL opcional ───────────────────────────────────────────────────────
# CH_DB_URL=postgresql://… pytest  → toda la suite (servidor incluido) corre contra
# PostgreSQL; cada test empieza con el esquema vacío.

@pytest.fixture(autouse=True)
def _postgres_limpio():
    url = os.environ.get("CH_DB_URL", "")
    if url.startswith("postgresql://"):
        import asyncpg

        async def reset():
            conn = await asyncpg.connect(url)
            try:
                for (schema,) in await conn.fetch("SELECT nspname FROM pg_namespace WHERE nspname LIKE 'tenant\\_%'"):
                    await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')   # esquemas de tenants
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            finally:
                await conn.close()
        asyncio.run(reset())
    yield


# ── Fixtures básicas ──────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def sample_finding():
    return Finding(
        id="test_finding_001",
        category="ssh",
        severity="high",
        title="Test Finding",
        description="Descripción de prueba",
        remediation="Comando de remediación",
        auto_fix=True,
    )


@pytest.fixture
def critical_finding():
    return Finding(
        id="critical_001",
        category="firewall",
        severity="critical",
        title="Finding Crítico",
        description="",
        remediation="ufw enable",
        auto_fix=True,
    )


@pytest.fixture
def findings_list():
    return [
        Finding(id=f"f_{i}", category="ssh", severity=sev,
                title=f"Finding {i}", description="", remediation="")
        for i, sev in enumerate(["critical", "high", "high", "medium", "low", "info"])
    ]


@pytest_asyncio.fixture
async def db(tmp_path):
    """Base de datos SQLite temporal para tests."""
    database = Database(tmp_path / "test.db")
    await database.init()
    return database


@pytest_asyncio.fixture
async def cfg(tmp_path):
    """Config mínima para tests."""
    config = CyberHoundConfig()
    config.db_path = str(tmp_path / "test.db")
    config.auth.password_hash = hashlib.sha256(b"test1234").hexdigest()
    config.auth.secret = "test_secret_32_chars_exactly_ok!!"
    config.scheduler.enabled = False
    return config
