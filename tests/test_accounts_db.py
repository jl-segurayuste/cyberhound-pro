"""Sesiones, tokens de API, auditoría y migraciones (SQLite, y PostgreSQL con CH_DB_URL)."""
import os
from datetime import UTC, datetime, timedelta

import pytest_asyncio

from cyberhound.core.database import DB_VERSION
from cyberhound.core.database_pg import DB_VERSION as PG_DB_VERSION, create_database

FUTURE = (datetime.now(UTC) + timedelta(hours=8)).isoformat()


@pytest_asyncio.fixture
async def db(tmp_path):
    d = create_database(db_url=os.environ.get("CH_DB_URL", ""), db_path=str(tmp_path / "a.db"))
    await d.init()
    yield d
    if hasattr(d, "close"):
        await d.close()


async def test_sesiones(db):
    await db.create_session("j1", "ana", FUTURE, "10.0.0.1", "Firefox")
    await db.create_session("j2", "ana", FUTURE, "10.0.0.2", "Chrome")
    await db.create_session("j3", "luis", FUTURE)
    assert (await db.get_active_session("j1"))["username"] == "ana"
    assert {s["jti"] for s in await db.list_sessions("ana")} == {"j1", "j2"}
    assert await db.revoke_session("j2", "luis") is False          # no es suya
    assert await db.revoke_session("j2", "ana") is True
    assert await db.get_active_session("j2") is None
    assert await db.revoke_user_sessions("ana", keep_jti="j1") == 0   # j2 ya revocada, j1 se conserva
    assert await db.get_active_session("j1")
    assert await db.revoke_user_sessions("ana") == 1
    assert await db.get_active_session("j1") is None and await db.get_active_session("j3")


async def test_sesion_caducada_no_vale(db):
    await db.create_session("old", "ana", (datetime.now(UTC) - timedelta(minutes=1)).isoformat())
    assert await db.get_active_session("old") is None
    assert await db.list_sessions("ana") == []


async def test_tokens(db):
    await db.create_api_token("t1", "ana", "ci", "hash1", "viewer", None)
    await db.create_api_token("t2", "ana", "backup", "hash2", "operator", FUTURE)
    assert (await db.get_api_token("t1"))["token_hash"] == "hash1"
    assert [t["name"] for t in await db.list_api_tokens("ana")] in (["backup", "ci"], ["ci", "backup"])
    assert "token_hash" not in (await db.list_api_tokens("ana"))[0]
    await db.touch_api_token("t1")
    assert (await db.get_api_token("t1"))["last_used"]
    assert await db.revoke_api_token("t1", "otro") is False
    assert await db.revoke_api_token("t1", "ana") is True and await db.get_api_token("t1") is None
    assert await db.revoke_user_api_tokens("ana") == 1


async def test_auditoria_y_filtros(db):
    await db.add_audit_event("login", "ana", "10.0.0.1", detail="ok")
    await db.add_audit_event("login", "luis", "10.0.0.9", detail="contraseña incorrecta", ok=False)
    await db.add_audit_event("user_update", "ana", target="luis", detail="rol=viewer")
    ev = await db.list_audit_events()
    assert [e["action"] for e in ev] == ["user_update", "login", "login"]   # más reciente primero
    assert len(await db.list_audit_events(action="login")) == 2
    assert [e["username"] for e in await db.list_audit_events(only_failures=True)] == ["luis"]
    assert len(await db.list_audit_events(q="10.0.0.9")) == 1
    assert len(await db.list_audit_events(username="ana", limit=1)) == 1


async def test_bd_sqlite_antigua_se_actualiza(tmp_path):
    """Una BD de una versión anterior (sin las tablas nuevas) se migra al abrirla."""
    import sqlite3

    from cyberhound.core.database import Database
    path = tmp_path / "vieja.db"
    with sqlite3.connect(path) as c:
        c.executescript("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
                        "INSERT INTO schema_version VALUES (5, '2026-01-01');")
    d = Database(path)
    await d.init()
    await d.create_session("j", "ana", FUTURE)
    with sqlite3.connect(path) as c:
        assert c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == DB_VERSION


async def test_bd_postgres_antigua_se_actualiza():
    url = os.environ.get("CH_DB_URL", "")
    if not url.startswith("postgresql://"):
        import pytest
        pytest.skip("solo con CH_DB_URL=postgresql://…")
    import asyncpg

    from cyberhound.core.database_pg import DatabasePG
    conn = await asyncpg.connect(url)
    await conn.execute('CREATE SCHEMA "tenant_vieja"; SET search_path TO "tenant_vieja";'
                       "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
                       "INSERT INTO schema_version VALUES (3, '2026-01-01');")
    await conn.close()
    d = DatabasePG(url, schema="tenant_vieja")
    await d.init()
    await d.create_session("j", "ana", FUTURE)
    assert await d.get_active_session("j")
    assert await d._val("SELECT MAX(version) FROM schema_version") == PG_DB_VERSION
    await d.close()
