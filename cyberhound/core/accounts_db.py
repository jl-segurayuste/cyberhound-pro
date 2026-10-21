"""
Sesiones, tokens de API y eventos de auditoría: tablas y métodos comunes a SQLite y PostgreSQL.

Los dos backends heredan `AccountsMixin` y aportan `_run`, `_rows` y `_val` (SQL con `?`;
PostgreSQL los traduce a `$1, $2…`). Al vivir en la BD de cada tenant, en multi-tenant las
sesiones, tokens y auditoría de una organización no se mezclan con los de otra.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

ACCOUNTS_TABLES = """
CREATE TABLE IF NOT EXISTS sessions (
    jti         TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    last_seen   TEXT,
    ip          TEXT DEFAULT '',
    user_agent  TEXT DEFAULT '',
    revoked     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    last_used   TEXT,
    revoked     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(username);
CREATE TABLE IF NOT EXISTS audit_events (
    id          {serial} PRIMARY KEY,
    ts          TEXT NOT NULL,
    username    TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    action      TEXT NOT NULL,
    target      TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    ok          INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
"""
SQLITE_ACCOUNTS = ACCOUNTS_TABLES.replace("{serial}", "INTEGER")   # INTEGER PRIMARY KEY = autoincremento
PG_ACCOUNTS = ACCOUNTS_TABLES.replace("{serial}", "SERIAL")

# Solo se refresca last_seen si han pasado más de esto (no escribir en cada petición)
_TOUCH_EVERY = timedelta(seconds=60)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AccountsMixin:
    async def _run(self, sql: str, *args) -> int: ...        # filas afectadas
    async def _rows(self, sql: str, *args) -> list[dict]: ...
    async def _val(self, sql: str, *args): ...

    # ── Sesiones ──────────────────────────────────────────────────────────────

    async def create_session(self, jti: str, username: str, expires_at: str, ip: str = "",
                             user_agent: str = "") -> None:
        now = _now()
        await self._run("INSERT INTO sessions (jti,username,created_at,expires_at,last_seen,ip,user_agent) "
                        "VALUES (?,?,?,?,?,?,?)", jti, username, now, expires_at, now, ip[:64], user_agent[:200])

    async def get_active_session(self, jti: str) -> dict | None:
        """La sesión si sigue viva (ni revocada ni caducada); de paso actualiza last_seen."""
        rows = await self._rows("SELECT * FROM sessions WHERE jti=? AND revoked=0", jti)
        if not rows:
            return None
        s = rows[0]
        now = datetime.now(UTC)
        if datetime.fromisoformat(s["expires_at"]) <= now:
            return None
        if not s.get("last_seen") or now - datetime.fromisoformat(s["last_seen"]) > _TOUCH_EVERY:
            await self._run("UPDATE sessions SET last_seen=? WHERE jti=?", now.isoformat(), jti)
        return s

    async def list_sessions(self, username: str) -> list[dict]:
        return await self._rows(
            "SELECT jti,created_at,expires_at,last_seen,ip,user_agent FROM sessions "
            "WHERE username=? AND revoked=0 AND expires_at>? ORDER BY last_seen DESC", username, _now())

    async def revoke_session(self, jti: str, username: str | None = None) -> bool:
        if username is None:
            return await self._run("UPDATE sessions SET revoked=1 WHERE jti=? AND revoked=0", jti) > 0
        return await self._run("UPDATE sessions SET revoked=1 WHERE jti=? AND username=? AND revoked=0",
                               jti, username) > 0

    async def revoke_user_sessions(self, username: str, keep_jti: str | None = None) -> int:
        return await self._run("UPDATE sessions SET revoked=1 WHERE username=? AND revoked=0 AND jti<>?",
                               username, keep_jti or "")

    async def purge_sessions(self, older_than_days: int = 30) -> int:
        cut = (datetime.now(UTC) - timedelta(days=older_than_days)).isoformat()
        return await self._run("DELETE FROM sessions WHERE expires_at<?", cut)

    # ── Tokens de API ─────────────────────────────────────────────────────────

    async def create_api_token(self, token_id: str, username: str, name: str, token_hash: str, role: str,
                               expires_at: str | None) -> None:
        await self._run("INSERT INTO api_tokens (id,username,name,token_hash,role,created_at,expires_at) "
                        "VALUES (?,?,?,?,?,?,?)", token_id, username, name[:80], token_hash, role, _now(),
                        expires_at)

    async def get_api_token(self, token_id: str) -> dict | None:
        rows = await self._rows("SELECT * FROM api_tokens WHERE id=? AND revoked=0", token_id)
        return rows[0] if rows else None

    async def touch_api_token(self, token_id: str) -> None:
        await self._run("UPDATE api_tokens SET last_used=? WHERE id=?", _now(), token_id)

    async def list_api_tokens(self, username: str) -> list[dict]:
        return await self._rows("SELECT id,name,role,created_at,expires_at,last_used FROM api_tokens "
                                "WHERE username=? AND revoked=0 ORDER BY created_at DESC", username)

    async def revoke_api_token(self, token_id: str, username: str | None = None) -> bool:
        if username is None:
            return await self._run("UPDATE api_tokens SET revoked=1 WHERE id=? AND revoked=0", token_id) > 0
        return await self._run("UPDATE api_tokens SET revoked=1 WHERE id=? AND username=? AND revoked=0",
                               token_id, username) > 0

    async def revoke_user_api_tokens(self, username: str) -> int:
        return await self._run("UPDATE api_tokens SET revoked=1 WHERE username=? AND revoked=0", username)

    # ── Auditoría ─────────────────────────────────────────────────────────────

    async def add_audit_event(self, action: str, username: str = "", ip: str = "", target: str = "",
                              detail: str = "", ok: bool = True) -> None:
        await self._run("INSERT INTO audit_events (ts,username,ip,action,target,detail,ok) VALUES (?,?,?,?,?,?,?)",
                        _now(), username[:64], ip[:64], action[:40], str(target)[:200], str(detail)[:500],
                        1 if ok else 0)

    async def list_audit_events(self, limit: int = 200, action: str = "", username: str = "", q: str = "",
                                only_failures: bool = False) -> list[dict]:
        where, args = [], []
        for cond, value in (("action=?", action), ("username=?", username)):
            if value:
                where.append(cond)
                args.append(value)
        if q:
            where.append("(target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
            args += [f"%{q}%"] * 3
        if only_failures:
            where.append("ok=0")
        sql = "SELECT ts,username,ip,action,target,detail,ok FROM audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        return await self._rows(sql, *args, max(1, min(int(limit), 1000)))
