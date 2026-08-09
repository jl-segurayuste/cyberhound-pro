"""
Capa de persistencia PostgreSQL para CyberHound Pro.

Alternativa a SQLite para despliegues de alta disponibilidad
o multi-instancia (múltiples servidores CyberHound contra la misma BD).

Requisitos:
  pip install asyncpg

Configuración:
  db_url: postgresql://user:password@host:5432/cyberhound
  O con variables de entorno:
  CH_DB_URL=postgresql://user:password@host:5432/cyberhound

Misma interfaz que database.py — los métodos son compatibles.
"""
from __future__ import annotations

import fnmatch
import json
import time
from datetime import UTC, datetime

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("database_pg")

SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id             SERIAL PRIMARY KEY,
    scan_type      TEXT NOT NULL,
    target         TEXT NOT NULL DEFAULT 'localhost',
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    duration_s     REAL,
    score          INTEGER,
    total_findings INTEGER DEFAULT 0,
    critical       INTEGER DEFAULT 0,
    high           INTEGER DEFAULT 0,
    medium         INTEGER DEFAULT 0,
    low            INTEGER DEFAULT 0,
    status         TEXT DEFAULT 'running',
    triggered_by   TEXT DEFAULT 'manual'
);
CREATE TABLE IF NOT EXISTS findings (
    id          SERIAL PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    finding_id  TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    evidence    TEXT,
    auto_fix    BOOLEAN DEFAULT FALSE,
    file_path   TEXT,
    line_number INTEGER DEFAULT 0,
    source_host TEXT DEFAULT '',
    fixed_at    TEXT,
    fixed_by    TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    ip            TEXT PRIMARY KEY,
    mac           TEXT DEFAULT '',
    hostname      TEXT DEFAULT '',
    vendor        TEXT DEFAULT '',
    os_name       TEXT DEFAULT '',
    open_ports    TEXT DEFAULT '[]',
    risk_level    TEXT DEFAULT 'unknown',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    is_authorized INTEGER DEFAULT 1,
    notes         TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS suppressions (
    id                  SERIAL PRIMARY KEY,
    finding_id_pattern  TEXT NOT NULL UNIQUE,
    reason              TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT
);
CREATE TABLE IF NOT EXISTS users (
    username           TEXT PRIMARY KEY,
    password_hash      TEXT NOT NULL,
    role               TEXT NOT NULL DEFAULT 'viewer',
    created_at         TEXT NOT NULL,
    last_login         TEXT,
    active             INTEGER DEFAULT 1,
    totp_enabled       INTEGER DEFAULT 0,
    totp_secret        TEXT,
    totp_pending_secret TEXT,
    recovery_codes_json TEXT DEFAULT '[]',
    totp_last_counter  INTEGER
);
CREATE TABLE IF NOT EXISTS notifications (
    id         SERIAL PRIMARY KEY,
    scan_id    INTEGER REFERENCES scans(id),
    level      TEXT NOT NULL,
    message    TEXT NOT NULL,
    sent       INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    sent_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_started_at  ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_scans_type        ON scans(scan_type);
"""

DB_VERSION = 3


def _now() -> str:
    return datetime.now(UTC).isoformat()


class DatabasePG:
    """
    Base de datos PostgreSQL con la misma interfaz que Database (SQLite).
    Usa asyncpg para máximo rendimiento.
    """

    def __init__(self, url: str) -> None:
        self.url  = url
        self._pool = None

    async def init(self) -> None:
        try:
            import asyncpg
        except ImportError as e:
            raise RuntimeError(
                "asyncpg no instalado. Instala con: pip install asyncpg"
            ) from e

        import asyncpg
        self._pool = await asyncpg.create_pool(
            self.url,
            min_size=2, max_size=10,
            command_timeout=30,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(SCHEMA_PG)
            # `CREATE TABLE IF NOT EXISTS` no altera una tabla `users` que ya
            # existiera de un despliegue anterior a esta columna -- a
            # diferencia de database.py (SQLite), este backend no tiene lista
            # de migraciones incrementales. `ADD COLUMN IF NOT EXISTS` es
            # idempotente y no requiere una.
            await conn.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_counter INTEGER"
            )
            version = await conn.fetchval("SELECT MAX(version) FROM schema_version")
            if not version or version < DB_VERSION:
                await conn.execute(
                    "INSERT INTO schema_version VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    DB_VERSION, _now(),
                )
        logger.info("PostgreSQL inicializado: %s", self.url.split("@")[-1])

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def _exec(self, query: str, *args) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(query, *args)

    async def _fetch(self, query: str, *args) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(r) for r in rows]

    async def _fetchval(self, query: str, *args):
        async with self._pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    # ── Scans (misma interfaz que Database) ───────────────────────────────────

    async def create_scan(self, scan_type: str, target: str = "localhost", triggered_by: str = "manual") -> int:
        return await self._fetchval(
            "INSERT INTO scans (scan_type,target,started_at,status,triggered_by) "
            "VALUES ($1,$2,$3,'running',$4) RETURNING id",
            scan_type, target, _now(), triggered_by,
        )

    async def complete_scan(self, scan_id: int, findings: list[Finding], score: int | None = None) -> None:
        counts = {"critical":0,"high":0,"medium":0,"low":0}
        for f in findings:
            if f.severity in counts: counts[f.severity] += 1

        if score is None:
            try:
                from cyberhound.core.scoring import compute_score
                score = compute_score(findings).score
            except Exception:
                score = max(0, 100 - counts["critical"]*20 - counts["high"]*10 - counts["medium"]*4 - counts["low"])

        started = await self._fetchval("SELECT started_at FROM scans WHERE id=$1", scan_id)
        try:
            duration = time.time() - datetime.fromisoformat(started).timestamp()
        except Exception:
            duration = 0.0

        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET finished_at=$1,duration_s=$2,score=$3,"
                "total_findings=$4,critical=$5,high=$6,medium=$7,low=$8,status='completed' WHERE id=$9",
                _now(), duration, score, len(findings),
                counts["critical"], counts["high"], counts["medium"], counts["low"], scan_id,
            )
            await conn.executemany(
                "INSERT INTO findings (scan_id,finding_id,category,severity,title,"
                "description,remediation,evidence,auto_fix,file_path,line_number,source_host) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                [(scan_id, f.id, f.category, f.severity, f.title,
                  f.description, f.remediation, f.evidence,
                  f.auto_fix, f.file_path, f.line_number, f.source_host)
                 for f in findings],
            )

    async def fail_scan(self, scan_id: int) -> None:
        await self._exec(
            "UPDATE scans SET status='failed',finished_at=$1 WHERE id=$2",
            _now(), scan_id,
        )

    async def get_scan_history(self, scan_type: str | None = None, limit: int = 50) -> list[dict]:
        if scan_type:
            return await self._fetch(
                "SELECT * FROM scans WHERE scan_type=$1 ORDER BY started_at DESC LIMIT $2",
                scan_type, limit,
            )
        return await self._fetch("SELECT * FROM scans ORDER BY started_at DESC LIMIT $1", limit)

    async def get_scan_findings(self, scan_id: int) -> list[dict]:
        return await self._fetch(
            "SELECT * FROM findings WHERE scan_id=$1 ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            scan_id,
        )

    async def get_score_trend(self, scan_type: str = "audit", days: int = 30) -> list[dict]:
        return await self._fetch(
            "SELECT started_at,score,total_findings,critical,high FROM scans "
            "WHERE scan_type=$1 AND status='completed' "
            "AND started_at >= NOW() - ($2 * INTERVAL '1 day') ORDER BY started_at ASC",
            scan_type, days,
        )

    # ── Assets / Suppressions / Users — misma interfaz ───────────────────────

    async def upsert_asset(self, asset) -> bool:
        existing = await self._fetchval("SELECT ip FROM assets WHERE ip=$1", asset.ip)
        now = _now()
        if existing is None:
            await self._exec(
                "INSERT INTO assets (ip,mac,hostname,vendor,os_name,open_ports,"
                "risk_level,first_seen,last_seen,is_authorized) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                asset.ip, asset.mac, asset.hostname, asset.vendor,
                asset.os_name, asset.open_ports, asset.risk_level, now, now, asset.is_authorized,
            )
            return True
        else:
            await self._exec(
                "UPDATE assets SET mac=$1,hostname=$2,vendor=$3,os_name=$4,"
                "open_ports=$5,risk_level=$6,last_seen=$7 WHERE ip=$8",
                asset.mac, asset.hostname, asset.vendor, asset.os_name,
                asset.open_ports, asset.risk_level, now, asset.ip,
            )
            return False

    async def get_assets(self) -> list[dict]:
        rows = await self._fetch("SELECT * FROM assets ORDER BY last_seen DESC")
        for r in rows:
            try:
                r["open_ports"] = json.loads(r.get("open_ports", "[]"))
            except Exception:
                r["open_ports"] = []
        return rows

    async def set_asset_authorized(self, ip: str, authorized: bool, notes: str = "") -> None:
        await self._exec(
            "UPDATE assets SET is_authorized=$1,notes=$2 WHERE ip=$3",
            int(authorized), notes, ip,
        )

    async def add_suppression(self, pattern: str, reason: str, created_by: str, expires_at: str | None = None) -> None:
        await self._exec(
            "INSERT INTO suppressions (finding_id_pattern,reason,created_by,created_at,expires_at) "
            "VALUES ($1,$2,$3,$4,$5) ON CONFLICT (finding_id_pattern) DO UPDATE SET reason=$2",
            pattern, reason, created_by, _now(), expires_at,
        )

    async def remove_suppression(self, pattern: str) -> None:
        await self._exec("DELETE FROM suppressions WHERE finding_id_pattern=$1", pattern)

    async def get_suppressions(self) -> list[dict]:
        return await self._fetch("SELECT * FROM suppressions ORDER BY created_at DESC")

    async def is_suppressed(self, finding_id: str) -> bool:
        now = _now()
        for s in await self.get_suppressions():
            if s.get("expires_at") and s["expires_at"] < now:
                continue
            if fnmatch.fnmatch(finding_id, s["finding_id_pattern"]):
                return True
        return False

    async def filter_suppressed(self, findings: list[Finding]) -> list[Finding]:
        result = []
        for f in findings:
            if not await self.is_suppressed(f.id):
                result.append(f)
        return result

    async def get_user(self, username: str) -> dict | None:
        rows = await self._fetch(
            "SELECT * FROM users WHERE username=$1 AND active=1", username
        )
        return rows[0] if rows else None

    async def ensure_admin_exists(self, username: str, password_hash: str) -> None:
        existing = await self.get_user(username)
        if not existing:
            await self._exec(
                "INSERT INTO users (username,password_hash,role,created_at) VALUES ($1,$2,'admin',$3)",
                username, password_hash, _now(),
            )

    async def update_last_login(self, username: str) -> None:
        await self._exec("UPDATE users SET last_login=$1 WHERE username=$2", _now(), username)

    async def update_user(self, username: str, **kwargs) -> None:
        allowed = {"password_hash","role","active"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        sets = ", ".join(f"{k}=${i+2}" for i, k in enumerate(fields))
        await self._exec(
            f"UPDATE users SET {sets} WHERE username=$1",
            username, *fields.values(),
        )

    async def list_users(self) -> list[dict]:
        return await self._fetch(
            "SELECT username,role,created_at,last_login,active FROM users"
        )

    async def create_user(self, user) -> None:
        await self._exec(
            "INSERT INTO users (username,password_hash,role,created_at,active) VALUES ($1,$2,$3,$4,$5)",
            user.username, user.password_hash, user.role, user.created_at, user.active,
        )

    # ── TOTP / 2FA ────────────────────────────────────────────────────────────
    # Bug real encontrado 2026-08-09: este backend no implementaba NINGUNO de
    # estos métodos pese a que el docstring del módulo afirma "misma interfaz
    # que database.py" -- cualquier despliegue con Postgres rompía con
    # AttributeError en cuanto se tocaba /api/2fa/*.

    async def set_totp_pending(self, username: str, secret: str, recovery_codes: list[str]) -> None:
        from cyberhound.core.totp import hash_recovery_code
        hashes = [hash_recovery_code(c) for c in recovery_codes]
        await self._exec(
            "UPDATE users SET totp_pending_secret=$1, recovery_codes_json=$2 WHERE username=$3",
            secret, json.dumps(hashes), username,
        )

    async def get_totp_pending(self, username: str) -> dict | None:
        secret = await self._fetchval(
            "SELECT totp_pending_secret FROM users WHERE username=$1", username
        )
        return {"secret": secret} if secret else None

    async def activate_totp(self, username: str) -> None:
        await self._exec(
            "UPDATE users SET totp_enabled=1, totp_secret=totp_pending_secret, "
            "totp_pending_secret=NULL WHERE username=$1",
            username,
        )

    async def disable_totp(self, username: str) -> None:
        await self._exec(
            "UPDATE users SET totp_enabled=0, totp_secret=NULL, "
            "totp_pending_secret=NULL WHERE username=$1",
            username,
        )

    async def update_totp_last_counter(self, username: str, counter: int) -> None:
        """Registra el último paso (step) TOTP consumido -- impide reutilizar
        el mismo código dos veces. Ver bug real corregido 2026-08-09 en
        `TOTPManager.verify`/`activate_2fa`."""
        await self._exec(
            "UPDATE users SET totp_last_counter=$1 WHERE username=$2", counter, username
        )

    async def update_recovery_codes(self, username: str, hashes: list[str]) -> None:
        await self._exec(
            "UPDATE users SET recovery_codes_json=$1 WHERE username=$2",
            json.dumps(hashes), username,
        )

    async def add_notification(self, message: str, level: str = "info", scan_id: int | None = None) -> None:
        await self._exec(
            "INSERT INTO notifications (scan_id,level,message,created_at) VALUES ($1,$2,$3,$4)",
            scan_id, level, message, _now(),
        )

    async def get_pending_notifications(self) -> list[dict]:
        return await self._fetch("SELECT * FROM notifications WHERE sent=0 ORDER BY created_at ASC")

    async def mark_notification_sent(self, notif_id: int) -> None:
        await self._exec("UPDATE notifications SET sent=1,sent_at=$1 WHERE id=$2", _now(), notif_id)

    async def mark_finding_fixed(self, scan_id: int, finding_id: str, fixed_by: str) -> None:
        await self._exec(
            "UPDATE findings SET fixed_at=$1,fixed_by=$2 WHERE scan_id=$3 AND finding_id=$4",
            _now(), fixed_by, scan_id, finding_id,
        )

    async def get_comparison(self, scan_id: int) -> dict:
        scan_type = await self._fetchval("SELECT scan_type FROM scans WHERE id=$1", scan_id)
        if not scan_type:
            return {}
        prev_id = await self._fetchval(
            "SELECT id FROM scans WHERE scan_type=$1 AND status='completed' AND id<$2 ORDER BY id DESC LIMIT 1",
            scan_type, scan_id,
        )
        if not prev_id:
            return {"first_scan": True}
        current_rows  = await self._fetch("SELECT finding_id,severity FROM findings WHERE scan_id=$1", scan_id)
        previous_rows = await self._fetch("SELECT finding_id,severity FROM findings WHERE scan_id=$1", prev_id)
        current  = {r["finding_id"]: r["severity"] for r in current_rows}
        previous = {r["finding_id"]: r["severity"] for r in previous_rows}
        new_ids  = set(current) - set(previous)
        resolved = set(previous) - set(current)
        return {
            "previous_scan_id": prev_id,
            "new":      [{"id": i, "severity": current[i]}  for i in new_ids],
            "resolved": [{"id": i, "severity": previous[i]} for i in resolved],
            "unchanged": len(set(current) & set(previous)),
        }

    async def get_dashboard_stats(self) -> dict:
        last_scans = {}
        for stype in ("audit", "malware", "network", "code"):
            rows = await self._fetch(
                "SELECT * FROM scans WHERE scan_type=$1 AND status='completed' "
                "ORDER BY started_at DESC LIMIT 1", stype
            )
            last_scans[stype] = rows[0] if rows else None

        total_assets = await self._fetchval("SELECT COUNT(*) FROM assets") or 0
        unauthorized = await self._fetchval("SELECT COUNT(*) FROM assets WHERE is_authorized=0") or 0
        score_trend_rows = await self._fetch(
            "SELECT DATE(started_at) as day, AVG(score) as avg_score FROM scans "
            "WHERE scan_type='audit' AND status='completed' "
            "AND started_at >= NOW() - INTERVAL '30 days' GROUP BY day ORDER BY day ASC"
        )
        critical_findings: list[dict] = []
        if last_scans.get("audit"):
            critical_findings = await self._fetch(
                "SELECT * FROM findings WHERE scan_id=$1 AND severity='critical' "
                "AND fixed_at IS NULL LIMIT 10",
                last_scans["audit"]["id"],
            )

        return {
            "last_scans":          last_scans,
            "total_assets":        total_assets,
            "unauthorized_assets": unauthorized,
            "score_trend":         score_trend_rows,
            "critical_findings":   critical_findings,
        }


def create_database(db_url: str = "", db_path: str = ""):
    """
    Factory que devuelve DatabasePG o Database según la configuración.
    Si db_url empieza por 'postgresql://', usa PostgreSQL.
    Si no, usa SQLite.
    """
    if db_url and db_url.startswith("postgresql://"):
        logger.info("Usando PostgreSQL: %s", db_url.split("@")[-1] if "@" in db_url else db_url)
        return DatabasePG(db_url)
    else:
        from pathlib import Path

        from cyberhound.core.database import DEFAULT_DB_PATH, Database
        path = Path(db_path) if db_path else DEFAULT_DB_PATH
        logger.info("Usando SQLite: %s", path)
        return Database(path)
